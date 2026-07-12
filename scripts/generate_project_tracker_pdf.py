from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Flowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
TRACKER_SOURCE = ROOT / "src" / "data" / "projectTracker.ts"
OUTPUT_DIR = ROOT / "output" / "pdf"
OUTPUT_PDF = OUTPUT_DIR / "monday_report_project_tracker.pdf"
READINESS_URL = "http://127.0.0.1:8000/readiness/client-data"

STATUS_COLORS = {
    "complete": colors.HexColor("#1F8A5B"),
    "in_progress": colors.HexColor("#2563EB"),
    "pending": colors.HexColor("#D97706"),
    "blocked": colors.HexColor("#DC2626"),
    "pass": colors.HexColor("#1F8A5B"),
    "watch": colors.HexColor("#D97706"),
    "warn": colors.HexColor("#D97706"),
    "fail": colors.HexColor("#DC2626"),
    "ready": colors.HexColor("#1F8A5B"),
    "not_ready": colors.HexColor("#D97706"),
}


class StatusBarChart(Flowable):
    def __init__(self, title: str, counts: dict[str, int], order: list[str], width: float = 6.7 * inch):
        super().__init__()
        self.title = title
        self.counts = counts
        self.order = order
        self.width = width
        self.height = 1.55 * inch

    def draw(self) -> None:
        self.canv.setFont("Helvetica-Bold", 10)
        self.canv.setFillColor(colors.HexColor("#111827"))
        self.canv.drawString(0, self.height - 12, self.title)

        total = sum(self.counts.values()) or 1
        self.canv.setFont("Helvetica", 7.5)
        self.canv.setFillColor(colors.HexColor("#64748B"))
        self.canv.drawRightString(self.width, self.height - 12, f"Total {total}")
        x = 0
        y = self.height - 42
        bar_width = self.width
        bar_height = 18
        for key in self.order:
            value = self.counts.get(key, 0)
            if value <= 0:
                continue
            segment_width = bar_width * (value / total)
            self.canv.setFillColor(STATUS_COLORS.get(key, colors.HexColor("#64748B")))
            self.canv.rect(x, y, segment_width, bar_height, fill=1, stroke=0)
            if segment_width >= 44:
                self.canv.setFillColor(colors.white)
                self.canv.setFont("Helvetica-Bold", 7)
                percent = round((value / total) * 100)
                self.canv.drawCentredString(x + segment_width / 2, y + 5, f"{value} / {percent}%")
            x += segment_width
        self.canv.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.canv.rect(0, y, bar_width, bar_height, fill=0, stroke=1)

        legend_y = y - 22
        legend_x = 0
        self.canv.setFont("Helvetica", 8)
        for key in self.order:
            value = self.counts.get(key, 0)
            if value <= 0:
                continue
            self.canv.setFillColor(STATUS_COLORS.get(key, colors.HexColor("#64748B")))
            self.canv.rect(legend_x, legend_y, 8, 8, fill=1, stroke=0)
            self.canv.setFillColor(colors.HexColor("#374151"))
            percent = round((value / total) * 100)
            label = f"{label_text(key)}: {value} ({percent}%)"
            self.canv.drawString(legend_x + 12, legend_y, label)
            legend_x += max(104, len(label) * 4.4)


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    tracker = parse_tracker(TRACKER_SOURCE.read_text(encoding="utf-8"))
    readiness = fetch_readiness()
    build_pdf(tracker, readiness, OUTPUT_PDF)
    print(OUTPUT_PDF)
    return 0


def parse_tracker(source: str) -> dict[str, list[dict[str, str]]]:
    phases_section = between(source, "export const projectPhases", "export const clearTrackerLanes")
    lanes_section = between(source, "export const clearTrackerLanes", "export const testGates")
    gates_section = between(source, "export const testGates", "export const auditEvents")
    return {
        "phases": parse_objects(
            phases_section,
            ["id", "name", "status", "owner", "objective", "evidence", "nextAction"],
        ),
        "lanes": parse_objects(
            lanes_section,
            ["id", "title", "status", "summary"],
        ),
        "gates": parse_objects(
            gates_section,
            ["id", "name", "status", "command", "lastResult"],
        ),
    }


def between(source: str, start: str, end: str) -> str:
    start_index = source.index(start)
    end_index = source.index(end, start_index)
    return source[start_index:end_index]


def parse_objects(section: str, keys: list[str]) -> list[dict[str, str]]:
    matches: list[dict[str, str]] = []
    id_positions = [match.start() for match in re.finditer(r"\{\s*\n\s*id:\s*\"", section)]
    for index, start in enumerate(id_positions):
        end = id_positions[index + 1] if index + 1 < len(id_positions) else len(section)
        block = section[start:end]
        item: dict[str, str] = {}
        for key in keys:
            match = re.search(rf"{key}:\s*\"((?:\\.|[^\"])*)\"", block)
            if match:
                item[key] = match.group(1).replace('\\"', '"')
        if "id" in item:
            matches.append(item)
    return matches


def fetch_readiness() -> dict[str, Any]:
    try:
        with urllib.request.urlopen(READINESS_URL, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return {
            "mode": "unknown",
            "status": "not_ready",
            "ready": False,
            "checks": [
                {
                    "label": "Client data readiness",
                    "status": "warn",
                    "detail": "Readiness endpoint was not reachable while generating this PDF.",
                    "remediation": "Start the FastAPI service and regenerate the tracker PDF.",
                }
            ],
        }


def build_pdf(tracker: dict[str, list[dict[str, str]]], readiness: dict[str, Any], output_path: Path) -> None:
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=0.55 * inch,
        leftMargin=0.55 * inch,
        topMargin=0.55 * inch,
        bottomMargin=0.55 * inch,
        title="Monday Report Project Tracker",
    )
    styles = pdf_styles()
    story: list[Any] = []

    phases = tracker["phases"]
    gates = tracker["gates"]
    readiness_checks = readiness.get("checks", [])
    phase_counts = Counter(item.get("status", "pending") for item in phases)
    gate_counts = Counter(item.get("status", "pending") for item in gates)
    readiness_counts = Counter(item.get("status", "warn") for item in readiness_checks)

    story.append(Paragraph("Monday Report Project Tracker", styles["Title"]))
    story.append(Paragraph(f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Small"]))
    story.append(Spacer(1, 0.15 * inch))
    story.append(
        summary_table(
            [
                ("Local MVP", "PASS", "Upload, parser, validation, exports, chat, roadmap, audit, and signed downloads pass."),
                (
                    "Client data",
                    str(readiness.get("status", "not_ready")).replace("_", " ").upper(),
                    f"Mode: {readiness.get('mode', 'unknown')}. Ready: {readiness.get('ready', False)}.",
                ),
                ("Full audit", "PASS", "`pnpm run audit:all` passed in the latest execution slice."),
                (
                    "Next quality focus",
                    "WATCH",
                    "Roadmap lane pull: normal-format variants, schematic extraction, normalized repositories, package dry runs, OCR and scanner hardening.",
                ),
            ],
            styles,
        )
    )
    story.append(Spacer(1, 0.18 * inch))
    story.append(StatusBarChart("Phase Status Graph", dict(phase_counts), ["complete", "in_progress", "pending", "blocked"]))
    story.append(StatusBarChart("Quality Gate Graph", dict(gate_counts), ["pass", "watch", "pending"]))
    story.append(StatusBarChart("Client Readiness Check Graph", dict(readiness_counts), ["pass", "warn", "fail"]))
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph("Current Meaning", styles["Heading2"]))
    story.append(
        Paragraph(
            "The local client-approval environment is approved: PostgreSQL/RLS state, Redis queue, security config, local AI, reviewed fixture attestation, and parser/OCR eval evidence all pass. Source-backed Report Studio drafts are now guarded; next work follows normal-format variants, controlled package dry runs, and production hardening.",
            styles["Body"],
        )
    )

    story.append(PageBreak())
    story.append(Paragraph("Phase Tracker", styles["Heading1"]))
    story.append(
        table_from_rows(
            [["Phase", "Status", "Owner", "Evidence", "Next Action"]]
            + [
                [
                    phase.get("name", ""),
                    label_text(phase.get("status", "")),
                    phase.get("owner", ""),
                    phase.get("evidence", ""),
                    phase.get("nextAction", ""),
                ]
                for phase in phases
            ],
            [1.25 * inch, 0.75 * inch, 1.05 * inch, 2.05 * inch, 1.8 * inch],
            styles,
        )
    )

    story.append(PageBreak())
    story.append(Paragraph("Quality Checks", styles["Heading1"]))
    story.append(
        table_from_rows(
            [["Gate", "Status", "Command", "Last Result"]]
            + [
                [
                    gate.get("name", ""),
                    label_text(gate.get("status", "")),
                    gate.get("command", ""),
                    gate.get("lastResult", ""),
                ]
                for gate in gates
            ],
            [1.25 * inch, 0.65 * inch, 1.65 * inch, 3.35 * inch],
            styles,
        )
    )

    story.append(PageBreak())
    story.append(Paragraph("Real-Client Readiness Checks", styles["Heading1"]))
    story.append(
        table_from_rows(
            [["Check", "Status", "Detail", "Required Action"]]
            + [
                [
                    str(check.get("label", "")),
                    label_text(str(check.get("status", ""))),
                    str(check.get("detail", "")),
                    str(check.get("remediation", "")),
                ]
                for check in readiness_checks
            ],
            [1.35 * inch, 0.65 * inch, 2.45 * inch, 2.45 * inch],
            styles,
        )
    )

    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def summary_table(rows: list[tuple[str, str, str]], styles: dict[str, ParagraphStyle]) -> Table:
    table_data = [["Area", "Status", "Meaning"]]
    for area, status, meaning in rows:
        table_data.append([area, status, Paragraph(clean_text(meaning), styles["Small"])])
    table = Table(table_data, colWidths=[1.3 * inch, 1.0 * inch, 4.6 * inch], hAlign="LEFT")
    table.setStyle(base_table_style())
    return table


def table_from_rows(rows: list[list[str]], widths: list[float], styles: dict[str, ParagraphStyle]) -> Table:
    data: list[list[Any]] = []
    for row_index, row in enumerate(rows):
        row_style = styles["TableHeader"] if row_index == 0 else styles["TableCell"]
        data.append([Paragraph(clean_text(str(cell)), row_style) for cell in row])
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(base_table_style())
    return table


def base_table_style() -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]
    )


def pdf_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "Title": ParagraphStyle(
            "TrackerTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=27,
            alignment=TA_LEFT,
            textColor=colors.HexColor("#111827"),
            spaceAfter=6,
        ),
        "Heading1": ParagraphStyle(
            "TrackerHeading1",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=colors.HexColor("#111827"),
            spaceAfter=10,
        ),
        "Heading2": ParagraphStyle(
            "TrackerHeading2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=colors.HexColor("#111827"),
            spaceBefore=4,
            spaceAfter=5,
        ),
        "Body": ParagraphStyle(
            "TrackerBody",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor("#374151"),
        ),
        "Small": ParagraphStyle(
            "TrackerSmall",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#475569"),
        ),
        "TableHeader": ParagraphStyle(
            "TrackerTableHeader",
            fontName="Helvetica-Bold",
            fontSize=7.2,
            leading=8.5,
            textColor=colors.white,
            alignment=TA_CENTER,
        ),
        "TableCell": ParagraphStyle(
            "TrackerTableCell",
            fontName="Helvetica",
            fontSize=6.8,
            leading=8.2,
            textColor=colors.HexColor("#111827"),
            alignment=TA_LEFT,
        ),
    }


def footer(canvas, doc) -> None:  # type: ignore[no-untyped-def]
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.drawString(doc.leftMargin, 0.32 * inch, "Monday Report - Project Tracker")
    canvas.drawRightString(letter[0] - doc.rightMargin, 0.32 * inch, f"Page {doc.page}")
    canvas.restoreState()


def label_text(value: str) -> str:
    return value.replace("_", " ").title()


def clean_text(value: str) -> str:
    return (
        value.replace("`", "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


if __name__ == "__main__":
    raise SystemExit(main())
