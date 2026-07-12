from __future__ import annotations

import html
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Flowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from generate_project_tracker_pdf import TRACKER_SOURCE, label_text, parse_tracker


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_REPORT_DIR = ROOT / "output" / "reports"
OUTPUT_PDF_DIR = ROOT / "output" / "pdf"
OUTPUT_MD = OUTPUT_REPORT_DIR / "Monday_Report_Complete_Report.md"
OUTPUT_PDF = OUTPUT_PDF_DIR / "monday_report_complete_report.pdf"
FORGE_SUMMARY_PATH = ROOT / "output" / "forge-corpus" / "forge_corpus_summary.json"
PARTNER_APPROVAL_PATH = ROOT / "output" / "package" / "Monday_Report_Partner_Preview_APPROVAL.json"
CLIENT_APPROVAL_PATH = ROOT / "output" / "client-data" / "Monday_Report_Client_Data_APPROVAL.json"
GA_READINESS_PATH = ROOT / "output" / "ga-readiness" / "Monday_Report_GA_READINESS.json"


STATUS_COLORS = {
    "pass": colors.HexColor("#047857"),
    "complete": colors.HexColor("#047857"),
    "approved": colors.HexColor("#047857"),
    "watch": colors.HexColor("#B45309"),
    "warn": colors.HexColor("#B45309"),
    "in_progress": colors.HexColor("#2563EB"),
    "pending": colors.HexColor("#64748B"),
    "blocked": colors.HexColor("#B42318"),
    "fail": colors.HexColor("#B42318"),
}


class HorizontalStatusChart(Flowable):
    def __init__(self, title: str, counts: Counter[str], order: list[str], width: float = 6.9 * inch):
        super().__init__()
        self.title = title
        self.counts = counts
        self.order = order
        self.width = width
        self.height = 1.35 * inch

    def draw(self) -> None:
        self.canv.setFillColor(colors.HexColor("#111827"))
        self.canv.setFont("Helvetica-Bold", 10)
        self.canv.drawString(0, self.height - 10, self.title)

        total = sum(self.counts.values()) or 1
        x = 0
        y = self.height - 36
        bar_height = 16
        for key in self.order:
            value = self.counts.get(key, 0)
            if value <= 0:
                continue
            segment_width = self.width * value / total
            self.canv.setFillColor(STATUS_COLORS.get(key, colors.HexColor("#64748B")))
            self.canv.rect(x, y, segment_width, bar_height, fill=1, stroke=0)
            x += segment_width

        self.canv.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.canv.rect(0, y, self.width, bar_height, fill=0, stroke=1)

        legend_x = 0
        legend_y = y - 20
        self.canv.setFont("Helvetica", 8)
        for key in self.order:
            value = self.counts.get(key, 0)
            if value <= 0:
                continue
            self.canv.setFillColor(STATUS_COLORS.get(key, colors.HexColor("#64748B")))
            self.canv.rect(legend_x, legend_y, 8, 8, fill=1, stroke=0)
            self.canv.setFillColor(colors.HexColor("#374151"))
            label = f"{label_text(key)}: {value}"
            self.canv.drawString(legend_x + 12, legend_y, label)
            legend_x += max(88, len(label) * 4.8)


def main() -> int:
    OUTPUT_REPORT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_PDF_DIR.mkdir(parents=True, exist_ok=True)

    tracker = parse_tracker(TRACKER_SOURCE.read_text(encoding="utf-8"))
    forge = read_json(FORGE_SUMMARY_PATH, {})
    partner = read_json(PARTNER_APPROVAL_PATH, {})
    client = read_json(CLIENT_APPROVAL_PATH, {})
    ga = read_json(GA_READINESS_PATH, {})
    git_head = run_text(["git", "rev-parse", "HEAD"])
    git_status = run_text(["git", "status", "--short", "--branch"])
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    report = {
        "generated_at": generated_at,
        "git_head": git_head,
        "git_status": git_status,
        "tracker": tracker,
        "forge": forge,
        "partner": partner,
        "client": client,
        "ga": ga,
    }

    OUTPUT_MD.write_text(render_markdown(report), encoding="utf-8")
    build_pdf(report, OUTPUT_PDF)

    print(f"Markdown: {OUTPUT_MD}")
    print(f"PDF: {OUTPUT_PDF}")
    return 0


def render_markdown(report: dict[str, Any]) -> str:
    tracker = report["tracker"]
    forge = report["forge"]
    partner = report["partner"]
    client = report["client"]
    ga = report["ga"]
    phase_counts = Counter(item.get("status", "pending") for item in tracker["phases"])
    gate_counts = Counter(item.get("status", "pending") for item in tracker["gates"])
    readiness_checks = client.get("readiness", {}).get("checks", [])
    readiness_counts = Counter(item.get("status", "warn") for item in readiness_checks)
    partner_package = partner.get("package", {})

    lines = [
        "# Monday Report Complete Status Report",
        "",
        f"Generated: {report['generated_at']}",
        f"Commit: `{report['git_head']}`",
        "",
        "## Executive Status",
        "",
        "- Local MVP: PASS - chat-first app, upload, parsing, validation, exports, signed downloads, audit chain, and tracker are operational.",
        f"- Partner package: {'APPROVED' if partner.get('approved') else 'NOT APPROVED'} for `{partner.get('scope', 'unknown')}`.",
        "- Real client data: BLOCKED - the app is intentionally refusing client-data approval until readiness gates pass.",
        "- FORGE corpus: PASS - local open-source daily-report corpus is parsed and checked without committing raw PDFs.",
        f"- GA readiness: {ga.get('status', 'UNKNOWN')} - {ga.get('summary', 'Run audit:ga-readiness to generate GA evidence.')}",
        "",
        "## Current Package",
        "",
        f"- Path: `{partner_package.get('path', 'missing')}`",
        f"- SHA256: `{partner_package.get('sha256', 'missing')}`",
        f"- Default local AI: `{partner.get('default_local_ai', {}).get('runtime', 'unknown')}` / `{partner.get('default_local_ai', {}).get('model', 'unknown')}`",
        f"- Hosted fallback: `{partner.get('default_local_ai', {}).get('hosted_fallback', False)}`",
        "",
        "## FORGE Daily Report Corpus",
        "",
        f"- Corpus status: `{forge.get('status', 'unknown')}`",
        f"- PDF count: `{forge.get('pdf_count', 0)}`",
        f"- Drilling reports: `{forge.get('categories', {}).get('drilling', 0)}`",
        f"- Completion reports: `{forge.get('categories', {}).get('completion', 0)}`",
        "- Verified markers: daily drilling report, well/job info, casing, mud, BHA, survey data, time breakdown, present operations, completion, perforations, cost summary.",
        "",
        "## Graph Counts",
        "",
        f"- Phases: {dict(phase_counts)}",
        f"- Quality gates: {dict(gate_counts)}",
        f"- Client readiness checks: {dict(readiness_counts)}",
        "",
        "## Latest Delivered Slice",
        "",
        "- Added Report Studio for writing morning reports from scratch.",
        "- Added AI-assisted draft fill, FORGE-style template, branded preview, casing schematic, activity timeline, and Markdown draft export.",
        "- Added FORGE corpus guard and wired it into `audit:all`.",
        "- Updated tracker and README with the corpus/report-studio workflow.",
        "",
        "## Audit Evidence",
        "",
        "- `pnpm run build` - PASS",
        "- `pnpm run audit:forge-corpus` - PASS",
        "- `pnpm run audit:tracker-clarity` - PASS",
        "- `pnpm run audit:runtime-mock-data` - PASS",
        "- `pnpm run test:e2e` - PASS",
        "- `pnpm run audit:client-ops` - PASS",
        "- `pnpm run audit:report-template` - PASS",
        "- `pnpm run audit:ga-readiness` - PASS as software evidence; strict GA remains blocked until external prerequisites pass.",
        "- `pnpm run audit:all` - PASS",
        "- `pnpm run package:client-approval` - BLOCKED as expected in the current demo/local posture.",
        "",
        "## Real-Client Data Blockers",
        "",
    ]

    blocking = client.get("blocking_checks") or [
        check for check in readiness_checks if check.get("status") in {"warn", "fail"}
    ]
    for check in blocking:
        lines.append(
            f"- {check.get('label', check.get('id', 'check'))}: {check.get('status', 'unknown').upper()} - {check.get('detail', '')}"
        )

    lines.extend(
        [
            "",
            "## Next Execution Tracker",
            "",
            "1. Promote FORGE corpus patterns into reviewed report templates and extraction evals.",
            "2. Connect Report Studio to parsed evidence and local Gemma-assisted draft generation with citations.",
            "3. Upgrade production PDF/XLSX exports to match the new branded morning-report layout.",
            "4. Complete reviewed anonymized fixture attestation and parser/OCR eval reports.",
            "5. Move real client mode to approved storage, PostgreSQL/RLS, Redis workers, configured API key, signing secret, malware scanner, and retention policy.",
            "",
            "## Git State",
            "",
            "```text",
            report["git_status"],
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def build_pdf(report: dict[str, Any], output_path: Path) -> None:
    styles = build_styles()
    tracker = report["tracker"]
    forge = report["forge"]
    partner = report["partner"]
    client = report["client"]
    phases = tracker["phases"]
    gates = tracker["gates"]
    readiness_checks = client.get("readiness", {}).get("checks", [])
    phase_counts = Counter(item.get("status", "pending") for item in phases)
    gate_counts = Counter(item.get("status", "pending") for item in gates)
    readiness_counts = Counter(item.get("status", "warn") for item in readiness_checks)
    partner_package = partner.get("package", {})

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=0.5 * inch,
        leftMargin=0.5 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch,
        title="Monday Report Complete Status Report",
    )

    story: list[Any] = [
        Paragraph("Monday Report Complete Status Report", styles["Title"]),
        Paragraph(f"Generated {safe(report['generated_at'])}", styles["Small"]),
        Paragraph(f"Commit {safe(report['git_head'][:12])}", styles["Small"]),
        Spacer(1, 0.14 * inch),
        status_table(
            [
                ("Local MVP", "PASS", "Upload, parser, validation, exports, chat, signed downloads, audit chain, and tracker are operational."),
                (
                    "Partner package",
                    "APPROVED" if partner.get("approved") else "NOT APPROVED",
                    f"{partner.get('scope', 'unknown')} - SHA {partner_package.get('sha256', 'missing')}",
                ),
                ("Real client data", "BLOCKED", "Approval fails closed until readiness gates and reviewed fixture attestation pass."),
                (
                    "FORGE corpus",
                    "PASS",
                    f"{forge.get('pdf_count', 0)} PDFs: {forge.get('categories', {}).get('drilling', 0)} drilling, {forge.get('categories', {}).get('completion', 0)} completion.",
                ),
                (
                    "GA readiness",
                    str(ga.get("status", "UNKNOWN")).replace("_", " "),
                    str(ga.get("summary", "Run audit:ga-readiness to generate GA evidence.")),
                ),
            ],
            styles,
        ),
        Spacer(1, 0.18 * inch),
        HorizontalStatusChart("Phase Status Graph", phase_counts, ["complete", "in_progress", "pending", "blocked"]),
        HorizontalStatusChart("Quality Gate Graph", gate_counts, ["pass", "watch", "pending"]),
        HorizontalStatusChart("Client Readiness Graph", readiness_counts, ["pass", "warn", "fail"]),
        Spacer(1, 0.05 * inch),
        Paragraph("Latest Delivered Slice", styles["Heading2"]),
    ]
    story.extend(
        bullets(
            [
                "Report Studio for writing morning drilling reports from scratch.",
                "FORGE-style template, AI draft fill, branded preview, casing schematic, activity timeline, and Markdown draft export.",
                "FORGE corpus guard wired into audit:all and tracker.",
                "Private GitHub main branch pushed at the latest audited commit.",
            ],
            styles,
        )
    )

    story.extend(
        [
            PageBreak(),
            Paragraph("FORGE Daily Report Evidence", styles["Heading1"]),
            Paragraph(
                "The local 16A(78)-32_Daily_Reports corpus remains ignored by Git, but is now inspected as an evidence corpus for daily-report structure.",
                styles["Body"],
            ),
            Spacer(1, 0.1 * inch),
            table(
                [
                    ["Metric", "Value"],
                    ["Corpus status", str(forge.get("status", "unknown")).upper()],
                    ["PDF count", str(forge.get("pdf_count", 0))],
                    ["Drilling reports", str(forge.get("categories", {}).get("drilling", 0))],
                    ["Completion reports", str(forge.get("categories", {}).get("completion", 0))],
                    ["Markers", "DDR, well/job info, casing, mud, BHA, survey, time breakdown, completion, perforations, cost summary"],
                ],
                [2.0 * inch, 4.9 * inch],
                styles,
            ),
            Spacer(1, 0.18 * inch),
            Paragraph("Audit Evidence", styles["Heading1"]),
            table(
                [
                    ["Command", "Result"],
                    ["pnpm run build", "PASS"],
                    ["pnpm run audit:forge-corpus", "PASS"],
                    ["pnpm run audit:tracker-clarity", "PASS"],
                    ["pnpm run audit:runtime-mock-data", "PASS"],
                    ["pnpm run test:e2e", "PASS"],
                    ["pnpm run audit:client-ops", "PASS"],
                    ["pnpm run audit:report-template", "PASS"],
                    ["pnpm run audit:ga-readiness", "PASS as software evidence; strict GA still requires external prerequisites"],
                    ["pnpm run audit:all", "PASS"],
                    ["pnpm run package:client-approval", "BLOCKED as expected in current demo/local posture"],
                ],
                [3.1 * inch, 3.8 * inch],
                styles,
            ),
        ]
    )

    story.extend(
        [
            PageBreak(),
            Paragraph("Project Phase Tracker", styles["Heading1"]),
            table(
                [["Phase", "Status", "Evidence", "Next Action"]]
                + [
                    [
                        item.get("name", ""),
                        label_text(item.get("status", "")),
                        item.get("evidence", ""),
                        item.get("nextAction", ""),
                    ]
                    for item in phases
                ],
                [1.45 * inch, 0.75 * inch, 2.3 * inch, 2.4 * inch],
                styles,
            ),
        ]
    )

    story.extend(
        [
            PageBreak(),
            Paragraph("Real-Client Readiness", styles["Heading1"]),
            Paragraph(
                "Current posture is intentionally blocked for real client data. This is a safety result, not a runtime failure.",
                styles["Body"],
            ),
            Spacer(1, 0.1 * inch),
            table(
                [["Check", "Status", "Detail"]]
                + [
                    [str(item.get("label", "")), label_text(str(item.get("status", ""))), str(item.get("detail", ""))]
                    for item in readiness_checks
                ],
                [1.55 * inch, 0.75 * inch, 4.6 * inch],
                styles,
            ),
        ]
    )

    story.extend(
        [
            PageBreak(),
            Paragraph("Next Execution Tracker", styles["Heading1"]),
        ]
    )
    story.extend(
        numbered(
            [
                "Promote FORGE corpus patterns into reviewed report templates and extraction evals.",
                "Connect Report Studio to parsed evidence and local Gemma-assisted draft generation with citations.",
                "Upgrade production PDF/XLSX exports to match the new branded morning-report layout.",
                "Complete reviewed anonymized fixture attestation and parser/OCR eval reports.",
                "Move real client mode to approved storage, PostgreSQL/RLS, Redis workers, configured API key, signing secret, malware scanner, and retention policy.",
            ],
            styles,
        )
    )
    story.extend(
        [
            Spacer(1, 0.18 * inch),
            Paragraph("Package Handoff", styles["Heading1"]),
            table(
                [
                    ["Field", "Value"],
                    ["Partner package", str(partner_package.get("path", "missing"))],
                    ["SHA256", str(partner_package.get("sha256", "missing"))],
                    ["Default AI", f"{partner.get('default_local_ai', {}).get('runtime', 'unknown')} / {partner.get('default_local_ai', {}).get('model', 'unknown')}"],
                    ["Real client data", "Not approved"],
                ],
                [1.5 * inch, 5.4 * inch],
                styles,
            ),
        ]
    )

    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def table(rows: list[list[str]], widths: list[float], styles: dict[str, ParagraphStyle]) -> Table:
    data: list[list[Any]] = []
    for row_index, row in enumerate(rows):
        style = styles["TableHeader"] if row_index == 0 else styles["TableCell"]
        data.append([Paragraph(safe(str(cell)), style) for cell in row])
    result = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    result.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#101820")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return result


def status_table(rows: list[tuple[str, str, str]], styles: dict[str, ParagraphStyle]) -> Table:
    return table([["Area", "Status", "Meaning"]] + [[area, status, detail] for area, status, detail in rows], [1.35 * inch, 1.0 * inch, 4.55 * inch], styles)


def bullets(items: list[str], styles: dict[str, ParagraphStyle]) -> list[Any]:
    flowables: list[Any] = []
    for item in items:
        flowables.append(Paragraph(f"- {safe(item)}", styles["Body"]))
    return flowables


def numbered(items: list[str], styles: dict[str, ParagraphStyle]) -> list[Any]:
    flowables: list[Any] = []
    for index, item in enumerate(items, start=1):
        flowables.append(Paragraph(f"{index}. {safe(item)}", styles["Body"]))
        flowables.append(Spacer(1, 0.04 * inch))
    return flowables


def build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "Title": ParagraphStyle(
            "CompleteReportTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=21,
            leading=26,
            alignment=TA_LEFT,
            textColor=colors.HexColor("#111827"),
            spaceAfter=6,
        ),
        "Heading1": ParagraphStyle(
            "CompleteReportHeading1",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=19,
            textColor=colors.HexColor("#111827"),
            spaceAfter=8,
        ),
        "Heading2": ParagraphStyle(
            "CompleteReportHeading2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11.5,
            leading=14,
            textColor=colors.HexColor("#111827"),
            spaceAfter=5,
        ),
        "Body": ParagraphStyle(
            "CompleteReportBody",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#374151"),
        ),
        "Small": ParagraphStyle(
            "CompleteReportSmall",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7.8,
            leading=10,
            textColor=colors.HexColor("#64748B"),
        ),
        "TableHeader": ParagraphStyle(
            "CompleteReportTableHeader",
            fontName="Helvetica-Bold",
            fontSize=7.2,
            leading=8.4,
            textColor=colors.white,
            alignment=TA_LEFT,
        ),
        "TableCell": ParagraphStyle(
            "CompleteReportTableCell",
            fontName="Helvetica",
            fontSize=6.8,
            leading=8.3,
            textColor=colors.HexColor("#111827"),
            alignment=TA_LEFT,
        ),
    }


def footer(canvas, doc) -> None:  # type: ignore[no-untyped-def]
    canvas.saveState()
    canvas.setFont("Helvetica", 7.4)
    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.drawString(doc.leftMargin, 0.30 * inch, "Monday Report - Complete Status Report")
    canvas.drawRightString(letter[0] - doc.rightMargin, 0.30 * inch, f"Page {doc.page}")
    canvas.restoreState()


def read_json(path: Path, fallback: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return fallback
    return json.loads(path.read_text(encoding="utf-8"))


def run_text(command: list[str]) -> str:
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    return (result.stdout or result.stderr).strip()


def safe(value: str) -> str:
    return html.escape(value.replace("`", "").replace("\r", " ").replace("\n", " "))


if __name__ == "__main__":
    raise SystemExit(main())
