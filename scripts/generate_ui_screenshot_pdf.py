from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "output" / "qa" / "ui_quality_e2e_manifest.json"
OUTPUT_PDF = ROOT / "output" / "pdf" / "monday_report_ui_quality_screenshots.pdf"


def main() -> int:
    if not MANIFEST.exists():
        print(f"Missing UI manifest: {MANIFEST}")
        return 1
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    OUTPUT_PDF.parent.mkdir(parents=True, exist_ok=True)
    build_pdf(manifest, OUTPUT_PDF)
    print(OUTPUT_PDF)
    return 0


def build_pdf(manifest: dict, output_pdf: Path) -> None:
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=30,
        textColor=colors.HexColor("#111827"),
        spaceAfter=12,
    )
    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=19,
        textColor=colors.HexColor("#111827"),
        spaceBefore=8,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )

    doc = SimpleDocTemplate(
        str(output_pdf),
        pagesize=letter,
        rightMargin=0.55 * inch,
        leftMargin=0.55 * inch,
        topMargin=0.45 * inch,
        bottomMargin=0.45 * inch,
        title="Monday Report UI Quality Screenshots",
    )

    story: list = [
        Paragraph("Monday Report UI Quality Screenshots", title_style),
        Paragraph(
            f"Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')} from live browser automation against {manifest.get('web_base', 'unknown')}.",
            body_style,
        ),
        Spacer(1, 0.15 * inch),
    ]

    checks = manifest.get("checks", [])
    status_rows = [["Status", "Check", "Detail"]]
    for check in checks:
        status_rows.append([
            "PASS" if check.get("ok") else "FAIL",
            str(check.get("name", "")),
            Paragraph(escape_text(str(check.get("detail", ""))[:180]), body_style),
        ])
    status_table = Table(status_rows, colWidths=[0.6 * inch, 1.75 * inch, 4.6 * inch], repeatRows=1)
    status_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ]
        )
    )
    story.append(status_table)

    screenshots = []
    seen = set()
    for check in checks:
        screenshot = check.get("screenshot")
        if screenshot and screenshot not in seen and Path(screenshot).exists():
            seen.add(screenshot)
            screenshots.append((check.get("name", "Screenshot"), Path(screenshot)))

    for index, (name, screenshot_path) in enumerate(screenshots, start=1):
        story.append(PageBreak())
        story.append(Paragraph(f"{index}. {escape_text(str(name).replace(' screenshot', ''))}", heading_style))
        story.append(Paragraph(escape_text(str(screenshot_path)), body_style))
        story.append(Spacer(1, 0.1 * inch))
        story.append(scaled_image(screenshot_path, max_width=7.1 * inch, max_height=8.3 * inch))

    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def scaled_image(path: Path, max_width: float, max_height: float) -> Image:
    reader = ImageReader(str(path))
    width, height = reader.getSize()
    scale = min(max_width / width, max_height / height)
    return Image(str(path), width=width * scale, height=height * scale)


def escape_text(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(doc.leftMargin, 0.25 * inch, "Monday Report - UI Quality Evidence")
    canvas.drawRightString(letter[0] - doc.rightMargin, 0.25 * inch, f"Page {doc.page}")
    canvas.restoreState()


if __name__ == "__main__":
    sys.exit(main())
