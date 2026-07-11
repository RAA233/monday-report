from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


OCR_ENGINE_ENV = "MONDAY_REPORT_OCR_ENGINE"
TESSERACT_CMD_ENV = "MONDAY_REPORT_TESSERACT_CMD"
OCR_TIMEOUT_ENV = "MONDAY_REPORT_OCR_TIMEOUT_SECONDS"
OCR_EXTRA_ARGS_ENV = "MONDAY_REPORT_OCR_EXTRA_ARGS"
OCR_READY_ENGINES = {"tesseract"}


@dataclass(frozen=True)
class OCRStatus:
    engine: str
    configured: bool
    reachable: bool
    detail: str


@dataclass(frozen=True)
class OCRExtractionResult:
    ok: bool
    text: str
    pages: list[dict[str, object]]
    engine: str
    detail: str


def evaluate_ocr_status() -> OCRStatus:
    engine = configured_ocr_engine()
    if engine == "unconfigured":
        return OCRStatus(
            engine=engine,
            configured=False,
            reachable=False,
            detail="No local OCR engine configured.",
        )

    if engine not in OCR_READY_ENGINES:
        return OCRStatus(
            engine=engine,
            configured=True,
            reachable=False,
            detail=f"Unsupported OCR engine {engine!r}; supported engines: tesseract.",
        )

    command = ocr_command_parts()
    if not command:
        return OCRStatus(
            engine=engine,
            configured=True,
            reachable=False,
            detail="OCR command is empty.",
        )

    try:
        result = subprocess.run(
            command + ["--version"],
            capture_output=True,
            check=False,
            text=True,
            timeout=ocr_timeout_seconds(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return OCRStatus(
            engine=engine,
            configured=True,
            reachable=False,
            detail=f"{engine} OCR command is not reachable: {exc.__class__.__name__}.",
        )

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or f"{engine} returned {result.returncode}.").strip()
        return OCRStatus(engine=engine, configured=True, reachable=False, detail=detail[:240])

    return OCRStatus(engine=engine, configured=True, reachable=True, detail=f"{engine} OCR command is reachable.")


def extract_ocr_text(original_path: str, mime_type: str, content: bytes) -> OCRExtractionResult:
    status = evaluate_ocr_status()
    if not status.configured or not status.reachable:
        return OCRExtractionResult(False, "", [], status.engine, status.detail)

    suffix = Path(original_path).suffix.lower()
    with tempfile.TemporaryDirectory(prefix="monday-report-ocr-") as tmp:
        tmp_root = Path(tmp)
        page_images = (
            render_pdf_pages(content, tmp_root)
            if suffix == ".pdf" or mime_type.lower() == "application/pdf"
            else [write_image(content, original_path, tmp_root)]
        )
        pages: list[dict[str, object]] = []
        for page_number, image_path in enumerate(page_images, start=1):
            text = run_ocr_command(image_path)
            if text.strip():
                pages.append({"page": page_number, "text": text.strip()})

    joined_text = "\n".join(str(page["text"]) for page in pages)
    return OCRExtractionResult(
        ok=bool(joined_text.strip()),
        text=joined_text,
        pages=pages,
        engine=status.engine,
        detail="OCR text extracted." if joined_text.strip() else "OCR command returned no text.",
    )


def configured_ocr_engine() -> str:
    value = os.getenv(OCR_ENGINE_ENV, "").strip().lower()
    return value or "unconfigured"


def ocr_command_parts() -> list[str]:
    command = os.getenv(TESSERACT_CMD_ENV, "tesseract").strip()
    return shlex.split(command)


def ocr_extra_args() -> list[str]:
    return shlex.split(os.getenv(OCR_EXTRA_ARGS_ENV, "").strip())


def ocr_timeout_seconds() -> float:
    raw_value = os.getenv(OCR_TIMEOUT_ENV, "15").strip()
    try:
        return max(1.0, min(float(raw_value), 120.0))
    except ValueError:
        return 15.0


def render_pdf_pages(content: bytes, tmp_root: Path) -> list[Path]:
    try:
        import fitz  # type: ignore[import-not-found]
    except ImportError:
        return []

    page_paths: list[Path] = []
    try:
        with fitz.open(stream=content, filetype="pdf") as document:
            for page_index, page in enumerate(document, start=1):
                pixmap = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
                page_path = tmp_root / f"page-{page_index}.png"
                pixmap.save(page_path)
                page_paths.append(page_path)
    except Exception:
        return []
    return page_paths


def write_image(content: bytes, original_path: str, tmp_root: Path) -> Path:
    suffix = Path(original_path).suffix.lower() or ".img"
    image_path = tmp_root / f"image{suffix}"
    image_path.write_bytes(content)
    return image_path


def run_ocr_command(image_path: Path) -> str:
    try:
        result = subprocess.run(
            ocr_command_parts() + [str(image_path), "stdout", *ocr_extra_args()],
            capture_output=True,
            check=False,
            text=True,
            timeout=ocr_timeout_seconds(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()
