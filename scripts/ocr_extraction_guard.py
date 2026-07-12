from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-ocr-extraction-") as tmp:
        tmp_root = Path(tmp)
        fake_ocr = tmp_root / "fake_tesseract.py"
        fake_ocr.write_text(
            "\n".join(
                [
                    "from __future__ import annotations",
                    "import sys",
                    "if '--version' in sys.argv:",
                    "    print('fake-tesseract 1.0')",
                    "    raise SystemExit(0)",
                    "print('OCR DDR: Anonymized Directional Services MWD signal loss. npt_hours 6.25. POOH to replace MWD tool.')",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        configure_guard_env(tmp_root, fake_ocr)

        from backend.app.main import app
        from backend.app.store import store

        client = TestClient(app)
        workspace = next(iter(store.workspaces.values()))

        scanned_pdf_upload = upload_file(
            client,
            workspace.id,
            "ocr/scanned_ddr.pdf",
            build_scanned_pdf_fixture(),
            "application/pdf",
        )
        checks.append(
            assert_check(
                "Scanned PDF upload accepted",
                scanned_pdf_upload.status_code == 201,
                response_detail(scanned_pdf_upload),
            )
        )

        processed = store.process_queued_jobs()
        checks.append(assert_check("OCR extraction job processed", processed == 1, f"processed={processed}"))

        store.refresh()
        ocr_documents = [
            document
            for document in store.parsed_documents.values()
            if document.workspace_id == workspace.id and document.parser_name == "ocr_text_v1"
        ]
        checks.append(
            assert_check(
                "OCR text document completed",
                len(ocr_documents) == 1
                and ocr_documents[0].status.value == "complete"
                and ocr_documents[0].chunk_count >= 1
                and "MWD signal loss" in ocr_documents[0].text_preview,
                [document.model_dump(mode="json") for document in ocr_documents],
            )
        )

        parser_metadata = ocr_documents[0].metadata.get("parser", {}) if ocr_documents else {}
        checks.append(
            assert_check(
                "OCR parser metadata records engine and source",
                parser_metadata.get("ocr_status") == "extracted"
                and parser_metadata.get("engine") == "tesseract"
                and parser_metadata.get("source_parser_name") == "pdf_text_v1"
                and parser_metadata.get("routing_reason") == "scanned_pdf_or_image_only"
                and parser_metadata.get("page_count") == 1,
                parser_metadata,
            )
        )

        document_id = ocr_documents[0].id if ocr_documents else None
        chunks = [
            chunk
            for chunk in store.document_chunks.values()
            if chunk.document_id == document_id and chunk.workspace_id == workspace.id
        ]
        checks.append(
            assert_check(
                "OCR chunks keep image-page citation locators",
                len(chunks) >= 1
                and chunks[0].locator_type == "image"
                and chunks[0].locator.get("page") == 1
                and chunks[0].locator.get("ocr_engine") == "tesseract"
                and chunks[0].locator.get("ocr_status") == "extracted"
                and "MWD signal loss" in chunks[0].text,
                [chunk.model_dump(mode="json") for chunk in chunks],
            )
        )

        document_file_id = ocr_documents[0].file_id if ocr_documents else None
        failures = [
            failure
            for failure in store.failures.values()
            if failure.workspace_id == workspace.id
            and any(citation.file_id == document_file_id for citation in failure.citations)
        ]
        checks.append(
            assert_check(
                "OCR text feeds failure extraction",
                len(failures) == 1
                and failures[0].company == "Anonymized Directional Services"
                and failures[0].npt_hours == 6.25
                and any(citation.locator_type == "image" for citation in failures[0].citations),
                [failure.model_dump(mode="json") for failure in failures],
            )
        )

        extract_events = [event for event in store.audit_logs if event.action == "ocr.extract_complete"]
        route_events = [event for event in store.audit_logs if event.action == "ocr.route"]
        parse_events = [
            event
            for event in store.audit_logs
            if event.action == "document.parse_complete" and event.metadata.get("parser_name") == "ocr_text_v1"
        ]
        checks.append(
            assert_check(
                "OCR extraction is audited without fallback route",
                len(extract_events) == 1 and len(parse_events) == 1 and not route_events,
                {
                    "extract_events": [event.metadata for event in extract_events],
                    "parse_events": [event.metadata for event in parse_events],
                    "route_events": [event.metadata for event in route_events],
                },
            )
        )

        integrity = store.audit_integrity_status()
        checks.append(
            assert_check(
                "OCR extraction audit chain sealed",
                integrity.status == "sealed" and integrity.broken_events == 0,
                integrity.model_dump(mode="json"),
            )
        )

    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")
    return 1 if failed else 0


def configure_guard_env(tmp_root: Path, fake_ocr: Path) -> None:
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
    os.environ["MONDAY_REPORT_DISABLE_DEMO_SEED"] = "true"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "OCR Extraction Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "ocr-extraction-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "OCR Extraction Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client OCR extraction guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")
    os.environ["MONDAY_REPORT_OCR_ENGINE"] = "tesseract"
    os.environ["MONDAY_REPORT_TESSERACT_CMD"] = f'"{sys.executable}" "{fake_ocr}"'


def upload_file(client: TestClient, workspace_id, file_name: str, content: bytes, mime_type: str):
    return client.post(
        "/uploads/direct",
        data={
            "workspace_id": str(workspace_id),
            "file_name": file_name,
            "source_type": "files",
        },
        files={"file": (Path(file_name).name, content, mime_type)},
    )


def build_scanned_pdf_fixture() -> bytes:
    import fitz  # type: ignore[import-not-found]

    document = fitz.open()
    document.new_page(width=612, height=792)
    content = document.tobytes()
    document.close()
    return content


def response_detail(response) -> object:
    try:
        return response.json()
    except ValueError:
        return response.text


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
