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
    with tempfile.TemporaryDirectory(prefix="monday-report-pdf-parser-") as tmp:
        configure_guard_env(Path(tmp))

        from backend.app.main import app
        from backend.app.store import store

        client = TestClient(app)
        workspace = next(iter(store.workspaces.values()))
        pdf_content = build_pdf_fixture(
            [
                "DDR package cover page for Monday Report parser guard.",
                "PDF DDR summary. Review the NPT table for failure evidence.",
            ],
        )
        upload_response = client.post(
            "/uploads/direct",
            data={
                "workspace_id": str(workspace.id),
                "file_name": "client-pdf/ddr_2026_07_06.pdf",
                "source_type": "files",
            },
            files={"file": ("ddr_2026_07_06.pdf", pdf_content, "application/pdf")},
        )
        upload_payload = upload_response.json() if upload_response.status_code == 201 else {}
        checks.append(
            assert_check(
                "PDF upload accepted",
                upload_response.status_code == 201
                and upload_payload.get("file", {}).get("sha256")
                and upload_payload.get("file", {}).get("byte_size") == len(pdf_content),
                response_detail(upload_response),
            )
        )

        processed = store.process_queued_jobs()
        checks.append(assert_check("PDF worker job processed", processed == 1, f"processed={processed}"))

        upload_id = upload_payload.get("upload", {}).get("id")
        documents = [
            item
            for item in client.get(f"/documents?workspace_id={workspace.id}").json()
            if item.get("upload_id") == upload_id
        ]
        pdf_documents = [item for item in documents if item.get("parser_name") == "pdf_text_v1"]
        pdf_document = pdf_documents[0] if pdf_documents else {}
        parser_metadata = pdf_document.get("metadata", {}).get("parser", {})
        checks.append(
            assert_check(
                "PyMuPDF text parser created a document",
                len(pdf_documents) == 1
                and "MWD signal loss" in pdf_document.get("text_preview", "")
                and parser_metadata.get("extraction") == "embedded_text"
                and parser_metadata.get("engine") == "pymupdf"
                and parser_metadata.get("page_count") == 2
                and parser_metadata.get("pages_with_text") == 2
                and parser_metadata.get("table_count") == 1
                and parser_metadata.get("tables", [{}])[0].get("row_count") == 2
                and len(parser_metadata.get("page_text_lengths", [])) == 2
                and "pages" not in parser_metadata,
                pdf_document,
            )
        )

        chunks = client.get(f"/documents/{pdf_document.get('id')}/chunks").json() if pdf_document.get("id") else []
        pdf_chunks = [chunk for chunk in chunks if chunk.get("locator_type") == "pdf"]
        located_pages = {chunk.get("locator", {}).get("page") for chunk in pdf_chunks}
        checks.append(
            assert_check(
                "PDF chunks include page-specific source locator metadata",
                len(pdf_chunks) >= 2
                and {1, 2}.issubset(located_pages)
                and all(chunk.get("locator", {}).get("extraction") == "embedded_text" for chunk in pdf_chunks),
                pdf_chunks,
            )
        )

        table_chunks = [
            chunk
            for chunk in pdf_chunks
            if chunk.get("locator", {}).get("table") == 1 and chunk.get("locator", {}).get("row_start") == 2
        ]
        checks.append(
            assert_check(
                "PDF table rows become cited source chunks",
                len(table_chunks) == 1
                and table_chunks[0].get("locator", {}).get("page") == 2
                and "NPT Hours: 6.25" in table_chunks[0].get("text", "")
                and "ABC Directional Services" in table_chunks[0].get("text", ""),
                table_chunks,
            )
        )

        failures = [
            item
            for item in client.get(f"/failures?workspace_id={workspace.id}").json()
            if any(citation.get("locator", {}).get("upload_id") == upload_id for citation in item.get("citations", []))
        ]
        checks.append(
            assert_check(
                "PDF evidence can drive cited failure extraction",
                any(
                    failure.get("event_type") == "MWD signal loss"
                    and failure.get("company") == "ABC Directional Services"
                    and abs(float(failure.get("npt_hours", 0)) - 6.25) < 0.01
                    and any(citation.get("locator", {}).get("table") == 1 for citation in failure.get("citations", []))
                    for failure in failures
                ),
                failures,
            )
        )

        store.refresh()
        parse_events = [
            event
            for event in store.audit_logs
            if event.action == "document.parse_complete" and event.metadata.get("parser_name") == "pdf_text_v1"
        ]
        checks.append(
            assert_check(
                "PDF parsing is audited",
                len(parse_events) == 1,
                [event.metadata for event in parse_events],
            )
        )

        integrity = store.audit_integrity_status()
        checks.append(
            assert_check(
                "PDF parser audit chain sealed",
                integrity.status == "sealed" and integrity.broken_events == 0,
                integrity.model_dump(mode="json"),
            )
        )

    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")
    return 1 if failed else 0


def configure_guard_env(tmp_root: Path) -> None:
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
    os.environ["MONDAY_REPORT_DISABLE_DEMO_SEED"] = "true"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "PDF Parser Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "pdf-parser-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "PDF Parser Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client PDF parser guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")


def build_pdf_fixture(pages: list[str]) -> bytes:
    import fitz  # type: ignore[import-not-found]

    document = fitz.open()
    for page_index, text in enumerate(pages, start=1):
        page = document.new_page()
        page.insert_text((72, 72), text, fontsize=11)
        if page_index == 2:
            draw_npt_table(page)
    return document.tobytes()


def draw_npt_table(page) -> None:
    left = 72
    top = 130
    columns = [left, left + 92, left + 230, left + 350, left + 430]
    rows = [top, top + 28, top + 56]
    for x in columns:
        page.draw_line((x, rows[0]), (x, rows[-1]), color=(0, 0, 0), width=0.5)
    for y in rows:
        page.draw_line((columns[0], y), (columns[-1], y), color=(0, 0, 0), width=0.5)

    values = [
        ["Date", "Company", "Event", "NPT Hours"],
        ["2026-07-06", "ABC Directional Services", "MWD signal loss", "6.25"],
    ]
    for row_index, row in enumerate(values):
        for column_index, value in enumerate(row):
            page.insert_text((columns[column_index] + 4, rows[row_index] + 18), value, fontsize=8)


def response_detail(response) -> object:
    try:
        return response.json()
    except ValueError:
        return response.text


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
