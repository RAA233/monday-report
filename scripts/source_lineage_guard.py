from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phase_audit import build_docx_fixture, build_xlsx_fixture  # noqa: E402


EXPECTED_LOCATORS = {
    "csv_text_v1": {
        "locator_type": "csv",
        "fields": {"extraction": "csv_rows", "row_start": 1, "row_end": 2},
    },
    "xlsx_text_v1": {
        "locator_type": "excel",
        "fields": {"extraction": "worksheet_rows", "sheet": "workbook"},
    },
    "docx_text_v1": {
        "locator_type": "word",
        "fields": {"extraction": "word_document_xml", "section": "body"},
    },
    "email_text_v1": {
        "locator_type": "email",
        "fields": {"extraction": "email_body", "part": "body", "subject": "Monday Report lineage update"},
    },
}


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-source-lineage-") as tmp:
        configure_guard_env(Path(tmp))

        from backend.app.main import app
        from backend.app.store import store

        client = TestClient(app)
        workspace = next(iter(store.workspaces.values()))
        uploads = [
            upload_file(
                client,
                workspace.id,
                "lineage/npt_events.csv",
                b"date,company,event,npt_hours\n2026-07-06,ABC Directional Services,MWD signal loss,8.5\n",
                "text/csv",
            ),
            upload_file(
                client,
                workspace.id,
                "lineage/service_quality.xlsx",
                build_xlsx_fixture(
                    [
                        ["date", "company", "event", "npt_hours"],
                        ["2026-07-06", "ABC Directional Services", "MWD signal loss", "8.5"],
                    ]
                ),
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ),
            upload_file(
                client,
                workspace.id,
                "lineage/daily_summary.docx",
                build_docx_fixture(
                    "Daily summary confirms ABC Directional Services MWD signal loss and POOH."
                ),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ),
            upload_file(
                client,
                workspace.id,
                "lineage/ops_update.eml",
                (
                    "From: ops@example.test\r\n"
                    "To: drilling@example.test\r\n"
                    "Subject: Monday Report lineage update\r\n"
                    "Content-Type: text/plain; charset=utf-8\r\n"
                    "\r\n"
                    "Email note: ABC Directional Services reported MWD signal loss with 8.5 NPT hours.\r\n"
                ).encode("utf-8"),
                "message/rfc822",
            ),
        ]
        checks.append(
            assert_check(
                "Lineage candidate uploads accepted",
                all(response.status_code == 201 for response in uploads),
                [response_detail(response) for response in uploads],
            )
        )

        processed = store.process_queued_jobs()
        checks.append(assert_check("Lineage jobs processed", processed == 4, f"processed={processed}"))

        store.refresh()
        documents = [
            document
            for document in store.parsed_documents.values()
            if document.workspace_id == workspace.id
        ]
        documents_by_parser = {document.parser_name: document for document in documents}
        checks.append(
            assert_check(
                "Typed parsers created documents",
                set(EXPECTED_LOCATORS).issubset(documents_by_parser),
                sorted(documents_by_parser),
            )
        )

        locator_failures: list[dict[str, object]] = []
        for parser_name, expected in EXPECTED_LOCATORS.items():
            document = documents_by_parser.get(parser_name)
            if document is None:
                locator_failures.append({"parser_name": parser_name, "reason": "missing_document"})
                continue
            chunks = [
                chunk
                for chunk in store.document_chunks.values()
                if chunk.document_id == document.id and chunk.text.strip()
            ]
            if not chunks:
                locator_failures.append({"parser_name": parser_name, "reason": "missing_chunks"})
                continue
            first_chunk = chunks[0]
            locator = first_chunk.locator
            mismatches = {
                key: {"expected": value, "actual": locator.get(key)}
                for key, value in expected["fields"].items()
                if locator.get(key) != value
            }
            required_base = {"chunk", "file_path", "upload_id", "document_id", "parser_name"}
            missing_base = sorted(required_base - set(locator))
            if (
                first_chunk.locator_type != expected["locator_type"]
                or locator.get("parser_name") != parser_name
                or mismatches
                or missing_base
            ):
                locator_failures.append(
                    {
                        "parser_name": parser_name,
                        "locator_type": first_chunk.locator_type,
                        "locator": locator,
                        "mismatches": mismatches,
                        "missing_base": missing_base,
                    }
                )

        checks.append(
            assert_check(
                "Chunks carry typed source locators",
                not locator_failures,
                locator_failures or "csv/excel/word/email locators verified",
            )
        )

        parse_events = [
            event
            for event in store.audit_logs
            if event.action == "document.parse_complete"
            and event.metadata.get("parser_name") in EXPECTED_LOCATORS
        ]
        checks.append(
            assert_check(
                "Typed parser completions are audited",
                {event.metadata.get("parser_name") for event in parse_events} == set(EXPECTED_LOCATORS),
                [event.metadata for event in parse_events],
            )
        )

        integrity = store.audit_integrity_status()
        checks.append(
            assert_check(
                "Source lineage audit chain sealed",
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
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Source Lineage Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "source-lineage-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Source Lineage Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client source lineage guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")


def upload_file(
    client: TestClient,
    workspace_id: object,
    file_name: str,
    content: bytes,
    mime_type: str,
) -> object:
    return client.post(
        "/uploads/direct",
        data={"workspace_id": str(workspace_id), "file_name": file_name, "source_type": "files"},
        files={"file": (Path(file_name).name, content, mime_type)},
    )


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


def response_detail(response: object) -> object:
    try:
        return response.json()
    except ValueError:
        return getattr(response, "text", "")


if __name__ == "__main__":
    sys.exit(main())
