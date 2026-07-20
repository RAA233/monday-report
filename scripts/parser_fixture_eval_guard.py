from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.fixture_evals import PARSER_EVAL_REPORT_ENV  # noqa: E402
from backend.app.fixtures import REQUIRED_GOLDEN_FIXTURE_FAMILIES  # noqa: E402
from phase_audit import build_docx_fixture, build_pdf_fixture, build_xlsx_fixture  # noqa: E402


@dataclass(frozen=True)
class EvalFixture:
    family: str
    file_name: str
    content: bytes
    mime_type: str
    expected_parser: str | None
    expected_locator: str | None
    expected_failure: bool = False
    duplicate_of: str | None = None
    expected_job_result: str | None = None


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-parser-fixture-eval-") as tmp:
        tmp_root = Path(tmp)
        fake_ocr = write_fake_ocr(tmp_root)
        configure_guard_env(tmp_root, fake_ocr)

        from backend.app.main import app
        from backend.app.store import store

        client = TestClient(app)

        no_report = client.get("/readiness/client-data").json()
        no_report_check = readiness_check(no_report, "parser_fixture_evals")
        checks.append(
            assert_check(
                "Parser fixture evals warn without report",
                no_report_check.get("status") == "warn"
                and PARSER_EVAL_REPORT_ENV in no_report_check.get("detail", ""),
                no_report_check,
            )
        )

        partial_report = tmp_root / "partial-parser-eval-report.json"
        write_static_report(
            partial_report,
            [
                static_case("ddr", "pass"),
                static_case("scanned_pdf", "fail"),
            ],
        )
        os.environ[PARSER_EVAL_REPORT_ENV] = str(partial_report)
        partial = client.get("/readiness/client-data").json()
        partial_check = readiness_check(partial, "parser_fixture_evals")
        checks.append(
            assert_check(
                "Incomplete parser fixture eval report does not certify readiness",
                partial_check.get("status") == "warn"
                and "missing evals" in partial_check.get("detail", "")
                and "failed evals" in partial_check.get("detail", ""),
                partial_check,
            )
        )

        workspace = next(iter(store.workspaces.values()))
        fixtures = build_eval_fixtures()
        file_ids: dict[str, UUID] = {}
        responses = []
        for fixture in fixtures:
            response = upload_file(client, workspace.id, fixture)
            responses.append(response_detail(response))
            if response.status_code == 201:
                file_ids[fixture.family] = UUID(response.json()["file"]["id"])
        checks.append(
            assert_check(
                "Parser eval fixture uploads accepted",
                len(file_ids) == len(fixtures),
                responses,
            )
        )

        processed = store.process_queued_jobs()
        checks.append(
            assert_check(
                "Parser eval fixture jobs processed",
                processed == len(fixtures),
                f"processed={processed} expected={len(fixtures)}",
            )
        )

        store.refresh()
        report = build_observed_report(store, fixtures, file_ids)
        report_path = tmp_root / "parser-eval-report.json"
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

        checks.append(
            assert_check(
                "Observed parser eval report passes every required family",
                report.get("status") == "pass"
                and len(report.get("cases", [])) == len(REQUIRED_GOLDEN_FIXTURE_FAMILIES)
                and all(case.get("status") == "pass" for case in report.get("cases", [])),
                report,
            )
        )

        os.environ[PARSER_EVAL_REPORT_ENV] = str(report_path)
        passing = client.get("/readiness/client-data").json()
        passing_check = readiness_check(passing, "parser_fixture_evals")
        checks.append(
            assert_check(
                "Passing parser fixture eval report certifies parser eval gate",
                passing_check.get("status") == "pass"
                and f"{len(REQUIRED_GOLDEN_FIXTURE_FAMILIES)}/{len(REQUIRED_GOLDEN_FIXTURE_FAMILIES)}"
                in passing_check.get("detail", ""),
                passing_check,
            )
        )

        os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "client"
        os.environ[PARSER_EVAL_REPORT_ENV] = str(partial_report)
        # Detailed readiness is now a permission-gated (view_runtime_status) read.
        # Client mode fails closed unless the shared key is configured (deployment
        # precondition) AND rejects the shared key for auth, so also authenticate
        # with a per-user admin credential.
        os.environ["MONDAY_REPORT_API_KEY"] = "parser-eval-guard-client-key-0123456789"
        os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = "parser-eval-guard-audit-hmac-key-0123456ab"
        from backend.app.schemas import Role

        _admin = store.create_user("parser-eval-admin@example.test", "Parser Eval Admin", [Role.ADMIN])
        _cred, _tok = store.create_credential(_admin.id)
        client_mode_partial = client.get(
            "/readiness/client-data", headers={"X-Monday-Report-Key": _tok}
        ).json()
        client_mode_check = readiness_check(client_mode_partial, "parser_fixture_evals")
        checks.append(
            assert_check(
                "Client mode fails closed on incomplete parser fixture evals",
                client_mode_check.get("status") == "fail" and client_mode_partial.get("ready") is False,
                {"ready": client_mode_partial.get("ready"), "check": client_mode_check},
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
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Parser Eval Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "parser-eval-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Parser Eval Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client parser eval guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")
    os.environ["MONDAY_REPORT_OCR_ENGINE"] = "tesseract"
    os.environ["MONDAY_REPORT_TESSERACT_CMD"] = f'"{sys.executable}" "{fake_ocr}"'
    os.environ.pop(PARSER_EVAL_REPORT_ENV, None)


def write_fake_ocr(tmp_root: Path) -> Path:
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
    return fake_ocr


def build_eval_fixtures() -> list[EvalFixture]:
    ddr_pdf = build_pdf_fixture(
        "DDR: Anonymized Directional Services MWD signal loss with npt_hours 8.5. POOH and replace MWD tool."
    )
    return [
        EvalFixture("ddr", "fixtures/ddr/anonymized_ddr.pdf", ddr_pdf, "application/pdf", "pdf_text_v1", "pdf", True),
        EvalFixture(
            "bha",
            "fixtures/bha/anonymized_bha.xlsx",
            build_xlsx_fixture([["bha", "tool", "serial"], ["BHA-17", "stabilizer", "ANON-001"]]),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "xlsx_text_v1",
            "excel",
        ),
        EvalFixture(
            "mwd_lwd",
            "fixtures/mwd_lwd/anonymized_mwd_lwd.docx",
            build_docx_fixture("MWD/LWD run report confirms telemetry checks and service quality notes."),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "docx_text_v1",
            "word",
        ),
        EvalFixture(
            "rss",
            "fixtures/rss/anonymized_rss.pdf",
            build_pdf_fixture("RSS run evidence with steering performance and nonproductive-time context."),
            "application/pdf",
            "pdf_text_v1",
            "pdf",
        ),
        EvalFixture(
            "mud_motor",
            "fixtures/mud_motor/anonymized_motor.txt",
            b"Mud motor run report with bearing condition and differential pressure notes.",
            "text/plain",
            "plain_text_v1",
            "text",
        ),
        EvalFixture(
            "bit_record",
            "fixtures/bit/anonymized_bit_record.xlsx",
            build_xlsx_fixture([["bit", "dull_grade", "meters"], ["ANON-BIT", "1-1-WT", "420"]]),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "xlsx_text_v1",
            "excel",
        ),
        EvalFixture(
            "mud_report",
            "fixtures/mud/anonymized_mud_report.pdf",
            build_pdf_fixture("Mud report with density, rheology, losses, and operational context."),
            "application/pdf",
            "pdf_text_v1",
            "pdf",
        ),
        EvalFixture(
            "npt_report",
            "fixtures/npt/anonymized_npt.csv",
            b"date,company,event,npt_hours\n2026-07-06,Anonymized Directional Services,MWD communication issue,3.0\n",
            "text/csv",
            "csv_text_v1",
            "csv",
        ),
        EvalFixture(
            "scanned_pdf",
            "fixtures/scanned/anonymized_scanned_ddr.pdf",
            build_scanned_pdf_fixture(),
            "application/pdf",
            "ocr_text_v1",
            "image",
            True,
        ),
        EvalFixture(
            "excel_workbook",
            "fixtures/excel/anonymized_service_quality.xlsx",
            build_xlsx_fixture([["date", "company", "score"], ["2026-07-06", "Anonymized Directional Services", "92"]]),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "xlsx_text_v1",
            "excel",
        ),
        EvalFixture(
            "email_with_attachment",
            "fixtures/email/anonymized_ops_update.eml",
            (
                "From: ops@example.test\r\n"
                "To: drilling@example.test\r\n"
                "Subject: Anonymized operations update\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                "\r\n"
                "Email body records service-quality follow-up and attached anonymized context.\r\n"
            ).encode("utf-8"),
            "message/rfc822",
            "email_text_v1",
            "email",
        ),
        EvalFixture(
            "corrupted_file",
            "fixtures/corrupted/anonymized_corrupted.bin",
            b"\x00\x01\x02unsupported-parser-fixture",
            "application/octet-stream",
            None,
            None,
            expected_job_result="no_text_extracted",
        ),
        EvalFixture(
            "duplicate_file",
            "fixtures/duplicate/anonymized_duplicate_ddr.pdf",
            ddr_pdf,
            "application/pdf",
            "pdf_text_v1",
            "pdf",
            duplicate_of="ddr",
        ),
    ]


def upload_file(client: TestClient, workspace_id: UUID, fixture: EvalFixture):
    return client.post(
        "/uploads/direct",
        data={
            "workspace_id": str(workspace_id),
            "file_name": fixture.file_name,
            "source_type": "files",
        },
        files={"file": (Path(fixture.file_name).name, fixture.content, fixture.mime_type)},
    )


def build_observed_report(store, fixtures: list[EvalFixture], file_ids: dict[str, UUID]) -> dict[str, object]:
    cases = [build_observed_case(store, fixture, file_ids) for fixture in fixtures]
    return {
        "fixture_set": "parser-fixture-eval-guard",
        "status": "pass" if all(case["status"] == "pass" for case in cases) else "fail",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cases": cases,
    }


def build_observed_case(store, fixture: EvalFixture, file_ids: dict[str, UUID]) -> dict[str, object]:
    file_id = file_ids.get(fixture.family)
    file_record = store.files.get(file_id) if file_id else None
    documents = [
        document
        for document in store.parsed_documents.values()
        if file_id and document.file_id == file_id
    ]
    chunks = [
        chunk
        for chunk in store.document_chunks.values()
        if file_id and chunk.file_id == file_id
    ]
    jobs = [job for job in store.jobs.values() if file_id and job.file_id == file_id]
    failures = [
        failure
        for failure in store.failures.values()
        if any(citation.file_id == file_id for citation in failure.citations)
    ]

    checks: list[dict[str, object]] = []
    if fixture.expected_parser:
        parser_names = {document.parser_name for document in documents}
        add_check(checks, "expected_parser", fixture.expected_parser in parser_names, sorted(parser_names))
        locator_types = {chunk.locator_type for chunk in chunks}
        add_check(checks, "expected_locator", fixture.expected_locator in locator_types, sorted(locator_types))
        add_check(checks, "chunks_created", len(chunks) > 0, len(chunks))
    else:
        job_results = {str(job.payload.get("result")) for job in jobs}
        job_statuses = {job.status.value for job in jobs}
        add_check(checks, "expected_failed_job", "failed" in job_statuses, sorted(job_statuses))
        add_check(checks, "expected_job_result", fixture.expected_job_result in job_results, sorted(job_results))

    if fixture.expected_failure:
        add_check(checks, "failure_extracted", len(failures) >= 1, [failure.model_dump(mode="json") for failure in failures])
    if fixture.duplicate_of:
        duplicate_file_id = file_ids.get(fixture.duplicate_of)
        duplicate_source = store.files.get(duplicate_file_id) if duplicate_file_id else None
        add_check(
            checks,
            "duplicate_sha256",
            bool(file_record and duplicate_source and file_record.sha256 == duplicate_source.sha256),
            {
                "fixture_sha256": file_record.sha256 if file_record else None,
                "duplicate_of_sha256": duplicate_source.sha256 if duplicate_source else None,
            },
        )

    return {
        "id": f"case-{fixture.family}",
        "family": fixture.family,
        "file": fixture.file_name,
        "status": "pass" if all(check["status"] == "pass" for check in checks) else "fail",
        "observed": {
            "parser_names": sorted({document.parser_name for document in documents}),
            "locator_types": sorted({chunk.locator_type for chunk in chunks}),
            "chunk_count": len(chunks),
            "job_statuses": sorted({job.status.value for job in jobs}),
            "job_results": sorted({str(job.payload.get("result")) for job in jobs}),
            "failure_count": len(failures),
            "sha256": file_record.sha256 if file_record else None,
        },
        "checks": checks,
    }


def add_check(checks: list[dict[str, object]], name: str, ok: bool, detail: object) -> None:
    checks.append({"name": name, "status": "pass" if ok else "fail", "detail": detail})


def write_static_report(path: Path, cases: list[dict[str, object]]) -> None:
    report = {
        "fixture_set": path.stem,
        "status": "pass" if all(case.get("status") == "pass" for case in cases) else "fail",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cases": cases,
    }
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def static_case(family: str, status: str) -> dict[str, object]:
    return {
        "id": f"case-{family}",
        "family": family,
        "status": status,
        "checks": [{"name": "static_eval", "status": status, "detail": "static guard report"}],
    }


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


def readiness_check(payload: dict, check_id: str) -> dict:
    for check in payload.get("checks", []):
        if check.get("id") == check_id:
            return check
    return {}


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
