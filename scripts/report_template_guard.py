from __future__ import annotations

import json
import os
import sys
import tempfile
import zipfile
from datetime import date
from io import BytesIO
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-template-") as tmp:
        configure_guard_env(Path(tmp))

        from backend.app.schemas import Citation, FailureRecord, MondayReportCreate, ValidationStatus
        from backend.app.store import store

        workspace = next(iter(store.workspaces.values()))
        citation = Citation(
            locator_type="pdf",
            locator={"page": 1, "table": 1, "row_start": 2},
            snippet="Source-backed MWD signal loss citation.",
            confidence=0.91,
        )
        failure = FailureRecord(
            tenant_id=store.tenant.id,
            workspace_id=workspace.id,
            event_type="MWD signal loss",
            severity="High",
            summary="MWD signal loss caused 8.5 hours NPT while drilling ahead.",
            company="Anonymized Directional Services",
            tool_type="MWD",
            tool_serial="MWD-042",
            npt_hours=8.5,
            confidence=0.91,
            validation_status=ValidationStatus.VALIDATED,
            citations=[citation],
        )
        store.failures[failure.id] = failure
        store.save()

        report = store.create_monday_report(
            MondayReportCreate(
                workspace_id=workspace.id,
                period_start=date(2026, 7, 6),
                period_end=date(2026, 7, 12),
            )
        )
        checks.append(
            assert_check(
                "Report JSON includes GA report sections",
                report.report_json.get("metrics", {}).get("failure_count") == 1
                and "morning_report" in report.report_json
                and report.report_json.get("morning_report", {}).get("casing_schematic")
                and report.report_json.get("morning_report", {}).get("activity_timeline"),
                report.report_json,
            )
        )

        exports = {fmt: store.export_monday_report(report.id, fmt) for fmt in ["json", "html", "pdf", "xlsx"]}
        exported_bytes = {
            fmt: store.export_path_from_uri(export.storage_uri).read_bytes()  # type: ignore[union-attr]
            for fmt, export in exports.items()
        }

        json_payload = json.loads(exported_bytes["json"].decode("utf-8"))
        checks.append(
            assert_check(
                "JSON export carries metrics and casing",
                json_payload.get("metrics", {}).get("total_npt_hours") == 8.5
                and len(json_payload.get("morning_report", {}).get("casing_schematic", [])) >= 4,
                json_payload,
            )
        )

        html_text = exported_bytes["html"].decode("utf-8", errors="replace")
        checks.append(
            assert_check(
                "HTML export uses branded operations template",
                "<h1>Morning Operations Report</h1>" in html_text
                and "Casing Schematic" in html_text
                and "24 Hr Activity Timeline" in html_text
                and "MWD signal loss" in html_text,
                "html markers present" if "Casing Schematic" in html_text else html_text[:300],
            )
        )

        checks.append(
            assert_check(
                "PDF export uses branded operations template",
                exported_bytes["pdf"].startswith(b"%PDF-1.4")
                and b"%%EOF" in exported_bytes["pdf"][-32:]
                and pdf_contains(exported_bytes["pdf"], ["Morning Operations Report", "Casing Schematic", "24 Hr Activity Timeline"]),
                f"bytes={len(exported_bytes['pdf'])}",
            )
        )

        xlsx_text = xlsx_inline_text(exported_bytes["xlsx"])
        checks.append(
            assert_check(
                "XLSX export includes metrics, casing, and timeline",
                "Metrics" in xlsx_text
                and "Casing Schematic" in xlsx_text
                and "24 Hr Activity Timeline" in xlsx_text
                and "MWD signal loss" in xlsx_text,
                "xlsx markers present" if "Casing Schematic" in xlsx_text else xlsx_text[:300],
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
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Report Template Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "report-template-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Report Template Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client report template guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")
    for key in [
        "MONDAY_REPORT_API_KEY",
        "VITE_MONDAY_REPORT_API_KEY",
        "MONDAY_REPORT_SIGNING_SECRET",
        "MONDAY_REPORT_REPOSITORY_BACKEND",
        "MONDAY_REPORT_DATABASE_URL",
        "DATABASE_URL",
        "MONDAY_REPORT_QUEUE_BACKEND",
        "MONDAY_REPORT_REDIS_URL",
        "REDIS_URL",
    ]:
        os.environ.pop(key, None)


def pdf_contains(content: bytes, markers: list[str]) -> bool:
    import fitz  # type: ignore[import-not-found]

    document = fitz.open(stream=content, filetype="pdf")
    try:
        text = "\n".join(document.load_page(index).get_text("text") for index in range(document.page_count))
    finally:
        document.close()
    return all(marker in text for marker in markers)


def xlsx_inline_text(content: bytes) -> str:
    with zipfile.ZipFile(BytesIO(content)) as archive:
        return "\n".join(
            archive.read(name).decode("utf-8", errors="replace")
            for name in archive.namelist()
            if name.endswith(".xml")
        )


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
