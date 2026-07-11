from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-export-idempotency-") as tmp:
        configure_guard_env(Path(tmp))

        from backend.app.main import app
        from backend.app.store import store

        client = TestClient(app)
        workspace = next(iter(store.workspaces.values()))

        report_response = client.post(
            "/monday-reports",
            json={
                "workspace_id": str(workspace.id),
                "period_start": "2026-07-06",
                "period_end": "2026-07-12",
            },
        )
        report = report_response.json()
        report_id = report.get("id") if report_response.status_code == 201 else None
        checks.append(
            assert_check(
                "Report created for idempotent export",
                report_response.status_code == 201 and report_id is not None,
                response_detail(report_response),
            )
        )

        first_export = client.post(f"/monday-reports/{report_id}/exports/json") if report_id else None
        second_export = client.post(f"/monday-reports/{report_id}/exports/json") if report_id else None
        first_payload = first_export.json() if first_export is not None and first_export.status_code == 200 else {}
        second_payload = second_export.json() if second_export is not None and second_export.status_code == 200 else {}
        store.refresh()
        export_records = [
            report_export
            for report_export in store.report_exports.values()
            if report_id is not None and str(report_export.report_id) == report_id and report_export.format == "json"
        ]
        checks.append(
            assert_check(
                "Repeated JSON export reuses the same record",
                first_export is not None
                and second_export is not None
                and first_export.status_code == 200
                and second_export.status_code == 200
                and first_payload.get("id") == second_payload.get("id")
                and len(export_records) == 1,
                {
                    "first": first_payload.get("id"),
                    "second": second_payload.get("id"),
                    "records": len(export_records),
                },
            )
        )

        export_events = [
            event
            for event in store.audit_logs
            if event.action == "monday_report.export"
            and report_id is not None
            and str(event.resource_id) == report_id
        ]
        reused_events = [
            event
            for event in store.audit_logs
            if event.action == "monday_report.export_reused"
            and report_id is not None
            and str(event.resource_id) == report_id
        ]
        checks.append(
            assert_check(
                "Export reuse is audited without duplicate export event",
                len(export_events) == 1 and len(reused_events) == 1,
                {"export_events": len(export_events), "reused_events": len(reused_events)},
            )
        )

        signed_response = (
            client.post(f"/report-exports/{first_payload.get('id')}/signed-url")
            if first_payload.get("id")
            else None
        )
        downloaded = signed_download_content(client, signed_response) if signed_response is not None else None
        checks.append(
            assert_check(
                "Reused export downloads through signed URL",
                downloaded is not None and b'"title": "Monday Report"' in downloaded,
                f"bytes={len(downloaded or b'')}",
            )
        )

        integrity = store.audit_integrity_status()
        checks.append(
            assert_check(
                "Report export idempotency audit chain sealed",
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
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Report Export Idempotency Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "report-export-idempotency-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Report Export Idempotency Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client report export idempotency guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")


def signed_download_content(client: TestClient, signed_response) -> bytes | None:
    if signed_response.status_code != 200:
        return None
    parsed = urlparse(signed_response.json()["url"])
    response = client.get(f"{parsed.path}?{parsed.query}")
    return response.content if response.status_code == 200 else None


def response_detail(response) -> str:
    if response.status_code >= 400:
        return response.text
    try:
        payload = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"
    if isinstance(payload, dict):
        return str(payload.get("id", f"HTTP {response.status_code}"))
    return f"HTTP {response.status_code}"


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
