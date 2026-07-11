from __future__ import annotations

import os
import sys
import tempfile
from datetime import date
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CLIENT_API_KEY = "client-operation-test-key-012345"
CLIENT_HEADERS = {"X-Monday-Report-Key": CLIENT_API_KEY}


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-client-ops-") as tmp:
        configure_guard_env(Path(tmp))

        from backend.app.main import app
        from backend.app.schemas import MondayReportCreate
        from backend.app.store import store

        client = TestClient(app)
        workspace = next(iter(store.workspaces.values()))
        seeded_report = store.create_monday_report(
            MondayReportCreate(
                workspace_id=workspace.id,
                period_start=date(2026, 7, 6),
                period_end=date(2026, 7, 12),
            )
        )

        blocked_chat = client.post(
            "/chat/messages",
            json={"workspace_id": str(workspace.id), "content": "Generate Monday Report", "filters": {}},
            headers=CLIENT_HEADERS,
        )
        checks.append(assert_check("Client mode blocks chat when not ready", blocked_chat.status_code == 423, blocked_chat.text))

        blocked_report = client.post(
            "/monday-reports",
            json={
                "workspace_id": str(workspace.id),
                "period_start": "2026-07-06",
                "period_end": "2026-07-12",
            },
            headers=CLIENT_HEADERS,
        )
        checks.append(
            assert_check(
                "Client mode blocks report creation when not ready",
                blocked_report.status_code == 423,
                blocked_report.text,
            )
        )

        blocked_export = client.post(f"/monday-reports/{seeded_report.id}/exports/json", headers=CLIENT_HEADERS)
        checks.append(
            assert_check(
                "Client mode blocks report export when not ready",
                blocked_export.status_code == 423,
                blocked_export.text,
            )
        )

        blocked_documents = client.get(f"/documents?workspace_id={workspace.id}", headers=CLIENT_HEADERS)
        checks.append(
            assert_check(
                "Client mode blocks document reads when not ready",
                blocked_documents.status_code == 423,
                blocked_documents.text,
            )
        )

        store.refresh()
        blocked_events = [event for event in store.audit_logs if event.action == "client_data.operation_blocked"]
        checks.append(
            assert_check(
                "Blocked client operations audited",
                len(blocked_events) >= 4,
                f"{len(blocked_events)} blocked operation event(s)",
            )
        )

    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")
    return 1 if failed else 0


def configure_guard_env(tmp_root: Path) -> None:
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "client"
    os.environ["MONDAY_REPORT_API_KEY"] = CLIENT_API_KEY
    os.environ["MONDAY_REPORT_DISABLE_DEMO_SEED"] = "true"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Client Operation Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "client-operation-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Client Operation Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client operation guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")
    for key in [
        "MONDAY_REPORT_SIGNING_SECRET",
        "MONDAY_REPORT_MAX_UPLOAD_BYTES",
        "MONDAY_REPORT_MAX_ZIP_ENTRIES",
        "MONDAY_REPORT_MAX_ZIP_UNCOMPRESSED_BYTES",
        "MONDAY_REPORT_REPOSITORY_BACKEND",
        "MONDAY_REPORT_DATABASE_URL",
        "DATABASE_URL",
        "MONDAY_REPORT_QUEUE_BACKEND",
        "MONDAY_REPORT_REDIS_URL",
        "REDIS_URL",
        "MONDAY_REPORT_PRODUCTION_PARSERS",
        "MONDAY_REPORT_PARSER_EVAL_REPORT",
        "MONDAY_REPORT_MALWARE_SCANNER",
        "OLLAMA_HOST",
        "LM_STUDIO_BASE_URL",
    ]:
        os.environ.pop(key, None)


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
