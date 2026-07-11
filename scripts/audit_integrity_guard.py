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
    with tempfile.TemporaryDirectory(prefix="monday-report-audit-chain-") as tmp:
        configure_guard_env(Path(tmp))

        from backend.app.main import app
        from backend.app.store import store

        client = TestClient(app)
        initial = client.get("/audit-logs/integrity")
        initial_payload = initial.json()
        checks.append(
            assert_check(
                "Fresh audit chain sealed",
                initial.status_code == 200
                and initial_payload.get("status") == "sealed"
                and initial_payload.get("hashed_events") == initial_payload.get("total_events")
                and initial_payload.get("broken_events") == 0,
                initial_payload,
            )
        )

        workspace_create = client.post(
            "/workspaces",
            json={"name": "Audit chain workspace", "asset": "client asset", "campaign": "client campaign"},
        )
        checks.append(
            assert_check(
                "Audited operation created",
                workspace_create.status_code == 201,
                response_detail(workspace_create),
            )
        )
        after_write = client.get("/audit-logs/integrity").json()
        checks.append(
            assert_check(
                "Audit chain remains sealed after write",
                after_write.get("status") == "sealed" and after_write.get("broken_events") == 0,
                after_write,
            )
        )

        store.refresh()
        store.audit_logs[0].metadata["tamper_probe"] = True
        store.save()
        tampered = client.get("/audit-logs/integrity").json()
        checks.append(
            assert_check(
                "Audit chain detects tamper",
                tampered.get("status") == "broken" and int(tampered.get("broken_events", 0)) >= 1,
                tampered,
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
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Audit Chain Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "audit-chain-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Audit Chain Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client audit chain guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")


def response_detail(response) -> object:
    try:
        return response.json()
    except ValueError:
        return f"HTTP {response.status_code}"


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
