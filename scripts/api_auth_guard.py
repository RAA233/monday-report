from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CLIENT_API_KEY = "api-auth-test-client-key-012345"
CLIENT_HEADERS = {"X-Monday-Report-Key": CLIENT_API_KEY}


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-api-auth-") as tmp:
        configure_guard_env(Path(tmp))

        from backend.app.main import app
        from backend.app.store import store

        client = TestClient(app)
        health = client.get("/health")
        checks.append(assert_check("Health exempt from API key", health.status_code == 200, health.text))

        missing_config = client.get("/auth/session")
        checks.append(
            assert_check(
                "Client mode fails closed without configured API key",
                missing_config.status_code == 503,
                missing_config.text,
            )
        )

        os.environ["MONDAY_REPORT_API_KEY"] = CLIENT_API_KEY
        missing_header = client.get("/auth/session")
        checks.append(
            assert_check(
                "Client mode rejects missing API key header",
                missing_header.status_code == 401,
                missing_header.text,
            )
        )
        wrong_header = client.get("/auth/session", headers={"X-Monday-Report-Key": "wrong-key"})
        checks.append(
            assert_check(
                "Client mode rejects invalid API key header",
                wrong_header.status_code == 401,
                wrong_header.text,
            )
        )
        accepted = client.get("/auth/session", headers=CLIENT_HEADERS)
        checks.append(
            assert_check(
                "Client mode accepts valid API key header",
                accepted.status_code == 200 and accepted.json().get("tenant", {}).get("slug") == "api-auth-guard",
                response_detail(accepted),
            )
        )

        store.refresh()
        auth_blocks = [event for event in store.audit_logs if event.action == "api.auth_blocked"]
        checks.append(
            assert_check(
                "API auth failures audited",
                len(auth_blocks) >= 3,
                f"{len(auth_blocks)} auth block event(s)",
            )
        )

    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")
    return 1 if failed else 0


def configure_guard_env(tmp_root: Path) -> None:
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "client"
    os.environ.pop("MONDAY_REPORT_API_KEY", None)
    os.environ["MONDAY_REPORT_DISABLE_DEMO_SEED"] = "true"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "API Auth Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "api-auth-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "API Auth Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client API auth guard"
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
