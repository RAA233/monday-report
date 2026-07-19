from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SHARED_KEY = "api-auth-test-client-key-012345"
SHARED_HEADERS = {"X-Monday-Report-Key": SHARED_KEY}


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-api-auth-") as tmp:
        configure_guard_env(Path(tmp))

        from backend.app.main import app
        from backend.app.schemas import Role
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

        os.environ["MONDAY_REPORT_API_KEY"] = SHARED_KEY
        missing_header = client.get("/auth/session")
        checks.append(
            assert_check(
                "Client mode rejects missing API key header",
                missing_header.status_code == 401,
                missing_header.text,
            )
        )
        wrong_header = client.get("/auth/session", headers={"X-Monday-Report-Key": "wrong-key-value-012345"})
        checks.append(
            assert_check(
                "Client mode rejects invalid API key header",
                wrong_header.status_code == 401,
                wrong_header.text,
            )
        )

        # (2) Legacy shared key is REJECTED in client mode — it is NOT a
        # client-mode administrator.
        shared_client = client.get("/auth/session", headers=SHARED_HEADERS)
        checks.append(
            assert_check(
                "Client mode REJECTS the legacy shared key (no client-mode admin)",
                shared_client.status_code in (401, 403),
                response_detail(shared_client),
            )
        )

        # (3) An active persisted per-user credential works in client mode.
        admin_user = store.create_user("client-admin@example.test", "Client Admin", [Role.ADMIN])
        credential, admin_token = store.create_credential(admin_user.id)
        accepted = client.get("/auth/session", headers={"X-Monday-Report-Key": admin_token})
        session = accepted.json() if accepted.status_code == 200 else {}
        ident = session.get("authenticated_identity") or {}
        checks.append(
            assert_check(
                "Client mode accepts an active per-user credential",
                accepted.status_code == 200
                and session.get("tenant", {}).get("slug") == "api-auth-guard"
                and ident.get("actor_source") == "authenticated",
                response_detail(accepted),
            )
        )

        # (4) A revoked credential fails immediately.
        store.revoke_credential(credential.credential_id)
        revoked = client.get("/auth/session", headers={"X-Monday-Report-Key": admin_token})
        checks.append(
            assert_check(
                "Revoked per-user credential fails immediately in client mode",
                revoked.status_code == 401,
                revoked.text,
            )
        )

        # (5) A bootstrap/demo identity alone cannot satisfy client-mode per-user
        # evidence: with the only real credential revoked, no active
        # non-bootstrap credential exists.
        checks.append(
            assert_check(
                "Bootstrap-only identity is not per-user client evidence",
                store.has_non_bootstrap_identity() is False,
                {"has_non_bootstrap_identity": store.has_non_bootstrap_identity()},
            )
        )

        # (1) Legacy shared key STILL works in local/demo compatibility mode.
        os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
        demo_shared = client.get("/auth/session", headers=SHARED_HEADERS)
        demo_ident = demo_shared.json().get("authenticated_identity") if demo_shared.status_code == 200 else {}
        checks.append(
            assert_check(
                "Legacy shared key works in local/demo mode as demo_bootstrap",
                demo_shared.status_code == 200 and (demo_ident or {}).get("actor_source") == "demo_bootstrap",
                response_detail(demo_shared),
            )
        )
        os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "client"

        store.refresh()
        auth_blocks = [event for event in store.audit_logs if event.action == "api.auth_blocked"]
        checks.append(
            assert_check(
                "API auth failures audited",
                len(auth_blocks) >= 4,
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
