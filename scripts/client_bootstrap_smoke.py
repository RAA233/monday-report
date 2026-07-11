from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="monday-report-client-") as temp_dir:
        root = Path(temp_dir)
        os.environ.update(
            {
                "MONDAY_REPORT_STATE_PATH": str(root / "state" / "client_state.json"),
                "MONDAY_REPORT_STORAGE_ROOT": str(root / "storage"),
                "MONDAY_REPORT_EXPORT_ROOT": str(root / "exports"),
                "MONDAY_REPORT_TENANT_NAME": "Client Energy",
                "MONDAY_REPORT_TENANT_SLUG": "client-energy",
                "MONDAY_REPORT_USER_EMAIL": "engineer@client.example",
                "MONDAY_REPORT_USER_FULL_NAME": "Client Engineer",
                "MONDAY_REPORT_DEFAULT_WORKSPACE_NAME": "Client readiness workspace",
                "MONDAY_REPORT_DISABLE_DEMO_SEED": "true",
            }
        )

        from backend.app.readiness import evaluate_client_data_readiness
        from backend.app.store import LocalStateStore

        store = LocalStateStore()
        readiness = evaluate_client_data_readiness(store)
        has_demo_seed = any(log.action == "state.seed" for log in store.audit_logs)
        has_demo_failure = len(store.failures) > 0
        identity_ok = store.tenant.slug == "client-energy" and store.user.email == "engineer@client.example"
        demo_check = next(check for check in readiness.checks if check.id == "demo_seed_removed")
        ok = not has_demo_seed and not has_demo_failure and identity_ok and demo_check.status == "pass"

    if ok:
        print("PASS: Client bootstrap smoke - clean tenant/user state without demo seed")
        return 0

    print(
        "FAIL: Client bootstrap smoke - "
        f"has_demo_seed={has_demo_seed} has_demo_failure={has_demo_failure} identity_ok={identity_ok} "
        f"demo_check={demo_check.status}"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
