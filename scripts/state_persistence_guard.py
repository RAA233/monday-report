from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-state-persistence-") as tmp:
        configure_guard_env(Path(tmp))

        from backend.app.store import store

        state_path = Path(os.environ["MONDAY_REPORT_STATE_PATH"])
        initial_payload = load_payload(state_path)
        checks.append(
            assert_check(
                "Initial local state is valid JSON",
                initial_payload.get("tenant", {}).get("slug") == "state-persistence-guard",
                f"state={state_path}",
            )
        )

        for index in range(25):
            store.audit(
                "state.persistence_probe",
                "tenant",
                store.tenant.id,
                {"probe_index": index, "guard": "state_persistence"},
            )
            payload = load_payload(state_path)
            checks.append(
                assert_check(
                    f"State remains parseable after save {index + 1}",
                    isinstance(payload.get("audit_logs"), list),
                    f"audit_logs={len(payload.get('audit_logs', []))}",
                )
            )

        original_state = state_path.read_text(encoding="utf-8")
        state_path.write_text("{", encoding="utf-8")

        def restore_state() -> None:
            time.sleep(0.04)
            state_path.write_text(original_state, encoding="utf-8")

        restorer = threading.Thread(target=restore_state)
        restorer.start()
        retry_payload = store._read_state_payload()
        restorer.join()
        checks.append(
            assert_check(
                "State refresh retries transient partial reads",
                retry_payload is not None and retry_payload.get("tenant", {}).get("slug") == "state-persistence-guard",
                "partial-read recovered",
            )
        )

        store.refresh()
        store.audit(
            "state.persistence_verified",
            "tenant",
            store.tenant.id,
            {"guard": "state_persistence"},
        )

        orphaned_temp_files = list(state_path.parent.glob(f"{state_path.name}.*.tmp"))
        legacy_temp_file = state_path.with_suffix(".tmp")
        checks.append(
            assert_check(
                "Atomic state writes leave no temp files",
                not orphaned_temp_files and not legacy_temp_file.exists(),
                {
                    "orphaned_temp_files": [path.name for path in orphaned_temp_files],
                    "legacy_temp_exists": legacy_temp_file.exists(),
                },
            )
        )

        integrity = store.audit_integrity_status()
        checks.append(
            assert_check(
                "State persistence audit chain sealed",
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
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "State Persistence Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "state-persistence-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "State Persistence Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client state persistence guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")


def load_payload(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
