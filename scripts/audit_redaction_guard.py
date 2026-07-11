from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-audit-redaction-") as tmp:
        configure_guard_env(Path(tmp))

        from backend.app.store import store

        sensitive_prompt = "Client confidential prompt with reviewer@example.test and token abcdefghijklmnopqrstuvwxyz1234567890"
        sensitive_path = "client/well-7/confidential-ddr.pdf"
        store.audit(
            "audit.redaction_probe",
            "workspace",
            metadata={
                "prompt": sensitive_prompt,
                "file_name": sensitive_path,
                "nested": {
                    "content": "Customer incident details should never appear raw.",
                    "safe_count": 7,
                },
                "safe_status": "checked",
            },
        )
        store.refresh()
        event = store.audit_logs[-1]
        metadata = event.metadata
        checks.append(
            assert_check(
                "Sensitive prompt redacted",
                redacted(metadata.get("prompt")) and sensitive_prompt not in str(metadata),
                metadata.get("prompt"),
            )
        )
        checks.append(
            assert_check(
                "Sensitive filename redacted",
                redacted(metadata.get("file_name")) and sensitive_path not in str(metadata),
                metadata.get("file_name"),
            )
        )
        nested = metadata.get("nested", {})
        checks.append(
            assert_check(
                "Nested sensitive content redacted",
                isinstance(nested, dict) and redacted(nested.get("content")) and nested.get("safe_count") == 7,
                nested,
            )
        )
        checks.append(
            assert_check(
                "Safe metadata preserved",
                metadata.get("safe_status") == "checked",
                metadata,
            )
        )
        integrity = store.audit_integrity_status()
        checks.append(
            assert_check(
                "Redacted audit chain remains sealed",
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
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Audit Redaction Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "audit-redaction-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Audit Redaction Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client audit redaction guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")


def redacted(value: object) -> bool:
    return isinstance(value, dict) and value.get("redacted") is True and isinstance(value.get("sha256"), str)


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
