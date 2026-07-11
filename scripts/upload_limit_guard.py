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
    with tempfile.TemporaryDirectory(prefix="monday-report-upload-limit-") as tmp:
        configure_guard_env(Path(tmp))

        from backend.app.main import app
        from backend.app.store import store

        client = TestClient(app)
        workspace = next(iter(store.workspaces.values()))
        metadata_reject = client.post(
            "/uploads",
            json={
                "workspace_id": str(workspace.id),
                "file_name": "oversized/client_package.zip",
                "byte_size": 65,
                "mime_type": "application/zip",
                "source_type": "zip",
            },
        )
        checks.append(
            assert_check(
                "Metadata upload size guard",
                metadata_reject.status_code == 413,
                response_detail(metadata_reject),
            )
        )

        direct_reject = client.post(
            "/uploads/direct",
            data={
                "workspace_id": str(workspace.id),
                "file_name": "oversized/source.txt",
                "source_type": "files",
            },
            files={"file": ("source.txt", b"x" * 65, "text/plain")},
        )
        checks.append(
            assert_check(
                "Direct upload size guard",
                direct_reject.status_code == 413,
                response_detail(direct_reject),
            )
        )

        accepted = client.post(
            "/uploads/direct",
            data={
                "workspace_id": str(workspace.id),
                "file_name": "accepted/source.txt",
                "source_type": "files",
            },
            files={"file": ("source.txt", b"MWD signal loss evidence", "text/plain")},
        )
        checks.append(
            assert_check(
                "Upload below limit accepted",
                accepted.status_code == 201,
                response_detail(accepted),
            )
        )

        store.refresh()
        rejected_events = [event for event in store.audit_logs if event.action == "upload.rejected"]
        checks.append(
            assert_check(
                "Upload rejection audited",
                len(rejected_events) >= 2,
                f"{len(rejected_events)} rejection audit event(s)",
            )
        )

    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")
    return 1 if failed else 0


def configure_guard_env(tmp_root: Path) -> None:
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
    os.environ["MONDAY_REPORT_MAX_UPLOAD_BYTES"] = "64"
    os.environ["MONDAY_REPORT_DISABLE_DEMO_SEED"] = "true"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Upload Limit Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "upload-limit-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Upload Limit Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client upload limit guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")


def response_detail(response) -> str:
    if response.status_code >= 400:
        return response.text
    try:
        payload = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"
    if isinstance(payload, dict) and "upload" in payload and isinstance(payload["upload"], dict):
        return str(payload["upload"].get("id", f"HTTP {response.status_code}"))
    return f"HTTP {response.status_code}"


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
