from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-upload-ownership-") as tmp:
        tmp_root = Path(tmp)
        configure_guard_env(tmp_root)

        from backend.app.main import app
        from backend.app.store import store

        client = TestClient(app)
        workspace = next(iter(store.workspaces.values()))

        source_upload = client.post(
            "/uploads/direct",
            data={
                "workspace_id": str(workspace.id),
                "file_name": "ownership/source.txt",
                "source_type": "files",
            },
            files={"file": ("source.txt", b"owned source bytes", "text/plain")},
        )
        source_payload = source_upload.json()
        source_upload_id = source_payload.get("upload", {}).get("id") if source_upload.status_code == 201 else None
        source_file_id = source_payload.get("file", {}).get("id") if source_upload.status_code == 201 else None
        checks.append(
            assert_check(
                "Source upload with stored bytes created",
                source_upload.status_code == 201 and source_upload_id is not None and source_file_id is not None,
                response_detail(source_upload),
            )
        )

        target_upload = client.post(
            "/uploads",
            json={
                "workspace_id": str(workspace.id),
                "file_name": "ownership/target.txt",
                "byte_size": 19,
                "mime_type": "text/plain",
                "source_type": "files",
            },
        )
        target_payload = target_upload.json()
        target_upload_id = target_payload.get("upload", {}).get("id") if target_upload.status_code == 201 else None
        target_file_id = target_payload.get("file", {}).get("id") if target_upload.status_code == 201 else None
        checks.append(
            assert_check(
                "Target metadata upload created",
                target_upload.status_code == 201 and target_upload_id is not None and target_file_id is not None,
                response_detail(target_upload),
            )
        )

        mismatch_response = (
            client.post(f"/uploads/{target_upload_id}/complete", json={"file_ids": [source_file_id]})
            if target_upload_id and source_file_id
            else None
        )
        store.refresh()
        target_jobs = [
            job for job in store.jobs.values() if target_upload_id is not None and str(job.upload_id) == target_upload_id
        ]
        source_jobs = [
            job for job in store.jobs.values() if source_upload_id is not None and str(job.upload_id) == source_upload_id
        ]
        mismatch_events = [
            event
            for event in store.audit_logs
            if event.action == "upload.complete_rejected"
            and target_upload_id is not None
            and str(event.resource_id) == target_upload_id
        ]
        checks.append(
            assert_check(
                "Cross-upload completion is rejected",
                mismatch_response is not None
                and mismatch_response.status_code == 409
                and "does not belong" in mismatch_response.text,
                response_detail(mismatch_response) if mismatch_response is not None else "uploads were not created",
            )
        )
        checks.append(
            assert_check(
                "Rejected cross-upload creates no target job",
                len(target_jobs) == 0 and len(source_jobs) == 1,
                {"target_jobs": len(target_jobs), "source_jobs": len(source_jobs)},
            )
        )
        checks.append(
            assert_check(
                "Cross-upload rejection is audited",
                len(mismatch_events) == 1
                and mismatch_events[0].metadata.get("reason") == "file_upload_mismatch"
                and redacted_fingerprint(mismatch_events[0].metadata.get("file_id"))
                and redacted_fingerprint(mismatch_events[0].metadata.get("file_upload_id")),
                [event.metadata for event in mismatch_events],
            )
        )

        valid_target_response = (
            client.post(f"/uploads/{target_upload_id}/complete", json={"file_ids": [target_file_id]})
            if target_upload_id and target_file_id
            else None
        )
        store.refresh()
        target_upload_record = store.uploads.get(UUID(target_upload_id)) if target_upload_id else None
        checks.append(
            assert_check(
                "Own metadata file still reaches missing-storage guard",
                valid_target_response is not None
                and valid_target_response.status_code == 200
                and valid_target_response.json().get("status") == "failed"
                and target_upload_record is not None
                and target_upload_record.status.value == "failed",
                response_detail(valid_target_response) if valid_target_response is not None else "target upload was not created",
            )
        )

        integrity = store.audit_integrity_status()
        checks.append(
            assert_check(
                "Upload ownership audit chain sealed",
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
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Upload Ownership Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "upload-ownership-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Upload Ownership Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client upload ownership guard"
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


def redacted_fingerprint(value: object) -> bool:
    return (
        isinstance(value, dict)
        and value.get("redacted") is True
        and value.get("reason") == "sensitive_pattern"
        and isinstance(value.get("sha256"), str)
        and len(value["sha256"]) == 64
    )


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
