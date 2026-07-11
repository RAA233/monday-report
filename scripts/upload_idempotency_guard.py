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
    with tempfile.TemporaryDirectory(prefix="monday-report-upload-idempotency-") as tmp:
        tmp_root = Path(tmp)
        configure_guard_env(tmp_root)

        from backend.app.main import app
        from backend.app.store import store

        client = TestClient(app)
        workspace = next(iter(store.workspaces.values()))

        upload_response = client.post(
            "/uploads/direct",
            data={
                "workspace_id": str(workspace.id),
                "file_name": "idempotency/source.txt",
                "source_type": "files",
            },
            files={
                "file": (
                    "source.txt",
                    b"Daily note: benign upload completion idempotency evidence.",
                    "text/plain",
                )
            },
        )
        upload_payload = upload_response.json()
        upload_id = upload_payload.get("upload", {}).get("id") if upload_response.status_code == 201 else None
        file_id = upload_payload.get("file", {}).get("id") if upload_response.status_code == 201 else None
        checks.append(
            assert_check(
                "Initial direct upload created one completion job",
                upload_response.status_code == 201
                and upload_id is not None
                and file_id is not None
                and len(jobs_for_upload(store, upload_id)) == 1,
                response_detail(upload_response),
            )
        )

        duplicate_response = (
            client.post(f"/uploads/{upload_id}/complete", json={"file_ids": [file_id, file_id]})
            if upload_id and file_id
            else None
        )
        store.refresh()
        duplicate_events = [
            event
            for event in store.audit_logs
            if event.action == "upload.complete_duplicate_file"
            and upload_id is not None
            and str(event.resource_id) == upload_id
        ]
        checks.append(
            assert_check(
                "Duplicate file IDs reuse the existing job",
                duplicate_response is not None
                and duplicate_response.status_code == 200
                and duplicate_response.json().get("status") == "processing"
                and len(jobs_for_upload(store, upload_id)) == 1,
                response_detail(duplicate_response) if duplicate_response is not None else "upload was not created",
            )
        )
        checks.append(
            assert_check(
                "Duplicate completion is audited with redacted file ID",
                len(duplicate_events) == 1 and redacted_fingerprint(duplicate_events[0].metadata.get("file_id")),
                [event.metadata for event in duplicate_events],
            )
        )

        processed = store.process_queued_jobs()
        store.refresh()
        completed_upload = store.uploads.get(UUID(upload_id)) if upload_id else None
        checks.append(
            assert_check(
                "Original queued job processes once",
                processed == 1
                and len(jobs_for_upload(store, upload_id)) == 1
                and completed_upload is not None
                and completed_upload.status.value == "complete",
                {
                    "processed": processed,
                    "jobs": len(jobs_for_upload(store, upload_id)),
                    "status": completed_upload.status.value if completed_upload else None,
                },
            )
        )

        repeat_response = (
            client.post(f"/uploads/{upload_id}/complete", json={"file_ids": [file_id]}) if upload_id and file_id else None
        )
        store.refresh()
        repeat_upload = store.uploads.get(UUID(upload_id)) if upload_id else None
        checks.append(
            assert_check(
                "Repeating complete after processing stays complete",
                repeat_response is not None
                and repeat_response.status_code == 200
                and repeat_response.json().get("status") == "complete"
                and len(jobs_for_upload(store, upload_id)) == 1
                and repeat_upload is not None
                and repeat_upload.status.value == "complete",
                response_detail(repeat_response) if repeat_response is not None else "upload was not created",
            )
        )

        integrity = store.audit_integrity_status()
        checks.append(
            assert_check(
                "Upload idempotency audit chain sealed",
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
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Upload Idempotency Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "upload-idempotency-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Upload Idempotency Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client upload idempotency guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")


def jobs_for_upload(store, upload_id: str | None) -> list:
    if upload_id is None:
        return []
    return [job for job in store.jobs.values() if str(job.upload_id) == upload_id]


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
