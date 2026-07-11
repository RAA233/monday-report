from __future__ import annotations

import os
import sys
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-archive-safety-") as tmp:
        configure_guard_env(Path(tmp))

        from backend.app.main import app
        from backend.app.store import store

        client = TestClient(app)
        workspace = next(iter(store.workspaces.values()))

        readiness = client.get("/readiness/client-data").json()
        checks.append(
            assert_check(
                "Archive limits readiness configured",
                readiness_check(readiness, "archive_limits").get("status") == "pass",
                readiness_check(readiness, "archive_limits"),
            )
        )

        too_many_upload_id = upload_zip(
            client,
            str(workspace.id),
            "archive/too_many_entries.zip",
            build_many_entries_zip(3),
        )
        checks.append(
            assert_check(
                "Too-many-entries ZIP accepted for worker rejection",
                too_many_upload_id is not None,
                too_many_upload_id,
            )
        )
        processed_many = store.process_queued_jobs()
        store.refresh()
        too_many_job = job_for_upload(store, too_many_upload_id)
        checks.append(
            assert_check(
                "Too-many-entries ZIP rejected",
                processed_many == 1
                and too_many_job is not None
                and too_many_job.status.value == "failed"
                and upload_status(store, too_many_upload_id) == "failed"
                and too_many_job.payload.get("result") == "zip_too_many_entries",
                too_many_job.payload if too_many_job else None,
            )
        )
        checks.append(
            assert_check(
                "Too-many-entries ZIP creates no child files",
                child_file_count(store, too_many_upload_id) == 0,
                f"{child_file_count(store, too_many_upload_id)} child file(s)",
            )
        )

        too_large_upload_id = upload_zip(
            client,
            str(workspace.id),
            "archive/too_large.zip",
            build_large_zip(65),
        )
        checks.append(
            assert_check(
                "Too-large ZIP accepted for worker rejection",
                too_large_upload_id is not None,
                too_large_upload_id,
            )
        )
        processed_large = store.process_queued_jobs()
        store.refresh()
        too_large_job = job_for_upload(store, too_large_upload_id)
        checks.append(
            assert_check(
                "Too-large ZIP rejected",
                processed_large == 1
                and too_large_job is not None
                and too_large_job.status.value == "failed"
                and upload_status(store, too_large_upload_id) == "failed"
                and too_large_job.payload.get("result") == "zip_too_large",
                too_large_job.payload if too_large_job else None,
            )
        )
        checks.append(
            assert_check(
                "Too-large ZIP creates no child files",
                child_file_count(store, too_large_upload_id) == 0,
                f"{child_file_count(store, too_large_upload_id)} child file(s)",
            )
        )

        rejected_events = [event for event in store.audit_logs if event.action == "archive.rejected"]
        rejected_reasons = {event.metadata.get("reason") for event in rejected_events}
        failed_upload_events = [event for event in store.audit_logs if event.action == "upload.processing_failed"]
        checks.append(
            assert_check(
                "Archive rejections audited",
                {"zip_too_many_entries", "zip_too_large"}.issubset(rejected_reasons),
                f"{len(rejected_events)} archive rejection event(s): {sorted(str(item) for item in rejected_reasons)}",
            )
        )
        checks.append(
            assert_check(
                "Archive upload failures audited",
                len(failed_upload_events) == 2,
                f"{len(failed_upload_events)} failed upload event(s)",
            )
        )

        integrity = store.audit_integrity_status()
        checks.append(
            assert_check(
                "Archive safety audit chain sealed",
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
    os.environ["MONDAY_REPORT_MAX_ZIP_ENTRIES"] = "2"
    os.environ["MONDAY_REPORT_MAX_ZIP_UNCOMPRESSED_BYTES"] = "64"
    os.environ["MONDAY_REPORT_DISABLE_DEMO_SEED"] = "true"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Archive Safety Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "archive-safety-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Archive Safety Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client archive safety guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")


def upload_zip(client: TestClient, workspace_id: str, file_name: str, content: bytes) -> str | None:
    response = client.post(
        "/uploads/direct",
        data={
            "workspace_id": workspace_id,
            "file_name": file_name,
            "source_type": "zip",
        },
        files={"file": (Path(file_name).name, content, "application/zip")},
    )
    if response.status_code != 201:
        return None
    return response.json()["upload"]["id"]


def build_many_entries_zip(entry_count: int) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for index in range(entry_count):
            archive.writestr(f"reports/entry_{index}.txt", "safe evidence")
    return buffer.getvalue()


def build_large_zip(byte_count: int) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("reports/large.txt", b"x" * byte_count)
    return buffer.getvalue()


def readiness_check(payload: dict, check_id: str) -> dict:
    for check in payload.get("checks", []):
        if check.get("id") == check_id:
            return check
    return {}


def job_for_upload(store, upload_id: str | None):
    if upload_id is None:
        return None
    for job in store.jobs.values():
        if str(job.upload_id) == upload_id:
            return job
    return None


def upload_status(store, upload_id: str | None) -> str | None:
    if upload_id is None:
        return None
    for upload in store.uploads.values():
        if str(upload.id) == upload_id:
            return upload.status.value
    return None


def child_file_count(store, upload_id: str | None) -> int:
    if upload_id is None:
        return 0
    return sum(
        1
        for file_record in store.files.values()
        if str(file_record.upload_id) == upload_id and "/extracted/" in file_record.storage_uri
    )


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
