from __future__ import annotations

import os
import re
import sys
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path
from urllib.parse import urlparse
from uuid import UUID

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

UNSAFE_URI_PARTS = re.compile(r'[<>:"|?*\\]')


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-storage-path-") as tmp:
        tmp_root = Path(tmp)
        configure_guard_env(tmp_root)

        from backend.app.main import app
        from backend.app.store import store

        client = TestClient(app)
        workspace = next(iter(store.workspaces.values()))

        metadata_upload = client.post(
            "/uploads",
            json={
                "workspace_id": str(workspace.id),
                "file_name": "..\\..\\escape\\NUL.txt",
                "byte_size": 31,
                "mime_type": "text/plain",
                "source_type": "files",
            },
        )
        metadata_payload = metadata_upload.json()
        metadata_upload_id = metadata_payload.get("upload", {}).get("id") if metadata_upload.status_code == 201 else None
        metadata_file_id = metadata_payload.get("file", {}).get("id") if metadata_upload.status_code == 201 else None
        checks.append(
            assert_check(
                "Traversal metadata upload accepted safely",
                metadata_upload.status_code == 201 and metadata_upload_id is not None and metadata_file_id is not None,
                response_detail(metadata_upload),
            )
        )

        store.refresh()
        metadata_file = store.files.get(UUID(metadata_file_id)) if metadata_file_id else None
        checks.append(
            assert_check(
                "Metadata upload URI parts are sanitized",
                metadata_file is not None
                and safe_object_uri(metadata_file.storage_uri)
                and "_NUL.txt" in metadata_file.storage_uri,
                metadata_file.storage_uri if metadata_file else None,
            )
        )

        metadata_complete = (
            client.post(f"/uploads/{metadata_upload_id}/complete", json={"file_ids": [metadata_file_id]})
            if metadata_upload_id and metadata_file_id
            else None
        )
        store.refresh()
        metadata_jobs = [
            job for job in store.jobs.values() if metadata_upload_id and str(job.upload_id) == metadata_upload_id
        ]
        missing_storage_events = [
            event
            for event in store.audit_logs
            if event.action == "upload_file.missing_storage"
            and metadata_file_id is not None
            and str(event.resource_id) == metadata_file_id
        ]
        checks.append(
            assert_check(
                "Metadata-only upload fails closed without stored bytes",
                metadata_complete is not None
                and metadata_complete.status_code == 200
                and metadata_complete.json().get("status") == "failed",
                response_detail(metadata_complete) if metadata_complete is not None else "metadata upload was not created",
            )
        )
        checks.append(
            assert_check(
                "Missing metadata storage is audited without jobs",
                len(metadata_jobs) == 0 and len(missing_storage_events) == 1,
                {"jobs": len(metadata_jobs), "missing_storage_events": len(missing_storage_events)},
            )
        )

        direct_upload = client.post(
            "/uploads/direct",
            data={
                "workspace_id": str(workspace.id),
                "file_name": "..\\..\\escape\\CON.txt",
                "source_type": "files",
            },
            files={"file": ("CON.txt", b"direct path boundary evidence", "text/plain")},
        )
        direct_payload = direct_upload.json()
        direct_file_id = direct_payload["file"]["id"] if direct_upload.status_code == 201 else None
        checks.append(
            assert_check(
                "Traversal direct upload accepted safely",
                direct_upload.status_code == 201 and direct_file_id is not None,
                response_detail(direct_upload),
            )
        )

        store.refresh()
        direct_file = store.files.get(UUID(direct_file_id)) if direct_file_id else None
        direct_path = store.file_path_from_uri(direct_file.storage_uri) if direct_file else None
        checks.append(
            assert_check(
                "Direct upload path stays under storage root",
                direct_file is not None
                and direct_path is not None
                and direct_path.exists()
                and path_is_within(direct_path, store.storage_root)
                and direct_path.read_bytes() == b"direct path boundary evidence",
                {"storage_uri": direct_file.storage_uri if direct_file else None, "path": str(direct_path)},
            )
        )
        checks.append(
            assert_check(
                "Direct upload URI parts are sanitized",
                direct_file is not None and safe_object_uri(direct_file.storage_uri) and "_CON.txt" in direct_file.storage_uri,
                direct_file.storage_uri if direct_file else None,
            )
        )

        signed_response = client.post(f"/upload-files/{direct_file_id}/signed-url")
        signed_download = signed_download_content(client, signed_response)
        checks.append(
            assert_check(
                "Sanitized direct upload downloads through signed URL",
                signed_download == b"direct path boundary evidence",
                f"bytes={len(signed_download or b'')}",
            )
        )

        zip_upload = client.post(
            "/uploads/direct",
            data={
                "workspace_id": str(workspace.id),
                "file_name": "unsafe/client_package.zip",
                "source_type": "zip",
            },
            files={"file": ("client_package.zip", build_unsafe_zip(), "application/zip")},
        )
        zip_upload_id = zip_upload.json()["upload"]["id"] if zip_upload.status_code == 201 else None
        checks.append(
            assert_check(
                "Traversal ZIP upload accepted before expansion",
                zip_upload.status_code == 201 and zip_upload_id is not None,
                response_detail(zip_upload),
            )
        )

        processed = store.process_queued_jobs()
        store.refresh()
        object_files = [
            file_record
            for file_record in store.files.values()
            if str(file_record.upload_id) == zip_upload_id and file_record.storage_uri.startswith("object://")
        ]
        object_paths = [store.file_path_from_uri(file_record.storage_uri) for file_record in object_files]
        checks.append(
            assert_check(
                "ZIP child paths stay under storage root",
                processed >= 1
                and len(object_files) >= 4
                and all(path is not None and path.exists() and path_is_within(path, store.storage_root) for path in object_paths),
                f"processed={processed} object_files={len(object_files)}",
            )
        )
        checks.append(
            assert_check(
                "ZIP child URI parts are sanitized",
                object_files
                and all(safe_object_uri(file_record.storage_uri) for file_record in object_files)
                and any("_NUL.txt" in file_record.storage_uri for file_record in object_files),
                [file_record.storage_uri for file_record in object_files],
            )
        )

        integrity = store.audit_integrity_status()
        checks.append(
            assert_check(
                "Storage path guard audit chain sealed",
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
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Storage Path Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "storage-path-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Storage Path Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client storage path guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")


def build_unsafe_zip() -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../../escape/NUL.txt", b"reserved name should stay in tenant storage")
        archive.writestr("C:\\absolute\\tool.log", b"windows absolute-ish path should be sanitized")
        archive.writestr("safe/ddr.txt", b"MWD signal loss. npt_hours 2026-07-06,ABC Directional Services,MWD signal loss,8.5")
    return buffer.getvalue()


def signed_download_content(client: TestClient, signed_response) -> bytes | None:
    if signed_response.status_code != 200:
        return None
    parsed = urlparse(signed_response.json()["url"])
    response = client.get(f"{parsed.path}?{parsed.query}")
    return response.content if response.status_code == 200 else None


def safe_object_uri(storage_uri: str) -> bool:
    if not storage_uri.startswith("object://"):
        return False
    parts = [part for part in storage_uri.removeprefix("object://").split("/") if part]
    return bool(parts) and all(part not in {".", ".."} and not UNSAFE_URI_PARTS.search(part) for part in parts)


def path_is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


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
