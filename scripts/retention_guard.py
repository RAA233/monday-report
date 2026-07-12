from __future__ import annotations

import os
import sys
import tempfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-retention-") as tmp:
        configure_guard_env(Path(tmp))

        from backend.app.main import app
        from backend.app.schemas import MondayReportCreate
        from backend.app.store import store

        client = TestClient(app)
        workspace = next(iter(store.workspaces.values()))
        old_upload, old_file, _ = store.create_uploaded_file(
            workspace_id=workspace.id,
            file_name="expired/ddr.txt",
            mime_type="text/plain",
            source_type="files",
            content=b"MWD signal loss. npt_hours 2026-07-06,Anonymized Directional Services,MWD signal loss,8.5",
        )
        old_upload = store.complete_upload(old_upload.id, [old_file.id])
        store.process_queued_jobs()
        old_report = store.create_monday_report(
            MondayReportCreate(
                workspace_id=workspace.id,
                period_start=date(2026, 7, 6),
                period_end=date(2026, 7, 12),
            )
        )
        old_export = store.export_monday_report(old_report.id, "json")
        new_upload, new_file, _ = store.create_uploaded_file(
            workspace_id=workspace.id,
            file_name="fresh/ddr.txt",
            mime_type="text/plain",
            source_type="files",
            content=b"Fresh client source evidence",
        )
        old_storage_path = store.file_path_from_uri(old_file.storage_uri)
        old_export_path = store.export_path_from_uri(old_export.storage_uri)
        age_expired_records(store, old_upload.id, old_report.id, old_export.id)
        store.save()

        dry_run = client.post("/retention/run")
        dry_payload = dry_run.json()
        checks.append(
            assert_check(
                "Retention dry-run finds expired artifacts",
                dry_run.status_code == 200
                and dry_payload.get("mode") == "dry_run"
                and dry_payload.get("uploads", 0) >= 1
                and dry_payload.get("report_exports", 0) >= 1,
                dry_payload,
            )
        )
        checks.append(
            assert_check(
                "Retention dry-run preserves files",
                old_storage_path is not None
                and old_storage_path.exists()
                and old_export_path is not None
                and old_export_path.exists(),
                {"storage": str(old_storage_path), "export": str(old_export_path)},
            )
        )

        applied = client.post("/retention/run?apply=true")
        apply_payload = applied.json()
        store.refresh()
        checks.append(
            assert_check(
                "Retention apply removes expired records",
                applied.status_code == 200
                and apply_payload.get("mode") == "applied"
                and old_upload.id not in store.uploads
                and old_file.id not in store.files
                and old_report.id not in store.monday_reports
                and old_export.id not in store.report_exports,
                apply_payload,
            )
        )
        checks.append(
            assert_check(
                "Retention apply removes expired files only",
                old_storage_path is not None
                and not old_storage_path.exists()
                and old_export_path is not None
                and not old_export_path.exists()
                and new_upload.id in store.uploads
                and new_file.id in store.files,
                {"new_upload": str(new_upload.id), "new_file": str(new_file.id)},
            )
        )
        checks.append(
            assert_check(
                "Retention apply audited",
                any(event.action == "retention.apply" for event in store.audit_logs),
                f"{len(store.audit_logs)} audit event(s)",
            )
        )
        integrity = store.audit_integrity_status()
        checks.append(
            assert_check(
                "Retention audit chain remains sealed",
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
    os.environ["MONDAY_REPORT_RETENTION_DAYS"] = "1"
    os.environ["MONDAY_REPORT_DISABLE_DEMO_SEED"] = "true"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Retention Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "retention-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Retention Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client retention guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")


def age_expired_records(store, upload_id, report_id, export_id) -> None:
    expired_at = datetime.now(timezone.utc) - timedelta(days=5)
    store.uploads[upload_id].created_at = expired_at
    store.monday_reports[report_id].created_at = expired_at
    store.report_exports[export_id].created_at = expired_at
    for job in store.jobs.values():
        if job.upload_id == upload_id:
            job.created_at = expired_at
    for document in store.parsed_documents.values():
        if document.upload_id == upload_id:
            document.created_at = expired_at
    for chunk in store.document_chunks.values():
        if chunk.upload_id == upload_id:
            chunk.created_at = expired_at


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
