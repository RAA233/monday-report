from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-draft-") as tmp:
        configure_guard_env(Path(tmp))

        from backend.app.main import report_draft
        from backend.app.schemas import (
            Citation,
            DocumentChunk,
            FailureRecord,
            ParsedDocument,
            ProcessingStatus,
            ValidationStatus,
            ValidationTask,
        )
        from backend.app.store import store

        workspace = next(iter(store.workspaces.values()))
        upload_id = uuid4()
        file_id = uuid4()
        document_id = uuid4()
        document = ParsedDocument(
            id=document_id,
            tenant_id=store.tenant.id,
            workspace_id=workspace.id,
            upload_id=upload_id,
            file_id=file_id,
            title="FORGE 16A(78)-32 Daily Drilling Report",
            parser_name="guard_parser",
            status=ProcessingStatus.COMPLETE,
            text_preview="12.25 in hole section drilling ahead. MD 8620 ft. TVD 7980 ft. Mud weight 10.2 ppg.",
            chunk_count=3,
            metadata={"guard": "report_draft"},
        )
        store.parsed_documents[document.id] = document
        chunks = [
            "12.25 in hole section drilling ahead at MD 8620 ft and TVD 7980 ft with 10.2 ppg mud.",
            "MWD signal loss created non-productive time while drilling ahead.",
            "Casing shoe readiness and cementing dependencies require supervisor confirmation.",
        ]
        for ordinal, text in enumerate(chunks, start=1):
            chunk = DocumentChunk(
                tenant_id=store.tenant.id,
                workspace_id=workspace.id,
                upload_id=upload_id,
                file_id=file_id,
                document_id=document.id,
                ordinal=ordinal,
                text=text,
                locator_type="pdf",
                locator={"page": ordinal, "file_path": "FORGE_16A_DDR.pdf"},
                confidence=0.91,
            )
            store.document_chunks[chunk.id] = chunk

        citation = Citation(
            file_id=file_id,
            locator_type="pdf",
            locator={"page": 2, "file_path": "FORGE_16A_DDR.pdf"},
            snippet="MWD signal loss created non-productive time while drilling ahead.",
            confidence=0.93,
        )
        failure = FailureRecord(
            tenant_id=store.tenant.id,
            workspace_id=workspace.id,
            event_type="MWD signal loss",
            severity="High",
            summary="MWD signal loss caused NPT while drilling ahead.",
            company="Anonymized Directional Services",
            tool_type="MWD",
            tool_serial="MWD-042",
            npt_hours=8.5,
            confidence=0.93,
            validation_status=ValidationStatus.OPEN,
            citations=[citation],
        )
        task = ValidationTask(
            tenant_id=store.tenant.id,
            target_type="failure",
            target_id=failure.id,
            reason="Report draft guard validation task.",
            priority="high",
            status=ValidationStatus.OPEN,
        )
        store.failures[failure.id] = failure
        store.validation_tasks[task.id] = task
        store.save()

        draft = report_draft(workspace.id)
        payload = draft.model_dump(mode="json")

        checks.append(
            assert_check(
                "Form-ready fields",
                draft.report_no.startswith("MR-SRC-")
                and draft.well
                and draft.rig
                and "Source-backed review" in draft.present_ops
                and "Normalize the latest source reports" in draft.next_ops
                and "Surface | 13.375 in" in draft.casing_program
                and "00:00-06:00" in draft.operations_log,
                payload,
            )
        )
        checks.append(
            assert_check(
                "Evidence counts and hints",
                draft.source_document_count == 1
                and draft.source_chunk_count == 3
                and draft.failure_count == 1
                and draft.open_validation_tasks == 1
                and draft.citation_count >= 1
                and draft.hole_size == "12.25 in"
                and draft.md_ft == "8620"
                and draft.tvd_ft == "7980"
                and draft.mud_weight == "10.2 ppg",
                payload,
            )
        )
        checks.append(
            assert_check(
                "Validation and citations",
                draft.validation_gate == "review_required"
                and len(draft.citations) >= 1
                and any("client-mode" in note.lower() for note in draft.confidence_notes),
                payload,
            )
        )
        store.refresh()
        checks.append(
            assert_check(
                "Audit event",
                any(log.action == "report_draft.generate" and log.resource_id == workspace.id for log in store.audit_logs),
                [log.action for log in store.audit_logs[-5:]],
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
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Report Draft Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "report-draft-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Report Draft Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Evidence draft guard workspace"
    os.environ["MONDAY_REPORT_DEFAULT_ASSET"] = "FORGE 16A(78)-32"
    os.environ["MONDAY_REPORT_DEFAULT_CAMPAIGN"] = "Drilling morning report"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")
    for key in [
        "MONDAY_REPORT_API_KEY",
        "VITE_MONDAY_REPORT_API_KEY",
        "MONDAY_REPORT_SIGNING_SECRET",
        "MONDAY_REPORT_REPOSITORY_BACKEND",
        "MONDAY_REPORT_DATABASE_URL",
        "DATABASE_URL",
        "MONDAY_REPORT_QUEUE_BACKEND",
        "MONDAY_REPORT_REDIS_URL",
        "REDIS_URL",
    ]:
        os.environ.pop(key, None)


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
