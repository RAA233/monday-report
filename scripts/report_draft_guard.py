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
            Workspace,
        )
        from backend.app.store import store

        workspace = next(iter(store.workspaces.values()))
        upload_id = uuid4()
        file_id = uuid4()
        document_id = uuid4()
        # Source profile with two casing strings, a conflicting third Surface depth,
        # and two timed activity rows. Scalar fields are left empty so the existing
        # scalar-hint assertions continue to exercise the chunk-hint path.
        report_profile = {
            "profile_version": "pdf_report_profile_v1",
            "document_type": "daily_drilling_report",
            "confidence": 0.9,
            "field_count": 0,
            "section_count": 0,
            "fields": {},
            "sections": {},
            "casing_strings": [
                {"name": "Surface", "od": "13.375 in", "top_ft": None, "shoe_ft": 1629.0, "status": "set", "page": 1, "confidence": 0.95},
                {"name": "Intermediate", "od": "9.625 in", "top_ft": None, "shoe_ft": 6500.0, "status": "planned", "page": 1, "confidence": 0.9},
                {"name": "Surface", "od": "13.375 in", "top_ft": None, "shoe_ft": 1705.0, "status": "reported", "page": 2, "confidence": 0.7},
            ],
            "activity_timeline": [
                {"time": "00:00-06:00", "activity": "Drill ahead 12.25 in section.", "page": 1, "confidence": 0.82},
                {"time": "06:00-12:00", "activity": "Circulate bottoms up and survey.", "page": 1, "confidence": 0.82},
            ],
        }
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
            metadata={"guard": "report_draft", "parser": {"report_profile": report_profile}},
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
        reference_workspace = Workspace(
            tenant_id=store.tenant.id,
            name="Reference-only guard workspace",
            asset="No-evidence asset",
            campaign="Reference fallback",
        )
        store.workspaces[reference_workspace.id] = reference_workspace
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
                and "Normalize the latest source reports" in draft.next_ops,
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
        checks.append(
            assert_check(
                "Source-backed casing rows carry page/confidence provenance",
                draft.schematic_source == "source"
                and len(draft.casing_strings) >= 2
                and all(row.source == "source" for row in draft.casing_strings)
                and any(
                    row.name == "Surface"
                    and row.od == "13.375 in"
                    and row.shoe_ft == 1629.0
                    and row.page == 1
                    and row.confidence is not None
                    for row in draft.casing_strings
                )
                # Legacy flat string is derived from the same source rows.
                and "Surface | 13.375 in" in draft.casing_program,
                payload,
            )
        )
        checks.append(
            assert_check(
                "Source-backed timeline rows carry provenance",
                len(draft.activity_timeline) >= 2
                and all(seg.source == "source" and seg.page for seg in draft.activity_timeline)
                and "00:00-06:00" in draft.operations_log,
                payload,
            )
        )
        surface_rows = [row for row in draft.casing_strings if row.name == "Surface"]
        checks.append(
            assert_check(
                "Conflicting casing depths are surfaced, not silently merged",
                len(surface_rows) == 2 and {row.shoe_ft for row in surface_rows} == {1629.0, 1705.0},
                [row.model_dump(mode="json") for row in surface_rows],
            )
        )

        reference_draft = report_draft(reference_workspace.id)
        reference_payload = reference_draft.model_dump(mode="json")
        checks.append(
            assert_check(
                "Reference fallback casing rows are labelled and unsourced",
                reference_draft.schematic_source == "reference"
                and len(reference_draft.casing_strings) == 4
                and all(
                    row.source == "reference" and row.page is None and row.confidence is None
                    for row in reference_draft.casing_strings
                )
                and "Surface | 13.375 in" in reference_draft.casing_program,
                reference_payload,
            )
        )
        checks.append(
            assert_check(
                "Reference fallback timeline requires DDR confirmation",
                len(reference_draft.activity_timeline) >= 2
                and all(seg.source == "reference" and seg.page is None for seg in reference_draft.activity_timeline)
                and any("confirm" in note.lower() for note in reference_draft.confidence_notes),
                reference_payload,
            )
        )
        checks.append(
            assert_check(
                "Cross-workspace source rows do not leak into an empty workspace",
                reference_draft.source_document_count == 0
                and not any(row.source == "source" for row in reference_draft.casing_strings)
                and not any(seg.source == "source" for seg in reference_draft.activity_timeline),
                reference_payload,
            )
        )

        store.refresh()
        source_audit = next(
            (
                log
                for log in reversed(store.audit_logs)
                if log.action == "report_draft.generate" and log.resource_id == workspace.id
            ),
            None,
        )
        checks.append(
            assert_check(
                "Audit event records source provenance",
                source_audit is not None
                and source_audit.metadata.get("schematic_source") == "source"
                and int(source_audit.metadata.get("casing_source_rows", 0)) >= 2
                and int(source_audit.metadata.get("timeline_source_rows", 0)) >= 2
                and source_audit.metadata.get("parser_version") == "pdf_report_profile_v1",
                source_audit.metadata if source_audit else None,
            )
        )
        reference_audit = next(
            (
                log
                for log in reversed(store.audit_logs)
                if log.action == "report_draft.generate" and log.resource_id == reference_workspace.id
            ),
            None,
        )
        checks.append(
            assert_check(
                "Audit event records reference provenance",
                reference_audit is not None
                and reference_audit.metadata.get("schematic_source") == "reference"
                and int(reference_audit.metadata.get("casing_reference_rows", 0)) == 4,
                reference_audit.metadata if reference_audit else None,
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
