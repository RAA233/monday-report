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
            # Survey stations: one clean row plus a same-MD conflict pair.
            "survey_stations": [
                {
                    "measured_depth_ft": 8000.0,
                    "inclination_deg": 20.5,
                    "azimuth_deg": 115.0,
                    "true_vertical_depth_ft": 7600.0,
                    "dogleg_severity_dp100ft": 1.2,
                    "north_south_ft": None,
                    "east_west_ft": None,
                    "station_id": "S-1",
                    "survey_type": None,
                    "page": 1,
                    "confidence": 0.8,
                    "conflict": False,
                },
                {
                    "measured_depth_ft": 8500.0,
                    "inclination_deg": 24.5,
                    "azimuth_deg": 118.2,
                    "true_vertical_depth_ft": 7900.0,
                    "dogleg_severity_dp100ft": 1.8,
                    "north_south_ft": None,
                    "east_west_ft": None,
                    "station_id": "S-2",
                    "survey_type": None,
                    "page": 1,
                    "confidence": 0.5,
                    "conflict": True,
                },
                {
                    "measured_depth_ft": 8500.0,
                    "inclination_deg": 25.1,
                    "azimuth_deg": 119.0,
                    "true_vertical_depth_ft": None,
                    "dogleg_severity_dp100ft": None,
                    "north_south_ft": None,
                    "east_west_ft": None,
                    "station_id": "S-3",
                    "survey_type": None,
                    "page": 2,
                    "confidence": 0.5,
                    "conflict": True,
                },
                # Contiguous eligible pair after the conflict block: drives one
                # calculated minimum-curvature interval in a second segment with
                # a source-TVD anchor (mixed coordinate reference) and a
                # deliberate source-vs-calculated TVD disagreement at 9400 ft.
                {
                    "measured_depth_ft": 9000.0,
                    "inclination_deg": 27.0,
                    "azimuth_deg": 120.0,
                    "true_vertical_depth_ft": 8500.0,
                    "dogleg_severity_dp100ft": None,
                    "north_south_ft": None,
                    "east_west_ft": None,
                    "station_id": "S-4",
                    "survey_type": None,
                    "page": 2,
                    "confidence": 0.85,
                    "conflict": False,
                },
                {
                    "measured_depth_ft": 9400.0,
                    "inclination_deg": 29.0,
                    "azimuth_deg": 121.0,
                    "true_vertical_depth_ft": 8880.0,
                    "dogleg_severity_dp100ft": None,
                    "north_south_ft": None,
                    "east_west_ft": None,
                    "station_id": "S-5",
                    "survey_type": None,
                    "page": 2,
                    "confidence": 0.9,
                    "conflict": False,
                },
            ],
            "survey_truncated": False,
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
        checks.append(
            assert_check(
                "Source-backed survey stations carry page/confidence provenance",
                draft.survey_source == "source"
                and len(draft.survey_stations) == 5
                and all(row.source == "source" for row in draft.survey_stations)
                and all(row.page is not None for row in draft.survey_stations)
                and all(row.confidence is not None for row in draft.survey_stations)
                and any(
                    row.measured_depth_ft == 8000.0
                    and row.inclination_deg == 20.5
                    and row.true_vertical_depth_ft == 7600.0
                    and row.conflict is False
                    for row in draft.survey_stations
                ),
                payload,
            )
        )
        trajectory = draft.trajectory
        checks.append(
            assert_check(
                "Trajectory calculation derives one interval with calculated provenance",
                draft.trajectory_source == "calculated"
                and trajectory is not None
                and trajectory.method == "minimum_curvature"
                and trajectory.method_version == "v1"
                and trajectory.review_state == "review_required"
                and trajectory.interval_count == 1
                and trajectory.segment_count == 1
                and trajectory.eligible_station_count == 3
                and trajectory.skips.conflict == 2
                and trajectory.input_confidence_min == 0.85
                and trajectory.intervals[0].md_start_ft == 9000.0
                and trajectory.intervals[0].md_end_ft == 9400.0
                and trajectory.intervals[0].source == "calculated"
                and abs(trajectory.intervals[0].dls_deg_per_100ft - 0.51) < 0.05
                and abs(trajectory.intervals[0].delta_tvd_ft - 353.16) < 0.5,
                trajectory.model_dump(mode="json") if trajectory else None,
            )
        )
        checks.append(
            assert_check(
                "Trajectory never bridges the conflict block (no 8000->9000 interval)",
                trajectory is not None
                and all(interval.md_start_ft >= 9000.0 for interval in trajectory.intervals),
                [interval.model_dump(mode="json") for interval in trajectory.intervals] if trajectory else None,
            )
        )
        checks.append(
            assert_check(
                "Trajectory anchor uses source TVD with relative N/S and E/W (mixed reference)",
                trajectory is not None
                and trajectory.coordinate_reference.tvd == "source_absolute"
                and trajectory.coordinate_reference.north_south == "relative_first_station"
                and trajectory.coordinate_reference.east_west == "relative_first_station"
                and trajectory.anchor is not None
                and trajectory.anchor.measured_depth_ft == 9000.0
                and trajectory.anchor.tvd_ft == 8500.0
                and trajectory.stations[0].tvd_ft == 8500.0
                and trajectory.stations[0].north_south_ft == 0.0
                # Explicit segment/survey-type identity for visualization consumers.
                and all(item.segment >= 1 and item.survey_type is None for item in trajectory.stations),
                trajectory.anchor.model_dump(mode="json") if trajectory and trajectory.anchor else None,
            )
        )
        source_9400 = next(row for row in draft.survey_stations if row.measured_depth_ft == 9400.0)
        calc_9400 = next(item for item in trajectory.stations if item.measured_depth_ft == 9400.0)
        checks.append(
            assert_check(
                "Source and calculated TVD disagree side-by-side without overwrite",
                source_9400.true_vertical_depth_ft == 8880.0
                and abs(calc_9400.tvd_ft - 8853.2) < 1.0
                and abs(calc_9400.tvd_ft - source_9400.true_vertical_depth_ft) > 20.0,
                {"source_tvd": source_9400.true_vertical_depth_ft, "calculated_tvd": calc_9400.tvd_ft},
            )
        )
        conflict_stations = [row for row in draft.survey_stations if row.conflict]
        checks.append(
            assert_check(
                "Conflicting same-MD survey rows stay visible with reduced confidence",
                len(conflict_stations) == 2
                and {row.inclination_deg for row in conflict_stations} == {24.5, 25.1}
                and all(row.confidence is not None and row.confidence <= 0.5 for row in conflict_stations)
                # Missing engineering values are never back-filled.
                and any(row.true_vertical_depth_ft is None for row in conflict_stations),
                [row.model_dump(mode="json") for row in conflict_stations],
            )
        )

        from datetime import date

        from backend.app.schemas import MondayReportCreate

        report = store.create_monday_report(
            MondayReportCreate(
                workspace_id=workspace.id,
                period_start=date(2026, 7, 13),
                period_end=date(2026, 7, 19),
            )
        )
        report_survey = report.report_json.get("morning_report", {}).get("survey_stations", [])
        checks.append(
            assert_check(
                "Monday Report JSON survey rows match the report draft exactly",
                report.report_json.get("morning_report", {}).get("survey_source") == "source"
                and [row.get("measured_depth_ft") for row in report_survey]
                == [row.measured_depth_ft for row in draft.survey_stations]
                and [row.get("inclination_deg") for row in report_survey]
                == [row.inclination_deg for row in draft.survey_stations]
                and [bool(row.get("conflict")) for row in report_survey]
                == [row.conflict for row in draft.survey_stations],
                report_survey,
            )
        )
        report_trajectory = report.report_json.get("morning_report", {}).get("trajectory_calculation")
        checks.append(
            assert_check(
                "Monday Report JSON trajectory block matches the report draft exactly",
                report.report_json.get("morning_report", {}).get("trajectory_source") == "calculated"
                and trajectory is not None
                and report_trajectory == trajectory.model_dump(mode="json"),
                report_trajectory,
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
                and not any(seg.source == "source" for seg in reference_draft.activity_timeline)
                and reference_draft.survey_stations == [],
                reference_payload,
            )
        )
        checks.append(
            assert_check(
                "No survey evidence yields an empty list, never fabricated stations",
                reference_draft.survey_source == "none" and reference_draft.survey_stations == [],
                reference_payload,
            )
        )
        checks.append(
            assert_check(
                "No survey evidence yields no trajectory calculation",
                reference_draft.trajectory is None and reference_draft.trajectory_source == "none",
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
                and source_audit.metadata.get("survey_source") == "source"
                and int(source_audit.metadata.get("survey_source_rows", 0)) == 5
                and int(source_audit.metadata.get("survey_conflict_rows", 0)) == 2
                and source_audit.metadata.get("survey_truncated") is False
                and source_audit.metadata.get("trajectory_source") == "calculated"
                and source_audit.metadata.get("trajectory_method") == "minimum_curvature v1"
                and source_audit.metadata.get("trajectory_review_state") == "review_required"
                and int(source_audit.metadata.get("trajectory_intervals", 0)) == 1
                and int(source_audit.metadata.get("trajectory_segments", 0)) == 1
                and "tvd:source_absolute" in str(source_audit.metadata.get("trajectory_reference"))
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
                and int(reference_audit.metadata.get("casing_reference_rows", 0)) == 4
                and reference_audit.metadata.get("survey_source") == "none"
                and int(reference_audit.metadata.get("survey_source_rows", 0)) == 0
                and reference_audit.metadata.get("trajectory_source") == "none"
                and int(reference_audit.metadata.get("trajectory_intervals", 0)) == 0,
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
