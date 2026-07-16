"""Behavioral guard for source-derived hydraulics observation extraction.

Exercises the deterministic_hydraulics v1 parser end-to-end (PDF upload ->
profile rows -> cited chunks -> report draft -> Monday Report JSON) plus pure
extraction vectors for unit conversion, context-aware conflicts, review flags,
rejection rules, determinism, truncation, and the recommended-only boundary
for Hydraulics/Torque & Drag diagnostics and Benchmarking.
"""
from __future__ import annotations

import copy
import os
import sys
import tempfile
from datetime import date
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    checks: list[dict[str, object]] = []

    def check(name: str, ok: bool, detail: object) -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    with tempfile.TemporaryDirectory(prefix="monday-report-hydraulics-") as tmp:
        configure_guard_env(Path(tmp))

        from backend.app.main import app
        from backend.app.schemas import MondayReportCreate, Workspace
        from backend.app.store import LocalStateStore, store

        # ---------- Pure extraction vectors ----------
        lines = [
            (1, "06:00 Flow Rate: 650 gpm, SPP: 3,200 psi"),
            (1, "06:00 Pump 2 flow rate: 2,460 L/min"),
            (1, "Planned flow rate: 700 gpm"),
            (1, "12:00 Standpipe Pressure: 22,000 kPa"),
            (1, "Mud Weight: 10.2 ppg"),
            (1, "Kill mud weight: 1.50 sg"),
            (1, "ECD: 10.6 ppg"),
            (1, "PV: 18 cP, YP: 22 lbf/100ft2"),
            (1, "Pump rate: 120 spm"),
            (1, "Nozzles: 3 x 12/32 in"),
            (1, "MW 1.15"),
            (1, "Flow rate: -5 gpm"),
            (2, "SPP: 99,999 psi"),
            (1, "06:00 Flow Rate: 655 gpm"),
            (1, "06:00 Flow Rate: 655 gpm"),
        ]
        rows, truncated = LocalStateStore._extract_hydraulics_observations(copy.deepcopy(lines), [])

        def rows_for(measurement: str) -> list[dict]:
            return [row for row in rows if row["measurement"] == measurement]

        check(
            "Narrative extraction with multiple labelled values per line",
            len(rows) == 14
            and truncated is False
            and len(rows_for("flow_rate")) == 4
            and len(rows_for("standpipe_pressure")) == 3,
            {"rows": len(rows)},
        )
        kpa = next((row for row in rows_for("standpipe_pressure") if row["source_unit"] == "kpa"), None)
        lpm = next((row for row in rows_for("flow_rate") if "l/min" in str(row["source_unit"])), None)
        sg = next((row for row in rows_for("mud_weight") if row["source_unit"] == "sg"), None)
        check(
            "Explicit conversions: kPa->psi, L/min->gpm, sg->ppg with source values retained",
            kpa is not None
            and abs(kpa["value"] - 3190.83) < 0.02
            and kpa["unit"] == "psi"
            and kpa["source_value_text"] == "22,000 kpa"
            and lpm is not None
            and abs(lpm["value"] - 649.86) < 0.02
            and sg is not None
            and abs(sg["value"] - 12.52) < 0.01
            and sg["fluid_system_label"] == "kill mud",
            {"kpa": kpa, "lpm": lpm, "sg": sg},
        )
        check(
            "Ambiguous 'MW 1.15' and negative flow are never emitted or converted",
            not any(row["source_value_text"].startswith("1.15") for row in rows_for("mud_weight"))
            and not any((row.get("value") or 0) < 0 for row in rows),
            [row["source_value_text"] for row in rows_for("mud_weight")],
        )
        same_context_flow = [
            row for row in rows_for("flow_rate") if row["activity_time"] == "06:00" and row["equipment_label"] is None
        ]
        pump2 = next((row for row in rows_for("flow_rate") if row["equipment_label"] == "Pump 2"), None)
        planned = next((row for row in rows_for("flow_rate") if row["observation_status"] == "planned"), None)
        check(
            "Same-context values conflict; different pump, fluid system, and planned status never do",
            len(same_context_flow) == 2
            and all(row["conflict"] for row in same_context_flow)
            and all(row["confidence"] <= 0.5 for row in same_context_flow)
            and pump2 is not None
            and pump2["conflict"] is False
            and planned is not None
            and planned["conflict"] is False
            and sg["conflict"] is False,
            same_context_flow,
        )
        nozzle = rows_for("nozzle_configuration")
        check(
            "Nozzle configuration is text-only with no numeric value or TFA",
            len(nozzle) == 1
            and nozzle[0]["value"] is None
            and nozzle[0]["unit"] is None
            and nozzle[0]["source_value_text"] == "3 x 12/32 in",
            nozzle,
        )
        review = next((row for row in rows_for("standpipe_pressure") if row["review_flag"]), None)
        check(
            "Unusual finite value is retained with a review flag, not discarded",
            review is not None
            and review["value"] == 99999.0
            and review["review_reason"] == "source value requires review",
            review,
        )
        check(
            "Time context is preserved raw and normalized; missing time keeps the row",
            all(row["activity_time"] == "06:00" for row in same_context_flow)
            and all(row["activity_time_source_text"] == "06:00" for row in same_context_flow)
            and next(row for row in rows_for("ecd"))["activity_time"] is None,
            "time handling",
        )
        check(
            "Parser provenance is deterministic_hydraulics v1 on every row",
            all(
                row["parser_method"] == "deterministic_hydraulics" and row["parser_version"] == "v1"
                for row in rows
            ),
            "provenance",
        )
        rerun_rows, _ = LocalStateStore._extract_hydraulics_observations(copy.deepcopy(lines), [])
        check("Repeated extraction is deterministic (duplicates deduped)", rerun_rows == rows, len(rerun_rows))
        table_rows, _ = LocalStateStore._extract_hydraulics_observations(
            [],
            [
                {
                    "page": 2,
                    "rows": [
                        ["Time", "Flow (gpm)", "SPP (psi)"],
                        ["06:00", "645", "3,150"],
                        ["07:00", "660", "3,240"],
                    ],
                }
            ],
        )
        check(
            "Table extraction with header units produces timed observations",
            len(table_rows) == 4
            and all(row["page"] == 2 for row in table_rows)
            and any(row["value"] == 645.0 and row["activity_time"] == "06:00" for row in table_rows),
            table_rows,
        )
        many = [(1, f"{6 + i // 60:02d}:{i % 60:02d} Flow Rate: {600 + i} gpm") for i in range(120)]
        capped, capped_truncated = LocalStateStore._extract_hydraulics_observations(many, [])
        check("Row cap truncates deterministically and records it", len(capped) == 100 and capped_truncated is True, len(capped))
        empty_rows, empty_truncated = LocalStateStore._extract_hydraulics_observations(
            [(1, "General drilling narrative with no labelled hydraulics values.")], []
        )
        check("Unsupported input yields no rows (no fabrication)", empty_rows == [] and empty_truncated is False, empty_rows)

        # ---------- End-to-end: PDF -> chunks -> draft -> JSON ----------
        client = TestClient(app)
        workspace = next(iter(store.workspaces.values()))
        from scripts.pdf_parser_guard import build_pdf_fixture

        pdf_content = build_pdf_fixture(
            [
                "\n".join(
                    [
                        "Daily Drilling Report",
                        "Well: Hydraulics Guard Well",
                        "Mud Weight: 10.2 ppg",
                        "06:00 Flow Rate: 650 gpm, SPP: 3,200 psi",
                        "06:00 Pump 2 flow rate: 2,460 L/min",
                        "Planned flow rate: 700 gpm",
                        "ECD: 10.6 ppg",
                        "Nozzles: 3 x 12/32 in",
                    ]
                )
            ]
        )
        upload_response = client.post(
            "/uploads/direct",
            data={"workspace_id": str(workspace.id), "file_name": "qa/hydraulics_ddr.pdf", "source_type": "files"},
            files={"file": ("hydraulics_ddr.pdf", pdf_content, "application/pdf")},
        )
        check("Hydraulics PDF upload accepted", upload_response.status_code == 201, upload_response.status_code)
        processed = store.process_queued_jobs()
        check("Hydraulics PDF parsed by the worker", processed == 1, processed)

        def diagnostics_snapshot() -> dict[str, list[tuple[str, str]]]:
            return {
                str(event.id): [(str(action.id), action.status) for action in event.diagnostic_actions]
                for event in store.anomaly_events.values()
            }

        diagnostics_before = diagnostics_snapshot()
        measurements_before = len(store.benchmark_measurements)

        draft_response = client.get(f"/workspaces/{workspace.id}/report-draft")
        draft = draft_response.json()
        observations = draft.get("hydraulics_observations", [])
        check(
            "Report draft carries source hydraulics observations with provenance",
            draft_response.status_code == 200
            and draft.get("hydraulics_source") == "source"
            and len(observations) >= 5
            and all(row["source"] == "source" for row in observations)
            and all(row["parser_method"] == "deterministic_hydraulics" for row in observations)
            and all(isinstance(row["page"], int) for row in observations)
            and any(row["measurement"] == "flow_rate" and row["equipment_label"] == "Pump 2" for row in observations)
            and any(row["measurement"] == "nozzle_configuration" and row["value"] is None for row in observations),
            {"count": len(observations), "source": draft.get("hydraulics_source")},
        )
        check(
            "Legacy mud-weight scalar remains intact alongside observations",
            draft.get("mud_weight") == "10.2"
            and any(row["measurement"] == "mud_weight" and row["value"] == 10.2 for row in observations),
            draft.get("mud_weight"),
        )
        document = next(iter(client.get(f"/documents?workspace_id={workspace.id}").json()))
        chunks = client.get(f"/documents/{document['id']}/chunks").json()
        hydraulic_chunks = [
            chunk for chunk in chunks if chunk.get("locator", {}).get("field") == "hydraulic_observation"
        ]
        check(
            "Hydraulics observations become page-cited evidence chunks",
            len(hydraulic_chunks) >= 5
            and all(isinstance(chunk["locator"].get("page"), int) for chunk in hydraulic_chunks)
            and any("Flow Rate" in chunk["text"] for chunk in hydraulic_chunks),
            len(hydraulic_chunks),
        )
        report = store.create_monday_report(
            MondayReportCreate(workspace_id=workspace.id, period_start=date(2026, 7, 13), period_end=date(2026, 7, 19))
        )
        morning = report.report_json.get("morning_report", {})
        check(
            "Monday Report JSON hydraulics block matches the report draft exactly",
            morning.get("hydraulics_source") == "source"
            and morning.get("hydraulics_observations") == observations,
            {"json_rows": len(morning.get("hydraulics_observations", []))},
        )
        diagnostics_after = diagnostics_snapshot()
        check(
            "Recommendation boundary: no DiagnosticAction or Benchmarking coupling",
            diagnostics_after == diagnostics_before
            and len(store.benchmark_measurements) == measurements_before,
            {"diagnostics": len(diagnostics_after), "measurements": len(store.benchmark_measurements)},
        )
        isolated = Workspace(
            tenant_id=store.tenant.id,
            name="Hydraulics isolation workspace",
            asset="No-evidence asset",
            campaign="Isolation",
        )
        store.workspaces[isolated.id] = isolated
        store.save()
        isolated_draft = client.get(f"/workspaces/{isolated.id}/report-draft").json()
        check(
            "Cross-workspace isolation: no hydraulics leakage and honest none state",
            isolated_draft.get("hydraulics_source") == "none"
            and isolated_draft.get("hydraulics_observations") == [],
            isolated_draft.get("hydraulics_source"),
        )
        store.refresh()
        audit = next(
            (
                log
                for log in reversed(store.audit_logs)
                if log.action == "report_draft.generate" and log.resource_id == workspace.id
            ),
            None,
        )
        check(
            "Audit metadata records aggregate hydraulics provenance only",
            audit is not None
            and audit.metadata.get("hydraulics_source") == "source"
            and int(audit.metadata.get("hydraulics_source_rows", 0)) >= 5
            and audit.metadata.get("hydraulics_parser") == "deterministic_hydraulics v1"
            and "650" not in str(audit.metadata),
            audit.metadata if audit else None,
        )

    failed = [item for item in checks if not item["ok"]]
    for item in checks:
        status = "PASS" if item["ok"] else "FAIL"
        print(f"{status}: {item['name']} - {item['detail']}")
    return 1 if failed else 0


def configure_guard_env(tmp_root: Path) -> None:
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
    os.environ["MONDAY_REPORT_DISABLE_DEMO_SEED"] = "true"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Hydraulics Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "hydraulics-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Hydraulics Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Hydraulics guard workspace"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")
    for key in [
        "MONDAY_REPORT_API_KEY",
        "MONDAY_REPORT_SIGNING_SECRET",
        "MONDAY_REPORT_REPOSITORY_BACKEND",
        "MONDAY_REPORT_DATABASE_URL",
        "DATABASE_URL",
        "MONDAY_REPORT_QUEUE_BACKEND",
        "MONDAY_REPORT_REDIS_URL",
        "REDIS_URL",
    ]:
        os.environ.pop(key, None)


if __name__ == "__main__":
    sys.exit(main())
