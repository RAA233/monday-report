from __future__ import annotations

import json
import os
import sys
import tempfile
import zipfile
from datetime import date, datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-benchmarking-") as tmp:
        configure_guard_env(Path(tmp))

        from fastapi.testclient import TestClient

        from backend.app.main import app
        from backend.app.schemas import (
            BenchmarkMeasurementCreate,
            BenchmarkValueUpdate,
            MondayReportCreate,
            Role,
            ValidationStatus,
            ValidationTaskUpdate,
        )
        from backend.app.store import FEET_DRILLED_PER_DAY, store

        client = TestClient(app)
        workspace = next(iter(store.workspaces.values()))
        gordon = next(item for item in store.benchmark_values.values() if item.benchmark_name == "Gordon average")
        noble = next(item for item in store.benchmark_values.values() if item.benchmark_name == "Noble top-quartile")
        critical_rule = next(item for item in store.anomaly_rules.values() if item.severity == "Critical")
        critical_threshold = store._threshold_for_rule(critical_rule)

        checks.append(assert_check("Gordon seed benchmark", gordon.value == 528 and gordon.unit == "ft/day", gordon.model_dump(mode="json")))
        checks.append(assert_check("Noble seed benchmark", noble.value == 588 and noble.unit == "ft/day", noble.model_dump(mode="json")))
        checks.append(assert_check("Critical threshold", critical_threshold == 448.8, critical_threshold))

        above = store.record_benchmark_measurement(
            workspace.id,
            BenchmarkMeasurementCreate(
                metric=FEET_DRILLED_PER_DAY,
                value=600,
                unit="ft/day",
                data_source="Guard DDR above benchmark",
                data_timestamp=datetime.now(timezone.utc) - timedelta(hours=36),
                source_identifier="guard-ddr-above",
            ),
        )
        checks.append(
            assert_check(
                "Above benchmark performance",
                any(
                    item.performance_status == "Above benchmark"
                    for item in above.comparisons
                    if item.metric == FEET_DRILLED_PER_DAY
                ),
                [item.model_dump(mode="json") for item in above.comparisons],
            )
        )

        advisory = store.record_benchmark_measurement(
            workspace.id,
            BenchmarkMeasurementCreate(
                metric=FEET_DRILLED_PER_DAY,
                value=560,
                unit="ft/day",
                data_source="Guard DDR advisory",
                data_timestamp=datetime.now(timezone.utc) - timedelta(hours=30),
                source_identifier="guard-ddr-advisory",
            ),
        )
        checks.append(
            assert_check(
                "Advisory deviation",
                any(item.severity == "Advisory" for item in advisory.active_anomalies),
                [item.summary for item in advisory.active_anomalies],
            )
        )

        warning = store.record_benchmark_measurement(
            workspace.id,
            BenchmarkMeasurementCreate(
                metric=FEET_DRILLED_PER_DAY,
                value=500,
                unit="ft/day",
                data_source="Guard DDR warning",
                data_timestamp=datetime.now(timezone.utc) - timedelta(hours=24),
                source_identifier="guard-ddr-warning",
            ),
        )
        checks.append(
            assert_check(
                "Warning deviation",
                any(item.severity == "Warning" for item in warning.active_anomalies),
                [item.summary for item in warning.active_anomalies],
            )
        )

        stale = store.record_benchmark_measurement(
            workspace.id,
            BenchmarkMeasurementCreate(
                metric=FEET_DRILLED_PER_DAY,
                value=470,
                unit="ft/day",
                data_source="Guard stale DDR",
                data_timestamp=datetime.now(timezone.utc) - timedelta(hours=18),
                confidence_status="stale",
                source_identifier="guard-ddr-stale",
            ),
        )
        checks.append(
            assert_check(
                "Stale data status",
                any(item.performance_status == "Stale data" for item in stale.comparisons if item.benchmark_name == "Gordon average"),
                [item.model_dump(mode="json") for item in stale.comparisons],
            )
        )

        critical = store.record_benchmark_measurement(
            workspace.id,
            BenchmarkMeasurementCreate(
                metric=FEET_DRILLED_PER_DAY,
                value=440,
                unit="ft/day",
                data_source="Guard DDR critical",
                data_timestamp=datetime.now(timezone.utc),
                source_identifier="guard-ddr-critical",
                moc_reference="MOC-GUARD-001",
            ),
        )
        critical_anomaly = next((item for item in critical.active_anomalies if item.severity == "Critical"), None)
        checks.append(assert_check("Critical anomaly created", critical_anomaly is not None, [item.summary for item in critical.active_anomalies]))
        checks.append(
            assert_check(
                "Hydraulics and Torque & Drag triggers",
                critical_anomaly is not None
                and {item.module for item in critical_anomaly.diagnostic_actions} == {"Hydraulics", "Torque & Drag"}
                and all(item.status == "Recommended" for item in critical_anomaly.diagnostic_actions),
                critical_anomaly.model_dump(mode="json") if critical_anomaly else "missing critical anomaly",
            )
        )
        checks.append(
            assert_check(
                "Source citation attached",
                critical_anomaly is not None and bool(critical_anomaly.supporting_citations),
                critical_anomaly.model_dump(mode="json") if critical_anomaly else "missing critical anomaly",
            )
        )
        anomaly_tasks = [
            task
            for task in store.validation_tasks.values()
            if critical_anomaly is not None and task.target_id == critical_anomaly.id and task.target_type == "anomaly_event"
        ]
        checks.append(assert_check("Risk watchlist validation task", len(anomaly_tasks) == 1, [task.model_dump(mode="json") for task in anomaly_tasks]))

        unit_status = store.record_benchmark_measurement(
            workspace.id,
            BenchmarkMeasurementCreate(
                metric=FEET_DRILLED_PER_DAY,
                value=140,
                unit="m/day",
                data_source="Guard metric unit DDR",
                data_timestamp=datetime.now(timezone.utc) + timedelta(seconds=1),
                source_identifier="guard-ddr-metric",
            ),
        )
        checks.append(
            assert_check(
                "Unit conversion",
                any(
                    item.benchmark_name == "Gordon average"
                    and item.current_value is not None
                    and 459 <= item.current_value <= 460
                    for item in unit_status.comparisons
                ),
                [item.model_dump(mode="json") for item in unit_status.comparisons],
            )
        )

        checks.append(
            assert_check(
                "Missing data comparison rows",
                any(item.metric == "dogleg_severity" and item.performance_status == "Insufficient data" for item in unit_status.comparisons),
                [item.model_dump(mode="json") for item in unit_status.comparisons if item.metric == "dogleg_severity"],
            )
        )

        viewer_roles = store.user.roles
        store.user.roles = [Role.VIEWER]
        store.save()
        denied = client.patch(
            f"/benchmarking/values/{gordon.id}",
            json={"value": 529, "reason": "Viewer should not update benchmark config."},
        )
        checks.append(assert_check("Role-based config permission", denied.status_code == 403, denied.text))
        store.user.roles = viewer_roles
        store.save()

        updated = store.update_benchmark_value(
            noble.id,
            BenchmarkValueUpdate(
                value=590,
                reason="Benchmarking guard verifies configurable benchmark values.",
            ),
        )
        checks.append(assert_check("Configurable benchmark values", updated.value == 590, updated.model_dump(mode="json")))

        for task in list(store.validation_tasks.values()):
            if task.target_type == "anomaly_event" and task.status == ValidationStatus.OPEN:
                store.update_validation_task(
                    task.id,
                    ValidationTaskUpdate(
                        status=ValidationStatus.VALIDATED,
                        resolution_note="Benchmarking guard accepted critical anomaly evidence.",
                    ),
                )

        report = store.create_monday_report(
            MondayReportCreate(
                workspace_id=workspace.id,
                period_start=date(2026, 7, 6),
                period_end=date(2026, 7, 12),
            )
        )
        checks.append(
            assert_check(
                "Report carries market benchmark section",
                "benchmarking" in report.report_json
                and "market_benchmark" in report.report_json.get("morning_report", {})
                and "management_of_change_evidence" in report.report_json.get("morning_report", {}),
                report.report_json.get("morning_report", {}),
            )
        )
        checks.append(
            assert_check(
                "AI approval workflow",
                all(
                    item.get("review_status") == "review_required"
                    for item in report.report_json.get("benchmarking", {}).get("ai_interpretation", [])
                ),
                report.report_json.get("benchmarking", {}).get("ai_interpretation", []),
            )
        )

        exports = {fmt: store.export_monday_report(report.id, fmt) for fmt in ["json", "csv", "html", "pdf", "xlsx"]}
        export_bytes = {
            fmt: store.export_path_from_uri(export.storage_uri).read_bytes()  # type: ignore[union-attr]
            for fmt, export in exports.items()
        }
        json_payload = json.loads(export_bytes["json"].decode("utf-8"))
        checks.append(
            assert_check(
                "Evidence export JSON contents",
                json_payload.get("benchmarking", {}).get("benchmark_values")
                and json_payload.get("morning_report", {}).get("management_of_change_evidence", {}).get("triggered_anomaly_rules"),
                json_payload.get("benchmarking", {}),
            )
        )
        checks.append(assert_check("Evidence export CSV contents", "benchmark_metric" in export_bytes["csv"].decode("utf-8"), "benchmark_metric header"))
        checks.append(assert_check("Evidence export HTML contents", "Market Benchmark" in export_bytes["html"].decode("utf-8", errors="replace"), "Market Benchmark section"))
        checks.append(assert_check("Evidence export PDF contents", pdf_contains(export_bytes["pdf"], ["Market Benchmark"]), "PDF Market Benchmark text"))
        checks.append(assert_check("Evidence export XLSX contents", "Market Benchmark" in xlsx_inline_text(export_bytes["xlsx"]), "XLSX Market Benchmark text"))

        audit_actions = {event.action for event in store.audit_logs}
        checks.append(
            assert_check(
                "Audit-event creation",
                {
                    "benchmark_config.seed",
                    "benchmark_measurement.create",
                    "benchmark_anomaly.create",
                    "risk_watchlist.add",
                    "benchmark_config.update",
                }.issubset(audit_actions),
                sorted(audit_actions),
            )
        )

    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")
    if failed:
        print(f"\nBenchmarking guard failed with {len(failed)} failing check(s).")
        return 1
    print("\nBenchmarking guard passed.")
    return 0


def configure_guard_env(tmp_root: Path) -> None:
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
    os.environ["MONDAY_REPORT_DISABLE_DEMO_SEED"] = "true"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Benchmarking Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "benchmarking-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "benchmarking@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Benchmarking Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Benchmarking guard workspace"
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


def pdf_contains(content: bytes, markers: list[str]) -> bool:
    import fitz  # type: ignore[import-not-found]

    document = fitz.open(stream=content, filetype="pdf")
    try:
        text = "\n".join(document.load_page(index).get_text("text") for index in range(document.page_count))
    finally:
        document.close()
    return all(marker in text for marker in markers)


def xlsx_inline_text(content: bytes) -> str:
    with zipfile.ZipFile(BytesIO(content)) as archive:
        return "\n".join(
            archive.read(name).decode("utf-8", errors="replace")
            for name in archive.namelist()
            if name.endswith(".xml")
        )


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": bool(ok), "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
