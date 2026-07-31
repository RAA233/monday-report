"""Reproduce the inherited LocalStateStore write-loss defect, deterministically.

Two forms, both proven against the REAL store methods and the REAL route sequence:

  C2  the blocked-export path (main.py export_monday_report 409 branch):
      refresh -> bind report -> report_open_validation_tasks() [refreshes AGAIN,
      orphaning the bound report] -> report.status = "review" -> audit(save=True).
      The audit event persists; the status mutation does not. HTTP would be 409.
      Zero concurrency required.

  C1  a concurrent GET refresh landing between a writer's in-memory mutation and
      its disk serialize (the update_validation_task W2 window). The writer's
      collections are rebound out from under it, so save() serializes stale state
      and both the task mutation and its validation_task.update audit event vanish
      while the PATCH would answer 200.

Each check asserts the INVARIANT (business state and its audit event persist
together). The script therefore FAILS on the defective base and PASSES once the
store is atomic. It reads assertions from the on-disk snapshot, NEVER from a
return value or response body.

Standalone, demo-mode, no database, no browser, no network. Prints JSON; exit 0
only when every invariant holds.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _fresh_env(root: Path) -> None:
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(root / "exports")
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
    # A fresh, isolated store singleton bound to this temp path.
    for mod in [m for m in list(sys.modules) if m.startswith("backend.app")]:
        del sys.modules[mod]


def _seed(store):
    """A workspace, a draft report in it, a failure, and an OPEN failure-targeted
    validation task — the minimum for the blocked-export gate to fire."""
    from backend.app.schemas import (
        FailureRecord,
        MondayReport,
        ValidationTask,
        Workspace,
    )

    tenant_id = store.tenant.id
    workspace = Workspace(tenant_id=tenant_id, name="Repro workspace", asset="a", campaign="c")
    store.workspaces[workspace.id] = workspace

    failure = FailureRecord(
        tenant_id=tenant_id,
        workspace_id=workspace.id,
        event_type="npt",
        severity="High",
        summary="MWD signal loss",
        confidence=0.9,
    )
    store.failures[failure.id] = failure

    task = ValidationTask(
        tenant_id=tenant_id,
        target_type="failure",
        target_id=failure.id,
        reason="High-severity extracted failure requires review.",
        status="open",
    )
    store.validation_tasks[task.id] = task

    report = MondayReport(
        tenant_id=tenant_id,
        workspace_id=workspace.id,
        period_start="2026-07-06",
        period_end="2026-07-12",
        report_json={"summary": "seed"},
        status="draft",
    )
    store.monday_reports[report.id] = report
    store.save()
    return workspace.id, failure.id, task.id, report.id


def _disk(store) -> dict:
    return json.loads(Path(store.state_path).read_text(encoding="utf-8"))


def _event_present(snapshot: dict, action: str, resource_id) -> bool:
    return any(
        e.get("action") == action and str(e.get("resource_id")) == str(resource_id)
        for e in snapshot.get("audit_logs", [])
    )


def check_c2_blocked_export(results: list) -> None:
    """The blocked-export path: status mutation and its audit event must persist
    together. Base defect: the event persists, the status does not."""
    with tempfile.TemporaryDirectory(prefix="mr-repro-c2-") as tmp:
        _fresh_env(Path(tmp))
        from backend.app.store import store

        _ws, _failure_id, _task_id, report_id = _seed(store)

        # Exactly the main.py export_monday_report 409 sequence.
        store.refresh()
        report = store.monday_reports.get(report_id)
        open_tasks = store.report_open_validation_tasks(report_id)
        assert open_tasks, "seed error: the gate did not see an open task"
        report.status = "review"
        if isinstance(report.report_json, dict):
            report.report_json["validation"] = {"open_tasks": len(open_tasks), "status": "requires_review"}
        store.audit(
            "monday_report.export_blocked",
            "monday_report",
            report_id,
            {"open_validation_tasks": len(open_tasks)},
        )

        snapshot = _disk(store)
        persisted = next(r for r in snapshot["monday_reports"] if r["id"] == str(report_id))
        status_persisted = persisted["status"] == "review"
        event_persisted = _event_present(snapshot, "monday_report.export_blocked", report_id)

        results.append({
            "id": "c2-blocked-export-business-audit-coupled",
            "ok": status_persisted and event_persisted,
            "detail": (
                f"persisted report status={persisted['status']!r} (want 'review'); "
                f"export_blocked audit event persisted={event_persisted}; "
                f"business+audit coupled={status_persisted and event_persisted}"
            ),
            "contradiction": event_persisted and not status_persisted,
        })


def check_c1_concurrent_refresh(results: list) -> None:
    """A concurrent reader refresh in the writer's serialize window. Modelled by
    firing a real refresh() from inside _state_payload — the exact interleaving a
    GET poller produces on the shared singleton. Base defect: the mutation and its
    audit event are serialized away."""
    with tempfile.TemporaryDirectory(prefix="mr-repro-c1-") as tmp:
        _fresh_env(Path(tmp))
        from backend.app.schemas import ValidationTaskUpdate
        from backend.app.store import store

        _ws, _failure_id, task_id, _report_id = _seed(store)

        original_state_payload = store._state_payload
        fired = {"n": 0}

        def racing_state_payload():
            # A concurrent GET's refresh() lands here, between the writer's
            # in-memory mutation (already done) and this serialize. On the shared
            # singleton it rebinds the collections to the on-disk (pre-mutation)
            # state, which is exactly what the writer is about to serialize.
            if fired["n"] == 0:
                fired["n"] += 1
                store.refresh()
            return original_state_payload()

        store._state_payload = racing_state_payload
        try:
            store.update_validation_task(task_id, ValidationTaskUpdate(status="validated"))
        finally:
            store._state_payload = original_state_payload

        snapshot = _disk(store)
        persisted = next(t for t in snapshot["validation_tasks"] if t["id"] == str(task_id))
        status_persisted = persisted["status"] == "validated"
        event_persisted = _event_present(snapshot, "validation_task.update", task_id)

        results.append({
            "id": "c1-concurrent-refresh-business-audit-coupled",
            "ok": status_persisted and event_persisted,
            "detail": (
                f"persisted task status={persisted['status']!r} (want 'validated'); "
                f"validation_task.update audit event persisted={event_persisted}; "
                f"business+audit coupled={status_persisted and event_persisted}"
            ),
            "injected_reader_refresh": fired["n"],
        })


def check_negative_control_no_injection(results: list) -> None:
    """Zero-concurrency control: with NO injected refresh, a plain PATCH must
    persist cleanly on BOTH the base and the fixed store. Proves the two checks
    above fail because of the interleaving, not because the harness is broken."""
    with tempfile.TemporaryDirectory(prefix="mr-repro-ctrl-") as tmp:
        _fresh_env(Path(tmp))
        from backend.app.schemas import ValidationTaskUpdate
        from backend.app.store import store

        _ws, _failure_id, task_id, _report_id = _seed(store)
        store.update_validation_task(task_id, ValidationTaskUpdate(status="validated"))

        snapshot = _disk(store)
        persisted = next(t for t in snapshot["validation_tasks"] if t["id"] == str(task_id))
        ok = persisted["status"] == "validated" and _event_present(snapshot, "validation_task.update", task_id)
        results.append({
            "id": "control-no-injection-persists",
            "ok": ok,
            "detail": f"uninjected PATCH persisted status={persisted['status']!r} and its event: {ok}",
        })


def main() -> int:
    results: list = []
    check_negative_control_no_injection(results)
    check_c2_blocked_export(results)
    check_c1_concurrent_refresh(results)

    passed = sum(1 for r in results if r["ok"])
    failed = len(results) - passed
    report = {
        "guard": "local_snapshot_atomicity_repro",
        "summary": {"passed": passed, "failed": failed},
        "invariant": "every mutation the API accepts persists together with its audit event",
        "results": results,
    }
    print(json.dumps(report, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
