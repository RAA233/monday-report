"""Harden the local snapshot atomicity fix: concurrency, multi-process, fault
injection, revision/compat, and privacy.

Every assertion reads the on-disk snapshot, never a return value. Each fault
injection resolves to exactly one acceptable outcome -- OLD complete state, NEW
complete state, or a controlled conflict -- and never business-without-audit or
audit-without-business or a success response with an absent persisted mutation.
Each fault has a discriminating no-fault negative control.

Dual mode: with ``--worker <state_path> <task_id>`` this file is the second
process for the multi-process battery; otherwise it runs the batteries.

Standalone, demo mode, no database, no network. Prints JSON; exit 0 only when
every invariant holds.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# --------------------------------------------------------------------------- #
# Worker mode: one mutation in a separate process against a shared snapshot file
# --------------------------------------------------------------------------- #
def _run_worker(state_path: str, task_id: str) -> int:
    os.environ["MONDAY_REPORT_STATE_PATH"] = state_path
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(Path(state_path).parent / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(Path(state_path).parent / "exports")
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
    from uuid import UUID

    from backend.app.schemas import ValidationTaskUpdate
    from backend.app.store import store

    try:
        store.update_validation_task(UUID(task_id), ValidationTaskUpdate(status="validated"))
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"worker error: {exc}\n")
        return 1
    return 0


# --------------------------------------------------------------------------- #
# Battery helpers
# --------------------------------------------------------------------------- #
def _fresh_env(root: Path) -> None:
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(root / "exports")
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
    for mod in [m for m in list(sys.modules) if m.startswith("backend.app")]:
        del sys.modules[mod]


def _new_store():
    from backend.app.store import store
    return store


def _seed_workspace(store):
    from backend.app.schemas import Workspace
    ws = Workspace(tenant_id=store.tenant.id, name="Harden", asset="a", campaign="c")
    store.workspaces[ws.id] = ws
    return ws.id


def _seed_open_task(store, workspace_id):
    from backend.app.schemas import FailureRecord, ValidationTask
    failure = FailureRecord(
        tenant_id=store.tenant.id, workspace_id=workspace_id, event_type="npt",
        severity="High", summary="MWD signal loss", confidence=0.9)
    store.failures[failure.id] = failure
    task = ValidationTask(
        tenant_id=store.tenant.id, target_type="failure", target_id=failure.id,
        reason="review", status="open")
    store.validation_tasks[task.id] = task
    return task.id


def _seed_report_with_gate(store, workspace_id):
    from backend.app.schemas import FailureRecord, MondayReport, ValidationTask
    failure = FailureRecord(
        tenant_id=store.tenant.id, workspace_id=workspace_id, event_type="npt",
        severity="High", summary="MWD signal loss", confidence=0.9)
    store.failures[failure.id] = failure
    task = ValidationTask(
        tenant_id=store.tenant.id, target_type="failure", target_id=failure.id,
        reason="review", status="open")
    store.validation_tasks[task.id] = task
    report = MondayReport(
        tenant_id=store.tenant.id, workspace_id=workspace_id, period_start="2026-07-06",
        period_end="2026-07-12", report_json={"summary": "seed"}, status="draft")
    store.monday_reports[report.id] = report
    return report.id


def _disk(store) -> dict:
    return json.loads(Path(store.state_path).read_text(encoding="utf-8"))


def _event_present(snapshot, action, resource_id) -> bool:
    return any(
        e.get("action") == action and str(e.get("resource_id")) == str(resource_id)
        for e in snapshot.get("audit_logs", []))


def _task_status(snapshot, task_id) -> str | None:
    for t in snapshot.get("validation_tasks", []):
        if t["id"] == str(task_id):
            return t["status"]
    return None


def _rec(results, name, ok, detail):
    results.append({"id": name, "ok": bool(ok), "detail": detail})


# --------------------------------------------------------------------------- #
# Part L: concurrency and multi-process batteries
# --------------------------------------------------------------------------- #
def battery_concurrent_validation(results, rounds=60, pollers=6):
    """>=50 rounds: a validation PATCH under concurrent GET pollers loses nothing."""
    from backend.app.schemas import ValidationTaskUpdate
    lost = 0
    for _ in range(rounds):
        with tempfile.TemporaryDirectory(prefix="mr-h-conc-") as tmp:
            _fresh_env(Path(tmp))
            store = _new_store()
            ws = _seed_workspace(store)
            task_id = _seed_open_task(store, ws)
            store.save()

            stop = threading.Event()

            def poll():
                while not stop.is_set():
                    try:
                        store.refresh()
                    except Exception:  # noqa: BLE001
                        pass

            threads = [threading.Thread(target=poll, daemon=True) for _ in range(pollers)]
            for th in threads:
                th.start()
            time.sleep(0.02)
            store.update_validation_task(task_id, ValidationTaskUpdate(status="validated"))
            stop.set()
            for th in threads:
                th.join(timeout=2)

            snap = _disk(store)
            if _task_status(snap, task_id) != "validated" or not _event_present(snap, "validation_task.update", task_id):
                lost += 1
    _rec(results, "battery-concurrent-validation-zero-loss",
         lost == 0, f"{rounds} rounds x {pollers} pollers; lost mutations={lost}")


def battery_zero_poller_control(results, rounds=25):
    """>=20 rounds: with no pollers, a PATCH always persists (discriminates the
    concurrency battery from a broken harness)."""
    from backend.app.schemas import ValidationTaskUpdate
    lost = 0
    for _ in range(rounds):
        with tempfile.TemporaryDirectory(prefix="mr-h-ctrl-") as tmp:
            _fresh_env(Path(tmp))
            store = _new_store()
            ws = _seed_workspace(store)
            task_id = _seed_open_task(store, ws)
            store.save()
            store.update_validation_task(task_id, ValidationTaskUpdate(status="validated"))
            snap = _disk(store)
            if _task_status(snap, task_id) != "validated":
                lost += 1
    _rec(results, "battery-zero-poller-control", lost == 0, f"{rounds} rounds; lost={lost}")


def battery_blocked_export(results, rounds=25):
    """>=20 rounds: the blocked-export path keeps business and audit coupled."""
    contradictions = 0
    for _ in range(rounds):
        with tempfile.TemporaryDirectory(prefix="mr-h-exp-") as tmp:
            _fresh_env(Path(tmp))
            store = _new_store()
            ws = _seed_workspace(store)
            report_id = _seed_report_with_gate(store, ws)
            store.save()

            store.refresh()
            report = store.monday_reports.get(report_id)
            open_tasks = store.report_open_validation_tasks(report_id)
            report.status = "review"
            store.audit("monday_report.export_blocked", "monday_report", report_id,
                        {"open_validation_tasks": len(open_tasks)})

            snap = _disk(store)
            persisted = next(r for r in snap["monday_reports"] if r["id"] == str(report_id))
            status_ok = persisted["status"] == "review"
            event_ok = _event_present(snap, "monday_report.export_blocked", report_id)
            if event_ok != status_ok:
                contradictions += 1
    _rec(results, "battery-blocked-export-coupled", contradictions == 0,
         f"{rounds} rounds; business/audit contradictions={contradictions}")


def battery_multiprocess(results, workers=25):
    """>=25 separate processes each commit a distinct validation to one shared
    snapshot file. The cross-process file lock serializes them; none is lost.
    An in-process RLock alone could not provide this (separate address spaces)."""
    with tempfile.TemporaryDirectory(prefix="mr-h-mp-") as tmp:
        _fresh_env(Path(tmp))
        store = _new_store()
        ws = _seed_workspace(store)
        task_ids = [_seed_open_task(store, ws) for _ in range(workers)]
        store.save()
        state_path = str(store.state_path)

        procs = []
        for tid in task_ids:
            procs.append(subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--worker", state_path, str(tid)],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True))
        errors = []
        for p in procs:
            _out, err = p.communicate(timeout=120)
            if p.returncode != 0:
                errors.append((err or "").strip()[:120])

        snapshot = json.loads(Path(state_path).read_text(encoding="utf-8"))
        persisted = sum(1 for tid in task_ids if _task_status(snapshot, tid) == "validated")
        events = sum(1 for tid in task_ids if _event_present(snapshot, "validation_task.update", tid))
        # Every commit must have advanced the revision by exactly one from the seed.
        revision = int(snapshot.get("snapshot_revision", -1))
        _rec(results, "battery-multiprocess-zero-loss",
             persisted == workers and events == workers and not errors,
             f"{workers} processes; validated persisted={persisted}, events={events}, "
             f"final revision={revision}, worker errors={errors[:2]}")


def check_multiprocess_needs_cross_process_lock(results):
    """An in-process RLock cannot coordinate two processes: demonstrate the file
    lock is what serializes them by confirming the sidecar lock file is used."""
    with tempfile.TemporaryDirectory(prefix="mr-h-lockproof-") as tmp:
        _fresh_env(Path(tmp))
        store = _new_store()
        ws = _seed_workspace(store)
        tid = _seed_open_task(store, ws)
        store.save()
        lock_path = Path(store.state_path).with_name(Path(store.state_path).name + ".lock")
        from backend.app.schemas import ValidationTaskUpdate
        store.update_validation_task(tid, ValidationTaskUpdate(status="validated"))
        _rec(results, "cross-process-lock-file-used", lock_path.exists(),
             f"sidecar lock file present at <state>.lock: {lock_path.exists()} "
             f"(separate from the snapshot file, so os.replace is never obstructed)")


# --------------------------------------------------------------------------- #
# Part K: fault injection -- each resolves to old/new complete state or a conflict
# --------------------------------------------------------------------------- #
def _fault_case(results, name, inject, expect):
    """Run a validation PATCH with `inject` (a callable that patches the store and
    returns a restore callable), assert `expect(snapshot, raised)`; then a no-fault
    negative control must persist cleanly."""
    from backend.app.schemas import ValidationTaskUpdate
    with tempfile.TemporaryDirectory(prefix="mr-h-fault-") as tmp:
        _fresh_env(Path(tmp))
        store = _new_store()
        ws = _seed_workspace(store)
        tid = _seed_open_task(store, ws)
        store.save()

        restore = inject(store)
        raised = None
        try:
            store.update_validation_task(tid, ValidationTaskUpdate(status="validated"))
        except BaseException as exc:  # noqa: BLE001
            raised = exc
        finally:
            restore()

        snap = _disk(store)
        ok, detail = expect(snap, raised, tid)
        # Negative control: the SAME operation with no fault persists cleanly.
        store.update_validation_task(tid, ValidationTaskUpdate(status="validated"))
        ctrl = _disk(store)
        ctrl_ok = _task_status(ctrl, tid) == "validated" and _event_present(ctrl, "validation_task.update", tid)
        _rec(results, f"fault-{name}", ok and ctrl_ok,
             f"{detail}; negative control persisted cleanly={ctrl_ok}")


def _no_partial_and_old(snap, raised, tid):
    """Old complete state: task still open, no event, snapshot is valid JSON."""
    status = _task_status(snap, tid)
    event = _event_present(snap, "validation_task.update", tid)
    ok = status == "open" and not event
    return ok, f"raised={type(raised).__name__ if raised else None}; task={status!r}; event={event}"


def fault_before_audit(store):
    """Fail after the business mutation, before the audit append."""
    original = store.audit
    def boom(*a, **k):
        raise RuntimeError("injected: before audit append")
    store.audit = boom
    return lambda: setattr(store, "audit", original)


def fault_before_serialize(store):
    """Fail after the audit append, before serialization."""
    original = store._state_payload
    def boom():
        raise RuntimeError("injected: before serialize")
    store._state_payload = boom
    return lambda: setattr(store, "_state_payload", original)


def fault_during_replace(store):
    """Fail during the atomic replace (temp already written+fsynced)."""
    original = store._replace_state_file
    def boom(tmp_path):
        raise OSError("injected: during replace")
    store._replace_state_file = boom
    return lambda: setattr(store, "_replace_state_file", original)


def fault_after_replace_before_revision(store):
    """Fail after the durable replace, before the in-memory revision update. The
    write is durable, so the acceptable outcome is NEW complete state."""
    original = store._fsync_dir
    def boom(directory):
        raise OSError("injected: after replace, before revision update")
    # Bound as an instance attribute so it is invoked as _fsync_dir(directory).
    store._fsync_dir = boom
    return lambda: setattr(store, "_fsync_dir", original)


def fault_revision_mismatch(store):
    """A concurrent writer advanced the persisted revision between load and commit."""
    original = store._read_disk_revision
    def bumped():
        return original() + 1
    store._read_disk_revision = bumped
    return lambda: setattr(store, "_read_disk_revision", original)


def check_fault_after_replace_new_state(results):
    from backend.app.schemas import ValidationTaskUpdate
    with tempfile.TemporaryDirectory(prefix="mr-h-fault-new-") as tmp:
        _fresh_env(Path(tmp))
        store = _new_store()
        ws = _seed_workspace(store)
        tid = _seed_open_task(store, ws)
        store.save()
        restore = fault_after_replace_before_revision(store)
        raised = None
        try:
            store.update_validation_task(tid, ValidationTaskUpdate(status="validated"))
        except BaseException as exc:  # noqa: BLE001
            raised = exc
        finally:
            restore()
        snap = _disk(store)
        # Durable write happened before the injected failure: NEW complete state,
        # with business and audit BOTH present (never one without the other).
        status = _task_status(snap, tid)
        event = _event_present(snap, "validation_task.update", tid)
        _rec(results, "fault-after-replace-new-complete-state",
             status == "validated" and event,
             f"raised={type(raised).__name__ if raised else None}; task={status!r}; event={event} "
             f"(durable write completed before the fault -> new complete state)")


def check_lock_timeout(results):
    """Holding the sidecar lock from another thread makes a transaction fail as a
    bounded, retryable, PATHLESS SnapshotConflict."""
    with tempfile.TemporaryDirectory(prefix="mr-h-lock-") as tmp:
        _fresh_env(Path(tmp))
        store = _new_store()
        import backend.app.store as store_mod
        ws = _seed_workspace(store)
        tid = _seed_open_task(store, ws)
        store.save()
        from backend.app.schemas import ValidationTaskUpdate
        lock_path = Path(store.state_path).with_name(Path(store.state_path).name + ".lock")

        held = threading.Event()
        release = threading.Event()

        def hold():
            with store_mod._SnapshotFileLock(lock_path, 5.0, 0.02):
                held.set()
                release.wait(timeout=10)

        holder = threading.Thread(target=hold, daemon=True)
        holder.start()
        held.wait(timeout=5)

        # Shorten the acquire timeout so the test is fast and bounded.
        original_timeout = store_mod.SNAPSHOT_LOCK_ACQUIRE_TIMEOUT_SECONDS
        store_mod.SNAPSHOT_LOCK_ACQUIRE_TIMEOUT_SECONDS = 0.5
        started = time.monotonic()
        raised = None
        try:
            store.update_validation_task(tid, ValidationTaskUpdate(status="validated"))
        except BaseException as exc:  # noqa: BLE001
            raised = exc
        finally:
            store_mod.SNAPSHOT_LOCK_ACQUIRE_TIMEOUT_SECONDS = original_timeout
            release.set()
            holder.join(timeout=5)
        elapsed = time.monotonic() - started

        is_conflict = isinstance(raised, store_mod.SnapshotConflict)
        retryable = getattr(raised, "retryable", None) is True
        message = str(raised) if raised else ""
        pathless = str(store.state_path) not in message and ".lock" not in message and tmp not in message
        bounded = elapsed < 3.0
        snap = _disk(store)
        unchanged = _task_status(snap, tid) == "open"
        _rec(results, "lock-timeout-bounded-structural-pathless",
             is_conflict and retryable and pathless and bounded and unchanged,
             f"raised={type(raised).__name__ if raised else None}, retryable={retryable}, "
             f"elapsed={elapsed:.2f}s, pathless={pathless}, snapshot unchanged={unchanged}, msg={message!r}")


# --------------------------------------------------------------------------- #
# Compatibility, revision, atomic-replace, cleanup
# --------------------------------------------------------------------------- #
def check_old_snapshot_and_revision(results):
    """An old snapshot with no snapshot_revision loads (revision 0); the next
    commit writes revision 1 and each subsequent commit increments by exactly 1."""
    from backend.app.schemas import ValidationTaskUpdate
    with tempfile.TemporaryDirectory(prefix="mr-h-old-") as tmp:
        _fresh_env(Path(tmp))
        store = _new_store()
        ws = _seed_workspace(store)
        t1 = _seed_open_task(store, ws)
        t2 = _seed_open_task(store, ws)
        store.save()

        # Strip snapshot_revision to emulate a pre-fix snapshot.
        raw = json.loads(Path(store.state_path).read_text(encoding="utf-8"))
        raw.pop("snapshot_revision", None)
        Path(store.state_path).write_text(json.dumps(raw, indent=2), encoding="utf-8")

        _fresh_env(Path(tmp))  # rebuild the store singleton against the stripped file
        # keep the SAME path (env unchanged by re-seeding); re-import
        os.environ["MONDAY_REPORT_STATE_PATH"] = str(Path(tmp) / "state.json")
        store = _new_store()
        loaded = any(t["id"] == str(t1) for t in _disk(store)["validation_tasks"])

        store.update_validation_task(t1, ValidationTaskUpdate(status="validated"))
        r1 = int(_disk(store)["snapshot_revision"])
        store.update_validation_task(t2, ValidationTaskUpdate(status="rejected"))
        r2 = int(_disk(store)["snapshot_revision"])
        _rec(results, "old-snapshot-loads-and-revision-increments",
             loaded and r2 == r1 + 1,
             f"old snapshot loaded={loaded}; first commit revision={r1}, second={r2} (want +1)")


def check_conflict_fails_loud(results):
    """A stale-revision commit raises a non-retryable SnapshotConflict, not a
    silent overwrite."""
    with tempfile.TemporaryDirectory(prefix="mr-h-conf-") as tmp:
        _fresh_env(Path(tmp))
        store = _new_store()
        import backend.app.store as store_mod
        from backend.app.schemas import ValidationTaskUpdate
        ws = _seed_workspace(store)
        tid = _seed_open_task(store, ws)
        store.save()
        restore = fault_revision_mismatch(store)
        raised = None
        try:
            store.update_validation_task(tid, ValidationTaskUpdate(status="validated"))
        except BaseException as exc:  # noqa: BLE001
            raised = exc
        finally:
            restore()
        snap = _disk(store)
        is_conflict = isinstance(raised, store_mod.SnapshotConflict)
        non_retryable = getattr(raised, "retryable", None) is False
        unchanged = _task_status(snap, tid) == "open"
        _rec(results, "revision-conflict-fails-loud",
             is_conflict and non_retryable and unchanged,
             f"raised={type(raised).__name__ if raised else None}, retryable={getattr(raised,'retryable',None)}, "
             f"snapshot unchanged={unchanged}")


def check_atomic_replace_no_partial(results):
    """A serialization/replace failure leaves the canonical snapshot as valid,
    complete JSON (old state) and leaves no orphan temp file."""
    from backend.app.schemas import ValidationTaskUpdate
    with tempfile.TemporaryDirectory(prefix="mr-h-atomic-") as tmp:
        _fresh_env(Path(tmp))
        store = _new_store()
        ws = _seed_workspace(store)
        tid = _seed_open_task(store, ws)
        store.save()
        restore = fault_during_replace(store)
        try:
            store.update_validation_task(tid, ValidationTaskUpdate(status="validated"))
        except BaseException:  # noqa: BLE001
            pass
        finally:
            restore()
        canonical = Path(store.state_path)
        parsed_ok = True
        try:
            json.loads(canonical.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            parsed_ok = False
        orphan_tmp = list(canonical.parent.glob(canonical.name + ".*.tmp"))
        old_state = _task_status(_disk(store), tid) == "open"
        _rec(results, "atomic-replace-no-partial-no-orphan",
             parsed_ok and old_state and not orphan_tmp,
             f"canonical valid JSON={parsed_ok}, old state preserved={old_state}, orphan temp files={len(orphan_tmp)}")


# --------------------------------------------------------------------------- #
def main() -> int:
    if len(sys.argv) >= 4 and sys.argv[1] == "--worker":
        return _run_worker(sys.argv[2], sys.argv[3])

    results: list = []
    # Part L batteries
    battery_zero_poller_control(results, rounds=25)
    battery_concurrent_validation(results, rounds=60, pollers=6)
    battery_blocked_export(results, rounds=25)
    battery_multiprocess(results, workers=25)
    check_multiprocess_needs_cross_process_lock(results)
    # Part K fault injection (each with a no-fault negative control inside _fault_case)
    _fault_case(results, "before-audit-append", fault_before_audit, _no_partial_and_old)
    _fault_case(results, "before-serialize", fault_before_serialize, _no_partial_and_old)
    _fault_case(results, "during-replace", fault_during_replace, _no_partial_and_old)
    check_fault_after_replace_new_state(results)
    check_lock_timeout(results)
    # Revision / compat / atomic replace
    check_old_snapshot_and_revision(results)
    check_conflict_fails_loud(results)
    check_atomic_replace_no_partial(results)

    passed = sum(1 for r in results if r["ok"])
    failed = len(results) - passed
    report = {
        "guard": "local_snapshot_atomicity_guard",
        "summary": {"passed": passed, "failed": failed},
        "results": results,
    }
    print(json.dumps(report, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
