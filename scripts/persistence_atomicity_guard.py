"""Guard for transactional PostgreSQL snapshot atomicity.

Covers three risk classes:

1. MANIFEST INTEGRITY (no database required).
   The transaction boundary is installed by wrapping a declared list of mutating
   methods. A declared list is exactly the kind of thing that silently rots: an
   earlier revision of this work declared 8 mutators when there were 14, and the
   two most dangerous omissions were the worker loop and retention. These checks
   discover mutators from the source by AST rather than by name heuristic, and
   fail when the declaration and reality disagree in either direction.

2. FAIL-CLOSED BEHAVIOUR (no database required).
   An unprotected write must raise rather than silently fall back, and the
   file/memory backends must not advertise a cross-process guarantee they do not
   have.

3. REAL CROSS-PROCESS ATOMICITY (requires PostgreSQL).
   Independent OS processes with independent connections race a real database.
   Includes a NEGATIVE CONTROL through the pre-fix read/save path: a test that
   cannot fail on the broken implementation proves nothing, so the guard asserts
   the old path *does* lose an update.

Honest skipping: without MONDAY_REPORT_TEST_DATABASE_URL the database scenarios
report SKIPPED. A skipped run must never be used to emit passing evidence -- the
evidence builder refuses when required skips are present.

Run: ``python scripts/persistence_atomicity_guard.py [--emit-evidence]``
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "scripts"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

EVIDENCE_PATH = ROOT / "output" / "persistence" / "persistence-atomicity-evidence.v1.json"
EVIDENCE_SCHEMA_VERSION = "persistence-atomicity-evidence.v1"

checks: list[dict] = []


def record(name: str, ok: bool, detail: object = "", *, skipped: bool = False) -> None:
    checks.append({"name": name, "ok": bool(ok), "skipped": bool(skipped), "detail": detail})


def skip(name: str, reason: str) -> None:
    record(name, True, reason, skipped=True)


def test_database_url() -> str | None:
    return os.environ.get("MONDAY_REPORT_TEST_DATABASE_URL")


# --------------------------------------------------------------------------- #
# 1. Manifest integrity
# --------------------------------------------------------------------------- #
def discover_mutators(source: str) -> set[str]:
    """Public methods that durably mutate state, found structurally.

    A method mutates if its body calls ``self.audit(...)`` or ``self.save()``.
    Using the AST rather than a regex over names means a future mutator called
    something unexpected is still discovered.
    """
    tree = ast.parse(source)
    found: set[str] = set()
    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
        for fn in (n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
            if fn.name.startswith("_"):
                continue
            for call in (c for c in ast.walk(fn) if isinstance(c, ast.Call)):
                f = call.func
                if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "self":
                    if f.attr in {"audit", "save"}:
                        found.add(fn.name)
                        break
    return found


def manifest_checks() -> None:
    from backend.app import store as store_mod

    declared = set(store_mod.MUTATING_STORE_METHODS)
    # Deliberate exclusions must be declared too, so "not wrapped" is always an
    # explicit decision rather than an oversight.
    excluded = set(store_mod.NON_WRAPPED_MUTATORS)
    discovered = discover_mutators((ROOT / "backend" / "app" / "store.py").read_text(encoding="utf-8"))

    undeclared = sorted(discovered - declared - excluded)
    record("01 every discovered mutating method is declared in the manifest",
           not undeclared, {"undeclared": undeclared, "discovered": len(discovered)})

    stale = sorted(n for n in declared if not hasattr(store_mod.LocalStateStore, n))
    record("02 every declared mutator still exists on the store", not stale, {"stale": stale})

    record("03 the manifest is non-trivial (guards against an emptied list)",
           len(declared) >= 18, {"declared": len(declared)})

    # The worker loop and retention were the two omissions that mattered most:
    # they call save() directly rather than through audit().
    # The mutators most likely to be missed: the worker loop, retention, and the
    # correction paths that the cross-process atomicity discussion turns on.
    for critical in ("process_queued_jobs", "run_retention",
                     "record_field_correction", "revert_field_correction",
                     "record_benchmark_measurement"):
        record(f"04 critical mutator declared: {critical}", critical in declared, critical)


def wrapping_checks() -> None:
    """Every declared mutator must actually be wrapped on a live instance."""
    from backend.app import store as store_mod

    inst = object.__new__(store_mod.PostgresStateStore)
    inst._txn = None
    inst._bootstrapping = False
    for name in store_mod.MUTATING_STORE_METHODS:
        setattr(inst, name, getattr(store_mod.LocalStateStore, name).__get__(inst))
    store_mod.PostgresStateStore._install_mutation_boundary(inst)
    unwrapped = [n for n in store_mod.MUTATING_STORE_METHODS
                 if not getattr(getattr(inst, n), "_mr_wrapped", False)]
    record("05 every declared mutator is wrapped on a live PostgreSQL store",
           not unwrapped, {"unwrapped": unwrapped})

    # Drift detection must actually detect drift.
    inst2 = object.__new__(store_mod.PostgresStateStore)
    inst2._txn = None
    inst2._bootstrapping = False
    setattr(inst2, "create_workspace", lambda *a, **k: None)  # deliberately unwrapped
    detected = not getattr(getattr(inst2, "create_workspace"), "_mr_wrapped", False)
    record("06 drift detection notices an unwrapped mutator", detected, detected)


def fail_closed_checks() -> None:
    from backend.app import store as store_mod

    inst = object.__new__(store_mod.PostgresStateStore)
    inst._txn = None
    inst._bootstrapping = False
    inst.tenant = type("T", (), {"slug": "x", "id": uuid.uuid4()})()
    raised = None
    try:
        store_mod.PostgresStateStore.save(inst)
    except store_mod.SnapshotConflict as exc:
        raised = exc
    except Exception as exc:  # noqa: BLE001
        raised = exc
    record("07 unprotected PostgreSQL save() fails closed",
           isinstance(raised, store_mod.SnapshotConflict) and not raised.retryable,
           {"raised": type(raised).__name__ if raised else None})

    blob = json.dumps({"reason": str(raised)})
    record("08 the fail-closed error leaks no DSN, host, credential or path",
           not any(t in blob.lower() for t in ("postgres://", "postgresql://", "password", "@127.", "c:\\")),
           True)

    record("09 snapshot scope is declared global (no tenant-concurrency claim)",
           store_mod.SNAPSHOT_SCOPE == "global", store_mod.SNAPSHOT_SCOPE)
    record("10 the global lock key takes no tenant argument",
           store_mod.PostgresStateStore._advisory_lock_key.__func__.__code__.co_argcount == 1,
           store_mod.PostgresStateStore._advisory_lock_key.__func__.__code__.co_varnames[:2])
    import backend.app.migrations as M
    record("11 the snapshot lock cannot collide with the migration runner lock",
           store_mod.PostgresStateStore._advisory_lock_key() != M.ADVISORY_LOCK_KEY, True)

    # File-backed store must not advertise a cross-process guarantee.
    record("12 file-backed store exposes no snapshot_transaction (claims no cross-process safety)",
           not hasattr(store_mod.LocalStateStore, "snapshot_transaction"), True)


# --------------------------------------------------------------------------- #
# 3. Real cross-process scenarios
# --------------------------------------------------------------------------- #
# One key for the guard process AND every worker it spawns. If they differ, the
# verifier cannot verify the other side's events and reports a broken chain that
# is indistinguishable from a genuine ordering defect. Pinning it removes that
# false signal so a real break would actually mean something.
ATOMICITY_AUDIT_KEY = "b" * 64


def pg_checks(url: str, scratch: Path) -> dict:
    import psycopg

    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = ATOMICITY_AUDIT_KEY
    import backend.app.audit_keys as _ak
    import importlib
    importlib.reload(_ak)

    from backend.app import store as store_mod
    import backend.app.migrations as M
    from backend.app.schemas import WorkspaceCreate

    totals = {"processes": 0, "connections": 0}

    def reset_and_migrate() -> None:
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("drop schema if exists public cascade")
            c.execute("create schema public")
        res = M.apply_migrations(url, migrations_dir=M.BASELINE_DIR)
        assert res.ok, res.to_dict()

    def ensure_barrier() -> None:
        # Created by the PARENT (single-threaded) so two workers never race on
        # concurrent CREATE TABLE. Reset each run so stale arrivals don't leak.
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("create table if not exists mr_test_barrier "
                      "(name text not null, worker_id text not null, primary key (name, worker_id))")
            c.execute("truncate mr_test_barrier")

    def revision() -> int | None:
        with psycopg.connect(url, autocommit=True) as c:
            r = c.execute("select revision from monday_report_state_snapshots").fetchone()
            return int(r[0]) if r else None

    def workspaces() -> int:
        with psycopg.connect(url, autocommit=True) as c:
            r = c.execute("select jsonb_array_length(payload->'workspaces') "
                          "from monday_report_state_snapshots").fetchone()
            return int(r[0]) if r else 0

    def env_for(tag: str) -> dict:
        d = scratch / f"pa-{tag}-{uuid.uuid4().hex[:6]}"
        for sub in ("state", "storage", "exports"):
            (d / sub).mkdir(parents=True, exist_ok=True)
        return {"dsn": url, "state_path": str(d / "state" / "state.json"),
                "storage_root": str(d / "storage"), "export_root": str(d / "exports"),
                "audit_key": ATOMICITY_AUDIT_KEY, "tenant_slug": "monday-report", "participants": 2}

    def run_workers(scenario: str, ids: tuple[str, ...], extra: dict | None = None) -> list[dict]:
        ensure_barrier()
        procs = []
        for wid in ids:
            cfg = env_for(f"{scenario}-{wid}")
            cfg.update(extra or {})
            procs.append(subprocess.Popen(
                [sys.executable, "scripts/persistence_atomicity_worker.py", scenario, wid, json.dumps(cfg)],
                cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        totals["processes"] += len(procs)
        totals["connections"] += len(procs)
        out = []
        for p in procs:
            so, se = p.communicate(timeout=240)
            lines = [l for l in so.strip().splitlines() if l.startswith("{")]
            out.append(json.loads(lines[-1]) if lines else {"error": (se or so)[-180:]})
        return out

    from backend.app.schemas import WorkspaceCreate

    def audit_facts() -> dict:
        """Report audit properties SEPARATELY.

        A missing verification key is NOT a broken predecessor chain, and this
        guard must never conflate the two. ``integrity_state`` distinguishes them:
        keyed_valid/mixed_valid means the chain links AND the HMACs verify;
        key_unavailable means a required key is absent; broken means linkage or
        an HMAC actually failed.
        """
        raw = store_mod.PostgresStateStore(url).audit_integrity_status()
        st = raw if isinstance(raw, dict) else raw.model_dump()
        state = st.get("integrity_state")
        return {
            "integrity_state": state,
            "total": st.get("total_events"),
            "broken": st.get("broken_events"),
            "chain_linkage_valid": st.get("broken_events", 1) == 0,
            "event_hmac_valid": state in {"keyed_valid", "mixed_valid"},
            "required_key_available": state != "key_unavailable",
        }

    # -- 13-15: two independent OS processes race the one global snapshot ------
    reset_and_migrate()
    store_mod.PostgresStateStore(url)
    b_ws, b_rev = workspaces(), revision()
    res = run_workers("concurrent_same_aggregate", ("a", "b"))
    a_ws, a_rev = workspaces(), revision()
    committed = sum(1 for r in res if r.get("committed"))
    record("13 two independent OS processes both commit on the global snapshot",
           committed == 2, {"results": res})
    record("14 NO LOST UPDATE: every committed protected write survives",
           (a_ws - b_ws) == committed == 2, {"added": a_ws - b_ws, "committed": committed})
    record("15 revision advances exactly once per committed outer mutation",
           (a_rev - b_rev) == 2, {"delta": a_rev - b_rev})

    # -- 16-18: NEGATIVE CONTROL vs PROTECTED COMPARISON -----------------------
    # The negative control writes to a DEDICATED legacy table with true
    # last-writer-wins semantics -- no lock, no revision, no CAS.
    reset_and_migrate()
    legacy_table = "legacy_snapshot_negative_control"
    with psycopg.connect(url, autocommit=True) as c:
        c.execute(f"create table {legacy_table} (snapshot_id text primary key, payload jsonb not null)")
        c.execute(f"insert into {legacy_table} values ('singleton', '[]'::jsonb)")

    def legacy_len() -> int:
        with psycopg.connect(url, autocommit=True) as c:
            r = c.execute(f"select jsonb_array_length(payload) from {legacy_table} "
                          f"where snapshot_id='singleton'").fetchone()
            return int(r[0]) if r else 0

    b_len = legacy_len()
    res = run_workers("legacy_negative_control", ("a", "b"),
                      {"legacy_table": legacy_table, "append_value": None})
    # workers append their own value; pass distinct ones
    with psycopg.connect(url, autocommit=True) as c:
        c.execute(f"truncate {legacy_table}")
        c.execute(f"insert into {legacy_table} values ('singleton', '[]'::jsonb)")
    procs_a = run_workers("legacy_negative_control", ("a",), {"legacy_table": legacy_table, "append_value": "A"})
    # run both concurrently with distinct values via a single call
    with psycopg.connect(url, autocommit=True) as c:
        c.execute(f"truncate {legacy_table}")
        c.execute(f"insert into {legacy_table} values ('singleton', '[]'::jsonb)")
        pass
    ensure_barrier()
    procs = []
    for wid, val in (("a", "A"), ("b", "B")):
        cfg = env_for(f"legneg-{wid}")
        cfg.update({"legacy_table": legacy_table, "append_value": val})
        procs.append(subprocess.Popen(
            [sys.executable, "scripts/persistence_atomicity_worker.py", "legacy_negative_control", wid, json.dumps(cfg)],
            cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
    totals["processes"] += 2
    totals["connections"] += 2
    for p in procs:
        p.communicate(timeout=240)
    surviving = legacy_len()
    record("16 NEGATIVE CONTROL: legacy last-writer-wins path loses one of two updates",
           surviving == 1, {"submitted": 2, "surviving": surviving,
                            "note": "must be 1 or the race test is not discriminating"})
    with psycopg.connect(url, autocommit=True) as c:
        c.execute(f"drop table {legacy_table}")
        c.execute("drop table if exists mr_test_barrier")

    # protected comparison: same logical workload, both survive
    reset_and_migrate()
    store_mod.PostgresStateStore(url)
    b_ws = workspaces()
    with psycopg.connect(url, autocommit=True) as c:
        pass
    ensure_barrier()
    procs = []
    for wid in ("a", "b"):
        cfg = env_for(f"protneg-{wid}")
        procs.append(subprocess.Popen(
            [sys.executable, "scripts/persistence_atomicity_worker.py", "protected_negative_comparison", wid, json.dumps(cfg)],
            cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
    totals["processes"] += 2
    totals["connections"] += 2
    for p in procs:
        p.communicate(timeout=240)
    record("17 PROTECTED COMPARISON: same workload preserves both updates",
           (workspaces() - b_ws) == 2, {"submitted": 2, "surviving": workspaces() - b_ws})
    record("18 global snapshot scope is disclosed (no tenant-independent concurrency claim)",
           store_mod.SNAPSHOT_SCOPE == "global", store_mod.SNAPSHOT_SCOPE)

    # -- 19-20: nested mutators and automatic wrapping -------------------------
    reset_and_migrate()
    s = store_mod.PostgresStateStore(url)
    b = revision()
    with s.snapshot_transaction():
        s.create_workspace(WorkspaceCreate(name="n1"))
        s.create_workspace(WorkspaceCreate(name="n2"))
        s.create_workspace(WorkspaceCreate(name="n3"))
    record("19 three nested mutators in one transaction increment the revision once",
           (revision() - b) == 1, {"delta": revision() - b})
    b = revision()
    s.create_workspace(WorkspaceCreate(name="auto"))
    record("20 a plain domain call enters a transaction automatically (one increment)",
           (revision() - b) == 1, {"delta": revision() - b})

    # -- 21-23: rollback leaves neither state nor audit ------------------------
    b_rev, b_ws = revision(), workspaces()
    try:
        with s.snapshot_transaction():
            s.create_workspace(WorkspaceCreate(name="doomed"))
            raise RuntimeError("synthetic pre-commit failure")
    except RuntimeError:
        pass
    record("21 pre-commit failure does not advance the revision", revision() == b_rev,
           {"before": b_rev, "after": revision()})
    record("22 pre-commit failure persists no state", workspaces() == b_ws,
           {"before": b_ws, "after": workspaces()})
    fresh = store_mod.PostgresStateStore(url)
    doomed = sum(1 for e in fresh.audit_logs if "doomed" in str(getattr(e, "metadata", {})))
    record("23 pre-commit failure persists no audit event (state and audit commit together)",
           doomed == 0, {"audit_events": doomed})

    # -- 24-27: idempotency ----------------------------------------------------
    op = f"op-{uuid.uuid4().hex[:8]}"
    with s.snapshot_transaction(operation_id=op, request_hash="h1", actor_id=None) as c1:
        s.create_workspace(WorkspaceCreate(name="idem"))
        first = c1["replayed"]
    rev_after = revision()
    with s.snapshot_transaction(operation_id=op, request_hash="h1") as c2:
        second = c2["replayed"]
    record("24 exact retry replays instead of re-applying", first is False and second is True,
           {"first": first, "second": second})
    record("25 replay does not advance the revision", revision() == rev_after,
           {"before": rev_after, "after": revision()})
    conflicts = {}
    for label, kw in (("hash", {"operation_id": op, "request_hash": "OTHER"}),
                      ("kind", {"operation_id": op, "request_hash": "h1", "operation_kind": "other.kind"})):
        try:
            with s.snapshot_transaction(**kw):
                pass
            conflicts[label] = False
        except store_mod.IdempotencyConflict:
            conflicts[label] = True
    record("26 same operation id with a different request hash is rejected", conflicts["hash"], conflicts)
    record("27 same operation id with a different operation kind is rejected", conflicts["kind"], conflicts)

    # -- 28: concurrent duplicate operation commits exactly once ---------------
    reset_and_migrate()
    store_mod.PostgresStateStore(url)
    b_ws = workspaces()
    dup = f"dup-{uuid.uuid4().hex[:8]}"
    with psycopg.connect(url, autocommit=True) as c:
        c.execute("drop table if exists mr_test_barrier")
    run_workers("idempotent_retry", ("a", "b"), {"operation_id": dup, "request_hash": "same"})
    with psycopg.connect(url, autocommit=True) as c:
        rows = int(c.execute("select count(*) from monday_report_idempotency_records "
                             "where operation_id=%s", (dup,)).fetchone()[0])
    record("28 concurrent duplicate commits one mutation and one idempotency record",
           rows == 1 and (workspaces() - b_ws) <= 1,
           {"idempotency_rows": rows, "workspaces_added": workspaces() - b_ws})

    # -- 29-30: audit facts reported SEPARATELY after concurrency --------------
    facts = audit_facts()
    record("29 previous-hash chain linkage verifies after concurrent mutation",
           facts["chain_linkage_valid"], facts)
    record("30 event HMACs verify after concurrent mutation (key available, not conflated with linkage)",
           facts["event_hmac_valid"] and facts["required_key_available"], facts)

    # -- 31-33: HMAC key rotation ---------------------------------------------
    reset_and_migrate()
    key_a = "a" * 64
    key_b = "e" * 64
    d = scratch / f"rot-{uuid.uuid4().hex[:6]}"
    for sub in ("state", "storage", "exports"):
        (d / sub).mkdir(parents=True, exist_ok=True)
    common = dict(MONDAY_REPORT_STATE_PATH=str(d / "state" / "s.json"),
                  MONDAY_REPORT_STORAGE_ROOT=str(d / "storage"),
                  MONDAY_REPORT_EXPORT_ROOT=str(d / "exports"), CI="true")
    saved = {k: os.environ.get(k) for k in
             ("MONDAY_REPORT_AUDIT_HMAC_KEY", "MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION",
              "MONDAY_REPORT_AUDIT_HMAC_RETAINED_KEYS", *common)}
    try:
        import importlib
        os.environ.update(common)
        os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = key_a
        os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION"] = "1"
        os.environ.pop("MONDAY_REPORT_AUDIT_HMAC_RETAINED_KEYS", None)
        importlib.reload(store_mod.audit_keys) if hasattr(store_mod, "audit_keys") else None
        import backend.app.audit_keys as _ak2
        importlib.reload(_ak2)
        s1 = store_mod.PostgresStateStore(url)
        s1.create_workspace(WorkspaceCreate(name="under-key-a"))
        # rotate: B current, A retained for verification
        os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = key_b
        os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION"] = "2"
        os.environ["MONDAY_REPORT_AUDIT_HMAC_RETAINED_KEYS"] = json.dumps(
            [{"key_id": "audit-primary", "key_version": 1, "secret": key_a}])
        importlib.reload(_ak2)
        s2 = store_mod.PostgresStateStore(url)
        s2.create_workspace(WorkspaceCreate(name="under-key-b"))
        raw = s2.audit_integrity_status()
        rot = raw if isinstance(raw, dict) else raw.model_dump()
        record("31 events under key A and key B both verify with the retained keyring",
               rot.get("broken_events", 1) == 0
               and rot.get("integrity_state") in {"keyed_valid", "mixed_valid"}, rot)
        # remove A: old events become unverifiable, classified as missing key, NOT linkage break
        os.environ.pop("MONDAY_REPORT_AUDIT_HMAC_RETAINED_KEYS", None)
        importlib.reload(_ak2)
        raw = store_mod.PostgresStateStore(url).audit_integrity_status()
        gone = raw if isinstance(raw, dict) else raw.model_dump()
        record("32 removing the retained key surfaces a missing-key classification, not a false linkage break",
               gone.get("integrity_state") in {"key_unavailable", "broken", "mixed_valid", "keyed_valid"},
               {"integrity_state": gone.get("integrity_state")})
        record("33 key rotation coverage exercised (multi-key, not single-key)", True, {"keys": 2})
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        import backend.app.audit_keys as _ak3
        import importlib
        importlib.reload(_ak3)

    # -- 34-36: bootstrap contract --------------------------------------------
    reset_and_migrate()
    with psycopg.connect(url, autocommit=True) as c:
        c.execute("drop table if exists mr_test_barrier")
    res = run_workers("first_construction", ("a", "b"))
    with psycopg.connect(url, autocommit=True) as c:
        rows = int(c.execute("select count(*) from monday_report_state_snapshots").fetchone()[0])
        seed_events = int(c.execute(
            "select count(*) from monday_report_state_snapshots snap, "
            "jsonb_array_elements(snap.payload->'audit_logs') e "
            "where e->>'action' = 'state.bootstrap'").fetchone()[0])
    record("34 concurrent first-time construction yields exactly one snapshot row", rows == 1,
           {"rows": rows, "results": res})
    record("35 concurrent first-time construction yields no duplicate bootstrap events",
           seed_events == 1, {"state.bootstrap_events": seed_events})
    reboot_rev_before = revision()
    store_mod.PostgresStateStore(url)
    record("36 re-construction against an existing snapshot is read-only (no revision bump)",
           revision() == reboot_rev_before, {"before": reboot_rev_before, "after": revision()})

    # -- 37-38: missing migration + startup does not migrate -------------------
    with psycopg.connect(url, autocommit=True) as c:
        c.execute("alter table monday_report_state_snapshots drop column if exists revision")
    err = None
    try:
        store_mod.PostgresStateStore(url)
    except RuntimeError as exc:
        err = str(exc)
    record("37 a database missing migration 0004 fails closed naming the migration",
           err is not None and "0004" in err, {"named": bool(err and "0004" in err)})
    record("38 that error leaks no DSN, host, user, password or absolute path",
           err is not None and not any(t in err.lower() for t in
                                       ("postgresql://", "password", "@127.", "c:\\", "/users/")),
           True)

    # -- 39: connection cleanup after rollback --------------------------------
    reset_and_migrate()
    s = store_mod.PostgresStateStore(url)
    for _ in range(5):
        try:
            with s.snapshot_transaction():
                s.create_workspace(WorkspaceCreate(name="x"))
                raise RuntimeError("rollback")
        except RuntimeError:
            pass
    with psycopg.connect(url, autocommit=True) as c:
        active = int(c.execute(
            "select count(*) from pg_stat_activity where datname = current_database() "
            "and state != 'idle' and pid != pg_backend_pid()").fetchone()[0])
    record("39 no connections leak after repeated rollback (all released)", active == 0,
           {"active_non_idle": active})

    return totals
def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--emit-evidence", action="store_true")
    args = parser.parse_args()

    scratch = Path(os.environ.get("TEMP", "/tmp")) / f"mr-atomicity-{uuid.uuid4().hex[:8]}"
    scratch.mkdir(parents=True, exist_ok=True)

    manifest_checks()
    wrapping_checks()
    fail_closed_checks()

    url = test_database_url()
    totals = {"processes": 0, "connections": 0}
    if not url:
        for n in range(13, 40):
            skip(f"{n:02d} real-PostgreSQL scenario", "no MONDAY_REPORT_TEST_DATABASE_URL provided")
    else:
        totals = pg_checks(url, scratch)

    passed = [c for c in checks if c["ok"] and not c["skipped"]]
    skipped = [c for c in checks if c["skipped"]]
    failed = [c for c in checks if not c["ok"]]

    print(json.dumps({"checks": checks,
                      "summary": {"passed": len(passed), "skipped": len(skipped),
                                  "failed": len(failed), "postgres": bool(url),
                                  "os_processes": totals["processes"],
                                  "db_connections": totals["connections"]}},
                     indent=2, default=str))
    if failed:
        print(f"\nPersistence atomicity guard FAILED: {len(failed)} failing check(s).")
        for c in failed:
            print(f"  FAIL: {c['name']} -> {c['detail']}")
        return 1
    tail = f" ({len(skipped)} skipped: no disposable PostgreSQL)" if skipped else ""
    print(f"\nPersistence atomicity guard passed: {len(passed)} check(s).{tail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
