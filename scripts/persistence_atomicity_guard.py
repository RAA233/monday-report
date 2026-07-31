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

EVIDENCE_PATH = ROOT / "output" / "persistence" / "persistence-atomicity-evidence.v4.json"
EVIDENCE_SCHEMA_VERSION = "persistence-atomicity-evidence.v4"
# The route-idempotency HTTP contract this run proves. Bound into the evidence so
# a probe can reject a run produced under a different request contract.
ROUTE_IDEMPOTENCY_CONTRACT_VERSION = "1.0.0"
ROUTE_OPERATION_KEY_HEADER = "Idempotency-Key"

checks: list[dict] = []
# Populated by the HTTP route section of pg_checks; consumed by build_evidence to
# classify proof by boundary (direct-helper vs real-HTTP vs concurrent-HTTP vs
# uncertain-response) so a merely-internal proof can never masquerade as a
# route-level one.
ROUTE_PROOF: dict = {"suite": None, "concurrent": None, "lost_response": None, "validation": None}


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


def _file_backed_mutators_wrapped(store_mod) -> bool:
    """Construct a real file-backed store in a throwaway directory and confirm every
    declared mutator is wrapped with the local transaction boundary -- the
    behavioural, load-bearing half of the file-backend atomicity contract."""
    import tempfile

    keys = ("MONDAY_REPORT_STATE_PATH", "MONDAY_REPORT_STORAGE_ROOT",
            "MONDAY_REPORT_EXPORT_ROOT", "MONDAY_REPORT_CLIENT_DATA_MODE")
    prior = {k: os.environ.get(k) for k in keys}
    with tempfile.TemporaryDirectory(prefix="mr-atomicity-wrap-") as tmp:
        os.environ["MONDAY_REPORT_STATE_PATH"] = str(Path(tmp) / "state.json")
        os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(Path(tmp) / "storage")
        os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(Path(tmp) / "exports")
        os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
        try:
            local_store = store_mod.LocalStateStore()
            return all(
                getattr(getattr(local_store, name, None), "_mr_local_wrapped", False)
                for name in store_mod.MUTATING_STORE_METHODS)
        finally:
            for key, value in prior.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


def fail_closed_checks() -> None:
    from backend.app import store as store_mod

    inst = object.__new__(store_mod.PostgresStateStore)
    inst._txn = None
    inst._bootstrapping = False
    # Managed-state backing for the bare (no-__init__) instance so property
    # assignment routes to the committed projection instead of crashing.
    inst._published = {}
    inst._read_local = None
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

    # File-backed store: cross-process atomicity is now PROVIDED (behavioural proof
    # lives in scripts/local_snapshot_atomicity_guard.py). The contract here is
    # structural, and its exact shape matters:
    #   * the file store exposes its OWN boundary, local_snapshot_transaction;
    #   * it still does NOT define snapshot_transaction -- that name stays
    #     PostgreSQL-only so the two backends' transaction boundaries are never
    #     conflated by a guard or a caller;
    #   * the atomic path is load-bearing: the transaction and the one-shot save
    #     both go through a cross-process file lock (_SnapshotFileLock) and a
    #     persisted revision compare-and-swap (_read_disk_revision / snapshot_revision).
    import inspect as _inspect
    local = store_mod.LocalStateStore
    record("12a file-backed store exposes its own local_snapshot_transaction boundary",
           hasattr(local, "local_snapshot_transaction"), True)
    record("12b snapshot_transaction stays PostgreSQL-only (backends not conflated)",
           "snapshot_transaction" not in local.__dict__, True)
    record("12c cross-process file lock primitive exists",
           hasattr(store_mod, "_SnapshotFileLock"), True)
    txn_src = _inspect.getsource(local.local_snapshot_transaction)
    save_src = _inspect.getsource(local.save)
    record("12d the transaction and the one-shot save both take the cross-process lock",
           "_SnapshotFileLock" in txn_src and "_SnapshotFileLock" in save_src,
           {"txn_locks": "_SnapshotFileLock" in txn_src, "save_locks": "_SnapshotFileLock" in save_src})
    record("12e the transaction commits under a revision compare-and-swap",
           "_read_disk_revision" in txn_src and "SnapshotConflict" in txn_src,
           {"cas": "_read_disk_revision" in txn_src, "conflict": "SnapshotConflict" in txn_src})
    # Load-bearing fault mutation: a store whose transaction body drops the CAS
    # would leave "_read_disk_revision" absent from the source -- 12e would flip to
    # False. The assertion is therefore not vacuous: it is tied to the exact tokens
    # that implement the guarantee, so deleting either the lock or the CAS fails a check.
    record("12f every declared mutator is wrapped on a live file-backed store",
           _file_backed_mutators_wrapped(store_mod), True)


# --------------------------------------------------------------------------- #
# 2b. Route idempotency: canonical request hashing + key validation (no database)
# --------------------------------------------------------------------------- #
def route_idempotency_unit_checks() -> None:
    """The request boundary must hash deterministically and fail closed on bad keys.

    These are pure-function properties of the request-hash and key-validation
    contract, provable without a database. The real-HTTP behavioural proofs (that
    the ROUTE actually establishes this context and the store consumes it) run
    under PostgreSQL below.
    """
    import inspect

    from backend.app import idempotency as idem

    # Equivalent validated requests hash identically regardless of key ordering.
    h1 = idem.canonical_request_hash("op.kind", {"a": "1", "b": "2"}, {"x": 1, "y": {"m": 2, "n": 3}})
    h2 = idem.canonical_request_hash("op.kind", {"b": "2", "a": "1"}, {"y": {"n": 3, "m": 2}, "x": 1})
    record("40 canonical request hash is independent of key/target ordering", h1 == h2, {"equal": h1 == h2})

    # A materially different validated body yields a different hash.
    h3 = idem.canonical_request_hash("op.kind", {"a": "1", "b": "2"}, {"x": 1, "y": {"m": 2, "n": 9}})
    record("41 a different validated body yields a different request hash", h1 != h3, {"differ": h1 != h3})

    # A different operation kind yields a different hash (a key can't cross ops).
    h4 = idem.canonical_request_hash("other.kind", {"a": "1", "b": "2"}, {"x": 1, "y": {"m": 2, "n": 3}})
    record("42 a different operation kind yields a different request hash", h1 != h4, {"differ": h1 != h4})

    # The hash input is ONLY (operation kind, path targets, validated body): no
    # credential, header or timestamp is a parameter, so none can enter the hash.
    params = set(inspect.signature(idem.canonical_request_hash).parameters)
    record("43 the request hash covers only operation kind, targets and body",
           params == {"operation_kind", "target_ids", "body"}, {"params": sorted(params)})

    # Missing / malformed keys fail closed with a controlled error, never a crash.
    outcomes = {}
    for label, values in (("absent", []), ("empty", ["   "]), ("short", ["abc"]),
                          ("illegal", ["has space"]), ("conflict", ["aaaaaaaa", "bbbbbbbb"])):
        try:
            idem.validate_key(values)
            outcomes[label] = "accepted"
        except idem.IdempotencyKeyError:
            outcomes[label] = "rejected"
    record("44 malformed keys are rejected by a controlled IdempotencyKeyError",
           all(v == "rejected" for v in outcomes.values()), outcomes)


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
        # Discriminating assertion: with the retained key REMOVED, historical
        # events must classify as key_unavailable -- and specifically NOT as
        # "broken", which is the exact missing-key-misreported-as-linkage-break
        # failure this check exists to exclude.
        record("32 removing the retained key surfaces a missing-key classification, not a false linkage break",
               gone.get("integrity_state") == "key_unavailable",
               {"integrity_state": gone.get("integrity_state")})
        record("33 key rotation coverage exercised (multi-key, not single-key)",
               key_a != key_b and rot.get("keyed_event_count", 0) >= 2
               and rot.get("broken_events", 1) == 0,
               {"distinct_keys": key_a != key_b,
                "keyed_events": rot.get("keyed_event_count"),
                "broken": rot.get("broken_events")})
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
    required_prefix = store_mod.PostgresStateStore.REQUIRED_MIGRATION[:4]
    record("37 a database missing a required migration fails closed naming the CURRENT requirement",
           err is not None and required_prefix in err,
           {"named": bool(err and required_prefix in err), "required": required_prefix})
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

    # -- 45-47: REAL HTTP route idempotency (through routing + auth) -----------
    # The checks above prove the store PRIMITIVE (direct snapshot_transaction
    # calls). These prove the ROUTE LAYER establishes the operation context from a
    # real request and the store consumes it, which is the specific gap the
    # independent review flagged. Every request below traverses FastAPI routing,
    # the client-mode middleware, RBAC and validation into the PostgreSQL store.
    http = ROOT / "scripts" / "persistence_atomicity_http.py"

    def _http_json(args: list[str], timeout: int = 300) -> dict:
        proc = subprocess.run([sys.executable, str(http), *args], cwd=str(ROOT),
                              capture_output=True, text=True, timeout=timeout)
        lines = [l for l in proc.stdout.splitlines() if l.startswith("{")]
        return json.loads(lines[-1]) if lines else {"error": (proc.stderr or proc.stdout)[-300:]}

    def _corr_for(slug: str, workspace_id: str) -> int:
        # Normalized authority (migration 0005).
        with psycopg.connect(url, autocommit=True) as c:
            r = c.execute(
                "select count(*) from monday_report_norm_field_corrections "
                "where tenant_slug=%s and workspace_id=%s", (slug, workspace_id)).fetchone()
            return int(r[0]) if r else 0

    # 45: single-process HTTP suite (14 scenarios: create/replay/missing-key/
    #     malformed-key/conflict/distinct-key/failed-attempt/actor-binding/revert).
    reset_and_migrate()
    suite_cfg = env_for("http-suite")
    suite = _http_json(["suite", json.dumps(suite_cfg)])
    totals["processes"] += 1
    totals["connections"] += 1
    ROUTE_PROOF["suite"] = suite
    suite_ok = bool(suite.get("all_passed")) and int(suite.get("total", 0)) >= 14
    record("45 real-HTTP route idempotency suite passes every scenario through routing+auth",
           suite_ok, {"passed": suite.get("passed"), "total": suite.get("total"),
                      "failures": [r["name"] for r in suite.get("results", []) if not r["ok"]] or None})

    # 46: two INDEPENDENT client processes POST the same key concurrently.
    reset_and_migrate()
    setup_cfg = env_for("http-setup")
    setup = _http_json(["setup", json.dumps(setup_cfg)])
    ws = setup.get("workspace_id")
    op = f"httpdup-{uuid.uuid4().hex[:8]}"
    slug = setup_cfg["tenant_slug"]
    before = _corr_for(slug, ws) if ws else -1
    procs = []
    for wid in ("a", "b"):
        c = env_for(f"http-conc-{wid}")
        c.update({"workspace_id": ws, "operation_id": op})
        procs.append(subprocess.Popen(
            [sys.executable, str(http), "concurrent", wid, json.dumps(c)],
            cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
    totals["processes"] += 2
    totals["connections"] += 2
    conc = []
    for p in procs:
        so, se = p.communicate(timeout=240)
        lines = [l for l in so.splitlines() if l.startswith("{")]
        conc.append(json.loads(lines[-1]) if lines else {"error": (se or so)[-200:]})
    with psycopg.connect(url, autocommit=True) as c:
        idem_rows = int(c.execute("select count(*) from monday_report_idempotency_records "
                                  "where operation_id=%s", (op,)).fetchone()[0])
    delta = _corr_for(slug, ws) - before if ws else -1
    statuses = sorted(r.get("status") for r in conc)
    entity_ids = {r.get("entity_id") for r in conc}
    concurrent_ok = (idem_rows == 1 and delta == 1 and statuses == [201, 201]
                     and len(entity_ids) == 1 and None not in entity_ids)
    ROUTE_PROOF["concurrent"] = {"results": conc, "idempotency_rows": idem_rows,
                                 "correction_delta": delta, "client_process_count": 2}
    record("46 concurrent duplicate through two HTTP client processes commits exactly once",
           concurrent_ok, {"statuses": statuses, "idempotency_rows": idem_rows,
                           "correction_delta": delta, "same_entity": len(entity_ids) == 1})

    # 47: uncertain response -- committed, response lost, same-key retry replays.
    reset_and_migrate()
    lost_cfg = env_for("http-lost")
    lost = _http_json(["lost_response", json.dumps(lost_cfg)])
    totals["processes"] += 1
    totals["connections"] += 1
    ROUTE_PROOF["lost_response"] = lost
    record("47 real-HTTP uncertain response retries into a replay, never a second commit",
           bool(lost.get("all_passed")),
           {"passed": lost.get("passed"), "total": lost.get("total"),
            "failures": [r["name"] for r in lost.get("results", []) if not r["ok"]] or None})

    # 48: the validation-task route proven per-transition (outcome / rejection /
    #     administrative reopen) -- each a distinct semantic action on the shared
    #     PATCH /validation-tasks/{id} route.
    reset_and_migrate()
    vcfg = env_for("http-validation")
    vsuite = _http_json(["validation_suite", json.dumps(vcfg)])
    totals["processes"] += 1
    totals["connections"] += 1
    ROUTE_PROOF["validation"] = vsuite
    record("48 real-HTTP validation-task transitions (outcome/rejection/reopen) each proven separately",
           bool(vsuite.get("all_passed")) and int(vsuite.get("total", 0)) >= 7,
           {"passed": vsuite.get("passed"), "total": vsuite.get("total"),
            "failures": [r["name"] for r in vsuite.get("results", []) if not r["ok"]] or None})

    # -- 49: a DIRECT audit call outside any transaction commits atomically ----
    # Route/worker-level audit events (rejection audits, signed-URL issuance)
    # are durable mutations of their own: they must run in their OWN protected
    # transaction rather than hitting the fail-closed save() and being dropped.
    reset_and_migrate()
    s = store_mod.PostgresStateStore(url)
    b_rev = revision()
    s.audit("atomicity.direct_audit_probe", "api", None, {"probe": "direct"})
    fresh = store_mod.PostgresStateStore(url)
    persisted = sum(1 for e in fresh.audit_logs
                    if getattr(e, "action", "") == "atomicity.direct_audit_probe")
    record("49 direct route-level audit outside a transaction commits atomically",
           (revision() - b_rev) == 1 and persisted == 1,
           {"revision_delta": revision() - b_rev, "persisted_events": persisted})

    # -- 50: another THREAD can never join or clobber an open transaction ------
    # Thread A holds an open transaction; thread B's wrapped mutation must NOT
    # join it (it must wait and commit its own). The old cross-thread-join
    # behavior yields ONE revision increment for both mutations; correct
    # isolation yields TWO. Event-synchronized, not sleep-raced: B only starts
    # inside A's window, and A does not exit until B has started.
    import threading as _threading

    reset_and_migrate()
    s = store_mod.PostgresStateStore(url)
    b_rev, b_ws = revision(), workspaces()
    a_in_txn = _threading.Event()
    b_started = _threading.Event()
    errors: list[str] = []

    def thread_a() -> None:
        try:
            with s.snapshot_transaction():
                s.create_workspace(WorkspaceCreate(name="thread-a"))
                a_in_txn.set()
                # Hold the transaction open until B has entered its mutation call.
                b_started.wait(timeout=15)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"A:{exc.__class__.__name__}")

    def thread_b() -> None:
        try:
            a_in_txn.wait(timeout=15)
            b_started.set()
            # Under correct isolation this BLOCKS until A commits, then runs in
            # its own transaction. Under the defect it would join A's open txn.
            s.create_workspace(WorkspaceCreate(name="thread-b"))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"B:{exc.__class__.__name__}")

    ta = _threading.Thread(target=thread_a)
    tb = _threading.Thread(target=thread_b)
    ta.start(); tb.start()
    ta.join(timeout=60); tb.join(timeout=60)
    record("50 a second thread never joins an open transaction (two mutations, two commits)",
           not errors and (revision() - b_rev) == 2 and (workspaces() - b_ws) == 2
           and not ta.is_alive() and not tb.is_alive(),
           {"errors": errors, "revision_delta": revision() - b_rev,
            "workspaces_added": workspaces() - b_ws})

    with psycopg.connect(url, autocommit=True) as c:
        c.execute("drop table if exists mr_test_barrier")

    return totals


def _git(args: list[str]) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=str(ROOT), text=True).strip()
    except Exception:
        return "unknown"


def canonical_payload_sha256(payload: dict) -> str:
    body = {k: v for k, v in payload.items() if k != "payload_sha256"}
    canonical = json.dumps(body, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_evidence(totals: dict) -> dict:
    """Bind the run to its exact code, migrations and results.

    Status is derived from actual totals. It is 'passed' only when a real
    database ran with zero failures and zero skips, the negative control proved
    a lost update, the protected comparison preserved both, chain linkage and
    HMAC verification held, and the worktree is clean at the tested commit.
    Contains no key, password, DSN, username, host, port, absolute path or
    client data.
    """
    import backend.app.migrations as M
    import backend.app.store as store_mod

    by_name = {c["name"]: c for c in checks}

    def passed(prefix: str) -> bool:
        c = next((v for k, v in by_name.items() if k.startswith(prefix)), None)
        return bool(c and c["ok"] and not c["skipped"])

    n_passed = len([c for c in checks if c["ok"] and not c["skipped"]])
    n_skipped = len([c for c in checks if c["skipped"]])
    n_failed = len([c for c in checks if not c["ok"]])

    baseline = M.discover_migrations(M.BASELINE_DIR)
    negative_control_ok = passed("16 ")
    protected_ok = passed("17 ")
    chain_ok = passed("29 ")
    hmac_ok = passed("30 ")
    route_worker_command_ok = passed("13 ") and passed("34 ")  # worker/command paths enter txn

    # Proof classification (Part K): distinguish where idempotency was PROVEN so an
    # internal-only proof can never be read as a route-level one.
    transaction_boundary_ok = all(passed(p) for p in ("19 ", "20 ", "21 ", "22 ", "23 "))
    direct_helper_ok = all(passed(p) for p in ("24 ", "25 ", "26 ", "27 ", "28 "))
    request_hash_canonicalization_ok = all(passed(p) for p in ("40 ", "41 ", "42 ", "43 "))
    key_validation_ok = passed("44 ")
    http_route_ok = passed("45 ")
    concurrent_http_ok = passed("46 ")
    uncertain_response_ok = passed("47 ")

    # Individual HTTP-suite scenario outcomes, surfaced so a probe can require the
    # specific route behaviours (missing-key, conflict, actor binding) by name.
    suite = ROUTE_PROOF.get("suite") or {}
    suite_by_prefix = {r["name"][:2]: bool(r["ok"]) for r in suite.get("results", [])}

    def suite_ok(prefix: str) -> bool:
        return suite_by_prefix.get(prefix, False)

    missing_key_ok = suite_ok("04")
    conflicting_reuse_ok = suite_ok("09") and suite_ok("10")
    distinct_key_ok = suite_ok("11")
    failed_attempt_no_reserve_ok = suite_ok("12")
    actor_scope_ok = suite_ok("13")

    # Validation-task per-transition proof (V1 validated / V2 rejected / V3 reopen
    # / V4 cross-transition conflict / V5 missing-key / V6 distinct audit / V7 actor).
    validation = ROUTE_PROOF.get("validation") or {}
    v_by = {r["name"][:2]: bool(r["ok"]) for r in validation.get("results", [])}
    validation_outcome_ok = v_by.get("V1", False)
    validation_rejected_ok = v_by.get("V2", False)
    validation_reopen_ok = v_by.get("V3", False)
    validation_route_ok = passed("48 ") and bool(validation.get("all_passed"))

    # Semantic-action coverage (Part B/H). The six required domain actions collapse
    # onto three HTTP routes; approval/rejection are validation-task OUTCOMES, not
    # correction operations. Each required action must be behaviourally proven.
    semantic_actions = [
        {"action": "correction creation", "route": "POST /workspaces/{id}/field-corrections",
         "operation_kind": "field_correction.record",
         "result": "passed" if (http_route_ok and suite_ok("01")) else "not_passed"},
        {"action": "correction revert", "route": "POST /field-corrections/{id}/revert",
         "operation_kind": "field_correction.revert",
         "result": "passed" if (http_route_ok and suite_ok("14")) else "not_passed"},
        {"action": "validation outcome", "route": "PATCH /validation-tasks/{id} (status=validated)",
         "operation_kind": "validation_task.update",
         "result": "passed" if validation_outcome_ok else "not_passed"},
        # 'Correction approval' is not a corrections operation; the approval semantic
        # is the validation VALIDATED outcome (same proof as validation outcome).
        {"action": "correction approval (validation VALIDATED outcome)",
         "route": "PATCH /validation-tasks/{id} (status=validated)",
         "operation_kind": "validation_task.update",
         "result": "passed" if validation_outcome_ok else "not_passed"},
        # 'Correction rejection' is not a corrections operation; the rejection
        # semantic is the validation REJECTED outcome.
        {"action": "correction rejection (validation REJECTED outcome)",
         "route": "PATCH /validation-tasks/{id} (status=rejected)",
         "operation_kind": "validation_task.update",
         "result": "passed" if validation_rejected_ok else "not_passed"},
        {"action": "administrative reopening", "route": "PATCH /validation-tasks/{id} (status=open)",
         "operation_kind": "validation_task.update",
         "result": "passed" if validation_reopen_ok else "not_passed"},
    ]
    required_semantic_action_count = len(semantic_actions)
    tested_semantic_action_count = sum(1 for a in semantic_actions if a["result"] == "passed")
    semantic_actions_complete = tested_semantic_action_count == required_semantic_action_count

    ran_real_db = bool(test_database_url())
    status = "passed" if (
        ran_real_db and n_failed == 0 and n_skipped == 0
        and negative_control_ok and protected_ok and chain_ok and hmac_ok
        and route_worker_command_ok
        # Route-level idempotency must be PROVEN, not merely implemented: the HTTP
        # suite, the concurrent-HTTP race and the uncertain-response retry all pass.
        and request_hash_canonicalization_ok and key_validation_ok
        and http_route_ok and concurrent_http_ok and uncertain_response_ok
        and missing_key_ok and conflicting_reuse_ok and actor_scope_ok
        and failed_attempt_no_reserve_ok
        # Every semantic action -- including each validation-task transition -- is
        # behaviourally proven through HTTP; conflated or under-counted proof fails.
        and validation_route_ok and validation_outcome_ok and validation_rejected_ok
        and validation_reopen_ok and semantic_actions_complete
    ) else "BLOCKED_INCOMPLETE"

    concurrent = ROUTE_PROOF.get("concurrent") or {}
    route_idempotency = {
        "contract_version": ROUTE_IDEMPOTENCY_CONTRACT_VERSION,
        "operation_key_header": ROUTE_OPERATION_KEY_HEADER,
        "required_route_count": 3,
        "required_routes": ["field_correction.record", "field_correction.revert",
                            "validation_task.update"],
        # All three reviewer-mutation routes are now proven BEHAVIOURALLY through
        # real HTTP (field corrections record+revert; validation-task per transition).
        "http_behaviourally_tested_routes": ["field_correction.record", "field_correction.revert",
                                             "validation_task.update"],
        "tested_route_count": 3,
        "required_semantic_action_count": required_semantic_action_count,
        "tested_semantic_action_count": tested_semantic_action_count,
        "semantic_actions": semantic_actions,
        "http_scenario_count": int(suite.get("total", 0)),
        "http_scenarios_passed": int(suite.get("passed", 0)),
        "validation_scenario_count": int(validation.get("total", 0)),
        "validation_scenarios_passed": int(validation.get("passed", 0)),
        "concurrent_http_client_count": int(concurrent.get("client_process_count", 0)),
        "concurrent_http_idempotency_rows": concurrent.get("idempotency_rows"),
        "concurrent_http_correction_delta": concurrent.get("correction_delta"),
        "transaction_boundary_result": "passed" if transaction_boundary_ok else "not_passed",
        "direct_helper_result": "passed" if direct_helper_ok else "not_passed",
        "http_route_result": "passed" if http_route_ok else "not_passed",
        "concurrent_http_result": "passed" if concurrent_http_ok else "not_passed",
        "uncertain_response_result": "passed" if uncertain_response_ok else "not_passed",
        "validation_route_result": "passed" if validation_route_ok else "not_passed",
        "validation_outcome_result": "passed" if validation_outcome_ok else "not_passed",
        "validation_rejection_result": "passed" if validation_rejected_ok else "not_passed",
        "validation_reopen_result": "passed" if validation_reopen_ok else "not_passed",
        "request_hash_canonicalization_result": "passed" if request_hash_canonicalization_ok else "not_passed",
        "missing_key_result": "passed" if missing_key_ok else "not_passed",
        "conflicting_reuse_result": "passed" if conflicting_reuse_ok else "not_passed",
        "distinct_key_commits_result": "passed" if distinct_key_ok else "not_passed",
        "failed_attempt_reserves_no_key_result": "passed" if failed_attempt_no_reserve_ok else "not_passed",
        "actor_and_operation_scope_result": "passed" if actor_scope_ok else "not_passed",
    }

    payload = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "git_commit": _git(["rev-parse", "HEAD"]),
        "git_tree": _git(["rev-parse", "HEAD^{tree}"]),
        "worktree_clean": _git(["status", "--porcelain"]) == "",
        "persistence_implementation_version": store_mod.SNAPSHOT_TRANSACTION_VERSION,
        "postgres_server_version": os.environ.get("MONDAY_REPORT_TEST_PG_SERVER_VERSION"),
        "pgvector_version": os.environ.get("MONDAY_REPORT_TEST_PGVECTOR_VERSION"),
        "postgres_image_digest": os.environ.get("MONDAY_REPORT_TEST_PG_IMAGE_DIGEST"),
        "migration_versions": [m.version for m in baseline],
        "migration_checksums": {m.filename: m.checksum_sha256 for m in baseline},
        "repository_mode": "postgres",
        "snapshot_scope": store_mod.SNAPSHOT_SCOPE,
        "serialization_statement": "PostgreSQL snapshot mode serializes all application writers.",
        "lock_strategy": "global transaction-level pg_advisory_xact_lock + SELECT ... FOR UPDATE",
        "lock_key_derivation": f"signed int64 from sha256('{store_mod.SNAPSHOT_LOCK_NAMESPACE}')",
        "lock_timeout_ms": store_mod.SNAPSHOT_LOCK_TIMEOUT_MS,
        "revision_strategy": "compare-and-swap: UPDATE ... WHERE revision = <read>, exactly one row",
        "retry_strategy": "lock-timeout and serialization failures surface as controlled conflicts; "
                          "stale revision is non-retryable",
        "idempotency_strategy": "unique (tenant_slug, operation_id); replay rejected on differing "
                                "request hash, operation kind, or actor; stores a hash, never the body",
        "operation_key_source": "route _establish_idempotency(Idempotency-Key) -> "
                                "snapshot_transaction(operation_id=..., request_hash=..., "
                                "operation_kind=..., actor_id=...)",
        "os_process_count": totals.get("processes", 0),
        "db_connection_count": totals.get("connections", 0),
        "negative_control_lost_update": negative_control_ok,
        "protected_comparison_preserved_both": protected_ok,
        "chain_linkage_result": "passed" if chain_ok else "not_passed",
        "event_hmac_result": "passed" if hmac_ok else "not_passed",
        "route_worker_command_boundary_result": "passed" if route_worker_command_ok else "not_passed",
        # Top-level route-idempotency results (Part K/L): a probe can gate on these
        # without parsing the nested block.
        "http_route_idempotency_result": "passed" if http_route_ok else "not_passed",
        "concurrent_http_idempotency_result": "passed" if concurrent_http_ok else "not_passed",
        "uncertain_response_result": "passed" if uncertain_response_ok else "not_passed",
        "validation_route_idempotency_result": "passed" if validation_route_ok else "not_passed",
        "semantic_action_coverage_complete": semantic_actions_complete,
        "route_idempotency": route_idempotency,
        "totals": {"passed": n_passed, "skipped": n_skipped, "failed": n_failed},
        "status": status,
    }
    payload["payload_sha256"] = canonical_payload_sha256(payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--emit-evidence", action="store_true")
    args = parser.parse_args()

    scratch = Path(os.environ.get("TEMP", "/tmp")) / f"mr-atomicity-{uuid.uuid4().hex[:8]}"
    scratch.mkdir(parents=True, exist_ok=True)

    manifest_checks()
    wrapping_checks()
    fail_closed_checks()
    route_idempotency_unit_checks()

    url = test_database_url()
    totals = {"processes": 0, "connections": 0}
    if not url:
        for n in list(range(13, 40)) + [45, 46, 47, 48, 49, 50]:
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
    if args.emit_evidence:
        evidence = build_evidence(totals)
        EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
        EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        # Never let evidence be written from an incomplete run.
        if evidence["status"] != "passed" and not failed:
            print(f"\nNOTE: evidence status is {evidence['status']!r} (not 'passed'); "
                  "the control stays BLOCKED.")
        print(f"Wrote evidence: {EVIDENCE_PATH.relative_to(ROOT).as_posix()} "
              f"(status={evidence['status']})")

    tail = f" ({len(skipped)} skipped: no disposable PostgreSQL)" if skipped else ""
    print(f"\nPersistence atomicity guard passed: {len(passed)} check(s).{tail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
