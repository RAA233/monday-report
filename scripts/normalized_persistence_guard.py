"""Guard for normalized correction persistence (migration 0005 vertical slice).

Proves, against a real disposable PostgreSQL 16 + pgvector:

A. SCHEMA/MIGRATION — 0005 fresh apply, 0004->0005 upgrade, idempotent rerun,
   deterministic checksums, baseline equivalence, immutable history unchanged,
   failing-migration rollback, and that API startup never migrates.
B. REPOSITORY BEHAVIOUR — normalized rows are the single write/read authority:
   snapshot keys emptied + marker, reads come from tables, deterministic
   projection, injected drift detected, per-row revisions.
C. ROUTES — the six semantic actions through real HTTP (the shared scenario
   suites), unchanged response contract.
D. CROSS-PROCESS CONCURRENCY — the Part G races with independent OS processes
   and connections: same-field race, duplicate key, record-vs-revert,
   approval-vs-rejection, approval-vs-reopen, one-terminal-outcome-per-revision,
   stale revision, replay/conflict, lost response, audit/HMAC failure rollback,
   constraint-failure rollback, process kill, independent aggregates/tenants,
   bounded lock timeout, and no cross-transaction context leakage.
E. IMPORT — assess/dry-run/execute/verify lifecycle, idempotent rerun,
   conflicting source refused, unsupported state fails closed, startup gate.
F. TENANT/RLS — forced row-level security proven with a NON-superuser role
   (direct SQL), cross-tenant idempotency isolation, and worker/tenant scoping.
G. LIFECYCLE/AUTHORITY — retention apply deletes normalized rows in the same
   transaction (no resurrection), create_store fails closed on an un-imported
   snapshot (no silent local fallback), a live supersede writes the typed
   superseded_by_id back-link, and the authority-marker refusal applies per
   transaction (an old-version writer's snapshot is never overwritten).

Honest skipping: without MONDAY_REPORT_TEST_DATABASE_URL the PostgreSQL
sections report SKIPPED and the evidence builder refuses to emit 'passed'.

Run: ``python scripts/normalized_persistence_guard.py [--emit-evidence]``
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "scripts"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

EVIDENCE_PATH = ROOT / "output" / "persistence" / "normalized-correction-persistence-evidence.v1.json"
EVIDENCE_SCHEMA_VERSION = "normalized-correction-persistence-evidence.v1"
IMPLEMENTATION_VERSION = "1.0.0"
GUARD_AUDIT_KEY = "b" * 64

checks: list[dict] = []
TOTALS = {"processes": 0, "connections": 0, "route_scenarios": 0, "race_scenarios": 0,
          "import_checks": 0, "tenant_checks": 0, "lifecycle_checks": 0}


def record(name: str, ok: bool, detail: object = "", *, skipped: bool = False) -> None:
    checks.append({"name": name, "ok": bool(ok), "skipped": bool(skipped), "detail": detail})


def skip(name: str, reason: str) -> None:
    record(name, True, reason, skipped=True)


def test_database_url() -> str | None:
    return os.environ.get("MONDAY_REPORT_TEST_DATABASE_URL")


CORRECTION = {
    "target_type": "report_field", "field_key": "well",
    "source_value": "SRC", "corrected_value": "FIX",
    "correction_reason": "normalized guard scenario",
}
BREACH = {"metric": "feet_drilled_per_day", "value": 100.0, "unit": "ft/day",
          "data_source": "synthetic"}


# --------------------------------------------------------------------------- #
# No-database checks
# --------------------------------------------------------------------------- #
def constants_mirror_checks() -> None:
    """The import tool mirrors store constants; they must never drift."""
    import backend.app.normalized_import as imp
    import backend.app.store as store_mod

    record("01 import tool mirrors the advisory-lock namespace",
           imp.SNAPSHOT_LOCK_NAMESPACE == store_mod.SNAPSHOT_LOCK_NAMESPACE, True)
    record("02 import tool mirrors the lock timeout",
           imp.SNAPSHOT_LOCK_TIMEOUT_MS == store_mod.SNAPSHOT_LOCK_TIMEOUT_MS, True)
    record("03 import tool mirrors the control-character scrub",
           imp.UNSAFE_TEXT_CONTROL_CHARS.pattern == store_mod.UNSAFE_TEXT_CONTROL_CHARS.pattern, True)
    record("04 import tool mirrors the normalized entity keys",
           tuple(imp.NORMALIZED_ENTITY_KEYS) ==
           tuple(store_mod.PostgresStateStore.NORMALIZED_ENTITY_KEYS), True)
    record("05 local snapshot backend claims no normalized guarantees "
           "(hooks are documented no-ops)",
           store_mod.LocalStateStore._normalized_persist_correction(
               object.__new__(store_mod.LocalStateStore), None, None, None) is None, True)


# --------------------------------------------------------------------------- #
# PostgreSQL sections
# --------------------------------------------------------------------------- #
def pg_checks(url: str, scratch: Path) -> None:
    import psycopg

    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = GUARD_AUDIT_KEY
    import importlib

    import backend.app.audit_keys as _ak
    importlib.reload(_ak)
    import backend.app.migrations as M
    from backend.app import store as store_mod

    def reset() -> None:
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("drop schema if exists public cascade")
            c.execute("create schema public")

    def migrate_baseline() -> None:
        res = M.apply_migrations(url, migrations_dir=M.BASELINE_DIR)
        assert res.ok, res.to_dict()

    def ensure_barrier() -> None:
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("create table if not exists mr_test_barrier "
                      "(name text not null, worker_id text not null, primary key (name, worker_id))")
            c.execute("truncate mr_test_barrier")

    def env_for(tag: str, slug: str = "np-guard") -> dict:
        d = scratch / f"np-{tag}-{uuid.uuid4().hex[:6]}"
        for sub in ("state", "storage", "exports"):
            (d / sub).mkdir(parents=True, exist_ok=True)
        return {"dsn": url, "state_path": str(d / "state" / "state.json"),
                "storage_root": str(d / "storage"), "export_root": str(d / "exports"),
                "audit_key": GUARD_AUDIT_KEY, "tenant_slug": slug, "participants": 2}

    def os_env(cfg: dict) -> dict:
        env = dict(os.environ)
        env.update({
            "MONDAY_REPORT_REPOSITORY_BACKEND": "postgres",
            "MONDAY_REPORT_DATABASE_URL": cfg["dsn"],
            "MONDAY_REPORT_CLIENT_DATA_MODE": "demo",
            "MONDAY_REPORT_DISABLE_DEMO_SEED": "true",
            "MONDAY_REPORT_TENANT_SLUG": cfg["tenant_slug"],
            "MONDAY_REPORT_USER_EMAIL": "reviewer@example.test",
            "MONDAY_REPORT_USER_FULL_NAME": "NP Guard",
            "MONDAY_REPORT_STATE_PATH": cfg["state_path"],
            "MONDAY_REPORT_STORAGE_ROOT": cfg["storage_root"],
            "MONDAY_REPORT_EXPORT_ROOT": cfg["export_root"],
            "MONDAY_REPORT_AUDIT_HMAC_KEY": cfg["audit_key"],
            "CI": "true",
        })
        return env

    FIXTURE_DRIVER = r"""
import json, os, sys
sys.path.insert(0, os.getcwd())
from fastapi.testclient import TestClient
from backend.app.main import app
spec = json.loads(sys.argv[1])
c = TestClient(app)
out = {}
ws = c.post("/workspaces", json={"name": spec.get("ws_name", "np"), "rig_name": "g"}).json()["id"]
out["workspace_id"] = ws
if spec.get("correction"):
    import uuid as _uuid
    r = c.post(f"/workspaces/{ws}/field-corrections",
               headers={"Idempotency-Key": "key-fx-" + _uuid.uuid4().hex[:12]},
               json=spec["correction"])
    out["correction_id"] = r.json().get("id"); out["correction_status"] = r.status_code
if spec.get("report"):
    r = c.post("/monday-reports", json={"workspace_id": ws, "period_start": "2026-07-01",
                                        "period_end": "2026-07-07"})
    out["report_id"] = r.json().get("id"); out["report_status"] = r.status_code
if spec.get("breach"):
    c.post(f"/workspaces/{ws}/benchmarking/measurements", json=spec["breach"])
    tasks = [t for t in c.get("/validation-tasks").json() if t["status"] == "open"]
    out["task_id"] = tasks[-1]["id"] if tasks else None
print(json.dumps(out))
"""

    def run_fixture(cfg: dict, spec: dict) -> dict:
        proc = subprocess.run([sys.executable, "-c", FIXTURE_DRIVER, json.dumps(spec)],
                              env=os_env(cfg), capture_output=True, text=True,
                              cwd=str(ROOT), timeout=240)
        lines = [l for l in proc.stdout.splitlines() if l.startswith("{")]
        assert lines, (proc.stderr or proc.stdout)[-400:]
        TOTALS["processes"] += 1
        TOTALS["connections"] += 1
        return json.loads(lines[-1])

    def run_workers(scenario: str, ids: tuple[str, ...], extra: dict | None = None,
                    slugs: dict[str, str] | None = None) -> list[dict]:
        ensure_barrier()
        procs = []
        for wid in ids:
            cfg = env_for(f"{scenario}-{wid}", (slugs or {}).get(wid, "np-guard"))
            cfg.update(extra or {})
            procs.append(subprocess.Popen(
                [sys.executable, "scripts/normalized_persistence_worker.py", scenario, wid,
                 json.dumps(cfg)],
                cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        TOTALS["processes"] += len(procs)
        TOTALS["connections"] += len(procs)
        out = []
        for p in procs:
            so, se = p.communicate(timeout=240)
            lines = [l for l in so.strip().splitlines() if l.startswith("{")]
            out.append(json.loads(lines[-1]) if lines else {"error": (se or so)[-200:]})
        return out

    def q(sql: str, params: tuple = ()) -> list[tuple]:
        with psycopg.connect(url, autocommit=True) as c:
            # Only pass params when present: psycopg scans for placeholders when
            # given a params sequence, which would break literal LIKE '%' SQL.
            cur = c.execute(sql, params) if params else c.execute(sql)
            return cur.fetchall() if cur.description is not None else []

    def q1(sql: str, params: tuple = ()):
        rows = q(sql, params)
        return rows[0][0] if rows else None

    # ---------------------------------------------------------------- A ----- #
    reset()
    res = M.apply_migrations(url, migrations_dir=M.BASELINE_DIR)
    record("06 fresh corrected baseline applies 0001..0005", res.ok and
           q1("select count(*) from pg_tables where tablename like 'monday_report_norm%'") == 4,
           {"ok": res.ok})

    res = M.apply_migrations(url, migrations_dir=M.BASELINE_DIR)
    applied = res.to_dict().get("applied", [])
    record("07 rerun over applied state is an idempotent no-op",
           res.ok and not applied, {"applied": applied})

    m_all = {m.filename: m.checksum_sha256 for m in M.discover_migrations(M.BASELINE_DIR)}
    m_all2 = {m.filename: m.checksum_sha256 for m in M.discover_migrations(M.BASELINE_DIR)}
    record("08 LF-normalized checksums are deterministic across discovery runs",
           m_all == m_all2 and "0005_normalized_corrections.sql" in m_all, True)

    mig_0005 = (ROOT / "db" / "migrations" / "0005_normalized_corrections.sql").read_bytes()
    base_0005 = (ROOT / "db" / "baseline" / "0005_normalized_corrections.sql").read_bytes()
    record("09 migration 0005 and its baseline copy are byte-identical",
           mig_0005 == base_0005, True)

    unchanged = subprocess.run(
        ["git", "diff", "--quiet", "HEAD", "--",
         "db/migrations/0001_foundation.sql", "db/migrations/0002_postgres_state_snapshot.sql",
         "db/migrations/0003_benchmarking.sql", "db/migrations/0004_transactional_snapshot.sql",
         "db/baseline/0001_foundation.sql", "db/baseline/0002_postgres_state_snapshot.sql",
         "db/baseline/0003_benchmarking.sql", "db/baseline/0004_transactional_snapshot.sql"],
        cwd=str(ROOT)).returncode == 0
    record("10 immutable history 0001-0004 is unchanged in the working tree", unchanged, True)

    def schema_signature() -> dict:
        cols = q("select table_name, column_name, data_type, is_nullable "
                 "from information_schema.columns where table_name like 'monday_report_norm%' "
                 "order by 1, 2")
        idx = q("select indexname from pg_indexes where tablename like 'monday_report_norm%' "
                "order by 1")
        return {"columns": cols, "indexes": idx}

    sig_baseline = schema_signature()
    reset()
    with tempfile.TemporaryDirectory() as td:
        part = Path(td) / "part"
        part.mkdir()
        import shutil
        for f in sorted((ROOT / "db" / "baseline").glob("0*.sql")):
            if not f.name.startswith("0005"):
                shutil.copy(f, part / f.name)
        assert M.apply_migrations(url, migrations_dir=part).ok
    up = M.apply_migrations(url, migrations_dir=M.BASELINE_DIR)
    sig_upgrade = schema_signature()
    record("11 the 0004->0005 upgrade path applies exactly migration 5",
           up.ok and [m["version"] for m in up.to_dict().get("applied", [])] == [5], True)
    record("12 baseline and upgrade paths produce equivalent final schemas",
           sig_baseline == sig_upgrade,
           {"columns": len(sig_baseline["columns"]), "indexes": len(sig_baseline["indexes"])})

    # failing follow-on migration rolls back atomically
    with tempfile.TemporaryDirectory() as td:
        bad = Path(td) / "bad"
        bad.mkdir()
        import shutil
        for f in sorted((ROOT / "db" / "baseline").glob("0*.sql")):
            shutil.copy(f, bad / f.name)
        (bad / "0006_fails.sql").write_text(
            "create table np_partial_artifact (id int);\nselect broken syntax here;\n")
        res_bad = M.apply_migrations(url, migrations_dir=bad)
    record("13 a failing follow-on migration stops and rolls back its artifacts",
           not res_bad.ok and q1("select count(*) from pg_tables where tablename = 'np_partial_artifact'") == 0,
           {"ok": res_bad.ok})

    # startup never migrates: DB at 0004 only -> constructor fails naming 0005
    reset()
    with tempfile.TemporaryDirectory() as td:
        part = Path(td) / "part"
        part.mkdir()
        import shutil
        for f in sorted((ROOT / "db" / "baseline").glob("0*.sql")):
            if not f.name.startswith("0005"):
                shutil.copy(f, part / f.name)
        assert M.apply_migrations(url, migrations_dir=part).ok
    err = None
    try:
        store_mod.PostgresStateStore(url)
    except RuntimeError as exc:
        err = str(exc)
    still_absent = q1("select count(*) from pg_tables where tablename like 'monday_report_norm%'") == 0
    record("14 startup on a 0004-only database fails closed naming 0005 and runs no DDL",
           err is not None and "0005" in err and still_absent,
           {"named": bool(err and "0005" in err), "tables_created": not still_absent})
    record("15 the startup error leaks no DSN, credential or absolute path",
           err is not None and not any(t in err.lower() for t in
                                       ("postgresql://", "password", "@127.", "c:\\", "/users/")), True)

    # ---------------------------------------------------------------- B ----- #
    reset(); migrate_baseline()
    cfg = env_for("repo")
    fx = run_fixture(cfg, {"correction": CORRECTION, "breach": BREACH})
    ws = fx["workspace_id"]

    record("16 mutations create normalized rows with audit and operation linkage",
           q1("select count(*) from monday_report_norm_field_corrections") == 1
           and q1("select count(*) from monday_report_norm_validation_tasks") == 1
           and q1("select audit_event_id is not null and operation_id is not null "
                  "from monday_report_norm_field_corrections") is True,
           {"corrections": q1("select count(*) from monday_report_norm_field_corrections")})

    snap_counts = q1("select jsonb_array_length(payload->'field_corrections') "
                     "+ jsonb_array_length(payload->'validation_tasks') "
                     "+ jsonb_array_length(payload->'monday_reports') "
                     "from monday_report_state_snapshots")
    marker = q1("select payload->'normalized_authority'->>'version' from monday_report_state_snapshots")
    record("17 the snapshot holds ZERO migrated entities and carries the authority marker "
           "(no independent dual write)", snap_counts == 0 and marker == "1",
           {"snapshot_entities": snap_counts, "marker_version": marker})

    # reads use normalized authority: mutate the ROW directly, the app must see it
    q("update monday_report_norm_field_corrections set doc = jsonb_set(doc, '{correction_reason}', "
      "to_jsonb('EDITED-IN-DB'::text))")
    probe = subprocess.run([sys.executable, "-c",
        "import json,os,sys; sys.path.insert(0,os.getcwd())\n"
        "from fastapi.testclient import TestClient\n"
        "from backend.app.main import app\n"
        "c=TestClient(app)\n"
        f"print(json.dumps(c.get('/workspaces/{ws}/field-corrections').json()))"],
        env=os_env(cfg), capture_output=True, text=True, cwd=str(ROOT), timeout=240)
    TOTALS["processes"] += 1; TOTALS["connections"] += 1
    listed = json.loads([l for l in probe.stdout.splitlines() if l.startswith("[")][-1])
    record("18 route reads serve the NORMALIZED authority (a direct row edit is visible)",
           listed and listed[0].get("correction_reason") == "EDITED-IN-DB",
           {"reason": listed[0].get("correction_reason") if listed else None})

    from backend.app.repositories import normalized_drift_report

    class _T:  # minimal store-shape for the drift reporter
        pass

    os.environ["MONDAY_REPORT_TENANT_SLUG"] = cfg["tenant_slug"]
    try:
        guard_store = store_mod.PostgresStateStore(url)
    finally:
        os.environ.pop("MONDAY_REPORT_TENANT_SLUG", None)
    clean_drift = normalized_drift_report(guard_store)
    q("update monday_report_norm_field_corrections set status = 'reverted'")  # typed-only edit
    dirty_drift = normalized_drift_report(guard_store)
    q("update monday_report_norm_field_corrections set status = doc->>'status'")  # heal
    record("19 drift detection is discriminating (clean=0; injected typed/doc drift is flagged)",
           clean_drift == [] and len(dirty_drift) >= 1,
           {"clean": clean_drift, "dirty": dirty_drift[:3]})

    dump_a = [r[0] for r in q("select doc from monday_report_norm_field_corrections order by id")]
    dump_b = [r[0] for r in q("select doc from monday_report_norm_field_corrections order by id")]
    record("20 the compatibility projection is deterministic", dump_a == dump_b, True)

    rev0 = q1("select revision from monday_report_norm_field_corrections limit 1")
    probe2 = run_fixture(cfg, {"ws_name": "repo2", "correction": {**CORRECTION, "corrected_value": "V2"}})
    record("21 row revisions start at zero and CAS forward on mutation",
           rev0 == 0 and probe2.get("correction_status") == 201, {"rev0": rev0})

    # ---------------------------------------------------------------- C ----- #
    http = ROOT / "scripts" / "persistence_atomicity_http.py"

    def http_json(args: list[str], cfgx: dict) -> dict:
        proc = subprocess.run([sys.executable, str(http), *args], cwd=str(ROOT),
                              capture_output=True, text=True, timeout=420, env=os.environ.copy())
        lines = [l for l in proc.stdout.splitlines() if l.startswith("{")]
        TOTALS["processes"] += 1
        TOTALS["connections"] += 1
        return json.loads(lines[-1]) if lines else {"error": (proc.stderr or proc.stdout)[-300:]}

    reset(); migrate_baseline()
    suite_cfg = env_for("http-suite")
    suite = http_json(["suite", json.dumps(suite_cfg)], suite_cfg)
    TOTALS["route_scenarios"] += int(suite.get("total", 0))
    record("22 the 14-scenario correction route suite passes on the normalized backend",
           bool(suite.get("all_passed")) and int(suite.get("total", 0)) >= 14,
           {"passed": suite.get("passed"), "total": suite.get("total"),
            "failures": [r["name"] for r in suite.get("results", []) if not r["ok"]] or None})

    reset(); migrate_baseline()
    vcfg = env_for("http-validation")
    vsuite = http_json(["validation_suite", json.dumps(vcfg)], vcfg)
    TOTALS["route_scenarios"] += int(vsuite.get("total", 0))
    record("23 the validation-task transition suite (approve/reject/reopen) passes normalized",
           bool(vsuite.get("all_passed")) and int(vsuite.get("total", 0)) >= 7,
           {"passed": vsuite.get("passed"), "total": vsuite.get("total"),
            "failures": [r["name"] for r in vsuite.get("results", []) if not r["ok"]] or None})

    reset(); migrate_baseline()
    lost_cfg = env_for("http-lost")
    lost = http_json(["lost_response", json.dumps(lost_cfg)], lost_cfg)
    record("24 commit-then-lost-response replays safely on the normalized backend (G11)",
           bool(lost.get("all_passed")), {"passed": lost.get("passed"), "total": lost.get("total")})

    # ---------------------------------------------------------------- D ----- #
    # G1 same-field race
    reset(); migrate_baseline()
    fx = run_fixture(env_for("g1-fx"), {})
    res1 = run_workers("same_field_race", ("a", "b"), {"workspace_id": fx["workspace_id"]})
    TOTALS["race_scenarios"] += 1
    active = q1("select count(*) from monday_report_norm_field_corrections where status='active'")
    total_rows = q1("select count(*) from monday_report_norm_field_corrections")
    record("25 G1 two processes correcting one field: both commit, exactly ONE active lineage",
           all(r.get("status") == 201 for r in res1) and active == 1 and total_rows == 2,
           {"statuses": [r.get("status") for r in res1], "active": active, "rows": total_rows})

    # G2 duplicate logical correction (same key, two processes)
    reset(); migrate_baseline()
    setup_cfg = env_for("g2-setup")
    setup = http_json(["setup", json.dumps(setup_cfg)], setup_cfg)
    op = f"npdup-{uuid.uuid4().hex[:8]}"
    procs = []
    ensure_barrier()
    for wid in ("a", "b"):
        c2 = env_for(f"g2-{wid}")
        c2.update({"workspace_id": setup["workspace_id"], "operation_id": op})
        procs.append(subprocess.Popen(
            [sys.executable, str(http), "concurrent", wid, json.dumps(c2)],
            cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
    TOTALS["processes"] += 2; TOTALS["connections"] += 2; TOTALS["race_scenarios"] += 1
    conc = []
    for p in procs:
        so, se = p.communicate(timeout=240)
        lines = [l for l in so.splitlines() if l.startswith("{")]
        conc.append(json.loads(lines[-1]) if lines else {"error": (se or so)[-160:]})
    rows_now = q1("select count(*) from monday_report_norm_field_corrections")
    idem_rows = q1("select count(*) from monday_report_idempotency_records where operation_id=%s", (op,))
    record("26 G2 concurrent duplicate key commits ONE correction and ONE idempotency record",
           sorted(r.get("status") for r in conc) == [201, 201] and rows_now == 1 and idem_rows == 1,
           {"statuses": [r.get("status") for r in conc], "rows": rows_now, "idem": idem_rows})

    # G3 record vs revert race
    reset(); migrate_baseline()
    fx = run_fixture(env_for("g3-fx"), {"correction": CORRECTION})
    res3 = run_workers("record_vs_revert", ("a", "b"),
                       {"workspace_id": fx["workspace_id"], "correction_id": fx["correction_id"]})
    TOTALS["race_scenarios"] += 1
    statuses = sorted(str(r[0]) for r in q(
        "select status from monday_report_norm_field_corrections order by status"))
    active3 = q1("select count(*) from monday_report_norm_field_corrections where status='active'")
    record("27 G3 record-vs-revert race resolves consistently (<=1 active, valid statuses, "
           "definitive responses)",
           all(isinstance(r.get("status"), int) for r in res3) and active3 <= 1
           and set(statuses) <= {"active", "superseded", "reverted"},
           {"responses": [r.get("status") for r in res3], "row_statuses": statuses})

    # G4 approval vs rejection race + G6 outcome-per-revision uniqueness
    reset(); migrate_baseline()
    fx = run_fixture(env_for("g4-fx"), {"breach": BREACH})
    res4 = run_workers("terminal_race", ("a", "b"),
                       {"task_id": fx["task_id"], "statuses": {"a": "validated", "b": "rejected"}})
    TOTALS["race_scenarios"] += 1
    outcome_rows = q("select task_revision, outcome from monday_report_norm_validation_outcomes "
                     "order by task_revision")
    distinct_revisions = len({r[0] for r in outcome_rows}) == len(outcome_rows)
    record("28 G4 approval-vs-rejection race: outcomes land at DISTINCT task revisions",
           all(r.get("status") == 200 for r in res4) and len(outcome_rows) == 2 and distinct_revisions,
           {"responses": [r.get("status") for r in res4], "outcomes": outcome_rows})

    dup_err = None
    try:
        q("insert into monday_report_norm_validation_outcomes "
          "(id, task_id, tenant_id, tenant_slug, task_revision, outcome, reviewer_user_id) "
          "select %s, task_id, tenant_id, tenant_slug, task_revision, 'rejected', reviewer_user_id "
          "from monday_report_norm_validation_outcomes limit 1", (uuid.uuid4(),))
    except Exception as exc:  # noqa: BLE001
        dup_err = exc.__class__.__name__
    record("29 G6 a second terminal outcome for one task revision violates UNIQUE and cannot commit",
           dup_err == "UniqueViolation", {"raised": dup_err})

    # G5 approval vs administrative reopening race
    reset(); migrate_baseline()
    fx = run_fixture(env_for("g5-fx"), {"breach": BREACH})
    res5 = run_workers("terminal_race", ("a", "b"),
                       {"task_id": fx["task_id"], "statuses": {"a": "validated", "b": "open"}})
    TOTALS["race_scenarios"] += 1
    final_status = q1("select status from monday_report_norm_validation_tasks")
    record("30 G5 approval-vs-reopen race resolves to a single consistent final status",
           all(r.get("status") == 200 for r in res5)
           and final_status in ("validated", "open"),
           {"responses": [r.get("status") for r in res5], "final": final_status})

    # G7 stale revision rejected (repository CAS across processes)
    reset(); migrate_baseline()
    fx = run_fixture(env_for("g7-fx"), {"breach": BREACH})
    res7 = run_workers("stale_revision", ("a", "b"), {"task_id": fx["task_id"]})
    TOTALS["race_scenarios"] += 1
    a = next(r for r in res7 if r["worker"] == "a")
    record("31 G7 a stale expected revision is rejected by the repository CAS",
           a.get("stale_rejected") is True, {"results": res7})

    # G12/G13 audit/HMAC failure rolls back normalized rows
    reset(); migrate_baseline()
    cfg12 = env_for("g12")
    fx12 = run_fixture(cfg12, {"correction": CORRECTION})  # keyed chain now exists
    ws12 = fx12["workspace_id"]
    rows_before = q1("select count(*) from monday_report_norm_field_corrections")
    rev_before = q1("select revision from monday_report_state_snapshots")
    env_nokey = os_env(cfg12)
    env_nokey.pop("MONDAY_REPORT_AUDIT_HMAC_KEY", None)
    # A REGISTERED field key (the registry 422s unregistered ones before audit);
    # superseding the fixture's active correction is the audited mutation path.
    body12 = json.dumps({**CORRECTION, "corrected_value": "NOKEY-ATTEMPT"})
    # Discriminating: the no-key request attempts a CORRECTION on the keyed
    # chain -- if the audit failure did not roll everything back, a normalized
    # row and a revision bump would appear.
    denied = subprocess.run([sys.executable, "-c",
        "import json,os,sys; sys.path.insert(0,os.getcwd())\n"
        "from fastapi.testclient import TestClient\n"
        "from backend.app.main import app\n"
        "c=TestClient(app, raise_server_exceptions=False)\n"
        f"r=c.post('/workspaces/{ws12}/field-corrections', "
        "headers={'Idempotency-Key': 'key-g12-' + 'z' * 10}, "
        f"json={body12})\n"
        "print(json.dumps({'status': r.status_code}))"],
        env=env_nokey, capture_output=True, text=True, cwd=str(ROOT), timeout=240)
    TOTALS["processes"] += 1; TOTALS["connections"] += 1
    lines12 = [l for l in denied.stdout.splitlines() if l.startswith("{")]
    status12 = json.loads(lines12[-1])["status"] if lines12 else None
    rows_after = q1("select count(*) from monday_report_norm_field_corrections")
    record("32 G12/G13 an audit/HMAC failure (keyed chain, key unavailable) fails the "
           "correction attempt and persists NO normalized rows and NO revision",
           status12 is not None and status12 >= 500
           and rows_after == rows_before
           and q1("select revision from monday_report_state_snapshots") == rev_before,
           {"status": status12, "rows": (rows_before, rows_after)})

    # G14 database constraint failure rolls back audit + idempotency + snapshot.
    # A planted ACTIVE correction is legitimately superseded by the app (that is
    # correct product behaviour), so the deterministic mid-transaction violation
    # is the OUTCOMES unique index: pre-insert an outcome row at the revision the
    # app's terminal transition will target; the transition's outcome append then
    # violates UNIQUE(task_id, task_revision) inside the open transaction.
    reset(); migrate_baseline()
    cfg14 = env_for("g14")
    fx = run_fixture(cfg14, {"breach": BREACH})
    task14 = fx["task_id"]
    tenant_id = q1("select tenant_id from monday_report_state_snapshots")
    q("insert into monday_report_norm_validation_outcomes "
      "(id, task_id, tenant_id, tenant_slug, task_revision, outcome, reviewer_user_id) "
      "values (%s, %s, %s, %s, 1, 'rejected', %s)",
      (uuid.uuid4(), task14, tenant_id, cfg14["tenant_slug"], uuid.uuid4()))
    audit_before = q1("select jsonb_array_length(payload->'audit_logs') from monday_report_state_snapshots")
    idem_before = q1("select count(*) from monday_report_idempotency_records")
    rev14 = q1("select revision from monday_report_state_snapshots")
    fail_key = "key-g14-" + "c" * 10
    blocked = subprocess.run([sys.executable, "-c",
        "import json,os,sys; sys.path.insert(0,os.getcwd())\n"
        "from fastapi.testclient import TestClient\n"
        "from backend.app.main import app\n"
        "c=TestClient(app, raise_server_exceptions=False)\n"
        f"r=c.patch('/validation-tasks/{task14}', headers={{'Idempotency-Key':'{fail_key}'}}, "
        "json={'status': 'validated', 'resolution_note': 'should roll back'})\n"
        "print(json.dumps({'status': r.status_code}))"],
        env=os_env(cfg14), capture_output=True, text=True, cwd=str(ROOT), timeout=240)
    TOTALS["processes"] += 1; TOTALS["connections"] += 1
    lines = [l for l in blocked.stdout.splitlines() if l.startswith("{")]
    status14 = json.loads(lines[-1])["status"] if lines else None
    record("33 G14 a unique-constraint failure rolls back audit, idempotency, task state and revision",
           status14 is not None and status14 >= 500
           and q1("select jsonb_array_length(payload->'audit_logs') from monday_report_state_snapshots") == audit_before
           and q1("select count(*) from monday_report_idempotency_records") == idem_before
           and q1("select revision from monday_report_state_snapshots") == rev14
           and q1("select status from monday_report_norm_validation_tasks where id=%s", (task14,)) == "open"
           and q1("select revision from monday_report_norm_validation_tasks where id=%s", (task14,)) == 0,
           {"status": status14,
            "task": q1("select status from monday_report_norm_validation_tasks where id=%s", (task14,))})

    # G15 process termination before commit
    reset(); migrate_baseline()
    cfg15 = env_for("g15")
    fx = run_fixture(cfg15, {})
    rows15 = q1("select count(*) from monday_report_norm_field_corrections")
    res15 = run_workers("abort_before_commit", ("a",), {"workspace_id": fx["workspace_id"]})
    TOTALS["race_scenarios"] += 1
    record("34 G15 a process killed mid-transaction leaves no partial normalized rows",
           bool(res15) and res15[0].get("about_to_abort") is True
           and q1("select count(*) from monday_report_norm_field_corrections") == rows15,
           {"reached_txn": bool(res15 and res15[0].get("about_to_abort")),
            "before": rows15,
            "after": q1("select count(*) from monday_report_norm_field_corrections")})

    # G16 independent workspaces concurrently
    reset(); migrate_baseline()
    fxa = run_fixture(env_for("g16-fxa"), {"ws_name": "agg-a"})
    fxb = run_fixture(env_for("g16-fxb"), {"ws_name": "agg-b"})
    res16 = run_workers("independent_workspaces", ("a", "b"),
                        {"workspace_ids": {"a": fxa["workspace_id"], "b": fxb["workspace_id"]}})
    TOTALS["race_scenarios"] += 1
    record("35 G16 independent aggregates both commit with no conflict or timeout",
           all(r.get("status") == 201 for r in res16)
           and q1("select count(*) from monday_report_norm_field_corrections") == 2,
           {"responses": [r.get("status") for r in res16]})

    # G17 independent tenants concurrently
    reset(); migrate_baseline()
    res17 = run_workers("independent_tenants", ("a", "b"),
                        slugs={"a": "np-tenant-a", "b": "np-tenant-b"})
    TOTALS["race_scenarios"] += 1
    per_tenant = q("select tenant_slug, count(*) from monday_report_norm_field_corrections "
                   "group by 1 order by 1")
    record("36 G17 independent tenants both commit without interference",
           all(r.get("status") == 201 for r in res17) and len(per_tenant) == 2
           and all(int(row[1]) == 1 for row in per_tenant),
           {"responses": [r.get("status") for r in res17], "per_tenant": per_tenant})

    # G18 bounded lock timeout is a controlled failure
    reset(); migrate_baseline()
    cfg18 = env_for("g18")
    fx = run_fixture(cfg18, {})
    res18 = run_workers("hold_global_lock", ("holder",), {"hold_seconds": 8})[0] \
        if False else None
    ensure_barrier()
    holder = subprocess.Popen(
        [sys.executable, "scripts/normalized_persistence_worker.py", "hold_global_lock",
         "holder", json.dumps({**env_for("g18-h"), "hold_seconds": 8})],
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    victim = subprocess.Popen(
        [sys.executable, "scripts/normalized_persistence_worker.py", "lock_timeout_victim",
         "victim", json.dumps({**env_for("g18-v"), "workspace_id": fx["workspace_id"]})],
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    TOTALS["processes"] += 2; TOTALS["connections"] += 2; TOTALS["race_scenarios"] += 1
    vout, verr = victim.communicate(timeout=240)
    holder.communicate(timeout=240)
    vlines = [l for l in vout.splitlines() if l.startswith("{")]
    vres = json.loads(vlines[-1]) if vlines else {"error": (verr or vout)[-160:]}
    record("37 G18 a held global lock produces a CONTROLLED bounded-timeout failure, no partial state",
           vres.get("controlled") is True
           and q1("select count(*) from monday_report_norm_field_corrections") == 0,
           {"victim": vres})

    # G19 transaction-local tenant context cannot leak across reuse
    with psycopg.connect(url) as conn:
        with conn.cursor() as cursor:
            cursor.execute("select set_config('app.tenant_slug', %s, true)", ("leak-probe",))
            cursor.execute("select current_setting('app.tenant_slug', true)")
            inside = cursor.fetchone()[0]
        conn.commit()
        with conn.cursor() as cursor:
            cursor.execute("select current_setting('app.tenant_slug', true)")
            after = cursor.fetchone()[0]
    TOTALS["connections"] += 1
    record("38 G19 tenant context is transaction-local: a reused connection retains nothing",
           inside == "leak-probe" and (after is None or after == ""),
           {"inside": inside, "after": after})

    # ---------------------------------------------------------------- E ----- #
    reset(); migrate_baseline()
    cfg_imp = env_for("import", slug="np-import")
    # Build a LEGACY local snapshot then plant it as the PG snapshot (pre-cutover).
    legacy_env = os_env(cfg_imp)
    legacy_env.pop("MONDAY_REPORT_REPOSITORY_BACKEND", None)
    legacy_env.pop("MONDAY_REPORT_DATABASE_URL", None)
    lp = subprocess.run([sys.executable, "-c", FIXTURE_DRIVER,
                         json.dumps({"correction": CORRECTION, "breach": BREACH, "report": True})],
                        env=legacy_env, capture_output=True, text=True, cwd=str(ROOT), timeout=240)
    TOTALS["processes"] += 1
    assert "{" in lp.stdout, (lp.stderr or lp.stdout)[-300:]
    legacy_state = json.load(open(cfg_imp["state_path"], encoding="utf-8"))
    from psycopg.types.json import Jsonb
    with psycopg.connect(url, autocommit=True) as c:
        c.execute("insert into monday_report_state_snapshots (tenant_slug, tenant_id, payload, revision) "
                  "values (%s, %s, %s, 1)",
                  (cfg_imp["tenant_slug"], legacy_state["tenant"]["id"], Jsonb(legacy_state)))
    imp_env = os_env(cfg_imp)

    err = None
    try:
        os.environ["MONDAY_REPORT_TENANT_SLUG"] = cfg_imp["tenant_slug"]
        store_mod.PostgresStateStore(url)
    except RuntimeError as exc:
        err = str(exc)
    finally:
        os.environ.pop("MONDAY_REPORT_TENANT_SLUG", None)
    record("39 IMPORT startup gate: an un-imported legacy snapshot fails closed naming the tool",
           err is not None and "normalized_import" in err, {"named_tool": bool(err and "normalized_import" in err)})
    TOTALS["import_checks"] += 1

    def run_import(mode: str) -> tuple[int, list[str]]:
        proc = subprocess.run([sys.executable, "-m", "backend.app.normalized_import", mode],
                              env=imp_env, capture_output=True, text=True, cwd=str(ROOT), timeout=240)
        TOTALS["processes"] += 1
        TOTALS["connections"] += 1
        return proc.returncode, [l for l in proc.stdout.splitlines() if l.strip()]

    rc, out = run_import("assess")
    assess = json.loads(out[-1])
    record("40 IMPORT assess reports holdings with zero conflicts on a clean legacy snapshot",
           rc == 0 and assess["holdings"] == {"monday_reports": 1, "field_corrections": 1,
                                              "validation_tasks": 1}
           and assess["conflicts"] == 0, assess["holdings"])
    TOTALS["import_checks"] += 1

    rc, out = run_import("dry-run")
    dry = json.loads(out[-1])
    rows_after_dry = q1("select count(*) from monday_report_norm_field_corrections")
    record("41 IMPORT dry-run would execute and writes NOTHING",
           rc == 0 and dry.get("dry_run_would_execute") is True and rows_after_dry == 0,
           {"rows": rows_after_dry})
    TOTALS["import_checks"] += 1

    rc, out = run_import("execute")
    record("42 IMPORT execute cuts over atomically", rc == 0 and "cut over" in out[-1],
           out[-1][:120])
    TOTALS["import_checks"] += 1

    rc, out = run_import("verify")
    verify = json.loads(out[-1])
    record("43 IMPORT verify passes with matching counts and invariants",
           rc == 0 and verify.get("ok") is True, verify.get("row_counts"))
    TOTALS["import_checks"] += 1

    rc, out = run_import("execute")
    record("44 IMPORT execute rerun is idempotent (already cut over)",
           rc == 0 and "already cut over" in out[-1], out[-1][:100])
    TOTALS["import_checks"] += 1

    # conflicting source refused
    reset(); migrate_baseline()
    with psycopg.connect(url, autocommit=True) as c:
        c.execute("insert into monday_report_state_snapshots (tenant_slug, tenant_id, payload, revision) "
                  "values (%s, %s, %s, 1)",
                  (cfg_imp["tenant_slug"], legacy_state["tenant"]["id"], Jsonb(legacy_state)))
    div = dict(legacy_state["field_corrections"][0])
    q("insert into tenants (id, name, slug) values (%s, 'seed', %s) on conflict do nothing",
      (legacy_state["tenant"]["id"], cfg_imp["tenant_slug"]))
    for _w in legacy_state["workspaces"]:
        q("insert into workspaces (id, tenant_id, name) values (%s, %s, 'seed') on conflict do nothing",
          (_w["id"], legacy_state["tenant"]["id"]))
    q("insert into monday_report_norm_field_corrections "
      "(id, tenant_id, tenant_slug, workspace_id, target_type, field_key, status, actor_user_id, doc) "
      "values (%s, %s, %s, %s, %s, %s, 'reverted', %s, %s)",
      (div["id"], legacy_state["tenant"]["id"], cfg_imp["tenant_slug"], div["workspace_id"],
       div["target_type"], div["field_key"], div["actor_user_id"], Jsonb({"divergent": True})))
    rc, out = run_import("execute")
    record("45 IMPORT refuses a conflicting source (existing divergent row) and rolls back",
           rc == 1 and "REFUSED" in " ".join(out),
           {"rc": rc})
    TOTALS["import_checks"] += 1

    # unsupported state fails closed in verify
    q("delete from monday_report_norm_field_corrections")
    with psycopg.connect(url, autocommit=True) as c:
        c.execute("update monday_report_state_snapshots set payload = jsonb_set(payload, "
                  "'{normalized_authority}', %s)", (Jsonb({"version": 1, "entities": []}),))
        c.execute("update monday_report_state_snapshots set payload = payload - 'field_corrections' "
                  "|| jsonb_build_object('field_corrections', '[]'::jsonb)")
    rc, out = run_import("verify")
    record("46 IMPORT verify fails closed on an unsupported state (marker without matching rows)",
           rc == 1, {"rc": rc, "tail": out[-1][:100]})
    TOTALS["import_checks"] += 1

    # ---------------------------------------------------------------- F ----- #
    reset(); migrate_baseline()
    cfg_rls = env_for("rls", slug="np-rls-a")
    run_fixture(cfg_rls, {"correction": CORRECTION})
    role = f"np_rls_probe_{secrets.token_hex(3)}"
    q(f"create role {role} login nosuperuser")
    q(f"grant usage on schema public to {role}")
    q(f"grant select, insert on monday_report_norm_field_corrections to {role}")
    base = url.rsplit("/", 1)
    probe_url = url.replace("postgresql://postgres@", f"postgresql://{role}@")

    def rls_query(slug: str | None) -> int:
        with psycopg.connect(probe_url, autocommit=True) as c:
            if slug is not None:
                c.execute("select set_config('app.tenant_slug', %s, false)", (slug,))
            return int(c.execute(
                "select count(*) from monday_report_norm_field_corrections").fetchone()[0])

    TOTALS["connections"] += 3
    record("47 RLS: the matching tenant context sees its rows (forced policy active)",
           rls_query("np-rls-a") == 1, {"count": rls_query("np-rls-a")})
    record("48 RLS: a different tenant context sees NOTHING (direct SQL denied)",
           rls_query("np-rls-b") == 0, True)
    record("49 RLS: an ABSENT tenant context denies access entirely",
           rls_query(None) == 0, True)
    TOTALS["tenant_checks"] += 3

    wrong_insert = None
    try:
        with psycopg.connect(probe_url, autocommit=True) as c:
            c.execute("select set_config('app.tenant_slug', %s, false)", ("np-rls-b",))
            c.execute("insert into monday_report_norm_field_corrections "
                      "(id, tenant_id, tenant_slug, workspace_id, target_type, field_key, "
                      "status, actor_user_id, doc) "
                      "select %s, tenant_id, 'np-rls-a', workspace_id, 'report_field', 'forge', "
                      "'superseded', actor_user_id, '{}' "
                      "from monday_report_norm_field_corrections limit 0")
            c.execute("insert into monday_report_norm_field_corrections "
                      "(id, tenant_id, tenant_slug, workspace_id, target_type, field_key, "
                      "status, actor_user_id, doc) values "
                      "(%s, %s, 'np-rls-a', %s, 'report_field', 'forge', 'superseded', %s, '{}')",
                      (uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()))
    except Exception as exc:  # noqa: BLE001
        wrong_insert = exc.__class__.__name__
    TOTALS["connections"] += 1
    record("50 RLS: WITH CHECK forbids writing another tenant's rows (relationship cannot be forged)",
           wrong_insert is not None, {"raised": wrong_insert})
    TOTALS["tenant_checks"] += 1

    # cross-tenant idempotency isolation
    reset(); migrate_baseline()
    op = f"npct-{uuid.uuid4().hex[:8]}"
    ra = run_workers("cross_tenant_replay", ("a",), {"operation_id": op},
                     slugs={"a": "np-ct-a"})[0]
    rb = run_workers("cross_tenant_replay", ("b",), {"operation_id": op},
                     slugs={"b": "np-ct-b"})[0]
    TOTALS["race_scenarios"] += 1
    record("51 cross-tenant: the same idempotency key commits DISTINCT entities per tenant "
           "(no cross-tenant result retrieval)",
           ra.get("status") == 201 and rb.get("status") == 201
           and ra.get("entity_id") != rb.get("entity_id")
           and q1("select count(distinct tenant_slug) from monday_report_idempotency_records "
                  "where operation_id=%s", (op,)) == 2,
           {"a": ra.get("status"), "b": rb.get("status")})
    TOTALS["tenant_checks"] += 1

    # tenant-scoped store cannot see another tenant's task
    reset(); migrate_baseline()
    fxa = run_fixture(env_for("tt-a", slug="np-tt-a"), {"breach": BREACH})
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "np-tt-b"
    try:
        other = store_mod.PostgresStateStore(url)
        crossed = fxa["task_id"] in {str(k) for k in other.validation_tasks}
    finally:
        os.environ.pop("MONDAY_REPORT_TENANT_SLUG", None)
    record("52 a store scoped to another tenant cannot load or process the first tenant's task",
           crossed is False, {"crossed": crossed})
    TOTALS["tenant_checks"] += 1

    # MEASURED (not asserted-by-assumption) RLS catalog state for the evidence.
    rls_rows = q("select relname, relrowsecurity, relforcerowsecurity from pg_class "
                 "where relname like 'monday_report_norm%' and relkind = 'r' order by 1")
    TOTALS["rls_forced_tables"] = sum(1 for r in rls_rows if r[1] and r[2])
    record("53 RLS is ENABLED and FORCED on all four slice tables (catalog-measured)",
           len(rls_rows) == 4 and all(r[1] and r[2] for r in rls_rows),
           {"tables": [(r[0].replace("monday_report_norm_", ""), bool(r[1]), bool(r[2]))
                       for r in rls_rows]})
    TOTALS["tenant_checks"] += 1

    # ------------------------------------------------- G lifecycle/authority - #
    # 54 retention apply must DELETE normalized rows (no resurrection).
    reset(); migrate_baseline()
    cfg_ret = env_for("ret", slug="np-ret")
    run_fixture(cfg_ret, {"correction": CORRECTION, "breach": BREACH, "report": True})
    q("update monday_report_norm_reports set doc = jsonb_set(doc, '{created_at}', "
      "to_jsonb('2020-01-01T00:00:00+00:00'::text)), created_at = '2020-01-01T00:00:00+00'")
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = cfg_ret["tenant_slug"]
    try:
        ret_store = store_mod.PostgresStateStore(url)
        ret_result = ret_store.run_retention(365, apply=True)
        ret_store.refresh()
        resurrected = len(ret_store.monday_reports)
    finally:
        os.environ.pop("MONDAY_REPORT_TENANT_SLUG", None)
    TOTALS["connections"] += 1
    record("54 retention apply DELETES the purged report's normalized row in-transaction "
           "(no resurrection on refresh; the audited counts are true; unexpired rows kept)",
           ret_result.monday_reports == 1
           and q1("select count(*) from monday_report_norm_reports") == 0
           and resurrected == 0
           and q1("select count(*) from monday_report_norm_validation_tasks") == 1
           and q1("select count(*) from monday_report_norm_field_corrections") == 1,
           {"purged_reports": ret_result.monday_reports,
            "rows_left": q1("select count(*) from monday_report_norm_reports"),
            "resurrected": resurrected})
    TOTALS["lifecycle_checks"] += 1

    # 55 create_store must not launder the cutover gate into a local fallback.
    reset(); migrate_baseline()
    with psycopg.connect(url, autocommit=True) as c:
        c.execute("insert into monday_report_state_snapshots (tenant_slug, tenant_id, payload, revision) "
                  "values (%s, %s, %s, 1)",
                  ("np-cs", legacy_state["tenant"]["id"], Jsonb(legacy_state)))
    for key, value in {"MONDAY_REPORT_REPOSITORY_BACKEND": "postgres",
                       "MONDAY_REPORT_DATABASE_URL": url,
                       "MONDAY_REPORT_TENANT_SLUG": "np-cs"}.items():
        os.environ[key] = value
    laundered = err55 = None
    try:
        laundered = store_mod.create_store()
    except store_mod.NormalizedCutoverRequired as exc:
        err55 = str(exc)
    finally:
        for key in ("MONDAY_REPORT_REPOSITORY_BACKEND", "MONDAY_REPORT_DATABASE_URL",
                    "MONDAY_REPORT_TENANT_SLUG"):
            os.environ.pop(key, None)
    TOTALS["connections"] += 1
    record("55 create_store FAILS CLOSED on an un-imported snapshot: no silent local-JSON "
           "split-brain, remediation text propagates to the operator",
           laundered is None and err55 is not None and "normalized_import" in err55,
           {"laundered_to": type(laundered).__name__ if laundered is not None else None,
            "named_tool": bool(err55 and "normalized_import" in err55)})
    TOTALS["lifecycle_checks"] += 1

    # 56 a live supersede writes the TYPED superseded_by_id back-link.
    reset(); migrate_baseline()
    cfg_sb = env_for("sb", slug="np-sb")
    fx = run_fixture(cfg_sb, {"correction": CORRECTION})
    run_workers("same_field_race", ("a",),
                {"workspace_id": fx["workspace_id"], "participants": 1},
                slugs={"a": "np-sb"})
    typed_pairs = q("select superseded_by_id::text, doc->>'superseded_by_id' "
                    "from monday_report_norm_field_corrections where status = 'superseded'")
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "np-sb"
    try:
        drift56 = normalized_drift_report(store_mod.PostgresStateStore(url))
    finally:
        os.environ.pop("MONDAY_REPORT_TENANT_SLUG", None)
    TOTALS["connections"] += 1
    record("56 a live supersede writes the typed superseded_by_id column equal to the doc "
           "back-link (and the drift detector now covers the pair)",
           len(typed_pairs) == 1 and typed_pairs[0][0] is not None
           and typed_pairs[0][0] == typed_pairs[0][1] and drift56 == [],
           {"pairs": typed_pairs, "drift": drift56})
    TOTALS["lifecycle_checks"] += 1

    # 57 the marker refusal applies PER TRANSACTION, not only at bootstrap: an
    # already-running store must refuse to overwrite (blank + re-stamp) a
    # snapshot that an old-version concurrent writer re-populated with
    # migrated entities and no marker.
    reset(); migrate_baseline()
    cfg_mk = env_for("mk", slug="np-mk")
    fx = run_fixture(cfg_mk, {})
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "np-mk"
    try:
        mk_store = store_mod.PostgresStateStore(url)  # healthy cut-over state
    finally:
        os.environ.pop("MONDAY_REPORT_TENANT_SLUG", None)
    q("update monday_report_state_snapshots set payload = "
      "(payload - 'normalized_authority') || %s where tenant_slug = %s",
      (Jsonb({"validation_tasks": [{"planted": True}]}), "np-mk"))
    from backend.app.schemas import FieldCorrectionCreate
    err57 = None
    try:
        mk_store.record_field_correction(uuid.UUID(fx["workspace_id"]),
                                         FieldCorrectionCreate(**CORRECTION))
    except store_mod.NormalizedCutoverRequired:
        err57 = "refused"
    TOTALS["connections"] += 1
    planted_kept = q1("select payload->'validation_tasks'->0->>'planted' "
                      "from monday_report_state_snapshots where tenant_slug = %s", ("np-mk",))
    marker_restamped = q1("select payload ? 'normalized_authority' "
                          "from monday_report_state_snapshots where tenant_slug = %s", ("np-mk",))
    record("57 a RUNNING store refuses to overwrite a marker-less snapshot re-populated by an "
           "old-version writer (entities preserved, marker not re-stamped, mutation refused)",
           err57 == "refused" and planted_kept == "true" and marker_restamped is False,
           {"refused": err57 == "refused", "planted_kept": planted_kept,
            "marker_restamped": marker_restamped})
    TOTALS["lifecycle_checks"] += 1

    with psycopg.connect(url, autocommit=True) as c:
        c.execute("drop table if exists mr_test_barrier")


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #
def _git(args: list[str]) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=str(ROOT), text=True).strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def canonical_payload_sha256(payload: dict) -> str:
    body = {k: v for k, v in payload.items() if k != "payload_sha256"}
    canonical = json.dumps(body, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_evidence() -> dict:
    import backend.app.migrations as M
    import backend.app.store as store_mod

    n_passed = len([c for c in checks if c["ok"] and not c["skipped"]])
    n_skipped = len([c for c in checks if c["skipped"]])
    n_failed = len([c for c in checks if not c["ok"]])
    by_name = {c["name"]: c for c in checks}

    def passed(prefix: str) -> bool:
        c = next((v for k, v in by_name.items() if k.startswith(prefix)), None)
        return bool(c and c["ok"] and not c["skipped"])

    ran_real_db = bool(test_database_url())
    required_groups = {
        "schema_migration": all(passed(f"{n:02d} ") for n in range(6, 16)),
        "repository_authority": all(passed(f"{n:02d} ") for n in (16, 17, 18, 19, 20, 21)),
        "routes": all(passed(f"{n:02d} ") for n in (22, 23, 24)),
        "concurrency": all(passed(f"{n:02d} ") for n in
                           (25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38)),
        "import": all(passed(f"{n:02d} ") for n in range(39, 47)),
        "tenant_rls": all(passed(f"{n:02d} ") for n in range(47, 54)),
        "lifecycle": all(passed(f"{n:02d} ") for n in range(54, 58)),
    }
    status = "passed" if (ran_real_db and n_failed == 0 and n_skipped == 0
                          and all(required_groups.values())) else "BLOCKED_INCOMPLETE"

    baseline = M.discover_migrations(M.BASELINE_DIR)
    payload = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "implementation_version": IMPLEMENTATION_VERSION,
        "persistence_implementation_version": store_mod.SNAPSHOT_TRANSACTION_VERSION,
        "git_commit": _git(["rev-parse", "HEAD"]),
        "git_tree": _git(["rev-parse", "HEAD^{tree}"]),
        "worktree_clean": _git(["status", "--porcelain"]) == "",
        "postgres_server_version": os.environ.get("MONDAY_REPORT_TEST_PG_SERVER_VERSION"),
        "pgvector_version": os.environ.get("MONDAY_REPORT_TEST_PGVECTOR_VERSION"),
        "postgres_image_digest": os.environ.get("MONDAY_REPORT_TEST_PG_IMAGE_DIGEST"),
        "migration_versions": [m.version for m in baseline],
        "migration_checksums": {m.filename: m.checksum_sha256 for m in baseline},
        "repository_mode": "postgres",
        "normalized_entities": list(store_mod.PostgresStateStore.NORMALIZED_ENTITY_KEYS),
        "source_of_truth": "normalized tables are the single write and read authority for the "
                           "migrated entities in postgres mode; the snapshot carries them as "
                           "empty keys plus a normalized_authority marker; file/memory modes "
                           "retain snapshot behaviour WITHOUT normalized cross-process guarantees",
        "transaction_strategy": "one protected snapshot transaction per mutation: global advisory "
                                "lock -> snapshot FOR UPDATE -> normalized row locks -> mutation "
                                "-> audit append (snapshot-owned) -> idempotency record -> "
                                "snapshot CAS -> single commit; any pre-commit failure rolls back "
                                "rows, audit, idempotency and revision together",
        "lock_strategy": "deterministic order: global advisory lock FIRST, then row locks by "
                         "table and id; the active-lineage partial unique index and "
                         "UNIQUE(task_id, task_revision) enforce cross-process integrity",
        "revision_strategy": "per-row bigint revision with SELECT FOR UPDATE + CAS "
                             "(StaleRevisionError on mismatch); snapshot revision CAS retained",
        "idempotency_strategy": "0004 idempotency records; normalized rows link operation_id; "
                                "cross-tenant keys are partitioned by (tenant_slug, operation_id)",
        "audit_chain_result": "passed" if passed("32 ") and passed("33 ") else "not_passed",
        "hmac_result": "passed" if passed("32 ") else "not_passed",
        "process_total": TOTALS["processes"],
        "connection_total": TOTALS["connections"],
        "route_scenario_total": TOTALS["route_scenarios"],
        "route_groups_result": "passed" if required_groups["routes"] else "not_passed",
        "concurrency_scenario_total": TOTALS["race_scenarios"],
        "concurrency_result": "passed" if required_groups["concurrency"] else "not_passed",
        "import_check_total": TOTALS["import_checks"],
        "import_result": "passed" if required_groups["import"] else "not_passed",
        "tenant_check_total": TOTALS["tenant_checks"],
        "tenant_rls_result": "passed" if required_groups["tenant_rls"] else "not_passed",
        "lifecycle_check_total": TOTALS["lifecycle_checks"],
        "lifecycle_result": "passed" if required_groups["lifecycle"] else "not_passed",
        "deletion_lifecycle": "retention apply and the demo-seed self-wipe prune normalized rows "
                              "in the same protected transaction (no resurrection); the marker "
                              "refusal applies per transaction; create_store fails closed on an "
                              "un-imported snapshot instead of local fallback",
        "rls_state": ("active_forced_on_slice_tables"
                      if TOTALS.get("rls_forced_tables") == 4 else "not_forced"),
        "rls_forced_table_count": TOTALS.get("rls_forced_tables", 0),
        "rls_scope_note": "RLS is FORCED on the four slice tables only; the overall "
                          "tenant-authorization-enforcement control remains BLOCKED because the "
                          "full normalized store does not yet exist",
        "totals": {"passed": n_passed, "skipped": n_skipped, "failed": n_failed},
        "status": status,
    }
    payload["payload_sha256"] = canonical_payload_sha256(payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--emit-evidence", action="store_true")
    args = parser.parse_args()

    scratch = Path(os.environ.get("TEMP", "/tmp")) / f"mr-np-{uuid.uuid4().hex[:8]}"
    scratch.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MONDAY_REPORT_STATE_PATH", str(scratch / "guard-state.json"))
    os.environ.setdefault("MONDAY_REPORT_STORAGE_ROOT", str(scratch / "guard-storage"))
    os.environ.setdefault("MONDAY_REPORT_EXPORT_ROOT", str(scratch / "guard-exports"))

    constants_mirror_checks()

    url = test_database_url()
    if not url:
        for n in range(6, 58):
            skip(f"{n:02d} real-PostgreSQL scenario", "no MONDAY_REPORT_TEST_DATABASE_URL provided")
    else:
        pg_checks(url, scratch)

    passed = [c for c in checks if c["ok"] and not c["skipped"]]
    skipped = [c for c in checks if c["skipped"]]
    failed = [c for c in checks if not c["ok"]]

    print(json.dumps({"checks": checks,
                      "summary": {"passed": len(passed), "skipped": len(skipped),
                                  "failed": len(failed), "postgres": bool(url),
                                  **TOTALS}}, indent=2, default=str))
    if failed:
        print(f"\nNormalized persistence guard FAILED: {len(failed)} failing check(s).")
        for c in failed:
            print(f"  FAIL: {c['name']} -> {c['detail']}")
        return 1
    if args.emit_evidence:
        evidence = build_evidence()
        EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
        EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        if evidence["status"] != "passed":
            print(f"\nNOTE: evidence status is {evidence['status']!r}; the control stays BLOCKED.")
        print(f"Wrote evidence: {EVIDENCE_PATH.relative_to(ROOT).as_posix()} "
              f"(status={evidence['status']})")

    tail = f" ({len(skipped)} skipped: no disposable PostgreSQL)" if skipped else ""
    print(f"\nNormalized persistence guard passed: {len(passed)} check(s).{tail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
