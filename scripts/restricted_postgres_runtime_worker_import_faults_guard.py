"""Non-vacuity battery for the external worker + import slice (Outcome-1 slice 4).

Proves the audit:restricted-postgres-runtime-worker-import slice's assertions are NON-VACUOUS. For each
listed violation it EITHER runs a LIVE control against the accepted runner-owned stack proving the slice's
assertion discriminates (a worker success vs a failure; import assess is read-only vs execute writes; a
reverted-in-finally RLS mutation exposes cross-tenant rows), OR evaluates a mirror of the slice's exact
pass-predicate against a crafted VIOLATED observation and confirms it rejects it, OR is a STRUCTURAL check
of the slice's own fail-closed gates (driven through the REAL M._emit / M.EXPECTED_IDS) or of the slice
SOURCE (that the worker/import are launched as external subprocesses, never in-process). Every check is
classified honestly by execution level; every live database/role mutation is reverted in a finally block.

HONEST SCOPE:
  claim_scope = restricted-runtime-worker-import-faults-only
  eligible_for_tenant_evidence = false / eligible_for_readiness = false / production_parity = false
It must NEVER be consumed as tenant-authorization or readiness evidence. Requires Docker.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import secrets
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT, ROOT / "scripts"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import restricted_postgres_startup_guard as G  # noqa: E402

STATE_TABLE = "monday_report_state_snapshots"
checks: list[dict] = []
LEAK_TERMS: list[str] = []


def _scrub(text: str) -> str:
    for term in LEAK_TERMS:
        if term:
            text = text.replace(str(term), "<redacted>")
    return text


def mut(cid, ok, desc, level, extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level, **(extra or {})})


def run() -> int:
    allow_unavailable = "--allow-unavailable" in sys.argv
    if G._docker(["info"]).returncode != 0:
        mut("setup", allow_unavailable, "docker availability", "structural source check")
        return _emit(skipped=allow_unavailable)

    # ================= STRUCTURAL: drive the slice's own fail-closed gates =================
    spec = importlib.util.spec_from_file_location(
        "wislice", str(ROOT / "scripts" / "restricted_postgres_runtime_worker_import_guard.py"))
    M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)

    def _populate_all():
        M.checks.clear()
        for k in M.COUNTERS:
            M.COUNTERS[k] = 0
        for cid in M.EXPECTED_IDS:
            M.rec(cid, True, desc="ok", category="p", proc="-", tenant="-", principal="-", job="-",
                  expected="-", db_post="-", audit_post="-")

    def _emit_rc():
        with contextlib.redirect_stdout(io.StringIO()):
            return M._emit()

    _populate_all()
    mut("FS00", _emit_rc() == 0, "a complete, clean slice inventory passes the gate (gates are not always-fail)",
        "structural source check")
    _populate_all(); M.COUNTERS["normal_worker_process_failures"] = 1
    mut("FS01", _emit_rc() == 1, "a NORMAL worker process failure forces the slice verdict non-passing",
        "structural source check")
    _populate_all(); M.COUNTERS["normal_import_process_failures"] = 1
    mut("FS02", _emit_rc() == 1, "a NORMAL import process failure forces the slice verdict non-passing",
        "structural source check")
    _populate_all(); M.checks.pop()
    mut("FS03", _emit_rc() == 1, "a missing expected slice check id forces the slice verdict non-passing",
        "structural source check")
    _populate_all()
    M.rec(M.EXPECTED_IDS[0], True, desc="dup", category="p", proc="-", tenant="-", principal="-", job="-",
          expected="-", db_post="-", audit_post="-")
    mut("FS04", _emit_rc() == 1, "a duplicate check id forces the slice verdict non-passing",
        "structural source check")
    M.checks.clear()
    for k in M.COUNTERS:
        M.COUNTERS[k] = 0

    # STRUCTURAL SOURCE: the slice launches EXTERNAL subprocesses; it never runs the worker/import in-process
    src = (ROOT / "scripts" / "restricted_postgres_runtime_worker_import_guard.py").read_text(encoding="utf-8")
    # code-specific patterns (won't match the docstring's prose mentions of "no TestClient / run_once()")
    forbidden = ["TestClient(", ".run_once(", "threading.Thread(", "normalized_import.run(",
                 ".process_queued_jobs(", "import_mod.run(", "worker.run_once", "worker.main("]
    uses_module = 'subprocess.Popen([sys.executable, "-m", "backend.app.worker"]' in src \
        and 'subprocess.run([sys.executable, "-m", "backend.app.normalized_import"' in src
    mut("FS05", uses_module and not any(f in src for f in forbidden),
        "the slice source launches the worker/import as EXTERNAL subprocesses (`-m backend.app.worker` / "
        "`-m backend.app.normalized_import`) and contains no in-process TestClient/run_once()/thread execution",
        "structural source check",
        extra={"external_module_launch": uses_module, "forbidden_found": [f for f in forbidden if f in src]})

    # ================= PREDICATE/UNIT: mirrors of the slice pass-predicates =================
    def pd(cid, desc, pred, violated, correct):
        mut(cid, (pred(violated) is False) and (pred(correct) is True), desc, "predicate/unit mutation",
            extra={"rejects_violation": pred(violated) is False, "accepts_correct": pred(correct) is True})

    # worker env-hygiene: PF01-04 drive the ACTUAL module-scope M.env_hygiene function (not a local mirror)
    # against crafted child environments, so it is the REAL hygiene gate that rejects each violation.
    _RT = "postgresql://rt_login:pw@10.9.9.9:5432/mrdb"
    _BOOT = "postgresql://boot_admin:pw@10.9.9.9:5432/mrdb"
    _MIGDSN = "postgresql://mig_admin:pw@10.9.9.9:5432/mrdb"
    _MIGROLE = "mr_migration_admin_role_zzz"

    def hy_ok(child_env):
        h = M.env_hygiene(child_env, rt=_RT, boot=_BOOT, mig_dsn=_MIGDSN, mig_role=_MIGROLE)
        return h["restricted_dsn_only"] and h["no_migration_dsn"] and h["no_libpq_leak"] and h["no_local_fallback"]
    GOOD = {"MONDAY_REPORT_DATABASE_URL": _RT, "MONDAY_REPORT_REPOSITORY_BACKEND": "postgres"}
    pd("PF01", "a worker child-env carrying the MIGRATION role/DSN is caught by the REAL M.env_hygiene gate",
       hy_ok, {**GOOD, "MONDAY_REPORT_MIGRATION_HINT": _MIGROLE}, GOOD)
    pd("PF02", "a worker child-env using the BOOTSTRAP admin DSN (not restricted-only) is caught by the REAL gate",
       hy_ok, {**GOOD, "MONDAY_REPORT_DATABASE_URL": _BOOT}, GOOD)
    pd("PF03", "a worker child-env with a libpq (PG*) leak is caught by the REAL gate",
       hy_ok, {**GOOD, "PGPASSWORD": "leak"}, GOOD)
    pd("PF04", "a worker child-env with a LOCAL fallback backend is caught by the REAL gate",
       hy_ok, {**GOOD, "MONDAY_REPORT_REPOSITORY_BACKEND": "local"}, GOOD)
    # worker DB identity: superuser / BYPASSRLS / non-rt / non-group would be caught
    def id_ok(o):
        return o["is_rt"] and (o["super"] is False) and (o["bypass"] is False) and o["grp"] >= 1
    IDG = {"is_rt": True, "super": False, "bypass": False, "grp": 1}
    pd("PF05", "a worker DB session that is a SUPERUSER would be caught", id_ok, {**IDG, "super": True}, IDG)
    pd("PF06", "a worker DB session with BYPASSRLS would be caught", id_ok, {**IDG, "bypass": True}, IDG)
    pd("PF07", "a worker session that is NOT the restricted role would be caught", id_ok, {**IDG, "is_rt": False}, IDG)
    # payload tenant/actor override trusted -> the named foreign tenant changed (b_unchanged False) would be caught
    pd("PF08", "a job PAYLOAD tenant/actor override that MUTATED the foreign tenant would be caught",
       lambda o: o["processed"] == 1 and o["b_unchanged"], {"processed": 1, "b_unchanged": False}, {"processed": 1, "b_unchanged": True})
    # A-failure contaminates B / next process uncontaminated -> caught (B must succeed independently)
    pd("PF09", "a tenant-A worker failure that CONTAMINATED the tenant-B process (B did not cleanly succeed) would be caught",
       lambda o: o["b_processed"] == 1 and o["a_failed"] == 1,
       {"b_processed": 0, "a_failed": 1}, {"b_processed": 1, "a_failed": 1})
    # retry changes tenant -> control tenant changed would be caught
    pd("PF10", "a retry that changed a DIFFERENT tenant (control not unchanged) would be caught",
       lambda o: o["complete"] == 1 and o["attempts"] >= 2 and o["control_unchanged"],
       {"complete": 1, "attempts": 2, "control_unchanged": False}, {"complete": 1, "attempts": 2, "control_unchanged": True})
    # duplicate delivery duplicates business state -> a non-zero reprocess would be caught
    pd("PF11", "a re-run that reprocessed terminal jobs (duplicate business effect) would be caught",
       lambda processed: processed == 0, 1, 0)
    # worker fail-closed bypassed (mutation despite missing key) -> caught
    pd("PF12", "a fail-closed worker that MUTATED state despite a missing audit key would be caught",
       lambda o: o["rc"] != 0 and o["unchanged"], {"rc": 0, "unchanged": False}, {"rc": 1, "unchanged": True})
    # worker success audit wrong tenant / keyed integrity -> caught
    pd("PF13", "a broken worker audit chain (not keyed_valid) would be caught",
       lambda o: o["state"] == "keyed_valid" and o["broken"] == 0, {"state": "broken", "broken": 1},
       {"state": "keyed_valid", "broken": 0})
    pd("PF14", "a FAILED worker job that emitted a false success audit would be caught",
       lambda failed_success_audits: failed_success_audits == 0, 1, 0)
    # import assess / dry-run change rows -> caught
    pd("PF15", "an import ASSESS that changed rows would be caught",
       lambda o: o["rc"] == 0 and o["a_unchanged"] and o["b_unchanged"],
       {"rc": 0, "a_unchanged": False, "b_unchanged": True}, {"rc": 0, "a_unchanged": True, "b_unchanged": True})
    pd("PF16", "an import DRY-RUN that changed rows would be caught",
       lambda o: o["would"] and o["a_unchanged"], {"would": True, "a_unchanged": False}, {"would": True, "a_unchanged": True})
    # import execute changes the WRONG tenant -> caught
    pd("PF17", "an import EXECUTE that changed the OTHER tenant would be caught",
       lambda o: o["result"] == "cut over" and o["b_unchanged"],
       {"result": "cut over", "b_unchanged": False}, {"result": "cut over", "b_unchanged": True})
    # import accepts a payload tenant override -> caught (must be non-zero/refused)
    pd("PF18", "an import that ACCEPTED a foreign-tenant_id payload (exit 0) would be caught",
       lambda rc: rc == 1, 0, 1)
    # import failure partially commits -> caught (cross-tenant id reuse must leave A row unchanged, R unchanged)
    pd("PF19", "an import cross-tenant id reuse that PARTIALLY committed (imp-a row changed) would be caught",
       lambda o: o["rc"] != 0 and o["imp_r_unchanged"] and o["imp_a_row_unchanged"],
       {"rc": 1, "imp_r_unchanged": True, "imp_a_row_unchanged": False},
       {"rc": 1, "imp_r_unchanged": True, "imp_a_row_unchanged": True})
    # import principal / RLS boundary -> caught
    pd("PF20", "an import running as a SUPERUSER runtime, or one that disabled RLS/FORCE, would be caught",
       lambda o: o["non_super"] and o["non_bypass"] and o["rls_force_intact"],
       {"non_super": False, "non_bypass": True, "rls_force_intact": True},
       {"non_super": True, "non_bypass": True, "rls_force_intact": True})
    pd("PF21", "an import that DISABLED RLS/FORCE on a protected table would be caught",
       lambda o: o["non_super"] and o["non_bypass"] and o["rls_force_intact"],
       {"non_super": True, "non_bypass": True, "rls_force_intact": False},
       {"non_super": True, "non_bypass": True, "rls_force_intact": True})
    # verify accepts wrong digest / wrong tenant / misses tampering -> caught
    pd("PF22", "a VERIFY that reported ok:true for a tampered/wrong-digest tenant would be caught",
       lambda verify_ok: verify_ok is False, True, False)
    pd("PF23", "a VERIFY that reported ok:true for a never-cut-over (no-marker) tenant would be caught",
       lambda verify_ok: verify_ok is False, True, False)

    # ================= LIVE controls =================
    def on_live(ctx):
        import psycopg
        import backend.app.store as store_mod
        from backend.app.schemas import WorkspaceCreate
        boot, rt, rt_role = ctx["boot_dsn"], ctx["rt_dsn"], ctx["rt_role"]
        base_env = dict(ctx["base_env"]); run_hash = ctx["run_hash"]
        _tmp = str(Path(os.environ.get("TEMP", "/tmp")))
        LEAK_TERMS[:] = sorted({str(t) for t in [ctx["run_id"], run_hash, rt_role, ctx["mig_role"], boot, rt,
                                                 ctx["mig_dsn"], ctx["db"], ctx["token"],
                                                 base_env["MONDAY_REPORT_API_KEY"], str(ROOT), _tmp] if t},
                               key=len, reverse=True)
        scratches = []
        rls_seed_slugs: list[str] = []  # FL03 seed rows, always removed in finally

        def prov(slug, n, *, delete_file=False):
            scratch = Path(_tmp) / f"mr-wif-{slug}-{run_hash}"
            for sub in ("state", "storage", "exports"):
                (scratch / sub).mkdir(parents=True, exist_ok=True)
            scratches.append(scratch)
            env = dict(base_env)
            env.update({"MONDAY_REPORT_DATABASE_URL": f"{rt}?application_name=mr-wif-{slug}-{run_hash}",
                        "MONDAY_REPORT_TENANT_SLUG": slug, "MONDAY_REPORT_TENANT_NAME": slug,
                        "MONDAY_REPORT_USER_EMAIL": f"u@{slug}.test", "MONDAY_REPORT_USER_FULL_NAME": slug,
                        "MONDAY_REPORT_STATE_PATH": str(scratch / "state" / "s.json"),
                        "MONDAY_REPORT_STORAGE_ROOT": str(scratch / "storage"),
                        "MONDAY_REPORT_EXPORT_ROOT": str(scratch / "exports"),
                        "MONDAY_REPORT_API_KEY": secrets.token_urlsafe(20)})
            LEAK_TERMS.append(env["MONDAY_REPORT_API_KEY"])
            sv = {k: os.environ.get(k) for k in env}
            os.environ.update(env)
            try:
                st = store_mod.create_store()
                ws = st.create_workspace(WorkspaceCreate(name="w", rig_name="g"))
                for i in range(n):
                    up, fr, _ = st.create_uploaded_file(ws.id, f"n{i}.txt", "text/plain", "files",
                                                        b"rig note; no npt.\n", save=True)
                    st.complete_upload(up.id, [fr.id])
            finally:
                for k, v in sv.items():
                    (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))
            if delete_file:
                shutil.rmtree(scratch / "storage" / slug, ignore_errors=True)
            return G._child_env(env)

        def run_worker(child_env):
            p = subprocess.run([sys.executable, "-m", "backend.app.worker"], cwd=str(ROOT), env=child_env,
                               capture_output=True, text=True, timeout=90)
            import re
            m = re.search(r"Processed (\d+)", p.stdout or "")
            return p.returncode, (int(m.group(1)) if m else None)

        def jstat(slug, status):
            with psycopg.connect(boot, autocommit=True) as c:
                return int(c.execute(f"select count(*) from {STATE_TABLE} s, jsonb_array_elements(s.payload->'jobs') e "
                                     "where s.tenant_slug=%s and e->>'status'=%s", (slug, status)).fetchone()[0])

        try:
            # FL01: a worker SUCCEEDS on an intact job and FAILS on a removed-source job (discriminating, non-blanket)
            ok_env = prov("wif-ok", 1)
            bad_env = prov("wif-bad", 1, delete_file=True)
            rc_ok, proc_ok = run_worker(ok_env)
            rc_bad, proc_bad = run_worker(bad_env)
            mut("FL01", rc_ok == 0 and jstat("wif-ok", "complete") == 1 and rc_bad == 0
                and jstat("wif-bad", "failed") == 1 and jstat("wif-bad", "complete") == 0,
                "LIVE: an external worker COMPLETES an intact job and FAILS a removed-source job (success/failure "
                "discriminates; not a blanket outcome)", "live worker failure",
                extra={"ok_complete": jstat("wif-ok", "complete"), "bad_failed": jstat("wif-bad", "failed")})

            # FL02: import ASSESS changes 0 rows while EXECUTE writes rows (read-only vs write discriminates)
            from psycopg.types.json import Jsonb
            import datetime as dt
            from backend.app.schemas import FieldCorrection
            tid = str(uuid.uuid4()); wsid = str(uuid.uuid4()); slug = "wif-imp"
            corr = FieldCorrection(tenant_id=uuid.UUID(tid), workspace_id=uuid.UUID(wsid),
                                   target_type="report_field", field_key="rig_name", correction_reason="s",
                                   actor_user_id=uuid.uuid4(), actor_email="s@x.test", status="active",
                                   created_at=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
            payload = {"tenant": {"id": tid, "name": "s", "slug": slug},
                       "workspaces": [{"id": wsid, "tenant_id": tid, "name": "w"}],
                       "monday_reports": [], "field_corrections": [corr.model_dump(mode="json")],
                       "validation_tasks": [], "audit_logs": []}
            with psycopg.connect(boot, autocommit=True) as c:
                c.execute(f"delete from {STATE_TABLE} where tenant_slug=%s", (slug,))
                c.execute(f"insert into {STATE_TABLE} (tenant_slug, tenant_id, payload, revision) values (%s,%s,%s,1)",
                          (slug, tid, Jsonb(payload)))
            imp_env = G._child_env({**base_env, "MONDAY_REPORT_DATABASE_URL": f"{rt}?application_name=mr-wif-imp-{run_hash}",
                                    "MONDAY_REPORT_TENANT_SLUG": slug})

            def norm_c():
                with psycopg.connect(boot, autocommit=True) as c:
                    return int(c.execute("select count(*) from monday_report_norm_field_corrections where tenant_slug=%s",
                                         (slug,)).fetchone()[0])

            def run_imp(mode):
                return subprocess.run([sys.executable, "-m", "backend.app.normalized_import", mode], cwd=str(ROOT),
                                      env=imp_env, capture_output=True, text=True, timeout=60).returncode
            before = norm_c(); run_imp("assess"); after_assess = norm_c(); run_imp("execute"); after_exec = norm_c()
            mut("FL02", before == 0 and after_assess == 0 and after_exec == 1,
                "LIVE: import ASSESS changes 0 rows; EXECUTE writes exactly the migrated row (read-only vs write "
                "discriminates)", "whole-stack import mutation",
                extra={"before": before, "after_assess": after_assess, "after_execute": after_exec})

            # FL03: DISABLE RLS (reverted-in-finally) exposes cross-tenant snapshot rows to the restricted login,
            # proving RLS is load-bearing for the worker/import read path.
            rls_seed_slugs[:] = ["wif-ra-" + run_hash, "wif-rb-" + run_hash]
            with psycopg.connect(boot, autocommit=True) as c:
                c.execute(f"insert into {STATE_TABLE} (tenant_slug, tenant_id, payload, revision) "
                          "values (%s,%s,'{}',1),(%s,%s,'{}',1) on conflict (tenant_slug) do nothing",
                          (rls_seed_slugs[0], str(uuid.uuid4()), rls_seed_slugs[1], str(uuid.uuid4())))
            both = f"tenant_slug in ('wif-ra-{run_hash}','wif-rb-{run_hash}')"

            def rt_count(guc):
                c = psycopg.connect(rt); c.autocommit = False
                try:
                    with c.cursor() as cur:
                        cur.execute("select set_config('app.tenant_slug', %s, true)", (guc,))
                        cur.execute(f"select count(*) from {STATE_TABLE} where {both}")
                        return int(cur.fetchone()[0])
                finally:
                    c.rollback(); c.close()
            base_seen = rt_count("wif-ra-" + run_hash)
            try:
                with psycopg.connect(boot, autocommit=True) as c:
                    c.execute(f"alter table {STATE_TABLE} disable row level security")
                exposed = rt_count("wif-ra-" + run_hash)
            finally:
                with psycopg.connect(boot, autocommit=True) as c:
                    c.execute(f"alter table {STATE_TABLE} enable row level security")
            restored = rt_count("wif-ra-" + run_hash)
            mut("FL03", base_seen == 1 and exposed == 2 and restored == 1,
                "LIVE POLICY MUTATION (reverted): DISABLE ROW LEVEL SECURITY exposes BOTH tenants' snapshot rows to "
                "the restricted login (RLS is load-bearing for worker/import); re-enabled in finally restores scoping",
                "live PostgreSQL mutation", extra={"base": base_seen, "exposed": exposed, "restored": restored})
        finally:
            with contextlib.suppress(Exception):
                with psycopg.connect(boot, autocommit=True) as c:
                    c.execute(f"alter table {STATE_TABLE} enable row level security")
            if rls_seed_slugs:  # FL03 seed rows removed here so a mid-FL03 abort cannot leak them
                with contextlib.suppress(Exception):
                    with psycopg.connect(boot, autocommit=True) as c:
                        c.execute(f"delete from {STATE_TABLE} where tenant_slug = any(%s::text[])", (rls_seed_slugs,))
            for sc in scratches:
                shutil.rmtree(sc, ignore_errors=True)

    G.checks = []
    err = {}

    def wrapped(ctx):
        try:
            on_live(ctx)
        except Exception as exc:  # noqa: BLE001
            import traceback
            err["type"] = type(exc).__name__
            err["tb"] = traceback.format_exc()[-2200:]
    G._ON_LIVE = wrapped
    try:
        G.run_stack()
    finally:
        G._ON_LIVE = None
    foundation_fail = [c["id"] for c in getattr(G, "checks", []) if not c.get("ok", True) and not c.get("skipped", False)]
    if foundation_fail:
        mut("foundation", False, f"foundation checks not ok: {sorted(foundation_fail)[:8]}", "structural source check")
    if err:
        print("ON_LIVE ERROR:", err.get("type"), file=sys.stderr)
        print(_scrub(err.get("tb", "")), file=sys.stderr)
        mut("on_live_abort", False, f"on_live aborted with {err.get('type')} (see stderr)", "structural source check")
    return _emit()


FAULTS_EXPECTED = ([f"FS0{i}" for i in range(6)]
                   + [f"PF{n:02d}" for n in range(1, 24)]
                   + ["FL01", "FL02", "FL03"])


def _emit(skipped=False) -> int:
    if not skipped:  # completeness: every expected fault check must be present exactly once (no silent drop/dup)
        ids = [c["check_id"] for c in checks]
        missing = [x for x in FAULTS_EXPECTED if x not in ids]
        dups = sorted({x for x in FAULTS_EXPECTED if ids.count(x) > 1})
        if missing or dups:
            mut("completeness", False, f"expected fault checks incomplete (missing={missing} dups={dups})",
                "structural source check")
    passed = [c for c in checks if c["ok"]]
    failed = [c for c in checks if not c["ok"]]
    battery = "passed" if (checks and not failed and not skipped) else ("skipped" if skipped else "failed")
    exec_totals = {}
    for c in checks:
        exec_totals[c["execution_level"]] = exec_totals.get(c["execution_level"], 0) + 1
    out = {"checks": checks,
           "summary": {"passed": len(passed) if not skipped else 0,
                       "skipped": len(checks) if skipped else 0,
                       "failed": 0 if skipped else len(failed),
                       "execution_level_totals": exec_totals,
                       "claim_scope": "restricted-runtime-worker-import-faults-only",
                       "mutation_battery": battery,
                       "eligible_for_tenant_evidence": False,
                       "eligible_for_readiness": False,
                       "production_parity": False,
                       "migration_principal_class": "test-only-bootstrap-migration-admin"}}
    print(_scrub(json.dumps(out, indent=2, default=str)))
    if skipped:
        print("\nWorker/import fault battery SKIPPED (docker unavailable, non-certifying).")
        return 0
    if failed:
        print(f"\nWorker/import fault battery FAILED: {len(failed)} check(s).")
        for c in failed:
            print(_scrub(f"  FAIL: {c['check_id']} -> {c.get('description','')}"))
        return 1
    print(f"\nWorker/import fault battery passed: {len(passed)} non-vacuity proof(s)."
          "\n[claim_scope=restricted-runtime-worker-import-faults-only; NOT evidence/readiness eligible]")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
