"""Non-vacuity battery for the cross-tenant HTTP + direct-RLS isolation slice (Outcome-1 slice 3).

Proves the audit:restricted-postgres-runtime-isolation slice's assertions are NON-VACUOUS. For each
listed violation it EITHER runs a LIVE control against the accepted runner-owned stack proving the slice's
assertion discriminates (an own-tenant read succeeds while a cross-tenant one is denied; a missing GUC
hides rows the GUC reveals; a cross-tenant write affects zero rows a same-tenant write changes), OR
performs a LIVE, reverted-in-finally PostgreSQL policy/role mutation demonstrating the RLS defense is
load-bearing (DISABLE ROW LEVEL SECURITY / grant BYPASSRLS both expose cross-tenant rows, then are
reverted), OR evaluates a mirror of the slice's exact pass-predicate against a crafted VIOLATED
observation and confirms the predicate rejects it, OR is a STRUCTURAL check of the slice's own fail-closed
gates driven through the REAL M._emit / M.EXPECTED_IDS (normal-HTTP 423/500/503 counter, completeness of
the expected inventory, and duplicate-id detection). Every check is classified honestly by execution
level. Every live policy/role mutation is reverted in a finally block. Requires Docker.

HONEST SCOPE:
  claim_scope = restricted-runtime-cross-tenant-http-rls-faults-only
  eligible_for_tenant_evidence = false / eligible_for_readiness = false / production_parity = false
It must NEVER be consumed as tenant-authorization or readiness evidence.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import secrets
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT, ROOT / "scripts"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import restricted_postgres_startup_guard as G  # noqa: E402

checks: list[dict] = []
LEAK_TERMS: list[str] = []


def _scrub(text: str) -> str:
    for term in LEAK_TERMS:
        if term:
            text = text.replace(term, "<redacted>")
    return text


def mut(cid, ok, desc, level, extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level, **(extra or {})})


def _http(method, url, key=None):
    headers = {"X-Monday-Report-Key": key} if key else {}
    req = urllib.request.Request(url, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:  # noqa: BLE001
        return None


def run() -> int:
    allow_unavailable = "--allow-unavailable" in sys.argv
    if G._docker(["info"]).returncode != 0:
        mut("setup", allow_unavailable, "docker availability", "structural source check")
        return _emit(skipped=allow_unavailable)

    # ================= STRUCTURAL: drive the slice's own fail-closed gates =================
    spec = importlib.util.spec_from_file_location(
        "isoslice", str(ROOT / "scripts" / "restricted_postgres_runtime_isolation_guard.py"))
    M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)

    def _populate_all():
        M.checks.clear(); M.HTTP_STATUSES.clear()
        for cid in M.EXPECTED_IDS:
            M.rec(cid, True, desc="ok", category="p", op="-", tenant="-", actor="-", resource="-",
                  expected="-", db_post="-", audit_post="-")

    def _emit_rc():
        with contextlib.redirect_stdout(io.StringIO()):
            return M._emit()

    _populate_all()
    mut("FS00", _emit_rc() == 0, "a complete, clean slice inventory passes the gate (gates are not always-fail)",
        "structural source check")
    for cid, code in (("FS01", 423), ("FS02", 500), ("FS03", 503)):
        _populate_all(); M.HTTP_STATUSES.append(code)
        mut(cid, _emit_rc() == 1, f"a normal-traffic {code} forces the slice verdict non-passing",
            "structural source check")
    _populate_all(); M.checks.pop()
    mut("FS04", _emit_rc() == 1, "a missing expected slice check id forces the slice verdict non-passing",
        "structural source check")
    _populate_all()
    M.rec(M.EXPECTED_IDS[0], True, desc="dup", category="p", op="-", tenant="-", actor="-", resource="-",
          expected="-", db_post="-", audit_post="-")
    mut("FS05", _emit_rc() == 1, "a duplicate check id forces the slice verdict non-passing",
        "structural source check")
    M.checks.clear(); M.HTTP_STATUSES.clear()

    # ================= PREDICATE/UNIT: mirrors of the slice pass-predicates =================
    def pd(cid, desc, pred, violated, correct):
        mut(cid, (pred(violated) is False) and (pred(correct) is True), desc, "predicate/unit mutation",
            extra={"rejects_violation": pred(violated) is False, "accepts_correct": pred(correct) is True})

    # cross-tenant HTTP denials (a success would be caught)
    pd("PF01", "a cross-tenant report-scoped op (export/signed-url mint) that SUCCEEDED (200) would be caught",
       lambda s: s in (403, 404), 200, 404)
    pd("PF02", "a cross-tenant CORRECTION creation that SUCCEEDED (201) would be caught", lambda s: s in (403, 404), 201, 404)
    pd("PF03", "a cross-tenant CORRECTION read that SUCCEEDED (200) would be caught", lambda s: s in (403, 404), 200, 403)
    pd("PF04", "a cross-tenant task APPROVE that SUCCEEDED (200) would be caught", lambda s: s == 404, 200, 404)
    pd("PF05", "a cross-tenant task REJECT that SUCCEEDED (200) would be caught", lambda s: s == 404, 200, 404)
    pd("PF06", "a cross-tenant task REOPEN that SUCCEEDED (200) would be caught", lambda s: s == 404, 200, 404)
    pd("PF07", "a cross-tenant EXPORT that SUCCEEDED (200) would be caught", lambda s: s in (403, 404), 200, 404)
    pd("PF08", "a cross-tenant SIGNED-REFERENCE retrieval that SUCCEEDED (200) would be caught", lambda s: s == 404, 200, 404)
    # tenant-B state exposed after an A action (unchanged-snapshot predicate)
    def unchanged(o):
        return o["before"] == o["after"]
    pd("PF09", "a tenant-B idempotency result EXPOSED (B state changed by A) would be caught",
       unchanged, {"before": {"biz": 5}, "after": {"biz": 6}}, {"before": {"biz": 5}, "after": {"biz": 5}})
    # spoof trusted (a spoof that mutated/leaked B would be caught)
    pd("PF10", "a BODY tenant spoof that mutated tenant B (B delta != 0) would be caught",
       lambda d: d == 0, 1, 0)
    pd("PF11", "a QUERY tenant spoof that leaked a B report into A's list would be caught",
       lambda leaked: leaked is False, True, False)
    pd("PF12", "a HEADER tenant spoof that returned a B report (200) would be caught", lambda s: s in (403, 404), 200, 404)
    pd("PF13", "an ACTOR spoof that leaked a B report would be caught", lambda leaked: leaked is False, True, False)
    # RLS inventory violations (each would flip the MP predicate)
    def mp_ok(m):
        return bool(m.get("rowsecurity")) and bool(m.get("forced")) and m.get("tenant_policies", 0) >= 1 \
            and not m.get("widening") and not m.get("owned_by_runtime")
    pd("PF14", "RLS DISABLED on a protected table would be caught",
       mp_ok, {"rowsecurity": False, "forced": True, "tenant_policies": 1, "widening": False, "owned_by_runtime": False},
       {"rowsecurity": True, "forced": True, "tenant_policies": 1, "widening": False, "owned_by_runtime": False})
    pd("PF15", "FORCE row level security DISABLED would be caught",
       mp_ok, {"rowsecurity": True, "forced": False, "tenant_policies": 1, "widening": False, "owned_by_runtime": False},
       {"rowsecurity": True, "forced": True, "tenant_policies": 1, "widening": False, "owned_by_runtime": False})
    pd("PF16", "the tenant_isolation policy REMOVED (0 policies) would be caught",
       mp_ok, {"rowsecurity": True, "forced": True, "tenant_policies": 0, "widening": False, "owned_by_runtime": False},
       {"rowsecurity": True, "forced": True, "tenant_policies": 1, "widening": False, "owned_by_runtime": False})
    pd("PF17", "a PUBLIC/widening permissive policy added would be caught",
       mp_ok, {"rowsecurity": True, "forced": True, "tenant_policies": 1, "widening": True, "owned_by_runtime": False},
       {"rowsecurity": True, "forced": True, "tenant_policies": 1, "widening": False, "owned_by_runtime": False})
    pd("PF18", "the runtime role OWNING a protected table would be caught",
       mp_ok, {"rowsecurity": True, "forced": True, "tenant_policies": 1, "widening": False, "owned_by_runtime": True},
       {"rowsecurity": True, "forced": True, "tenant_policies": 1, "widening": False, "owned_by_runtime": False})
    pd("PF19", "the runtime role having BYPASSRLS or superuser would be caught",
       lambda m: (not m["is_superuser"]) and (not m["has_bypassrls"]) and m["is_login_not_group"],
       {"is_superuser": False, "has_bypassrls": True, "is_login_not_group": True},
       {"is_superuser": False, "has_bypassrls": False, "is_login_not_group": True})
    # RLS read fail-closed (a missing/invalid GUC exposing rows would be caught)
    pd("PF20", "a missing/invalid/unknown GUC EXPOSING rows would be caught",
       lambda o: o["missing"] == 0 and o["invalid"] == 0 and o["unknown"] == 0,
       {"missing": 5, "invalid": 0, "unknown": 0}, {"missing": 0, "invalid": 0, "unknown": 0})
    # RLS write controls
    pd("PF21", "a cross-tenant INSERT that SUCCEEDED (no 42501) would be caught",
       lambda o: (not o["ok"]) and o["sqlstate"] == "42501", {"ok": True, "sqlstate": None}, {"ok": False, "sqlstate": "42501"})
    pd("PF22", "a cross-tenant UPDATE that changed rows (rowcount>0) would be caught", lambda rc: rc == 0, 1, 0)
    pd("PF23", "a cross-tenant DELETE that removed rows (rowcount>0) would be caught", lambda rc: rc == 0, 1, 0)
    # WITH CHECK distinguished from a constraint failure (a 23xxx mislabeled as RLS proof would be caught)
    pd("PF24", "a plain constraint failure (23xxx) mislabeled as an RLS WITH CHECK denial would be caught",
       lambda o: (not o["ok"]) and o["sqlstate"] == "42501", {"ok": False, "sqlstate": "23503"}, {"ok": False, "sqlstate": "42501"})
    # pool leak
    pd("PF25", "a pooled connection LEAKING tenant-A context into tenant B (A rows visible under B) would be caught",
       lambda n: n == 0, 5, 0)

    # ================= LIVE controls (incl. reverted-in-finally policy/role mutations) =======
    def on_live(ctx):
        import psycopg
        api, token = ctx["api_base"], ctx["token"]
        boot, rt, rt_role = ctx["boot_dsn"], ctx["rt_dsn"], ctx["rt_role"]
        run_hash = ctx["run_hash"]
        LEAK_TERMS[:] = sorted({str(t) for t in [ctx["run_id"], run_hash, rt_role, ctx["mig_role"], boot, rt,
                                                 ctx["mig_dsn"], ctx["db"], token, ctx["base_env"]["MONDAY_REPORT_API_KEY"]] if t},
                               key=len, reverse=True)
        SN = "monday_report_state_snapshots"
        fa, fb = "flt-a-" + run_hash, "flt-b-" + run_hash
        boot_c = psycopg.connect(boot); boot_c.autocommit = True

        def rt_scoped_count(guc, where, params):
            c = psycopg.connect(rt); c.autocommit = False
            try:
                with c.cursor() as cur:
                    if guc is not None:
                        cur.execute("select set_config('app.tenant_slug', %s, true)", (guc,))
                    cur.execute(f"select count(*) from {SN} where {where}", params)
                    return int(cur.fetchone()[0])
            finally:
                c.rollback(); c.close()

        def rt_write(guc, sql, params):
            c = psycopg.connect(rt); c.autocommit = False
            try:
                with c.cursor() as cur:
                    if guc is not None:
                        cur.execute("select set_config('app.tenant_slug', %s, true)", (guc,))
                    cur.execute(sql, params)
                    return cur.rowcount
            finally:
                c.rollback(); c.close()

        try:
            # two synthetic tenant rows (superuser bypasses RLS+WITH CHECK to seed both tenants)
            with boot_c.cursor() as cur:
                cur.execute(f"insert into {SN} (tenant_slug, tenant_id, payload) values (%s,%s,'{{}}'),(%s,%s,'{{}}') "
                            "on conflict (tenant_slug) do nothing",
                            (fa, str(uuid.uuid4()), fb, str(uuid.uuid4())))
            both = f"tenant_slug in ('{fa}','{fb}')"

            # FL-httpdenial: an own-tenant read succeeds while a random report id is denied (path is real)
            own = _http("GET", f"{api}/monday-reports", key=token)
            rnd = _http("GET", f"{api}/monday-reports/{uuid.uuid4()}", key=token)
            mut("FL01", own == 200 and rnd == 404,
                "LIVE HTTP: an own-tenant list is 200 while a random report id is 404 (denial path is real, not blanket)",
                "live HTTP denial", extra={"own": own, "random": rnd})

            # FL-missingguc: with GUC=fa the runtime sees only fa; with NO GUC it sees zero (GUC gate is real)
            with_guc = rt_scoped_count(fa, both, ())
            no_guc = rt_scoped_count(None, both, ())
            mut("FL02", with_guc == 1 and no_guc == 0,
                "LIVE RLS: GUC=fa sees exactly its own row; NO GUC sees zero (the app.tenant_slug gate is load-bearing)",
                "live PostgreSQL data mutation", extra={"with_guc": with_guc, "no_guc": no_guc})

            # FL-crosswrite: same-tenant UPDATE changes 1 row; cross-tenant UPDATE changes 0 (USING is real)
            same = rt_write(fa, f"update {SN} set payload=payload where tenant_slug=%s", (fa,))
            cross = rt_write(fa, f"update {SN} set payload=payload where tenant_slug=%s", (fb,))
            mut("FL03", same == 1 and cross == 0,
                "LIVE RLS: same-tenant UPDATE affects 1 row, cross-tenant UPDATE affects 0 (USING is real, not blanket-deny)",
                "live PostgreSQL data mutation", extra={"same_tenant": same, "cross_tenant": cross})

            # FL-rls-disable: DISABLING RLS exposes the other tenant's row; REVERTED in finally
            baseline = rt_scoped_count(fa, both, ())
            try:
                with boot_c.cursor() as cur:
                    cur.execute(f"alter table {SN} disable row level security")
                exposed = rt_scoped_count(fa, both, ())
            finally:
                with boot_c.cursor() as cur:
                    cur.execute(f"alter table {SN} enable row level security")
            restored = rt_scoped_count(fa, both, ())
            mut("FL04", baseline == 1 and exposed == 2 and restored == 1,
                "LIVE POLICY MUTATION (reverted): DISABLE ROW LEVEL SECURITY exposes BOTH tenants' rows, "
                "proving RLS is load-bearing; re-enabled in finally restores isolation",
                "live PostgreSQL policy mutation",
                extra={"baseline": baseline, "exposed_when_disabled": exposed, "restored": restored})

            # FL-bypassrls: granting BYPASSRLS to the runtime role exposes both tenants; REVERTED in finally
            try:
                with boot_c.cursor() as cur:
                    cur.execute(f'alter role "{rt_role}" bypassrls')
                exposed_b = rt_scoped_count(fa, both, ())  # fresh connection reads the new role attribute
            finally:
                with boot_c.cursor() as cur:
                    cur.execute(f'alter role "{rt_role}" nobypassrls')
            restored_b = rt_scoped_count(fa, both, ())
            mut("FL05", exposed_b == 2 and restored_b == 1,
                "LIVE ROLE MUTATION (reverted): granting BYPASSRLS to the runtime role exposes BOTH tenants' rows, "
                "proving the non-BYPASSRLS requirement is load-bearing; reverted in finally",
                "live PostgreSQL policy mutation",
                extra={"exposed_when_bypassrls": exposed_b, "restored": restored_b})
        finally:
            try:
                with boot_c.cursor() as cur:
                    # fail-safe: ensure RLS/role are restored even on an early error, then remove seed rows
                    cur.execute(f"alter table {SN} enable row level security")
                    cur.execute(f'alter role "{rt_role}" nobypassrls')
                    cur.execute(f"delete from {SN} where tenant_slug in (%s,%s)", (fa, fb))
            except Exception:
                pass
            boot_c.close()

    G.checks = []
    err = {}

    def wrapped(ctx):
        try:
            on_live(ctx)
        except Exception as exc:  # noqa: BLE001
            import traceback
            err["type"] = type(exc).__name__
            err["tb"] = traceback.format_exc()[-2000:]
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


def _emit(skipped=False) -> int:
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
                       "claim_scope": "restricted-runtime-cross-tenant-http-rls-faults-only",
                       "mutation_battery": battery,
                       "eligible_for_tenant_evidence": False,
                       "eligible_for_readiness": False,
                       "production_parity": False,
                       "migration_principal_class": "test-only-bootstrap-migration-admin"}}
    print(_scrub(json.dumps(out, indent=2, default=str)))
    if skipped:
        print("\nIsolation fault battery SKIPPED (docker unavailable, non-certifying).")
        return 0
    if failed:
        print(f"\nIsolation fault battery FAILED: {len(failed)} check(s).")
        for c in failed:
            print(_scrub(f"  FAIL: {c['check_id']} -> {c.get('description','')}"))
        return 1
    print(f"\nIsolation fault battery passed: {len(passed)} non-vacuity proof(s)."
          "\n[claim_scope=restricted-runtime-cross-tenant-http-rls-faults-only; NOT evidence/readiness eligible]")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
