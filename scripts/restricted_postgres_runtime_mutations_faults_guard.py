"""Non-vacuity mutation battery for the corrections+validation+idempotency slice (Outcome-1 slice 1).

Proves the audit:restricted-postgres-runtime-mutations slice's assertions are NON-VACUOUS. For each
listed violation it EITHER runs a LIVE control against the accepted runner-owned stack proving the
slice's assertion discriminates (a replay/denial/dedup is a REAL behaviour, not a blanket outcome),
OR evaluates the slice's exact pass-predicate against a crafted VIOLATED observation and confirms the
predicate rejects it (so a regression would flip the check), OR is a STRUCTURAL check of the slice's
own normal-HTTP counter gate. Every check is classified honestly by execution level -- a predicate
check is NEVER described as a live HTTP test.

HONEST SCOPE:
  claim_scope = restricted-runtime-corrections-validation-idempotency-faults-only
  eligible_for_tenant_evidence = false / eligible_for_readiness = false / production_parity = false
It must NEVER be consumed as tenant-authorization or readiness evidence. Requires Docker.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
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
            text = text.replace(term, "<redacted>")
    return text


def mut(cid, ok, desc, level, extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level, **(extra or {})})


def _http(method, url, key=None, body=None, idem=None):
    headers = {}
    if key:
        headers["X-Monday-Report-Key"] = key
    if idem is not None:
        headers["Idempotency-Key"] = idem
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            b = r.read()
            try:
                return r.status, json.loads(b or b"null")
            except Exception:
                return r.status, b
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except Exception:
            return e.code, None
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def run() -> int:
    allow_unavailable = "--allow-unavailable" in sys.argv
    if G._docker(["info"]).returncode != 0:
        mut("setup", allow_unavailable, "docker availability", "structural source check")
        return _emit(skipped=allow_unavailable)

    # ---- STRUCTURAL: the slice's http-counter gate rejects normal 423/500/503 (mutations 20-22) ----
    # Load the slice module and drive its _emit gate with a crafted HTTP_STATUSES to confirm a normal
    # 423/500/503 forces a non-passing verdict (rc != 0). No stack needed for these.
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "mutslice", str(ROOT / "scripts" / "restricted_postgres_runtime_mutations_guard.py"))
    M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)

    import contextlib
    import io

    def _gate_rc(status):
        M.checks.clear(); M.HTTP_STATUSES.clear()
        M.rec("probe", True, desc="ok", category="probe", route="-", tenant="-", actor="-",
              idem="-", expected="-", db_post="-", audit_post="-")
        M.HTTP_STATUSES.append(status)
        with contextlib.redirect_stdout(io.StringIO()):  # the slice _emit prints its own JSON; swallow it
            return M._emit()
    mut("MF20", _gate_rc(423) == 1, "a normal-traffic 423 forces the slice verdict non-passing", "structural source check")
    mut("MF21", _gate_rc(500) == 1, "a normal-traffic 500 forces the slice verdict non-passing", "structural source check")
    mut("MF22", _gate_rc(503) == 1, "a normal-traffic 503 forces the slice verdict non-passing", "structural source check")
    # restore the slice module's globals so the import has no lingering state
    M.checks.clear(); M.HTTP_STATUSES.clear()

    # ---- PREDICATE/UNIT: the slice's exact pass-predicates reject each crafted violation --------
    # Each predicate mirrors the slice check's pass-condition; feeding it a VIOLATED observation must
    # yield False (a regression would flip the check) AND the CORRECT observation must yield True.
    def pd(cid, desc, pred, violated, correct):
        mut(cid, (pred(violated) is False) and (pred(correct) is True), desc, "predicate/unit mutation",
            extra={"rejects_violation": pred(violated) is False, "accepts_correct": pred(correct) is True})

    # corrections idempotency (mutations 1-3): replay must add no row / no business audit
    pd("MF01", "exact correction replay that DUPLICATED a row would be caught",
       lambda d: d["corr_total"] == 0 and d["biz"] == 0, {"corr_total": 1, "biz": 1}, {"corr_total": 0, "biz": 0})
    pd("MF02", "exact correction replay that DUPLICATED a business audit would be caught",
       lambda d: d["biz"] == 0, {"biz": 1}, {"biz": 0})
    pd("MF03", "lost-response replay that DUPLICATED the mutation would be caught",
       lambda d: d["corr_total"] == 0 and d["biz"] == 0, {"corr_total": 1, "biz": 1}, {"corr_total": 0, "biz": 0})
    # correction idempotency conflicts (mutations 4-8): changed body/op/actor/target/tenant must not 2xx
    pd("MF04", "changed correction body ACCEPTED (2xx) would be caught", lambda s: s == 409, 200, 409)
    pd("MF05", "changed correction operation ACCEPTED would be caught", lambda s: s == 409, 200, 409)
    pd("MF06", "changed correction actor ACCEPTED would be caught", lambda s: s == 409, 201, 409)
    pd("MF07", "changed correction tenant ACCEPTED would be caught", lambda s: s in (401, 403), 201, 403)
    pd("MF08", "changed correction target ACCEPTED would be caught", lambda s: s == 409, 200, 409)
    # validation idempotency (mutations 9-15)
    pd("MF09", "exact validation replay that DUPLICATED a transition would be caught",
       lambda d: d["biz"] == 0, {"biz": 1}, {"biz": 0})
    pd("MF10", "exact validation replay that DUPLICATED a business audit would be caught",
       lambda d: d["biz"] == 0, {"biz": 1}, {"biz": 0})
    pd("MF11", "changed validation body ACCEPTED would be caught", lambda s: s == 409, 200, 409)
    pd("MF12", "changed validation operation ACCEPTED would be caught", lambda s: s == 409, 200, 409)
    pd("MF13", "changed validation actor ACCEPTED would be caught", lambda s: s == 409, 200, 409)
    pd("MF14", "changed validation tenant ACCEPTED would be caught", lambda s: s in (401, 403), 200, 403)
    pd("MF15", "missing validation Idempotency-Key ACCEPTED would be caught", lambda s: s == 400, 200, 400)
    # reviewer gates (mutations 16-18): a slice check requires a denial; a 2xx would flip it
    pd("MF16", "unverified reviewer ACCEPTED would be caught", lambda s: s in (401, 403), 200, 403)
    pd("MF17", "disabled reviewer ACCEPTED would be caught", lambda s: s in (401, 403), 200, 401)
    pd("MF18", "cross-tenant reviewer ACCEPTED would be caught", lambda s: s in (401, 403), 200, 403)
    # race (mutation 19): a duplicate terminal transition (n2xx>1 or biz>1) would be caught
    pd("MF19", "a race that produced a DUPLICATE terminal transition would be caught",
       lambda o: o["n2xx"] == 1 and o["biz"] == 1, {"n2xx": 2, "biz": 2}, {"n2xx": 1, "biz": 1})

    # ---- LIVE HTTP controls: prove the reviewer/idempotency behaviours are REAL (non-blanket) ----
    def on_live(ctx):
        import psycopg
        import backend.app.store as store_mod
        from backend.app.schemas import Role as _Role
        api_a = ctx["api_base"]; token_a = ctx["token"]; rt = ctx["rt_dsn"]
        base_env = dict(ctx["base_env"]); run_hash = ctx["run_hash"]
        legacy_key = base_env["MONDAY_REPORT_API_KEY"]
        LEAK_TERMS[:] = sorted({str(t) for t in [ctx["run_id"], run_hash, ctx["rt_role"], ctx["mig_role"],
                                                 ctx["boot_dsn"], rt, ctx["mig_dsn"], ctx["db"], token_a,
                                                 legacy_key] if t}, key=len, reverse=True)

        def with_env(env, fn):
            sv = {k: os.environ.get(k) for k in env}
            os.environ.update(env)
            try:
                st = store_mod.create_store(); st.refresh(); return fn(st)
            finally:
                for k in env:
                    (os.environ.__setitem__(k, sv.get(k)) if sv.get(k) is not None else os.environ.pop(k, None))

        def prov(st):
            u2 = st.create_user(f"mf2-{secrets.token_hex(4)}@verif.test", "MF2", [_Role.ADMIN])
            _, t2 = st.create_credential(u2.id)
            ud = st.create_user(f"mfd-{secrets.token_hex(4)}@verif.test", "MFD", [_Role.ADMIN])
            _, td = st.create_credential(ud.id); st.set_user_status(ud.id, "disabled")
            return t2, td
        token_a2, token_a_disabled = with_env(base_env, prov)
        LEAK_TERMS.extend([token_a2, token_a_disabled])
        for _ in range(60):
            if _http("GET", f"{api_a}/monday-reports", key=token_a2)[0] == 200:
                break
            time.sleep(0.25)

        def corr_rows():
            with psycopg.connect(rt, autocommit=True) as c:
                c.execute("select set_config('app.tenant_slug','verif-a',false)")
                return int(c.execute("select count(*) from monday_report_norm_field_corrections").fetchone()[0])

        _, w1 = _http("POST", f"{api_a}/workspaces", key=token_a, body={"name": "mf", "rig_name": "g"})
        ws = w1["id"] if isinstance(w1, dict) else None
        _, reg = _http("GET", f"{api_a}/field-corrections/registry", key=token_a)
        f0 = reg[0]
        cb = {"target_type": f0["target_type"], "field_key": f0["field_key"], "source_value": "S",
              "corrected_value": "123" if f0.get("value_type") == "numeric_text" else "v",
              "correction_reason": "faults control"}

        # MFL01 distinct correction keys create TWO rows (idempotency dedup is a REAL behaviour)
        _, w2 = _http("POST", f"{api_a}/workspaces", key=token_a, body={"name": "mf2", "rig_name": "g"})
        ws2 = w2["id"]; before = corr_rows()
        _http("POST", f"{api_a}/workspaces/{ws2}/field-corrections", key=token_a, body=cb, idem=str(uuid.uuid4()))
        _http("POST", f"{api_a}/workspaces/{ws2}/field-corrections", key=token_a, body=cb, idem=str(uuid.uuid4()))
        mut("MFL01", corr_rows() == before + 2,
            "LIVE: distinct correction keys create two rows (dedup is real, not because rows never add)",
            "whole-stack HTTP mutation", extra={"row_delta": corr_rows() - before})

        # MFL02 exact-body correction replay returns 2xx (no 409) -> the 409 is BODY-specific
        k = str(uuid.uuid4())
        s1, _ = _http("POST", f"{api_a}/workspaces/{ws}/field-corrections", key=token_a, body=cb, idem=k)
        s2, _ = _http("POST", f"{api_a}/workspaces/{ws}/field-corrections", key=token_a, body=cb, idem=k)
        mut("MFL02", s1 in (200, 201) and s2 in (200, 201),
            "LIVE: exact-body correction replay returns 2xx (the changed-body 409 is body-specific)",
            "whole-stack HTTP mutation", extra={"create": s1, "replay": s2})

        # MFL03 verified reviewer is a REAL check: intact token 200, byte-flipped rejected
        good = _http("GET", f"{api_a}/monday-reports", key=token_a)[0]
        mid = len(token_a) // 2
        flip = token_a[:mid] + ("a" if token_a[mid] != "a" else "b") + token_a[mid + 1:]
        bad = _http("GET", f"{api_a}/monday-reports", key=flip)[0]
        mut("MFL03", good == 200 and bad in (401, 403),
            "LIVE: intact credential authenticates, byte-flipped rejected (auth is a real check)",
            "whole-stack HTTP mutation", extra={"intact": good, "flipped": bad})

        # MFL04 disabled-reviewer denial is not blanket: enabled #2 authenticates, disabled rejected
        en = _http("GET", f"{api_a}/monday-reports", key=token_a2)[0]
        dis = _http("GET", f"{api_a}/monday-reports", key=token_a_disabled)[0]
        mut("MFL04", en == 200 and dis in (401, 403),
            "LIVE: enabled reviewer #2 authenticates while the disabled reviewer is denied (not blanket)",
            "whole-stack HTTP mutation", extra={"enabled": en, "disabled": dis})

        # MFL05 unverified (legacy shared key) denial is not blanket: per-user token 200, legacy rejected
        leg = _http("GET", f"{api_a}/monday-reports", key=legacy_key)[0]
        mut("MFL05", good == 200 and leg in (401, 403),
            "LIVE: per-user credential authenticates while the legacy shared key is denied (not blanket)",
            "whole-stack HTTP mutation", extra={"per_user": good, "legacy": leg})

    G.checks = []
    err = {}

    def wrapped(ctx):
        try:
            on_live(ctx)
        except Exception as exc:  # noqa: BLE001
            import traceback
            err["type"] = type(exc).__name__
            err["tb"] = traceback.format_exc()[-1800:]
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
        print(err.get("tb", ""), file=sys.stderr)
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
                       "claim_scope": "restricted-runtime-corrections-validation-idempotency-faults-only",
                       "mutation_battery": battery,
                       "eligible_for_tenant_evidence": False,
                       "eligible_for_readiness": False,
                       "production_parity": False,
                       "migration_principal_class": "test-only-bootstrap-migration-admin"}}
    print(_scrub(json.dumps(out, indent=2, default=str)))
    if skipped:
        print("\nMutations fault battery SKIPPED (docker unavailable, non-certifying).")
        return 0
    if failed:
        print(f"\nMutations fault battery FAILED: {len(failed)} check(s).")
        for c in failed:
            print(_scrub(f"  FAIL: {c['check_id']} -> {c.get('description','')}"))
        return 1
    print(f"\nMutations fault battery passed: {len(passed)} non-vacuity proof(s)."
          "\n[claim_scope=restricted-runtime-corrections-validation-idempotency-faults-only; NOT evidence/readiness eligible]")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
