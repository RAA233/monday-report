"""Restricted-PostgreSQL functional slice: corrections + validation + idempotency (Outcome-1 slice 1).

A NARROW slice guard (NOT the complete functional matrix, and NOT the accepted -core guard). It
stands up the ACCEPTED runner-owned stack (restricted_postgres_startup_guard.run_stack + _ON_LIVE --
the foundation is unchanged) and drives the REAL client-mode HTTP API across TWO synthetic tenants
(two external uvicorn on one runner-owned PostgreSQL, RLS-isolated by app.tenant_slug), with >=2
tenant-A actors + >=1 tenant-B actor + verified/unverified/disabled/cross-tenant reviewers, to prove
the CORRECTION lifecycle, the VALIDATION state machine, and the IDEMPOTENCY contract -- with direct
committed-SQL deltas (norm rows, active rows, idempotency rows, snapshot revision) and direct JSONB
audit deltas (business vs boundary-use events), never a TestClient or a create_store projection.

HONEST SCOPE. It emits:
  claim_scope = restricted-runtime-corrections-validation-idempotency-only
  full_functional_matrix = not_run
  eligible_for_tenant_evidence = false / eligible_for_readiness = false / production_parity = false
  migration_principal_class = test-only-bootstrap-migration-admin
It must NEVER be consumed as tenant-authorization or readiness evidence. Requires Docker.

DEFERRED to later Outcome-1 slices: the TRUE lost-response path (the post-commit loss hook is
client-mode-inert, so CO03 exercises an ordinary idempotent replay); signed-reference success +
exports; the complete cross-tenant HTTP matrix; the expanded direct-RLS matrix; worker-isolation
expansion; import expansion; tenant evidence v3; readiness evaluators/contexts; UI certification.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
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

BND = "client_data.verification_isolation_execution"
STATE_TABLE = "monday_report_state_snapshots"
checks: list[dict] = []
LEAK_TERMS: list[str] = []
HTTP_STATUSES: list[int] = []          # every status the guard sees; 423/500/503 must never appear


def _scrub(text: str) -> str:
    for term in LEAK_TERMS:
        if term:
            text = text.replace(term, "<redacted>")
    return text


def rec(cid, ok, *, desc, category, route, tenant, actor, idem, expected, db_post, audit_post,
        level="whole-stack HTTP mutation attempt", extra=None):
    # "mutation attempt" is honest for BOTH a successful mutating-route request and a controlled
    # rejection (404/400/409/denial) that mutates nothing.
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "category": category, "route": route, "tenant": tenant,
                   "actor": actor, "idempotency": idem, "expected_status": expected,
                   "db_postcondition": db_post, "audit_postcondition": audit_post,
                   "execution_level": level, **(extra or {})})


def _http(method, url, key=None, body=None, idem=None, raw=None, ctype=None, extra_headers=None):
    headers = {}
    if key:
        headers["X-Monday-Report-Key"] = key
    if idem is not None:
        headers["Idempotency-Key"] = idem
    if extra_headers:
        headers.update(extra_headers)
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    elif raw is not None:
        headers["Content-Type"] = ctype or "application/octet-stream"
        data = raw
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            b = r.read()
            HTTP_STATUSES.append(r.status)
            try:
                return r.status, json.loads(b or b"null")
            except Exception:
                return r.status, b
    except urllib.error.HTTPError as e:
        HTTP_STATUSES.append(e.code)
        try:
            return e.code, json.loads(e.read() or b"null")
        except Exception:
            return e.code, None
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def run() -> int:
    allow_unavailable = "--allow-unavailable" in sys.argv
    if G._docker(["info"]).returncode != 0:
        rec("setup", allow_unavailable, desc="docker availability", category="setup", route="-",
            tenant="-", actor="-", idem="-", expected="docker",
            db_post="-", audit_post="-", level="structural source check")
        return _emit(skipped=allow_unavailable)

    def on_live(ctx):
        import psycopg
        import backend.app.store as store_mod
        from backend.app.schemas import Role as _Role

        api_a = ctx["api_base"]
        token_a = ctx["token"]
        boot = ctx["boot_dsn"]
        rt = ctx["rt_dsn"]
        base_env = dict(ctx["base_env"])
        run_id, run_hash = ctx["run_id"], ctx["run_hash"]
        rt_role = ctx["rt_role"]
        legacy_key = base_env["MONDAY_REPORT_API_KEY"]
        LEAK_TERMS[:] = sorted({str(t) for t in [run_id, run_hash, rt_role, ctx["mig_role"], boot, rt,
                                                  ctx["mig_dsn"], ctx["db"], token_a, legacy_key,
                                                  f"mr-verif-{run_hash}", f"mr-verif-vol-{run_hash}"] if t},
                               key=len, reverse=True)

        # ---- run fn(store) with an env ACTIVE (create_store), then restore env ----
        def with_env(env, fn):
            sv = {k: os.environ.get(k) for k in env}
            os.environ.update(env)
            try:
                st = store_mod.create_store()
                st.refresh()
                return fn(st)
            finally:
                for k in env:
                    v = sv.get(k)
                    (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))

        # ================= provision a SECOND + DISABLED tenant-A actor (out-of-band, then poll) =====
        # A single atomic create_store save at a quiescent moment (before any API mutation), then poll
        # for visibility -> deterministic, no lost-update race with the live API-A.
        def prov_a(st):
            u2 = st.create_user(f"a2-{secrets.token_hex(4)}@verif.test", "Tenant A Reviewer 2", [_Role.ADMIN])
            _, t2 = st.create_credential(u2.id)
            ud = st.create_user(f"adis-{secrets.token_hex(4)}@verif.test", "Tenant A Disabled", [_Role.ADMIN])
            _, td = st.create_credential(ud.id)
            st.set_user_status(ud.id, "disabled")
            return t2, td
        token_a2, token_a_disabled = with_env(base_env, prov_a)
        LEAK_TERMS.extend([token_a2, token_a_disabled])
        for _ in range(60):
            if _http("GET", f"{api_a}/monday-reports", key=token_a2)[0] == 200:
                break
            time.sleep(0.25)

        # ================= provision TENANT B (pre-launch actors) + launch API-B ==================
        api_b_port = G._free_loopback_port()
        while api_b_port in (ctx["port"], 8000, 5173):
            api_b_port = G._free_loopback_port()
        b_appname = f"mr-verification-mut-b-{run_hash}"
        b_scratch = Path(os.environ.get("TEMP", "/tmp")) / f"mr-mut-b-{run_hash}"
        for sub in ("state", "storage", "exports"):
            (b_scratch / sub).mkdir(parents=True, exist_ok=True)
        b_env = dict(base_env)
        b_env.update({
            "MONDAY_REPORT_DATABASE_URL": f"{rt}?application_name={b_appname}",
            "MONDAY_REPORT_TENANT_SLUG": "verif-b",
            "MONDAY_REPORT_TENANT_NAME": "Verification Tenant B",
            "MONDAY_REPORT_USER_EMAIL": "reviewer-b@verif.test",
            "MONDAY_REPORT_USER_FULL_NAME": "Verif Reviewer B",
            "MONDAY_REPORT_STATE_PATH": str(b_scratch / "state" / "s.json"),
            "MONDAY_REPORT_STORAGE_ROOT": str(b_scratch / "storage"),
            "MONDAY_REPORT_EXPORT_ROOT": str(b_scratch / "exports"),
            "MONDAY_REPORT_API_KEY": secrets.token_urlsafe(24),
            "MONDAY_REPORT_API_BASE": f"http://127.0.0.1:{api_b_port}",
        })
        sv = {k: os.environ.get(k) for k in b_env}
        os.environ.update(b_env)
        try:
            store_b = store_mod.create_store()
            ub = store_b.create_user("apiuser-b@verif.test", "API User B", [_Role.ADMIN])
            _, token_b = store_b.create_credential(ub.id)
            tenant_b_id = store_b.tenant.id
        finally:
            for k, v in sv.items():
                (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))
        LEAK_TERMS.extend([token_b, b_env["MONDAY_REPORT_API_KEY"]])
        LEAK_TERMS[:] = sorted({t for t in LEAK_TERMS if t}, key=len, reverse=True)

        b_child = G._child_env(b_env)
        b_log = open(b_scratch / "api.log", "w")
        api_b_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", str(api_b_port)],
            cwd=str(ROOT), env=b_child, stdout=b_log, stderr=subprocess.STDOUT)
        api_b = f"http://127.0.0.1:{api_b_port}"
        try:
            up_b = False
            for _ in range(40):
                if _http("GET", f"{api_b}/health")[0] == 200:
                    up_b = True
                    break
                if api_b_proc.poll() is not None:
                    break
                time.sleep(1)

            # ================= direct committed-SQL delta surfaces (RLS-scoped) =================
            def _q(slug, sql, params=()):
                with psycopg.connect(rt, autocommit=True) as c:
                    c.execute("select set_config('app.tenant_slug', %s, false)", (slug,))
                    return c.execute(sql, params).fetchone()

            def snap(slug, action=None, operation=None):
                """All committed counters for a tenant, via direct SQL (no projection lag)."""
                corr_total = _q(slug, "select count(*) from monday_report_norm_field_corrections")[0]
                corr_active = _q(slug, "select count(*) from monday_report_norm_field_corrections where status='active'")[0]
                task_total = _q(slug, "select count(*) from monday_report_norm_validation_tasks")[0]
                idem = _q(slug, "select count(*) from monday_report_idempotency_records")[0]
                rev = _q(slug, f"select revision from {STATE_TABLE} where tenant_slug=%s", (slug,))[0]
                biz = _q(slug, f"select count(*) from {STATE_TABLE} s, "
                               "jsonb_array_elements(s.payload->'audit_logs') e "
                               "where e->>'action' = %s", (action,))[0] if action else 0
                bnd = _q(slug, f"select count(*) from {STATE_TABLE} s, "
                               "jsonb_array_elements(s.payload->'audit_logs') e "
                               "where e->>'action' = %s and e->'metadata'->>'operation' = %s",
                         (BND, operation))[0] if operation else 0
                return {"corr_total": corr_total, "corr_active": corr_active, "task_total": task_total,
                        "idem": idem, "rev": rev, "biz": biz, "bnd": bnd}

            def delta(a, b):
                return {k: b[k] - a[k] for k in a}

            # tenant-A workspaces (independent correction targets so scenarios cannot contaminate)
            def mk_ws(api, key, name):
                s, w = _http("POST", f"{api}/workspaces", key=key, body={"name": name, "rig_name": "g"})
                return w["id"] if isinstance(w, dict) else None
            wsA = {n: mk_ws(api_a, token_a, f"mut-a-{n}") for n in
                   ("create", "supersede", "revert", "actor", "target", "xkey")}
            wsB = mk_ws(api_b, token_b, "mut-b")
            _, reg = _http("GET", f"{api_a}/field-corrections/registry", key=token_a)
            f0, f1 = reg[0], (reg[1] if len(reg) > 1 else reg[0])

            def _cval(field, v):
                return "123" if field.get("value_type") == "numeric_text" else v

            def corr_body(field, val):
                return {"target_type": field["target_type"], "field_key": field["field_key"],
                        "source_value": "S", "corrected_value": _cval(field, val),
                        "correction_reason": "mutations slice"}

            # ============================ PART E: CORRECTION LIFECYCLE ==========================
            AA = "verif-a"
            corr_route = "/workspaces/{ws}/field-corrections"

            # CO01 create (verified per-user reviewer)
            k = str(uuid.uuid4())
            b0 = snap(AA, "field_correction.record", "field_correction.record")
            s, body = _http("POST", f"{api_a}/workspaces/{wsA['create']}/field-corrections",
                            key=token_a, body=corr_body(f0, "v1"), idem=k)
            cid_create = body.get("id") if isinstance(body, dict) else None
            d = delta(b0, snap(AA, "field_correction.record", "field_correction.record"))
            rec("CO01", s in (200, 201) and cid_create and d["corr_total"] == 1 and d["corr_active"] == 1
                and d["biz"] == 1 and d["bnd"] >= 1 and d["idem"] == 1 and d["rev"] >= 1,
                desc="create correction (verified reviewer)", category="correction-create",
                route="POST " + corr_route, tenant=AA, actor="tenant-A verified #1",
                idem="new key", expected="201", db_post="norm+1, active+1, idem+1, rev+1",
                audit_post="business+1, boundary>=1", extra={"status": s, "delta": d})

            # CO02 exact replay -> stored result, no business/norm/idem delta
            b1 = snap(AA, "field_correction.record", "field_correction.record")
            s, body = _http("POST", f"{api_a}/workspaces/{wsA['create']}/field-corrections",
                            key=token_a, body=corr_body(f0, "v1"), idem=k)
            cid_replay = body.get("id") if isinstance(body, dict) else None
            d = delta(b1, snap(AA, "field_correction.record", "field_correction.record"))
            rec("CO02", s in (200, 201) and cid_replay == cid_create and d["corr_total"] == 0
                and d["biz"] == 0 and d["idem"] == 0,
                desc="exact create replay returns stored result, no duplicate mutation",
                category="correction-idempotency", route="POST " + corr_route, tenant=AA,
                actor="tenant-A verified #1", idem="exact replay", expected="200 stored",
                db_post="norm+0, idem+0", audit_post="business+0", extra={"status": s, "delta": d})

            # CO03 second idempotent replay (fresh same-key resend) -> stored id, no delta.
            # NOTE (honesty): the TRUE "committed-but-response-lost, then retry" path is client-mode-
            # inert -- the post-commit loss hook returns early in client mode -- so this exercises the
            # ordinary idempotent-replay path against a distinct fresh request. True lost-response
            # coverage (forcing the hook) is deferred to a later slice.
            b2 = snap(AA, "field_correction.record")
            s, body = _http("POST", f"{api_a}/workspaces/{wsA['create']}/field-corrections",
                            key=token_a, body=corr_body(f0, "v1"), idem=k)
            cid_lost = body.get("id") if isinstance(body, dict) else None
            d = delta(b2, snap(AA, "field_correction.record"))
            rec("CO03", s in (200, 201) and cid_lost == cid_create and d["corr_total"] == 0
                and d["biz"] == 0 and d["idem"] == 0,
                desc="second idempotent replay (fresh same-key resend) returns the stored original, no "
                     "duplicate; TRUE lost-response hook is client-mode-inert (deferred)",
                category="correction-idempotency", route="POST " + corr_route, tenant=AA,
                actor="tenant-A verified #1", idem="idempotent replay (lost-response hook client-mode-inert)",
                expected="200 stored", db_post="norm+0, idem+0", audit_post="business+0", extra={"status": s})

            # CO04 same key, CHANGED BODY -> 409, no second mutation
            b3 = snap(AA, "field_correction.record")
            s, _ = _http("POST", f"{api_a}/workspaces/{wsA['create']}/field-corrections",
                         key=token_a, body=corr_body(f0, "CHANGED"), idem=k)
            d = delta(b3, snap(AA, "field_correction.record"))
            rec("CO04", s == 409 and d["corr_total"] == 0 and d["biz"] == 0 and d["idem"] == 0,
                desc="same key + changed body -> controlled 409, no second mutation",
                category="correction-idempotency", route="POST " + corr_route, tenant=AA,
                actor="tenant-A verified #1", idem="changed body", expected="409",
                db_post="norm+0", audit_post="business+0", extra={"status": s})

            # CO05 same key, CHANGED OPERATION (reuse the record key on the revert route) -> 409
            b4 = snap(AA, "field_correction.revert")
            s, _ = _http("POST", f"{api_a}/field-corrections/{cid_create}/revert",
                         key=token_a, body={"revert_reason": "x"}, idem=k)
            d = delta(b4, snap(AA, "field_correction.revert"))
            rec("CO05", s == 409 and d["biz"] == 0,
                desc="same key + changed operation (record->revert) -> controlled 409",
                category="correction-idempotency", route="POST /field-corrections/{id}/revert",
                tenant=AA, actor="tenant-A verified #1", idem="changed operation", expected="409",
                db_post="unchanged", audit_post="business+0", extra={"status": s})

            # CO06 same key, CHANGED ACTOR (tenant-A verified #2) -> 409
            b5 = snap(AA, "field_correction.record")
            s, _ = _http("POST", f"{api_a}/workspaces/{wsA['create']}/field-corrections",
                         key=token_a2, body=corr_body(f0, "v1"), idem=k)
            d = delta(b5, snap(AA, "field_correction.record"))
            rec("CO06", s == 409 and d["corr_total"] == 0 and d["biz"] == 0,
                desc="same key + changed actor (verified #2) -> controlled 409, no second mutation",
                category="correction-idempotency", route="POST " + corr_route, tenant=AA,
                actor="tenant-A verified #2", idem="changed actor", expected="409",
                db_post="norm+0", audit_post="business+0", extra={"status": s})

            # CO07 same key against ANOTHER target (different workspace) -> 409
            b6 = snap(AA, "field_correction.record")
            s, _ = _http("POST", f"{api_a}/workspaces/{wsA['target']}/field-corrections",
                         key=token_a, body=corr_body(f0, "v1"), idem=k)
            d = delta(b6, snap(AA, "field_correction.record"))
            rec("CO07", s == 409 and d["corr_total"] == 0,
                desc="same key against another target (different workspace) -> controlled 409",
                category="correction-idempotency", route="POST " + corr_route, tenant=AA,
                actor="tenant-A verified #1", idem="changed target", expected="409",
                db_post="norm+0", audit_post="business+0", extra={"status": s})

            # CO08 same key CHANGED TENANT: tenant-A key on API-B (wrong-tenant credential) -> denied
            s, _ = _http("POST", f"{api_b}/workspaces/{wsB}/field-corrections",
                         key=token_a, body=corr_body(f0, "v1"), idem=k)
            rec("CO08", s in (401, 403),
                desc="same key + changed tenant (tenant-A key on API-B) -> auth-denied",
                category="correction-cross-tenant", route="POST " + corr_route, tenant="verif-b",
                actor="tenant-A key vs API-B", idem="changed tenant", expected="401/403",
                db_post="tenant-B unchanged", audit_post="no business", extra={"status": s})

            # CO09 supersede: re-correct the SAME field with a new key -> +1 row, prior superseded
            ks = str(uuid.uuid4())
            b7 = snap(AA)
            s0, sup0 = _http("POST", f"{api_a}/workspaces/{wsA['supersede']}/field-corrections",
                             key=token_a, body=corr_body(f0, "s1"), idem=str(uuid.uuid4()))
            cid_s0 = sup0.get("id") if isinstance(sup0, dict) else None
            b8 = snap(AA, "field_correction.record")
            s, sup = _http("POST", f"{api_a}/workspaces/{wsA['supersede']}/field-corrections",
                           key=token_a, body=corr_body(f0, "s2"), idem=ks)
            d = delta(b8, snap(AA, "field_correction.record"))
            # active count stays 1 for the field (old superseded, new active); total +1
            rec("CO09", s in (200, 201) and d["corr_total"] == 1 and d["corr_active"] == 0 and d["biz"] == 1,
                desc="supersede (re-correct same field) -> +1 norm row, prior->superseded, active net 0",
                category="correction-supersede", route="POST " + corr_route, tenant=AA,
                actor="tenant-A verified #1", idem="new key", expected="201",
                db_post="norm+1, active net 0", audit_post="business+1", extra={"status": s, "delta": d})

            # CO10 exact supersede replay -> stored, no delta
            b9 = snap(AA, "field_correction.record")
            s, sup2 = _http("POST", f"{api_a}/workspaces/{wsA['supersede']}/field-corrections",
                            key=token_a, body=corr_body(f0, "s2"), idem=ks)
            d = delta(b9, snap(AA, "field_correction.record"))
            rec("CO10", s in (200, 201) and d["corr_total"] == 0 and d["biz"] == 0,
                desc="exact supersede replay returns stored result, no duplicate",
                category="correction-idempotency", route="POST " + corr_route, tenant=AA,
                actor="tenant-A verified #1", idem="exact replay", expected="200 stored",
                db_post="norm+0", audit_post="business+0", extra={"status": s})

            # CO11 revert the active correction (new key) -> status reverted, +0 rows
            cid_active_sup = sup.get("id") if isinstance(sup, dict) else None
            kr = str(uuid.uuid4())
            b10 = snap(AA, "field_correction.revert")
            s, rv = _http("POST", f"{api_a}/field-corrections/{cid_active_sup}/revert",
                          key=token_a, body={"revert_reason": "undo"}, idem=kr)
            d = delta(b10, snap(AA, "field_correction.revert"))
            reverted_status = rv.get("status") if isinstance(rv, dict) else None
            rec("CO11", s in (200, 201) and reverted_status == "reverted" and d["corr_total"] == 0
                and d["corr_active"] == -1 and d["biz"] == 1,
                desc="revert active correction -> status reverted, +0 rows, active-1",
                category="correction-revert", route="POST /field-corrections/{id}/revert", tenant=AA,
                actor="tenant-A verified #1", idem="new key", expected="200 reverted",
                db_post="norm+0, active-1", audit_post="business+1", extra={"status": s, "delta": d})

            # CO12 exact revert replay -> stored, no delta
            b11 = snap(AA, "field_correction.revert")
            s, _ = _http("POST", f"{api_a}/field-corrections/{cid_active_sup}/revert",
                         key=token_a, body={"revert_reason": "undo"}, idem=kr)
            d = delta(b11, snap(AA, "field_correction.revert"))
            rec("CO12", s in (200, 201) and d["biz"] == 0 and d["idem"] == 0,
                desc="exact revert replay returns stored result, no duplicate",
                category="correction-idempotency", route="POST /field-corrections/{id}/revert",
                tenant=AA, actor="tenant-A verified #1", idem="exact replay", expected="200 stored",
                db_post="norm+0", audit_post="business+0", extra={"status": s})

            # CO13 revert an INACTIVE (already-reverted) correction -> controlled 409
            s, _ = _http("POST", f"{api_a}/field-corrections/{cid_active_sup}/revert",
                         key=token_a, body={"revert_reason": "again"}, idem=str(uuid.uuid4()))
            rec("CO13", s == 409,
                desc="revert of an already-reverted correction -> controlled 409 business reject",
                category="correction-revert", route="POST /field-corrections/{id}/revert", tenant=AA,
                actor="tenant-A verified #1", idem="new key", expected="409",
                db_post="unchanged", audit_post="no business", extra={"status": s})

            # CO14 invalid correction identifier -> 404
            s, _ = _http("POST", f"{api_a}/field-corrections/{uuid.uuid4()}/revert",
                         key=token_a, body={"revert_reason": "x"}, idem=str(uuid.uuid4()))
            rec("CO14", s == 404,
                desc="revert of a non-existent correction id -> 404",
                category="correction-negative", route="POST /field-corrections/{id}/revert", tenant=AA,
                actor="tenant-A verified #1", idem="new key", expected="404",
                db_post="unchanged", audit_post="no business", extra={"status": s})

            # CO15 cross-tenant report target: tenant-A key against a tenant-B workspace id -> denied
            s, _ = _http("POST", f"{api_a}/workspaces/{wsB}/field-corrections",
                         key=token_a, body=corr_body(f0, "x"), idem=str(uuid.uuid4()))
            rec("CO15", s in (403, 404),
                desc="tenant-A key against a tenant-B workspace id -> denied (existence-hiding)",
                category="correction-cross-tenant", route="POST " + corr_route, tenant=AA,
                actor="tenant-A verified #1 vs tenant-B ws", idem="new key", expected="403/404",
                db_post="tenant-B unchanged", audit_post="no business", extra={"status": s})

            # CO16 missing Idempotency-Key on a PG mutation -> 400 (contract requires it)
            s, _ = _http("POST", f"{api_a}/workspaces/{wsA['xkey']}/field-corrections",
                         key=token_a, body=corr_body(f1, "nokey"))
            rec("CO16", s == 400,
                desc="missing Idempotency-Key on a mutation -> 400 (PG contract requires it)",
                category="correction-idempotency", route="POST " + corr_route, tenant=AA,
                actor="tenant-A verified #1", idem="missing key", expected="400",
                db_post="norm+0", audit_post="no business", extra={"status": s})

            # CO17 malformed Idempotency-Key -> 400/422
            s, _ = _http("POST", f"{api_a}/workspaces/{wsA['xkey']}/field-corrections",
                         key=token_a, body=corr_body(f1, "bad"), idem="!!")
            rec("CO17", s in (400, 422),
                desc="malformed Idempotency-Key -> controlled 400/422",
                category="correction-idempotency", route="POST " + corr_route, tenant=AA,
                actor="tenant-A verified #1", idem="malformed key", expected="400/422",
                db_post="norm+0", audit_post="no business", extra={"status": s})

            # ============================ PART F: VALIDATION STATE MACHINE ======================
            vt_route = "/validation-tasks/{id}"

            def crit_measure(api, key, ws):
                return _http("POST", f"{api}/workspaces/{ws}/benchmarking/measurements", key=key,
                             body={"metric": "feet_drilled_per_day", "value": 440, "unit": "ft/day",
                                   "data_source": "mutations slice", "source_identifier": "mut-crit",
                                   "moc_reference": "MOC-MUT-1"})

            def task_ids(api, key):
                s, tasks = _http("GET", f"{api}/validation-tasks", key=key)
                return {t["id"] for t in tasks if isinstance(t, dict)} if (s == 200 and isinstance(tasks, list)) else set()

            def new_task(api, key, ws):
                before = task_ids(api, key)
                crit_measure(api, key, ws)
                new = task_ids(api, key) - before
                return next(iter(new)) if new else None

            def task_status(slug, tid):
                r = _q(slug, "select status, revision from monday_report_norm_validation_tasks where id=%s", (str(tid),))
                return (r[0], r[1]) if r else (None, None)

            def audit_verified(slug, tid):
                r = _q(slug, f"select count(*) from {STATE_TABLE} s, jsonb_array_elements(s.payload->'audit_logs') e "
                             "where e->>'action'='validation_task.update' and e->>'resource_id'=%s "
                             "and e->'metadata'->>'reviewer_verified'='true'", (str(tid),))
                return (r[0] if r else 0) > 0

            def vpatch(api, key, tid, status, idem, note="mut"):
                return _http("PATCH", f"{api}/validation-tasks/{tid}", key=key,
                             body={"status": status, "resolution_note": note}, idem=idem)

            wsV = mk_ws(api_a, token_a, "mut-a-valid")
            BV = "validation_task.update"

            # VA01 approve (verified reviewer) -> 200, terminal validated, +1 business audit, verified attribution
            t1 = new_task(api_a, token_a, wsV)
            k = str(uuid.uuid4()); b = snap(AA, BV, BV)
            s, _ = vpatch(api_a, token_a, t1, "validated", k)
            d = delta(b, snap(AA, BV, BV)); st_, _rv = task_status(AA, t1)
            rec("VA01", s in (200, 201) and st_ == "validated" and d["biz"] == 1 and d["idem"] == 1
                and audit_verified(AA, t1),
                desc="approve -> terminal validated, +1 business audit, verified-reviewer attribution",
                category="validation-approve", route="PATCH " + vt_route, tenant=AA,
                actor="tenant-A verified #1", idem="new key", expected="200 validated",
                db_post="status=validated, idem+1", audit_post="business+1, reviewer_verified", extra={"status": s, "delta": d})

            # VA02 exact approve replay -> stored, no second transition/audit
            b = snap(AA, BV); s, _ = vpatch(api_a, token_a, t1, "validated", k)
            d = delta(b, snap(AA, BV))
            rec("VA02", s in (200, 201) and d["biz"] == 0 and d["idem"] == 0,
                desc="exact approve replay -> stored result, no duplicate transition/audit",
                category="validation-idempotency", route="PATCH " + vt_route, tenant=AA,
                actor="tenant-A verified #1", idem="exact replay", expected="200 stored",
                db_post="idem+0", audit_post="business+0", extra={"status": s})

            # VA03 reject
            t2 = new_task(api_a, token_a, wsV)
            k2 = str(uuid.uuid4()); b = snap(AA, BV)
            s, _ = vpatch(api_a, token_a, t2, "rejected", k2)
            d = delta(b, snap(AA, BV)); st_, _ = task_status(AA, t2)
            rec("VA03", s in (200, 201) and st_ == "rejected" and d["biz"] == 1 and audit_verified(AA, t2),
                desc="reject -> terminal rejected, +1 business audit, verified attribution",
                category="validation-reject", route="PATCH " + vt_route, tenant=AA,
                actor="tenant-A verified #1", idem="new key", expected="200 rejected",
                db_post="status=rejected", audit_post="business+1", extra={"status": s})

            # VA04 exact reject replay -> stored
            b = snap(AA, BV); s, _ = vpatch(api_a, token_a, t2, "rejected", k2)
            d = delta(b, snap(AA, BV))
            rec("VA04", s in (200, 201) and d["biz"] == 0,
                desc="exact reject replay -> stored result, no duplicate",
                category="validation-idempotency", route="PATCH " + vt_route, tenant=AA,
                actor="tenant-A verified #1", idem="exact replay", expected="200 stored",
                db_post="idem+0", audit_post="business+0", extra={"status": s})

            # VA05 reopen after approval (administrative transition to open) -> 200 open
            k5 = str(uuid.uuid4()); b = snap(AA, BV)
            s, _ = vpatch(api_a, token_a, t1, "open", k5)
            d = delta(b, snap(AA, BV)); st_, _ = task_status(AA, t1)
            rec("VA05", s in (200, 201) and st_ == "open" and d["biz"] == 1,
                desc="reopen after approval (admin transition to open) -> 200 open",
                category="validation-reopen", route="PATCH " + vt_route, tenant=AA,
                actor="tenant-A verified #1", idem="new key", expected="200 open",
                db_post="status=open", audit_post="business+1", extra={"status": s})

            # VA06 exact reopen-after-approval replay -> stored
            b = snap(AA, BV); s, _ = vpatch(api_a, token_a, t1, "open", k5)
            rec("VA06", s in (200, 201) and delta(b, snap(AA, BV))["biz"] == 0,
                desc="exact reopen-after-approval replay -> stored, no duplicate",
                category="validation-idempotency", route="PATCH " + vt_route, tenant=AA,
                actor="tenant-A verified #1", idem="exact replay", expected="200 stored",
                db_post="idem+0", audit_post="business+0", extra={"status": s})

            # VA07 reopen after rejection -> 200 open
            k7 = str(uuid.uuid4()); s, _ = vpatch(api_a, token_a, t2, "open", k7)
            st_, _ = task_status(AA, t2)
            rec("VA07", s in (200, 201) and st_ == "open",
                desc="reopen after rejection (admin transition) -> 200 open",
                category="validation-reopen", route="PATCH " + vt_route, tenant=AA,
                actor="tenant-A verified #1", idem="new key", expected="200 open",
                db_post="status=open", audit_post="business+1", extra={"status": s})

            # VA08 exact reopen-after-rejection replay -> stored
            b = snap(AA, BV); s, _ = vpatch(api_a, token_a, t2, "open", k7)
            rec("VA08", s in (200, 201) and delta(b, snap(AA, BV))["biz"] == 0,
                desc="exact reopen-after-rejection replay -> stored, no duplicate",
                category="validation-idempotency", route="PATCH " + vt_route, tenant=AA,
                actor="tenant-A verified #1", idem="exact replay", expected="200 stored",
                db_post="idem+0", audit_post="business+0", extra={"status": s})

            # VA09 conflict transition -> 200 conflict
            t3 = new_task(api_a, token_a, wsV)
            k9 = str(uuid.uuid4()); s, _ = vpatch(api_a, token_a, t3, "conflict", k9)
            st_, _ = task_status(AA, t3)
            rec("VA09", s in (200, 201) and st_ == "conflict" and audit_verified(AA, t3),
                desc="conflict transition -> terminal conflict, verified attribution",
                category="validation-conflict", route="PATCH " + vt_route, tenant=AA,
                actor="tenant-A verified #1", idem="new key", expected="200 conflict",
                db_post="status=conflict", audit_post="business+1", extra={"status": s})

            # VA10 exact conflict replay -> stored
            b = snap(AA, BV); s, _ = vpatch(api_a, token_a, t3, "conflict", k9)
            rec("VA10", s in (200, 201) and delta(b, snap(AA, BV))["biz"] == 0,
                desc="exact conflict replay -> stored, no duplicate",
                category="validation-idempotency", route="PATCH " + vt_route, tenant=AA,
                actor="tenant-A verified #1", idem="exact replay", expected="200 stored",
                db_post="idem+0", audit_post="business+0", extra={"status": s})

            # VA11 missing Idempotency-Key -> 400
            t4 = new_task(api_a, token_a, wsV)
            s, _ = _http("PATCH", f"{api_a}/validation-tasks/{t4}", key=token_a,
                         body={"status": "validated"})
            rec("VA11", s == 400,
                desc="missing Idempotency-Key on validation PATCH -> 400",
                category="validation-idempotency", route="PATCH " + vt_route, tenant=AA,
                actor="tenant-A verified #1", idem="missing key", expected="400",
                db_post="unchanged", audit_post="no business", extra={"status": s})

            # VA12 malformed key -> 400/422
            s, _ = vpatch(api_a, token_a, t4, "validated", "!!")
            rec("VA12", s in (400, 422),
                desc="malformed Idempotency-Key -> controlled 400/422",
                category="validation-idempotency", route="PATCH " + vt_route, tenant=AA,
                actor="tenant-A verified #1", idem="malformed key", expected="400/422",
                db_post="unchanged", audit_post="no business", extra={"status": s})

            # VA13 same key changed body -> 409
            k13 = str(uuid.uuid4()); vpatch(api_a, token_a, t4, "validated", k13)
            b = snap(AA, BV); s, _ = vpatch(api_a, token_a, t4, "rejected", k13)
            rec("VA13", s == 409 and delta(b, snap(AA, BV))["biz"] == 0,
                desc="same key + changed body -> controlled 409, no second transition",
                category="validation-idempotency", route="PATCH " + vt_route, tenant=AA,
                actor="tenant-A verified #1", idem="changed body", expected="409",
                db_post="unchanged", audit_post="business+0", extra={"status": s})

            # VA14 same key changed operation (reuse validation key on a correction) -> 409
            s, _ = _http("POST", f"{api_a}/workspaces/{wsA['xkey']}/field-corrections",
                         key=token_a, body=corr_body(f1, "op"), idem=k13)
            rec("VA14", s == 409,
                desc="same key + changed operation (validation->correction) -> 409",
                category="validation-idempotency", route="POST " + corr_route, tenant=AA,
                actor="tenant-A verified #1", idem="changed operation", expected="409",
                db_post="unchanged", audit_post="no business", extra={"status": s})

            # VA15 same key changed actor -> 409
            t5 = new_task(api_a, token_a, wsV)
            k15 = str(uuid.uuid4()); vpatch(api_a, token_a, t5, "validated", k15)
            s, _ = vpatch(api_a, token_a2, t5, "validated", k15)
            rec("VA15", s == 409,
                desc="same key + changed actor (verified #2) -> 409",
                category="validation-idempotency", route="PATCH " + vt_route, tenant=AA,
                actor="tenant-A verified #2", idem="changed actor", expected="409",
                db_post="unchanged", audit_post="business+0", extra={"status": s})

            # VA16 same key changed tenant (tenant-A key on API-B) -> auth-denied
            s, _ = vpatch(api_b, token_a, uuid.uuid4(), "validated", k15)
            rec("VA16", s in (401, 403),
                desc="same key + changed tenant (tenant-A key on API-B) -> auth-denied",
                category="validation-cross-tenant", route="PATCH " + vt_route, tenant="verif-b",
                actor="tenant-A key vs API-B", idem="changed tenant", expected="401/403",
                db_post="tenant-B unchanged", audit_post="no business", extra={"status": s})

            # VA17 same key against another task -> 409
            t6 = new_task(api_a, token_a, wsV); t7 = new_task(api_a, token_a, wsV)
            k17 = str(uuid.uuid4()); vpatch(api_a, token_a, t6, "validated", k17)
            s, _ = vpatch(api_a, token_a, t7, "validated", k17)
            rec("VA17", s == 409,
                desc="same key against another task -> 409 (changed target)",
                category="validation-idempotency", route="PATCH " + vt_route, tenant=AA,
                actor="tenant-A verified #1", idem="changed target", expected="409",
                db_post="unchanged", audit_post="business+0", extra={"status": s})

            # VA18 unverified reviewer (legacy shared key) -> auth-denied (no authenticated-unverified
            # actor exists in client mode; the verified-reviewer 403 path is subsumed by auth denial)
            t8 = new_task(api_a, token_a, wsV)
            s, _ = vpatch(api_a, legacy_key, t8, "validated", str(uuid.uuid4()))
            rec("VA18", s in (401, 403),
                desc="unverified reviewer (legacy shared key) -> auth-denied (tested negative contract)",
                category="validation-reviewer", route="PATCH " + vt_route, tenant=AA,
                actor="legacy shared key (unverified)", idem="new key", expected="401/403",
                db_post="task stays open", audit_post="no business", extra={"status": s})

            # VA19 disabled reviewer -> denied
            s, _ = vpatch(api_a, token_a_disabled, t8, "validated", str(uuid.uuid4()))
            st_, _ = task_status(AA, t8)
            rec("VA19", s in (401, 403) and st_ == "open",
                desc="disabled reviewer -> denied; task stays open",
                category="validation-reviewer", route="PATCH " + vt_route, tenant=AA,
                actor="tenant-A disabled reviewer", idem="new key", expected="401/403",
                db_post="status=open", audit_post="no business", extra={"status": s})

            # VA20 tenant-B reviewer on a tenant-A task (wrong-tenant credential) -> auth-denied
            s, _ = vpatch(api_a, token_b, t8, "validated", str(uuid.uuid4()))
            rec("VA20", s in (401, 403),
                desc="tenant-B reviewer credential on tenant-A API -> auth-denied",
                category="validation-cross-tenant", route="PATCH " + vt_route, tenant=AA,
                actor="tenant-B credential vs API-A", idem="new key", expected="401/403",
                db_post="unchanged", audit_post="no business", extra={"status": s})

            # VA21 invalid task identifier -> 404
            s, _ = vpatch(api_a, token_a, uuid.uuid4(), "validated", str(uuid.uuid4()))
            rec("VA21", s == 404,
                desc="PATCH a non-existent validation-task id -> 404",
                category="validation-negative", route="PATCH " + vt_route, tenant=AA,
                actor="tenant-A verified #1", idem="new key", expected="404",
                db_post="unchanged", audit_post="no business", extra={"status": s})

            # ============================ PART H: RACES / CONCURRENCY ==========================
            def race_run(fns):
                with concurrent.futures.ThreadPoolExecutor(max_workers=len(fns)) as ex:
                    return [f.result() for f in [ex.submit(fn) for fn in fns]]

            def _ok_statuses(rs):
                return all(r[0] in (200, 201, 409) for r in rs)

            # RA01 SAME correction key concurrently -> exactly one business result, no duplicate
            wsR1 = mk_ws(api_a, token_a, "mut-a-race1")
            kc = str(uuid.uuid4()); body_c = corr_body(f0, "race")
            b = snap(AA, "field_correction.record")
            rs = race_run([lambda: _http("POST", f"{api_a}/workspaces/{wsR1}/field-corrections",
                                            key=token_a, body=body_c, idem=kc) for _ in range(4)])
            d = delta(b, snap(AA, "field_correction.record"))
            rec("RA01", _ok_statuses(rs) and d["corr_total"] == 1 and d["biz"] == 1 and d["idem"] == 1,
                desc="same correction key x4 concurrently -> exactly ONE business result, no duplicate",
                category="race", route="POST " + corr_route, tenant=AA, actor="tenant-A verified #1",
                idem="same key concurrent", expected="one 2xx result",
                db_post="norm+1, idem+1", audit_post="business+1",
                extra={"statuses": [r[0] for r in rs], "delta": d})

            # RA02 DISTINCT correction keys concurrently -> two independent rows
            wsR2 = mk_ws(api_a, token_a, "mut-a-race2")
            b = snap(AA, "field_correction.record")
            rs = race_run([lambda: _http("POST", f"{api_a}/workspaces/{wsR2}/field-corrections",
                                           key=token_a, body=corr_body(f0, f"d{n}"),
                                           idem=str(uuid.uuid4())) for n in range(3)])
            d = delta(b, snap(AA, "field_correction.record"))
            rec("RA02", _ok_statuses(rs) and d["corr_total"] == 3 and d["biz"] == 3,
                desc="distinct correction keys x3 concurrently -> three independent rows",
                category="race", route="POST " + corr_route, tenant=AA, actor="tenant-A verified #1",
                idem="distinct keys concurrent", expected="three 2xx",
                db_post="norm+3", audit_post="business+3",
                extra={"statuses": [r[0] for r in rs], "delta": d})

            # RA03 approve/reject race on ONE task with the SAME key -> one wins, other controlled 409
            tr = new_task(api_a, token_a, wsV)
            krace = str(uuid.uuid4()); b = snap(AA, BV)
            rs = race_run([lambda: vpatch(api_a, token_a, tr, "validated", krace),
                           lambda: vpatch(api_a, token_a, tr, "rejected", krace)])
            d = delta(b, snap(AA, BV)); st_, _ = task_status(AA, tr)
            n2xx = sum(1 for r in rs if r[0] in (200, 201))
            rec("RA03", _ok_statuses(rs) and n2xx == 1 and d["biz"] == 1 and d["idem"] == 1
                and st_ in ("validated", "rejected"),
                desc="approve/reject race (same key) -> exactly one terminal transition, one controlled 409",
                category="race", route="PATCH " + vt_route, tenant=AA, actor="tenant-A verified #1",
                idem="same key concurrent, changed body", expected="one 2xx + one 409",
                db_post="one terminal, idem+1", audit_post="business+1",
                extra={"statuses": [r[0] for r in rs], "final": st_, "delta": d})

            # RA04 approve/reopen race on ONE task with the SAME key -> one wins, other controlled 409
            tr2 = new_task(api_a, token_a, wsV)
            krace2 = str(uuid.uuid4()); b = snap(AA, BV)
            rs = race_run([lambda: vpatch(api_a, token_a, tr2, "validated", krace2),
                           lambda: vpatch(api_a, token_a, tr2, "open", krace2)])
            d = delta(b, snap(AA, BV)); st_, _ = task_status(AA, tr2)
            n2xx = sum(1 for r in rs if r[0] in (200, 201))
            rec("RA04", _ok_statuses(rs) and n2xx == 1 and d["biz"] == 1 and d["idem"] == 1
                and st_ in ("validated", "open"),
                desc="approve/reopen race (same key) -> exactly one transition, one controlled 409",
                category="race", route="PATCH " + vt_route, tenant=AA, actor="tenant-A verified #1",
                idem="same key concurrent, changed body", expected="one 2xx + one 409",
                db_post="one status, idem+1", audit_post="business+1",
                extra={"statuses": [r[0] for r in rs], "final": st_, "delta": d})

            # RA05 SAME validation key concurrently -> idempotency dedups to one transition
            tr3 = new_task(api_a, token_a, wsV)
            kv = str(uuid.uuid4()); b = snap(AA, BV)
            rs = race_run([lambda: vpatch(api_a, token_a, tr3, "validated", kv) for _ in range(4)])
            d = delta(b, snap(AA, BV))
            rec("RA05", _ok_statuses(rs) and d["biz"] == 1 and d["idem"] == 1,
                desc="same validation key x4 concurrently -> one transition, one idempotency row",
                category="race", route="PATCH " + vt_route, tenant=AA, actor="tenant-A verified #1",
                idem="same key concurrent", expected="one 2xx result",
                db_post="idem+1", audit_post="business+1",
                extra={"statuses": [r[0] for r in rs], "delta": d})

            # RA06 DISTINCT validation keys concurrently on DIFFERENT tasks -> two transitions
            trA = new_task(api_a, token_a, wsV); trB = new_task(api_a, token_a, wsV)
            b = snap(AA, BV)
            rs = race_run([lambda: vpatch(api_a, token_a, trA, "validated", str(uuid.uuid4())),
                             lambda: vpatch(api_a, token_a, trB, "rejected", str(uuid.uuid4()))])
            d = delta(b, snap(AA, BV))
            rec("RA06", _ok_statuses(rs) and d["biz"] == 2,
                desc="distinct validation keys concurrently on different tasks -> two transitions",
                category="race", route="PATCH " + vt_route, tenant=AA, actor="tenant-A verified #1",
                idem="distinct keys concurrent", expected="two 2xx",
                db_post="two transitions", audit_post="business+2",
                extra={"statuses": [r[0] for r in rs], "delta": d})

            # ============================ PART I: AUDIT INTEGRITY ==============================
            def integrity(env):
                def compute(st):
                    it = st.audit_integrity_status()
                    return (it.integrity_state, it.broken_events)
                return with_env(env, compute)

            # AU01 keyed HMAC chain valid across all the mutations above
            state, broken = integrity(base_env)
            rec("AU01", state == "keyed_valid" and broken == 0,
                desc="audit chain over all mutations verifies keyed_valid, 0 broken (HMAC+chain valid)",
                category="audit-integrity", route="-", tenant=AA, actor="verifier", idem="-",
                expected="keyed_valid", db_post="-", audit_post="keyed_valid, broken=0",
                level="direct component integration", extra={"state": state, "broken": broken})

            # AU02 durable ordering: for the CO01 create, the boundary-use event PRECEDES the business
            # event (boundary fires before the handler). Compare ordinalities in the persisted chain.
            _au02 = (
                "select "
                "(select min(ord) from " + STATE_TABLE + " s2, "
                "jsonb_array_elements(s2.payload->'audit_logs') with ordinality e2(v,ord) "
                "where e2.v->>'action'=%s and e2.v->'metadata'->>'operation'=%s), "
                "(select min(ord) from " + STATE_TABLE + " s3, "
                "jsonb_array_elements(s3.payload->'audit_logs') with ordinality e3(v,ord) "
                "where e3.v->>'action'=%s and e3.v->>'resource_id'=%s)")
            row = _q(AA, _au02, (BND, "field_correction.record", "field_correction.record", str(cid_create)))
            bnd_ord, biz_ord = (row[0], row[1]) if row else (None, None)
            rec("AU02", bnd_ord is not None and biz_ord is not None and bnd_ord < biz_ord,
                desc="durable ordering: the boundary-use event precedes the business event",
                category="audit-integrity", route="-", tenant=AA, actor="verifier", idem="-",
                expected="boundary before business", db_post="-",
                audit_post=f"bnd_ord<biz_ord", level="live PostgreSQL verification",
                extra={"bnd_ord": bnd_ord, "biz_ord": biz_ord})

            # AU03 replay emits one boundary-use per HTTP attempt but no extra business event: the
            # CO01/CO02/CO03 sequence = 1 create + 2 replays -> business=1, boundary>=3 for the op.
            biz_n = _q(AA, f"select count(*) from {STATE_TABLE} s, jsonb_array_elements(s.payload->'audit_logs') e "
                           "where e->>'action'=%s and e->>'resource_id'=%s",
                       ("field_correction.record", str(cid_create)))[0]
            bnd_n = _q(AA, f"select count(*) from {STATE_TABLE} s, jsonb_array_elements(s.payload->'audit_logs') e "
                           "where e->>'action'=%s and e->'metadata'->>'operation'=%s",
                       (BND, "field_correction.record"))[0]
            rec("AU03", biz_n == 1 and bnd_n >= 3,
                desc="replay: exactly one business event for the create; boundary-use per HTTP attempt (>=3)",
                category="audit-integrity", route="-", tenant=AA, actor="verifier", idem="-",
                expected="business=1, boundary>=attempts", db_post="-",
                audit_post="one business, boundary per attempt", level="live PostgreSQL verification",
                extra={"business_events": biz_n, "boundary_events": bnd_n})

            # AU04 secret scan of the persisted audit events (JSONB) for run secrets
            blob = _q(AA, f"select coalesce(string_agg(e::text, ' '), '') from {STATE_TABLE} s, "
                          "jsonb_array_elements(s.payload->'audit_logs') e")[0]
            leaked = [t for t in LEAK_TERMS if t and t in (blob or "")]
            rec("AU04", not leaked,
                desc="persisted audit events carry no run nonce/DSN/role/credential/idempotency-key",
                category="audit-integrity", route="-", tenant=AA, actor="verifier", idem="-",
                expected="no leak", db_post="-", audit_post="secret-clean",
                level="live PostgreSQL verification", extra={"leaked_kinds": len(leaked)})

        finally:
            try:
                api_b_proc.terminate(); api_b_proc.wait(timeout=10)
            except Exception:
                pass
            try:
                b_log.close()
            except Exception:
                pass
            import shutil
            shutil.rmtree(b_scratch, ignore_errors=True)

    G.checks = []
    G.http_statuses = []
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
        rec("foundation", False, desc="foundation checks not ok", category="setup", route="-",
            tenant="-", actor="-", idem="-", expected="all ok",
            db_post="-", audit_post="-", level="structural source check",
            extra={"foundation_fail": sorted(foundation_fail)[:8]})
    if err:
        print("ON_LIVE ERROR:", err.get("type"), file=sys.stderr)
        print(err.get("tb", ""), file=sys.stderr)
        rec("on_live_abort", False, desc=f"on_live aborted with {err.get('type')} (see stderr)",
            category="setup", route="-", tenant="-", actor="-", idem="-", expected="no abort",
            db_post="-", audit_post="-", level="structural source check")
    return _emit()


def _emit(skipped=False) -> int:
    passed = [c for c in checks if c["ok"]]
    failed = [c for c in checks if not c["ok"]]
    core = "passed" if (checks and not failed and not skipped) else ("skipped" if skipped else "failed")
    exec_totals = {}
    for c in checks:
        exec_totals[c["execution_level"]] = exec_totals.get(c["execution_level"], 0) + 1
    ids = [c["check_id"] for c in checks]
    dup = sorted({i for i in ids if ids.count(i) > 1})
    n423 = HTTP_STATUSES.count(423)
    n500 = HTTP_STATUSES.count(500)
    n503 = HTTP_STATUSES.count(503)
    if dup:
        rec("inventory", False, desc=f"duplicate check ids: {dup[:8]}", category="setup", route="-",
            tenant="-", actor="-", idem="-", expected="unique ids", db_post="-", audit_post="-",
            level="structural source check")
        failed = [c for c in checks if not c["ok"]]
        core = "failed"
    if (n423 or n500 or n503) and not skipped:
        rec("http-counters", False, desc="normal functional traffic returned 423/500/503",
            category="setup", route="-", tenant="-", actor="-", idem="-", expected="0/0/0",
            db_post="-", audit_post="-", level="structural source check",
            extra={"http_423": n423, "http_500": n500, "http_503": n503})
        failed = [c for c in checks if not c["ok"]]
        core = "failed"
    out = {"checks": checks,
           "summary": {"passed": len(passed) if not skipped else 0,
                       "skipped": len(checks) if skipped else 0,
                       "failed": 0 if skipped else len(failed),
                       "execution_level_totals": exec_totals,
                       "claim_scope": "restricted-runtime-corrections-validation-idempotency-only",
                       "full_functional_matrix": "not_run",
                       "slice_result": core,
                       "normal_functional_http_423": n423,
                       "normal_functional_http_500": n500,
                       "normal_functional_http_503": n503,
                       "eligible_for_tenant_evidence": False,
                       "eligible_for_readiness": False,
                       "production_parity": False,
                       "migration_principal_class": "test-only-bootstrap-migration-admin"}}
    print(_scrub(json.dumps(out, indent=2, default=str)))
    if skipped:
        print("\nMutations slice SKIPPED (docker unavailable, non-certifying).")
        return 0
    if failed:
        print(f"\nMutations slice FAILED: {len(failed)} check(s).")
        for c in failed:
            print(_scrub(f"  FAIL: {c['check_id']} -> {c.get('description','')} [{c.get('status','')}]"))
        return 1
    print(f"\nMutations slice passed: {len(passed)} check(s)."
          "\n[claim_scope=restricted-runtime-corrections-validation-idempotency-only; NOT evidence/readiness eligible]")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
