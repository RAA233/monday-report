"""Restricted-PostgreSQL functional slice: cross-tenant HTTP + direct-RLS isolation (Outcome-1 slice 3).

A NARROW slice guard (NOT the complete functional matrix; NOT the accepted core/mutations/exports guards).
Built on the ACCEPTED restricted-PostgreSQL foundation (restricted_postgres_startup_guard.run_stack +
_ON_LIVE, byte-unchanged). It launches TWO synthetic tenants (isoA/isoB) as external client-mode uvicorn
on one runner-owned PostgreSQL (RLS-isolated) with independent persisted users/credentials/reports/
corrections/validation-tasks/exports/signed-references/idempotency-records, and ALSO connects directly as
the restricted runtime LOGIN, to prove:

  * the CROSS-TENANT HTTP matrix -- reports, corrections, validation tasks, idempotency, exports, and
    signed references: every tenant-A attempt on a tenant-B resource is a controlled denial / existence-
    hiding that mutates NOTHING in tenant B (proven by direct committed-SQL postconditions), and every
    body/query/header tenant spoof and actor spoof is ignored (the tenant is derived from the credential);
  * the direct RLS guarantee -- every protected table is RLS-enabled + FORCEd with a tenant_isolation
    policy keyed on app.tenant_slug, the runtime role is a non-superuser / non-BYPASSRLS / non-owner LOGIN,
    reads are tenant-scoped and fail closed on a missing/empty/invalid/unknown GUC, and writes are
    constrained by USING (cross-tenant UPDATE/DELETE affect zero rows) and WITH CHECK (cross-tenant
    INSERT / update-into-another-tenant raise the RLS policy error 42501, distinguished from a plain
    constraint failure);
  * the tenant-context lifecycle -- the app's transaction-local GUC is cleared by commit/rollback/failure
    and never inherited when the same physical connection is reused for another tenant.

The RLS checks import and exercise the ACTUAL application contract (backend.app.tenant_rls:
policy_inventory / measure_runtime_role / apply_verified_tenant_scope / PROTECTED_TABLES /
GUC_TRUST_MODEL), never a copy. All isolation postconditions are direct committed SQL (never a TestClient
or a create_store projection). Raw idempotency keys and signed tokens are never printed.

HONEST SCOPE. It emits:
  claim_scope = restricted-runtime-cross-tenant-http-rls-only
  full_functional_matrix = not_run
  eligible_for_tenant_evidence = false / eligible_for_readiness = false / production_parity = false
  migration_principal_class = test-only-bootstrap-migration-admin
It must NEVER be consumed as tenant-authorization or readiness evidence. Requires Docker.

Trust model (emitted verbatim, never overstated): a holder of valid runtime database credentials CAN set
app.tenant_slug; RLS protects trusted application-set context and forgotten predicates; it is NOT a
defense against arbitrary hostile SQL using compromised runtime credentials.

DEFERRED to later slices: expanded worker tenant-switch isolation, complete import isolation, tenant
evidence v3, readiness evaluator/context changes, UI certification, and the complete-runtime aggregation.
"""
from __future__ import annotations

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

STATE_TABLE = "monday_report_state_snapshots"
SIGNING_ENV = "MONDAY_REPORT_SIGNING_SECRET"
PURPOSE = "report_export_download"
# The exact Part-Q trust-model disclosure (must not be strengthened).
TRUST_DISCLOSURE = (
    "A holder of valid runtime database credentials can set app.tenant_slug. "
    "RLS protects trusted application-set context and forgotten predicates. "
    "It is not a defense against arbitrary hostile SQL using compromised runtime credentials."
)
checks: list[dict] = []
LEAK_TERMS: list[str] = []
HTTP_STATUSES: list[int] = []


def _scrub(text: str) -> str:
    for term in LEAK_TERMS:
        if term:
            text = text.replace(term, "<redacted>")
    return text


def _fp(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:32]  # >=128-bit, non-reversible


def rec(cid, ok, *, desc, category, op, tenant, actor, resource, expected, db_post, audit_post,
        level="whole-stack HTTP mutation", extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "category": category, "operation": op, "tenant": tenant,
                   "actor": actor, "resource": resource, "expected": expected, "db_postcondition": db_post,
                   "audit_postcondition": audit_post, "execution_level": level, **(extra or {})})


def _http(method, url, key=None, body=None, raw=None, ctype=None, extra_headers=None):
    headers = {}
    if key:
        headers["X-Monday-Report-Key"] = key
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


def _dl(url):
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            HTTP_STATUSES.append(r.status)
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        HTTP_STATUSES.append(e.code)
        try:
            return e.code, e.read()
        except Exception:
            return e.code, b""
    except Exception as e:  # noqa: BLE001
        return None, str(e).encode()


def run() -> int:
    allow_unavailable = "--allow-unavailable" in sys.argv
    if G._docker(["info"]).returncode != 0:
        rec("setup", allow_unavailable, desc="docker availability", category="setup", op="-", tenant="-",
            actor="-", resource="-", expected="docker", db_post="-", audit_post="-",
            level="structural source check")
        return _emit(skipped=allow_unavailable)

    def on_live(ctx):
        import psycopg
        import backend.app.store as store_mod
        from backend.app.schemas import Role as _Role
        from backend.app.signed_urls import create_signed_token
        from backend.app.tenant_rls import (PROTECTED_TABLES, NORMALIZED_TABLES, TENANT_GUC,
                                            GUC_TRUST_MODEL, policy_inventory, measure_runtime_role,
                                            apply_verified_tenant_scope)

        api_verif, token_verif = ctx["api_base"], ctx["token"]
        boot, rt = ctx["boot_dsn"], ctx["rt_dsn"]
        base_env = dict(ctx["base_env"])
        run_id, run_hash = ctx["run_id"], ctx["run_hash"]
        rt_role, mig_role = ctx["rt_role"], ctx["mig_role"]
        signing_secret = "iso3-signing-" + secrets.token_hex(28)
        _tmp_base = str(Path(os.environ.get("TEMP", "/tmp")))
        LEAK_TERMS[:] = sorted({str(t) for t in [run_id, run_hash, rt_role, mig_role, boot, rt,
                                                 ctx["mig_dsn"], ctx["db"], token_verif, signing_secret,
                                                 base_env["MONDAY_REPORT_API_KEY"], str(ROOT), _tmp_base] if t},
                               key=len, reverse=True)

        procs, logs, scratches, used_ports = [], [], [], set()

        def launch_tenant(slug, name, email):
            port = G._free_loopback_port()
            while port in used_ports or port in (ctx["port"], 8000, 5173):
                port = G._free_loopback_port()
            used_ports.add(port)
            appname = f"mr-verif-iso-{slug}-{run_hash}"
            scratch = Path(os.environ.get("TEMP", "/tmp")) / f"mr-iso-{slug}-{run_hash}"
            for sub in ("state", "storage", "exports"):
                (scratch / sub).mkdir(parents=True, exist_ok=True)
            env = dict(base_env)
            env.update({
                "MONDAY_REPORT_DATABASE_URL": f"{rt}?application_name={appname}",
                "MONDAY_REPORT_TENANT_SLUG": slug, "MONDAY_REPORT_TENANT_NAME": name,
                "MONDAY_REPORT_USER_EMAIL": email, "MONDAY_REPORT_USER_FULL_NAME": name,
                "MONDAY_REPORT_STATE_PATH": str(scratch / "state" / "s.json"),
                "MONDAY_REPORT_STORAGE_ROOT": str(scratch / "storage"),
                "MONDAY_REPORT_EXPORT_ROOT": str(scratch / "exports"),
                "MONDAY_REPORT_API_KEY": secrets.token_urlsafe(24),
                "MONDAY_REPORT_API_BASE": f"http://127.0.0.1:{port}",
                SIGNING_ENV: signing_secret,
            })
            sv = {k: os.environ.get(k) for k in env}
            os.environ.update(env)
            try:
                st = store_mod.create_store()
                actors = {}
                u1 = st.create_user(email, name, [_Role.ADMIN]); _, actors["primary"] = st.create_credential(u1.id)
                u2 = st.create_user(f"rev2-{secrets.token_hex(3)}@{slug}.test", name + " 2", [_Role.ADMIN])
                _, actors["second"] = st.create_credential(u2.id)
                ud = st.create_user(f"dis-{secrets.token_hex(3)}@{slug}.test", name + " Disabled", [_Role.ADMIN])
                _, actors["disabled"] = st.create_credential(ud.id); st.set_user_status(ud.id, "disabled")
                tenant_id = st.tenant.id
            finally:
                for k, v in sv.items():
                    (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))
            LEAK_TERMS.extend([env["MONDAY_REPORT_API_KEY"], *actors.values()])
            LEAK_TERMS[:] = sorted({t for t in LEAK_TERMS if t}, key=len, reverse=True)
            log = open(scratch / "api.log", "w")
            proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "backend.app.main:app", "--host",
                                     "127.0.0.1", "--port", str(port)], cwd=str(ROOT),
                                    env=G._child_env(env), stdout=log, stderr=subprocess.STDOUT)
            procs.append(proc); logs.append(log); scratches.append(scratch)
            api = f"http://127.0.0.1:{port}"
            for _ in range(45):
                if _http("GET", f"{api}/health")[0] == 200:
                    break
                if proc.poll() is not None:
                    break
                time.sleep(1)
            return {"api": api, "port": port, "env": env, "scratch": scratch,
                    "legacy_key": env["MONDAY_REPORT_API_KEY"], "tenant_id": tenant_id, "slug": slug,
                    "actors": actors}

        # ---------------- direct restricted-LOGIN SQL surfaces (RLS applies) ----------------
        def scoped(slug, sql, params=()):
            """Run a SELECT under GUC=slug via the REAL app binding; rollback (non-destructive)."""
            c = psycopg.connect(rt); c.autocommit = False
            try:
                with c.cursor() as cur:
                    apply_verified_tenant_scope(cur, slug)
                    cur.execute(sql, params)
                    return cur.fetchone()
            finally:
                c.rollback(); c.close()

        def raw_read(table, guc):
            """count(*) of a protected table under a RAW GUC value (None => unset); rollback."""
            c = psycopg.connect(rt); c.autocommit = False
            try:
                with c.cursor() as cur:
                    if guc is not None:
                        cur.execute("select set_config('app.tenant_slug', %s, true)", (guc,))
                    cur.execute(f"select count(*) from {table}")  # table from PROTECTED_TABLES (trusted)
                    return int(cur.fetchone()[0])
            finally:
                c.rollback(); c.close()

        def rls_write(guc, sql, params=(), use_app_binding=False):
            """Execute a write under GUC; return (ok, rowcount, sqlstate); always rollback."""
            c = psycopg.connect(rt); c.autocommit = False
            try:
                with c.cursor() as cur:
                    if use_app_binding:
                        apply_verified_tenant_scope(cur, guc)
                    elif guc is not None:
                        cur.execute("select set_config('app.tenant_slug', %s, true)", (guc,))
                    try:
                        cur.execute(sql, params)
                        return (True, cur.rowcount, None)
                    except psycopg.Error as e:
                        return (False, -1, getattr(e, "sqlstate", None))
            finally:
                c.rollback(); c.close()

        def scount(slug, table, where="true", params=()):
            row = scoped(slug, f"select count(*) from {table} where {where}", params)
            return int(row[0]) if row else 0

        # per-tenant business/audit/revision surfaces (RLS-scoped, via the app binding; one connection/txn)
        def snap(slug):
            c = psycopg.connect(rt); c.autocommit = False
            try:
                with c.cursor() as cur:
                    apply_verified_tenant_scope(cur, slug)
                    def q(sql, params=()):
                        cur.execute(sql, params); return cur.fetchone()[0]
                    rev = scoped_one(cur, f"select revision from {STATE_TABLE} where tenant_slug=%s", (slug,))
                    return {
                        "rev": int(rev) if rev is not None else -1,
                        "reports": q("select count(*) from monday_report_norm_reports"),
                        "corr": q("select count(*) from monday_report_norm_field_corrections"),
                        "corr_active": q("select count(*) from monday_report_norm_field_corrections where status='active'"),
                        "tasks": q("select count(*) from monday_report_norm_validation_tasks"),
                        "idem": q("select count(*) from monday_report_idempotency_records"),
                        "exports": q(f"select coalesce(jsonb_array_length(payload->'report_exports'),0) "
                                     f"from {STATE_TABLE} where tenant_slug=%s", (slug,)),
                        "biz": q(f"select coalesce(jsonb_array_length(payload->'audit_logs'),0) "
                                 f"from {STATE_TABLE} where tenant_slug=%s", (slug,)),
                    }
            finally:
                c.rollback(); c.close()

        def scoped_one(cur, sql, params=()):
            cur.execute(sql, params); row = cur.fetchone()
            return row[0] if row else None

        def unchanged(before, after, ignore=()):
            return all(before[k] == after[k] for k in before if k not in ignore)

        try:
            A = launch_tenant("iso-a", "Isolation Tenant A", "a@iso.test")
            B = launch_tenant("iso-b", "Isolation Tenant B", "b@iso.test")
            api_a, api_b = A["api"], B["api"]
            a1, a2, adis = A["actors"]["primary"], A["actors"]["second"], A["actors"]["disabled"]
            b1 = B["actors"]["primary"]
            AA, BB = "iso-a", "iso-b"
            if not (_http("GET", f"{api_a}/health")[0] == 200 and _http("GET", f"{api_b}/health")[0] == 200):
                rec("setup-apis", False, desc="both tenant APIs failed to come live", category="setup",
                    op="-", tenant="-", actor="-", resource="-", expected="both live", db_post="-",
                    audit_post="-", level="structural source check")
                return

            # ============================= HTTP building blocks ==============================
            def mk_ws(api, key, name):
                s, w = _http("POST", f"{api}/workspaces", key=key, body={"name": name, "rig_name": "g"})
                return w["id"] if isinstance(w, dict) else None

            def mk_report(api, key, ws):
                s, r = _http("POST", f"{api}/monday-reports", key=key,
                             body={"workspace_id": ws, "period_start": "2026-01-01", "period_end": "2026-01-07"})
                return r["id"] if isinstance(r, dict) and "id" in r else None

            def reg_field(api, key):
                _, reg = _http("GET", f"{api}/field-corrections/registry", key=key)
                return reg[0] if isinstance(reg, list) and reg else None

            def corr_body(f, val):
                return {"target_type": f["target_type"], "field_key": f["field_key"], "source_value": "S",
                        "corrected_value": "123" if f.get("value_type") == "numeric_text" else val,
                        "correction_reason": "iso slice"}

            def mk_correction(api, key, ws, f, val):
                s, b = _http("POST", f"{api}/workspaces/{ws}/field-corrections", key=key,
                             body=corr_body(f, val), extra_headers={"Idempotency-Key": str(uuid.uuid4())})
                return (s, b.get("id") if isinstance(b, dict) else None)

            def task_ids(api, key):
                s, tasks = _http("GET", f"{api}/validation-tasks", key=key)
                return {t["id"] for t in tasks if isinstance(t, dict)} if (s == 200 and isinstance(tasks, list)) else set()

            def crit_task(api, key, ws):
                before = task_ids(api, key)
                _http("POST", f"{api}/workspaces/{ws}/benchmarking/measurements", key=key,
                      body={"metric": "feet_drilled_per_day", "value": 440, "unit": "ft/day",
                            "data_source": "iso", "source_identifier": "iso-crit", "moc_reference": "MOC-ISO"})
                return next(iter(task_ids(api, key) - before), None)

            def resolve_task(api, key, tid):
                return _http("PATCH", f"{api}/validation-tasks/{tid}", key=key,
                             body={"status": "validated", "resolution_note": "iso"},
                             extra_headers={"Idempotency-Key": str(uuid.uuid4())})[0]

            def export(api, key, report, fmt="json", extra_headers=None):
                return _http("POST", f"{api}/monday-reports/{report}/exports/{fmt}", key=key, extra_headers=extra_headers)

            def mint(api, key, export_id):
                return _http("POST", f"{api}/report-exports/{export_id}/signed-url", key=key)

            def sign(res, tenant, ttl=900, purpose=PURPOSE):
                old = os.environ.get(SIGNING_ENV); os.environ[SIGNING_ENV] = signing_secret
                try:
                    tok, _ = create_signed_token(res, purpose, ttl, tenant_id=tenant)
                    LEAK_TERMS.append(tok); LEAK_TERMS[:] = sorted({t for t in LEAK_TERMS if t}, key=len, reverse=True)
                    return tok
                finally:
                    (os.environ.__setitem__(SIGNING_ENV, old) if old is not None else os.environ.pop(SIGNING_ENV, None))

            # ==================== PART G: independent two-tenant state ======================
            def build_state(api, key):
                fa = reg_field(api, key)
                ws = mk_ws(api, key, "iso-ws")
                # a resolved report (benchmark breach -> open task -> resolve -> export)
                topen = crit_task(api, key, ws)
                rpt = mk_report(api, key, ws)
                resolve_task(api, key, topen)
                _, ex = export(api, key, rpt, "json")
                export_id = ex.get("id") if isinstance(ex, dict) else None
                # a separate clean report for cross-tenant export attempts
                ws2 = mk_ws(api, key, "iso-ws2")
                rpt2 = mk_report(api, key, ws2)
                # active + superseded correction on ws2
                _, c1 = mk_correction(api, key, ws2, fa, "v1")
                _, c2 = mk_correction(api, key, ws2, fa, "v2")   # supersedes c1
                # reverted correction on a third ws
                ws3 = mk_ws(api, key, "iso-ws3")
                _, c3 = mk_correction(api, key, ws3, fa, "r1")
                _http("POST", f"{api}/field-corrections/{c3}/revert", key=key,
                      body={"revert_reason": "iso"}, extra_headers={"Idempotency-Key": str(uuid.uuid4())})
                # a fresh open task (unresolved) on ws2
                topen2 = crit_task(api, key, ws2)
                # signed reference for the resolved export
                s_m, m = mint(api, key, export_id)
                url = m.get("url") if isinstance(m, dict) else ""
                token = url.split("token=", 1)[1] if "token=" in url else ""
                if token:
                    LEAK_TERMS.append(token)
                return {"fa": fa, "ws": ws, "ws2": ws2, "ws3": ws3, "report": rpt, "report2": rpt2,
                        "export_id": export_id, "corr_active": c2, "corr_reverted": c3,
                        "task_open": topen2, "task_resolved": topen, "token": token}
            SA = build_state(api_a, a1)
            SB = build_state(api_b, b1)
            LEAK_TERMS[:] = sorted({t for t in LEAK_TERMS if t}, key=len, reverse=True)

            # ============================ PART H: cross-tenant REPORT ========================
            # Route inventory note: the API has NO per-report GET route (only POST /monday-reports [create],
            # GET /monday-reports [list], and POST /monday-reports/{id}/exports/{fmt} [export]). Report-read
            # isolation is therefore covered by the list non-leak + the report-scoped EXPORT and signed-
            # reference denials, each with a direct-SQL tenant-B postcondition -- never by asserting a 404
            # against a route that does not exist.
            def denied(cid, ok, *, desc, op, actor, resource, expected, extra=None, level="live HTTP denial"):
                rec(cid, ok, desc=desc, category="cross-tenant-report", op=op, tenant=f"{AA} vs {BB}",
                    actor=actor, resource=resource, expected=expected, db_post="tenant-B unchanged",
                    audit_post="no tenant-B business", level=level, extra=extra)

            # HR00: PROVE the per-report GET route is absent -- A's OWN report id also 404s (route-not-found,
            # not tenant isolation). Documents the unsupported operation instead of faking a denial.
            s_own, _ = _http("GET", f"{api_a}/monday-reports/{SA['report']}", key=a1)
            denied("HR00", s_own in (404, 405),
                   desc="no per-report GET route exists (A's OWN report id -> route-absent 404/405); report-read "
                        "isolation is covered by HR02 list + HR03 export + HR04 signed, not a fake read denial",
                   op="GET /monday-reports/{id} [UNSUPPORTED ROUTE]", actor="A verified (own report)",
                   resource="own report id", expected="404/405 route-absent", extra={"status": s_own},
                   level="structural source check")

            # HR01: A mints a signed reference for a B export (report-export-scoped op that DOES exist + is
            # tenant-owned) -> 404, B unchanged.
            b0 = snap(BB)
            s, _ = mint(api_a, a1, SB["export_id"])
            denied("HR01", s in (403, 404) and unchanged(b0, snap(BB)),
                   desc="A mints a signed reference for a B export -> 404 (existence-hiding), B unchanged",
                   op="POST /report-exports/{B_export}/signed-url", actor="A verified", resource="B export", expected="403/404",
                   extra={"status": s})

            s, lst = _http("GET", f"{api_a}/monday-reports", key=a1)
            ids = {r.get("id") for r in lst} if isinstance(lst, list) else set()
            denied("HR02", s == 200 and SB["report"] not in ids and SB["report2"] not in ids,
                   desc="A lists reports -> sees only A; no B report leaks",
                   op="GET /monday-reports", actor="A verified", resource="B reports", expected="200 A-only",
                   extra={"status": s}, level="whole-stack HTTP read")

            b0 = snap(BB)
            s, _ = export(api_a, a1, SB["report"])
            denied("HR03", s in (403, 404) and snap(BB)["exports"] == b0["exports"],
                   desc="A exports a B report -> 404, no B export created",
                   op="POST /monday-reports/{B_report}/exports/json", actor="A verified", resource="B report",
                   expected="403/404", extra={"status": s})

            b0 = snap(BB)
            st_dl, body = _dl(f"{api_a}/signed/report-exports/{SB['export_id']}?token={SB['token']}")
            denied("HR04", st_dl == 404 and b"monday_report" not in (body or b"") and unchanged(b0, snap(BB)),
                   desc="A presents a B signed reference at A's API -> 404 (B export not in A), no disclosure",
                   op="GET /signed/report-exports/{B_export}", actor="A verified", resource="B export", expected="404",
                   extra={"status": st_dl})

            s, _ = export(api_a, a1, uuid.uuid4())
            denied("HR05", s == 404, desc="A exports a substituted (random) report id -> 404 (resource-negative control)",
                   op="POST /monday-reports/{random}/exports/json", actor="A verified", resource="random id", expected="404", extra={"status": s})

            b0 = snap(BB)
            s, body = _http("POST", f"{api_a}/monday-reports", key=a1,
                            body={"workspace_id": SA["ws"], "period_start": "2026-02-01", "period_end": "2026-02-07",
                                  "tenant_id": str(B["tenant_id"]), "tenant_slug": BB})
            new_rid = body.get("id") if isinstance(body, dict) else None
            in_a = new_rid in ({r.get("id") for r in _http("GET", f"{api_a}/monday-reports", key=a1)[1]} if new_rid else set())
            denied("HR06", s in (200, 201) and in_a and unchanged(b0, snap(BB)),
                   desc="tenant spoof in BODY is ignored -> report created in A, B unchanged",
                   op="POST /monday-reports (+body tenant spoof)", actor="A verified", resource="A workspace",
                   expected="200 scoped-to-A", extra={"status": s}, level="whole-stack HTTP mutation")

            s, lst = _http("GET", f"{api_a}/monday-reports?tenant_id={B['tenant_id']}", key=a1)
            ids = {r.get("id") for r in lst} if isinstance(lst, list) else set()
            denied("HR07", s == 200 and SB["report"] not in ids,
                   desc="tenant spoof in QUERY is ignored -> still A-scoped list",
                   op="GET /monday-reports?tenant_id=B", actor="A verified", resource="B reports", expected="200 A-only",
                   extra={"status": s}, level="whole-stack HTTP read")

            b0 = snap(BB)
            s, _ = export(api_a, a1, SB["report"], extra_headers={"X-Tenant-Id": str(B["tenant_id"]), "X-Tenant-Slug": BB})
            denied("HR08", s in (403, 404) and snap(BB)["exports"] == b0["exports"],
                   desc="ordinary tenant HEADER spoof on a B-report export is ignored -> still 404, B unchanged",
                   op="POST /monday-reports/{B_report}/exports/json (+header spoof)", actor="A verified + header spoof",
                   resource="B report", expected="403/404", extra={"status": s})

            s, lst = _http("GET", f"{api_a}/monday-reports", key=a1,
                           extra_headers={"X-Actor-Id": "spoofed", "X-User-Id": str(uuid.uuid4())})
            ids = {r.get("id") for r in lst} if isinstance(lst, list) else set()
            denied("HR09", s == 200 and SB["report"] not in ids,
                   desc="actor HEADER spoof is ignored -> actor derived from credential, A-scoped",
                   op="GET /monday-reports (+actor spoof)", actor="A verified + actor spoof", resource="B reports",
                   expected="200 A-only", extra={"status": s}, level="whole-stack HTTP read")

            a0 = snap(AA)
            s, _ = export(api_b, b1, SA["report"])
            denied("HR10", s in (403, 404) and snap(AA)["exports"] == a0["exports"],
                   desc="symmetric: B exports an A report -> 404, A export count unchanged",
                   op="POST /monday-reports/{A_report}/exports/json", actor="B verified", resource="A report", expected="403/404", extra={"status": s})

            # ============================ PART I: cross-tenant CORRECTION ====================
            def cdenied(cid, ok, *, desc, op, actor, expected, delta=None, extra=None, level="live HTTP denial"):
                e = dict(extra or {})
                if delta is not None:
                    e["b_delta"] = delta
                rec(cid, ok, desc=desc, category="cross-tenant-correction", op=op, tenant=f"{AA} vs {BB}",
                    actor=actor, resource="B correction/report", expected=expected,
                    db_post="tenant-B corr/rev/audit/idem +0", audit_post="no tenant-B business", level=level, extra=e)

            fa = SA["fa"]
            b0 = snap(BB)
            s, _ = _http("POST", f"{api_a}/workspaces/{SB['ws2']}/field-corrections", key=a1,
                         body=corr_body(fa, "x"), extra_headers={"Idempotency-Key": str(uuid.uuid4())})
            d = {k: snap(BB)[k] - b0[k] for k in b0}
            cdenied("IC01", s in (403, 404) and d["corr"] == 0 and d["biz"] == 0 and d["idem"] == 0,
                    desc="A creates a correction on a B workspace -> denied, no B mutation",
                    op="POST /workspaces/{B_ws}/field-corrections", actor="A verified", expected="403/404",
                    delta={k: d[k] for k in ("corr", "biz", "idem")}, extra={"status": s})

            s, _ = _http("GET", f"{api_a}/workspaces/{SB['ws2']}/field-corrections", key=a1)
            cdenied("IC02", s in (403, 404), desc="A reads B corrections -> denied (B ws not visible)",
                    op="GET /workspaces/{B_ws}/field-corrections", actor="A verified", expected="403/404", extra={"status": s})

            b0 = snap(BB)
            s, _ = _http("POST", f"{api_a}/workspaces/{SB['ws2']}/field-corrections", key=a1,
                         body=corr_body(fa, "v3"), extra_headers={"Idempotency-Key": str(uuid.uuid4())})
            cdenied("IC03", s in (403, 404) and snap(BB)["corr"] == b0["corr"],
                    desc="A supersedes a B correction (re-correct B field) -> denied, B corr count unchanged",
                    op="POST /workspaces/{B_ws}/field-corrections", actor="A verified", expected="403/404", extra={"status": s})

            b0 = snap(BB)
            s, _ = _http("POST", f"{api_a}/field-corrections/{SB['corr_active']}/revert", key=a1,
                         body={"revert_reason": "x"}, extra_headers={"Idempotency-Key": str(uuid.uuid4())})
            d = {k: snap(BB)[k] - b0[k] for k in b0}
            cdenied("IC04", s == 404 and d["corr_active"] == 0 and d["biz"] == 0,
                    desc="A reverts a B correction -> 404, B active/audit unchanged",
                    op="POST /field-corrections/{B_corr}/revert", actor="A verified", expected="404",
                    delta={"corr_active": d["corr_active"], "biz": d["biz"]}, extra={"status": s})

            # reuse-B-key-against-B: B commits a key on its own ws; A reuses THAT SAME key against the B ws
            # -> denied (ws not in A), B unchanged from its own commit.
            ic5key = str(uuid.uuid4())
            _http("POST", f"{api_b}/workspaces/{SB['ws2']}/field-corrections", key=b1,
                  body=corr_body(SB["fa"], "ic5"), extra_headers={"Idempotency-Key": ic5key})  # B commits ic5key
            b_mid = snap(BB)
            s, _ = _http("POST", f"{api_a}/workspaces/{SB['ws2']}/field-corrections", key=a1,
                         body=corr_body(fa, "ic5"), extra_headers={"Idempotency-Key": ic5key})   # A reuses B's key on B ws
            cdenied("IC05", s in (403, 404) and unchanged(b_mid, snap(BB)),
                    desc="A reuses a B-COMMITTED idempotency key against the B ws -> denied (ws not in A), B unchanged",
                    op="POST /workspaces/{B_ws}/field-corrections (reuse B key)", actor="A verified (B's key)",
                    expected="403/404", extra={"status": s, "key_fp": _fp(ic5key)})

            # reuse-B-key-as-A: A uses a key B already used, on A's own ws -> independent success, B unchanged
            bkey = str(uuid.uuid4())
            _http("POST", f"{api_b}/workspaces/{SB['ws2']}/field-corrections", key=b1,
                  body=corr_body(SB["fa"], "bk"), extra_headers={"Idempotency-Key": bkey})  # B uses bkey (its own)
            b_mid = snap(BB); a0 = snap(AA)
            s, _ = _http("POST", f"{api_a}/workspaces/{SA['ws2']}/field-corrections", key=a1,
                         body=corr_body(fa, "ak"), extra_headers={"Idempotency-Key": bkey})   # A reuses bkey in A
            cdenied("IC06", s in (200, 201) and snap(AA)["corr"] == a0["corr"] + 1 and unchanged(b_mid, snap(BB)),
                    desc="A reuses a key B already used -> independent A-scoped result; B unchanged (keys are tenant-namespaced)",
                    op="POST /workspaces/{A_ws}/field-corrections", actor="A verified (B's key)",
                    expected="200 A-scoped, B unchanged", extra={"status": s, "key_fp": _fp(bkey)},
                    level="whole-stack HTTP mutation")

            s, _ = _http("POST", f"{api_a}/field-corrections/{uuid.uuid4()}/revert", key=a1,
                         body={"revert_reason": "x"}, extra_headers={"Idempotency-Key": str(uuid.uuid4())})
            cdenied("IC07", s == 404, desc="A reverts a substituted (random) correction id -> 404",
                    op="POST /field-corrections/{random}/revert", actor="A verified", expected="404", extra={"status": s})

            b0 = snap(BB)
            s, _ = _http("POST", f"{api_a}/workspaces/{SB['ws2']}/field-corrections", key=a1,
                         body=corr_body(fa, "hs"), extra_headers={"Idempotency-Key": str(uuid.uuid4()),
                                                                  "X-Tenant-Slug": BB, "X-Tenant-Id": str(B["tenant_id"])})
            cdenied("IC08", s in (403, 404) and snap(BB)["corr"] == b0["corr"],
                    desc="tenant/actor spoof headers on a B correction are ignored -> still denied, B unchanged",
                    op="POST /workspaces/{B_ws}/field-corrections (+spoof)", actor="A verified + spoof", expected="403/404", extra={"status": s})

            # ============================ PART J: cross-tenant VALIDATION ====================
            def jdenied(cid, ok, *, desc, op, actor, expected, extra=None, level="live HTTP denial"):
                rec(cid, ok, desc=desc, category="cross-tenant-validation", op=op, tenant=f"{AA} vs {BB}",
                    actor=actor, resource="B validation task", expected=expected,
                    db_post="B task/rev/audit +0", audit_post="no tenant-B business", level=level, extra=extra)

            def task_status(slug, tid):
                r = scoped(slug, "select status, revision from monday_report_norm_validation_tasks where id=%s", (str(tid),))
                return (r[0], r[1]) if r else (None, None)

            a_tasks = task_ids(api_a, a1)
            jdenied("JV01", SB["task_open"] not in a_tasks and SB["task_resolved"] not in a_tasks,
                    desc="A lists validation tasks -> no B task leaks", op="GET /validation-tasks",
                    actor="A verified", expected="A-only list", extra={"a_task_count": len(a_tasks)},
                    level="whole-stack HTTP read")

            st_b0, rv_b0 = task_status(BB, SB["task_open"]); b0 = snap(BB)
            for cid, status in (("JV02", "validated"), ("JV03", "rejected"), ("JV04", "open")):
                s, _ = _http("PATCH", f"{api_a}/validation-tasks/{SB['task_open']}", key=a1,
                             body={"status": status, "resolution_note": "x"},
                             extra_headers={"Idempotency-Key": str(uuid.uuid4())})
                st_now, rv_now = task_status(BB, SB["task_open"])
                jdenied(cid, s == 404 and st_now == st_b0 and rv_now == rv_b0 and snap(BB)["biz"] == b0["biz"],
                        desc=f"A transitions a B task ({status}) -> 404, B task state/rev/audit unchanged",
                        op="PATCH /validation-tasks/{B_task}", actor="A verified", expected="404",
                        extra={"status": s, "b_task_status": st_now})

            # JV05: A COMMITS an idempotency key on its OWN task, then reuses THAT key against a B task.
            akey = str(uuid.uuid4())
            _http("PATCH", f"{api_a}/validation-tasks/{SA['task_open']}", key=a1,
                  body={"status": "validated", "resolution_note": "a-own"},
                  extra_headers={"Idempotency-Key": akey})   # A commits akey on its own task
            st_b0, rv_b0 = task_status(BB, SB["task_open"])
            s, _ = _http("PATCH", f"{api_a}/validation-tasks/{SB['task_open']}", key=a1,
                         body={"status": "validated", "resolution_note": "x"},
                         extra_headers={"Idempotency-Key": akey})   # A reuses akey against a B task
            st_now, rv_now = task_status(BB, SB["task_open"])
            jdenied("JV05", s == 404 and st_now == st_b0 and rv_now == rv_b0,
                    desc="A commits a key on its OWN task then reuses that key against a B task -> 404, B task unchanged",
                    op="PATCH /validation-tasks/{B_task} (reuse A key)", actor="A verified (A's own key)",
                    expected="404", extra={"status": s, "b_task_status": st_now})

            s, _ = _http("PATCH", f"{api_a}/validation-tasks/{uuid.uuid4()}", key=a1,
                         body={"status": "validated", "resolution_note": "x"},
                         extra_headers={"Idempotency-Key": str(uuid.uuid4())})
            jdenied("JV06", s == 404, desc="A transitions a substituted (random) task id -> 404",
                    op="PATCH /validation-tasks/{random}", actor="A verified", expected="404", extra={"status": s})

            st_b0, rv_b0 = task_status(BB, SB["task_open"])
            s, _ = _http("PATCH", f"{api_a}/validation-tasks/{SB['task_open']}", key=adis,
                         body={"status": "validated", "resolution_note": "x"},
                         extra_headers={"Idempotency-Key": str(uuid.uuid4())})
            st_now, _ = task_status(BB, SB["task_open"])
            jdenied("JV07", s in (401, 403, 404) and st_now == st_b0,
                    desc="A DISABLED reviewer on a B task -> denied (auth/existence), B task unchanged",
                    op="PATCH /validation-tasks/{B_task}", actor="A disabled reviewer", expected="401/403/404",
                    extra={"status": s, "b_task_status": st_now})

            st_b0, rv_b0 = task_status(BB, SB["task_open"])
            s, _ = _http("PATCH", f"{api_a}/validation-tasks/{SB['task_open']}", key=A["legacy_key"],
                         body={"status": "validated", "resolution_note": "x"},
                         extra_headers={"Idempotency-Key": str(uuid.uuid4())})
            st_now, _ = task_status(BB, SB["task_open"])
            jdenied("JV08", s in (401, 403) and st_now == st_b0,
                    desc="A unverified legacy key on a B task -> auth-denied (client mode), B task unchanged",
                    op="PATCH /validation-tasks/{B_task}", actor="A legacy key (unverified)", expected="401/403",
                    extra={"status": s, "b_task_status": st_now})

            st_b0, rv_b0 = task_status(BB, SB["task_open"])
            s, _ = _http("PATCH", f"{api_a}/validation-tasks/{SB['task_open']}", key=a1,
                         body={"status": "validated", "resolution_note": "x"},
                         extra_headers={"Idempotency-Key": str(uuid.uuid4()), "X-Tenant-Slug": BB})
            st_now, _ = task_status(BB, SB["task_open"])
            jdenied("JV09", s == 404 and st_now == st_b0,
                    desc="tenant spoof header on a B task PATCH is ignored -> 404, B task unchanged",
                    op="PATCH /validation-tasks/{B_task} (+spoof)", actor="A verified + spoof", expected="404", extra={"status": s})

            # ============================ PART K: cross-tenant IDEMPOTENCY ===================
            # No direct idempotency-retrieval route exists; replay is through the business route (documented).
            rep_key = str(uuid.uuid4())
            _http("POST", f"{api_b}/workspaces/{SB['ws2']}/field-corrections", key=b1,
                  body=corr_body(SB["fa"], "rk"), extra_headers={"Idempotency-Key": rep_key})  # B commits rep_key (its own)
            b_mid = snap(BB)
            s, _ = _http("POST", f"{api_a}/workspaces/{SB['ws2']}/field-corrections", key=a1,
                         body=corr_body(fa, "rk"), extra_headers={"Idempotency-Key": rep_key})   # A replays B key on B ws
            rec("KI01", s in (403, 404) and unchanged(b_mid, snap(BB)),  # A's denied replay changed nothing in B
                desc="A replays a B idempotency key against a B ws -> denied; no B result disclosed, B unchanged",
                category="cross-tenant-idempotency", op="POST /workspaces/{B_ws}/field-corrections (replay B key)",
                tenant=f"{AA} vs {BB}", actor="A verified (B key)", resource="B idempotency record",
                expected="403/404", db_post="B idem +0 from A", audit_post="no B business from A",
                level="live HTTP denial", extra={"status": s, "key_fp": _fp(rep_key)})

            # same key under another tenant, on the caller's OWN ws -> independent namespaces
            a0 = snap(AA); b0 = snap(BB); nk = str(uuid.uuid4())
            sa, _ = _http("POST", f"{api_a}/workspaces/{SA['ws2']}/field-corrections", key=a1,
                          body=corr_body(fa, "nk"), extra_headers={"Idempotency-Key": nk})
            sb, _ = _http("POST", f"{api_b}/workspaces/{SB['ws2']}/field-corrections", key=b1,
                          body=corr_body(SB["fa"], "nk"), extra_headers={"Idempotency-Key": nk})
            rec("KI02", sa in (200, 201) and sb in (200, 201)
                and snap(AA)["idem"] == a0["idem"] + 1 and snap(BB)["idem"] == b0["idem"] + 1,
                desc="the SAME key under both tenants -> two independent records; idempotency is tenant-namespaced",
                category="cross-tenant-idempotency", op="POST field-corrections (same key, both tenants)",
                tenant=f"{AA} & {BB}", actor="A & B verified", resource="idempotency record",
                expected="two independent 2xx", db_post="A idem +1, B idem +1", audit_post="each tenant own",
                level="whole-stack HTTP mutation", extra={"a_status": sa, "b_status": sb, "key_fp": _fp(nk)})

            # replay the SAME key/body within A -> A-scoped stored result (no B disclosure)
            a0 = snap(AA)
            sa2, _ = _http("POST", f"{api_a}/workspaces/{SA['ws2']}/field-corrections", key=a1,
                           body=corr_body(fa, "nk"), extra_headers={"Idempotency-Key": nk})
            rec("KI03", sa2 in (200, 201) and snap(AA)["idem"] == a0["idem"],
                desc="A replays its own key+body -> stored A result, no new record (tenant-scoped lookup)",
                category="cross-tenant-idempotency", op="POST field-corrections (A replays own key)",
                tenant=AA, actor="A verified", resource="A idempotency record", expected="200 stored",
                db_post="A idem +0", audit_post="no duplicate", level="whole-stack HTTP mutation", extra={"status": sa2})

            # ==================== PART L: export + signed-reference isolation ================
            def ldenied(cid, ok, *, desc, op, actor, expected, extra=None, level="live HTTP denial"):
                rec(cid, ok, desc=desc, category="cross-tenant-export-signed", op=op, tenant=f"{AA} vs {BB}",
                    actor=actor, resource="B export/reference", expected=expected,
                    db_post="B export +0", audit_post="no B download/signed", level=level, extra=extra)

            b0 = snap(BB)
            s, _ = export(api_a, a1, SB["report"])
            ldenied("LE01", s in (403, 404) and snap(BB)["exports"] == b0["exports"],
                    desc="A exports a B report -> 404, B export count unchanged", op="POST exports (A on B report)",
                    actor="A verified", expected="403/404", extra={"status": s})
            a0 = snap(AA)
            s, _ = export(api_b, b1, SA["report"])
            ldenied("LE02", s in (403, 404) and snap(AA)["exports"] == a0["exports"],
                    desc="B exports an A report -> 404, A export count unchanged", op="POST exports (B on A report)",
                    actor="B verified", expected="403/404", extra={"status": s})
            b0 = snap(BB)
            s, _ = mint(api_a, a1, SB["export_id"])
            ldenied("LE03", s in (403, 404) and unchanged(b0, snap(BB)),
                    desc="A mints a signed reference for a B export -> 404, B unchanged",
                    op="POST /report-exports/{B_export}/signed-url", actor="A verified", expected="403/404", extra={"status": s})
            st_dl, body = _dl(f"{api_a}/signed/report-exports/{SB['export_id']}?token={SB['token']}")
            ldenied("LE04", st_dl == 404 and b"monday_report" not in (body or b""),
                    desc="A retrieves a B signed reference (B token, A API) -> 404, no disclosure",
                    op="GET /signed/report-exports/{B_export}", actor="A verified", expected="404", extra={"status": st_dl})
            st_dl, body = _dl(f"{api_b}/signed/report-exports/{SA['export_id']}?token={SA['token']}")
            ldenied("LE05", st_dl == 404 and b"monday_report" not in (body or b""),
                    desc="B retrieves an A signed reference -> 404, no disclosure",
                    op="GET /signed/report-exports/{A_export}", actor="B verified", expected="404", extra={"status": st_dl})
            wrong_tok = sign(uuid.UUID(str(SA["export_id"])), B["tenant_id"])  # A export, B tenant binding
            st_dl, body = _dl(f"{api_a}/signed/report-exports/{SA['export_id']}?token={wrong_tok}")
            ldenied("LE06", st_dl == 404 and b"monday_report" not in (body or b""),
                    desc="a token for an A export forged with B's tenant binding -> 404 (tenant-capability binding)",
                    op="GET /signed/report-exports/{A_export} (wrong-tenant token)", actor="forged", expected="404",
                    extra={"status": st_dl, "token_fp": _fp(wrong_tok)})
            st_dl, body = _dl(f"{api_b}/signed/report-exports/{uuid.uuid4()}?token={SA['token']}")
            ldenied("LE07", st_dl in (403, 404), desc="substitute export id under B API with an A token -> denied",
                    op="GET /signed/report-exports/{random}", actor="forged", expected="403/404", extra={"status": st_dl})
            st_dl, body = _dl(f"{api_b}/signed/report-exports/{SA['export_id']}?token={SA['token']}")
            ldenied("LE08", st_dl == 404 and b"monday_report" not in (body or b""),
                    desc="replay a VALID A token under the B API -> 404 (A export not in B), no disclosure",
                    op="GET /signed/report-exports/{A_export} @B", actor="A token vs B API", expected="404", extra={"status": st_dl})

            # ==================== PART M: direct RLS inventory (real contract) ===============
            boot_c = psycopg.connect(boot); boot_c.autocommit = True
            rt_c = psycopg.connect(rt); rt_c.autocommit = True
            try:
                inv = policy_inventory(boot_c)["tables"]
                meas = measure_runtime_role(rt_c)
                tenant_pred = "current_setting('app.tenant_slug'"
                for t in PROTECTED_TABLES:
                    meta = inv.get(t)
                    pols = meta["policies"] if meta else []
                    tenant_pols = [p for p in pols if p.get("using") and tenant_pred in p["using"]]
                    widening = [p for p in pols
                                if p.get("permissive") and (not p.get("using") or p["using"].strip() in ("true", "(true)")
                                or (p.get("roles") == ["PUBLIC"] and (not p.get("using") or tenant_pred not in (p["using"] or ""))))]
                    ok = bool(meta) and meta["rowsecurity"] and meta["forced"] and len(tenant_pols) >= 1 \
                        and not widening and meta["owner"] != meas.get("current_user")
                    rec(f"MP-{t}", ok, desc=f"{t}: RLS enabled+FORCED, tenant_isolation policy on app.tenant_slug, "
                        "no widening/PUBLIC policy, not owned by the runtime role",
                        category="rls-inventory", op=f"pg_class/pg_policy: {t}", tenant="-", actor="verifier",
                        resource=t, expected="RLS+FORCE+tenant policy+non-owner", db_post="-",
                        audit_post="-", level="live PostgreSQL policy inspection",
                        extra={"rowsecurity": meta["rowsecurity"] if meta else None,
                               "forced": meta["forced"] if meta else None,
                               "tenant_policies": len(tenant_pols), "widening_policies": len(widening),
                               "owned_by_runtime": (meta["owner"] == meas.get("current_user")) if meta else None})
                # runtime role attributes
                rec("MP-role", not meas["is_superuser"] and not meas["has_bypassrls"]
                    and meas["can_login"] and meas["is_login_not_group"] and not meas["missing_forced_tables"]
                    and not meas["owner_bypass_tables"],
                    desc="runtime role: LOGIN (not the group), non-superuser, non-BYPASSRLS, owns no unforced protected table",
                    category="rls-inventory", op="pg_roles(current_user)", tenant="-", actor="verifier",
                    resource="runtime role", expected="least-privilege non-bypass LOGIN", db_post="-",
                    audit_post="-", level="live PostgreSQL policy inspection",
                    extra={"is_superuser": meas["is_superuser"], "has_bypassrls": meas["has_bypassrls"],
                           "is_login_not_group": meas["is_login_not_group"],
                           "missing_forced": meas["missing_forced_tables"], "owner_bypass": meas["owner_bypass_tables"]})

                # ==================== PART N: direct RLS READ controls =======================
                key_col = {"tenants": "slug", "workspaces": "tenant_id"}
                def keyval(t, slug, tid):
                    if t == "tenants":
                        return slug
                    if t == "workspaces":
                        return str(tid)
                    return slug
                for t in PROTECTED_TABLES:
                    kc = key_col.get(t, "tenant_slug")
                    a_seen_a = scount(AA, t, f"{kc} = %s", (keyval(t, AA, A["tenant_id"]),))
                    a_seen_b = scount(AA, t, f"{kc} = %s", (keyval(t, BB, B["tenant_id"]),))
                    b_seen_b = scount(BB, t, f"{kc} = %s", (keyval(t, BB, B["tenant_id"]),))
                    b_seen_a = scount(BB, t, f"{kc} = %s", (keyval(t, AA, A["tenant_id"]),))
                    rec(f"NR-{t}", a_seen_a >= 1 and a_seen_b == 0 and b_seen_b >= 1 and b_seen_a == 0,
                        desc=f"{t}: GUC=A sees only A rows, GUC=B sees only B rows (no cross-tenant read)",
                        category="rls-read", op=f"select under GUC: {t}", tenant=f"{AA}/{BB}", actor="runtime login",
                        resource=t, expected="A>=1 & A-sees-B=0 & B>=1 & B-sees-A=0", db_post="scoped read",
                        audit_post="-", level="live PostgreSQL RLS read",
                        extra={"a_sees_a": a_seen_a, "a_sees_b": a_seen_b, "b_sees_b": b_seen_b, "b_sees_a": b_seen_a})
                    missing = raw_read(t, None)
                    empty = raw_read(t, "")
                    invalid = raw_read(t, "   ")
                    unknown = raw_read(t, "no-such-tenant-" + run_hash)
                    rec(f"NF-{t}", missing == 0 and empty == 0 and invalid == 0 and unknown == 0,
                        desc=f"{t}: missing/empty/invalid/unknown GUC -> zero rows (fail-closed)",
                        category="rls-read-failclosed", op=f"select under bad GUC: {t}", tenant="-",
                        actor="runtime login", resource=t, expected="all variants -> 0 rows",
                        db_post="0 rows", audit_post="-", level="live PostgreSQL RLS read",
                        extra={"missing": missing, "empty": empty, "invalid": invalid, "unknown": unknown})

                # ==================== PART O: direct RLS WRITE controls ======================
                RLS_ERR = "42501"
                def is_rls(sqlstate):
                    return sqlstate == RLS_ERR
                key_col2 = {"tenants": "slug", "workspaces": "tenant_id"}
                foreign_val = {"tenants": "zzz-nx-" + run_hash, "workspaces": str(B["tenant_id"])}
                for t in PROTECTED_TABLES:
                    kc = key_col2.get(t, "tenant_slug")
                    a_key = keyval(t, AA, A["tenant_id"])
                    b_key = keyval(t, BB, B["tenant_id"])
                    fval = foreign_val.get(t, "zzz-nx-" + run_hash)
                    # USING: cross-tenant UPDATE/DELETE affect zero rows
                    up_ok, up_rc, up_ss = rls_write(AA, f"update {t} set {kc}={kc} where {kc} = %s", (b_key,))
                    del_ok, del_rc, del_ss = rls_write(AA, f"delete from {t} where {kc} = %s", (b_key,))
                    rec(f"WUSE-{t}", up_ok and up_rc == 0 and del_ok and del_rc == 0,
                        desc=f"{t}: cross-tenant UPDATE and DELETE (GUC=A on B rows) affect ZERO rows (USING)",
                        category="rls-write-using", op=f"update/delete cross-tenant: {t}", tenant=f"{AA} on {BB}",
                        actor="runtime login", resource=t, expected="0 rows updated, 0 rows deleted",
                        db_post="B rows untouched", audit_post="-", level="live PostgreSQL RLS write",
                        extra={"update_rowcount": up_rc, "delete_rowcount": del_rc})
                    # WITH CHECK: moving an A row into another tenant raises the RLS policy error 42501.
                    # RLS WITH CHECK is enforced per row BEFORE any AFTER-ROW RI trigger, so this is a clean
                    # policy denial (42501) even on a referenced parent table -- distinguished from a plain
                    # constraint failure (23xxx) by the SQLSTATE.
                    wc_ok, wc_rc, wc_ss = rls_write(AA, f"update {t} set {kc} = %s where {kc} = %s", (fval, a_key))
                    rec(f"WCHK-{t}", (not wc_ok) and is_rls(wc_ss),
                        desc=f"{t}: moving an A row into another tenant -> RLS policy error 42501 (WITH CHECK), "
                             "not a plain constraint failure (23xxx)",
                        category="rls-write-withcheck", op=f"update-into-foreign-tenant: {t}", tenant=f"{AA}->foreign",
                        actor="runtime login", resource=t, expected="42501 row-level-security",
                        db_post="A row unchanged (rolled back)", audit_post="-", level="live PostgreSQL RLS write",
                        extra={"sqlstate": wc_ss, "rowcount": wc_rc})
                    # positive control: same-tenant UPDATE is permitted (>=1 row), rolled back
                    pos_ok, pos_rc, pos_ss = rls_write(AA, f"update {t} set {kc}={kc} where {kc} = %s", (a_key,))
                    rec(f"WPOS-{t}", pos_ok and pos_rc >= 1,
                        desc=f"{t}: same-tenant UPDATE (GUC=A on A rows) is PERMITTED (>=1 row) -- policy is not blanket-deny",
                        category="rls-write-positive", op=f"update same-tenant: {t}", tenant=AA,
                        actor="runtime login", resource=t, expected=">=1 row updated", db_post="rolled back",
                        audit_post="-", level="live PostgreSQL RLS write", extra={"rowcount": pos_rc})
                    # missing GUC: cross/any UPDATE + DELETE affect zero rows (fail-closed writes)
                    mu_ok, mu_rc, _ = rls_write(None, f"update {t} set {kc}={kc} where {kc} = %s", (a_key,))
                    md_ok, md_rc, _ = rls_write(None, f"delete from {t} where {kc} = %s", (a_key,))
                    rec(f"WMIS-{t}", mu_ok and mu_rc == 0 and md_ok and md_rc == 0,
                        desc=f"{t}: with NO GUC set, UPDATE/DELETE affect zero rows (fail-closed writes)",
                        category="rls-write-failclosed", op=f"update/delete no-GUC: {t}", tenant="-",
                        actor="runtime login", resource=t, expected="0 rows", db_post="no write", audit_post="-",
                        level="live PostgreSQL RLS write", extra={"update_rowcount": mu_rc, "delete_rowcount": md_rc})

                # concrete INSERT proofs on the low-FK tables (idempotency + snapshots)
                # positive INSERT under own tenant (idempotency) -> 1 row (rolled back)
                op_id = "iso-op-" + secrets.token_hex(6)
                pi_ok, pi_rc, _ = rls_write(AA,
                    "insert into monday_report_idempotency_records "
                    "(tenant_slug, operation_id, operation_kind, request_hash, committed_revision) "
                    "values (%s,%s,'iso','h',1)", (AA, op_id))
                rec("WINS-pos", pi_ok and pi_rc == 1,
                    desc="INSERT under own tenant (idempotency_records, GUC=A, tenant_slug=A) -> permitted, 1 row",
                    category="rls-write-positive", op="insert own-tenant: idempotency_records", tenant=AA,
                    actor="runtime login", resource="monday_report_idempotency_records", expected="1 row inserted",
                    db_post="rolled back", audit_post="-", level="live PostgreSQL RLS write", extra={"rowcount": pi_rc})
                # cross-tenant INSERT (idempotency + snapshots) -> WITH CHECK 42501
                ci_ok, _, ci_ss = rls_write(AA,
                    "insert into monday_report_idempotency_records "
                    "(tenant_slug, operation_id, operation_kind, request_hash, committed_revision) "
                    "values (%s,%s,'iso','h',1)", (BB, "iso-x-" + secrets.token_hex(6)))
                cs_ok, _, cs_ss = rls_write(AA,
                    "insert into monday_report_state_snapshots (tenant_slug, tenant_id, payload) "
                    "values (%s,%s,'{}')", ("zzz-nx-" + run_hash, str(uuid.uuid4())))
                rec("WINS-chk", (not ci_ok) and is_rls(ci_ss) and (not cs_ok) and is_rls(cs_ss),
                    desc="cross-tenant INSERT (idempotency_records + state_snapshots, GUC=A, foreign tenant_slug) "
                         "-> RLS policy error 42501 (WITH CHECK), not a constraint failure",
                    category="rls-write-withcheck", op="insert cross-tenant: idempotency+snapshots", tenant=f"{AA}->foreign",
                    actor="runtime login", resource="idempotency_records, state_snapshots", expected="42501 both",
                    db_post="no insert", audit_post="-", level="live PostgreSQL RLS write",
                    extra={"idem_sqlstate": ci_ss, "snapshot_sqlstate": cs_ss})

                # ==================== PART P: context lifecycle + pool safety =================
                # ONE physical connection reused for A then B, using the REAL app binding.
                lc = psycopg.connect(rt); lc.autocommit = False
                try:
                    def backend_pid(cur):
                        cur.execute("select pg_backend_pid()"); return cur.fetchone()[0]
                    with lc.cursor() as cur:
                        pid0 = backend_pid(cur)  # internal only, never emitted
                        # txn A: see A rows
                        apply_verified_tenant_scope(cur, AA)
                        cur.execute("select count(*) from monday_report_norm_reports"); a_rows = int(cur.fetchone()[0])
                    lc.rollback()
                    with lc.cursor() as cur:
                        pid1 = backend_pid(cur)
                        # same connection, NO context set after rollback -> must see zero (context cleared)
                        cur.execute("select count(*) from monday_report_norm_reports"); after_rollback = int(cur.fetchone()[0])
                        # txn B on the same connection
                        apply_verified_tenant_scope(cur, BB)
                        cur.execute("select count(*) from monday_report_norm_reports"); b_rows = int(cur.fetchone()[0])
                        # a B row is not an A row and vice versa (disjoint) proven by NR-* above; here we prove no leak
                        cur.execute("select count(*) from monday_report_norm_reports where tenant_slug = %s", (AA,))
                        a_visible_under_b = int(cur.fetchone()[0])
                    lc.rollback()
                    with lc.cursor() as cur:
                        pid2 = backend_pid(cur)
                        cur.execute("select count(*) from monday_report_norm_reports"); after_b_rollback = int(cur.fetchone()[0])
                    lc.rollback()
                    same_conn = (pid0 == pid1 == pid2)
                    rec("PL01", same_conn and a_rows >= 1 and after_rollback == 0 and b_rows >= 1
                        and a_visible_under_b == 0 and after_b_rollback == 0,
                        desc="same physical connection reused A->B: context is transaction-local, cleared on rollback, "
                             "and never inherited (no A rows visible under B; zero rows with no context)",
                        category="context-lifecycle", op="apply_verified_tenant_scope reuse (1 connection)",
                        tenant=f"{AA}->{BB}", actor="runtime login", resource="pooled connection", expected="no leak",
                        db_post="context transaction-local", audit_post="-", level="live PostgreSQL verification",
                        extra={"same_connection": same_conn, "a_rows": a_rows, "cleared_after_rollback": after_rollback,
                               "b_rows": b_rows, "a_visible_under_b": a_visible_under_b,
                               "cleared_after_b": after_b_rollback})
                    # transaction FAILURE after setting A clears the scope (aborted txn -> rollback)
                    leaked_after_fail = None
                    with lc.cursor() as cur:
                        apply_verified_tenant_scope(cur, AA)
                        try:
                            cur.execute("select 1/0")  # force an error -> transaction aborts
                        except psycopg.Error:
                            pass
                    lc.rollback()
                    with lc.cursor() as cur:
                        cur.execute("select count(*) from monday_report_norm_reports"); leaked_after_fail = int(cur.fetchone()[0])
                    lc.rollback()
                    rec("PL02", leaked_after_fail == 0,
                        desc="a transaction that FAILS after setting tenant A leaves no context (rollback clears it -> 0 rows)",
                        category="context-lifecycle", op="failed txn after set A", tenant=AA, actor="runtime login",
                        resource="connection", expected="0 rows after failure", db_post="scope cleared", audit_post="-",
                        level="live PostgreSQL verification", extra={"rows_after_failure": leaked_after_fail})
                    # apply_verified_tenant_scope refuses an empty context (fail-closed binding)
                    empty_refused = False
                    with lc.cursor() as cur:
                        try:
                            apply_verified_tenant_scope(cur, "")
                        except Exception:
                            empty_refused = True
                    lc.rollback()
                    rec("PL03", empty_refused,
                        desc="the app binding refuses an empty tenant context (fail closed, never applies an empty scope)",
                        category="context-lifecycle", op="apply_verified_tenant_scope('')", tenant="-",
                        actor="runtime login", resource="binding", expected="raises", db_post="-", audit_post="-",
                        level="direct component integration", extra={"empty_refused": empty_refused})
                finally:
                    lc.rollback(); lc.close()

                # ==================== PART Q: trust-model disclosure =========================
                gm = GUC_TRUST_MODEL.lower()
                rec("TM01", "can set app.tenant_slug" in TRUST_DISCLOSURE
                    and "not a defense against arbitrary hostile sql" in TRUST_DISCLOSURE.lower()
                    and "not a defense" in gm and "connected principal can set app.tenant_slug" in gm,
                    desc="emit the exact GUC trust-model disclosure; consistent with the source and not overstated",
                    category="trust-model", op="-", tenant="-", actor="verifier", resource="trust model",
                    expected="verbatim disclosure present + consistent with source", db_post="-", audit_post="-",
                    level="structural source check",
                    extra={"disclosure": TRUST_DISCLOSURE, "source_trust_model": GUC_TRUST_MODEL})
            finally:
                boot_c.close(); rt_c.close()
        finally:
            for pr in procs:
                try:
                    pr.terminate(); pr.wait(timeout=10)
                except Exception:
                    pass
            for lg in logs:
                try:
                    lg.close()
                except Exception:
                    pass
            import shutil
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
            err["tb"] = traceback.format_exc()[-2000:]
    G._ON_LIVE = wrapped
    try:
        G.run_stack()
    finally:
        G._ON_LIVE = None
    foundation_fail = [c["id"] for c in getattr(G, "checks", []) if not c.get("ok", True) and not c.get("skipped", False)]
    if foundation_fail:
        rec("foundation", False, desc="foundation checks not ok", category="setup", op="-", tenant="-",
            actor="-", resource="-", expected="all ok", db_post="-", audit_post="-",
            level="structural source check", extra={"foundation_fail": sorted(foundation_fail)[:8]})
    if err:
        print("ON_LIVE ERROR:", err.get("type"), file=sys.stderr)
        print(_scrub(err.get("tb", "")), file=sys.stderr)
        rec("on_live_abort", False, desc=f"on_live aborted with {err.get('type')} (see stderr)",
            category="setup", op="-", tenant="-", actor="-", resource="-", expected="no abort", db_post="-",
            audit_post="-", level="structural source check")
    return _emit()


_PT = ("tenants", "workspaces", "monday_report_state_snapshots", "monday_report_idempotency_records",
       "monday_report_norm_reports", "monday_report_norm_field_corrections",
       "monday_report_norm_validation_tasks", "monday_report_norm_validation_outcomes")
EXPECTED_IDS = (
    [f"HR{i:02d}" for i in range(0, 11)] + [f"IC{i:02d}" for i in range(1, 9)]
    + [f"JV{i:02d}" for i in range(1, 10)] + [f"KI{i:02d}" for i in range(1, 4)]
    + [f"LE{i:02d}" for i in range(1, 9)]
    + [f"MP-{t}" for t in _PT] + ["MP-role"]
    + [f"NR-{t}" for t in _PT] + [f"NF-{t}" for t in _PT]
    + [f"WUSE-{t}" for t in _PT] + [f"WCHK-{t}" for t in _PT]
    + [f"WPOS-{t}" for t in _PT] + [f"WMIS-{t}" for t in _PT]
    + ["WINS-pos", "WINS-chk", "PL01", "PL02", "PL03", "TM01"]
)


def _emit(skipped=False) -> int:
    passed = [c for c in checks if c["ok"]]
    failed = [c for c in checks if not c["ok"]]
    core = "passed" if (checks and not failed and not skipped) else ("skipped" if skipped else "failed")
    exec_totals = {}
    for c in checks:
        exec_totals[c["execution_level"]] = exec_totals.get(c["execution_level"], 0) + 1
    ids = [c["check_id"] for c in checks]
    dup = sorted({i for i in ids if ids.count(i) > 1})
    present = set(ids)
    missing = [i for i in EXPECTED_IDS if i not in present]
    SETUP_IDS = {"completeness", "inventory", "http-counters", "foundation", "on_live_abort", "setup", "setup-apis"}
    unexpected = sorted(i for i in present if i not in EXPECTED_IDS and i not in SETUP_IDS)
    aborted = any(c["check_id"] in ("on_live_abort", "setup-apis", "foundation") for c in checks)
    n423 = HTTP_STATUSES.count(423); n500 = HTTP_STATUSES.count(500); n503 = HTTP_STATUSES.count(503)
    if missing and not skipped and not aborted:
        rec("completeness", False, desc=f"missing expected slice checks: {missing[:8]}", category="setup",
            op="-", tenant="-", actor="-", resource="-", expected="all slice checks present", db_post="-",
            audit_post="-", level="structural source check", extra={"missing_count": len(missing)})
        failed = [c for c in checks if not c["ok"]]; core = "failed"
    if unexpected and not skipped:
        rec("inventory-unexpected", False, desc=f"emitted check ids not in the expected inventory: {unexpected[:8]}",
            category="setup", op="-", tenant="-", actor="-", resource="-", expected="only expected ids",
            db_post="-", audit_post="-", level="structural source check", extra={"unexpected": unexpected[:16]})
        failed = [c for c in checks if not c["ok"]]; core = "failed"
    if dup:
        rec("inventory", False, desc=f"duplicate check ids: {dup[:8]}", category="setup", op="-", tenant="-",
            actor="-", resource="-", expected="unique ids", db_post="-", audit_post="-",
            level="structural source check")
        failed = [c for c in checks if not c["ok"]]; core = "failed"
    if (n423 or n500 or n503) and not skipped:
        rec("http-counters", False, desc="normal functional traffic returned 423/500/503", category="setup",
            op="-", tenant="-", actor="-", resource="-", expected="0/0/0", db_post="-", audit_post="-",
            level="structural source check", extra={"http_423": n423, "http_500": n500, "http_503": n503})
        failed = [c for c in checks if not c["ok"]]; core = "failed"
    out = {"checks": checks,
           "summary": {"passed": len(passed) if not skipped else 0,
                       "skipped": len(checks) if skipped else 0,
                       "failed": 0 if skipped else len(failed),
                       "execution_level_totals": exec_totals,
                       "claim_scope": "restricted-runtime-cross-tenant-http-rls-only",
                       "full_functional_matrix": "not_run",
                       "slice_result": core,
                       "normal_functional_http_423": n423,
                       "normal_functional_http_500": n500,
                       "normal_functional_http_503": n503,
                       "trust_model_disclosure": TRUST_DISCLOSURE,
                       "eligible_for_tenant_evidence": False,
                       "eligible_for_readiness": False,
                       "production_parity": False,
                       "migration_principal_class": "test-only-bootstrap-migration-admin"}}
    print(_scrub(json.dumps(out, indent=2, default=str)))
    if skipped:
        print("\nIsolation slice SKIPPED (docker unavailable, non-certifying).")
        return 0
    if failed:
        print(f"\nIsolation slice FAILED: {len(failed)} check(s).")
        for c in failed:
            print(_scrub(f"  FAIL: {c['check_id']} -> {c.get('description','')} [{c.get('status','')}]"))
        return 1
    print(f"\nIsolation slice passed: {len(passed)} check(s)."
          "\n[claim_scope=restricted-runtime-cross-tenant-http-rls-only; NOT evidence/readiness eligible]")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
