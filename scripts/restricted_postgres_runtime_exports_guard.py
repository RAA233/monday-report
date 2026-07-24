"""Restricted-PostgreSQL functional slice: external export + signed-reference verification (Outcome-1 slice 2).

A NARROW slice guard (NOT the complete functional matrix, and NOT the accepted -core/-mutations guards).
It stands up the ACCEPTED runner-owned stack (restricted_postgres_startup_guard.run_stack + _ON_LIVE -- the
foundation is byte-unchanged) and drives the REAL client-mode HTTP API across TWO synthetic signing-secret
tenants (exp-a / exp-b -- two external uvicorn on the one runner-owned PostgreSQL, RLS-isolated by
app.tenant_slug), plus the actual EXTERNAL worker entrypoint (`python -m backend.app.worker`) on a real
queued upload job, to prove:

  * the EXPORT contract: unresolved report -> 409 VALIDATION gate (explicitly distinguished from a
    SnapshotConflict/stale-revision 409); the override (allow_unresolved_validation) is INERT in client
    mode (a client-data-safety property); the RESOLVED export matrix across all five formats, resolved via
    the ACTUAL mechanism -- a verified-reviewer validation-task PATCH, NOT the worker; export authorization
    + cross-tenant existence-hiding; content-idempotent re-export;
  * the SIGNED-REFERENCE contract: mint requires a signing secret in client mode (409 without one, proven
    on the foundation's own no-secret API); successful mint + retrieve with correct content-type +
    disposition + sha256 binding; the denial matrix (tamper / segment-drop / resource + tenant substitution
    / expiry / wrong-purpose / wrong-secret / missing binding / cross-tenant); and test-controlled expiry
    boundaries (no long sleeps);
  * the EXTERNAL worker's identity/isolation on a real job (restricted login only -- no migration/bootstrap
    DSN, no libpq leak -- committed effect advances the durable snapshot revision);
  * audit integrity (keyed HMAC chain) + a secret scan of the persisted audit.

All measurement is by direct committed SQL (snapshot revision, report_exports JSONB) and direct JSONB audit
deltas (business vs boundary-use events), RLS-scoped by app.tenant_slug -- never a TestClient or a
create_store projection. Signed tokens are never printed; when correlation is needed a >=128-bit token
FINGERPRINT (sha256 truncated) is emitted instead.

HONEST SCOPE. It emits:
  claim_scope = restricted-runtime-exports-signed-references-only
  full_functional_matrix = not_run
  eligible_for_tenant_evidence = false / eligible_for_readiness = false / production_parity = false
  migration_principal_class = test-only-bootstrap-migration-admin
It must NEVER be consumed as tenant-authorization or readiness evidence. Requires Docker.

DEFERRED to later Outcome-1 slices: the expanded all-route cross-tenant matrix; the complete direct-RLS
matrix; full worker tenant-switch isolation; import isolation; tenant evidence v3; readiness
evaluators/contexts; UI certification.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
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
SIGNING_ENV = "MONDAY_REPORT_SIGNING_SECRET"
PURPOSE = "report_export_download"
MEDIA = {"json": "application/json", "csv": "text/csv", "html": "text/html", "pdf": "application/pdf",
         "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
checks: list[dict] = []
LEAK_TERMS: list[str] = []
HTTP_STATUSES: list[int] = []          # every status the guard sees; 423/500/503 must never appear


def _scrub(text: str) -> str:
    for term in LEAK_TERMS:
        if term:
            text = text.replace(term, "<redacted>")
    return text


def _fp(token: str) -> str:
    """A non-reversible >=128-bit fingerprint of a signed token (never the token itself)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:32]


def is_validation_409(body_or_detail) -> bool:
    """The export 409 gate discriminator (module-scope so the fault battery tests the ACTUAL predicate):
    the VALIDATION-domain 409 ("Report has unresolved validation tasks"), explicitly NOT a
    SnapshotConflict/stale-revision 409. Accepts either a JSON body dict or a raw detail string."""
    detail = body_or_detail.get("detail") if isinstance(body_or_detail, dict) else body_or_detail
    dl = (detail or "").lower()
    return ("unresolved validation" in dl) and ("stale" not in dl) and ("revision" not in dl) \
        and ("retry" not in dl) and ("conflict" not in dl)


def rec(cid, ok, *, desc, category, route, tenant, actor, expected, db_post, audit_post,
        level="whole-stack HTTP export/signed attempt", extra=None):
    # "attempt" is honest for BOTH a successful mutating request and a controlled rejection
    # (403/404/409/422/denial) that discloses nothing and mutates nothing.
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "category": category, "route": route, "tenant": tenant,
                   "actor": actor, "expected_status": expected, "db_postcondition": db_post,
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


def _download(url, key=None):
    """GET returning (status, content_bytes, content_type, content_disposition) with header capture."""
    headers = {"X-Monday-Report-Key": key} if key else {}
    req = urllib.request.Request(url, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            b = r.read()
            HTTP_STATUSES.append(r.status)
            return r.status, b, r.headers.get("Content-Type"), r.headers.get("Content-Disposition")
    except urllib.error.HTTPError as e:
        HTTP_STATUSES.append(e.code)
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, body, e.headers.get("Content-Type") if e.headers else None, None
    except Exception as e:  # noqa: BLE001
        return None, str(e).encode(), None, None


def _multipart(fields, filename, content, ctype="text/plain"):
    boundary = "----mrbnd" + secrets.token_hex(10)
    buf = b""
    for k, v in fields.items():
        buf += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").encode()
    buf += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
            f"Content-Type: {ctype}\r\n\r\n").encode()
    buf += content + f"\r\n--{boundary}--\r\n".encode()
    return buf, f"multipart/form-data; boundary={boundary}"


def run() -> int:
    allow_unavailable = "--allow-unavailable" in sys.argv
    if G._docker(["info"]).returncode != 0:
        rec("setup", allow_unavailable, desc="docker availability", category="setup", route="-",
            tenant="-", actor="-", expected="docker", db_post="-", audit_post="-",
            level="structural source check")
        return _emit(skipped=allow_unavailable)

    def on_live(ctx):
        import psycopg
        import backend.app.store as store_mod
        from backend.app.schemas import Role as _Role
        from backend.app.signed_urls import create_signed_token

        api_verif = ctx["api_base"]            # foundation API-A (verif-a) -- NO signing secret
        token_verif = ctx["token"]
        boot, rt = ctx["boot_dsn"], ctx["rt_dsn"]
        base_env = dict(ctx["base_env"])
        run_id, run_hash = ctx["run_id"], ctx["run_hash"]
        rt_role = ctx["rt_role"]
        signing_secret = "exp2-signing-" + secrets.token_hex(28)   # fresh test-only secret, >=32 chars
        LEAK_TERMS[:] = sorted({str(t) for t in [run_id, run_hash, rt_role, ctx["mig_role"], boot, rt,
                                                  ctx["mig_dsn"], ctx["db"], token_verif, signing_secret,
                                                  base_env["MONDAY_REPORT_API_KEY"],
                                                  f"mr-verif-{run_hash}", f"mr-verif-vol-{run_hash}"] if t},
                               key=len, reverse=True)

        procs, logs, scratches, used_ports = [], [], [], set()

        def launch_tenant(slug, name, email):
            """Provision a signing-secret tenant (pre-launch) + start its external uvicorn."""
            port = G._free_loopback_port()
            while port in used_ports or port in (ctx["port"], 8000, 5173):
                port = G._free_loopback_port()
            used_ports.add(port)
            appname = f"mr-verif-exp-{slug}-{run_hash}"
            scratch = Path(os.environ.get("TEMP", "/tmp")) / f"mr-exp-{slug}-{run_hash}"
            for sub in ("state", "storage", "exports"):
                (scratch / sub).mkdir(parents=True, exist_ok=True)
            env = dict(base_env)
            env.update({
                "MONDAY_REPORT_DATABASE_URL": f"{rt}?application_name={appname}",
                "MONDAY_REPORT_TENANT_SLUG": slug,
                "MONDAY_REPORT_TENANT_NAME": name,
                "MONDAY_REPORT_USER_EMAIL": email,
                "MONDAY_REPORT_USER_FULL_NAME": name,
                "MONDAY_REPORT_STATE_PATH": str(scratch / "state" / "s.json"),
                "MONDAY_REPORT_STORAGE_ROOT": str(scratch / "storage"),
                "MONDAY_REPORT_EXPORT_ROOT": str(scratch / "exports"),
                "MONDAY_REPORT_API_KEY": secrets.token_urlsafe(24),
                "MONDAY_REPORT_API_BASE": f"http://127.0.0.1:{port}",
                SIGNING_ENV: signing_secret,
            })
            # provision actors in-process (create_store) BEFORE the API starts -> race-free
            sv = {k: os.environ.get(k) for k in env}
            os.environ.update(env)
            try:
                st = store_mod.create_store()
                actors = {}
                u1 = st.create_user(email, name, [_Role.ADMIN]); _, actors["primary"] = st.create_credential(u1.id)
                u2 = st.create_user(f"second-{secrets.token_hex(3)}@{slug}.test", name + " 2", [_Role.ADMIN])
                _, actors["second"] = st.create_credential(u2.id)
                ud = st.create_user(f"disabled-{secrets.token_hex(3)}@{slug}.test", name + " Disabled", [_Role.ADMIN])
                _, actors["disabled"] = st.create_credential(ud.id)
                st.set_user_status(ud.id, "disabled")
                tenant_id = st.tenant.id
            finally:
                for k, v in sv.items():
                    (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))
            LEAK_TERMS.extend([env["MONDAY_REPORT_API_KEY"], *actors.values()])
            LEAK_TERMS[:] = sorted({t for t in LEAK_TERMS if t}, key=len, reverse=True)
            child = G._child_env(env)
            log = open(scratch / "api.log", "w")
            proc = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1",
                 "--port", str(port)], cwd=str(ROOT), env=child, stdout=log, stderr=subprocess.STDOUT)
            procs.append(proc); logs.append(log); scratches.append(scratch)
            api = f"http://127.0.0.1:{port}"
            up = False
            for _ in range(45):
                if _http("GET", f"{api}/health")[0] == 200:
                    up = True
                    break
                if proc.poll() is not None:
                    break
                time.sleep(1)
            return {"api": api, "port": port, "env": env, "child": child, "scratch": scratch,
                    "legacy_key": env["MONDAY_REPORT_API_KEY"], "tenant_id": tenant_id,
                    "slug": slug, "actors": actors, "appname": appname}

        try:
            A = launch_tenant("exp-a", "Export Tenant A", "reviewer-a@exp.test")
            B = launch_tenant("exp-b", "Export Tenant B", "reviewer-b@exp.test")
            api_a, api_b = A["api"], B["api"]
            a1, a2, adis = A["actors"]["primary"], A["actors"]["second"], A["actors"]["disabled"]
            b1 = B["actors"]["primary"]

            if not (_http("GET", f"{api_a}/health")[0] == 200 and _http("GET", f"{api_b}/health")[0] == 200):
                rec("setup-apis", False, desc="both signing-secret tenant APIs failed to come live",
                    category="setup", route="-", tenant="-", actor="-", expected="both live",
                    db_post="-", audit_post="-", level="structural source check")
                return  # finally-block cleans up; _emit records the setup failure

            # ---------------------- direct committed-SQL surfaces (RLS-scoped) ----------------------
            def _q(slug, sql, params=()):
                with psycopg.connect(rt, autocommit=True) as c:
                    c.execute("select set_config('app.tenant_slug', %s, false)", (slug,))
                    return c.execute(sql, params).fetchone()

            def rev(slug):
                return _q(slug, f"select revision from {STATE_TABLE} where tenant_slug=%s", (slug,))[0]

            def xcount(slug):
                return _q(slug, f"select coalesce(jsonb_array_length(payload->'report_exports'),0) "
                                f"from {STATE_TABLE} where tenant_slug=%s", (slug,))[0]

            def biz(slug, action, resource_id=None):
                if resource_id is None:
                    return _q(slug, f"select count(*) from {STATE_TABLE} s, jsonb_array_elements(s.payload->'audit_logs') e "
                                    "where e->>'action'=%s", (action,))[0]
                return _q(slug, f"select count(*) from {STATE_TABLE} s, jsonb_array_elements(s.payload->'audit_logs') e "
                                "where e->>'action'=%s and e->>'resource_id'=%s", (action, str(resource_id)))[0]

            def bnd(slug, operation):
                return _q(slug, f"select count(*) from {STATE_TABLE} s, jsonb_array_elements(s.payload->'audit_logs') e "
                                "where e->>'action'=%s and e->'metadata'->>'operation'=%s", (BND, operation))[0]

            def audit_blob(slug):
                return _q(slug, f"select coalesce(string_agg(e::text,' '),'') from {STATE_TABLE} s, "
                                "jsonb_array_elements(s.payload->'audit_logs') e")[0] or ""

            # ------------------------------- HTTP building blocks -----------------------------------
            def mk_ws(api, key, name):
                s, w = _http("POST", f"{api}/workspaces", key=key, body={"name": name, "rig_name": "g"})
                return w["id"] if isinstance(w, dict) else None

            def mk_report(api, key, ws):
                s, r = _http("POST", f"{api}/monday-reports", key=key,
                             body={"workspace_id": ws, "period_start": "2026-01-01", "period_end": "2026-01-07"})
                return (s, r["id"]) if (isinstance(r, dict) and "id" in r) else (s, None)

            def task_ids(api, key):
                s, tasks = _http("GET", f"{api}/validation-tasks", key=key)
                return {t["id"] for t in tasks if isinstance(t, dict)} if (s == 200 and isinstance(tasks, list)) else set()

            def crit_task(api, key, ws):
                """A Critical benchmark breach -> a new OPEN anomaly validation task; return its id."""
                before = task_ids(api, key)
                _http("POST", f"{api}/workspaces/{ws}/benchmarking/measurements", key=key,
                      body={"metric": "feet_drilled_per_day", "value": 440, "unit": "ft/day",
                            "data_source": "exports slice", "source_identifier": "exp-crit",
                            "moc_reference": "MOC-EXP-1"})
                new = task_ids(api, key) - before
                return next(iter(new)) if new else None

            def export(api, key, report_id, fmt, override=None, extra_headers=None):
                q = "" if override is None else f"?allow_unresolved_validation={'true' if override else 'false'}"
                return _http("POST", f"{api}/monday-reports/{report_id}/exports/{fmt}{q}",
                             key=key, extra_headers=extra_headers)

            def mint(api, key, export_id):
                return _http("POST", f"{api}/report-exports/{export_id}/signed-url", key=key)

            def sign(resource_id, tenant_id, secret, ttl=900, purpose=PURPOSE):
                """Mint a capability token with a chosen secret/ttl/purpose (test-controlled).
                Every minted token is registered in LEAK_TERMS so the final _scrub cannot emit it raw."""
                sv = os.environ.get(SIGNING_ENV)
                os.environ[SIGNING_ENV] = secret
                try:
                    tok, _exp = create_signed_token(resource_id, purpose, ttl, tenant_id=tenant_id)
                    LEAK_TERMS.append(tok)
                    LEAK_TERMS[:] = sorted({t for t in LEAK_TERMS if t}, key=len, reverse=True)
                    return tok
                finally:
                    (os.environ.__setitem__(SIGNING_ENV, sv) if sv is not None else os.environ.pop(SIGNING_ENV, None))

            def retrieve(api, export_id, token):
                return _download(f"{api}/signed/report-exports/{export_id}?token={token}")

            AA, BB = "exp-a", "exp-b"

            def resolve_open_task(api, key, tid):
                return _http("PATCH", f"{api}/validation-tasks/{tid}", key=key,
                             body={"status": "validated", "resolution_note": "exports slice resolution"},
                             extra_headers={"Idempotency-Key": str(uuid.uuid4())})

            # =====================================================================================
            # PART G -- UNRESOLVED EXPORT: the 409 VALIDATION gate (NOT a SnapshotConflict)
            # =====================================================================================
            wsU = mk_ws(api_a, a1, "exp-a-unresolved")
            tU = crit_task(api_a, a1, wsU)                 # open anomaly validation task in wsU
            sU, rU = mk_report(api_a, a1, wsU)

            for i, fmt in enumerate(("pdf", "csv", "xlsx", "json", "html"), start=1):
                x0 = xcount(AA)
                s, body = export(api_a, a1, rU, fmt)
                dx = xcount(AA) - x0
                rec(f"EXU0{i}", s == 409 and is_validation_409(body) and dx == 0,
                    desc=f"unresolved report export ({fmt}) -> 409 VALIDATION gate, no export record",
                    category="export-validation-gate", route="POST /monday-reports/{id}/exports/" + fmt,
                    tenant=AA, actor="exp-a verified #1", expected="409 validation",
                    db_post="report_exports+0", audit_post="export_blocked",
                    extra={"status": s, "detail_is_validation": is_validation_409(body), "dx": dx})

            # EXU06: the gate is a VALIDATION-domain 409, explicitly NOT a stale-revision SnapshotConflict
            s, body = export(api_a, a1, rU, "pdf")
            detail = (body.get("detail") if isinstance(body, dict) else "") or ""
            rec("EXU06", s == 409 and is_validation_409(body) and tU is not None,
                desc="the export 409 is the validation-domain message, not a SnapshotConflict/stale-revision 409",
                category="export-validation-gate", route="POST /monday-reports/{id}/exports/pdf",
                tenant=AA, actor="exp-a verified #1", expected="409 'unresolved validation tasks'",
                db_post="report_exports+0", audit_post="export_blocked",
                extra={"status": s, "detail": _scrub(detail)})

            # EXU07: override is INERT in client mode -> allow_unresolved_validation=true STILL 409
            x0 = xcount(AA)
            s, body = export(api_a, a1, rU, "pdf", override=True)
            dx = xcount(AA) - x0
            rec("EXU07", s == 409 and is_validation_409(body) and dx == 0,
                desc="allow_unresolved_validation=true is INERT in client mode -> still 409 (client-data safety)",
                category="export-override-inert", route="POST /monday-reports/{id}/exports/pdf?allow_unresolved_validation=true",
                tenant=AA, actor="exp-a verified #1", expected="409 (override ignored in client mode)",
                db_post="report_exports+0", audit_post="export_blocked", extra={"status": s, "dx": dx})

            # =====================================================================================
            # PART H -- RESOLVED EXPORT MATRIX (resolution via verified-reviewer PATCH, NOT the worker)
            # =====================================================================================
            sR, _ = resolve_open_task(api_a, a1, tU)        # verified reviewer resolves the open task
            trow = _q(AA, "select status from monday_report_norm_validation_tasks where id=%s", (str(tU),))
            tU_status = trow[0] if trow else None
            rec("EXR00", sR in (200, 201) and tU_status == "validated",
                desc="resolve the open validation task via verified-reviewer PATCH (the ACTUAL resolution path)",
                category="export-resolution", route="PATCH /validation-tasks/{id}", tenant=AA,
                actor="exp-a verified #1", expected="200 validated", db_post="task status=validated (no longer open)",
                audit_post="validation_task.update", extra={"status": sR, "task_status": tU_status})

            export_ids = {}
            for i, fmt in enumerate(("json", "csv", "html", "pdf", "xlsx"), start=1):
                x0 = xcount(AA); bz = biz(AA, "monday_report.export", rU)
                s, body = export(api_a, a1, rU, fmt)
                dx = xcount(AA) - x0
                ok = (s == 200 and isinstance(body, dict) and body.get("format") == fmt
                      and body.get("byte_size", 0) > 0 and body.get("sha256") and dx == 1
                      and (biz(AA, "monday_report.export", rU) - bz) == 1)
                if isinstance(body, dict) and body.get("id"):
                    export_ids[fmt] = body["id"]
                rec(f"EXR0{i}", ok,
                    desc=f"resolved report export ({fmt}) -> 200 ReportExport, +1 record, byte_size>0, sha256 bound",
                    category="export-resolved", route="POST /monday-reports/{id}/exports/" + fmt,
                    tenant=AA, actor="exp-a verified #1", expected="200 ReportExport",
                    db_post="report_exports+1", audit_post="monday_report.export +1",
                    extra={"status": s, "dx": dx, "byte_size": body.get("byte_size") if isinstance(body, dict) else None})

            # EXR06: content-idempotent re-export -> SAME export id, NO new record (content-idempotency)
            x0 = xcount(AA)
            s, body = export(api_a, a1, rU, "pdf")
            dx = xcount(AA) - x0
            rec("EXR06", s == 200 and isinstance(body, dict) and body.get("id") == export_ids.get("pdf") and dx == 0,
                desc="re-export same report+format -> content-idempotent (same export reused), no duplicate record",
                category="export-idempotency", route="POST /monday-reports/{id}/exports/pdf", tenant=AA,
                actor="exp-a verified #1", expected="200 reused export", db_post="report_exports+0",
                audit_post="monday_report.export_reused", extra={"status": s, "dx": dx})

            # EXR07: a genuinely clean report (no breach, no open task) exports with NO resolution needed
            wsClean = mk_ws(api_a, a1, "exp-a-clean")
            _, rClean = mk_report(api_a, a1, wsClean)
            s, body = export(api_a, a1, rClean, "json")
            rec("EXR07", s == 200 and isinstance(body, dict) and body.get("byte_size", 0) > 0,
                desc="clean report (never had an open task) exports without any resolution step",
                category="export-resolved", route="POST /monday-reports/{id}/exports/json", tenant=AA,
                actor="exp-a verified #1", expected="200 ReportExport", db_post="report_exports+1",
                audit_post="monday_report.export", extra={"status": s})

            # =====================================================================================
            # PART H(worker) -- EXTERNAL worker identity/isolation on a REAL queued upload job
            # =====================================================================================
            wsWk = mk_ws(api_a, a1, "exp-a-worker")
            payload, ctype = _multipart({"workspace_id": wsWk, "file_name": "note.txt", "source_type": "files"},
                                        "note.txt",
                                        b"Rig daily note: circulated bottoms up; no NPT recorded on this shift.\n")
            su, _ = _http("POST", f"{api_a}/uploads/direct", key=a1, raw=payload, ctype=ctype)
            rev_after_upload = rev(AA)
            vt_before_worker = biz(AA, "validation_task.update", None)   # reviewer resolutions so far (EXR00)
            wenv = A["child"]  # explicit allowlisted child env (no libpq/PG* leakage) with rt DSN + signing secret
            wlog_path = A["scratch"] / "worker.log"
            wlog = open(wlog_path, "w")
            wproc = subprocess.Popen([sys.executable, "-m", "backend.app.worker"], cwd=str(ROOT),
                                     env=wenv, stdout=wlog, stderr=subprocess.STDOUT)
            procs.append(wproc); logs.append(wlog)   # reap in the outer finally even if wait() times out
            wrc = wproc.wait(timeout=120)
            wlog.flush()
            wout = wlog_path.read_text(errors="replace")
            m = re.search(r"Processed (\d+) Monday Report job", wout)
            processed = int(m.group(1)) if m else -1
            rev_after_worker = rev(AA)
            vt_after_worker = biz(AA, "validation_task.update", None)

            # WK01: the external worker processed the real job and advanced the durable snapshot revision
            rec("WK01", su in (200, 201) and wrc == 0 and processed >= 1 and rev_after_worker > rev_after_upload,
                desc="external worker (`python -m backend.app.worker`) processed a real upload job; snapshot revision advanced",
                category="worker-isolation", route="`python -m backend.app.worker`", tenant=AA,
                actor="external worker (restricted login)", expected="exit 0, processed>=1, rev advanced",
                db_post="revision advanced", audit_post="job processed",
                level="external worker subprocess on a real queued job",
                extra={"upload_status": su, "worker_rc": wrc, "processed": processed,
                       "rev_advanced": rev_after_worker - rev_after_upload})

            # WK02: worker identity/isolation by env-hygiene -- the ONLY DB credential is the restricted
            # runtime DSN; the migration/bootstrap DSN + their roles are absent; no libpq/PG* leakage.
            wdsn = wenv.get("MONDAY_REPORT_DATABASE_URL", "")
            no_libpq = G._no_libpq_leak(wenv)   # the accepted foundation's own libpq-leak check
            hygiene = (rt in wdsn and boot not in wdsn and ctx["mig_dsn"] not in wdsn
                       and ctx["mig_role"] not in " ".join(wenv.values()) and no_libpq)
            rec("WK02", hygiene and wrc == 0,
                desc="worker runs on the restricted runtime login ONLY: no bootstrap/migration DSN or role, no libpq leak",
                category="worker-isolation", route="`python -m backend.app.worker`", tenant=AA,
                actor="external worker (restricted login)", expected="restricted DSN only",
                db_post="committed under restricted login", audit_post="-",
                level="external worker env-hygiene + committed effect",
                extra={"restricted_dsn_only": bool(rt in wdsn and boot not in wdsn),
                       "no_migration_material": bool(ctx["mig_dsn"] not in wdsn), "no_libpq_leak": bool(no_libpq)})

            # WK03: DISCRIMINATING negative -- the worker does NOT resolve report-export validation tasks. It
            # processed a real job (WK01) yet authored ZERO validation_task.update audits during its run
            # (vt count unchanged across the subprocess), while the verified-reviewer PATCH (EXR00, sR 2xx)
            # authored the ONLY resolution. A worker that wrongly resolved a task would raise vt_after.
            rec("WK03", processed >= 1 and vt_after_worker == vt_before_worker and vt_before_worker >= 1
                and sR in (200, 201),
                desc="the worker authored NO validation resolution during its run (vt count unchanged); "
                     "report-export resolution is exclusively the verified-reviewer PATCH (EXR00)",
                category="worker-contract", route="`python -m backend.app.worker`", tenant=AA, actor="verifier",
                expected="worker vt-delta == 0; reviewer authored resolution", db_post="no worker resolution",
                audit_post="validation_task.update unchanged across the worker run",
                level="live PostgreSQL verification",
                extra={"worker_processed": processed, "vt_before_worker": vt_before_worker,
                       "vt_after_worker": vt_after_worker, "reviewer_resolution_status": sR})

            # =====================================================================================
            # PART I -- EXPORT AUTHORIZATION + CROSS-TENANT (existence-hiding)
            # =====================================================================================
            # a resolved export exists on tenant B too (clean report, no breach)
            wsBc = mk_ws(api_b, b1, "exp-b-clean")
            _, rB = mk_report(api_b, b1, wsBc)
            sB, bodyB = export(api_b, b1, rB, "json")
            expB_id = bodyB["id"] if isinstance(bodyB, dict) and bodyB.get("id") else None

            # EA01: second verified actor (A2) exports a tenant-A report -> 200 (multi-actor authorization)
            s, _ = export(api_a, a2, rClean, "csv")
            rec("EA01", s == 200, desc="second verified reviewer (A2) exports a tenant-A report -> 200",
                category="export-authz", route="POST /monday-reports/{id}/exports/csv", tenant=AA,
                actor="exp-a verified #2", expected="200", db_post="report_exports+1", audit_post="monday_report.export",
                extra={"status": s})

            # EA02: tenant-B reviewer exports a tenant-B report -> 200
            rec("EA02", sB == 200 and expB_id, desc="tenant-B reviewer exports a tenant-B report -> 200",
                category="export-authz", route="POST /monday-reports/{id}/exports/json", tenant=BB,
                actor="exp-b verified #1", expected="200", db_post="report_exports+1", audit_post="monday_report.export",
                extra={"status": sB})

            # EA03: tenant-A key against a tenant-B report id (cross-tenant) -> 404 existence-hiding, B unchanged
            xb0 = xcount(BB)
            s, _ = export(api_a, a1, rB, "pdf")
            rec("EA03", s == 404 and xcount(BB) == xb0,
                desc="tenant-A reviewer exports a tenant-B report id -> 404 (existence-hiding), tenant-B unchanged",
                category="export-cross-tenant", route="POST /monday-reports/{id}/exports/pdf", tenant=AA,
                actor="exp-a #1 vs tenant-B report", expected="404", db_post="tenant-B report_exports+0",
                audit_post="no export", extra={"status": s})

            # EA04: tenant-B key against a tenant-A report id -> 404, A unchanged
            xa0 = xcount(AA)
            s, _ = export(api_b, b1, rClean, "pdf")
            rec("EA04", s == 404 and xcount(AA) == xa0,
                desc="tenant-B reviewer exports a tenant-A report id -> 404 (existence-hiding), tenant-A unchanged",
                category="export-cross-tenant", route="POST /monday-reports/{id}/exports/pdf", tenant=BB,
                actor="exp-b #1 vs tenant-A report", expected="404", db_post="tenant-A report_exports+0",
                audit_post="no export", extra={"status": s})

            # EA05: missing credential -> denied
            s, _ = export(api_a, None, rClean, "json")
            rec("EA05", s in (401, 403), desc="export with no credential -> auth denied",
                category="export-authz", route="POST /monday-reports/{id}/exports/json", tenant=AA,
                actor="anonymous", expected="401/403", db_post="unchanged", audit_post="no export", extra={"status": s})

            # EA06: invalid credential -> denied
            s, _ = export(api_a, "not-a-real-key-" + secrets.token_hex(6), rClean, "json")
            rec("EA06", s in (401, 403), desc="export with an invalid credential -> auth denied",
                category="export-authz", route="POST /monday-reports/{id}/exports/json", tenant=AA,
                actor="invalid key", expected="401/403", db_post="unchanged", audit_post="no export", extra={"status": s})

            # EA07: disabled credential -> denied
            s, _ = export(api_a, adis, rClean, "json")
            rec("EA07", s in (401, 403), desc="export with a DISABLED reviewer credential -> auth denied",
                category="export-authz", route="POST /monday-reports/{id}/exports/json", tenant=AA,
                actor="exp-a disabled", expected="401/403", db_post="unchanged", audit_post="no export", extra={"status": s})

            # EA08: unverified legacy shared key -> denied in client mode
            s, _ = export(api_a, A["legacy_key"], rClean, "json")
            rec("EA08", s in (401, 403), desc="export with the legacy shared key (unverified) -> denied in client mode",
                category="export-authz", route="POST /monday-reports/{id}/exports/json", tenant=AA,
                actor="legacy shared key", expected="401/403", db_post="unchanged", audit_post="no export", extra={"status": s})

            # EA09: non-existent report id -> 404
            s, _ = export(api_a, a1, uuid.uuid4(), "json")
            rec("EA09", s == 404, desc="export a non-existent report id -> 404",
                category="export-negative", route="POST /monday-reports/{id}/exports/json", tenant=AA,
                actor="exp-a verified #1", expected="404", db_post="unchanged", audit_post="no export", extra={"status": s})

            # EA10: spoofed tenant headers are ignored AND the write is credential-scoped -- the export lands in
            # exp-a (record +1) and tenant-B is untouched (direct-SQL control; a header-honoring cross-tenant
            # bug would instead bump exp-b's record count).
            xa_pre, xb_pre = xcount(AA), xcount(BB)
            s, _ = export(api_a, a1, rClean, "html", extra_headers={"X-Tenant-Id": str(B["tenant_id"]),
                                                                    "X-Tenant-Slug": "exp-b"})
            rec("EA10", s == 200 and xcount(AA) == xa_pre + 1 and xcount(BB) == xb_pre,
                desc="spoofed X-Tenant-Id/Slug headers are ignored; the export is credential-scoped to exp-a "
                     "(record +1) and tenant-B is untouched",
                category="export-tenant-spoof", route="POST /monday-reports/{id}/exports/html", tenant=AA,
                actor="exp-a #1 + spoofed tenant headers", expected="200; exp-a +1; exp-b +0",
                db_post="exp-a report_exports+1, exp-b report_exports+0", audit_post="monday_report.export",
                extra={"status": s, "exp_a_delta": xcount(AA) - xa_pre, "exp_b_delta": xcount(BB) - xb_pre})

            # =====================================================================================
            # PART SR-gate -- MINT requires a signing secret in client mode (foundation no-secret API)
            # =====================================================================================
            wsVf = mk_ws(api_verif, token_verif, "verif-a-nosecret")
            _, rVf = mk_report(api_verif, token_verif, wsVf)
            sVf, bodyVf = export(api_verif, token_verif, rVf, "json")
            expVf = bodyVf["id"] if isinstance(bodyVf, dict) and bodyVf.get("id") else None
            s, body = mint(api_verif, token_verif, expVf) if expVf else (None, None)
            d = (body.get("detail") if isinstance(body, dict) else "") or ""
            rec("SRG01", sVf == 200 and s == 409 and "signing secret" in d.lower(),
                desc="signed-URL mint without a configured signing secret in client mode -> 409 (proven on the foundation API)",
                category="signed-secret-gate", route="POST /report-exports/{id}/signed-url", tenant="verif-a",
                actor="foundation reviewer (no signing secret)", expected="409 signing-secret-required",
                db_post="no token minted", audit_post="report_export.signed_url_blocked",
                extra={"export_status": sVf, "mint_status": s, "detail": _scrub(d)})

            # =====================================================================================
            # PART K -- SIGNED-REFERENCE SUCCESS (tenant A, signing secret configured)
            # =====================================================================================
            expA_pdf = export_ids.get("pdf")
            # ReportExport metadata (sha256/byte_size) for content-binding assertion
            _, meta = _http("GET", f"{api_a}/monday-reports?workspace_id={wsU}", key=a1)  # touch to ensure store live
            sha_expected = None
            for fmt in ("pdf",):
                # re-export returns the stored ReportExport (content-idempotent) with sha256
                _, rx = export(api_a, a1, rU, fmt)
                if isinstance(rx, dict):
                    sha_expected = rx.get("sha256")

            s, body = mint(api_a, a1, expA_pdf)
            url = body.get("url") if isinstance(body, dict) else None
            token = url.split("token=", 1)[1] if (url and "token=" in url) else None
            if token:
                LEAK_TERMS.append(token); LEAK_TERMS[:] = sorted({t for t in LEAK_TERMS if t}, key=len, reverse=True)
            rec("SR01", s == 200 and url and body.get("expires_at") and token and str(expA_pdf) in url,
                desc="mint a signed reference for a tenant-A export -> 200 {url, expires_at}, resource-bound",
                category="signed-success", route="POST /report-exports/{id}/signed-url", tenant=AA,
                actor="exp-a verified #1", expected="200 SignedUrlResponse", db_post="stateless token (no record)",
                audit_post="report_export.signed_url", extra={"status": s, "token_fp": _fp(token) if token else None})

            # SR02: retrieve via the signed URL -> 200 content + correct content-type + disposition
            st, content, ct, disp = retrieve(api_a, expA_pdf, token) if token else (None, b"", None, None)
            rec("SR02", st == 200 and content and ct == MEDIA["pdf"]
                and disp == 'attachment; filename="monday_report.pdf"',
                desc="retrieve the signed reference -> 200 with correct Content-Type + Content-Disposition",
                category="signed-success", route="GET /signed/report-exports/{id}", tenant=AA,
                actor="signed-capability holder", expected="200 pdf attachment", db_post="-",
                audit_post="report_export.download", level="whole-stack signed retrieval",
                extra={"status": st, "content_type": ct, "disposition": disp, "bytes": len(content or b"")})

            # SR03: retrieved content sha256 == the ReportExport.sha256 (exact resource binding)
            actual_sha = hashlib.sha256(content).hexdigest() if content else None
            rec("SR03", actual_sha is not None and sha_expected is not None and actual_sha == sha_expected,
                desc="retrieved bytes' sha256 equals the ReportExport.sha256 (exact report/export/tenant binding)",
                category="signed-success", route="GET /signed/report-exports/{id}", tenant=AA,
                actor="signed-capability holder", expected="sha256 match", db_post="-", audit_post="-",
                level="whole-stack signed retrieval", extra={"sha_match": actual_sha == sha_expected})

            # SR04: response headers carry no signing secret / DSN / role / run nonce
            hdr_blob = f"{ct or ''} {disp or ''}"
            leaked_hdr = [t for t in LEAK_TERMS if t and t in hdr_blob]
            rec("SR04", not leaked_hdr,
                desc="signed-retrieval response headers disclose no signing secret / DSN / role / run nonce",
                category="signed-secret-hygiene", route="GET /signed/report-exports/{id}", tenant=AA,
                actor="verifier", expected="no leak", db_post="-", audit_post="-",
                level="response-header inspection", extra={"leaked_kinds": len(leaked_hdr)})

            # SR05: audit attribution -- signed_url mint + download business audits present for exp-a
            su_audit = biz(AA, "report_export.signed_url", expA_pdf)
            dl_audit = biz(AA, "report_export.download", expA_pdf)
            rec("SR05", su_audit >= 1 and dl_audit >= 1,
                desc="mint + download emit tenant-scoped business audits (signed_url, download) for the export",
                category="signed-audit", route="-", tenant=AA, actor="verifier", expected="both audits present",
                db_post="-", audit_post="report_export.signed_url + report_export.download",
                level="live PostgreSQL verification", extra={"signed_url_audits": su_audit, "download_audits": dl_audit})

            # =====================================================================================
            # PART L -- SIGNED-REFERENCE DENIAL MATRIX (forged tokens; the secret is known to the guard)
            # =====================================================================================
            tok_valid_A = sign(uuid.UUID(str(expA_pdf)), A["tenant_id"], signing_secret)
            LEAK_TERMS.append(tok_valid_A); LEAK_TERMS[:] = sorted({t for t in LEAK_TERMS if t}, key=len, reverse=True)

            def denied_no_content(st, body):
                return st != 200 and (not body or b"monday_report" not in (body if isinstance(body, bytes) else b""))

            # SD01: cross-tenant use -- a VALID tenant-A token presented to the tenant-B API -> 404 (not in B)
            st, body, _, _ = retrieve(api_b, expA_pdf, tok_valid_A)
            rec("SD01", st == 404 and denied_no_content(st, body),
                desc="a valid tenant-A signed reference presented to the tenant-B API -> 404 (cross-tenant existence-hiding)",
                category="signed-cross-tenant", route="GET /signed/report-exports/{id}", tenant=BB,
                actor="tenant-A token vs tenant-B API", expected="404", db_post="-", audit_post="no download",
                extra={"status": st, "token_fp": _fp(tok_valid_A)})

            # SD02: no token -> 422 (required query param missing)
            st, body, _, _ = _download(f"{api_a}/signed/report-exports/{expA_pdf}")
            rec("SD02", st == 422, desc="signed retrieval with no token -> 422 (required capability missing)",
                category="signed-denial", route="GET /signed/report-exports/{id}", tenant=AA,
                actor="anonymous", expected="422", db_post="-", audit_post="no download", extra={"status": st})

            # SD03: single-byte tamper of the payload segment -> signature mismatch -> 403
            payload_seg, sig_seg = tok_valid_A.split(".", 1)
            flipped = ("b" if payload_seg[0] != "b" else "c") + payload_seg[1:]
            st, body, _, _ = retrieve(api_a, expA_pdf, f"{flipped}.{sig_seg}")
            rec("SD03", st == 403 and denied_no_content(st, body),
                desc="single-byte tamper of the token payload -> signature mismatch -> 403",
                category="signed-denial", route="GET /signed/report-exports/{id}", tenant=AA,
                actor="tampered token", expected="403", db_post="-", audit_post="no download", extra={"status": st})

            # SD04: drop the signature segment (no '.') -> 403
            st, body, _, _ = retrieve(api_a, expA_pdf, payload_seg)
            rec("SD04", st == 403, desc="token with the signature segment removed -> 403",
                category="signed-denial", route="GET /signed/report-exports/{id}", tenant=AA,
                actor="segment-dropped token", expected="403", db_post="-", audit_post="no download", extra={"status": st})

            # SD05: append extra bytes to the signature -> 403
            st, body, _, _ = retrieve(api_a, expA_pdf, f"{payload_seg}.{sig_seg}AAAA")
            rec("SD05", st == 403, desc="token with appended signature bytes -> 403",
                category="signed-denial", route="GET /signed/report-exports/{id}", tenant=AA,
                actor="appended-signature token", expected="403", db_post="-", audit_post="no download", extra={"status": st})

            # SD06: resource substitution -- a token minted for export-pdf used at the export-csv path -> 403
            expA_csv = export_ids.get("csv")
            st, body, _, _ = retrieve(api_a, expA_csv, tok_valid_A)
            rec("SD06", st == 403, desc="token bound to export X presented at export Y's path -> 403 (resource mismatch)",
                category="signed-denial", route="GET /signed/report-exports/{id}", tenant=AA,
                actor="resource-substituted token", expected="403", db_post="-", audit_post="no download", extra={"status": st})

            # SD07: tenant substitution -- forge a token with the RIGHT resource but a WRONG tenant_id -> 404
            tok_wrong_tenant = sign(uuid.UUID(str(expA_pdf)), uuid.uuid4(), signing_secret)
            st, body, _, _ = retrieve(api_a, expA_pdf, tok_wrong_tenant)
            rec("SD07", st == 404 and denied_no_content(st, body),
                desc="token with a wrong tenant binding (valid signature/resource) -> 404 (tenant-capability binding)",
                category="signed-denial", route="GET /signed/report-exports/{id}", tenant=AA,
                actor="wrong-tenant token", expected="404", db_post="-", audit_post="no download",
                extra={"status": st, "token_fp": _fp(tok_wrong_tenant)})

            # SD08: expired token (test-controlled negative ttl) -> 403
            tok_expired = sign(uuid.UUID(str(expA_pdf)), A["tenant_id"], signing_secret, ttl=-30)
            st, body, _, _ = retrieve(api_a, expA_pdf, tok_expired)
            rec("SD08", st == 403 and denied_no_content(st, body),
                desc="an expired token (exp in the past) -> 403",
                category="signed-expiry", route="GET /signed/report-exports/{id}", tenant=AA,
                actor="expired token", expected="403", db_post="-", audit_post="no download",
                extra={"status": st, "token_fp": _fp(tok_expired)})

            # SD09: wrong purpose -> 403
            tok_wrong_purpose = sign(uuid.UUID(str(expA_pdf)), A["tenant_id"], signing_secret, purpose="upload_file_download")
            st, body, _, _ = retrieve(api_a, expA_pdf, tok_wrong_purpose)
            rec("SD09", st == 403, desc="token minted for a different purpose -> 403 (purpose binding)",
                category="signed-denial", route="GET /signed/report-exports/{id}", tenant=AA,
                actor="wrong-purpose token", expected="403", db_post="-", audit_post="no download", extra={"status": st})

            # SD10: wrong signing secret -> signature mismatch under the API's secret -> 403
            tok_wrong_secret = sign(uuid.UUID(str(expA_pdf)), A["tenant_id"], "a-different-secret-" + secrets.token_hex(20))
            st, body, _, _ = retrieve(api_a, expA_pdf, tok_wrong_secret)
            rec("SD10", st == 403 and denied_no_content(st, body),
                desc="token signed with a DIFFERENT secret -> signature mismatch -> 403",
                category="signed-denial", route="GET /signed/report-exports/{id}", tenant=AA,
                actor="wrong-secret token", expected="403", db_post="-", audit_post="no download",
                extra={"status": st, "token_fp": _fp(tok_wrong_secret)})

            # SD11: token bound to a NON-EXISTENT resource (valid signature/tenant) -> 404
            ghost = uuid.uuid4()
            tok_ghost = sign(ghost, A["tenant_id"], signing_secret)
            st, body, _, _ = retrieve(api_a, ghost, tok_ghost)
            rec("SD11", st == 404, desc="token bound to a non-existent export id -> 404 (no resource)",
                category="signed-denial", route="GET /signed/report-exports/{id}", tenant=AA,
                actor="ghost-resource token", expected="404", db_post="-", audit_post="no download", extra={"status": st})

            # SD12: legacy token with NO tenant binding fails the tenant-checked verification -> 404
            tok_no_tenant = sign(uuid.UUID(str(expA_pdf)), None, signing_secret)
            st, body, _, _ = retrieve(api_a, expA_pdf, tok_no_tenant)
            rec("SD12", st == 404 and denied_no_content(st, body),
                desc="a legacy token with no tenant binding fails the tenant-checked redemption -> 404",
                category="signed-denial", route="GET /signed/report-exports/{id}", tenant=AA,
                actor="no-tenant-binding token", expected="404", db_post="-", audit_post="no download", extra={"status": st})

            # =====================================================================================
            # PART M -- EXPIRY BOUNDARY (test-controlled exp; no long sleeps)
            # =====================================================================================
            # TM01: comfortably-valid future exp -> 200
            st, content, _, _ = retrieve(api_a, expA_pdf, sign(uuid.UUID(str(expA_pdf)), A["tenant_id"], signing_secret, ttl=900))
            rec("TM01", st == 200 and content, desc="valid future exp (ttl=900s) -> 200",
                category="signed-time", route="GET /signed/report-exports/{id}", tenant=AA, actor="valid token",
                expected="200", db_post="-", audit_post="report_export.download", extra={"status": st})

            # TM02: near-future exp, retrieved immediately (now < exp) -> 200 (just-inside boundary, no sleep)
            st, content, _, _ = retrieve(api_a, expA_pdf, sign(uuid.UUID(str(expA_pdf)), A["tenant_id"], signing_secret, ttl=3))
            rec("TM02", st == 200 and content, desc="near-future exp (ttl=3s) retrieved immediately -> 200 (just inside)",
                category="signed-time", route="GET /signed/report-exports/{id}", tenant=AA, actor="near-valid token",
                expected="200", db_post="-", audit_post="report_export.download", extra={"status": st})

            # TM03: just-expired exp (exp strictly in the past) -> 403 (just-outside boundary, deterministic)
            st, body, _, _ = retrieve(api_a, expA_pdf, sign(uuid.UUID(str(expA_pdf)), A["tenant_id"], signing_secret, ttl=-1))
            rec("TM03", st == 403, desc="just-expired exp (ttl=-1s) -> 403 (boundary is exp>=now inclusive)",
                category="signed-time", route="GET /signed/report-exports/{id}", tenant=AA, actor="just-expired token",
                expected="403", db_post="-", audit_post="no download", extra={"status": st})

            # TM04: long-expired exp -> 403
            st, body, _, _ = retrieve(api_a, expA_pdf, sign(uuid.UUID(str(expA_pdf)), A["tenant_id"], signing_secret, ttl=-3600))
            rec("TM04", st == 403, desc="long-expired exp (ttl=-3600s) -> 403",
                category="signed-time", route="GET /signed/report-exports/{id}", tenant=AA, actor="long-expired token",
                expected="403", db_post="-", audit_post="no download", extra={"status": st})

            # =====================================================================================
            # PART N -- IDEMPOTENCY CONTRACT (export/signed-url are NOT idempotency-key-gated)
            # =====================================================================================
            # ID01: export requires NO Idempotency-Key (unlike corrections/validation) -> 200 without one;
            #       and re-export is content-idempotent (verified in EXR06). Contract: key not required.
            x0 = xcount(AA)
            s, body = export(api_a, a1, rU, "csv")  # no Idempotency-Key header sent at all
            rec("ID01", s == 200 and isinstance(body, dict) and body.get("id") == export_ids.get("csv") and xcount(AA) == x0,
                desc="export requires NO Idempotency-Key (content-idempotent); a keyless re-export returns the stored export",
                category="idempotency-contract", route="POST /monday-reports/{id}/exports/csv", tenant=AA,
                actor="exp-a verified #1", expected="200 (no key required)", db_post="report_exports+0",
                audit_post="monday_report.export_reused", extra={"status": s, "export_idempotency_key_required": False})

            # ID02: signed-URL mint requires NO Idempotency-Key and is stateless -> two mints, two usable tokens
            s1, m1 = mint(api_a, a1, expA_pdf)
            s2, m2 = mint(api_a, a1, expA_pdf)
            t1 = m1.get("url", "").split("token=", 1)[-1] if isinstance(m1, dict) else None
            t2 = m2.get("url", "").split("token=", 1)[-1] if isinstance(m2, dict) else None
            for t in (t1, t2):
                if t:
                    LEAK_TERMS.append(t)
            LEAK_TERMS[:] = sorted({t for t in LEAK_TERMS if t}, key=len, reverse=True)
            r1 = retrieve(api_a, expA_pdf, t1)[0] if t1 else None
            r2 = retrieve(api_a, expA_pdf, t2)[0] if t2 else None
            rec("ID02", s1 == 200 and s2 == 200 and r1 == 200 and r2 == 200,
                desc="signed-URL mint requires NO Idempotency-Key and is stateless -> two independent, usable tokens",
                category="idempotency-contract", route="POST /report-exports/{id}/signed-url", tenant=AA,
                actor="exp-a verified #1", expected="two 200 mints, both retrievable", db_post="stateless",
                audit_post="two report_export.signed_url", extra={"mint1": s1, "mint2": s2, "get1": r1, "get2": r2,
                                                                   "signed_url_idempotency_key_required": False})

            # =====================================================================================
            # PART O -- AUDIT INTEGRITY + SECRET SCAN
            # =====================================================================================
            def integrity(env):
                sv = {k: os.environ.get(k) for k in env}
                os.environ.update(env)
                try:
                    st = store_mod.create_store(); st.refresh()
                    it = st.audit_integrity_status()
                    return (it.integrity_state, it.broken_events)
                finally:
                    for k, v in sv.items():
                        (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))

            state, broken = integrity(A["env"])
            rec("AU01", state == "keyed_valid" and broken == 0,
                desc="tenant-A audit chain over all export/signed mutations verifies keyed_valid, 0 broken",
                category="audit-integrity", route="-", tenant=AA, actor="verifier", expected="keyed_valid",
                db_post="-", audit_post="keyed_valid, broken=0", level="direct component integration",
                extra={"state": state, "broken": broken})

            # AU02: for a successful export the boundary-use event PRECEDES the business event
            _au02 = ("select "
                     "(select min(ord) from " + STATE_TABLE + " s2, "
                     "jsonb_array_elements(s2.payload->'audit_logs') with ordinality e2(v,ord) "
                     "where e2.v->>'action'=%s and e2.v->'metadata'->>'operation'=%s), "
                     "(select min(ord) from " + STATE_TABLE + " s3, "
                     "jsonb_array_elements(s3.payload->'audit_logs') with ordinality e3(v,ord) "
                     "where e3.v->>'action'=%s and e3.v->>'resource_id'=%s)")
            row = _q(AA, _au02, (BND, "monday_report.export", "monday_report.export", str(rU)))
            bnd_ord, biz_ord = (row[0], row[1]) if row else (None, None)
            rec("AU02", bnd_ord is not None and biz_ord is not None and bnd_ord < biz_ord,
                desc="durable ordering: the export boundary-use event precedes the export business event",
                category="audit-integrity", route="-", tenant=AA, actor="verifier", expected="boundary before business",
                db_post="-", audit_post="bnd_ord<biz_ord", level="live PostgreSQL verification",
                extra={"bnd_ord": bnd_ord, "biz_ord": biz_ord})

            # AU03: signed_url mint + download audits are present and boundary-paired for the export
            rec("AU03", biz(AA, "report_export.signed_url", expA_pdf) >= 1
                and biz(AA, "report_export.download", expA_pdf) >= 1 and bnd(AA, "monday_report.export") >= 1,
                desc="signed_url mint + download audits present; export business events are boundary-paired",
                category="audit-integrity", route="-", tenant=AA, actor="verifier",
                expected="mint+download+boundary present", db_post="-",
                audit_post="signed_url, download, boundary(monday_report.export)", level="live PostgreSQL verification",
                extra={"signed_url": biz(AA, "report_export.signed_url", expA_pdf),
                       "download": biz(AA, "report_export.download", expA_pdf),
                       "export_boundary": bnd(AA, "monday_report.export")})

            # AU04: secret scan of the persisted audit (JSONB) -- no signing secret / token / DSN / role / nonce
            blob = audit_blob(AA) + " " + audit_blob(BB)
            leaked = [t for t in LEAK_TERMS if t and t in blob]
            rec("AU04", not leaked,
                desc="persisted audit events carry no signing secret, signed token, DSN, role, or run nonce",
                category="audit-integrity", route="-", tenant=AA, actor="verifier", expected="no leak",
                db_post="-", audit_post="secret-clean", level="live PostgreSQL verification",
                extra={"leaked_kinds": len(leaked)})

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
            tenant="-", actor="-", expected="all ok", db_post="-", audit_post="-",
            level="structural source check", extra={"foundation_fail": sorted(foundation_fail)[:8]})
    if err:
        print("ON_LIVE ERROR:", err.get("type"), file=sys.stderr)
        print(_scrub(err.get("tb", "")), file=sys.stderr)   # scrub DSNs/tokens/secret out of the traceback
        rec("on_live_abort", False, desc=f"on_live aborted with {err.get('type')} (see stderr)",
            category="setup", route="-", tenant="-", actor="-", expected="no abort", db_post="-",
            audit_post="-", level="structural source check")
    return _emit()


# expected check-id inventory (fail-closed if any is missing -> abort cannot masquerade as success)
EXPECTED_IDS = (
    [f"EXU0{i}" for i in range(1, 8)] + ["EXR00"] + [f"EXR0{i}" for i in range(1, 8)]
    + ["WK01", "WK02", "WK03"]
    + [f"EA0{i}" for i in range(1, 10)] + ["EA10", "SRG01"]
    + [f"SR0{i}" for i in range(1, 6)]
    + [f"SD0{i}" for i in range(1, 10)] + ["SD10", "SD11", "SD12"]
    + ["TM01", "TM02", "TM03", "TM04", "ID01", "ID02", "AU01", "AU02", "AU03", "AU04"]
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
    n423 = HTTP_STATUSES.count(423)
    n500 = HTTP_STATUSES.count(500)
    n503 = HTTP_STATUSES.count(503)
    if dup:
        rec("inventory", False, desc=f"duplicate check ids: {dup[:8]}", category="setup", route="-",
            tenant="-", actor="-", expected="unique ids", db_post="-", audit_post="-",
            level="structural source check")
        failed = [c for c in checks if not c["ok"]]
        core = "failed"
    # Fail-closed completeness gate: unless the run was cleanly skipped or already aborted at setup,
    # every expected slice check MUST be present -- a mid-run abort cannot masquerade as success.
    aborted = any(c["check_id"] in ("on_live_abort", "setup-apis", "foundation") for c in checks)
    if missing and not skipped and not aborted:
        rec("completeness", False, desc=f"missing expected slice checks: {missing[:8]}", category="setup",
            route="-", tenant="-", actor="-", expected="all slice checks present", db_post="-",
            audit_post="-", level="structural source check", extra={"missing_count": len(missing)})
        failed = [c for c in checks if not c["ok"]]
        core = "failed"
    if (n423 or n500 or n503) and not skipped:
        rec("http-counters", False, desc="normal functional traffic returned 423/500/503",
            category="setup", route="-", tenant="-", actor="-", expected="0/0/0", db_post="-",
            audit_post="-", level="structural source check",
            extra={"http_423": n423, "http_500": n500, "http_503": n503})
        failed = [c for c in checks if not c["ok"]]
        core = "failed"
    out = {"checks": checks,
           "summary": {"passed": len(passed) if not skipped else 0,
                       "skipped": len(checks) if skipped else 0,
                       "failed": 0 if skipped else len(failed),
                       "execution_level_totals": exec_totals,
                       "claim_scope": "restricted-runtime-exports-signed-references-only",
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
        print("\nExports slice SKIPPED (docker unavailable, non-certifying).")
        return 0
    if failed:
        print(f"\nExports slice FAILED: {len(failed)} check(s).")
        for c in failed:
            print(_scrub(f"  FAIL: {c['check_id']} -> {c.get('description','')} [{c.get('status','')}]"))
        return 1
    print(f"\nExports slice passed: {len(passed)} check(s)."
          "\n[claim_scope=restricted-runtime-exports-signed-references-only; NOT evidence/readiness eligible]")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
