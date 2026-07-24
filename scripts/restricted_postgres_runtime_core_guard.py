"""Restricted-PostgreSQL functional runtime guard -- functional CORE (NOT the complete matrix).

Stands up the ACCEPTED runner-owned stack (via restricted_postgres_startup_guard.run_stack
and its _ON_LIVE hook -- the accepted foundation is unchanged) and drives the REAL client-mode
HTTP API across TWO synthetic tenants (two external uvicorn processes on the same runner-owned
PostgreSQL, RLS-isolated by app.tenant_slug), plus the external worker and the import module, to
prove a CORE slice of the restricted-runtime FUNCTIONAL behaviour: authentication/identity,
field-correction + idempotency (create/replay/changed-body/lost-response), validation-task
transitions (verified-reviewer terminal VALIDATED outcome + idempotent replay + cross-tenant denial),
the report-export validation gate (409 while unresolved, all-format export once resolved, the
client-mode signed-url 409 gate), cross-tenant HTTP isolation, direct RLS negative controls, malware
blocking, audit integrity, worker identity, and the tenant-scoped import env boundary.

NAMING / HONEST SCOPE. This is the functional CORE, deliberately NOT the exhaustive matrix -- so the
command is `audit:restricted-postgres-runtime-core` and the unqualified `audit:restricted-postgres-
runtime` is RESERVED for the future COMPLETE guard. It emits:
  claim_scope = restricted-runtime-functional-core-only
  full_functional_matrix = not_run     (the COMPLETE matrix is NOT run here)
  functional_core = passed|failed
  covered_areas / deferred_areas       (explicit -- no overclaim)
  eligible_for_tenant_evidence = false
  eligible_for_readiness = false
  production_parity = false
  migration_principal_class = test-only-bootstrap-migration-admin
It must NEVER be consumed as tenant-authorization or readiness evidence. Requires Docker.

DEFERRED to the future COMPLETE guard (honest, specific): reject/reopen/conflict validation
transitions and their replays/races; the full idempotency variant matrix (changed-operation/actor/
tenant, stale-revision); correction supersede/revert; the export-OVERRIDE path and full tenant-A/
tenant-B export matrix; signed-reference SUCCESSFUL retrieval + tamper/expiry/substitution + secret
scan; the complete cross-tenant HTTP matrix; the expanded direct-RLS matrix (INSERT/UPDATE/DELETE
per protected table, per-txn/rollback/pool GUC clearing); the complete worker tenant-isolation
matrix; the complete import assess/dry-run/execute/verify matrix. The non-vacuity mutation battery
for this core is audit:restricted-postgres-runtime-core-faults.
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

BND = "client_data.verification_isolation_execution"
checks: list[dict] = []
# High-entropy run secrets (nonces, DSNs, roles, db, container names, token). Populated once
# the live ctx is known; the final emitted JSON is scrubbed against these so no check detail --
# present or future -- can leak a nonce/DSN/role/container-id/credential into the verdict.
LEAK_TERMS: list[str] = []


def _scrub(text: str) -> str:
    for term in LEAK_TERMS:
        if term:
            text = text.replace(term, "<redacted>")
    return text


COVERED = ["auth-identity(core)", "corrections-idempotency(create/replay/changed-body/lost-response)",
           "validation-transition(validated-terminal+replay+cross-tenant)",
           "report-export-gate(409+all-format+signed-url-409)", "cross-tenant-http(core)",
           "rls-direct(read+cross-tenant-write)", "malware", "audit-integrity",
           "worker-identity", "import-env-boundary"]
# Deferred to the future COMPLETE guard (`audit:restricted-postgres-runtime`). Explicit + specific.
DEFERRED = ["validation-reject/reopen/conflict-transitions+replays+races",
            "idempotency-variants(changed-operation/actor/tenant, stale-revision)",
            "correction-supersede/revert",
            "export-override-path+full-tenant-A/B-export-matrix",
            "signed-reference-successful-retrieval+tamper/expiry/substitution+secret-scan",
            "complete-cross-tenant-HTTP-matrix", "expanded-direct-RLS-matrix(INSERT/UPDATE/DELETE+GUC-lifecycle)",
            "complete-worker-tenant-isolation-matrix", "complete-import-assess/dry-run/execute/verify-matrix",
            "functional-mutation-battery(audit:restricted-postgres-runtime-core-faults)"]
# The full functional-matrix inventory. A clean run records exactly these; a missing id means a
# check silently did not run (partial matrix) and _emit fails closed rather than reading "passed".
EXPECTED_CHECK_IDS = [
    "RT01", "RT02", "RT03", "RT04", "RT07", "RT08",              # auth/identity
    "RT10", "RT11", "RT12", "RT13",                              # corrections + idempotency
    "RT14", "RT15", "RT16", "RT17", "RT18", "RT19",              # validation transitions
    "RT41", "RT42", "RT43",                                      # export gate
    "RT20", "RT21", "RT22",                                      # cross-tenant HTTP
    "RT30", "RT31", "RT32", "RT33",                              # RLS direct
    "RT40",                                                      # malware
    "RT50", "RT51",                                              # audit integrity
    "RT60",                                                      # worker identity
    "RT70",                                                      # import boundary
]


def record(cid, ok, area, detail="", level="live HTTP mutation"):
    checks.append({"id": cid, "ok": bool(ok), "area": area, "execution_level": level, "detail": detail})


def safe(cid, area, fn, level="live HTTP mutation"):
    try:
        ok, detail = fn()
        record(cid, ok, area, detail, level)
    except Exception as exc:  # noqa: BLE001
        # Emit only the exception TYPE (a message may embed a DSN/port/role/path); the full
        # traceback goes to stderr and the final JSON is _scrub-ed against LEAK_TERMS.
        import traceback
        print(f"CHECK {cid} raised: {traceback.format_exc()[-800:]}", file=sys.stderr)
        record(cid, False, area, f"error: {type(exc).__name__}", level)


def _http(method, url, key=None, body=None, idem=None, raw=None, ctype=None):
    headers = {}
    if key:
        headers["X-Monday-Report-Key"] = key
    if idem is not None:
        headers["Idempotency-Key"] = idem
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    elif raw is not None:
        headers["Content-Type"] = ctype or "application/octet-stream"
        data = raw
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
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
        for cid in ["setup"]:
            record(cid, allow_unavailable, "setup",
                   "docker unavailable" if allow_unavailable else "docker required; pass --allow-unavailable",
                   level="structural source check")
        return _emit(skipped=allow_unavailable)

    def on_live(ctx):
        api_a = ctx["api_base"]
        token_a = ctx["token"]
        boot = ctx["boot_dsn"]
        rt = ctx["rt_dsn"]
        base_env = dict(ctx["base_env"])
        run_id, run_hash = ctx["run_id"], ctx["run_hash"]
        rt_role = ctx["rt_role"]
        secrets_list = [run_id, boot, rt, ctx["mig_dsn"], rt_role, ctx["mig_role"], ctx["db"], str(ctx["port"]),
                        f"mr-verif-{run_hash}", f"mr-verif-vol-{run_hash}", token_a]
        # Safety-net scrub set: HIGH-ENTROPY terms only (never the low-entropy port, which could
        # collide with a legitimate numeric detail). Longest-first so a DSN is redacted before the
        # bare db/role substrings it contains.
        LEAK_TERMS[:] = sorted(
            {str(t) for t in [run_id, run_hash, rt_role, ctx["mig_role"], boot, rt, ctx["mig_dsn"],
                              ctx["db"], token_a, f"mr-verif-{run_hash}", f"mr-verif-vol-{run_hash}"] if t},
            key=len, reverse=True)
        legacy_key = base_env["MONDAY_REPORT_API_KEY"]  # shared key -> not a verified reviewer
        import psycopg
        import backend.app.store as store_mod
        from backend.app.schemas import Role as _Role

        # ---------- provision TENANT B (second snapshot) + user + credential ----------
        api_b_port = G._free_loopback_port()
        while api_b_port in (ctx["port"], 8000, 5173):
            api_b_port = G._free_loopback_port()
        b_appname = f"mr-verification-api-b-{run_hash}"
        b_scratch = Path(os.environ.get("TEMP", "/tmp")) / f"mr-rt-b-{run_hash}"
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
        saved = {k: os.environ.get(k) for k in b_env}
        os.environ.update(b_env)
        try:
            store_b = store_mod.create_store()
            ub = store_b.create_user("apiuser-b@verif.test", "API User B", [_Role.ADMIN])
            _, token_b = store_b.create_credential(ub.id)
            tenant_b_id = store_b.tenant.id
            # Add tenant-B's token + both API keys to BOTH the RT51 audit-scan set (secrets_list)
            # and the emit-time safety-net scrub set (they post-date the initial assignments).
            secrets_list.extend([token_b, b_env["MONDAY_REPORT_API_KEY"], legacy_key])
            LEAK_TERMS.extend([token_b, b_env["MONDAY_REPORT_API_KEY"], legacy_key])
            LEAK_TERMS[:] = sorted({t for t in LEAK_TERMS if t}, key=len, reverse=True)
        finally:
            for k, v in saved.items():
                (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))

        # launch API-B (external uvicorn, tenant-B env, restricted runtime login)
        b_child = G._child_env(b_env)
        b_log = open(b_scratch / "api.log", "w")
        api_b_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", str(api_b_port)],
            cwd=str(ROOT), env=b_child, stdout=b_log, stderr=subprocess.STDOUT)
        api_b = f"http://127.0.0.1:{api_b_port}"
        try:
            up_b = False
            for _ in range(40):
                s, _b = _http("GET", f"{api_b}/health")
                if s == 200:
                    up_b = True
                    break
                if api_b_proc.poll() is not None:
                    break
                time.sleep(1)

            # helper: read a tenant's store view (audit + workspaces) as admin-scoped store
            def view(env):
                sv = {k: os.environ.get(k) for k in env}
                os.environ.update(env)
                try:
                    st = store_mod.create_store()
                    st.refresh()
                    return st
                finally:
                    for k, v in sv.items():
                        (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))

            # helper: run fn(store) with the tenant env ACTIVE for the whole call, so
            # env-dependent lookups (audit HMAC key provider -> os.getenv) resolve. view()
            # restores env before returning, which is fine for already-loaded rows but
            # yields key_unavailable for audit_integrity_status() called post-return.
            def view_do(env, fn):
                sv = {k: os.environ.get(k) for k in env}
                os.environ.update(env)
                try:
                    st = store_mod.create_store()
                    st.refresh()
                    return fn(st)
                finally:
                    for k, v in sv.items():
                        (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))

            hA = {"key": token_a}
            # a workspace + a correctable field for tenant A
            _, wsA = _http("POST", f"{api_a}/workspaces", key=token_a, body={"name": "rt-a", "rig_name": "g"})
            wsA_id = wsA["id"] if isinstance(wsA, dict) else None
            _, wsB = _http("POST", f"{api_b}/workspaces", key=token_b, body={"name": "rt-b", "rig_name": "g"})
            wsB_id = wsB["id"] if isinstance(wsB, dict) else None
            _, reg = _http("GET", f"{api_a}/field-corrections/registry", key=token_a)
            f0 = reg[0]
            vt = f0.get("value_type")

            def corr_body(val):
                return {"target_type": f0["target_type"], "field_key": f0["field_key"], "source_value": "S",
                        "corrected_value": ("123" if vt == "numeric_text" else val),
                        "correction_reason": "runtime functional test"}

            def rowsA():
                # DIRECT committed count as the restricted role (RLS-scoped to verif-a), not a
                # create_store projection: a second in-process store lags the live API's refresh
                # generations AND opens an extra snapshot-lock connection against the live tenant.
                # Tenant A has exactly one workspace (wsA), so the tenant-scoped count IS the wsA
                # count -- no workspace_id predicate (avoids a str-vs-uuid cast).
                with psycopg.connect(rt, autocommit=True) as c:
                    c.execute("select set_config('app.tenant_slug', %s, false)", ("verif-a",))
                    return int(c.execute(
                        "select count(*) from monday_report_norm_field_corrections").fetchone()[0])

            # ================= E: AUTH / IDENTITY =================
            safe("RT01 health A + B", "auth-identity",
                 lambda: ((_http("GET", f"{api_a}/health")[0] == 200 and up_b), {"api_b_up": up_b}))
            safe("RT02 valid per-user credential authenticates a read (A + B)", "auth-identity",
                 lambda: ((_http("GET", f"{api_a}/monday-reports", key=token_a)[0] == 200
                           and _http("GET", f"{api_b}/monday-reports", key=token_b)[0] == 200), ""))
            safe("RT03 missing credential denied", "auth-identity",
                 lambda: (_http("GET", f"{api_a}/monday-reports")[0] in (401, 403), ""))
            safe("RT04 invalid credential denied", "auth-identity",
                 lambda: (_http("GET", f"{api_a}/monday-reports", key="not-a-real-token-xxxxxxxx")[0] in (401, 403), ""))
            safe("RT08 legacy shared key rejected in client mode", "auth-identity",
                 lambda: (_http("GET", f"{api_a}/monday-reports", key=legacy_key)[0] in (401, 403), ""))
            safe("RT07 wrong-tenant credential rejected (A key vs API-B)", "auth-identity",
                 lambda: (_http("GET", f"{api_b}/monday-reports", key=token_a)[0] in (401, 403), ""))

            # ================= F/H: CORRECTIONS + IDEMPOTENCY (tenant A) =================
            base_rows = rowsA()
            k1 = str(uuid.uuid4())
            s10, b10 = _http("POST", f"{api_a}/workspaces/{wsA_id}/field-corrections", key=token_a, body=corr_body("A1"), idem=k1)
            cid10 = b10.get("id") if isinstance(b10, dict) else None
            record("RT10 create correction (verified per-user reviewer)",
                   s10 in (200, 201) and rowsA() == base_rows + 1 and bool(cid10),
                   "corrections-idempotency", {"status": s10, "rows": rowsA()})
            s11, _ = _http("POST", f"{api_a}/workspaces/{wsA_id}/field-corrections", key=token_a, body=corr_body("A1"), idem=k1)
            record("RT11 exact replay does not duplicate", s11 in (200, 201) and rowsA() == base_rows + 1,
                   "corrections-idempotency", {"status": s11, "rows": rowsA()})
            s12, _ = _http("POST", f"{api_a}/workspaces/{wsA_id}/field-corrections", key=token_a, body=corr_body("A-DIFFERENT"), idem=k1)
            record("RT12 changed body under same key conflicts (409)", s12 == 409 and rowsA() == base_rows + 1,
                   "corrections-idempotency", {"status": s12})
            # RT13: a FRESH same-key resend (lost-response replay) must return the STORED result
            # (same correction id as RT10) and add NO new row -- a real replay, not a re-read of s11.
            s13, b13 = _http("POST", f"{api_a}/workspaces/{wsA_id}/field-corrections", key=token_a, body=corr_body("A1"), idem=k1)
            cid13 = b13.get("id") if isinstance(b13, dict) else None
            record("RT13 lost-response replay returns the stored result, no duplicate",
                   s13 in (200, 201) and cid13 is not None and cid13 == cid10 and rowsA() == base_rows + 1,
                   "corrections-idempotency", {"status": s13, "same_stored_id": cid13 == cid10})

            # ================= I: MALWARE =================
            def malware():
                eicar = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
                before = len([f for f in view(base_env).files.values() if getattr(f, "malware_status", "") == "blocked"])
                # multipart/form-data for POST /uploads/direct. workspace_id is a REQUIRED
                # Form(...) field (not a query param); the file part carries the EICAR bytes.
                boundary = "----mrguard" + secrets.token_hex(6)
                b = f"--{boundary}".encode()
                payload = (
                    b + b"\r\nContent-Disposition: form-data; name=\"workspace_id\"\r\n\r\n"
                    + str(wsA_id).encode() + b"\r\n"
                    + b + b"\r\nContent-Disposition: form-data; name=\"file\"; filename=\"eicar.txt\"\r\n"
                    + b"Content-Type: text/plain\r\n\r\n" + eicar + b"\r\n"
                    + b + b"--\r\n")
                st, body = _http("POST", f"{api_a}/uploads/direct", key=token_a,
                                 raw=payload, ctype=f"multipart/form-data; boundary={boundary}")
                after = len([f for f in view(base_env).files.values() if getattr(f, "malware_status", "") == "blocked"])
                blocked_audit = sum(1 for e in view(base_env).audit_logs if e.action == "upload.blocked")
                detail = (body.get("detail") if isinstance(body, dict) else None)
                return (st == 422 and after == before + 1 and blocked_audit >= 1,
                        {"status": st, "blocked_delta": after - before, "blocked_audits": blocked_audit,
                         "detail": detail})
            safe("RT40 EICAR -> 422, blocked file row +1, upload.blocked audit", "malware", malware)

            # ================= G: VALIDATION-TASK TRANSITIONS (tenant A) =================
            # A Critical benchmark breach (value below the critical threshold) spawns a
            # Critical anomaly + an OPEN validation task -- the review workflow's real input.
            def crit_measure(api, key, ws):
                return _http("POST", f"{api}/workspaces/{ws}/benchmarking/measurements", key=key,
                             body={"metric": "feet_drilled_per_day", "value": 440, "unit": "ft/day",
                                   "data_source": "runtime guard critical DDR",
                                   "source_identifier": "rt-guard-critical", "moc_reference": "MOC-RT-001"})

            def open_anomaly_task(api, key):
                s, tasks = _http("GET", f"{api}/validation-tasks", key=key)
                if s != 200 or not isinstance(tasks, list):
                    return None
                for t in tasks:
                    if t.get("status") == "open" and t.get("target_type") == "anomaly_event":
                        return t.get("id")
                return None

            sMA, _ = crit_measure(api_a, token_a, wsA_id)
            crit_measure(api_b, token_b, wsB_id)  # tenant-B task for the cross-tenant control
            taskA = open_anomaly_task(api_a, token_a)
            taskB = open_anomaly_task(api_b, token_b)
            record("RT14 Critical benchmark breach spawns an OPEN anomaly validation task",
                   sMA in (200, 201) and bool(taskA), "validation-transition",
                   {"measure_status": sMA, "task_present": bool(taskA)})

            # RT15 unauthenticated validation mutation denied (task stays OPEN)
            s15, _ = _http("PATCH", f"{api_a}/validation-tasks/{taskA}", body={"status": "validated"})
            record("RT15 unauthenticated validation PATCH denied", s15 in (401, 403),
                   "validation-transition", {"status": s15})

            # RT16 cross-tenant: tenant-A reviewer PATCH against a REAL tenant-B task id -> 404
            # (invisible). Require taskB to actually exist, else this is not a cross-tenant test.
            s16, _ = _http("PATCH", f"{api_a}/validation-tasks/{taskB}", key=token_a,
                           body={"status": "validated"}, idem=str(uuid.uuid4()))
            record("RT16 cross-tenant validation PATCH denied (B task invisible to A)",
                   bool(taskB) and s16 in (403, 404),
                   "validation-transition", {"status": s16, "taskB_present": bool(taskB)})

            # ================= I: EXPORT VALIDATION GATE (tenant A) =================
            # Create a report; while the Critical validation task is OPEN, export is blocked (409).
            _, rep = _http("POST", f"{api_a}/monday-reports", key=token_a,
                           body={"workspace_id": str(wsA_id), "period_start": "2026-07-01", "period_end": "2026-07-07"})
            report_id = rep.get("id") if isinstance(rep, dict) else None
            sXgate, _ = _http("POST", f"{api_a}/monday-reports/{report_id}/exports/json", key=token_a)
            record("RT41 export blocked with 409 while a validation task is OPEN",
                   sXgate == 409 and bool(report_id), "report-export-gate", {"status": sXgate})

            # RT17 verified per-user reviewer validates the OPEN task -> 200, terminal VALIDATED
            k17 = str(uuid.uuid4())
            s17, body17 = _http("PATCH", f"{api_a}/validation-tasks/{taskA}", key=token_a,
                                body={"status": "validated", "resolution_note": "runtime functional"}, idem=k17)
            status_after = body17.get("status") if isinstance(body17, dict) else None
            record("RT17 verified reviewer validates the OPEN task (200, terminal VALIDATED)",
                   s17 in (200, 201) and status_after == "validated", "validation-transition",
                   {"status": s17, "task_status": status_after})

            # RT18 idempotent replay of the terminal transition -> stored result, no second audit
            def validate_audits():
                return sum(1 for e in view(base_env).audit_logs
                           if e.action == "validation_task.update" and str(e.resource_id) == str(taskA))
            audits_before = validate_audits()
            s18, _ = _http("PATCH", f"{api_a}/validation-tasks/{taskA}", key=token_a,
                           body={"status": "validated", "resolution_note": "runtime functional"}, idem=k17)
            record("RT18 idempotent validation replay returns stored result, no double transition",
                   s18 in (200, 201) and validate_audits() == audits_before, "validation-transition",
                   {"status": s18, "audits": validate_audits()})

            # RT19 terminal transition records a VERIFIED reviewer + a sealed audit
            def review_attr():
                def compute(st):
                    ev = [e for e in st.audit_logs if e.action == "validation_task.update"
                          and str(e.resource_id) == str(taskA) and (e.metadata or {}).get("to") == "validated"]
                    tsk = st.validation_tasks.get(uuid.UUID(taskA)) if taskA else None
                    verified = bool(ev) and ev[-1].metadata.get("reviewer_verified") is True
                    attributed = bool(tsk) and getattr(tsk, "reviewer_credential_fingerprint", None) is not None \
                        and getattr(tsk, "reviewer_actor_source", None) == "authenticated"
                    return (verified and attributed,
                            {"audit_reviewer_verified": verified, "task_attributed": attributed})
                return view_do(base_env, compute)
            safe("RT19 terminal validation records a verified reviewer + sealed audit",
                 "validation-transition", review_attr, level="direct component integration")

            # RT42 once validation is resolved, export succeeds (200) for every format -> ReportExport
            def export_ok():
                results = {}
                for fmt in ("json", "csv", "html", "pdf", "xlsx"):
                    s, _b = _http("POST", f"{api_a}/monday-reports/{report_id}/exports/{fmt}", key=token_a)
                    results[fmt] = s
                return (all(s in (200, 201) for s in results.values()), {"formats": results})
            safe("RT42 export succeeds for all formats once validation is resolved",
                 "report-export-gate", export_ok)

            # RT43 signed-url GATE. This foundation configures NO signing secret, so client mode gates
            # signed-url issuance at 409 and mints NO URL (main.py: signing_secret_configured() ->
            # 409) -- a real client-data-safety behavior. Asserting the 409 + no-URL is non-vacuous
            # (the 200 branch + its secret-scan is DEFERRED: it needs a signing secret in the stack,
            # which is the accepted foundation's env and out of scope here).
            def signed_url_gate():
                s, b = _http("POST", f"{api_a}/monday-reports/{report_id}/exports/json", key=token_a)
                export_id = b.get("id") if isinstance(b, dict) else None
                s2, b2 = _http("POST", f"{api_a}/report-exports/{export_id}/signed-url", key=token_a, body={})
                url = b2.get("url") if isinstance(b2, dict) else None
                return (bool(export_id) and s2 == 409 and not url,
                        {"export_created": bool(export_id), "status": s2, "url_minted": bool(url)})
            safe("RT43 signed-url gated in client mode without a signing secret (409, no URL minted)",
                 "report-export-gate", signed_url_gate)

            # ================= J: CROSS-TENANT HTTP =================
            safe("RT20 tenant-A API cannot create a correction against a tenant-B workspace id", "cross-tenant-http",
                 lambda: (_http("POST", f"{api_a}/workspaces/{wsB_id}/field-corrections", key=token_a,
                                body=corr_body("x"), idem=str(uuid.uuid4()))[0] in (403, 404), {"wsB": str(wsB_id)}))
            safe("RT21 tenant-A API cannot read a tenant-B workspace's corrections", "cross-tenant-http",
                 lambda: (_http("GET", f"{api_a}/workspaces/{wsB_id}/field-corrections", key=token_a)[0] in (403, 404), ""))
            def spoof():
                # a tenant header/body cannot change the process tenant; the request still
                # resolves tenant A and cannot reach tenant-B's workspace.
                req = urllib.request.Request(f"{api_a}/workspaces/{wsB_id}/field-corrections", method="GET",
                                             headers={"X-Monday-Report-Key": token_a,
                                                      "X-Tenant-Id": str(tenant_b_id), "X-Tenant-Slug": "verif-b"})
                try:
                    with urllib.request.urlopen(req, timeout=15) as r:
                        st = r.status
                except urllib.error.HTTPError as e:
                    st = e.code
                except Exception:
                    st = None
                return (st in (403, 404), {"status": st})
            safe("RT22 tenant spoof via header is ignored (still denied)", "cross-tenant-http", spoof,
                 level="live HTTP mutation")

            # ================= K: RLS DIRECT NEGATIVE CONTROLS =================
            def rls_scope(slug):
                with psycopg.connect(rt, autocommit=True) as c:
                    c.execute("select set_config('app.tenant_slug', %s, false)", (slug,))
                    return c.execute("select count(*) from monday_report_state_snapshots").fetchone()[0]
            def rls_invalid(slug):
                with psycopg.connect(rt, autocommit=True) as c:
                    if slug is not None:
                        c.execute("select set_config('app.tenant_slug', %s, false)", (slug,))
                    return c.execute("select count(*) from monday_report_state_snapshots").fetchone()[0]
            safe("RT30 RLS: slug=verif-a sees only tenant-A snapshot (exactly 1)", "rls-direct",
                 lambda: (int(rls_scope("verif-a")) == 1, {"rows": rls_scope("verif-a")}), level="live PostgreSQL mutation")
            safe("RT31 RLS: slug=verif-b sees only tenant-B snapshot (exactly 1)", "rls-direct",
                 lambda: (int(rls_scope("verif-b")) == 1, {"rows": rls_scope("verif-b")}), level="live PostgreSQL mutation")
            safe("RT32 RLS: invalid slug -> 0 rows (fail closed)", "rls-direct",
                 lambda: (int(rls_invalid("does-not-exist")) == 0, ""), level="live PostgreSQL mutation")
            def rls_write():
                # USING/WITH CHECK: as slug A, try to update tenant B's snapshot row. RLS
                # hides B's row under slug A, so the UPDATE affects exactly 0 rows. Read the
                # affected count from the CURSOR (Connection.execute returns a Cursor;
                # Connection has no .rowcount). A control update of A's OWN row must affect 1,
                # proving the 0 is RLS isolation, not a no-op predicate.
                with psycopg.connect(rt, autocommit=True) as c:
                    c.execute("select set_config('app.tenant_slug', %s, false)", ("verif-a",))
                    cross = c.execute(
                        "update monday_report_state_snapshots set updated_at=now() where tenant_slug='verif-b'").rowcount
                    own = c.execute(
                        "update monday_report_state_snapshots set updated_at=now() where tenant_slug='verif-a'").rowcount
                    return (cross == 0 and own == 1,
                            {"cross_tenant_rows": cross, "own_tenant_rows": own})
            safe("RT33 RLS WITH CHECK/USING blocks cross-tenant write (0 rows affected)", "rls-direct", rls_write,
                 level="live PostgreSQL mutation")

            # ================= N: AUDIT INTEGRITY =================
            def audit_ok():
                # audit_integrity_status() resolves the HMAC key via os.getenv, so it MUST
                # run with base_env active (view_do), else it fails closed to key_unavailable.
                def compute(st):
                    integ = st.audit_integrity_status()
                    bnd = [e for e in st.audit_logs if e.action == BND and (e.metadata or {}).get("operation") == "field_correction.record"]
                    biz = [e for e in st.audit_logs if e.action == "field_correction.record"]
                    actor_tenant_ok = bool(bnd) and bnd[0].tenant_id == st.tenant.id
                    return (integ.integrity_state == "keyed_valid" and integ.broken_events == 0
                            and bool(bnd) and bool(biz) and actor_tenant_ok,
                            {"state": integ.integrity_state, "broken": integ.broken_events,
                             "boundary_events": len(bnd), "business_events": len(biz)})
                return view_do(base_env, compute)
            safe("RT50 audit chain keyed_valid + boundary-use & business audit for the mutation", "audit-integrity",
                 audit_ok, level="direct component integration")
            def secret_scan():
                st = view(base_env)
                blob = json.dumps([{"a": e.action, "m": e.metadata} for e in st.audit_logs], default=str)
                leaked = [s for s in secrets_list if s and s in blob]
                return (not leaked and run_id not in blob, {"leaked_kinds": len(leaked)})
            safe("RT51 audit events carry no nonce/DSN/role/docker-id/credential", "audit-integrity",
                 secret_scan, level="direct component integration")

            # ================= L: WORKER IDENTITY =================
            def worker_identity():
                w_appname = f"mr-verification-rt-worker-{run_hash}"
                w_env = G._child_env({**b_env, "MONDAY_REPORT_DATABASE_URL": f"{rt}?application_name={w_appname}",
                                      "MONDAY_REPORT_TENANT_SLUG": "verif-a",
                                      "MONDAY_REPORT_STATE_PATH": str(b_scratch / "state" / "w.json")})
                lock_key = store_mod.PostgresStateStore._advisory_lock_key()
                leak = G._libpq_leak_keys(w_env)
                has_mig = any("MIGRATIONS_DATABASE_URL" in k for k in w_env)
                with psycopg.connect(boot, autocommit=True) as obs:
                    t0 = obs.execute("select now()").fetchone()[0]
                    obs.execute("select pg_advisory_lock(%s)", (lock_key,))
                    wp = subprocess.Popen([sys.executable, "-m", "backend.app.worker"], cwd=str(ROOT),
                                          env=w_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    try:
                        usename = None
                        for _ in range(120):
                            rows = obs.execute(
                                "select usename from pg_stat_activity where application_name=%s and backend_start>=%s",
                                (w_appname, t0)).fetchall()
                            if rows:
                                usename = rows[0][0]
                                break
                            time.sleep(0.1)
                    finally:
                        obs.execute("select pg_advisory_unlock(%s)", (lock_key,))
                        try:
                            wp.terminate(); wp.wait(timeout=10)
                        except Exception:
                            pass
                # NEVER emit the raw session role name (it embeds the run nonce). Emit the
                # boolean assertion plus a non-reversible fingerprint for failure diagnosis.
                return (usename == rt_role and not leak and not has_mig,
                        {"session_user_is_restricted_runtime_login": usename == rt_role,
                         "session_user_fp8": hashlib.sha256((usename or "").encode()).hexdigest()[:8],
                         "libpq_leak_keys": len(leak), "has_migration_dsn": has_mig})
            safe("RT60 external worker connects as the restricted runtime login; no migration DSN/libpq leak",
                 "worker-identity", worker_identity, level="live worker mutation")

            # ================= M: IMPORT BOUNDARY =================
            def import_assess():
                ie = G._child_env(base_env)
                has_mig = any("MIGRATIONS_DATABASE_URL" in k for k in ie)
                p = subprocess.run([sys.executable, "-m", "backend.app.normalized_import", "assess"],
                                   cwd=str(ROOT), env=ie, capture_output=True, text=True, timeout=120)
                out = (p.stdout + p.stderr)
                leaked = any(s and s in out for s in secrets_list if s != ctx["db"])
                # Require SUCCESS (exit 0) AND a structured tenant-scoped assessment (JSON dict), not
                # merely a clean error -- so a working import is distinguished from one that fails.
                parsed = None
                for cand in (p.stdout.strip(), (p.stdout.strip().splitlines() or [""])[-1]):
                    try:
                        parsed = json.loads(cand); break
                    except Exception:
                        parsed = None
                assess_json = isinstance(parsed, dict) and len(parsed) > 0
                # Emit only field-name keys (never values, which could carry the db name); the final
                # JSON _scrub is a further backstop.
                return (p.returncode == 0 and assess_json and not has_mig and not leaked,
                        {"exit": p.returncode, "assess_json": assess_json, "has_migration_dsn": has_mig,
                         "leaked": leaked, "keys": sorted(parsed.keys())[:6] if isinstance(parsed, dict) else None})
            safe("RT70 import 'assess' runs external (exit 0, tenant-scoped JSON); no migration DSN; no secret leak",
                 "import-boundary", import_assess, level="live process/session mutation")

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
    G._ON_LIVE = on_live
    err = {}
    def wrapped(ctx):
        try:
            on_live(ctx)
        except Exception as exc:  # noqa: BLE001
            import traceback
            # Only the exception TYPE reaches the certifying JSON output; the full message
            # (which may embed a DSN/path) stays on stderr, never in the emitted verdict.
            err["type"] = type(exc).__name__
            err["msg"] = f"{type(exc).__name__}: {str(exc)[:160]}"
            err["tb"] = traceback.format_exc()[-1600:]
    G._ON_LIVE = wrapped
    try:
        G.run_stack()
    finally:
        G._ON_LIVE = None
    # F6: the functional narrative ("real API on a restricted, RLS-isolated login") rests on a
    # healthy stack. run_stack() raises only on HARD failures; a SOFT-failed foundation check
    # records False without raising. Fail closed if any foundation check is not ok.
    foundation_fail = [c["id"] for c in getattr(G, "checks", []) if not c.get("ok", True) and not c.get("skipped", False)]
    if foundation_fail:
        record("foundation", False, "setup",
               f"foundation checks not ok: {sorted(foundation_fail)[:8]}", level="structural source check")
    # F1: an on_live abort AFTER some checks already recorded must NOT read as passed. Record a
    # failure UNCONDITIONALLY (not only when zero checks ran) so _emit -> core=failed / exit 1.
    if err:
        print("ON_LIVE ERROR:", err.get("msg"), file=sys.stderr)
        print(err.get("tb", ""), file=sys.stderr)
        record("on_live_abort", False, "setup",
               f"functional on_live aborted with {err.get('type')} after {len(checks)} checks (see stderr)",
               level="structural source check")
    # F1 (count gate): a partial matrix with zero failures must not read as passed. Require the
    # full expected check-id set; a missing id is a failure (unless the whole run was skipped).
    expected_ids = {c.split()[0] for c in EXPECTED_CHECK_IDS}
    present_ids = {c["id"].split()[0] for c in checks}
    missing = sorted(expected_ids - present_ids)
    if missing and not err:
        record("coverage", False, "setup",
               f"expected checks missing (partial matrix): {missing[:12]}", level="structural source check")
    return _emit()


def _emit(skipped=False) -> int:
    passed = [c for c in checks if c["ok"]]
    failed = [c for c in checks if not c["ok"]]
    core = "passed" if (checks and not failed and not skipped) else ("skipped" if skipped else "failed")
    exec_totals = {}
    for c in checks:
        exec_totals[c["execution_level"]] = exec_totals.get(c["execution_level"], 0) + 1
    enriched = [{**c, "claim_scope": "restricted-runtime-functional-core-only"} for c in checks]
    # _scrub the ENTIRE emitted verdict as a safety net: no nonce/DSN/role/db/token/container-id
    # can reach stdout even if a check detail accidentally carried one.
    print(_scrub(json.dumps({"checks": enriched,
                      "summary": {"passed": len(passed) if not skipped else 0,
                                  "skipped": len(checks) if skipped else 0,
                                  "failed": 0 if skipped else len(failed),
                                  "execution_level_totals": exec_totals,
                                  "claim_scope": "restricted-runtime-functional-core-only",
                                  "full_functional_matrix": "not_run",
                                  "functional_core": core,
                                  "covered_areas": COVERED,
                                  "deferred_areas": DEFERRED,
                                  "eligible_for_tenant_evidence": False,
                                  "eligible_for_readiness": False,
                                  "production_parity": False,
                                  "migration_principal_class": "test-only-bootstrap-migration-admin"}},
                     indent=2, default=str)))
    if skipped:
        print("\nRestricted-runtime functional guard SKIPPED (docker unavailable, non-certifying).")
        return 0
    if failed:
        print(f"\nRestricted-runtime functional CORE FAILED: {len(failed)} check(s).")
        for c in failed:
            print(_scrub(f"  FAIL: {c['id']} -> {c['detail']}"))
        return 1
    print(f"\nRestricted-runtime functional CORE passed: {len(passed)} check(s)."
          "\n[claim_scope=restricted-runtime-functional-core-only; full matrix NOT run; NOT evidence/readiness eligible]")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
