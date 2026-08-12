"""Restricted-PostgreSQL functional slice: external worker + import boundary (Outcome-1 slice 4).

A NARROW slice guard (NOT the complete functional matrix; NOT the accepted foundation/startup/boundary/
core/mutations/exports/isolation guards). Built on the ACCEPTED restricted-PostgreSQL foundation
(restricted_postgres_startup_guard.run_stack + _ON_LIVE, byte-unchanged). It provisions TWO synthetic
worker tenants and TWO synthetic import tenants on one runner-owned PostgreSQL, then drives the REAL
external OS entrypoints -- `python -m backend.app.worker` and `python -m backend.app.normalized_import
{assess|dry-run|execute|verify}` -- as separate processes connecting with the RESTRICTED runtime LOGIN,
to prove:

  * WORKER (one-shot, single-tenant-per-process): process authenticity + env-hygiene (production module,
    distinct child PID, restricted DSN only, no migration/bootstrap DSN, libpq stripped, no local
    fallback); live database identity via pg_stat_activity (session_user = restricted LOGIN, non-superuser,
    non-BYPASSRLS, non-owner, group member, unique application_name, backend_start after launch);
    tenant-A and tenant-B success with direct committed-SQL postconditions and cross-tenant non-alteration;
    PROCESS-BOUNDARY failure/recovery isolation (a tenant-A job failure never contaminates a separate
    tenant-B worker process); operator re-queue retry stays with the original tenant; fail-closed refusal
    on a missing audit key with zero mutation; the tenant/actor are derived from trusted env, never a job
    payload; audit integrity + a secret scan.
  * IMPORT (external operator cutover tool): assess/dry-run are read-only (zero rows changed); execute is a
    single-transaction, idempotent (marker -> degrades), refuse-on-conflict cutover; verify is
    authoritative (marker counts + id digests vs tenant-scoped rows); the tenant selector is env, never a
    payload; a foreign tenant_id / cross-tenant id-reuse payload is REFUSED; wrong-digest / wrong-tenant /
    post-execute tampering fail verify; the import runs as the restricted login (no RLS/FORCE disable, no
    superuser path, no migration DSN).

The worker/import are NEVER executed in-process (no TestClient, no run_once() in the guard interpreter, no
guard-owned thread, no in-process import function). All postconditions are direct committed SQL. Raw job
payloads, credentials, DSNs, keys, role names, PIDs, and digests are never printed.

HONEST SCOPE. It emits:
  claim_scope = restricted-runtime-worker-import-only
  full_functional_matrix = not_run
  eligible_for_tenant_evidence = false / eligible_for_readiness = false / production_parity = false
  migration_principal_class = test-only-bootstrap-migration-admin
It must NEVER be consumed as tenant-authorization or readiness evidence. Requires Docker.

The worker is SINGLE-TENANT-PER-PROCESS and ONE-SHOT: isolation between tenants is PROCESS-BOUNDARY
isolation (separate external worker processes), NOT same-process A->B context switching -- described
honestly throughout.

DEFERRED to later work: tenant evidence v3, readiness-evaluator changes, four readiness contexts, UI
certification, and the final aggregate audit:restricted-postgres-runtime command.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
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
# controlled-negative results (expected non-zero exits) are counted SEPARATELY from normal failures
COUNTERS = {"normal_worker_process_failures": 0, "normal_import_process_failures": 0,
            "controlled_worker_negatives": 0, "controlled_import_negatives": 0,
            "normal_functional_http_423": 0, "normal_functional_http_500": 0, "normal_functional_http_503": 0}


def _scrub(text: str) -> str:
    for term in LEAK_TERMS:
        if term:
            text = text.replace(str(term), "<redacted>")
    return text


def _fp(s: str) -> str:
    return hashlib.sha256(str(s).encode("utf-8")).hexdigest()[:32]  # >=128-bit, non-reversible


def rec(cid, ok, *, desc, category, proc, tenant, principal, job, expected, db_post, audit_post,
        level="whole-stack worker mutation", extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "category": category, "process": proc, "tenant": tenant,
                   "principal": principal, "job_or_import": job, "expected": expected,
                   "db_postcondition": db_post, "audit_postcondition": audit_post,
                   "execution_level": level, **(extra or {})})


def env_hygiene(child_env, *, rt, boot, mig_dsn, mig_role):
    """The worker/import child-env hygiene predicate (module-scope so the fault battery tests the ACTUAL
    function, not a copy): only the restricted runtime DSN, no migration/bootstrap DSN, no libpq leak,
    no local fallback backend."""
    dsn = child_env.get("MONDAY_REPORT_DATABASE_URL", "")
    return {"restricted_dsn_only": rt in dsn and boot not in dsn,
            "no_migration_dsn": mig_dsn not in dsn and mig_role not in " ".join(str(v) for v in child_env.values()),
            "no_libpq_leak": G._no_libpq_leak(child_env),
            "no_local_fallback": child_env.get("MONDAY_REPORT_REPOSITORY_BACKEND") == "postgres"}


def run() -> int:
    allow_unavailable = "--allow-unavailable" in sys.argv
    if G._docker(["info"]).returncode != 0:
        rec("setup", allow_unavailable, desc="docker availability", category="setup", proc="-", tenant="-",
            principal="-", job="-", expected="docker", db_post="-", audit_post="-",
            level="structural source check")
        return _emit(skipped=allow_unavailable)

    def on_live(ctx):
        import psycopg
        import backend.app.store as store_mod
        from backend.app.schemas import (Role as _Role, WorkspaceCreate, FieldCorrection, MondayReport,
                                         ValidationTask)

        boot, rt = ctx["boot_dsn"], ctx["rt_dsn"]
        rt_role, mig_role = ctx["rt_role"], ctx["mig_role"]
        base_env = dict(ctx["base_env"])
        run_hash = ctx["run_hash"]
        _tmp_base = str(Path(os.environ.get("TEMP", "/tmp")))
        LEAK_TERMS[:] = sorted({str(t) for t in [ctx["run_id"], run_hash, rt_role, mig_role, boot, rt,
                                                 ctx["mig_dsn"], ctx["db"], ctx["token"],
                                                 base_env["MONDAY_REPORT_API_KEY"],
                                                 base_env.get("MONDAY_REPORT_AUDIT_HMAC_KEY"),
                                                 str(ROOT), _tmp_base] if t}, key=len, reverse=True)
        scratches: list[Path] = []

        # ---------------- direct committed-SQL surfaces (boot = superuser reader; rt = restricted) --------
        def boot_q(sql, params=()):
            with psycopg.connect(boot, autocommit=True) as c:
                return c.execute(sql, params).fetchone()

        def boot_all(sql, params=()):
            with psycopg.connect(boot, autocommit=True) as c:
                return c.execute(sql, params).fetchall()

        def snap(slug):
            def j(status):
                return int(boot_q(f"select count(*) from {STATE_TABLE} s, jsonb_array_elements(s.payload->'jobs') e "
                                  "where s.tenant_slug=%s and e->>'status'=%s", (slug, status))[0])
            rev = boot_q(f"select revision from {STATE_TABLE} where tenant_slug=%s", (slug,))
            docs = boot_q(f"select coalesce(jsonb_array_length(payload->'parsed_documents'),0) "
                          f"from {STATE_TABLE} where tenant_slug=%s", (slug,))
            return {"rev": int(rev[0]) if rev else -1, "queued": j("queued"), "complete": j("complete"),
                    "failed": j("failed"), "docs": int(docs[0]) if docs else 0}

        def audit_count(slug, action):
            return int(boot_q(f"select count(*) from {STATE_TABLE} s, jsonb_array_elements(s.payload->'audit_logs') e "
                              "where s.tenant_slug=%s and e->>'action'=%s", (slug, action))[0])

        def norm_count(slug, table):
            return int(boot_q(f"select count(*) from {table} where tenant_slug=%s", (slug,))[0])

        def child(env):
            return G._child_env(env)

        # ---------------- provisioning: worker tenants (create_store, in-process SETUP only) --------------
        def prov_env(slug):
            scratch = Path(_tmp_base) / f"mr-wi-{slug}-{run_hash}"
            for sub in ("state", "storage", "exports"):
                (scratch / sub).mkdir(parents=True, exist_ok=True)
            scratches.append(scratch)
            env = dict(base_env)
            env.update({
                "MONDAY_REPORT_DATABASE_URL": f"{rt}?application_name=mr-wi-{slug}-{run_hash}",
                "MONDAY_REPORT_TENANT_SLUG": slug, "MONDAY_REPORT_TENANT_NAME": f"WI {slug}",
                "MONDAY_REPORT_USER_EMAIL": f"user@{slug}.test", "MONDAY_REPORT_USER_FULL_NAME": f"WI {slug}",
                "MONDAY_REPORT_STATE_PATH": str(scratch / "state" / "s.json"),
                "MONDAY_REPORT_STORAGE_ROOT": str(scratch / "storage"),
                "MONDAY_REPORT_EXPORT_ROOT": str(scratch / "exports"),
                "MONDAY_REPORT_API_KEY": secrets.token_urlsafe(24),
            })
            LEAK_TERMS.append(env["MONDAY_REPORT_API_KEY"])
            LEAK_TERMS[:] = sorted({t for t in LEAK_TERMS if t}, key=len, reverse=True)
            return env, scratch

        def provision_worker(slug, n_uploads):
            env, scratch = prov_env(slug)
            sv = {k: os.environ.get(k) for k in env}
            os.environ.update(env)
            try:
                st = store_mod.create_store()
                ws = st.create_workspace(WorkspaceCreate(name="wi", rig_name="g"))
                uploads = []
                for i in range(n_uploads):
                    content = (f"Rig daily note {i} for {slug}: circulated bottoms up; rows follow.\n"
                               + "\n".join(f"row,{i},{k},value" for k in range(40))).encode()
                    up, fr, _ = st.create_uploaded_file(ws.id, f"note{i}.txt", "text/plain", "files",
                                                        content, save=True)
                    st.complete_upload(up.id, [fr.id])
                    uploads.append(str(up.id))
                tenant_id = str(st.tenant.id)
            finally:
                for k, v in sv.items():
                    (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))
            return {"env": env, "scratch": scratch, "uploads": uploads, "tenant_id": tenant_id, "slug": slug}

        # ---------------- provisioning: import tenants (seed a legacy pre-cutover snapshot via boot) -------
        def build_entities(tenant_id, ws_id, *, override_tenant_id=None, reuse_corr_id=None):
            now = _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)
            et = override_tenant_id or tenant_id
            report = MondayReport(tenant_id=uuid.UUID(et), workspace_id=uuid.UUID(ws_id),
                                  period_start=_dt.date(2026, 1, 1), period_end=_dt.date(2026, 1, 7),
                                  report_json={"seed": True}, created_at=now)
            corr = FieldCorrection(id=uuid.UUID(reuse_corr_id) if reuse_corr_id else uuid.uuid4(),
                                   tenant_id=uuid.UUID(et), workspace_id=uuid.UUID(ws_id),
                                   target_type="report_field", field_key="rig_name",
                                   correction_reason="seed", actor_user_id=uuid.uuid4(),
                                   actor_email=f"seed@x.test", status="active", created_at=now)
            task = ValidationTask(tenant_id=uuid.UUID(et), target_type="failure", target_id=uuid.uuid4(),
                                  reason="seed", status="open", created_at=now)
            return report, corr, task

        def seed_import(slug, *, override_tenant_id=None, reuse_corr_id=None):
            env, scratch = prov_env(slug)
            env["MONDAY_REPORT_DATABASE_URL"] = f"{rt}?application_name=mr-imp-{slug}-{run_hash}"
            tenant_id = str(uuid.uuid4())
            ws_id = str(uuid.uuid4())
            report, corr, task = build_entities(tenant_id, ws_id, override_tenant_id=override_tenant_id,
                                                reuse_corr_id=reuse_corr_id)
            payload = {
                "tenant": {"id": tenant_id, "name": f"WI {slug}", "slug": slug},
                "workspaces": [{"id": ws_id, "tenant_id": tenant_id, "name": "wi"}],
                "monday_reports": [report.model_dump(mode="json")],
                "field_corrections": [corr.model_dump(mode="json")],
                "validation_tasks": [task.model_dump(mode="json")],
                "audit_logs": [],
            }
            from psycopg.types.json import Jsonb
            with psycopg.connect(boot, autocommit=True) as c:
                c.execute(f"delete from {STATE_TABLE} where tenant_slug=%s", (slug,))
                c.execute(f"insert into {STATE_TABLE} (tenant_slug, tenant_id, payload, revision) "
                          "values (%s,%s,%s,1)", (slug, tenant_id, Jsonb(payload)))
            return {"env": env, "scratch": scratch, "tenant_id": tenant_id, "ws_id": ws_id,
                    "corr_id": str(corr.id), "report_id": str(report.id), "task_id": str(task.id), "slug": slug}

        # ---------------- external process runners --------------------------------------------------------
        # A run expected to SUCCEED (controlled=False, default) that exits non-zero increments the NORMAL
        # failure counter (which fails the slice); a controlled-negative run (controlled=True) does not.
        worker_outs: list[str] = []

        def run_worker(env, *, extra=None, timeout=120, controlled=False):
            e = child(env)
            if extra:
                e.update(extra)
            proc = subprocess.run([sys.executable, "-m", "backend.app.worker"], cwd=str(ROOT), env=e,
                                  capture_output=True, text=True, timeout=timeout)
            out = (proc.stdout or "") + (proc.stderr or "")
            worker_outs.append(out)
            if not controlled and proc.returncode != 0:
                COUNTERS["normal_worker_process_failures"] += 1
            m = re.search(r"Processed (\d+) Monday Report job", out)
            return {"rc": proc.returncode, "processed": int(m.group(1)) if m else None,
                    "out": out, "stdout": proc.stdout or "", "stderr": proc.stderr or "", "child_env": e}

        def run_import(env, mode, *, extra=None, timeout=90, controlled=False):
            e = child(env)
            if extra:
                e.update(extra)
            proc = subprocess.run([sys.executable, "-m", "backend.app.normalized_import", mode], cwd=str(ROOT),
                                  env=e, capture_output=True, text=True, timeout=timeout)
            if not controlled and proc.returncode != 0:
                COUNTERS["normal_import_process_failures"] += 1
            lines = [ln for ln in (proc.stdout or "").splitlines() if ln.strip().startswith("{")]
            parsed = [json.loads(ln) for ln in lines]
            return {"rc": proc.returncode, "json": parsed, "out": (proc.stdout or "") + (proc.stderr or ""),
                    "stdout": proc.stdout or "", "stderr": proc.stderr or "", "child_env": e}

        def _hygiene(child_env):  # bind the run's principals to the module-scope predicate
            return env_hygiene(child_env, rt=rt, boot=boot, mig_dsn=ctx["mig_dsn"], mig_role=mig_role)

        try:
            # =====================================================================================
            # PART F/G: worker process authenticity + identity + tenant-A/B success
            # =====================================================================================
            WA = provision_worker("wrk-a", 6)
            WB = provision_worker("wrk-b", 6)

            # WF01 process authenticity + env-hygiene (external module, restricted DSN only, no fallback)
            b_before = snap("wrk-b")
            t0 = boot_q("select now()")[0]
            app_a = f"mr-wi-wrk-a-{run_hash}"
            proc = subprocess.Popen([sys.executable, "-m", "backend.app.worker"], cwd=str(ROOT),
                                    env=child(WA["env"]), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            # WF02: catch the worker's live DB session while it processes the 6 jobs. Freshness
            # (backend_start > launch time) is in the WHERE clause, so only a session started AFTER this
            # worker launched can ever match -- never a stale same-application_name session.
            sess = None
            for _ in range(600):
                rows = boot_all("select usename, application_name from pg_stat_activity "
                                "where application_name=%s and usename is not null and backend_start > %s",
                                (app_a, t0))
                if rows:
                    sess = rows[0]
                    break
                if proc.poll() is not None:
                    break
                time.sleep(0.01)
            out_a, _ = proc.communicate(timeout=120)
            rc_a = proc.returncode
            worker_outs.append(out_a or "")
            if rc_a != 0:
                COUNTERS["normal_worker_process_failures"] += 1
            m = re.search(r"Processed (\d+) Monday Report job", out_a or "")
            processed_a = int(m.group(1)) if m else None
            hy = _hygiene(child(WA["env"]))
            rec("WF01", rc_a == 0 and processed_a == 6 and all(hy.values()),
                desc="worker runs as a SEPARATE OS process via the production module; restricted runtime DSN only, "
                     "no migration/bootstrap DSN, libpq stripped, no local fallback; bounded clean exit",
                category="worker-authenticity", proc="python -m backend.app.worker", tenant="wrk-a",
                principal="restricted runtime login", job="6 upload jobs", expected="exit 0, processed=6, restricted-only",
                db_post="jobs complete", audit_post="-", level="whole-stack worker mutation",
                extra={"rc": rc_a, "processed": processed_a, **hy})

            role_row = boot_q("select rolsuper, rolbypassrls, rolcanlogin from pg_roles where rolname=%s",
                              (sess[0],)) if sess else None
            owner_row = boot_q("select bool_or(pg_get_userbyid(relowner)=%s) from pg_class "
                               "where relname = any(%s)",
                               (sess[0], ["monday_report_norm_field_corrections", STATE_TABLE])) if sess else None
            grp = boot_q("select count(*) from pg_auth_members m join pg_roles r on r.oid=m.member "
                         "join pg_roles g on g.oid=m.roleid where r.rolname=%s and g.rolname='monday_report_app'",
                         (sess[0],)) if sess else None
            rec("WF02", bool(sess) and sess[0] == rt_role and role_row
                and role_row[0] is False and role_row[1] is False and role_row[2] is True
                and owner_row and owner_row[0] is False and grp and grp[0] >= 1,
                desc="live FRESH worker DB session (pg_stat_activity, backend_start after launch enforced in the "
                     "query): session_user = restricted LOGIN, non-superuser, non-BYPASSRLS, owns no protected "
                     "table, member of the app group",
                category="worker-identity", proc="pg_stat_activity", tenant="wrk-a",
                principal="restricted runtime login", job="live session", expected="least-privilege runtime login",
                db_post="-", audit_post="-", level="live PostgreSQL verification",
                extra={"observed_session": bool(sess), "session_is_rt_role": bool(sess and sess[0] == rt_role),
                       "is_superuser": role_row[0] if role_row else None,
                       "has_bypassrls": role_row[1] if role_row else None,
                       "owns_protected": owner_row[0] if owner_row else None,
                       "group_member": (grp[0] if grp else 0), "app_name_fp": _fp(app_a)})

            # WG01: tenant-A success -> 6 complete, revision advanced, parse audits, tenant B untouched
            a_after = snap("wrk-a")
            rec("WG01", a_after["complete"] == 6 and a_after["queued"] == 0 and a_after["rev"] >= 1
                and audit_count("wrk-a", "document.parse_complete") >= 6
                and snap("wrk-b") == b_before,
                desc="tenant-A worker succeeds: all 6 jobs COMPLETE, snapshot revision advanced, parse audits "
                     "present; tenant-B snapshot unchanged (revision + job/doc counts)",
                category="worker-success", proc="python -m backend.app.worker", tenant="wrk-a",
                principal="restricted runtime login", job="6 upload jobs", expected="6 complete, B unchanged",
                db_post="wrk-a complete=6, wrk-b unchanged", audit_post="document.parse_complete>=6",
                extra={"complete": a_after["complete"], "queued": a_after["queued"],
                       "parse_audits": audit_count("wrk-a", "document.parse_complete"),
                       "b_unchanged": snap("wrk-b") == b_before})

            # WG02: tenant-B success -> A untouched
            a_snap = snap("wrk-a")
            rb = run_worker(WB["env"])
            rec("WG02", rb["rc"] == 0 and rb["processed"] == 6 and snap("wrk-b")["complete"] == 6
                and snap("wrk-a") == a_snap,
                desc="tenant-B worker succeeds (separate process): 6 jobs COMPLETE; tenant-A unchanged",
                category="worker-success", proc="python -m backend.app.worker", tenant="wrk-b",
                principal="restricted runtime login", job="6 upload jobs", expected="6 complete, A unchanged",
                db_post="wrk-b complete=6, wrk-a unchanged", audit_post="document.parse_complete>=6",
                extra={"rc": rb["rc"], "processed": rb["processed"], "a_unchanged": snap("wrk-a") == a_snap})

            # =====================================================================================
            # PART H: worker failure + recovery isolation (PROCESS-BOUNDARY, one-shot per tenant)
            # =====================================================================================
            FA = provision_worker("wrk-fa", 1)
            FB = provision_worker("wrk-fb", 1)
            # delete FA's stored file bytes -> the FA worker parse fails (file_missing) deterministically
            shutil.rmtree(FA["scratch"] / "storage" / "wrk-fa", ignore_errors=True)
            fb_before = snap("wrk-fb")
            rfa = run_worker(FA["env"])  # PROCESS exits 0 (job fails internally); normal-failure counter guards it
            fa1 = snap("wrk-fa")
            rec("WH01", rfa["rc"] == 0 and fa1["failed"] == 1 and fa1["complete"] == 0 and fa1["docs"] == 0
                and audit_count("wrk-fa", "document.parse_complete") == 0 and snap("wrk-fb") == fb_before,
                desc="tenant-A job FAILS (source file removed) -> job FAILED, no COMPLETE, no parsed document, no "
                     "partial success; tenant-B unchanged",
                category="worker-failure", proc="python -m backend.app.worker", tenant="wrk-fa",
                principal="restricted runtime login", job="poisoned/unavailable-source job", expected="job FAILED, no partial",
                db_post="wrk-fa failed=1 complete=0", audit_post="no parse_complete",
                level="live worker failure", extra={"rc": rfa["rc"], "failed": fa1["failed"], "complete": fa1["complete"]})

            # WH02: a SEPARATE tenant-B worker process succeeds after A's failure (process-boundary isolation)
            rfb = run_worker(FB["env"])
            rec("WH02", rfb["rc"] == 0 and rfb["processed"] == 1 and snap("wrk-fb")["complete"] == 1
                and snap("wrk-fa")["failed"] == 1,
                desc="a separate tenant-B worker process succeeds AFTER A's failure (process-boundary isolation; "
                     "no prior-tenant context leaks into the fresh process)",
                category="worker-isolation", proc="python -m backend.app.worker", tenant="wrk-fb",
                principal="restricted runtime login", job="clean job", expected="B success, A stays failed",
                db_post="wrk-fb complete=1", audit_post="document.parse_complete>=1",
                extra={"rc": rfb["rc"], "processed": rfb["processed"], "a_still_failed": snap("wrk-fa")["failed"] == 1})

            # WH03/WH04: symmetric (B fails, A succeeds after)
            GA = provision_worker("wrk-ga", 1)
            GB = provision_worker("wrk-gb", 1)
            shutil.rmtree(GB["scratch"] / "storage" / "wrk-gb", ignore_errors=True)
            ga_before = snap("wrk-ga")
            rgb = run_worker(GB["env"])  # PROCESS exits 0 (job fails internally); normal-failure counter guards it
            rec("WH03", rgb["rc"] == 0 and snap("wrk-gb")["failed"] == 1 and snap("wrk-ga") == ga_before,
                desc="symmetric: tenant-B job FAILS; tenant-A unchanged",
                category="worker-failure", proc="python -m backend.app.worker", tenant="wrk-gb",
                principal="restricted runtime login", job="unavailable-source job", expected="B failed, A unchanged",
                db_post="wrk-gb failed=1", audit_post="no parse_complete", level="live worker failure",
                extra={"failed": snap("wrk-gb")["failed"]})
            rga = run_worker(GA["env"])
            rec("WH04", rga["rc"] == 0 and rga["processed"] == 1 and snap("wrk-ga")["complete"] == 1,
                desc="tenant-A worker process succeeds after B's failure (uncontaminated fresh process)",
                category="worker-isolation", proc="python -m backend.app.worker", tenant="wrk-ga",
                principal="restricted runtime login", job="clean job", expected="A success",
                db_post="wrk-ga complete=1", audit_post="document.parse_complete>=1", extra={"processed": rga["processed"]})

            # WH05: operator RE-QUEUE retry / worker-restart stays with the ORIGINAL tenant. A fresh tenant with an
            # intact source: run -> COMPLETE, then re-queue (complete->queued, as the restricted login) and re-run ->
            # reprocessed to COMPLETE with attempts>=2, entirely tenant-scoped; a control tenant is untouched.
            RA = provision_worker("wrk-ra", 1)
            RB = provision_worker("wrk-rb", 1)
            rb_before = snap("wrk-rb")
            run_worker(RA["env"])  # first pass -> COMPLETE (attempts=1)
            with psycopg.connect(rt, autocommit=False) as rc_conn:
                with rc_conn.cursor() as cur:
                    cur.execute("select set_config('app.tenant_slug', %s, true)", ("wrk-ra",))
                    cur.execute(f"update {STATE_TABLE} set payload = jsonb_set(payload, '{{jobs}}'::text[], "
                                "(select jsonb_agg(case when j->>'status'='complete' "
                                "then jsonb_set(j,'{status}'::text[],'\"queued\"'::jsonb) else j end) "
                                f"from jsonb_array_elements(payload->'jobs') j)), revision = revision + 1 "
                                "where tenant_slug = %s::text", ("wrk-ra",))
                rc_conn.commit()
            r_retry = run_worker(RA["env"])
            ra2 = snap("wrk-ra")
            attempts = boot_q(f"select max((e->>'attempts')::int) from {STATE_TABLE} s, "
                              "jsonb_array_elements(s.payload->'jobs') e where s.tenant_slug=%s", ("wrk-ra",))
            rec("WH05", r_retry["rc"] == 0 and r_retry["processed"] == 1 and ra2["complete"] == 1
                and ra2["failed"] == 0 and attempts and attempts[0] >= 2 and snap("wrk-rb") == rb_before,
                desc="operator re-queue RETRY / worker-restart of a tenant-A job stays with tenant A: reprocessed to "
                     "COMPLETE with attempts>=2; the control tenant (wrk-rb) is unchanged (revision + job/doc counts)",
                category="worker-retry", proc="python -m backend.app.worker", tenant="wrk-ra",
                principal="restricted runtime login", job="re-queued job", expected="complete, attempts>=2, same tenant",
                db_post="wrk-ra complete=1 attempts>=2, wrk-rb unchanged", audit_post="document.parse_complete",
                extra={"complete": ra2["complete"], "attempts": attempts[0] if attempts else None,
                       "control_unchanged": snap("wrk-rb") == rb_before})

            # WH06: fail-closed refusal on a missing audit key -> non-zero exit, ZERO mutation
            HC = provision_worker("wrk-hc", 2)
            hc_before = snap("wrk-hc")
            r_fc = run_worker(HC["env"], extra={"MONDAY_REPORT_AUDIT_HMAC_KEY": ""}, controlled=True)
            rec("WH06", r_fc["rc"] != 0 and snap("wrk-hc") == hc_before,
                desc="worker with a missing audit key FAILS CLOSED before any mutation (non-zero exit, snapshot "
                     "unchanged (revision + job/doc counts), jobs stay QUEUED)",
                category="worker-failclosed", proc="python -m backend.app.worker", tenant="wrk-hc",
                principal="restricted runtime login", job="2 jobs (never processed)", expected="non-zero exit, no mutation",
                db_post="wrk-hc unchanged", audit_post="no audit written", level="live worker failure",
                extra={"rc": r_fc["rc"], "unchanged": snap("wrk-hc") == hc_before})
            COUNTERS["controlled_worker_negatives"] += 1

            # =====================================================================================
            # PART I: worker derives tenant/actor from trusted ENV, never a job payload
            # =====================================================================================
            IA = provision_worker("wrk-ia", 1)
            IB = provision_worker("wrk-ib", 1)
            ib_before = snap("wrk-ib")
            # stamp a spoofed tenant/actor into the job payload of wrk-ia (as the rt login), then run the
            # wrk-ia worker: the spoof must be IGNORED (tenant = env), and wrk-ib must be untouched.
            with psycopg.connect(rt, autocommit=False) as rc_conn:
                with rc_conn.cursor() as cur:
                    cur.execute("select set_config('app.tenant_slug', %s, true)", ("wrk-ia",))
                    cur.execute(f"update {STATE_TABLE} set payload = jsonb_set(payload, '{{jobs}}'::text[], "
                                "(select jsonb_agg(j || jsonb_build_object('tenant_slug','wrk-ib',"
                                "'actor','spoofed','tenant_id',%s::text)) from jsonb_array_elements(payload->'jobs') j)), "
                                "revision = revision + 1 where tenant_slug = %s::text", (IB["tenant_id"], "wrk-ia"))
                rc_conn.commit()
            r_ia = run_worker(IA["env"])
            rec("WI01", r_ia["rc"] == 0 and r_ia["processed"] == 1 and snap("wrk-ia")["complete"] == 1
                and snap("wrk-ib") == ib_before,
                desc="a job payload carrying a spoofed tenant_slug/tenant_id/actor is IGNORED -> processed under the "
                     "env tenant (wrk-ia), and the named foreign tenant (wrk-ib) is untouched",
                category="worker-payload-isolation", proc="python -m backend.app.worker", tenant="wrk-ia",
                principal="restricted runtime login", job="payload-tenant-spoof job", expected="env tenant wins, B untouched",
                db_post="wrk-ia complete=1, wrk-ib unchanged", audit_post="attributed to wrk-ia",
                extra={"processed": r_ia["processed"], "b_unchanged": snap("wrk-ib") == ib_before})

            # WI02: a worker running as wrk-ib does NOT see/process wrk-ia's jobs (RLS + snapshot scoping)
            ia_after = snap("wrk-ia")
            r_ib = run_worker(IB["env"])
            rec("WI02", r_ib["rc"] == 0 and r_ib["processed"] == 1 and snap("wrk-ia") == ia_after,
                desc="a worker process for wrk-ib processes ONLY wrk-ib's own jobs; wrk-ia's snapshot is unchanged "
                     "(cross-tenant job invisibility)",
                category="worker-payload-isolation", proc="python -m backend.app.worker", tenant="wrk-ib",
                principal="restricted runtime login", job="own job only", expected="processes own only",
                db_post="wrk-ia unchanged", audit_post="-", extra={"processed": r_ib["processed"],
                                                                    "a_unchanged": snap("wrk-ia") == ia_after})

            # =====================================================================================
            # PART J/K: duplicate delivery + worker audit integrity + secret scan
            # =====================================================================================
            # WJ01: re-running the worker after all jobs are terminal processes ZERO (no duplicate business effect)
            complete_before = snap("wrk-a")["complete"]
            r_dup = run_worker(WA["env"])
            rec("WJ01", r_dup["rc"] == 0 and r_dup["processed"] == 0 and snap("wrk-a")["complete"] == complete_before,
                desc="re-running the worker after all jobs are terminal processes 0 (no duplicate business effect; "
                     "the one-shot worker only picks up QUEUED jobs)",
                category="worker-idempotency", proc="python -m backend.app.worker", tenant="wrk-a",
                principal="restricted runtime login", job="no queued jobs", expected="processed=0, no change",
                db_post="wrk-a complete unchanged", audit_post="no new audit", extra={"processed": r_dup["processed"]})

            def integrity(env):
                sv = {k: os.environ.get(k) for k in env}
                os.environ.update(env)
                try:
                    st = store_mod.create_store(); st.refresh()
                    it = st.audit_integrity_status()
                    return it.integrity_state, it.broken_events
                finally:
                    for k, v in sv.items():
                        (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))
            st_a, broken_a = integrity(WA["env"])
            rec("WK01", st_a == "keyed_valid" and broken_a == 0
                and audit_count("wrk-a", "document.parse_complete") >= 6
                and audit_count("wrk-fa", "document.parse_complete") == 0,  # FA's job FAILED -> no success audit
                desc="worker audit chain verifies keyed_valid (0 broken) after all worker activity; successful jobs "
                     "carry document.parse_complete, the FAILED tenant-A job carries NO success audit",
                category="worker-audit", proc="-", tenant="wrk-a", principal="verifier", job="audit chain",
                expected="keyed_valid, honest attribution", db_post="-", audit_post="keyed_valid, broken=0",
                level="direct component integration", extra={"state": st_a, "broken": broken_a})

            blob = boot_q(f"select coalesce(string_agg(e::text,' '),'') from {STATE_TABLE} s, "
                          "jsonb_array_elements(s.payload->'audit_logs') e where s.tenant_slug like 'wrk-%%'")[0] or ""
            worker_out = " ".join(worker_outs)  # every worker run output (WF01 + all run_worker calls)
            leaked = [t for t in LEAK_TERMS if t and (t in blob or t in worker_out)]
            rec("WK02", not leaked,
                desc="worker stdout/stderr and persisted worker audit events carry no raw payload/credential/DSN/"
                     "audit-key/run-nonce/role/host/path",
                category="worker-secret-scan", proc="-", tenant="wrk-*", principal="verifier", job="secret scan",
                expected="secret-clean", db_post="-", audit_post="secret-clean",
                level="live PostgreSQL verification", extra={"leaked_kinds": len(leaked)})

            # =====================================================================================
            # PART L/M: import assess + dry-run (read-only) + tenant-selection controls
            # =====================================================================================
            IMA = seed_import("imp-a")
            IMB = seed_import("imp-b")

            def norm_all(slug):
                return {t: norm_count(slug, t) for t in ("monday_report_norm_reports",
                        "monday_report_norm_field_corrections", "monday_report_norm_validation_tasks")}

            b_norm0 = norm_all("imp-b"); a_norm0 = norm_all("imp-a")
            r_ass = run_import(IMA["env"], "assess")
            asum = r_ass["json"][0] if r_ass["json"] else {}
            rec("LI01", r_ass["rc"] == 0 and asum.get("snapshot_present") and asum.get("holdings", {}).get("field_corrections") == 1
                and asum.get("conflicts") == 0 and norm_all("imp-a") == a_norm0 and norm_all("imp-b") == b_norm0,
                desc="import ASSESS (external process) is read-only: reports the selected tenant's holdings, changes "
                     "ZERO rows for either tenant",
                category="import-assess", proc="python -m backend.app.normalized_import assess", tenant="imp-a",
                principal="restricted runtime login", job="assess", expected="exit 0, 0 rows changed",
                db_post="imp-a/imp-b norm unchanged", audit_post="-", level="whole-stack import mutation",
                extra={"rc": r_ass["rc"], "holdings": asum.get("holdings"), "a_unchanged": norm_all("imp-a") == a_norm0,
                       "b_unchanged": norm_all("imp-b") == b_norm0})

            r_dry = run_import(IMA["env"], "dry-run")
            dj = r_dry["json"]
            would = next((x for x in dj if "dry_run_would_execute" in x), {})
            rec("LI02", r_dry["rc"] == 0 and would.get("dry_run_would_execute") is True
                and norm_all("imp-a") == a_norm0 and norm_all("imp-b") == b_norm0,
                desc="import DRY-RUN performs the full transformation in memory and writes NOTHING (0 rows), reporting "
                     "it would execute",
                category="import-dryrun", proc="python -m backend.app.normalized_import dry-run", tenant="imp-a",
                principal="restricted runtime login", job="dry-run", expected="exit 0, would_execute, 0 rows",
                db_post="imp-a/imp-b norm unchanged", audit_post="-", level="whole-stack import mutation",
                extra={"rc": r_dry["rc"], "would_execute": would.get("dry_run_would_execute")})

            # MI01: assess selects ONLY its own tenant (imp-b assess reports imp-b holdings, imp-a untouched)
            r_assb = run_import(IMB["env"], "assess")
            asumb = r_assb["json"][0] if r_assb["json"] else {}
            rec("MI01", r_assb["rc"] == 0 and asumb.get("holdings", {}).get("field_corrections") == 1
                and norm_all("imp-a") == a_norm0,
                desc="import ASSESS for imp-b reads only imp-b's snapshot; imp-a is untouched (env tenant selector)",
                category="import-tenant-select", proc="python -m backend.app.normalized_import assess", tenant="imp-b",
                principal="restricted runtime login", job="assess", expected="imp-b holdings, imp-a untouched",
                db_post="imp-a unchanged", audit_post="-", level="whole-stack import mutation",
                extra={"rc": r_assb["rc"], "holdings": asumb.get("holdings")})

            # MI02: unknown tenant selection -> no snapshot, no rows changed (controlled)
            r_unk = run_import(IMA["env"], "assess", extra={"MONDAY_REPORT_TENANT_SLUG": "no-such-" + run_hash})
            usum = r_unk["json"][0] if r_unk["json"] else {}
            rec("MI02", r_unk["rc"] == 0 and usum.get("snapshot_present") is False
                and norm_all("imp-a") == a_norm0 and norm_all("imp-b") == b_norm0,
                desc="import ASSESS with an UNKNOWN tenant selector -> snapshot_present=false, zero rows changed "
                     "(tenant is env-selected, never inferred from data)",
                category="import-tenant-select", proc="python -m backend.app.normalized_import assess",
                tenant="unknown", principal="restricted runtime login", job="assess", expected="no snapshot, 0 rows",
                db_post="no changes", audit_post="-", level="live import denial",
                extra={"rc": r_unk["rc"], "snapshot_present": usum.get("snapshot_present")})

            # =====================================================================================
            # PART N: import execute (idempotent, refuse-on-conflict, cross-tenant)
            # =====================================================================================
            b_norm1 = norm_all("imp-b")
            r_ex = run_import(IMA["env"], "execute")
            ex = next((x for x in r_ex["json"] if x.get("result") in ("cut over", "already cut over; use verify")
                       or "accounting" in x), r_ex["json"][-1] if r_ex["json"] else {})
            a_norm_after = norm_all("imp-a")
            rec("NI01", r_ex["rc"] == 0 and ex.get("result") == "cut over"
                and a_norm_after["monday_report_norm_field_corrections"] == 1
                and a_norm_after["monday_report_norm_reports"] == 1
                and a_norm_after["monday_report_norm_validation_tasks"] == 1
                and norm_all("imp-b") == b_norm1,
                desc="import EXECUTE (imp-a) inserts the normalized rows in ONE transaction, writes the authority "
                     "marker, strips the migrated snapshot keys; imp-b unchanged",
                category="import-execute", proc="python -m backend.app.normalized_import execute", tenant="imp-a",
                principal="restricted runtime login", job="execute", expected="cut over, rows inserted, B unchanged",
                db_post="imp-a norm=1/1/1, imp-b unchanged", audit_post="import marker written",
                level="whole-stack import mutation", extra={"rc": r_ex["rc"], "import_result": ex.get("result"),
                                                            "a_norm": a_norm_after, "b_unchanged": norm_all("imp-b") == b_norm1})

            # NI02: execute imp-b -> imp-a unchanged
            a_norm2 = norm_all("imp-a")
            r_exb = run_import(IMB["env"], "execute")
            exb = r_exb["json"][-1] if r_exb["json"] else {}
            rec("NI02", r_exb["rc"] == 0 and exb.get("result") == "cut over"
                and norm_count("imp-b", "monday_report_norm_field_corrections") == 1 and norm_all("imp-a") == a_norm2,
                desc="import EXECUTE (imp-b) cuts over imp-b; imp-a unchanged",
                category="import-execute", proc="python -m backend.app.normalized_import execute", tenant="imp-b",
                principal="restricted runtime login", job="execute", expected="cut over, A unchanged",
                db_post="imp-b norm=1, imp-a unchanged", audit_post="import marker", level="whole-stack import mutation",
                extra={"rc": r_exb["rc"], "import_result": exb.get("result"), "a_unchanged": norm_all("imp-a") == a_norm2})

            # NI03: duplicate execute imp-a -> idempotent "already cut over", 0 new rows
            a_norm3 = norm_all("imp-a")
            r_dupex = run_import(IMA["env"], "execute")
            dupex = r_dupex["json"][-1] if r_dupex["json"] else {}
            rec("NI03", r_dupex["rc"] == 0 and dupex.get("result") == "already cut over; use verify"
                and norm_all("imp-a") == a_norm3,
                desc="duplicate EXECUTE (imp-a) is idempotent: 'already cut over; use verify', ZERO new rows",
                category="import-idempotency", proc="python -m backend.app.normalized_import execute", tenant="imp-a",
                principal="restricted runtime login", job="execute (re-run)", expected="already cut over, 0 new rows",
                db_post="imp-a norm unchanged", audit_post="no new marker", level="whole-stack import mutation",
                extra={"rc": r_dupex["rc"], "import_result": dupex.get("result")})

            # NI04: execute with a FOREIGN tenant_id in the payload entities -> REFUSED, 0 rows
            IMO = seed_import("imp-o", override_tenant_id=str(uuid.uuid4()))
            o_norm0 = norm_all("imp-o")
            r_over = run_import(IMO["env"], "execute", controlled=True)
            over = next((x for x in r_over["json"] if "result" in x), {})
            rec("NI04", r_over["rc"] == 1 and "REFUSED" in str(over.get("result", ""))
                and norm_all("imp-o") == o_norm0,
                desc="EXECUTE with entities whose tenant_id does not match the snapshot tenant -> REFUSED "
                     "(relationship/tenant-mismatch), zero rows written",
                category="import-payload-refuse", proc="python -m backend.app.normalized_import execute", tenant="imp-o",
                principal="restricted runtime login", job="execute (payload tenant override)", expected="REFUSED, 0 rows",
                db_post="imp-o norm unchanged", audit_post="-", level="live import denial",
                extra={"rc": r_over["rc"], "import_result": over.get("result")})
            COUNTERS["controlled_import_negatives"] += 1

            # NI05: cross-tenant id reuse (an id already owned by imp-a). HONEST FINDING: under the restricted
            # RLS login the tool's tenant-scoped existence probe CANNOT see imp-a's row, so the duplicate is
            # rejected instead by the GLOBAL primary-key constraint -> the transaction aborts and rolls back
            # atomically (non-zero exit, zero imp-r rows written, imp-a's row UNCHANGED). Cross-tenant id reuse
            # is PREVENTED either way; under a superuser/owner principal it would be the tool's graceful
            # conflict classification, under the restricted login it is the PK constraint + atomic rollback.
            IMR = seed_import("imp-r", reuse_corr_id=IMA["corr_id"])
            r_norm0 = norm_all("imp-r")
            a_corr_row = boot_q("select doc from monday_report_norm_field_corrections where id=%s and tenant_slug=%s",
                                (IMA["corr_id"], "imp-a"))
            r_reuse = run_import(IMR["env"], "execute", controlled=True)
            a_corr_row2 = boot_q("select doc from monday_report_norm_field_corrections where id=%s and tenant_slug=%s",
                                 (IMA["corr_id"], "imp-a"))
            rec("NI05", r_reuse["rc"] != 0 and norm_all("imp-r") == r_norm0 and a_corr_row2 == a_corr_row
                and a_corr_row is not None,
                desc="cross-tenant id reuse is PREVENTED under the restricted login: the duplicate id is rejected "
                     "(global primary key) and the transaction rolls back atomically -> non-zero exit, zero imp-r "
                     "rows written, imp-a's existing row UNCHANGED (no cross-tenant clobber)",
                category="import-cross-tenant", proc="python -m backend.app.normalized_import execute", tenant="imp-r",
                principal="restricted runtime login", job="execute (cross-tenant id reuse)", expected="prevented, 0 rows, A row intact",
                db_post="imp-r norm unchanged, imp-a corr unchanged", audit_post="-", level="live import denial",
                extra={"rc": r_reuse["rc"], "imp_r_unchanged": norm_all("imp-r") == r_norm0,
                       "imp_a_row_unchanged": a_corr_row2 == a_corr_row})
            COUNTERS["controlled_import_negatives"] += 1

            # =====================================================================================
            # PART O: import verify (authoritative marker vs actual; tamper detection)
            # =====================================================================================
            r_ver = run_import(IMA["env"], "verify")
            ver = r_ver["json"][-1] if r_ver["json"] else {}
            rec("OI01", r_ver["rc"] == 0 and ver.get("ok") is True and not ver.get("problems"),
                desc="import VERIFY (imp-a) after a correct cutover -> ok:true (marker counts + id digests match the "
                     "tenant-scoped rows)",
                category="import-verify", proc="python -m backend.app.normalized_import verify", tenant="imp-a",
                principal="restricted runtime login", job="verify", expected="ok:true",
                db_post="-", audit_post="-", level="whole-stack import mutation", extra={"rc": r_ver["rc"], "verify_ok": ver.get("ok")})

            # OI02: post-execute tampering (delete a norm row via boot) -> verify count/digest mismatch, exit 1
            with psycopg.connect(boot, autocommit=True) as c:
                c.execute("delete from monday_report_norm_validation_tasks where tenant_slug='imp-a'")
            r_ver2 = run_import(IMA["env"], "verify", controlled=True)
            ver2 = r_ver2["json"][-1] if r_ver2["json"] else {}
            rec("OI02", r_ver2["rc"] == 1 and ver2.get("ok") is False and ver2.get("problems"),
                desc="post-execute TAMPERING (a normalized row deleted) -> VERIFY fails: count/digest mismatch, exit 1",
                category="import-verify", proc="python -m backend.app.normalized_import verify", tenant="imp-a",
                principal="restricted runtime login", job="verify (tampered)", expected="ok:false, problems",
                db_post="-", audit_post="-", level="live import denial",
                extra={"rc": r_ver2["rc"], "verify_ok": ver2.get("ok"), "problem_count": len(ver2.get("problems") or [])})
            COUNTERS["controlled_import_negatives"] += 1

            # OI03: verify a tenant with NO marker (never cut over) -> problems, exit 1
            IMV = seed_import("imp-v")
            r_ver3 = run_import(IMV["env"], "verify", controlled=True)
            ver3 = r_ver3["json"][-1] if r_ver3["json"] else {}
            rec("OI03", r_ver3["rc"] == 1 and ver3.get("ok") is False,
                desc="VERIFY a tenant that was never cut over (no authority marker) -> not ok, exit 1",
                category="import-verify", proc="python -m backend.app.normalized_import verify", tenant="imp-v",
                principal="restricted runtime login", job="verify (no marker)", expected="ok:false",
                db_post="-", audit_post="-", level="live import denial", extra={"rc": r_ver3["rc"], "verify_ok": ver3.get("ok")})
            COUNTERS["controlled_import_negatives"] += 1

            # =====================================================================================
            # PART P: import principal + RLS boundary
            # =====================================================================================
            # the import ran as the restricted login (env-hygiene) and did NOT need/inherit a privileged
            # principal; RLS/FORCE remain intact after all import activity.
            hy_imp = _hygiene(child(IMB["env"]))
            role_ok = boot_q("select rolsuper, rolbypassrls from pg_roles where rolname=%s", (rt_role,))
            rls_intact = boot_q("select bool_and(relrowsecurity and relforcerowsecurity) from pg_class "
                                "where relname = any(%s)",
                                (["monday_report_norm_field_corrections", "monday_report_norm_reports",
                                  "monday_report_norm_validation_tasks", STATE_TABLE],))
            rec("PI01", all(hy_imp.values()) and role_ok and role_ok[0] is False and role_ok[1] is False
                and rls_intact and rls_intact[0] is True,
                desc="the import ran as the restricted runtime login (no migration/bootstrap DSN, no libpq leak, no "
                     "local fallback); the runtime role stays non-superuser/non-BYPASSRLS; RLS+FORCE remain enabled "
                     "on every protected table after all import activity (no disabling)",
                category="import-principal", proc="python -m backend.app.normalized_import", tenant="imp-*",
                principal="restricted runtime login", job="all modes", expected="restricted principal, RLS intact",
                db_post="RLS+FORCE intact", audit_post="-", level="live PostgreSQL verification",
                extra={**hy_imp, "runtime_non_super": role_ok[0] is False if role_ok else None,
                       "runtime_non_bypass": role_ok[1] is False if role_ok else None,
                       "rls_force_intact": rls_intact[0] if rls_intact else None})

            # secret scan of import output. The tool's DATA output (stdout) must be clean of EVERY leak term
            # (credentials/DSNs/keys/roles/tokens/nonce/db-name AND paths). Stderr may legitimately carry a
            # crash-traceback MODULE PATH (public repo structure; see NI05's restricted-login PK rejection),
            # which is not a secret data leak -- so stderr is scanned only for SECRET terms (paths excluded).
            secret_terms = [t for t in LEAK_TERMS if t and t not in (str(ROOT), _tmp_base)]
            imp_runs = (r_ass, r_dry, r_assb, r_unk, r_ex, r_exb, r_dupex, r_over, r_reuse, r_ver, r_ver2, r_ver3)
            imp_stdout = " ".join((r.get("stdout") or "") for r in imp_runs)
            imp_stderr = " ".join((r.get("stderr") or "") for r in imp_runs)
            imp_leaked = [t for t in LEAK_TERMS if t and t in imp_stdout] + [t for t in secret_terms if t in imp_stderr]
            rec("PI02", not imp_leaked,
                desc="import STDOUT (the tool's data surface) carries no leak term (credential/DSN/key/role/token/"
                     "nonce/db/path); STDERR carries no secret (a crash-traceback module path is not a data leak)",
                category="import-secret-scan", proc="-", tenant="imp-*", principal="verifier", job="secret scan",
                expected="secret-clean", db_post="-", audit_post="-", level="live PostgreSQL verification",
                extra={"leaked_kinds": len(imp_leaked)})

        finally:
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
        rec("foundation", False, desc="foundation checks not ok", category="setup", proc="-", tenant="-",
            principal="-", job="-", expected="all ok", db_post="-", audit_post="-",
            level="structural source check", extra={"foundation_fail": sorted(foundation_fail)[:8]})
    if err:
        print("ON_LIVE ERROR:", err.get("type"), file=sys.stderr)
        print(_scrub(err.get("tb", "")), file=sys.stderr)
        rec("on_live_abort", False, desc=f"on_live aborted with {err.get('type')} (see stderr)",
            category="setup", proc="-", tenant="-", principal="-", job="-", expected="no abort", db_post="-",
            audit_post="-", level="structural source check")
    return _emit()


EXPECTED_IDS = [
    "WF01", "WF02", "WG01", "WG02", "WH01", "WH02", "WH03", "WH04", "WH05", "WH06", "WI01", "WI02",
    "WJ01", "WK01", "WK02", "LI01", "LI02", "MI01", "MI02", "NI01", "NI02", "NI03", "NI04", "NI05",
    "OI01", "OI02", "OI03", "PI01", "PI02",
]


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
    SETUP_IDS = {"completeness", "inventory", "inventory-unexpected", "http-counters", "worker-counters",
                 "import-counters", "foundation", "on_live_abort", "setup", "setup-apis"}
    unexpected = sorted(i for i in present if i not in EXPECTED_IDS and i not in SETUP_IDS)
    aborted = any(c["check_id"] in ("on_live_abort", "setup-apis", "foundation") for c in checks)
    if missing and not skipped and not aborted:
        rec("completeness", False, desc=f"missing expected slice checks: {missing[:8]}", category="setup",
            proc="-", tenant="-", principal="-", job="-", expected="all slice checks present", db_post="-",
            audit_post="-", level="structural source check", extra={"missing_count": len(missing)})
        failed = [c for c in checks if not c["ok"]]; core = "failed"
    if unexpected and not skipped:
        rec("inventory-unexpected", False, desc=f"emitted ids not in the expected inventory: {unexpected[:8]}",
            category="setup", proc="-", tenant="-", principal="-", job="-", expected="only expected ids",
            db_post="-", audit_post="-", level="structural source check", extra={"unexpected": unexpected[:16]})
        failed = [c for c in checks if not c["ok"]]; core = "failed"
    if dup:
        rec("inventory", False, desc=f"duplicate check ids: {dup[:8]}", category="setup", proc="-", tenant="-",
            principal="-", job="-", expected="unique ids", db_post="-", audit_post="-",
            level="structural source check")
        failed = [c for c in checks if not c["ok"]]; core = "failed"
    if (COUNTERS["normal_worker_process_failures"] or COUNTERS["normal_import_process_failures"]) and not skipped:
        rec("worker-counters", False, desc="a NORMAL worker/import process failed unexpectedly", category="setup",
            proc="-", tenant="-", principal="-", job="-", expected="0 normal failures", db_post="-", audit_post="-",
            level="structural source check", extra={k: COUNTERS[k] for k in COUNTERS})
        failed = [c for c in checks if not c["ok"]]; core = "failed"
    out = {"checks": checks,
           "summary": {"passed": len(passed) if not skipped else 0,
                       "skipped": len(checks) if skipped else 0,
                       "failed": 0 if skipped else len(failed),
                       "execution_level_totals": exec_totals,
                       "claim_scope": "restricted-runtime-worker-import-only",
                       "full_functional_matrix": "not_run",
                       "slice_result": core,
                       "worker_architecture": "one-shot single-tenant-per-process; isolation is PROCESS-BOUNDARY",
                       "import_tenant_selector": "env MONDAY_REPORT_TENANT_SLUG (never a request payload)",
                       **COUNTERS,
                       "eligible_for_tenant_evidence": False,
                       "eligible_for_readiness": False,
                       "production_parity": False,
                       "migration_principal_class": "test-only-bootstrap-migration-admin"}}
    print(_scrub(json.dumps(out, indent=2, default=str)))
    if skipped:
        print("\nWorker/import slice SKIPPED (docker unavailable, non-certifying).")
        return 0
    if failed:
        print(f"\nWorker/import slice FAILED: {len(failed)} check(s).")
        for c in failed:
            print(_scrub(f"  FAIL: {c['check_id']} -> {c.get('description','')}"))
        return 1
    print(f"\nWorker/import slice passed: {len(passed)} check(s)."
          "\n[claim_scope=restricted-runtime-worker-import-only; NOT evidence/readiness eligible]")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
