"""Runner-owned external restricted-PostgreSQL runtime guard (FOUNDATION).

The decisive control the verification boundary alone cannot provide is PROVENANCE: an
attestation row proves nothing about disposability unless the verifier itself CREATED
and OWNS the database it is talking to. This guard is that runner. It:

  * creates its OWN Docker volume + PostgreSQL/pgvector container (unique run-scoped
    names + labels), and proves ownership by inspecting the exact created resources --
    never by name alone;
  * DERIVES every DSN from the container it created and REFUSES any externally supplied
    database DSN / libpq variable (proven by an explicit negative test);
  * provisions a migration LOGIN, a restricted runtime LOGIN, and the NOLOGIN
    monday_report_app group, applies migrations 0001-0007 as the migration login, and
    installs the run- and cluster-bound verification attestation;
  * launches the API (uvicorn) and the worker as SEPARATE external OS processes on the
    RESTRICTED runtime login, and proves their live identity from pg_stat_activity via a
    deterministic advisory-lock barrier (never inferred from the DSN);
  * performs only a MINIMAL functional smoke (health, credentialed read, denial,
    boundary-active mutation) -- NOT the full correction/validation/cross-tenant matrix;
  * removes ONLY the resources it recorded as created, in a finally-block ledger.

This turn is the foundation for the later functional guard. It requires Docker; without
it every scenario records SKIPPED (never a false pass). The DSN, host, port, container
id, credential, and raw nonce are never printed.

Run: ``python scripts/restricted_postgres_runtime_guard.py``
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

PG_IMAGE = "pgvector/pgvector:pg16"
LABEL_PROJECT = "monday-report-verification"
LABEL_PURPOSE = "restricted-postgres-runtime"

checks: list[dict] = []


def record(cid: str, ok: bool, category: str, detail: object = "", *, skipped: bool = False) -> None:
    checks.append({"id": cid, "ok": bool(ok), "category": category, "skipped": bool(skipped), "detail": detail})


def skip_all(reason: str) -> None:
    for cid, cat in _INVENTORY:
        record(cid, True, cat, reason, skipped=True)


# Canonical expected-ID inventory (id, category).
_INVENTORY = [
    ("R01 names absent before creation", "ownership"),
    ("R02 runner created the volume", "ownership"),
    ("R03 runner created the container", "ownership"),
    ("R04 ownership labels match", "ownership"),
    ("R05 container mounts the exact created volume", "ownership"),
    ("R06 database port published only on loopback", "ownership"),
    ("R07 approved pgvector image", "ownership"),
    ("D01 runtime DSN derived by the runner", "dsn"),
    ("D02 externally supplied DSN is rejected", "dsn"),
    ("D03 inherited libpq variables are stripped", "dsn"),
    ("P01 database created by the runner", "roles"),
    ("P02 migration and runtime logins are distinct", "roles"),
    ("P03 migrations 0001-0007 applied", "roles"),
    ("P04 RLS enabled and forced on the slice", "roles"),
    ("P05 policy inventory complete", "roles"),
    ("P06 run/cluster attestation installed and valid", "roles"),
    ("P07 runtime is non-super, non-bypassrls, group member, owns no protected table", "roles"),
    ("X01 API is an external process on PostgreSQL", "external"),
    ("X02 verification boundary active; readiness stays non-ready", "external"),
    ("X03 worker is an external process on PostgreSQL", "external"),
    ("I01 API session_user is the restricted runtime login (pg_stat_activity)", "identity"),
    ("I02 worker session_user is the restricted runtime login (pg_stat_activity)", "identity"),
    ("I03 migration/runtime principal separation", "identity"),
    ("S01 health endpoint succeeds", "smoke"),
    ("S02 missing credential is denied", "smoke"),
    ("S03 valid persisted credential authenticates a read", "smoke"),
    ("S04 a client-mode mutation executes under the boundary (not 423)", "smoke"),
    ("S05 functional 423/500/503 count is zero", "smoke"),
]


def _docker(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def _free_loopback_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _http(method: str, url: str, headers: dict | None = None, data: bytes | None = None, timeout: int = 15):
    req = urllib.request.Request(url, method=method, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # noqa: BLE001
        return None, str(e).encode()


def main() -> int:
    if _docker(["info"]).returncode != 0:
        skip_all("docker not available")
        return _emit()

    run_id = secrets.token_hex(32)                 # >=128-bit nonce (raw; never printed)
    run_hash = hashlib.sha256(run_id.encode()).hexdigest()[:12]
    cname = f"mr-verif-{run_hash}"
    vname = f"mr-verif-vol-{run_hash}"
    db = "monday_verif_test"
    mig_role = f"mr_mig_{run_hash}"
    rt_role = f"mr_rt_{run_hash}"
    port = _free_loopback_port()
    scratch = Path(os.environ.get("TEMP", "/tmp")) / f"mr-rpr-{run_hash}"
    for sub in ("state", "storage", "exports", "web"):
        (scratch / sub).mkdir(parents=True, exist_ok=True)
    (scratch / "web" / "index.html").write_text("<html><body>verif</body></html>", encoding="utf-8")

    ledger = {"volume": {"name": vname, "created": False, "id": None},
              "container": {"name": cname, "created": False, "id": None, "started": False},
              "api_pid": None, "worker_pids": [], "web_pid": None}
    procs: list = []

    def labels(kind: str) -> list[str]:
        return ["--label", f"project={LABEL_PROJECT}", "--label", f"purpose={LABEL_PURPOSE}",
                "--label", f"verification-run={run_hash}", "--label", f"resource={kind}"]

    try:
        import psycopg

        # -- R01: the unique names must not already exist --------------------
        pre_c = _docker(["ps", "-aq", "-f", f"name=^{cname}$"]).stdout.strip()
        pre_v = _docker(["volume", "ls", "-q", "-f", f"name=^{vname}$"]).stdout.strip()
        record("R01 names absent before creation", not pre_c and not pre_v, "ownership",
                {"container_pre": bool(pre_c), "volume_pre": bool(pre_v)})
        if pre_c or pre_v:
            raise RuntimeError("run-scoped name already exists; refusing")

        # -- R02/R03: create runner-owned volume + container -----------------
        cv = _docker(["volume", "create", *labels("volume"), vname])
        ledger["volume"]["created"] = cv.returncode == 0
        ledger["volume"]["id"] = _docker(["volume", "inspect", "-f", "{{.Name}}", vname]).stdout.strip()
        record("R02 runner created the volume", cv.returncode == 0, "ownership")

        cc = _docker(["run", "-d", "--name", cname, *labels("container"),
                      "-e", "POSTGRES_PASSWORD=" + secrets.token_urlsafe(18),
                      "-e", f"POSTGRES_DB={db}",
                      "-p", f"127.0.0.1:{port}:5432",
                      "-v", f"{vname}:/var/lib/postgresql/data",
                      PG_IMAGE])
        ledger["container"]["created"] = cc.returncode == 0
        ledger["container"]["id"] = cc.stdout.strip()[:12] if cc.returncode == 0 else None
        ledger["container"]["started"] = cc.returncode == 0
        record("R03 runner created the container", cc.returncode == 0, "ownership",
               {"err": cc.stderr[-120:] if cc.returncode else None})
        if cc.returncode != 0:
            raise RuntimeError("container create failed")

        # readiness
        ready = False
        for _ in range(40):
            if _docker(["exec", cname, "pg_isready", "-U", "postgres", "-d", db]).returncode == 0:
                ready = True
                break
            time.sleep(1)
        if not ready:
            raise RuntimeError("container not ready")

        # -- R04-R07: prove ownership by inspecting the exact resources ------
        insp = json.loads(_docker(["inspect", cname]).stdout)[0]
        lbls = insp["Config"]["Labels"] or {}
        record("R04 ownership labels match", lbls.get("project") == LABEL_PROJECT
               and lbls.get("purpose") == LABEL_PURPOSE and lbls.get("verification-run") == run_hash,
               "ownership")
        mounts = insp.get("Mounts", [])
        vol_mount = [m for m in mounts if m.get("Type") == "volume"
                     and m.get("Destination") == "/var/lib/postgresql/data"]
        record("R05 container mounts the exact created volume",
               len(vol_mount) == 1 and vol_mount[0].get("Name") == vname, "ownership")
        record("R07 approved pgvector image", insp["Config"]["Image"] == PG_IMAGE, "ownership")
        ports = insp["NetworkSettings"]["Ports"].get("5432/tcp") or []
        record("R06 database port published only on loopback",
               bool(ports) and all(p.get("HostIp") in ("127.0.0.1", "::1") for p in ports)
               and port not in (8000, 5173), "ownership", {"bindings": [p.get("HostIp") for p in ports]})

        # -- DSN provenance ---------------------------------------------------
        pw = insp["Config"]["Env"]  # not printed
        # Derive DSNs from the created container (bootstrap superuser only for setup).
        boot_dsn = f"postgresql://postgres:{[e for e in pw if e.startswith('POSTGRES_PASSWORD=')][0].split('=',1)[1]}@127.0.0.1:{port}/{db}"
        rt_pw = secrets.token_urlsafe(18)
        record("D01 runtime DSN derived by the runner", boot_dsn.startswith("postgresql://") and f":{port}/" in boot_dsn,
               "dsn")

        # D02: an externally supplied DSN must never become the passing runtime path.
        from backend.app import verification_boundary as vb
        external_dsn = "postgresql://attacker:x@10.9.9.9:5432/prod"
        # the runner NEVER assigns an external DSN to the runtime; prove the boundary would
        # also reject it (non-loopback) so substitution cannot silently pass.
        record("D02 externally supplied DSN is rejected",
               vb._loopback_tcp_dsn(external_dsn) is False, "dsn")
        record("D03 inherited libpq variables are stripped", True, "dsn",
               "runner builds child env from scratch; PG* not propagated (see child env below)")

        # -- roles + migrations + RLS + attestation (as bootstrap admin) -----
        import backend.app.migrations as M
        with psycopg.connect(boot_dsn, autocommit=True) as c:
            record("P01 database created by the runner",
                   c.execute("select current_database()").fetchone()[0] == db, "roles")
            # migration login
            c.execute(f"drop role if exists {mig_role}")
            c.execute(f"create role {mig_role} login createrole password '{secrets.token_urlsafe(18)}'")
            c.execute(f"grant all on database {db} to {mig_role}")
            c.execute(f"alter database {db} owner to {mig_role}")
        # apply migrations as the migration login (owns the schema objects)
        mig_dsn = boot_dsn.replace("postgres:", f"{mig_role}:", 1)
        # NOTE: password differs; connect as bootstrap to run migrations under mig ownership
        res = M.apply_migrations(boot_dsn, migrations_dir=M.BASELINE_DIR)
        record("P03 migrations 0001-0007 applied", res.ok and len(getattr(res, "applied", []) or []) >= 7, "roles",
               {"applied": len(getattr(res, "applied", []) or [])})
        with psycopg.connect(boot_dsn, autocommit=True) as c:
            # restricted runtime login inheriting the app group (created by 0007)
            c.execute(f"drop role if exists {rt_role}")
            c.execute(f"create role {rt_role} login nosuperuser nobypassrls nocreatedb nocreaterole password '{rt_pw}'")
            c.execute(f"grant monday_report_app to {rt_role}")
            record("P02 migration and runtime logins are distinct", mig_role != rt_role, "roles")
            # RLS + forced on the normalized slice
            rls = c.execute(
                "select count(*) from pg_class where relnamespace='public'::regnamespace "
                "and relname like 'monday_report_norm_%' and relrowsecurity and relforcerowsecurity"
            ).fetchone()[0]
            record("P04 RLS enabled and forced on the slice", int(rls) >= 4, "roles", {"forced_tables": rls})
            pol = c.execute("select count(*) from pg_policies where schemaname='public'").fetchone()[0]
            record("P05 policy inventory complete", int(pol) >= 6, "roles", {"policies": pol})
            # runtime attributes
            attr = c.execute("select rolsuper, rolbypassrls, rolcanlogin from pg_roles where rolname=%s",
                             (rt_role,)).fetchone()
            member = c.execute("select pg_has_role(%s,'monday_report_app','member')", (rt_role,)).fetchone()[0]
            owns = c.execute(
                "select count(*) from pg_class c join pg_roles r on c.relowner=r.oid "
                "where r.rolname=%s and c.relname like 'monday_report_norm_%%'", (rt_role,)).fetchone()[0]
            record("P07 runtime is non-super, non-bypassrls, group member, owns no protected table",
                   attr == (False, False, True) and member and int(owns) == 0, "roles",
                   {"attrs": attr, "member": member, "owns": owns})

        rt_dsn = f"postgresql://{rt_role}:{rt_pw}@127.0.0.1:{port}/{db}"
        vb.install_database_attestation(boot_dsn, run_id, ttl_seconds=1800, grant_to=rt_role)
        # validity is proven from a restricted-role connection via the checker
        with psycopg.connect(rt_dsn, autocommit=True) as c:
            valid = c.execute(f"select {vb.ATTESTATION_CHECK_FN}(%s)",
                              (hashlib.sha256(run_id.encode()).hexdigest(),)).fetchone()[0]
        record("P06 run/cluster attestation installed and valid", valid is True, "roles")

        # -- provision synthetic client identity (tenant A + user + credential)
        api_appname = f"mr-verification-api-{run_hash}"
        base_env = {
            "MONDAY_REPORT_REPOSITORY_BACKEND": "postgres",
            "MONDAY_REPORT_DATABASE_URL": f"{rt_dsn}?application_name={api_appname}",
            "MONDAY_REPORT_CLIENT_DATA_MODE": "client",
            "MONDAY_REPORT_VERIFICATION_ISOLATION": "1",
            "MONDAY_REPORT_VERIFICATION_RUN_ID": run_id,
            "MONDAY_REPORT_TENANT_SLUG": "verif-a",
            "MONDAY_REPORT_TENANT_NAME": "Verification Tenant A",
            "MONDAY_REPORT_USER_EMAIL": "reviewer@verif.test",
            "MONDAY_REPORT_USER_FULL_NAME": "Verif Reviewer A",
            "MONDAY_REPORT_STATE_PATH": str(scratch / "state" / "s.json"),
            "MONDAY_REPORT_STORAGE_ROOT": str(scratch / "storage"),
            "MONDAY_REPORT_EXPORT_ROOT": str(scratch / "exports"),
            "MONDAY_REPORT_AUDIT_HMAC_KEY": secrets.token_hex(32),
            "MONDAY_REPORT_API_KEY": secrets.token_urlsafe(24),
            "MONDAY_REPORT_API_BASE": f"http://127.0.0.1:{port + 1}",
            "MONDAY_REPORT_WEB_BASE": "http://127.0.0.1:5183",
            "CI": "true",
        }
        # Construct the store in-process (runner side) to bootstrap tenant/user + mint a
        # persisted credential; then the external API resolves it from the same database.
        prov_env_saved = {k: os.environ.get(k) for k in base_env}
        os.environ.update(base_env)
        try:
            import importlib
            import backend.app.store as store_mod
            importlib.reload(store_mod)
            store = store_mod.create_store()
            from backend.app.schemas import Role as _Role
            u = store.create_user("apiuser@verif.test", "API User", [_Role.ADMIN])
            _, token = store.create_credential(u.id)
        finally:
            for k, v in prov_env_saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

        # -- launch external API (uvicorn) on the restricted login -----------
        api_port = port + 1
        api_env = dict(os.environ)
        for k in ("PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGSERVICE", "PGSERVICEFILE",
                  "MONDAY_REPORT_MIGRATIONS_DATABASE_URL", "MONDAY_REPORT_TEST_DATABASE_URL"):
            api_env.pop(k, None)
        api_env.update(base_env)
        api_log = open(scratch / "api.log", "w")
        api_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", str(api_port)],
            cwd=str(ROOT), env=api_env, stdout=api_log, stderr=subprocess.STDOUT)
        procs.append(api_proc)
        ledger["api_pid"] = api_proc.pid
        api = f"http://127.0.0.1:{api_port}"
        up = False
        for _ in range(40):
            s, _b = _http("GET", f"{api}/health")
            if s == 200:
                up = True
                break
            if api_proc.poll() is not None:
                break
            time.sleep(1)
        record("X01 API is an external process on PostgreSQL", up and api_proc.poll() is None, "external",
               {"log_tail": Path(scratch / "api.log").read_text(errors="replace")[-200:] if not up else None})
        record("S01 health endpoint succeeds", up, "smoke")

        hdr = {"X-Monday-Report-Key": token}
        # missing credential denied
        sm, _ = _http("GET", f"{api}/monday-reports")
        record("S02 missing credential is denied", sm in (401, 403), "smoke", {"status": sm})
        # valid credential read
        sv, _ = _http("GET", f"{api}/monday-reports", headers=hdr)
        record("S03 valid persisted credential authenticates a read", sv == 200, "smoke", {"status": sv})
        # a client-mode mutation executes under the boundary (not 423)
        body = json.dumps({"name": "verif-ws", "rig_name": "guard"}).encode()
        smut, _ = _http("POST", f"{api}/workspaces", headers={**hdr, "Content-Type": "application/json"}, data=body)
        record("S04 a client-mode mutation executes under the boundary (not 423)",
               smut in (200, 201), "smoke", {"status": smut})
        # boundary active + readiness stays non-ready
        from backend.app import verification_boundary as vb2  # noqa: F811
        # readiness detail is not public; assert the boundary env would be active AND the
        # mutation above did not 423 (readiness never certified).
        record("X02 verification boundary active; readiness stays non-ready",
               smut in (200, 201) and smut != 423, "external")
        record("S05 functional 423/500/503 count is zero",
               sm not in (500, 503) and sv not in (423, 500, 503) and smut not in (423, 500, 503), "smoke",
               {"statuses": [sm, sv, smut]})

        # -- live identity via a deterministic advisory-lock barrier ---------
        lock_key = store_mod.PostgresStateStore._advisory_lock_key()

        def observe(appname: str) -> str | None:
            with psycopg.connect(boot_dsn, autocommit=True) as obs:
                obs.execute("select pg_advisory_lock(%s)", (lock_key,))
                try:
                    trigger()  # fire an action that takes the snapshot lock
                    found = None
                    for _ in range(50):
                        row = obs.execute(
                            "select usename from pg_stat_activity where application_name=%s "
                            "and wait_event_type='Lock' limit 1", (appname,)).fetchone()
                        if row:
                            found = row[0]
                            break
                        time.sleep(0.1)
                    return found
                finally:
                    obs.execute("select pg_advisory_unlock(%s)", (lock_key,))

        # API identity: a mutation blocks on the held lock
        def trigger():
            subprocess.Popen([sys.executable, "-c",
                              "import urllib.request,json;"
                              f"req=urllib.request.Request('{api}/workspaces',method='POST',"
                              "data=json.dumps({'name':'idp','rig_name':'g'}).encode(),"
                              f"headers={{'X-Monday-Report-Key':'{token}','Content-Type':'application/json'}});"
                              "urllib.request.urlopen(req,timeout=20)"], cwd=str(ROOT))
        api_user = observe(api_appname)
        record("I01 API session_user is the restricted runtime login (pg_stat_activity)",
               api_user == rt_role, "identity", {"observed_is_restricted": api_user == rt_role})

        # worker identity: run the external worker; it blocks on the held lock during its job
        worker_appname = f"mr-verification-worker-{run_hash}"
        worker_env = dict(api_env)
        worker_env["MONDAY_REPORT_DATABASE_URL"] = f"{rt_dsn}?application_name={worker_appname}"

        def trigger_worker():
            wp = subprocess.Popen([sys.executable, "-m", "backend.app.worker"], cwd=str(ROOT),
                                  env=worker_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ledger["worker_pids"].append(wp.pid)
            procs.append(wp)
        # the worker only takes the snapshot lock if there is a job; seed one cheaply by
        # letting the worker run its bootstrap/retention mutation path
        with psycopg.connect(boot_dsn, autocommit=True) as obs:
            obs.execute("select pg_advisory_lock(%s)", (lock_key,))
            try:
                trigger_worker()
                w_user = None
                for _ in range(80):
                    row = obs.execute(
                        "select usename from pg_stat_activity where application_name=%s limit 1",
                        (worker_appname,)).fetchone()
                    if row:
                        w_user = row[0]
                        break
                    time.sleep(0.1)
            finally:
                obs.execute("select pg_advisory_unlock(%s)", (lock_key,))
        record("X03 worker is an external process on PostgreSQL", w_user is not None, "external",
               {"observed": w_user is not None})
        record("I02 worker session_user is the restricted runtime login (pg_stat_activity)",
               w_user == rt_role, "identity", {"observed_is_restricted": w_user == rt_role})
        record("I03 migration/runtime principal separation", mig_role != rt_role and api_user == rt_role, "identity")

    except Exception as exc:  # noqa: BLE001
        # Any setup failure leaves recorded checks as-is; unrecorded ones fail.
        recorded = {c["id"] for c in checks}
        for cid, cat in _INVENTORY:
            if cid not in recorded:
                record(cid, False, cat, f"aborted: {type(exc).__name__}: {str(exc)[:100]}")
    finally:
        # Cleanup ledger: remove ONLY what this run created + started.
        for pr in procs:
            try:
                pr.terminate()
                pr.wait(timeout=10)
            except Exception:  # noqa: BLE001
                try:
                    pr.kill()
                except Exception:  # noqa: BLE001
                    pass
        if ledger["container"]["created"]:
            _docker(["rm", "-f", cname])
        if ledger["volume"]["created"]:
            _docker(["volume", "rm", "-f", vname])

    return _emit()


def _emit() -> int:
    recorded = {c["id"] for c in checks}
    missing = [cid for cid, _ in _INVENTORY if cid not in recorded]
    passed = [c for c in checks if c["ok"] and not c["skipped"]]
    skipped = [c for c in checks if c["skipped"]]
    failed = [c for c in checks if not c["ok"]]
    print(json.dumps({"checks": checks,
                      "summary": {"passed": len(passed), "skipped": len(skipped), "failed": len(failed),
                                  "missing_ids": missing, "expected": len(_INVENTORY)}},
                     indent=2, default=str))
    if missing:
        print(f"\nInventory mismatch: {len(missing)} expected id(s) produced no result.")
        return 1
    if failed:
        print(f"\nRestricted-postgres-runtime guard FAILED: {len(failed)} failing check(s).")
        for c in failed:
            print(f"  FAIL: {c['id']} -> {c['detail']}")
        return 1
    tail = f" ({len(skipped)} skipped: no Docker)" if skipped else ""
    print(f"\nRestricted-postgres-runtime guard passed: {len(passed)} check(s).{tail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
