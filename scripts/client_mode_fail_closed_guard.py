"""Client-mode fail-closed store-construction guard (M1/M2 remediation proof).

Proves the two PR #19 review residuals stay closed, at the layer each one is
actually enforced:

M1  In client (protected) mode a runtime-role MEASUREMENT failure must fail
    closed: the PostgreSQL server was reachable (schema verification passed)
    but role safety could not be verified, so the protected store must refuse
    to start instead of silently degrading to the local JSON authority. When
    postgres is UNREACHABLE (or no database URL is configured) the app
    deliberately starts degraded so operators can read the readiness blockers
    (``runtime_backend_guard`` / ``infrastructure_readiness_guard`` codify
    that design) -- for that path this guard pins the ROUTE-LAYER defense that
    makes the degrade safe: every sampled business read/write returns 423 and
    nothing is persisted to the degraded local store. (Behavioral sampling on
    top of ``client_data_operation_guard``'s chat/report/export/documents
    blocks; the gate is applied per-route via ``require_client_data_ready``.)

M2  A runtime role that OWNS a protected table must be rejected in client mode
    even when FORCE row level security is enabled (the owner can revoke FORCE
    with plain DDL). Ownership is measured from ``pg_class``, so the rejection
    covers every DB-connection fallback path -- including migrations applied via
    the documented ``DATABASE_URL`` fallback with
    ``MONDAY_REPORT_MIGRATIONS_DATABASE_URL`` unset, where the env-derived
    migration-role equality comparison silently no-ops.

Checks 01-05 are hermetic (no database; the unreachable-postgres scenarios use
a closed loopback port). Checks 06-08 require a REAL disposable PostgreSQL via
``MONDAY_REPORT_TEST_DATABASE_URL``.

Strict foundation mode (``--require-db``): checks 06-08 MUST execute -- a
missing ``MONDAY_REPORT_TEST_DATABASE_URL`` records each of them as a FAILING
check (never a skip) and the guard exits non-zero, so an aggregate chain that
consumes only the return code (``audit:all``) cannot report success for the
M1/M2 foundation proof without the database-backed checks having run. The
``audit:client-mode-fail-closed`` entry and the ``audit:all`` chain invoke this
mode. Without the flag, the ordinary honest-skip convention applies (recorded
skips, exit 0) for intentionally DSN-less environments; a passing pre-merge
run has FAIL=0 and SKIP=0 either way.

Run:  python scripts/client_mode_fail_closed_guard.py [--require-db]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# A closed port on loopback: connection refused / timeout -> a GENERIC store
# construction failure (none of the enumerated role conditions).
DEAD_DSN = "postgresql://mr_dead:x@127.0.0.1:59993/monday_report"

checks: list[dict] = []


def record(name: str, ok: bool, detail: object = "", *, skipped: bool = False) -> None:
    checks.append({"name": name, "ok": bool(ok) or skipped, "skipped": skipped, "detail": detail})


def skip(name: str, reason: str) -> None:
    record(name, True, reason, skipped=True)


def check(name: str, ok: bool, detail: object = "") -> None:
    record(name, ok, detail)


def test_database_url() -> str | None:
    return os.environ.get("MONDAY_REPORT_TEST_DATABASE_URL")


# --------------------------------------------------------------------------- #
# Subprocess probes.
#
# ``backend.app.store`` builds the module-level store at import time from
# environment state, so every scenario runs in a FRESH subprocess with a
# scrubbed, scenario-specific environment and an isolated state root. Each
# probe prints one terminal JSON line.
# --------------------------------------------------------------------------- #
_CONSTRUCT_PROBE = r'''
import json, sys
mode = sys.argv[1]
if mode == "measurement_failure":
    import backend.app.store as store_mod
    def _boom(connection, *, migration_role=None):
        raise RuntimeError("simulated generic runtime-role measurement failure")
    store_mod.assert_runtime_role_safe = _boom
else:
    import backend.app.store as store_mod
try:
    s = store_mod.create_store()
    print(json.dumps({"raised": None, "store_type": type(s).__name__}))
except Exception as exc:
    print(json.dumps({"raised": type(exc).__name__, "store_type": None}))
'''

# Degraded client mode: postgres requested but not constructible -> the app
# comes up on the local fallback. The defense making that safe is the 423
# readiness lock on business routes; sample a WRITE, an UPLOAD and a READ with
# an authenticated ADMIN credential and verify nothing business-shaped lands in
# the degraded local snapshot.
_DEGRADED_ROUTES_PROBE = r'''
import json, os, sys
from pathlib import Path
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.schemas import Role
from backend.app.store import store

out = {"store_type": type(store).__name__}
client = TestClient(app)
admin = store.create_user("cmfc-admin@example.test", "CMFC Admin", [Role.ADMIN])
_cred, token = store.create_credential(admin.id)
headers = {"X-Monday-Report-Key": token}
ws = next(iter(store.workspaces.values()))
r = client.post("/monday-reports", headers=headers, json={
    "workspace_id": str(ws.id), "period_start": "2026-07-06", "period_end": "2026-07-12"})
out["create_report_status"] = r.status_code
r = client.post("/uploads/direct", headers=headers,
                files={"file": ("probe.txt", b"evidence", "text/plain")},
                data={"workspace_id": str(ws.id), "source_type": "files"})
out["upload_status"] = r.status_code
r = client.get("/monday-reports", headers=headers)
out["list_reports_status"] = r.status_code
snap_path = Path(os.environ["MONDAY_REPORT_STATE_PATH"])
if snap_path.exists():
    snap = json.loads(snap_path.read_text(encoding="utf-8"))
    out["persisted_reports"] = len(snap.get("monday_reports", {}) or {})
    out["persisted_files"] = len(snap.get("uploaded_files", {}) or {})
print(json.dumps(out))
'''


def run_probe(probe: str, argv: list[str], *, client: bool, dsn: str | None) -> dict:
    iso = tempfile.mkdtemp(prefix="mr-cmfc-")
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("MONDAY_REPORT_") and k != "DATABASE_URL"}
    env.update({
        "MONDAY_REPORT_CLIENT_DATA_MODE": "client" if client else "demo",
        "MONDAY_REPORT_REPOSITORY_BACKEND": "postgres",
        "MONDAY_REPORT_STATE_PATH": os.path.join(iso, "state.json"),
        "MONDAY_REPORT_STORAGE_ROOT": os.path.join(iso, "storage"),
        "MONDAY_REPORT_EXPORT_ROOT": os.path.join(iso, "exports"),
    })
    if client:
        env.update({
            "MONDAY_REPORT_API_KEY": "cmfc-guard-key-0123456789",
            "MONDAY_REPORT_AUDIT_HMAC_KEY": "cmfc-guard-audit-hmac-key-0123456789abcd",
            "MONDAY_REPORT_SIGNING_SECRET": "cmfc-guard-secret-0123456789abcdef",
            "MONDAY_REPORT_DISABLE_DEMO_SEED": "true",
            "MONDAY_REPORT_TENANT_NAME": "CMFC Guard Tenant",
            "MONDAY_REPORT_TENANT_SLUG": "cmfc-guard",
            "MONDAY_REPORT_USER_EMAIL": "reviewer@example.test",
            "MONDAY_REPORT_USER_FULL_NAME": "CMFC Reviewer",
            "MONDAY_REPORT_DEFAULT_WORKSPACE_NAME": "CMFC guard workspace",
        })
    if dsn is not None:
        env["MONDAY_REPORT_DATABASE_URL"] = dsn
    proc = subprocess.run([sys.executable, "-c", probe, *argv], cwd=str(ROOT),
                          capture_output=True, text=True, env=env, timeout=300)
    for line in reversed(proc.stdout.strip().splitlines() or []):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    # Import-time failure (module-level create_store() raised): classify from stderr.
    tail = proc.stderr.strip().splitlines()
    exc_name = tail[-1].split(":", 1)[0].strip() if tail else "unknown"
    return {"raised": exc_name.rsplit(".", 1)[-1], "store_type": None, "import_time": True}


# --------------------------------------------------------------------------- #
# 01-05 hermetic
# --------------------------------------------------------------------------- #
def hermetic_checks() -> None:
    from backend.app.tenant_rls import PROTECTED_TABLES, runtime_role_violations

    # 01 (M2, unit): ownership WITH FORCE RLS is disqualifying by measurement.
    synthetic = {
        "session_user": "owner_role", "current_user": "owner_role",
        "can_login": True, "is_login_not_group": True, "group_membership": [],
        "is_superuser": False, "has_bypassrls": False,
        "tables": {t: {"rowsecurity": True, "forced": True, "owned": t == PROTECTED_TABLES[0]}
                   for t in PROTECTED_TABLES},
        "missing_forced_tables": [], "owner_bypass_tables": [],
        "forced_normalized_count": 4,
    }
    reasons = runtime_role_violations(synthetic)
    check("01 a runtime role owning a protected table is a violation even with FORCE RLS",
          any("owns a protected table (the owner can disable row level security" in r
              for r in reasons),
          {"reasons": reasons})

    # 02 (M1 defense pin): degraded client mode (unreachable postgres -> local
    # fallback by design) must 423-lock business writes AND reads, and persist
    # no business state to the degraded local snapshot.
    r = run_probe(_DEGRADED_ROUTES_PROBE, [], client=True, dsn=DEAD_DSN)
    check("02 degraded client mode locks business routes (423) and persists nothing",
          r.get("store_type") == "LocalStateStore"
          and r.get("create_report_status") == 423
          and r.get("upload_status") == 423
          and r.get("list_reports_status") == 423
          and r.get("persisted_reports") == 0
          and r.get("persisted_files") == 0,
          r)

    # 03 (M1 defense pin): same lock when postgres is requested with NO
    # database URL configured (the other silent-degrade entry path).
    r = run_probe(_DEGRADED_ROUTES_PROBE, [], client=True, dsn=None)
    check("03 no-database-URL client mode locks business routes (423) and persists nothing",
          r.get("store_type") == "LocalStateStore"
          and r.get("create_report_status") == 423
          and r.get("upload_status") == 423
          and r.get("list_reports_status") == 423
          and r.get("persisted_reports") == 0
          and r.get("persisted_files") == 0,
          r)

    # 04 (contrast): demo mode keeps the documented degrade-with-warning path.
    r = run_probe(_CONSTRUCT_PROBE, ["plain"], client=False, dsn=DEAD_DSN)
    check("04 demo mode: unreachable postgres still degrades to LocalStateStore",
          r.get("store_type") == "LocalStateStore", r)

    # 05 (contrast): demo mode + no URL serves the local store (unchanged).
    r = run_probe(_CONSTRUCT_PROBE, ["plain"], client=False, dsn=None)
    check("05 demo mode: postgres requested with no database URL serves LocalStateStore",
          r.get("store_type") == "LocalStateStore", r)


# --------------------------------------------------------------------------- #
# 06-08 real disposable PostgreSQL
# --------------------------------------------------------------------------- #
def _admin_connect(url: str):
    import psycopg

    c = psycopg.connect(url, connect_timeout=5)
    c.autocommit = True
    return c


def _restricted_dsn(url: str, role: str, password: str) -> str:
    return re.sub(r"//[^@/]+@", f"//{role}:{password}@", url)


def database_checks(url: str) -> None:
    from backend.app import migrations as M
    from backend.app.tenant_rls import PROTECTED_TABLES

    rt_role, owner_role = "cmfc_runtime", "cmfc_owner"
    rt_dsn = _restricted_dsn(url, rt_role, "cmfc_rt_pw")
    owner_dsn = _restricted_dsn(url, owner_role, "cmfc_ow_pw")
    with _admin_connect(url) as c:
        c.execute("drop schema if exists public cascade")
        c.execute("create schema public")
        c.execute("grant all on schema public to public")
    M.apply_migrations(url, migrations_dir=M.BASELINE_DIR)
    try:
        with _admin_connect(url) as c:
            for role, pw in ((rt_role, "cmfc_rt_pw"), (owner_role, "cmfc_ow_pw")):
                c.execute(f"drop role if exists {role}")
                c.execute(
                    f"create role {role} login password '{pw}' "
                    "nosuperuser nobypassrls nocreatedb nocreaterole inherit")
                c.execute(f"grant monday_report_app to {role}")
            c.execute(f"grant usage on schema public to {owner_role}")
            for t in PROTECTED_TABLES:
                c.execute(f'alter table if exists "{t}" owner to {owner_role}')
            forced = c.execute(
                "select count(*) from pg_class where relname = any(%s) "
                "and relforcerowsecurity", (list(PROTECTED_TABLES),)).fetchone()[0]

        # 06 (M1): a generic MEASUREMENT failure over a live, migrated postgres
        # (server reachable, role UNVERIFIED) fails closed in client mode as
        # TenantRuntimeRoleError -- never a silent LocalStateStore.
        r = run_probe(_CONSTRUCT_PROBE, ["measurement_failure"], client=True, dsn=rt_dsn)
        check("06 client mode: a generic runtime-role measurement failure fails closed "
              "as TenantRuntimeRoleError",
              r.get("store_type") is None and r.get("raised") == "TenantRuntimeRoleError",
              r)

        # 07 (M2): the protected-table OWNER role is rejected at startup in
        # client mode even though FORCE RLS is enabled on every protected table,
        # and even though no migration-role env comparison is configured.
        r = run_probe(_CONSTRUCT_PROBE, ["plain"], client=True, dsn=owner_dsn)
        check("07 client mode: a protected-table owner runtime role is rejected "
              "(FORCE RLS on; no MONDAY_REPORT_MIGRATIONS_DATABASE_URL set)",
              r.get("store_type") is None
              and r.get("raised") == "TenantRuntimeRoleError"
              and forced == len(PROTECTED_TABLES),
              {"result": r, "forced_tables": forced})

        # 08 (no false positive): the restricted non-owner runtime role still
        # constructs the protected store under the identical configuration.
        r = run_probe(_CONSTRUCT_PROBE, ["plain"], client=True, dsn=rt_dsn)
        check("08 client mode: the restricted non-owner runtime role is still accepted",
              r.get("store_type") == "PostgresStateStore", r)
    finally:
        with _admin_connect(url) as c:
            for t in PROTECTED_TABLES:
                c.execute(f'alter table if exists "{t}" owner to current_user')
            for role in (rt_role, owner_role):
                c.execute(f"drop owned by {role} cascade")
                c.execute(f"drop role if exists {role}")


DB_CHECK_IDS = ("06", "07", "08")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-db", action="store_true",
        help="strict foundation mode: the DB-backed M1/M2 checks (06-08) MUST "
             "execute; a missing MONDAY_REPORT_TEST_DATABASE_URL records them "
             "as FAILING checks and the guard exits non-zero (never a skip).")
    args = parser.parse_args()

    hermetic_checks()
    url = test_database_url()
    if not url:
        if args.require_db:
            # Strict foundation mode: a required check that cannot execute is a
            # FAILURE, not a skip, so a return-code-only consumer (audit:all)
            # can never report success for the M1/M2 proof without the
            # database-backed checks having run.
            for cid in DB_CHECK_IDS:
                check(f"{cid} real-PostgreSQL scenario", False,
                      "strict foundation mode (--require-db): "
                      "MONDAY_REPORT_TEST_DATABASE_URL is required and the "
                      "DB-backed M1/M2 checks must execute; refusing to skip")
        else:
            for cid in DB_CHECK_IDS:
                skip(f"{cid} real-PostgreSQL scenario",
                     "no MONDAY_REPORT_TEST_DATABASE_URL provided")
    else:
        database_checks(url)

    n_pass = sum(1 for c in checks if c["ok"] and not c["skipped"])
    n_skip = sum(1 for c in checks if c["skipped"])
    n_fail = sum(1 for c in checks if not c["ok"])
    print(json.dumps({"checks": checks,
                      "summary": {"passed": n_pass, "skipped": n_skip, "failed": n_fail,
                                  "postgres": bool(url)}}, indent=2, default=str))
    if n_fail:
        print(f"\nClient-mode fail-closed guard FAILED: {n_fail} failing check(s).")
        for c in checks:
            if not c["ok"]:
                print(f"  FAIL: {c['name']} -> {c['detail']}")
        return 1
    tail = f" ({n_skip} skipped: no disposable PostgreSQL)" if n_skip else ""
    print(f"\nClient-mode fail-closed guard passed: {n_pass} check(s).{tail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
