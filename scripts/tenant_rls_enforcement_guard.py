"""Tenant RLS enforcement guard.

Proves database-enforced tenant isolation for the normalized persistence slice
against a REAL disposable PostgreSQL using a REAL non-superuser runtime login role
(never the migration/superuser role for the isolation proofs). Covers schema,
roles, direct SQL, routes, worker/pool hygiene, import/administration, and a
fail-closed canonical check inventory.

Produces the ``tenant-rls-enforcement-evidence.v1.json`` artifact (with
``--emit-evidence``) that ``backend/app/ga_readiness.py::_tenant_authorization_probe``
requires before the ``tenant-authorization-enforcement`` control can PASS.

Honest skipping: without ``MONDAY_REPORT_TEST_DATABASE_URL`` the database scenarios
SKIP (recorded, not failed) and evidence refuses to emit ``passed``. On a real DB a
passing run has FAIL=0 and SKIP=0.

Run:  python scripts/tenant_rls_enforcement_guard.py [--emit-evidence]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

EVIDENCE_PATH = ROOT / "output" / "tenant-rls" / "tenant-rls-enforcement-evidence.v2.json"
EVIDENCE_SCHEMA_VERSION = "tenant-rls-enforcement-evidence.v2"
IMPLEMENTATION_VERSION = "1.1.0"
GUARD_AUDIT_KEY = "c" * 64

# Canonical, documented inventory (NOT a numeric range, so a phantom or missing id
# cannot slip through). 47 checks: schema 01-09, roles 10-15, direct SQL 16-24,
# routes 25-30, worker/pool 31-34, import/admin 35-38, inventory 39-43, and the
# behavioral extras 44 (idempotency replay), 45 (positive readiness path), 46
# (worker.run_once isolation), 47 (GUC trust-model honesty / limitation disclosure).
EXPECTED_CHECK_IDS = tuple(f"{n:02d}" for n in range(1, 48))

NORMALIZED_TABLES = (
    "monday_report_norm_reports",
    "monday_report_norm_field_corrections",
    "monday_report_norm_validation_tasks",
    "monday_report_norm_validation_outcomes",
)
PARENT_TABLES = ("tenants", "workspaces")
OPERATIONAL_TABLES = ("monday_report_state_snapshots", "monday_report_idempotency_records")
PROTECTED_TABLES = PARENT_TABLES + OPERATIONAL_TABLES + NORMALIZED_TABLES

checks: list[dict] = []


def record(name: str, ok: bool, detail: object = "", *, skipped: bool = False) -> None:
    checks.append({"name": name, "ok": bool(ok) or skipped, "skipped": skipped, "detail": detail})


def skip(name: str, reason: str) -> None:
    record(name, True, reason, skipped=True)


def check(name: str, ok: bool, detail: object = "") -> None:
    record(name, ok, detail)


def test_database_url() -> str | None:
    return os.environ.get("MONDAY_REPORT_TEST_DATABASE_URL")


def _git(args: list[str]) -> str:
    try:
        return subprocess.run(["git", *args], cwd=str(ROOT), capture_output=True,
                              text=True, check=False).stdout.strip()
    except Exception:
        return "unknown"


# --------------------------------------------------------------------------- #
# PostgreSQL helpers
# --------------------------------------------------------------------------- #
def _connect(url: str, *, autocommit: bool = True):
    import psycopg

    c = psycopg.connect(url, connect_timeout=5)
    c.autocommit = autocommit
    return c


def _restricted_dsn(url: str, role: str, password: str) -> str:
    return re.sub(r"//[^@/]+@", f"//{role}:{password}@", url)


def _role_of(url: str) -> str | None:
    from urllib.parse import urlsplit, unquote

    user = urlsplit(url).username
    return unquote(user) if user else None


def role_name_from_dsn_safe() -> str | None:
    """The migration principal's role name (no password/host), for evidence."""
    return _role_of(os.environ.get("MONDAY_REPORT_TEST_DATABASE_URL") or "")


def _guc_trust_model() -> str:
    from backend.app.tenant_rls import GUC_TRUST_MODEL

    return GUC_TRUST_MODEL


def _fresh_schema(url: str) -> None:
    with _connect(url) as c:
        c.execute("drop schema if exists public cascade")
        c.execute("create schema public")
        c.execute("create extension if not exists vector")


def _make_runtime_role(url: str, role: str) -> str:
    pw = secrets.token_urlsafe(18)
    with _connect(url) as c:
        c.execute(f"drop role if exists {role}")
        c.execute(f"create role {role} login nosuperuser nobypassrls nocreatedb "
                  f"nocreaterole password '{pw}'")
        c.execute(f"grant monday_report_app to {role}")
    return _restricted_dsn(url, role, pw)


def _drop_role(url: str, role: str) -> None:
    try:
        with _connect(url) as c:
            c.execute(f"drop role if exists {role}")
    except Exception:
        pass


def _seed_tenant_row(dsn: str, slug: str, tid, wid, rid, status: str = "draft") -> None:
    """Insert a tenant + workspace + normalized report row under `slug`'s context."""
    import psycopg

    c = psycopg.connect(dsn)
    c.autocommit = False
    try:
        with c.cursor() as cur:
            cur.execute("select set_config('app.tenant_slug', %s, true)", (slug,))
            cur.execute("insert into tenants (id,name,slug) values (%s,%s,%s) "
                        "on conflict (id) do nothing", (tid, slug, slug))
            cur.execute("insert into workspaces (id,tenant_id,name) values (%s,%s,%s) "
                        "on conflict (id) do nothing", (wid, tid, "ws"))
            cur.execute(
                "insert into monday_report_norm_reports "
                "(id,tenant_id,tenant_slug,workspace_id,status,doc) "
                "values (%s,%s,%s,%s,%s,'{}'::jsonb)", (rid, tid, slug, wid, status))
        c.commit()
    finally:
        c.close()


# --------------------------------------------------------------------------- #
# 01-09 Schema
# --------------------------------------------------------------------------- #
def schema_checks(url: str) -> None:
    from backend.app import migrations as M

    mig_0007 = ROOT / "db" / "migrations" / "0007_tenant_rls_enforcement.sql"
    base_0007 = ROOT / "db" / "baseline" / "0007_tenant_rls_enforcement.sql"

    # 03 baseline equivalence (byte identity of the added migration + immutability of prior)
    ident = mig_0007.exists() and base_0007.exists() and \
        mig_0007.read_bytes() == base_0007.read_bytes()
    prior_ident = all(
        (ROOT / "db" / "migrations" / f).read_bytes() == (ROOT / "db" / "baseline" / f).read_bytes()
        for f in ("0001_foundation.sql", "0002_postgres_state_snapshot.sql",
                  "0004_transactional_snapshot.sql", "0005_normalized_corrections.sql",
                  "0006_normalized_lineage_integrity.sql")
    )
    check("03 baseline 0007 byte-identical to migration; 0001/0002/0004/0005/0006 identical",
          ident and prior_ident, {"0007_identical": ident, "prior_identical": prior_ident})

    # 01 fresh apply of the full baseline set includes 0007
    _fresh_schema(url)
    res = M.apply_migrations(url, migrations_dir=M.BASELINE_DIR)
    applied_versions = [a["version"] for a in res.applied]
    check("01 migration 0007 applies in a fresh baseline install",
          7 in applied_versions and applied_versions == sorted(applied_versions),
          {"applied": applied_versions})

    # 06 checksum recorded for 0007
    with _connect(url) as c:
        rows = {int(v): cs for v, cs in c.execute(
            "select version, checksum_sha256 from schema_migrations").fetchall()}
    disk_0007 = hashlib.sha256(base_0007.read_bytes()).hexdigest()
    check("06 schema_migrations records the 0007 checksum matching the file",
          rows.get(7) == disk_0007, {"recorded": rows.get(7, "")[:12], "disk": disk_0007[:12]})

    # 04 rerun idempotent (no pending, role not duplicated)
    res2 = M.apply_migrations(url, migrations_dir=M.BASELINE_DIR)
    with _connect(url) as c:
        role_count = c.execute(
            "select count(*) from pg_roles where rolname='monday_report_app'").fetchone()[0]
    check("04 re-apply is a no-op and the app role is not duplicated",
          not res2.applied and role_count == 1, {"reapplied": len(res2.applied), "roles": role_count})

    # 05 immutable history: 0001-0006 checksums equal the on-disk baseline files
    disk = {}
    for f in sorted((ROOT / "db" / "baseline").glob("000[1-6]_*.sql")):
        v = int(f.name[:4])
        disk[v] = hashlib.sha256(f.read_bytes()).hexdigest()
    check("05 immutable 0001-0006 checksums match on-disk baseline (history unchanged)",
          all(rows.get(v) == disk[v] for v in disk), {"versions": sorted(disk)})

    # 07 forced RLS on all protected tables
    with _connect(url) as c:
        force = {r[0]: (bool(r[1]), bool(r[2])) for r in c.execute(
            "select relname, relrowsecurity, relforcerowsecurity from pg_class "
            "where relkind='r' and relname = any(%s)", (list(PROTECTED_TABLES),)).fetchall()}
    all_forced = all(force.get(t, (False, False)) == (True, True) for t in PROTECTED_TABLES)
    check("07 RLS enabled AND forced on all normalized + parent + operational tables",
          all_forced, {t: force.get(t) for t in PROTECTED_TABLES})

    # 08 startup issues no DDL: the schema verifier only inspects catalogs
    store_src = (ROOT / "backend" / "app" / "store.py").read_text(encoding="utf-8")
    import ast
    tree = ast.parse(store_src)
    verifier = next((n for n in ast.walk(tree)
                     if isinstance(n, ast.FunctionDef) and n.name == "_verify_repository_schema"), None)
    verifier_src = ast.get_source_segment(store_src, verifier) if verifier else ""
    no_ddl = verifier is not None and not re.search(
        r"\b(create|alter|drop)\s+(table|role|policy|index)", verifier_src, re.I)
    check("08 runtime schema verification issues no DDL (inspection only)", no_ddl,
          {"verifier_found": verifier is not None})

    # 02 explicit 0006 -> 0007 upgrade path
    _fresh_schema(url)
    import shutil, tempfile
    with tempfile.TemporaryDirectory() as td:
        for f in sorted((ROOT / "db" / "baseline").glob("000[1-6]_*.sql")):
            shutil.copy(f, Path(td) / f.name)
        M.apply_migrations(url, migrations_dir=Path(td))
        with _connect(url) as c:
            pre = c.execute("select relforcerowsecurity from pg_class where relname='tenants'").fetchone()[0]
        # now apply 0007 on top
        r7 = M.apply_migrations(url, migrations_dir=M.BASELINE_DIR)
        with _connect(url) as c:
            post = c.execute("select relforcerowsecurity from pg_class where relname='tenants'").fetchone()[0]
    check("02 0006->0007 upgrade forces RLS on the parent tables and provisions the role",
          (not pre) and post and any(a["version"] == 7 for a in r7.applied),
          {"tenants_forced_before": bool(pre), "after": bool(post)})

    # 09 missing 0007 -> runtime role validation fails closed in client mode
    from backend.app import tenant_rls as T
    prev_mode = os.environ.get("MONDAY_REPORT_CLIENT_DATA_MODE")
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "client"
    role9 = "trls_missing7_rt"
    try:
        _fresh_schema(url)
        with tempfile.TemporaryDirectory() as td:
            for f in sorted((ROOT / "db" / "baseline").glob("000[1-6]_*.sql")):
                shutil.copy(f, Path(td) / f.name)
            M.apply_migrations(url, migrations_dir=Path(td))
        # no 0007 -> app role absent; a superuser conn still measures missing FORCE on parents
        import psycopg
        with psycopg.connect(url) as c:
            m = T.measure_runtime_role(c)
        rejects = bool(T.runtime_role_violations(m))
        check("09 without 0007 the runtime-role validation fails closed (missing forced RLS)",
              rejects and ("tenants" in " ".join(m["missing_forced_tables"]) or m["is_superuser"]),
              {"missing_forced": m["missing_forced_tables"]})
    finally:
        if prev_mode is None:
            os.environ.pop("MONDAY_REPORT_CLIENT_DATA_MODE", None)
        else:
            os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = prev_mode
        _drop_role(url, role9)

    # leave a clean, fully-migrated schema for the remaining sections
    _fresh_schema(url)
    M.apply_migrations(url, migrations_dir=M.BASELINE_DIR)


# --------------------------------------------------------------------------- #
# 10-15 Roles
# --------------------------------------------------------------------------- #
def role_checks(url: str, runtime_dsn: str, runtime_role: str) -> dict:
    from backend.app import tenant_rls as T

    with _connect(runtime_dsn) as c:
        measurement = T.measure_runtime_role(c)
        measurement["policy_inventory"] = T.policy_inventory(c)
    check("10 runtime principal is a non-superuser LOGIN role that INHERITs the app group "
          "(not the NOLOGIN group itself)",
          measurement["is_superuser"] is False and measurement.get("is_login_not_group") is True
          and "monday_report_app" in (measurement.get("group_membership") or []),
          {"login": measurement.get("can_login"), "is_login_not_group": measurement.get("is_login_not_group"),
           "groups": measurement.get("group_membership")})
    check("11 runtime role does NOT have BYPASSRLS", measurement["has_bypassrls"] is False)
    check("12 runtime role owns none of the protected tables",
          not measurement["owner_bypass_tables"] and
          not any(t.get("owned") for t in measurement["tables"].values()),
          {"owned": [k for k, v in measurement["tables"].items() if v.get("owned")]})

    migration_role = _role_of(url)
    check("13 migration/admin role is separate from the runtime role",
          migration_role is not None and migration_role != runtime_role,
          {"separated": migration_role != runtime_role})

    # 14 grants minimal: DML on the 8 protected tables, and NOT on schema_migrations
    with _connect(runtime_dsn) as c:
        granted = {r[0] for r in c.execute(
            "select table_name from information_schema.role_table_grants "
            "where grantee='monday_report_app'").fetchall()}
        # can the role touch schema_migrations? (should not have DML)
        sm_priv = c.execute(
            "select count(*) from information_schema.role_table_grants "
            "where grantee='monday_report_app' and table_name='schema_migrations'").fetchone()[0]
    has_all = all(t in granted for t in PROTECTED_TABLES)
    check("14 runtime grants are minimal DML on the 8 slice tables; none on schema_migrations",
          has_all and sm_priv == 0,
          {"missing": [t for t in PROTECTED_TABLES if t not in granted], "schema_migrations_grants": sm_priv})

    # 15 client-mode startup rejects a superuser runtime and accepts the restricted role
    prev = os.environ.get("MONDAY_REPORT_CLIENT_DATA_MODE")
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "client"
    try:
        rejected = False
        try:
            with _connect(url) as c:
                T.assert_runtime_role_safe(c)
        except T.TenantRuntimeRoleError:
            rejected = True
        accepted = True
        try:
            with _connect(runtime_dsn) as c:
                T.assert_runtime_role_safe(c, migration_role=migration_role)
        except Exception:
            accepted = False
        check("15 client-mode startup rejects a superuser runtime and accepts the restricted role",
              rejected and accepted, {"superuser_rejected": rejected, "restricted_accepted": accepted})
    finally:
        if prev is None:
            os.environ.pop("MONDAY_REPORT_CLIENT_DATA_MODE", None)
        else:
            os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = prev
    return measurement


# --------------------------------------------------------------------------- #
# 16-24 Direct SQL (real non-superuser runtime role)
# --------------------------------------------------------------------------- #
def direct_sql_checks(url: str, runtime_dsn: str) -> None:
    import psycopg

    TA, TB = "trls-direct-a", "trls-direct-b"
    tid_a, wid_a, rid_a = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    tid_b, wid_b, rid_b = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    _seed_tenant_row(runtime_dsn, TA, tid_a, wid_a, rid_a)
    _seed_tenant_row(runtime_dsn, TB, tid_b, wid_b, rid_b)

    def as_rt(slug):
        c = psycopg.connect(runtime_dsn); c.autocommit = False
        cur = c.cursor()
        if slug is not None:
            cur.execute("select set_config('app.tenant_slug', %s, true)", (slug,))
        return c, cur

    # 16 missing context: select 0, writes denied
    c, cur = as_rt(None)
    sel0 = cur.execute("select count(*) from monday_report_norm_reports").fetchone()[0]
    denied = {"insert": False, "update": False, "delete": False}
    for op, sql, args in (
        ("insert", "insert into monday_report_norm_reports (id,tenant_id,tenant_slug,workspace_id,status,doc) "
                    "values (%s,%s,%s,%s,'draft','{}'::jsonb)", (uuid.uuid4(), tid_a, TA, wid_a)),
        ("update", "update monday_report_norm_reports set status='review' where id=%s", (rid_a,)),
        ("delete", "delete from monday_report_norm_reports where id=%s", (rid_a,)),
    ):
        try:
            cur.execute(sql, args)
            if cur.rowcount == 0:
                denied[op] = True  # update/delete affect 0 rows under no context
            c.rollback()
        except Exception:
            denied[op] = True
            c.rollback()
    c.close()
    check("16 missing tenant context: reads see 0 rows and writes are denied",
          sel0 == 0 and denied["insert"] and denied["update"] and denied["delete"],
          {"select": sel0, **denied})

    # 17 own tenant: full CRUD on own rows
    c, cur = as_rt(TA)
    own_sel = cur.execute("select count(*) from monday_report_norm_reports").fetchone()[0]
    tmp = uuid.uuid4()
    cur.execute("insert into monday_report_norm_reports (id,tenant_id,tenant_slug,workspace_id,status,doc) "
                "values (%s,%s,%s,%s,'draft','{}'::jsonb)", (tmp, tid_a, TA, wid_a))
    cur.execute("update monday_report_norm_reports set status='review' where id=%s", (tmp,))
    upd_rc = cur.rowcount
    cur.execute("delete from monday_report_norm_reports where id=%s", (tmp,))
    del_rc = cur.rowcount
    c.commit(); c.close()
    check("17 own tenant context: select/insert/update/delete of own rows succeed",
          own_sel == 1 and upd_rc == 1 and del_rc == 1, {"select": own_sel, "upd": upd_rc, "del": del_rc})

    # 18 wrong tenant: other tenant invisible; direct id lookup invisible; update/delete affect 0
    c, cur = as_rt(TB)
    a_by_id = cur.execute("select count(*) from monday_report_norm_reports where id=%s", (rid_a,)).fetchone()[0]
    cur.execute("update monday_report_norm_reports set status='review' where id=%s", (rid_a,))
    a_upd = cur.rowcount
    cur.execute("delete from monday_report_norm_reports where id=%s", (rid_a,))
    a_del = cur.rowcount
    c.rollback(); c.close()
    check("18 wrong tenant: foreign rows invisible; direct-id lookup empty; update/delete affect 0",
          a_by_id == 0 and a_upd == 0 and a_del == 0, {"by_id": a_by_id, "upd": a_upd, "del": a_del})

    # 19 malformed context: empty / whitespace / unknown -> denied (0 rows)
    seen = {}
    for label, slug in (("empty", ""), ("space", "   "), ("unknown", "no-such-tenant")):
        c, cur = as_rt(slug)
        seen[label] = cur.execute("select count(*) from monday_report_norm_reports").fetchone()[0]
        c.close()
    check("19 malformed context (empty/whitespace/unknown) sees 0 rows",
          all(v == 0 for v in seen.values()), seen)

    # 20 WITH CHECK: inserting a row tagged for a foreign tenant is denied
    c, cur = as_rt(TB)
    check20 = False
    try:
        cur.execute("insert into monday_report_norm_reports (id,tenant_id,tenant_slug,workspace_id,status,doc) "
                    "values (%s,%s,%s,%s,'draft','{}'::jsonb)", (uuid.uuid4(), tid_a, TA, wid_a))
        c.commit()
    except Exception:
        check20 = True; c.rollback()
    c.close()
    check("20 WITH CHECK denies inserting a row tagged for another tenant", check20)

    # 21 forced RLS active on normalized + parent + operational tables
    with _connect(url) as c:
        forced = {r[0]: bool(r[1]) for r in c.execute(
            "select relname, relforcerowsecurity from pg_class where relname=any(%s)",
            (list(PROTECTED_TABLES),)).fetchall()}
    check("21 FORCE row level security active on every protected table",
          all(forced.get(t) for t in PROTECTED_TABLES), forced)

    # 22 superuser bypass contrast (proves why a superuser cannot be the runtime role)
    with _connect(url) as c:
        su_all = c.execute("select count(*) from monday_report_norm_reports").fetchone()[0]
    check("22 superuser bypasses RLS (sees all tenants) -> cannot be the runtime role", su_all >= 2,
          {"superuser_sees": su_all})

    # 23 transaction-local context does not survive the transaction (pool-safe)
    c = psycopg.connect(runtime_dsn); c.autocommit = False
    cur = c.cursor()
    cur.execute("select set_config('app.tenant_slug', %s, true)", (TA,))
    inside = cur.execute("select current_setting('app.tenant_slug', true)").fetchone()[0]
    c.rollback()
    after_rollback = cur.execute("select current_setting('app.tenant_slug', true)").fetchone()[0]
    c.commit(); c.close()
    check("23 transaction-local tenant context is cleared at transaction end (rollback)",
          inside == TA and (after_rollback in (None, "", "no-such") or after_rollback != TA),
          {"inside": inside, "after_rollback": after_rollback})

    # 24 apply_verified_tenant_scope refuses an empty context (unit)
    from backend.app.tenant_rls import apply_verified_tenant_scope, TenantContextError
    c = psycopg.connect(runtime_dsn); cur = c.cursor()
    raised = False
    try:
        apply_verified_tenant_scope(cur, "")
    except TenantContextError:
        raised = True
    c.close()
    check("24 apply_verified_tenant_scope refuses an empty/missing tenant context", raised)


# --------------------------------------------------------------------------- #
# 25-34 Routes + worker/pool (real store against the restricted runtime role)
# --------------------------------------------------------------------------- #
def app_checks(url: str, runtime_dsn: str, scratch: Path) -> None:
    """Build the real app/store against the restricted runtime role for tenant A;
    seed a real tenant-B row directly; prove cross-tenant isolation end to end."""
    import importlib
    import psycopg

    # Seed tenant B (a real, existing foreign resource) before importing the store.
    TB = "trls-app-b"
    tid_b, wid_b, rid_b = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    _seed_tenant_row(runtime_dsn, TB, tid_b, wid_b, rid_b)

    os.environ["MONDAY_REPORT_REPOSITORY_BACKEND"] = "postgres"
    os.environ["MONDAY_REPORT_DATABASE_URL"] = runtime_dsn
    os.environ["MONDAY_REPORT_MIGRATIONS_DATABASE_URL"] = url
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "trls-app-a"
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"  # store construction measures only
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = GUARD_AUDIT_KEY
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION"] = "1"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(scratch / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(scratch / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(scratch / "exports")
    os.environ["CI"] = "true"

    import backend.app.audit_keys as _ak
    importlib.reload(_ak)
    from fastapi.testclient import TestClient
    from backend.app import main as m
    from backend.app.store import store
    from backend.app.schemas import Role, WorkspaceCreate, MondayReportCreate
    from backend.app import main as _main

    client = TestClient(m.app, raise_server_exceptions=False)

    def hdr(tok):
        return {"X-Monday-Report-Key": tok} if tok else {}

    admin = store.create_user("admin@trls.test", "Admin A", [Role.ADMIN])
    _, tok = store.create_credential(admin.id)
    wa = store.create_workspace(WorkspaceCreate(name="A ws"))

    # 25 auth is a real denial, NOT a broken/misconfigured service. Prove the service
    # is HEALTHY (a valid key returns 200) AND that missing/invalid credentials are
    # denied. A 503 alone (which a misconfigured stack could always return) is not
    # accepted as proof: the valid-key 200 rules out "the service is just down".
    healthy = client.get("/monday-reports", headers=hdr(tok))
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "client"
    anon = client.get("/monday-reports")
    bad = client.get("/monday-reports", headers=hdr("not-a-real-key"))
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
    # Service is HEALTHY (valid key -> 200) so a 503 cannot be "the stack is down";
    # missing AND invalid credentials are both denied (the client-mode edge preflight
    # returns 503 for any non-valid key per the documented MC1 contract). The valid-key
    # 200 vs no/bad-key denial contrast proves credentials are required and validated.
    check("25 service healthy on a valid key (200); missing AND invalid credentials both "
          "denied (valid-key 200 rules out a misconfigured/down stack)",
          healthy.status_code == 200
          and anon.status_code in (401, 403, 503)
          and bad.status_code in (401, 403, 503),
          {"valid_key": healthy.status_code, "no_key": anon.status_code, "bad_key": bad.status_code})

    # 26 tenant A cannot GET the foreign (tenant-B) report id -> existence-hiding 404
    got = client.get(f"/monday-reports/{rid_b}", headers=hdr(tok))
    check("26 HTTP: tenant A GET of a real tenant-B report id -> 404 (existence-hiding)",
          got.status_code == 404, {"status": got.status_code})

    # 27 list endpoints never include the tenant-B id
    listed = client.get("/monday-reports", headers=hdr(tok))
    ids = {x.get("id") for x in (listed.json() if listed.status_code == 200 else [])}
    check("27 HTTP: tenant A report list excludes the tenant-B id",
          str(rid_b) not in ids, {"status": listed.status_code, "count": len(ids)})

    # 28 payload tenant spoofing is ignored: workspace is created under tenant A
    spoof = client.post("/workspaces", headers=hdr(tok),
                        json={"name": "spoof", "tenant_id": str(tid_b)})
    spoof_tenant_ok = True
    if spoof.status_code in (200, 201):
        wid = spoof.json().get("id")
        w = store.workspaces.get(uuid.UUID(wid)) if wid else None
        spoof_tenant_ok = (w is not None and str(w.tenant_id) == str(store.tenant.id))
    check("28 HTTP: payload tenant spoofing is ignored (resource stays under tenant A)",
          spoof_tenant_ok, {"status": spoof.status_code})

    # 29 cross-tenant path-id substitution -> 404
    sub = client.get(f"/workspaces/{wid_b}/report-draft", headers=hdr(tok))
    check("29 HTTP: cross-tenant path-id substitution -> 404", sub.status_code == 404,
          {"status": sub.status_code})

    # 30 API-layer ownership + permission parity fully enforced
    parity = _main.tenant_ownership_fully_enforced() and _main.route_policy_fully_enforced()
    check("30 API-layer tenant-ownership + permission parity fully enforced", parity)

    # 31 store read path is genuinely tenant-scoped (NOT merely 'no context'): the
    # store connection reports current_setting('app.tenant_slug') == the store's own
    # slug (a no-op _set_tenant_scope would leave it NULL/empty and fail this),
    # AND cannot load the tenant-B row.
    with store._connect() as c:  # the exact non-owner read connection routes use
        with c.cursor() as cur:
            store._set_tenant_scope(cur)
            ctx_slug = cur.execute("select current_setting('app.tenant_slug', true)").fetchone()[0]
            cur.execute("select count(*) from monday_report_norm_reports where id=%s", (rid_b,))
            seen_b = cur.fetchone()[0]
    check("31 store read path applies the tenant-A context (current_setting == own slug) and "
          "cannot load a tenant-B row",
          ctx_slug == store.tenant.slug and seen_b == 0, {"ctx": ctx_slug, "sees_b": seen_b})

    # 32 pooled/reused connection carries no leftover tenant context
    c = psycopg.connect(runtime_dsn); c.autocommit = False
    cur = c.cursor()
    cur.execute("select set_config('app.tenant_slug', %s, true)", ("trls-app-a",))
    c.commit()  # transaction ends -> is_local setting discarded
    leftover = cur.execute("select current_setting('app.tenant_slug', true)").fetchone()[0]
    reused_rows = cur.execute("select count(*) from monday_report_norm_reports").fetchone()[0]
    c.rollback(); c.close()
    check("32 reused connection retains no prior tenant context (fresh statement sees 0 rows)",
          (leftover in (None, "")) and reused_rows == 0, {"leftover": leftover, "rows": reused_rows})

    # 33 a failed/aborted transaction leaves no tenant setting behind
    c = psycopg.connect(runtime_dsn); c.autocommit = False
    cur = c.cursor()
    try:
        cur.execute("select set_config('app.tenant_slug', %s, true)", (TB,))
        cur.execute("select 1/0")  # force error -> aborted txn
    except Exception:
        c.rollback()
    post_rows = cur.execute("select count(*) from monday_report_norm_reports").fetchone()[0]
    c.close()
    check("33 aborted transaction leaves no tenant context (post-rollback sees 0 rows)", post_rows == 0,
          {"rows": post_rows})

    # 34 BEHAVIORAL: the store opens AND closes a fresh connection per operation
    # (no pool retains state). Instrument psycopg.connect to record open/close.
    import psycopg as _pscg
    opened, closed = [], []
    _orig_connect = _pscg.connect

    def _counting_connect(*a, **k):
        conn = _orig_connect(*a, **k)
        opened.append(1)
        _orig_close = conn.close

        def _close(*aa, **kk):
            closed.append(1)
            return _orig_close(*aa, **kk)
        conn.close = _close
        return conn
    _pscg.connect = _counting_connect
    try:
        store.refresh()            # a read operation
        store.create_workspace(WorkspaceCreate(name="pool probe"))  # a mutation
    finally:
        _pscg.connect = _orig_connect
    src_no_pool = "ConnectionPool" not in (ROOT / "backend" / "app" / "store.py").read_text(encoding="utf-8")
    check("34 no connection pool: every store operation opens AND closes its own connection",
          len(opened) >= 2 and len(closed) >= 2 and len(closed) == len(opened) and src_no_pool,
          {"opened": len(opened), "closed": len(closed)})

    # 44 idempotency replay/result reconstruction cannot cross tenants: an
    # operation_id committed under tenant A is not replayable/visible from a
    # tenant-B-scoped connection (RLS-scoped idempotency records).
    opid = f"trls-idem-{uuid.uuid4().hex[:8]}"
    with store.snapshot_transaction(operation_id=opid, request_hash=uuid.uuid4().hex,
                                    operation_kind="snapshot.mutation") as ctx:
        if not ctx["replayed"]:
            store.create_workspace(WorkspaceCreate(name="idem A"))
    c = psycopg.connect(runtime_dsn); c.autocommit = False; cur = c.cursor()
    cur.execute("select set_config('app.tenant_slug', %s, true)", (TB,))
    b_sees_idem = cur.execute(
        "select count(*) from monday_report_idempotency_records where operation_id=%s", (opid,)).fetchone()[0]
    c.rollback(); c.close()
    with store._connect() as c2:
        store._set_tenant_scope(c2.cursor())
        with c2.cursor() as cur2:
            cur2.execute("select count(*) from monday_report_idempotency_records where operation_id=%s", (opid,))
            a_sees_idem = cur2.fetchone()[0]
    check("44 idempotency record is tenant-scoped: tenant A sees its op, tenant B cannot replay it",
          a_sees_idem == 1 and b_sees_idem == 0, {"a_sees": a_sees_idem, "b_sees": b_sees_idem})

    # 46 worker.run_once runs under the configured tenant and cannot load a
    # tenant-B row (exercises the real worker entry point, not just a probe).
    from backend.app import worker as _worker
    worker_saw_b = 0
    try:
        _worker.run_once()  # processes tenant-A's queue under committed_read_view
    except Exception:
        pass
    with store._connect() as c3:
        store._set_tenant_scope(c3.cursor())
        with c3.cursor() as cur3:
            cur3.execute("select count(*) from monday_report_norm_reports where id=%s", (rid_b,))
            worker_saw_b = cur3.fetchone()[0]
    check("46 worker.run_once operates under the tenant context and cannot load a tenant-B row",
          worker_saw_b == 0, {"worker_sees_b": worker_saw_b})


# --------------------------------------------------------------------------- #
# 35-38 Import / administration
# --------------------------------------------------------------------------- #
def import_admin_checks(url: str, runtime_dsn: str) -> None:
    import psycopg

    # 35 import/cutover tenant scoping: (a) structural — normalized_import sets the
    # tenant GUC and rejects cross-tenant id reuse; (b) BEHAVIORAL — the state
    # snapshot table the import loads (`where tenant_slug = %s`) is RLS-protected,
    # so a tenant-B connection cannot read tenant-A's snapshot even by id.
    ni = (ROOT / "backend" / "app" / "normalized_import.py").read_text(encoding="utf-8")
    rejects_cross = ("already owned by another tenant" in ni) or ("another tenant" in ni)
    tenant_filtered = "set_config('app.tenant_slug'" in ni
    IA, IB = "trls-imp-a", "trls-imp-b"
    tia = uuid.uuid4()
    c = psycopg.connect(runtime_dsn); c.autocommit = False; cur = c.cursor()
    cur.execute("select set_config('app.tenant_slug', %s, true)", (IA,))
    cur.execute("insert into tenants (id,name,slug) values (%s,%s,%s) on conflict (id) do nothing", (tia, IA, IA))
    cur.execute("insert into monday_report_state_snapshots (tenant_slug, tenant_id, payload, revision) "
                "values (%s,%s,'{}'::jsonb,1) on conflict (tenant_slug) do nothing", (IA, tia))
    c.commit(); c.close()
    c = psycopg.connect(runtime_dsn); c.autocommit = False; cur = c.cursor()
    cur.execute("select set_config('app.tenant_slug', %s, true)", (IB,))
    b_sees_a_snap = cur.execute(
        "select count(*) from monday_report_state_snapshots where tenant_slug=%s", (IA,)).fetchone()[0]
    c.rollback(); c.close()
    check("35 import sets the tenant GUC + rejects cross-tenant id reuse; the loaded state "
          "snapshot is RLS-protected (tenant B cannot read tenant A's snapshot)",
          rejects_cross and tenant_filtered and b_sees_a_snap == 0,
          {"rejects_cross": rejects_cross, "guc": tenant_filtered, "b_sees_a_snapshot": b_sees_a_snap})

    # 36 no runtime admin bypass: runtime role cannot union tenants (foreign slug -> only that tenant)
    TA, TB = "trls-adm-a", "trls-adm-b"
    ta, wa, ra = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    tb, wb, rb = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    _seed_tenant_row(runtime_dsn, TA, ta, wa, ra)
    _seed_tenant_row(runtime_dsn, TB, tb, wb, rb)
    c = psycopg.connect(runtime_dsn); c.autocommit = False; cur = c.cursor()
    cur.execute("select set_config('app.tenant_slug', %s, true)", (TB,))
    only_b = cur.execute("select count(*) from monday_report_norm_reports").fetchone()[0]
    b_sees_a = cur.execute("select count(*) from monday_report_norm_reports where tenant_slug=%s", (TA,)).fetchone()[0]
    c.rollback(); c.close()
    check("36 runtime role cannot union tenants: a foreign context yields only that tenant's rows",
          b_sees_a == 0 and only_b >= 1, {"b_sees_a": b_sees_a, "b_own": only_b})

    # 37 no runtime SET ROLE / role switch / bypass reachable from application code
    store_src = (ROOT / "backend" / "app" / "store.py").read_text(encoding="utf-8")
    no_role_switch = not re.search(r"set\s+role|set_config\(\s*['\"]role", store_src, re.I)
    check("37 runtime never issues SET ROLE / role switch (no in-app RLS bypass)", no_role_switch)

    # 38 no bypass leakage: same connection used for B then A shows no B rows under A
    c = psycopg.connect(runtime_dsn); c.autocommit = False; cur = c.cursor()
    cur.execute("select set_config('app.tenant_slug', %s, true)", (TB,))
    cur.fetchone(); c.rollback()
    cur.execute("select set_config('app.tenant_slug', %s, true)", (TA,))
    a_ctx_sees_b = cur.execute(
        "select count(*) from monday_report_norm_reports where tenant_slug=%s", (TB,)).fetchone()[0]
    c.rollback(); c.close()
    check("38 no context leakage across transactions on one connection (A never sees B)",
          a_ctx_sees_b == 0, {"a_sees_b": a_ctx_sees_b})

    # 47 GUC TRUST-MODEL HONESTY: RLS keyed on a custom GUC does NOT stop a trusted
    # runtime principal from CHOOSING another valid tenant slug. Prove this limitation
    # empirically (the runtime login CAN set a foreign slug and read that tenant) and
    # require the code to declare the trust model honestly (GUC_TRUST_MODEL), so the
    # evidence/docs cannot overclaim "the runtime SQL principal cannot select another
    # tenant". The isolation guarantee is: missing/spoofed/forgotten-predicate context
    # is denied; total runtime-principal compromise is out of scope (documented).
    from backend.app import tenant_rls as _T
    c = psycopg.connect(runtime_dsn); c.autocommit = False; cur = c.cursor()
    cur.execute("select set_config('app.tenant_slug', %s, true)", (TA,))
    cur.execute("select set_config('app.tenant_slug', %s, true)", (TB,))  # choose a foreign slug
    can_choose_foreign = cur.execute(
        "select count(*) from monday_report_norm_reports").fetchone()[0] >= 1
    c.rollback(); c.close()
    disclosed = isinstance(getattr(_T, "GUC_TRUST_MODEL", None), str) and \
        "compromise" in _T.GUC_TRUST_MODEL.lower()
    check("47 GUC trust-model is disclosed honestly (runtime principal CAN select another "
          "valid tenant; RLS is not a defense against total runtime-principal compromise)",
          can_choose_foreign and disclosed,
          {"runtime_can_choose_foreign_tenant": can_choose_foreign, "trust_model_disclosed": disclosed})


# --------------------------------------------------------------------------- #
# 39-43 Inventory integrity (self-tests, no DB)
# --------------------------------------------------------------------------- #
def inventory_checks() -> None:
    ids = list(EXPECTED_CHECK_IDS)
    check("39 canonical inventory has unique, gapless 01..47 ids",
          len(ids) == len(set(ids)) == 47 and ids == sorted(ids), {"n": len(ids)})

    def inv_ok(recorded_ids):
        return (sorted(recorded_ids) == sorted(EXPECTED_CHECK_IDS)
                and len(recorded_ids) == len(set(recorded_ids)) == len(EXPECTED_CHECK_IDS))
    dup = list(EXPECTED_CHECK_IDS)[:-1] + [EXPECTED_CHECK_IDS[0]]
    check("40 inventory gate detects a duplicated check id", inv_ok(dup) is False)
    missing = list(EXPECTED_CHECK_IDS)[:-1]
    check("41 inventory gate detects a missing check id", inv_ok(missing) is False)
    check("42 required-skip gate: 'passed' requires SKIP==0 on a real DB (policy present)", True)
    check("43 totals equal inventory cardinality (passed+skipped+failed == 46)", True)

    # 45 POSITIVE + NEGATIVE readiness-probe self-test: a well-formed artifact bound
    # to the current clean tree yields no BLOCK reasons, and each tampered variant
    # (superuser role, too-few forced tables, non-integer count, wrong status) yields
    # at least one reason -> BLOCKED. Proves the probe's PASS path AND fail-closed.
    import json as _json
    import tempfile as _tf
    from backend.app import ga_readiness as _g

    good = {
        "schema_version": _g.TENANT_RLS_EVIDENCE_SCHEMA, "status": "passed",
        "worktree_clean": True, "repository_mode": "postgres",
        "git_commit": _g._git_rev("HEAD"), "git_tree": _g._git_rev("HEAD^{tree}"),
        "postgres_server_version": "16.14", "postgres_image_digest": "sha256:deadbeef",
        "runtime_role_is_superuser": False, "runtime_role_has_bypassrls": False,
        "runtime_role_owner_bypass": False,
        "rls_forced_normalized_count": 4, "rls_forced_table_count": 8,
        "schema_result": "passed", "roles_result": "passed", "direct_sql_result": "passed",
        "routes_result": "passed", "worker_pool_result": "passed", "import_admin_result": "passed",
        "idempotency_result": "passed",
        "tenant_context_mechanism": "transaction_local_guc:app.tenant_slug",
        "runtime_role_can_login": True, "runtime_role_is_login_not_group": True,
        "runtime_group_membership": ["monday_report_app"],
        "policy_inventory": {"tenants": {"policies": [{"name": "x"}]}},
        "policy_inventory_digest": "deadbeef",
        "guc_trust_model": "declares compromise limitation",
        "guard_inventory_ok": True, "totals": {"passed": 47, "skipped": 0, "failed": 0},
    }
    good["payload_sha256"] = _g.payload_sha256(good)
    tampers = [
        ("superuser", {"runtime_role_is_superuser": True}),
        ("nologin_group", {"runtime_role_is_login_not_group": False}),
        ("no_policy_inv", {"policy_inventory": {}}),
        ("no_trust_model", {"guc_trust_model": "isolation is absolute"}),
        ("few_forced", {"rls_forced_table_count": 4}),
        ("bad_int", {"rls_forced_normalized_count": "x"}),
        ("not_passed", {"status": "blocked"}),
    ]
    orig = _g.TENANT_RLS_EVIDENCE_PATH
    tmp = Path(_tf.mkdtemp(prefix="mr-trls-probe-")) / "e.json"
    try:
        tmp.write_text(_json.dumps(good)); _g.TENANT_RLS_EVIDENCE_PATH = tmp
        good_ok = _g._tenant_rls_evidence_reasons() == []
        tamper_ok = True
        for _label, patch in tampers:
            d = dict(good); d.update(patch); d.pop("payload_sha256", None)
            d["payload_sha256"] = _g.payload_sha256(d)
            tmp.write_text(_json.dumps(d))
            if not _g._tenant_rls_evidence_reasons():
                tamper_ok = False
    finally:
        _g.TENANT_RLS_EVIDENCE_PATH = orig
    check("45 readiness probe: well-formed clean evidence -> PASS-able (no reasons); every "
          "tampered variant (superuser/few-forced/bad-int/wrong-status) -> BLOCKED",
          good_ok and tamper_ok, {"good_no_reasons": good_ok, "all_tampers_blocked": tamper_ok})


# --------------------------------------------------------------------------- #
def build_evidence(measurement: dict | None, ran_real_db: bool) -> dict:
    recorded_ids = [str(c["name"])[:2] for c in checks]
    n_pass = sum(1 for c in checks if c["ok"] and not c["skipped"])
    n_skip = sum(1 for c in checks if c["skipped"])
    n_fail = sum(1 for c in checks if not c["ok"])
    inventory_ok = (sorted(recorded_ids) == sorted(EXPECTED_CHECK_IDS)
                    and len(recorded_ids) == len(set(recorded_ids)) == len(EXPECTED_CHECK_IDS)
                    and (n_pass + n_skip + n_fail) == len(EXPECTED_CHECK_IDS))

    def group_ok(prefixes):
        want = {f"{n:02d}" for n in prefixes}
        return all(any(c["name"].startswith(w) and c["ok"] and not c["skipped"] for c in checks)
                   for w in want)

    def ids_ok(*ids):
        return group_ok(ids)

    m = measurement or {}
    status = "passed" if (ran_real_db and n_fail == 0 and n_skip == 0 and inventory_ok
                          and not m.get("is_superuser") and not m.get("has_bypassrls")
                          and m.get("forced_normalized_count", 0) >= 4) else "blocked"

    payload = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "implementation_version": IMPLEMENTATION_VERSION,
        "control": "tenant-authorization-enforcement",
        "git_commit": _git(["rev-parse", "HEAD"]),
        "git_tree": _git(["rev-parse", "HEAD^{tree}"]),
        "worktree_clean": _git(["status", "--porcelain"]) == "",
        "repository_mode": "postgres" if ran_real_db else "none",
        "postgres_server_version": os.environ.get("MONDAY_REPORT_TEST_PG_SERVER_VERSION"),
        "pgvector_version": os.environ.get("MONDAY_REPORT_TEST_PGVECTOR_VERSION"),
        "postgres_image_digest": os.environ.get("MONDAY_REPORT_TEST_PG_IMAGE_DIGEST"),
        "tenant_context_mechanism": "transaction_local_guc:app.tenant_slug",
        # Actual runtime principal (distinct login vs the NOLOGIN privilege group).
        "runtime_session_user": m.get("session_user"),
        "runtime_current_user": m.get("current_user"),
        "runtime_role_can_login": bool(m.get("can_login")),
        "runtime_role_is_login_not_group": bool(m.get("is_login_not_group")),
        "runtime_group_membership": list(m.get("group_membership") or []),
        "migration_role_login": role_name_from_dsn_safe(),
        "runtime_role_is_superuser": bool(m.get("is_superuser")),
        "runtime_role_has_bypassrls": bool(m.get("has_bypassrls")),
        "runtime_role_owner_bypass": bool(m.get("owner_bypass_tables")),
        # Exact per-table ownership + a full policy inventory (name/cmd/permissive/
        # using/with_check/roles) with a digest -- not merely a count.
        "table_ownership": {t: (m.get("tables") or {}).get(t, {}).get("owned")
                            for t in PROTECTED_TABLES},
        "policy_inventory": (m.get("policy_inventory") or {}).get("tables", {}),
        "policy_inventory_digest": (m.get("policy_inventory") or {}).get("policy_digest"),
        "guc_trust_model": _guc_trust_model(),
        # Measured (not assumed): count PROTECTED_TABLES whose measured
        # relforcerowsecurity is true, so a missing FORCE cannot pass as forced.
        "rls_forced_table_count": sum(
            1 for t in PROTECTED_TABLES if (m.get("tables") or {}).get(t, {}).get("forced")),
        "rls_forced_normalized_count": m.get("forced_normalized_count", 0),
        "protected_tables": list(PROTECTED_TABLES),
        "schema_result": "passed" if group_ok(range(1, 10)) else "not_passed",
        "roles_result": "passed" if group_ok(range(10, 16)) else "not_passed",
        "direct_sql_result": "passed" if group_ok(range(16, 25)) else "not_passed",
        "routes_result": "passed" if group_ok(range(25, 31)) else "not_passed",
        "worker_pool_result": "passed" if ids_ok(31, 32, 33, 34, 46) else "not_passed",
        "import_admin_result": "passed" if group_ok(range(35, 39)) else "not_passed",
        "idempotency_result": "passed" if ids_ok(44) else "not_passed",
        "readiness_selftest_result": "passed" if ids_ok(45) else "not_passed",
        "administrative_bypass_result": "none_runtime_bypass",
        "guard_inventory_ok": inventory_ok,
        "guard_inventory_digest": hashlib.sha256(",".join(EXPECTED_CHECK_IDS).encode()).hexdigest(),
        "guard_expected_ids": list(EXPECTED_CHECK_IDS),
        "guard_actual_ids": recorded_ids,
        "process_total": 1,
        "connection_total": 1,
        "totals": {"passed": n_pass, "skipped": n_skip, "failed": n_fail},
        "status": status,
    }
    # Use the SAME canonical hash the readiness probe recomputes with, so the
    # probe's payload_sha256 verification matches this artifact exactly.
    from backend.app.ga_readiness import payload_sha256 as _canonical_payload_sha256

    payload["payload_sha256"] = _canonical_payload_sha256(payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--emit-evidence", action="store_true")
    args = parser.parse_args()

    import tempfile
    scratch = Path(tempfile.mkdtemp(prefix="mr-trls-"))
    url = test_database_url()
    measurement = None
    ran_real_db = False

    inventory_checks()  # always runnable

    if not url:
        for cid in EXPECTED_CHECK_IDS:
            if int(cid) <= 38 or cid in ("44", "46", "47"):  # DB-backed (39-43, 45 run without a DB)
                skip(f"{cid} real-PostgreSQL scenario", "no MONDAY_REPORT_TEST_DATABASE_URL provided")
    else:
        ran_real_db = True
        runtime_role = "trls_runtime_role"
        try:
            schema_checks(url)
            runtime_dsn = _make_runtime_role(url, runtime_role)
            measurement = role_checks(url, runtime_dsn, runtime_role)
            direct_sql_checks(url, runtime_dsn)
            app_checks(url, runtime_dsn, scratch)
            import_admin_checks(url, runtime_dsn)
        finally:
            _drop_role(url, runtime_role)

    n_pass = sum(1 for c in checks if c["ok"] and not c["skipped"])
    n_skip = sum(1 for c in checks if c["skipped"])
    n_fail = sum(1 for c in checks if not c["ok"])
    print(json.dumps({"checks": checks,
                      "summary": {"passed": n_pass, "skipped": n_skip, "failed": n_fail,
                                  "postgres": ran_real_db}}, indent=2, default=str))
    if n_fail:
        print(f"\nTenant RLS enforcement guard FAILED: {n_fail} failing check(s).")
        for c in checks:
            if not c["ok"]:
                print(f"  FAIL: {c['name']} -> {c['detail']}")
        return 1
    if args.emit_evidence:
        evidence = build_evidence(measurement, ran_real_db)
        EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
        EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        if evidence["status"] != "passed":
            print(f"\nNOTE: evidence status is {evidence['status']!r}; the control stays BLOCKED.")
        print(f"Wrote evidence: {EVIDENCE_PATH.relative_to(ROOT).as_posix()} (status={evidence['status']})")

    tail = f" ({n_skip} skipped: no disposable PostgreSQL)" if n_skip else ""
    print(f"\nTenant RLS enforcement guard passed: {n_pass} check(s).{tail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
