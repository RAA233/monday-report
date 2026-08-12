"""Runtime tenant-RLS enforcement: role safety validation + verified tenant context.

This is the application-side half of the ``tenant-authorization-enforcement`` GA
control's "Postgres RLS active for the normalized store" clause. The database half
lives in migration ``0007_tenant_rls_enforcement.sql`` (forced RLS + a
least-privilege ``monday_report_app`` group role). Here we:

* refuse to run the protected PostgreSQL store under an unsafe runtime role (a
  superuser, a ``BYPASSRLS`` role, a role that owns a protected table WITHOUT
  ``FORCE ROW LEVEL SECURITY`` so it would bypass the policy, or the migration
  role), because any of those silently bypasses RLS and makes tenant isolation a
  fiction; and
* apply the transaction-local ``app.tenant_slug`` GUC and VERIFY it took effect
  before any tenant-sensitive query runs, so a silently-dropped context denies
  rather than leaks.

Errors are redacted: they name only the failed property (and, for forced-RLS gaps,
the table name, which is not a secret) -- never a role name, password, DSN, or host.
Demo/local mode measures but never rejects, so the existing superuser-backed tests
and guards keep working; only client/protected mode fails closed.
"""
from __future__ import annotations

import os
from typing import Any

# The tenant-scoped tables the normalized-persistence slice reads/writes through
# the runtime role. Each must have RLS enabled AND forced so the runtime role
# (which must not be a superuser/BYPASSRLS/owner-bypass) cannot see or write
# another tenant's rows.
PROTECTED_TABLES: tuple[str, ...] = (
    "tenants",
    "workspaces",
    "monday_report_state_snapshots",
    "monday_report_idempotency_records",
    "monday_report_norm_reports",
    "monday_report_norm_field_corrections",
    "monday_report_norm_validation_tasks",
    "monday_report_norm_validation_outcomes",
)

# The normalized-store tables whose FORCE row level security the readiness
# evidence counts (the resolution condition's "normalized store").
NORMALIZED_TABLES: tuple[str, ...] = (
    "monday_report_norm_reports",
    "monday_report_norm_field_corrections",
    "monday_report_norm_validation_tasks",
    "monday_report_norm_validation_outcomes",
)

TENANT_GUC = "app.tenant_slug"

# Honest trust-model disclosure for the app.tenant_slug GUC. RLS keyed on a custom
# GUC protects against a MISSING context (deny), a query that forgets the tenant
# predicate (RLS still scopes to the set slug), and route/payload/header tenant
# spoofing (the slug is derived from authenticated server state, never client input).
# It is NOT a defense against total compromise of, or arbitrary SQL execution as, the
# trusted runtime principal: a connected principal CAN set the GUC to any valid slug
# and read that tenant. RLS therefore reduces blast radius and enforces the API-layer
# tenant boundary at the database, but is not a hard boundary against a fully
# compromised runtime role (which is why the runtime role is least-privilege,
# non-superuser, and non-BYPASSRLS, and cross-tenant admin work uses a separate role).
GUC_TRUST_MODEL = (
    "rls_guc_app_set_context: protects against missing/spoofed/forgotten-predicate "
    "tenant context; NOT a defense against total runtime-principal compromise "
    "(a connected principal can set app.tenant_slug to any valid tenant)"
)


def policy_inventory(connection: Any) -> dict:
    """Enumerate RLS state, owner, and every policy for the protected tables.

    Returns {tables: {name: {...}}, policy_digest: sha256-hex}. Used by the guard to
    emit an exact, auditable policy inventory (not merely a count) into evidence.
    """
    import hashlib
    import json as _json

    result: dict[str, dict] = {}
    with connection.cursor() as cursor:
        cursor.execute(
            "select c.relname, c.relrowsecurity, c.relforcerowsecurity, "
            "       pg_get_userbyid(c.relowner) as owner "
            "from pg_class c where c.relkind='r' and c.relname = any(%s)",
            (list(PROTECTED_TABLES),),
        )
        for name, rowsec, forced, owner in cursor.fetchall():
            result[name] = {
                "rowsecurity": bool(rowsec), "forced": bool(forced),
                "owner": owner, "policies": [],
            }
        cursor.execute(
            "select c.relname, p.polname, "
            "  case p.polcmd when 'r' then 'SELECT' when 'a' then 'INSERT' "
            "    when 'w' then 'UPDATE' when 'd' then 'DELETE' else 'ALL' end as cmd, "
            "  p.polpermissive, "
            "  pg_get_expr(p.polqual, p.polrelid) as using_expr, "
            "  pg_get_expr(p.polwithcheck, p.polrelid) as check_expr, "
            "  coalesce((select array_agg(rolname order by rolname) from pg_roles "
            "     where oid = any(p.polroles)), array['PUBLIC']) as roles "
            "from pg_policy p join pg_class c on c.oid = p.polrelid "
            "where c.relname = any(%s)",
            (list(PROTECTED_TABLES),),
        )
        for relname, polname, cmd, permissive, using_expr, check_expr, roles in cursor.fetchall():
            if relname in result:
                result[relname]["policies"].append({
                    "name": polname, "cmd": cmd, "permissive": bool(permissive),
                    "using": using_expr, "with_check": check_expr,
                    "roles": list(roles) if roles else [],
                })
    canonical = _json.dumps(result, sort_keys=True, default=str)
    return {"tables": result, "policy_digest": hashlib.sha256(canonical.encode()).hexdigest()}


class TenantRuntimeRoleError(RuntimeError):
    """The runtime PostgreSQL role cannot safely enforce tenant RLS."""


class TenantContextError(RuntimeError):
    """The transaction-local tenant context is missing, empty, or unverifiable."""


def _client_data_mode() -> str:
    raw = os.getenv("MONDAY_REPORT_CLIENT_DATA_MODE", "demo").strip().lower()
    return "client" if raw in {"1", "true", "yes", "client", "production", "prod", "real"} else "demo"


def enforce_runtime_role() -> bool:
    """True when startup must FAIL CLOSED on an unsafe runtime role (client mode)."""
    return _client_data_mode() == "client"


def role_name_from_dsn(dsn: str | None) -> str | None:
    """Extract only the ROLE (user) component of a DSN -- never the password/host.

    Returns None when absent/unparseable. Used solely to compare the runtime role
    against the migration role; the result is never logged or surfaced.
    """
    if not dsn:
        return None
    try:
        from urllib.parse import urlsplit, unquote

        user = urlsplit(dsn).username
        if user:
            return unquote(user)
    except Exception:
        pass
    # libpq keyword/DSN form: "host=... user=role password=...". Match a user token.
    import re as _re

    m = _re.search(r"(?:^|\s)user\s*=\s*'?([^'\s]+)'?", dsn or "")
    return m.group(1) if m else None


def measure_runtime_role(connection: Any) -> dict:
    """Measure the runtime connection's role and the protected tables' RLS state.

    Non-raising. Returns a dict suitable for evidence/readiness. Never includes a
    password/DSN/host; the current role name is included only as ``current_user``
    for the migration-role comparison and is not emitted into evidence by callers.
    """
    with connection.cursor() as cursor:
        cursor.execute("select session_user, current_user")
        session_user, current_user = cursor.fetchone()
        cursor.execute(
            "select rolsuper, rolbypassrls, rolcanlogin from pg_roles where rolname = current_user"
        )
        row = cursor.fetchone()
        is_super = bool(row[0]) if row else True  # unknown -> treat as unsafe
        has_bypassrls = bool(row[1]) if row else True
        can_login = bool(row[2]) if row else False
        # Group roles the runtime login is a member of (the privilege group must be a
        # role it INHERITs, not the login principal itself).
        cursor.execute(
            "select g.rolname from pg_auth_members m "
            "join pg_roles r on r.oid = m.member join pg_roles g on g.oid = m.roleid "
            "where r.rolname = current_user"
        )
        group_membership = sorted(row2[0] for row2 in cursor.fetchall())
        cursor.execute(
            "select c.relname, c.relrowsecurity, c.relforcerowsecurity, "
            "       pg_get_userbyid(c.relowner) = current_user as owned_by_current "
            "from pg_class c "
            "where c.relkind = 'r' and c.relname = any(%s)",
            (list(PROTECTED_TABLES),),
        )
        tables = {
            r[0]: {"rowsecurity": bool(r[1]), "forced": bool(r[2]), "owned": bool(r[3])}
            for r in cursor.fetchall()
        }

    missing_forced = [
        t for t in PROTECTED_TABLES
        if not tables.get(t, {}).get("forced", False)
    ]
    owner_bypass = [
        t for t, meta in tables.items()
        if meta.get("owned") and not meta.get("forced")
    ]
    forced_normalized = [t for t in NORMALIZED_TABLES if tables.get(t, {}).get("forced")]
    return {
        "session_user": session_user,
        "current_user": current_user,
        "can_login": can_login,
        # The runtime login must be a LOGIN principal that INHERITs the app group,
        # never the NOLOGIN group role itself.
        "is_login_not_group": can_login and current_user != "monday_report_app",
        "group_membership": group_membership,
        "is_superuser": is_super,
        "has_bypassrls": has_bypassrls,
        "tables": tables,
        "missing_forced_tables": missing_forced,
        "owner_bypass_tables": sorted(owner_bypass),
        "forced_normalized_count": len(forced_normalized),
    }


def runtime_role_violations(measurement: dict, *, migration_role: str | None = None) -> list[str]:
    """Redacted list of reasons the runtime role cannot enforce tenant RLS."""
    reasons: list[str] = []
    if measurement.get("is_superuser"):
        reasons.append("runtime database role is a superuser (bypasses row level security)")
    if measurement.get("has_bypassrls"):
        reasons.append("runtime database role has BYPASSRLS (bypasses row level security)")
    for table in measurement.get("owner_bypass_tables", []):
        reasons.append(
            f"runtime database role owns a protected table without FORCE row level "
            f"security (owner bypass): {table}"
        )
    # Ownership itself is disqualifying even WITH FORCE row level security: the
    # owner can revoke FORCE (or drop the policies) with plain DDL at any time,
    # so a runtime that owns a protected table is the migration/owner principal
    # regardless of which DSN environment variable it arrived through. This is
    # measured from pg_class, so it covers every documented DB-connection
    # fallback path that the env-derived migration-role comparison below misses
    # (e.g. migrations applied via the DATABASE_URL fallback with
    # MONDAY_REPORT_MIGRATIONS_DATABASE_URL unset).
    for table, meta in sorted((measurement.get("tables") or {}).items()):
        if meta.get("owned") and not meta.get("forced"):
            continue  # already reported as owner bypass above
        if meta.get("owned"):
            reasons.append(
                f"runtime database role owns a protected table (the owner can "
                f"disable row level security with DDL): {table}"
            )
    for table in measurement.get("missing_forced_tables", []):
        reasons.append(f"protected table is missing FORCE row level security: {table}")
    if migration_role and measurement.get("current_user") == migration_role:
        reasons.append("runtime database role equals the migration role")
    return reasons


def assert_runtime_role_safe(connection: Any, *, migration_role: str | None = None) -> dict:
    """Measure the runtime role; in client mode raise on any violation.

    Returns the measurement dict (so callers can record it). Raises
    :class:`TenantRuntimeRoleError` with a redacted message when client mode is
    active and the role cannot enforce RLS. In demo/local mode it only measures.
    """
    measurement = measure_runtime_role(connection)
    if not enforce_runtime_role():
        return measurement
    reasons = runtime_role_violations(measurement, migration_role=migration_role)
    if reasons:
        raise TenantRuntimeRoleError(
            "refusing to start the protected PostgreSQL store: the runtime role "
            "cannot enforce tenant isolation (" + "; ".join(reasons) + ")"
        )
    return measurement


def apply_verified_tenant_scope(cursor: Any, tenant_slug: str) -> None:
    """Set the transaction-local ``app.tenant_slug`` GUC and VERIFY it took effect.

    Fail closed (raise :class:`TenantContextError`) when the slug is empty or the
    setting does not read back as the intended value, so a silently-dropped context
    denies rather than exposing another tenant's rows. ``is_local => true`` scopes it
    to the current transaction; rollback/commit clear it and pooled reuse cannot
    retain it.
    """
    if tenant_slug is None or not str(tenant_slug).strip():
        raise TenantContextError("refusing to apply an empty tenant context")
    cursor.execute("select set_config(%s, %s, true)", (TENANT_GUC, tenant_slug))
    applied = cursor.fetchone()[0]
    if applied != tenant_slug:
        raise TenantContextError("tenant context verification failed after set_config")
