"""Fail-closed verification-isolation boundary for the client-mode readiness lock.

THE PROBLEM. In client mode, ``require_client_data_ready`` returns HTTP 423 until
every client-data readiness check passes. Several of those checks are, by design,
un-satisfiable by a disposable test stack (a reachable local LLM with the pinned
model, a *reviewed* anonymized client-fixture attestation, passing parser/OCR
fixture evals). That is correct for production safety, but it makes it impossible to
exercise the real client-mode request path (authentication, per-user credential
validation, RBAC, tenant ownership, verified-reviewer enforcement, forced RLS on a
restricted PostgreSQL runtime role, the idempotency contract) in an automated
tenant-isolation test: the release-readiness lock -- unrelated to tenant isolation
-- masks the very behaviour under test.

THE BOUNDARY. This module answers one question: *is this process a provably
isolated, disposable, synthetic verification stack?* Only then does
``require_client_data_ready`` allow the route to EXECUTE instead of raising 423. It
changes nothing else: authentication, identity resolution, RBAC, ownership, tenant
authorization, verified-reviewer enforcement, forced RLS, the restricted runtime
role, audit HMAC/chain, and the idempotency contract all stay active and are NOT
bypassed; ``evaluate_client_data_readiness(...).ready`` still returns False; NO GA
control is made to pass; and every relaxed execution is audited FAIL-CLOSED (if the
audit cannot be durably recorded the route does not continue).

WHY A DATABASE-SIDE ATTESTATION. An environment-only predicate is spoofable -- a
production database can be *named* with a "test" substring, reached over a loopback
tunnel, or fronted by a non-live proxy port. So the strong signal is a marker that
must physically exist IN the database the app is using: a dedicated attestation row
that only the disposable-stack harness creates (never a production migration),
carries no secret, is verified on the same runtime connection before the gate is
relaxed, and disappears when the disposable database is dropped. A production
database simply does not contain it. The environment signals (opt-in marker, real
PostgreSQL backend, strict loopback-TCP DSN, isolated real-path roots, non-live
ports) are necessary pre-conditions that gate whether the database is even
consulted -- a production request (no opt-in marker) never opens that connection.

FAIL CLOSED on every axis. Any missing signal, any live indicator, any DSN that is
not a clean single-host loopback TCP URL, any root that canonicalises under
``.local_data``, or an absent/erroring attestation disables the boundary and the 423
stands. It reads ONLY process configuration and the database attestation -- never a
request header, query parameter, or body -- so no caller can trigger it, and it
cannot make any readiness or GA control pass. It is a narrow, audited, production-
inert switch, not a generic ``DISABLE_READINESS`` flag.
"""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import unquote, urlsplit

VERIFICATION_MARKER_ENV = "MONDAY_REPORT_VERIFICATION_ISOLATION"

LIVE_STATE_MARKER = ".local_data"
LIVE_API_PORT = 8000
LIVE_WEB_PORT = 5173

# Loopback hosts only. 0.0.0.0 is a bind-all wildcard, never a connect target, and
# is deliberately excluded (a bind-all indicates a service exposed beyond loopback).
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
POSTGRES_SCHEMES = {"postgres", "postgresql"}

# The database-side disposable-environment attestation. Created ONLY by the isolated
# harness (never by a production migration); carries no secret; dropped with the
# disposable database.
ATTESTATION_TABLE = "mr_verification_isolation_attestation"
ATTESTATION_MARKER = "disposable-verification-environment"


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _runtime_dsn() -> str:
    return (os.environ.get("MONDAY_REPORT_DATABASE_URL") or os.environ.get("DATABASE_URL") or "").strip()


def _loopback_tcp_dsn(dsn: str) -> bool:
    """True only for a clean single-host loopback TCP PostgreSQL URL.

    Rejects (fails closed) keyword-form DSNs (no URL host), Unix-domain sockets
    (empty/`/`-prefixed host or a ``host=`` socket-dir query), multi-host URLs,
    non-loopback hosts, non-PostgreSQL schemes, and URL-encoded host obfuscation.
    """
    if not dsn or "://" not in dsn:
        return False  # keyword-form / libpq DSN -> no parseable URL host
    try:
        parts = urlsplit(dsn)
    except ValueError:
        return False
    if (parts.scheme or "").lower() not in POSTGRES_SCHEMES:
        return False
    netloc = parts.netloc
    # Multi-host URLs (postgresql://h1,h2/db) are never a single disposable target.
    hostportion = netloc.split("@")[-1]
    if "," in hostportion:
        return False
    # A ``host=`` query parameter can redirect to a Unix socket or another host.
    if "host=" in (parts.query or "").lower():
        return False
    try:
        host = parts.hostname
    except ValueError:
        return False
    if not host:
        return False  # Unix-domain socket or malformed -> no TCP host
    # Reject URL-encoded host obfuscation: the decoded form must equal the raw form.
    if unquote(host) != host:
        return False
    if host.lower().strip() not in LOOPBACK_HOSTS:
        return False
    # A real TCP port must be present (a socket path carries none).
    try:
        if parts.port is None:
            return False
    except ValueError:
        return False
    return True


def _isolated_root(value: str | None) -> bool:
    """True only when the root is set and its CANONICAL path (symlinks resolved,
    normalised) does not fall under the live ``.local_data`` tree. Catches symlink
    escapes, relative-path escapes, and platform path aliases."""
    if not value:
        return False
    try:
        resolved = Path(os.path.realpath(value))
    except (OSError, ValueError):
        return False  # unresolvable -> fail closed
    parts = {p.lower() for p in resolved.parts}
    # Compare by path COMPONENT, not substring, so ``.local_data`` anywhere in the
    # resolved ancestry disqualifies it while an innocuous name cannot false-match.
    return LIVE_STATE_MARKER not in parts


def _port(url: str | None) -> int | None:
    if not url:
        return None
    try:
        return urlsplit(url if "//" in url else f"//{url}").port
    except ValueError:
        return None


def isolation_signals() -> dict[str, bool]:
    """Every ENVIRONMENT isolation signal, from process config only (no database).

    These are necessary pre-conditions. They gate whether the database attestation
    is even consulted; a production request (no opt-in marker) short-circuits here
    and never opens a database connection.
    """
    dsn = _runtime_dsn()
    return {
        "marker_set": _truthy(os.environ.get(VERIFICATION_MARKER_ENV)),
        "postgres_backend": os.environ.get("MONDAY_REPORT_REPOSITORY_BACKEND", "") == "postgres" and bool(dsn),
        "loopback_tcp_dsn": _loopback_tcp_dsn(dsn),
        "isolated_state_root": _isolated_root(os.environ.get("MONDAY_REPORT_STATE_PATH")),
        "isolated_storage_root": _isolated_root(os.environ.get("MONDAY_REPORT_STORAGE_ROOT")),
        "isolated_export_root": _isolated_root(os.environ.get("MONDAY_REPORT_EXPORT_ROOT")),
        "non_live_api_port": _port(os.environ.get("MONDAY_REPORT_API_BASE")) != LIVE_API_PORT,
        "non_live_web_port": _port(os.environ.get("MONDAY_REPORT_WEB_BASE")) != LIVE_WEB_PORT,
    }


def database_attestation_present(dsn: str | None = None) -> bool:
    """True iff the disposable-environment attestation row exists in the runtime
    database, verified on a fresh connection to it. Fails closed on ANY error (no
    connection, missing table, missing marker, driver error)."""
    dsn = dsn if dsn is not None else _runtime_dsn()
    if not _loopback_tcp_dsn(dsn):
        return False
    try:
        import psycopg
    except Exception:  # noqa: BLE001 - driver unavailable -> fail closed
        return False
    try:
        with psycopg.connect(dsn, connect_timeout=5, autocommit=True) as conn:
            row = conn.execute(
                f"select 1 from {ATTESTATION_TABLE} where marker = %s",
                (ATTESTATION_MARKER,),
            ).fetchone()
            return row is not None
    except Exception:  # noqa: BLE001 - table absent / permission / connection -> fail closed
        return False


def verification_context() -> dict:
    """Single evaluation of the whole boundary (env signals + database attestation).

    The database is consulted ONLY when every environment signal already holds, so a
    production request never opens the attestation connection. Returns the aggregate
    decision plus each signal, redacted to booleans and signal names -- never a DSN,
    host, port, credential, or path.
    """
    signals = isolation_signals()
    env_ok = all(signals.values())
    attestation = env_ok and database_attestation_present()
    active = env_ok and attestation
    withheld = [k for k, v in signals.items() if not v]
    if env_ok and not attestation:
        withheld.append("database_attestation")
    return {
        "verification_isolation_active": active,
        "signals": {**signals, "database_attestation": attestation},
        "withheld_by": sorted(withheld),
    }


def verification_execution_allowed() -> bool:
    """True only when the process is a provably-isolated disposable verification
    stack (environment isolation AND the database-side attestation). Fails closed on
    any missing/live signal or absent attestation. Never reads request state."""
    return verification_context()["verification_isolation_active"]


def verification_context_summary() -> dict:
    """Redacted, non-sensitive summary for audit/evidence: booleans and signal names
    only, never the DSN, host, port, credential, or absolute path."""
    return verification_context()


def install_database_attestation(dsn: str, *, grant_to: str | None = None) -> None:
    """Create the disposable-environment attestation in a disposable database. Called
    ONLY by the isolated verification harness -- never by a production migration.
    Idempotent; carries no secret; optionally grants SELECT to the runtime group."""
    import psycopg

    with psycopg.connect(dsn, connect_timeout=5, autocommit=True) as conn:
        conn.execute(f"create table if not exists {ATTESTATION_TABLE} (marker text primary key)")
        conn.execute(
            f"insert into {ATTESTATION_TABLE} (marker) values (%s) on conflict do nothing",
            (ATTESTATION_MARKER,),
        )
        if grant_to:
            conn.execute(f"grant select on {ATTESTATION_TABLE} to {grant_to}")
