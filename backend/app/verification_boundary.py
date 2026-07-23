"""Fail-closed verification-isolation boundary for the client-mode readiness lock.

THE PROBLEM. In client mode, ``require_client_data_ready`` returns HTTP 423 until
every client-data readiness check passes. Several of those checks are, by design,
un-satisfiable by a disposable test stack -- a reachable local LLM with the pinned
model, a *reviewed* anonymized client-fixture attestation, passing parser/OCR
fixture evals. That is correct for production safety, but it makes it impossible to
exercise the real client-mode request path (authentication, RBAC, tenant
authorization, forced RLS on a restricted PostgreSQL runtime role, the idempotency
contract) in an automated tenant-isolation test: the release-readiness lock -- which
is unrelated to tenant isolation -- masks the very behaviour under test.

THE BOUNDARY. This module answers exactly one question: *is this process a
provably-isolated, disposable, synthetic verification stack?* When (and only when)
the answer is yes, ``require_client_data_ready`` allows the route to EXECUTE instead
of raising 423. It changes nothing else:

* authentication, identity resolution, RBAC, resource ownership, tenant
  authorization, forced RLS, the restricted runtime role, and the idempotency
  contract all remain fully active and are NOT bypassed;
* ``evaluate_client_data_readiness(...).ready`` still returns False, every readiness
  check still reports its real status, and NO GA readiness control is made to pass;
* every relaxed execution writes an audit event, so it is never silent.

FAIL CLOSED. The boundary is off unless an explicit opt-in marker is set AND the
process is independently provable to be isolated on every axis below. Any missing
signal, or any single live indicator, disables it and the 423 stands. It is driven
ONLY by process configuration (env + DSN + filesystem roots) -- never by a request
header, query parameter, or body -- so no caller can trigger it. It cannot activate
against a production database (the database name must carry the repository's
disposable-``test`` marker, the same convention ``migration_runner_guard`` enforces)
or a live path (state/storage/export roots must be outside ``.local_data``) or the
live ports (8000 / 5173). It is therefore not usable with production data.

This is deliberately a narrow, audited, config-only, production-inert switch, NOT a
generic ``DISABLE_READINESS`` flag: the marker alone does nothing without the full
isolation conjunction.
"""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit

# The explicit opt-in. Necessary but never sufficient on its own.
VERIFICATION_MARKER_ENV = "MONDAY_REPORT_VERIFICATION_ISOLATION"

# Live-runtime fingerprints the boundary must never overlap with.
LIVE_STATE_MARKER = ".local_data"
LIVE_API_PORT = 8000
LIVE_WEB_PORT = 5173

# The repository's established disposable-database convention (see
# migration_runner_guard's disposable-db safety preflight): a real client/production
# database is never named with this marker.
DISPOSABLE_DB_MARKER = "test"

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _under_live_state(value: str | None) -> bool:
    return bool(value) and LIVE_STATE_MARKER in str(value).replace("\\", "/")


def _port(url: str | None) -> int | None:
    if not url:
        return None
    try:
        return urlsplit(url if "//" in url else f"//{url}").port
    except ValueError:
        return None


def isolation_signals() -> dict[str, bool]:
    """Every isolation signal, evaluated independently from process config only.

    The boundary activates iff EVERY value here is True. Exposed (not just the
    aggregate) so the runtime guard and evidence can record precisely why the
    boundary did or did not engage, and so a reviewer can see there is no hidden
    disjunction.
    """
    marker = _truthy(os.environ.get(VERIFICATION_MARKER_ENV))

    backend = os.environ.get("MONDAY_REPORT_REPOSITORY_BACKEND", "")
    dsn = os.environ.get("MONDAY_REPORT_DATABASE_URL") or os.environ.get("DATABASE_URL") or ""
    parts = urlsplit(dsn) if dsn else None
    db_name = (parts.path.lstrip("/") if parts else "").lower()
    host = (parts.hostname or "").lower() if parts else ""

    state = os.environ.get("MONDAY_REPORT_STATE_PATH")
    storage = os.environ.get("MONDAY_REPORT_STORAGE_ROOT")
    export = os.environ.get("MONDAY_REPORT_EXPORT_ROOT")

    api_base = os.environ.get("MONDAY_REPORT_API_BASE")
    web_base = os.environ.get("MONDAY_REPORT_WEB_BASE")

    return {
        # Explicit opt-in.
        "marker_set": marker,
        # A real, transactional PostgreSQL backend (not a local/file fallback).
        "postgres_backend": backend == "postgres" and bool(dsn),
        # Loopback only -- never a remote/production host.
        "loopback_dsn": host in LOOPBACK_HOSTS,
        # Disposable database name -- a production database never carries this marker.
        "disposable_db_name": DISPOSABLE_DB_MARKER in db_name,
        # All three persistence roots configured and none under the live .local_data.
        "isolated_state_root": bool(state) and not _under_live_state(state),
        "isolated_storage_root": bool(storage) and not _under_live_state(storage),
        "isolated_export_root": bool(export) and not _under_live_state(export),
        # If service bases are advertised they must not be the live ports (unset is
        # acceptable -- the server process need not know its own external base).
        "non_live_api_port": _port(api_base) != LIVE_API_PORT,
        "non_live_web_port": _port(web_base) != LIVE_WEB_PORT,
    }


def verification_execution_allowed() -> bool:
    """True only when the process is a provably-isolated disposable verification
    stack. Fails closed on any missing or live signal. Never reads request state."""
    return all(isolation_signals().values())


def verification_context_summary() -> dict:
    """Redacted, non-sensitive summary for audit/evidence: booleans only, never the
    DSN, host, port, credential, or absolute path."""
    signals = isolation_signals()
    return {
        "verification_isolation_active": all(signals.values()),
        "signals": signals,
        # Named so a reader can see exactly which signal(s) withheld activation,
        # without exposing any value.
        "withheld_by": sorted(k for k, v in signals.items() if not v),
    }
