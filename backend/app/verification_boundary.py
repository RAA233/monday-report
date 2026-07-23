"""Fail-closed verification-isolation boundary for the client-mode readiness lock.

THE PROBLEM. In client mode, ``require_client_data_ready`` returns HTTP 423 until
every client-data readiness check passes. Several are, by design, un-satisfiable by a
disposable test stack (a reachable local LLM with the pinned model, a *reviewed*
anonymized client-fixture attestation, passing parser/OCR fixture evals). That is
correct for production safety, but it makes it impossible to exercise the real
client-mode request path (authentication, per-user credential validation, RBAC,
tenant ownership, verified-reviewer enforcement, forced RLS on a restricted
PostgreSQL runtime role, the idempotency contract) in an automated tenant-isolation
test: an unrelated release-readiness lock masks the behaviour under test.

THE BOUNDARY. This module answers one question: *is this process a provably isolated,
disposable, single-run verification stack?* Only then does ``require_client_data_ready``
allow the route to EXECUTE instead of raising 423. It changes nothing else --
authentication, identity resolution, RBAC, ownership, tenant authorization,
verified-reviewer enforcement, forced RLS, audit HMAC/chain, and idempotency all stay
active; ``evaluate_client_data_readiness(...).ready`` still returns False; NO GA
control is made to pass; and every relaxed execution is audited FAIL-CLOSED.

WHY A RUN-SCOPED DATABASE ATTESTATION. An environment-only predicate is spoofable
(a production database can be *named* with "test", reached over a loopback tunnel, or
fronted by a non-live proxy port). A *static* database marker is still insufficient --
it survives a clone, a test-to-production restore, or a retained/reused disposable
database. So activation requires a **run-scoped** attestation: a row whose primary key
is the SHA-256 of a fresh >=128-bit run identifier that only the current harness knows,
with a short expiry, installed by the migration/admin principal AFTER migrations and
role provisioning, granted SELECT-only to the runtime group (PUBLIC and the runtime
role hold no write privilege), verified on the same runtime connection against
``current_database()``. The raw run id is never logged, never stored (only its hash),
and never emitted into evidence. A clone/restore of yesterday's database carries an
expired hash; a different run carries a different hash; a production database carries
none. The environment signals merely gate whether the database is consulted at all --
a production request (no opt-in marker / no run id) never opens that connection.

FAIL CLOSED on every axis. Any missing signal, live indicator, non-loopback-TCP DSN,
root canonicalising under ``.local_data``, or absent/expired/mismatched attestation
disables the boundary and the 423 stands. It reads ONLY process configuration and the
database attestation -- never a request header, query, or body -- so no caller can
trigger it, and it cannot make any readiness or GA control pass.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
from pathlib import Path
from urllib.parse import urlsplit

VERIFICATION_MARKER_ENV = "MONDAY_REPORT_VERIFICATION_ISOLATION"
# The raw run identifier (>=128 bits). Supplied to the isolated harness only; the
# database stores its SHA-256, never the raw value, and it is never logged/emitted.
VERIFICATION_RUN_ID_ENV = "MONDAY_REPORT_VERIFICATION_RUN_ID"
MIN_RUN_ID_CHARS = 32  # >= 128 bits when hex-encoded

LIVE_STATE_MARKER = ".local_data"
LIVE_API_PORT = 8000
LIVE_WEB_PORT = 5173
POSTGRES_SCHEMES = {"postgres", "postgresql"}

# Schema-qualified so a shadow table in another search-path schema cannot satisfy it.
ATTESTATION_SCHEMA = "public"
ATTESTATION_TABLE = "mr_verification_isolation_attestation"
ATTESTATION_QUALIFIED = f"{ATTESTATION_SCHEMA}.{ATTESTATION_TABLE}"
ATTESTATION_PURPOSE = "monday-report-restricted-runtime-verification"


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _runtime_dsn() -> str:
    return (os.environ.get("MONDAY_REPORT_DATABASE_URL") or os.environ.get("DATABASE_URL") or "").strip()


def _run_id() -> str:
    return (os.environ.get(VERIFICATION_RUN_ID_ENV) or "").strip()


def _run_id_hash(run_id: str) -> str:
    return hashlib.sha256(run_id.encode("utf-8")).hexdigest()


def _all_loopback(host: str) -> bool:
    """True only when every address the host resolves to is loopback. Literal
    loopback IPs pass directly; ``localhost`` is resolved and EVERY returned address
    must be loopback (a split-horizon localhost pointing off-box fails closed)."""
    h = host.strip().strip("[]").lower()
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        pass
    if h != "localhost":
        return False
    try:
        infos = socket.getaddrinfo(h, None)
    except socket.gaierror:
        return False
    addrs = {info[4][0] for info in infos}
    if not addrs:
        return False
    for a in addrs:
        try:
            if not ipaddress.ip_address(a.split("%")[0]).is_loopback:
                return False
        except ValueError:
            return False
    return True


def _loopback_tcp_dsn(dsn: str) -> bool:
    """True only for a clean single-host loopback TCP PostgreSQL URL.

    Rejects (fails closed) keyword-form DSNs, Unix sockets, ``host=`` redirects,
    multi-host URLs, percent-encoded delimiters, userinfo confusion, empty database,
    fragments, non-loopback hosts, non-PostgreSQL schemes, and portless DSNs.
    """
    if not dsn or "://" not in dsn:
        return False
    try:
        parts = urlsplit(dsn)
    except ValueError:
        return False
    if (parts.scheme or "").lower() not in POSTGRES_SCHEMES:
        return False
    if parts.fragment:
        return False
    netloc = parts.netloc
    hostportion = netloc.split("@")[-1]
    # No percent-encoding in the authority (an encoded comma/slash could smuggle a
    # second host or a socket path past the parser).
    if "%" in hostportion:
        return False
    if "," in hostportion:
        return False
    if "host=" in (parts.query or "").lower():
        return False
    try:
        host = parts.hostname
        port = parts.port
    except ValueError:
        return False
    if not host or port is None:
        return False
    if not _all_loopback(host):
        return False
    db = (parts.path or "").lstrip("/")
    if not db or "/" in db:
        return False
    return True


def _isolated_root(value: str | None) -> bool:
    if not value:
        return False
    try:
        resolved = Path(os.path.realpath(value))
    except (OSError, ValueError):
        return False
    parts = {p.lower() for p in resolved.parts}
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

    Necessary pre-conditions; they gate whether the database attestation is even
    consulted. A production request (no opt-in marker / no run id) short-circuits
    here and never opens a database connection.
    """
    dsn = _runtime_dsn()
    run_id = _run_id()
    return {
        "marker_set": _truthy(os.environ.get(VERIFICATION_MARKER_ENV)),
        "run_id_present": len(run_id) >= MIN_RUN_ID_CHARS,
        "postgres_backend": os.environ.get("MONDAY_REPORT_REPOSITORY_BACKEND", "") == "postgres" and bool(dsn),
        "loopback_tcp_dsn": _loopback_tcp_dsn(dsn),
        "isolated_state_root": _isolated_root(os.environ.get("MONDAY_REPORT_STATE_PATH")),
        "isolated_storage_root": _isolated_root(os.environ.get("MONDAY_REPORT_STORAGE_ROOT")),
        "isolated_export_root": _isolated_root(os.environ.get("MONDAY_REPORT_EXPORT_ROOT")),
        "non_live_api_port": _port(os.environ.get("MONDAY_REPORT_API_BASE")) != LIVE_API_PORT,
        "non_live_web_port": _port(os.environ.get("MONDAY_REPORT_WEB_BASE")) != LIVE_WEB_PORT,
    }


def _expected_db_name(dsn: str) -> str:
    try:
        return (urlsplit(dsn).path or "").lstrip("/")
    except ValueError:
        return ""


# A collision-resistant SHA-256 fingerprint of the CURRENT PostgreSQL cluster + server
# instance, computed entirely inside PostgreSQL on one connection. Bound to the cluster
# ``system_identifier`` (assigned at initdb, so a logical dump/restore gets a new one)
# AND the postmaster start time (so a physical filesystem copy, which preserves the
# system_identifier, still differs because it is started separately) AND the database
# name/OID/server address/port. jsonb_build_object produces a canonical, key-sorted,
# structurally-delimited encoding, so fields cannot run together ambiguously. The
# ``system_identifier`` is read via pg_control_system(), which needs elevated
# privileges, so the whole comparison runs inside a SECURITY DEFINER function the
# migration/admin principal owns -- the runtime role only EXECUTEs it and never reads
# the raw cluster id.
FINGERPRINT_VERSION = 3
_FINGERPRINT_EXPR = (
    "encode(sha256(convert_to(jsonb_build_object("
    f"'v', {FINGERPRINT_VERSION}, "
    f"'purpose', '{ATTESTATION_PURPOSE}', "
    "'sysid', (select system_identifier::text from pg_control_system()), "
    "'db', current_database(), "
    "'oid', (select oid::text from pg_database where datname = current_database()), "
    "'addr', coalesce(host(inet_server_addr()), ''), "
    "'port', coalesce(inet_server_port()::text, ''), "
    "'pmst', extract(epoch from pg_postmaster_start_time())::text"
    ")::text, 'UTF8')), 'hex')"
)

# The SECURITY DEFINER checker: owned by the migration/admin principal, non-mutating,
# fixed search_path, EXECUTE granted only to the runtime group (never PUBLIC). It reads
# the attestation table and returns only a boolean, so the runtime role never reads the
# stored fingerprint or raw run hash and cannot replace the function. (The cluster
# system_identifier itself is a public identifier; the boundary is that the runtime
# cannot WRITE the attestation, not that it cannot learn the cluster id.)
ATTESTATION_CHECK_FN = f"{ATTESTATION_SCHEMA}.mr_verification_isolation_check"


def _is_loopback_addr(addr: str | None) -> bool:
    if not addr:
        return False
    try:
        return ipaddress.ip_address(addr.split("%")[0]).is_loopback
    except ValueError:
        return False


def _is_local_server_addr(addr: str | None) -> bool:
    """True for a server that is not globally routable: loopback, RFC1918 private, or
    link-local / unique-local. False for a public address or an unparseable value.

    NOTE (deliberate deviation, documented). The stricter "inet_server_addr() must be
    loopback" is incompatible with the disposable PostgreSQL this boundary exists to
    verify: a container reached through host port-mapping reports its own address as
    the container-internal IP (e.g. 172.17.x.x), never 127.0.0.1, so a loopback-only
    gate would make the boundary un-activatable in the very environment it is for.
    The clone/restore threat is instead defeated by the server-instance FINGERPRINT
    (a different server has a different postmaster start time / OID / address), and a
    tunnel to a *production* server is defeated by the attestation simply being ABSENT
    there. Rejecting globally-routable addresses keeps defence-in-depth against a
    tunnel to a public production host while permitting a local/container database.
    """
    if not addr:
        return False
    try:
        return not ipaddress.ip_address(addr.split("%")[0]).is_global
    except ValueError:
        return False


def database_attestation_present(dsn: str | None = None, run_id: str | None = None) -> bool:
    """True iff a matching, unexpired, run- AND server-instance-scoped attestation
    exists in the runtime database, verified on a fresh connection to it. Binds to the
    live server instance so a clone/restore to another server (or a loopback tunnel to
    a non-loopback server) cannot qualify. Fails closed on ANY error/mismatch:

    * the DSN-named database equals ``current_database()``;
    * the server's OWN address (``inet_server_addr()``) is not globally routable
      (loopback/private/container) -- a tunnel to a public production host fails here;
      the address is also folded into the fingerprint so a clone to a differently
      addressed server is rejected regardless;
    * exactly one unexpired record whose ``run_id_hash`` and stored server fingerprint
      both match the live values on this connection.
    """
    dsn = dsn if dsn is not None else _runtime_dsn()
    run_id = run_id if run_id is not None else _run_id()
    if not _loopback_tcp_dsn(dsn) or len(run_id) < MIN_RUN_ID_CHARS:
        return False
    expected_db = _expected_db_name(dsn)
    try:
        import psycopg
    except Exception:  # noqa: BLE001
        return False
    try:
        with psycopg.connect(dsn, connect_timeout=5, autocommit=True) as conn:
            # The whole cluster-bound match runs inside the admin-owned SECURITY DEFINER
            # checker (fully qualified call, single text argument, no dynamic SQL); the
            # runtime role only EXECUTEs it and receives a boolean.
            row = conn.execute(
                f"select current_database(), host(inet_server_addr()), {ATTESTATION_CHECK_FN}(%s)",
                (_run_id_hash(run_id),),
            ).fetchone()
            if not row:
                return False
            actual_db, server_addr, matches = row
            if actual_db != expected_db:
                return False  # env-to-database equality: the DSN names the live db
            if not _is_local_server_addr(server_addr):
                return False  # reject a globally-routable server address (public-prod tunnel)
            return matches is True  # single active run- + cluster/server-bound record
    except Exception:  # noqa: BLE001
        return False


def verification_context() -> dict:
    """Single evaluation (environment signals + run-scoped database attestation).

    The database is consulted only when every environment signal already holds, so a
    production request never opens the attestation connection. Redacted: booleans and
    signal names only -- never a DSN, host, port, credential, path, or run identifier.
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
    return verification_context()["verification_isolation_active"]


def verification_context_summary() -> dict:
    return verification_context()


def verification_run_fingerprint() -> str | None:
    """A short, non-reversible fingerprint of the run id for audit binding: the first
    12 hex chars of its SHA-256. Never the raw run id. None when unset."""
    run_id = _run_id()
    return _run_id_hash(run_id)[:12] if len(run_id) >= MIN_RUN_ID_CHARS else None


def install_database_attestation(
    dsn: str,
    run_id: str,
    *,
    ttl_seconds: int = 3600,
    grant_to: str | None = None,
) -> None:
    """Install the cluster-bound attestation in a disposable database. Called ONLY by
    the isolated verification harness (never a production migration), AFTER migrations
    and role provisioning, on a connection to the SAME server the app uses. Stores only
    the SHA-256 of ``run_id`` and a SHA-256 cluster/server fingerprint (never the raw
    run id, never the raw cluster id). The runtime role receives EXECUTE on the
    SECURITY DEFINER checker only -- no direct table access, no PUBLIC privilege."""
    import psycopg

    if len(run_id) < MIN_RUN_ID_CHARS:
        raise ValueError("run_id must be at least 128 bits")
    if grant_to and not grant_to.replace("_", "").isalnum():
        raise ValueError("grant_to must be a bare identifier")  # no injection via role name
    with psycopg.connect(dsn, connect_timeout=5, autocommit=True) as conn:
        # Fail closed if the privileged cluster id is unreadable here: the whole model
        # depends on binding to it, so a silent fallback to a weaker fingerprint is
        # unacceptable.
        sysid = conn.execute("select system_identifier::text from pg_control_system()").fetchone()
        if not sysid or not sysid[0]:
            raise RuntimeError("cluster system_identifier unavailable; environment unsupported")
        conn.execute(
            f"create table if not exists {ATTESTATION_QUALIFIED} ("
            "run_id_hash text primary key, "
            "server_fingerprint text not null, "
            "created_at timestamptz not null default now(), "
            "expires_at timestamptz not null, "
            "purpose text not null)"
        )
        conn.execute(f"revoke all on {ATTESTATION_QUALIFIED} from public")
        conn.execute(f"truncate {ATTESTATION_QUALIFIED}")  # single active record
        # The fingerprint is computed on THIS (same-server, admin) connection; the
        # runtime check recomputes it via the SECURITY DEFINER function on the same
        # server. A clone/restore to another cluster has a different system_identifier
        # and/or postmaster start time, so it will not match.
        conn.execute(
            f"insert into {ATTESTATION_QUALIFIED} (run_id_hash, server_fingerprint, expires_at, purpose) "
            f"values (%s, {_FINGERPRINT_EXPR}, now() + make_interval(secs => %s), %s)",
            (_run_id_hash(run_id), int(ttl_seconds), ATTESTATION_PURPOSE),
        )
        # The admin-owned, non-mutating checker. Fixed search_path; reads the privileged
        # cluster id and the attestation and returns only a boolean.
        conn.execute(
            f"create or replace function {ATTESTATION_CHECK_FN}(p_run_hash text) "
            "returns boolean language sql security definer "
            "set search_path = pg_catalog, public as $mrfn$ "
            "select count(*) = 1 "
            f"from {ATTESTATION_QUALIFIED} a "
            "where a.run_id_hash = p_run_hash and a.expires_at > now() "
            f"and a.server_fingerprint = {_FINGERPRINT_EXPR} $mrfn$"
        )
        conn.execute(f"revoke all on function {ATTESTATION_CHECK_FN}(text) from public")
        if grant_to:
            # EXECUTE-only on the checker; no direct table privilege.
            conn.execute(f"grant execute on function {ATTESTATION_CHECK_FN}(text) to {grant_to}")
