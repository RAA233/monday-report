"""Production-PROFILE PostgreSQL database adapter (behavioral tier).

SCOPE — read this first. This module implements and lets a disposable test harness
PROVE the *behavioral* production-profile of a PostgreSQL database adapter: explicit
fail-closed selection, a real bounded connection pool, enforced verified TLS,
migration/runtime role separation with a least-privilege runtime role, forced RLS,
schema/migration verification, transaction-local tenant context with pool hygiene,
business/audit atomicity (inherited from ``PostgresStateStore``), a bounded
pre-mutation retry boundary with NO post-mutation retry, and bounded startup/shutdown.

It is verified ONLY against isolated, disposable PostgreSQL with disposable test
certificates. It therefore does NOT — and this module's evidence tier must never let it
be read to — establish production-TARGET acceptance: no real endpoint, credentials,
managed-service identity, private networking, durable-replicated storage, backup,
restore, failover, monitoring, capacity, or operational ownership are certified here.
The accepted ``production-database-adapter-evidence.v1`` production-target control
(``ga_postgres_adapter``) remains BLOCKED and independent of this module. See
``production_database_profile_evidence.py`` for the behavioral schema and the
``PRODUCTION_DATABASE_ADAPTER_BEHAVIORAL_ACCEPTED`` disclosure.

Nothing here connects to a real production database or reads real credentials: every
connection target is supplied explicitly by the caller (the disposable harness).
"""
from __future__ import annotations

import contextlib
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator


# --------------------------------------------------------------------------- errors
class ProductionProfileConfigError(RuntimeError):
    """A production-profile configuration is missing, malformed, or unsafe.

    Raised BEFORE any traffic or business mutation. The message is always redacted
    (no DSN, host, password, cert material, or role name), so it is safe to log.
    """


class PoolExhausted(RuntimeError):
    """A pooled connection could not be acquired within the bounded acquisition
    deadline. Fail-closed backpressure — never a silent unbounded wait."""


class PoolClosed(RuntimeError):
    """A lease was requested after the pool began shutting down."""


class AdapterNotStarted(RuntimeError):
    """A pooled operation was requested before ``start()`` completed."""


# --------------------------------------------------------------------------- redaction
_LEAK_PATTERNS: tuple[str, ...] = (
    r"postgres(?:ql)?://\S+",
    r"password\s*=\s*\S+",
    r"\bhost\s*=\s*\S+",
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
    r"sslrootcert\s*=\s*\S+",
    r"sslcert\s*=\s*\S+",
    r"sslkey\s*=\s*\S+",
    r"user\s*=\s*\S+",
)


def redact(text: str) -> str:
    """Strip DSN/credential/host/cert shapes from a diagnostic string. Used on every
    surfaced message so a configuration error can never leak a secret."""
    out = text or ""
    for pat in _LEAK_PATTERNS:
        out = re.sub(pat, "<redacted>", out, flags=re.IGNORECASE)
    return out[:400]


# --------------------------------------------------------------------------- TLS modes
#: libpq sslmode values that DO verify the server certificate and hostname.
_VERIFYING_SSLMODES: frozenset[str] = frozenset({"verify-full"})
#: sslmodes rejected in production profile: plaintext, opportunistic, or
#: encryption-without-verification. ``verify-ca`` is rejected too — it verifies the
#: chain but NOT the hostname, so it does not defeat a redirected-endpoint attack.
_REJECTED_SSLMODES: frozenset[str] = frozenset(
    {"disable", "allow", "prefer", "require", "verify-ca"})


# --------------------------------------------------------------------------- config
@dataclass(frozen=True)
class PoolConfig:
    """Explicit, bounded pool settings. Every field is REQUIRED — there is no
    'unbounded' sentinel and no implicit default that could disable a bound."""
    min_size: int
    max_size: int
    acquire_timeout_seconds: float
    connect_timeout_seconds: float
    idle_lifetime_seconds: float
    shutdown_deadline_seconds: float
    statement_timeout_ms: int
    lock_timeout_ms: int
    idle_in_transaction_timeout_ms: int

    def validate(self) -> None:
        if not (1 <= self.min_size <= self.max_size <= 512):
            raise ProductionProfileConfigError(
                "pool sizes must satisfy 1 <= min <= max <= 512 (no unbounded pool)")
        for name, value in (
            ("acquire_timeout_seconds", self.acquire_timeout_seconds),
            ("connect_timeout_seconds", self.connect_timeout_seconds),
            ("idle_lifetime_seconds", self.idle_lifetime_seconds),
            ("shutdown_deadline_seconds", self.shutdown_deadline_seconds),
        ):
            if not (value and 0 < float(value) <= 600):
                raise ProductionProfileConfigError(
                    f"{name} must be a bounded positive duration (0, 600]s")
        for name, value in (
            ("statement_timeout_ms", self.statement_timeout_ms),
            ("lock_timeout_ms", self.lock_timeout_ms),
            ("idle_in_transaction_timeout_ms", self.idle_in_transaction_timeout_ms),
        ):
            if not (0 < int(value) <= 600_000):
                raise ProductionProfileConfigError(
                    f"{name} must be a bounded positive timeout (0, 600000]ms")


#: Documented default pool profile. Rationale is recorded per field so no value is
#: 'arbitrary': these suit a small always-on API + worker fleet against one primary.
DEFAULT_POOL = PoolConfig(
    min_size=2,               # keep a warm floor so the first request does not pay cold-connect
    max_size=16,              # bounded ceiling; backpressure past this, never unbounded growth
    acquire_timeout_seconds=5.0,     # a caller waits at most 5s for a slot, then fails closed
    connect_timeout_seconds=5.0,     # libpq connect deadline; bounds a slow/lost server
    idle_lifetime_seconds=120.0,     # recycle a connection idle >2min so stale sessions do not accrue
    shutdown_deadline_seconds=10.0,  # bounded drain; never hang on shutdown
    statement_timeout_ms=15_000,     # server caps any single statement at 15s
    lock_timeout_ms=5_000,           # never block on a lock more than 5s
    idle_in_transaction_timeout_ms=15_000,  # a forgotten open transaction is reaped
)


@dataclass(frozen=True)
class ProductionProfileConfig:
    """A fully-resolved, validated production-profile configuration.

    ``profile`` MUST be the literal ``"production"`` for the production adapter to be
    selected; anything else is a hard selection failure (no implicit downgrade)."""
    profile: str
    dsn: str                       # supplied explicitly by the caller (disposable harness)
    sslmode: str
    sslrootcert: str
    migration_role: str            # for the migration!=runtime separation check
    pool: PoolConfig = field(default_factory=lambda: DEFAULT_POOL)
    #: Test-only escape hatch. It can NEVER be true when profile == "production": a
    #: production profile rejects any relaxation, so an operator cannot accidentally
    #: ship a verification shortcut. Only a non-production profile may set it.
    allow_unverified_tls_for_test: bool = False

    def validate(self) -> None:
        if self.profile != "production":
            raise ProductionProfileConfigError(
                "production adapter selected without profile == 'production' "
                "(no implicit fallback)")
        if not self.dsn or not isinstance(self.dsn, str):
            raise ProductionProfileConfigError("production DSN is missing")
        if self.allow_unverified_tls_for_test:
            # Structurally impossible to relax TLS in production profile.
            raise ProductionProfileConfigError(
                "unverified-TLS escape hatch cannot activate in production profile")
        mode = (self.sslmode or "").strip().lower()
        if mode in _REJECTED_SSLMODES:
            raise ProductionProfileConfigError(
                f"sslmode {mode!r} does not verify the server: production requires verify-full")
        if mode not in _VERIFYING_SSLMODES:
            raise ProductionProfileConfigError(
                f"unknown or non-verifying sslmode {mode!r}; production requires verify-full")
        if not self.sslrootcert or not os.path.isfile(self.sslrootcert):
            raise ProductionProfileConfigError(
                "sslrootcert (CA bundle) is required and must exist for verify-full")
        # A DSN that itself disables/relaxes TLS is rejected even if sslmode field says
        # verify-full — the effective libpq value would be the DSN's.
        dsn_mode = re.search(r"sslmode\s*=\s*([a-z-]+)", self.dsn, re.IGNORECASE)
        if dsn_mode and dsn_mode.group(1).strip().lower() in _REJECTED_SSLMODES:
            raise ProductionProfileConfigError(
                "the DSN embeds a non-verifying sslmode; production requires verify-full")
        self.pool.validate()

    # ---- effective libpq connection kwargs (TLS enforced) ----
    def connect_kwargs(self) -> dict[str, Any]:
        """psycopg.connect kwargs that FORCE verify-full TLS regardless of the DSN.

        Passing sslmode/sslrootcert as explicit kwargs makes libpq use them; combined
        with the DSN check above, a plaintext or verify-disabled connection cannot be
        established in production profile."""
        return {
            "sslmode": "verify-full",
            "sslrootcert": self.sslrootcert,
            "connect_timeout": int(self.pool.connect_timeout_seconds),
        }


def load_config_from_env(env: dict[str, str] | None = None) -> ProductionProfileConfig:
    """Resolve a production-profile config from explicit env vars, fail-closed.

    Reads only variables this task owns:
      MONDAY_REPORT_DB_PROFILE           must be 'production'
      MONDAY_REPORT_PROD_DSN             the (disposable, in this task) target DSN
      MONDAY_REPORT_PROD_SSLMODE         must be 'verify-full'
      MONDAY_REPORT_PROD_SSLROOTCERT     path to the CA bundle
      MONDAY_REPORT_PROD_MIGRATION_ROLE  migration principal (for the != runtime check)
      MONDAY_REPORT_PROD_POOL_*          optional bounded pool overrides
    A missing/malformed value raises ProductionProfileConfigError BEFORE any connect.
    """
    e = dict(os.environ if env is None else env)

    def _int(name: str, default: int) -> int:
        raw = e.get(name)
        if raw is None or raw == "":
            return default
        try:
            return int(raw)
        except ValueError:
            raise ProductionProfileConfigError(f"{name} is not an integer")

    def _float(name: str, default: float) -> float:
        raw = e.get(name)
        if raw is None or raw == "":
            return default
        try:
            return float(raw)
        except ValueError:
            raise ProductionProfileConfigError(f"{name} is not a number")

    pool = PoolConfig(
        min_size=_int("MONDAY_REPORT_PROD_POOL_MIN", DEFAULT_POOL.min_size),
        max_size=_int("MONDAY_REPORT_PROD_POOL_MAX", DEFAULT_POOL.max_size),
        acquire_timeout_seconds=_float("MONDAY_REPORT_PROD_POOL_ACQUIRE_TIMEOUT",
                                       DEFAULT_POOL.acquire_timeout_seconds),
        connect_timeout_seconds=_float("MONDAY_REPORT_PROD_POOL_CONNECT_TIMEOUT",
                                       DEFAULT_POOL.connect_timeout_seconds),
        idle_lifetime_seconds=_float("MONDAY_REPORT_PROD_POOL_IDLE_LIFETIME",
                                     DEFAULT_POOL.idle_lifetime_seconds),
        shutdown_deadline_seconds=_float("MONDAY_REPORT_PROD_POOL_SHUTDOWN_DEADLINE",
                                         DEFAULT_POOL.shutdown_deadline_seconds),
        statement_timeout_ms=_int("MONDAY_REPORT_PROD_STATEMENT_TIMEOUT_MS",
                                  DEFAULT_POOL.statement_timeout_ms),
        lock_timeout_ms=_int("MONDAY_REPORT_PROD_LOCK_TIMEOUT_MS",
                             DEFAULT_POOL.lock_timeout_ms),
        idle_in_transaction_timeout_ms=_int("MONDAY_REPORT_PROD_IDLE_IN_TXN_TIMEOUT_MS",
                                            DEFAULT_POOL.idle_in_transaction_timeout_ms),
    )
    config = ProductionProfileConfig(
        profile=e.get("MONDAY_REPORT_DB_PROFILE", ""),
        dsn=e.get("MONDAY_REPORT_PROD_DSN", ""),
        sslmode=e.get("MONDAY_REPORT_PROD_SSLMODE", ""),
        sslrootcert=e.get("MONDAY_REPORT_PROD_SSLROOTCERT", ""),
        migration_role=e.get("MONDAY_REPORT_PROD_MIGRATION_ROLE", ""),
        pool=pool,
    )
    config.validate()
    return config


# --------------------------------------------------------------------------- pool
class _PooledConnection:
    """One physical connection tracked by the pool, with its creation/last-use clock."""

    __slots__ = ("raw", "created_at", "last_used_at")

    def __init__(self, raw: Any, now: float) -> None:
        self.raw = raw
        self.created_at = now
        self.last_used_at = now


class BoundedConnectionPool:
    """A real, thread-safe, strictly-bounded psycopg connection pool.

    Guarantees: never more than ``max_size`` physical connections; a lease waits at
    most ``acquire_timeout_seconds`` and then raises :class:`PoolExhausted` (bounded
    backpressure, never an unbounded wait); a returned connection is rolled back and
    its session state reset before reuse (pool hygiene); idle connections past
    ``idle_lifetime_seconds`` are recycled; shutdown drains within a bounded deadline,
    rolls back in-flight work, and closes every connection.
    """

    def __init__(self, config: ProductionProfileConfig,
                 *, connect: Callable[[], Any] | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._config = config
        self._pool = config.pool
        self._clock = clock
        self._connect_factory = connect or self._default_connect
        self._lock = threading.Lock()
        self._idle: list[_PooledConnection] = []
        self._in_use: set[int] = set()
        self._total = 0                      # physical connections that exist
        self._closing = False
        # A bounded counting semaphore is the hard ceiling: at most max_size permits,
        # so no more than max_size concurrent leases can ever be outstanding.
        self._slots = threading.BoundedSemaphore(self._pool.max_size)
        self._acquired_slots_lock = threading.Lock()
        self.stats = {"created": 0, "reused": 0, "recycled_idle": 0, "acquire_timeouts": 0,
                      "rollbacks_on_return": 0, "closed": 0}

    # -- connection factory (TLS enforced) --
    def _default_connect(self) -> Any:
        import psycopg
        conn = psycopg.connect(self._config.dsn, autocommit=False,
                               **self._config.connect_kwargs())
        self._apply_session_timeouts(conn)
        return conn

    def _apply_session_timeouts(self, conn: Any) -> None:
        # SET is a utility statement and cannot take a bind parameter; set_config(...,
        # is_local => false) is the parameterised SESSION-level equivalent.
        with conn.cursor() as cur:
            cur.execute("select set_config('statement_timeout', %s, false)",
                        (str(self._pool.statement_timeout_ms),))
            cur.execute("select set_config('lock_timeout', %s, false)",
                        (str(self._pool.lock_timeout_ms),))
            cur.execute("select set_config('idle_in_transaction_session_timeout', %s, false)",
                        (str(self._pool.idle_in_transaction_timeout_ms),))
        conn.commit()

    def prefill(self) -> None:
        """Open the warm floor (min_size). Bounded and fail-closed."""
        with self._lock:
            need = max(0, self._pool.min_size - self._total)
        for _ in range(need):
            conn = self._connect_factory()
            with self._lock:
                self._total += 1
                self.stats["created"] += 1
                self._idle.append(_PooledConnection(conn, self._clock()))

    @contextlib.contextmanager
    def lease(self) -> Iterator[Any]:
        """Check a connection out of the pool for the duration of the block.

        On exit the connection is rolled back (discarding any open transaction) and
        its session-local overrides are reset before it returns to the pool — an
        alternating tenant cannot inherit a prior tenant's context or a dirty txn."""
        if self._closing:
            raise PoolClosed("pool is shutting down")
        acquired = self._slots.acquire(timeout=self._pool.acquire_timeout_seconds)
        if not acquired:
            with self._lock:
                self.stats["acquire_timeouts"] += 1
            raise PoolExhausted("no pooled connection available within the acquisition deadline")
        pooled: _PooledConnection | None = None
        try:
            pooled = self._checkout()
            yield pooled.raw
        finally:
            if pooled is not None:
                self._checkin(pooled)
            self._slots.release()

    def _checkout(self) -> _PooledConnection:
        now = self._clock()
        with self._lock:
            if self._closing:
                raise PoolClosed("pool is shutting down")
            # Discard idle connections that outlived their lifetime.
            while self._idle:
                cand = self._idle.pop()
                if now - cand.last_used_at > self._pool.idle_lifetime_seconds:
                    self._destroy(cand)
                    self.stats["recycled_idle"] += 1
                    continue
                if self._is_healthy(cand.raw):
                    cand.last_used_at = now
                    self._in_use.add(id(cand))
                    self.stats["reused"] += 1
                    return cand
                self._destroy(cand)
            # None reusable: create a new physical connection (bounded by the semaphore).
            conn = self._connect_factory()
            self._total += 1
            self.stats["created"] += 1
            pooled = _PooledConnection(conn, now)
            self._in_use.add(id(pooled))
            return pooled

    def _checkin(self, pooled: _PooledConnection) -> None:
        # Reset BEFORE returning: rollback any open txn and clear session-local state so
        # a reused connection never carries a prior tenant's app.tenant_slug / overrides.
        clean = False
        try:
            pooled.raw.rollback()
            with self._lock:
                self.stats["rollbacks_on_return"] += 1
            with pooled.raw.cursor() as cur:
                cur.execute("reset all")
            pooled.raw.commit()
            self._apply_session_timeouts(pooled.raw)
            clean = True
        except Exception:
            clean = False
        with self._lock:
            self._in_use.discard(id(pooled))
            if self._closing or not clean or not self._is_healthy(pooled.raw):
                self._destroy(pooled)
                return
            pooled.last_used_at = self._clock()
            self._idle.append(pooled)

    def _is_healthy(self, conn: Any) -> bool:
        try:
            if getattr(conn, "closed", False):
                return False
            with conn.cursor() as cur:
                cur.execute("select 1")
                cur.fetchone()
            conn.commit()
            return True
        except Exception:
            return False

    def _destroy(self, pooled: _PooledConnection) -> None:
        try:
            pooled.raw.close()
        except Exception:
            pass
        self.stats["closed"] += 1
        self._total = max(0, self._total - 1)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"total": self._total, "idle": len(self._idle),
                    "in_use": len(self._in_use), "max_size": self._pool.max_size,
                    "min_size": self._pool.min_size, "closing": self._closing,
                    **{k: v for k, v in self.stats.items()}}

    def close(self) -> dict[str, Any]:
        """Bounded drain: stop new leases, wait up to the deadline for in-use to return,
        rollback + close everything. Never hangs; reports whether it drained cleanly."""
        deadline = self._clock() + self._pool.shutdown_deadline_seconds
        with self._lock:
            self._closing = True
        # Wait (bounded) for outstanding leases to check in.
        drained = True
        while True:
            with self._lock:
                outstanding = len(self._in_use)
                idle = list(self._idle)
                self._idle.clear()
            for pooled in idle:
                self._destroy(pooled)
            if outstanding == 0:
                break
            if self._clock() >= deadline:
                drained = False
                break
            time.sleep(0.02)
        with self._lock:
            leftover = self._total
        return {"drained_cleanly": drained, "connections_remaining": leftover,
                "closed": self.stats["closed"]}


# --------------------------------------------------------------------------- Layer-1 probe
_TRANSIENT_CONNECT_MARKERS = (
    "server closed the connection", "connection refused", "could not connect",
    "the database system is starting up", "connection failed", "timeout expired",
    "operation timed out",
)
_NONTRANSIENT_CONNECT_MARKERS = (
    "password authentication failed", "permission denied", "does not exist",
    "certificate verify failed", "no pg_hba.conf entry", "ssl error",
)


class StableSqlUnavailable(RuntimeError):
    """The target never became TCP+SQL ready within the bounded deadline."""


def wait_for_stable_sql(connect: Callable[[], Any], *, deadline_seconds: float = 30.0,
                        poll_seconds: float = 0.5) -> list[dict]:
    """Layer-1: open a REAL session + select-1 + close, retrying ONLY transient
    connect classes within a bounded deadline, before any semantic bootstrap. Fails
    closed on a non-transient class (auth/permission/TLS/missing) with no retry."""
    history: list[dict] = []
    start = time.monotonic()
    while True:
        try:
            conn = connect()
            try:
                with conn.cursor() as cur:
                    cur.execute("select 1")
                    cur.fetchone()
            finally:
                conn.close()
            history.append({"outcome": "connected"})
            return history
        except Exception as exc:  # noqa: BLE001
            msg = str(exc).lower()
            if any(m in msg for m in _NONTRANSIENT_CONNECT_MARKERS) and not any(
                    m in msg for m in _TRANSIENT_CONNECT_MARKERS):
                raise StableSqlUnavailable("non-transient connect failure (fail-closed)") from None
            history.append({"outcome": "transient"})
            elapsed = time.monotonic() - start
            if elapsed + poll_seconds >= deadline_seconds:
                raise StableSqlUnavailable(
                    "stable SQL readiness deadline exceeded (transient)") from None
            time.sleep(poll_seconds)


# --------------------------------------------------------------------------- adapter
class ProductionDatabaseAdapter:
    """Owns the production-profile config, the bounded pool, and the startup/shutdown
    lifecycle. Every business operation runs through tenant_transaction, which leases a
    pooled TLS connection and applies transaction-local tenant scope."""

    def __init__(self, config: ProductionProfileConfig,
                 *, connect: Callable[[], Any] | None = None) -> None:
        config.validate()  # fail closed again at construction
        self._config = config
        self._pool = BoundedConnectionPool(config, connect=connect)
        self._started = False
        self._identity: dict[str, Any] = {}
        self._schema: dict[str, Any] = {}
        self._sql_readiness: list[dict] = []

    def start(self) -> dict[str, Any]:
        """Bounded, fail-closed startup. Proves: config valid, stable SQL available,
        pool initialised, schema compatible, runtime identity restricted, RLS forced."""
        self._config.validate()
        self._sql_readiness = wait_for_stable_sql(self._pool._connect_factory)
        self._pool.prefill()
        with self._pool.lease() as conn:
            self._identity = self._measure_identity(conn)
            self._schema = self._verify_schema(conn)
        violations = self._identity.get("violations", ["identity not measured"])
        if violations:
            raise ProductionProfileConfigError(
                "runtime role not least-privilege / RLS not forced: "
                + redact("; ".join(violations)))
        if not self._schema.get("compatible"):
            raise ProductionProfileConfigError(
                "schema/migration verification failed: " + redact(str(self._schema.get("reason", ""))))
        self._started = True
        return self.status()

    def _measure_identity(self, conn: Any) -> dict[str, Any]:
        from . import tenant_rls
        m = tenant_rls.measure_runtime_role(conn)
        violations = list(tenant_rls.runtime_role_violations(
            m, migration_role=self._config.migration_role or None))
        same_as_migration = bool(self._config.migration_role) and \
            m.get("current_user") == self._config.migration_role
        if same_as_migration:
            violations.append("runtime role equals migration role")
        inv = tenant_rls.policy_inventory(conn)
        policies = inv.get("policies", inv) if isinstance(inv, dict) else inv
        return {
            "is_superuser": bool(m.get("is_superuser")),
            "has_bypassrls": bool(m.get("has_bypassrls")),
            "is_login": bool(m.get("can_login")),
            "is_login_not_group": bool(m.get("is_login_not_group")),
            "owner_bypass_tables": len(m.get("owner_bypass_tables", [])),
            "missing_forced_tables": len(m.get("missing_forced_tables", [])),
            "forced_normalized_count": int(m.get("forced_normalized_count", 0)),
            "migration_distinct_from_runtime": not same_as_migration,
            "policy_count": len(policies) if isinstance(policies, (list, dict)) else 0,
            "violations": violations,
        }

    def _verify_schema(self, conn: Any) -> dict[str, Any]:
        """Fail-closed schema posture: required extension present, forced RLS on the
        protected tables, migration marker table present. NEVER runs DDL."""
        try:
            with conn.cursor() as cur:
                cur.execute("select exists(select 1 from pg_extension where extname='vector')")
                has_vector = bool(cur.fetchone()[0])
                cur.execute("select exists(select 1 from information_schema.tables "
                            "where table_name='monday_report_state_snapshots')")
                has_state = bool(cur.fetchone()[0])
                cur.execute(
                    "select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace "
                    "where c.relforcerowsecurity and n.nspname='public'")
                forced_count = int(cur.fetchone()[0])
            conn.commit()
        except Exception as exc:  # noqa: BLE001
            return {"compatible": False, "reason": redact(str(exc))}
        compatible = has_vector and has_state and forced_count >= 1
        return {"compatible": compatible, "has_vector_extension": has_vector,
                "has_state_table": has_state, "forced_rls_table_count": forced_count,
                "reason": "" if compatible else "missing extension/table/forced-RLS"}

    @contextlib.contextmanager
    def tenant_transaction(self, tenant_slug: str) -> Iterator[Any]:
        """Lease a pooled connection, BEGIN, apply TRANSACTION-LOCAL tenant scope, and
        yield a cursor. Commit on success; roll back on any error. The connection's
        session state is reset on return to the pool (no tenant retained)."""
        from . import tenant_rls
        if not self._started:
            raise AdapterNotStarted("adapter.start() must complete before a transaction")
        if not tenant_slug:
            raise tenant_rls.TenantContextError("tenant scope is required (fail closed)")
        with self._pool.lease() as conn:
            try:
                with conn.cursor() as cur:
                    tenant_rls.apply_verified_tenant_scope(cur, tenant_slug)
                    yield cur
                conn.commit()
            except BaseException:
                conn.rollback()
                raise

    def pre_mutation_attempt(self, fn: Callable[[], Any], *, max_attempts: int = 3) -> Any:
        """Layer-2: retry ONLY explicitly-classified transient failures that occur
        BEFORE a business mutation begins. Never retries a non-transient class."""
        last: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                return fn()
            except (PoolExhausted, StableSqlUnavailable) as exc:
                last = exc
                if attempt == max_attempts:
                    break
                time.sleep(min(0.5 * attempt, 2.0))
            except Exception as exc:  # noqa: BLE001 - non-transient: never retried
                raise exc
        raise last if last is not None else RuntimeError("pre-mutation retry exhausted")

    def shutdown(self) -> dict[str, Any]:
        result = self._pool.close()
        self._started = False
        return result

    def status(self) -> dict[str, Any]:
        return {
            "adapter": "production_profile_postgres",
            "started": self._started,
            "tls": {"required_mode": "verify-full", "verified": True,
                    "plaintext_rejected": True, "verify_disabled_rejected": True},
            "runtime_identity": {
                "is_superuser": self._identity.get("is_superuser"),
                "has_bypassrls": self._identity.get("has_bypassrls"),
                "is_login_not_group": self._identity.get("is_login_not_group"),
                "migration_distinct_from_runtime": self._identity.get("migration_distinct_from_runtime"),
                "least_privilege_ok": not self._identity.get("violations"),
            },
            "rls": {"forced_table_count": self._schema.get("forced_rls_table_count"),
                    "missing_forced_tables": self._identity.get("missing_forced_tables"),
                    "policy_count": self._identity.get("policy_count")},
            "schema": {"compatible": self._schema.get("compatible"),
                       "has_vector_extension": self._schema.get("has_vector_extension"),
                       "has_state_table": self._schema.get("has_state_table")},
            "pool": self._pool.snapshot(),
            "sql_readiness_attempts": len(self._sql_readiness),
        }
