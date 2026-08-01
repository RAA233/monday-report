"""Production-PROFILE queue adapter (BEHAVIORAL tier) over Redis Streams.

SCOPE — read first. This module implements, and a disposable harness PROVES, the
*behavioral* production-profile of an asynchronous queue adapter: explicit fail-closed
selection with no in-memory/inline fallback, bounded producer/consumer/worker resources
and backpressure, tenant- and idempotency-bound message metadata, at-least-once delivery
with a claim/lease (Redis Streams consumer groups + XCLAIM), acknowledgement ONLY after
the business mutation AND its audit event commit durably (through the accepted database
behavioral profile), a durable tenant-scoped idempotency strategy that makes duplicate
delivery a no-op at the business-effect level, bounded classified retry with backoff, an
explicit dead-letter stream after retry exhaustion with authorized idempotent replay,
bounded worker concurrency, and bounded startup/shutdown.

It is verified ONLY against a disposable Docker Redis + disposable PostgreSQL. It does
NOT — and its evidence tier must never be read to — establish production-TARGET queue
acceptance: no real broker endpoint, credentials, managed-service identity, private
networking, durable-replicated storage, executed failover/recovery drills, real
dead-letter inspection, capacity/latency, or monitoring are certified. The accepted
``production-queue-adapter-evidence.v1`` control (``ga_redis_adapter``) is not modified
and REMAINS BLOCKED; ``PRODUCTION_QUEUE_ADAPTER_NOT_ACCEPTED`` stands. See
``production_queue_profile_evidence.py`` for the behavioral schema and verdict
``PRODUCTION_QUEUE_ADAPTER_BEHAVIORAL_ACCEPTED``.

Nothing here connects to a real production queue or reads a real credential; every target
is supplied explicitly by the disposable harness.
"""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

DELIVERY_MODEL = "at-least-once"
MESSAGE_SCHEMA_VERSION = "mr-queue-msg.v1"


# --------------------------------------------------------------------------- errors
class QueueProfileConfigError(RuntimeError):
    """A queue production-profile configuration is missing/malformed/unsafe. Raised BEFORE
    any work is accepted. Always redacted."""


class MessageValidationError(RuntimeError):
    """A message failed schema/size/metadata validation and is rejected (never executed)."""


class NonRetryable(RuntimeError):
    """A failure class that must NEVER be retried (auth, tenant mismatch, invalid payload,
    business rejection, poison). Routes straight to the dead-letter path."""


class AdapterNotStarted(RuntimeError):
    pass


# --------------------------------------------------------------------------- redaction
_LEAK_PATTERNS = (
    r"redis(?:s)?://\S+", r"password\s*[:=]\s*\S+", r"\bhost\s*=\s*\S+",
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b", r"requirepass\s+\S+",
)


def redact(text: str) -> str:
    out = text or ""
    for pat in _LEAK_PATTERNS:
        out = re.sub(pat, "<redacted>", out, flags=re.IGNORECASE)
    return out[:400]


# --------------------------------------------------------------------------- config
@dataclass(frozen=True)
class QueueBounds:
    """Explicit bounded settings — every field REQUIRED, no unbounded sentinel."""
    producer_connections: int
    consumer_connections: int
    worker_concurrency: int
    receive_batch_size: int
    enqueue_timeout_seconds: float
    receive_block_ms: int
    lease_ms: int
    ack_timeout_seconds: float
    shutdown_drain_seconds: float
    max_payload_bytes: int
    max_retries: int
    backoff_base_ms: int

    def validate(self) -> None:
        checks = {
            "producer_connections": (self.producer_connections, 1, 64),
            "consumer_connections": (self.consumer_connections, 1, 64),
            "worker_concurrency": (self.worker_concurrency, 1, 64),
            "receive_batch_size": (self.receive_batch_size, 1, 1000),
            "lease_ms": (self.lease_ms, 100, 600_000),
            "max_payload_bytes": (self.max_payload_bytes, 1, 1_048_576),
            "max_retries": (self.max_retries, 1, 1000),
            "backoff_base_ms": (self.backoff_base_ms, 1, 60_000),
            "receive_block_ms": (self.receive_block_ms, 1, 60_000),
        }
        for name, (v, lo, hi) in checks.items():
            if not (isinstance(v, int) and lo <= v <= hi):
                raise QueueProfileConfigError(f"{name} must be an integer in [{lo},{hi}] (bounded)")
        for name, v in (("enqueue_timeout_seconds", self.enqueue_timeout_seconds),
                        ("ack_timeout_seconds", self.ack_timeout_seconds),
                        ("shutdown_drain_seconds", self.shutdown_drain_seconds)):
            if not (v and 0 < float(v) <= 600):
                raise QueueProfileConfigError(f"{name} must be a bounded positive duration (0,600]s")


DEFAULT_BOUNDS = QueueBounds(
    producer_connections=4, consumer_connections=4, worker_concurrency=4,
    receive_batch_size=16, enqueue_timeout_seconds=5.0, receive_block_ms=1000,
    lease_ms=30_000, ack_timeout_seconds=10.0, shutdown_drain_seconds=10.0,
    max_payload_bytes=65_536, max_retries=5, backoff_base_ms=50,
)


@dataclass(frozen=True)
class QueueProfileConfig:
    """Fully-resolved, validated queue production-profile config. ``profile`` MUST be the
    literal ``"production"`` for the broker adapter to be selected — no inline/in-memory
    fallback exists."""
    profile: str
    redis_url: str                 # supplied explicitly by the disposable harness
    stream_key: str                # per-deployment work stream
    group: str                     # consumer group
    dead_letter_key: str           # dead-letter stream
    require_tls: bool
    bounds: QueueBounds = field(default_factory=lambda: DEFAULT_BOUNDS)
    allow_inline_for_test: bool = False   # can NEVER be true in production profile

    def validate(self) -> None:
        if self.profile != "production":
            raise QueueProfileConfigError(
                "queue adapter selected without profile == 'production' (no inline/in-memory fallback)")
        if self.allow_inline_for_test:
            raise QueueProfileConfigError("inline execution cannot be enabled in production profile")
        if not self.redis_url or not isinstance(self.redis_url, str):
            raise QueueProfileConfigError("queue target URL is missing")
        if not (self.stream_key and self.group and self.dead_letter_key):
            raise QueueProfileConfigError("stream/group/dead-letter keys are all required")
        low = self.redis_url.lower()
        if self.require_tls and not low.startswith("rediss://"):
            raise QueueProfileConfigError("verified TLS required but the URL is not rediss://")
        # even without require_tls, a plaintext redis:// with an embedded ssl=false is refused
        if "ssl=false" in low or "ssl_cert_reqs=none" in low:
            raise QueueProfileConfigError("the URL disables TLS verification")
        self.bounds.validate()


def load_config_from_env(env: dict | None = None) -> QueueProfileConfig:
    import os
    e = dict(os.environ if env is None else env)
    cfg = QueueProfileConfig(
        profile=e.get("MONDAY_REPORT_QUEUE_PROFILE", ""),
        redis_url=e.get("MONDAY_REPORT_QUEUE_URL", ""),
        stream_key=e.get("MONDAY_REPORT_QUEUE_STREAM", ""),
        group=e.get("MONDAY_REPORT_QUEUE_GROUP", ""),
        dead_letter_key=e.get("MONDAY_REPORT_QUEUE_DLQ", ""),
        require_tls=e.get("MONDAY_REPORT_QUEUE_REQUIRE_TLS", "true").lower() == "true",
    )
    cfg.validate()
    return cfg


# --------------------------------------------------------------------------- message
_REQUIRED_META = ("schema_version", "tenant_slug", "operation", "idempotency_key",
                  "correlation_id", "enqueued_at", "attempt")


def build_message(*, tenant_slug: str, operation: str, idempotency_key: str,
                  correlation_id: str, payload: dict, enqueued_at: float) -> dict:
    if not tenant_slug:
        raise MessageValidationError("tenant_slug is required (fail closed)")
    if not operation:
        raise MessageValidationError("operation is required")
    if not idempotency_key:
        raise MessageValidationError("idempotency_key is required")
    return {
        "schema_version": MESSAGE_SCHEMA_VERSION,
        "tenant_slug": tenant_slug,
        "operation": operation,
        "idempotency_key": idempotency_key,
        "correlation_id": correlation_id,
        "enqueued_at": f"{enqueued_at:.6f}",
        "attempt": "1",
        "payload": json.dumps(payload, separators=(",", ":")),
    }


def validate_message(fields: dict, *, max_payload_bytes: int) -> dict:
    """Strict validation. Rejects unknown schema version, missing metadata, oversized or
    unsafe payload. Returns a normalized dict; raises MessageValidationError (non-retryable)."""
    for key in _REQUIRED_META:
        if key not in fields or fields.get(key) in (None, ""):
            raise MessageValidationError(f"message missing required metadata: {key}")
    if fields["schema_version"] != MESSAGE_SCHEMA_VERSION:
        raise MessageValidationError(f"unknown message schema_version {fields['schema_version']!r}")
    raw = fields.get("payload", "")
    if len(raw.encode("utf-8")) > max_payload_bytes:
        raise MessageValidationError("payload exceeds the maximum size")
    try:
        payload = json.loads(raw)   # json.loads only — never eval/pickle
    except Exception:
        raise MessageValidationError("payload is not valid JSON")
    if not isinstance(payload, dict):
        raise MessageValidationError("payload must be a JSON object")
    return {**fields, "payload_obj": payload}


# --------------------------------------------------------------------------- adapter
class ProductionQueueAdapter:
    """Redis Streams broker adapter. Producer/consumer connections are bounded; delivery is
    at-least-once with a lease (pending entries reclaimed via XAUTOCLAIM after the lease);
    ack happens only after the handler reports durable success; retries are bounded and
    classified; exhaustion routes to a dead-letter stream. Tenant scope is carried on the
    message and validated before any business access — never inferred from worker-global
    state."""

    def __init__(self, config: QueueProfileConfig, *, redis_factory: Callable[[], Any] | None = None):
        config.validate()
        self._config = config
        self._bounds = config.bounds
        self._redis_factory = redis_factory or self._default_redis
        self._producer = None
        self._consumers: list[Any] = []
        self._started = False
        self._lock = threading.Lock()
        self.stats = {"enqueued": 0, "delivered": 0, "acked": 0, "retries": 0,
                      "dead_lettered": 0, "duplicates_suppressed": 0, "replays": 0,
                      "validation_rejected": 0, "in_flight": 0}

    def _default_redis(self) -> Any:
        import redis
        return redis.Redis.from_url(self._config.redis_url, decode_responses=True,
                                    socket_connect_timeout=int(self._bounds.enqueue_timeout_seconds),
                                    socket_timeout=int(self._bounds.ack_timeout_seconds))

    # -- startup --
    def start(self) -> dict:
        self._config.validate()
        self._producer = self._redis_factory()
        self._producer.ping()
        # bounded consumer connections
        for _ in range(self._bounds.consumer_connections):
            self._consumers.append(self._redis_factory())
        # create the consumer group (idempotent)
        try:
            self._producer.xgroup_create(self._config.stream_key, self._config.group,
                                         id="0", mkstream=True)
        except Exception as exc:  # BUSYGROUP is fine
            if "BUSYGROUP" not in str(exc):
                raise QueueProfileConfigError("could not create consumer group: " + redact(str(exc)))
        # ensure the dead-letter stream exists without adding a fake job
        self._producer.xadd(self._config.dead_letter_key, {"_init": "1"})
        self._producer.xtrim(self._config.dead_letter_key, maxlen=0, approximate=False)
        self._started = True
        return self.status()

    def _require_started(self) -> None:
        if not self._started:
            raise AdapterNotStarted("adapter.start() must complete before use")

    # -- producer --
    def enqueue(self, message: dict) -> str:
        self._require_started()
        raw = message.get("payload", "")
        if len(raw.encode("utf-8")) > self._bounds.max_payload_bytes:
            raise MessageValidationError("payload exceeds the maximum size")
        for key in _REQUIRED_META:
            if not message.get(key):
                raise MessageValidationError(f"cannot enqueue without {key}")
        mid = self._producer.xadd(self._config.stream_key, message)
        with self._lock:
            self.stats["enqueued"] += 1
        return mid

    # -- consumer / worker --
    def _classify(self, exc: BaseException) -> str:
        if isinstance(exc, (MessageValidationError, NonRetryable)):
            return "non_retryable"
        text = str(exc).lower()
        transient = ("connection", "timeout", "temporarily", "loading", "readonly",
                     "try again", "pool")
        return "transient" if any(t in text for t in transient) else "non_retryable"

    def drain_once(self, handler: Callable[[dict], None], *, consumer_name: str,
                   redis_conn: Any) -> dict:
        """Claim up to a bounded batch (new + reclaimed-past-lease), process each through
        ``handler`` (which must persist durably before returning), then ACK. On a transient
        failure below the retry budget the message stays pending (redelivered after the
        lease); on exhaustion or a non-retryable class it is dead-lettered and ACKed."""
        self._require_started()
        outcome = {"processed": 0, "acked": 0, "retried": 0, "dead_lettered": 0, "rejected": 0}
        # 1. reclaim entries whose lease expired (visibility timeout) — bounded batch
        try:
            _cursor, reclaimed, _ = redis_conn.xautoclaim(
                self._config.stream_key, self._config.group, consumer_name,
                min_idle_time=self._bounds.lease_ms, count=self._bounds.receive_batch_size)
        except Exception:
            reclaimed = []
        # 2. new entries
        resp = redis_conn.xreadgroup(self._config.group, consumer_name,
                                     {self._config.stream_key: ">"},
                                     count=self._bounds.receive_batch_size,
                                     block=self._bounds.receive_block_ms)
        new_entries = resp[0][1] if resp else []
        entries = list(reclaimed) + list(new_entries)
        for mid, fields in entries:
            self._process_one(handler, redis_conn, consumer_name, mid, fields, outcome)
        return outcome

    def _process_one(self, handler, redis_conn, consumer_name, mid, fields, outcome) -> None:
        with self._lock:
            self.stats["delivered"] += 1
            self.stats["in_flight"] += 1
        try:
            attempt = int(fields.get("attempt", "1"))
            try:
                msg = validate_message(fields, max_payload_bytes=self._bounds.max_payload_bytes)
            except MessageValidationError as exc:
                with self._lock:
                    self.stats["validation_rejected"] += 1
                self._dead_letter(redis_conn, mid, fields, "validation", exc, outcome)
                return
            try:
                handler(msg)     # MUST persist business+audit+idempotency durably before returning
                redis_conn.xack(self._config.stream_key, self._config.group, mid)
                redis_conn.xdel(self._config.stream_key, mid)
                with self._lock:
                    self.stats["acked"] += 1
                outcome["processed"] += 1
                outcome["acked"] += 1
            except BaseException as exc:  # noqa: BLE001
                klass = self._classify(exc)
                if klass == "transient" and attempt < self._bounds.max_retries:
                    # bounded retry: re-enqueue with an incremented attempt + backoff marker;
                    # ack the old delivery so the pending entry does not also redeliver.
                    with self._lock:
                        self.stats["retries"] += 1
                    self._requeue_with_backoff(redis_conn, fields, attempt)
                    redis_conn.xack(self._config.stream_key, self._config.group, mid)
                    redis_conn.xdel(self._config.stream_key, mid)
                    outcome["retried"] += 1
                else:
                    self._dead_letter(redis_conn, mid, fields, klass, exc, outcome)
        finally:
            with self._lock:
                self.stats["in_flight"] -= 1

    def _requeue_with_backoff(self, redis_conn, fields, attempt) -> None:
        backoff = min(self._bounds.backoff_base_ms * (2 ** (attempt - 1)), 5000) / 1000.0
        time.sleep(backoff)
        redis_conn.xadd(self._config.stream_key, {**fields, "attempt": str(attempt + 1)})

    def _dead_letter(self, redis_conn, mid, fields, klass, exc, outcome) -> None:
        # Isolate the poison/exhausted message with a REDACTED classification; retain tenant
        # namespace but not payload bodies with client data (payload is kept opaque).
        record = {"tenant_slug": fields.get("tenant_slug", ""),
                  "operation": fields.get("operation", ""),
                  "idempotency_key": fields.get("idempotency_key", ""),
                  "correlation_id": fields.get("correlation_id", ""),
                  "failure_class": klass, "reason": redact(str(exc)),
                  "attempts": fields.get("attempt", "1")}
        redis_conn.xadd(self._config.dead_letter_key, record)
        redis_conn.xack(self._config.stream_key, self._config.group, mid)
        redis_conn.xdel(self._config.stream_key, mid)
        with self._lock:
            self.stats["dead_lettered"] += 1
        outcome["dead_lettered"] += 1

    def dead_letter_depth(self) -> int:
        self._require_started()
        return int(self._producer.xlen(self._config.dead_letter_key))

    def replay_dead_letter(self, dlq_id: str, *, authorized: bool) -> str:
        """Authorized, idempotent replay: re-enqueue the ORIGINAL idempotency identity so the
        business effect stays exactly-once. Refuses without explicit authorization."""
        self._require_started()
        if not authorized:
            raise NonRetryable("dead-letter replay requires explicit operator authorization")
        rows = self._producer.xrange(self._config.dead_letter_key, min=dlq_id, max=dlq_id)
        if not rows:
            raise NonRetryable("dead-letter entry not found")
        _id, rec = rows[0]
        msg = build_message(tenant_slug=rec["tenant_slug"], operation=rec["operation"],
                            idempotency_key=rec["idempotency_key"],
                            correlation_id=rec.get("correlation_id", ""), payload={},
                            enqueued_at=time.time())
        mid = self.enqueue(msg)
        self._producer.xdel(self._config.dead_letter_key, dlq_id)
        with self._lock:
            self.stats["replays"] += 1
        return mid

    # -- shutdown --
    def shutdown(self) -> dict:
        deadline = time.monotonic() + self._bounds.shutdown_drain_seconds
        # stop accepting: bounded wait for in-flight to finish; never ack unfinished work.
        drained = True
        while True:
            with self._lock:
                inflight = self.stats["in_flight"]
            if inflight == 0:
                break
            if time.monotonic() >= deadline:
                drained = False
                break
            time.sleep(0.02)
        closed = 0
        for conn in [self._producer, *self._consumers]:
            try:
                conn.close(); closed += 1
            except Exception:
                pass
        self._started = False
        return {"drained_cleanly": drained, "connections_closed": closed}

    # -- redacted observability --
    def status(self) -> dict:
        try:
            depth = int(self._producer.xlen(self._config.stream_key)) if self._producer else None
        except Exception:
            depth = None
        return {
            "adapter": "production_profile_redis_streams",
            "started": self._started,
            "delivery_model": DELIVERY_MODEL,
            "transport": {"tls_required": self._config.require_tls},
            "bounds": {"worker_concurrency": self._bounds.worker_concurrency,
                       "receive_batch_size": self._bounds.receive_batch_size,
                       "max_retries": self._bounds.max_retries,
                       "lease_ms": self._bounds.lease_ms,
                       "max_payload_bytes": self._bounds.max_payload_bytes},
            "queue_depth_class": ("empty" if depth == 0 else "nonempty" if depth else "unknown"),
            "producers": 1, "consumers": len(self._consumers),
            "stats": dict(self.stats),
        }
