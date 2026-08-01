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
        # Runtime concurrency ceiling: a BoundedSemaphore sized to worker_concurrency gates
        # EVERY handler invocation (normal delivery, transient retry re-run, lease reclaim,
        # dead-letter routing, authorized replay), so the number of handlers running at once
        # can never exceed the configured bound regardless of how many worker threads,
        # reclaimed entries, or batch items exist. _active/_max_active track the live and
        # peak concurrency for redacted observability.
        self._handler_slots = threading.BoundedSemaphore(config.bounds.worker_concurrency)
        self._active = 0
        self._max_active = 0
        self.stats = {"enqueued": 0, "delivered": 0, "acked": 0, "retries": 0,
                      "dead_lettered": 0, "duplicates_suppressed": 0, "replays": 0,
                      "unauthorized_replays_refused": 0, "validation_rejected": 0, "in_flight": 0}

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
                self._run_handler(handler, msg)  # slot-gated; persists durably before returning
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

    def _run_handler(self, handler, msg) -> None:
        """Invoke the business handler under the bounded concurrency slot. Acquiring the
        BoundedSemaphore here is what enforces active_handlers <= worker_concurrency across
        every worker thread and every path that runs a handler (delivery, retry re-run,
        reclaim, replay)."""
        self._handler_slots.acquire()
        try:
            with self._lock:
                self._active += 1
                if self._active > self._max_active:
                    self._max_active = self._active
            handler(msg)
        finally:
            with self._lock:
                self._active -= 1
            self._handler_slots.release()

    def _requeue_with_backoff(self, redis_conn, fields, attempt) -> None:
        backoff = min(self._bounds.backoff_base_ms * (2 ** (attempt - 1)), 5000) / 1000.0
        time.sleep(backoff)
        redis_conn.xadd(self._config.stream_key, {**fields, "attempt": str(attempt + 1)})

    def _dead_letter(self, redis_conn, mid, fields, klass, exc, outcome) -> None:
        """Isolate a poison/exhausted message as a DURABLE, replay-capable envelope. It
        retains the full validated replay envelope — schema version, original message id,
        tenant-bound context, operation, idempotency key, correlation, ORIGINAL VALIDATED
        payload, enqueue timestamp, attempt count — plus a REDACTED failure classification
        and the dead-letter timestamp. It never stores credentials/endpoints/traces/container
        or process ids, and a payload that FAILED validation (oversized/malformed) is NOT
        retained raw — it is recorded as `payload_rejected` so an unbounded/unsafe body never
        lands in the DLQ."""
        payload_valid = klass != "validation"
        try:
            raw = fields.get("payload", "")
            payload_ok = payload_valid and len(raw.encode("utf-8")) <= self._bounds.max_payload_bytes
            if payload_ok:
                json.loads(raw)  # safe JSON only; unknown fields are the caller's payload shape
        except Exception:
            payload_ok = False
        record = {
            "schema_version": fields.get("schema_version", MESSAGE_SCHEMA_VERSION),
            "original_message_id": mid,
            "tenant_slug": fields.get("tenant_slug", ""),
            "operation": fields.get("operation", ""),
            "idempotency_key": fields.get("idempotency_key", ""),
            "correlation_id": fields.get("correlation_id", ""),
            "trace_id": fields.get("trace_id", ""),
            "payload": fields.get("payload", "") if payload_ok else "",
            "payload_status": "retained" if payload_ok else "payload_rejected",
            "enqueued_at": fields.get("enqueued_at", ""),
            "attempts": fields.get("attempt", "1"),
            "failure_class": klass,
            "reason": redact(str(exc)),
            "dead_letter_at": f"{time.time():.6f}",
            "replayed": "0",
        }
        redis_conn.xadd(self._config.dead_letter_key, record)
        redis_conn.xack(self._config.stream_key, self._config.group, mid)
        redis_conn.xdel(self._config.stream_key, mid)
        with self._lock:
            self.stats["dead_lettered"] += 1
        outcome["dead_lettered"] += 1

    def dead_letter_depth(self) -> int:
        self._require_started()
        return int(self._producer.xlen(self._config.dead_letter_key))

    def read_dead_letter(self, dlq_id: str) -> dict | None:
        """Return the durable DLQ envelope (redacted — never printed by the adapter)."""
        self._require_started()
        rows = self._producer.xrange(self._config.dead_letter_key, min=dlq_id, max=dlq_id)
        return rows[0][1] if rows else None

    def replay_dead_letter(self, dlq_id: str, *, authorized: bool,
                           authorization_class: str = "operator") -> str:
        """FAITHFUL authorized replay: read the durable DLQ envelope and re-enqueue the
        ORIGINAL validated message (same tenant, operation, idempotency key, schema version,
        correlation id, and PAYLOAD), appending replay metadata WITHOUT changing the original
        idempotency identity. Unauthorized replay fails closed and leaves the DLQ record
        intact. On success the DLQ entry is moved to an append-only replay-audit stream so it
        stays auditable while the payload leaves the active DLQ."""
        self._require_started()
        if not authorized:
            with self._lock:
                self.stats["unauthorized_replays_refused"] += 1
            raise NonRetryable("dead-letter replay requires explicit operator authorization")
        rec = self.read_dead_letter(dlq_id)
        if rec is None:
            raise NonRetryable("dead-letter entry not found")
        if rec.get("payload_status") != "retained":
            raise NonRetryable("dead-letter record has no retained payload to replay faithfully")
        try:
            payload = json.loads(rec.get("payload", "") or "{}")
        except Exception:
            raise NonRetryable("dead-letter payload failed re-validation")
        # Rebuild the ORIGINAL envelope; build_message re-validates tenant/op/idem.
        message = build_message(tenant_slug=rec["tenant_slug"], operation=rec["operation"],
                                idempotency_key=rec["idempotency_key"],
                                correlation_id=rec.get("correlation_id", ""), payload=payload,
                                enqueued_at=time.time())
        # size/schema re-checked at enqueue too.
        rid = f"replay-{int(time.time()*1e6)}"
        message["replay_request_id"] = rid
        message["authorized_replay_at"] = f"{time.time():.6f}"
        message["operator_authorization_class"] = authorization_class
        message["replay_attempt"] = str(int(rec.get("replay_attempt", "0")) + 1)
        mid = self.enqueue(message)
        # move to the replay-audit stream (auditable), then remove from the active DLQ.
        audit_key = f"{self._config.dead_letter_key}:replayed"
        self._producer.xadd(audit_key, {**{k: rec.get(k, "") for k in
                            ("schema_version", "tenant_slug", "operation", "idempotency_key",
                             "correlation_id", "failure_class", "attempts")},
                            "replay_request_id": rid, "authorization_class": authorization_class,
                            "replayed_at": message["authorized_replay_at"]})
        self._producer.xdel(self._config.dead_letter_key, dlq_id)
        with self._lock:
            self.stats["replays"] += 1
        return mid

    def run_worker_pool(self, handler, *, stop_event, consumer_prefix: str = "w") -> dict:
        """Spawn EXACTLY worker_concurrency worker threads, each looping drain_once until
        stop_event is set. Combined with the per-handler slot semaphore, the number of
        business handlers running concurrently never exceeds worker_concurrency."""
        self._require_started()
        n = self._bounds.worker_concurrency
        results = {"threads": n}
        errors: list[str] = []

        def loop(idx: int) -> None:
            conn = self._consumers[idx % len(self._consumers)]
            while not stop_event.is_set():
                try:
                    oc = self.drain_once(handler, consumer_name=f"{consumer_prefix}{idx}", redis_conn=conn)
                    if oc["processed"] == 0 and oc["dead_lettered"] == 0 and oc["retried"] == 0:
                        time.sleep(0.02)
                except Exception as exc:  # noqa: BLE001
                    errors.append(redact(str(exc)))
                    time.sleep(0.05)
        threads = [threading.Thread(target=loop, args=(k,), daemon=True) for k in range(n)]
        for t in threads:
            t.start()
        results["_threads"] = threads
        results["_errors"] = errors
        return results

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
            "concurrency": {"configured": self._bounds.worker_concurrency,
                            "active": self._active, "max_observed": self._max_active,
                            "within_bound": self._max_active <= self._bounds.worker_concurrency},
            "stats": dict(self.stats),
        }
