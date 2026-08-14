---
name: monday-report-queue
description: >-
  Worker/queue adapter, retry/DLQ semantics, and the production-queue adapter for
  Monday Report. INVOKE for queue/worker processing, delivery-semantics, retry or
  dead-letter work, or production-queue adapter/evidence questions. Triggers:
  "queue", "worker", "retry/backoff", "dead letter", "at-least-once vs
  exactly-once", "why is production queue NOT_ACCEPTED", "disposable Redis".
---

# Monday Report — queue & worker

Two queue backends: `inline_worker` (demo) vs `redis` (client mode). Reported by
`runtime_backends.py` (`detect_active_queue_backend()`). Worker entry:
`python -m backend.app.worker` (`pnpm run worker:once`, minimal run-once).

## Two distinct things — do not conflate
1. **Runtime queue** (`queue_backend.py`): a best-effort **index over
   authoritative store state** — non-atomic `SADD`+`RPUSH` enqueue, `LPOP`+`SREM`
   dequeue, **no lease, no ack, no retry, no DLQ**. Honest delivery is
   **at-most-once** with a *permanent* loss window (the dedupe-set entry blocks
   re-derivation). Exactly-once business/audit effect comes from the DB-durable,
   tenant-scoped idempotency in the store, not the queue. See
   [[monday-report-backend-api]].
2. **Production-queue behavioral adapter** (`production_queue_adapter.py`): the
   aspirational Redis Streams profile — **at-least-once**, consumer groups +
   `XCLAIM` claim/lease, **ack only after the business mutation + audit commit
   durably**, durable tenant-scoped idempotency (duplicate = no-op), **bounded
   classified retry with exponential backoff**, explicit **dead-letter stream**
   after retry exhaustion + authorized idempotent **replay**; `NonRetryable`
   (auth/tenant-mismatch/poison) routes straight to DLQ.

## Verification
- Behavioral/profile guards (disposable evidence): `audit:production-queue-profile`,
  `audit:production-queue-profile-evidence`, `audit:production-queue-adapter-evidence`,
  `audit:production-queue-secret-scan`. Regenerate profile evidence with
  `pnpm run ga:production-queue-profile-evidence`.
- Disposable Redis for local runs comes from `docker-compose.client.yml`. Prove
  effects (delivered-once, no cross-tenant, no loss/dup under stress), not method
  presence. See [[monday-report-testing]].

## Production-queue adapter — stays NOT_ACCEPTED
- `production_queue_adapter_evidence.py` requires a real **production target** and
  a **declared delivery model** whose loss window and idempotency compatibility
  are observed; **`exactly-once` is rejected**. Domains include
  `retry_and_backoff_policy` (needs an **executed delivery-retry drill**),
  `dead_letter_behavior` (needs an **executed poison-message drill**), plus
  failover/recovery/duplicate-delivery drills; the retry limit must be a positive
  int ≤ the max (unbounded budget rejected); the dead-letter disposition must be
  substantive.
- **Rejected**: loopback / docker-bridge / unknown endpoints; `staging`/`test`/
  `development` environments; eviction that can discard a queued job. A disposable
  Docker Redis, a liveness PING, an in-memory queue, the restricted worker matrix,
  and production DATABASE evidence are each explicitly **non-qualifying**.
- Result: `ga_redis_adapter` remains BLOCKED and
  `PRODUCTION_QUEUE_ADAPTER_NOT_ACCEPTED` stands. Also blocked and separate:
  `ga_worker_heartbeat` (the run-once worker has no heartbeat/retry/DLQ). See
  [[monday-report-release-ga]].

## Non-goals / safety
- **Never fabricate a production queue target, drill, or evidence** to flip
  acceptance. Contract/behavioral acceptance ≠ production adapter acceptance.
- Do not claim exactly-once *delivery*; the guarantee is at-least-once delivery +
  DB-durable idempotency = exactly-once *effect*.
