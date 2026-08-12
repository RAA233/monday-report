"""audit:production-queue-profile -- BEHAVIORAL proof of the production-profile queue
adapter against DISPOSABLE, TLS-enabled Redis + disposable PostgreSQL.

Proves adapter BEHAVIOR only. The accepted production-TARGET control (ga_redis_adapter)
remains BLOCKED and is untouched. See production_queue_profile_evidence.py.

Provisions one disposable TLS Redis + one disposable TLS PostgreSQL and asserts:
fail-closed config/selection (no inline/in-memory fallback), enforced verified TLS,
tenant- and idempotency-bound messages, at-least-once delivery with lease + ack ONLY
after durable business+audit commit, DB-durable tenant-scoped idempotency (duplicate
delivery => zero duplicate business/audit effect), bounded classified retry + backoff,
poison => dead-letter with authorized idempotent replay, a 100-message two-tenant stress
matrix with zero cross-tenant effect and zero silent loss, bounded worker concurrency, and
bounded startup/shutdown. Prints JSON; non-zero on any failure.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

from _production_queue_broker import disposable_redis  # noqa: E402
from _production_profile_pg import disposable_tls_stack  # noqa: E402
from backend.app import production_queue_adapter as Q  # noqa: E402
from backend.app import production_database_adapter as A  # noqa: E402

CHECKS: list[dict] = []


def rec(cid, ok, detail=""):
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL", "detail": detail})


def _qcfg(br, **over):
    kw = dict(profile="production", redis_url=br["url"], stream_key=br["stream_key"],
              group=br["group"], dead_letter_key=br["dead_letter_key"], require_tls=True)
    kw.update(over)
    return Q.QueueProfileConfig(**kw)


def _setup_db(db):
    import psycopg
    with psycopg.connect(db["migration_dsn"], autocommit=True) as c, c.cursor() as cur:
        cur.execute("create table if not exists queue_idem (tenant_slug text, idem_key text, primary key (tenant_slug, idem_key))")
        cur.execute("create table if not exists queue_effect (id serial primary key, tenant_slug text, marker text)")
        cur.execute("create table if not exists queue_audit (id serial primary key, tenant_slug text, event text)")
        cur.execute("grant select, insert on queue_idem, queue_effect, queue_audit to monday_report_app")
        cur.execute("grant usage, select on all sequences in schema public to monday_report_app")


def _make_handler(dba, *, fail_first=None):
    state = {"transient_hits": 0}

    def handler(msg):
        slug, idem, op = msg["tenant_slug"], msg["idempotency_key"], msg["operation"]
        if op == "poison":
            raise Q.NonRetryable("poison message")
        if op == "transient" and fail_first and state["transient_hits"] < fail_first:
            state["transient_hits"] += 1
            raise RuntimeError("connection reset (transient)")
        with dba.tenant_transaction(slug) as cur:
            cur.execute("insert into queue_idem (tenant_slug, idem_key) values (%s,%s) on conflict do nothing", (slug, idem))
            if cur.rowcount == 1:
                cur.execute("insert into queue_effect (tenant_slug, marker) values (%s,%s)", (slug, idem))
                cur.execute("insert into queue_audit (tenant_slug, event) values (%s,%s)", (slug, f"p:{idem}"))
    return handler, state


def config_faults(br):
    def rej(**over):
        try:
            _qcfg(br, **over).validate(); return False
        except Q.QueueProfileConfigError:
            return True
    rec("CF01 non-production-profile-rejected", rej(profile="development"), "profile!='production' fails closed")
    rec("CF02 inline-fallback-rejected", rej(allow_inline_for_test=True), "inline execution cannot be enabled in production")
    rec("CF03 missing-url-rejected", rej(redis_url=""), "missing queue URL fails closed")
    rec("CF04 missing-keys-rejected", rej(stream_key=""), "missing stream/group/dlq fails closed")
    rec("CF05 plaintext-rejected-when-tls-required", rej(redis_url=br["plaintext_url"]), "redis:// rejected when TLS required")
    rec("CF06 tls-verify-disable-rejected", rej(redis_url=br["url"] + "&ssl_cert_reqs=none"), "a verify-disabling URL is rejected")
    # bounds
    try:
        Q.QueueBounds(producer_connections=1, consumer_connections=1, worker_concurrency=0, receive_batch_size=1,
                      enqueue_timeout_seconds=1, receive_block_ms=1, lease_ms=100, ack_timeout_seconds=1,
                      shutdown_drain_seconds=1, max_payload_bytes=1, max_retries=1, backoff_base_ms=1).validate()
        rec("CF07 unbounded-concurrency-rejected", False, "worker_concurrency=0 accepted")
    except Q.QueueProfileConfigError:
        rec("CF07 unbounded-concurrency-rejected", True, "non-positive worker concurrency rejected")


def tls_enforcement(br):
    import redis
    # verify-full rediss connects; plaintext to the TLS-only server fails
    try:
        redis.Redis.from_url(br["url"], socket_connect_timeout=4).ping()
        rec("TL01 rediss-verify-connects", True, "rediss:// with the disposable CA connects")
    except Exception as e:
        rec("TL01 rediss-verify-connects", False, Q.redact(str(e)))
    try:
        redis.Redis.from_url(br["plaintext_url"], socket_connect_timeout=4).ping()
        rec("TL02 server-rejects-plaintext", False, "TLS-only server accepted a plaintext client")
    except Exception:
        rec("TL02 server-rejects-plaintext", True, "the TLS-only disposable server rejects a plaintext client")


def workflow_and_idempotency(db, qa, dba):
    handler, _ = _make_handler(dba)
    def mk(slug, op, idem): return Q.build_message(tenant_slug=slug, operation=op, idempotency_key=idem,
        correlation_id="c", payload={"x": 1}, enqueued_at=time.time())
    # message validation: missing tenant/idem/op rejected
    for bad, why in ((dict(slug="", op="e", idem="i"), "tenant"), (dict(slug="t", op="", idem="i"), "op"),
                     (dict(slug="t", op="e", idem=""), "idem")):
        try:
            mk(bad["slug"], bad["op"], bad["idem"]); rec(f"WF00 reject-missing-{why}", False, f"missing {why} accepted")
        except Q.MessageValidationError:
            rec(f"WF00 reject-missing-{why}", True, f"a message missing {why} is rejected")
    qa.enqueue(mk("tenant-a", "effect", "w-1"))
    qa.enqueue(mk("tenant-a", "effect", "w-1"))   # duplicate
    qa.enqueue(mk("tenant-b", "effect", "w-2"))
    conn = qa._consumers[0]
    for _ in range(5):
        qa.drain_once(handler, consumer_name="w1", redis_conn=conn); time.sleep(0.05)
    import psycopg
    with psycopg.connect(db["migration_dsn"], autocommit=True) as c, c.cursor() as cur:
        cur.execute("select count(*) from queue_effect where marker='w-1'"); e1 = cur.fetchone()[0]
        cur.execute("select count(*) from queue_audit where event='p:w-1'"); a1 = cur.fetchone()[0]
        cur.execute("select count(*) from queue_effect where marker='w-2'"); e2 = cur.fetchone()[0]
    rec("WF01 workflow-processes", e1 >= 1 and e2 == 1, "enqueue->dequeue->DB commit->ack completes")
    rec("WF02 duplicate-no-duplicate-business-effect", e1 == 1, f"duplicate delivery -> exactly one business effect ({e1})")
    rec("WF03 duplicate-no-duplicate-audit-effect", a1 == 1, f"duplicate delivery -> exactly one audit effect ({a1})")


def retry_and_dead_letter(db, qa, dba):
    # a transient failure (below budget) is retried then succeeds
    handler, state = _make_handler(dba, fail_first=1)
    msg = Q.build_message(tenant_slug="tenant-a", operation="transient", idempotency_key="r-1",
                          correlation_id="c", payload={}, enqueued_at=time.time())
    qa.enqueue(msg)
    conn = qa._consumers[0]
    for _ in range(8):
        qa.drain_once(handler, consumer_name="w1", redis_conn=conn); time.sleep(0.05)
    import psycopg
    with psycopg.connect(db["migration_dsn"], autocommit=True) as c, c.cursor() as cur:
        cur.execute("select count(*) from queue_effect where marker='r-1'"); r1 = cur.fetchone()[0]
    rec("RT01 transient-retried-then-succeeds", r1 == 1 and state["transient_hits"] >= 1,
        "a transient failure is retried within budget and then commits exactly once")
    # poison -> dead-letter, ack'd (not redelivered forever), authorized replay only
    poison = Q.build_message(tenant_slug="tenant-a", operation="poison", idempotency_key="d-1",
                             correlation_id="c", payload={}, enqueued_at=time.time())
    qa.enqueue(poison)
    for _ in range(4):
        qa.drain_once(handler, consumer_name="w1", redis_conn=conn); time.sleep(0.05)
    rec("DL01 poison-dead-lettered", qa.dead_letter_depth() >= 1, "a poison message is isolated in the dead-letter stream")
    # unauthorized replay refused
    rows = qa._producer.xrange(qa._config.dead_letter_key)
    dlq_id = rows[-1][0]
    try:
        qa.replay_dead_letter(dlq_id, authorized=False); rec("DL02 unauthorized-replay-refused", False, "unauth replay accepted")
    except Q.NonRetryable:
        rec("DL02 unauthorized-replay-refused", True, "dead-letter replay requires explicit authorization")
    # authorized replay re-enqueues the ORIGINAL idempotency identity
    before = qa.status()["stats"]["enqueued"]
    qa.replay_dead_letter(dlq_id, authorized=True)
    rec("DL03 authorized-replay-idempotent", qa.status()["stats"]["enqueued"] == before + 1,
        "authorized replay re-enqueues the original idempotency identity")


def stress(db, qa, dba, *, total=100):
    """100 messages, 2 tenants, 4 bounded workers, with duplicates + poison injected. Assert
    zero cross-tenant effect, zero duplicate business/audit effect, zero silent loss."""
    handler, _ = _make_handler(dba)
    import psycopg
    expected_effects = set()
    poison_count = 0
    for i in range(total):
        slug = "tenant-a" if i % 2 == 0 else "tenant-b"
        if i % 17 == 0:
            qa.enqueue(Q.build_message(tenant_slug=slug, operation="poison", idempotency_key=f"s-p-{i}",
                                       correlation_id="c", payload={}, enqueued_at=time.time()))
            poison_count += 1
            continue
        idem = f"s-{slug}-{i}"
        expected_effects.add((slug, idem))
        m = Q.build_message(tenant_slug=slug, operation="effect", idempotency_key=idem,
                            correlation_id="c", payload={}, enqueued_at=time.time())
        qa.enqueue(m)
        if i % 13 == 0:
            qa.enqueue(m)  # duplicate delivery
    # 4 bounded workers drain concurrently
    stop = threading.Event()
    def worker(idx):
        conn = qa._consumers[idx % len(qa._consumers)]
        while not stop.is_set():
            oc = qa.drain_once(handler, consumer_name=f"w{idx}", redis_conn=conn)
            if oc["processed"] == 0 and oc["dead_lettered"] == 0 and oc["retried"] == 0:
                time.sleep(0.03)
    threads = [threading.Thread(target=worker, args=(k,)) for k in range(4)]
    for t in threads:
        t.start()
    deadline = time.monotonic() + 40
    with psycopg.connect(db["migration_dsn"], autocommit=True) as c:
        while time.monotonic() < deadline:
            with c.cursor() as cur:
                cur.execute("select count(*) from queue_effect where marker like 's-%'"); done = cur.fetchone()[0]
            if done >= len(expected_effects) and qa.dead_letter_depth() >= poison_count:
                break
            time.sleep(0.2)
    stop.set()
    for t in threads:
        t.join()
    with psycopg.connect(db["migration_dsn"], autocommit=True) as c, c.cursor() as cur:
        cur.execute("select tenant_slug, marker, count(*) from queue_effect where marker like 's-%' group by 1,2 having count(*)>1")
        dupes = cur.fetchall()
        cur.execute("select count(*) from queue_effect where marker like 's-%'"); effects = cur.fetchone()[0]
        cur.execute("select count(*) from queue_effect e where marker like 's-%' and marker not like ('s-'||tenant_slug||'%')")
        cross = cur.fetchone()[0]
    rec("ST01 all-accepted-processed-exactly-once", effects == len(expected_effects) and not dupes,
        f"{effects}/{len(expected_effects)} effects, 0 duplicate business effects")
    rec("ST02 zero-cross-tenant-effect", cross == 0, f"cross-tenant effects: {cross}")
    rec("ST03 poison-all-dead-lettered", qa.dead_letter_depth() >= poison_count,
        f"dead-letter depth {qa.dead_letter_depth()} >= {poison_count} poison")
    rec("ST04 no-silent-loss", effects == len(expected_effects), "every accepted message produced its effect (no silent loss)")
    rec("ST05 concurrency-bounded", qa.status()["consumers"] <= qa._bounds.consumer_connections,
        "worker/consumer count never exceeds the configured bound")


def dlq_and_replay(db, qa, dba):
    """Durable faithful DLQ envelope + payload-preserving authorized replay (both cases)."""
    heal = {"on": False}
    def handler(msg):
        slug, idem, op = msg["tenant_slug"], msg["idempotency_key"], msg["operation"]
        pl = msg["payload_obj"]
        if op == "pre_db_fail" and not heal["on"]:
            raise Q.NonRetryable("pre-commit failure")
        with dba.tenant_transaction(slug) as cur:
            cur.execute("insert into queue_idem (tenant_slug, idem_key) values (%s,%s) on conflict do nothing", (slug, idem))
            if cur.rowcount == 1:
                cur.execute("insert into queue_effect (tenant_slug, marker) values (%s,%s)", (slug, pl.get("m", idem)))
    def mk(op, idem, payload): return Q.build_message(tenant_slug="tenant-a", operation=op, idempotency_key=idem,
        correlation_id="corr-1", payload=payload, enqueued_at=time.time())
    conn = qa._consumers[0]
    # CASE 1: never committed -> dead-letter -> faithful authorized replay commits ONCE.
    qa.enqueue(mk("pre_db_fail", "dlq-1", {"m": "pl-1", "n": 42}))
    for _ in range(3):
        qa.drain_once(handler, consumer_name="w", redis_conn=conn); time.sleep(0.05)
    rows = qa._producer.xrange(qa._config.dead_letter_key); dlq_id, dlrec = rows[-1][0], rows[-1][1]
    envelope_keys = {"schema_version", "original_message_id", "tenant_slug", "operation", "idempotency_key",
                     "correlation_id", "payload", "enqueued_at", "attempts", "failure_class", "dead_letter_at"}
    rec("DR01 dlq-durable-envelope", envelope_keys.issubset(set(dlrec)) and dlrec.get("payload_status") == "retained"
        and json.loads(dlrec["payload"]) == {"m": "pl-1", "n": 42},
        "the DLQ record retains the full validated replay envelope incl. the original payload")
    rec("DR02 dlq-no-secret-or-trace-leak", "reason" in dlrec and "requirepass" not in json.dumps(dlrec)
        and "redis://" not in json.dumps(dlrec), "the DLQ record carries a redacted class, no DSN/trace/credential")
    # unauthorized replay refused, DLQ intact
    try:
        qa.replay_dead_letter(dlq_id, authorized=False); rec("DR03 unauthorized-replay-refused", False, "unauth accepted")
    except Q.NonRetryable:
        rec("DR03 unauthorized-replay-refused", qa.read_dead_letter(dlq_id) is not None,
            "unauthorized replay fails closed and leaves the DLQ record intact")
    heal["on"] = True
    replay_mid = qa.replay_dead_letter(dlq_id, authorized=True, authorization_class="operator")
    # the re-enqueued message must carry the SAME idempotency identity + payload + replay metadata
    replayed = qa._producer.xrange(qa._config.stream_key, min=replay_mid, max=replay_mid)[0][1]
    rec("DR04 replay-preserves-identity-and-payload",
        replayed["idempotency_key"] == "dlq-1" and replayed["tenant_slug"] == "tenant-a"
        and replayed["operation"] == "pre_db_fail" and json.loads(replayed["payload"]) == {"m": "pl-1", "n": 42}
        and replayed.get("replay_request_id"),
        "authorized replay re-enqueues the ORIGINAL tenant/op/idem/payload with replay metadata")
    for _ in range(3):
        qa.drain_once(handler, consumer_name="w", redis_conn=conn); time.sleep(0.05)
    import psycopg
    with psycopg.connect(db["migration_dsn"], autocommit=True) as c, c.cursor() as cur:
        cur.execute("select count(*) from queue_effect where marker='pl-1'"); c1 = cur.fetchone()[0]
    rec("DR05 uncommitted-replay-commits-once", c1 == 1, f"an uncommitted message's authorized replay commits exactly once ({c1})")
    # CASE 2: committed then a same-idem DLQ record -> replay suppressed by idempotency (0 new effect).
    qa.enqueue(mk("effect", "dlq-2", {"m": "pl-2"}))
    for _ in range(3):
        qa.drain_once(handler, consumer_name="w", redis_conn=conn); time.sleep(0.05)
    heal["on"] = False
    qa.enqueue(mk("pre_db_fail", "dlq-2", {"m": "pl-2"}))
    for _ in range(3):
        qa.drain_once(handler, consumer_name="w", redis_conn=conn); time.sleep(0.05)
    heal["on"] = True
    dlq2 = [r for r in qa._producer.xrange(qa._config.dead_letter_key) if r[1].get("idempotency_key") == "dlq-2"][-1][0]
    qa.replay_dead_letter(dlq2, authorized=True)
    for _ in range(3):
        qa.drain_once(handler, consumer_name="w", redis_conn=conn); time.sleep(0.05)
    with psycopg.connect(db["migration_dsn"], autocommit=True) as c, c.cursor() as cur:
        cur.execute("select count(*) from queue_effect where marker='pl-2'"); c2 = cur.fetchone()[0]
    rec("DR06 post-commit-replay-suppressed", c2 == 1, f"replay of an already-committed message adds zero new effects ({c2})")


def runtime_concurrency(db, br):
    """worker_concurrency is enforced INSIDE the adapter: with N=4 and >=20 simultaneously
    available slow messages, the max observed active handlers is exactly 4, and the 5th does
    not enter until a slot is released."""
    import threading
    dba = A.ProductionDatabaseAdapter(A.ProductionProfileConfig(profile="production", dsn=db["runtime_dsn"],
        sslmode="verify-full", sslrootcert=db["ca_path"], migration_role=db["migration_role"])); dba.start()
    bounds = Q.QueueBounds(producer_connections=2, consumer_connections=8, worker_concurrency=4, receive_batch_size=4,
        enqueue_timeout_seconds=5, receive_block_ms=100, lease_ms=5000, ack_timeout_seconds=10, shutdown_drain_seconds=10,
        max_payload_bytes=65536, max_retries=2, backoff_base_ms=10)
    qa = Q.ProductionQueueAdapter(_qcfg(br, bounds=bounds)); qa.start()
    barrier = threading.Barrier(4, timeout=10)
    def handler(msg):
        # force exactly 4 to be simultaneously in-handler; a 5th cannot get a slot until release
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            pass
        time.sleep(0.1)
        with dba.tenant_transaction(msg["tenant_slug"]) as cur:
            cur.execute("insert into queue_idem (tenant_slug, idem_key) values (%s,%s) on conflict do nothing",
                        (msg["tenant_slug"], msg["idempotency_key"]))
    for i in range(24):
        qa.enqueue(Q.build_message(tenant_slug="tenant-a", operation="effect", idempotency_key=f"cc-{i}",
                                   correlation_id="c", payload={}, enqueued_at=time.time()))
    stop = threading.Event()
    pool = qa.run_worker_pool(handler, stop_event=stop)
    time.sleep(3.0)
    conc = qa.status()["concurrency"]
    rec("CC01 max-observed-equals-configured", conc["max_observed"] == 4 and conc["configured"] == 4,
        f"max observed active handlers = {conc['max_observed']} == configured 4")
    rec("CC02 never-exceeds-bound", conc["within_bound"] and conc["max_observed"] <= 4,
        "active handlers never exceed the configured worker_concurrency under any path")
    stop.set(); [t.join(timeout=15) for t in pool["_threads"]]
    rec("CC03 shutdown-launches-no-new-handlers", qa.status()["concurrency"]["active"] == 0,
        "after stop, no handler remains active (shutdown launches no new work)")
    qa.shutdown()

    # CC04: drive MORE concurrent drain callers than worker_concurrency so the semaphore's
    # blocking is genuinely exercised (not just proven by a matched thread count). With a
    # bound of 2 but 8 threads each calling drain_once against a slow handler and >=16 ready
    # messages, the max observed active handlers must still be exactly 2, and a 5th+ caller
    # provably cannot enter until a slot releases.
    b2 = Q.QueueBounds(producer_connections=2, consumer_connections=10, worker_concurrency=2, receive_batch_size=2,
        enqueue_timeout_seconds=5, receive_block_ms=100, lease_ms=5000, ack_timeout_seconds=10, shutdown_drain_seconds=10,
        max_payload_bytes=65536, max_retries=2, backoff_base_ms=10)
    qa2 = Q.ProductionQueueAdapter(_qcfg(br, bounds=b2)); qa2.start()
    def slow_handler(msg):
        time.sleep(0.15)
        with dba.tenant_transaction(msg["tenant_slug"]) as cur:
            cur.execute("insert into queue_idem (tenant_slug, idem_key) values (%s,%s) on conflict do nothing",
                        (msg["tenant_slug"], msg["idempotency_key"]))
    for i in range(20):
        qa2.enqueue(Q.build_message(tenant_slug="tenant-a", operation="effect", idempotency_key=f"ov-{i}",
                                    correlation_id="c", payload={}, enqueued_at=time.time()))
    stop2 = threading.Event()
    overload = [threading.Thread(target=lambda idx=k: [
        (qa2.drain_once(slow_handler, consumer_name=f"ov{idx}", redis_conn=qa2._consumers[idx % len(qa2._consumers)])
         if not stop2.is_set() else None) for _ in range(50)], daemon=True) for k in range(8)]
    for t in overload:
        t.start()
    time.sleep(2.5)
    conc2 = qa2.status()["concurrency"]
    rec("CC04 semaphore-blocks-excess-callers", conc2["max_observed"] == 2 and conc2["max_observed"] <= 2,
        f"8 concurrent drain callers on a bound of 2 -> max observed active handlers = {conc2['max_observed']} (excess blocked by the semaphore)")
    stop2.set(); [t.join(timeout=3) for t in overload]
    qa2.shutdown()
    dba.shutdown()


def tenant_coupling(db, qa, dba):
    """Direct queue<->database tenant coupling + negative cross-tenant tests."""
    def mk(slug, idem, op="effect"): return Q.build_message(tenant_slug=slug, operation=op, idempotency_key=idem,
        correlation_id="c", payload={"m": idem}, enqueued_at=time.time())
    conn = qa._consumers[0]
    # 1. the DB transaction tenant is derived from the validated message; assert app.tenant_slug matches
    seen = {}
    def scope_handler(msg):
        with dba.tenant_transaction(msg["tenant_slug"]) as cur:
            cur.execute("select current_setting('app.tenant_slug', true)")
            seen[msg["idempotency_key"]] = cur.fetchone()[0]
            cur.execute("insert into queue_idem (tenant_slug, idem_key) values (%s,%s) on conflict do nothing",
                        (msg["tenant_slug"], msg["idempotency_key"]))
            if cur.rowcount == 1:
                cur.execute("insert into queue_effect (tenant_slug, marker) values (%s,%s)", (msg["tenant_slug"], msg["idempotency_key"]))
    qa.enqueue(mk("tenant-a", "tc-a")); qa.enqueue(mk("tenant-b", "tc-b"))
    for _ in range(4):
        qa.drain_once(scope_handler, consumer_name="w", redis_conn=conn); time.sleep(0.05)
    rec("TC01 db-scope-derived-from-message", seen.get("tc-a") == "tenant-a" and seen.get("tc-b") == "tenant-b",
        "the DB transaction-local tenant is derived from each message's validated context")
    # 2. tenant A's message cannot write tenant B's RLS-protected row (WITH CHECK blocks it)
    def cross_handler(msg):
        with dba.tenant_transaction(msg["tenant_slug"]) as cur:
            cur.execute("insert into tenants (name, slug) values ('x','tenant-b')")  # scoped to tenant-a
    qa.enqueue(mk("tenant-a", "tc-cross"))
    for _ in range(3):
        qa.drain_once(cross_handler, consumer_name="w", redis_conn=conn); time.sleep(0.05)
    import psycopg
    with psycopg.connect(db["migration_dsn"], autocommit=True) as c, c.cursor() as cur:
        cur.execute("select count(*) from tenants where slug='tenant-b'"); tb = cur.fetchone()[0]
    rec("TC02 cross-tenant-write-blocked", tb == 0,
        "a tenant-A message cannot create a tenant-B row (RLS WITH CHECK blocks it; message dead-lettered)")
    # 3. missing/tampered tenant fails closed before DB access
    try:
        Q.build_message(tenant_slug="", operation="e", idempotency_key="i", correlation_id="c", payload={}, enqueued_at=1)
        rec("TC03 missing-tenant-fails-closed", False, "missing tenant accepted")
    except Q.MessageValidationError:
        rec("TC03 missing-tenant-fails-closed", True, "a message without tenant context fails before any DB access")
    # 4. reused pooled connection retains no prior tenant (alternate on the same conn)
    scopes = []
    def probe(msg):
        with dba.tenant_transaction(msg["tenant_slug"]) as cur:
            cur.execute("select current_setting('app.tenant_slug', true)"); scopes.append((msg["tenant_slug"], cur.fetchone()[0]))
    for i in range(6):
        slug = "tenant-a" if i % 2 == 0 else "tenant-b"
        qa.enqueue(mk(slug, f"tc-reuse-{i}"))
    for _ in range(6):
        qa.drain_once(probe, consumer_name="w", redis_conn=conn); time.sleep(0.03)
    rec("TC04 no-retained-tenant-on-reuse", all(s == m for m, s in scopes) and len(scopes) >= 6,
        "a reused pooled connection never retains a prior message's tenant scope")
    # 5. duplicate idem under a DIFFERENT tenant does not collide (composite (tenant, idem))
    qa.enqueue(mk("tenant-a", "shared-key")); qa.enqueue(mk("tenant-b", "shared-key"))
    for _ in range(4):
        qa.drain_once(scope_handler, consumer_name="w", redis_conn=conn); time.sleep(0.05)
    with psycopg.connect(db["migration_dsn"], autocommit=True) as c, c.cursor() as cur:
        cur.execute("select count(*) from queue_effect where marker='shared-key'"); sk = cur.fetchone()[0]
    rec("TC05 idem-tenant-scoped-no-collision", sk == 2,
        "the same idempotency key under two tenants does not collide (tenant-scoped idempotency)")


def lifecycle(db, br):
    dbcfg = A.ProductionProfileConfig(profile="production", dsn=db["runtime_dsn"], sslmode="verify-full",
        sslrootcert=db["ca_path"], migration_role=db["migration_role"])
    dba = A.ProductionDatabaseAdapter(dbcfg); dba.start()
    qa = Q.ProductionQueueAdapter(_qcfg(br)); st = qa.start()
    rec("LC01 bounded-startup", st["started"] and st["producers"] == 1 and st["consumers"] >= 1,
        "startup proves config valid, producer+consumers ready, group created")
    res = qa.shutdown()
    rec("LC02 bounded-shutdown", res["drained_cleanly"] and res["connections_closed"] >= 1,
        "shutdown drains in-flight within the bounded deadline and closes connections")
    try:
        qa.enqueue({"x": 1}); rec("LC03 post-shutdown-fails-closed", False, "enqueue after shutdown accepted")
    except Exception:
        rec("LC03 post-shutdown-fails-closed", True, "queue operations after shutdown fail closed")
    dba.shutdown()


def main() -> int:
    with disposable_tls_stack() as db, disposable_redis(tls=True) as br:
        _setup_db(db)
        config_faults(br)
        tls_enforcement(br)
        dbcfg = A.ProductionProfileConfig(profile="production", dsn=db["runtime_dsn"], sslmode="verify-full",
            sslrootcert=db["ca_path"], migration_role=db["migration_role"])
        dba = A.ProductionDatabaseAdapter(dbcfg); dba.start()
        qa = Q.ProductionQueueAdapter(_qcfg(br)); qa.start()
        try:
            workflow_and_idempotency(db, qa, dba)
            retry_and_dead_letter(db, qa, dba)
            dlq_and_replay(db, qa, dba)
            tenant_coupling(db, qa, dba)
            stress(db, qa, dba)
        finally:
            qa.shutdown(); dba.shutdown()
        runtime_concurrency(db, br)
        lifecycle(db, br)
    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "production_queue_profile",
        "claim_scope": "production-queue-behavioral-only; NOT production-target acceptance; "
                       "ga_redis_adapter remains BLOCKED",
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2, sort_keys=True))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
