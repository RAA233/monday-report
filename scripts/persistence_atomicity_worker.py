"""Child process for the persistence-atomicity guard.

Runs in a SEPARATE operating-system process with its OWN PostgreSQL connection,
so the concurrency it exercises is genuine cross-process concurrency rather than
threads sharing an interpreter (and therefore sharing the in-process RLocks that
the store already holds).

Coordination uses a PostgreSQL barrier table rather than sleeps: each worker
announces arrival and then polls until the expected number of participants have
arrived. That makes the interleaving deterministic instead of timing-dependent.

Invoked as:
    python scripts/persistence_atomicity_worker.py <scenario> <worker_id> <json_config>

Writes a single JSON object to stdout. Never prints the DSN.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

BARRIER_TABLE = "mr_test_barrier"


def _ws(name: str):
    from backend.app.schemas import WorkspaceCreate

    return WorkspaceCreate(name=name)


def barrier(dsn: str, name: str, worker_id: str, participants: int, timeout: float = 30.0) -> None:
    """Block until ``participants`` workers have reached ``name``."""
    import psycopg

    # The parent creates the barrier table before spawning workers; creating it
    # here would race two workers on concurrent DDL. Just register arrival.
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            f"insert into {BARRIER_TABLE} (name, worker_id) values (%s, %s) on conflict do nothing",
            (name, worker_id),
        )
        deadline = time.time() + timeout
        while time.time() < deadline:
            row = conn.execute(
                f"select count(*) from {BARRIER_TABLE} where name = %s", (name,)
            ).fetchone()
            if row and int(row[0]) >= participants:
                return
            time.sleep(0.02)
        raise TimeoutError(f"barrier {name!r} timed out")


def build_store(cfg: dict):
    """Construct a PostgresStateStore in an isolated per-worker environment."""
    os.environ["MONDAY_REPORT_STATE_PATH"] = cfg["state_path"]
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = cfg["storage_root"]
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = cfg["export_root"]
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = cfg["audit_key"]
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = cfg["tenant_slug"]
    os.environ["CI"] = "true"

    from backend.app.store import PostgresStateStore

    return PostgresStateStore(cfg["dsn"])


def main() -> int:
    scenario, worker_id, raw_cfg = sys.argv[1], sys.argv[2], sys.argv[3]
    cfg = json.loads(raw_cfg)
    dsn = cfg["dsn"]
    out: dict[str, object] = {"scenario": scenario, "worker": worker_id}

    try:
        from backend.app.store import IdempotencyConflict, SnapshotConflict

        # first_construction must race the CONSTRUCTOR itself, so it barriers
        # before building. Every other scenario builds first.
        if scenario == "first_construction":
            barrier(dsn, "firstctor:ready", worker_id, cfg["participants"])
            store = build_store(cfg)
            out["committed"] = True
            print(json.dumps(out))
            return 0

        store = build_store(cfg)

        if scenario in {"concurrent_same_aggregate", "unrelated_tenants"}:
            # Both workers read, both mutate, both commit. With a correct
            # transaction each increment survives; with last-writer-wins one is lost.
            barrier(dsn, f"{scenario}:ready", worker_id, cfg["participants"])
            committed = False
            reason = None
            try:
                with store.snapshot_transaction() as ctx:
                    # A workspace is a first-class domain entity, so this exercises
                    # the real mutation path rather than a synthetic counter.
                    store.create_workspace(_ws(f"ws-{worker_id}"))
                    out["revision_before"] = ctx["revision"]
                committed = True
            except SnapshotConflict as exc:
                reason = exc.reason
            out["committed"] = committed
            out["conflict"] = reason

        elif scenario == "legacy_negative_control":
            # NEGATIVE CONTROL. Faithfully reproduces the historical
            # last-writer-wins defect against a DEDICATED disposable test table --
            # NOT current save()/CAS code, which no longer loses updates. Both
            # processes read the same initial payload, barrier, then blind-upsert.
            # Exactly one logical update must survive, or the guard's race test is
            # not discriminating.
            import psycopg
            append = cfg["append_value"]
            table = cfg["legacy_table"]
            with psycopg.connect(dsn, autocommit=True) as conn:
                # read the shared initial payload (a JSON list) on this process's
                # OWN connection, with no lock
                row = conn.execute(
                    f"select payload from {table} where snapshot_id = 'singleton'").fetchone()
                current = list(row[0]) if row else []
            barrier(dsn, "legneg:read", worker_id, cfg["participants"])
            current.append(append)  # mutate in memory
            with psycopg.connect(dsn, autocommit=True) as conn:
                from psycopg.types.json import Jsonb
                # historical blind write: no lock, no revision, no CAS
                conn.execute(
                    f"insert into {table} (snapshot_id, payload) values ('singleton', %s) "
                    f"on conflict (snapshot_id) do update set payload = excluded.payload",
                    (Jsonb(current),))
            out["committed"] = True

        elif scenario == "protected_negative_comparison":
            # Same logical workload through the PROTECTED path: both updates survive.
            barrier(dsn, "protneg:ready", worker_id, cfg["participants"])
            with store.snapshot_transaction():
                store.create_workspace(_ws(f"prot-{worker_id}"))
            out["committed"] = True

        elif scenario == "stale_revision":
            # Worker A opens a transaction and holds it; worker B commits first.
            if worker_id == "b":
                with store.snapshot_transaction():
                    store.create_workspace(_ws("ws-b"))
                barrier(dsn, "stale:b_done", worker_id, 1)
            else:
                barrier(dsn, "stale:b_done", "b", 1)
                with store.snapshot_transaction() as ctx:
                    store.create_workspace(_ws("ws-a"))
                    out["revision_seen"] = ctx["revision"]
            out["committed"] = True

        elif scenario == "idempotent_retry":
            op = cfg["operation_id"]
            req = cfg["request_hash"]
            barrier(dsn, "idem:ready", worker_id, cfg["participants"])
            replayed = None
            try:
                with store.snapshot_transaction(operation_id=op, request_hash=req) as ctx:
                    replayed = bool(ctx["replayed"])
                    if not replayed:
                        store.create_workspace(_ws(f"idem-{op}"))
                out["committed"] = True
                out["replayed"] = replayed
            except SnapshotConflict as exc:
                out["committed"] = False
                out["conflict"] = exc.reason

        elif scenario == "idempotent_different_payload":
            op = cfg["operation_id"]
            try:
                with store.snapshot_transaction(operation_id=op, request_hash=cfg["request_hash"]):
                    store.create_workspace(_ws("idem-diff"))
                out["committed"] = True
                out["rejected"] = False
            except IdempotencyConflict:
                out["committed"] = False
                out["rejected"] = True

        elif scenario == "rollback_before_commit":
            # A failure raised inside the transaction must leave NOTHING behind:
            # no workspace, no audit event, no revision increment.
            try:
                with store.snapshot_transaction():
                    store.create_workspace(_ws("doomed"))
                    raise RuntimeError("synthetic pre-commit failure")
            except RuntimeError:
                pass
            out["committed"] = False

        elif scenario == "abort_before_commit":
            # Terminate hard while holding an open transaction. PostgreSQL must
            # roll it back when the connection dies.
            with store.snapshot_transaction():
                store.create_workspace(_ws("killed"))
                sys.stdout.write(json.dumps({"scenario": scenario, "worker": worker_id,
                                             "about_to_abort": True}) + "\n")
                sys.stdout.flush()
                os._exit(9)

        else:
            out["error"] = f"unknown scenario {scenario!r}"
            print(json.dumps(out))
            return 2

    except Exception as exc:  # noqa: BLE001 - report, never leak the DSN
        out["error"] = f"{exc.__class__.__name__}: {str(exc)[:200]}"
        print(json.dumps(out))
        return 1

    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
