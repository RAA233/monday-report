"""Child process for the normalized-persistence guard.

Each invocation runs in its OWN operating-system process with its OWN
PostgreSQL connections, exercising genuine cross-process concurrency against
the normalized correction tables. Coordination uses the PostgreSQL barrier
table created by the PARENT (never here, to avoid DDL races).

Invoked as:
    python scripts/normalized_persistence_worker.py <scenario> <worker_id> <json_config>

Writes one JSON object to stdout. Never prints the DSN or credentials.
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


def barrier(dsn: str, name: str, worker_id: str, participants: int, timeout: float = 30.0) -> None:
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            f"insert into {BARRIER_TABLE} (name, worker_id) values (%s, %s) on conflict do nothing",
            (name, worker_id))
        deadline = time.time() + timeout
        while time.time() < deadline:
            row = conn.execute(f"select count(*) from {BARRIER_TABLE} where name = %s", (name,)).fetchone()
            if row and int(row[0]) >= participants:
                return
            time.sleep(0.02)
        raise TimeoutError(f"barrier {name!r} timed out")


def configure(cfg: dict) -> None:
    os.environ.update({
        "MONDAY_REPORT_REPOSITORY_BACKEND": "postgres",
        "MONDAY_REPORT_DATABASE_URL": cfg["dsn"],
        "MONDAY_REPORT_CLIENT_DATA_MODE": "demo",
        "MONDAY_REPORT_DISABLE_DEMO_SEED": "true",
        "MONDAY_REPORT_TENANT_SLUG": cfg["tenant_slug"],
        "MONDAY_REPORT_USER_EMAIL": "reviewer@example.test",
        "MONDAY_REPORT_USER_FULL_NAME": "NP Worker",
        "MONDAY_REPORT_STATE_PATH": cfg["state_path"],
        "MONDAY_REPORT_STORAGE_ROOT": cfg["storage_root"],
        "MONDAY_REPORT_EXPORT_ROOT": cfg["export_root"],
        "MONDAY_REPORT_AUDIT_HMAC_KEY": cfg["audit_key"],
        "CI": "true",
    })


CORRECTION = {
    "target_type": "report_field", "field_key": "well",
    "source_value": "SRC", "corrected_value": "FIX",
    "correction_reason": "normalized race scenario",
}


def main() -> int:
    scenario, worker_id, raw = sys.argv[1], sys.argv[2], sys.argv[3]
    cfg = json.loads(raw)
    dsn = cfg["dsn"]
    out: dict[str, object] = {"scenario": scenario, "worker": worker_id}
    configure(cfg)

    try:
        from fastapi.testclient import TestClient

        from backend.app.main import app

        client = TestClient(app, raise_server_exceptions=False)

        def post_correction(workspace_id: str, key: str, body: dict | None = None):
            return client.post(f"/workspaces/{workspace_id}/field-corrections",
                               headers={"Idempotency-Key": key}, json=body or CORRECTION)

        if scenario == "same_field_race":
            # G1: both processes correct the SAME field coordinate; the second
            # supersedes the first; the one-active unique index must hold.
            barrier(dsn, "sfr:ready", worker_id, cfg["participants"])
            r = post_correction(cfg["workspace_id"], f"key-sfr-{worker_id}-" + "x" * 8,
                                {**CORRECTION, "corrected_value": f"FIX-{worker_id}"})
            out["status"] = r.status_code

        elif scenario == "record_vs_revert":
            # G3: A records a superseding correction while B reverts the prior.
            barrier(dsn, "rvr:ready", worker_id, cfg["participants"])
            if worker_id == "a":
                r = post_correction(cfg["workspace_id"], "key-rvr-a-" + "x" * 8,
                                    {**CORRECTION, "corrected_value": "RACE-NEW"})
            else:
                r = client.post(f"/field-corrections/{cfg['correction_id']}/revert",
                                headers={"Idempotency-Key": "key-rvr-b-" + "x" * 8},
                                json={"revert_reason": "race revert"})
            out["status"] = r.status_code

        elif scenario == "terminal_race":
            # G4/G5: racing PATCH transitions on one task (statuses from cfg).
            barrier(dsn, "tr:ready", worker_id, cfg["participants"])
            r = client.patch(f"/validation-tasks/{cfg['task_id']}",
                             headers={"Idempotency-Key": f"key-tr-{worker_id}-" + "x" * 8},
                             json={"status": cfg["statuses"][worker_id],
                                   "resolution_note": f"race {worker_id}"})
            out["status"] = r.status_code

        elif scenario == "stale_revision":
            # G7: repository-level expected-revision conflict across processes.
            from backend.app.repositories import PgValidationTaskRepository, StaleRevisionError
            from backend.app.store import store

            if worker_id == "b":
                r = client.patch(f"/validation-tasks/{cfg['task_id']}",
                                 headers={"Idempotency-Key": "key-stale-b-" + "x" * 8},
                                 json={"status": "validated", "resolution_note": "b wins"})
                out["status"] = r.status_code
                barrier(dsn, "stale:b_done", worker_id, 1)
            else:
                # WAIT for B's announcement without inserting it ourselves (a
                # self-insert would satisfy the count immediately and void the
                # ordering this scenario depends on).
                import psycopg

                deadline = time.time() + 30
                with psycopg.connect(dsn, autocommit=True) as conn:
                    while time.time() < deadline:
                        row = conn.execute(
                            f"select count(*) from {BARRIER_TABLE} "
                            f"where name = 'stale:b_done' and worker_id = 'b'").fetchone()
                        if row and int(row[0]) >= 1:
                            break
                        time.sleep(0.05)
                    else:
                        raise TimeoutError("b never announced completion")
                store.refresh()
                task = store.validation_tasks[__import__("uuid").UUID(cfg["task_id"])]
                try:
                    with store.snapshot_transaction():
                        PgValidationTaskRepository(store).transition(
                            task, previous_status="open", is_review_outcome=True,
                            reviewer_verified=False, audit_event_id=None, operation_id=None,
                            expected_revision=0)  # stale: B already bumped it to 1
                    out["stale_rejected"] = False
                except StaleRevisionError:
                    out["stale_rejected"] = True

        elif scenario == "independent_workspaces":
            # G16: distinct aggregates commit concurrently without conflicts.
            barrier(dsn, "iw:ready", worker_id, cfg["participants"])
            r = post_correction(cfg["workspace_ids"][worker_id], f"key-iw-{worker_id}-" + "x" * 8)
            out["status"] = r.status_code

        elif scenario == "independent_tenants":
            # G17: distinct tenant slugs (separate snapshots) commit concurrently.
            barrier(dsn, "it:ready", worker_id, cfg["participants"])
            ws = client.post("/workspaces", json={"name": f"it-{worker_id}", "rig_name": "g"}).json()["id"]
            r = post_correction(ws, f"key-it-{worker_id}-" + "x" * 8)
            out["status"] = r.status_code

        elif scenario == "hold_global_lock":
            # G18 support: hold the global advisory lock long enough for the
            # partner process to hit its bounded lock timeout.
            import psycopg

            from backend.app.store import PostgresStateStore
            key = PostgresStateStore._advisory_lock_key()
            with psycopg.connect(dsn) as conn:
                with conn.cursor() as cursor:
                    cursor.execute("select pg_advisory_xact_lock(%s)", (key,))
                barrier(dsn, "hold:acquired", worker_id, 1)
                time.sleep(float(cfg.get("hold_seconds", 8)))
                conn.rollback()
            out["held"] = True

        elif scenario == "lock_timeout_victim":
            # G18: mutation during a held global lock -> controlled 503, no state.
            barrier(dsn, "hold:acquired", "holder", 1)
            r = post_correction(cfg["workspace_id"], "key-lt-" + "x" * 10)
            out["status"] = r.status_code
            out["controlled"] = r.status_code in (503, 409)

        elif scenario == "abort_before_commit":
            # G15: die mid-transaction; PostgreSQL must roll everything back.
            from backend.app.schemas import FieldCorrectionCreate
            from backend.app.store import store

            with store.snapshot_transaction():
                store.record_field_correction(
                    __import__("uuid").UUID(cfg["workspace_id"]),
                    FieldCorrectionCreate(**CORRECTION))
                sys.stdout.write(json.dumps({"scenario": scenario, "worker": worker_id,
                                             "about_to_abort": True}) + "\n")
                sys.stdout.flush()
                os._exit(9)

        elif scenario == "cross_tenant_replay":
            # Tenant B replays tenant A's idempotency key: must commit its OWN
            # entity, never retrieve A's result.
            ws = client.post("/workspaces", json={"name": "ctr", "rig_name": "g"}).json()["id"]
            r = post_correction(ws, cfg["operation_id"])
            out["status"] = r.status_code
            out["entity_id"] = r.json().get("id")

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
