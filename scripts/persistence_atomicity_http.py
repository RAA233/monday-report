"""Real-HTTP idempotency proof for the transactional PostgreSQL snapshot store.

The store primitive ``snapshot_transaction(operation_id=...)`` can replay a
committed operation, but that is only meaningful if a real HTTP request reaches
it with a key. This harness proves the ROUTE layer does exactly that: every
scenario is a genuine HTTP request through FastAPI's router, the client-mode
middleware, RBAC (``require_permission``), resource-ownership and request
validation, into the PostgreSQL-backed store. Nothing here calls the store
directly.

Two entry points, both requiring a disposable PostgreSQL (never a live one):

* ``suite <json_cfg>`` -- run the 14 single-process HTTP scenarios in this
  process and print a JSON result object.
* ``concurrent <worker_id> <json_cfg>`` -- one of two INDEPENDENT OS processes
  that each build their own app + connection and, after a shared barrier, POST
  the SAME correction with the SAME Idempotency-Key. The parent checks that
  exactly one mutation and one idempotency record result.

Environment (demo mode + postgres backend) is configured BEFORE importing the
app, because the app builds its store singleton at import. Demo mode still runs
the full middleware + RBAC stack (the request actor is the explicit demo-bootstrap
identity), so these are real routed+authorized requests; it simply does not
require a client API key, which keeps the proof self-contained. The DSN is never
printed.
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

VALID_CORRECTION = {
    "target_type": "report_field",
    "field_key": "well",
    "source_value": "SENTINELSRC 0091",
    "corrected_value": "ALPINE 22B [45]-07",
    "correction_reason": "Restore the bracketed pad code dropped in extraction.",
}


def _configure_env(cfg: dict) -> None:
    """Set env so the app builds a PostgreSQL-backed store in demo mode."""
    os.environ["MONDAY_REPORT_REPOSITORY_BACKEND"] = "postgres"
    os.environ["MONDAY_REPORT_DATABASE_URL"] = cfg["dsn"]
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
    os.environ["MONDAY_REPORT_DISABLE_DEMO_SEED"] = "true"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = cfg["tenant_slug"]
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Atomicity HTTP Guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Atomicity HTTP Reviewer"
    os.environ["MONDAY_REPORT_STATE_PATH"] = cfg["state_path"]
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = cfg["storage_root"]
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = cfg["export_root"]
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = cfg["audit_key"]
    os.environ["CI"] = "true"


def _client(raise_server_exceptions: bool = True):
    from fastapi.testclient import TestClient
    from backend.app.main import app

    return TestClient(app, raise_server_exceptions=raise_server_exceptions)


# --------------------------------------------------------------------------- #
# Direct-DB observation helpers (verify the persisted truth, not the response)
# --------------------------------------------------------------------------- #
def _revision(dsn: str, slug: str) -> int | None:
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as c:
        r = c.execute("select revision from monday_report_state_snapshots where tenant_slug=%s",
                      (slug,)).fetchone()
        return int(r[0]) if r else None


def _corrections_for(dsn: str, slug: str, workspace_id: str) -> int:
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as c:
        r = c.execute(
            "select count(*) from monday_report_state_snapshots snap, "
            "jsonb_array_elements(snap.payload->'field_corrections') fc "
            "where snap.tenant_slug=%s and fc->>'workspace_id' = %s",
            (slug, workspace_id)).fetchone()
        return int(r[0]) if r else 0


def _idempotency_row(dsn: str, slug: str, operation_id: str) -> dict:
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as c:
        r = c.execute(
            "select count(*), (array_agg(actor_id))[1], (array_agg(operation_kind))[1] "
            "from monday_report_idempotency_records where tenant_slug=%s and operation_id=%s",
            (slug, operation_id)).fetchone()
    return {"rows": int(r[0]), "actor_id": (str(r[1]) if r[1] else None), "operation_kind": r[2]}


def barrier(dsn: str, name: str, worker_id: str, participants: int, timeout: float = 30.0) -> None:
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            f"insert into {BARRIER_TABLE} (name, worker_id) values (%s, %s) on conflict do nothing",
            (name, worker_id))
        deadline = time.time() + timeout
        while time.time() < deadline:
            row = conn.execute(f"select count(*) from {BARRIER_TABLE} where name=%s", (name,)).fetchone()
            if row and int(row[0]) >= participants:
                return
            time.sleep(0.02)
        raise TimeoutError(f"barrier {name!r} timed out")


# --------------------------------------------------------------------------- #
# The 14 single-process HTTP scenarios
# --------------------------------------------------------------------------- #
def run_suite(cfg: dict) -> dict:
    dsn = cfg["dsn"]
    slug = cfg["tenant_slug"]
    client = _client()
    results: list[dict] = []

    def record(name: str, ok: bool, detail: object = "") -> None:
        results.append({"name": name, "ok": bool(ok), "detail": detail})

    def new_workspace(name: str) -> str:
        # POST /workspaces is a mutator but is NOT one of the idempotency-gated
        # routes, so it needs no key: proof that the requirement is scoped to the
        # wired reviewer routes, not blanket-applied.
        r = client.post("/workspaces", json={"name": name, "rig_name": "guard"})
        assert r.status_code in (200, 201), (r.status_code, r.text[:200])
        return r.json()["id"]

    def hdr(key: str) -> dict:
        return {"Idempotency-Key": key}

    session = client.get("/auth/session").json()
    actor_id = (session.get("authenticated_identity") or {}).get("user_id")

    ws = new_workspace("http-idem-primary")
    k1 = "key-" + "1" * 12

    # 1. First keyed create commits exactly one correction + one idempotency row.
    r1 = client.post(f"/workspaces/{ws}/field-corrections", headers=hdr(k1), json=VALID_CORRECTION)
    e1 = r1.json() if r1.status_code == 201 else {}
    row1 = _idempotency_row(dsn, slug, k1)
    record("01 first keyed create commits (201) with one idempotency record",
           r1.status_code == 201 and row1["rows"] == 1 and _corrections_for(dsn, slug, ws) == 1,
           {"status": r1.status_code, "idem_rows": row1["rows"], "corrections": _corrections_for(dsn, slug, ws)})

    rev_after_create = _revision(dsn, slug)

    # 2. Exact replay returns the SAME entity, no second correction, no new record.
    r2 = client.post(f"/workspaces/{ws}/field-corrections", headers=hdr(k1), json=VALID_CORRECTION)
    e2 = r2.json() if r2.status_code == 201 else {}
    record("02 exact replay returns the committed entity, mutating nothing",
           r2.status_code == 201 and e2.get("id") == e1.get("id")
           and _corrections_for(dsn, slug, ws) == 1 and _idempotency_row(dsn, slug, k1)["rows"] == 1,
           {"status": r2.status_code, "same_id": e2.get("id") == e1.get("id"),
            "corrections": _corrections_for(dsn, slug, ws)})

    # 3. Replay does not advance the revision (=> no new state or audit committed).
    record("03 replay advances no revision (no duplicate commit or audit)",
           _revision(dsn, slug) == rev_after_create,
           {"before": rev_after_create, "after": _revision(dsn, slug)})

    # 4. Missing key on a required route fails closed BEFORE any mutation.
    r4 = client.post(f"/workspaces/{ws}/field-corrections", json=VALID_CORRECTION)
    record("04 missing Idempotency-Key is rejected 400 and mutates nothing",
           r4.status_code == 400 and _corrections_for(dsn, slug, ws) == 1,
           {"status": r4.status_code, "corrections": _corrections_for(dsn, slug, ws)})

    # 5-8. Malformed keys are rejected 400 (empty, too short, illegal chars, conflicting).
    r5 = client.post(f"/workspaces/{ws}/field-corrections", headers={"Idempotency-Key": "   "}, json=VALID_CORRECTION)
    record("05 empty Idempotency-Key is rejected 400", r5.status_code == 400, r5.status_code)
    r6 = client.post(f"/workspaces/{ws}/field-corrections", headers=hdr("short"), json=VALID_CORRECTION)
    record("06 too-short Idempotency-Key is rejected 400", r6.status_code == 400, r6.status_code)
    r7 = client.post(f"/workspaces/{ws}/field-corrections", headers=hdr("has space!"), json=VALID_CORRECTION)
    record("07 illegal-character Idempotency-Key is rejected 400", r7.status_code == 400, r7.status_code)
    r8 = client.post(f"/workspaces/{ws}/field-corrections",
                     headers=[("idempotency-key", "aaaaaaaa"), ("idempotency-key", "bbbbbbbb"),
                              ("content-type", "application/json")],
                     content=json.dumps(VALID_CORRECTION))
    record("08 conflicting duplicate Idempotency-Key headers are rejected 400", r8.status_code == 400, r8.status_code)

    # 9. Same key, DIFFERENT validated body => conflict 409, no mutation.
    diff_body = {**VALID_CORRECTION, "corrected_value": "ALPINE 22B [45]-08"}
    r9 = client.post(f"/workspaces/{ws}/field-corrections", headers=hdr(k1), json=diff_body)
    record("09 same key with a different request body is a 409 conflict, no mutation",
           r9.status_code == 409 and _corrections_for(dsn, slug, ws) == 1,
           {"status": r9.status_code, "corrections": _corrections_for(dsn, slug, ws)})

    # 10. Same key reused on a DIFFERENT operation kind (revert) => 409, E1 untouched.
    r10 = client.post(f"/field-corrections/{e1.get('id')}/revert", headers=hdr(k1),
                      json={"revert_reason": "should not apply"})
    hist = client.get(f"/workspaces/{ws}/field-corrections").json()
    e1_status = next((c["status"] for c in hist if c["id"] == e1.get("id")), None)
    record("10 same key reused for a different operation kind is a 409 conflict",
           r10.status_code == 409 and e1_status == "active",
           {"status": r10.status_code, "e1_status": e1_status})

    # 11. A DIFFERENT key with the same body commits a distinct entity: the KEY,
    #     not the body, is the idempotency unit.
    k2 = "key-" + "2" * 12
    r11 = client.post(f"/workspaces/{ws}/field-corrections", headers=hdr(k2), json=VALID_CORRECTION)
    e11 = r11.json() if r11.status_code == 201 else {}
    record("11 a distinct key with the same body commits a distinct entity",
           r11.status_code == 201 and e11.get("id") != e1.get("id")
           and _corrections_for(dsn, slug, ws) == 2,
           {"status": r11.status_code, "distinct": e11.get("id") != e1.get("id"),
            "corrections": _corrections_for(dsn, slug, ws)})

    # 12. A failed mutation does NOT reserve its key: revert twice; the second
    #     revert fails at the store (already reverted) and its key stays free.
    ws2 = new_workspace("http-idem-revert")
    kc = "key-create-" + "c" * 8
    c = client.post(f"/workspaces/{ws2}/field-corrections", headers=hdr(kc), json=VALID_CORRECTION).json()
    kr_ok = "key-revert-" + "r" * 8
    rok = client.post(f"/field-corrections/{c['id']}/revert", headers=hdr(kr_ok),
                      json={"revert_reason": "first revert"})
    k_fail = "key-fail-" + "f" * 9
    rfail = client.post(f"/field-corrections/{c['id']}/revert", headers=hdr(k_fail),
                        json={"revert_reason": "already reverted"})
    fail_row = _idempotency_row(dsn, slug, k_fail)
    record("12 a failed mutation (already-reverted) reserves no idempotency key",
           rok.status_code == 200 and rfail.status_code == 409 and fail_row["rows"] == 0,
           {"first": rok.status_code, "second": rfail.status_code, "failed_key_rows": fail_row["rows"]})

    # 13. The record binds the resolved request ACTOR (server-side identity), not
    #     a client-asserted one.
    record("13 the idempotency record binds the resolved request actor id",
           bool(actor_id) and row1["actor_id"] == actor_id
           and row1["operation_kind"] == "field_correction.record",
           {"record_actor": row1["actor_id"], "session_actor": actor_id, "kind": row1["operation_kind"]})

    # 14. Revert is idempotent too: same revert key twice replays, one record,
    #     one logical revert, revision steady across the replay.
    ws3 = new_workspace("http-idem-revert2")
    c3 = client.post(f"/workspaces/{ws3}/field-corrections", headers=hdr("key-c3-" + "3" * 10),
                     json=VALID_CORRECTION).json()
    kr = "key-revert2-" + "v" * 8
    rr1 = client.post(f"/field-corrections/{c3['id']}/revert", headers=hdr(kr), json={"revert_reason": "revert once"})
    rev_after_revert = _revision(dsn, slug)
    rr2 = client.post(f"/field-corrections/{c3['id']}/revert", headers=hdr(kr), json={"revert_reason": "revert once"})
    kr_row = _idempotency_row(dsn, slug, kr)
    hist3 = client.get(f"/workspaces/{ws3}/field-corrections").json()
    c3_status = next((x["status"] for x in hist3 if x["id"] == c3["id"]), None)
    record("14 revert is idempotent: replay returns the reverted entity, one record",
           rr1.status_code == 200 and rr2.status_code == 200
           and rr2.json().get("id") == c3["id"] and kr_row["rows"] == 1
           and c3_status == "reverted" and _revision(dsn, slug) == rev_after_revert,
           {"first": rr1.status_code, "second": rr2.status_code, "revert_key_rows": kr_row["rows"],
            "c3_status": c3_status, "revision_steady": _revision(dsn, slug) == rev_after_revert})

    passed = sum(1 for r in results if r["ok"])
    return {"mode": "suite", "results": results, "passed": passed, "total": len(results),
            "all_passed": passed == len(results), "shared_workspace": ws}


# --------------------------------------------------------------------------- #
# Concurrent duplicate through HTTP (one of two independent OS processes)
# --------------------------------------------------------------------------- #
def run_lost_response(cfg: dict) -> dict:
    """Prove an UNCERTAIN response cannot double-commit.

    Arms the test-only post-commit hook for one key, sends the create (which
    commits and then loses its response -> 500), confirms the mutation and its
    idempotency record are already durably present, and shows that a same-key
    retry replays the committed entity (201) rather than committing a second
    time. The hook stays armed across the retry; the replay path bypasses it, so
    nothing is 'turned off' to make the retry succeed. The hook is inert in
    client mode, which this run also asserts."""
    from backend.app import idempotency

    dsn = cfg["dsn"]
    slug = cfg["tenant_slug"]
    client = _client(raise_server_exceptions=False)
    results: list[dict] = []

    def record(name: str, ok: bool, detail: object = "") -> None:
        results.append({"name": name, "ok": bool(ok), "detail": detail})

    r = client.post("/workspaces", json={"name": "http-lost-response", "rig_name": "guard"})
    ws = r.json()["id"]
    key = "key-lost-" + "l" * 10

    # Arm the hook for exactly this key.
    os.environ[idempotency.LOST_RESPONSE_ENV] = key

    first = client.post(f"/workspaces/{ws}/field-corrections",
                        headers={"Idempotency-Key": key}, json=VALID_CORRECTION)
    row = _idempotency_row(dsn, slug, key)
    committed = _corrections_for(dsn, slug, ws)
    record("L1 response lost after commit surfaces a 5xx to the caller",
           first.status_code >= 500, {"status": first.status_code})
    record("L2 the mutation and its idempotency record are already durable",
           committed == 1 and row["rows"] == 1, {"corrections": committed, "idem_rows": row["rows"]})

    # Retry with the SAME key while the hook is STILL armed: the replay path must
    # bypass the hook and return the committed entity.
    retry = client.post(f"/workspaces/{ws}/field-corrections",
                        headers={"Idempotency-Key": key}, json=VALID_CORRECTION)
    body = retry.json() if retry.status_code == 201 else {}
    record("L3 same-key retry replays the committed entity (201), hook still armed",
           retry.status_code == 201 and _corrections_for(dsn, slug, ws) == 1
           and row["rows"] == _idempotency_row(dsn, slug, key)["rows"] == 1,
           {"status": retry.status_code, "corrections": _corrections_for(dsn, slug, ws),
            "entity_id": body.get("id")})

    # The hook must be inert in client mode: even armed, it does not fire.
    fired_in_client = None
    try:
        os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "client"
        idempotency.simulate_lost_response(key)  # should NOT raise
        fired_in_client = False
    except idempotency.LostResponseSimulation:
        fired_in_client = True
    finally:
        os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
        os.environ.pop(idempotency.LOST_RESPONSE_ENV, None)
    record("L4 the lost-response hook is inert in client mode", fired_in_client is False,
           {"fired_in_client": fired_in_client})

    passed = sum(1 for r in results if r["ok"])
    return {"mode": "lost_response", "results": results, "passed": passed,
            "total": len(results), "all_passed": passed == len(results)}


def run_setup(cfg: dict) -> dict:
    """Single-process preparation for the concurrent scenario.

    Creates the shared workspace (committed to the global snapshot) and the
    barrier table -- done once by the parent so the two racing workers never
    contend on CREATE TABLE."""
    import psycopg

    with psycopg.connect(cfg["dsn"], autocommit=True) as c:
        c.execute(f"create table if not exists {BARRIER_TABLE} "
                  f"(name text not null, worker_id text not null, primary key (name, worker_id))")
        c.execute(f"truncate {BARRIER_TABLE}")
    client = _client()
    r = client.post("/workspaces", json={"name": "http-dup-shared", "rig_name": "guard"})
    return {"mode": "setup", "workspace_id": r.json()["id"]}


def run_concurrent(worker_id: str, cfg: dict) -> dict:
    dsn = cfg["dsn"]
    client = _client(raise_server_exceptions=False)
    barrier(dsn, "http-dup:ready", worker_id, cfg["participants"])
    r = client.post(f"/workspaces/{cfg['workspace_id']}/field-corrections",
                    headers={"Idempotency-Key": cfg["operation_id"]}, json=VALID_CORRECTION)
    body = {}
    try:
        body = r.json()
    except Exception:  # noqa: BLE001
        pass
    return {"mode": "concurrent", "worker": worker_id, "status": r.status_code,
            "entity_id": body.get("id")}


def main() -> int:
    mode = sys.argv[1]
    if mode == "suite":
        cfg = json.loads(sys.argv[2])
        _configure_env(cfg)
        print(json.dumps(run_suite(cfg), default=str))
        return 0
    if mode == "lost_response":
        cfg = json.loads(sys.argv[2])
        _configure_env(cfg)
        print(json.dumps(run_lost_response(cfg), default=str))
        return 0
    if mode == "setup":
        cfg = json.loads(sys.argv[2])
        _configure_env(cfg)
        print(json.dumps(run_setup(cfg), default=str))
        return 0
    if mode == "concurrent":
        worker_id = sys.argv[2]
        cfg = json.loads(sys.argv[3])
        _configure_env(cfg)
        try:
            print(json.dumps(run_concurrent(worker_id, cfg), default=str))
        except Exception as exc:  # noqa: BLE001 - report, never leak the DSN
            print(json.dumps({"mode": "concurrent", "worker": worker_id,
                              "error": f"{exc.__class__.__name__}: {str(exc)[:200]}"}))
            return 1
        return 0
    print(json.dumps({"error": f"unknown mode {mode!r}"}))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
