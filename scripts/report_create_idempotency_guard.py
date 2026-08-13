"""audit:report-create-idempotency -- replay-safe POST /monday-reports, measured at the
NORMALIZED AUTHORITY and the durable idempotency TABLE on the restricted PostgreSQL runtime.

CLAIM SCOPE: POST /monday-reports ONLY. This guard says nothing about any other route's
idempotency. It pins exactly one property: an ``Idempotency-Key`` on POST /monday-reports
makes report creation replay-safe -- a same tenant + same key + same body retry returns the
ORIGINAL report and creates NO duplicate ``monday_report_norm_reports`` row and NO second
``monday_report.create`` audit event, while a same-key/different-body request fails closed
(409) and mutates nothing.

Why this is measured as a COUNT effect, not a response string: a route could answer 200 with
the old id yet still have written a second row or a second audit event. So every replay/
conflict check compares the number of normalized report rows AND the number of
``monday_report.create`` audit events before/after -- the delta must be +0.

The atomicity argument (report row + audit event + idempotency record commit or roll back as
ONE unit) rests on ``PostgresStateStore.snapshot_transaction``: the ``on conflict
(tenant_slug, operation_id) do nothing`` insert of the idempotency record runs inside the SAME
locked compare-and-swap transaction that commits the snapshot/normalized write and the audit
append (store.py, the single commit at the end of ``snapshot_transaction``). The idempotency
table's ``primary key (tenant_slug, operation_id)`` is what makes two concurrent same-key POSTs
commit exactly once -- the second inserter violates the PK inside its own transaction and rolls
back. Cross-tenant independence is structural: the key is part of that same primary key, so a
key committed under tenant A can never satisfy or collide with tenant B.

Live path (Docker): reuses ``restricted_postgres_startup_guard.run_stack`` -- the runner-owned
disposable pgvector container, migrations 0001-0007, restricted runtime role -- then boots
demo-mode API processes on the postgres backend (custom tenants that emit ``state.bootstrap``
with ``demo_seed=false`` so the demo self-wipe never runs, making restart durability a valid
claim). It drives IC01..IC06 with no browser, RESTARTS the API to prove durability, and boots a
SECOND tenant against the SAME database to prove cross-tenant isolation.

IC01  first POST with a key -> 201, one report, one monday_report.create audit event.
IC02  replay same key+body -> same report id, norm-report count +0, audit-create count +0.
IC03  same key + different body -> 409, norm-report count +0, audit-create count +0.
IC04  restart durability: after an API process restart a same-key replay returns the original,
      norm-report count +0.
IC05  tenant isolation: the same key under a DIFFERENT tenant creates its own report; tenant A's
      report count is unchanged (no cross-tenant satisfaction).
IC06  mechanism engaged + torn-state impossible: a durable idempotency record with
      operation_kind='monday_report.create' exists for the created report, AND the created id has
      BOTH a normalized report row and an idempotency record referencing it (neither orphaned).
      Pre-fix -- the route never established an idempotency context -- no such record can exist,
      so IC06 fails; the Docker-free fault battery drives that negative control explicitly.

Local-store parity (no Docker): the same IC01/IC02/IC03 request logic on the local JSON backend
must AGREE -- replay returns the original report with +0 rows/events, and a same-key/different-
body request is refused with +0 effect. This exercises the file backend's own single
compare-and-swap transaction (report row + audit event + idempotency record in one write).

``--allow-unavailable`` reports UNAVAILABLE without Docker (never a false pass); the Docker-free
fault battery and the local-parity checks still run.
"""
from __future__ import annotations

import copy
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

NORM_REPORTS_TABLE = "monday_report_norm_reports"
IDEM_TABLE = "monday_report_idempotency_records"
TENANT_A = "idemcreatea"
TENANT_B = "idemcreateb"
CREATE_ACTION = "monday_report.create"

CHECK_IDS = [
    ("IC01-first-create-201-one-row-one-event",
     "first POST with a key answers 201 with a report id and exactly one norm row + one create event"),
    ("IC02-replay-same-id-zero-delta",
     "a same key+body replay returns the SAME report id with +0 norm rows and +0 create events"),
    ("IC03-conflict-409-zero-delta",
     "a same key + different body request fails closed (409) and mutates nothing (+0 rows, +0 events)"),
    ("IC04-restart-replay-durable",
     "after an API process restart a same-key replay returns the original with +0 norm rows"),
    ("IC05-tenant-isolation-independent",
     "the same key under a different tenant creates its own report; tenant A's count is unchanged"),
    ("IC06-mechanism-engaged-no-torn-state",
     "a monday_report.create idempotency record exists AND the created id has both a norm row and that record"),
]


# --------------------------------------------------------------- pure judgment --
def _judge(obs: dict) -> dict:
    """PURE judgment over one observation dict. Extracted so the fault battery can drive it
    with mutated observations and confirm each gate is load-bearing."""
    a = obs.get("tenantA") or {}
    ic01 = a.get("ic01") or {}
    ic02 = a.get("ic02") or {}
    ic03 = a.get("ic03") or {}
    restart = a.get("restart") or {}
    b = obs.get("tenantB") or {}
    ic05 = b.get("ic05") or {}
    idem = a.get("idem_records") or []
    created_id = ic01.get("id")

    base_norm = ic01.get("norm_count")
    base_evt = ic01.get("audit_create_count")

    idem_for_create = [r for r in idem if r.get("operation_kind") == CREATE_ACTION]
    idem_result_ids = {r.get("result_identifier") for r in idem_for_create}
    norm_ids_after = set(a.get("norm_ids_final") or [])

    results = {
        "IC01-first-create-201-one-row-one-event":
            ic01.get("status") == 201 and bool(created_id)
            and base_norm == 1 and base_evt == 1,
        "IC02-replay-same-id-zero-delta":
            ic02.get("status") in (200, 201) and ic02.get("id") == created_id
            and ic02.get("norm_count") == base_norm
            and ic02.get("audit_create_count") == base_evt,
        "IC03-conflict-409-zero-delta":
            ic03.get("status") == 409
            and ic03.get("norm_count") == base_norm
            and ic03.get("audit_create_count") == base_evt,
        "IC04-restart-replay-durable":
            restart.get("status") in (200, 201) and restart.get("id") == created_id
            and restart.get("norm_count") == base_norm,
        "IC05-tenant-isolation-independent":
            ic05.get("status") == 201 and bool(ic05.get("id"))
            and ic05.get("id") != created_id
            and ic05.get("tenantA_norm_count") == base_norm,
        "IC06-mechanism-engaged-no-torn-state":
            bool(created_id) and created_id in idem_result_ids
            and created_id in norm_ids_after,
    }
    checks = [
        {"check_id": cid, "result": "PASS" if results[cid] else "FAIL", "contract": contract}
        for cid, contract in CHECK_IDS
    ]
    ok = not obs.get("fatal") and all(results.values())
    return {"checks": checks, "_ok": ok}


def _canonical_obs() -> dict:
    """A synthetic fully-valid observation for the Docker-free fault battery."""
    rid = "00000000-0000-0000-0000-0000000c0de1"
    rid_b = "00000000-0000-0000-0000-0000000c0de2"
    return {
        "tenantA": {
            "ic01": {"status": 201, "id": rid, "norm_count": 1, "audit_create_count": 1},
            "ic02": {"status": 201, "id": rid, "norm_count": 1, "audit_create_count": 1},
            "ic03": {"status": 409, "norm_count": 1, "audit_create_count": 1},
            "restart": {"status": 201, "id": rid, "norm_count": 1},
            "idem_records": [
                {"operation_kind": CREATE_ACTION, "result_identifier": rid,
                 "request_hash": "h", "operation_id": "key-aaaaaaaa"},
            ],
            "norm_ids_final": [rid],
        },
        "tenantB": {"ic05": {"status": 201, "id": rid_b, "tenantA_norm_count": 1}},
    }


def _fault_battery() -> tuple[list[dict], bool]:
    """Prove the judgment refuses each forged/torn/duplicate observation (and is not always-fail)."""

    def refuses(mutate) -> bool:
        obs = copy.deepcopy(_canonical_obs())
        mutate(obs)
        return not _judge(obs)["_ok"]

    proofs = [
        ("F00-valid-observation-certifies", _judge(_canonical_obs())["_ok"],
         "a complete valid observation certifies (the gates are not always-fail)"),
        ("F01-replay-created-second-row-refused",
         refuses(lambda o: o["tenantA"]["ic02"].__setitem__("norm_count", 2)),
         "a replay that added a second normalized report row is refused (duplicate report)"),
        ("F02-replay-created-second-event-refused",
         refuses(lambda o: o["tenantA"]["ic02"].__setitem__("audit_create_count", 2)),
         "a replay that appended a second monday_report.create audit event is refused"),
        ("F03-replay-returned-new-id-refused",
         refuses(lambda o: o["tenantA"]["ic02"].__setitem__("id", "different")),
         "a replay that returned a NEW report id (not the original) is refused"),
        ("F04-conflict-not-409-refused",
         refuses(lambda o: o["tenantA"]["ic03"].__setitem__("status", 201)),
         "a same-key/different-body request that did NOT fail closed (409) is refused"),
        ("F05-conflict-mutated-refused",
         refuses(lambda o: o["tenantA"]["ic03"].__setitem__("norm_count", 2)),
         "a conflict path that still created a row is refused (the conflict must mutate nothing)"),
        ("F06-restart-lost-report-refused",
         refuses(lambda o: o["tenantA"]["restart"].__setitem__("id", None)),
         "a report that does not replay after a restart is refused"),
        ("F07-cross-tenant-satisfied-refused",
         refuses(lambda o: o["tenantB"]["ic05"].__setitem__("id", o["tenantA"]["ic01"]["id"])),
         "tenant B returning tenant A's report id (cross-tenant satisfaction) is refused"),
        ("F08-cross-tenant-mutated-A-refused",
         refuses(lambda o: o["tenantB"]["ic05"].__setitem__("tenantA_norm_count", 2)),
         "tenant B's POST changing tenant A's report count is refused"),
        ("F09-negative-control-no-idem-record-refused",
         refuses(lambda o: o["tenantA"].__setitem__("idem_records", [])),
         "PRE-FIX signature: 201 + report row but NO monday_report.create idempotency record is refused"),
        ("F10-torn-report-without-record-refused",
         refuses(lambda o: o["tenantA"]["idem_records"][0].__setitem__("result_identifier", "orphan")),
         "a norm report row whose id has no idempotency record (torn state) is refused"),
        ("F11-torn-record-without-report-refused",
         refuses(lambda o: o["tenantA"].__setitem__("norm_ids_final", [])),
         "an idempotency record whose report id has no normalized row (torn state) is refused"),
    ]
    rows = [{"proof_id": pid, "result": "PASS" if ok else "FAIL", "detail": detail}
            for pid, ok, detail in proofs]
    return rows, all(ok for _, ok, _ in proofs)


# --------------------------------------------------------- local-store parity --
def _local_parity() -> tuple[list[dict], bool]:
    """Run IC01/IC02/IC03 request logic on the local JSON backend, in-process, and confirm the
    SAME logical guarantee holds there (replay returns the original with +0 effect; a
    same-key/different-body request is refused with +0 effect)."""
    rows: list[dict] = []
    scratch = Path(tempfile.mkdtemp(prefix="mr-idem-local-"))
    env_saved = {k: os.environ.get(k) for k in (
        "MONDAY_REPORT_CLIENT_DATA_MODE", "MONDAY_REPORT_REPOSITORY_BACKEND",
        "MONDAY_REPORT_STATE_PATH", "MONDAY_REPORT_STORAGE_ROOT",
        "MONDAY_REPORT_EXPORT_ROOT", "MONDAY_REPORT_AUDIT_HMAC_KEY", "CI")}
    os.environ.update({
        "MONDAY_REPORT_CLIENT_DATA_MODE": "demo",
        "MONDAY_REPORT_REPOSITORY_BACKEND": "local",
        "MONDAY_REPORT_STATE_PATH": str(scratch / "state.json"),
        "MONDAY_REPORT_STORAGE_ROOT": str(scratch / "storage"),
        "MONDAY_REPORT_EXPORT_ROOT": str(scratch / "exports"),
        "MONDAY_REPORT_AUDIT_HMAC_KEY": "local_parity_key_0123456789abcdef",
        "CI": "true",
    })
    ok_all = True
    try:
        # Fresh import so the app/store bind to this process's local env.
        for mod in [m for m in list(sys.modules) if m.startswith("backend.app")]:
            del sys.modules[mod]
        from fastapi.testclient import TestClient  # noqa: WPS433
        from backend.app.main import app  # noqa: WPS433
        from backend.app import store as store_mod  # noqa: WPS433

        client = TestClient(app)
        ws = client.get("/workspaces").json()[0]["id"]
        body = {"workspace_id": ws, "period_start": "2026-08-10", "period_end": "2026-08-16"}
        key = "local-parity-key-01"

        def counts() -> tuple[int, int]:
            st = store_mod.store
            st.refresh()
            n_rep = len(st.monday_reports)
            n_evt = sum(1 for e in st.audit_logs if e.action == CREATE_ACTION)
            return n_rep, n_evt

        r1 = client.post("/monday-reports", json=body, headers={"Idempotency-Key": key})
        c1 = counts()
        r2 = client.post("/monday-reports", json=body, headers={"Idempotency-Key": key})
        c2 = counts()
        body2 = dict(body, period_end="2026-08-17")
        r3 = client.post("/monday-reports", json=body2, headers={"Idempotency-Key": key})
        c3 = counts()

        lp = [
            ("LP01-local-first-create",
             r1.status_code == 201 and c1 == (1, 1),
             "first keyed POST creates exactly one report + one create event on the local backend"),
            ("LP02-local-replay-zero-delta",
             r2.status_code in (200, 201) and r2.json().get("id") == r1.json().get("id") and c2 == c1,
             "a local replay returns the SAME report id with +0 rows and +0 create events"),
            ("LP03-local-conflict-zero-delta",
             r3.status_code == 409 and c3 == c1,
             "a local same-key/different-body request is refused (409) and mutates nothing"),
        ]
        for cid, passed, detail in lp:
            ok_all = ok_all and passed
            rows.append({"check_id": cid, "result": "PASS" if passed else "FAIL", "detail": detail})
    except Exception as exc:  # noqa: BLE001
        import traceback
        ok_all = False
        rows.append({"check_id": "LP00-local-parity-harness",
                     "result": "FAIL", "detail": traceback.format_exc()[-800:]})
    finally:
        for k, v in env_saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        for mod in [m for m in list(sys.modules) if m.startswith("backend.app")]:
            del sys.modules[mod]
    return rows, ok_all


# ------------------------------------------------------------- live collection --
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http(url: str, seconds: int) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                if r.status == 200:
                    return True
        except Exception:  # noqa: BLE001
            time.sleep(0.5)
    return False


def _api_call(base: str, path: str, method: str = "GET", body=None, key: str | None = None):
    """Return (status, json_or_None). A non-2xx is reported with its status, not raised."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if key is not None:
        headers["Idempotency-Key"] = key
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw) if raw else None
        except Exception:  # noqa: BLE001
            return exc.code, None


def _collect_live() -> dict:
    import restricted_postgres_startup_guard as G

    obs: dict = {}
    G.checks = []

    def on_live(ctx):
        import psycopg

        scratch = Path(tempfile.mkdtemp(prefix="mr-idem-create-"))
        audit_key = ctx["base_env"].get("MONDAY_REPORT_AUDIT_HMAC_KEY") or os.urandom(24).hex()
        boot = ctx["boot_dsn"]

        def base_env(tenant_slug: str, appname: str) -> dict:
            env = {k: v for k, v in os.environ.items() if not k.startswith("MONDAY_REPORT_")}
            sub = scratch / tenant_slug
            for d in ("storage", "exports"):
                (sub / d).mkdir(parents=True, exist_ok=True)
            env.update({
                "CI": "true", "MONDAY_REPORT_CLIENT_DATA_MODE": "demo",
                "MONDAY_REPORT_REPOSITORY_BACKEND": "postgres",
                "MONDAY_REPORT_DATABASE_URL": f"{ctx['rt_dsn']}?application_name={appname}",
                "MONDAY_REPORT_AUDIT_HMAC_KEY": audit_key,
                "MONDAY_REPORT_TENANT_NAME": f"Idem Create {tenant_slug}",
                "MONDAY_REPORT_TENANT_SLUG": tenant_slug,
                "MONDAY_REPORT_STORAGE_ROOT": str(sub / "storage"),
                "MONDAY_REPORT_EXPORT_ROOT": str(sub / "exports"),
            })
            return env

        def start_api(env: dict, port: int, logname: str):
            return subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "backend.app.main:app",
                 "--host", "127.0.0.1", "--port", str(port)],
                cwd=str(ROOT), env=env,
                stdout=open(scratch / logname, "w"), stderr=subprocess.STDOUT,
            )

        def norm_count(slug: str) -> int:
            with psycopg.connect(boot, autocommit=True) as c:
                return c.execute(
                    f"select count(*) from {NORM_REPORTS_TABLE} where tenant_slug=%s",
                    (slug,)).fetchone()[0]

        def norm_ids(slug: str) -> list[str]:
            with psycopg.connect(boot, autocommit=True) as c:
                return [str(r[0]) for r in c.execute(
                    f"select id from {NORM_REPORTS_TABLE} where tenant_slug=%s", (slug,)).fetchall()]

        def idem_records(slug: str) -> list[dict]:
            with psycopg.connect(boot, autocommit=True) as c:
                return [
                    {"operation_id": r[0], "operation_kind": r[1], "request_hash": r[2],
                     "result_kind": r[3], "result_identifier": str(r[4]) if r[4] else None}
                    for r in c.execute(
                        "select operation_id, operation_kind, request_hash, result_kind, "
                        f"result_identifier from {IDEM_TABLE} where tenant_slug=%s", (slug,)).fetchall()]

        def audit_create_count(base: str) -> int:
            _s, logs = _api_call(base, "/audit-logs?limit=300")
            return sum(1 for e in (logs or []) if e.get("action") == CREATE_ACTION)

        procs: list = []
        try:
            # ---- Tenant A: IC01..IC04 ----
            env_a = base_env(TENANT_A, "idem-a")
            port_a = _free_port()
            api_a = start_api(env_a, port_a, "api_a.log")
            procs.append(api_a)
            base_a = f"http://127.0.0.1:{port_a}"
            if not _wait_http(base_a + "/health", 90):
                obs["fatal"] = "tenant A api not healthy"
                return
            ws_a = _api_call(base_a, "/workspaces")[1][0]["id"]
            body_a = {"workspace_id": ws_a, "period_start": "2026-08-10", "period_end": "2026-08-16"}
            body_a2 = dict(body_a, period_end="2026-08-17")
            key = "idem-create-key-aaaa1111"

            s1, j1 = _api_call(base_a, "/monday-reports", "POST", body_a, key=key)
            ic01 = {"status": s1, "id": (j1 or {}).get("id"),
                    "norm_count": norm_count(TENANT_A), "audit_create_count": audit_create_count(base_a)}

            s2, j2 = _api_call(base_a, "/monday-reports", "POST", body_a, key=key)
            ic02 = {"status": s2, "id": (j2 or {}).get("id"),
                    "norm_count": norm_count(TENANT_A), "audit_create_count": audit_create_count(base_a)}

            s3, _j3 = _api_call(base_a, "/monday-reports", "POST", body_a2, key=key)
            ic03 = {"status": s3,
                    "norm_count": norm_count(TENANT_A), "audit_create_count": audit_create_count(base_a)}

            recs = idem_records(TENANT_A)

            # ---- IC04: restart durability ----
            api_a.terminate()
            try:
                api_a.wait(timeout=15)
            except Exception:  # noqa: BLE001
                api_a.kill()
            procs.remove(api_a)
            port_a2 = _free_port()
            api_a2 = start_api(env_a, port_a2, "api_a2.log")
            procs.append(api_a2)
            base_a2 = f"http://127.0.0.1:{port_a2}"
            if not _wait_http(base_a2 + "/health", 90):
                obs["fatal"] = "restarted tenant A api not healthy"
                return
            s4, j4 = _api_call(base_a2, "/monday-reports", "POST", body_a, key=key)
            restart = {"status": s4, "id": (j4 or {}).get("id"), "norm_count": norm_count(TENANT_A)}

            norm_ids_final = norm_ids(TENANT_A)

            # ---- Tenant B: IC05 cross-tenant isolation (same key, same DB) ----
            env_b = base_env(TENANT_B, "idem-b")
            port_b = _free_port()
            api_b = start_api(env_b, port_b, "api_b.log")
            procs.append(api_b)
            base_b = f"http://127.0.0.1:{port_b}"
            if not _wait_http(base_b + "/health", 90):
                obs["fatal"] = "tenant B api not healthy"
                return
            ws_b = _api_call(base_b, "/workspaces")[1][0]["id"]
            body_b = {"workspace_id": ws_b, "period_start": "2026-08-10", "period_end": "2026-08-16"}
            s5, j5 = _api_call(base_b, "/monday-reports", "POST", body_b, key=key)
            ic05 = {"status": s5, "id": (j5 or {}).get("id"), "tenantA_norm_count": norm_count(TENANT_A)}

            obs["tenantA"] = {"ic01": ic01, "ic02": ic02, "ic03": ic03,
                              "restart": restart, "idem_records": recs, "norm_ids_final": norm_ids_final}
            obs["tenantB"] = {"ic05": ic05}
        except Exception:  # noqa: BLE001
            import traceback
            obs["fatal"] = traceback.format_exc()[-1500:]
        finally:
            for pr in procs:
                try:
                    pr.terminate()
                    pr.wait(timeout=15)
                except Exception:  # noqa: BLE001
                    pr.kill()

    G._ON_LIVE = on_live
    try:
        G.run_stack()
    finally:
        G._ON_LIVE = None
    if not obs:
        obs["fatal"] = "restricted stack never reached the live hook"
    return obs


def main() -> int:
    allow_unavailable = "--allow-unavailable" in sys.argv
    docker_ok = False
    try:
        docker_ok = subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
    except Exception:  # noqa: BLE001
        docker_ok = False

    fault_rows, faults_ok = _fault_battery()
    local_rows, local_ok = _local_parity()

    if docker_ok:
        obs = _collect_live()
        judged = _judge(obs)
        live_ok = judged["_ok"]
        certification = "passed" if (live_ok and faults_ok and local_ok) else "not_passed"
    else:
        obs = {"fatal": "docker_unavailable"}
        judged = {"checks": [{"check_id": cid, "result": "SKIPPED", "contract": contract}
                             for cid, contract in CHECK_IDS]}
        live_ok = False
        certification = "unavailable" if (allow_unavailable and faults_ok and local_ok) else "not_passed"

    out = {
        "guard": "report-create-idempotency",
        "claim_scope": "POST /monday-reports idempotency ONLY",
        "checks": judged["checks"],
        "local_parity_checks": local_rows,
        "fault_proofs": fault_rows,
        "observation": {k: v for k, v in obs.items() if k != "fatal"},
        "fatal": obs.get("fatal"),
        "summary": {
            "docker_available": docker_ok,
            "live_checks_passed": live_ok,
            "local_parity_passed": local_ok,
            "fault_proofs_passed": faults_ok,
            "certification": certification,
        },
    }
    print(json.dumps(out, indent=2, default=str))
    if certification == "passed":
        print("\nreport-create-idempotency: POST /monday-reports is replay-safe at the normalized "
              "authority; local backend agrees; torn state impossible.")
        return 0
    if certification == "unavailable":
        print("\nreport-create-idempotency: Docker unavailable -> UNAVAILABLE (never a false pass); "
              f"fault proofs {'green' if faults_ok else 'FAILED'}; local parity "
              f"{'green' if local_ok else 'FAILED'}.")
        return 0 if (faults_ok and local_ok) else 1
    print("\nreport-create-idempotency: NOT passed.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
