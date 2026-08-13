"""audit:report-create-persistence -- durable Monday-report creation on the restricted
PostgreSQL runtime, measured at the NORMALIZED AUTHORITY.

Background (2026-08-13): a "confirmed lost write" was reported against the PostgreSQL
snapshot path -- POST /monday-reports answered 201, the audit chain recorded
monday_report.create, GET served the report, but the tenant's
``monday_report_state_snapshots`` payload kept ``"monday_reports": []``. Live
reproduction against the runner-owned restricted stack DISPROVED the loss: the created
row is durably committed to ``monday_report_norm_reports`` (the write/read authority for
migrated entities on this backend, linked to its audit event in the same transaction),
and the snapshot key is EMPTY BY DESIGN -- ``PostgresStateStore.NORMALIZED_ENTITY_KEYS``
blanks migrated entities from the snapshot payload and stamps the
``normalized_authority`` marker, so counting ``payload->'monday_reports'`` measures a
deliberately-empty projection, not the durable state. This guard pins BOTH halves so
neither can silently regress:

  * the mutation IS durable at the authority location before the response is trusted
    (a real lost write -- 201 + audit event + NO normalized row -- fails RC04/RC06); and
  * the single-authority invariant holds (a dual-write of reports back into the
    snapshot payload, or a dropped marker, fails RC07/RC08).

Live path (Docker): reuses ``restricted_postgres_startup_guard.run_stack`` -- the
runner-owned disposable pgvector container, migrations 0001-0007, restricted runtime
login -- boots a demo-mode API on the postgres backend, POSTs /monday-reports with no
browser and no concurrency, observes API + snapshot + normalized rows, then RESTARTS the
API process and re-observes (this stack's custom tenant seeds with ``demo_seed=false``,
so the demo self-wipe does not run and restart durability is a valid claim here).

Judgment is a PURE function over the collected observation, and a Docker-free fault
battery drives it with mutated observations to prove every refusal is load-bearing
(including F01, the exact reported lost-write signature). ``--allow-unavailable``
reports UNAVAILABLE without Docker (never a false pass); the fault battery still runs.

CLAIM SCOPE: report-create-persistence-only. Not tenant-authorization evidence, not a
readiness proof, not the full mutation matrix (audit:restricted-postgres-runtime-*).
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
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

STATE_TABLE = "monday_report_state_snapshots"
NORM_REPORTS_TABLE = "monday_report_norm_reports"
TENANT_SLUG = "reportcreate"

CHECK_IDS = [
    ("RC01-api-create-201", "the POST answered with a created report id and a draft/review status"),
    ("RC02-api-list-serves-created", "GET /monday-reports serves the created report"),
    ("RC03-audit-chain-has-create-event", "the audit chain records monday_report.create"),
    ("RC04-normalized-row-durable", "the created id is committed to monday_report_norm_reports BEFORE any restart"),
    ("RC05-normalized-status-matches", "the normalized row carries the API-reported status"),
    ("RC06-normalized-row-audit-linked", "the normalized row references a monday_report.create audit event id"),
    ("RC07-snapshot-key-blank-by-design", "the snapshot payload keeps monday_reports EMPTY (no dual write)"),
    ("RC08-authority-marker-covers-reports", "the normalized_authority marker lists monday_reports"),
    ("RC09-restart-list-serves-created", "a FRESH API process (empty memory) still serves the report"),
    ("RC10-restart-normalized-row-present", "the normalized row survives the process restart"),
]


def _judge(obs: dict) -> dict:
    """PURE judgment over one observation dict -> checks + certification. Extracted so the
    fault battery can drive it with mutated observations and confirm each gate refuses."""
    created = obs.get("created") or {}
    cid = created.get("id")
    norm = obs.get("norm_reports") or []
    norm_by_id = {row.get("id"): row for row in norm}
    row = norm_by_id.get(cid)
    snapshot = obs.get("snapshot") or {}
    marker = snapshot.get("normalized_authority_marker") or {}
    restart = obs.get("restart") or {}
    create_audit_ids = set(obs.get("audit_create_event_ids") or [])

    results = {
        "RC01-api-create-201": bool(cid) and created.get("status") in {"draft", "review"},
        "RC02-api-list-serves-created": any(item.get("id") == cid for item in obs.get("api_list") or []),
        "RC03-audit-chain-has-create-event": bool(create_audit_ids),
        "RC04-normalized-row-durable": row is not None,
        "RC05-normalized-status-matches": bool(row) and row.get("status") == created.get("status"),
        "RC06-normalized-row-audit-linked": bool(row) and row.get("audit_event_id") in create_audit_ids,
        "RC07-snapshot-key-blank-by-design": snapshot.get("monday_reports_len") == 0,
        "RC08-authority-marker-covers-reports": "monday_reports" in (marker.get("entities") or []),
        "RC09-restart-list-serves-created": any(item.get("id") == cid for item in restart.get("api_list") or []),
        "RC10-restart-normalized-row-present": cid in (restart.get("norm_report_ids") or []),
    }
    checks = [
        {"check_id": check_id, "result": "PASS" if results[check_id] else "FAIL", "contract": contract}
        for check_id, contract in CHECK_IDS
    ]
    ok = not obs.get("fatal") and all(results.values())
    return {"checks": checks, "_ok": ok}


def _canonical_obs() -> dict:
    """A synthetic fully-valid observation for the Docker-free fault battery."""
    rid = "00000000-0000-0000-0000-00000000c0de"
    aid = "00000000-0000-0000-0000-00000000a0d1"
    return {
        "created": {"id": rid, "status": "draft"},
        "api_list": [{"id": rid, "status": "draft"}],
        "audit_create_event_ids": [aid],
        "snapshot": {
            "monday_reports_len": 0,
            "normalized_authority_marker": {
                "version": 2,
                "entities": ["monday_reports", "field_corrections", "validation_tasks"],
            },
        },
        "norm_reports": [{"id": rid, "status": "draft", "audit_event_id": aid}],
        "restart": {"api_list": [{"id": rid, "status": "draft"}], "norm_report_ids": [rid]},
    }


def _fault_battery() -> tuple[list[dict], bool]:
    """Prove the judgment refuses each forged/lost observation (and is not always-fail)."""

    def refuses(mutate) -> bool:
        obs = copy.deepcopy(_canonical_obs())
        mutate(obs)
        return not _judge(obs)["_ok"]

    proofs = [
        ("F00-valid-observation-certifies", _judge(_canonical_obs())["_ok"],
         "a complete valid observation certifies (the gates are not always-fail)"),
        ("F01-lost-write-signature-refused",
         refuses(lambda o: o.__setitem__("norm_reports", [])),
         "201 + audit event + NO normalized row -- the exact reported lost-write signature -- is refused"),
        ("F02-normalized-id-mismatch-refused",
         refuses(lambda o: o["norm_reports"][0].__setitem__("id", "other")),
         "a normalized row under a different id does not stand in for the created report"),
        ("F03-unlinked-audit-refused",
         refuses(lambda o: o["norm_reports"][0].__setitem__("audit_event_id", None)),
         "a normalized row with no monday_report.create audit linkage is refused"),
        ("F04-dual-write-refused",
         refuses(lambda o: o["snapshot"].__setitem__("monday_reports_len", 1)),
         "reports re-materialized into the snapshot payload (dual authority) are refused"),
        ("F05-dropped-marker-refused",
         refuses(lambda o: o["snapshot"]["normalized_authority_marker"].__setitem__("entities", [])),
         "a normalized_authority marker that stops covering monday_reports is refused"),
        ("F06-restart-loss-refused",
         refuses(lambda o: o.__setitem__("restart", {"api_list": [], "norm_report_ids": []})),
         "a report that vanishes across a process restart is refused"),
        ("F07-audit-only-persistence-refused",
         refuses(lambda o: o.__setitem__("audit_create_event_ids", [])),
         "an observation with no monday_report.create audit event is refused"),
    ]
    rows = [{"proof_id": pid, "result": "PASS" if ok else "FAIL", "detail": detail}
            for pid, ok, detail in proofs]
    return rows, all(ok for _, ok, _ in proofs)


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


def _api_json(base: str, path: str, method: str = "GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def _collect_live() -> dict:
    import restricted_postgres_startup_guard as G

    obs: dict = {}
    G.checks = []

    def on_live(ctx):
        import psycopg

        scratch = Path(tempfile.mkdtemp(prefix="mr-report-create-"))
        for sub in ("storage", "exports"):
            (scratch / sub).mkdir(parents=True, exist_ok=True)
        audit_key = ctx["base_env"].get("MONDAY_REPORT_AUDIT_HMAC_KEY") or os.urandom(24).hex()
        env = {k: v for k, v in os.environ.items() if not k.startswith("MONDAY_REPORT_")}
        env.update({
            "CI": "true", "MONDAY_REPORT_CLIENT_DATA_MODE": "demo",
            "MONDAY_REPORT_REPOSITORY_BACKEND": "postgres",
            "MONDAY_REPORT_DATABASE_URL": f"{ctx['rt_dsn']}?application_name=report-create-guard",
            "MONDAY_REPORT_AUDIT_HMAC_KEY": audit_key,
            "MONDAY_REPORT_TENANT_NAME": "Report Create Guard",
            "MONDAY_REPORT_TENANT_SLUG": TENANT_SLUG,
            "MONDAY_REPORT_STORAGE_ROOT": str(scratch / "storage"),
            "MONDAY_REPORT_EXPORT_ROOT": str(scratch / "exports"),
        })
        boot = ctx["boot_dsn"]

        def start_api(port: int, logname: str):
            return subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "backend.app.main:app",
                 "--host", "127.0.0.1", "--port", str(port)],
                cwd=str(ROOT), env=env,
                stdout=open(scratch / logname, "w"), stderr=subprocess.STDOUT,
            )

        port = _free_port()
        api = start_api(port, "api.log")
        base = f"http://127.0.0.1:{port}"
        try:
            if not _wait_http(base + "/health", 90):
                obs["fatal"] = "api not healthy"
                return
            ws = _api_json(base, "/workspaces")[0]["id"]
            created = _api_json(base, "/monday-reports", method="POST", body={
                "workspace_id": ws, "period_start": "2026-08-10", "period_end": "2026-08-16"})
            obs["created"] = {"id": created.get("id"), "status": created.get("status")}
            obs["api_list"] = [{"id": i.get("id"), "status": i.get("status")}
                               for i in _api_json(base, "/monday-reports")]
            audit = _api_json(base, "/audit-logs?limit=80")
            obs["audit_create_event_ids"] = [
                str(e.get("id")) for e in audit if e.get("action") == "monday_report.create"]
            with psycopg.connect(boot, autocommit=True) as c:
                row = c.execute(
                    "select coalesce(jsonb_array_length(payload->'monday_reports'), -1), "
                    "payload->'normalized_authority' "
                    f"from {STATE_TABLE} where tenant_slug=%s", (TENANT_SLUG,)).fetchone()
                obs["snapshot"] = {
                    "monday_reports_len": row[0] if row else None,
                    "normalized_authority_marker": row[1] if row else None,
                }
                obs["norm_reports"] = [
                    {"id": str(r[0]), "status": r[1], "audit_event_id": str(r[2]) if r[2] else None}
                    for r in c.execute(
                        f"select id, status, audit_event_id from {NORM_REPORTS_TABLE} "
                        "where tenant_slug=%s", (TENANT_SLUG,)).fetchall()]
            # Restart durability: kill the process (drop every in-memory dict),
            # boot a fresh one, and observe API + normalized rows again.
            api.terminate()
            try:
                api.wait(timeout=15)
            except Exception:  # noqa: BLE001
                api.kill()
            port2 = _free_port()
            api2 = start_api(port2, "api2.log")
            base2 = f"http://127.0.0.1:{port2}"
            try:
                if not _wait_http(base2 + "/health", 90):
                    obs["fatal"] = "restarted api not healthy"
                    return
                relisted = _api_json(base2, "/monday-reports")
                with psycopg.connect(boot, autocommit=True) as c:
                    ids = [str(r[0]) for r in c.execute(
                        f"select id from {NORM_REPORTS_TABLE} where tenant_slug=%s",
                        (TENANT_SLUG,)).fetchall()]
                obs["restart"] = {
                    "api_list": [{"id": i.get("id"), "status": i.get("status")} for i in relisted],
                    "norm_report_ids": ids,
                }
            finally:
                try:
                    api2.terminate()
                    api2.wait(timeout=15)
                except Exception:  # noqa: BLE001
                    api2.kill()
        except Exception:  # noqa: BLE001
            import traceback

            obs["fatal"] = traceback.format_exc()[-1200:]
        finally:
            try:
                api.terminate()
                api.wait(timeout=15)
            except Exception:  # noqa: BLE001
                api.kill()

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

    if docker_ok:
        obs = _collect_live()
        judged = _judge(obs)
        live_ok = judged["_ok"]
        certification = "passed" if (live_ok and faults_ok) else "not_passed"
    else:
        obs = {"fatal": "docker_unavailable"}
        judged = {"checks": [{"check_id": cid, "result": "SKIPPED", "contract": contract}
                             for cid, contract in CHECK_IDS]}
        live_ok = False
        certification = "unavailable" if allow_unavailable else "not_passed"

    out = {
        "guard": "report-create-persistence",
        "checks": judged["checks"],
        "fault_proofs": fault_rows,
        "observation": {k: v for k, v in obs.items() if k != "fatal"},
        "fatal": obs.get("fatal"),
        "summary": {
            "claim_scope": "report-create-persistence-only",
            "eligible_for_tenant_evidence": False,
            "eligible_for_readiness": False,
            "docker_available": docker_ok,
            "live_checks_passed": live_ok,
            "fault_proofs_passed": faults_ok,
            "certification": certification,
        },
    }
    print(json.dumps(out, indent=2, default=str))
    if certification == "passed":
        print("\nreport-create-persistence: durable at the normalized authority; "
              "single-authority invariant intact.")
        return 0
    if certification == "unavailable":
        print("\nreport-create-persistence: Docker unavailable -> UNAVAILABLE (never a false pass); "
              f"fault proofs {'green' if faults_ok else 'FAILED'}.")
        return 0 if faults_ok else 1
    print("\nreport-create-persistence: NOT passed.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
