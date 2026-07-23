"""Guard for the fail-closed verification-isolation boundary.

The boundary (backend/app/verification_boundary.py) lets a provably-isolated
disposable verification stack execute the real client-mode request path instead of
receiving the release-readiness HTTP 423, WITHOUT bypassing auth/RBAC/tenant-authz/
verified-reviewer/RLS/idempotency and WITHOUT certifying readiness or approving GA.
Because it relaxes a client-data-safety lock, its safety rests on failing closed.

Most checks need no database: the environment predicate and the production-shaped
activation attacks are all rejected before any database connection is opened. The
POSITIVE activation path -- environment isolation PLUS the database-side attestation
row -- and the fail-closed audit are proven against a real disposable PostgreSQL
when MONDAY_REPORT_TEST_DATABASE_URL is set (recorded SKIP otherwise).

Run: ``python scripts/verification_boundary_guard.py``
"""
from __future__ import annotations

import ast
import json
import os
import re
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

checks: list[dict] = []


def record(name: str, ok: bool, detail: object = "", *, skipped: bool = False) -> None:
    checks.append({"name": name, "ok": bool(ok), "skipped": bool(skipped), "detail": detail})


# A loopback DSN pointing at a port with no server: the environment predicate passes
# but the attestation connection is refused immediately -> boundary inert. This is
# exactly the tunnel / "test"-named-production-db case: env looks isolated, but the
# database carries no attestation.
NO_SERVER_DSN = "postgresql://rt:pw@127.0.0.1:5999/monday_rt_test"

RUN_ID = "a" * 64  # a stand-in >=128-bit run id for environment-predicate tests

ISOLATED_ENV = {
    "MONDAY_REPORT_VERIFICATION_ISOLATION": "1",
    "MONDAY_REPORT_VERIFICATION_RUN_ID": RUN_ID,
    "MONDAY_REPORT_REPOSITORY_BACKEND": "postgres",
    "MONDAY_REPORT_DATABASE_URL": NO_SERVER_DSN,
    "MONDAY_REPORT_STATE_PATH": r"C:\scratch-verify\state\state.json",
    "MONDAY_REPORT_STORAGE_ROOT": r"C:\scratch-verify\storage",
    "MONDAY_REPORT_EXPORT_ROOT": r"C:\scratch-verify\exports",
    "MONDAY_REPORT_API_BASE": "http://127.0.0.1:8066",
    "MONDAY_REPORT_WEB_BASE": "http://127.0.0.1:5199",
}
_ENVKEYS = list(ISOLATED_ENV) + ["DATABASE_URL"]


def _apply(env: dict) -> None:
    for k in _ENVKEYS:
        os.environ.pop(k, None)
    os.environ.update(env)


def main() -> int:
    from backend.app import verification_boundary as vb

    def signals_all():
        return all(vb.isolation_signals().values())

    # -- environment predicate ------------------------------------------------
    _apply({})
    record("01 boundary is OFF with no configuration", vb.verification_execution_allowed() is False)

    _apply({"MONDAY_REPORT_VERIFICATION_ISOLATION": "1"})
    record("02 the opt-in marker ALONE never activates the boundary",
           vb.verification_execution_allowed() is False)

    # 03 the environment conjunction can hold yet the boundary stays OFF without the
    #    database attestation -- proving env signals (incl. a 'test' db-name) are
    #    necessary but NOT sufficient. This is the tunnel / test-named-prod-db defence.
    _apply(ISOLATED_ENV)
    record("03 full environment isolation WITHOUT the database attestation stays OFF",
           signals_all() is True and vb.verification_execution_allowed() is False,
           {"env_signals_all": signals_all(), "withheld_by": vb.verification_context()["withheld_by"]})

    # 04-11 removing ANY single environment signal drops the env predicate.
    axes = {
        "04 without the opt-in marker": {**ISOLATED_ENV, "MONDAY_REPORT_VERIFICATION_ISOLATION": "0"},
        "05 with a local/file backend": {**ISOLATED_ENV, "MONDAY_REPORT_REPOSITORY_BACKEND": "local_json"},
        "06 with a live API port 8000": {**ISOLATED_ENV, "MONDAY_REPORT_API_BASE": "http://127.0.0.1:8000"},
        "07 with a live web port 5173": {**ISOLATED_ENV, "MONDAY_REPORT_WEB_BASE": "http://127.0.0.1:5173"},
        "08 with a state root under .local_data":
            {**ISOLATED_ENV, "MONDAY_REPORT_STATE_PATH": r"C:\app\.local_data\state.json"},
        "09 with a storage root under .local_data":
            {**ISOLATED_ENV, "MONDAY_REPORT_STORAGE_ROOT": r"C:\app\.local_data\storage"},
        "10 with a relative root normalising into .local_data":
            {**ISOLATED_ENV, "MONDAY_REPORT_EXPORT_ROOT": r"C:\scratch\..\app\.local_data\exports"},
        "11 with an export root left unset": {k: v for k, v in ISOLATED_ENV.items()
                                              if k != "MONDAY_REPORT_EXPORT_ROOT"},
        "11b without a verification run id": {k: v for k, v in ISOLATED_ENV.items()
                                             if k != "MONDAY_REPORT_VERIFICATION_RUN_ID"},
        "11c with a too-short (low-entropy) run id":
            {**ISOLATED_ENV, "MONDAY_REPORT_VERIFICATION_RUN_ID": "short"},
    }
    for name, env in axes.items():
        _apply(env)
        record(f"{name} drops the environment predicate", signals_all() is False,
               {"withheld_by": vb.verification_context()["withheld_by"]})

    # -- DSN parsing attacks: only a clean single-host loopback TCP URL qualifies --
    dsn_cases = {
        "12 unix-domain socket DSN": "postgresql://rt:pw@/monday_rt_test?host=/var/run/postgresql",
        "13 keyword-form libpq DSN": "host=127.0.0.1 port=5432 dbname=monday_rt_test user=rt",
        "14 multi-host DSN": "postgresql://rt:pw@127.0.0.1,10.0.0.5:5432/monday_rt_test",
        "15 URL-encoded host obfuscation": "postgresql://rt:pw@%31%32%37%2e0%2e0%2e1:5432/monday_rt_test",
        "16 non-loopback remote host": "postgresql://rt:pw@db.prod.internal:5432/monday_rt_test",
        "17 host= query redirecting the connection": "postgresql://rt:pw@127.0.0.1:5432/monday_rt_test?host=10.0.0.9",
        "18 non-postgres scheme": "mysql://rt:pw@127.0.0.1:5432/monday_rt_test",
        "19 loopback host but no TCP port": "postgresql://rt:pw@127.0.0.1/monday_rt_test",
    }
    for name, dsn in dsn_cases.items():
        record(f"{name} is rejected by loopback-TCP DSN parsing", vb._loopback_tcp_dsn(dsn) is False,
               {"dsn_form": name})
    record("20 a clean loopback IPv4 TCP DSN is accepted by the parser",
           vb._loopback_tcp_dsn("postgresql://rt:pw@127.0.0.1:5432/monday_rt_test") is True)
    record("21 a clean IPv6 loopback TCP DSN is accepted by the parser",
           vb._loopback_tcp_dsn("postgresql://rt:pw@[::1]:5432/monday_rt_test") is True)
    record("21b _is_local_server_addr accepts loopback/private (incl. container IPs), rejects public",
           vb._is_local_server_addr("127.0.0.1") and vb._is_local_server_addr("::1")
           and vb._is_local_server_addr("172.17.0.4") and vb._is_local_server_addr("10.0.0.5")
           and not vb._is_local_server_addr("8.8.8.8") and not vb._is_local_server_addr("93.184.216.34")
           and not vb._is_local_server_addr(None))

    # -- path canonicalisation ------------------------------------------------
    record("22 a root whose canonical path is under .local_data is rejected",
           vb._isolated_root(r"C:\app\.local_data\storage") is False)
    record("23 a relative root normalising into .local_data is rejected",
           vb._isolated_root(r"C:\scratch\..\app\.local_data\x") is False)
    record("24 an unset root is rejected", vb._isolated_root(None) is False)
    record("25 an isolated scratch root is accepted",
           vb._isolated_root(str(Path(os.environ.get("TEMP", ".")) / "mr-verify-ok")) is True)

    # -- fully production-shaped configuration can never activate --------------
    _apply({
        "MONDAY_REPORT_VERIFICATION_ISOLATION": "1",
        "MONDAY_REPORT_REPOSITORY_BACKEND": "postgres",
        "MONDAY_REPORT_DATABASE_URL": "postgresql://app:pw@prod-db.internal:5432/monday_production_test",
        "MONDAY_REPORT_STATE_PATH": r"C:\app\.local_data\state.json",
        "MONDAY_REPORT_STORAGE_ROOT": r"C:\app\.local_data\storage",
        "MONDAY_REPORT_EXPORT_ROOT": r"C:\app\.local_data\exports",
        "MONDAY_REPORT_API_BASE": "http://0.0.0.0:8000",
        "MONDAY_REPORT_WEB_BASE": "http://0.0.0.0:5173",
    })
    record("26 a production-shaped environment (even a 'test'-suffixed db name) can never activate",
           vb.verification_execution_allowed() is False)

    # -- attestation helper fails closed without a reachable disposable database --
    record("27 database_attestation_present is False for a non-loopback DSN",
           vb.database_attestation_present("postgresql://rt:pw@db.prod:5432/x_test") is False)
    _apply(ISOLATED_ENV)
    record("28 database_attestation_present is False when the database is unreachable",
           vb.database_attestation_present() is False)

    # -- redaction + request-independence + wiring ----------------------------
    _apply(ISOLATED_ENV)
    blob = json.dumps(vb.verification_context())
    leaked = [t for t in ("postgresql://", "127.0.0.1", "5999", "pw@", "scratch-verify", "c:\\", "monday_rt_test")
              if t in blob.lower()]
    record("29 the audit/evidence summary leaks no DSN, host, port, credential or path",
           not leaked, {"leaked": leaked})

    src = (ROOT / "backend" / "app" / "verification_boundary.py").read_text(encoding="utf-8")
    reads_request = any(
        isinstance(n, ast.Attribute) and n.attr in {"headers", "query_params", "cookies", "body"}
        for n in ast.walk(ast.parse(src))
    )
    record("30 the boundary consults only process config + the database, never request state",
           not reads_request)

    main_src = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
    gate = main_src.split("def require_client_data_ready", 1)[1].split("\ndef ", 1)[0]
    record("31 require_client_data_ready consults verification_context and still raises 423 otherwise",
           "verification_context()" in gate and "status_code=423" in gate)
    # The relaxation audit must be FAIL-CLOSED: store.audit (not _best_effort_audit)
    # inside a try that raises on failure, before returning.
    relax = gate.split("verification_isolation_active", 1)[1].split("return", 1)[0] if "verification_isolation_active" in gate else ""
    record("32 the relaxation is audited FAIL-CLOSED (store.audit in try/except -> 503, never best-effort)",
           "store.audit(" in relax and "except" in relax and "status_code=503" in relax
           and "_best_effort_audit" not in relax,
           {"fail_closed_audit": "store.audit(" in relax and "except" in relax})

    # -- run-scoped attestation lifecycle + privilege proof (real PostgreSQL) ---
    dsn = os.environ.get("MONDAY_REPORT_TEST_DATABASE_URL")
    if not dsn or not vb._loopback_tcp_dsn(dsn):
        for n in ("33 run-scoped activation", "34 wrong run id inert", "35 expired inert",
                  "36 reinstated active", "37 runtime SELECT allowed", "38 runtime write denied",
                  "39 runtime TRUNCATE/DROP denied", "40 removal deactivates"):
            record(n, True, "no loopback MONDAY_REPORT_TEST_DATABASE_URL provided", skipped=True)
    else:
        import psycopg
        run_id = secrets.token_hex(32)
        db = vb._expected_db_name(dsn)

        def clean():
            with psycopg.connect(dsn, autocommit=True) as c:
                c.execute(f"drop table if exists {vb.ATTESTATION_QUALIFIED} cascade")

        clean()
        env = {**ISOLATED_ENV, "MONDAY_REPORT_DATABASE_URL": dsn, "MONDAY_REPORT_VERIFICATION_RUN_ID": run_id}
        _apply(env)
        before = vb.verification_execution_allowed()
        vb.install_database_attestation(dsn, run_id, ttl_seconds=3600)
        after = vb.verification_execution_allowed()
        record("33 activation requires the installed run-scoped attestation",
               before is False and after is True, {"before": before, "after": after})

        _apply({**env, "MONDAY_REPORT_VERIFICATION_RUN_ID": secrets.token_hex(32)})
        record("34 a DIFFERENT run id does not satisfy the attestation",
               vb.verification_execution_allowed() is False)

        _apply(env)
        vb.install_database_attestation(dsn, run_id, ttl_seconds=-10)
        record("35 an EXPIRED attestation does not activate the boundary",
               vb.verification_execution_allowed() is False)

        vb.install_database_attestation(dsn, run_id, ttl_seconds=3600)
        record("36 activation holds again after reinstalling a fresh attestation",
               vb.verification_execution_allowed() is True)

        # Privilege proof: a restricted runtime role may SELECT but cannot write/DDL.
        role = f"vbnd_rt_{secrets.token_hex(4)}"
        pw = secrets.token_urlsafe(18)
        with psycopg.connect(dsn, autocommit=True) as c:
            c.execute(f"drop role if exists {role}")
            c.execute(f"create role {role} login nosuperuser nobypassrls nocreatedb nocreaterole password '{pw}'")
            c.execute(f"grant connect on database {db} to {role}")
            c.execute(f"grant usage on schema {vb.ATTESTATION_SCHEMA} to {role}")
            c.execute(f"grant select on {vb.ATTESTATION_QUALIFIED} to {role}")
        rt_dsn = re.sub(r"//[^@/]+@", f"//{role}:{pw}@", dsn)

        def rt_denied(sql: str) -> bool:
            try:
                with psycopg.connect(rt_dsn, autocommit=True) as c:
                    c.execute(sql)
                return False
            except Exception:  # noqa: BLE001 - any refusal counts as denied
                return True

        with psycopg.connect(rt_dsn, autocommit=True) as c:
            sel = c.execute(f"select count(*) from {vb.ATTESTATION_QUALIFIED}").fetchone()[0]
        record("37 the restricted runtime role MAY SELECT the attestation", sel is not None, {"rows": sel})
        record("38 the restricted runtime role CANNOT INSERT/UPDATE/DELETE the attestation",
               rt_denied(f"insert into {vb.ATTESTATION_QUALIFIED}(run_id_hash,expires_at,purpose) values ('z',now(),'z')")
               and rt_denied(f"update {vb.ATTESTATION_QUALIFIED} set purpose='y'")
               and rt_denied(f"delete from {vb.ATTESTATION_QUALIFIED}"))
        record("39 the restricted runtime role CANNOT TRUNCATE or DROP the attestation",
               rt_denied(f"truncate {vb.ATTESTATION_QUALIFIED}")
               and rt_denied(f"drop table {vb.ATTESTATION_QUALIFIED}"))
        with psycopg.connect(dsn, autocommit=True) as c:
            c.execute(f"drop owned by {role}")  # revoke its grants before dropping
            c.execute(f"drop role if exists {role}")

        clean()
        _apply(env)
        record("40 removing the attestation deactivates the boundary",
               vb.verification_execution_allowed() is False)

        # 41 CLONE-TO-ANOTHER-SERVER (Part B): copy the attestation row verbatim into a
        # SECOND server with the SAME database name and the SAME run id, unexpired. The
        # server-instance fingerprint must reject it.
        dsn_b = os.environ.get("MONDAY_REPORT_TEST_DATABASE_URL_B")
        if dsn_b and vb._loopback_tcp_dsn(dsn_b) and vb._expected_db_name(dsn_b) == db:
            vb.install_database_attestation(dsn, run_id, ttl_seconds=3600)
            with psycopg.connect(dsn, autocommit=True) as ca:
                cloned = ca.execute(
                    f"select run_id_hash, server_fingerprint, created_at, expires_at, purpose "
                    f"from {vb.ATTESTATION_QUALIFIED}").fetchone()
            with psycopg.connect(dsn_b, autocommit=True) as cb:
                cb.execute(f"drop table if exists {vb.ATTESTATION_QUALIFIED} cascade")
                cb.execute(
                    f"create table {vb.ATTESTATION_QUALIFIED}(run_id_hash text primary key, "
                    "server_fingerprint text not null, created_at timestamptz not null default now(), "
                    "expires_at timestamptz not null, purpose text not null)")
                cb.execute(f"insert into {vb.ATTESTATION_QUALIFIED} values (%s,%s,%s,%s,%s)", cloned)
            _apply({**ISOLATED_ENV, "MONDAY_REPORT_DATABASE_URL": dsn_b,
                    "MONDAY_REPORT_VERIFICATION_RUN_ID": run_id})
            on_clone = vb.verification_execution_allowed()
            record("41 an attestation CLONED to another server does not activate (server-instance binding)",
                   on_clone is False, {"activated_on_clone": on_clone})
            with psycopg.connect(dsn_b, autocommit=True) as cb:
                cb.execute(f"drop table if exists {vb.ATTESTATION_QUALIFIED} cascade")
            clean()
        else:
            record("41 clone-to-another-server rejection", True,
                   "no MONDAY_REPORT_TEST_DATABASE_URL_B (same db name)", skipped=True)

    passed = [c for c in checks if c["ok"] and not c["skipped"]]
    skipped = [c for c in checks if c["skipped"]]
    failed = [c for c in checks if not c["ok"]]
    print(json.dumps({"checks": checks,
                      "summary": {"passed": len(passed), "skipped": len(skipped), "failed": len(failed)}},
                     indent=2, default=str))
    if failed:
        print(f"\nVerification-boundary guard FAILED: {len(failed)} failing check(s).")
        for c in failed:
            print(f"  FAIL: {c['name']} -> {c['detail']}")
        return 1
    tail = f" ({len(skipped)} skipped: no disposable PostgreSQL)" if skipped else ""
    print(f"\nVerification-boundary guard passed: {len(passed)} check(s).{tail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
