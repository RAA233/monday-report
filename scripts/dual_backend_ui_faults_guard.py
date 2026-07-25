"""audit:dual-backend-ui-faults -- non-vacuity battery for the dual-backend UI certification.

Drives the certifier's REAL judgment function (dual_backend_ui_guard.judge) with a valid synthetic pair of
backend observations (confirmed to certify first), then mutates each dimension and confirms the certifier
REFUSES to certify. Plus structural source checks proving the real certification path launches a real
browser + real external API + real built frontend (never TestClient / mocked business API / route
interception / static-page-only reachability).

Docker-free and deterministic (synthetic observations); the real certification path itself uses real
processes. HONEST scope:
  claim_scope = dual-backend-ui-faults-only
  eligible_for_tenant_evidence = false / eligible_for_readiness = false / production_parity = false
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import dual_backend_ui_guard as U  # noqa: E402

checks: list[dict] = []


def rec(cid, ok, desc, level="predicate/unit mutation"):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level})


def valid_backend(backend):
    scen = [{"check_id": sid, "result": "PASS"} for sid in U.EXPECTED_SCENARIOS]
    counters = {k: 0 for k in ["console_error_count", "uncaught_exception_count", "failed_business_request_count",
                               "normal_HTTP_423_count", "normal_HTTP_500_count", "normal_HTTP_503_count"]}
    db = {"uploaded_files": 1, "parsed_documents": 1, "benchmark_measurements": 1}
    if backend == "postgres":
        identity = {"store_class": "PostgresStateStore", "repository_backend": "postgres",
                    "session_user_is_restricted_login": True, "runtime_not_superuser": True,
                    "runtime_not_bypassrls": True, "runtime_not_table_owner": True,
                    "rls_enabled_and_forced": True, "local_fallback_impossible": True}
    else:
        identity = {"store_class": "LocalStateStore(local/file JSON snapshot)", "repository_backend": "local",
                    "postgres_connection": "absent", "isolated_roots_only": True}
    return {"backend": backend, "fatal": None, "scenarios": scen, "counters": counters,
            "identity": identity, "db_postconditions": db}


def certified(local, pg):
    out = U.judge(local, pg, docker_ok=True)
    return out.get("_ok") is True and out["summary"]["certification"] == "passed"


def refuses(mutate):
    local, pg = valid_backend("local"), valid_backend("postgres")
    mutate(local, pg)
    return not certified(local, pg)


def run() -> int:
    # baseline: a valid pair certifies (gates are not always-fail)
    rec("FB00", certified(valid_backend("local"), valid_backend("postgres")),
        "a complete valid dual-backend observation certifies (gates are not always-fail)",
        level="structural source check")

    # ---- per-dimension refusal mutations ----
    rec("DF01 browser-not-launched", refuses(lambda l, p: l.__setitem__("fatal", "browser launch failed")),
        "a backend whose browser/run aborted (fatal) is not certified")
    rec("DF02 frontend-static-placeholder",
        refuses(lambda l, p: l["scenarios"].__setitem__(0, {"check_id": "UI01-bootstrap", "result": "FAIL"})),
        "a bootstrap FAIL (frontend not really connected to the API) is not certified")
    rec("DF05 local-uses-postgres", refuses(lambda l, p: l["identity"].__setitem__("repository_backend", "postgres")),
        "the local backend accidentally using PostgreSQL is not certified")
    rec("DF06a pg-falls-back-local", refuses(lambda l, p: p["identity"].__setitem__("store_class", "LocalStateStore")),
        "the PostgreSQL run falling back to a local store is not certified")
    rec("DF06b pg-session-not-restricted",
        refuses(lambda l, p: p["identity"].__setitem__("session_user_is_restricted_login", False)),
        "the PostgreSQL run whose session is NOT the restricted login is not certified")
    rec("DF06c pg-superuser", refuses(lambda l, p: p["identity"].__setitem__("runtime_not_superuser", False)),
        "the PostgreSQL run connecting as a superuser is not certified")
    rec("DF06d pg-bypassrls", refuses(lambda l, p: p["identity"].__setitem__("runtime_not_bypassrls", False)),
        "the PostgreSQL run with BYPASSRLS is not certified")
    rec("DF06e pg-rls-not-forced", refuses(lambda l, p: p["identity"].__setitem__("rls_enabled_and_forced", False)),
        "the PostgreSQL run without RLS enabled+forced is not certified")
    rec("DF07 renamed/unknown-scenario-id",
        refuses(lambda l, p: l["scenarios"].__setitem__(0, {"check_id": "UI01-renamed-away", "result": "PASS"})),
        "a renamed/unknown scenario id (so an expected canonical id is absent) is caught as missing and "
        "is not certified -- an all-PASS list of the WRONG ids cannot certify")
    rec("DF08 cross-tenant-content",
        refuses(lambda l, p: l["scenarios"].__setitem__(1, {"check_id": "UI02-tenant-presentation", "result": "FAIL"})),
        "wrong/cross-tenant content in the tenant-presentation scenario is not certified")
    rec("DF09 upload-success-without-db",
        refuses(lambda l, p: l["db_postconditions"].__setitem__("uploaded_files", 0)),
        "an upload UI success with NO committed database row is not certified")
    rec("DF09b parse-success-without-db",
        refuses(lambda l, p: p["db_postconditions"].__setitem__("parsed_documents", 0)),
        "a parsed-document postcondition of zero after an upload is not certified")
    rec("DF10 benchmarking-success-without-db",
        refuses(lambda l, p: p["db_postconditions"].__setitem__("benchmark_measurements", 0)),
        "a benchmarking UI success with NO committed measurement row is not certified")
    rec("DF11 resolved-download-missing",
        refuses(lambda l, p: l["scenarios"].__setitem__(7, {"check_id": "UI08-draft-download", "result": "FAIL"})),
        "a missing/empty browser download is not certified")
    rec("DF12 console-error-ignored",
        refuses(lambda l, p: p["counters"].__setitem__("console_error_count", 1)),
        "a console error is not ignored")
    rec("DF13 uncaught-exception-ignored",
        refuses(lambda l, p: p["counters"].__setitem__("uncaught_exception_count", 1)),
        "an uncaught exception is not ignored")
    rec("DF14 http-423-ignored", refuses(lambda l, p: p["counters"].__setitem__("normal_HTTP_423_count", 1)),
        "a normal HTTP 423 is not ignored")
    rec("DF15 http-500-ignored", refuses(lambda l, p: p["counters"].__setitem__("normal_HTTP_500_count", 1)),
        "a normal HTTP 500 is not ignored")
    rec("DF16 http-503-ignored", refuses(lambda l, p: p["counters"].__setitem__("normal_HTTP_503_count", 1)),
        "a normal HTTP 503 is not ignored")
    rec("DF17 failed-business-request-ignored",
        refuses(lambda l, p: p["counters"].__setitem__("failed_business_request_count", 1)),
        "a failed business request is not ignored")
    rec("DF18 backend-scenario-omitted", refuses(lambda l, p: p["scenarios"].pop()),
        "one backend omitting a canonical scenario is not certified")
    rec("DF19 local-pg-outcome-mismatch",
        refuses(lambda l, p: p["scenarios"].__setitem__(2, {"check_id": "UI03-navigation", "result": "FAIL"})),
        "a local/PostgreSQL outcome mismatch is not certified")

    # secret-in-observation -> secret scan fails certification
    def leak(l, p):
        p["identity"]["debug_dsn"] = "postgresql://leak:pw@127.0.0.1:5432/db"
    rec("DF20 secret-in-observation", refuses(leak),
        "a DSN/secret appearing anywhere in the observation fails the secret scan and is not certified")

    # ---- Docker-unavailable never certifies the PG backend ----
    out_unavail = U.judge(valid_backend("local"),
                          {"backend": "postgres", "fatal": "docker_unavailable", "scenarios": [],
                           "counters": {}, "unavailable": True}, docker_ok=False)
    rec("DF21 docker-unavailable-not-certified",
        out_unavail["summary"]["restricted_postgres_backend_certified"] is False and out_unavail["_ok"] is False,
        "when Docker is unavailable the PostgreSQL backend is never certified and the run is not passed")

    # ---- structural source: real browser + real API + real frontend; no mocks/interception ----
    scen_src = (ROOT / "scripts" / "dual_backend_ui_scenarios.mjs").read_text(encoding="utf-8")
    guard_src = (ROOT / "scripts" / "dual_backend_ui_guard.py").read_text(encoding="utf-8")
    rec("DF22 real-browser-no-mock",
        "chromium.launch(" in scen_src and "page.route(" not in scen_src and "route.fulfill(" not in scen_src
        and "TestClient(" not in scen_src,
        "the scenario runner launches a REAL Chrome and never intercepts/mocks a business route",
        level="structural source check")
    rec("DF23 real-external-api-and-frontend",
        'subprocess.Popen([sys.executable, "-m", "uvicorn"' in guard_src
        and '"build"' in guard_src and '"preview"' in guard_src
        and "str(SCEN)" in guard_src and "TestClient(" not in guard_src,
        "the certifier launches a REAL external uvicorn API + builds/serves the REAL frontend + drives the "
        "REAL browser scenario runner (no TestClient / mocked business API)",
        level="structural source check")
    rec("DF24 real-subprocess-worker-postcondition",
        '"-m", "backend.app.worker"' in guard_src,
        "the upload database postcondition is observed after a REAL external worker parses the upload",
        level="structural source check")

    return _emit()


def _emit(skipped=False) -> int:
    passed = [c for c in checks if c["ok"]]
    failed = [c for c in checks if not c["ok"]]
    levels = {}
    for c in checks:
        levels[c["execution_level"]] = levels.get(c["execution_level"], 0) + 1
    out = {"checks": checks,
           "summary": {"passed": len(passed), "skipped": 0, "failed": len(failed),
                       "execution_level_totals": levels,
                       "claim_scope": "dual-backend-ui-faults-only",
                       "fault_battery": "passed" if not failed else "failed",
                       "eligible_for_tenant_evidence": False, "eligible_for_readiness": False,
                       "production_parity": False}}
    print(json.dumps(out, indent=2, default=str))
    if failed:
        print(f"\nDual-backend UI fault battery FAILED: {len(failed)} check(s).")
        for c in failed:
            print(f"  FAIL: {c['check_id']} -> {c['description']}")
        return 1
    print(f"\nDual-backend UI fault battery passed: {len(passed)} non-vacuity proof(s)."
          "\n[claim_scope=dual-backend-ui-faults-only; NOT evidence/readiness eligible]")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
