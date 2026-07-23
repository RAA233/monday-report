"""Guard for the fail-closed verification-isolation boundary (no database required).

The boundary (backend/app/verification_boundary.py) lets a provably-isolated
disposable verification stack execute the real client-mode request path instead of
receiving the release-readiness HTTP 423, WITHOUT bypassing auth/RBAC/tenant-authz/
RLS/idempotency and WITHOUT certifying readiness or approving GA. Because it relaxes
a client-data-safety lock, its safety rests entirely on failing closed. This guard
proves that:

* it is OFF by default and requires an explicit opt-in marker;
* it activates ONLY under the full isolation conjunction;
* removing ANY single signal disables it (it is a conjunction, never a disjunction);
* a production-shaped environment (remote host, production database name, live
  .local_data root, live 8000/5173 ports, local/file backend) can never activate it;
* its request-independent: only process configuration is consulted, never a header,
  query, or body;
* its audit/evidence summary leaks no DSN, host, port, credential, or path;
* the readiness gate actually consults it AND audits every relaxed execution
  (structural check, so the wiring cannot silently regress).

Run: ``python scripts/verification_boundary_guard.py``
"""
from __future__ import annotations

import ast
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

checks: list[dict] = []


def record(name: str, ok: bool, detail: object = "") -> None:
    checks.append({"name": name, "ok": bool(ok), "detail": detail})


# A fully-isolated disposable verification environment.
ISOLATED = {
    "MONDAY_REPORT_VERIFICATION_ISOLATION": "1",
    "MONDAY_REPORT_REPOSITORY_BACKEND": "postgres",
    "MONDAY_REPORT_DATABASE_URL": "postgresql://rt:pw@127.0.0.1:5439/monday_rt_test",
    "MONDAY_REPORT_STATE_PATH": r"C:\scratch-verify\state\state.json",
    "MONDAY_REPORT_STORAGE_ROOT": r"C:\scratch-verify\storage",
    "MONDAY_REPORT_EXPORT_ROOT": r"C:\scratch-verify\exports",
    "MONDAY_REPORT_API_BASE": "http://127.0.0.1:8066",
    "MONDAY_REPORT_WEB_BASE": "http://127.0.0.1:5199",
}

_KEYS = list(ISOLATED) + ["DATABASE_URL"]


def _apply(env: dict) -> None:
    for k in _KEYS:
        os.environ.pop(k, None)
    os.environ.update(env)


def main() -> int:
    from backend.app import verification_boundary as vb

    # 01 OFF by default (no env at all).
    _apply({})
    record("01 boundary is OFF with no configuration", vb.verification_execution_allowed() is False)

    # 02 ON under the full isolation conjunction.
    _apply(ISOLATED)
    record("02 boundary is ON under the full isolation conjunction",
           vb.verification_execution_allowed() is True)

    # 03 the marker alone (a bare DISABLE_READINESS-style flag) never activates it.
    _apply({"MONDAY_REPORT_VERIFICATION_ISOLATION": "1"})
    record("03 the opt-in marker ALONE does not activate the boundary",
           vb.verification_execution_allowed() is False)

    # 04-11 removing ANY single signal disables it (conjunction, not disjunction).
    single_axis = {
        "04 without the opt-in marker": {**ISOLATED, "MONDAY_REPORT_VERIFICATION_ISOLATION": "0"},
        "05 with a local/file backend": {**ISOLATED, "MONDAY_REPORT_REPOSITORY_BACKEND": "local_json"},
        "06 with a remote (non-loopback) database host":
            {**ISOLATED, "MONDAY_REPORT_DATABASE_URL": "postgresql://rt:pw@db.prod.example:5432/monday_rt_test"},
        "07 with a production (non-test) database name":
            {**ISOLATED, "MONDAY_REPORT_DATABASE_URL": "postgresql://rt:pw@127.0.0.1:5439/monday_client"},
        "08 with a state root under live .local_data":
            {**ISOLATED, "MONDAY_REPORT_STATE_PATH": r"C:\app\.local_data\state.json"},
        "09 with a storage root under live .local_data":
            {**ISOLATED, "MONDAY_REPORT_STORAGE_ROOT": r"C:\app\.local_data\storage"},
        "10 with the live API port 8000":
            {**ISOLATED, "MONDAY_REPORT_API_BASE": "http://127.0.0.1:8000"},
        "11 with the live web port 5173":
            {**ISOLATED, "MONDAY_REPORT_WEB_BASE": "http://127.0.0.1:5173"},
    }
    for name, env in single_axis.items():
        _apply(env)
        record(f"{name} disables the boundary (fail closed)",
               vb.verification_execution_allowed() is False,
               {"withheld_by": vb.verification_context_summary()["withheld_by"]})

    # 12 a fully production-shaped environment can never activate it.
    _apply({
        "MONDAY_REPORT_VERIFICATION_ISOLATION": "1",
        "MONDAY_REPORT_REPOSITORY_BACKEND": "postgres",
        "MONDAY_REPORT_DATABASE_URL": "postgresql://app:pw@prod-db.internal:5432/monday_production",
        "MONDAY_REPORT_STATE_PATH": r"C:\app\.local_data\state.json",
        "MONDAY_REPORT_STORAGE_ROOT": r"C:\app\.local_data\storage",
        "MONDAY_REPORT_EXPORT_ROOT": r"C:\app\.local_data\exports",
        "MONDAY_REPORT_API_BASE": "http://0.0.0.0:8000",
        "MONDAY_REPORT_WEB_BASE": "http://0.0.0.0:5173",
    })
    record("12 a production-shaped environment can never activate the boundary",
           vb.verification_execution_allowed() is False)

    # 13 the summary leaks no DSN, host, port, credential, or path (booleans + signal names only).
    _apply(ISOLATED)
    blob = json.dumps(vb.verification_context_summary())
    leaked = [t for t in ("postgresql://", "127.0.0.1", "5439", "pw@", "scratch-verify", "c:\\", "monday_rt_test")
              if t in blob.lower()]
    record("13 the audit/evidence summary leaks no DSN, host, port, credential or path",
           not leaked, {"leaked": leaked})

    # 14 request-independence: the boundary reads ONLY os.environ, never request state.
    src = (ROOT / "backend" / "app" / "verification_boundary.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    reads_request = any(
        isinstance(n, ast.Attribute) and n.attr in {"headers", "query_params", "cookies", "body"}
        for n in ast.walk(tree)
    )
    record("14 the boundary consults only process config, never request headers/query/body",
           not reads_request)

    # 15 the readiness gate actually consults the boundary AND audits the relaxed
    #    execution (structural, so the wiring cannot silently regress).
    main_src = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
    gate = main_src.split("def require_client_data_ready", 1)[1].split("\ndef ", 1)[0]
    calls_boundary = "verification_execution_allowed()" in gate
    audits_before_return = "verification_isolation_execution" in gate
    still_raises_423 = 'status_code=423' in gate
    record("15 require_client_data_ready consults the boundary, audits it, and still raises 423 otherwise",
           calls_boundary and audits_before_return and still_raises_423,
           {"calls_boundary": calls_boundary, "audits": audits_before_return, "raises_423": still_raises_423})

    passed = [c for c in checks if c["ok"]]
    failed = [c for c in checks if not c["ok"]]
    print(json.dumps({"checks": checks,
                      "summary": {"passed": len(passed), "failed": len(failed), "skipped": 0}},
                     indent=2, default=str))
    if failed:
        print(f"\nVerification-boundary guard FAILED: {len(failed)} failing check(s).")
        for c in failed:
            print(f"  FAIL: {c['name']} -> {c['detail']}")
        return 1
    print(f"\nVerification-boundary guard passed: {len(passed)} check(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
