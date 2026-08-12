"""audit:readiness-context-pg-observer -- focused proof that the restricted-PostgreSQL context
observer is REAL and load-bearing.

This is the Docker-requiring companion to the Docker-free ``audit:readiness-contexts-faults``
battery. It executes ONE real PostgreSQL readiness context end to end through the accepted
restricted-PostgreSQL foundation and asserts the properties the observer must prove, then checks the
fail-closed directions that need no Docker.

It deliberately runs a SINGLE context (``demo-postgres``): it proves the observer executes and is
authentic; it is NOT the four-context certification and can never emit
``FOUR_READINESS_CONTEXTS_ACCEPTED`` (that needs all four contexts and belongs to a later exact-head
execution after fresh tenant evidence).

Positive case (needs Docker): the observer no longer raises ExecutionUnavailable; the runtime is the
RESTRICTED, non-superuser, non-BYPASSRLS login; RLS is forced; migration and runtime roles are
distinct; the context is really executed (not inferred); the inventory binding is exact; and global
GA blockers stay visible without being treated as a context-execution failure.

Negative cases (no Docker): a blocked capacity gate refuses rather than launching, and a refusal is
fail-closed (carries no dispositions and can never be accepted).

Prints JSON; exits non-zero unless every check passes. Emits no DSN, role, container id or path.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

import readiness_contexts_runner as R  # noqa: E402
from backend.app import readiness_contexts as RC  # noqa: E402

#: Generic test/PG env that must never leak into the observed runtime.
_LEAKED = R._LEAKED_PG_ENV

CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str = "", extra=None) -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "detail": detail, **({"extra": extra} if extra is not None else {})})


def docker_available() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=40).returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _clear_leaked_env() -> dict:
    saved = {k: os.environ.get(k) for k in _LEAKED}
    for k in _LEAKED:
        os.environ.pop(k, None)
    return saved


def _restore_env(saved: dict) -> None:
    for k, v in saved.items():
        (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))


def positive_real_execution() -> None:
    """Execute the real demo-postgres context and assert the observer's guarantees.

    The disposable stack occasionally fails to become ready within the foundation's timeout under
    host load; that is a transient PROVISIONING refusal (correct fail-closed behaviour), not a logic
    defect, so up to three attempts are made to obtain an executed result. A persistent inability to
    execute still FAILS -- the retries only absorb transient container-readiness timeouts.
    """
    import time

    summary = None
    r = None
    attempts = 0
    last_refusal = None
    for attempts in range(1, 4):
        saved = _clear_leaked_env()
        try:
            summary = R.run_contexts(["demo-postgres"])
        finally:
            _restore_env(saved)
        results = summary.get("results") or []
        if results and results[0].get("result") == "evaluated":
            r = results[0]
            break
        last_refusal = (results[0].get("refusal_reason") if results else "no result")
        time.sleep(5)  # let a half-torn-down container/volume settle before retrying

    rec("PG01 single-context-result",
        bool(summary) and len(summary.get("results") or []) == 1
        and summary["results"][0]["context_id"] == "demo-postgres",
        "exactly one demo-postgres result was produced")
    if r is None:
        rec("PG02 observer-executed-not-unavailable", False,
            f"the observer never produced an executed result in {attempts} attempt(s)",
            extra={"last_refusal_reason": last_refusal})
        return

    rec("PG02 observer-executed-not-unavailable",
        r.get("result") == "evaluated" and r.get("context_execution_status") == "executed",
        "the PostgreSQL observer produced an EXECUTED result -- it no longer raises "
        "ExecutionUnavailable", extra={"result": r.get("result")})

    rec("PG03 recognised-restricted-observer",
        r.get("observer") == "restricted_postgres_runtime"
        and r.get("observer") in R.RECOGNISED_OBSERVERS,
        "the observation came from the recognised restricted-PostgreSQL observer")

    ident = r.get("pg_runtime_identity") or {}
    rec("PG04 restricted-non-superuser-role",
        ident.get("session_user_is_restricted_login") is True
        and ident.get("runtime_not_superuser") is True,
        "the runtime login is a restricted, non-superuser LOGIN role")
    rec("PG05 non-bypassrls-non-owner",
        ident.get("runtime_not_bypassrls") is True
        and ident.get("runtime_owns_no_protected_tables") is True,
        "the runtime login is non-BYPASSRLS and owns none of the protected tables")
    rec("PG06 rls-forced",
        ident.get("rls_forced_on_protected_tables") is True
        and int(ident.get("forced_rls_table_count") or 0) > 0,
        "row-level security is FORCED on the protected tables",
        extra={"forced_rls_table_count": ident.get("forced_rls_table_count")})
    rec("PG07 distinct-migration-and-runtime-roles",
        r.get("migration_runtime_roles_distinct") is True,
        "the migration principal and the runtime login are distinct roles")

    rec("PG08 executed-not-inferred",
        r.get("dispositions_source") == "backend.app.ga_readiness.evaluate_blockers"
        and r.get("result") == "evaluated" and not r.get("refusal_reason"),
        "dispositions came from the real evaluator on an executed runtime, not inferred from a "
        "contract prediction")

    rec("PG09 inventory-binding-exact",
        r.get("inventory_hash") == R.ACCEPTED_INVENTORY_HASH == RC.canonical_hash(),
        "the executed context is bound to the accepted canonical inventory hash")

    # global GA blockers remain visible AND are not treated as a context-execution failure
    global_blk = r.get("global_release_blockers") or []
    rec("PG10 global-ga-blockers-visible-not-context-failure",
        r.get("context_execution_status") == "executed"
        and bool(global_blk) and r.get("overall_GA_status") == "GA_BLOCKED"
        and r.get("ga_ready") is False,
        "repository-wide GA blockers stay visible and GA stays blocked, yet the context still counts "
        "as EXECUTED -- execution acceptance is independent of GA readiness",
        extra={"global_release_blockers": global_blk})

    # a real production-adapter control must be among the global blockers (never promoted by the
    # restricted runtime)
    rec("PG11 production-adapters-never-promoted",
        "ga_postgres_adapter" in global_blk and "ga_redis_adapter" in global_blk,
        "the restricted runtime never promotes the production database/queue adapter controls")

    # the single-context run is NOT the four-context certification
    rec("PG12 not-four-context-certification",
        summary.get("accepted") is False
        and summary.get("execution_verdict") == "FOUR_READINESS_CONTEXTS_NOT_ACCEPTED",
        "a single-context run never reaches four-context acceptance")


def negative_capacity_blocked() -> None:
    """A blocked capacity gate refuses without launching anything (Docker-free)."""
    calls = {"n": 0}
    real_observer = R.collect_observations

    def tripwire(run_input):
        calls["n"] += 1
        return real_observer(run_input)

    blocked = {"filesystem_total_bytes": 1_000_000_000_000, "filesystem_free_bytes": 1,
               "free_bytes_ok": False, "free_percentage_ok": False,
               "readiness_execution_capacity": "blocked"}
    summary = R.run_contexts(["demo-postgres"], observer=tripwire, capacity=blocked)
    rec("PG13 capacity-blocked-launches-nothing",
        calls["n"] == 0 and summary.get("accepted") is False
        and summary.get("certification") in ("unavailable", "not_passed"),
        "below the capacity gate the observer is never called and nothing is accepted",
        extra={"observer_invocations": calls["n"]})


def negative_refusal_fail_closed() -> None:
    """An observer that reports unavailability yields a fail-closed refusal (Docker-free)."""
    def unavailable(run_input):
        raise R.ExecutionUnavailable("synthetic: stack unavailable")

    summary = R.run_contexts(["demo-postgres"], observer=unavailable)
    r = (summary.get("results") or [{}])[0]
    rec("PG14 refusal-is-fail-closed",
        r.get("result") == "refused" and r.get("context_execution_status") == "refused"
        and not r.get("control_dispositions") and r.get("ga_ready") is False
        and summary.get("accepted") is False,
        "an unavailable observer produces a refusal that carries no dispositions and can never be "
        "accepted")


def main() -> int:
    docker = docker_available()
    if docker:
        positive_real_execution()
    else:
        rec("PG00 docker-unavailable-positive-skipped", False,
            "Docker is unavailable, so the real-execution proof could not run; refusing to certify")
    negative_capacity_blocked()
    negative_refusal_fail_closed()

    passed = sum(1 for c in CHECKS if c["ok"])
    failed = len(CHECKS) - passed
    report = {
        "guard": "readiness_context_pg_observer",
        "claim_scope": "restricted-postgres-context-observer-only",
        "docker_available": docker,
        "eligible_for_four_context_acceptance": False,
        "summary": {"passed": passed, "failed": failed,
                    "certification": "passed" if failed == 0 else "not_passed"},
        "checks": CHECKS,
    }
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
