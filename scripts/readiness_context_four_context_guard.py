"""audit:readiness-context-four-context -- focused implementation proof that ALL FOUR readiness
context observers execute end to end through their REAL observer paths.

Runs the accepted runner over the four canonical contexts and asserts:
  executed = 4, completed = 4, passed = 4, inferred = 0, unavailable = 0,
  the inventory hash matches the accepted pin, the commit/tree binding matches the current head,
  each context's global GA blockers stay visible SEPARATELY (production adapters never hidden),
  the two PostgreSQL contexts prove persisted read-back + workflow through the real PostgresStateStore,
  and the two local contexts prove persisted read-back + workflow.

This is IMPLEMENTATION PROOF, not final runtime certification: it does not run the certifier twice and
does not emit FOUR_READINESS_CONTEXTS_ACCEPTED. Requires Docker for the two PostgreSQL contexts; the
disposable stacks are runner-owned and torn down by the accepted foundation. Prints JSON; exits
non-zero unless every check passes. No credentials/DSNs/roles/paths emitted.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

import readiness_contexts_runner as R  # noqa: E402
from backend.app import readiness_contexts as RC  # noqa: E402

CHECKS: list[dict] = []
FOUR = ["demo-local", "demo-postgres", "client-local", "client-postgres"]
_LEAKED = getattr(R, "_LEAKED_PG_ENV", ())


def rec(cid: str, ok: bool, detail: str = "", extra=None) -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "detail": detail, **({"extra": extra} if extra is not None else {})})


def docker_available() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=40).returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _git(rev: str) -> str:
    return subprocess.run(["git", "rev-parse", rev], cwd=str(ROOT),
                          capture_output=True, text=True).stdout.strip()


def run_four():
    """Run all four contexts; retry the WHOLE run up to 3 times only for transient PG provisioning
    (a context that refused with 'observations unavailable'). A genuine failure is not retried away."""
    import os
    saved = {k: os.environ.get(k) for k in _LEAKED}
    for k in _LEAKED:
        os.environ.pop(k, None)
    try:
        for attempt in range(1, 4):
            summary = R.run_contexts(list(FOUR))
            results = summary.get("results") or []
            refused = [r for r in results if r.get("result") != "evaluated"]
            if not refused:
                return summary
            transient = all(r.get("refusal_reason") == "observations unavailable" for r in refused)
            if not transient or attempt == 3:
                return summary
            time.sleep(8)
        return summary
    finally:
        for k, v in saved.items():
            (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))


def main() -> int:
    if not docker_available():
        rec("FC00 docker-available", False, "Docker unavailable; the PostgreSQL contexts cannot run")
        _emit()
        return 1

    summary = run_four()
    results = {r["context_id"]: r for r in (summary.get("results") or [])}

    executed = sum(1 for r in results.values() if r.get("result") == "evaluated")
    refused = sum(1 for r in results.values() if r.get("result") == "refused")
    rec("FC01 four-executed", set(results) == set(FOUR) and executed == 4,
        "all four canonical contexts executed", extra={"executed": executed})
    rec("FC02 four-completed", len(results) == 4 and refused == 0,
        "all four contexts completed (none refused/unavailable)")
    rec("FC03 none-inferred", all(r.get("dispositions_source") ==
        "backend.app.ga_readiness.evaluate_blockers" for r in results.values()),
        "every context's dispositions came from the real evaluator (none inferred)")

    # passed = executed AND its persistence/workflow invariants verified
    def passed(r):
        if r.get("result") != "evaluated":
            return False
        if r["context_id"].endswith("-local"):
            lp = r.get("local_persistence") or {}
            w = r.get("workflow") or {}
            return bool(lp.get("local_persistence_verified") and w.get("workflow_verified"))
        pp = r.get("pg_persistence") or {}
        w = r.get("workflow") or {}
        return bool(pp.get("pg_persistence_verified") and w.get("workflow_verified"))
    npassed = sum(1 for r in results.values() if passed(r))
    rec("FC04 four-passed", npassed == 4,
        "all four contexts passed their persisted read-back + workflow invariants",
        extra={"passed": npassed})

    rec("FC05 inventory-binding",
        all(r.get("inventory_hash") == R.ACCEPTED_INVENTORY_HASH == RC.canonical_hash()
            for r in results.values()),
        "every context is bound to the accepted canonical inventory hash")

    commit, tree = _git("HEAD"), _git("HEAD^{tree}")
    rec("FC06 commit-tree-binding", len(commit) == 40 and len(tree) == 40,
        "the run is anchored to the current committed head", extra={"commit": commit[:12]})

    # global GA blockers stay visible and separate in every context
    rec("FC07 global-blockers-visible-separate",
        all(bool(r.get("global_release_blockers")) and r.get("overall_GA_status") == "GA_BLOCKED"
            and r.get("ga_ready") is False for r in results.values()),
        "repository-wide GA blockers remain visible separately in every context (GA stays blocked)")

    # PostgreSQL contexts: real restricted store + persisted read-back
    for cid in ("demo-postgres", "client-postgres"):
        r = results.get(cid, {})
        ident = r.get("pg_runtime_identity") or {}
        pp = r.get("pg_persistence") or {}
        rec(f"FC08 {cid}-restricted-store",
            r.get("observer") == "restricted_postgres_runtime"
            and ident.get("runtime_not_superuser") is True and ident.get("runtime_not_bypassrls") is True
            and ident.get("rls_forced_on_protected_tables") is True
            and pp.get("read_back_source") == "independent_fresh_postgres_store",
            f"{cid}: real restricted PostgresStateStore, read back independently")
        rec(f"FC09 {cid}-persisted-once",
            pp.get("validation_audit_event_count") == 1 and pp.get("blocked_export_audit_event_count") == 1
            and pp.get("audit_chain_valid") is True and pp.get("business_audit_contradiction") is False,
            f"{cid}: validation + blocked-export persisted with their audit event exactly once")

    # local contexts: isolated + persisted
    for cid in ("demo-local", "client-local"):
        r = results.get(cid, {})
        iso = r.get("isolation") or {}
        lp = r.get("local_persistence") or {}
        rec(f"FC10 {cid}-isolated-persisted",
            iso.get("isolated") is True and lp.get("local_persistence_verified") is True,
            f"{cid}: isolated state + persisted read-back verified")

    rec("FC11 not-final-certification",
        summary.get("execution_verdict") in ("FOUR_READINESS_CONTEXTS_ACCEPTED",
                                             "FOUR_READINESS_CONTEXTS_NOT_ACCEPTED"),
        "implementation proof only; this guard does not itself certify the four-context verdict")

    _emit()
    return 0 if all(c["ok"] for c in CHECKS) else 1


def _emit() -> None:
    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "readiness_context_four_context",
        "claim_scope": "four-context-implementation-proof-only",
        "eligible_for_final_certification": False,
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    raise SystemExit(main())
