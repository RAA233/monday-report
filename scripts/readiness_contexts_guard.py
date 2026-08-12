"""audit:readiness-contexts -- certification guard for a real four-context execution.

Certifies a COMPLETE four-context execution: two full runs, identical canonical bodies and hashes,
every canonical context evaluated, no duplicate/missing/unknown context, no required SKIP, every
readiness boolean false and ``GA_BLOCKED``.

This guard is capacity-gated by construction. It calls the runner's own read-only gate FIRST and,
below the threshold, launches nothing and emits a complete controlled unavailable summary with
``certification="unavailable"`` / ``accepted=false`` and a NON-ZERO exit. It never reports the
contract's expected dispositions as executed results, and it never converts an unavailable run into
a pass.

Honest scope: claim_scope = readiness-context-execution-only; eligible_for_tenant_evidence = false;
eligible_for_readiness = false; production_parity = false; release_recommendation = GA_BLOCKED.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "scripts"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from backend.app import readiness_contexts as RC  # noqa: E402
import readiness_contexts_runner as R  # noqa: E402

checks: list[dict] = []


def rec(cid, ok, desc, level="execution integration", extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level, **(extra or {})})


def emit(summary: dict, rc: int) -> int:
    print(json.dumps(summary, indent=2, sort_keys=True, default=str))
    return rc


def run() -> int:
    passed, facts = R.capacity_gate()

    # ---------------------------------------------------------------- capacity gate comes FIRST
    if not passed:
        # Nothing is launched. No disposition is produced. Exit non-zero.
        summary = {
            "guard": "audit:readiness-contexts",
            "schema": R.EXECUTION_SCHEMA,
            "claim_scope": "readiness-context-execution-only",
            "inventory_hash": RC.canonical_hash(),
            "readiness_execution_capacity": "blocked",
            "capacity": facts,
            "contexts_executed": False,
            "dispositions_produced": False,
            "context_count": 0,
            "results": [],
            "certification": "unavailable",
            "accepted": False,
            "client_data_ready": False,
            "release_candidate_ready": False,
            "ga_ready": False,
            "production_parity": False,
            "eligible_for_tenant_evidence": False,
            "eligible_for_readiness": False,
            "execution_verdict": "FOUR_READINESS_CONTEXTS_NOT_ACCEPTED",
            "release_recommendation": "GA_BLOCKED",
            "reason": ("environment-capacity gate blocked (required free bytes >= 40 GiB AND free "
                       "percentage >= 15%); no container, database, API, worker, frontend or browser "
                       "was launched and no context disposition was produced"),
            "static_expectations_reported_as_results": False,
        }
        return emit(summary, 1)

    # ---------------------------------------------------------------- two full runs
    first = R.run_contexts()
    second = R.run_contexts()

    body_first = R.canonical_result_json(first)
    body_second = R.canonical_result_json(second)

    rec("RX01 two-full-runs-executed",
        first.get("contexts_executed") is True and second.get("contexts_executed") is True,
        "both full runs executed the contexts (neither degraded to an unavailable summary)")
    rec("RX02 four-contexts", first.get("context_count") == len(RC.CANONICAL_CONTEXT_ORDER),
        f"exactly {len(RC.CANONICAL_CONTEXT_ORDER)} canonical contexts produced a result")
    ids = [r["context_id"] for r in first.get("results", [])]
    rec("RX03 no-duplicate-missing-unknown",
        sorted(ids) == sorted(RC.CANONICAL_CONTEXT_ORDER),
        "the executed context set equals the canonical set exactly: no duplicate, no missing, "
        "no unknown context",
        extra={"context_ids": ids})
    rec("RX04 no-required-skip",
        all(r.get("result") == "evaluated" for r in first.get("results", [])),
        "no canonical context was skipped or refused")
    rec("RX05 identical-canonical-body", body_first == body_second,
        "the two full runs produced a byte-identical canonical result body")
    rec("RX06 identical-canonical-hash",
        first.get("canonical_result_hash") == second.get("canonical_result_hash"),
        "the two full runs produced the same canonical result hash",
        extra={"canonical_result_hash": first.get("canonical_result_hash")})
    rec("RX07 inventory-hash-bound",
        first.get("inventory_hash") == RC.canonical_hash(),
        "the run is bound to the accepted canonical inventory hash",
        extra={"inventory_hash": first.get("inventory_hash")})
    rec("RX08 no-cross-context-mutation", first.get("cross_context_mutation") == [],
        "no context input was mutated during the run (per-context fingerprints unchanged)")

    # ---------------------------------------------------------------- ordering independence
    orders = {
        "canonical": R.run_contexts(),
        "reverse": R.run_contexts(reverse=True),
        "seeded": R.run_contexts(seed=20260726),
    }
    rec("RX09 order-independent",
        len({R.canonical_result_json(s) for s in orders.values()}) == 1,
        "canonical, reverse and seeded-random execution orders produce identical canonical bodies",
        level="context-order integration")
    singles = {cid: R.run_contexts([cid]) for cid in RC.CANONICAL_CONTEXT_ORDER}
    per_ctx_all = {r["context_id"]: r for r in first.get("results", [])}
    single_match = all(
        json.dumps(singles[cid]["results"][0], sort_keys=True, default=str)
        == json.dumps(per_ctx_all.get(cid), sort_keys=True, default=str)
        for cid in RC.CANONICAL_CONTEXT_ORDER
        if singles[cid].get("results")
    )
    rec("RX10 single-matches-all", single_match,
        "each context executed individually yields the same canonical result as in the full run",
        level="context-order integration")

    # ---------------------------------------------------------------- readiness must stay false
    for key in ("client_data_ready", "release_candidate_ready", "ga_ready", "production_parity"):
        rec(f"RX11 {key}-false", first.get(key) is False,
            f"aggregate {key} is false")
    rec("RX12 per-context-readiness-false",
        all(not r["client_data_ready"] and not r["release_candidate_ready"] and not r["ga_ready"]
            for r in first.get("results", [])),
        "every context reports client_data_ready, release_candidate_ready and ga_ready false")
    rec("RX13 ga-blocked", first.get("release_recommendation") == "GA_BLOCKED",
        "the release recommendation is GA_BLOCKED")
    rec("RX14 every-context-blocks",
        all(r["blocking_controls"] for r in first.get("results", [])),
        "every context reports a non-empty blocking-control set")

    passed_n = sum(1 for c in checks if c["ok"])
    failed_n = len(checks) - passed_n
    accepted = failed_n == 0 and first.get("accepted") is True

    summary = {
        "guard": "audit:readiness-contexts",
        "schema": R.EXECUTION_SCHEMA,
        "claim_scope": "readiness-context-execution-only",
        "inventory_hash": RC.canonical_hash(),
        "readiness_execution_capacity": facts.get("readiness_execution_capacity", "available"),
        "capacity": facts,
        # Read from the RUN, never hardcoded: the PostgreSQL observer is capacity-gated, so a
        # gate-passing invocation can still have contexts that refused. Asserting these would claim
        # an execution that did not happen.
        "contexts_executed": first.get("contexts_executed") is True,
        "dispositions_produced": bool(first.get("results")) and all(
            r.get("result") == "evaluated" for r in first.get("results", [])),
        "summary": {"passed": passed_n, "failed": failed_n, "skipped": 0,
                    "certification": "passed" if accepted else "not_passed"},
        "checks": checks,
        "canonical_result_hash": first.get("canonical_result_hash"),
        "results": first.get("results", []),
        "accepted": accepted,
        "client_data_ready": False,
        "release_candidate_ready": False,
        "ga_ready": False,
        "production_parity": False,
        "eligible_for_tenant_evidence": False,
        "eligible_for_readiness": False,
        "execution_verdict": ("FOUR_READINESS_CONTEXTS_ACCEPTED" if accepted
                              else "FOUR_READINESS_CONTEXTS_NOT_ACCEPTED"),
        "release_recommendation": "GA_BLOCKED",
        "static_expectations_reported_as_results": False,
    }
    return emit(summary, 0 if accepted else 1)


if __name__ == "__main__":
    raise SystemExit(run())
