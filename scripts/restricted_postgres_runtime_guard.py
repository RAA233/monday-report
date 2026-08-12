"""audit:restricted-postgres-runtime -- the RESERVED complete restricted-PostgreSQL functional matrix.

Executes all five ACCEPTED functional slice guards (core, mutations, exports, isolation, worker-import)
as REAL external subprocesses on independently provisioned, runner-owned disposable stacks, verifies each
against the canonical manifest (SHA-256, claim scope, exact expected check-id set, counts, eligibility,
parity, migration principal, zero normal-failure counters), aggregates the namespaced inventory (266
checks), and emits the honest complete claim contract ONLY when every child passes:

    claim_scope            = restricted-runtime-functional-complete
    full_functional_matrix = passed
    eligible_for_tenant_evidence = false / eligible_for_readiness = false / production_parity = false
    execution_model        = accepted slices executed on independent runner-owned disposable stacks
    deferred_functional_areas = []

This is NOT tenant evidence, NOT readiness evidence, NOT production-adapter/production-parity evidence.
Requires Docker; `--allow-unavailable` degrades to a non-certifying (not-passed) unavailable disposition.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import restricted_postgres_runtime_aggregate_core as C  # noqa: E402


def main() -> int:
    return C.certify("functional", allow_unavailable="--allow-unavailable" in sys.argv)


if __name__ == "__main__":
    raise SystemExit(main())
