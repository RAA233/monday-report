"""audit:restricted-postgres-runtime-faults -- the RESERVED complete restricted-PostgreSQL fault matrix.

Executes all five ACCEPTED functional-fault guards (core-faults, mutations-faults, exports-faults,
isolation-faults, worker-import-faults) as REAL external subprocesses, verifies each against the
canonical manifest (SHA-256, claim scope, exact expected check-id set, counts, eligibility), aggregates
the namespaced inventory (144 checks) preserving the children's honest execution-level classifications,
and emits ONLY when every fault child passes:

    claim_scope                  = restricted-runtime-functional-faults-complete
    full_functional_fault_matrix = passed
    eligible_for_tenant_evidence = false / eligible_for_readiness = false

This is NOT tenant evidence, NOT readiness evidence, NOT production-parity evidence. Requires Docker;
`--allow-unavailable` degrades to a non-certifying (not-passed) unavailable disposition.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import restricted_postgres_runtime_aggregate_core as C  # noqa: E402


def main() -> int:
    return C.certify("fault", allow_unavailable="--allow-unavailable" in sys.argv)


if __name__ == "__main__":
    raise SystemExit(main())
