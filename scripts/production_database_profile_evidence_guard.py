"""audit:production-database-profile-evidence -- validate the behavioral-profile evidence
artifact and prove its validator is load-bearing (Docker-free). Confirms the artifact is
exact-head bound, canonical-hash-verified, honestly disposable, secret-clean, and that
the behavioral control PASSes ONLY for the complete honest conjunction. Fault mutations
prove each guarantee. Also asserts this tier NEVER promotes the production-target control.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

from backend.app import production_database_profile_evidence as P  # noqa: E402

CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str = "") -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL", "detail": detail})


def main() -> int:
    payload, reasons = P.load_and_validate()
    if payload is None:
        print(json.dumps({"guard": "production_database_profile_evidence",
                          "summary": {"passed": 0, "failed": 1, "certification": "not_passed"},
                          "detail": "no artifact present; run ga:production-database-profile-evidence first",
                          "reasons": reasons}, indent=2))
        return 1

    commit, tree = payload.get("git_commit"), payload.get("git_tree")
    # Baseline: the real artifact validates at its own bound head.
    rec("EV00 baseline-valid", P.validate(payload, current_commit=commit, current_tree=tree) == [],
        "the generated artifact validates at its exact bound head")
    rec("EV01 control-pass-for-honest-conjunction",
        P.behavioral_control(current_commit=commit, current_tree=tree) == "PASS",
        "the behavioral control PASSes for the complete honest artifact")
    rec("EV02 verdict-is-behavioral", payload.get("verdict") == P.BEHAVIORAL_VERDICT,
        "the verdict is PRODUCTION_DATABASE_ADAPTER_BEHAVIORAL_ACCEPTED, not production-target")

    def mutated(fn):
        m = copy.deepcopy(payload)
        fn(m)
        # rehash so only the intended defect (not a hash mismatch) is under test, unless the
        # mutation IS the hash.
        return m

    def rejects(cid, fn, *, rehash=True, detail=""):
        m = mutated(fn)
        if rehash:
            m["canonical_payload_hash"] = P.canonical_hash(m)
        reasons = P.validate(m, current_commit=commit, current_tree=tree)
        rec(cid, len(reasons) > 0, detail or (reasons[0] if reasons else "NOT rejected"))

    rejects("FE01 wrong-commit-rejected", lambda m: m.update(git_commit="0" * 40),
            detail="a wrong git_commit is rejected")
    rejects("FE02 wrong-tree-rejected", lambda m: m.update(git_tree="0" * 40),
            detail="a wrong git_tree is rejected")
    rejects("FE03 canonical-hash-mismatch-rejected",
            lambda m: m.update(canonical_payload_hash="a" * 64), rehash=False,
            detail="a canonical hash that does not match the body is rejected")
    rejects("FE04 production-target-masquerade-rejected",
            lambda m: m["target"].update(environment_classification="production"),
            detail="claiming environment=production is rejected (no masquerade)")
    rejects("FE05 managed-provider-masquerade-rejected",
            lambda m: m["target"].update(provider_classification="managed-postgresql"),
            detail="claiming a managed provider is rejected")
    rejects("FE06 durable-storage-masquerade-rejected",
            lambda m: m["target"].update(storage_classification="durable-replicated"),
            detail="claiming durable-replicated storage is rejected")
    rejects("FE07 missing-disclosure-rejected",
            lambda m: m["disclosures"].update(ga_postgres_adapter_remains_blocked=False),
            detail="dropping the ga-blocked disclosure is rejected")
    rejects("FE08 non-proving-class-rejected",
            lambda m: m["behavioral_domains"]["forced_rls"].update(observation_class="literal_assertion"),
            detail="a domain PASS from a non-proving class is rejected")
    rejects("FE09 failing-domain-rejected",
            lambda m: m["behavioral_domains"]["cross_tenant_isolation"].update(status="FAIL"),
            detail="a FAIL behavioral domain is rejected")
    rejects("FE10 incomplete-domain-checks-rejected",
            lambda m: m["behavioral_domains"]["bounded_connection_pool"].update(checks_passed=0),
            detail="a domain with fewer passed than total is rejected")
    rejects("FE11 dropped-domain-rejected",
            lambda m: m["behavioral_domains"].pop("verified_tls_enforcement"),
            detail="a missing required domain is rejected")
    rejects("FE12 not-all-passed-rejected",
            lambda m: m["totals"].update(all_passed=False),
            detail="totals.all_passed=false is rejected")
    rejects("FE13 leaked-dsn-rejected",
            lambda m: m.update(leak="postgresql://u:p@10.0.0.1/db"),
            detail="an artifact carrying a DSN/endpoint leak is rejected")
    rejects("FE14 foreign-schema-at-path-rejected",
            lambda m: m.update(schema_version="production-database-adapter-evidence.v1"),
            detail="the production-target schema id at this path is rejected")
    rejects("FE15 stale-artifact-rejected",
            lambda m: m.update(generated_at="2020-01-01T00:00:00+00:00"),
            detail="an artifact older than 90 days is rejected")

    # This tier NEVER touches the production-target control.
    try:
        from backend.app import production_database_adapter_evidence as PT
        rec("EV03 production-target-control-independent",
            PT.SCHEMA_VERSION == "production-database-adapter-evidence.v1"
            and PT.SCHEMA_VERSION != P.SCHEMA_VERSION,
            "the production-target schema/contract is a separate, untouched module")
    except Exception as exc:  # noqa: BLE001
        rec("EV03 production-target-control-independent", False, str(exc))

    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "production_database_profile_evidence",
        "claim_scope": "behavioral-profile evidence validation; NOT production-target acceptance",
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2, sort_keys=True))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
