"""audit:production-queue-profile-evidence -- validate the behavioral-profile queue
evidence artifact and prove its validator is load-bearing (Docker-free). Exact-head bound,
canonical-hash-verified, honestly disposable, secret-clean; behavioral control PASSes only
for the complete honest conjunction. Fault mutations prove each guarantee. Asserts this
tier never promotes the production-target queue control.
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

from backend.app import production_queue_profile_evidence as P  # noqa: E402

CHECKS: list[dict] = []


def rec(cid, ok, detail=""):
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL", "detail": detail})


def main() -> int:
    payload, reasons = P.load_and_validate()
    if payload is None:
        print(json.dumps({"guard": "production_queue_profile_evidence",
                          "summary": {"passed": 0, "failed": 1, "certification": "not_passed"},
                          "detail": "no artifact; run ga:production-queue-profile-evidence first",
                          "reasons": reasons}, indent=2))
        return 1
    commit, tree = payload.get("git_commit"), payload.get("git_tree")
    rec("EV00 baseline-valid", P.validate(payload, current_commit=commit, current_tree=tree) == [],
        "the generated artifact validates at its exact bound head")
    rec("EV01 control-pass-for-honest-conjunction",
        P.behavioral_control(current_commit=commit, current_tree=tree) == "PASS",
        "the behavioral control PASSes for the complete honest artifact")
    rec("EV02 verdict-is-behavioral", payload.get("verdict") == P.BEHAVIORAL_VERDICT,
        "verdict is PRODUCTION_QUEUE_ADAPTER_BEHAVIORAL_ACCEPTED, not production-target")

    def rejects(cid, fn, *, rehash=True, detail=""):
        m = copy.deepcopy(payload)
        fn(m)
        if rehash:
            m["canonical_payload_hash"] = P.canonical_hash(m)
        reasons = P.validate(m, current_commit=commit, current_tree=tree)
        rec(cid, len(reasons) > 0, detail or (reasons[0] if reasons else "NOT rejected"))

    rejects("FE01 wrong-commit-rejected", lambda m: m.update(git_commit="0" * 40), detail="wrong git_commit rejected")
    rejects("FE02 wrong-tree-rejected", lambda m: m.update(git_tree="0" * 40), detail="wrong git_tree rejected")
    rejects("FE03 hash-mismatch-rejected", lambda m: m.update(canonical_payload_hash="a" * 64), rehash=False,
            detail="a non-matching canonical hash is rejected")
    rejects("FE04 environment-masquerade-rejected", lambda m: m["target"].update(environment_classification="production"),
            detail="environment=production is rejected (no masquerade)")
    rejects("FE05 provider-masquerade-rejected", lambda m: m["target"].update(provider_classification="managed-queue-service"),
            detail="a managed provider is rejected")
    rejects("FE06 durability-masquerade-rejected", lambda m: m["target"].update(durability_classification="durable-replicated"),
            detail="durable-replicated durability is rejected")
    rejects("FE07 exactly-once-masquerade-rejected", lambda m: m["target"].update(delivery_model="exactly-once"),
            detail="an exactly-once delivery claim is rejected")
    rejects("FE08 missing-disclosure-rejected", lambda m: m["disclosures"].update(ga_redis_adapter_remains_blocked=False),
            detail="dropping the ga-blocked disclosure is rejected")
    rejects("FE09 non-proving-class-rejected",
            lambda m: m["behavioral_domains"]["poison_dead_letter_isolation"].update(observation_class="queue_reachability_ping"),
            detail="a domain PASS from a non-proving class (ping) is rejected")
    rejects("FE10 failing-domain-rejected",
            lambda m: m["behavioral_domains"]["duplicate_delivery_no_duplicate_effect"].update(status="FAIL"),
            detail="a FAIL behavioral domain is rejected")
    rejects("FE11 incomplete-domain-rejected",
            lambda m: m["behavioral_domains"]["cross_tenant_isolation"].update(checks_passed=0),
            detail="a domain with fewer passed than total is rejected")
    rejects("FE12 dropped-domain-rejected", lambda m: m["behavioral_domains"].pop("authorized_replay_and_idempotency"),
            detail="a missing required domain is rejected")
    rejects("FE13 not-all-passed-rejected", lambda m: m["totals"].update(all_passed=False),
            detail="totals.all_passed=false is rejected")
    rejects("FE14 leaked-url-rejected", lambda m: m.update(leak="redis://:pw@10.0.0.1:6379"),
            detail="an artifact carrying a broker URL/credential leak is rejected")
    rejects("FE15 foreign-schema-at-path-rejected", lambda m: m.update(schema_version="production-queue-adapter-evidence.v1"),
            detail="the production-target schema id at this path is rejected")
    rejects("FE16 stale-artifact-rejected", lambda m: m.update(generated_at="2020-01-01T00:00:00+00:00"),
            detail="an artifact older than 90 days is rejected")

    try:
        from backend.app import production_queue_adapter_evidence as PT
        rec("EV03 production-target-control-independent",
            PT.SCHEMA_VERSION == "production-queue-adapter-evidence.v1" and PT.SCHEMA_VERSION != P.SCHEMA_VERSION,
            "the production-target queue schema/contract is a separate, untouched module")
    except Exception as exc:  # noqa: BLE001
        rec("EV03 production-target-control-independent", False, str(exc))

    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({"guard": "production_queue_profile_evidence",
                      "claim_scope": "behavioral-profile queue evidence validation; NOT production-target acceptance",
                      "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                                  "certification": "passed" if passed == len(CHECKS) else "not_passed"},
                      "checks": CHECKS}, indent=2, sort_keys=True))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
