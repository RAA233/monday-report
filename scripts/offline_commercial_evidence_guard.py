"""audit:offline-commercial-evidence -- validate the Offline Edition evidence
artifact and prove the validator is load-bearing via fault mutations. Also
asserts this tier CANNOT influence the production-target or GA controls.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app import offline_commercial_evidence as E  # noqa: E402
from backend.app.licensing.canonical import canonical_hash  # noqa: E402

CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str = "") -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "detail": detail})


def main() -> int:
    CHECKS.clear()
    payload, reasons = E.load_and_validate()
    if payload is None:
        print(json.dumps({"guard": "offline_commercial_evidence",
                          "summary": {"passed": 0, "failed": 1,
                                      "certification": "not_passed"},
                          "detail": "no artifact; run ga:offline-commercial-evidence first"}))
        return 1
    commit, tree = payload.get("git_commit"), payload.get("git_tree")

    rec("OE00 baseline-valid", reasons == [],
        f"the generated artifact validates at its exact head ({reasons or 'valid'})")
    verdicts = E.control_verdicts(payload, reasons)
    rec("OE01 controls-pass-for-honest-artifact",
        verdicts == {"offline_license_enforcement": "PASS",
                     "offline_windows_package": "PASS",
                     "offline_commercial_package": "PASS"},
        f"the three OFFLINE controls PASS together ({verdicts})")

    def rehash(document: dict) -> dict:
        body = {k: v for k, v in document.items() if k != "canonical_payload_hash"}
        document["canonical_payload_hash"] = canonical_hash(body)
        return document

    def rejects(cid: str, mutate, *, skip_rehash: bool = False, detail: str = "") -> None:
        mutant = copy.deepcopy(payload)
        mutate(mutant)
        if not skip_rehash:
            rehash(mutant)
        result = E.validate(mutant, current_commit=commit, current_tree=tree)
        rec(cid, len(result) > 0, detail or (result[0] if result else "NOT rejected"))

    rejects("OE02 wrong-commit-rejected", lambda m: m.update(git_commit="0" * 40))
    rejects("OE03 wrong-tree-rejected", lambda m: m.update(git_tree="0" * 40))
    rejects("OE04 hash-tamper-rejected",
            lambda m: m.update(canonical_payload_hash="f" * 64), skip_rehash=True)
    rejects("OE05 stale-artifact-rejected",
            lambda m: m.update(generated_at="2020-01-01T00:00:00+00:00"))
    rejects("OE06 dropped-disclosure-rejected",
            lambda m: m["disclosures"].update(not_ga_acceptance=False))
    rejects("OE07 failing-battery-rejected",
            lambda m: m["results"]["license_battery"].update(failed=3))
    rejects("OE08 missing-section-rejected",
            lambda m: m["results"].pop("package_matrix"))
    rejects("OE09 empty-environment-matrix-rejected",
            lambda m: m["results"]["package_matrix"].update(environments_executed=[]))
    rejects("OE10 private-key-presence-rejected",
            lambda m: m["package"].update(private_key_absent=False))
    rejects("OE11 leak-shape-rejected",
            lambda m: m.update(diagnostic="adapter 00:1A:2B:3C:4D:5E failed"))
    rejects("OE12 missing-installer-hash-rejected",
            lambda m: m["package"].update(installer_sha256=""))

    blocked = E.control_verdicts(payload, ["any reason"])
    rec("OE13 invalid-artifact-blocks-all-controls",
        set(blocked.values()) == {"BLOCKED"},
        "an invalid artifact can never yield a PASS control")

    ga_registry = ROOT / "evals" / "ga" / "blocker_registry.v1.json"
    if ga_registry.exists():
        registry = json.loads(ga_registry.read_text(encoding="utf-8"))
        entries = registry.get("blockers", registry.get("controls", registry))
        count = len(entries) if isinstance(entries, (list, dict)) else 0
        offline_in_registry = "offline" in json.dumps(registry).lower()
        rec("OE14 ga-registry-untouched",
            count == 28 and not offline_in_registry,
            f"the GA registry still holds its 28 controls and no offline control "
            f"was injected (count={count})")
    else:
        rec("OE14 ga-registry-untouched", False, "GA registry file missing")

    evidence_text = json.dumps(payload)
    rec("OE15 no-production-target-claim",
        "PRODUCTION_DATABASE_ADAPTER_ACCEPTED" not in evidence_text
        and "PRODUCTION_QUEUE_ADAPTER_ACCEPTED" not in evidence_text
        and "GA_ACCEPTED" not in evidence_text.replace("NOT_GA_ACCEPTED", ""),
        "the offline evidence never asserts production-target or GA acceptance")

    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "offline_commercial_evidence",
        "claim_scope": "offline evidence validation; separate from production/GA controls",
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
