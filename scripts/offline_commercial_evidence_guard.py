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
    coverage_met = E.environment_coverage_met(payload)
    expected_package = "PASS" if coverage_met else "BLOCKED"
    rec("OE01 controls-consistent-with-coverage",
        verdicts["offline_license_enforcement"] == "PASS"
        and verdicts["offline_windows_package"] == expected_package
        and verdicts["offline_commercial_package"] == expected_package,
        f"license control PASSes on green batteries; package/commercial follow the "
        f"environment minimum honestly ({verdicts}, coverage_met={coverage_met})")
    import copy as _copy

    def _consistent(document: dict, environments: list[str], accepted: bool = True) -> dict:
        """Rewrite the coverage-bearing fields consistently, then rehash.

        An INCONSISTENT edit is what OE12b/OE12c reject; this helper produces the
        consistent form so the coverage gate itself is what is under test.
        """

        document["results"]["package_matrix"]["environments_executed"] = list(environments)
        document["environment_coverage"]["executed"] = list(environments)
        meets = len(environments) >= E.REQUIRED_ENVIRONMENT_MINIMUM and accepted
        document["environment_coverage"]["meets_minimum"] = (
            len(environments) >= E.REQUIRED_ENVIRONMENT_MINIMUM)
        document["verdicts"]["package"] = (
            E.PACKAGE_VERDICT if meets else "OFFLINE_WINDOWS_PACKAGE_NOT_ACCEPTED")
        document["verdicts"]["commercial"] = (
            E.COMMERCIAL_VERDICT if meets else "OFFLINE_COMMERCIAL_PACKAGE_NOT_ACCEPTED")
        # Refresh BOTH seals, or the coverage gate under test is masked by a
        # stale-hash rejection that blocks every control including the licensing
        # one -- which is exactly what this pair is trying to hold still.
        document["reproducible_payload_hash"] = E.reproducible_hash(document)
        body = {k: v for k, v in document.items() if k != "canonical_payload_hash"}
        document["canonical_payload_hash"] = canonical_hash(body)
        return document

    # The gate must work in BOTH directions. Now that Environment 2 is a real
    # clean Hyper-V VM, the artifact genuinely carries two environments, so the
    # load-bearing direction to prove is that NARROWING it back to one blocks.
    widened = _consistent(_copy.deepcopy(payload),
                          ["windows-11-host-isolated", "windows-11-hyperv"])
    widened_verdicts = E.control_verdicts(
        widened, E.validate(widened, current_commit=commit, current_tree=tree))
    rec("OE01b coverage-gate-passes-on-two-environments",
        widened_verdicts["offline_windows_package"] == "PASS"
        and widened_verdicts["offline_commercial_package"] == "PASS",
        "a green matrix across two distinct environments yields package/commercial PASS")

    narrowed = _consistent(_copy.deepcopy(payload), ["windows-11-host-isolated"])
    narrowed_verdicts = E.control_verdicts(
        narrowed, E.validate(narrowed, current_commit=commit, current_tree=tree))
    rec("OE01c coverage-gate-blocks-single-environment",
        narrowed_verdicts["offline_windows_package"] == "BLOCKED"
        and narrowed_verdicts["offline_commercial_package"] == "BLOCKED"
        and narrowed_verdicts["offline_license_enforcement"] ==
            widened_verdicts["offline_license_enforcement"],
        "the SAME green matrix narrowed to one environment blocks package/commercial "
        "while leaving the license control untouched — the environment gate is the "
        "only thing that moved")

    def rehash(document: dict) -> dict:
        body = {k: v for k, v in document.items() if k != "canonical_payload_hash"}
        document["canonical_payload_hash"] = canonical_hash(body)
        return document

    def rejects(cid: str, mutate, *, skip_rehash: bool = False, detail: str = "",
                expect: str | None = None, reseal: bool = True) -> None:
        """Require the mutation to be refused -- and, when ``expect`` is given,
        refused FOR THAT REASON rather than incidentally by a stale seal.

        ``reseal`` refreshes the reproducible hash too, so a mutation aimed at a
        semantic rule is not masked by a hash mismatch.
        """

        mutant = copy.deepcopy(payload)
        mutate(mutant)
        if reseal:
            mutant["reproducible_payload_hash"] = E.reproducible_hash(mutant)
        if not skip_rehash:
            rehash(mutant)
        result = E.validate(mutant, current_commit=commit, current_tree=tree)
        ok = len(result) > 0 and (expect is None or any(expect in r for r in result))
        rec(cid, ok, detail or (("; ".join(result))[:200] if result else "NOT rejected"))

    # Every rejection below reseals the reproducible hash first, so the refusal
    # comes from the RULE under test and not incidentally from a stale seal, and
    # each asserts the reason it is meant to trigger.
    rejects("OE02 wrong-commit-rejected", lambda m: m.update(git_commit="0" * 40),
            expect="current exact commit")
    rejects("OE03 wrong-tree-rejected", lambda m: m.update(git_tree="0" * 40),
            expect="current exact tree")
    rejects("OE04 hash-tamper-rejected",
            lambda m: m.update(canonical_payload_hash="f" * 64), skip_rehash=True,
            reseal=False, expect="canonical payload hash")
    rejects("OE05 stale-artifact-rejected",
            lambda m: m.update(generated_at="2020-01-01T00:00:00+00:00"),
            expect="stale")
    rejects("OE06 dropped-disclosure-rejected",
            lambda m: m["disclosures"].update(not_ga_acceptance=False),
            expect="disclosure")
    rejects("OE07 failing-battery-rejected",
            lambda m: m["results"]["license_battery"].update(failed=3),
            expect="not fully passing")
    rejects("OE08 missing-section-rejected",
            lambda m: m["results"].pop("package_matrix"),
            expect="missing result section")
    rejects("OE09 empty-environment-matrix-rejected",
            lambda m: m["results"]["package_matrix"].update(environments_executed=[]),
            expect="no executed environment")
    rejects("OE10 private-key-presence-rejected",
            lambda m: m["package"].update(private_key_absent=False),
            expect="private-key-absence")
    rejects("OE11 leak-shape-rejected",
            lambda m: m.update(diagnostic="adapter 00:1A:2B:3C:4D:5E failed"),  # leak-test fixture
            expect="leak shape")
    rejects("OE12 missing-installer-hash-rejected",
            lambda m: m["package"].update(installer_sha256=""),
            expect="installer hash")

    def _claim_acceptance(m: dict) -> None:
        # Narrow coverage to ONE environment consistently -- executed list and
        # meets_minimum agree, so nothing else in the document is malformed --
        # while leaving the ACCEPTED verdicts in place. The only thing wrong is
        # that the stored verdicts outrun what the recorded results support.
        m["results"]["package_matrix"]["environments_executed"] = ["windows-11-host-isolated"]
        m["environment_coverage"]["executed"] = ["windows-11-host-isolated"]
        m["environment_coverage"]["meets_minimum"] = False
        m["verdicts"]["package"] = E.PACKAGE_VERDICT
        m["verdicts"]["commercial"] = E.COMMERCIAL_VERDICT

    rejects("OE12b overclaimed-verdict-rejected", _claim_acceptance, reseal=True,
            expect="stored verdict",
            detail="a hand-edited artifact cannot assert an acceptance the recorded "
                   "results do not support, even with both seals recomputed")
    rejects("OE12c forged-coverage-flag-rejected",
            lambda m: m["environment_coverage"].update(meets_minimum=False),
            reseal=True, expect="meets_minimum",
            detail="meets_minimum must agree with the recorded executed environments")

    # ---- the two-environment record the package matrix is derived from ----
    rec("OE16 two-environment-record-bound",
        isinstance(payload.get("two_environment_record"), dict)
        and payload["two_environment_record"].get("schema_version")
            == E.TWO_ENVIRONMENT_RECORD_SCHEMA
        and payload["two_environment_record"].get("accepted") is True,
        "the artifact carries the accepted two-environment record its package "
        "matrix was derived from")

    rejects("OE17 missing-two-environment-record-rejected",
            lambda m: m.pop("two_environment_record"), expect="no two-environment record",
            detail="evidence without a two-environment record cannot claim two environments")
    rejects("OE18 unaccepted-two-environment-record-rejected",
            lambda m: m["two_environment_record"].update(accepted=False),
            expect="was not accepted")
    rejects("OE19 non-identical-package-bytes-rejected",
            lambda m: m["two_environment_record"].update(identical_package_bytes=False),
            expect="identical package bytes",
            detail="the two environments must have run byte-identical package bytes")
    rejects("OE20 duplicate-environment-identity-rejected",
            lambda m: m["two_environment_record"].update(independent_identities=False),
            expect="independent identities",
            detail="one machine reported twice is not two environments")
    # The reproducible hash must be exactly what a second run at this head would
    # agree on: everything except when the run happened.
    rec("OE15b reproducible-hash-excludes-only-the-timestamp",
        E.reproducible_hash(payload) == payload.get("reproducible_payload_hash")
        and E.reproducible_hash({**payload, "generated_at": "1999-01-01T00:00:00+00:00"})
            == payload.get("reproducible_payload_hash"),
        "the reproducible hash is stable across generation time and unchanged by it")
    rejects("OE15c reproducible-hash-tamper-rejected",
            lambda m: m.update(reproducible_payload_hash="f" * 64),
            reseal=False, expect="reproducible payload hash")
    rejects("OE15d reproducible-hash-covers-results",
            lambda m: m["results"]["license_battery"].update(passed=999),
            reseal=False, expect="reproducible payload hash",
            detail="a changed result changes the reproducible hash, so a second "
                   "run at the same head could not agree with it")

    rejects("OE20b record-from-a-different-commit-rejected",
            lambda m: m["two_environment_record"].update(source_commit="0" * 40),
            expect="different commit",
            detail="a record produced at another head cannot be bound to this evidence")
    rejects("OE20c record-from-a-different-tree-rejected",
            lambda m: m["two_environment_record"].update(source_tree="0" * 40),
            expect="different tree")
    rejects("OE21 repeated-environment-class-rejected",
            lambda m: m["results"]["package_matrix"].update(
                environments_executed=["windows-11-hyperv", "windows-11-hyperv"]),
            expect="same environment class twice",
            detail="the same environment class listed twice is one environment counted twice")

    # ---- the proofs that make the second environment meaningful ----
    for cid, section in (("OE22", "airgap_boundary"),
                         ("OE23", "hyperv_isolation"),
                         ("OE24", "combiner_faults")):
        rejects(f"{cid} missing-{section.replace('_', '-')}-section-rejected",
                lambda m, s=section: m["results"].pop(s),
                expect="missing result section")
        rejects(f"{cid}b failing-{section.replace('_', '-')}-rejected",
                lambda m, s=section: m["results"][s].update(failed=1),
                expect="not fully passing")

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
