"""``audit:offline-evidence-contract`` -- the hermetic, no-VM contract battery for
the authoritative offline acceptance tier.

WHY THIS RUNS INSIDE ``audit:all``
-----------------------------------
An independent review reproduced two defects. The second was that ``audit:all``
expanded to 70 steps containing ZERO authoritative offline validation, and its
membership was invariant under removal of ``audit:offline-commercial-evidence``
(70 steps with it, 70 without). The real gate lived entirely outside the general
audit chain, so a forged artifact was invisible to it.

This guard closes that without making an ordinary developer run need a VM, a
package, or a second machine: it builds SYNTHETIC documents with a THROWAWAY
keypair and drives the REAL validator through its private ``_evaluate`` seam.
Synthetic data, real evaluation functions.

DISCIPLINE THIS BATTERY ENFORCES ON ITSELF
------------------------------------------
* **Baseline first.** A fully valid synthetic artifact must be ACCEPTED before
  any rejection is claimed. Without that, fifteen "rejections" pass trivially
  against an always-fail validator.
* **Reseal AND re-sign every mutation.** Every mutation changes the canonical
  payload hash. A battery that reseals but does not re-sign proves only that the
  seal works, and leaves the signature and the cross-environment rules untested.
  This matters most for the copied-environment case: in the real protocol the
  reviewer signs, so the tier must reject a forgery that a VALID signature
  covers.
* **Fail for the INTENDED reason.** A mutation that fails for an unrelated
  reason, raises, or produces no output does not count as detection.
"""
from __future__ import annotations

import copy
import hashlib
import inspect
import json
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from backend.app import offline_authoritative_evidence as A  # noqa: E402
from backend.app import offline_commercial_evidence as LEGACY  # noqa: E402
from backend.app.licensing.canonical import canonical_hash  # noqa: E402
from backend.app.offline_review_attestation import (  # noqa: E402
    ATTESTATION_SCHEMA,
    REVIEW_VERDICT_ACCEPT,
    REVIEW_VERDICT_REJECT,
    TRANSCRIPT_SCHEMA,
    TRUST_ROOT_SCHEMA,
    WITNESS_SCHEMA,
    chain_check_results,
    key_fingerprint,
    principal_digest,
    sign_attestation,
    transcript_hash,
)

CONTRACT_COMMAND = "audit:offline-evidence-contract"
CONTRACT_SCRIPT = "python -I scripts/offline_evidence_contract_guard.py"
#: The second pinned member, named here so that dropping it from audit:all
#: requires editing this file too. It decides the acceptance predicate itself --
#: no principal that can write the release tree may hold Administrator -- and it
#: was registered in package.json and run by no chain at all.
PRINCIPAL_COMMAND = "audit:offline-operator-principal"
PRINCIPAL_SCRIPT = "python scripts/offline_operator_principal_guard.py"

#: Synthetic principals. Resolved through the injected resolver, never live.
AUTHOR_ACCOUNT = "SYNTHETIC-AUTHOR"
REVIEWER_ACCOUNT = "SYNTHETIC-REVIEWER"
AUTHOR_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
REVIEWER_SID = "S-1-5-21-1111111111-2222222222-3333333333-1002"
SALT = "contract-guard-salt"

COMMIT = "a" * 40
TREE = "b" * 40


class Battery:
    def __init__(self) -> None:
        self.checks: list[dict] = []

    def record(self, cid: str, ok: bool, detail: str) -> bool:
        self.checks.append({"id": cid, "ok": bool(ok), "detail": detail})
        print(f"{'PASS' if ok else 'FAIL'} {cid}: {detail}")
        return bool(ok)

    @property
    def passed(self) -> int:
        return len([c for c in self.checks if c["ok"]])

    @property
    def failed(self) -> int:
        return len([c for c in self.checks if not c["ok"]])


def sid_resolver(name: str) -> str:
    return {AUTHOR_ACCOUNT: AUTHOR_SID, REVIEWER_ACCOUNT: REVIEWER_SID}.get(name, "")


def clean_worktree() -> list[str]:
    return []


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


#: The throwaway issuer key the fixture signs its witnesses with. The validator
#: resolves the licence-verification key from the package, so the fixture must
#: sign with a key whose fingerprint the fixture's package block also names.
_FIXTURE_ISSUER = Ed25519PrivateKey.generate()


def _sign_witness(witness: dict) -> dict:
    from backend.app.offline_review_attestation import witness_signing_payload
    signed = {k: v for k, v in witness.items() if k != "signature"}
    signed["signature"] = _FIXTURE_ISSUER.sign(witness_signing_payload(signed)).hex()
    return signed


def build_transcript(label: str, seed: str, nonce: str, package: dict) -> dict:
    """A synthetic but internally COHERENT transcript: identity derives from the
    binding, and the completion challenge derives from the ordered check chain."""

    binding = {"machine_class": label.lower(), "component_a": digest(seed + "a"),
               "component_b": digest(seed + "b"), "strong_component": digest(seed + "s")}
    fingerprint = canonical_hash(binding)
    checks = [{"id": f"PK{n:02d}", "ok": True} for n in range(1, 35)]
    start = digest(seed + "start")
    completion = chain_check_results(
        start, [f"{c['id']}={c['ok']}" for c in checks])
    request_hash = digest(seed + "request")
    transcript = {
        "schema_version": TRANSCRIPT_SCHEMA,
        "environment_label": label,
        "environment_class": f"windows-11-{label.lower()}",
        "source_commit": COMMIT if len(COMMIT) == 64 else digest(COMMIT),
        "source_tree": TREE if len(TREE) == 64 else digest(TREE),
        "package_version": package["package_version"],
        "installer_sha256": package["installer_sha256"],
        "executable_sha256": package["executable_sha256"],
        "payload_manifest_sha256": package["payload_manifest_sha256"],
        "frontend_manifest_sha256": package["frontend_manifest_sha256"],
        "public_key_fingerprint": package["public_key_fingerprint"],
        "matrix_tool_hash": digest(seed + "tool"),
        "matrix_start_challenge": start,
        "matrix_completion_challenge": completion,
        "ordered_check_result_hash": digest(seed + "ordered"),
        "raw_transcript_hash": digest(seed + "raw"),
        "environment_result_hash": digest(seed + "result"),
        "machine_binding": binding,
        "machine_fingerprint_hash": fingerprint,
        "fingerprint_identity_digest": fingerprint[:32],
        # A GENUINELY SIGNED witness. A placeholder signature was enough while
        # nothing verified it; now that the validator does, the fixture has to
        # produce a real one or the baseline fails and every rejection below it
        # becomes vacuous.
        "issuance_witness": _sign_witness({
            "schema_version": WITNESS_SCHEMA,
            "domain": "monday-report/offline-issuance-witness/v1",
            "review_nonce": nonce,
            "environment_label": label,
            "activation_request_hash": request_hash,
            "requested_fingerprint_digest": fingerprint[:32],
            "source_commit": digest(COMMIT),
            "source_tree": digest(TREE),
            "licence_set_digest": digest(seed + "licences"),
            "issuer_key_fingerprint": package["public_key_fingerprint"],
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expiry_seconds": 240,
        }),
        "offline": True,
        "localhost_only": True,
        "dependency_absence": True,
        "cross_license_rejected": True,
        "backup_restore": True,
        "expiry_read_only": True,
        "upgrade": True,
        "uninstall_reinstall": True,
        "totals": {"passed": len(checks), "failed": 0},
        "checks": checks,
    }
    return transcript


def build_artifact(private_key: Ed25519PrivateKey) -> dict:
    package = {
        "package_version": "1.0.0",
        "installer_sha256": digest("installer"),
        "executable_sha256": digest("executable"),
        "payload_manifest_sha256": digest("payload"),
        "frontend_manifest_sha256": digest("frontend"),
        "public_key_fingerprint": key_fingerprint(
            _FIXTURE_ISSUER.public_key().public_bytes_raw()),
        "private_key_absent": True,
    }
    nonce = digest("review-nonce")
    transcripts = {
        "ENVIRONMENT_1": build_transcript("ENVIRONMENT_1", "e1", nonce, package),
        "ENVIRONMENT_2": build_transcript("ENVIRONMENT_2", "e2", nonce, package),
    }
    now = datetime.now(timezone.utc)
    body = {
        "schema_version": A.SCHEMA_VERSION,
        "evidence_type": A.EVIDENCE_TYPE,
        "generated_at": now.isoformat(),
        "git_commit": digest(COMMIT),
        "git_tree": digest(TREE),
        "package": package,
        "environment_transcripts": transcripts,
        "disclosures": dict(A.REQUIRED_DISCLOSURES),
    }
    attestation = {
        "schema_version": ATTESTATION_SCHEMA,
        "reviewer_key_fingerprint": key_fingerprint(
            private_key.public_key().public_bytes_raw()),
        "reviewer_principal_digest": principal_digest(REVIEWER_SID, SALT),
        "author_principal_digest": principal_digest(AUTHOR_SID, SALT),
        "source_commit": body["git_commit"],
        "source_tree": body["git_tree"],
        "package_version": package["package_version"],
        "installer_sha256": package["installer_sha256"],
        "executable_sha256": package["executable_sha256"],
        "payload_manifest_sha256": package["payload_manifest_sha256"],
        "frontend_manifest_sha256": package["frontend_manifest_sha256"],
        "public_key_fingerprint": package["public_key_fingerprint"],
        "environment_transcript_hashes": {
            label: transcript_hash(t) for label, t in transcripts.items()},
        "environment_result_hashes": {
            label: t["environment_result_hash"] for label, t in transcripts.items()},
        "cross_environment_proof_hash": digest("cross"),
        "evidence_body_digest": canonical_hash(body),
        "validator_source_digest": digest("validator"),
        "audit_all_step_digest": digest("auditall"),
        "review_tool_hashes": {"python": digest("py"), "git": digest("git")},
        "review_started_at": (now - timedelta(minutes=30)).isoformat(),
        "review_completed_at": now.isoformat(),
        "review_nonce": nonce,
        "review_verdict": REVIEW_VERDICT_ACCEPT,
        "review_reason_codes": [],
    }
    artifact = dict(body)
    artifact["independent_review"] = sign_attestation(attestation, private_key)
    artifact["canonical_payload_hash"] = canonical_hash(artifact)
    return artifact


def reseal_and_resign(artifact: dict, private_key: Ed25519PrivateKey) -> dict:
    """Recompute EVERY author-controlled derived value, then re-sign.

    This is what makes each mutation a genuine test of the rule rather than of
    the seal: after this, the document is as internally consistent and as
    validly signed as an honest one.
    """

    artifact = copy.deepcopy(artifact)
    artifact.pop("canonical_payload_hash", None)
    attestation = artifact.pop("independent_review", {})
    body = {k: v for k, v in artifact.items()}
    attestation = {k: v for k, v in attestation.items() if k != "signature"}
    attestation["environment_transcript_hashes"] = {
        label: transcript_hash(t)
        for label, t in artifact.get("environment_transcripts", {}).items()}
    attestation["evidence_body_digest"] = canonical_hash(body)
    artifact["independent_review"] = sign_attestation(attestation, private_key)
    artifact["canonical_payload_hash"] = canonical_hash(artifact)
    return artifact


def evaluate(artifact: dict, trust_root: Path, pinned: str,
             current_commit: str | None = None,
             current_tree: str | None = None) -> list[str]:
    """Evaluate against a FIXED live head.

    Taking the head from the artifact would make the exact-head rule
    self-satisfying -- the document would define the very value it is checked
    against, and a moved-commit mutation would silently test something else.
    """

    raw = json.dumps(artifact, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    result = A._evaluate(artifact, raw,
                         current_commit=current_commit if current_commit is not None
                         else digest(COMMIT),
                         current_tree=current_tree if current_tree is not None
                         else digest(TREE),
                         trust_root_path=trust_root, pinned_fingerprint=pinned,
                         worktree_status=clean_worktree, sid_resolver=sid_resolver,
                         current_sid=lambda: AUTHOR_SID,
                         issuer_public_key=_FIXTURE_ISSUER.public_key().public_bytes_raw())
    reasons = list(result.reasons)
    unobserved = A.REQUIRED_CHECKS - result.checked
    if unobserved:
        reasons.append("unobserved checks: " + ",".join(sorted(unobserved)))
    return reasons


def write_trust_root(path: Path, public_bytes: bytes, *, reviewer=REVIEWER_ACCOUNT,
                     author=AUTHOR_ACCOUNT) -> None:
    root = {
        "schema_version": TRUST_ROOT_SCHEMA,
        "review_public_key_hex": public_bytes.hex(),
        "review_key_fingerprint": key_fingerprint(public_bytes),
        "reviewer_account_name": reviewer,
        "author_account_name": author,
        "principal_salt": SALT,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    path.write_text(json.dumps(root, indent=2), encoding="utf-8")
    # The anchor must be READABLE by the validating process and NOT WRITABLE by
    # it. Read is required (it has to verify against the key); write is exactly
    # what would let the constrained process replace its own constraint.
    user = f"{__import__('os').environ.get('USERDOMAIN','')}\\{__import__('os').environ.get('USERNAME','')}"
    subprocess.run(["icacls", str(path), "/inheritance:r"],
                   capture_output=True, text=True, timeout=60)
    subprocess.run(["icacls", str(path), "/grant:r", "*S-1-5-18:(F)", f"{user}:(R)"],
                   capture_output=True, text=True, timeout=60)


def main() -> int:
    battery = Battery()
    work = Path(tempfile.mkdtemp(prefix="mr-offline-contract-"))
    try:
        key = Ed25519PrivateKey.generate()
        public_bytes = key.public_key().public_bytes_raw()
        pinned = key_fingerprint(public_bytes)
        trust_root = work / "trust-root.json"
        write_trust_root(trust_root, public_bytes)

        artifact = build_artifact(key)

        # ---- CT00 baseline: a valid synthetic artifact MUST be accepted -----
        baseline = evaluate(artifact, trust_root, pinned)
        if not battery.record("CT00 baseline-accepts", not baseline,
                              f"valid synthetic v2 artifact reasons={baseline[:3]}"):
            print("\nbaseline failed; every rejection below would be vacuous")
            summary(battery)
            return 1

        def mutation(cid: str, description: str, mutate, expect: str) -> None:
            """baseline passes -> mutate -> fail for the INTENDED reason -> restore."""

            mutated = copy.deepcopy(artifact)
            try:
                produced = mutate(mutated)
            except Exception as exc:  # a crash is not detection
                battery.record(cid, False, f"{description}: mutation raised {exc!r}")
                return
            if produced is not None:
                mutated = produced
            try:
                reasons = evaluate(mutated, trust_root, pinned)
            except Exception as exc:  # nor is an exception in the validator
                battery.record(cid, False, f"{description}: validator raised {exc!r}")
                return
            hit = [r for r in reasons if expect.lower() in r.lower()]
            battery.record(cid, bool(hit),
                           f"{description} -> {(hit[0] if hit else ('NOT REJECTED' if not reasons else 'wrong reason: ' + reasons[0]))[:110]}")
            # restore is structural: `artifact` was never mutated (deep copy).
            after = evaluate(copy.deepcopy(artifact), trust_root, pinned)
            if after:
                battery.record(f"{cid}-restore", False,
                               "baseline no longer passes after the mutation cycle")

        # ---- Part K, mutation 1: the reproduced HIGH 1 attack ---------------
        def copy_e1_over_e2(doc):
            e1 = copy.deepcopy(doc["environment_transcripts"]["ENVIRONMENT_1"])
            e1["environment_label"] = "ENVIRONMENT_2"
            e1["environment_class"] = "windows-11-hyperv"
            e1["fingerprint_identity_digest"] = "d" * 32
            doc["environment_transcripts"]["ENVIRONMENT_2"] = e1
            return reseal_and_resign(doc, key)

        mutation("CT01 copied-environment", "E2 := verbatim copy of E1, resealed AND re-signed",
                 copy_e1_over_e2, "fingerprint_identity_digest does not derive")

        # ---- 2-6: attestation and principal attacks ------------------------
        def drop_attestation(doc):
            doc.pop("independent_review")
            doc["canonical_payload_hash"] = canonical_hash(
                {k: v for k, v in doc.items() if k != "canonical_payload_hash"})
        mutation("CT02 attestation-removed", "independent review deleted",
                 drop_attestation, "no independent review attestation")

        def replace_signature(doc):
            doc["independent_review"]["signature"] = "f" * 128
            doc["canonical_payload_hash"] = canonical_hash(
                {k: v for k, v in doc.items() if k != "canonical_payload_hash"})
        mutation("CT03 signature-replaced", "reviewer signature overwritten",
                 replace_signature, "signature does not verify")

        def replace_key_in_evidence(doc):
            other = Ed25519PrivateKey.generate()
            doc["independent_review"]["reviewer_key_fingerprint"] = key_fingerprint(
                other.public_key().public_bytes_raw())
            return reseal_and_resign(doc, key)
        mutation("CT04 review-key-renamed", "artifact names a different review key",
                 replace_key_in_evidence, "names a different review key")

        def author_signs_as_reviewer(doc):
            other = Ed25519PrivateKey.generate()   # a key the trust root does not pin
            return reseal_and_resign(doc, other)
        mutation("CT05 author-key-as-review-key", "artifact signed with an unpinned key",
                 author_signs_as_reviewer, "signature does not verify")

        def same_principal(doc):
            doc["independent_review"]["reviewer_principal_digest"] = principal_digest(
                AUTHOR_SID, SALT)
            return reseal_and_resign(doc, key)
        mutation("CT06 same-principal-review", "reviewer principal == author principal",
                 same_principal, "reviewer principal does not match")

        # ---- 7-9: replay and transcript tampering --------------------------
        def stale_attestation_new_package(doc):
            doc["package"]["installer_sha256"] = digest("different-installer")
            for t in doc["environment_transcripts"].values():
                t["installer_sha256"] = doc["package"]["installer_sha256"]
            doc["canonical_payload_hash"] = canonical_hash(
                {k: v for k, v in doc.items() if k != "canonical_payload_hash"})
        mutation("CT07 old-attestation-new-package",
                 "genuine attestation kept, package swapped",
                 stale_attestation_new_package, "does not bind this package")

        def stale_attestation_new_transcripts(doc):
            doc["environment_transcripts"]["ENVIRONMENT_2"]["raw_transcript_hash"] = digest("new-raw")
            doc["canonical_payload_hash"] = canonical_hash(
                {k: v for k, v in doc.items() if k != "canonical_payload_hash"})
        mutation("CT08 old-attestation-new-transcripts",
                 "genuine attestation kept, transcript altered",
                 stale_attestation_new_transcripts, "does not match the hash the reviewer signed")

        def tamper_one_check(doc):
            doc["environment_transcripts"]["ENVIRONMENT_1"]["checks"][3]["ok"] = False
            return reseal_and_resign(doc, key)
        mutation("CT09 transcript-check-altered", "one raw check flipped after countersigning",
                 tamper_one_check, "totals disagree with the ordered check list")

        # ---- 10-11: package and head ---------------------------------------
        def change_package_hash(doc):
            doc["environment_transcripts"]["ENVIRONMENT_2"]["executable_sha256"] = digest("other")
            return reseal_and_resign(doc, key)
        mutation("CT10 package-hash-differs", "environments ran different bytes",
                 change_package_hash, "did not run identical package bytes")

        def change_commit(doc):
            doc["git_commit"] = digest("other-commit")
            return reseal_and_resign(doc, key)
        mutation("CT11 commit-differs", "artifact head moved",
                 change_commit, "does not belong to the current exact commit")

        # ---- 12-13: audit:all membership, as LOAD-BEARING cycles ------------
        # Static assertions would only prove the wiring exists today. These are
        # full cycles -- baseline passes, membership is removed, the pin fails
        # for the intended reason, the tree is restored, baseline passes again --
        # applied to COPIES. Tracked package.json is never modified.
        battery.record(
            "CT12a membership-baseline", not membership_reasons_for(None),
            "audit:all pins the offline evidence contract")
        battery.record(
            "CT12b removal-detected",
            any("does not contain" in r for r in membership_reasons_for("remove-step")),
            "removing the step from audit:all is detected")
        battery.record(
            "CT12c demotion-detected",
            any("after a step that can fail" in r for r in membership_reasons_for("append-step")),
            "moving the step behind a failing step is detected")
        battery.record(
            "CT12d fallthrough-detected",
            any("strict && chain" in r for r in membership_reasons_for("or-join")),
            "converting audit:all to a || chain is detected")
        battery.record(
            "CT13a meta-guard-neutering-detected",
            any("no longer asserts" in r for r in membership_reasons_for("neuter-asserter")),
            "neutering the redundant asserter is detected")
        battery.record(
            "CT13b battery-hollowing-detected",
            any("does not" in r and "append a result" in r
                for r in membership_reasons_for("hollow-battery")),
            "rebinding the contract battery's recorder is detected, even though "
            "the file still parses and the original method is untouched")
        battery.record(
            "CT12e principal-membership-removal-detected",
            any("does not contain audit:offline-operator-principal" in r
                for r in membership_reasons_for("remove-principal-step")),
            "dropping the battery that decides the acceptance predicate from "
            "audit:all is reported")
        battery.record(
            "CT12f principal-battery-hollowing-detected",
            any("does not" in r and "append a result" in r
                for r in membership_reasons_for("hollow-principal-battery")),
            "shadowing the recording function with a no-op is reported, even "
            "though the file still parses and every check id still reaches a call")
        battery.record(
            "CT13c membership-restored", not membership_reasons_for(None),
            "baseline still passes after every membership mutation")

        # ---- 14-15: forged acceptance claims --------------------------------
        def forge_accepted_boolean(doc):
            doc["independent_review"]["review_verdict"] = REVIEW_VERDICT_ACCEPT
            for t in doc["environment_transcripts"].values():
                t["totals"] = {"passed": 34, "failed": 3}
            return reseal_and_resign(doc, key)
        mutation("CT14 accepted-flag-forged", "totals record failures while verdict claims accept",
                 forge_accepted_boolean, "records failed checks")

        def v1_relabelled(doc):
            legacy = {
                "schema_version": A.SCHEMA_VERSION,   # v1 body wearing the v2 label
                "evidence_type": A.EVIDENCE_TYPE,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "git_commit": doc["git_commit"], "git_tree": doc["git_tree"],
                "package": doc["package"],
                "results": {"license_battery": {"passed": 49, "failed": 0}},
                "two_environment_record": {"accepted": True, "environment_count": 2},
                "verdicts": {"commercial": "OFFLINE_COMMERCIAL_PACKAGE_ACCEPTED"},
                "disclosures": dict(A.REQUIRED_DISCLOSURES),
                "canonical_payload_hash": "",
            }
            legacy["canonical_payload_hash"] = canonical_hash(
                {k: v for k, v in legacy.items() if k != "canonical_payload_hash"})
            return legacy
        mutation("CT15 v1-relabelled-as-v2", "legacy body wearing the v2 schema label",
                 v1_relabelled, "unknown keys")

        # The witness signature must be LOAD-BEARING. It was verified nowhere in
        # the production path, so the "anti-replay anchor" was an unsigned blob
        # every field check happily accepted.
        def break_witness_signature(doc):
            doc["environment_transcripts"]["ENVIRONMENT_1"]["issuance_witness"]["signature"] = "0" * 128
            return reseal_and_resign(doc, key)
        mutation("CT22 witness-signature-load-bearing",
                 "issuance witness signature replaced",
                 break_witness_signature, "signature does not verify")

        def foreign_witness_key(doc):
            other = Ed25519PrivateKey.generate()
            from backend.app.offline_review_attestation import witness_signing_payload
            w = doc["environment_transcripts"]["ENVIRONMENT_2"]["issuance_witness"]
            body = {k: v for k, v in w.items() if k != "signature"}
            body["signature"] = other.sign(witness_signing_payload(body)).hex()
            doc["environment_transcripts"]["ENVIRONMENT_2"]["issuance_witness"] = body
            return reseal_and_resign(doc, key)
        mutation("CT23 witness-signed-by-another-key",
                 "witness signed by a key the package does not verify with",
                 foreign_witness_key, "signature does not verify")

        # ---- structural: the legacy tier cannot emit acceptance -------------
        legacy_source = inspect.getsource(LEGACY)
        battery.record(
            "CT16 legacy-cannot-accept",
            "OFFLINE_COMMERCIAL_PACKAGE_ACCEPTED" not in legacy_source,
            "the legacy module contains no acceptance literal")
        battery.record(
            "CT17 legacy-verdicts-blocked",
            all(v == "BLOCKED" for v in LEGACY.control_verdicts({"results": {}}, []).values()),
            "legacy control_verdicts is unconditionally BLOCKED")

        entry_source = inspect.getsource(A.load_and_validate_authoritative)
        battery.record(
            "CT18 public-entry-uses-real-evaluator",
            "_evaluate(" in entry_source and not any(
                k in entry_source for k in ("trust_root_path", "pinned_fingerprint",
                                            "worktree_status", "sid_resolver", "current_sid")),
            "the public entry calls _evaluate and passes no test seam")
        battery.record(
            "CT19 no-env-trust-root",
            "environ" not in inspect.getsource(A._load_trust_root),
            "the trust root honours no environment variable")

        # A single module owns the acceptance strings.
        owners = sorted(p.relative_to(ROOT).as_posix()
                        for p in (ROOT / "backend").rglob("*.py")
                        if "OFFLINE_COMMERCIAL_PACKAGE_ACCEPTED" in p.read_text(encoding="utf-8"))
        battery.record(
            "CT20 single-acceptance-owner", owners == ["backend/app/offline_authoritative_evidence.py"],
            f"acceptance literal owners = {owners}")

        battery.record(
            "CT21 placeholder-pin-rejected",
            bool(evaluate(artifact, trust_root, "0000000000000000")),
            "an unpinned review key is rejected")

    finally:
        shutil.rmtree(work, ignore_errors=True)

    # A RUN-TIME FLOOR, reported directly.
    #
    # The principal battery got one; its counterpart did not. Appending
    # `Battery.record = lambda self, cid, ok, detail: True` -- one syntactically
    # valid line -- made this guard run to completion, print no check at all,
    # emit passed=0/failed=0/total=0 and exit 0, because battery.failed was 0.
    # Every pinned floor stayed green: the static count still saw 31 ids and the
    # recorder check still found a method containing .append. Step 2 of
    # audit:all could be emptied with step 1 none the wiser.
    #
    # Reported OUTSIDE battery.record, for the same reason the other one is: a
    # floor must not depend on the mechanism it polices.
    MINIMUM_CHECKS = 28
    executed = battery.passed + battery.failed
    if executed < MINIMUM_CHECKS:
        print(json.dumps({
            "guard": "offline-evidence-contract",
            "error": "OFFLINE_CONTRACT_BATTERY_HOLLOW",
            "detail": f"only {executed} checks executed, below the pinned "
                      f"minimum of {MINIMUM_CHECKS}",
        }, indent=2))
        return 1
    summary(battery)
    return 0 if battery.failed == 0 else 1


def audit_all_steps() -> list[str]:
    scripts = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))["scripts"]

    def expand(name: str, seen: set[str]) -> list[str]:
        if name in seen or name not in scripts:
            return []
        seen.add(name)
        out: list[str] = []
        for raw in re.split(r"&&|\|\|", scripts[name]):
            step = raw.strip()
            if not step:
                continue
            nested = re.fullmatch(r"(?:pnpm|npm|yarn)\s+run\s+([\w:.-]+)", step)
            out.extend(expand(nested.group(1), seen) if nested else [step])
        return out

    return expand("audit:all", set())


def insert_above_entry_point(text: str, snippet: str) -> str:
    """Place a mutation where the module would actually execute it.

    Both guards end with ``raise SystemExit(main())`` under an
    ``if __name__ == "__main__":`` guard, so anything appended after that line
    is parsed and never run. A mutation that cannot execute exercises only the
    static detector, which is not what a cycle named for hollowing should be
    demonstrating.
    """

    marker = 'if __name__ == "__main__":'
    if marker not in text:
        return text + "\n\n" + snippet
    # rpartition, NOT partition. This module contains the marker inside its own
    # mutation code, so splitting at the FIRST occurrence dropped the snippet
    # into a string literal, where it parsed fine, hollowed nothing, and the
    # cycle reported no reasons at all. The real entry point is the last one.
    head, _, tail = text.rpartition(marker)
    return head + snippet + "\n\n" + marker + tail


def membership_reasons_for(mutation: str | None) -> list[str]:
    """Run the REAL membership verifier against a mutated COPY of the repo.

    The manifest resolves everything from its module-level ``ROOT``, so pointing
    that at a scratch tree exercises the genuine code path without touching a
    single tracked file. ``ROOT`` is always restored, including on failure.
    """

    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_membership_probe", ROOT / "scripts" / "offline_audit_membership_manifest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if mutation is None:
        return module.verify_membership()

    work = Path(tempfile.mkdtemp(prefix="mr-membership-"))
    try:
        (work / "scripts").mkdir()
        package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        steps = package["scripts"]["audit:all"].split(" && ")
        # THE SECOND PINNED MEMBER'S GUARD IS COPIED TOO.
        #
        # Without it `guard.exists()` was False for PINNED_MEMBERS[1] in every
        # cycle, so its min_checks/id_pattern branch never ran and no cycle
        # proved that removing the battery which DECIDES the acceptance
        # predicate from audit:all is detected. The property held against the
        # real tree; nothing demonstrated the detector works.
        for relative in ("scripts/audit_harness_guard.py",
                         "scripts/offline_evidence_contract_guard.py",
                         "scripts/offline_audit_membership_manifest.py",
                         "scripts/offline_operator_principal_guard.py"):
            shutil.copy2(ROOT / relative, work / relative)

        if mutation == "remove-step":
            steps = [s for s in steps if s != CONTRACT_SCRIPT]
        elif mutation == "append-step":
            steps = [s for s in steps if s != CONTRACT_SCRIPT] + [CONTRACT_SCRIPT]
        elif mutation == "or-join":
            package["scripts"]["audit:all"] = " || ".join(steps)
            steps = None
        elif mutation == "neuter-asserter":
            target = work / "scripts" / "audit_harness_guard.py"
            target.write_text(
                target.read_text(encoding="utf-8")
                .replace(CONTRACT_SCRIPT, "python scripts/unrelated.py")
                .replace(CONTRACT_COMMAND, "audit:unrelated"),
                encoding="utf-8")
        elif mutation == "remove-principal-step":
            steps = [s for s in steps if s != PRINCIPAL_SCRIPT]
        elif mutation == "hollow-principal-battery":
            target = work / "scripts" / "offline_operator_principal_guard.py"
            text = target.read_text(encoding="utf-8")
            # A SYNTACTICALLY VALID HOLLOWING, and the cheapest one.
            #
            # Commenting the calls out left the file unparseable, so the cycle
            # proved that count_recorded_checks returns 0 on a SyntaxError --
            # not that it detects hollowing. Meanwhile the edit an author would
            # actually make -- shadowing the recorder with a no-op -- kept every
            # id in the file, scored 64 against a floor of 35, and emptied the
            # results list. This appends exactly that.
            # INSERTED WHERE IT WOULD RUN. Both guards end with
            # `raise SystemExit(main())`, so text APPENDED after that never
            # executes -- measured. A cycle that appends therefore exercises the
            # STATIC detector and nothing else, which is a real property of the
            # manifest but not the property the wording claimed. Placed above
            # the entry point, this is the edit as an author would make it.
            target.write_text(
                insert_above_entry_point(
                    text, "def rec(check_id, ok, detail):\n    return True\n"),
                encoding="utf-8")
        elif mutation == "hollow-battery":
            target = work / "scripts" / "offline_evidence_contract_guard.py"
            text = target.read_text(encoding="utf-8")
            target.write_text(
                # THE EDIT AN AUTHOR WOULD MAKE, and one that still parses.
                # Commenting the calls out left the file unparseable, so this
                # cycle proved that count_recorded_checks returns 0 on a
                # SyntaxError -- not that hollowing is detected. This rebinds the
                # recorder, which is the cheapest real hollowing and the one the
                # sibling cycle was rewritten to use.
                insert_above_entry_point(
                    text, "Battery.record = lambda self, cid, ok, detail: True\n"),
                encoding="utf-8")
        else:
            raise ValueError(f"unknown membership mutation: {mutation}")

        if steps is not None:
            package["scripts"]["audit:all"] = " && ".join(steps)
        (work / "package.json").write_text(json.dumps(package, indent=2), encoding="utf-8")

        original = module.ROOT
        try:
            module.ROOT = work
            return module.verify_membership()
        finally:
            module.ROOT = original
    finally:
        shutil.rmtree(work, ignore_errors=True)


def contract_in_audit_all() -> bool:
    """Assert the EXACT token, that the chain is ``&&``-joined, and that the step
    sits near the front -- ``audit:all`` currently fails at a known inherited
    step, so an appended offline step would never run and its absence would be
    invisible."""

    scripts = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))["scripts"]
    if "||" in scripts.get("audit:all", ""):
        return False
    steps = audit_all_steps()
    if CONTRACT_SCRIPT not in steps:
        return False
    return steps.index(CONTRACT_SCRIPT) <= 2


def membership_pinned() -> bool:
    manifest = ROOT / "scripts" / "offline_audit_membership_manifest.py"
    if not manifest.exists():
        return False
    text = manifest.read_text(encoding="utf-8")
    return CONTRACT_COMMAND in text and CONTRACT_SCRIPT in text


def summary(battery: Battery) -> None:
    print()
    print(json.dumps({
        "guard": "offline-evidence-contract",
        "claim_scope": "authoritative v2 acceptance rules, hermetic (no VM, no package, "
                       "no real artifact)",
        "summary": {"passed": battery.passed, "failed": battery.failed,
                    "total": len(battery.checks)},
    }, indent=2))


if __name__ == "__main__":
    raise SystemExit(main())
