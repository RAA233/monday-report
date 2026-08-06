"""``offline-commercial-package-evidence.v1`` — exact-head evidence for the
Windows-first Offline Edition.

A SEPARATE evidence tier: it certifies offline licensing enforcement and the
Windows package matrix ONLY. It never touches, replaces, or satisfies the
production-target database/queue contracts, the 28-control GA registry, GA50,
or the tracked GA artifact, and it makes no SaaS or GA claim. Redacted facts
only — no private keys, real licenses, raw machine identifiers, MAC addresses,
customer data, private paths, or process ids.
"""
from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .licensing.canonical import canonical_hash

SCHEMA_VERSION = "offline-commercial-package-evidence.v1"
EVIDENCE_TYPE = "offline_commercial_package_behavior"

LICENSE_VERDICT = "OFFLINE_LICENSE_ENFORCEMENT_ACCEPTED"
PACKAGE_VERDICT = "OFFLINE_WINDOWS_PACKAGE_ACCEPTED"
COMMERCIAL_VERDICT = "OFFLINE_COMMERCIAL_PACKAGE_ACCEPTED"

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_PATH = ROOT / "output" / "offline-commercial" / "offline-commercial-package-evidence.v1.json"

MAX_AGE_DAYS = 90

REQUIRED_DISCLOSURES = {
    "not_ga_acceptance": True,
    "not_saas_acceptance": True,
    "production_database_target_control_unchanged": True,
    "production_queue_target_control_unchanged": True,
    "ga_registry_28_controls_untouched": True,
    "anti_tamper_is_deterrence_not_absolute": True,
}

REQUIRED_RESULT_SECTIONS = (
    "license_battery",
    "runtime_battery",
    "package_matrix",
    "secret_scan",
    # Added when Environment 2 moved to a task-owned clean Hyper-V VM. The
    # package matrix now spans two machines, so the artifact must also carry the
    # proofs that make the second environment meaningful: the air-gapped signing
    # boundary, the Hyper-V isolation and security posture, and the combiner
    # refusals that stop one environment masquerading as two. Additive only --
    # no section was removed or renamed, and the schema version is unchanged.
    "airgap_boundary",
    "hyperv_isolation",
    "combiner_faults",
)

#: The two-environment record the package matrix is derived from.
TWO_ENVIRONMENT_RECORD_SCHEMA = "offline-two-environment-record.v1"

#: The combiner's own output, and the raw runner records it was folded from.
#: Deriving the acceptance facts from the embedded COPY of the record proved
#: nothing: the copy is unauthenticated free text inside the artifact, so one
#: machine's block duplicated under a second label with a different digest still
#: validated. The embedded copy must therefore agree with the sealed record on
#: disk, and that record must re-derive from the raw environment records.
TWO_ENVIRONMENT_RECORD_PATH = (ROOT / "output" / "offline-commercial"
                               / "offline-two-environment-record.v1.json")
ENVIRONMENT_RECORDS_DIR = ROOT / "output" / "offline-commercial" / "environments"

#: Per-environment fields the embedded copy must reproduce exactly.
#: source_commit/source_tree are included deliberately: omitting them left the
#: environments' exact-head binding readable from the artifact's own copy, so a
#: single string edit certified environments that had actually run at a
#: different commit while the sealed record still said so.
_ENVIRONMENT_BOUND_FIELDS = (
    "environment_class", "fingerprint_identity_digest", "installer_sha256",
    "executable_sha256", "payload_manifest_sha256", "frontend_manifest_sha256",
    "source_commit", "source_tree",
)


def validate_record_chain(payload: dict) -> list[str]:
    """Bind the artifact's embedded record to the sealed record on disk.

    ``record_hash`` was format-checked and never recomputed, so it anchored
    nothing. Here the on-disk record's own seal is re-derived, the artifact's
    ``record_hash`` must equal it, and every per-environment field the artifact
    carries must match the record field for field. Fabricating an environment
    now requires editing the sealed record too -- and the guard additionally
    re-derives that record from the raw runner outputs.
    """

    reasons: list[str] = []
    embedded = payload.get("two_environment_record")
    if not isinstance(embedded, dict) or not embedded:
        return reasons  # absence is already reported by validate()

    if not TWO_ENVIRONMENT_RECORD_PATH.exists():
        return ["the sealed two-environment record is absent, so the artifact's "
                "embedded copy cannot be verified"]
    try:
        record = json.loads(TWO_ENVIRONMENT_RECORD_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ["the sealed two-environment record could not be read"]

    sealed = canonical_hash({k: v for k, v in record.items() if k != "record_hash"})
    if sealed != record.get("record_hash"):
        reasons.append("the two-environment record's own seal does not verify")
    if embedded.get("record_hash") != record.get("record_hash"):
        reasons.append("the artifact's record_hash does not match the sealed record")

    for field in ("accepted", "environment_count", "identical_package_bytes",
                  "independent_identities"):
        if embedded.get(field) != record.get(field):
            reasons.append(f"the artifact's {field} disagrees with the sealed record")

    embedded_envs = embedded.get("environments", {}) or {}
    record_envs = record.get("environments", {}) or {}
    if set(embedded_envs) != set(record_envs):
        reasons.append("the artifact carries different environment labels than the "
                       "sealed record")
    else:
        for label, env in embedded_envs.items():
            source = record_envs.get(label, {})
            for field in _ENVIRONMENT_BOUND_FIELDS:
                if env.get(field) != source.get(field):
                    reasons.append(f"environment {label} {field} disagrees with the "
                                   f"sealed record")
            if env.get("totals") != source.get("totals"):
                reasons.append(f"environment {label} totals disagree with the sealed record")

    # The head the ENVIRONMENTS actually ran at must be the head this evidence
    # belongs to, and it is read from the SEALED record, never from the copy.
    for label, env in record_envs.items():
        if str(env.get("source_commit", "")) != str(payload.get("git_commit", "")):
            reasons.append(f"environment {label} ran at a different commit than this evidence")
        if str(env.get("source_tree", "")) != str(payload.get("git_tree", "")):
            reasons.append(f"environment {label} ran at a different tree than this evidence")
    return reasons

#: Contractual floors on how much each section must actually have executed.
#: Requiring only ``passed > 0`` let every recorded count be shrunk to 1 while
#: the artifact still validated as accepted -- the numbers carried no enforced
#: meaning. The air-gap, license and runtime floors are the accepted minima for
#: this tier; the rest are set well below current totals so an honest battery
#: can grow, but far above a token single check.
MINIMUM_SECTION_DEPTH = {
    "license_battery": 49,
    "runtime_battery": 24,
    "airgap_boundary": 27,
    "hyperv_isolation": 40,
    "combiner_faults": 25,
    "secret_scan": 5,
    # 34 checks per environment across two environments. The previous floor of
    # 40 was exactly twice the 20 ids the named proof groups referenced, so a
    # matrix that silently dropped the other 14 -- including PK31
    # private-key-absent-from-package -- still cleared it.
    "package_matrix": 68,
}

#: Keys that legitimately differ between two independent generations at the same
#: head. ``canonical_payload_hash`` binds the whole document INCLUDING the
#: timestamp -- it is a tamper seal, not a reproducibility claim, and it uses the
#: licensing canonicalizer, which must not be changed because real licenses are
#: signed over it. ``reproducible_payload_hash`` is the separate, additive claim:
#: two independent runs at one commit must agree on everything except when they
#: ran. The sibling production-profile evidence tiers exclude the same keys.
NON_REPRODUCIBLE_KEYS = frozenset({
    "canonical_payload_hash", "reproducible_payload_hash", "generated_at",
})


def _strip_volatile(obj):
    if isinstance(obj, dict):
        return {k: _strip_volatile(v) for k, v in obj.items()
                if k not in NON_REPRODUCIBLE_KEYS}
    if isinstance(obj, list):
        return [_strip_volatile(v) for v in obj]
    return obj


def reproducible_hash(payload: dict) -> str:
    """Hash of everything a second generation at the same head must reproduce."""

    return canonical_hash(_strip_volatile(payload))

#: Leak shapes that must never appear anywhere in the evidence document.
_LEAK_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),  # MAC address
    re.compile(r"[A-Za-z]:\\\\?Users\\\\?[^\s\"']+"),  # private Windows path
    re.compile(r"(?i)(?:requirepass|password|token)\s*[:=]"),
)


def git_rev(ref: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), "rev-parse", ref],
                          capture_output=True, text=True, timeout=30).stdout.strip()


def worktree_is_clean() -> bool:
    status = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain"],
                            capture_output=True, text=True, timeout=30).stdout
    return not [line for line in status.splitlines() if not line.strip().startswith("??")]


def validate(payload: dict, *, current_commit: str, current_tree: str) -> list[str]:
    """Return every reason the artifact is NOT acceptable (empty = valid)."""

    reasons: list[str] = []
    if not isinstance(payload, dict):
        return ["payload is not an object"]
    if payload.get("schema_version") != SCHEMA_VERSION:
        reasons.append("wrong schema_version for this evidence tier")
    if payload.get("evidence_type") != EVIDENCE_TYPE:
        reasons.append("wrong evidence_type")
    if payload.get("git_commit") != current_commit:
        reasons.append("evidence does not belong to the current exact commit")
    if payload.get("git_tree") != current_tree:
        reasons.append("evidence does not belong to the current exact tree")
    if payload.get("worktree_clean") is not True:
        reasons.append("evidence was generated from a dirty worktree")

    generated_at = payload.get("generated_at", "")
    try:
        age = datetime.now(timezone.utc) - datetime.fromisoformat(str(generated_at))
        if age.days > MAX_AGE_DAYS:
            reasons.append("evidence is stale")
    except ValueError:
        reasons.append("generated_at is malformed")

    disclosures = payload.get("disclosures", {})
    for key, expected in REQUIRED_DISCLOSURES.items():
        if disclosures.get(key) is not expected:
            reasons.append(f"required disclosure missing or altered: {key}")

    results = payload.get("results", {})
    for section in REQUIRED_RESULT_SECTIONS:
        block = results.get(section)
        if not isinstance(block, dict):
            reasons.append(f"missing result section: {section}")
            continue
        if int(block.get("failed", 1)) != 0 or int(block.get("passed", 0)) <= 0:
            reasons.append(f"result section not fully passing: {section}")
        elif int(block.get("passed", 0)) < MINIMUM_SECTION_DEPTH.get(section, 1):
            reasons.append(f"result section below its required depth: {section}")
    matrix = results.get("package_matrix", {})
    if isinstance(matrix, dict):
        environments = matrix.get("environments_executed", [])
        if not isinstance(environments, list) or not environments:
            reasons.append("package matrix reports no executed environment")
        # Two entries naming the same CLASS are not two entries naming the same
        # machine. Part-O allows "one current Windows 11 environment PLUS one
        # second clean Windows environment or VM", and two clean Windows 11
        # hosts legitimately share a class. Independence is established below
        # from distinct machine identity digests, which is the fact that
        # actually matters; rejecting on the label rejected honest pairs.

    # The package matrix is now derived from the two-environment record, so the
    # record itself must be present, accepted, and internally consistent.
    record = payload.get("two_environment_record", {})
    if not isinstance(record, dict) or not record:
        reasons.append("no two-environment record is bound to this evidence")
    else:
        if record.get("schema_version") != TWO_ENVIRONMENT_RECORD_SCHEMA:
            reasons.append("two-environment record carries the wrong schema version")
        if record.get("accepted") is not True:
            reasons.append("the two-environment record was not accepted")
        if int(record.get("environment_count", 0)) != REQUIRED_ENVIRONMENT_MINIMUM:
            reasons.append("the two-environment record does not carry exactly two environments")
        if not re.fullmatch(r"[0-9a-f]{64}", str(record.get("record_hash", ""))):
            reasons.append("two-environment record hash missing or malformed")

        # DERIVE the independence and identical-bytes facts from the
        # per-environment data the record carries, and require the stored
        # summary booleans to agree. Accepting those booleans on trust made them
        # unfalsifiable: one machine reported twice, an empty environments map,
        # a single environment, two entries of the same class, or per-environment
        # totals full of failures all validated as accepted.
        environments = record.get("environments")
        if not isinstance(environments, dict) or not environments:
            reasons.append("the two-environment record carries no per-environment data")
        else:
            if len(environments) != REQUIRED_ENVIRONMENT_MINIMUM:
                reasons.append("the two-environment record does not carry exactly two environments")
            if int(record.get("environment_count", 0)) != len(environments):
                reasons.append("environment_count disagrees with the recorded environments")

            digests = [str(e.get("fingerprint_identity_digest", "")) for e in environments.values()]
            classes = [str(e.get("environment_class", "")) for e in environments.values()]
            # Independence rests on distinct MACHINE IDENTITIES, not on distinct
            # class labels: two genuinely separate clean Windows 11 hosts share a
            # class and are still two environments, which the Part-O wording
            # explicitly allows. The digest is a fixed-width hash, so require its
            # shape too -- an unconstrained string was accepted as an identity.
            derived_independent = (
                all(re.fullmatch(r"[0-9a-f]{32}", d or "") for d in digests)
                and len(set(digests)) == len(digests)
                and all(classes))
            if record.get("independent_identities") is not derived_independent:
                reasons.append("independent_identities disagrees with the recorded "
                               "per-environment identities")
            if not derived_independent:
                reasons.append("the two environments did not report independent identities")

            hash_fields = ("installer_sha256", "executable_sha256",
                           "payload_manifest_sha256", "frontend_manifest_sha256")
            derived_identical = True
            for field in hash_fields:
                values = [str(e.get(field, "")) for e in environments.values()]
                if not all(re.fullmatch(r"[0-9a-f]{64}", v or "") for v in values):
                    derived_identical = False
                elif len(set(values)) != 1:
                    derived_identical = False
            # The environments must also have run the package this artifact
            # describes. Without this the top-level installer hash and the
            # per-environment ones were never compared to each other.
            env_installers = {str(e.get("installer_sha256", "")) for e in environments.values()}
            declared_installer = str(payload.get("package", {}).get("installer_sha256", ""))
            if env_installers and env_installers != {declared_installer}:
                reasons.append("the environments did not run the package this evidence "
                               "describes")
            if record.get("identical_package_bytes") is not derived_identical:
                reasons.append("identical_package_bytes disagrees with the recorded "
                               "per-environment package hashes")
            if not derived_identical:
                reasons.append("the two environments did not run identical package bytes")

            for label, env in environments.items():
                totals = env.get("totals", {})
                if int(totals.get("failed", 1)) != 0 or int(totals.get("passed", 0)) <= 0:
                    reasons.append(f"environment {label} did not pass its matrix cleanly")

            # The package matrix must be the sum of what the environments
            # actually recorded, not an independent number.
            recorded = sum(int(e.get("totals", {}).get("passed", 0)) for e in environments.values())
            if int(matrix.get("passed", -1)) != recorded:
                reasons.append("package matrix total disagrees with the per-environment totals")

            # environments_executed is a free-text label supplied by the runner,
            # so on its own "two environments" reduces to two different strings.
            # Tie it to the classes the record actually carries.
            executed = matrix.get("environments_executed", [])
            if isinstance(executed, list) and set(executed) != set(classes):
                reasons.append("environments_executed disagrees with the classes recorded "
                               "in the two-environment record")
        # The bound record must come from the SAME head as the evidence. Without
        # this, a record produced at an earlier commit could be attached to
        # evidence claiming a later one: every per-environment field would still
        # agree with its sibling and the combiner would still have accepted it.
        if str(record.get("source_commit", "")) != str(payload.get("git_commit", "")):
            reasons.append("the two-environment record was produced at a different commit")
        if str(record.get("source_tree", "")) != str(payload.get("git_tree", "")):
            reasons.append("the two-environment record was produced at a different tree")

    package = payload.get("package", {})
    if not isinstance(package, dict) or package.get("private_key_absent") is not True:
        reasons.append("private-key-absence was not proven")
    if not re.fullmatch(r"[0-9a-f]{64}", str(package.get("installer_sha256", ""))):
        reasons.append("installer hash missing or malformed")
    if not re.fullmatch(r"[0-9a-f]{16}", str(package.get("public_key_fingerprint", ""))):
        reasons.append("public-key fingerprint missing or malformed")

    expected_hash = payload.get("canonical_payload_hash", "")
    body = {k: v for k, v in payload.items() if k != "canonical_payload_hash"}
    if canonical_hash(body) != expected_hash:
        reasons.append("canonical payload hash mismatch")
    if reproducible_hash(payload) != payload.get("reproducible_payload_hash", ""):
        reasons.append("reproducible payload hash mismatch")

    text = json.dumps(payload)
    for pattern in _LEAK_PATTERNS:
        if pattern.search(text):
            reasons.append(f"evidence contains a leak shape: {pattern.pattern[:40]}")
            break

    # The stored verdict block is a CLAIM; recompute it from the recorded
    # results so a hand-edited artifact cannot assert an acceptance the
    # controls do not support (the canonical hash alone is unsigned and
    # recomputable by anyone editing the file).
    if not reasons:
        derived = control_verdicts(payload, [])
        expected = {
            "license": (LICENSE_VERDICT if derived["offline_license_enforcement"] == "PASS"
                        else "OFFLINE_LICENSE_ENFORCEMENT_NOT_ACCEPTED"),
            "package": (PACKAGE_VERDICT if derived["offline_windows_package"] == "PASS"
                        else "OFFLINE_WINDOWS_PACKAGE_NOT_ACCEPTED"),
            "commercial": (COMMERCIAL_VERDICT if derived["offline_commercial_package"] == "PASS"
                           else "OFFLINE_COMMERCIAL_PACKAGE_NOT_ACCEPTED"),
        }
        stored = payload.get("verdicts", {})
        for key, value in expected.items():
            if stored.get(key) != value:
                reasons.append(
                    f"stored verdict '{key}' disagrees with the verdict derived from the "
                    f"recorded results"
                )
        coverage = payload.get("environment_coverage", {})
        if coverage and coverage.get("meets_minimum") is not environment_coverage_met(payload):
            reasons.append("environment_coverage.meets_minimum disagrees with the recorded "
                           "executed environments")
    return reasons


def load_and_validate() -> tuple[dict | None, list[str]]:
    if not EVIDENCE_PATH.exists():
        return None, ["no evidence artifact"]
    payload = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
    reasons = validate(payload, current_commit=git_rev("HEAD"),
                       current_tree=git_rev("HEAD^{tree}"))
    # RE-MEASURE cleanliness rather than trusting the stored boolean. git_tree is
    # HEAD^{tree}, the COMMITTED tree, so an uncommitted edit changes neither it
    # nor the recorded flag -- yet the chain re-derives the sealed record using
    # the current worktree's combiner, which an uncommitted edit would silently
    # supply. The sibling tenant tier already re-checks this.
    if not worktree_is_clean():
        reasons.append("the worktree is dirty at validation time")
    # The chain check needs the filesystem, so it lives here rather than in the
    # pure validate(). It is not optional: without it the artifact's embedded
    # record is self-describing and a fabricated environment passes.
    return payload, reasons + validate_record_chain(payload)


#: Part-O minimum: one current Windows 11 environment PLUS one second clean
#: Windows environment or VM. A matrix executed on fewer environments can be
#: fully green and still must NOT yield package acceptance.
REQUIRED_ENVIRONMENT_MINIMUM = 2


def environment_coverage_met(payload: dict) -> bool:
    environments = (payload.get("results", {}).get("package_matrix", {})
                    .get("environments_executed", []))
    return isinstance(environments, list) and len(environments) >= REQUIRED_ENVIRONMENT_MINIMUM


def control_verdicts(payload: dict, reasons: list[str]) -> dict[str, str]:
    """The three OFFLINE controls. Deliberately separate from — and unable to
    influence — the production-target and GA controls.

    ``offline_windows_package`` (and therefore ``offline_commercial_package``)
    requires the executed-environment minimum — a single-host matrix stays
    BLOCKED no matter how green it is.
    """

    if reasons:
        return {"offline_license_enforcement": "BLOCKED",
                "offline_windows_package": "BLOCKED",
                "offline_commercial_package": "BLOCKED"}
    results = payload.get("results", {})
    license_pass = (results.get("license_battery", {}).get("failed") == 0
                    and results.get("runtime_battery", {}).get("failed") == 0
                    and results.get("secret_scan", {}).get("failed") == 0
                    and results.get("airgap_boundary", {}).get("failed") == 0)
    record = payload.get("two_environment_record", {})
    package_pass = (results.get("package_matrix", {}).get("failed") == 0
                    and results.get("hyperv_isolation", {}).get("failed") == 0
                    and results.get("combiner_faults", {}).get("failed") == 0
                    and isinstance(record, dict) and record.get("accepted") is True
                    and record.get("identical_package_bytes") is True
                    and record.get("independent_identities") is True
                    and environment_coverage_met(payload))
    commercial_pass = (license_pass and package_pass
                       and payload.get("package", {}).get("private_key_absent") is True)
    return {
        "offline_license_enforcement": "PASS" if license_pass else "BLOCKED",
        "offline_windows_package": "PASS" if package_pass else "BLOCKED",
        "offline_commercial_package": "PASS" if commercial_pass else "BLOCKED",
    }
