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
)

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
    matrix = results.get("package_matrix", {})
    if isinstance(matrix, dict):
        environments = matrix.get("environments_executed", [])
        if not isinstance(environments, list) or not environments:
            reasons.append("package matrix reports no executed environment")

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

    text = json.dumps(payload)
    for pattern in _LEAK_PATTERNS:
        if pattern.search(text):
            reasons.append(f"evidence contains a leak shape: {pattern.pattern[:40]}")
            break
    return reasons


def load_and_validate() -> tuple[dict | None, list[str]]:
    if not EVIDENCE_PATH.exists():
        return None, ["no evidence artifact"]
    payload = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
    return payload, validate(payload, current_commit=git_rev("HEAD"),
                             current_tree=git_rev("HEAD^{tree}"))


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
                    and results.get("secret_scan", {}).get("failed") == 0)
    package_pass = (results.get("package_matrix", {}).get("failed") == 0
                    and environment_coverage_met(payload))
    commercial_pass = (license_pass and package_pass
                       and payload.get("package", {}).get("private_key_absent") is True)
    return {
        "offline_license_enforcement": "PASS" if license_pass else "BLOCKED",
        "offline_windows_package": "PASS" if package_pass else "BLOCKED",
        "offline_commercial_package": "PASS" if commercial_pass else "BLOCKED",
    }
