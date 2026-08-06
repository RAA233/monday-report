"""offline-package combine-environments -- fold two INDEPENDENT environment
results into the two-environment package record.

Rejects anything that would let a single environment masquerade as two: one
environment only, a duplicate environment identity (same machine fingerprint
hash), the same result submitted twice, differing package bytes, differing
source heads, differing product versions, a failed clean-state proof, or a
missing air-gap / offline / dependency-absence / copied-license proof.

Only redacted facts are carried forward — never raw identifiers, license
payloads, activation payloads, private paths, or process ids.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.licensing.canonical import canonical_hash  # noqa: E402

RECORD_SCHEMA = "offline-two-environment-record.v1"

#: Facts every environment result must agree on, byte for byte.
_MUST_MATCH = (
    "source_commit", "source_tree", "package_version", "installer_sha256",
    "executable_sha256", "payload_manifest_sha256", "frontend_manifest_sha256",
)

#: Check ids whose PASS is required in every environment.
_REQUIRED_CHECKS = {
    "airgap": ("PK07",),
    "offline_start": ("PK01",),
    "localhost": ("PK04",),
    "dependency_absence": ("EC02",),
    "activation": ("PK05", "PK08"),
    "machine_binding": ("PK18",),
    # Part L requires cross-environment rejection in BOTH directions, so PK19 is
    # required of every environment rather than only the one that happened to be
    # handed the other environment's license. An environment that never ran the
    # check has no matching id, `_passed` is False, and the pair is refused.
    "cross_environment_license": ("PK19",),
    "backup": ("PK13", "PK14"),
    "restore": ("PK15",),
    "expiry_read_only": ("PK22", "PK23", "PK24", "PK25"),
    "upgrade": ("PK27",),
    "uninstall_reinstall": ("PK28", "PK29"),
    "crash_recovery": ("PK11",),
}


def _passed(checks: list[dict], prefix: str) -> bool:
    matched = [c for c in checks if str(c.get("check_id", "")).startswith(prefix)]
    return bool(matched) and all(c.get("ok") for c in matched)


def redact(record: dict, request_record: dict) -> dict:
    """Build the redacted per-environment result."""

    checks = list(record.get("checks", [])) + list(request_record.get("checks", []))
    fingerprint_hash = str(request_record.get("machine_fingerprint_hash", ""))
    body = {
        "environment_label": record.get("environment_label"),
        "environment_class": record.get("environment_class"),
        "source_commit": record.get("source_commit"),
        "source_tree": record.get("source_tree"),
        "package_version": record.get("package_version"),
        "installer_sha256": record.get("installer_sha256"),
        "executable_sha256": record.get("executable_sha256"),
        "payload_manifest_sha256": record.get("payload_manifest_sha256"),
        "frontend_manifest_sha256": record.get("frontend_manifest_sha256"),
        # A DIGEST of the fingerprint hash: enough to prove the two environments
        # are distinct, never enough to identify a machine.
        "fingerprint_identity_digest": canonical_hash({"fp": fingerprint_hash})[:32],
        "clean_state": request_record.get("clean_state", {}),
        "dependency_absence": request_record.get("dependency_absence", {}),
        "airgap_proofs": record.get("airgap_proofs", []),
        "results": {name: all(_passed(checks, p) for p in prefixes)
                    for name, prefixes in _REQUIRED_CHECKS.items()},
        "totals": {
            "passed": record.get("totals", {}).get("passed", 0)
            + request_record.get("totals", {}).get("passed", 0),
            "failed": record.get("totals", {}).get("failed", 0)
            + request_record.get("totals", {}).get("failed", 0),
        },
    }
    body["result_hash"] = canonical_hash(body)
    return body


def validate_pair(env1: dict, env2: dict) -> list[str]:
    """Every reason the pair does NOT constitute two independent environments."""

    reasons: list[str] = []
    if env1.get("environment_label") == env2.get("environment_label"):
        reasons.append("both results carry the same environment label")
    if env1.get("result_hash") == env2.get("result_hash"):
        reasons.append("the same environment result was submitted twice")
    if env1.get("fingerprint_identity_digest") == env2.get("fingerprint_identity_digest"):
        reasons.append("duplicate environment identity (same machine fingerprint)")
    for field in _MUST_MATCH:
        if not env1.get(field) or env1.get(field) != env2.get(field):
            reasons.append(f"environments disagree on {field} (or it is missing)")
    for env in (env1, env2):
        label = env.get("environment_label", "?")
        if env.get("totals", {}).get("failed", 1) != 0:
            reasons.append(f"{label} has failing checks")
        if not all(env.get("clean_state", {}).values()):
            reasons.append(f"{label} failed its clean-state proof")
        if not all(env.get("dependency_absence", {}).values()):
            reasons.append(f"{label} failed its dependency-absence proof")
        if not env.get("airgap_proofs"):
            reasons.append(f"{label} carries no air-gap proof")
        for name, ok in dict(env.get("results", {})).items():
            if not ok:
                reasons.append(f"{label} missing proof: {name}")
    return reasons


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="offline-package combine-environments")
    parser.add_argument("--env1-result", required=True)
    parser.add_argument("--env1-request", required=True)
    parser.add_argument("--env2-result", required=True)
    parser.add_argument("--env2-request", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    env1 = redact(json.loads(Path(args.env1_result).read_text(encoding="utf-8")),
                  json.loads(Path(args.env1_request).read_text(encoding="utf-8")))
    env2 = redact(json.loads(Path(args.env2_result).read_text(encoding="utf-8")),
                  json.loads(Path(args.env2_request).read_text(encoding="utf-8")))
    reasons = validate_pair(env1, env2)

    record = {
        "schema_version": RECORD_SCHEMA,
        "environments": {"ENVIRONMENT_1": env1, "ENVIRONMENT_2": env2},
        "environment_count": 2,
        "identical_package_bytes": all(
            env1.get(f) == env2.get(f) for f in
            ("installer_sha256", "executable_sha256", "payload_manifest_sha256",
             "frontend_manifest_sha256")),
        "independent_identities": (
            env1.get("fingerprint_identity_digest") != env2.get("fingerprint_identity_digest")),
        "accepted": not reasons,
        "rejection_reasons": reasons,
    }
    record["record_hash"] = canonical_hash(record)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "combiner": "offline_two_environment",
        "accepted": record["accepted"],
        "environment_count": 2,
        "identical_package_bytes": record["identical_package_bytes"],
        "independent_identities": record["independent_identities"],
        "rejection_reasons": reasons,
        "record_hash": record["record_hash"],
    }, indent=2))
    return 0 if record["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
