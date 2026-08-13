"""ga:offline-commercial-evidence -- generate the exact-head Offline Edition
evidence artifact (gitignored output).

Executes the license battery, the runtime battery, the offline secret scan, the
air-gap boundary guard, the Hyper-V isolation guard and the combiner fault
battery, then binds their redacted results to the exact commit/tree.

The package matrix is NOT re-executed here. It spans two machines -- the host
and a task-owned clean Hyper-V VM -- so it cannot be reproduced inside a single
generator process, and re-running the retired single-host guard would have
reported one environment forever. It is instead DERIVED from the two-environment
record produced by scripts/offline_two_environment_matrix.py, which is itself
bound to the same commit, tree and package hashes. Absent that record, the
package and commercial verdicts stay honestly NOT_ACCEPTED.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT), str(ROOT / "scripts")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from backend.app import offline_commercial_evidence as E  # noqa: E402
from backend.app.licensing.canonical import canonical_hash  # noqa: E402
from backend.app.licensing.contract import PRODUCT_VERSION  # noqa: E402


def _run_guard(module_name: str) -> dict:
    module = __import__(module_name)
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        exit_code = module.main()
    try:
        report = json.loads(buffer.getvalue())
    except json.JSONDecodeError:
        report = {"summary": {"passed": 0, "failed": 1}}
    summary = dict(report.get("summary", {}))
    summary["exit_code"] = exit_code
    if "environments_executed" in report:
        summary["environments_executed"] = report["environments_executed"]
    return summary


#: Where the two-environment orchestrator leaves its record, repo-relative so
#: the artifact is reproducible without a machine-specific path.
TWO_ENVIRONMENT_RECORD = (ROOT / "output" / "offline-commercial"
                          / "offline-two-environment-record.v1.json")


def _pk31_executed_everywhere(record: dict) -> bool:
    """Every environment must have actually run PK31, not merely not failed it."""

    environments = (record or {}).get("environments", {})
    if not environments:
        return False
    for env in environments.values():
        missing = env.get("missing_or_failing_checks")
        # An EMPTY list means nothing is missing, which is the good case. Using
        # `or ["PK31"]` as the absent-fallback made the empty list falsy and
        # substituted the failure sentinel for the success case.
        if missing is None or "PK31" in missing:
            return False
    return True


def _two_environment_matrix() -> tuple[dict, dict, dict]:
    """Derive the package-matrix block from the two-environment record.

    Returns (raw record, redacted binding block, package_matrix block). When the
    record is absent the matrix is reported as zero environments and a failure,
    so the package verdict stays NOT_ACCEPTED rather than silently passing.
    """

    if not TWO_ENVIRONMENT_RECORD.exists():
        return {}, {}, {"passed": 0, "failed": 1, "environments_executed": []}

    record = json.loads(TWO_ENVIRONMENT_RECORD.read_text(encoding="utf-8"))
    environments = record.get("environments", {})
    passed = sum(int(env.get("totals", {}).get("passed", 0)) for env in environments.values())
    failed = sum(int(env.get("totals", {}).get("failed", 1)) for env in environments.values())
    if record.get("accepted") is not True:
        failed += 1

    # The environments must agree with EACH OTHER and with the head the evidence
    # is being generated at. Without this, a record produced at an earlier commit
    # could be bound to evidence claiming a later one: every per-environment
    # field would still match its sibling and the combiner would still have
    # accepted the pair.
    commits = {str(env.get("source_commit", "")) for env in environments.values()}
    trees = {str(env.get("source_tree", "")) for env in environments.values()}
    head, head_tree = E.git_rev("HEAD"), E.git_rev("HEAD^{tree}")
    bound_commit = commits.pop() if len(commits) == 1 else ""
    bound_tree = trees.pop() if len(trees) == 1 else ""
    if bound_commit != head or bound_tree != head_tree:
        failed += 1

    executed = [str(env.get("environment_class", "")) for env in environments.values()]
    binding = {
        "schema_version": record.get("schema_version"),
        "record_hash": record.get("record_hash"),
        "accepted": record.get("accepted"),
        # Carried so the validator can refuse a record produced at a different
        # head, independently of this generator.
        "source_commit": bound_commit,
        "source_tree": bound_tree,
        "environment_count": record.get("environment_count"),
        "identical_package_bytes": record.get("identical_package_bytes"),
        "independent_identities": record.get("independent_identities"),
        # Redacted per-environment facts only -- never the fingerprint hash --
        # but enough that the validator can DERIVE independence and
        # identical-package-bytes instead of trusting the summary booleans
        # above. Without the package hashes and identity digests here, those
        # booleans are unfalsifiable assertions.
        "environments": {
            label: {
                "environment_class": env.get("environment_class"),
                "fingerprint_identity_digest": env.get("fingerprint_identity_digest"),
                "totals": env.get("totals", {}),
                "installer_sha256": env.get("installer_sha256"),
                "executable_sha256": env.get("executable_sha256"),
                "payload_manifest_sha256": env.get("payload_manifest_sha256"),
                "frontend_manifest_sha256": env.get("frontend_manifest_sha256"),
                # The head each environment actually ran at, so the chain can
                # compare it against the sealed record rather than the artifact
                # asserting it.
                "source_commit": env.get("source_commit"),
                "source_tree": env.get("source_tree"),
                "missing_or_failing_checks": env.get("missing_or_failing_checks"),
                "executed_check_count": env.get("executed_check_count"),
            }
            for label, env in sorted(environments.items())
        },
    }
    return record, binding, {"passed": passed, "failed": failed,
                             "environments_executed": executed}


def main() -> int:
    commit = E.git_rev("HEAD")
    tree = E.git_rev("HEAD^{tree}")
    clean = E.worktree_is_clean()

    build_summary_path = ROOT / "output" / "offline-package" / "build-summary.json"
    if not build_summary_path.exists():
        print(json.dumps({"error": "package not built; run packaging/build_offline_package.py"}))
        return 1
    build_summary = json.loads(build_summary_path.read_text(encoding="utf-8"))

    license_battery = _run_guard("offline_license_guard")
    runtime_battery = _run_guard("offline_runtime_guard")
    secret_scan = _run_guard("offline_secret_scan_guard")
    airgap = _run_guard("offline_airgap_guard")
    hyperv = _run_guard("offline_hyperv_guard")
    combiner = _run_guard("offline_combine_environments_faults_guard")

    record, record_block, matrix_block = _two_environment_matrix()

    results = {
        "license_battery": {"passed": license_battery.get("passed", 0),
                            "failed": license_battery.get("failed", 1)},
        "runtime_battery": {"passed": runtime_battery.get("passed", 0),
                            "failed": runtime_battery.get("failed", 1)},
        "package_matrix": matrix_block,
        "secret_scan": {"passed": secret_scan.get("passed", 0),
                        "failed": secret_scan.get("failed", 1)},
        "airgap_boundary": {"passed": airgap.get("passed", 0),
                            "failed": airgap.get("failed", 1)},
        "hyperv_isolation": {"passed": hyperv.get("passed", 0),
                             "failed": hyperv.get("failed", 1)},
        "combiner_faults": {"passed": combiner.get("passed", 0),
                            "failed": combiner.get("failed", 1)},
    }
    all_passed = all(block["failed"] == 0 and block["passed"] > 0
                     for block in (results["license_battery"], results["runtime_battery"],
                                   results["package_matrix"], results["secret_scan"],
                                   results["airgap_boundary"], results["hyperv_isolation"],
                                   results["combiner_faults"]))
    # Part-O environment minimum: the package (and commercial) verdicts require
    # at least E.REQUIRED_ENVIRONMENT_MINIMUM executed clean environments, and
    # the two-environment record must itself have been accepted. A single-host
    # matrix is reported honestly and stays NOT_ACCEPTED.
    coverage_met = len(results["package_matrix"]["environments_executed"]) >= \
        E.REQUIRED_ENVIRONMENT_MINIMUM

    payload = {
        "schema_version": E.SCHEMA_VERSION,
        "evidence_type": E.EVIDENCE_TYPE,
        "git_commit": commit,
        "git_tree": tree,
        "worktree_clean": clean,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "package": {
            "package_version": PRODUCT_VERSION,
            "installer_sha256": build_summary.get("installer_sha256", ""),
            "payload_file_count": build_summary.get("payload_files", 0),
            "public_key_fingerprint": build_summary.get("public_key_fingerprint", ""),
            # Key absence is proven in four independent places: the secret scan
            # over package/payload/frontend/logs/evidence, PK31 inside each
            # environment matrix, the air-gap boundary battery, and the Hyper-V
            # guard's guest and transfer-set checks. PK31 is required EXPLICITLY
            # rather than inferred from a clean matrix total -- a matrix that
            # never ran PK31 also has a clean total, so the previous derivation
            # asserted a proof that had not been executed.
            "private_key_absent": results["secret_scan"]["failed"] == 0
                                  and results["package_matrix"]["failed"] == 0
                                  and results["airgap_boundary"]["failed"] == 0
                                  and results["hyperv_isolation"]["failed"] == 0
                                  and _pk31_executed_everywhere(record),
        },
        "licensing": {
            "license_schema": "monday-report-license.v1",
            "signature_algorithm": "Ed25519",
            "fingerprint_version": "mr-machine-fingerprint.v1",
            "activation_schema": "monday-report-activation-request.v1",
            "update_schema": "monday-report-update.v1",
            "state_schema": "mr-license-state.v1",
        },
        "disclosures": dict(E.REQUIRED_DISCLOSURES),
        "results": results,
        "two_environment_record": record_block,
        "environment_coverage": {
            "executed": results["package_matrix"]["environments_executed"],
            "required_minimum": E.REQUIRED_ENVIRONMENT_MINIMUM,
            "meets_minimum": coverage_met,
        },
    }

    # Derive the verdicts from the SAME authority the validator recomputes them
    # with, rather than restating the rule here. Two independent expressions of
    # one rule drift: this generator previously gated the license verdict on the
    # package matrix as well, so a green licensing tier with a failing matrix
    # stored NOT_ACCEPTED while the validator derived PASS and rejected the
    # artifact as self-contradictory.
    derived = E.control_verdicts(payload, [])
    payload["verdicts"] = {
        "license": (E.LICENSE_VERDICT if derived["offline_license_enforcement"] == "PASS"
                    else "OFFLINE_LICENSE_ENFORCEMENT_NOT_ACCEPTED"),
        "package": (E.PACKAGE_VERDICT if derived["offline_windows_package"] == "PASS"
                    else "OFFLINE_WINDOWS_PACKAGE_NOT_ACCEPTED"),
        "commercial": (E.COMMERCIAL_VERDICT if derived["offline_commercial_package"] == "PASS"
                       else "OFFLINE_COMMERCIAL_PACKAGE_NOT_ACCEPTED"),
    }
    license_accepted = derived["offline_license_enforcement"] == "PASS"
    package_accepted = derived["offline_windows_package"] == "PASS"
    commercial_accepted = derived["offline_commercial_package"] == "PASS"
    # Set BEFORE the canonical seal so the seal covers it.
    payload["reproducible_payload_hash"] = E.reproducible_hash(payload)
    payload["canonical_payload_hash"] = canonical_hash(payload)
    E.EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    E.EVIDENCE_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "wrote": str(E.EVIDENCE_PATH.relative_to(ROOT)),
        "results": results,
        "verdicts": payload["verdicts"],
        "canonical_payload_hash": payload["canonical_payload_hash"],
        "reproducible_payload_hash": payload["reproducible_payload_hash"],
    }, indent=2))
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
