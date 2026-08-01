"""ga:offline-commercial-evidence -- generate the exact-head Offline Edition
evidence artifact (gitignored output) by EXECUTING the license battery, the
runtime battery, the package matrix, and the offline secret scan, then binding
the redacted results to the exact commit/tree.
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
    package_matrix = _run_guard("offline_package_guard")
    secret_scan = _run_guard("offline_secret_scan_guard")

    results = {
        "license_battery": {"passed": license_battery.get("passed", 0),
                            "failed": license_battery.get("failed", 1)},
        "runtime_battery": {"passed": runtime_battery.get("passed", 0),
                            "failed": runtime_battery.get("failed", 1)},
        "package_matrix": {"passed": package_matrix.get("passed", 0),
                           "failed": package_matrix.get("failed", 1),
                           "environments_executed":
                               package_matrix.get("environments_executed", [])},
        "secret_scan": {"passed": secret_scan.get("passed", 0),
                        "failed": secret_scan.get("failed", 1)},
    }
    all_passed = all(block["failed"] == 0 and block["passed"] > 0
                     for block in (results["license_battery"], results["runtime_battery"],
                                   results["package_matrix"], results["secret_scan"]))

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
            "private_key_absent": results["secret_scan"]["failed"] == 0
                                  and results["package_matrix"]["failed"] == 0,
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
        "verdicts": {
            "license": E.LICENSE_VERDICT if all_passed else "OFFLINE_LICENSE_ENFORCEMENT_NOT_ACCEPTED",
            "package": E.PACKAGE_VERDICT if all_passed else "OFFLINE_WINDOWS_PACKAGE_NOT_ACCEPTED",
            "commercial": E.COMMERCIAL_VERDICT if all_passed else "OFFLINE_COMMERCIAL_PACKAGE_NOT_ACCEPTED",
        },
    }
    payload["canonical_payload_hash"] = canonical_hash(payload)
    E.EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    E.EVIDENCE_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "wrote": str(E.EVIDENCE_PATH.relative_to(ROOT)),
        "results": results,
        "verdicts": payload["verdicts"],
        "canonical_payload_hash": payload["canonical_payload_hash"],
    }, indent=2))
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
