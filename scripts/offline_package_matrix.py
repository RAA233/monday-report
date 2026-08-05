"""audit:offline-package -- orchestrate the AIR-GAPPED package matrix for one
environment.

Drives the three-step protocol as SEPARATE PROCESSES so the private key never
enters the environment-side process:

  1. offline_env_runner  --phase request   (no key; exports an activation request)
  2. offline_operator_issue                 (operator side; the only key holder)
  3. offline_env_runner  --phase resume     (no key; imports only signed licenses)

The orchestrator holds the key path only to pass it to step 2. Step 1 and step 3
are spawned with a scrubbed environment that cannot carry key material.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.licensing.canonical import canonical_hash  # noqa: E402

DEFAULT_APP_DIR = ROOT / "output" / "offline-package" / "stage" / "MondayReportOffline"

#: Names scrubbed from the environment-side child process.
_SCRUB = (
    "MONDAY_REPORT_OFFLINE_KEYS_DIR", "MONDAY_REPORT_LICENSE_PRIVATE_KEY",
    "MONDAY_REPORT_SIGNING_PRIVATE_KEY", "MONDAY_REPORT_ISSUER_PRIVATE_KEY",
    "OFFLINE_ISSUER_KEY",
)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run_env_phase(*, phase: str, env_label: str, env_class: str, app_dir: Path,
                  work_dir: Path, transfer_in: Path | None, transfer_out: Path,
                  port: int, expiry_wait: int, source_commit: str, source_tree: str,
                  package_version: str, installer_sha256: str) -> subprocess.CompletedProcess:
    """Spawn the environment-side runner with a SCRUBBED environment."""

    child_env = {k: v for k, v in os.environ.items() if k not in _SCRUB}
    args = [sys.executable, str(ROOT / "scripts" / "offline_env_runner.py"),
            "--phase", phase, "--env-label", env_label, "--env-class", env_class,
            "--package-dir", str(app_dir), "--work-dir", str(work_dir),
            "--transfer-out", str(transfer_out), "--port", str(port),
            "--expiry-wait", str(expiry_wait),
            "--source-commit", source_commit, "--source-tree", source_tree,
            "--package-version", package_version, "--installer-sha256", installer_sha256]
    if transfer_in is not None:
        args += ["--transfer-in", str(transfer_in)]
    return subprocess.run(args, env=child_env, capture_output=True, text=True, timeout=3600)


def operator_issue(*, request: Path, out: Path, key_file: Path, sequence: int,
                   validity_days: int = 365, grace_days: int = 14,
                   expires_at: str | None = None,
                   allowed_versions: str = "1.x") -> subprocess.CompletedProcess:
    args = [sys.executable, str(ROOT / "scripts" / "offline_operator_issue.py"),
            "--request", str(request), "--out", str(out),
            "--key-file", str(key_file), "--issue-sequence", str(sequence),
            "--validity-days", str(validity_days), "--grace-days", str(grace_days),
            "--allowed-versions", allowed_versions]
    if expires_at:
        args += ["--expires-at", expires_at]
    return subprocess.run(args, capture_output=True, text=True, timeout=300)


def build_license_bundle(*, request_path: Path, transfer_in: Path, key_file: Path,
                         expiry_seconds: int) -> dict:
    """Operator side: sign every license the environment matrix needs.

    Only signed licenses cross back into the environment.
    """

    transfer_in.mkdir(parents=True, exist_ok=True)
    results: dict[str, bool] = {}

    results["primary"] = operator_issue(
        request=request_path, out=transfer_in / "license-primary.json",
        key_file=key_file, sequence=1, validity_days=90).returncode == 0
    results["renewal"] = operator_issue(
        request=request_path, out=transfer_in / "license-renewal.json",
        key_file=key_file, sequence=2, validity_days=365).returncode == 0
    results["older"] = operator_issue(
        request=request_path, out=transfer_in / "license-older.json",
        key_file=key_file, sequence=1, validity_days=30).returncode == 0

    # A seconds-scale license so the expiry transition happens in real time.
    now = datetime.now(timezone.utc)
    results["short"] = operator_issue(
        request=request_path, out=transfer_in / "license-short.json",
        key_file=key_file, sequence=1, grace_days=0,
        expires_at=(now + timedelta(seconds=expiry_seconds)).isoformat()).returncode == 0

    # A license bound to DIFFERENT machine components (wrong-machine rejection).
    foreign_request = json.loads(request_path.read_text(encoding="utf-8"))
    binding = dict(foreign_request["machine_binding"])
    binding["component_hashes"] = {name: hashlib.sha256(f"foreign-{name}".encode()).hexdigest()
                                   for name in binding["component_hashes"]}
    foreign_request["machine_binding"] = binding
    foreign_request["machine_fingerprint_hash"] = canonical_hash(binding)
    foreign_path = transfer_in.parent / "foreign-request.json"
    foreign_path.write_text(json.dumps(foreign_request), encoding="utf-8")
    results["foreign"] = operator_issue(
        request=foreign_path, out=transfer_in / "license-foreign.json",
        key_file=key_file, sequence=1).returncode == 0
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="offline-package matrix")
    parser.add_argument("--env-label", default="ENVIRONMENT_1")
    parser.add_argument("--env-class", default="windows-11-host-isolated")
    parser.add_argument("--package-dir", default=str(DEFAULT_APP_DIR))
    parser.add_argument("--work-root", default="")
    parser.add_argument("--key-file", help="operator private key (host side only)")
    parser.add_argument("--port", type=int, default=47671)
    parser.add_argument("--expiry-seconds", type=int, default=25)
    parser.add_argument("--expiry-wait", type=int, default=32)
    parser.add_argument("--out", help="where to copy the environment result")
    args = parser.parse_args(argv)

    app_dir = Path(args.package_dir)
    exe = app_dir / "MondayReportOffline.exe"
    if not exe.exists():
        print(json.dumps({"guard": "offline_package",
                          "summary": {"passed": 0, "failed": 1, "certification": "not_passed"},
                          "detail": "package not built"}))
        return 1

    key_file = Path(args.key_file or os.environ.get("MONDAY_REPORT_OPERATOR_KEY_FILE", ""))
    if not key_file.is_file():
        print(json.dumps({"guard": "offline_package",
                          "summary": {"passed": 0, "failed": 1, "certification": "not_passed"},
                          "detail": "operator key must be supplied explicitly via --key-file "
                                    "or MONDAY_REPORT_OPERATOR_KEY_FILE (host side only)"}))
        return 1

    import tempfile
    work_root = Path(args.work_root) if args.work_root else Path(
        tempfile.mkdtemp(prefix="offline-matrix-"))
    work_dir = work_root / "env"
    transfer_out = work_root / "transfer-out"   # environment -> host
    transfer_in = work_root / "transfer-in"     # host -> environment
    for d in (work_dir, transfer_out, transfer_in):
        d.mkdir(parents=True, exist_ok=True)

    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                            capture_output=True, text=True, timeout=30).stdout.strip()
    tree = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD^{tree}"],
                          capture_output=True, text=True, timeout=30).stdout.strip()
    summary_path = app_dir.parents[1] / "build-summary.json"
    build_summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {}
    installer_hash = build_summary.get("installer_sha256", "")
    version = build_summary.get("product_version", "")

    common = dict(env_label=args.env_label, env_class=args.env_class, app_dir=app_dir,
                  work_dir=work_dir, transfer_out=transfer_out, port=args.port,
                  expiry_wait=args.expiry_wait, source_commit=commit, source_tree=tree,
                  package_version=version, installer_sha256=installer_hash)

    step1 = run_env_phase(phase="request", transfer_in=None, **common)
    request_path = transfer_out / "activation-request.json"
    if step1.returncode != 0 or not request_path.exists():
        print(step1.stdout or step1.stderr[-2000:])
        return 1

    bundle = build_license_bundle(request_path=request_path, transfer_in=transfer_in,
                                  key_file=key_file, expiry_seconds=args.expiry_seconds)
    if not all(bundle.values()):
        print(json.dumps({"guard": "offline_package", "detail": "operator issuance failed",
                          "bundle": bundle,
                          "summary": {"passed": 0, "failed": 1, "certification": "not_passed"}}))
        return 1

    step3 = run_env_phase(phase="resume", transfer_in=transfer_in, **common)
    result_path = transfer_out / "environment-result.json"
    if args.out and result_path.exists():
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(result_path.read_text(encoding="utf-8"), encoding="utf-8")

    request_record = json.loads((transfer_out / "environment-request-record.json").read_text(
        encoding="utf-8")) if (transfer_out / "environment-request-record.json").exists() else {}
    resume_record = json.loads(result_path.read_text(encoding="utf-8")) if result_path.exists() else {}
    passed = request_record.get("totals", {}).get("passed", 0) + resume_record.get("totals", {}).get("passed", 0)
    failed = request_record.get("totals", {}).get("failed", 1) + resume_record.get("totals", {}).get("failed", 1)

    print(json.dumps({
        "guard": "offline_package",
        "claim_scope": "air-gapped package matrix for ONE environment",
        "environment_label": args.env_label,
        "environments_executed": [args.env_class],
        "airgap": {"issuance_process_separate": True,
                   "environment_received_private_key": False},
        "summary": {"passed": passed, "failed": failed,
                    "certification": "passed" if failed == 0 else "not_passed"},
        "checks": (request_record.get("checks", []) + resume_record.get("checks", [])),
    }, indent=2))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
