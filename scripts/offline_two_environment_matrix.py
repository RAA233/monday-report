"""offline:two-environment-matrix -- run BOTH complete environment matrices
against one frozen package and fold them into the two-environment record.

Part L requires cross-environment license rejection in BOTH directions. A single
environment cannot prove that on its own, and running the two environments
end-to-end one after the other cannot either: whichever ran first has no second
environment to be handed a license from. So the request phases are interleaved
and the operator signs afterwards, when both activation requests exist:

  1. ENVIRONMENT_1 request   (host, restricted runtime PATH)
  2. ENVIRONMENT_2 request   (clean Hyper-V VM, no network adapter)
  3. sign the ENVIRONMENT_2 bundle -- including a GENUINE license issued for
     ENVIRONMENT_1's fingerprint as license-other-environment.json
  4. ENVIRONMENT_2 resume    -> full matrix, PK19 proves it rejects E1's license
  5. sign the ENVIRONMENT_1 bundle -- including a GENUINE license issued for
     ENVIRONMENT_2's fingerprint
  6. ENVIRONMENT_1 resume    -> full matrix, PK19 proves it rejects E2's license
  7. combine

Each bundle is signed immediately before its own resume, never both up front:
license-short.json carries a seconds-scale expiry so the read-only transition
happens in real time, and a bundle minted before the other environment's matrix
would have expired before it could be seen operating.

Signing happens on the host, outside the product and outside the VM. The private
key is passed only to the operator issuer.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from offline_combine_environments import redact, validate_pair, RECORD_SCHEMA  # noqa: E402
from offline_package_matrix import build_license_bundle, operator_issue, run_env_phase  # noqa: E402
from backend.app.licensing.canonical import canonical_hash  # noqa: E402

DEFAULT_APP_DIR = ROOT / "output" / "offline-package" / "stage" / "MondayReportOffline"
DEFAULT_RESULTS = Path(r"C:\mr-hv\results")
DEFAULT_E2_XFER = Path(r"C:\mr-hv\xfer")
HYPERV = ROOT / "scripts" / "offline_hyperv_matrix.py"

E1_LABEL = "ENVIRONMENT_1"
E1_CLASS = "windows-11-host-isolated"


def _git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args],
                          capture_output=True, text=True, timeout=60).stdout.strip()


def _hyperv(phase: str, *, key_file: Path, xfer: Path, app_dir: Path,
            other_license: Path | None, expiry_seconds: int,
            timeout: float) -> subprocess.CompletedProcess:
    args = [sys.executable, str(HYPERV), "--phase", phase,
            "--package-dir", str(app_dir), "--transfer-root", str(xfer),
            "--key-file", str(key_file), "--expiry-seconds", str(expiry_seconds)]
    if other_license is not None:
        args += ["--other-environment-license", str(other_license)]
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="offline two-environment matrix")
    parser.add_argument("--package-dir", default=str(DEFAULT_APP_DIR))
    parser.add_argument("--results-dir", default=str(DEFAULT_RESULTS))
    parser.add_argument("--e2-transfer-root", default=str(DEFAULT_E2_XFER))
    parser.add_argument("--key-file", help="operator private key (HOST side only)")
    parser.add_argument("--e1-port", type=int, default=47671)
    parser.add_argument("--expiry-seconds", type=int, default=240)
    parser.add_argument("--expiry-wait", type=int, default=32)
    parser.add_argument("--e1-work-root", default="")
    parser.add_argument("--skip-environment-2", action="store_true",
                        help="diagnostic only; the record is NOT produced and no "
                             "acceptance can follow")
    args = parser.parse_args(argv)

    app_dir = Path(args.package_dir)
    results = Path(args.results_dir)
    results.mkdir(parents=True, exist_ok=True)
    e2_xfer = Path(args.e2_transfer_root)

    if not (app_dir / "MondayReportOffline.exe").exists():
        print(json.dumps({"orchestrator": "offline_two_environment",
                          "detail": "package not built", "accepted": False}))
        return 1

    key_file = Path(args.key_file or os.environ.get("MONDAY_REPORT_OPERATOR_KEY_FILE", ""))
    if not key_file.is_file():
        print(json.dumps({"orchestrator": "offline_two_environment",
                          "detail": "operator key must be supplied explicitly "
                                    "(host side only, never transferred)",
                          "accepted": False}))
        return 1

    commit = _git("rev-parse", "HEAD")
    tree = _git("rev-parse", "HEAD^{tree}")
    summary_path = app_dir.parents[1] / "build-summary.json"
    build_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    version = build_summary.get("product_version", "")
    installer_hash = build_summary.get("installer_sha256", "")

    work_root = Path(args.e1_work_root) if args.e1_work_root else Path(
        tempfile.mkdtemp(prefix="offline-e1-"))
    e1_work = work_root / "env"
    e1_out = work_root / "transfer-out"
    e1_in = work_root / "transfer-in"
    for directory in (e1_work, e1_out, e1_in):
        directory.mkdir(parents=True, exist_ok=True)

    common = dict(env_label=E1_LABEL, env_class=E1_CLASS, app_dir=app_dir,
                  work_dir=e1_work, transfer_out=e1_out, port=args.e1_port,
                  expiry_wait=args.expiry_wait, source_commit=commit, source_tree=tree,
                  package_version=version, installer_sha256=installer_hash)
    stages: list[dict] = []

    def note(name: str, ok: bool, detail: str = "") -> None:
        stages.append({"stage": name, "ok": bool(ok), "detail": detail})

    # ---- 1. ENVIRONMENT_1 request -------------------------------------
    step = run_env_phase(phase="request", transfer_in=None, **common)
    e1_request = e1_out / "activation-request.json"
    note("environment-1-request", step.returncode == 0 and e1_request.exists(),
         (step.stdout or step.stderr or "")[-400:] if step.returncode else "")
    if not e1_request.exists():
        print(json.dumps({"orchestrator": "offline_two_environment", "accepted": False,
                          "stages": stages,
                          "detail": "ENVIRONMENT_1 exported no activation request"}, indent=2))
        return 1

    if args.skip_environment_2:
        print(json.dumps({"orchestrator": "offline_two_environment", "accepted": False,
                          "stages": stages,
                          "detail": "environment 2 skipped by request; no two-environment "
                                    "record produced and no acceptance can follow"}, indent=2))
        return 1

    # ---- 2. ENVIRONMENT_2 request --------------------------------------
    proc = _hyperv("request", key_file=key_file, xfer=e2_xfer, app_dir=app_dir,
                   other_license=None, expiry_seconds=args.expiry_seconds, timeout=7200)
    e2_request = e2_xfer / "activation-request.json"
    note("environment-2-request", proc.returncode == 0 and e2_request.exists(),
         (proc.stdout or proc.stderr or "")[-600:] if proc.returncode else "")
    if not e2_request.exists():
        print(json.dumps({"orchestrator": "offline_two_environment", "accepted": False,
                          "stages": stages,
                          "detail": "ENVIRONMENT_2 exported no activation request",
                          "environment_2_output": (proc.stdout or "")[-2000:]}, indent=2))
        return 1

    # ---- 3. cross license for ENVIRONMENT_2, then 4. its resume ---------
    cross_for_e2 = e2_xfer / "cross-license-from-environment-1.json"
    issued = operator_issue(request=e1_request, out=cross_for_e2, key_file=key_file, sequence=1)
    note("issue-cross-license-for-environment-2", issued.returncode == 0,
         "a genuine ENVIRONMENT_1 license, so ENVIRONMENT_2 can prove it refuses it")
    if issued.returncode != 0:
        print(json.dumps({"orchestrator": "offline_two_environment", "accepted": False,
                          "stages": stages, "detail": "cross-license issuance failed"}, indent=2))
        return 1

    proc = _hyperv("resume", key_file=key_file, xfer=e2_xfer, app_dir=app_dir,
                   other_license=cross_for_e2, expiry_seconds=args.expiry_seconds,
                   timeout=10800)
    e2_result = e2_xfer / "environment-result.json"
    e2_record = e2_xfer / "environment-request-record.json"
    note("environment-2-resume", proc.returncode == 0 and e2_result.exists(),
         (proc.stdout or "")[-600:] if proc.returncode else "")
    if not e2_result.exists():
        print(json.dumps({"orchestrator": "offline_two_environment", "accepted": False,
                          "stages": stages,
                          "detail": "ENVIRONMENT_2 produced no result",
                          "environment_2_output": (proc.stdout or "")[-2000:]}, indent=2))
        return 1

    # ---- 5. ENVIRONMENT_1 bundle, signed now so its short license is fresh
    bundle = build_license_bundle(request_path=e1_request, transfer_in=e1_in,
                                  key_file=key_file, expiry_seconds=args.expiry_seconds)
    note("issue-environment-1-bundle", all(bundle.values()), json.dumps(bundle))
    if not all(bundle.values()):
        print(json.dumps({"orchestrator": "offline_two_environment", "accepted": False,
                          "stages": stages, "detail": "operator issuance failed"}, indent=2))
        return 1

    cross_for_e1 = e1_in / "license-other-environment.json"
    issued = operator_issue(request=e2_request, out=cross_for_e1, key_file=key_file, sequence=1)
    note("issue-cross-license-for-environment-1", issued.returncode == 0,
         "a genuine ENVIRONMENT_2 license, so ENVIRONMENT_1 can prove it refuses it")
    if issued.returncode != 0:
        print(json.dumps({"orchestrator": "offline_two_environment", "accepted": False,
                          "stages": stages, "detail": "cross-license issuance failed"}, indent=2))
        return 1

    # ---- 6. ENVIRONMENT_1 resume ---------------------------------------
    step = run_env_phase(phase="resume", transfer_in=e1_in, **common)
    e1_result = e1_out / "environment-result.json"
    e1_record = e1_out / "environment-request-record.json"
    note("environment-1-resume", step.returncode == 0 and e1_result.exists(),
         (step.stdout or step.stderr or "")[-600:] if step.returncode else "")
    if not e1_result.exists():
        print(json.dumps({"orchestrator": "offline_two_environment", "accepted": False,
                          "stages": stages,
                          "detail": "ENVIRONMENT_1 produced no result",
                          "environment_1_output": (step.stdout or "")[-2000:]}, indent=2))
        return 1

    # ---- 7. combine -----------------------------------------------------
    for source, name in ((e1_result, "environment-1-result.json"),
                         (e1_record, "environment-1-request-record.json"),
                         (e2_result, "environment-2-result.json"),
                         (e2_record, "environment-2-request-record.json")):
        if source.exists():
            shutil.copy2(source, results / name)

    env1 = redact(json.loads((results / "environment-1-result.json").read_text(encoding="utf-8")),
                  json.loads((results / "environment-1-request-record.json").read_text(encoding="utf-8")))
    env2 = redact(json.loads((results / "environment-2-result.json").read_text(encoding="utf-8")),
                  json.loads((results / "environment-2-request-record.json").read_text(encoding="utf-8")))
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
    serialized = json.dumps(record, indent=2, sort_keys=True)
    record_path = results / "offline-two-environment-record.v1.json"
    record_path.write_text(serialized, encoding="utf-8")

    # The evidence generator reads a repo-relative copy, so the artifact is
    # reproducible without a machine-specific path. output/ is gitignored.
    repo_copy = ROOT / "output" / "offline-commercial" / "offline-two-environment-record.v1.json"
    repo_copy.parent.mkdir(parents=True, exist_ok=True)
    repo_copy.write_text(serialized, encoding="utf-8")

    # Keep the RAW runner records beside it. The evidence guard re-derives the
    # sealed record from these four files, which is the only anchor that cannot
    # be satisfied by editing the record: forging it means forging the runner
    # output, i.e. fabricating the environment execution itself.
    raw_dir = repo_copy.parent / "environments"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for name in ("environment-1-result.json", "environment-1-request-record.json",
                 "environment-2-result.json", "environment-2-request-record.json"):
        source = results / name
        if source.exists():
            shutil.copy2(source, raw_dir / name)

    print(json.dumps({
        "orchestrator": "offline_two_environment",
        "claim_scope": "both complete environment matrices against one frozen package, "
                       "with cross-environment license rejection proven in both directions",
        "source_commit": commit,
        "source_tree": tree,
        "package_version": version,
        "stages": stages,
        "accepted": record["accepted"],
        "environment_count": 2,
        "identical_package_bytes": record["identical_package_bytes"],
        "independent_identities": record["independent_identities"],
        "rejection_reasons": reasons,
        "record": str(record_path),
        "record_hash": record["record_hash"],
    }, indent=2))
    return 0 if record["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
