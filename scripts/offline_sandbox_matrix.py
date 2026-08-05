"""audit:offline-sandbox -- drive the ENVIRONMENT_2 matrix inside a locked-down
Windows Sandbox.

Host side of the air-gapped protocol for the second environment:

  1. stage the package, the PowerShell environment runner, and the session
     driver into SHORT transfer paths (Windows Sandbox silently fails to run
     its LogonCommand when a mapped host path is long);
  2. launch a locked-down Sandbox (no networking, no redirection, no host
     profile / repository / credential / signing-key mapping);
  3. wait for the sandbox to export its activation request;
  4. sign it HERE, on the host, outside the sandbox -- the key never enters;
  5. drop only the signed licenses into the sandbox input folder;
  6. wait for the completed redacted result and copy it out.

The signing key is passed to the operator issuer only. It is never staged, never
mapped, and never written into any sandbox-visible folder.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from offline_package_matrix import build_license_bundle  # noqa: E402

SANDBOX_EXE = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsSandbox.exe"
TEMPLATE = ROOT / "packaging" / "sandbox" / "environment2.wsb.template"
SESSION = ROOT / "packaging" / "sandbox" / "sandbox_session.ps1"
PS_RUNNER = ROOT / "scripts" / "offline_env_runner.ps1"
DEFAULT_APP_DIR = ROOT / "output" / "offline-package" / "stage" / "MondayReportOffline"

#: Deliberately SHORT (see the template comment).
DEFAULT_TRANSFER_ROOT = Path(r"C:\mrx-env2")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _wait_for(path: Path, *, timeout: float, label: str) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return True
        time.sleep(3)
    print(json.dumps({"waiting_failed": label, "expected": path.name}))
    return False


def close_sandbox() -> None:
    for name in ("WindowsSandboxClient", "WindowsSandboxRemoteSession", "WindowsSandboxServer",
                 "WindowsSandbox"):
        subprocess.run(["taskkill", "/IM", f"{name}.exe", "/F"],
                       capture_output=True, text=True, timeout=60)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="offline-sandbox matrix")
    parser.add_argument("--package-dir", default=str(DEFAULT_APP_DIR))
    parser.add_argument("--transfer-root", default=str(DEFAULT_TRANSFER_ROOT))
    parser.add_argument("--key-file", help="operator private key (HOST side only, never mapped)")
    parser.add_argument("--expiry-seconds", type=int, default=240)
    parser.add_argument("--request-timeout", type=float, default=900.0)
    parser.add_argument("--matrix-timeout", type=float, default=2700.0)
    parser.add_argument("--out", help="where to copy the ENVIRONMENT_2 result")
    parser.add_argument("--keep-open", action="store_true")
    args = parser.parse_args(argv)

    if not SANDBOX_EXE.exists():
        print(json.dumps({"guard": "offline_sandbox", "detail": "WindowsSandbox.exe absent",
                          "summary": {"passed": 0, "failed": 1, "certification": "not_passed"}}))
        return 1
    app_dir = Path(args.package_dir)
    key_file = Path(args.key_file or os.environ.get("MONDAY_REPORT_OPERATOR_KEY_FILE", ""))
    if not key_file.is_file():
        print(json.dumps({"guard": "offline_sandbox",
                          "detail": "operator key must be supplied explicitly (host side only)",
                          "summary": {"passed": 0, "failed": 1, "certification": "not_passed"}}))
        return 1

    root = Path(args.transfer_root)
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
    pkg, tool, inbox, outbox = root / "pkg", root / "tool", root / "in", root / "out"
    for d in (pkg, tool, inbox, outbox):
        d.mkdir(parents=True, exist_ok=True)

    # Stage the EXACT package bytes.
    shutil.copytree(app_dir, pkg, dirs_exist_ok=True)
    shutil.copy2(PS_RUNNER, tool / PS_RUNNER.name)
    shutil.copy2(SESSION, tool / SESSION.name)

    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                            capture_output=True, text=True, timeout=30).stdout.strip()
    tree = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD^{tree}"],
                          capture_output=True, text=True, timeout=30).stdout.strip()
    summary_path = app_dir.parents[1] / "build-summary.json"
    build_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    (tool / "package-meta.json").write_text(json.dumps({
        "source_commit": commit, "source_tree": tree,
        "package_version": build_summary.get("product_version", ""),
        "installer_sha256": build_summary.get("installer_sha256", ""),
    }, indent=2), encoding="utf-8")

    # Refuse to launch if anything key-shaped reached a mapped folder.
    for mapped in (pkg, tool, inbox, outbox):
        for path in mapped.rglob("*"):
            if path.is_file() and any(h in path.name.lower()
                                      for h in ("private", "issuer_key", "signing_key", "secret")):
                print(json.dumps({"guard": "offline_sandbox",
                                  "detail": "key-shaped file staged into a mapped folder",
                                  "summary": {"passed": 0, "failed": 1,
                                              "certification": "not_passed"}}))
                return 1

    config = (TEMPLATE.read_text(encoding="utf-8")
              .replace("__PKG__", str(pkg)).replace("__TOOL__", str(tool))
              .replace("__IN__", str(inbox)).replace("__OUT__", str(outbox)))
    wsb = root / "environment2.wsb"
    wsb.write_text(config, encoding="utf-8")

    close_sandbox()
    time.sleep(3)
    subprocess.Popen([str(SANDBOX_EXE), str(wsb)])

    try:
        if not _wait_for(outbox / "00-session-started.txt", timeout=600,
                         label="sandbox session start"):
            return 1
        request_path = outbox / "activation-request.json"
        if not _wait_for(request_path, timeout=args.request_timeout,
                         label="activation request export"):
            return 1

        # ---- HOST-SIDE SIGNING: outside the sandbox, key never mapped ----
        bundle = build_license_bundle(request_path=request_path, transfer_in=inbox,
                                      key_file=key_file, expiry_seconds=args.expiry_seconds)
        if not all(bundle.values()):
            print(json.dumps({"guard": "offline_sandbox", "detail": "operator issuance failed",
                              "bundle": bundle,
                              "summary": {"passed": 0, "failed": 1,
                                          "certification": "not_passed"}}))
            return 1

        # An ENVIRONMENT_1 license, so the sandbox can prove it rejects it.
        env1_license = Path(os.environ.get("MONDAY_REPORT_ENV1_LICENSE", ""))
        if env1_license.is_file():
            shutil.copy2(env1_license, inbox / "license-other-environment.json")

        if not _wait_for(outbox / "99-session-complete.txt", timeout=args.matrix_timeout,
                         label="environment 2 matrix completion"):
            return 1
    finally:
        if not args.keep_open:
            close_sandbox()

    error_marker = outbox / "99-session-error.txt"
    result_path = outbox / "environment-result.json"
    request_record = outbox / "environment-request-record.json"
    if error_marker.exists() or not result_path.exists():
        detail = error_marker.read_text(encoding="utf-8") if error_marker.exists() else "no result"
        print(json.dumps({"guard": "offline_sandbox", "detail": detail.strip()[:400],
                          "summary": {"passed": 0, "failed": 1, "certification": "not_passed"}}))
        return 1

    result = json.loads(result_path.read_text(encoding="utf-8"))
    record = json.loads(request_record.read_text(encoding="utf-8")) if request_record.exists() else {}
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(result_path.read_text(encoding="utf-8"), encoding="utf-8")
        Path(args.out).with_name("environment-2-request-record.json").write_text(
            request_record.read_text(encoding="utf-8"), encoding="utf-8")

    passed = result.get("totals", {}).get("passed", 0) + record.get("totals", {}).get("passed", 0)
    failed = result.get("totals", {}).get("failed", 1) + record.get("totals", {}).get("failed", 1)
    print(json.dumps({
        "guard": "offline_sandbox",
        "claim_scope": "ENVIRONMENT_2 air-gapped matrix inside locked-down Windows Sandbox",
        "environment_label": "ENVIRONMENT_2",
        "environments_executed": ["windows-11-sandbox (fresh, networking disabled)"],
        "airgap": {"signing_performed_on_host": True, "key_mapped_into_sandbox": False},
        "summary": {"passed": passed, "failed": failed,
                    "certification": "passed" if failed == 0 else "not_passed"},
        "checks": record.get("checks", []) + result.get("checks", []),
    }, indent=2))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
