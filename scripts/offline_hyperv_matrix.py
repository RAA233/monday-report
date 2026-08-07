"""audit:offline-hyperv -- drive the ENVIRONMENT_2 matrix inside a task-owned
clean Hyper-V virtual machine.

Host side of the air-gapped protocol for the second environment. Replaces the
retired Windows Sandbox orchestrator: the guest here is a genuine Generation 2
VM installed from official Microsoft evaluation media with Secure Boot (Windows
template) and a virtual TPM, and the host drives it one bounded stage at a time
over PowerShell Direct instead of dropping files and hoping.

  1. restore the clean baseline checkpoint and start the VM
  2. wait for bounded PowerShell Direct readiness            -> VM_READY
  3. verify the guest's clean-state booleans                 -> CLEAN_STATE_READY
  4. transfer the frozen package and recompute its hashes
     INSIDE the guest, requiring exact equality              -> PACKAGE_HASHES_VERIFIED
  5. run the activation-request phase and retrieve the request
                                                             -> ACTIVATION_REQUEST_READY
  6. validate request privacy, then invoke the HOST-ONLY operator issuer
  7. copy only the signed licenses back in                   -> LICENSE_IMPORTED
  8. resume the full matrix                                  -> MATRIX_RUNNING
  9. retrieve only the redacted result                       -> MATRIX_COMPLETE
 10. shut down gracefully and wait for full VM release

The signing key is passed to the operator issuer only. It never enters the VM,
the guest disk, the guest registry, the package, the transfer set, the guest
result, the logs, or the evidence. Transfer is non-network throughout
(Copy-VMFile host->guest, PowerShell Direct guest->host).

On timeout the orchestrator collects redacted diagnostics, attempts ONE graceful
shutdown, and stops honestly. It never infers success from a missing failure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from offline_package_matrix import build_license_bundle  # noqa: E402

CONTROL = ROOT / "packaging" / "hyperv" / "hyperv_control.ps1"
SESSION = ROOT / "packaging" / "hyperv" / "hyperv_session.ps1"
PS_RUNNER = ROOT / "scripts" / "offline_env_runner.ps1"
DEFAULT_APP_DIR = ROOT / "output" / "offline-package" / "stage" / "MondayReportOffline"
DEFAULT_TRANSFER_ROOT = Path(r"C:\mr-hv\xfer")
DEFAULT_VM = "MR-OFFLINE-E2"

GUEST_PKG = r"C:\pkg"
GUEST_TOOL = r"C:\tool"
GUEST_IN = r"C:\in"
GUEST_OUT = r"C:\out"

#: Bounded states, in order. Reported verbatim so a partial run is legible.
STATES = ("VM_READY", "CLEAN_STATE_READY", "PACKAGE_HASHES_VERIFIED",
          "ACTIVATION_REQUEST_READY", "LICENSE_IMPORTED", "MATRIX_RUNNING",
          "MATRIX_COMPLETE", "MATRIX_FAILED")

#: Filename fragments that must never reach a guest transfer directory.
_KEY_NAME_MARKERS = ("private", "issuer_key", "signing_key", "secret")

#: Environment names scrubbed from every child process.
_SCRUB = ("MONDAY_REPORT_OFFLINE_KEYS_DIR", "MONDAY_REPORT_LICENSE_PRIVATE_KEY",
          "MONDAY_REPORT_SIGNING_PRIVATE_KEY", "MONDAY_REPORT_ISSUER_PRIVATE_KEY",
          "OFFLINE_ISSUER_KEY",
          # Points at the operator key file; the transport has no use for it and
          # the comment above promised no key-shaped variable reaches it.
          "MONDAY_REPORT_OPERATOR_KEY_FILE")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


#: Where the guest credential is sealed. Set once from --state-root, because
#: credential ownership was migrated to the reviewer: the author's copy was
#: rotated away and no longer authenticates, so a run that does not carry the
#: right state root cannot open a guest session at all.
_STATE_ROOT = ""


def control(action: str, *, vm: str, timeout: float = 900.0, **kwargs) -> dict:
    """Invoke one host-side control action. Returns the parsed JSON envelope.

    The child environment is scrubbed so no key-shaped variable can reach the
    transport layer, which is also the only path into the guest.
    """

    args = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(CONTROL), "-Action", action, "-VmName", vm]
    if _STATE_ROOT:
        args += ["-StateRoot", _STATE_ROOT]
    for key, value in kwargs.items():
        if value is None or value == "":
            continue
        args += [f"-{key}", str(value)]
    child_env = {k: v for k, v in os.environ.items() if k not in _SCRUB}
    try:
        proc = subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout + 120, env=child_env)
    except subprocess.TimeoutExpired:
        # The docstring promises an honest stop on timeout. Letting
        # TimeoutExpired escape produced a bare traceback instead: no
        # MATRIX_FAILED envelope, no diagnostics, no shutdown, VM left running.
        return {"control": action, "ok": False, "returncode": -1,
                "detail": f"control action '{action}' exceeded its bounded timeout"}
    payload: dict = {}
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
    if not payload:
        payload = {"control": action, "ok": False,
                   "detail": (proc.stderr or proc.stdout or "no output")[-800:]}
    payload.setdefault("returncode", proc.returncode)
    return payload


def assert_no_key_material(paths: list[Path]) -> str | None:
    """Refuse before ANY transfer if something key-shaped is staged."""

    for base in paths:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            lowered = path.name.lower()
            if any(marker in lowered for marker in _KEY_NAME_MARKERS):
                return f"key-shaped file staged for transfer: {path.name}"
            if path.stat().st_size <= 4096:
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if "PRIVATE KEY" in text.upper():
                    return f"private key block present in a staged file: {path.name}"
                # The operator key ships as BARE HEX, not PEM, so the banner test
                # above never covered the format actually in use. A loose file
                # whose entire content is 64 hex characters is exactly that
                # shape; every legitimate transfer artifact is JSON, PowerShell
                # or a binary archive.
                if re.fullmatch(r"[0-9a-fA-F]{64}", text.strip()):
                    return f"bare key-shaped hex present in a staged file: {path.name}"
    return None


def stage_transfer_set(*, app_dir: Path, root: Path, source_commit: str = "",
                       source_tree: str = "") -> tuple[Path, dict]:
    """Stage the exact package archive, the runner, the session driver, and the
    package metadata the guest needs to recompute hashes independently."""

    pkg, tool, inbox, outbox = root / "pkg", root / "tool", root / "in", root / "out"
    for directory in (pkg, tool, inbox, outbox):
        if directory.exists():
            shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True, exist_ok=True)

    archives = sorted(app_dir.parents[1].glob("MondayReportOffline-*-win64.zip"))
    if not archives:
        raise FileNotFoundError("installer archive missing")
    archive = archives[-1]
    shutil.copy2(archive, pkg / archive.name)
    shutil.copy2(PS_RUNNER, tool / PS_RUNNER.name)
    shutil.copy2(SESSION, tool / SESSION.name)

    # The head binding is taken from the CALLER when supplied, and only falls
    # back to git.
    #
    # Shelling out to git here silently produced EMPTY strings for the reviewer:
    # the pristine export is created by the author, so git refuses to operate in
    # a repository the running user does not own and writes nothing to stdout.
    # The empty values then collapsed the guest runner's argument list --
    # "Missing an argument for parameter 'SourceCommit'" -- which surfaced only
    # as an empty phase log and an unexplained "the guest did not export an
    # activation request".
    #
    # The reviewer already holds these values in the frozen package descriptor
    # it verified, so it passes them explicitly and does not depend on git
    # working in a directory it does not own.
    commit = (source_commit or "").strip()
    tree = (source_tree or "").strip()
    if not commit or not tree:
        commit = commit or subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=30).stdout.strip()
        tree = tree or subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD^{tree}"],
            capture_output=True, text=True, timeout=30).stdout.strip()
    # FAIL CLOSED. A guest run bound to an empty head is not evidence about any
    # head, and writing the empty value defers the failure to a place where it
    # cannot be diagnosed.
    if not commit or not tree:
        raise RuntimeError(
            "source commit/tree could not be resolved; pass --source-commit and "
            "--source-tree explicitly (git cannot run in a repository this user "
            "does not own)")
    summary_path = app_dir.parents[1] / "build-summary.json"
    build_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    meta = {
        "source_commit": commit,
        "source_tree": tree,
        "package_version": build_summary.get("product_version", ""),
        "installer_sha256": build_summary.get("installer_sha256", ""),
    }
    (tool / "package-meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True),
                                            encoding="utf-8")
    return archive, meta


def push_tools(*, vm: str, root: Path) -> list[dict]:
    """Transfer ONLY the test tooling: the session driver, the environment
    runner and the package metadata.

    These must land before the clean-state stage, because that stage is executed
    BY the session driver. None of them is the product: the clean-state claim is
    about a prior Monday Report installation, its data, its licence and the
    absence of development dependencies, and no product file is transferred here.
    """

    steps = []
    for guest in (GUEST_PKG, GUEST_TOOL, GUEST_IN, GUEST_OUT):
        steps.append(control("mkdir", vm=vm, GuestPath=guest, timeout=180))
    for source in sorted((root / "tool").iterdir()):
        steps.append(control("push", vm=vm, SourcePath=str(source),
                             GuestPath=f"{GUEST_TOOL}\\{source.name}", timeout=600))
    return steps


def push_package(*, vm: str, root: Path) -> list[dict]:
    """Transfer the frozen package itself, AFTER the guest has proven it is
    clean, so the clean-state proof cannot be read as having been taken with the
    product already present."""

    steps = []
    for source in sorted((root / "pkg").iterdir()):
        steps.append(control("push", vm=vm, SourcePath=str(source),
                             GuestPath=f"{GUEST_PKG}\\{source.name}", timeout=1800))
    return steps


def pull_json(*, vm: str, guest_path: str) -> dict | None:
    payload = control("pull", vm=vm, GuestPath=guest_path, timeout=300)
    if not payload.get("present"):
        return None
    try:
        return json.loads(payload.get("content") or "")
    except json.JSONDecodeError:
        return None


def stop_honestly(*, vm: str, state: str, detail: str, states: list[str],
                  transitions: list[dict]) -> int:
    """Collect redacted diagnostics, attempt ONE graceful shutdown, stop."""

    diagnostics = control("diagnostics", vm=vm, timeout=300)
    control("shutdown", vm=vm, TimeoutSeconds=300, timeout=600)
    print(json.dumps({
        "guard": "offline_hyperv",
        "claim_scope": "ENVIRONMENT_2 air-gapped matrix inside a task-owned clean Hyper-V VM",
        "environment_label": "ENVIRONMENT_2",
        "state": "MATRIX_FAILED",
        "reached_state": state,
        "detail": detail,
        "states_observed": states,
        "transitions": transitions,
        "diagnostics": diagnostics.get("diagnostics", {}),
        "airgap": {"signing_performed_on_host": True, "key_transferred_into_guest": False},
        "summary": {"passed": 0, "failed": 1, "certification": "not_passed"},
    }, indent=2))
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="offline-hyperv matrix")
    parser.add_argument("--phase", choices=["request", "resume", "full"], default="full",
                        help="split phases so a two-environment orchestrator can interleave")
    parser.add_argument("--vm-name", default=DEFAULT_VM)
    parser.add_argument("--package-dir", default=str(DEFAULT_APP_DIR))
    parser.add_argument("--transfer-root", default=str(DEFAULT_TRANSFER_ROOT))
    parser.add_argument("--key-file",
                        help="operator private key. NON-AUTHORITATIVE developer mode only: "
                             "it signs in-process, so the principal running the matrix also "
                             "issues its own licences and the result cannot support "
                             "commercial acceptance. Refused outright in --brokered mode.")
    parser.add_argument("--brokered", action="store_true",
                        help="AUTHORITATIVE mode. Licences are obtained from the issuance "
                             "broker instead of being signed here, so the issuer key never "
                             "enters this process, this session, or the guest.")
    parser.add_argument("--review-nonce", default="",
                        help="reviewer-minted nonce; the issuance witness must answer it")
    parser.add_argument("--env-label", default="ENVIRONMENT_2")
    parser.add_argument("--source-commit", default="",
                        help="head binding supplied by the caller; the reviewer passes the "
                             "value from the frozen package descriptor because git cannot "
                             "run in a repository it does not own")
    parser.add_argument("--source-tree", default="",
                        help="tree binding supplied by the caller (see --source-commit)")
    parser.add_argument("--state-root", default="",
                        help="where the guest credential is sealed; the reviewer passes its "
                             "own state root because credential ownership was migrated")
    parser.add_argument("--other-environment-license",
                        help="a license issued for the OTHER environment, so this one can "
                             "prove it rejects a copied license (PK19)")
    parser.add_argument("--expiry-seconds", type=int, default=240)
    parser.add_argument("--ready-timeout", type=float, default=1800.0)
    parser.add_argument("--request-timeout", type=float, default=1800.0)
    parser.add_argument("--matrix-timeout", type=float, default=3600.0)
    parser.add_argument("--out", help="where to copy the ENVIRONMENT_2 result")
    args = parser.parse_args(argv)

    vm = args.vm_name
    root = Path(args.transfer_root)
    app_dir = Path(args.package_dir)
    states: list[str] = []
    transitions: list[dict] = []

    def record(payload: dict, label: str) -> None:
        transitions.append({"step": label, "ok": bool(payload.get("ok")),
                            "state": payload.get("guest_state") or payload.get("state") or ""})

    if not (app_dir / "MondayReportOffline.exe").exists():
        print(json.dumps({"guard": "offline_hyperv", "detail": "package not built",
                          "summary": {"passed": 0, "failed": 1, "certification": "not_passed"}}))
        return 1

    # ---- mode selection: authoritative brokered, or non-authoritative direct --
    #
    # In brokered mode this process never holds the issuer key. That is the whole
    # point: while the matrix signs its own licences, the principal running it is
    # also the principal issuing them, and its output cannot support commercial
    # acceptance no matter how green it is.
    global _STATE_ROOT
    if args.state_root:
        _STATE_ROOT = args.state_root

    if args.brokered:
        offered = [name for name in ("MONDAY_REPORT_OPERATOR_KEY_FILE",
                                     "MONDAY_REPORT_OPERATOR_KEY",
                                     "MONDAY_REPORT_OFFLINE_ISSUER_KEY")
                   if os.environ.get(name)]
        if args.key_file or offered:
            print(json.dumps({
                "guard": "offline_hyperv", "mode": "brokered",
                "refused": "ISSUER_KEY_OFFERED_IN_AUTHORITATIVE_MODE",
                "detail": "authoritative brokered mode refuses issuer key material; a matrix "
                          "that can sign its own licences is not independently attested "
                          f"(offered: {args.key_file and '--key-file'} {offered})",
                "summary": {"passed": 0, "failed": 1, "certification": "not_passed"}}))
            return 1
        if not args.review_nonce:
            print(json.dumps({
                "guard": "offline_hyperv", "mode": "brokered",
                "refused": "REVIEW_NONCE_REQUIRED",
                "detail": "brokered mode requires the reviewer-minted nonce the issuance "
                          "witness must answer",
                "summary": {"passed": 0, "failed": 1, "certification": "not_passed"}}))
            return 1
        key_file = None
    else:
        key_file = Path(args.key_file or os.environ.get("MONDAY_REPORT_OPERATOR_KEY_FILE", ""))
        if not key_file.is_file():
            print(json.dumps({"guard": "offline_hyperv",
                              "detail": "operator key must be supplied explicitly via --key-file or "
                                        "MONDAY_REPORT_OPERATOR_KEY_FILE (host side only, never transferred)",
                              "summary": {"passed": 0, "failed": 1, "certification": "not_passed"}}))
            return 1

    state_path = root / "orchestrator-state.json"

    # ------------------------------------------------------------- request
    if args.phase in ("request", "full"):
        root.mkdir(parents=True, exist_ok=True)
        # Clear the PREVIOUS run's artifacts from the transfer root. Only the
        # pkg/tool/in/out subdirectories were wiped, so a failed run left last
        # run's environment-result.json in place -- and the two-environment
        # orchestrator, finding the file present, folded a stale Environment 2
        # from an earlier commit into a fresh record.
        for stale in ("activation-request.json", "environment-request-record.json",
                      "environment-result.json", "orchestrator-state.json"):
            (root / stale).unlink(missing_ok=True)
        try:
            archive, meta = stage_transfer_set(
                app_dir=app_dir, root=root,
                source_commit=args.source_commit, source_tree=args.source_tree)
        except FileNotFoundError as exc:
            print(json.dumps({"guard": "offline_hyperv", "detail": str(exc),
                              "summary": {"passed": 0, "failed": 1, "certification": "not_passed"}}))
            return 1

        # The archive the guest will hash-verify must be the frozen one.
        staged_hash = _sha256(root / "pkg" / archive.name)
        if meta["installer_sha256"] and staged_hash != meta["installer_sha256"].lower():
            print(json.dumps({"guard": "offline_hyperv",
                              "detail": "staged archive does not match the frozen installer hash",
                              "summary": {"passed": 0, "failed": 1, "certification": "not_passed"}}))
            return 1

        refusal = assert_no_key_material([root / "pkg", root / "tool", root / "in"])
        if refusal:
            print(json.dumps({"guard": "offline_hyperv", "aborted": "AIRGAP_BOUNDARY_VIOLATION",
                              "detail": refusal,
                              "summary": {"passed": 0, "failed": 1, "certification": "not_passed"}}))
            return 2

        restored = control("restore-baseline", vm=vm, TimeoutSeconds=600, timeout=900)
        record(restored, "restore-baseline")
        if not restored.get("ok"):
            return stop_honestly(vm=vm, state="", detail=restored.get("detail", "baseline restore failed"),
                                 states=states, transitions=transitions)

        ready = control("wait-ready", vm=vm, TimeoutSeconds=int(args.ready_timeout),
                        timeout=args.ready_timeout)
        record(ready, "wait-ready")
        if not ready.get("ok"):
            return stop_honestly(vm=vm, state="", detail=ready.get("detail", "guest never became ready"),
                                 states=states, transitions=transitions)
        states.append("VM_READY")
        if int(ready.get("vm_network_adapter_count", -1)) != 0:
            return stop_honestly(vm=vm, state="VM_READY",
                                 detail="the VM carries a network adapter during certification",
                                 states=states, transitions=transitions)

        # Tooling first: the clean-state stage is executed BY the session driver.
        for step in push_tools(vm=vm, root=root):
            record(step, step.get("control", "push-tool"))
            if not step.get("ok"):
                return stop_honestly(vm=vm, state="VM_READY",
                                     detail=step.get("detail", "tool transfer failed"),
                                     states=states, transitions=transitions)

        clean = control("invoke-stage", vm=vm, Stage="clean", TimeoutSeconds=600, timeout=900)
        record(clean, "clean")
        if clean.get("guest_state") != "CLEAN_STATE_READY":
            return stop_honestly(vm=vm, state="VM_READY", detail="guest clean-state proof failed",
                                 states=states, transitions=transitions)
        states.append("CLEAN_STATE_READY")

        # The product only crosses AFTER the guest has proven it was clean.
        for step in push_package(vm=vm, root=root):
            record(step, step.get("control", "push-package"))
            if not step.get("ok"):
                return stop_honestly(vm=vm, state="CLEAN_STATE_READY",
                                     detail=step.get("detail", "package transfer failed"),
                                     states=states, transitions=transitions)

        staged = control("invoke-stage", vm=vm, Stage="stage-package", TimeoutSeconds=1200, timeout=1500)
        record(staged, "stage-package")
        if staged.get("guest_state") != "PACKAGE_HASHES_VERIFIED":
            return stop_honestly(vm=vm, state="CLEAN_STATE_READY",
                                 detail="the guest could not reproduce the frozen package hashes",
                                 states=states, transitions=transitions)
        states.append("PACKAGE_HASHES_VERIFIED")

        requested = control("invoke-stage", vm=vm, Stage="request",
                            TimeoutSeconds=int(args.request_timeout), timeout=args.request_timeout)
        record(requested, "request")
        if requested.get("guest_state") != "ACTIVATION_REQUEST_READY":
            return stop_honestly(vm=vm, state="PACKAGE_HASHES_VERIFIED",
                                 detail="the guest did not export an activation request",
                                 states=states, transitions=transitions)
        states.append("ACTIVATION_REQUEST_READY")

        request_doc = pull_json(vm=vm, guest_path=f"{GUEST_OUT}\\activation-request.json")
        record_doc = pull_json(vm=vm, guest_path=f"{GUEST_OUT}\\environment-request-record.json")
        if request_doc is None:
            return stop_honestly(vm=vm, state="ACTIVATION_REQUEST_READY",
                                 detail="the activation request could not be retrieved",
                                 states=states, transitions=transitions)

        (root / "activation-request.json").write_text(
            json.dumps(request_doc, indent=2, sort_keys=True), encoding="utf-8")
        if record_doc is not None:
            (root / "environment-request-record.json").write_text(
                json.dumps(record_doc, indent=2, sort_keys=True), encoding="utf-8")
        state_path.write_text(json.dumps({"states": states, "phase": "request"}, indent=2),
                              encoding="utf-8")

        if args.phase == "request":
            print(json.dumps({
                "guard": "offline_hyperv", "phase": "request",
                "environment_label": "ENVIRONMENT_2",
                "state": "ACTIVATION_REQUEST_READY",
                "states_observed": states,
                "activation_request": str(root / "activation-request.json"),
                "summary": {"passed": len(states), "failed": 0, "certification": "passed"},
            }, indent=2))
            return 0

    # -------------------------------------------------------------- resume
    if args.phase in ("resume", "full"):
        if args.phase == "resume":
            if state_path.exists():
                states = json.loads(state_path.read_text(encoding="utf-8")).get("states", [])
            ready = control("wait-ready", vm=vm, TimeoutSeconds=int(args.ready_timeout),
                            timeout=args.ready_timeout)
            record(ready, "wait-ready")
            if not ready.get("ok"):
                return stop_honestly(vm=vm, state="ACTIVATION_REQUEST_READY",
                                     detail="guest not reachable for the resume phase",
                                     states=states, transitions=transitions)

        request_path = root / "activation-request.json"
        if not request_path.exists():
            print(json.dumps({"guard": "offline_hyperv",
                              "detail": "no activation request from the request phase",
                              "summary": {"passed": 0, "failed": 1, "certification": "not_passed"}}))
            return 1

        # ---- HOST-SIDE SIGNING: outside the product and outside the VM ----
        inbox = root / "in"
        inbox.mkdir(parents=True, exist_ok=True)
        if args.brokered:
            # AUTHORITATIVE: ask the broker. The issuer key stays in the author's
            # process, outside this session and outside the guest; only signed
            # licences and an issuance witness come back, and this process cannot
            # write the directory they arrive in.
            sys.path.insert(0, str(ROOT / "scripts"))
            import offline_issuance_broker as broker  # noqa: PLC0415

            os.environ[broker.BROKER_FLAG] = "1"
            try:
                issued = broker.request_bundle(
                    request=request_path, transfer_in=inbox, sequence=1,
                    nonce=args.review_nonce, label=args.env_label)
            except (TimeoutError, ValueError, OSError) as exc:
                return stop_honestly(vm=vm, state="ACTIVATION_REQUEST_READY",
                                     detail=f"brokered issuance failed: {exc}",
                                     states=states, transitions=transitions)
            witness_path = inbox.parent / "issuance-witness.json"
            witness_path.write_text(
                json.dumps(issued.get("witness", {}), indent=2, sort_keys=True),
                encoding="utf-8")
            bundle = {name: True for name in issued.get("licences", [])}
            if not bundle:
                return stop_honestly(vm=vm, state="ACTIVATION_REQUEST_READY",
                                     detail="the broker returned no licences",
                                     states=states, transitions=transitions)
        else:
            bundle = build_license_bundle(request_path=request_path, transfer_in=inbox,
                                          key_file=key_file, expiry_seconds=args.expiry_seconds)
            if not all(bundle.values()):
                return stop_honestly(vm=vm, state="ACTIVATION_REQUEST_READY",
                                     detail=f"operator issuance failed: {bundle}",
                                     states=states, transitions=transitions)

        # A genuine license for the OTHER environment, so this one proves it
        # rejects a copied cross-environment license (PK19).
        other = Path(args.other_environment_license or
                     os.environ.get("MONDAY_REPORT_OTHER_ENV_LICENSE", ""))
        if other.is_file():
            shutil.copy2(other, inbox / "license-other-environment.json")

        refusal = assert_no_key_material([inbox])
        if refusal:
            print(json.dumps({"guard": "offline_hyperv", "aborted": "AIRGAP_BOUNDARY_VIOLATION",
                              "detail": refusal,
                              "summary": {"passed": 0, "failed": 1, "certification": "not_passed"}}))
            return 2

        for source in sorted(inbox.iterdir()):
            pushed = control("push", vm=vm, SourcePath=str(source),
                             GuestPath=f"{GUEST_IN}\\{source.name}", timeout=600)
            record(pushed, "push-license")
            if not pushed.get("ok"):
                return stop_honestly(vm=vm, state="ACTIVATION_REQUEST_READY",
                                     detail=pushed.get("detail", "license transfer failed"),
                                     states=states, transitions=transitions)
        states.append("LICENSE_IMPORTED")
        states.append("MATRIX_RUNNING")

        resumed = control("invoke-stage", vm=vm, Stage="resume",
                          TimeoutSeconds=int(args.matrix_timeout), timeout=args.matrix_timeout)
        record(resumed, "resume")
        if resumed.get("guest_state") != "MATRIX_COMPLETE":
            return stop_honestly(vm=vm, state="MATRIX_RUNNING",
                                 detail="the environment 2 matrix did not complete",
                                 states=states, transitions=transitions)
        states.append("MATRIX_COMPLETE")

        result = pull_json(vm=vm, guest_path=f"{GUEST_OUT}\\environment-result.json")
        record_doc = pull_json(vm=vm, guest_path=f"{GUEST_OUT}\\environment-request-record.json")
        if result is None:
            return stop_honestly(vm=vm, state="MATRIX_COMPLETE",
                                 detail="the redacted result could not be retrieved",
                                 states=states, transitions=transitions)

        (root / "environment-result.json").write_text(
            json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        if record_doc is not None:
            (root / "environment-request-record.json").write_text(
                json.dumps(record_doc, indent=2, sort_keys=True), encoding="utf-8")
        if args.out:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
            if record_doc is not None:
                out_path.with_name("environment-2-request-record.json").write_text(
                    json.dumps(record_doc, indent=2, sort_keys=True), encoding="utf-8")

        shutdown = control("shutdown", vm=vm, TimeoutSeconds=600, timeout=900)
        record(shutdown, "shutdown")

        request_record = json.loads((root / "environment-request-record.json").read_text(
            encoding="utf-8")) if (root / "environment-request-record.json").exists() else {}
        passed = (request_record.get("totals", {}).get("passed", 0)
                  + result.get("totals", {}).get("passed", 0))
        failed = (request_record.get("totals", {}).get("failed", 1)
                  + result.get("totals", {}).get("failed", 1))

        print(json.dumps({
            "guard": "offline_hyperv",
            "claim_scope": "ENVIRONMENT_2 air-gapped matrix inside a task-owned clean Hyper-V VM",
            "environment_label": "ENVIRONMENT_2",
            "environments_executed": ["windows-11-hyperv (clean install, no network adapter)"],
            "states_observed": states,
            "airgap": {"signing_performed_on_host": True,
                       "key_transferred_into_guest": False,
                       "transport": "Copy-VMFile + PowerShell Direct (non-network)"},
            "graceful_shutdown": bool(shutdown.get("ok")),
            "summary": {"passed": passed, "failed": failed,
                        "certification": "passed" if failed == 0 else "not_passed"},
            "checks": request_record.get("checks", []) + result.get("checks", []),
        }, indent=2))
        return 0 if failed == 0 else 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
