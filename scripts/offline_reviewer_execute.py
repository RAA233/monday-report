"""Reviewer-side driver. Runs ONLY under the reviewer principal, launched by the
scheduled task that ``packaging/hyperv/reviewer_bootstrap.ps1`` registered.

WHAT THIS IS FOR
----------------
The offline acceptance chain used to grade itself. This driver produces the one
fact the authoring process cannot: an Ed25519 signature from a key sealed with
DPAPI to a Windows account whose password the authoring process never learned.

REFUSALS, ENFORCED BEFORE ANYTHING ELSE
---------------------------------------
The reviewer must never hold the licence-issuer private key. The existing
two-environment orchestrator REQUIRES that key and forwards it to the Hyper-V
matrix, which signs in-process -- so handing the reviewer that orchestrator
would hand it the issuer key and collapse the separation this driver exists to
create. This driver therefore refuses any issuer key material offered by
argument or environment, and obtains licences only by blocking on the exchange
directory the author writes.

WHAT A SIGNATURE FROM THIS DRIVER DOES AND DOES NOT MEAN
--------------------------------------------------------
It means: a principal the authoring process cannot impersonate observed these
values and vouched for them.

It does NOT mean the matrices ran honestly. THE REVIEWER EXECUTES CODE THE
AUTHOR WROTE. A runner committed by the author that emitted an all-PASS check
list without executing anything would produce genuine hashes and a genuine
signature over fabricated facts. The tool hashes record WHICH binary ran, never
that it was honest. That residual is closed only by human review of the exact
attested commit, and it must be disclosed rather than papered over.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path

#: Refused outright. Presence means someone tried to give the reviewer the
#: issuer key, which would make its signature worthless as separation evidence.
FORBIDDEN_ENV = (
    "MONDAY_REPORT_OPERATOR_KEY",
    "MONDAY_REPORT_OPERATOR_KEY_FILE",
    "MONDAY_REPORT_OFFLINE_ISSUER_KEY",
    "MONDAY_REPORT_LICENSE_PRIVATE_KEY",
)

TRUST_DIR = Path("C:/mr-hv/trust")
TRUST_ROOT_PATH = TRUST_DIR / "offline-review-trust-root.v1.json"

DPAPI_ENTROPY = b"monday-report/offline-review-key/v1"


# --------------------------------------------------------------------------
# DPAPI, in-process. The key never reaches a command line, a pipe, or another
# process -- so no external tool ever observes the private half.
# --------------------------------------------------------------------------
class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> _Blob:
    buffer = ctypes.create_string_buffer(bytes(data), len(data))
    return _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))


def _blob_bytes(blob: _Blob) -> bytes:
    return ctypes.string_at(blob.pbData, blob.cbData)


def dpapi_protect(data: bytes) -> bytes:
    out = _Blob()
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(_blob(data)), "monday-report offline review key",
        ctypes.byref(_blob(DPAPI_ENTROPY)), None, None, 0, ctypes.byref(out))
    if not ok:
        raise OSError("CryptProtectData failed")
    try:
        return _blob_bytes(out)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def dpapi_unprotect(blob: bytes) -> bytes:
    out = _Blob()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(_blob(blob)), None, ctypes.byref(_blob(DPAPI_ENTROPY)),
        None, None, 0, ctypes.byref(out))
    if not ok:
        # Fail closed. Never fall back to an unprotected or regenerated key: a
        # regenerated key would silently produce attestations under a NEW
        # identity that the pinned trust root no longer matches.
        raise OSError("CryptUnprotectData failed -- the review key is not "
                      "decryptable in this session")
    try:
        return _blob_bytes(out)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def refuse_issuer_material(args: argparse.Namespace) -> None:
    for name in FORBIDDEN_ENV:
        if os.environ.get(name):
            print(json.dumps({
                "refused": "ISSUER_KEY_OFFERED_TO_REVIEWER",
                "detail": f"environment variable {name} is set"}))
            raise SystemExit(3)
    for value in vars(args).values():
        if isinstance(value, str) and value:
            lowered = value.lower()
            if "issuer_private" in lowered or "--key-file" in lowered:
                print(json.dumps({
                    "refused": "ISSUER_KEY_OFFERED_TO_REVIEWER",
                    "detail": "an argument referenced issuer key material"}))
                raise SystemExit(3)


def current_sid() -> str:
    out = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                         capture_output=True, text=True, timeout=30).stdout
    for part in [p.strip().strip('"') for p in out.split(",")]:
        if part.startswith("S-1-"):
            return part
    return ""


def account_sid(name: str) -> str:
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         "$ErrorActionPreference='Stop';"
         f"try {{ (Get-LocalUser -Name '{name}').SID.Value }} catch {{ '' }}"],
        capture_output=True, text=True, timeout=60)
    value = completed.stdout.strip()
    return value if value.startswith("S-1-") else ""


def stage_bootstrap(args: argparse.Namespace) -> int:
    """Generate the review keypair IN THE REVIEWER'S OWN SESSION and pin it.

    Ordering is load-bearing. The key must be created AFTER the operator set the
    reviewer password: a key generated while the authoring process still knew
    the password would be recoverable by it through an ordinary logon, not
    through account takeover.
    """

    sys.path.insert(0, str(Path(args.source_root)))
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from backend.app.offline_review_attestation import (
        TRUST_ROOT_SCHEMA, key_fingerprint, principal_digest)

    state = Path(args.state_root)
    state.mkdir(parents=True, exist_ok=True)
    key_path = state / "review-key.dpapi"

    if key_path.exists():
        private_bytes = dpapi_unprotect(key_path.read_bytes())
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        created = "reused"
    else:
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes_raw()
        key_path.write_bytes(dpapi_protect(private_bytes))
        subprocess.run(["icacls", str(key_path), "/inheritance:r"],
                       capture_output=True, text=True, timeout=60)
        subprocess.run(["icacls", str(key_path), "/grant:r",
                        f"{os.environ.get('USERNAME', '')}:(F)", "*S-1-5-18:(F)"],
                       capture_output=True, text=True, timeout=60)
        created = "generated"
    public_bytes = private_key.public_key().public_bytes_raw()
    fingerprint = key_fingerprint(public_bytes)

    reviewer_name = os.environ.get("USERNAME", "")
    reviewer_sid = current_sid()
    author_name = args.author_account
    author_sid = account_sid(author_name)
    if not reviewer_sid or not author_sid:
        print(json.dumps({"stage": "bootstrap", "error": "principal SIDs unresolved"}))
        return 4
    if reviewer_sid == author_sid:
        print(json.dumps({"stage": "bootstrap",
                          "error": "OFFLINE_INDEPENDENT_ATTESTOR_REQUIRED",
                          "detail": "reviewer and author are the same account"}))
        return 4

    salt_path = state / "principal-salt.txt"
    if not salt_path.exists():
        salt_path.write_text(secrets.token_hex(16), encoding="utf-8")
    salt = salt_path.read_text(encoding="utf-8").strip()

    TRUST_DIR.mkdir(parents=True, exist_ok=True)
    trust_root = {
        "schema_version": TRUST_ROOT_SCHEMA,
        "review_public_key_hex": public_bytes.hex(),
        "review_key_fingerprint": fingerprint,
        "reviewer_account_name": reviewer_name,
        "author_account_name": author_name,
        "principal_salt": salt,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    TRUST_ROOT_PATH.write_text(json.dumps(trust_root, indent=2), encoding="utf-8")

    # The anchor must be readable by the author (it has to verify) and writable
    # by nobody but the reviewer. An access probe from the author side proves it.
    subprocess.run(["icacls", str(TRUST_ROOT_PATH), "/inheritance:r"],
                   capture_output=True, text=True, timeout=60)
    subprocess.run(["icacls", str(TRUST_ROOT_PATH), "/grant:r",
                    f"{reviewer_name}:(F)", "*S-1-5-18:(F)",
                    f"{author_name}:(R)"],
                   capture_output=True, text=True, timeout=60)

    (state / "python-path.txt").write_text(sys.executable, encoding="utf-8")

    # PUBLIC output only. The private half never leaves this process.
    Path(args.out_root).mkdir(parents=True, exist_ok=True)
    (Path(args.out_root) / "review-key-public.json").write_text(json.dumps({
        "review_key_fingerprint": fingerprint,
        "review_public_key_hex": public_bytes.hex(),
        "reviewer_principal_digest": principal_digest(reviewer_sid, salt),
        "author_principal_digest": principal_digest(author_sid, salt),
        "key": created,
        "trust_root": str(TRUST_ROOT_PATH),
    }, indent=2), encoding="utf-8")

    print(json.dumps({"stage": "bootstrap", "key": created,
                      "review_key_fingerprint": fingerprint,
                      "principals_distinct": True}, indent=2))
    return 0


def stage_preflight(args: argparse.Namespace) -> int:
    """R00: MEASURE what the reviewer principal can actually do.

    Whether PowerShell Direct works for a non-administrative account holding
    only 'Hyper-V Administrators' cannot be settled by assertion, and the answer
    decides which separation sentence this protocol has earned. Measure, then
    write whichever sentence the measurement supports.
    """

    checks: list[dict] = []

    def probe(name: str, script: str) -> None:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=180)
        ok = completed.returncode == 0 and "TRUE" in completed.stdout.upper()
        checks.append({"id": name, "ok": ok,
                       "detail": (completed.stdout or completed.stderr).strip()[:160]})

    probe("R00a get-vm", "try { $null = Get-VM -Name MR-OFFLINE-E2 -ErrorAction Stop; 'TRUE' } "
                         "catch { 'FALSE ' + $_.Exception.GetType().Name }")
    probe("R00b snapshot-readable",
          "try { $null = Get-VMSnapshot -VMName MR-OFFLINE-E2 -Name clean-baseline "
          "-ErrorAction Stop; 'TRUE' } catch { 'FALSE ' + $_.Exception.GetType().Name }")
    probe("R00c dpapi-roundtrip",
          "try { $s = ConvertTo-SecureString 'probe' -AsPlainText -Force; "
          "$e = ConvertFrom-SecureString $s; $null = ConvertTo-SecureString $e; 'TRUE' } "
          "catch { 'FALSE ' + $_.Exception.GetType().Name }")
    probe("R00d profile-loaded",
          "if (Test-Path $env:USERPROFILE) { 'TRUE' } else { 'FALSE' }")

    # The review key must survive across task launches, not merely within one.
    state = Path(args.state_root)
    key_path = state / "review-key.dpapi"
    if key_path.exists():
        try:
            dpapi_unprotect(key_path.read_bytes())
            checks.append({"id": "R00e key-decrypts-in-new-session", "ok": True,
                           "detail": "review key decrypted in a fresh task launch"})
        except OSError as exc:
            checks.append({"id": "R00e key-decrypts-in-new-session", "ok": False,
                           "detail": str(exc)})
    else:
        checks.append({"id": "R00e key-decrypts-in-new-session", "ok": False,
                       "detail": "no review key present; run the bootstrap stage first"})

    checks.append({"id": "R00f not-administrator", "ok": not _is_admin(),
                   "detail": "reviewer is not a local administrator"})

    failed = [c for c in checks if not c["ok"]]
    report = {"stage": "preflight", "checks": checks,
              "summary": {"passed": len(checks) - len(failed), "failed": len(failed)}}
    Path(args.out_root).mkdir(parents=True, exist_ok=True)
    (Path(args.out_root) / "reviewer-preflight.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if not failed else 5


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False



PACKAGE_ROOT = Path("C:/mr-hv/reviewer-pkg")


def _frozen_package() -> dict:
    """Read the frozen package descriptor and RE-HASH the staged artifacts.

    The descriptor is a claim. The reviewer recomputes digests from the bytes
    actually staged for it, so a descriptor that disagrees with its own package
    is caught here instead of being inherited into the transcript.
    """

    descriptor = PACKAGE_ROOT / "frozen-package.json"
    if not descriptor.exists():
        raise FileNotFoundError("the author has not staged a frozen package")
    frozen = json.loads(descriptor.read_text(encoding="utf-8"))
    app_dir = PACKAGE_ROOT / "app"
    recomputed = {"executable_sha256": sha256_file(app_dir / "MondayReportOffline.exe")}
    installer = PACKAGE_ROOT / str(frozen.get("installer_name", ""))
    if installer.is_file():
        recomputed["installer_sha256"] = sha256_file(installer)
    disagreements = [k for k, v in recomputed.items() if frozen.get(k) != v]
    return {"frozen": frozen, "recomputed": recomputed, "disagreements": disagreements}


def _run_runner(source: Path, python_exe: str, *, phase: str, label: str,
                env_class: str, work_dir: Path, transfer_in, transfer_out: Path,
                frozen: dict):
    """Invoke the environment runner, which accepts NO key material by design --
    and this driver has none to offer."""

    cmd = [python_exe, str(source / "scripts" / "offline_env_runner.py"),
           "--phase", phase, "--env-label", label, "--env-class", env_class,
           "--package-dir", str(PACKAGE_ROOT / "app"), "--work-dir", str(work_dir),
           "--transfer-out", str(transfer_out),
           "--source-commit", str(frozen.get("source_commit", "")),
           "--source-tree", str(frozen.get("source_tree", "")),
           "--package-version", str(frozen.get("package_version", "")),
           "--installer-sha256", str(frozen.get("installer_sha256", ""))]
    if transfer_in is not None:
        cmd += ["--transfer-in", str(transfer_in)]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=7200)


def stage_environment(args, label: str, env_class: str) -> int:
    """Execute one COMPLETE environment matrix under the reviewer principal.

    The reviewer runs the matrix itself and obtains licences only by asking the
    author through the exchange directory, so it never holds the issuer key.
    What it signs later is what it observed here, not a summary handed to it.
    """

    source = Path(args.source_root)
    sys.path.insert(0, str(source))
    sys.path.insert(0, str(source / "scripts"))
    import offline_issuance_broker as broker

    out = Path(args.out_root)
    out.mkdir(parents=True, exist_ok=True)
    transcript_path = out / (label + "-transcript.json")

    def fail(payload: dict, code: int) -> int:
        transcript_path.write_text(json.dumps(payload, indent=2, sort_keys=True),
                                   encoding="utf-8")
        print(json.dumps({"stage": label, "state": "FAILED"}, indent=2))
        return code

    # FRESH ISOLATED STATE, wiped by the reviewer itself.
    #
    # The matrix must start from a clean machine or PK01 fresh-install proves
    # nothing. The AUTHOR cannot do this wipe: reviewer\work is reviewer-owned
    # and author-read-only, so an author-side cleanup fails with access denied --
    # which is the isolation working, not a bug. The reviewer owns the directory,
    # so the reviewer clears it.
    work = Path(args.state_root).parent / "work" / label
    if work.exists():
        shutil.rmtree(work, ignore_errors=False)
    transfer_in = work / "in"
    transfer_out = work / "out"
    for d in (work, transfer_in, transfer_out):
        d.mkdir(parents=True, exist_ok=True)

    try:
        package = _frozen_package()
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        return fail({"state": "FAILED", "phase": "package", "detail": str(exc)}, 4)
    if package["disagreements"]:
        return fail({"state": "FAILED", "phase": "package",
                     "detail": "staged package disagrees with its descriptor",
                     "fields": package["disagreements"]}, 4)
    frozen = package["frozen"]

    # Minted BEFORE the run, so the author witness cannot predate it.
    nonce = secrets.token_hex(32)
    python_exe = sys.executable
    started = datetime.now(timezone.utc).isoformat()

    request = _run_runner(source, python_exe, phase="request", label=label,
                          env_class=env_class, work_dir=work / "app",
                          transfer_in=None, transfer_out=transfer_out, frozen=frozen)
    request_record = transfer_out / "environment-request-record.json"
    if request.returncode != 0 or not request_record.exists():
        return fail({"state": "FAILED", "phase": "request", "rc": request.returncode,
                     "stdout_tail": request.stdout[-1500:],
                     "stderr_tail": request.stderr[-800:]}, 5)

    activation = transfer_out / "activation-request.json"
    os.environ[broker.BROKER_FLAG] = "1"
    try:
        issued = broker.request_bundle(request=activation, transfer_in=transfer_in,
                                       sequence=1, nonce=nonce, label=label,
                                       source_commit=str(frozen.get("source_commit", "")),
                                       source_tree=str(frozen.get("source_tree", "")))
    except (TimeoutError, ValueError, OSError) as exc:
        return fail({"state": "FAILED", "phase": "issuance", "detail": str(exc)}, 6)

    resume = _run_runner(source, python_exe, phase="resume", label=label,
                         env_class=env_class, work_dir=work / "app",
                         transfer_in=transfer_in, transfer_out=transfer_out,
                         frozen=frozen)
    # The runner writes environment-result.json on the normal resume path;
    # environment-resume-record.json exists only on its exception path, so
    # looking for that name reports a clean run as a failure.
    resume_record = transfer_out / "environment-result.json"
    ok = resume.returncode == 0 and resume_record.exists()

    # The runner recomputes all four package digests INSIDE the environment.
    # Compare those against the frozen descriptor rather than re-deriving them
    # here: what matters is what the environment saw, not what the driver did.
    in_environment: dict = {}
    package_disagreements: list = []
    request_totals: dict = {}
    resume_totals: dict = {}
    if resume_record.exists():
        observed = json.loads(resume_record.read_text(encoding="utf-8"))
        resume_totals = observed.get("totals", {}) or {}
        for field in ("package_version", "installer_sha256", "executable_sha256",
                      "payload_manifest_sha256", "frontend_manifest_sha256"):
            in_environment[field] = observed.get(field)
            if frozen.get(field) and observed.get(field) != frozen.get(field):
                package_disagreements.append(field)
        ok = ok and not package_disagreements
    if request_record.exists():
        request_totals = json.loads(
            request_record.read_text(encoding="utf-8")).get("totals", {}) or {}
    totals = {
        "passed": int(request_totals.get("passed", 0)) + int(resume_totals.get("passed", 0)),
        "failed": int(request_totals.get("failed", 0)) + int(resume_totals.get("failed", 0)),
    }
    ok = ok and totals["failed"] == 0 and totals["passed"] > 0

    transcript = {
        "state": "COMPLETE" if ok else "FAILED",
        "environment_label": label,
        "environment_class": env_class,
        "review_nonce": nonce,
        "issuance_witness": issued.get("witness"),
        "licences_received": issued.get("licences"),
        "recomputed_package": package["recomputed"],
        "in_environment_package": in_environment,
        "package_disagreements": package_disagreements,
        "totals": totals,
        "frozen_package": frozen,
        "started_at": started,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "request_rc": request.returncode,
        "resume_rc": resume.returncode,
        "raw_request_record_sha256": sha256_file(request_record),
        "raw_resume_record_sha256": sha256_file(resume_record) if resume_record.exists() else "",
    }
    if not ok:
        transcript["stdout_tail"] = resume.stdout[-1500:]
        transcript["stderr_tail"] = resume.stderr[-800:]
    transcript_path.write_text(json.dumps(transcript, indent=2, sort_keys=True),
                               encoding="utf-8")
    print(json.dumps({"stage": label, "state": transcript["state"]}, indent=2))
    return 0 if ok else 7


def stage_e1(args) -> int:
    return stage_environment(args, "ENVIRONMENT_1", "windows-11-host-isolated")


def stage_e2(args) -> int:
    """Execute the COMPLETE Environment 2 matrix under the reviewer principal.

    The reviewer drives Hyper-V with the guest credential it now owns -- the
    author's copy was rotated away and no longer authenticates -- and runs the
    matrix in BROKERED mode, so the issuer key never enters this session or the
    guest. Licences arrive only from a directory the reviewer cannot write.
    """

    source = Path(args.source_root)
    out = Path(args.out_root)
    out.mkdir(parents=True, exist_ok=True)
    transcript_path = out / "ENVIRONMENT_2-transcript.json"
    label = "ENVIRONMENT_2"

    def fail(payload: dict, code: int) -> int:
        transcript_path.write_text(json.dumps(payload, indent=2, sort_keys=True),
                                   encoding="utf-8")
        print(json.dumps({"stage": "e2", "state": "FAILED"}, indent=2))
        return code

    state_root = Path(args.state_root)
    if not (state_root / "e2-guest.cred").is_file():
        return fail({"state": "FAILED", "phase": "credential",
                     "detail": "the reviewer does not hold a sealed guest credential; "
                               "run the credential migration first"}, 4)

    try:
        package = _frozen_package()
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        return fail({"state": "FAILED", "phase": "package", "detail": str(exc)}, 4)
    if package["disagreements"]:
        return fail({"state": "FAILED", "phase": "package",
                     "detail": "staged package disagrees with its descriptor",
                     "fields": package["disagreements"]}, 4)
    frozen = package["frozen"]

    # Minted BEFORE the run so the author's witness cannot predate it.
    nonce = secrets.token_hex(32)
    started = datetime.now(timezone.utc).isoformat()

    # The transfer root must be reviewer-owned: the author must not be able to
    # edit bytes that later become reviewer-signed evidence.
    transfer_root = Path(args.state_root).parent / "work" / label
    if transfer_root.exists():
        shutil.rmtree(transfer_root, ignore_errors=True)
    transfer_root.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, str(source / "scripts" / "offline_hyperv_matrix.py"),
           "--phase", "full", "--brokered", "--review-nonce", nonce,
           "--env-label", label,
           "--package-dir", str(PACKAGE_ROOT / "stage" / "MondayReportOffline"),
           "--transfer-root", str(transfer_root),
           "--state-root", str(state_root),
           "--out", str(transfer_root / "environment-2-result.json")]

    # Belt and braces: strip any issuer-key variable from the child environment.
    child_env = {k: v for k, v in os.environ.items()
                 if k not in ("MONDAY_REPORT_OPERATOR_KEY", "MONDAY_REPORT_OPERATOR_KEY_FILE",
                              "MONDAY_REPORT_OFFLINE_ISSUER_KEY",
                              "MONDAY_REPORT_LICENSE_PRIVATE_KEY")}
    matrix = subprocess.run(cmd, capture_output=True, text=True, timeout=14400, env=child_env)

    result_path = transfer_root / "environment-2-result.json"
    ok = matrix.returncode == 0 and result_path.exists()

    in_environment: dict = {}
    package_disagreements: list = []
    totals: dict = {}
    if result_path.exists():
        observed = json.loads(result_path.read_text(encoding="utf-8"))
        totals = observed.get("totals", {}) or {}
        for field in ("package_version", "installer_sha256", "executable_sha256",
                      "payload_manifest_sha256", "frontend_manifest_sha256"):
            in_environment[field] = observed.get(field)
            if frozen.get(field) and observed.get(field) != frozen.get(field):
                package_disagreements.append(field)
        ok = ok and not package_disagreements
        ok = ok and int(totals.get("failed", 1)) == 0 and int(totals.get("passed", 0)) > 0

    witness = {}
    witness_path = transfer_root / "issuance-witness.json"
    if witness_path.exists():
        witness = json.loads(witness_path.read_text(encoding="utf-8"))
    ok = ok and bool(witness) and str(witness.get("review_nonce", "")) == nonce

    transcript = {
        "state": "COMPLETE" if ok else "FAILED",
        "environment_label": label,
        "environment_class": "windows-11-hyperv",
        "review_nonce": nonce,
        "issuance_witness": witness,
        "brokered": True,
        "issuer_key_present_in_session": False,
        "in_environment_package": in_environment,
        "package_disagreements": package_disagreements,
        "totals": totals,
        "frozen_package": frozen,
        "recomputed_package": package["recomputed"],
        "started_at": started,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "matrix_rc": matrix.returncode,
        "raw_result_sha256": sha256_file(result_path) if result_path.exists() else "",
    }
    if not ok:
        transcript["stdout_tail"] = matrix.stdout[-2000:]
        transcript["stderr_tail"] = matrix.stderr[-800:]
    transcript_path.write_text(json.dumps(transcript, indent=2, sort_keys=True),
                               encoding="utf-8")
    print(json.dumps({"stage": "e2", "state": transcript["state"]}, indent=2))
    return 0 if ok else 7


def stage_review(args: argparse.Namespace) -> int:
    """Full independent execution. Requires a bootstrapped key and a green
    preflight; refuses to sign anything it did not itself derive."""

    state = Path(args.state_root)
    key_path = state / "review-key.dpapi"
    if not key_path.exists():
        print(json.dumps({"stage": "review", "error": "no review key; bootstrap first"}))
        return 4
    preflight = Path(args.out_root) / "reviewer-preflight.json"
    if not preflight.exists():
        print(json.dumps({"stage": "review", "error": "preflight has not been run"}))
        return 5
    if json.loads(preflight.read_text(encoding="utf-8"))["summary"]["failed"]:
        print(json.dumps({"stage": "review", "error": "preflight is not green"}))
        return 5

    print(json.dumps({
        "stage": "review",
        "state": "READY",
        "note": "execution stage is driven by the exchange protocol; the reviewer "
                "obtains licences only from the author's drop directory and never "
                "holds the issuer key",
    }, indent=2))
    return 0


STAGES = {"bootstrap": stage_bootstrap, "preflight": stage_preflight,
          "e1": stage_e1, "e2": stage_e2, "review": stage_review}


def main() -> int:
    parser = argparse.ArgumentParser(description="reviewer-side acceptance driver")
    parser.add_argument("--stage", required=True, choices=sorted(STAGES))
    parser.add_argument("--run-id", default="unset")
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--state-root", required=True)
    parser.add_argument("--out-root", required=True)
    parser.add_argument("--xchg-root", required=True)
    parser.add_argument("--author-account", default="ralba")
    args = parser.parse_args()

    refuse_issuer_material(args)
    return STAGES[args.stage](args)


if __name__ == "__main__":
    raise SystemExit(main())
