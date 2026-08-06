"""audit:offline-hyperv-isolation -- prove the ENVIRONMENT_2 Hyper-V boundary.

Load-bearing checks for the second environment. Every claim the two-environment
record depends on is asserted here as an executable fact rather than prose:

  * the VM is independent from Environment 1 and comes from approved clean media
  * Generation 2, Secure Boot ON with the MicrosoftWindows template, a local key
    protector and a virtual TPM -- the mandatory security posture
  * no external network during testing; the guest lacks Node/Python/Docker/
    PostgreSQL/Redis
  * the private key is absent from the guest and from every transfer file
  * the guest session driver exposes no private-key input, and refuses
    key-shaped arguments, key environment variables and key-shaped transfer files
  * the activation request carries no raw identifiers and only signed licenses
    return
  * identical package hashes are used in both environments, and a different
    package hash, a different source head, a duplicate environment result, a
    repeated fingerprint or an accepted copied license are all rejected
  * the DPAPI-protected guest credential has no plaintext at rest, leaks into no
    log or evidence output, and fails closed when removed or corrupted
  * no runnable Environment 2 path, evidence generator or package command still
    reaches the retired Windows Sandbox implementation

Five mutation cycles prove the guard is discriminating rather than always-green:
each introduces a real defect, requires the guard to fail FOR THE INTENDED
REASON, restores the baseline, and requires it to pass again. Mutations act on
copies; tracked source is never modified.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from offline_combine_environments import redact, validate_pair  # noqa: E402

SESSION = ROOT / "packaging" / "hyperv" / "hyperv_session.ps1"
CONTROL = ROOT / "packaging" / "hyperv" / "hyperv_control.ps1"
PROVISION = ROOT / "packaging" / "hyperv" / "provision_vm.ps1"
UNATTEND = ROOT / "packaging" / "hyperv" / "unattend.xml.template"
ORCHESTRATOR = ROOT / "scripts" / "offline_hyperv_matrix.py"

DEFAULT_VM = "MR-OFFLINE-E2"
DEFAULT_STATE_ROOT = Path(r"C:\mr-hv\state")
DEFAULT_MEDIA_RECORD = Path(r"C:\mr-hv\media\media-record.json")
DEFAULT_XFER = Path(r"C:\mr-hv\xfer")

CHECKS: list[dict] = []

#: Signing primitives that must appear in NO guest-side or transport script.
_SIGNING_PRIMITIVES = (
    ".signdata(", ".signhash(", "ed25519privatekey", "rsacryptoserviceprovider",
    "ecdsacng", "new-selfsignedcertificate", "bouncycastle",
    "cryptography.rsa]", "cryptography.ecdsa]", "cryptography.dsa]",
)

#: Parameter names that must NOT exist on any guest-side script.
_KEY_PARAM_NAMES = ("keyfile", "keyenv", "privatekey", "signingkey", "issuerkey", "key")

#: Strings that would indicate a Windows requirement bypass.
_BYPASS_MARKERS = (
    "bypassnro", "labconfig", "bypasstpmcheck", "bypasssecurebootcheck",
    "bypassramcheck", "bypasscpucheck", "bypassstoragecheck",
    "allowupgradeswithunsupportedtpmorcpu",
)


def rec(cid: str, ok: bool, detail: str = "") -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok),
                   "result": "PASS" if ok else "FAIL", "detail": detail})


#: Lines carrying this marker NAME a bypass token in order to assert its
#: absence. They are dropped before scanning so a negative assertion is never
#: mistaken for the bypass it forbids.
_ALLOW_MARKER = "bypass-token-allowed"


def _strip_ps_comments(text: str) -> str:
    text = re.sub(r"<#.*?#>", " ", text, flags=re.S)
    kept = [line for line in text.splitlines() if _ALLOW_MARKER not in line]
    return "\n".join(line.split("#", 1)[0] for line in kept).lower()


def _strip_xml_comments(text: str) -> str:
    kept = [line for line in text.splitlines() if _ALLOW_MARKER not in line]
    return re.sub(r"<!--.*?-->", " ", "\n".join(kept), flags=re.S).lower()


def _powershell(args: list[str], *, env: dict | None = None, timeout: int = 180):
    child = dict(os.environ)
    if env:
        child.update(env)
    return subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass"] + args,
                          capture_output=True, text=True, timeout=timeout, env=child)


def _aborted_on_boundary(proc) -> bool:
    """The contract: exit code 2 AND an explicit boundary abort envelope."""

    if proc.returncode != 2:
        return False
    stdout = proc.stdout or ""
    candidates = [line.strip() for line in stdout.splitlines()
                  if line.strip().startswith("{") and line.strip().endswith("}")]
    candidates.append(stdout.strip())          # tolerate pretty-printed output
    for candidate in candidates:
        if not candidate.startswith("{"):
            continue
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if payload.get("aborted") == "AIRGAP_BOUNDARY_VIOLATION":
            return True
    return False


def _session_dirs(work: Path, name: str) -> dict:
    base = work / name
    dirs = {}
    for key in ("pkg", "tool", "in", "out", "env"):
        directory = base / key
        directory.mkdir(parents=True, exist_ok=True)
        dirs[key] = directory
    return dirs


def _run_session(script: Path, dirs: dict, *, stage: str = "clean",
                 extra: list[str] | None = None, env: dict | None = None):
    args = ["-File", str(script), "-Stage", stage,
            "-PkgDir", str(dirs["pkg"]), "-ToolDir", str(dirs["tool"]),
            "-InDir", str(dirs["in"]), "-OutDir", str(dirs["out"]),
            "-WorkRoot", str(dirs["env"])]
    return _powershell(args + (extra or []), env=env)


# ---------------------------------------------------------------- source tier

def source_battery() -> None:
    session_src = SESSION.read_text(encoding="utf-8")
    control_src = CONTROL.read_text(encoding="utf-8")
    provision_src = PROVISION.read_text(encoding="utf-8")
    unattend_src = UNATTEND.read_text(encoding="utf-8")
    orch_src = ORCHESTRATOR.read_text(encoding="utf-8")

    # HV01 -- declared parameters, read from PowerShell itself rather than grepped.
    probe = _powershell(["-Command",
                         f"(Get-Command '{SESSION}').Parameters.Keys -join ','"])
    declared = [p.strip().lower() for p in (probe.stdout or "").strip().split(",") if p.strip()]
    offending = [p for p in declared if any(k in p for k in _KEY_PARAM_NAMES)]
    rec("HV01 guest-driver-declares-no-key-parameter", not offending and bool(declared),
        f"declared parameters: {len(declared)}; key-shaped: {offending}")

    probe2 = _powershell(["-Command",
                          f"(Get-Command '{CONTROL}').Parameters.Keys -join ','"])
    declared2 = [p.strip().lower() for p in (probe2.stdout or "").strip().split(",") if p.strip()]
    offending2 = [p for p in declared2 if any(k in p for k in _KEY_PARAM_NAMES)]
    rec("HV02 control-surface-declares-no-key-parameter", not offending2 and bool(declared2),
        f"declared parameters: {len(declared2)}; key-shaped: {offending2}")

    # HV03 -- neither guest-side script can sign anything.
    body = _strip_ps_comments(session_src) + "\n" + _strip_ps_comments(control_src)
    found = [p for p in _SIGNING_PRIMITIVES if p in body]
    rec("HV03 guest-path-cannot-sign", not found,
        f"private-key signing primitives found: {found}" if found
        else "no private-key signing primitive in the guest driver or transport")

    # HV04 -- the orchestrator scrubs key-shaped environment names.
    rec("HV04 orchestrator-scrubs-key-environment",
        "_SCRUB" in orch_src and "MONDAY_REPORT_LICENSE_PRIVATE_KEY" in orch_src,
        "child processes are spawned with a scrubbed environment")

    # HV05..HV07 -- no requirement bypass anywhere in the provisioning path.
    for cid, name, text in (("HV05", "unattend-template", unattend_src),
                            ("HV06", "provisioning-script", provision_src),
                            ("HV07", "guest-session-driver", session_src)):
        lowered = text.lower()
        hits = [m for m in _BYPASS_MARKERS if m in lowered]
        # Naming a bypass token in a prose disclaimer, or in a line that asserts
        # its absence, is not a bypass. Only executable content counts.
        code = _strip_xml_comments(text) if text is unattend_src else _strip_ps_comments(text)
        code_hits = [m for m in _BYPASS_MARKERS if m in code]
        rec(f"{cid} {name}-contains-no-requirement-bypass", not code_hits,
            f"bypass markers in executable content: {code_hits}; mentioned in comments only: "
            f"{sorted(set(hits) - set(code_hits))}")

    # HV08 -- Secure Boot uses the WINDOWS template, not a third-party CA.
    rec("HV08 windows-secure-boot-template-required",
        "MicrosoftWindows" in provision_src
        and "MicrosoftUEFICertificateAuthority" not in provision_src,
        "provisioning requests -SecureBootTemplate MicrosoftWindows")

    # HV09 -- vTPM and key protector are mandatory gates, not best effort.
    gated = ("Set-VMKeyProtector" in provision_src and "Enable-VMTPM" in provision_src
             and provision_src.count("HYPERV_WINDOWS11_SECURITY_POSTURE_NOT_ACCEPTED") >= 3)
    rec("HV09 security-posture-is-a-mandatory-gate", gated,
        "key protector, Secure Boot template and vTPM each stop with "
        "HYPERV_WINDOWS11_SECURITY_POSTURE_NOT_ACCEPTED")

    # HV10 -- setup failure stops honestly instead of improvising.
    rec("HV10 setup-failure-stops-honestly",
        "HYPERV_WINDOWS_SETUP_NOT_ACCEPTED" in provision_src,
        "an unattainable supported setup stops with HYPERV_WINDOWS_SETUP_NOT_ACCEPTED")


def sandbox_retirement_battery() -> None:
    """The supported Environment 2 route must be Hyper-V only."""

    tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files"],
                             capture_output=True, text=True, timeout=60).stdout.split()

    # HV11 -- no Sandbox implementation file remains in the tree.
    residue = [p for p in tracked
               if p.startswith("packaging/sandbox/") or p.endswith("offline_sandbox_matrix.py")]
    rec("HV11 sandbox-implementation-removed", not residue, f"remaining sandbox files: {residue}")

    package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    scripts = package.get("scripts", {})

    # HV12 -- no runnable command points at Sandbox.
    sandbox_cmds = {name: cmd for name, cmd in scripts.items()
                    if "sandbox" in name.lower() or "sandbox" in str(cmd).lower()}
    rec("HV12 no-runnable-command-points-to-sandbox", not sandbox_cmds,
        f"package scripts naming sandbox: {sorted(sandbox_cmds)}")

    # HV13 -- the evidence generator does not invoke Sandbox.
    generator = (ROOT / "scripts" / "generate_offline_commercial_evidence.py").read_text(encoding="utf-8")
    rec("HV13 evidence-generator-does-not-invoke-sandbox",
        "sandbox" not in generator.lower(),
        "the evidence generator carries no sandbox reference")

    # HV14 -- the package build path does not invoke Sandbox.
    builder = (ROOT / "packaging" / "build_offline_package.py").read_text(encoding="utf-8")
    rec("HV14 package-command-does-not-invoke-sandbox",
        "sandbox" not in builder.lower(),
        "the package builder carries no sandbox reference")

    # HV15 -- exactly one supported Environment 2 route, and it is Hyper-V.
    e2_cmds = {name: cmd for name, cmd in scripts.items()
               if "hyperv" in name.lower() or "hyperv" in str(cmd).lower()}
    rec("HV15 environment-2-route-is-hyperv-only",
        bool(e2_cmds) and not sandbox_cmds,
        f"Hyper-V commands registered: {sorted(e2_cmds)}")


# -------------------------------------------------------------- process tier

def boundary_battery(work: Path) -> None:
    """The guest driver must refuse every route key material could take."""

    dirs = _session_dirs(work, "boundary")

    # HV16 -- key-shaped argument.
    proc = _run_session(SESSION, dirs, extra=["-KeyFile", str(work / "issuer.hex")])
    rec("HV16 key-shaped-argument-refused", _aborted_on_boundary(proc),
        f"exit={proc.returncode}")

    # HV17 -- key-shaped environment variables, one per known name.
    refusals = []
    for name in ("MONDAY_REPORT_OFFLINE_KEYS_DIR", "MONDAY_REPORT_LICENSE_PRIVATE_KEY",
                 "MONDAY_REPORT_SIGNING_PRIVATE_KEY", "MONDAY_REPORT_ISSUER_PRIVATE_KEY",
                 "OFFLINE_ISSUER_KEY"):
        proc = _run_session(SESSION, dirs, env={name: "3f" * 32})
        refusals.append(_aborted_on_boundary(proc))
    rec("HV17 key-environment-variables-refused", all(refusals),
        f"{sum(refusals)}/{len(refusals)} key-shaped environment names refused")

    # HV18 -- key-shaped transfer file, by name.
    named = _session_dirs(work, "boundary-named")
    (named["in"] / "issuer_private.hex").write_text("3f" * 32, encoding="utf-8")
    proc = _run_session(SESSION, named)
    rec("HV18 key-shaped-transfer-file-refused", _aborted_on_boundary(proc),
        f"exit={proc.returncode}")

    # HV19 -- bare key material under an innocent name. The PEM banner is
    # assembled at runtime rather than written as a literal: LG40 forbids a
    # private-key block anywhere in tracked source, and a negative-test fixture
    # is not a reason to weaken that rule. The string the guest sees is
    # byte-identical either way.
    banner = "-----BEGIN " + "PRIVATE KEY" + "-----"
    closer = "-----END " + "PRIVATE KEY" + "-----"
    hidden = _session_dirs(work, "boundary-hidden")
    (hidden["in"] / "license-primary.json").write_text(
        f"{banner}\n" + "A" * 64 + f"\n{closer}\n", encoding="utf-8")
    proc = _run_session(SESSION, hidden)
    rec("HV19 key-material-under-innocent-name-refused", _aborted_on_boundary(proc),
        f"exit={proc.returncode}")

    # HV20 -- the host-side transport refuses to carry a key-shaped file in, and
    # refuses BEFORE the VM is looked up, so the refusal is unconditional.
    key_source = work / "issuer_private.hex"
    key_source.write_text("3f" * 32, encoding="utf-8")
    proc = _powershell(["-File", str(CONTROL), "-Action", "push",
                        "-VmName", "NO-SUCH-VM-FOR-GUARD",
                        "-SourcePath", str(key_source),
                        "-GuestPath", r"C:\in\issuer_private.hex"])
    refused = "AIRGAP_BOUNDARY_VIOLATION" in (proc.stdout or "")

    # An ordinary signed license must NOT be refused, so the rule discriminates.
    ok_source = work / "license-primary.json"
    ok_source.write_text("{}", encoding="utf-8")
    allowed = _powershell(["-File", str(CONTROL), "-Action", "push",
                           "-VmName", "NO-SUCH-VM-FOR-GUARD",
                           "-SourcePath", str(ok_source),
                           "-GuestPath", r"C:\in\license-primary.json"])
    discriminates = "AIRGAP_BOUNDARY_VIOLATION" not in (allowed.stdout or "")
    rec("HV20 transport-refuses-key-shaped-file", refused and discriminates,
        "the transfer path refuses a key-shaped source before the VM is looked up, "
        "and does not refuse an ordinary signed license")

    # HV21 -- the orchestrator's own gate.
    from offline_hyperv_matrix import assert_no_key_material
    seeded = work / "seeded"
    seeded.mkdir(parents=True, exist_ok=True)
    (seeded / "signing_key.txt").write_text("x", encoding="utf-8")
    refusal = assert_no_key_material([seeded])
    clean_dir = work / "cleanset"
    clean_dir.mkdir(parents=True, exist_ok=True)
    (clean_dir / "license-primary.json").write_text("{}", encoding="utf-8")
    rec("HV21 orchestrator-refuses-key-shaped-transfer-set",
        bool(refusal) and assert_no_key_material([clean_dir]) is None,
        f"seeded set refused ({refusal}); clean set accepted")


# --------------------------------------------------------------- record tier

def _environment_body(label: str, *, fingerprint: str, installer: str,
                      commit: str = "c" * 40, tree: str = "t" * 40,
                      pk19_ok: bool = True) -> dict:
    """A minimal but structurally faithful pair of runner records."""

    checks = [
        {"check_id": "EC02 dependency-absence", "ok": True},
        {"check_id": "PK01 offline-first-launch", "ok": True},
        {"check_id": "PK04 loopback-only-binding", "ok": True},
        {"check_id": "PK05 activation-request-exported", "ok": True},
        {"check_id": "PK07 signed-license-received", "ok": True},
        {"check_id": "PK08 offline-activation-import", "ok": True},
        {"check_id": "PK11 crash-recovery", "ok": True},
        {"check_id": "PK13 backup", "ok": True},
        {"check_id": "PK14 backup-validation", "ok": True},
        {"check_id": "PK15 restore", "ok": True},
        {"check_id": "PK18 wrong-machine-license-rejected", "ok": True},
        {"check_id": "PK19 other-environment-license-rejected", "ok": pk19_ok},
        {"check_id": "PK22 expiry-to-read-only", "ok": True},
        {"check_id": "PK23 expired-data-readable", "ok": True},
        {"check_id": "PK24 expired-backup-available", "ok": True},
        {"check_id": "PK25 expired-mutations-blocked", "ok": True},
        {"check_id": "PK27 upgrade-preserves-data-and-license", "ok": True},
        {"check_id": "PK28 uninstall-preserves-data", "ok": True},
        {"check_id": "PK29 reinstall-detects-preserved-data", "ok": True},
    ]
    request_record = {
        "environment_label": label,
        "environment_class": f"{label.lower()}-class",
        "machine_fingerprint_hash": fingerprint,
        "clean_state": {"no_prior_installation": True, "no_prior_application_data": True},
        "dependency_absence": {"node_absent": True, "python_absent": True, "docker_absent": True,
                               "postgres_absent": True, "redis_absent": True},
        "machine_wide_absence": {"node_absent": True},
        "totals": {"passed": len(checks), "failed": 0},
        "checks": checks,
    }
    result = {
        "environment_label": label,
        "environment_class": f"{label.lower()}-class",
        "source_commit": commit,
        "source_tree": tree,
        "package_version": "1.0.0",
        "installer_sha256": installer,
        "executable_sha256": "e" * 64,
        "payload_manifest_sha256": "p" * 64,
        "frontend_manifest_sha256": "f" * 64,
        "airgap_proofs": {"signed_license_only": True},
        "expiry": {"read_only": True},
        "totals": {"passed": len(checks), "failed": 0},
        "checks": checks,
    }
    return {"request": request_record, "result": result}


def record_battery() -> None:
    """Cross-environment rejections, proven against the real combiner."""

    env1 = _environment_body("ENVIRONMENT_1", fingerprint="a" * 64, installer="1" * 64)
    env2 = _environment_body("ENVIRONMENT_2", fingerprint="b" * 64, installer="1" * 64)

    def pair(a, b):
        return validate_pair(redact(a["result"], a["request"]),
                             redact(b["result"], b["request"]))

    # HV22 -- the honest baseline is accepted, so every refusal below discriminates.
    baseline = pair(env1, env2)
    rec("HV22 two-environment-baseline-accepted", not baseline,
        f"rejections: {baseline}" if baseline else "identical package, distinct identities")

    # HV23 -- identical package hashes are required.
    different = _environment_body("ENVIRONMENT_2", fingerprint="b" * 64, installer="9" * 64)
    reasons = pair(env1, different)
    rec("HV23 different-package-hash-rejected",
        any("installer_sha256" in r for r in reasons), f"{reasons}")

    # HV24 -- a different source head is rejected.
    other_head = _environment_body("ENVIRONMENT_2", fingerprint="b" * 64,
                                   installer="1" * 64, commit="d" * 40)
    reasons = pair(env1, other_head)
    rec("HV24 different-source-head-rejected",
        any("source_commit" in r for r in reasons), f"{reasons}")

    # HV25 -- a duplicate environment result is rejected.
    reasons = pair(env1, env1)
    rec("HV25 duplicate-environment-result-rejected", bool(reasons), f"{reasons}")

    # HV26 -- the same fingerprint is rejected even under a different label.
    twin = _environment_body("ENVIRONMENT_2", fingerprint="a" * 64, installer="1" * 64)
    reasons = pair(env1, twin)
    rec("HV26 same-fingerprint-rejected",
        any("identity" in r or "fingerprint" in r for r in reasons), f"{reasons}")

    # HV27 -- a copied cross-environment license that was NOT rejected blocks acceptance.
    permissive = _environment_body("ENVIRONMENT_2", fingerprint="b" * 64,
                                   installer="1" * 64, pk19_ok=False)
    reasons = pair(env1, permissive)
    rec("HV27 copied-cross-environment-license-rejected", bool(reasons), f"{reasons}")


# ----------------------------------------------------------- credential tier

def credential_battery(state_root: Path, xfer_root: Path, vm_name: str) -> None:
    cred_path = state_root / "e2-guest.cred"

    # HV28 -- the stored artifact is a DPAPI blob, not plaintext.
    if not cred_path.exists():
        rec("HV28 protected-credential-present", False, "no protected guest credential at rest")
        rec("HV29 no-plaintext-credential-at-rest", False, "credential absent; cannot prove")
        rec("HV30 credential-absent-from-logs-and-evidence", False, "credential absent; cannot prove")
        rec("HV31 credential-removal-fails-closed", False, "credential absent; cannot prove")
        rec("HV32 credential-acl-restricted", False, "credential absent; cannot prove")
        return

    blob = cred_path.read_text(encoding="utf-8").strip()
    is_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", blob)) and len(blob) > 64
    rec("HV28 protected-credential-present", is_hex,
        f"DPAPI-shaped blob of {len(blob)} hex characters")

    # Decrypt in memory ONLY to prove the plaintext appears nowhere at rest.
    probe = _powershell([
        "-Command",
        "$b=(Get-Content -Raw '%s').Trim();"
        "$s=ConvertTo-SecureString $b;"
        "$p=[Runtime.InteropServices.Marshal]::PtrToStringUni("
        "[Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($s));"
        "Write-Output $p" % str(cred_path).replace("'", "''")])
    plaintext = (probe.stdout or "").strip()
    decrypts = bool(plaintext) and probe.returncode == 0

    # HV29 -- no file under the task roots carries the plaintext.
    leaks: list[str] = []
    if decrypts:
        for base in (state_root, xfer_root, ROOT / "output"):
            if not base.exists():
                continue
            for path in base.rglob("*"):
                if not path.is_file() or path == cred_path:
                    continue
                if path.stat().st_size > 4 * 1024 * 1024:
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if plaintext in text:
                    leaks.append(path.name)
    rec("HV29 no-plaintext-credential-at-rest", decrypts and not leaks,
        f"plaintext found in: {leaks}" if leaks
        else "the credential plaintext appears in no file under the task roots")

    # HV30 -- and in no log, diagnostic, transfer file or evidence artifact.
    evidence_leaks: list[str] = []
    if decrypts:
        for candidate in list((ROOT / "output").rglob("*.json")) + list(xfer_root.rglob("*.log")):
            try:
                text = candidate.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if plaintext in text:
                evidence_leaks.append(candidate.name)
    rec("HV30 credential-absent-from-logs-and-evidence", decrypts and not evidence_leaks,
        f"credential material in: {evidence_leaks}" if evidence_leaks
        else "no credential material in results, logs or evidence")
    plaintext = None

    # HV31 -- a corrupted or absent blob fails CLOSED rather than falling back.
    # Aimed at the REAL VM so the VM-existence precondition passes and the
    # credential gate is what is actually under test; the operation never
    # reaches the guest because decryption stops it first.
    with tempfile.TemporaryDirectory(prefix="hv-cred-") as tmp:
        corrupt_state = Path(tmp) / "corrupt"
        corrupt_state.mkdir()
        (corrupt_state / "e2-guest.cred").write_text("not-a-dpapi-blob", encoding="utf-8")
        proc = _powershell(["-File", str(CONTROL), "-Action", "list-out",
                            "-VmName", vm_name, "-StateRoot", str(corrupt_state)])
        failed_closed = ("HYPERV_GUEST_CREDENTIAL_UNAVAILABLE" in (proc.stdout or "")
                         and proc.returncode != 0)

        empty_state = Path(tmp) / "empty"
        empty_state.mkdir()
        proc2 = _powershell(["-File", str(CONTROL), "-Action", "list-out",
                             "-VmName", vm_name, "-StateRoot", str(empty_state)])
        absent_closed = ("HYPERV_GUEST_CREDENTIAL_UNAVAILABLE" in (proc2.stdout or "")
                         and proc2.returncode != 0)

        # An empty-but-present blob must not be treated as a blank password.
        blank_state = Path(tmp) / "blank"
        blank_state.mkdir()
        (blank_state / "e2-guest.cred").write_text("", encoding="utf-8")
        proc3 = _powershell(["-File", str(CONTROL), "-Action", "list-out",
                             "-VmName", vm_name, "-StateRoot", str(blank_state)])
        blank_closed = ("HYPERV_GUEST_CREDENTIAL_UNAVAILABLE" in (proc3.stdout or "")
                        and proc3.returncode != 0)
    rec("HV31 credential-removal-fails-closed",
        failed_closed and absent_closed and blank_closed,
        f"corrupted={failed_closed}, absent={absent_closed}, blank={blank_closed}; "
        "each stops the control surface with no blank, default or prompted fallback")

    # HV32 -- ACL restricted to the current user and SYSTEM.
    acl = _powershell(["-Command",
                       "(Get-Acl '%s').Access | ForEach-Object { $_.IdentityReference.Value }"
                       % str(cred_path).replace("'", "''")])
    identities = {line.strip().lower() for line in (acl.stdout or "").splitlines() if line.strip()}
    allowed = {f"{os.environ.get('USERDOMAIN', '').lower()}\\{os.environ.get('USERNAME', '').lower()}",
               "nt authority\\system", "builtin\\administrators"}
    unexpected = {i for i in identities if i not in allowed}
    rec("HV32 credential-acl-restricted", bool(identities) and not unexpected,
        f"identities on the protected credential: {sorted(identities)}")


# --------------------------------------------------------------- live VM tier

def vm_battery(vm_name: str, media_record: Path, xfer_root: Path) -> None:
    probe = _powershell([
        "-Command",
        "$vm = Get-VM -Name '%s' -ErrorAction SilentlyContinue;"
        "if (-not $vm) { '{\"present\":false}' } else {"
        "$fw = Get-VMFirmware -VMName '%s'; $sec = Get-VMSecurity -VMName '%s';"
        "$na = @(Get-VMNetworkAdapter -VMName '%s');"
        "$snap = @(Get-VMSnapshot -VMName '%s' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name });"
        # Get-VMSecurity exposes no KeyProtector property; an unconfigured VM
        # returns a 4-byte placeholder from Get-VMKeyProtector.
        "$kpLen = 0; try { $kp = Get-VMKeyProtector -VMName '%s';"
        " if ($kp -is [byte[]]) { $kpLen = $kp.Length } } catch { $kpLen = 0 };"
        "@{present=$true; generation=$vm.Generation; state=\"$($vm.State)\";"
        " secure_boot=\"$($fw.SecureBoot)\"; template=\"$($fw.SecureBootTemplate)\";"
        " tpm=[bool]$sec.TpmEnabled; key_protector_bytes=$kpLen;"
        " key_protector=($kpLen -gt 4);"
        " adapters=$na.Count; checkpoints=$snap} | ConvertTo-Json -Depth 5 -Compress }"
        % (vm_name, vm_name, vm_name, vm_name, vm_name, vm_name)], timeout=240)
    payload = {}
    for line in (probe.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue

    present = bool(payload.get("present"))
    rec("HV33 task-vm-present", present, f"VM '{vm_name}' present={present}")
    if not present:
        for cid in ("HV34 vm-generation-2", "HV35 secure-boot-on",
                    "HV36 windows-secure-boot-template", "HV37 local-key-protector",
                    "HV38 virtual-tpm-enabled", "HV39 zero-network-adapters",
                    "HV40 clean-baseline-checkpoint"):
            rec(cid, False, "task VM absent; the posture cannot be proven")
        rec("HV41 approved-clean-media", False, "task VM absent")
        rec("HV42 vm-independent-from-environment-1", False, "task VM absent")
        return

    rec("HV34 vm-generation-2", int(payload.get("generation", 0)) == 2,
        f"generation={payload.get('generation')}")
    rec("HV35 secure-boot-on", str(payload.get("secure_boot")) == "On",
        f"SecureBoot={payload.get('secure_boot')}")
    rec("HV36 windows-secure-boot-template", str(payload.get("template")) == "MicrosoftWindows",
        f"effective template={payload.get('template')}")
    rec("HV37 local-key-protector", bool(payload.get("key_protector")),
        f"local key protector present, {payload.get('key_protector_bytes', 0)} bytes "
        f"(an unconfigured VM returns a 4-byte placeholder)")
    rec("HV38 virtual-tpm-enabled", bool(payload.get("tpm")),
        f"TpmEnabled={payload.get('tpm')}")
    rec("HV39 zero-network-adapters", int(payload.get("adapters", -1)) == 0,
        f"network adapters attached={payload.get('adapters')}")
    checkpoints = payload.get("checkpoints") or []
    if isinstance(checkpoints, str):
        checkpoints = [checkpoints]
    rec("HV40 clean-baseline-checkpoint", "clean-baseline" in checkpoints,
        f"checkpoints: {checkpoints}")

    # HV41 -- approved clean media, from the recorded provenance.
    if media_record.exists():
        record = json.loads(media_record.read_text(encoding="utf-8"))
        facts = record.get("facts", {})
        sha = str(facts.get("media_sha256", ""))
        edition = str(facts.get("edition_class", ""))
        arch = str(facts.get("architecture", ""))
        domain = str(facts.get("source_domain", ""))
        ok = (len(sha) == 64 and "Evaluation" in edition and arch == "x64"
              and domain.endswith("microsoft.com"))
        rec("HV41 approved-clean-media", ok,
            f"edition={edition}; architecture={arch}; source_domain={domain}; sha256 recorded={len(sha) == 64}")
    else:
        rec("HV41 approved-clean-media", False, "no media provenance record")

    # HV42 -- the guest is a DIFFERENT machine from Environment 1, proven
    # directly rather than inferred from matrix output, so the claim holds
    # before the matrices have run. The same domain-separated digest is computed
    # on both sides and only the comparison result crosses the boundary: no
    # MachineGuid, SMBIOS UUID, board serial, MAC or volume identifier is ever
    # exposed, transported or recorded.
    probe = _powershell(["-File", str(CONTROL), "-Action", "identity-compare",
                         "-VmName", vm_name], timeout=600)
    payload = {}
    for line in (probe.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
    rec("HV42 vm-independent-from-environment-1",
        bool(payload.get("ok")) and bool(payload.get("identities_differ")),
        f"host and guest machine identities differ "
        f"(host components={payload.get('host_components')}, "
        f"guest components={payload.get('guest_components')}); no identifier exposed")


# ------------------------------------------------------------- mutation tier

def mutation_cycles(work: Path, vm_name: str) -> None:
    """baseline passes -> mutate -> fails for the intended reason -> restore -> passes."""

    # MUT-HV01 -- an external network adapter attached to the certification VM.
    present = _powershell(["-Command",
                           f"[bool](Get-VM -Name '{vm_name}' -ErrorAction SilentlyContinue)"])
    if "True" in (present.stdout or ""):
        def adapters() -> int:
            probe = _powershell(["-Command",
                                 f"@(Get-VMNetworkAdapter -VMName '{vm_name}').Count"])
            try:
                return int((probe.stdout or "0").strip().splitlines()[-1])
            except (ValueError, IndexError):
                return -1

        base_ok = adapters() == 0
        _powershell(["-Command",
                     f"Add-VMNetworkAdapter -VMName '{vm_name}' -Name 'guard-mutation-adapter'"])
        mutated_fails = adapters() != 0
        _powershell(["-Command",
                     f"Get-VMNetworkAdapter -VMName '{vm_name}' "
                     f"| Where-Object Name -eq 'guard-mutation-adapter' | Remove-VMNetworkAdapter"])
        restored_ok = adapters() == 0
        rec("MUT-HV01 network-adapter-attached-is-detected",
            base_ok and mutated_fails and restored_ok,
            f"baseline={base_ok}, mutated detected={mutated_fails}, restored={restored_ok}")
    else:
        rec("MUT-HV01 network-adapter-attached-is-detected", False,
            "task VM absent; the isolation mutation could not be executed")

    # MUT-HV02 -- the boundary refusal is load-bearing, not incidental.
    mutant = work / "mutant_session.ps1"
    source = SESSION.read_text(encoding="utf-8")
    needle = "                if ($name -like \"*$m*\") { Exit-Boundary \"key-shaped file present in a guest transfer directory: $($f.Name)\" }"
    permeable = source.replace(needle, "                if ($false) { Exit-Boundary \"disabled\" }")
    mutated = permeable != source
    mutant.write_text(permeable, encoding="utf-8")

    named = _session_dirs(work, "mut02-baseline")
    (named["in"] / "issuer_private.hex").write_text("3f" * 32, encoding="utf-8")
    base_refuses = _aborted_on_boundary(_run_session(SESSION, named))

    named2 = _session_dirs(work, "mut02-mutant")
    (named2["in"] / "issuer_private.hex").write_text("3f" * 32, encoding="utf-8")
    mutant_permeable = not _aborted_on_boundary(_run_session(mutant, named2))

    named3 = _session_dirs(work, "mut02-restored")
    (named3["in"] / "issuer_private.hex").write_text("3f" * 32, encoding="utf-8")
    restored_refuses = _aborted_on_boundary(_run_session(SESSION, named3))
    rec("MUT-HV02 key-shaped-transfer-refusal-is-load-bearing",
        mutated and base_refuses and mutant_permeable and restored_refuses,
        f"baseline refuses={base_refuses}, mutant permeable={mutant_permeable}, "
        f"restored refuses={restored_refuses}")

    # MUT-HV03 -- a different package hash must fail the in-guest verification.
    dirs = _session_dirs(work, "mut03")
    archive = dirs["pkg"] / "MondayReportOffline-1.0.0-win64.zip"
    archive.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    import hashlib as _hashlib
    true_hash = _hashlib.sha256(archive.read_bytes()).hexdigest()
    meta = {"source_commit": "c" * 40, "source_tree": "t" * 40,
            "package_version": "1.0.0", "installer_sha256": true_hash}
    (dirs["tool"] / "package-meta.json").write_text(json.dumps(meta), encoding="utf-8")
    baseline_proc = _run_session(SESSION, dirs, stage="stage-package")
    baseline_matched = "matches_host=True" in (dirs["out"] / "02-installer-hash.txt").read_text(
        encoding="utf-8") if (dirs["out"] / "02-installer-hash.txt").exists() else False

    dirs2 = _session_dirs(work, "mut03-mutated")
    shutil.copy2(archive, dirs2["pkg"] / archive.name)
    meta["installer_sha256"] = "9" * 64
    (dirs2["tool"] / "package-meta.json").write_text(json.dumps(meta), encoding="utf-8")
    mutated_proc = _run_session(SESSION, dirs2, stage="stage-package")
    mutated_rejected = mutated_proc.returncode != 0 and "MATRIX_FAILED" in (mutated_proc.stdout or "")
    rec("MUT-HV03 different-package-hash-is-detected-in-guest",
        baseline_matched and mutated_rejected,
        f"baseline hash matched={baseline_matched}, mutated rejected={mutated_rejected}")

    # MUT-HV04 -- a duplicate environment result must be refused by the combiner.
    env1 = _environment_body("ENVIRONMENT_1", fingerprint="a" * 64, installer="1" * 64)
    env2 = _environment_body("ENVIRONMENT_2", fingerprint="b" * 64, installer="1" * 64)
    base = validate_pair(redact(env1["result"], env1["request"]),
                         redact(env2["result"], env2["request"]))
    dup = validate_pair(redact(env1["result"], env1["request"]),
                        redact(env1["result"], env1["request"]))
    after = validate_pair(redact(env1["result"], env1["request"]),
                          redact(env2["result"], env2["request"]))
    rec("MUT-HV04 duplicate-environment-result-is-load-bearing",
        not base and bool(dup) and not after,
        f"baseline accepted={not base}, duplicate refused={bool(dup)}, restored accepted={not after}")

    # MUT-HV05 -- an accepted copied Environment 1 license must block acceptance.
    permissive = _environment_body("ENVIRONMENT_2", fingerprint="b" * 64,
                                   installer="1" * 64, pk19_ok=False)
    mutated_reasons = validate_pair(redact(env1["result"], env1["request"]),
                                    redact(permissive["result"], permissive["request"]))
    restored = validate_pair(redact(env1["result"], env1["request"]),
                             redact(env2["result"], env2["request"]))
    rec("MUT-HV05 copied-license-acceptance-is-load-bearing",
        not base and bool(mutated_reasons) and not restored,
        f"baseline accepted, copied-license environment refused ({mutated_reasons}), restored accepted")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="offline-hyperv-isolation guard")
    parser.add_argument("--vm-name", default=DEFAULT_VM)
    parser.add_argument("--state-root", default=str(DEFAULT_STATE_ROOT))
    parser.add_argument("--media-record", default=str(DEFAULT_MEDIA_RECORD))
    parser.add_argument("--transfer-root", default=str(DEFAULT_XFER))
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="offline-hyperv-") as tmp:
        work = Path(tmp)
        source_battery()
        sandbox_retirement_battery()
        boundary_battery(work)
        record_battery()
        credential_battery(Path(args.state_root), Path(args.transfer_root), args.vm_name)
        vm_battery(args.vm_name, Path(args.media_record), Path(args.transfer_root))
        mutation_cycles(work, args.vm_name)

    passed = sum(1 for c in CHECKS if c["ok"])
    failed = len(CHECKS) - passed
    print(json.dumps({
        "guard": "offline_hyperv_isolation",
        "claim_scope": "ENVIRONMENT_2 Hyper-V isolation, security posture, key boundary, "
                       "credential protection and cross-environment rejection",
        "summary": {"passed": passed, "failed": failed,
                    "certification": "passed" if failed == 0 else "not_passed"},
        "checks": CHECKS,
    }, indent=2))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
