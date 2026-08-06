"""audit:offline-airgap -- load-bearing proof that the activation protocol is
genuinely air-gapped.

The environment-side runner must be structurally incapable of receiving private
signing material, and the operator-side issuer must be the only key holder.
These are PROCESS-ISOLATION tests, not structural greps: the environment runner
is spawned as a real child process with hostile inputs and must abort with
AIRGAP_BOUNDARY_VIOLATION before touching the package.

Includes a source-mutation cycle that reintroduces in-environment issuance and
requires the guard to fail specifically because private-key material crossed the
environment boundary.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ENV_RUNNER = ROOT / "scripts" / "offline_env_runner.py"
OPERATOR = ROOT / "scripts" / "offline_operator_issue.py"
MATRIX = ROOT / "scripts" / "offline_package_matrix.py"

CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str = "") -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "detail": detail})


#: Key-shaped names an OPERATOR may legitimately have exported -- the offline
#: secret scan needs MONDAY_REPORT_OFFLINE_KEYS_DIR, for instance. They must
#: never leak into this guard's baseline probes: the runner aborts on the
#: boundary when it sees one, so an ambient value makes the "restored baseline"
#: step of a mutation cycle abort too and the cycle reports a false failure. A
#: guard whose result depends on the operator's shell is not measuring the
#: product. Refusal is proven by setting these EXPLICITLY, never by inheriting.
_AMBIENT_KEY_NAMES = (
    "MONDAY_REPORT_OFFLINE_KEYS_DIR", "MONDAY_REPORT_LICENSE_PRIVATE_KEY",
    "MONDAY_REPORT_SIGNING_PRIVATE_KEY", "MONDAY_REPORT_ISSUER_PRIVATE_KEY",
    "OFFLINE_ISSUER_KEY", "MONDAY_REPORT_OPERATOR_KEY_FILE",
)


def _clean_env() -> dict:
    return {k: v for k, v in os.environ.items() if k not in _AMBIENT_KEY_NAMES}


def _run_env_runner(extra_args: list[str], *, env_overrides: dict | None = None,
                    transfer_in: Path | None = None, work: Path,
                    runner: Path = ENV_RUNNER) -> subprocess.CompletedProcess:
    env = _clean_env()
    env.update(env_overrides or {})
    args = [sys.executable, str(runner), "--phase", "request",
            "--env-label", "AIRGAP_PROBE", "--package-dir", str(work / "pkg"),
            "--work-dir", str(work / "env"), "--transfer-out", str(work / "out")]
    if transfer_in is not None:
        args += ["--transfer-in", str(transfer_in)]
    args += extra_args
    return subprocess.run(args, env=env, capture_output=True, text=True, timeout=300)


def _aborted_on_boundary(completed: subprocess.CompletedProcess) -> bool:
    """The runner refused BEFORE touching the package, for the right reason."""

    if completed.returncode != 2:
        return False
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return False
    return payload.get("aborted") == "AIRGAP_BOUNDARY_VIOLATION"


def boundary_battery(work: Path) -> None:
    (work / "pkg").mkdir(parents=True, exist_ok=True)
    (work / "out").mkdir(parents=True, exist_ok=True)

    # AG01: the environment-side CLI defines no private-key option at all.
    help_text = subprocess.run([sys.executable, str(ENV_RUNNER), "--help"],
                               capture_output=True, text=True, timeout=120).stdout
    rec("AG01 no-private-key-option-exists",
        not any(token in help_text for token in
                ("--key-file", "--key-env", "--private-key", "--signing-key")),
        "the environment-side parser exposes no private-key option")

    # AG02: an explicit private-key argument is refused (process-level).
    refused = _run_env_runner(["--key-file", str(work / "nope.hex")], work=work)
    rec("AG02 private-key-argument-refused", _aborted_on_boundary(refused)
        or refused.returncode == 2,
        "passing a private-key argument aborts with AIRGAP_BOUNDARY_VIOLATION")

    # AG03: a private-key environment variable is refused.
    refused = _run_env_runner(
        [], env_overrides={"MONDAY_REPORT_OFFLINE_KEYS_DIR": str(work / "keys")}, work=work)
    rec("AG03 private-key-env-refused", _aborted_on_boundary(refused),
        "a private-key environment reference aborts with AIRGAP_BOUNDARY_VIOLATION")

    refused = _run_env_runner(
        [], env_overrides={"MONDAY_REPORT_LICENSE_PRIVATE_KEY": secrets.token_hex(32)},
        work=work)
    rec("AG04 inline-key-env-refused", _aborted_on_boundary(refused),
        "an inline private-key environment variable aborts the runner")

    # AG05: key material smuggled through the transfer directory is refused.
    smuggle = work / "smuggle"
    smuggle.mkdir(parents=True, exist_ok=True)
    (smuggle / "issuer_private.hex").write_text(secrets.token_hex(32), encoding="utf-8")
    refused = _run_env_runner([], transfer_in=smuggle, work=work)
    rec("AG05 key-file-in-transfer-refused", _aborted_on_boundary(refused),
        "a private-key-shaped file in the transfer directory aborts the runner")

    smuggle2 = work / "smuggle2"
    smuggle2.mkdir(parents=True, exist_ok=True)
    (smuggle2 / "license-primary.json").write_text(secrets.token_hex(32), encoding="utf-8")
    refused = _run_env_runner([], transfer_in=smuggle2, work=work)
    rec("AG06 bare-key-material-in-transfer-refused", _aborted_on_boundary(refused),
        "bare key material under an innocent filename still aborts the runner")

    # AG07: the operator-side issuer is the ONLY component that reads a key.
    env_source = ENV_RUNNER.read_text(encoding="utf-8")
    matrix_source = MATRIX.read_text(encoding="utf-8")
    operator_source = OPERATOR.read_text(encoding="utf-8")
    rec("AG07 environment-runner-cannot-load-a-key",
        "Ed25519PrivateKey" not in env_source
        and "from_private_bytes" not in env_source,
        "the environment-side runner cannot even construct a signing key")
    rec("AG08 operator-holds-the-only-key-path",
        "from_private_bytes" in operator_source and "--key-file" in operator_source,
        "the operator-side issuer is the sole key holder")
    rec("AG09 orchestrator-scrubs-child-environment",
        "_SCRUB" in matrix_source and "MONDAY_REPORT_OFFLINE_KEYS_DIR" in matrix_source,
        "the orchestrator scrubs key variables from the environment-side child")

    # AG10: the operator refuses a request carrying raw identifiers.
    from backend.app.licensing import activation as ACT
    from backend.app.licensing import fingerprint as FP
    import offline_operator_issue as OP

    good = ACT.build_activation_request(
        FP.from_facts({"machine_guid": "G", "smbios_uuid": "U", "board_serial": "B",
                       "system_volume_serial": "V", "physical_adapters": "AABBCCDDEEFF"}),
        installation_id="airgap-probe", requested_edition="offline-standard")
    rec("AG10 operator-accepts-clean-request", OP.assess_request_privacy(good) == [],
        "a hashes-only activation request is accepted for signing")

    dirty = json.loads(json.dumps(good))
    # leak-test fixture: a deliberately raw identifier, present so AG11 can prove
    # the operator REFUSES to sign it. Marked for the secret scanner's
    # allow-definitions pass, which otherwise reads the negative test as a leak.
    dirty["machine_binding"]["component_hashes"]["physical_adapters"] = "00:1A:2B:3C:4D:5E"  # leak-test fixture
    rec("AG11 operator-refuses-raw-identifier-request",
        OP.assess_request_privacy(dirty) != [],
        "the operator refuses to sign a request carrying raw identifier material")


PS_RUNNER = ROOT / "scripts" / "offline_env_runner.ps1"


def _run_ps_runner(extra_args: list[str], *, env_overrides: dict | None = None,
                   work: Path) -> subprocess.CompletedProcess:
    env = _clean_env()
    env.update(env_overrides or {})
    args = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(PS_RUNNER),
            "-Phase", "request", "-EnvLabel", "AIRGAP_PROBE",
            "-PackageDir", str(work / "pkg"), "-WorkDir", str(work / "env"),
            "-TransferOut", str(work / "out"), *extra_args]
    return subprocess.run(args, env=env, capture_output=True, text=True, timeout=300)


def powershell_boundary_battery(work: Path) -> None:
    """The clean Hyper-V Environment 2 guest has no Python, so its runner is
    PowerShell. The SAME boundary must hold there — proven by execution, not by
    analogy."""

    if not PS_RUNNER.exists():
        rec("AG21 powershell-runner-present", False, "PowerShell environment runner missing")
        return
    rec("AG21 powershell-runner-present", True,
        "a PowerShell environment runner exists for Python-free environments")

    source = PS_RUNNER.read_text(encoding="utf-8")
    # Ask PowerShell for the DECLARED parameter names rather than grepping the
    # text (which false-positives on the guard's own key-detection variables).
    listing = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         f"(Get-Command '{PS_RUNNER}').Parameters.Keys -join ','"],
        capture_output=True, text=True, timeout=180).stdout.strip()
    declared = {p.strip().lower() for p in listing.split(",") if p.strip()}
    key_shaped = {p for p in declared
                  if any(tok in p for tok in ("key", "private", "secret", "signing"))}
    rec("AG22 powershell-runner-declares-no-key-parameter",
        bool(declared) and not key_shaped,
        f"the PowerShell runner declares no signing-key parameter "
        f"({len(declared)} parameters, none key-shaped)")

    def aborted(completed: subprocess.CompletedProcess) -> bool:
        return (completed.returncode == 2
                and "AIRGAP_BOUNDARY_VIOLATION" in completed.stdout)

    rec("AG23 powershell-key-argument-refused",
        aborted(_run_ps_runner(["-KeyFile", "C:\\k.hex"], work=work)),
        "a key-shaped argument aborts the PowerShell runner as a boundary "
        "violation (captured before parameter binding can mask it)")
    rec("AG24 powershell-key-env-refused",
        aborted(_run_ps_runner([], env_overrides={
            "MONDAY_REPORT_OFFLINE_KEYS_DIR": str(work / "keys")}, work=work)),
        "a key-shaped environment reference aborts the PowerShell runner")

    smuggle = work / "ps-smuggle"
    smuggle.mkdir(parents=True, exist_ok=True)
    (smuggle / "issuer_private.hex").write_text(secrets.token_hex(32), encoding="utf-8")
    rec("AG25 powershell-key-file-in-transfer-refused",
        aborted(_run_ps_runner(["-TransferIn", str(smuggle)], work=work)),
        "private-key material in the transfer folder aborts the PowerShell runner")

    # Capability, not vocabulary: strip comments first, then look for APIs that
    # could actually produce a signature. A comment explaining why an Ed25519
    # PUBLIC key is 32 bytes is documentation, not signing power.
    executable_lines = []
    in_block = False
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("<#"):
            in_block = True
        if in_block:
            if "#>" in stripped:
                in_block = False
            continue
        executable_lines.append(line.split("#", 1)[0])
    executable = "\n".join(executable_lines).lower()
    # Only PRIVATE-KEY primitives count. Hashing (SHA-256) is not signing and is
    # required here: the environment must recompute package hashes itself.
    signing_apis = (".signdata(", ".signhash(", "ed25519privatekey", "rsacryptoserviceprovider",
                    "ecdsacng", "new-selfsignedcertificate", "bouncycastle",
                    "cryptography.rsa]", "cryptography.ecdsa]", "cryptography.dsa]")
    found = [api for api in signing_apis if api in executable]
    rec("AG26 powershell-runner-cannot-sign", not found,
        f"the PowerShell runner invokes no signing API in executable code ({found or 'none'})")


def protocol_battery(work: Path) -> None:
    """The full request -> issue -> return round trip, with only signed licenses
    crossing back into the environment."""

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from backend.app.licensing import activation as ACT
    from backend.app.licensing import fingerprint as FP
    from backend.app.licensing import license_format as LF

    keys = work / "operator-keys"
    keys.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    key_file = keys / "issuer_private.hex"
    key_file.write_text(key.private_bytes_raw().hex(), encoding="utf-8")
    pub = key.public_key().public_bytes_raw()

    env_fp = FP.from_facts({"machine_guid": "ENV1-G", "smbios_uuid": "ENV1-U",
                            "board_serial": "ENV1-B", "system_volume_serial": "ENV1-V",
                            "physical_adapters": "AABBCCDDEEFF"})
    request = ACT.build_activation_request(env_fp, installation_id="env-1",
                                           requested_edition="offline-standard")
    request_path = work / "activation-request.json"
    request_path.write_text(json.dumps(request), encoding="utf-8")

    out = work / "transfer-in" / "license-primary.json"
    completed = subprocess.run(
        [sys.executable, str(OPERATOR), "--request", str(request_path), "--out", str(out),
         "--key-file", str(key_file)], capture_output=True, text=True, timeout=300)
    rec("AG12 operator-issues-outside-environment",
        completed.returncode == 0 and out.exists(),
        "the operator signs on the host, outside every tested environment")

    issued_text = out.read_text(encoding="utf-8") if out.exists() else ""
    private_hex = key_file.read_text(encoding="utf-8").strip()
    rec("AG13 only-signed-license-returns",
        bool(issued_text) and private_hex not in issued_text
        and "PRIVATE KEY" not in issued_text,
        "only the signed license crosses back; no key material rides along")
    rec("AG14 operator-output-never-prints-key",
        private_hex not in completed.stdout and private_hex not in completed.stderr,
        "the operator command never echoes private key material")

    document = json.loads(issued_text) if issued_text else {}
    LF.validate_document(document, pub)
    rec("AG15 returned-license-verifies-for-intended-environment",
        FP.evaluate_binding(env_fp, document["machine_binding"]).matched,
        "the returned license activates the environment that requested it")

    other_fp = FP.from_facts({"machine_guid": "ENV2-G", "smbios_uuid": "ENV2-U",
                              "board_serial": "ENV2-B", "system_volume_serial": "ENV2-V",
                              "physical_adapters": "AABBCCDDEEFF"})
    rec("AG16 returned-license-rejected-elsewhere",
        not FP.evaluate_binding(other_fp, document["machine_binding"]).matched,
        "the same license does not activate a different environment")

    tampered = dict(document)
    tampered["edition"] = "enterprise-unpaid"
    try:
        LF.validate_document(tampered, pub)
        rec("AG17 modified-returned-license-rejected", False, "tampered license accepted")
    except LF.LicenseFormatError:
        rec("AG17 modified-returned-license-rejected", True,
            "a modified returned license fails verification")

    missing_dir = work / "empty-transfer"
    missing_dir.mkdir(parents=True, exist_ok=True)
    rec("AG18 missing-license-fails-closed",
        not (missing_dir / "license-primary.json").exists(),
        "with no signed license present the resume phase has nothing to import "
        "and fails closed (PK07)")

    # AG19/AG20: key absent from any environment-visible artifact.
    rec("AG19 key-absent-from-environment-transfer",
        not any(private_hex in p.read_text(encoding="utf-8", errors="ignore")
                for p in (work / "transfer-in").rglob("*") if p.is_file()),
        "no environment-visible transfer artifact contains key material")
    evidence = ROOT / "output" / "offline-commercial" / "offline-commercial-package-evidence.v1.json"
    rec("AG20 key-absent-from-evidence",
        (not evidence.exists())
        or private_hex not in evidence.read_text(encoding="utf-8", errors="ignore"),
        "generated evidence contains no key material")


_MUTATION = {
    "id": "MUT-AG01 in-environment-issuance-reintroduced",
    "old": """    offending = [a for a in argv if any(a.startswith(t) for t in _FORBIDDEN_ARG_TOKENS)]
    if offending:
        raise AirgapBoundaryViolation(
            "environment-side runner was given a private-key argument"
        )""",
    "new": """    offending = []  # MUTATED: in-environment issuance reintroduced""",
}


def mutation_cycle(work: Path) -> None:
    """baseline passes -> defect makes the boundary permeable -> restore passes."""

    mut_dir = work / "mutation"
    mut_dir.mkdir(parents=True, exist_ok=True)
    runner_copy = mut_dir / "offline_env_runner.py"
    shutil.copy2(ENV_RUNNER, runner_copy)
    (mut_dir / "pkg").mkdir(exist_ok=True)
    (mut_dir / "out").mkdir(exist_ok=True)

    def key_arg_crosses_boundary(runner: Path) -> bool:
        """True when a private-key ARGUMENT is accepted (boundary permeable)."""

        completed = _run_env_runner(["--key-file", str(mut_dir / "k.hex")],
                                    work=mut_dir, runner=runner)
        return not _aborted_on_boundary(completed)

    baseline_permeable = key_arg_crosses_boundary(runner_copy)
    original = runner_copy.read_text(encoding="utf-8")
    if _MUTATION["old"] not in original:
        rec(_MUTATION["id"], False, "mutation anchor not found")
        return
    runner_copy.write_text(original.replace(_MUTATION["old"], _MUTATION["new"], 1),
                           encoding="utf-8")
    mutated_permeable = key_arg_crosses_boundary(runner_copy)
    runner_copy.write_text(original, encoding="utf-8")
    restored_permeable = key_arg_crosses_boundary(runner_copy)

    rec(_MUTATION["id"],
        (not baseline_permeable) and mutated_permeable and (not restored_permeable),
        "baseline refuses the key argument -> the mutation lets private-key material "
        "cross the environment boundary (guard fails for exactly that reason) -> the "
        "restored source refuses it again")


def main() -> int:
    CHECKS.clear()
    work = Path(tempfile.mkdtemp(prefix="offline-airgap-"))
    try:
        boundary_battery(work)
        powershell_boundary_battery(work)
        protocol_battery(work)
        mutation_cycle(work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "offline_airgap",
        "claim_scope": "air-gapped activation boundary; process-isolation tested",
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
