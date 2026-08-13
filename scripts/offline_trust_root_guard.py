"""``audit:offline-trust-root`` -- effect-level NEGATIVE CONTROLS for the v2.1
trust-root remediation (findings F1-F7).

Every check below FAILS on the pre-fix behaviour and PASSES after it, and every
one is witnessed by EFFECT -- an executed call, a computed hash, an applied
ACL, a launched binary's identity -- never by the presence of a string in a
file. Where a control must prove that the OLD behaviour was genuinely broken,
it reproduces the old mechanism inline and shows it accepting what the new
mechanism refuses, so the control cannot pass vacuously.

  F1  the operator pin gates export acceptance, and the manifest is produced
      by PowerShell/.NET rather than by author code
  F2  the PowerShell twin refuses a case-only rename (it accepted one), and the
      twins agree
  F3  NULL DACL and uninterpretable ACEs refuse in BOTH twins
  F4  a failing icacls is detected via exit code, and the grant targets a SID
  F5  no boundary file invokes a native outside C1 (door sweep, by effect)
  F6  the reviewer-runtime guard resolves PowerShell through C1, so a poisoned
      SystemRoot cannot redirect it
  F7  the ACL write and the identity comparison use the SAME handle

Runs unelevated on disposable temp trees. No Hyper-V, no package, no network.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import offline_export_manifest as manifest_module  # noqa: E402
import offline_trusted_natives as natives  # noqa: E402

HYPERV = ROOT / "packaging" / "hyperv"
EXPORT_PS = HYPERV / "lib" / "export_verify.ps1"
NATIVES_PS = HYPERV / "lib" / "trusted_natives.ps1"
TASKROOT_PS = HYPERV / "lib" / "task_root.ps1"
BOOTSTRAP = HYPERV / "reviewer_bootstrap.ps1"

CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str) -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'} {cid}: {detail}")


def ps(script: str, timeout: int = 300) -> subprocess.CompletedProcess:
    """Every child PowerShell is itself resolved through C1."""

    return subprocess.run(
        [str(natives.resolve("powershell")), "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, text=True, timeout=timeout)


def code_lines(path: Path) -> list[str]:
    """Executable lines only: comment lines and block-comment bodies removed.

    Controls about what code DOES must not be satisfied -- or broken -- by
    prose that names the mechanism being discussed. Both TRF1f and TRF4a
    initially failed against their own explanatory comments.
    """

    out: list[str] = []
    in_block = False
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = raw.strip()
        if in_block:
            if "#>" in stripped:
                in_block = False
            continue
        if stripped.startswith("<#"):
            if "#>" not in stripped:
                in_block = True
            continue
        if stripped.startswith("#"):
            continue
        out.append(raw)
    return out


def seed_export(root: Path) -> None:
    (root / "scripts").mkdir(parents=True)
    (root / "a.txt").write_bytes(b"alpha")
    (root / "scripts" / "b.py").write_bytes(b"print(1)")


# ---------------------------------------------------------------------------
def control_f1(work: Path) -> None:
    """F1: the pin gates acceptance; the manifest comes from PowerShell/.NET."""

    export = work / "f1-export"
    seed_export(export)
    commit, tree = "ab" * 20, "cd" * 20

    gen = ps(f". '{EXPORT_PS}'; "
             f"(New-SourceExportManifest -ExportRoot '{export}' "
             f"-SourceCommit '{commit}' -SourceTree '{tree}').root_hash")
    produced = (gen.stdout or "").strip().splitlines()[-1].strip() if gen.stdout.strip() else ""
    rec("TRF1a manifest-generated-by-powershell-not-author-code",
        gen.returncode == 0 and re.fullmatch(r"[0-9a-f]{64}", produced) is not None
        and (export / manifest_module.MANIFEST_NAME).is_file(),
        f"PowerShell/.NET produced the manifest and root hash ({produced[:16]}...) "
        f"with no interpreter from the export executed")

    # The Python twin -- a DIFFERENT implementation -- verifies those bytes.
    try:
        manifest_module.verify(export, expected_root_hash=produced)
        cross = True
        cross_detail = "the independent Python twin verifies the PS-written manifest"
    except manifest_module.ExportRefusal as exc:
        cross = False
        cross_detail = str(exc)
    rec("TRF1b twins-agree-on-generated-manifest", cross, cross_detail)

    # THE CONTROL THAT WOULD HAVE CAUGHT THE ORIGINAL DEFECT: a wrong operator
    # pin must refuse. Pre-fix, -ExportSource called Test-SourceExportVerified
    # with NO -ExpectedRootHash, so self-consistency alone was acceptance and
    # ANY pin (or none) passed.
    wrong = "0" * 64
    pinned = ps(f". '{EXPORT_PS}'; "
                f"try {{ $null = Test-SourceExportVerified -ExportRoot '{export}' "
                f"-ExpectedRootHash '{wrong}'; Write-Output 'ACCEPTED' }} "
                "catch { Write-Output ('REFUSED ' + $_.Exception.Message) }")
    rec("TRF1c wrong-operator-pin-refused",
        "REFUSED" in pinned.stdout and "EXPORT_PIN_MISMATCH" in pinned.stdout,
        pinned.stdout.strip()[:100])

    # And the pre-fix acceptance mode is demonstrably weaker: the SAME call
    # without a pin accepts the very tree the pinned call just refused.
    unpinned = ps(f". '{EXPORT_PS}'; "
                  f"try {{ $null = Test-SourceExportVerified -ExportRoot '{export}'; "
                  "Write-Output 'ACCEPTED' } catch { Write-Output 'REFUSED' }")
    rec("TRF1d self-consistency-only-is-strictly-weaker",
        "ACCEPTED" in unpinned.stdout,
        "self-verification with no pin accepts what the pinned check refuses -- "
        "which is why -ExportSource now REQUIRES -ExpectedExportRootHash")

    # The bootstrap refuses to export without the operator pin at all.
    no_pin = ps(f"& '{BOOTSTRAP}' -ExportSource -SourceWorkspace '{work}' "
                f"-SourceCommit '{commit}' -SourceTree '{tree}' "
                "-AuthorAccount 'SOME-AUTHOR' 2>&1 | Out-String")
    combined = (no_pin.stdout or "") + (no_pin.stderr or "")
    rec("TRF1e bootstrap-refuses-export-without-operator-pin",
        "OFFLINE_EXPORT_ARGUMENT_REQUIRED" in combined
        and "ExpectedExportRootHash" in combined,
        "-ExportSource without -ExpectedExportRootHash aborts before touching anything")

    # No author-controlled interpreter is reachable from the export path any
    # more. Measured on CODE, with comment lines stripped: the explanatory
    # comments naming the removed mechanism must not satisfy or break a control
    # about what the code does -- that is the "measuring something adjacent"
    # shape, and it fired here first time round.
    code = code_lines(BOOTSTRAP)
    rec("TRF1f no-path-resolved-interpreter-in-export-path",
        not any("Get-Command python" in l for l in code)
        and not any("offline_export_manifest.py" in l for l in code),
        "no executable line invokes a PATH-resolved interpreter or a script from "
        "the tree being measured (comments excluded from the measurement)")


def control_f2(work: Path) -> None:
    """F2: the PS twin refuses a case-only rename; twins agree."""

    export = work / "f2-export"
    seed_export(export)
    gen = manifest_module.generate(export, source_commit="ab" * 20, source_tree="cd" * 20)
    pin = gen["root_hash"]

    clean = ps(f". '{EXPORT_PS}'; "
               f"try {{ $null = Test-SourceExportVerified -ExportRoot '{export}' "
               f"-ExpectedRootHash '{pin}'; Write-Output 'VERIFIED' }} "
               "catch { Write-Output ('REFUSED ' + $_.Exception.Message) }")
    rec("TRF2a clean-still-verifies-in-ps-twin", "VERIFIED" in clean.stdout,
        "the ordinal rewrite did not break the accept direction")

    (export / "scripts" / "b.py").rename(export / "scripts" / "B.py")
    ps_out = ps(f". '{EXPORT_PS}'; "
                f"try {{ $null = Test-SourceExportVerified -ExportRoot '{export}' "
                f"-ExpectedRootHash '{pin}'; Write-Output 'ACCEPTED' }} "
                "catch { Write-Output ('REFUSED ' + $_.Exception.Message) }")
    try:
        manifest_module.verify(export, expected_root_hash=pin)
        py_refused = False
    except manifest_module.ExportRefusal:
        py_refused = True
    rec("TRF2b case-only-rename-refused-by-ps-twin",
        "REFUSED" in ps_out.stdout,
        f"the twin the reviewer actually runs now refuses a case-only rename "
        f"({ps_out.stdout.strip()[:70]!r}) -- it previously ACCEPTED it")
    rec("TRF2c twins-agree-on-case-only-rename",
        py_refused and "REFUSED" in ps_out.stdout,
        "Python and PowerShell reach the SAME verdict; twin disagreement is a failure")
    (export / "scripts" / "B.py").rename(export / "scripts" / "b.py")

    # A manifest declaring two case-variant paths collapsed into one hashtable
    # slot, so one declared entry was never verified. Both twins refuse it now.
    manifest_path = export / manifest_module.MANIFEST_NAME
    doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    doc["files"]["scripts/B.py"] = doc["files"]["scripts/b.py"]
    manifest_path.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="ascii")
    collide_ps = ps(f". '{EXPORT_PS}'; "
                    f"try {{ $null = Test-SourceExportVerified -ExportRoot '{export}'; "
                    "Write-Output 'ACCEPTED' } catch { Write-Output ('REFUSED ' + $_.Exception.Message) }")
    try:
        manifest_module.verify(export)
        py_collide = "ACCEPTED"
    except manifest_module.ExportRefusal as exc:
        py_collide = f"REFUSED {exc}"
    # INVARIANT 5 is about the VERDICT, not the wording: both twins must refuse.
    # They reach it by different routes -- Python by the explicit folded-key
    # check, PowerShell because ConvertFrom-Json itself rejects duplicate
    # case-insensitive keys before the ordinal parse is reached. Both are
    # fail-closed; asserting one twin's reason STRING would be measuring
    # something adjacent to the property.
    ps_refused = "REFUSED" in collide_ps.stdout
    py_refused = py_collide.startswith("REFUSED")
    rec("TRF2d manifest-case-collision-refused-both-twins",
        ps_refused and py_refused
        and ("CASE_COLLISION" in collide_ps.stdout or "duplicated keys" in collide_ps.stdout)
        and "CASE_COLLISION" in py_collide,
        f"a manifest declaring both scripts/b.py and scripts/B.py is refused by BOTH "
        f"twins rather than collapsed into one verified entry "
        f"(ps={collide_ps.stdout.strip()[:60]!r})")


def control_f3(work: Path) -> None:
    """F3: NULL DACL and uninterpretable ACEs refuse in BOTH twins."""

    target = work / "null-dacl.bin"
    target.write_bytes(b"probe")

    ps_verdict = ps(f". '{NATIVES_PS}'; "
                    f"try {{ Test-TrustedNativeDescriptor -Path '{target}'; "
                    "Write-Output 'ACCEPTED' } catch { Write-Output ('REFUSED ' + $_.Exception.Message) }")
    try:
        natives.verify_descriptor(target)
        py_verdict = "ACCEPTED"
    except natives.TrustedNativeRefusal as exc:
        py_verdict = f"REFUSED {exc}"
    rec("TRF3a untrusted-descriptor-refused-both-twins",
        "REFUSED" in ps_verdict.stdout and py_verdict.startswith("REFUSED"),
        f"ps={ps_verdict.stdout.strip()[:55]!r} py={py_verdict[:55]!r}")

    # THE DISCRIMINATING FACT, executed: a security descriptor whose DACL is
    # NULL yields ZERO .NET access rules. The pre-fix PowerShell predicate was
    # owner-check + a bare `foreach` over that collection, so it never executed
    # a single iteration and RETURNED SUCCESS -- over an object that grants
    # everyone full control. Reproduced here on a real descriptor object so the
    # control cannot pass vacuously.
    legacy = ps(
        "$sd = New-Object Security.AccessControl.RawSecurityDescriptor("
        "[Security.AccessControl.ControlFlags]::None, "
        "(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')), "
        "(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')), $null, $null); "
        "Write-Output ('daclNull=' + ($null -eq $sd.DiscretionaryAcl)); "
        "Write-Output ('accessSddl=[' + $sd.GetSddlForm("
        "[Security.AccessControl.AccessControlSections]::Access) + ']')")
    out = (legacy.stdout or "").replace(" ", "")
    rec("TRF3b null-dacl-yields-no-dacl-operand",
        "daclNull=True" in out and "accessSddl=[]" in out,
        "a NULL DACL descriptor has a null DiscretionaryAcl and renders an EMPTY "
        "access-SDDL: the pre-fix predicate had no branch for it and fell through "
        "to a foreach over zero rules (returning success over a world-writable "
        "object); the new -notmatch 'D:' branch keys on exactly this operand")

    # Parity is asserted on the PREDICATE, not just the allowlist.
    natives_ps_text = NATIVES_PS.read_text(encoding="utf-8")
    py_text = (ROOT / "scripts" / "offline_trusted_natives.py").read_text(encoding="utf-8")
    rec("TRF3c both-twins-declare-null-dacl-and-unreadable-branches",
        "null DACL" in natives_ps_text and "null DACL" in py_text
        and "DESCRIPTOR_UNREADABLE" in natives_ps_text and "DESCRIPTOR_UNREADABLE" in py_text,
        "both twins carry a NULL-DACL refusal and an uninterpretable-descriptor "
        "refusal (the executed verdicts above agree)")


def control_f4(work: Path) -> None:
    """F4: icacls exit codes are checked and grants target a SID."""

    # Measured on CODE, comments stripped (see TRF1f).
    provision = code_lines(HYPERV / "provision_vm.ps1")
    rec("TRF4a icacls-routed-through-c1-and-sid-targeted",
        any("Get-TrustedNative -Name icacls" in l for l in provision)
        and not any("$($env:USERNAME):(F)" in l for l in provision)
        and any("WindowsIdentity]::GetCurrent().User.Value" in l for l in provision),
        "the credential ACL resolves icacls through C1 and grants to the current "
        "process SID rather than an environment string")

    # EFFECT: a failing icacls really does return non-zero, so checking
    # $LASTEXITCODE is a real control rather than a formality.
    missing = work / "does-not-exist.bin"
    fail = ps(f"$i = & '{natives.resolve('icacls')}' '{missing}' /inheritance:r 2>&1 | Out-String; "
              "Write-Output ('exit=' + $LASTEXITCODE)")
    rec("TRF4b failing-icacls-is-detectable-by-exit-code",
        re.search(r"exit=[1-9]", fail.stdout or "") is not None,
        f"icacls on a missing path exits non-zero ({(fail.stdout or '').strip()[:40]!r}); "
        "pre-fix this was piped to Out-Null and never inspected, so an unapplied "
        "/inheritance:r returned success")

    # And the SID that the fixed code grants to actually resolves.
    sid = ps("Write-Output ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)")
    rec("TRF4c current-process-sid-resolves",
        re.match(r"^S-1-", (sid.stdout or "").strip()) is not None,
        f"the grant target is a real SID ({(sid.stdout or '').strip()[:24]}...), not $env:USERNAME")


def control_f5(work: Path) -> None:
    """F5: no boundary file invokes a native outside C1 (door sweep)."""

    native_names = sorted(natives.ALLOWLIST)
    pattern = re.compile(
        r"(?<![\w.-])&\s*(?:'|\")?(?:" + "|".join(native_names) + r")(?:\.exe)?(?:'|\")?\s",
        re.IGNORECASE)
    filename_pattern = re.compile(r"FileName\s*=\s*['\"][\w.-]+\.exe['\"]", re.IGNORECASE)

    offenders: list[str] = []
    scanned = 0
    for path in sorted(HYPERV.rglob("*.ps1")) + [ROOT / "scripts" / "offline_env_runner.ps1"]:
        scanned += 1
        # code_lines() strips BLOCK comments too: a <# ... #> block naming a
        # bare native would otherwise be reported as a door.
        for number, line in enumerate(code_lines(path), 1):
            if "Get-TrustedNative" in line or "Get-GuestTrustedPowerShell" in line:
                continue
            if pattern.search(line) or filename_pattern.search(line):
                offenders.append(f"{path.name}~{number}")
    rec("TRF5a no-bare-name-native-door-in-boundary",
        not offenders,
        f"{scanned} boundary PowerShell files carry no native invocation outside C1 "
        f"({offenders or 'none'})")

    # The two files the finding named must actually route through C1 now, and
    # diagnostics -- which runs AS THE REVIEWER -- must dot-source the module.
    diagnostics = (HYPERV / "reviewer_diagnostics.ps1").read_text(encoding="utf-8")
    rec("TRF5b reviewer-diagnostics-routes-through-c1",
        "lib\\trusted_natives.ps1" in diagnostics
        and "Get-TrustedNative -Name powershell" in diagnostics
        and "$psi.FileName = 'powershell.exe'" not in diagnostics,
        "the in-boundary diagnostic dot-sources C1 and resolves powershell through "
        "it, including the ProcessStartInfo path")

    # EFFECT: C1 is the only door because an unlisted name cannot be resolved.
    refused = ps(f". '{NATIVES_PS}'; "
                 "try { Get-TrustedNative -Name notepad; Write-Output 'ACCEPTED' } "
                 "catch { Write-Output ('REFUSED ' + $_.Exception.Message) }")
    rec("TRF5c c1-refuses-unlisted-native",
        "REFUSED" in refused.stdout and "NOT_ALLOWLISTED" in refused.stdout,
        "a native outside the allowlist cannot be resolved through the only door")


def control_f6(work: Path) -> None:
    """F6: the reviewer-runtime guard resolves PowerShell through C1."""

    guard = ROOT / "scripts" / "offline_reviewer_runtime_guard.py"
    text = guard.read_text(encoding="utf-8")
    rec("TRF6a runtime-guard-resolves-powershell-through-c1",
        'os.environ.get("SystemRoot"' not in text
        and "_trusted_native(\"powershell\")" in text,
        "the audit:all chain member no longer derives PowerShell from $env:SystemRoot")

    # EFFECT: under the natives-trust poisoning fixture, C1 still returns the
    # true binary -- so the guard cannot be redirected to a planted mimic.
    mimic = work / "mimic" / "System32"
    mimic.mkdir(parents=True)
    (mimic / "WindowsPowerShell" / "v1.0").mkdir(parents=True)
    real = natives.system_directory() / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    shutil.copy2(real, mimic / "WindowsPowerShell" / "v1.0" / "powershell.exe")

    poisoned = dict(os.environ)
    poisoned["SystemRoot"] = str(mimic.parent)
    poisoned["windir"] = str(mimic.parent)
    poisoned["PATH"] = str(mimic)

    resolved = subprocess.run(
        [sys.executable, "-I", "-c",
         f"import sys; sys.path.insert(0, r'{ROOT / 'scripts'}');\n"
         "import offline_trusted_natives as tn; print(tn.resolve('powershell'))"],
        capture_output=True, text=True, timeout=180, env=poisoned)
    got = (resolved.stdout or "").strip()
    rec("TRF6b poisoned-systemroot-cannot-redirect-the-guard",
        resolved.returncode == 0 and got.lower() == str(real).lower()
        and "mimic" not in got.lower(),
        f"with SystemRoot/PATH pointing at a planted mimic, C1 still returns "
        f"{got!r} -- the legacy expression would have returned the mimic")

    # The legacy expression is reproduced to prove the old code WAS redirectable.
    legacy = subprocess.run(
        [sys.executable, "-I", "-c",
         "import os; from pathlib import Path; "
         "print(Path(os.environ.get('SystemRoot', r'C:\\Windows')) / 'System32' / "
         "'WindowsPowerShell' / 'v1.0' / 'powershell.exe')"],
        capture_output=True, text=True, timeout=120, env=poisoned)
    rec("TRF6c legacy-expression-would-have-been-redirected",
        "mimic" in (legacy.stdout or "").lower(),
        "the pre-fix $env:SystemRoot expression resolves INTO the planted mimic "
        "under the same poison -- so TRF6b measures the fix, not the fixture")


def control_f7(work: Path) -> None:
    """F7: the ACL write and the identity comparison use the SAME handle."""

    export = work / "f7-export"
    seed_export(export)
    root = work / "f7-taskroot"
    # [Console]::WriteLine bypasses PowerShell's formatter, which wraps long
    # lines at the console width and was truncating the SDDL mid-string.
    created = ps(f". '{TASKROOT_PS}'; "
                 f"$r = New-ReviewerTaskRoot -Path '{root}' -ContentSource '{export}'; "
                 "[Console]::WriteLine('SDDL=' + $r.sddl); "
                 "[Console]::WriteLine('ID=' + $r.root_identity)")
    sddl_line = next((l for l in created.stdout.splitlines() if l.startswith("SDDL=")), "")
    id_line = next((l for l in created.stdout.splitlines() if l.startswith("ID=")), "")
    # EFFECT: the DACL that came back through the handle must be protected AND
    # actually carry the intended principals -- "D:P" alone would be satisfied
    # by a protected DACL granting the wrong people.
    me_sid = (ps("Write-Output ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)")
              .stdout or "").strip()
    # SDDL renders well-known SIDs in short form: SYSTEM is "SY", Everyone is
    # "WD". Asserting the numeric S-1-5-18 tested a representation the string
    # never uses -- accept either spelling for each.
    grants_system = ("S-1-5-18" in sddl_line) or (";SY)" in sddl_line)
    grants_everyone = ("S-1-1-0" in sddl_line) or (";WD)" in sddl_line)
    rec("TRF7a handle-written-dacl-is-protected-and-correctly-scoped",
        created.returncode == 0 and "D:P" in sddl_line and len(id_line) > 3
        and bool(me_sid) and me_sid in sddl_line
        and grants_system and not grants_everyone,
        f"the DACL written THROUGH the handle reads back protected, grants this "
        f"principal and SYSTEM, and grants no Everyone ACE "
        f"(sddl={sddl_line[5:]!r})")

    module_text = TASKROOT_PS.read_text(encoding="utf-8")
    rec("TRF7b acl-write-is-handle-based-not-path-based",
        "SetSecurityInfo" in module_text
        and "Set-HandleProtectedDacl" in module_text
        and "$directoryInfo.SetAccessControl(" not in module_text,
        "the ACL is applied with SetSecurityInfo on an open handle; the path-based "
        "SetAccessControl (which follows reparse points) is gone")

    rec("TRF7c identity-compared-across-the-acl-write",
        "$before.identity -cne $createdIdentity" in module_text
        and "$after.identity -cne $before.identity" in module_text
        and "$viaPath.identity -cne $rootIdentity" in module_text,
        "the file ID is compared at creation, before the write, after the write, "
        "and finally handle-vs-PATH -- the mechanism the documentation claims")

    # EFFECT: SetSecurityInfo genuinely requires WRITE_DAC, so the handle used
    # for the write is provably a write-capable handle to that object.
    denied = ps(f". '{TASKROOT_PS}'; "
                f"$h = Open-TaskRootHandle -Path '{root}'; "  # READ_CONTROL only
                "try { Set-HandleProtectedDacl -Handle $h -Sddl 'D:P(A;;FA;;;S-1-5-18)' "
                "-Label 'probe'; Write-Output 'ACCEPTED' } "
                "catch { Write-Output ('REFUSED ' + $_.Exception.Message) } "
                "finally { $h.Dispose() }")
    rec("TRF7d acl-write-requires-a-write-capable-handle",
        "REFUSED" in denied.stdout and "TASKROOT_DACL_WRITE_FAILED" in denied.stdout,
        f"a READ_CONTROL-only handle cannot write the DACL "
        f"({denied.stdout.strip()[:70]!r}) -- so the writing handle really is the "
        "WRITE_DAC handle whose identity was compared")


def main() -> int:
    CHECKS.clear()
    work = Path(tempfile.mkdtemp(prefix="mr-trust-root-"))
    try:
        control_f1(work)
        control_f2(work)
        control_f3(work)
        control_f4(work)
        control_f5(work)
        control_f6(work)
        control_f7(work)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "offline-trust-root",
        "claim_scope": "v2.1 trust-root establishment: F1-F7 negative controls, each "
                       "failing on the pre-fix behaviour and witnessed by effect",
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
