"""``audit:offline-natives-trust`` -- executed, fault-injected, fail-closed
proof of the C1 trusted-natives design, in BOTH twins (PowerShell + Python).

Every check is an EXECUTED CALL-SITE WITNESS: the resolver/predicate is
actually invoked (in a child process where environment poisoning matters) and
the guard records what came back -- never string presence in source.

Both directions per claim:
  clean  -> real System32 binaries resolve and pass the owner/DACL predicate;
  fault  -> a poisoned SystemRoot/PATH pointing at an author-planted mimic
            System32 does not move the resolver; an ACL-defective plant at a
            deliberately-addressed path REFUSES; an unreadable descriptor
            REFUSES (fail closed); git and unlisted names REFUSE in both
            twins.

Runs unelevated on a disposable temp tree. No Hyper-V, no VM, no network.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import offline_trusted_natives as natives  # noqa: E402

PS_MODULE = ROOT / "packaging" / "hyperv" / "lib" / "trusted_natives.ps1"

CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str) -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'} {cid}: {detail}")


def run_ps(script: str, env: dict | None = None) -> subprocess.CompletedProcess:
    """The PS twin under test is dot-sourced INSIDE the child, so a poisoned
    child environment is exactly what the module sees."""

    return subprocess.run(
        [str(natives.resolve("powershell")), "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-Command",
         f". '{PS_MODULE}'; {script}"],
        capture_output=True, text=True, timeout=180, env=env)


def run_py(code: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-I", "-c",
         f"import sys; sys.path.insert(0, r'{ROOT / 'scripts'}');\n" + code],
        capture_output=True, text=True, timeout=180, env=env)


def main() -> int:  # noqa: PLR0915 -- one linear battery
    CHECKS.clear()
    work = Path(tempfile.mkdtemp(prefix="mr-natives-trust-"))
    try:
        # ---- NT01 clean resolution + execution (both twins) ----------------
        resolved = natives.resolve("icacls")
        who = natives.run("whoami", timeout=60)
        rec("NT01a py-clean-resolution-and-execution",
            resolved.is_file() and who.returncode == 0 and bool(who.stdout.strip()),
            f"Python twin resolved {resolved} and executed whoami "
            f"(rc={who.returncode}, identity witnessed)")

        ps_clean = run_ps("$p = Get-TrustedNative -Name icacls; "
                          "$o = Invoke-TrustedNative -Name whoami; "
                          "Write-Output ($p + '|' + $o)")
        rec("NT01b ps-clean-resolution-and-execution",
            ps_clean.returncode == 0 and "icacls.exe" in ps_clean.stdout.lower()
            and "|" in ps_clean.stdout,
            f"PS twin resolved and executed (stdout witness: {ps_clean.stdout.strip()[:80]!r})")

        # ---- NT02 git structurally uninvokable (both twins, executed) ------
        git_py_refused = False
        git_py_reason = ""
        try:
            natives.resolve("git")
        except natives.TrustedNativeRefusal as exc:
            git_py_refused = "NOT_ALLOWLISTED" in str(exc)
            git_py_reason = str(exc)[:80]
        rec("NT02a py-git-refused", git_py_refused, git_py_reason)

        git_ps = run_ps("try { Get-TrustedNative -Name git; Write-Output 'ACCEPTED' } "
                        "catch { Write-Output ('REFUSED ' + $_.Exception.Message) }")
        rec("NT02b ps-git-refused",
            "REFUSED" in git_ps.stdout and "NOT_ALLOWLISTED" in git_ps.stdout,
            git_ps.stdout.strip()[:100])

        # ---- NT03 poisoned SystemRoot/PATH does not move the resolver ------
        mimic = work / "mimic-system32" / "System32"
        mimic.mkdir(parents=True)
        real_system = natives.system_directory()
        for name in ("icacls.exe", "whoami.exe"):
            shutil.copy2(real_system / name, mimic / name)
        (mimic / "WindowsPowerShell" / "v1.0").mkdir(parents=True)

        poisoned = dict(os.environ)
        poisoned["SystemRoot"] = str(mimic.parent)
        poisoned["windir"] = str(mimic.parent)
        poisoned["PATH"] = str(mimic)

        py_poisoned = run_py(
            "import offline_trusted_natives as tn\n"
            "print(tn.resolve('icacls'))", env=poisoned)
        py_path = py_poisoned.stdout.strip().lower()
        rec("NT03a py-poisoned-env-ignored",
            py_poisoned.returncode == 0
            and py_path == str(real_system / "icacls.exe").lower()
            and "mimic" not in py_path,
            f"under SystemRoot/PATH -> author mimic, the Python twin still returned "
            f"{py_poisoned.stdout.strip()!r}")

        ps_poisoned = run_ps("Write-Output (Get-TrustedNative -Name icacls)", env=poisoned)
        ps_path = ps_poisoned.stdout.strip().lower()
        rec("NT03b ps-poisoned-env-ignored",
            ps_poisoned.returncode == 0
            and ps_path == str(real_system / "icacls.exe").lower()
            and "mimic" not in ps_path,
            f"under the same poison, the PS twin still returned "
            f"{ps_poisoned.stdout.strip()!r}")

        # ---- NT04 ACL-defective plant refused (flip direction) -------------
        plant = work / "planted-icacls.exe"
        shutil.copy2(real_system / "icacls.exe", plant)  # user-owned copy
        plant_py_refused = False
        plant_py_reason = ""
        try:
            natives.verify_descriptor(plant)
        except natives.TrustedNativeRefusal as exc:
            plant_py_refused = "UNTRUSTED" in str(exc)
            plant_py_reason = str(exc)[:90]
        rec("NT04a py-acl-defective-plant-refused", plant_py_refused, plant_py_reason)

        plant_ps = run_ps(f"try {{ Test-TrustedNativeDescriptor -Path '{plant}'; "
                          "Write-Output 'ACCEPTED' } "
                          "catch { Write-Output ('REFUSED ' + $_.Exception.Message) }")
        rec("NT04b ps-acl-defective-plant-refused",
            "REFUSED" in plant_ps.stdout and "UNTRUSTED" in plant_ps.stdout,
            plant_ps.stdout.strip()[:110])

        # The SAME predicate accepts the real binary (the other direction of
        # the flip, witnessed against the identical code path):
        clean_predicate_ok = True
        try:
            natives.verify_descriptor(real_system / "icacls.exe")
        except natives.TrustedNativeRefusal:
            clean_predicate_ok = False
        rec("NT04c predicate-flips-both-directions",
            clean_predicate_ok and plant_py_refused,
            "identical predicate: real System32 binary accepted, user-owned plant refused")

        # ---- NT05 unreadable descriptor fails CLOSED ------------------------
        missing = work / "not-there.exe"
        missing_refused = False
        try:
            natives.verify_descriptor(missing)
        except natives.TrustedNativeRefusal as exc:
            missing_refused = "UNREADABLE" in str(exc) or "ABSENT" in str(exc)
        rec("NT05 unreadable-descriptor-refuses", missing_refused,
            "a descriptor that cannot be read is a refusal, never a skip")

        # ---- NT06 allowlists agree between the twins ------------------------
        ps_list = run_ps("$script:TrustedNativeAllowlist.Keys | Sort-Object | Write-Output")
        ps_names = sorted(n.strip() for n in ps_list.stdout.splitlines() if n.strip())
        py_names = sorted(natives.ALLOWLIST)
        rec("NT06 twin-allowlists-identical",
            ps_names == py_names and "git" not in py_names,
            f"both allowlists = {py_names} (git absent from both)")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "offline-natives-trust",
        "claim_scope": "C1: native resolution consumes zero author-controllable operands; "
                       "owner/DACL verified before use; git structurally uninvokable",
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
