"""``audit:offline-boundary-shape`` -- executed, fault-injected, fail-closed
proof of the C4 git-free boundary.

Three executed claims, each with its fault direction:

  BS-git   git is absent from the C1 allowlist in BOTH twins, and invoking it
           through the module FAILS CLOSED (executed, not grepped).
  BS-repo  the O(1) repository-shape rule (Test-AuthorWorkspaceShape) accepts a
           single-repo-at-root workspace and REFUSES a nested repository and a
           no-repo directory -- the constant-time structural check that
           replaces the unbounded .git-internals scan. A nested repo planted
           into a source EXPORT is also refused by C2.
  BS-interp the isolated interpreter launched as the session launches it
           (python -I -S) does NOT load a seeded sitecustomize / ._pth even
           with PYTHONPATH pointing straight at it -- EXECUTED: the fixture is
           planted and the interpreter is asked whether it loaded, both ways.

Runs unelevated on a disposable temp tree.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import offline_export_manifest as manifest_module  # noqa: E402
import offline_trusted_natives as natives  # noqa: E402

NATIVES_PS = ROOT / "packaging" / "hyperv" / "lib" / "trusted_natives.ps1"
EXPORT_PS = ROOT / "packaging" / "hyperv" / "lib" / "export_verify.ps1"

CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str) -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'} {cid}: {detail}")


def run_ps(script: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(natives.resolve("powershell")), "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, text=True, timeout=180)


def main() -> int:  # noqa: PLR0915 -- one linear battery
    CHECKS.clear()
    work = Path(tempfile.mkdtemp(prefix="mr-boundary-shape-"))
    try:
        # ---- BS-git: absent from the allowlist AND uninvokable --------------
        py_git_refused = False
        try:
            natives.resolve("git")
        except natives.TrustedNativeRefusal as exc:
            py_git_refused = "NOT_ALLOWLISTED" in str(exc)
        rec("BS01 py-git-absent-and-uninvokable",
            "git" not in natives.ALLOWLIST and py_git_refused,
            "git is not on the Python allowlist and resolve('git') fails closed")

        ps_git = run_ps(
            f". '{NATIVES_PS}'; "
            "$absent = -not $script:TrustedNativeAllowlist.ContainsKey('git'); "
            "try { Get-TrustedNative -Name git; $invk = 'ACCEPTED' } "
            "catch { $invk = 'REFUSED' }; "
            "Write-Output ('ABSENT=' + $absent + ' INVOKE=' + $invk)")
        rec("BS02 ps-git-absent-and-uninvokable",
            "ABSENT=True" in ps_git.stdout and "INVOKE=REFUSED" in ps_git.stdout,
            ps_git.stdout.strip()[:90])

        # ---- BS-repo: the O(1) shape rule, both directions ------------------
        good_ws = work / "good-workspace"
        (good_ws / ".git").mkdir(parents=True)
        (good_ws / "scripts").mkdir()
        (good_ws / "scripts" / "x.py").write_bytes(b"print(1)\n")
        good = run_ps(
            f". '{EXPORT_PS}'; "
            f"try {{ $g = Test-AuthorWorkspaceShape -WorkspaceRoot '{good_ws}'; "
            "Write-Output ('OK ' + $g) } catch { Write-Output ('REFUSED ' + $_.Exception.Message) }")
        rec("BS03 single-repo-root-accepted",
            good.returncode == 0 and good.stdout.strip().startswith("OK"),
            f"exactly one repo at the workspace root is accepted ({good.stdout.strip()[:60]!r})")

        nested_ws = work / "nested-workspace"
        (nested_ws / ".git").mkdir(parents=True)
        (nested_ws / "vendor" / "lib" / ".git").mkdir(parents=True)
        nested = run_ps(
            f". '{EXPORT_PS}'; "
            f"try {{ Test-AuthorWorkspaceShape -WorkspaceRoot '{nested_ws}' | Out-Null; "
            "Write-Output 'ACCEPTED' } catch { Write-Output ('REFUSED ' + $_.Exception.Message) }")
        rec("BS04 nested-repository-refused",
            "REFUSED" in nested.stdout and "OFFLINE_EXPORT_NESTED_REPOSITORY" in nested.stdout,
            nested.stdout.strip()[:90])

        norepo_ws = work / "no-repo-workspace"
        (norepo_ws / "scripts").mkdir(parents=True)
        norepo = run_ps(
            f". '{EXPORT_PS}'; "
            f"try {{ Test-AuthorWorkspaceShape -WorkspaceRoot '{norepo_ws}' | Out-Null; "
            "Write-Output 'ACCEPTED' } catch { Write-Output ('REFUSED ' + $_.Exception.Message) }")
        rec("BS05 no-repository-root-refused",
            "REFUSED" in norepo.stdout
            and "OFFLINE_EXPORT_SOURCE_NOT_A_REPOSITORY_ROOT" in norepo.stdout,
            norepo.stdout.strip()[:90])

        # ---- BS-repo (C2): a nested repo planted in an EXPORT is refused ----
        export = work / "export"
        (export / "scripts").mkdir(parents=True)
        (export / "scripts" / "b.py").write_bytes(b"print('b')\n")
        gen = manifest_module.generate(export, source_commit="ab" * 20, source_tree="cd" * 20)
        (export / "vendor" / ".git").mkdir(parents=True)
        (export / "vendor" / ".git" / "config").write_bytes(b"[core]\n")
        nested_export_refused = False
        try:
            manifest_module.verify(export, expected_root_hash=gen["root_hash"])
        except manifest_module.ExportRefusal as exc:
            nested_export_refused = "EXPORT_CONTAINS_GIT_SHAPE" in str(exc)
        rec("BS06 nested-repo-in-export-refused-by-c2", nested_export_refused,
            "a .git planted anywhere in the export is an O(1) C2 refusal")
        shutil.rmtree(export / "vendor")

        # ---- BS-interp: seeded sitecustomize/._pth stays inert (executed) ---
        plant = work / "plant"
        plant.mkdir()
        (plant / "sitecustomize.py").write_bytes(
            b'import sys; sys.stderr.write("SITECUSTOMIZE_LOADED")\n')
        probe = plant / "probe.py"
        probe.write_bytes(
            b'import sys\n'
            b'hit = any("plant" in (p or "") for p in sys.path)\n'
            b'print("plant" if hit else "clean")\n'
            b'print("site" in sys.modules)\n')

        import os as _os
        poisoned = dict(_os.environ)
        poisoned["PYTHONPATH"] = str(plant)

        isolated = subprocess.run(
            [sys.executable, "-I", "-S", str(probe)],
            capture_output=True, text=True, timeout=120, env=poisoned)
        clean = ("clean" in isolated.stdout and "False" in isolated.stdout
                 and "SITECUSTOMIZE_LOADED" not in (isolated.stdout + isolated.stderr))
        rec("BS07 isolated-interpreter-ignores-seed",
            isolated.returncode == 0 and clean,
            f"python -I -S with PYTHONPATH -> plant: site NOT imported, sitecustomize "
            f"NOT loaded ({isolated.stdout.strip()!r})")

        # Fault-direction control: WITHOUT -I -S the same seed DOES load, so
        # the check above is measuring the flag, not an accident of the fixture.
        unguarded = subprocess.run(
            [sys.executable, str(probe)],
            capture_output=True, text=True, timeout=120, env=poisoned)
        seed_loaded = ("plant" in unguarded.stdout
                       or "SITECUSTOMIZE_LOADED" in (unguarded.stdout + unguarded.stderr))
        rec("BS08 seed-would-load-without-isolation", seed_loaded,
            "the identical seed DOES reach an unisolated interpreter -- so BS07 "
            "proves the -I -S control, not an inert fixture")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "offline-boundary-shape",
        "claim_scope": "C4: git is structurally uninvokable inside the boundary; provenance "
                       "is operator-recorded data; the isolated interpreter loads no seeded hook",
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
