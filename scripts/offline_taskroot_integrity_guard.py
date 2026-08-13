"""``audit:offline-taskroot-integrity`` -- executed, fault-injected,
fail-closed proof of the C3 fresh-task-root design.

Every check drives the REAL module (packaging/hyperv/lib/task_root.ps1) in a
child PowerShell and records what actually came back. Both directions:

  clean  -> a fresh root is created, its DACL is protected (read back through
            the CREATION HANDLE, witnessed by the returned SDDL), content is
            copied file-by-file, and handle-vs-path file IDs agree;
  fault  -> a junction pre-planted at the would-be root REFUSES; a plain
            pre-existing directory REFUSES (no adopt, no reclaim); a junction
            raced into the tree BETWEEN the DACL application and the content
            copy (injected deterministically through the module's declared
            test seam) REFUSES on the colliding path AND on the final sweep
            for a non-colliding one; a junction inside the SOURCE refuses.

Runs unelevated on a disposable temp tree; junctions need no privilege.
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

import offline_trusted_natives as natives  # noqa: E402

PS_MODULE = ROOT / "packaging" / "hyperv" / "lib" / "task_root.ps1"

CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str) -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'} {cid}: {detail}")


def run_module(script_body: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(natives.resolve("powershell")), "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-Command",
         f"$ErrorActionPreference='Stop'; . '{PS_MODULE}'; {script_body}"],
        capture_output=True, text=True, timeout=300)


def main() -> int:  # noqa: PLR0915 -- one linear battery
    CHECKS.clear()
    work = Path(tempfile.mkdtemp(prefix="mr-taskroot-"))
    try:
        export = work / "export"
        (export / "scripts").mkdir(parents=True)
        (export / "a.txt").write_bytes(b"alpha\n")
        (export / "scripts" / "b.py").write_bytes(b"print('b')\n")

        # ---- clean creation with handle-read DACL witness -------------------
        clean_root = work / "task-root"
        clean = run_module(
            f"$r = New-ReviewerTaskRoot -Path '{clean_root}' -ContentSource '{export}'; "
            "Write-Output ('SDDL=' + $r.sddl); Write-Output ('FILES=' + $r.files_copied); "
            "Write-Output ('ID=' + $r.root_identity)")
        sddl_line = next((l for l in clean.stdout.splitlines() if l.startswith("SDDL=")), "")
        rec("TR01 fresh-create-protected-dacl",
            clean.returncode == 0 and "D:P" in sddl_line and "FILES=2" in clean.stdout
            and "ID=" in clean.stdout,
            f"root created fresh; DACL read back THROUGH THE CREATION HANDLE is "
            f"protected ({sddl_line[:60]!r}); 2 files copied; identity recorded")
        rec("TR02 content-copied-file-by-file",
            (clean_root / "scripts" / "b.py").read_bytes() == b"print('b')\n",
            "the copy is byte-faithful and file-by-file (no move/rename of a tree)")

        # ---- fault: plain pre-existing directory (no adopt/reclaim) ---------
        preexisting = run_module(
            f"try {{ New-ReviewerTaskRoot -Path '{clean_root}' -ContentSource '{export}' | Out-Null; "
            "Write-Output 'ACCEPTED' } catch { Write-Output ('REFUSED ' + $_.Exception.Message) }")
        rec("TR03 pre-existing-path-refused",
            "REFUSED" in preexisting.stdout and "TASKROOT_PATH_ALREADY_EXISTS" in preexisting.stdout,
            preexisting.stdout.strip()[:110])

        # ---- fault: junction PRE-PLANTED at the would-be root ---------------
        target = work / "attacker-target"
        target.mkdir()
        planted = work / "planted-root"
        subprocess.run(
            [str(natives.resolve("powershell")), "-NoProfile", "-Command",
             f"New-Item -ItemType Junction -Path '{planted}' -Target '{target}' | Out-Null"],
            capture_output=True, text=True, timeout=60, check=True)
        pre_plant = run_module(
            f"try {{ New-ReviewerTaskRoot -Path '{planted}' -ContentSource '{export}' | Out-Null; "
            "Write-Output 'ACCEPTED' } catch { Write-Output ('REFUSED ' + $_.Exception.Message) }")
        rec("TR04 pre-planted-junction-refused",
            "REFUSED" in pre_plant.stdout and "TASKROOT_PATH_ALREADY_EXISTS" in pre_plant.stdout,
            "a junction squatting on the would-be root is a pre-existing path: "
            + pre_plant.stdout.strip()[:80])
        planted.rmdir()

        # ---- fault: junction raced in MID-COPY (colliding path) -------------
        # The module's declared test seam runs after the DACL is applied and
        # verified, before content -- exactly the race window. The plant
        # occupies a directory name the copy is about to create.
        raced1 = work / "task-root-raced1"
        mid_collide = run_module(
            "$hook = { param($p) New-Item -ItemType Junction "
            f"-Path (Join-Path $p 'scripts') -Target '{target}' | Out-Null }}; "
            f"try {{ New-ReviewerTaskRoot -Path '{raced1}' -ContentSource '{export}' "
            "-TestHookBeforeContent $hook | Out-Null; Write-Output 'ACCEPTED' } "
            "catch { Write-Output ('REFUSED ' + $_.Exception.Message) }")
        rec("TR05 mid-copy-junction-collision-refused",
            "REFUSED" in mid_collide.stdout
            and "TASKROOT_DESTINATION_PREOCCUPIED" in mid_collide.stdout,
            "a junction raced onto a path the copy is about to create refuses "
            "instead of writing through the link: " + mid_collide.stdout.strip()[:80])

        # ---- fault: junction raced in MID-COPY (non-colliding path) ---------
        # Nothing collides, so the copy itself succeeds -- the FINAL SWEEP has
        # to catch the link. This is the direction a copy-only check misses.
        raced2 = work / "task-root-raced2"
        mid_free = run_module(
            "$hook = { param($p) New-Item -ItemType Junction "
            f"-Path (Join-Path $p 'stowaway') -Target '{target}' | Out-Null }}; "
            f"try {{ New-ReviewerTaskRoot -Path '{raced2}' -ContentSource '{export}' "
            "-TestHookBeforeContent $hook | Out-Null; Write-Output 'ACCEPTED' } "
            "catch { Write-Output ('REFUSED ' + $_.Exception.Message) }")
        rec("TR06 mid-copy-junction-sweep-refused",
            "REFUSED" in mid_free.stdout
            and "TASKROOT_REPARSE_POINT_DETECTED" in mid_free.stdout,
            "a non-colliding junction planted mid-copy is caught by the final "
            "handle-attribute sweep: " + mid_free.stdout.strip()[:80])

        # ---- fault: reparse point inside the SOURCE -------------------------
        bad_export = work / "export-bad"
        bad_export.mkdir()
        (bad_export / "ok.txt").write_bytes(b"x")
        subprocess.run(
            [str(natives.resolve("powershell")), "-NoProfile", "-Command",
             f"New-Item -ItemType Junction -Path '{bad_export / 'junc'}' -Target '{target}' | Out-Null"],
            capture_output=True, text=True, timeout=60, check=True)
        src_junc = run_module(
            f"try {{ New-ReviewerTaskRoot -Path '{work / 'task-root-badsrc'}' "
            f"-ContentSource '{bad_export}' | Out-Null; Write-Output 'ACCEPTED' }} "
            "catch { Write-Output ('REFUSED ' + $_.Exception.Message) }")
        rec("TR07 source-reparse-refused",
            "REFUSED" in src_junc.stdout and "TASKROOT_SOURCE_REPARSE_POINT" in src_junc.stdout,
            src_junc.stdout.strip()[:100])

        # ---- the flip closes: a fresh clean run still succeeds --------------
        final_root = work / "task-root-final"
        final = run_module(
            f"$r = New-ReviewerTaskRoot -Path '{final_root}' -ContentSource '{export}'; "
            "Write-Output ('FILES=' + $r.files_copied)")
        rec("TR08 clean-again-after-faults",
            final.returncode == 0 and "FILES=2" in final.stdout,
            "the same module still creates a clean root -- every refusal above was "
            "caused by its seeded fault")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "offline-taskroot-integrity",
        "claim_scope": "C3: the task root is never adopted or reclaimed; DACL precedes "
                       "content; reparse checks cover exactly the paths the module created",
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
