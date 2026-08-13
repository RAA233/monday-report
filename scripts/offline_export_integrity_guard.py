"""``audit:offline-export-integrity`` -- executed, fault-injected, fail-closed
proof of the C2 export-manifest design, in BOTH twins (Python + PowerShell).

THE SIX-ROUND ATTACK CORPUS AS FIXTURES. Each of the shapes that defeated one
review round of the old architecture is planted into a real export and BOTH
verifiers are executed against it; the guard records the actual refusal (or,
for the one intentionally-inert shape, the actual indifference):

  round a-d  gitdir pointer file (worktree indirection)         -> refusal
  round e    submodule-style .git/modules/<n>/config            -> refusal
  round e    junctioned .git (reparse escape)                   -> refusal
  round f    refs/replace inside a planted .git                 -> refusal
  round f    commit-graph inside a planted .git                 -> refusal
  round f    per-directory .gitignore                           -> PROVABLY
             INERT: it is hashed like any other byte; its content changes the
             verdict only through its bytes, never through git semantics.

Plus the direct C2 faults: post-manifest byte flip, missing manifest (refusal
NOT skip), undeclared extra file, declared-but-absent file, pin mismatch,
junction outside .git, and the clean direction both twins agree on.

Runs unelevated on a disposable temp tree. Junctions need no privilege.
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

PS_MODULE = ROOT / "packaging" / "hyperv" / "lib" / "export_verify.ps1"

CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str) -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'} {cid}: {detail}")


def py_verify(export: Path, pin: str) -> tuple[bool, str]:
    try:
        manifest_module.verify(export, expected_root_hash=pin)
        return True, "verified"
    except manifest_module.ExportRefusal as exc:
        return False, str(exc)


def ps_verify(export: Path, pin: str) -> tuple[bool, str]:
    completed = subprocess.run(
        [str(natives.resolve("powershell")), "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-Command",
         f". '{PS_MODULE}'; "
         f"try {{ $null = Test-SourceExportVerified -ExportRoot '{export}' "
         f"-ExpectedRootHash '{pin}'; Write-Output 'VERIFIED' }} "
         "catch { Write-Output ('REFUSED ' + $_.Exception.Message) }"],
        capture_output=True, text=True, timeout=300)
    out = completed.stdout.strip()
    return out.startswith("VERIFIED"), out[:160]


def both_refuse(cid: str, label: str, export: Path, pin: str, expect_token: str) -> None:
    py_ok, py_msg = py_verify(export, pin)
    ps_ok, ps_msg = ps_verify(export, pin)
    rec(cid,
        (not py_ok) and (not ps_ok) and expect_token in py_msg and expect_token in ps_msg,
        f"{label}: py={py_msg[:70]!r} ps={ps_msg[:70]!r}")


def make_junction(link: Path, target: Path) -> None:
    subprocess.run(
        [str(natives.resolve("powershell")), "-NoProfile", "-NonInteractive", "-Command",
         f"New-Item -ItemType Junction -Path '{link}' -Target '{target}' | Out-Null"],
        capture_output=True, text=True, timeout=60, check=True)


def remove_junction(link: Path) -> None:
    # rmdir on the LINK removes the reparse point without touching the target.
    link.rmdir()


def main() -> int:  # noqa: PLR0915 -- one linear battery
    CHECKS.clear()
    work = Path(tempfile.mkdtemp(prefix="mr-export-integrity-"))
    export = work / "export"
    try:
        (export / "scripts").mkdir(parents=True)
        (export / "a.txt").write_bytes(b"alpha\n")
        (export / "scripts" / "b.py").write_bytes(b"print('b')\n")
        (export / "scripts" / ".gitignore").write_bytes(b"*.log\n")  # round-f shape, inert

        generated = manifest_module.generate(
            export, source_commit="ab" * 20, source_tree="cd" * 20)
        pin = generated["root_hash"]

        # ---- clean direction: BOTH twins verify the same bytes -------------
        py_ok, py_msg = py_verify(export, pin)
        ps_ok, ps_msg = ps_verify(export, pin)
        rec("EI01 clean-verifies-in-both-twins", py_ok and ps_ok,
            f"root hash {pin[:16]}... accepted by python and powershell verifiers")

        # ---- corpus: gitdir pointer (worktree indirection) ------------------
        pointer = export / "scripts" / ".git"
        pointer.write_bytes(b"gitdir: C:/elsewhere/.git/worktrees/w\n")
        both_refuse("EI02 gitdir-pointer-refused", "worktree gitdir pointer",
                    export, pin, "EXPORT_CONTAINS_GIT")
        pointer.unlink()

        # ---- corpus: submodule-style .git/modules config ---------------------
        module_config = export / ".git" / "modules" / "x"
        module_config.mkdir(parents=True)
        (module_config / "config").write_bytes(b"[core]\n\tfsmonitor = C:/evil.exe\n")
        both_refuse("EI03 submodule-modules-config-refused", "submodule .git/modules config",
                    export, pin, "EXPORT_CONTAINS_GIT_SHAPE")
        shutil.rmtree(export / ".git")

        # ---- corpus: refs/replace inside a planted .git ----------------------
        replace_dir = export / ".git" / "refs" / "replace"
        replace_dir.mkdir(parents=True)
        (replace_dir / ("ab" * 20)).write_bytes(("cd" * 20).encode())
        both_refuse("EI04 refs-replace-refused", "refs/replace object graft",
                    export, pin, "EXPORT_CONTAINS_GIT_SHAPE")
        shutil.rmtree(export / ".git")

        # ---- corpus: commit-graph inside a planted .git ----------------------
        graph_dir = export / ".git" / "objects" / "info"
        graph_dir.mkdir(parents=True)
        (graph_dir / "commit-graph").write_bytes(b"CGPH")
        both_refuse("EI05 commit-graph-refused", "commit-graph cache",
                    export, pin, "EXPORT_CONTAINS_GIT_SHAPE")
        shutil.rmtree(export / ".git")

        # ---- corpus: junctioned .git (round e) -------------------------------
        target = work / "attacker-git"
        (target / "hooks").mkdir(parents=True)
        make_junction(export / ".git", target)
        both_refuse("EI06 junctioned-git-refused", "junction at .git",
                    export, pin, "EXPORT_CONTAINS_GIT")
        remove_junction(export / ".git")

        # ---- corpus: junction OUTSIDE .git (adopted-directory class) ---------
        make_junction(export / "linked", target)
        both_refuse("EI07 junction-refused", "junction at a non-.git name",
                    export, pin, "EXPORT_CONTAINS_REPARSE_POINT")
        remove_junction(export / "linked")

        # ---- corpus: per-directory .gitignore is INERT, not semantic ---------
        # Its bytes are covered like any file: verification passes with the
        # manifest's bytes, and FLIPPING them is detected as a plain byte
        # change -- git semantics have no operand in the decision.
        py_ok, _ = py_verify(export, pin)
        original = (export / "scripts" / ".gitignore").read_bytes()
        (export / "scripts" / ".gitignore").write_bytes(b"!*.log\n# flipped\n")
        py_flip_ok, py_flip_msg = py_verify(export, pin)
        ps_flip_ok, ps_flip_msg = ps_verify(export, pin)
        (export / "scripts" / ".gitignore").write_bytes(original)
        rec("EI08 gitignore-inert-but-byte-covered",
            py_ok and (not py_flip_ok) and (not ps_flip_ok)
            and "EXPORT_BYTES_DIFFER" in py_flip_msg,
            "a .gitignore verifies as plain bytes; changing it is an ordinary "
            f"byte-flip refusal ({py_flip_msg[:60]!r})")

        # ---- direct faults ---------------------------------------------------
        (export / "a.txt").write_bytes(b"alphA\n")
        both_refuse("EI09 post-manifest-byte-flip-refused", "one flipped byte",
                    export, pin, "EXPORT_BYTES_DIFFER")
        (export / "a.txt").write_bytes(b"alpha\n")

        (export / "smuggled.py").write_bytes(b"import os\n")
        both_refuse("EI10 undeclared-file-refused", "extra undeclared file",
                    export, pin, "EXPORT_UNDECLARED_FILE")
        (export / "smuggled.py").unlink()

        (export / "scripts" / "b.py").unlink()
        both_refuse("EI11 declared-file-absent-refused", "declared file removed",
                    export, pin, "EXPORT_DECLARED_FILE_ABSENT")
        (export / "scripts" / "b.py").write_bytes(b"print('b')\n")

        manifest_path = export / manifest_module.MANIFEST_NAME
        hidden = work / "manifest-aside.json"
        manifest_path.replace(hidden)
        py_ok, py_msg = py_verify(export, pin)
        ps_ok, ps_msg = ps_verify(export, pin)
        rec("EI12 missing-manifest-refuses-not-skips",
            (not py_ok) and (not ps_ok)
            and "EXPORT_MANIFEST_MISSING" in py_msg and "EXPORT_MANIFEST_MISSING" in ps_msg,
            f"absence is a named refusal in both twins ({py_msg[:60]!r})")
        hidden.replace(manifest_path)

        both_refuse("EI13 pin-mismatch-refused", "wrong pinned root hash",
                    export, "0" * 64, "EXPORT_PIN_MISMATCH")

        # ---- the flip closes: clean again after every fault removed ---------
        py_ok, _ = py_verify(export, pin)
        ps_ok, _ = ps_verify(export, pin)
        rec("EI14 clean-again-after-faults", py_ok and ps_ok,
            "the same verifiers accept the restored tree -- every refusal above "
            "was caused by its fault, not by ambient state")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "offline-export-integrity",
        "claim_scope": "C2: the integrity decision's only operands are disk bytes and the "
                       "pinned manifest; the six-round .git corpus has nothing to attach to",
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
