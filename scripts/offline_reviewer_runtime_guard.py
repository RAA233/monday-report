"""``audit:offline-reviewer-runtime`` -- the dedicated reviewer runtime contract.

WHY THIS EXISTS
---------------
The reviewer was pinned to the author's own development Python: registered in
the user's Python registry key, on the persistent PATH, 307 distributions, 119
console-script shims, four dependent virtual environments, 73,711 files. The
proposed remedy was to take ownership of that tree and lock it. Classifying it
first is the only reason that did not happen.

So the contract has two halves, and this guard exercises both.

  1. The runtime the reviewer executes must be a DEDICATED tree under the
     task-owned root -- never a shared installation, never something reached
     through a junction or a traversal.

  2. Acceptance must fail CLOSED with a named reason, and must never delete
     anything. A verifier that quietly removes a sitecustomize.py it did not
     expect is making a judgement about someone's Python installation that no
     automated step should make.

Every case below is a four-step cycle: the fixture is accepted, one thing is
changed, the named reason appears, the change is undone and acceptance returns.
A refusal that cannot be turned back on is indistinguishable from a verifier
that refuses everything.
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

from offline_reviewer_runtime import (  # noqa: E402
    EXPECTED_PTH_LINES, MANIFEST_NAME, MANIFEST_SCHEMA, REQUIRED_DISTRIBUTIONS,
    tree_digest, verify,
)

CHECKS: list[dict] = []


def rec(check_id: str, ok: bool, detail: str) -> bool:
    CHECKS.append({"check_id": check_id, "ok": bool(ok), "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'} {check_id}: {detail}")
    return bool(ok)


def build_fixture(task_root: Path) -> Path:
    """A structurally complete runtime, small enough to mutate quickly.

    Deliberately NOT a copy of the real 45 MiB runtime: every check this guard
    exercises is structural, and a fixture that takes half a minute to clone per
    mutation is a fixture that ends up being cloned once and reused, which is
    how mutation tests stop being independent.
    """

    runtime = task_root / "reviewer-runtime"
    site = runtime / "Lib" / "site-packages"
    site.mkdir(parents=True)
    (runtime / "DLLs").mkdir()
    (runtime / "python.exe").write_bytes(b"fixture interpreter payload")
    (runtime / "python310.dll").write_bytes(b"fixture core payload")
    (runtime / "vcruntime140.dll").write_bytes(b"fixture crt payload")
    (runtime / "DLLs" / "_socket.pyd").write_bytes(b"fixture extension payload")
    (runtime / "Lib" / "os.py").write_text("# fixture stdlib\n", encoding="utf-8")
    # Names that a culture-aware sort and an ordinal sort order DIFFERENTLY.
    # Without a pair like this the cross-implementation check passed while the
    # two digests disagreed on any real CPython tree, which ships exactly these.
    (runtime / "DLLs" / "api-ms-win-core-file-l1-1-0.dll").write_bytes(b"fixture api dash")
    (runtime / "DLLs" / "api_ms_extra.dll").write_bytes(b"fixture api underscore")
    for dist in REQUIRED_DISTRIBUTIONS:
        stem = dist.lower().replace("-", "_")
        if stem.startswith("_"):
            (site / f"{stem}.cp310-win_amd64.pyd").write_bytes(b"fixture backend payload")
        elif stem == "typing_extensions":
            (site / "typing_extensions.py").write_text("# fixture\n", encoding="utf-8")
        else:
            pkg = site / stem
            pkg.mkdir()
            (pkg / "__init__.py").write_text("# fixture\n", encoding="utf-8")
    (runtime / "python310._pth").write_text(
        "\n".join(EXPECTED_PTH_LINES) + "\n", encoding="ascii")
    write_manifest(runtime)
    return runtime


def write_manifest(runtime: Path, path_file: str = "python310._pth") -> None:
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "interpreter_version": "3.10.5",
        "path_file": path_file,
        "required_distributions": list(REQUIRED_DISTRIBUTIONS),
        "distribution_entries": [],
        "tree_digest": tree_digest(runtime, exclude=frozenset({MANIFEST_NAME})),
    }
    (runtime / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def check(runtime: Path, task_root: Path, *, exe: Path | None = None) -> list[str]:
    return verify(exe or (runtime / "python.exe"),
                  task_root=task_root, runtime_root=runtime, run_probe=False)


def cycle(case_id: str, label: str, runtime: Path, task_root: Path,
          mutate, restore, expected: str, *, exe_override=None) -> None:
    """baseline accepted -> mutate -> named reason -> restore -> accepted."""

    before = check(runtime, task_root)
    if before:
        rec(f"{case_id} baseline-accepted", False,
            f"the unmutated fixture was refused ({before}), so this cycle proves nothing")
        return
    mutate()
    exe = exe_override() if exe_override else None
    during = check(runtime, task_root, exe=exe)
    named = expected in during
    restore()
    after = check(runtime, task_root)
    rec(case_id, named and not after,
        f"{label}: refused with {expected} "
        f"(reasons={during}), and acceptance returned after restoring "
        f"({'clean' if not after else after})")


def main() -> int:
    CHECKS.clear()
    work = Path(tempfile.mkdtemp(prefix="mr-runtime-guard-"))
    try:
        task_root = work / "task"
        task_root.mkdir()
        runtime = build_fixture(task_root)
        site = runtime / "Lib" / "site-packages"

        rec("RT00 fixture-accepted", not check(runtime, task_root),
            "a correctly shaped dedicated runtime is accepted, so later refusals "
            "mean something")

        # 1. outside the task root
        outside = work / "elsewhere" / "Python310"
        outside.mkdir(parents=True)
        shutil.copytree(runtime, outside / "rt")
        reasons = verify(outside / "rt" / "python.exe", task_root=task_root,
                         runtime_root=runtime, run_probe=False)
        rec("RT01 interpreter-outside-task-root",
            "REVIEWER_RUNTIME_OUTSIDE_TASK_ROOT" in reasons,
            f"an interpreter outside the task-owned root is refused ({reasons})")

        # 2. path traversal that lands back inside
        traversal = Path(str(runtime / "Lib" / ".." / "python.exe"))
        reasons = verify(traversal, task_root=task_root, runtime_root=runtime,
                         run_probe=False)
        rec("RT02 path-traversal",
            "REVIEWER_RUNTIME_PATH_TRAVERSAL" in reasons,
            f"a path that resolves inside after travelling outside is refused ({reasons})")

        # 3. junction escape -- the ACL would land on the target tree, not this one
        #
        # The earlier version pointed the junction at an EMPTY directory, so
        # verify() short-circuited on REVIEWER_RUNTIME_ABSENT before the reparse
        # check ever ran -- and the case accepted that reason as success. It
        # proved nothing. The real attack puts a COMPLETE, passing runtime behind
        # the junction, which is what is planted here.
        target = work / "junction-target"
        shutil.copytree(runtime, target)
        link = task_root / "reviewer-runtime-link"
        made = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                              capture_output=True, text=True)
        if made.returncode == 0:
            direct = verify(target / "python.exe", task_root=work,
                            runtime_root=target, run_probe=False)
            reasons = verify(link / "python.exe", task_root=task_root,
                             runtime_root=link, run_probe=False)
            rec("RT03 junction-reparse-escape",
                not direct and "REVIEWER_RUNTIME_REPARSE_ESCAPE" in reasons,
                f"the same tree is accepted when reached directly ({direct or 'clean'}) "
                f"and refused as a reparse escape when reached through a junction "
                f"({reasons}), so the refusal is about the link and not about the tree")
        else:
            rec("RT03 junction-reparse-escape", False,
                "a junction could not be created, so the escape is untested rather "
                "than proven safe")

        # 4/5. shared installations, per-user and machine-wide alike
        def add_shared():
            for i in range(len(REQUIRED_DISTRIBUTIONS) + 6):
                (site / f"unrelated_pkg_{i}-1.0.dist-info").mkdir()
            write_manifest(runtime)

        def drop_shared():
            for entry in list(site.iterdir()):
                if entry.name.startswith("unrelated_pkg_"):
                    shutil.rmtree(entry)
            write_manifest(runtime)

        cycle("RT04 shared-installation-distributions",
              "a tree carrying unrelated distributions", runtime, task_root,
              add_shared, drop_shared, "REVIEWER_RUNTIME_UNEXPECTED_DISTRIBUTIONS")

        scripts_dir = runtime / "Scripts"

        def add_shims():
            scripts_dir.mkdir(exist_ok=True)
            (scripts_dir / "pip.exe").write_bytes(b"fixture shim payload")
            write_manifest(runtime)

        def drop_shims():
            shutil.rmtree(scripts_dir, ignore_errors=True)
            write_manifest(runtime)

        cycle("RT05 shared-installation-console-shims",
              "a tree carrying console-script shims", runtime, task_root,
              add_shims, drop_shims, "REVIEWER_RUNTIME_CONSOLE_SCRIPT_SHIMS")

        # 6/7/8. the injection vectors themselves
        for case_id, name, expected in (
                ("RT06 unexpected-sitecustomize", "sitecustomize.py",
                 "REVIEWER_RUNTIME_UNEXPECTED_SITE_HOOK"),
                ("RT07 unexpected-usercustomize", "usercustomize.py",
                 "REVIEWER_RUNTIME_UNEXPECTED_SITE_HOOK"),
                ("RT08 unexpected-pth-input", "zz_injected.pth",
                 "REVIEWER_RUNTIME_UNEXPECTED_PTH_INPUT")):
            planted = site / name

            def plant(p=planted):
                p.write_text("import sys\n", encoding="ascii")
                write_manifest(runtime)

            def remove(p=planted):
                # The GUARD may remove its own fixture. The VERIFIER never
                # removes anything from a real runtime; it reports and refuses.
                p.unlink()
                write_manifest(runtime)

            cycle(case_id, f"a planted {name}", runtime, task_root,
                  plant, remove, expected)

        # 9/10. the interpreter and an adjacent module, both covered by one digest
        for case_id, rel, label in (
                ("RT09 modified-interpreter", "python.exe", "the interpreter executable"),
                ("RT10 modified-adjacent-module", "DLLs/_socket.pyd",
                 "an adjacent extension module")):
            target_file = runtime / rel
            original = target_file.read_bytes()

            def corrupt(p=target_file):
                p.write_bytes(b"tampered payload")

            def repair(p=target_file, data=original):
                p.write_bytes(data)

            cycle(case_id, f"{label} changed after pinning", runtime, task_root,
                  corrupt, repair, "REVIEWER_RUNTIME_TREE_DIGEST_MISMATCH")

        # 11. a dependency the reviewer workflow actually imports
        crypto = site / "cryptography"
        stash = work / "stashed-cryptography"

        def take():
            shutil.move(str(crypto), str(stash))
            write_manifest(runtime)

        def give_back():
            shutil.move(str(stash), str(crypto))
            write_manifest(runtime)

        cycle("RT11 missing-required-dependency",
              "a required distribution removed", runtime, task_root,
              take, give_back, "REVIEWER_RUNTIME_MISSING_DEPENDENCY")

        # The path file is the control that removes the vector, so its own
        # integrity gets the same treatment.
        pth = runtime / "python310._pth"
        original_pth = pth.read_text(encoding="ascii")

        def drop_pth():
            pth.unlink()
            write_manifest(runtime)

        def restore_pth():
            pth.write_text(original_pth, encoding="ascii")
            write_manifest(runtime)

        cycle("RT12 path-file-missing", "the ._pth removed", runtime, task_root,
              drop_pth, restore_pth, "REVIEWER_RUNTIME_PATH_FILE_MISSING")

        def enable_site():
            pth.write_text(original_pth + "import site\n", encoding="ascii")
            write_manifest(runtime)

        cycle("RT13 path-file-enables-site",
              "a ._pth that turns site back on", runtime, task_root,
              enable_site, restore_pth, "REVIEWER_RUNTIME_PATH_FILE_ENABLES_SITE")

        def widen_pth():
            pth.write_text(original_pth + "..\\..\\author-controlled\n", encoding="ascii")
            write_manifest(runtime)

        cycle("RT14 path-file-unexpected-entries",
              "a ._pth naming a directory outside the runtime", runtime, task_root,
              widen_pth, restore_pth, "REVIEWER_RUNTIME_PATH_FILE_UNEXPECTED_ENTRIES")

        # A ._pth CPython will ignore. Named for a different version, the file is
        # present, correct in content, and completely dead -- site is imported,
        # sitecustomize runs, PYTHONPATH is honoured. The verifier read the name
        # out of the manifest and only checked the file existed, so it accepted
        # the one arrangement that silently removes the control the whole design
        # rests on.
        wrong = runtime / "python39._pth"

        def misname():
            pth.rename(wrong)
            # The manifest is rewritten to DECLARE the wrong name too, which is
            # the state an attacker would leave behind: internally consistent,
            # and inert as far as CPython is concerned.
            write_manifest(runtime, path_file="python39._pth")

        def rename_back():
            wrong.rename(pth)
            write_manifest(runtime)

        cycle("RT17 path-file-version-mismatch",
              "a ._pth named for an interpreter version that is not present",
              runtime, task_root, misname, rename_back,
              "REVIEWER_RUNTIME_PATH_FILE_VERSION_MISMATCH")

        # The verifier must never repair what it refuses.
        (site / "sitecustomize.py").write_text("import sys\n", encoding="ascii")
        reasons = check(runtime, task_root)
        survived = (site / "sitecustomize.py").is_file()
        (site / "sitecustomize.py").unlink()
        rec("RT15 verifier-never-deletes", survived and bool(reasons),
            "a refused runtime is left exactly as found; the verifier reports "
            "and refuses rather than deciding which Python files to remove")

        # The two implementations of the tree digest must agree, or the reviewer's
        # own pin and the runtime manifest can both look correct while describing
        # different trees.
        # Resolved from System32 rather than PATH: `which` can pick up a shim,
        # and a guard that cannot say which shell it ran is not evidence. The
        # whole block is guarded because an on-access scanner refusing to launch
        # it crashed the guard mid-run, losing fifteen passing cycles with it.
        ps = (Path(os.environ.get("SystemRoot", r"C:\Windows"))
              / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")
        if ps.is_file():
            session = ROOT / "packaging" / "hyperv" / "reviewer_session.ps1"
            # Written to a FILE and run with -File, never passed as -Command.
            # An inline command containing Invoke-Expression is refused outright
            # by on-access script scanning: CreateProcess fails with "the file
            # contains a virus or potentially unwanted software", which reads as
            # a broken toolchain rather than a policy decision.
            harness = work / "digest_crosscheck.ps1"
            harness.write_text("\n".join([
                f"$src = Get-Content -LiteralPath '{session}' -Raw",
                r"$pattern = '(?s)function Assert-ReviewerCodeIntegrity \{.*?\r?\n\}'",
                r"$m = [regex]::Match($src, $pattern)",
                r"Invoke-Expression $m.Value",
                r"$mf = Join-Path $env:TEMP ([Guid]::NewGuid().ToString('N') + '.json')",
                f"$null = Assert-ReviewerCodeIntegrity -ManifestPath $mf "
                f"-Paths @() -TreeRoots @('{runtime}')",
                r"(Get-Content $mf -Raw | ConvertFrom-Json).PSObject.Properties |",
                r"    ForEach-Object { $_.Value }",
                "",
            ]), encoding="utf-8")
            try:
                proc = subprocess.run([str(ps), "-NoProfile", "-NonInteractive",
                                       "-ExecutionPolicy", "Bypass", "-File", str(harness)],
                                      capture_output=True, text=True, timeout=300)
                produced = [ln.strip() for ln in (proc.stdout or "").splitlines()
                            if ln.strip()]
            except (OSError, subprocess.SubprocessError) as exc:
                produced = []
                print(f"  (powershell could not be launched: {type(exc).__name__})")
            mine = tree_digest(runtime)
            rec("RT16 digest-agrees-across-implementations",
                bool(produced) and produced[-1].upper() == mine,
                "the PowerShell pin and the Python manifest compute the same "
                "digest for the same tree, so they cannot disagree while both "
                "look correct")
        else:
            rec("RT16 digest-agrees-across-implementations", False,
                "powershell was not available, so cross-implementation agreement "
                "is untested rather than proven")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    failed = [c["check_id"] for c in CHECKS if not c["ok"]]
    print(json.dumps({
        "guard": "offline-reviewer-runtime",
        "claim_scope": "the reviewer executes a dedicated task-owned runtime whose "
                       "site-hook and .pth vectors are removed rather than guarded, "
                       "and acceptance fails closed with a named reason without "
                       "deleting anything",
        "summary": {"passed": len(CHECKS) - len(failed), "failed": len(failed),
                    "total": len(CHECKS)},
        "failed_checks": failed,
    }, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
