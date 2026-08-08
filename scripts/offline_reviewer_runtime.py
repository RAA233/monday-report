"""Build and verify the DEDICATED, task-owned Python runtime the reviewer runs.

WHY THIS EXISTS
---------------
The reviewer was pinned to the author's own development interpreter. Classifying
it before doing anything to it is what stopped a much worse outcome: it is a
general per-user installation -- registered in the user's Python registry key, on
the persistent PATH, 307 installed distributions, 119 console-script shims, four
dependent virtual environments, 73,711 files, 3.13 GiB. Hardening that tree in
place would have taken ownership of the author's whole Python and broken every
one of those, for a certification run.

So the runtime moves instead of the ACL. A small dedicated tree is assembled
under the task-owned root from the local installation -- no download, no network,
nothing fetched -- containing the interpreter core, the standard library, and
exactly the distributions the reviewer workflow imports.

THE CONTROL THAT MATTERS IS NOT THE ACL
---------------------------------------
A ``._pth`` file beside python.exe makes CPython bypass its normal path
calculation, ignore PYTHONPATH, and skip importing ``site`` entirely unless a
line says otherwise. No ``site`` means no sitecustomize, no usercustomize, and no
``.pth`` processing at all. The C1 injection route stops existing rather than
being locked behind permissions -- and it was measured both ways: with the file
the planted hooks are inert, and with it removed the same hooks fire.

The ACL still matters, as depth. But a control that removes the mechanism is
worth more than one that guards it.

NOTHING HERE DELETES ANYTHING FROM A SHARED INSTALLATION. Verification reports
named reasons and refuses; it never "cleans up" an interpreter, and it never asks
an operator to decide which Python files are safe to remove.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

TASK_ROOT = Path("C:/mr-hv")
RUNTIME_ROOT = TASK_ROOT / "reviewer-runtime"
MANIFEST_NAME = "reviewer-runtime-manifest.v1.json"
MANIFEST_SCHEMA = "reviewer-runtime-manifest.v1"

# Exactly what the reviewer workflow imports, plus what those need in turn.
# cryptography for Ed25519; cffi/_cffi_backend/pycparser and typing_extensions
# are its declared runtime requirements on this interpreter version.
REQUIRED_DISTRIBUTIONS = (
    "cryptography", "cffi", "_cffi_backend", "pycparser", "typing_extensions",
)

# Imports proven to work in the built runtime before it is accepted. A runtime
# that verifies structurally but cannot sign anything is not a working runtime.
REQUIRED_IMPORTS = (
    "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey",
    "import json, hashlib, subprocess, ctypes, urllib.request",
)

# The standard library minus the parts the reviewer never touches. Trimming is
# not a security control -- it keeps the hashed surface small enough to reason
# about, and every excluded name is inert for this workflow.
_LIB_SKIP = frozenset({"site-packages", "test", "__pycache__", "idlelib",
                       "turtledemo", "tkinter"})

# The only path entries the runtime is allowed to declare. `import site` is
# deliberately absent, and its presence is a refusal reason rather than a
# preference.
EXPECTED_PTH_LINES = ("Lib", "DLLs", "Lib\\site-packages")

# Names that execute at interpreter start on a stock layout. None may exist in
# the dedicated runtime -- not because they would run (the ._pth stops that) but
# because their presence means something put them there.
_SITE_HOOKS = frozenset({"sitecustomize.py", "usercustomize.py"})


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def tree_digest(root: Path, *, exclude: frozenset[str] = frozenset()) -> str:
    """Deterministic recursive digest of a directory.

    Byte-identical to the PowerShell computation in reviewer_session.ps1, so the
    reviewer's own pin and this module cannot disagree about what is in the tree
    while both look correct. Lower-cased relative paths joined to their
    upper-case hashes, ORDINAL sort, LF separators, UTF-8, SHA-256.

    The ordinal sort is load-bearing rather than tidy: PowerShell's default
    Sort-Object is culture-aware and orders '-', '_' and '.' differently, and a
    real CPython runtime ships both api-ms-win-*.dll and api_ms_*.dll. The claim
    of byte-identity in this docstring was false until the two were made to sort
    the same way, and the cross-check that was supposed to catch it used a
    fixture with no such pair of names.
    """

    root = root.resolve()
    entries = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = str(path.relative_to(root))
        if rel in exclude:
            continue
        entries.append(f"{rel.lower()}:{_sha256_file(path)}")
    # Sort the ASSEMBLED entries, ordinally, exactly as the PowerShell side
    # does. Sorting the source paths instead left the two implementations free
    # to disagree on any name where a culture-aware comparison differs from an
    # ordinal one -- which a real CPython tree contains, in api-ms-win-*.dll.
    entries.sort()
    joined = "\n".join(entries)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest().upper()


def interpreter_version(exe: Path) -> str:
    """The version the runtime actually reports, not the one it was built from."""

    try:
        proc = subprocess.run([str(exe), "-I", "-c",
                               "import sys; print('.'.join(map(str, sys.version_info[:3])))"],
                              capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return ""
    if proc.returncode != 0:
        return ""
    return (proc.stdout or "").strip()


def shared_installation_reasons(root: Path) -> list[str]:
    """Is this tree a general installation that other software depends on?

    Refusing to touch a shared interpreter has to be decided from evidence, not
    from the path looking task-owned. These are the signals that distinguished
    the author's development Python from a dedicated runtime when the two were
    compared directly.
    """

    reasons: list[str] = []
    root = root.resolve()

    def _under(child: str, parent: Path) -> bool:
        try:
            Path(child).resolve().relative_to(parent)
            return True
        except (ValueError, OSError):
            return False

    try:
        import winreg  # noqa: PLC0415 -- Windows-only, imported where it is used

        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                base = winreg.OpenKey(hive, r"Software\Python\PythonCore")
            except OSError:
                continue
            with base:
                index = 0
                while True:
                    try:
                        name = winreg.EnumKey(base, index)
                    except OSError:
                        break
                    index += 1
                    try:
                        with winreg.OpenKey(base, name + r"\InstallPath") as key:
                            value = winreg.QueryValueEx(key, "")[0]
                    except OSError:
                        continue
                    if value and _under(value, root):
                        reasons.append("REVIEWER_RUNTIME_REGISTERED_INSTALLATION")
    except ImportError:
        pass

    for segment in (os.environ.get("PATH") or "").split(os.pathsep):
        if segment and _under(segment, root):
            reasons.append("REVIEWER_RUNTIME_ON_SEARCH_PATH")
            break

    site_packages = root / "Lib" / "site-packages"
    if site_packages.is_dir():
        installed = [p for p in site_packages.iterdir() if p.name.endswith(".dist-info")]
        if len(installed) > len(REQUIRED_DISTRIBUTIONS) + 2:
            reasons.append("REVIEWER_RUNTIME_UNEXPECTED_DISTRIBUTIONS")

    scripts = root / "Scripts"
    if scripts.is_dir() and any(p.suffix.lower() == ".exe" for p in scripts.iterdir()):
        reasons.append("REVIEWER_RUNTIME_CONSOLE_SCRIPT_SHIMS")

    return sorted(set(reasons))


def build(source_root: Path, dest_root: Path) -> dict:
    """Assemble the dedicated runtime from an already-present local installation.

    No network access of any kind. The source is the interpreter that already
    runs on this host, and only the pieces the reviewer needs are copied.
    """

    source_root = source_root.resolve()
    if dest_root.exists():
        shutil.rmtree(dest_root)
    (dest_root / "Lib" / "site-packages").mkdir(parents=True)

    for entry in sorted(os.listdir(source_root)):
        candidate = source_root / entry
        low = entry.lower()
        if not candidate.is_file():
            continue
        if low.startswith("pythonw"):
            continue           # no windowed launcher: the reviewer runs console
        if low.endswith((".exe", ".dll")):
            shutil.copy2(candidate, dest_root / entry)

    shutil.copytree(source_root / "DLLs", dest_root / "DLLs")

    for entry in sorted(os.listdir(source_root / "Lib")):
        if entry in _LIB_SKIP:
            continue
        src = source_root / "Lib" / entry
        dst = dest_root / "Lib" / entry
        if src.is_dir():
            shutil.copytree(src, dst,
                            ignore=shutil.ignore_patterns("__pycache__", "test", "tests"))
        else:
            shutil.copy2(src, dst)

    site_src = source_root / "Lib" / "site-packages"
    site_dst = dest_root / "Lib" / "site-packages"
    copied: list[str] = []
    missing: list[str] = []
    for dist in REQUIRED_DISTRIBUTIONS:
        stem = dist.lower().replace("-", "_")
        found = False
        for entry in sorted(os.listdir(site_src)):
            low = entry.lower()
            if low == stem or low.startswith(stem + "-") or low.startswith(stem + "."):
                src = site_src / entry
                dst = site_dst / entry
                if src.is_dir():
                    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__"))
                else:
                    shutil.copy2(src, dst)
                copied.append(entry)
                found = True
        if not found:
            missing.append(dist)
    if missing:
        raise SystemExit("REVIEWER_RUNTIME_MISSING_DEPENDENCY: " + ", ".join(missing))

    # Derived from the COPIED runtime's own core DLL, not from the interpreter
    # running this script. A `._pth` named for the wrong version is silently
    # ignored, which would leave the runtime on the default path calculation --
    # site imported, hooks live -- while every structural check still passed.
    # Two or more digits: python3.dll is the stable-ABI forwarder and carries no
    # minor version, so a looser glob matched both and stalled the build.
    import re  # noqa: PLC0415 -- one use, kept next to the pattern it serves

    cores = sorted(p.name for p in dest_root.glob("python*.dll")
                   if re.fullmatch(r"python\d{2,}\.dll", p.name, re.IGNORECASE))
    if len(cores) != 1:
        raise SystemExit("REVIEWER_RUNTIME_CORE_DLL_AMBIGUOUS: " + ", ".join(cores))
    version = cores[0][len("python"):-len(".dll")]
    (dest_root / f"python{version}._pth").write_text(
        "\n".join(EXPECTED_PTH_LINES) + "\n", encoding="ascii")

    exe = dest_root / "python.exe"
    reported = interpreter_version(exe)
    for statement in REQUIRED_IMPORTS:
        proc = subprocess.run([str(exe), "-I", "-c", statement],
                              capture_output=True, text=True, timeout=180)
        if proc.returncode != 0:
            raise SystemExit("REVIEWER_RUNTIME_IMPORT_FAILED: " + statement)

    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "interpreter_version": reported,
        "path_file": f"python{version}._pth",
        "required_distributions": list(REQUIRED_DISTRIBUTIONS),
        "distribution_entries": sorted(copied),
        "tree_digest": tree_digest(dest_root, exclude=frozenset({MANIFEST_NAME})),
    }
    (dest_root / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def site_is_disabled(exe: Path) -> bool:
    """Did the runtime actually start without importing ``site``?

    The whole design rests on this being true, and every other check infers it
    from a filename. This asks the interpreter.
    """

    try:
        proc = subprocess.run(
            [str(exe), "-I", "-c",
             "import sys; print('site' not in sys.modules and sys.flags.no_site == 1)"],
            capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return False
    # The exit code counts. A shim that printed "True" and exited 9 satisfied
    # the old comparison, which is to say the check trusted a string from a
    # process it had not established was healthy.
    if proc.returncode != 0:
        return False
    return (proc.stdout or "").strip() == "True"


def reparse_points_within(root: Path) -> list:
    """Any reparse point among the descendants of a tree that must be pinned."""

    found = []
    try:
        stack = [root]
        while stack:
            current = stack.pop()
            for entry in current.iterdir():
                try:
                    attrs = os.lstat(str(entry)).st_file_attributes
                except (OSError, AttributeError, ValueError):
                    # An entry this process cannot stat is an entry it cannot
                    # vouch for, inside a function whose whole job is to say
                    # there are no surprises here. Skipping it failed open in
                    # the middle of a fail-closed check.
                    found.append("REVIEWER_RUNTIME_UNREADABLE")
                    return found
                if attrs & 0x400:            # FILE_ATTRIBUTE_REPARSE_POINT
                    found.append("REVIEWER_RUNTIME_REPARSE_ESCAPE")
                    return found
                if attrs & 0x10:             # FILE_ATTRIBUTE_DIRECTORY
                    stack.append(entry)
    except OSError:
        found.append("REVIEWER_RUNTIME_UNREADABLE")
    return found


def verify(candidate_exe: Path, *, task_root: Path = TASK_ROOT,
           runtime_root: Path = RUNTIME_ROOT, run_probe: bool = True) -> list[str]:
    """Named, fail-closed reasons why this interpreter must not be accepted.

    Every check answers "may the operator lock and pin THIS tree", and an empty
    list is the only acceptance. The seams exist so the guard can drive the same
    code against disposable fixtures; the operator path never passes them.
    """

    reasons: list[str] = []
    raw = str(candidate_exe)

    # Traversal is judged on the string BEFORE resolution: a path that resolves
    # into the task root having travelled outside it is still a path someone
    # constructed to look local.
    if ".." in Path(raw).parts:
        reasons.append("REVIEWER_RUNTIME_PATH_TRAVERSAL")

    if not candidate_exe.exists():
        reasons.append("REVIEWER_RUNTIME_ABSENT")
        return sorted(set(reasons))

    # A reparse point anywhere on the way in is an escape, and it has to be
    # looked for BEFORE resolution.
    #
    # The previous version called .resolve() first. On Windows that collapses a
    # junction and hands back the TARGET, so the walk then inspected the
    # target's ancestors -- which contain no reparse point -- and a runtime
    # exposed through `mklink /J` was accepted. `stat()` follows the link too,
    # so the reparse attribute was never visible either; only `lstat()` sees it.
    #
    # This is not academic. `icacls /T` does NOT traverse a junction, so the
    # hardening step would report "no author-user ACE" while the real files
    # stayed author-writable, and `takeown /R` DOES traverse, so the author
    # could aim a recursive ownership seizure at any tree it chose.
    probe = candidate_exe
    while True:
        try:
            if os.lstat(str(probe)).st_file_attributes & 0x400:  # REPARSE_POINT
                reasons.append("REVIEWER_RUNTIME_REPARSE_ESCAPE")
                break
        except (OSError, AttributeError, ValueError):
            pass
        if probe.parent == probe:
            break
        probe = probe.parent

    resolved = candidate_exe.resolve()
    root = resolved.parent

    # Belt and braces: the literal path must already BE its resolved form. Any
    # link, 8.3 short name or drive substitution shows up as a difference here
    # even if the attribute walk above misses the mechanism.
    if os.path.normcase(str(candidate_exe)) != os.path.normcase(str(resolved)):
        reasons.append("REVIEWER_RUNTIME_REPARSE_ESCAPE")

    try:
        resolved.relative_to(task_root.resolve())
    except (ValueError, OSError):
        reasons.append("REVIEWER_RUNTIME_OUTSIDE_TASK_ROOT")
    else:
        try:
            resolved.relative_to(runtime_root.resolve())
        except (ValueError, OSError):
            reasons.append("REVIEWER_RUNTIME_OUTSIDE_RUNTIME_ROOT")

    # DESCENDANTS TOO.
    #
    # The walk above covers the path INTO the tree. It said nothing about links
    # inside it, and that is the more useful attack: a junction at
    # Lib\site-packages points everything the interpreter imports at a directory
    # the author still owns. `icacls /T` does not traverse it, so hardening
    # reports success over bytes it never touched; and the two digest
    # implementations disagree about it -- PowerShell's Get-ChildItem -Recurse
    # does not descend a junction while Path.rglob does -- so the reviewer's own
    # pin verified a tree whose contents had been swapped.
    #
    # Refused outright rather than followed or skipped. A pinned tree containing
    # a link is not a tree anyone can reason about.
    reasons.extend(reparse_points_within(root))

    reasons.extend(shared_installation_reasons(root))

    manifest_path = root / MANIFEST_NAME
    if not manifest_path.is_file():
        reasons.append("REVIEWER_RUNTIME_MANIFEST_ABSENT")
        manifest = {}
    else:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            reasons.append("REVIEWER_RUNTIME_MANIFEST_UNREADABLE")
            manifest = {}
        # Valid JSON is not necessarily an object. A manifest of `[]`, `null`,
        # `0` or `"hello"` raised AttributeError straight out of this function,
        # which escapes the named-reason contract and crashed the isolation
        # guard mid-run rather than refusing.
        if not isinstance(manifest, dict):
            reasons.append("REVIEWER_RUNTIME_MANIFEST_UNREADABLE")
            manifest = {}

    # The path file, its NAME, and what it declares.
    #
    # CPython only honours a `._pth` named for the interpreter it is sitting
    # beside. A file called python39._pth next to python310.dll is ignored
    # completely -- site is imported, sitecustomize runs, PYTHONPATH is honoured
    # -- and the previous check, which read the name out of the manifest and
    # only confirmed the file existed, accepted exactly that. The one control
    # the whole design rests on could be present, correct in content, and dead.
    expected_pth = ""
    cores = sorted(entry.name for entry in root.glob("python*.dll")
                   if re.fullmatch(r"python\d{2,}\.dll", entry.name, re.IGNORECASE))
    if len(cores) == 1:
        expected_pth = "python" + cores[0][len("python"):-len(".dll")] + "._pth"
    else:
        reasons.append("REVIEWER_RUNTIME_CORE_DLL_AMBIGUOUS")

    declared = str(manifest.get("path_file", "") or "")
    if expected_pth and declared.lower() != expected_pth.lower():
        reasons.append("REVIEWER_RUNTIME_PATH_FILE_VERSION_MISMATCH")
    pth = root / expected_pth if expected_pth else (root / declared if declared else None)
    if not pth or not pth.is_file():
        reasons.append("REVIEWER_RUNTIME_PATH_FILE_MISSING")
    else:
        # utf-8-sig, not ascii-with-errors-ignored. CPython reads a ._pth as
        # UTF-8, so a byte-order mark becomes part of the FIRST path entry;
        # dropping it silently here would have compared a line CPython never
        # sees against the expected set and called them equal.
        raw_pth = pth.read_text(encoding="utf-8-sig", errors="strict")
        lines = [ln.strip() for ln in raw_pth.splitlines()]
        if pth.read_bytes().startswith(b"\xef\xbb\xbf"):
            reasons.append("REVIEWER_RUNTIME_PATH_FILE_HAS_BOM")
        lines = [ln for ln in lines if ln and not ln.startswith("#")]
        if any(ln.lower() == "import site" for ln in lines):
            reasons.append("REVIEWER_RUNTIME_PATH_FILE_ENABLES_SITE")
        if [ln.lower() for ln in lines] != [ln.lower() for ln in EXPECTED_PTH_LINES]:
            reasons.append("REVIEWER_RUNTIME_PATH_FILE_UNEXPECTED_ENTRIES")

    # Hooks and .pth inputs. Reported, never removed: deleting Python files on
    # someone's behalf is exactly the ad-hoc judgement this must not require.
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        name = path.name.lower()
        if name in _SITE_HOOKS:
            reasons.append("REVIEWER_RUNTIME_UNEXPECTED_SITE_HOOK")
        elif name.endswith(".pth"):
            reasons.append("REVIEWER_RUNTIME_UNEXPECTED_PTH_INPUT")

    site_packages = root / "Lib" / "site-packages"
    for dist in REQUIRED_DISTRIBUTIONS:
        stem = dist.lower().replace("-", "_")
        if not site_packages.is_dir() or not any(
                e.name.lower() == stem or e.name.lower().startswith(stem + "-")
                or e.name.lower().startswith(stem + ".")
                for e in site_packages.iterdir()):
            reasons.append("REVIEWER_RUNTIME_MISSING_DEPENDENCY")
            break

    # A MISSING FIELD IS A REFUSAL, not a skipped check.
    #
    # This read the digest and only compared when it was non-empty, so a
    # manifest present with that one field blanked disabled the only whole-tree
    # comparison and returned clean over a tampered interpreter -- while a
    # manifest that was absent entirely produced a named refusal. The weaker
    # attack was the one that got through.
    recorded = str(manifest.get("tree_digest", "") or "")
    if manifest and (not recorded
                     or not str(manifest.get("interpreter_version", "") or "")):
        reasons.append("REVIEWER_RUNTIME_MANIFEST_INCOMPLETE")
    if recorded:
        # Covers the interpreter executable, every adjacent DLL, every extension
        # module and every stdlib file in one comparison -- separate checks for
        # "interpreter modified" and "module modified" would each have been a
        # sample of the thing this measures whole.
        if tree_digest(root, exclude=frozenset({MANIFEST_NAME})) != recorded:
            reasons.append("REVIEWER_RUNTIME_TREE_DIGEST_MISMATCH")

    if run_probe:
        expected_version = str(manifest.get("interpreter_version", "") or "")
        reported = interpreter_version(resolved)
        if not reported:
            reasons.append("REVIEWER_RUNTIME_INTERPRETER_UNRUNNABLE")
        elif expected_version and reported != expected_version:
            reasons.append("REVIEWER_RUNTIME_IDENTITY_MISMATCH")

        # MEASURE the control instead of inferring it from a filename.
        #
        # The expected ._pth name is derived from whatever python*.dll sits in
        # the directory, but CPython resolves the file against the DLL it
        # actually LOADS -- which can come from elsewhere. Renaming both the DLL
        # and the ._pth to a version that is not really there was accepted. So
        # the built runtime is asked directly whether site was imported.
        if not site_is_disabled(resolved):
            reasons.append("REVIEWER_RUNTIME_SITE_NOT_DISABLED")

    return sorted(set(reasons))


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", required=True, choices=("build", "verify", "digest"))
    parser.add_argument("--source-interpreter", default="")
    parser.add_argument("--runtime-root", default=str(RUNTIME_ROOT))
    args = parser.parse_args()

    root = Path(args.runtime_root)
    if args.action == "build":
        if not args.source_interpreter:
            print(json.dumps({"reasons": ["REVIEWER_RUNTIME_NO_SOURCE"]}))
            return 2
        source = Path(args.source_interpreter)
        source_root = source.parent if source.is_file() else source
        manifest = build(source_root, root)
        print(json.dumps(manifest, indent=2))
        return 0

    if args.action == "digest":
        print(tree_digest(root, exclude=frozenset({MANIFEST_NAME})))
        return 0

    reasons = verify(root / "python.exe", runtime_root=root)
    print(json.dumps({"accepted": not reasons, "reasons": reasons}, indent=2))
    return 0 if not reasons else 3


if __name__ == "__main__":
    raise SystemExit(main())
