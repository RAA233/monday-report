"""C2 -- generate and verify the git-free source-export manifest.

THE ONE RULE THAT MAKES THIS TERMINATE
--------------------------------------
The integrity decision's only operands are (a) the bytes on disk and (b) the
pinned manifest. Git semantics -- config includes, attributesFile, gitdir
pointers, alternates, submodule configs, refs/replace, hooks, commit-graph,
per-directory .gitignore -- have NO operand in the decision, so the unbounded
".git internals" class found across six review rounds simply has nothing to
attach to.

* The manifest is computed from FILE BYTES ON DISK -- explicitly never via
  ``git archive``, ``git hash-object``, or anything that reads a repository.
  Git may appear here ONLY as operator-recorded provenance strings
  (``source_commit`` / ``source_tree``), which are carried as data and never
  computed inside this module.
* The presence of ANY ``.git`` path component, any file beginning with
  ``gitdir:``, or any reparse point anywhere in the export is itself a
  refusal -- a shape check, not a content scan.
* Verification re-hashes the actual bytes of the tree being verified and
  requires an EXACT file-set match (no extras, no missing). A missing or
  unreadable manifest is a refusal, never a skip.

The reviewer-side PowerShell twin is ``packaging/hyperv/lib/export_verify.ps1``;
the two must agree byte-for-byte on the canonical root-hash computation:
relative paths are forward-slash, ASCII-only, ordinal-sorted; the root hash is
SHA-256 over the canonical JSON object
``{"files": {...}, "source_commit": "...", "source_tree": "..."}`` serialized
with sorted keys and ``(",", ":")`` separators.

Exit codes: 0 verified/generated, 2 refusal (named reason on stdout).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

MANIFEST_NAME = "source-export-manifest.v1.json"
MANIFEST_SCHEMA = "monday-report-source-export-manifest.v1"

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_HEX40 = frozenset("0123456789abcdef")


class ExportRefusal(RuntimeError):
    """Any C2 refusal. Raised, not returned, so callers cannot fail open."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_reparse(path: Path) -> bool:
    try:
        attributes = os.lstat(str(path)).st_file_attributes
    except (OSError, AttributeError, ValueError) as exc:
        raise ExportRefusal(f"EXPORT_ENTRY_UNREADABLE: {path} :: {exc}") from exc
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _refuse_shape(root: Path, rel: str, name: str, path: Path) -> None:
    """The O(1) shape refusals, applied to every entry as it is walked.

    CASE-INSENSITIVE, deliberately. Windows paths are case-insensitive, so a
    directory created as ``.GIT`` IS ``.git`` to every tool including git
    itself. A case-sensitive test keyed the refusal to fewer operands than the
    damage: an EMPTY ``.GIT`` tree carries no files, so the file-set comparison
    could not catch it incidentally either, and both twins verified an export
    containing a git directory. The rule is "any .git shape, any spelling".
    """

    if name.lower() == ".git":
        raise ExportRefusal(f"EXPORT_CONTAINS_GIT_SHAPE: {rel or name} under {root}")
    if _is_reparse(path):
        raise ExportRefusal(f"EXPORT_CONTAINS_REPARSE_POINT: {rel or name} under {root}")


def walk_export(root: Path) -> dict[str, Path]:
    """Every file in the export keyed by forward-slash relative path.

    Applies the shape refusals to EVERY directory and file encountered:
    a ``.git`` component at any depth, a reparse point anywhere, a file whose
    first bytes are ``gitdir:``, or a non-ASCII relative path all refuse.
    """

    if not root.is_dir():
        raise ExportRefusal(f"EXPORT_ROOT_ABSENT: {root}")
    if _is_reparse(root):
        raise ExportRefusal(f"EXPORT_CONTAINS_REPARSE_POINT: <root> {root}")

    files: dict[str, Path] = {}
    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError as exc:
            raise ExportRefusal(f"EXPORT_ENTRY_UNREADABLE: {current} :: {exc}") from exc
        for entry in entries:
            rel = entry.relative_to(root).as_posix()
            _refuse_shape(root, rel, entry.name, entry)
            try:
                rel.encode("ascii")
            except UnicodeEncodeError as exc:
                raise ExportRefusal(f"EXPORT_PATH_NOT_ASCII: {rel!r}") from exc
            if entry.is_dir():
                stack.append(entry)
                continue
            if entry.name == MANIFEST_NAME and entry.parent == root:
                continue  # the manifest travels beside the tree it describes
            with entry.open("rb") as handle:
                head = handle.read(7)
            if head.lower() == b"gitdir:":
                raise ExportRefusal(f"EXPORT_CONTAINS_GITDIR_POINTER: {rel}")
            files[rel] = entry
    return files


def root_hash(files: dict[str, str], source_commit: str, source_tree: str) -> str:
    canonical = json.dumps(
        {"files": files, "source_commit": source_commit, "source_tree": source_tree},
        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def generate(export_root: Path, *, source_commit: str, source_tree: str) -> dict:
    """Hash the export from DISK BYTES and write the manifest beside it.

    ``source_commit``/``source_tree`` are operator-recorded provenance data --
    validated for shape, carried verbatim, never computed here.
    """

    for label, value in (("source_commit", source_commit), ("source_tree", source_tree)):
        if len(value) != 40 or not set(value) <= _HEX40:
            raise ExportRefusal(f"EXPORT_PROVENANCE_MALFORMED: {label} must be 40 lowercase hex")

    hashes = {rel: _sha256_file(path) for rel, path in walk_export(export_root).items()}
    if not hashes:
        raise ExportRefusal(f"EXPORT_EMPTY: {export_root}")
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "file_count": len(hashes),
        "files": hashes,
        "root_hash": root_hash(hashes, source_commit, source_tree),
    }
    (export_root / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="ascii")
    return manifest


def load_manifest(manifest_path: Path) -> dict:
    """A missing or unreadable manifest is a REFUSAL, never a skip."""

    if not manifest_path.is_file():
        raise ExportRefusal(f"EXPORT_MANIFEST_MISSING: {manifest_path}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise ExportRefusal(f"EXPORT_MANIFEST_UNREADABLE: {manifest_path} :: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != MANIFEST_SCHEMA:
        raise ExportRefusal(f"EXPORT_MANIFEST_UNREADABLE: {manifest_path} :: wrong schema")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ExportRefusal(f"EXPORT_MANIFEST_UNREADABLE: {manifest_path} :: no files map")
    return manifest


def verify(export_root: Path, *, manifest_path: Path | None = None,
           expected_root_hash: str = "") -> dict:
    """Re-hash the ACTUAL BYTES of ``export_root`` and compare to the manifest.

    Refuses on: any shape violation (walked first), a missing/unreadable
    manifest, any extra file, any missing file, any hash mismatch, an internal
    root-hash mismatch, and -- when ``expected_root_hash`` is supplied (the
    reviewer's pinned value) -- a pin mismatch.
    """

    manifest_path = manifest_path or (export_root / MANIFEST_NAME)
    manifest = load_manifest(manifest_path)
    on_disk = walk_export(export_root)

    declared = manifest["files"]
    extra = sorted(set(on_disk) - set(declared))
    if extra:
        raise ExportRefusal(f"EXPORT_UNDECLARED_FILE: {extra[0]} (+{len(extra) - 1} more)")
    missing = sorted(set(declared) - set(on_disk))
    if missing:
        raise ExportRefusal(f"EXPORT_DECLARED_FILE_ABSENT: {missing[0]} (+{len(missing) - 1} more)")

    for rel, expected in sorted(declared.items()):
        actual = _sha256_file(on_disk[rel])
        if actual != expected:
            raise ExportRefusal(f"EXPORT_BYTES_DIFFER: {rel}")

    recomputed = root_hash(declared, str(manifest.get("source_commit", "")),
                           str(manifest.get("source_tree", "")))
    if recomputed != str(manifest.get("root_hash", "")):
        raise ExportRefusal("EXPORT_ROOT_HASH_MISMATCH: manifest disagrees with itself")
    if expected_root_hash and recomputed != expected_root_hash.lower():
        raise ExportRefusal("EXPORT_PIN_MISMATCH: manifest root hash does not match the "
                            "reviewer's pinned trust root")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="offline_export_manifest", description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)

    gen = sub.add_parser("generate", help="hash an export tree and write its manifest")
    gen.add_argument("--export-root", required=True)
    gen.add_argument("--source-commit", required=True,
                     help="operator-recorded provenance (data, never computed here)")
    gen.add_argument("--source-tree", required=True)

    ver = sub.add_parser("verify", help="re-hash an export tree against its manifest")
    ver.add_argument("--export-root", required=True)
    ver.add_argument("--manifest", default="")
    ver.add_argument("--expected-root-hash", default="")

    args = parser.parse_args(argv)
    try:
        if args.action == "generate":
            manifest = generate(Path(args.export_root),
                                source_commit=args.source_commit,
                                source_tree=args.source_tree)
            print(json.dumps({"generated": True, "file_count": manifest["file_count"],
                              "root_hash": manifest["root_hash"]}, indent=2))
        else:
            manifest = verify(Path(args.export_root),
                              manifest_path=Path(args.manifest) if args.manifest else None,
                              expected_root_hash=args.expected_root_hash)
            print(json.dumps({"verified": True, "file_count": manifest["file_count"],
                              "root_hash": manifest["root_hash"],
                              "source_commit": manifest["source_commit"],
                              "source_tree": manifest["source_tree"]}, indent=2))
    except ExportRefusal as exc:
        print(json.dumps({"refused": str(exc)}, indent=2))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
