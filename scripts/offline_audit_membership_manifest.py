"""Frozen manifest pinning the Offline Edition v2 effect-proving batteries into
``audit:all``.

WHY A MANIFEST AND NOT JUST MORE STEPS
--------------------------------------
An independent review of the earlier offline package reproduced this defect:
``audit:all`` expanded to a chain containing zero authoritative offline
validation, and its membership was INVARIANT under removal of the offline
command (same step count with it and without). The real finding is not "a step
is missing" -- it is "MEMBERSHIP IS UNPINNED". Adding one more member pins
nothing, and a meta-guard that lives inside the step it guards is the same
defect with one extra hop: delete both entries in a single commit and nothing
fails.

So membership is pinned HERE, in tracked source that shows up in a diff, and
asserted REDUNDANTLY from a guard that is not an offline guard
(``audit_harness_guard``, step 1 of ``audit:all``, whose removal drops several
unrelated checks and is therefore a conspicuous edit).

WHAT V2 PINS
------------
The four EFFECT-PROVING class batteries -- one per terminating trust-boundary
design (C1 natives, C2 export manifest, C3 fresh task root, C4 git-free
boundary). These replace the earlier architecture's giant
enumeration-shaped guards; each proves closure by executing its design against
a seeded-fault corpus and refusing, so pinning them is what keeps a green
``audit:all`` from silently meaning "offline was never validated".

WHAT IS AND IS NOT CLAIMED
--------------------------
Removal is no longer a one-line invisible edit: it requires coordinated edits
to ``package.json``, to this manifest, and to ``audit_harness_guard``. That is
deterrence, NOT impossibility. Do not write that removal is impossible.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: The offline batteries must appear WITHIN THE FIRST N STEPS of audit:all --
#: before any step that could fail for an unrelated reason, so their absence
#: cannot hide behind "audit:all failed for the usual reason". Step 0 is
#: audit_harness_guard (which also runs the redundant membership assertion), so
#: the offline block occupies the steps immediately after it.
MAX_POSITION = 6

#: Guards that must independently assert this membership. Listing them here is
#: what makes a silent single-file removal impossible to hide.
REDUNDANT_ASSERTERS = (
    "scripts/audit_harness_guard.py",
)

#: EVERY offline battery that must be in the chain. Each is an executed,
#: fault-injected, fail-closed guard; ``min_checks``/``id_pattern`` guard the
#: likelier regression (the step survives, most cases are deleted, it exits 0).
PINNED_MEMBERS = (
    {
        "command": "audit:offline-natives-trust",
        "script": "python scripts/offline_natives_trust_guard.py",
        "guard": "scripts/offline_natives_trust_guard.py",
        "min_checks": 10,
        "id_pattern": r"^NT\d+[a-z]?\s",
        "recorder": "rec",
    },
    {
        "command": "audit:offline-export-integrity",
        "script": "python scripts/offline_export_integrity_guard.py",
        "guard": "scripts/offline_export_integrity_guard.py",
        "min_checks": 12,
        "id_pattern": r"^EI\d+[a-z]?\s",
        "recorder": "rec",
    },
    {
        "command": "audit:offline-taskroot-integrity",
        "script": "python scripts/offline_taskroot_integrity_guard.py",
        "guard": "scripts/offline_taskroot_integrity_guard.py",
        "min_checks": 8,
        "id_pattern": r"^TR\d+[a-z]?\s",
        "recorder": "rec",
    },
    {
        "command": "audit:offline-boundary-shape",
        "script": "python scripts/offline_boundary_shape_guard.py",
        "guard": "scripts/offline_boundary_shape_guard.py",
        "min_checks": 8,
        "id_pattern": r"^BS\d+[a-z]?\s",
        "recorder": "rec",
    },
)


def expand_audit_all() -> list[str]:
    scripts = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))["scripts"]

    def expand(name: str, seen: set[str]) -> list[str]:
        if name in seen or name not in scripts:
            return []
        seen.add(name)
        out: list[str] = []
        for raw in re.split(r"&&|\|\|", scripts[name]):
            step = raw.strip()
            if not step:
                continue
            nested = re.fullmatch(r"(?:pnpm|npm|yarn)\s+run\s+([\w:.-]+)", step)
            out.extend(expand(nested.group(1), seen) if nested else [step])
        return out

    return expand("audit:all", set())


def count_recorded_checks(guard: Path, id_pattern: str) -> int:
    """Distinct check ids PASSED TO A CALL, read from the parse tree.

    Counting text let a battery's own documentation restore the floor: renaming
    every recording call and adding a docstring of the same literals scored
    identically to the intact guard. A docstring is an expression statement,
    never a call argument, so it cannot contribute here. Ids rather than call
    sites, because several cases are recorded from shared helpers.
    """

    try:
        tree = ast.parse(guard.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return 0
    matcher = re.compile(id_pattern)
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            first = node.body[0] if node.body else None
            if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)):
                docstrings.add(id(first.value))
    found = set()

    def ids_in(node) -> set:
        collected = set()
        for child in ast.walk(node):
            if (isinstance(child, ast.Constant) and isinstance(child.value, str)
                    and id(child) not in docstrings and matcher.match(child.value)):
                collected.add(child.value.split()[0])
        return collected

    def prune(node):
        """Drop `if <constant-falsy>:` bodies and statements after a return."""

        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.If) and isinstance(child.test, ast.Constant) \
                    and not child.test.value:
                child.body = []
            for attribute in ("body", "orelse", "finalbody"):
                block = getattr(child, attribute, None)
                if not isinstance(block, list):
                    continue
                for index, statement in enumerate(block):
                    if isinstance(statement, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                        del block[index + 1:]
                        break
            prune(child)

    prune(tree)

    functions = {node.name: node for node in tree.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    module_level = [node for node in tree.body if node not in functions.values()]

    def called_names(nodes) -> set:
        names = set()
        for root in nodes:
            for node in ast.walk(root):
                if isinstance(node, ast.Call):
                    func = node.func
                    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                    if name in functions:
                        names.add(name)
                elif isinstance(node, ast.Name) and node.id in functions:
                    names.add(node.id)
        return names

    live = {"main"} & set(functions)
    queue = list(called_names(module_level) | live)
    reached = set()
    while queue:
        name = queue.pop()
        if name in reached:
            continue
        reached.add(name)
        queue.extend(called_names([functions[name]]) - reached)

    searchable = list(module_level) + [functions[name] for name in reached]
    for root in searchable:
        for node in ast.walk(root):
            if not isinstance(node, ast.Call):
                continue
            for argument in list(node.args) + [kw.value for kw in node.keywords]:
                found |= ids_in(argument)
    return len(found)


def recorder_records(guard: Path, name: str) -> bool:
    """Does EVERY definition of the recording function actually record?

    Counting ids that reach a call cannot see a recorder that does nothing with
    them: `def rec(a, b, c): return True` keeps every id in the file and empties
    the results list. Appending a shadowing redefinition is the same edit
    without touching the original, so every definition is checked and any
    rebinding of the name is refused.
    """

    try:
        tree = ast.parse(guard.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return False
    for node in ast.walk(tree):
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets = [node.target]
        for target in targets:
            if isinstance(target, ast.Subscript):
                key = target.slice
                if isinstance(key, ast.Constant) and key.value == name:
                    return False
                continue
            bound = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
            if bound == name:
                return False
        if isinstance(node, ast.Call):
            func = node.func
            called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if called == "setattr" and len(node.args) >= 2:
                key = node.args[1]
                if isinstance(key, ast.Constant) and key.value == name:
                    return False

    definitions = [node for node in ast.walk(tree)
                   if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                   and node.name == name]
    if not definitions:
        return False
    for definition in definitions:
        appends = [child for child in ast.walk(definition)
                   if isinstance(child, ast.Call)
                   and isinstance(child.func, ast.Attribute)
                   and child.func.attr == "append"]
        if not appends:
            return False
    return True


def audit_all_step_digest() -> str:
    """Digest of the expanded step list. Bound into the reviewer's attestation
    so the chain that ran is the chain that was reviewed."""

    return hashlib.sha256("\n".join(expand_audit_all()).encode("utf-8")).hexdigest()


def verify_membership() -> list[str]:
    """Return every reason an offline battery is not properly pinned."""

    reasons: list[str] = []
    package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    scripts = package.get("scripts", {})

    audit_all = scripts.get("audit:all", "")
    if not audit_all:
        reasons.append("audit:all is absent")
        return reasons
    if "||" in audit_all:
        reasons.append("audit:all is not a strict && chain")

    steps = expand_audit_all()
    asserter_text = {}
    for relative in REDUNDANT_ASSERTERS:
        path = ROOT / relative
        if not path.exists():
            reasons.append(f"redundant asserter missing: {relative}")
            continue
        asserter_text[relative] = path.read_text(encoding="utf-8")

    for member in PINNED_MEMBERS:
        command, script = member["command"], member["script"]
        if scripts.get(command) != script:
            reasons.append(f"{command} is missing or does not run {script}")
        if script not in steps:
            reasons.append(f"audit:all does not contain {command}")
        else:
            position = steps.index(script)
            if position > MAX_POSITION:
                reasons.append(
                    f"{command} runs at position {position}, after steps that can fail; "
                    f"it must run within the first {MAX_POSITION + 1}")
        # Redundant assertion: the manifest itself is referenced by name from
        # audit_harness_guard, so a single asserter reference to the manifest
        # module covers all members. Require it explicitly.
        for relative, text in asserter_text.items():
            if "offline_audit_membership_manifest" not in text:
                reasons.append(f"{relative} no longer asserts offline membership")
        guard = ROOT / member["guard"]
        if not guard.exists():
            reasons.append(f"{command} guard missing: {member['guard']}")
            continue
        if not recorder_records(guard, member["recorder"]):
            reasons.append(
                f"{command}'s recording function {member['recorder']}() does not append a "
                f"result, so its check ids reach a call that keeps nothing")
        recorded = count_recorded_checks(guard, member["id_pattern"])
        if recorded < member["min_checks"]:
            reasons.append(
                f"{command} declares only {recorded} checks, below the pinned minimum "
                f"of {member['min_checks']}")
    return reasons


def main() -> int:
    reasons = verify_membership()
    print(json.dumps({
        "guard": "offline-audit-membership",
        "audit_all_step_digest": audit_all_step_digest(),
        "steps": len(expand_audit_all()),
        "reasons": reasons,
    }, indent=2))
    return 0 if not reasons else 1


if __name__ == "__main__":
    raise SystemExit(main())
