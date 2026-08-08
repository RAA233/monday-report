"""Frozen manifest pinning the offline evidence contract into ``audit:all``.

WHY A MANIFEST AND NOT JUST ANOTHER STEP
-----------------------------------------
An independent review reproduced this defect: ``audit:all`` expanded to 70 steps
containing zero authoritative offline validation, and its membership was
INVARIANT under removal of the offline evidence command (70 steps with it, 70
without). The real content of that finding is not "a step is missing" -- it is
"MEMBERSHIP IS UNPINNED". Adding one more member pins nothing, and a meta-guard
that lives inside the step it guards is the same defect with one extra hop:
delete both entries in a single commit and nothing fails.

So membership is pinned HERE, in tracked source that shows up in a diff, and
asserted REDUNDANTLY from a guard that is not the offline guard
(``audit_harness_guard``, step 1 of ``audit:all``, whose removal would also drop
several unrelated checks and is therefore a conspicuous edit).

WHAT IS AND IS NOT CLAIMED
--------------------------
Removal is no longer a one-line invisible edit: it requires coordinated edits to
``package.json``, to this manifest, and to ``audit_harness_guard``. That is
deterrence, NOT impossibility -- the same register the artifact already uses for
``anti_tamper_is_deterrence_not_absolute``. Do not write that removal is
impossible.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: The pinned command, its script, and where in the chain it must appear.
#:
#: Position matters. ``audit:all`` is a flat ``&&`` chain that currently stops at
#: a known inherited failure (GA50, and FB00 downstream of it). A step appended
#: after that point would never execute, so its absence would be invisible while
#: ``audit:all`` failed "for the usual reason". The contract must therefore run
#: BEFORE anything that can fail.
CONTRACT_COMMAND = "audit:offline-evidence-contract"
CONTRACT_SCRIPT = "python -I scripts/offline_evidence_contract_guard.py"
MAX_POSITION = 2


#: Guards that must independently assert this membership. Listing them here is
#: what makes a silent single-file removal impossible to hide.
REDUNDANT_ASSERTERS = (
    "scripts/audit_harness_guard.py",
    "scripts/offline_evidence_contract_guard.py",
)

#: Minimum number of checks the contract battery must execute. Outright removal
#: is the LESS likely regression; hollowing is likelier -- the step stays, most
#: rejection cases are deleted, and it still exits 0.
MIN_CONTRACT_CHECKS = 20

#: EVERY offline battery that must be in the chain, not just the first one.
#:
#: The operator-principal battery decides the acceptance predicate itself -- no
#: principal that can write the release tree may hold Administrator -- and it was
#: registered in package.json and referenced by nothing. A command no chain runs
#: is a command whose deletion costs one line and breaks no build, which is the
#: same unpinned-membership finding this manifest exists to answer, one level up.
#:
#: ``min_checks`` and ``pattern`` guard against the likelier regression: the step
#: survives, most of its cases are deleted, and it still exits 0.
PINNED_MEMBERS = (
    {
        "command": CONTRACT_COMMAND,
        "script": CONTRACT_SCRIPT,
        "guard": "scripts/offline_evidence_contract_guard.py",
        "min_checks": MIN_CONTRACT_CHECKS,
        "id_pattern": r"^[A-Z]{2,3}\d+[a-z]?\s",
    },
    {
        "command": "audit:offline-operator-principal",
        "script": "python scripts/offline_operator_principal_guard.py",
        "guard": "scripts/offline_operator_principal_guard.py",
        "min_checks": 35,
        "id_pattern": r"^OP\d+[a-z]?\s",
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

    Counting text let the battery's own documentation restore the floor:
    renaming every recording call and adding a docstring of the same literals
    scored identically to the intact guard. A docstring is an expression
    statement, never a call argument, so it cannot contribute here. Ids rather
    than call sites, because several cases are recorded from a shared mutation
    helper and counting call sites undercounted the battery by a quarter.
    """

    try:
        tree = ast.parse(guard.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return 0
    matcher = re.compile(id_pattern)
    # Docstrings are expression statements; excluding them is what stops the
    # battery's own prose from restoring its floor.
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            first = node.body[0] if node.body else None
            if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)):
                docstrings.add(id(first.value))
    found = set()
    for node in ast.walk(tree):
        # Anywhere but a docstring: several ids reach their recording call
        # through a tuple literal rather than as a direct argument, and counting
        # only direct arguments missed four of them.
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and id(node) not in docstrings and matcher.match(node.value)):
            found.add(node.value.split()[0])
    return len(found)


def audit_all_step_digest() -> str:
    """Digest of the expanded step list. Bound into the reviewer's attestation so
    the chain that ran is the chain that was reviewed."""

    return hashlib.sha256(
        "\n".join(expand_audit_all()).encode("utf-8")).hexdigest()


def verify_membership() -> list[str]:
    """Return every reason the contract is not properly pinned into audit:all."""

    reasons: list[str] = []
    package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    scripts = package.get("scripts", {})

    audit_all = scripts.get("audit:all", "")
    if not audit_all:
        reasons.append("audit:all is absent")
        return reasons
    # `||` would let a step "succeed" by falling through to an alternative.
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
                    f"{command} runs at position {position}, after a step that can "
                    f"fail; it must run within the first {MAX_POSITION + 1}")
        for relative, text in asserter_text.items():
            if script not in text and command not in text:
                reasons.append(f"{relative} no longer asserts {command}")
        guard = ROOT / member["guard"]
        if guard.exists():
            # Hollowing check: the battery must still execute a real number of
            # cases. COUNTED FROM THE PARSE TREE, because a text pattern counts
            # its own documentation -- renaming every rec("OP call and adding a
            # docstring full of the same literals restored the floor exactly.
            recorded = count_recorded_checks(guard, member["id_pattern"])
            if recorded < member["min_checks"]:
                reasons.append(
                    f"{command} declares only {recorded} checks, below the pinned "
                    f"minimum of {member['min_checks']}")
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
