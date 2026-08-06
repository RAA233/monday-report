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

    if scripts.get(CONTRACT_COMMAND) != CONTRACT_SCRIPT:
        reasons.append(f"{CONTRACT_COMMAND} is missing or does not run {CONTRACT_SCRIPT}")

    audit_all = scripts.get("audit:all", "")
    if not audit_all:
        reasons.append("audit:all is absent")
        return reasons
    # `||` would let a step "succeed" by falling through to an alternative.
    if "||" in audit_all:
        reasons.append("audit:all is not a strict && chain")

    steps = expand_audit_all()
    if CONTRACT_SCRIPT not in steps:
        reasons.append("audit:all does not contain the offline evidence contract step")
    else:
        position = steps.index(CONTRACT_SCRIPT)
        if position > MAX_POSITION:
            reasons.append(
                f"the offline evidence contract runs at position {position}, after a step "
                f"that can fail; it must run within the first {MAX_POSITION + 1}")

    for relative in REDUNDANT_ASSERTERS:
        path = ROOT / relative
        if not path.exists():
            reasons.append(f"redundant asserter missing: {relative}")
            continue
        text = path.read_text(encoding="utf-8")
        if CONTRACT_SCRIPT not in text and CONTRACT_COMMAND not in text:
            reasons.append(f"{relative} no longer asserts the contract membership")

    guard = ROOT / "scripts" / "offline_evidence_contract_guard.py"
    if guard.exists():
        # Hollowing check: the battery must still execute a real number of cases.
        recorded = len(re.findall(r'battery\.record\(\s*"|mutation\(\s*"',
                                  guard.read_text(encoding="utf-8")))
        if recorded < MIN_CONTRACT_CHECKS:
            reasons.append(
                f"the contract battery declares only {recorded} checks, below the pinned "
                f"minimum of {MIN_CONTRACT_CHECKS}")
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
