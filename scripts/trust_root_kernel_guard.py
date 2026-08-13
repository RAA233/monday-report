"""Trust-Root Kernel acceptance suite (Phase 1).

Every control in this suite certifies its property by EXECUTING a kernel
predicate against a real fixture and comparing the predicate's returned
verdict.  No control asserts on source text, and that is enforced mechanically
rather than by convention:

  * A control is DATA, not code.  It names a scenario, an expected verdict, an
    expected reason, and optionally some expected result fields.  There is no
    place in a control to put an assertion about source, because a control
    cannot contain an expression.

  * Every comparison the runner makes is written into an executed-assertion
    registry together with the sequence number of the invocation record it was
    taken from.  The meta-controls read that registry - a runtime object - and
    fail if any assertion is of a kind other than an executed predicate result,
    if any assertion does not trace back to a real invocation, or if any
    declared control produced no invocation at all.

  * The meta-control is itself proved to discriminate: META_SELF_TEST builds a
    throwaway registry containing a source-text assertion and requires the
    meta-predicate to reject it.

Run modes
  (default)          run the suite
  --mutation-audit   additionally remove each mechanism from a temporary copy
                     of the kernel and require the mapped controls to flip
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
KERNEL_PS = ROOT / "packaging" / "trustroot" / "TrustRootKernel.psm1"
HARNESS_PS = ROOT / "packaging" / "trustroot" / "Invoke-TrustRootScenarios.ps1"
KERNEL_PY = ROOT / "scripts" / "trust_root_kernel.py"
OPERATOR_DOC = ROOT / "docs" / "offline" / "trust-root-kernel-operator.md"

ASSERT_EXECUTED = "executed_predicate_result"
ASSERT_WITNESS = "executed_witness_binding"
ASSERT_SOURCE_TEXT = "source_text"
PERMITTED_ASSERTION_KINDS = frozenset({ASSERT_EXECUTED, ASSERT_WITNESS})


# --------------------------------------------------------------------------
# Executed-assertion registry
# --------------------------------------------------------------------------


@dataclass
class Registry:
    invocations: list[dict[str, Any]] = field(default_factory=list)
    assertions: list[dict[str, Any]] = field(default_factory=list)

    def record_invocation(self, twin: str, scenario: str, operation: str, record: dict) -> int:
        seq = len(self.invocations)
        self.invocations.append(
            {
                "seq": seq,
                "twin": twin,
                "scenario": scenario,
                "operation": operation,
                "verdict": record.get("verdict"),
                "reason": record.get("reason"),
                "record": record,
            }
        )
        return seq

    def record_assertion(
        self, control: str, kind: str, seqs: list[int], label: str, expected: Any, actual: Any
    ) -> bool:
        passed = expected == actual
        self.assertions.append(
            {
                "control": control,
                "kind": kind,
                "invocations": list(seqs),
                "label": label,
                "expected": expected,
                "actual": actual,
                "passed": passed,
            }
        )
        return passed


def meta_predicate(registry: Registry, declared: list[str]) -> list[dict[str, Any]]:
    """Judge a registry.  Returns a list of violations; empty means sound.

    This is the P3 enforcement point.  It reads the runtime registry, never the
    suite's own source.
    """
    violations: list[dict[str, Any]] = []

    for assertion in registry.assertions:
        if assertion["kind"] not in PERMITTED_ASSERTION_KINDS:
            violations.append(
                {
                    "kind": "non-executed assertion",
                    "control": assertion["control"],
                    "detail": "assertion kind %r certifies by something other than an executed effect"
                    % assertion["kind"],
                }
            )
        if not assertion["invocations"]:
            violations.append(
                {
                    "kind": "unbound assertion",
                    "control": assertion["control"],
                    "detail": "assertion %r references no executed invocation" % assertion["label"],
                }
            )
            continue
        for seq in assertion["invocations"]:
            if seq < 0 or seq >= len(registry.invocations):
                violations.append(
                    {
                        "kind": "dangling assertion",
                        "control": assertion["control"],
                        "detail": "invocation %d does not exist" % seq,
                    }
                )

    asserted = {a["control"] for a in registry.assertions}
    for control_id in declared:
        if control_id not in asserted:
            violations.append(
                {
                    "kind": "silent control",
                    "control": control_id,
                    "detail": "control produced no assertion",
                }
            )
    return violations


# --------------------------------------------------------------------------
# Controls (data only)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Control:
    id: str
    prop: str
    scenario: str
    verdict: str
    reason: str
    checks: tuple = ()
    negative: str | None = None
    twinned: bool = False


C = Control

CONTROLS: tuple[Control, ...] = (
    # ---- P0 fixture soundness ------------------------------------------
    C("TRK-P0-01", "P0", "P0_FIXTURE_BASELINE_SOUND", "ACCEPT", "OK"),
    # ---- P1 fresh root ---------------------------------------------------
    C("TRK-P1-01", "P1", "P1_CHAIN_CLEAN", "ACCEPT", "OK", twinned=True),
    C(
        "TRK-P1-02",
        "P1",
        "P1_CHAIN_WRITABLE_INTERMEDIATE",
        "REFUSE",
        "UNSAFE_WRITABLE_ACE",
        checks=(("endswith", "component", "\\mid"), ("not_endswith", "component", "\\leaf")),
        negative="NC02",
        twinned=True,
    ),
    C(
        "TRK-P1-03",
        "P1",
        "P1_CHAIN_NULL_DACL_INTERMEDIATE",
        "REFUSE",
        "DACL_ABSENT",
        checks=(("endswith", "component", "\\mid"),),
        negative="NC08",
        twinned=True,
    ),
    C(
        "TRK-P1-04",
        "P1",
        "P1_CHAIN_CALLBACK_ACE",
        "REFUSE",
        "ACE_UNINTERPRETABLE",
        checks=(("endswith", "component", "\\mid"),),
        negative="NC09",
        twinned=True,
    ),
    C(
        "TRK-P1-05",
        "P1",
        "P1_CHAIN_REPARSE_INTERMEDIATE",
        "REFUSE",
        "NODE_REPARSE",
        checks=(("endswith", "component", "\\mid"),),
        twinned=True,
    ),
    C("TRK-P1-06", "P1", "P1_CHAIN_NOT_ANCHORED", "REFUSE", "CHAIN_NOT_ANCHORED", twinned=True),
    C("TRK-P1-07", "P1", "P1_ROOT_FRESH", "ACCEPT", "OK", checks=(("equals", "created", True),)),
    C("TRK-P1-08", "P1", "P1_ROOT_PRECREATED", "REFUSE", "ROOT_EXISTS", negative="NC01a"),
    C("TRK-P1-09", "P1", "P1_ROOT_PRECREATED_JUNCTION", "REFUSE", "ROOT_EXISTS", negative="NC01b"),
    C(
        "TRK-P1-10",
        "P1",
        "P1_ROOT_PARENT_JUNCTION",
        "REFUSE",
        "NODE_REPARSE",
        checks=(("endswith", "component", "\\planted"), ("equals", "stage", "parent-chain")),
    ),
    C(
        "TRK-P1-11",
        "P1",
        "P1_ROOT_PARENT_WRITABLE",
        "REFUSE",
        "UNSAFE_WRITABLE_ACE",
        checks=(("equals", "stage", "parent-chain"),),
    ),
    C(
        "TRK-P1-12",
        "P1",
        "P1_LIVE_USER_PROFILE_REFUSED",
        "REFUSE",
        "UNSAFE_WRITABLE_ACE",
        twinned=True,
    ),
    C("TRK-P1-13", "P1", "P1_LIVE_PROGRAM_FILES_ACCEPTED", "ACCEPT", "OK", twinned=True),
    C("TRK-P1-17", "P1", "P1_NODE_OWNER_UNTRUSTED", "REFUSE", "OWNER_UNTRUSTED", twinned=True),
    C("TRK-P1-18", "P1", "P1_NODE_GENERIC_ALL_ACE", "REFUSE", "UNSAFE_WRITABLE_ACE", twinned=True),
    C("TRK-P1-19", "P1", "P1_NODE_FINAL_CONTENT_WRITE", "REFUSE", "UNSAFE_WRITABLE_ACE", twinned=True),
    C("TRK-P1-20", "P1", "P1_NODE_NONFINAL_CONTENT_WRITE", "ACCEPT", "OK", twinned=True),
    C(
        "TRK-P1-16",
        "P1",
        "P1_NODE_NULL_DACL_PRESENT_BIT",
        "REFUSE",
        "DACL_ABSENT",
        negative="NC08b",
        twinned=True,
    ),
    C("TRK-P1-14", "P1", "P1_IDENTITY_SWAP", "REFUSE", "IDENTITY_CHANGED", negative="NC12"),
    C("TRK-P1-15", "P1", "P1_IDENTITY_STABLE", "ACCEPT", "OK"),
    # ---- P2 atomic bundle pin -------------------------------------------
    C("TRK-P2-01", "P2", "P2_PIN_CLEAN", "ACCEPT", "OK", twinned=True),
    C("TRK-P2-02", "P2", "P2_PIN_MISMATCH", "REFUSE", "BUNDLE_PIN_MISMATCH", negative="NC04", twinned=True),
    C("TRK-P2-03", "P2", "P2_PIN_MEMBERSHIP_ADDED", "REFUSE", "BUNDLE_PIN_MISMATCH", twinned=True),
    C("TRK-P2-04", "P2", "P2_PIN_MEMBERSHIP_REMOVED", "REFUSE", "BUNDLE_PIN_MISMATCH", twinned=True),
    C("TRK-P2-10", "P2", "P2_BUNDLE_REPARSE", "REFUSE", "NODE_REPARSE", checks=(("equals", "stage", "bundle-enumeration"),)),
    C("TRK-P2-09", "P2", "P2_PIN_MEMBER_RENAMED", "REFUSE", "BUNDLE_PIN_MISMATCH", twinned=True),
    C(
        "TRK-P2-05",
        "P2",
        "P2_EXECUTED_OUTSIDE_BUNDLE",
        "REFUSE",
        "EXECUTED_NOT_IN_BUNDLE",
        negative="NC03",
        twinned=True,
    ),
    C(
        "TRK-P2-06",
        "P2",
        "P2_POST_PIN_TAMPER",
        "REFUSE",
        "BUNDLE_PIN_MISMATCH",
        checks=(("evidence_equals", "first_verdict", "ACCEPT"),),
        negative="NC05",
    ),
    C("TRK-P2-07", "P2", "P2_PIN_IMPLEMENTATION_IN_BUNDLE", "ACCEPT", "OK"),
    C("TRK-P2-08", "P2", "P2_PIN_CASE_COLLISION", "REFUSE", "CASE_COLLISION", negative="NC07b", twinned=True),
    # ---- P4 manifest / differential --------------------------------------
    C("TRK-P4-01", "P4", "P4_MANIFEST_CLEAN", "ACCEPT", "OK", twinned=True),
    C("TRK-P4-02", "P4", "P4_MANIFEST_DUPLICATE_KEY", "REFUSE", "MANIFEST_DUPLICATE_KEY", twinned=True),
    C("TRK-P4-03", "P4", "P4_MANIFEST_CASE_COLLISION", "REFUSE", "CASE_COLLISION", negative="NC07a", twinned=True),
    C("TRK-P4-04", "P4", "P4_MANIFEST_NON_FINITE", "REFUSE", "MANIFEST_MALFORMED", twinned=True),
    C("TRK-P4-05", "P4", "P4_MANIFEST_BIG_INTEGER", "REFUSE", "MANIFEST_MALFORMED", twinned=True),
    C("TRK-P4-06", "P4", "P4_MANIFEST_TRUNCATED", "REFUSE", "MANIFEST_MALFORMED", twinned=True),
    C("TRK-P4-07", "P4", "P4_MANIFEST_BOM", "REFUSE", "MANIFEST_MALFORMED", twinned=True),
    # ---- P5 native execution trace ---------------------------------------
    C("TRK-P5-01", "P5", "P5_SYSTEM_DIR_VERIFIED", "ACCEPT", "OK"),
    C(
        "TRK-P5-02",
        "P5",
        "P5_SYSTEM_DIR_IGNORES_ENV",
        "ACCEPT",
        "OK",
        checks=(("evidence_equals", "unchanged", True),),
    ),
    C(
        "TRK-P5-03",
        "P5",
        "P5_TRACE_CLEAN",
        "ACCEPT",
        "OK",
        checks=(("equals", "instrumented", 1), ("equals", "created", 1)),
    ),
    C(
        "TRK-P5-04",
        "P5",
        "P5_TRACE_PATH_HIJACK",
        "REFUSE",
        "NATIVE_OUTSIDE_ALLOWLIST",
        checks=(("list_any_endswith", "offenders", "p5-path-hijack\\icacls.exe"),),
        negative="NC10",
    ),
    C(
        "TRK-P5-05",
        "P5",
        "P5_TRACE_VARIABLE_INVOKE",
        "REFUSE",
        "NATIVE_OUTSIDE_ALLOWLIST",
        checks=(("list_any_endswith", "offenders", "p5-var-invoke\\hostname.exe"),),
    ),
    C("TRK-P5-06", "P5", "P5_NATIVE_NONZERO_EXIT", "REFUSE", "NATIVE_NONZERO_EXIT", checks=(("equals", "exit_code", 3),)),
    C("TRK-P5-07", "P5", "P5_NATIVE_NOT_ALLOWLISTED", "REFUSE", "NATIVE_OUTSIDE_ALLOWLIST"),
    C("TRK-P5-08", "P5", "P5_NATIVE_PREFIX_LOOKALIKE", "REFUSE", "NATIVE_OUTSIDE_ALLOWLIST"),
    C("TRK-P5-09", "P5", "P5_NATIVE_CASE_DIFFERING_PATH", "ACCEPT", "OK"),
    C("TRK-P5-10", "P5", "P5_SID_SELF", "ACCEPT", "OK"),
    C("TRK-P5-11", "P5", "P5_SID_WRONG_PRINCIPAL", "REFUSE", "PRINCIPAL_SID_MISMATCH", negative="NC11"),
)

DECLARED_IDS = tuple(control.id for control in CONTROLS)

# The twelve negative controls the kernel is required to carry, mapped to the
# control ids that demonstrate them.
NEGATIVE_CONTROLS = {
    "NC01 pre-created / junction trust root": ("TRK-P1-08", "TRK-P1-09"),
    "NC02 writable intermediate parent": ("TRK-P1-02",),
    "NC03 bundle missing one executed script": ("TRK-P2-05",),
    "NC04 bundle hash mismatch": ("TRK-P2-02",),
    "NC05 tampered post-pin script": ("TRK-P2-06",),
    "NC06 PS/Python differential disagreement": ("TRK-P4-DIFF-GUARD",),
    "NC07 case-only collision": ("TRK-P4-03", "TRK-P2-08"),
    "NC08 NULL DACL": ("TRK-P1-03", "TRK-P1-16"),
    "NC09 unknown relevant ACE": ("TRK-P1-04",),
    "NC10 bare / PATH native launch": ("TRK-P5-04",),
    "NC11 wrong operator SID": ("TRK-P5-11",),
    "NC12 runtime path swap after verification": ("TRK-P1-14",),
}


# --------------------------------------------------------------------------
# Mutations: remove a mechanism, require the mapped controls to flip
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Mutation:
    id: str
    target: str  # "ps" or "py"
    old: str
    new: str
    must_flip: tuple[str, ...]


MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        "MUT-CHAIN-LEAF-ONLY",
        "ps",
        "    for ($i = 0; $i -lt $list.Count; $i++) {\n        $result = Test-KernelNode",
        "    for ($i = $list.Count - 1; $i -lt $list.Count; $i++) {\n        $result = Test-KernelNode",
        ("TRK-P1-02", "TRK-P1-03", "TRK-P1-04", "TRK-P1-05"),
    ),
    Mutation(
        "MUT-NO-REPARSE-CHECK",
        "ps",
        "    if ($Node.reparse)     { return New-KernelVerdict $script:R.NODE_REPARSE @{ path = $path } }",
        "    if ($false)            { return New-KernelVerdict $script:R.NODE_REPARSE @{ path = $path } }",
        ("TRK-P1-05", "TRK-P1-10"),
    ),
    Mutation(
        "MUT-NO-DACL-PRESENT-CHECK",
        "ps",
        "    if (-not $sd.DaclPresent -or $sd.DaclNull) {",
        "    if ($sd.DaclNull) {",
        ("TRK-P1-03",),
    ),
    Mutation(
        "MUT-NO-NULL-DACL-POINTER-CHECK",
        "ps",
        "    if (-not $sd.DaclPresent -or $sd.DaclNull) {",
        "    if (-not $sd.DaclPresent) {",
        ("TRK-P1-16",),
    ),
    Mutation(
        "MUT-NO-ACE-INTERPRETABILITY",
        "ps",
        "        if (-not $ace.Interpretable) {\n            return New-KernelVerdict $script:R.ACE_UNINTERPRETABLE @{ path = $path; ace_type = $ace.AceType }\n        }",
        "        if ($false) {\n            return New-KernelVerdict $script:R.ACE_UNINTERPRETABLE @{ path = $path; ace_type = $ace.AceType }\n        }",
        ("TRK-P1-04",),
    ),
    Mutation(
        "MUT-ADOPT-EXISTING-ROOT",
        "ps",
        "        if ($err -eq 183) {\n            return New-KernelVerdict $script:R.ROOT_EXISTS @{ path = $full; win32 = $err }\n        }",
        "        if ($err -eq 183 -and $false) {\n            return New-KernelVerdict $script:R.ROOT_EXISTS @{ path = $full; win32 = $err }\n        }\n        if ($err -eq 183) { $null = Get-Item -LiteralPath $full -Force }",
        ("TRK-P1-08", "TRK-P1-09"),
    ),
    Mutation(
        "MUT-PIN-PARTIAL-ENUMERATION",
        "ps",
        "foreach ($file in (Get-ChildItem -LiteralPath $rootFull -Recurse -File -Force -Attributes !ReparsePoint)) {",
        "foreach ($file in (Get-ChildItem -LiteralPath $rootFull -Recurse -File -Force -Attributes !ReparsePoint -Filter '*.ps1')) {",
        ("TRK-P2-03", "TRK-P2-04"),
    ),
    Mutation(
        "MUT-PIN-DROPS-MEMBER-NAMES",
        "ps",
        '$lines = foreach ($row in $sorted) { "$($row.Path)$([char]0)$($row.Digest)$([char]0)$($row.Size)" }',
        '$lines = foreach ($row in $sorted) { "$($row.Digest)$([char]0)$($row.Size)" }',
        ("TRK-P2-09",),
    ),
    Mutation(
        "MUT-PIN-IGNORES-EXECUTED",
        "ps",
        "    foreach ($executed in $ExecutedPaths) {\n        if ([string]::IsNullOrWhiteSpace($executed)) { continue }",
        "    foreach ($executed in $ExecutedPaths) {\n        if ($true) { continue }",
        ("TRK-P2-05",),
    ),
    Mutation(
        "MUT-NO-ENGINE-OBSERVER",
        "ps",
        "        if ($resolved) {\n            $null = $lookups.Add([pscustomobject]@{ Name = $CommandName; Path = $resolved })\n        }",
        "        if ($false) {\n            $null = $lookups.Add([pscustomobject]@{ Name = $CommandName; Path = $resolved })\n        }",
        ("TRK-P5-04", "TRK-P5-05"),
    ),
    Mutation(
        "MUT-NO-JOB-OBSERVER",
        "ps",
            "            if ($observedPid -ne $script:TraceSelfPid) { $null = $createdPids.Add($observedPid) }",
        "            if ($false) { $null = $createdPids.Add($observedPid) }",
        ("TRK-P5-03",),
    ),
    Mutation(
        "MUT-SYSTEM-DIR-FROM-ENV",
        "ps",
        "    $candidate = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)",
        "    $candidate = Join-Path $env:SystemRoot 'System32'",
        ("TRK-P5-02",),
    ),
    Mutation(
        "MUT-SID-FROM-USERNAME",
        "ps",
        "            sid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value; source = 'process-token'",
        "            sid = (New-Object System.Security.Principal.NTAccount($env:USERNAME)).Translate([System.Security.Principal.SecurityIdentifier]).Value; source = 'username-env'",
        ("TRK-P5-11",),
    ),
    Mutation(
        "MUT-NO-IDENTITY-RECHECK",
        "ps",
        "    if ($actual -ne $Expected) {",
        "    if ($false) {",
        ("TRK-P1-14",),
    ),
    Mutation(
        "MUT-CASE-SENSITIVE-KEYS",
        "ps",
        "        $folded = $entry.Key.ToLowerInvariant()",
        "        $folded = $entry.Key",
        ("TRK-P4-03",),
    ),
    Mutation(
        "MUT-NO-CHAIN-ANCHOR",
        "ps",
        "    if (-not $anchored) {",
        "    if ($false) {",
        ("TRK-P1-06",),
    ),
    Mutation(
        "MUT-NO-GENERIC-RIGHTS-MAPPING",
        "ps",
        "        $effective = Convert-GenericRights -Mask $ace.Mask",
        "        $effective = $ace.Mask",
        ("TRK-P1-18",),
    ),
    Mutation(
        "MUT-NO-OWNER-CHECK",
        "ps",
        "    if ($trusted -notcontains $sd.OwnerSid) {",
        "    if ($false) {",
        ("TRK-P1-17",),
    ),
    Mutation(
        "MUT-NO-FINAL-CONTENT-RIGHTS",
        "ps",
        "    if ($isFinal) { $unsafeMask = $unsafeMask -bor $script:CONTENT_CLASS }",
        "    if ($false) { $unsafeMask = $unsafeMask -bor $script:CONTENT_CLASS }",
        ("TRK-P1-19", "TRK-P1-18"),
    ),
    Mutation(
        "MUT-NATIVE-PREFIX-MATCH",
        "ps",
        ".Equals($systemTrimmed, [StringComparison]::OrdinalIgnoreCase)) {",
        ".StartsWith($systemTrimmed, [StringComparison]::OrdinalIgnoreCase)) {",
        ("TRK-P5-08",),
    ),
    Mutation(
        "MUT-NO-EXIT-CODE-CHECK",
        "ps",
        "    if ($exitCode -ne 0) {",
        "    if ($false) {",
        ("TRK-P5-06",),
    ),
    Mutation(
        "MUT-BUNDLE-ALLOWS-REPARSE",
        "ps",
        "    $reparse = Find-BundleReparsePoint -Root $Root",
        "    $reparse = $null",
        ("TRK-P2-10",),
    ),
    # Python-side mutations prove the differential control has teeth in both
    # directions, not only when the PowerShell twin drifts.
    Mutation(
        "MUT-PY-NO-NULL-DACL-CHECK",
        "py",
        "    if not descriptor.dacl_present or descriptor.dacl_null:",
        "    if not descriptor.dacl_present:",
        ("TRK-P4-DIFF-P1_NODE_NULL_DACL_PRESENT_BIT",),
    ),
    Mutation(
        "MUT-PY-CASE-SENSITIVE-KEYS",
        "py",
        "        folded = key.lower()",
        "        folded = key",
        ("TRK-P4-DIFF-P4_MANIFEST_CASE_COLLISION",),
    ),
)


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------


def run_ps_harness(workdir: Path, kernel_path: Path, only: list[str] | None = None) -> dict[str, dict]:
    out = workdir / "ps-transcript.json"
    command = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(HARNESS_PS),
        "-OutFile",
        str(out),
        "-KernelPath",
        str(kernel_path),
    ]
    if only:
        command += ["-Only", ",".join(only)]
    completed = subprocess.run(command, capture_output=True, text=True)
    if not out.exists():
        raise SystemExit(
            "PowerShell harness produced no transcript.\nstdout: %s\nstderr: %s"
            % (completed.stdout[-2000:], completed.stderr[-2000:])
        )
    with io.open(out, encoding="utf-8-sig") as handle:
        records = json.load(handle)
    if isinstance(records, dict):
        records = [records]
    return {record["id"]: record for record in records}


def run_py_twin(workdir: Path, kernel_py: Path, ps_records: dict[str, dict]) -> dict[str, dict]:
    operation_map = {
        "evaluate_node": "evaluate_node",
        "evaluate_chain": "evaluate_chain",
        "canonicalize_manifest": "canonicalize_manifest",
        "compute_bundle_pin": "compute_bundle_pin",
        "verify_bundle": "verify_bundle",
    }
    jobs = []
    for scenario, record in ps_records.items():
        payload = record.get("twin_input")
        operation = operation_map.get(record.get("operation", ""))
        if payload is None or operation is None:
            continue
        jobs.append({"id": scenario, "operation": operation, "payload": payload})
    if not jobs:
        return {}
    jobs_path = workdir / "py-jobs.json"
    out_path = workdir / "py-transcript.json"
    with io.open(jobs_path, "w", encoding="utf-8") as handle:
        json.dump(jobs, handle)
    completed = subprocess.run(
        [sys.executable, str(kernel_py), "--jobs", str(jobs_path), "--out", str(out_path)],
        capture_output=True,
        text=True,
    )
    if not out_path.exists():
        raise SystemExit(
            "Python twin produced no transcript.\nstdout: %s\nstderr: %s"
            % (completed.stdout[-2000:], completed.stderr[-2000:])
        )
    with io.open(out_path, encoding="utf-8") as handle:
        return {record["id"]: record for record in json.load(handle)}


def field_value(record: dict, key: str, where: str) -> Any:
    container = record.get("result") if where == "result" else record.get("evidence")
    if not isinstance(container, dict):
        return None
    return container.get(key)


def evaluate_controls(
    registry: Registry, ps_records: dict[str, dict], py_records: dict[str, dict]
) -> dict[str, dict[str, Any]]:
    outcomes: dict[str, dict[str, Any]] = {}

    for control in CONTROLS:
        record = ps_records.get(control.scenario)
        if record is None:
            outcomes[control.id] = {
                "passed": False,
                "detail": "scenario %s did not execute" % control.scenario,
                "failures": ["scenario missing"],
            }
            continue
        seq = registry.record_invocation("powershell", control.scenario, record.get("operation", ""), record)
        failures: list[str] = []
        if not registry.record_assertion(
            control.id, ASSERT_EXECUTED, [seq], "verdict", control.verdict, record.get("verdict")
        ):
            failures.append("verdict %s != %s" % (record.get("verdict"), control.verdict))
        if not registry.record_assertion(
            control.id, ASSERT_EXECUTED, [seq], "reason", control.reason, record.get("reason")
        ):
            failures.append("reason %s != %s" % (record.get("reason"), control.reason))

        for check in control.checks:
            kind = check[0]
            key = check[1]
            expected = check[2]
            if kind == "evidence_equals":
                actual = field_value(record, key, "evidence")
                ok = registry.record_assertion(
                    control.id, ASSERT_EXECUTED, [seq], "evidence.%s" % key, expected, actual
                )
            elif kind == "equals":
                actual = field_value(record, key, "result")
                ok = registry.record_assertion(
                    control.id, ASSERT_EXECUTED, [seq], "result.%s" % key, expected, actual
                )
            elif kind == "endswith":
                raw = field_value(record, key, "result")
                actual = bool(isinstance(raw, str) and raw.lower().endswith(expected.lower()))
                ok = registry.record_assertion(
                    control.id, ASSERT_EXECUTED, [seq], "result.%s endswith %s" % (key, expected), True, actual
                )
            elif kind == "not_endswith":
                raw = field_value(record, key, "result")
                actual = bool(isinstance(raw, str) and raw.lower().endswith(expected.lower()))
                ok = registry.record_assertion(
                    control.id, ASSERT_EXECUTED, [seq], "result.%s not endswith %s" % (key, expected), False, actual
                )
            elif kind == "list_any_endswith":
                raw = field_value(record, key, "result")
                items = raw if isinstance(raw, list) else ([raw] if isinstance(raw, str) else [])
                actual = any(isinstance(i, str) and i.lower().endswith(expected.lower()) for i in items)
                ok = registry.record_assertion(
                    control.id, ASSERT_EXECUTED, [seq], "result.%s any endswith %s" % (key, expected), True, actual
                )
            else:
                raise SystemExit("unknown check kind %r" % kind)
            if not ok:
                failures.append("%s check on %s" % (kind, key))

        outcomes[control.id] = {
            "passed": not failures,
            "failures": failures,
            "scenario": control.scenario,
            "property": control.prop,
            "observed": "%s/%s" % (record.get("verdict"), record.get("reason")),
        }

    # A control declared twinned must actually have produced a twin record.
    # Without this, a twin that silently stopped running would remove the
    # differential comparison rather than fail it.
    for control in CONTROLS:
        if not control.twinned:
            continue
        record = ps_records.get(control.scenario)
        if record is None:
            continue
        seq = registry.record_invocation(
            "guard", control.scenario, "twin_coverage",
            {"verdict": "ACCEPT" if control.scenario in py_records else "REFUSE", "reason": "OK"},
        )
        if not registry.record_assertion(
            control.id, ASSERT_EXECUTED, [seq], "python twin ran", True, control.scenario in py_records
        ):
            outcomes[control.id]["passed"] = False
            outcomes[control.id]["failures"].append("declared twinned but the Python twin produced no record")

    # ---- P4 differential parity: identical inputs, compared verdicts -----
    for scenario, py_record in sorted(py_records.items()):
        ps_record = ps_records.get(scenario)
        if ps_record is None:
            continue
        control_id = "TRK-P4-DIFF-%s" % scenario
        ps_seq = registry.record_invocation(
            "powershell", scenario, ps_record.get("operation", ""), ps_record
        )
        py_seq = registry.record_invocation("python", scenario, py_record.get("operation", ""), py_record)
        failures = []
        if not registry.record_assertion(
            control_id, ASSERT_EXECUTED, [ps_seq, py_seq], "twin verdict", ps_record.get("verdict"), py_record.get("verdict")
        ):
            failures.append("verdict %s vs %s" % (ps_record.get("verdict"), py_record.get("verdict")))
        if not registry.record_assertion(
            control_id, ASSERT_EXECUTED, [ps_seq, py_seq], "twin reason", ps_record.get("reason"), py_record.get("reason")
        ):
            failures.append("reason %s vs %s" % (ps_record.get("reason"), py_record.get("reason")))
        outcomes[control_id] = {
            "passed": not failures,
            "failures": failures,
            "scenario": scenario,
            "property": "P4",
            "observed": "ps=%s/%s py=%s/%s"
            % (
                ps_record.get("verdict"),
                ps_record.get("reason"),
                py_record.get("verdict"),
                py_record.get("reason"),
            ),
        }

    # ---- NC06: the differential fixtures must be genuine traps -----------
    probe = ps_records.get("P4_STOCK_PARSER_PROBE")
    if probe is not None:
        control_id = "TRK-P4-DIFF-GUARD"
        seq = registry.record_invocation("powershell", "P4_STOCK_PARSER_PROBE", "stock_parser_probe", probe)
        probe_text = (probe.get("evidence") or {}).get("probe", "")
        try:
            json.loads(probe_text)
            python_stock_accepted = True
        except ValueError:
            python_stock_accepted = False
        py_seq = registry.record_invocation(
            "python",
            "P4_STOCK_PARSER_PROBE",
            "stock_parser_probe",
            {"verdict": "ACCEPT" if python_stock_accepted else "REFUSE", "reason": "OK", "result": {}},
        )
        ps_stock_accepted = bool((probe.get("evidence") or {}).get("stock_accepted"))
        failures = []
        # The stock parsers must DISAGREE (proving the fixture is a real trap)
        if not registry.record_assertion(
            control_id, ASSERT_EXECUTED, [seq, py_seq], "stock parsers disagree", True,
            ps_stock_accepted != python_stock_accepted,
        ):
            failures.append(
                "stock parsers agreed (ps=%s py=%s): fixture no longer discriminates"
                % (ps_stock_accepted, python_stock_accepted)
            )
        # ... while the kernel twins AGREE on the same bytes.
        kernel_ps = ps_records.get("P4_MANIFEST_CASE_COLLISION")
        kernel_py = py_records.get("P4_MANIFEST_CASE_COLLISION")
        if kernel_ps and kernel_py:
            k_ps_seq = registry.record_invocation("powershell", "P4_MANIFEST_CASE_COLLISION", "canonicalize_manifest", kernel_ps)
            k_py_seq = registry.record_invocation("python", "P4_MANIFEST_CASE_COLLISION", "canonicalize_manifest", kernel_py)
            if not registry.record_assertion(
                control_id, ASSERT_EXECUTED, [k_ps_seq, k_py_seq], "kernel twins agree",
                kernel_ps.get("reason"), kernel_py.get("reason"),
            ):
                failures.append("kernel twins disagreed on the trap fixture")
        else:
            failures.append("kernel twin records absent for the trap fixture")
        outcomes[control_id] = {
            "passed": not failures,
            "failures": failures,
            "scenario": "P4_STOCK_PARSER_PROBE",
            "property": "P4",
            "observed": "stock ps_accepted=%s py_accepted=%s" % (ps_stock_accepted, python_stock_accepted),
        }

    return outcomes


# --------------------------------------------------------------------------
# P6 - witness-driven documentation
# --------------------------------------------------------------------------

CLAIM_PATTERN = re.compile(r"^(?P<claim>.*?)<!--\s*witness:\s*(?P<witness>[A-Za-z0-9\-_,\s]+?)\s*-->", re.M)


def evaluate_documentation(outcomes: dict[str, dict[str, Any]], registry: Registry) -> dict[str, Any]:
    """Every operator-facing claim must name a witness that actually passed."""
    if not OPERATOR_DOC.exists():
        return {"passed": False, "failures": ["operator document missing"], "claims": 0}

    text = io.open(OPERATOR_DOC, encoding="utf-8").read()
    claims = [
        (match.group("claim").strip(), [w.strip() for w in match.group("witness").split(",") if w.strip()])
        for match in CLAIM_PATTERN.finditer(text)
    ]
    failures: list[str] = []
    seq = registry.record_invocation(
        "guard", "DOC_CLAIM_BINDING", "documentation_claims",
        {"verdict": "ACCEPT", "reason": "OK", "result": {"claims": len(claims)}},
    )
    if not claims:
        failures.append("operator document declares no witness-bound claims")

    for claim, witnesses in claims:
        for witness in witnesses:
            outcome = outcomes.get(witness)
            passed = bool(outcome and outcome["passed"])
            if not registry.record_assertion(
                "TRK-P6-DOC", ASSERT_WITNESS, [seq], "claim %r -> %s" % (claim[:48], witness), True, passed
            ):
                if outcome is None:
                    failures.append("claim %r cites unknown witness %s" % (claim[:60], witness))
                else:
                    failures.append("claim %r cites failing witness %s" % (claim[:60], witness))

    return {"passed": not failures, "failures": failures, "claims": len(claims)}


# --------------------------------------------------------------------------
# Mutation audit
# --------------------------------------------------------------------------


def run_mutation_audit(workdir: Path, baseline: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    ps_source = io.open(KERNEL_PS, encoding="utf-8").read()
    py_source = io.open(KERNEL_PY, encoding="utf-8").read()

    for mutation in MUTATIONS:
        source = ps_source if mutation.target == "ps" else py_source
        if source.count(mutation.old) != 1:
            results.append(
                {
                    "mutation": mutation.id,
                    "applied": False,
                    "flipped": [],
                    "not_flipped": list(mutation.must_flip),
                    "detail": "anchor matched %d times (expected 1)" % source.count(mutation.old),
                }
            )
            continue

        stage = workdir / ("mut-" + mutation.id)
        stage.mkdir(parents=True, exist_ok=True)
        kernel_ps = stage / "TrustRootKernel.psm1"
        kernel_py = stage / "trust_root_kernel.py"
        io.open(kernel_ps, "w", encoding="utf-8", newline="").write(
            source.replace(mutation.old, mutation.new) if mutation.target == "ps" else ps_source
        )
        io.open(kernel_py, "w", encoding="utf-8", newline="").write(
            source.replace(mutation.old, mutation.new) if mutation.target == "py" else py_source
        )

        try:
            ps_records = run_ps_harness(stage, kernel_ps)
            py_records = run_py_twin(stage, kernel_py, ps_records)
        except SystemExit as exc:
            # A mutation that makes the kernel unloadable still flips every
            # control it was mapped to, because none of them can pass.
            results.append(
                {
                    "mutation": mutation.id,
                    "applied": True,
                    "flipped": list(mutation.must_flip),
                    "not_flipped": [],
                    "detail": "kernel failed to run under mutation: %s" % str(exc)[:120],
                }
            )
            continue

        mutated_registry = Registry()
        mutated = evaluate_controls(mutated_registry, ps_records, py_records)
        flipped, not_flipped = [], []
        for control_id in mutation.must_flip:
            was = baseline.get(control_id, {}).get("passed", False)
            now = mutated.get(control_id, {}).get("passed", False)
            (flipped if (was and not now) else not_flipped).append(control_id)
        results.append(
            {
                "mutation": mutation.id,
                "applied": True,
                "flipped": flipped,
                "not_flipped": not_flipped,
                "detail": "",
            }
        )
    return results


# --------------------------------------------------------------------------


def meta_self_test() -> tuple[bool, str]:
    """Prove the meta-predicate rejects a source-text assertion.

    Built as a throwaway registry so the proof is an executed effect rather than
    a claim about the meta-control.
    """
    probe = Registry()
    seq = probe.record_invocation("guard", "SELF_TEST", "probe", {"verdict": "ACCEPT", "reason": "OK"})
    probe.record_assertion("PROBE-OK", ASSERT_EXECUTED, [seq], "sound", True, True)
    violations = meta_predicate(probe, ["PROBE-OK"])
    if violations:
        return False, "meta-predicate rejected a sound registry: %s" % violations

    poisoned = Registry()
    pseq = poisoned.record_invocation("guard", "SELF_TEST", "probe", {"verdict": "ACCEPT", "reason": "OK"})
    poisoned.record_assertion("PROBE-SOURCE", ASSERT_SOURCE_TEXT, [pseq], "grep", True, True)
    poisoned.record_assertion("PROBE-UNBOUND", ASSERT_EXECUTED, [], "no invocation", True, True)
    violations = meta_predicate(poisoned, ["PROBE-SOURCE", "PROBE-UNBOUND", "PROBE-SILENT"])
    kinds = {violation["kind"] for violation in violations}
    expected = {"non-executed assertion", "unbound assertion", "silent control"}
    if not expected.issubset(kinds):
        return False, "meta-predicate missed %s" % (expected - kinds)
    return True, "rejects source-text, unbound and silent controls"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Trust-root kernel acceptance suite")
    parser.add_argument("--mutation-audit", action="store_true", help="also prove every mechanism is load bearing")
    parser.add_argument("--json", default="", help="write machine-readable results here")
    args = parser.parse_args(argv)

    if os.name != "nt":
        print("FAIL  trust-root kernel guard requires Windows with PowerShell 5.1")
        return 1

    failures = 0
    with tempfile.TemporaryDirectory(prefix="trk-guard-") as temporary:
        workdir = Path(temporary)
        ps_records = run_ps_harness(workdir, KERNEL_PS)
        py_records = run_py_twin(workdir, KERNEL_PY, ps_records)

        registry = Registry()
        outcomes = evaluate_controls(registry, ps_records, py_records)
        doc_outcome = evaluate_documentation(outcomes, registry)
        outcomes["TRK-P6-DOC"] = {
            "passed": doc_outcome["passed"],
            "failures": doc_outcome["failures"],
            "scenario": "operator documentation",
            "property": "P6",
            "observed": "%d witness-bound claims" % doc_outcome["claims"],
        }

        print("== trust-root kernel controls ==")
        by_property: dict[str, list[int]] = {}
        for control_id in sorted(outcomes):
            outcome = outcomes[control_id]
            prop = outcome.get("property", "P?")
            bucket = by_property.setdefault(prop, [0, 0])
            bucket[1] += 1
            if outcome["passed"]:
                bucket[0] += 1
            else:
                failures += 1
            status = "PASS" if outcome["passed"] else "FAIL"
            detail = "" if outcome["passed"] else "  <- " + "; ".join(outcome["failures"])
            print("  %-4s %-36s %s%s" % (status, control_id, outcome.get("observed", ""), detail))

        print("\n== per-property counts ==")
        for prop in sorted(by_property):
            passed, total = by_property[prop]
            print("  %s  %d/%d" % (prop, passed, total))

        print("\n== meta-controls (P3) ==")
        declared = list(outcomes.keys())
        violations = meta_predicate(registry, declared)
        if violations:
            failures += 1
            for violation in violations:
                print("  FAIL META  %s: %s" % (violation["control"], violation["detail"]))
        else:
            print(
                "  PASS META-EXECUTED-ONLY      %d assertions, all executed-effect kinds"
                % len(registry.assertions)
            )
            print(
                "  PASS META-BOUND-TO-INVOCATION %d invocations, every assertion traced"
                % len(registry.invocations)
            )
            print("  PASS META-NO-SILENT-CONTROL   %d controls all asserted" % len(declared))
        tagged = {c.negative: c.id for c in CONTROLS if c.negative}
        mapped = {i for ids in NEGATIVE_CONTROLS.values() for i in ids}
        orphaned = sorted(cid for tag, cid in tagged.items() if cid not in mapped)
        if orphaned:
            failures += 1
            print("  FAIL META-NEGATIVE-MAP        controls tagged negative but unmapped: %s" % ", ".join(orphaned))
        else:
            print("  PASS META-NEGATIVE-MAP        %d tagged negative controls all mapped" % len(tagged))

        ok, detail = meta_self_test()
        if ok:
            print("  PASS META-SELF-TEST           %s" % detail)
        else:
            failures += 1
            print("  FAIL META-SELF-TEST           %s" % detail)

        print("\n== required negative controls ==")
        for label in sorted(NEGATIVE_CONTROLS):
            ids = NEGATIVE_CONTROLS[label]
            states = [(i, outcomes.get(i, {}).get("passed", False)) for i in ids]
            allpass = all(state for _, state in states)
            if not allpass:
                failures += 1
            print("  %-4s %-46s %s" % ("PASS" if allpass else "FAIL", label, ", ".join(i for i, _ in states)))

        mutation_results: list[dict[str, Any]] = []
        if args.mutation_audit:
            print("\n== mutation audit (delete the mechanism, the control must flip) ==")
            mutation_results = run_mutation_audit(workdir, outcomes)
            for result in mutation_results:
                ok = not result["not_flipped"] and result["flipped"]
                if not ok:
                    failures += 1
                print(
                    "  %-4s %-30s flipped=%s%s%s"
                    % (
                        "PASS" if ok else "FAIL",
                        result["mutation"],
                        ",".join(result["flipped"]) or "-",
                        ("  STILL PASSING=" + ",".join(result["not_flipped"])) if result["not_flipped"] else "",
                        ("  (" + result["detail"] + ")") if result["detail"] else "",
                    )
                )

        if args.json:
            with io.open(args.json, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "controls": outcomes,
                        "invocations": len(registry.invocations),
                        "assertions": len(registry.assertions),
                        "mutations": mutation_results,
                    },
                    handle,
                    indent=2,
                    sort_keys=True,
                )

    total = len(outcomes)
    print("\n%s  %d controls, %d failures" % ("FAIL" if failures else "PASS", total, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
