"""Shared aggregation core for the reserved COMPLETE restricted-PostgreSQL runtime commands.

Both `audit:restricted-postgres-runtime` (functional) and `audit:restricted-postgres-runtime-faults`
import this module. It:

  * verifies every accepted child's SHA-256 against the manifest (fail closed);
  * runs each accepted child guard as a REAL external subprocess (never imports its assertion helpers
    to simulate success);
  * parses each child's canonical JSON summary, namespaces every child check id, and evaluates it
    against the manifest contract (claim scope, exact expected id set, counts, eligibility, parity,
    migration principal, required zero normal-failure counters);
  * aggregates the namespaced inventory and the normal-failure counters and emits an honest complete
    claim contract only when every child passes.

`evaluate_child` and `aggregate` are PURE so the integrity battery can drive them with synthetic child
summaries; the certification path (`certify`) always executes the real child subprocesses.

All emitted text is scrubbed: no DSN, credential, path, role, raw token, PID, or Docker id is printed.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import restricted_postgres_runtime_manifest as M  # noqa: E402

# ---- redaction ------------------------------------------------------------------------------------
_DSN_RE = re.compile(r"postgres(?:ql)?://[^\s\"']+", re.IGNORECASE)
_PW_RE = re.compile(r"(?i)(password|pwd)\s*=\s*[^\s\"';]+")
_STATIC_PATHS = [str(ROOT), str(Path(os.environ.get("TEMP", "/tmp"))), str(Path(os.environ.get("TMP", "/tmp")))]


def scrub(text: str) -> str:
    if not text:
        return text
    text = _DSN_RE.sub("<redacted-dsn>", text)
    text = _PW_RE.sub("<redacted-secret>", text)
    for p in _STATIC_PATHS:
        if p:
            text = text.replace(p, "<path>")
    # collapse windows/unix absolute-path drive prefixes that may still carry a machine path
    text = re.sub(r"[A-Za-z]:\\[^\s\"']+", "<path>", text)
    return text


def docker_available() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=30).returncode == 0
    except Exception:  # noqa: BLE001
        return False


# ---- child subprocess runner ----------------------------------------------------------------------
class RunResult:
    __slots__ = ("rc", "summary", "check_ids", "parse_ok", "err")

    def __init__(self, rc, summary, check_ids, parse_ok, err):
        self.rc = rc
        self.summary = summary
        self.check_ids = check_ids
        self.parse_ok = parse_ok
        self.err = err


def _extract_ids(parsed) -> list:
    ids = []
    for c in parsed.get("checks", []) or []:
        cid = c.get("check_id")
        if cid is None:
            cid = c.get("id")
        ids.append(cid)
    return ids


def run_child(entry, *, timeout=600) -> RunResult:
    """Execute the accepted child guard as a REAL subprocess and parse its canonical JSON summary."""
    script = ROOT / entry["script"]
    try:
        proc = subprocess.run([sys.executable, str(script)], cwd=str(ROOT),
                              capture_output=True, text=True, timeout=timeout,
                              env={**os.environ, "CI": "true"})
    except subprocess.TimeoutExpired:
        return RunResult(None, None, [], False, "timeout")
    out = proc.stdout or ""
    try:
        decoded, _ = json.JSONDecoder().raw_decode(out[out.index("{"):])
        summary = decoded.get("summary", {})
        ids = _extract_ids(decoded)
        return RunResult(proc.returncode, summary, ids, True, scrub((proc.stderr or "")[-400:]))
    except Exception as exc:  # noqa: BLE001 -- malformed / no JSON
        return RunResult(proc.returncode, None, [], False, f"parse:{type(exc).__name__}")


# ---- pure evaluation ------------------------------------------------------------------------------
def evaluate_child(entry, kind, run: RunResult, expected_ids) -> list:
    """Return a list of fail-closed problem strings for one child; empty == the child certifies."""
    problems = []
    if run.rc != 0:
        problems.append("nonzero_exit")
    if not run.parse_ok or not isinstance(run.summary, dict):
        problems.append("malformed_summary")
        return problems  # nothing else is trustworthy
    s = run.summary
    if s.get("claim_scope") != entry["claim_scope"]:
        problems.append("claim_scope_mismatch")
    if s.get("passed") != entry["expected_count"]:
        problems.append("passed_count_mismatch")
    if s.get("failed") not in (0,):
        problems.append("failed_nonzero")
    if s.get("skipped") not in (0,):
        problems.append("skipped_nonzero")
    # inventory (exact frozen id set -> missing/unknown/duplicate/partial all detectable)
    ids = run.check_ids
    if len(ids) != entry["expected_count"]:
        problems.append("emitted_count_mismatch")
    if len(set(ids)) != len(ids):
        problems.append("duplicate_id")
    exp, got = set(expected_ids), set(ids)
    if exp - got:
        problems.append("missing_ids")
    if got - exp:
        problems.append("unknown_ids")
    # honest classification contract
    contract = M.FUNCTIONAL_CONTRACT if kind == "functional" else M.FAULT_CONTRACT
    for k, v in contract.items():
        if s.get(k) != v:
            problems.append(f"contract_{k}")
    # required normal-failure counters: present AND zero
    for c in entry["required_counters"]:
        if c not in s:
            problems.append(f"counter_missing:{c}")
        elif s.get(c) != 0:
            problems.append(f"counter_nonzero:{c}")
    return problems


def aggregate(entries, kind, results_by_name, expected_ids_map, *, deferred=(), cleanup="complete"):
    """Pure aggregation over evaluated children. Returns a verdict dict.

    `deferred` (must be empty for a COMPLETE matrix) and `cleanup` (must be "complete") are explicit
    inputs so the integrity battery can drive the deferred-nonempty and cleanup-incomplete failure modes.
    """
    total_expected = M.EXPECTED_FUNCTIONAL_TOTAL if kind == "functional" else M.EXPECTED_FAULT_TOTAL
    child_rows, all_ns_ids, ok = [], [], True
    agg_missing = agg_unknown = agg_dup_intra = 0
    for e in entries:
        r = results_by_name.get(e["name"])
        run = r["run"] if r else None
        problems = r["problems"] if r else ["child_missing"]
        ids = run.check_ids if run else []
        ns = [f"{e['name']}::{cid}" for cid in ids]
        all_ns_ids.extend(ns)
        exp = set(expected_ids_map.get(e["name"], []))
        got = set(ids)
        miss, unk = len(exp - got), len(got - exp)
        intra_dup = len(ids) - len(got)
        agg_missing += miss
        agg_unknown += unk
        agg_dup_intra += intra_dup
        s = run.summary if (run and run.summary) else {}
        child_rows.append({
            "name": e["name"], "command": e["command"], "expected_count": e["expected_count"],
            "passed": s.get("passed"), "failed": s.get("failed"), "skipped": s.get("skipped"),
            "emitted_ids": len(ids), "missing_ids": miss, "unknown_ids": unk, "duplicate_ids": intra_dup,
            "claim_scope": s.get("claim_scope"), "ok": not problems, "problems": problems,
        })
        if problems:
            ok = False
    # aggregate inventory
    emitted = len(all_ns_ids)
    unique = len(set(all_ns_ids))
    duplicate = emitted - unique
    if duplicate:
        ok = False
    if emitted != total_expected or unique != total_expected:
        ok = False
    # aggregate normal-failure counters (sum over children that emit them; absent -> 0 contribution)
    agg_counters = {c: 0 for c in (M.HTTP_COUNTERS + M.WORKER_COUNTERS)}
    for e in entries:
        r = results_by_name.get(e["name"])
        s = r["run"].summary if (r and r["run"] and r["run"].summary) else {}
        for c in agg_counters:
            v = s.get(c)
            if isinstance(v, bool):
                v = None
            if isinstance(v, int):
                agg_counters[c] += v
    if any(v != 0 for v in agg_counters.values()):
        ok = False
    # informational controlled-negative totals (never mixed into the failure gate)
    controlled = {"controlled_worker_negatives": 0, "controlled_import_negatives": 0}
    for e in entries:
        r = results_by_name.get(e["name"])
        s = r["run"].summary if (r and r["run"] and r["run"].summary) else {}
        for c in controlled:
            v = s.get(c)
            if isinstance(v, int) and not isinstance(v, bool):
                controlled[c] += v
    # execution-level totals: preserve each child's honest execution-level classification, aggregated
    exec_levels = {}
    for e in entries:
        r = results_by_name.get(e["name"])
        s = r["run"].summary if (r and r["run"] and r["run"].summary) else {}
        for lvl, n in (s.get("execution_level_totals") or {}).items():
            if isinstance(n, int) and not isinstance(n, bool):
                exec_levels[lvl] = exec_levels.get(lvl, 0) + n
    def _int(x):
        return x if (isinstance(x, int) and not isinstance(x, bool)) else 0
    agg_passed = sum(_int(c["passed"]) for c in child_rows)
    agg_skipped = sum(_int(c["skipped"]) for c in child_rows)
    agg_failed = total_expected - agg_passed
    deferred = list(deferred or [])
    if deferred:
        ok = False
    if cleanup != "complete":
        ok = False
    return {
        "ok": ok, "children": child_rows, "expected": total_expected,
        "deferred": deferred, "cleanup": cleanup,
        "passed": agg_passed, "failed": agg_failed, "skipped": agg_skipped,
        "emitted_ids": emitted, "unique_ids": unique, "duplicate_ids": duplicate,
        "missing_ids": agg_missing, "unknown_ids": agg_unknown, "intra_child_duplicate_ids": agg_dup_intra,
        "counters": agg_counters, "controlled": controlled, "execution_level_totals": exec_levels,
    }


# ---- certification + emission ---------------------------------------------------------------------
_KIND_META = {
    "functional": {"cmd": M.COMPLETE_FUNCTIONAL_COMMAND, "scope": "restricted-runtime-functional-complete",
                   "matrix_key": "full_functional_matrix", "checks_key": "aggregate_functional_checks",
                   "entries": None},
    "fault": {"cmd": M.COMPLETE_FAULT_COMMAND, "scope": "restricted-runtime-functional-faults-complete",
              "matrix_key": "full_functional_fault_matrix", "checks_key": "aggregate_fault_checks",
              "entries": None},
}


def _base_summary(kind, meta, verdict, *, passed):
    s = {
        meta["checks_key"]: verdict["emitted_ids"],
        "expected_checks": verdict["expected"],
        "passed": verdict["passed"], "failed": verdict["failed"], "skipped": verdict["skipped"],
        "emitted_ids": verdict["emitted_ids"], "unique_ids": verdict["unique_ids"],
        "duplicate_ids": verdict["duplicate_ids"] + verdict["intra_child_duplicate_ids"],
        "missing_ids": verdict["missing_ids"], "unknown_ids": verdict["unknown_ids"],
        "eligible_for_tenant_evidence": False, "eligible_for_readiness": False,
        "production_parity": False, "migration_principal_class": "test-only-bootstrap-migration-admin",
        "execution_model": "accepted slices executed on independent runner-owned disposable stacks",
        "child_hashes_verified": True, "cleanup": verdict.get("cleanup", "complete"),
    }
    s.update(verdict["counters"])
    s.update(verdict["controlled"])
    s["execution_level_totals"] = verdict["execution_level_totals"]
    if kind == "functional":
        s["deferred_functional_areas"] = verdict.get("deferred", [])
    else:
        s["full_functional_fault_matrix_execution_levels"] = verdict["execution_level_totals"]
    if passed:
        s["claim_scope"] = meta["scope"]
        s[meta["matrix_key"]] = "passed"
        s["certification"] = "passed"
    else:
        s["claim_scope"] = meta["scope"].replace("-complete", "-incomplete")
        s[meta["matrix_key"]] = "not_passed"
        s["certification"] = "not_passed"
    return s


def _emit(kind, verdict, *, passed) -> int:
    meta = _KIND_META[kind]
    out = {"aggregate": meta["cmd"], "children": verdict["children"],
           "summary": _base_summary(kind, meta, verdict, passed=passed)}
    print(scrub(json.dumps(out, indent=2, default=str)))
    label = "functional" if kind == "functional" else "functional-fault"
    if passed:
        print(f"\nComplete restricted-runtime {label} matrix PASSED: {verdict['emitted_ids']} checks "
              f"across {len(verdict['children'])} accepted slices "
              f"[claim_scope={meta['scope']}; NOT tenant-evidence/readiness/production].")
        return 0
    print(f"\nComplete restricted-runtime {label} matrix NOT PASSED.")
    for c in verdict["children"]:
        if c["problems"]:
            print(scrub(f"  child {c['name']}: {c['problems']}"))
    return 1


def _emit_unavailable(kind, allow_unavailable) -> int:
    meta = _KIND_META[kind]
    out = {"aggregate": meta["cmd"], "children": [],
           "summary": {"certification": "unavailable", meta["matrix_key"]: "not_run",
                       "eligible_for_tenant_evidence": False, "eligible_for_readiness": False,
                       "production_parity": False,
                       "migration_principal_class": "test-only-bootstrap-migration-admin",
                       "reason": "docker_unavailable"}}
    print(json.dumps(out, indent=2, default=str))
    if allow_unavailable:
        print("\nComplete restricted-runtime matrix UNAVAILABLE (docker) — non-certifying, not passed.")
        return 0
    print("\nComplete restricted-runtime matrix UNAVAILABLE (docker) — certification FAILED.")
    return 1


def _emit_static_failure(kind, reason, detail) -> int:
    meta = _KIND_META[kind]
    out = {"aggregate": meta["cmd"], "children": [],
           "summary": {"certification": "not_passed", meta["matrix_key"]: "not_passed",
                       "reason": reason, "eligible_for_tenant_evidence": False,
                       "eligible_for_readiness": False}}
    print(scrub(json.dumps(out, indent=2, default=str)))
    print(f"\nComplete restricted-runtime matrix NOT PASSED ({reason}).")
    for d in detail:
        print(scrub(f"  - {d}"))
    return 1


def certify(kind, *, allow_unavailable=False, run_child_fn=run_child) -> int:
    """The REAL certification path: verify hashes, run every accepted child as a subprocess, evaluate,
    aggregate, emit. Integrity tests exercise evaluate_child/aggregate directly with synthetic inputs;
    this path always executes the real child subprocesses."""
    entries = M.FUNCTIONAL if kind == "functional" else M.FAULT
    if not docker_available():
        return _emit_unavailable(kind, allow_unavailable)
    hp = M.verify_hashes(entries)
    if hp:
        return _emit_static_failure(kind, "child_hash_or_presence", hp)
    cp = M.verify_commands(entries)
    if cp:
        return _emit_static_failure(kind, "child_command_or_path", cp)
    try:
        eids = M.load_expected_ids()[kind]
    except M.ManifestError as exc:
        return _emit_static_failure(kind, "manifest_expected_ids", [str(exc)])
    results = {}
    for e in entries:
        run = run_child_fn(e)
        problems = evaluate_child(e, kind, run, eids[e["name"]])
        results[e["name"]] = {"run": run, "problems": problems}
    # cleanup is "complete" by construction: the aggregate provisions NO Docker/state itself -- each
    # child owns and tears down its own disposable stack, and subprocess.run reaps every child process
    # before we return. The integrity battery drives the cleanup!="complete" failure mode explicitly.
    verdict = aggregate(entries, kind, results, eids, cleanup="complete")
    return _emit(kind, verdict, passed=verdict["ok"])
