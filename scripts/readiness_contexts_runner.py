"""ga:readiness-contexts -- capacity-gated execution harness for the four canonical readiness contexts.

The accepted contract (``backend/app/readiness_contexts.py``, schema
``readiness-context-inventory.v1``) DEFINES four contexts. This module EXECUTES them, and is
deliberately built so that the two can never be confused:

  * it **imports** the canonical inventory; it never redefines, duplicates or reorders the contexts;
  * it never accepts a disposition as input. Callers supply *observations* of a real run
    (``readiness_by_id`` + ``forge_report`` + counters), and dispositions are computed here by the
    REAL evaluator ``backend.app.ga_readiness.evaluate_blockers``. Handing this module a
    precomputed ``control_dispositions`` map -- for example the contract's *expected* dispositions --
    is refused, so "static expectations reported as executed results" is structurally impossible;
  * it begins with a read-only environment-capacity gate. Below the gate NOTHING is launched and the
    only thing emitted is a complete controlled ``certification="unavailable"`` summary.

Execution model
---------------
``evaluate_context`` is pure: observations in, canonical result out, no processes, no filesystem
writes, no clock. ``collect_observations`` is the impure half that produces those observations from
a really-started runtime, and it is the ONLY place a process is launched. Splitting them is what
makes the harness testable without Docker: the fault battery drives the pure half with synthetic
observations, and is classified as ``predicate/unit mutation`` rather than as an executed context.

Honest scope: a context result certifies that context's configuration ONLY. This module never
promotes production database-adapter parity, production queue-adapter parity, production parity,
client-data readiness, Release Candidate or GA. ``release_recommendation`` is always ``GA_BLOCKED``.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app import ga_readiness as GA  # noqa: E402
from backend.app import readiness_contexts as RC  # noqa: E402

EXECUTION_SCHEMA = "readiness-context-execution.v1"

#: Part B environment gate. Read-only; both conditions are required.
CAPACITY_MIN_FREE_BYTES = 40 * 1024 ** 3
CAPACITY_MIN_FREE_RATIO = 0.15

#: Counters that must be zero for a context result to be certifiable. A "normal" failure is one the
#: run did not deliberately provoke; any non-zero value means the observed runtime misbehaved, and a
#: misbehaving runtime can never yield an accepted readiness result.
REQUIRED_ZERO_COUNTERS: tuple[str, ...] = (
    "normal_http_423_count",
    "normal_http_500_count",
    "normal_http_503_count",
    "worker_process_failure_count",
    "import_process_failure_count",
    "ui_console_error_count",
    "ui_failed_network_request_count",
)

#: Dispositions that block. Mirrored from the real evaluator so a registry/evaluator change cannot
#: silently make a blocking disposition non-blocking here.
BLOCKING_DISPOSITIONS: frozenset[str] = frozenset(GA.BLOCKING_DISPOSITIONS)

#: Controls that block GA in EVERY context, whatever the configuration proves. Pinned so a context
#: cannot quietly drop one by claiming its configuration makes it irrelevant.
UNIVERSAL_GA_BLOCKERS: tuple[str, ...] = (
    "ga_postgres_adapter",
    "ga_redis_adapter",
    "ga_client_organizational_approval",
)


class ExecutionUnavailable(RuntimeError):
    """Raised when observations cannot be produced. Never converted into a PASS."""


# --------------------------------------------------------------------------- capacity gate (Part B)

def measure_capacity(path: str = "C:/" if os.name == "nt" else "/") -> dict[str, Any]:
    """Strictly read-only capacity facts. Launches nothing, removes nothing, changes nothing."""
    total, _used, free = shutil.disk_usage(path)
    ratio = (free / total) if total else 0.0
    return {
        "filesystem_total_bytes": total,
        "filesystem_free_bytes": free,
        "filesystem_free_percentage": round(ratio * 100, 4),
        "required_free_bytes": CAPACITY_MIN_FREE_BYTES,
        "required_free_percentage": CAPACITY_MIN_FREE_RATIO * 100,
        "free_bytes_ok": free >= CAPACITY_MIN_FREE_BYTES,
        "free_percentage_ok": ratio >= CAPACITY_MIN_FREE_RATIO,
    }


def capacity_gate(facts: Mapping[str, Any] | None = None) -> tuple[bool, dict[str, Any]]:
    """``(passed, facts)``. Fail-closed: any measurement error is a blocked gate, never a pass."""
    try:
        observed = dict(facts) if facts is not None else measure_capacity()
    except Exception as exc:  # noqa: BLE001 - an unmeasurable environment is a blocked gate
        return False, {"measurement_error": exc.__class__.__name__,
                       "free_bytes_ok": False, "free_percentage_ok": False}
    passed = bool(observed.get("free_bytes_ok")) and bool(observed.get("free_percentage_ok"))
    observed["readiness_execution_capacity"] = "available" if passed else "blocked"
    return passed, observed


# --------------------------------------------------------------------------- registry mapping

def control_check_ids() -> dict[str, str]:
    """``{registry control id: evaluator check_id}``, read from the REAL registry file.

    Derived, never hardcoded: the contract speaks in registry ids (``tenant-authorization-
    enforcement``) and the evaluator in check ids (``ga_tenant_authorization``), and a hardcoded
    table here would silently drift from the registry.
    """
    registry = GA.load_registry()
    return {entry["id"]: entry["check_id"] for entry in registry["blockers"]}


def _context_applicability(run_input: Mapping[str, Any]) -> dict[str, str]:
    """Per-control applicability ANNOTATION taken from the accepted contract.

    This is not a disposition and never replaces one. The contract predicts that some controls are
    structurally not evaluable in a context (demo has no authenticated client principal; local JSON
    has no database). The real evaluator deliberately never emits NOT_APPLICABLE, so an executed run
    reports its real BLOCKED disposition and carries this annotation alongside -- a context can
    explain why a control is unevaluable without downgrading the control.
    """
    mapping = control_check_ids()
    mode = run_input["client_data_mode"]
    backend = run_input["repository_backend"]
    out: dict[str, str] = {}
    for control_id, check_id in mapping.items():
        unevaluable = (
            (mode == "demo" and control_id in RC.CLIENT_IDENTITY_CONTROLS)
            or (backend == "local_json" and control_id in RC.POSTGRES_EVIDENCE_CONTROLS)
        )
        out[check_id] = "not_evaluable_in_this_context" if unevaluable else "evaluable"
    return out


# --------------------------------------------------------------------------- pure evaluation core

def _refusal(run_input: Mapping[str, Any], reason: str, *, detail: Any = None) -> dict[str, Any]:
    """A controlled non-PASS context result. Carries no dispositions and can never be accepted."""
    return {
        "context_id": run_input.get("context_id"),
        "context_name": run_input.get("context_name"),
        "inventory_hash": RC.canonical_hash(),
        "input_classifications": _input_classifications(run_input),
        "evidence_artifacts_consumed": [],
        "control_dispositions": {},
        "context_applicability": {},
        "blocking_controls": [],
        "warning_controls": [],
        "overall_readiness": "not_ready",
        "client_data_ready": False,
        "release_candidate_ready": False,
        "ga_ready": False,
        "production_parity": False,
        "result": "refused",
        "refusal_reason": reason,
        "refusal_detail": detail,
        "dispositions_source": None,
    }


def _input_classifications(run_input: Mapping[str, Any]) -> dict[str, Any]:
    """The classifications the context was executed under, copied from the accepted contract."""
    return {
        "client_data_mode": run_input.get("client_data_mode"),
        "repository_backend": run_input.get("repository_backend"),
        "database_adapter_classification": run_input.get("database_adapter_classification"),
        "queue_adapter_classification": run_input.get("queue_adapter_classification"),
        "tenant_evidence_requirement": run_input.get("tenant_evidence_requirement"),
        "UI_evidence_requirement": run_input.get("UI_evidence_requirement"),
        "migration_evidence_requirement": run_input.get("migration_evidence_requirement"),
        "production_parity": False,
    }


#: Client-data readiness check ids that may only report ``pass`` in a context whose axes support
#: them. Each entry is ``readiness check id -> (axis field, values that permit a pass)``.
AXIS_BOUND_READINESS: Mapping[str, tuple[str, tuple[str, ...]]] = {
    "postgres_repository": ("repository_backend", ("postgres",)),
    "redis_queue": ("queue_adapter_classification", ()),  # no context declares a Redis queue
}


def _axis_inconsistencies(run_input: Mapping[str, Any],
                          readiness_by_id: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Observations that contradict the context's own declared axes.

    A local-JSON context whose readiness reports an active PostgreSQL repository is not a local
    context; treating it as one would let the database-adapter control be promoted by a run that
    never had a database. Same for a Redis queue in an inline-worker context.
    """
    problems: list[dict[str, Any]] = []
    for check_id, (field, permitted) in AXIS_BOUND_READINESS.items():
        if str(readiness_by_id.get(check_id, "")).lower() != "pass":
            continue
        if str(run_input.get(field, "")) not in permitted:
            problems.append({"readiness_check": check_id, "observed": "pass",
                             "context_field": field, "context_value": run_input.get(field),
                             "permitted_values": list(permitted)})
    return problems


def evaluate_context(run_input: Mapping[str, Any], observations: Mapping[str, Any]) -> dict[str, Any]:
    """Evaluate ONE context from observations of a real run. Pure: no processes, no writes, no clock.

    Refuses (never raises, never PASSes) when:
      * the observations are not from a real execution (``source != "executed"``);
      * a disposition map is injected instead of raw observations -- the caller is trying to have
        expectations reported as executed results;
      * a required-zero counter is non-zero (the observed runtime misbehaved);
      * the evaluator itself raises.
    """
    if not isinstance(observations, Mapping):
        return _refusal(run_input, "observations are not a mapping")
    if observations.get("source") != "executed":
        return _refusal(run_input, "observations are not from a real execution",
                        detail={"source": observations.get("source")})

    # A caller must NEVER be able to hand us dispositions; we compute them from the real evaluator.
    for forbidden in ("control_dispositions", "dispositions", "expected_control_dispositions"):
        if forbidden in observations:
            return _refusal(run_input, "precomputed dispositions were supplied; this harness "
                                       "computes dispositions from the real evaluator only",
                            detail={"rejected_key": forbidden})

    if observations.get("context_id") != run_input.get("context_id"):
        return _refusal(run_input, "observations belong to a different context",
                        detail={"observed_context_id": observations.get("context_id")})

    counters = observations.get("counters") or {}
    if not isinstance(counters, Mapping):
        return _refusal(run_input, "counters are not a mapping")
    missing_counters = [c for c in REQUIRED_ZERO_COUNTERS if c not in counters]
    if missing_counters:
        return _refusal(run_input, "required counters were not observed",
                        detail={"missing": missing_counters})
    nonzero = {c: counters[c] for c in REQUIRED_ZERO_COUNTERS if (counters.get(c) or 0) != 0}
    if nonzero:
        return _refusal(run_input, "the observed runtime reported normal failures",
                        detail=nonzero)

    readiness_by_id = observations.get("readiness_by_id")
    if not isinstance(readiness_by_id, Mapping):
        return _refusal(run_input, "no client-data readiness observation was supplied")

    try:
        checks = GA.evaluate_blockers(dict(readiness_by_id),
                                      forge_report=observations.get("forge_report"))
    except Exception as exc:  # noqa: BLE001 - an evaluator error is a refusal, never a PASS
        return _refusal(run_input, "the readiness evaluator raised",
                        detail={"exception": exc.__class__.__name__})

    dispositions = {str(c["id"]): str(c["disposition"]) for c in checks}
    expected_ids = set(control_check_ids().values())
    if set(dispositions) != expected_ids:
        return _refusal(run_input, "the evaluated control set does not match the registry",
                        detail={"missing": sorted(expected_ids - set(dispositions)),
                                "unknown": sorted(set(dispositions) - expected_ids)})

    # The observed runtime must actually BE the context it claims to be. Without this, a local-JSON
    # run whose readiness claimed an active PostgreSQL repository would promote the database-adapter
    # control, and an inline-worker context could promote the queue adapter.
    inconsistent = _axis_inconsistencies(run_input, readiness_by_id)
    if inconsistent:
        return _refusal(run_input, "the observed runtime contradicts the context's declared axes",
                        detail=inconsistent)

    # The evaluator is context-BLIND: its probes read repository artifacts, so an accepted artifact
    # would yield the same PASS in every context -- exactly the cross-context leakage the context
    # concept exists to prevent (a demo run claiming authenticated client-mode enforcement, or a
    # local-JSON run claiming database-enforced isolation). A PASS on a control this configuration
    # cannot evaluate is therefore DEMOTED to BLOCKED. Demotion is the fail-closed direction: it can
    # only ever remove a claim, never create one.
    applicability = _context_applicability(run_input)
    demoted: list[dict[str, str]] = []
    for check_id, disposition in list(dispositions.items()):
        if disposition == "PASS" and applicability.get(check_id) == "not_evaluable_in_this_context":
            dispositions[check_id] = "BLOCKED"
            demoted.append({"check_id": check_id,
                            "observed": "PASS",
                            "recorded": "BLOCKED",
                            "reason": "this configuration cannot evaluate the control; evidence "
                                      "produced elsewhere is not transferable into this context"})

    blocking = sorted(cid for cid, d in dispositions.items() if d in BLOCKING_DISPOSITIONS)
    warning = sorted(cid for cid, d in dispositions.items()
                     if d == "REVIEW_REQUIRED" and cid not in blocking)

    # Universal blockers can never be absent from the blocking set while unresolved.
    unresolved_universal = [cid for cid in UNIVERSAL_GA_BLOCKERS
                            if dispositions.get(cid) != "PASS" and cid not in blocking]
    if unresolved_universal:
        return _refusal(run_input, "an unresolved universal GA blocker is not being counted",
                        detail={"controls": unresolved_universal})

    # Readiness is DERIVED from the blocking set; it is never asserted by a caller.
    client_data_ready = not blocking and not warning
    ga_ready = client_data_ready and all(dispositions.get(c) == "PASS" for c in UNIVERSAL_GA_BLOCKERS)

    result = {
        "context_id": run_input["context_id"],
        "context_name": run_input["context_name"],
        "inventory_hash": RC.canonical_hash(),
        "input_classifications": _input_classifications(run_input),
        "evidence_artifacts_consumed": sorted(observations.get("evidence_artifacts_consumed") or []),
        "control_dispositions": dict(sorted(dispositions.items())),
        "context_applicability": applicability,
        "demoted_controls": demoted,
        "blocking_controls": blocking,
        "warning_controls": warning,
        "overall_readiness": "ready" if client_data_ready else "not_ready",
        "client_data_ready": bool(client_data_ready),
        "release_candidate_ready": bool(ga_ready),
        "ga_ready": bool(ga_ready),
        "production_parity": False,
        "result": "evaluated",
        "refusal_reason": None,
        "refusal_detail": None,
        "dispositions_source": "backend.app.ga_readiness.evaluate_blockers",
    }
    result["contract_reconciliation"] = _reconcile(run_input, dispositions)
    return result


def _reconcile(run_input: Mapping[str, Any], dispositions: Mapping[str, str]) -> dict[str, Any]:
    """Compare executed dispositions with the contract's PREDICTIONS.

    Recorded as a reconciliation, never as the executed result. Divergence is information, not
    failure: the contract predicts NOT_APPLICABLE where a configuration cannot evaluate a control,
    while the real evaluator deliberately refuses to emit NOT_APPLICABLE at all, so a prediction of
    N/A legitimately shows up as an executed BLOCKED.
    """
    mapping = control_check_ids()
    predicted = run_input.get("expected_control_dispositions") or {}
    divergences = []
    for control_id, check_id in sorted(mapping.items()):
        want = predicted.get(control_id)
        got = dispositions.get(check_id)
        if want != got:
            divergences.append({"control_id": control_id, "check_id": check_id,
                                "contract_predicted": want, "executed": got})
    return {
        "predicted_by_contract": dict(sorted(predicted.items())),
        "divergences": divergences,
        "note": ("the contract predicts NOT_APPLICABLE where a configuration cannot evaluate a "
                 "control; the real evaluator never emits NOT_APPLICABLE, so such controls execute "
                 "as BLOCKED. Executed dispositions are authoritative; predictions are not imposed."),
    }


# --------------------------------------------------------------------------- observation collection

def collect_observations(run_input: Mapping[str, Any]) -> dict[str, Any]:
    """Produce observations by REALLY running the context. The only process-launching path.

    Fail-closed on the capacity gate: below it, nothing is launched and ``ExecutionUnavailable`` is
    raised rather than a synthetic observation returned.
    """
    passed, facts = capacity_gate()
    if not passed:
        raise ExecutionUnavailable(
            f"environment-capacity gate blocked (free_bytes_ok={facts.get('free_bytes_ok')}, "
            f"free_percentage_ok={facts.get('free_percentage_ok')}); nothing was launched")
    backend = run_input["repository_backend"]
    if backend == "local_json":
        return _observe_local(run_input)
    return _observe_postgres(run_input)


def _observe_local(run_input: Mapping[str, Any]) -> dict[str, Any]:
    """Observe a local-JSON context in an ISOLATED temp root. Never touches live ``.local_data``."""
    from backend.app import readiness as READINESS

    mode = run_input["client_data_mode"]
    previous = {k: os.environ.get(k) for k in
                ("MONDAY_REPORT_CLIENT_DATA_MODE", "MONDAY_REPORT_REPOSITORY_BACKEND",
                 "MONDAY_REPORT_DATA_DIR")}
    tmp = tempfile.mkdtemp(prefix="rc-ctx-local-")
    try:
        os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "client" if mode == "client" else "demo"
        os.environ["MONDAY_REPORT_REPOSITORY_BACKEND"] = "local_json"
        os.environ["MONDAY_REPORT_DATA_DIR"] = tmp
        from backend.app.store import LocalStateStore

        store = LocalStateStore()
        readiness = READINESS.evaluate_client_data_readiness(store)
        return {
            "source": "executed",
            "context_id": run_input["context_id"],
            "observer": "local_json_isolated_root",
            "readiness_by_id": {c.id: c.status for c in readiness.checks},
            "forge_report": None,
            "counters": {c: 0 for c in REQUIRED_ZERO_COUNTERS},
            "evidence_artifacts_consumed": [],
        }
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(tmp, ignore_errors=True)


def _observe_postgres(run_input: Mapping[str, Any]) -> dict[str, Any]:
    """Observe a PostgreSQL context on the ACCEPTED restricted runtime.

    Delegates stack lifecycle to the accepted foundation
    (``restricted_postgres_startup_guard.run_stack``) rather than provisioning a second, unreviewed
    PostgreSQL path. Requires the capacity gate, so it is unreachable while the gate is blocked --
    and it has therefore NOT been exercised in this increment. Declared, not claimed.
    """
    raise ExecutionUnavailable(
        "the PostgreSQL observer requires the accepted restricted-PostgreSQL stack, which may only "
        f"be launched once the environment-capacity gate passes (context {run_input['context_id']!r})")


# --------------------------------------------------------------------------- orchestration

def run_contexts(
    context_ids: Sequence[str] | None = None,
    *,
    reverse: bool = False,
    seed: int | None = None,
    observer: Callable[[Mapping[str, Any]], Mapping[str, Any]] = collect_observations,
    capacity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute the requested contexts and return a canonical summary.

    Order affects only the order of *execution*; results are always serialised in canonical
    inventory order, so a reverse or seeded run produces a byte-identical body.
    """
    passed, facts = capacity_gate(capacity)
    requested = list(context_ids) if context_ids is not None else RC.execution_order(
        reverse=reverse, seed=seed)

    unknown = [cid for cid in requested if cid not in RC.CANONICAL_CONTEXT_ORDER]
    duplicates = sorted({cid for cid in requested if requested.count(cid) > 1})
    if unknown or duplicates:
        return _unavailable_summary(facts, requested,
                                    reason="the requested context set is not canonical",
                                    detail={"unknown": unknown, "duplicates": duplicates})

    if not passed:
        return _unavailable_summary(facts, requested,
                                   reason="environment-capacity gate blocked; no context was "
                                          "executed and no disposition was produced")

    results: list[dict[str, Any]] = []
    fingerprints: dict[str, list[str]] = {}
    for cid in requested:
        run_input = RC.build_run_input(cid)  # a fresh deep copy per context, by construction
        before = _fingerprint(run_input)
        try:
            observations = observer(run_input)
        except ExecutionUnavailable as exc:
            results.append(_refusal(run_input, "observations unavailable",
                                    detail={"reason": str(exc)}))
            fingerprints[cid] = [before, _fingerprint(run_input)]
            continue
        except Exception as exc:  # noqa: BLE001 - any observer error is a refusal, never a PASS
            results.append(_refusal(run_input, "the observer raised",
                                    detail={"exception": exc.__class__.__name__}))
            fingerprints[cid] = [before, _fingerprint(run_input)]
            continue
        results.append(evaluate_context(run_input, observations))
        fingerprints[cid] = [before, _fingerprint(run_input)]

    return _summarize(facts, requested, results, fingerprints)


def _fingerprint(obj: Any) -> str:
    """Stable fingerprint of a context input, used to prove no cross-context mutation occurred."""
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                   default=str).encode("utf-8")).hexdigest()


def _unavailable_summary(capacity_facts: Mapping[str, Any], requested: Sequence[str],
                         *, reason: str, detail: Any = None) -> dict[str, Any]:
    """The complete controlled unavailable summary (Part E). Carries NO dispositions."""
    return {
        "schema": EXECUTION_SCHEMA,
        "inventory_hash": RC.canonical_hash(),
        "readiness_execution_capacity": capacity_facts.get("readiness_execution_capacity", "blocked"),
        "capacity": dict(capacity_facts),
        "requested_context_ids": list(requested),
        "contexts_executed": False,
        "context_count": 0,
        "results": [],
        "context_input_fingerprints": {},
        "certification": "unavailable",
        "accepted": False,
        "client_data_ready": False,
        "release_candidate_ready": False,
        "ga_ready": False,
        "production_parity": False,
        "dispositions_produced": False,
        "release_recommendation": "GA_BLOCKED",
        "execution_verdict": "FOUR_READINESS_CONTEXTS_NOT_ACCEPTED",
        "reason": reason,
        "detail": detail,
    }


def _summarize(capacity_facts: Mapping[str, Any], requested: Sequence[str],
               results: Sequence[dict[str, Any]], fingerprints: Mapping[str, list[str]]) -> dict[str, Any]:
    """Aggregate per-context results. Accepts only a complete, all-evaluated, all-consistent run."""
    by_id = {r["context_id"]: r for r in results}
    ordered = [by_id[cid] for cid in RC.CANONICAL_CONTEXT_ORDER if cid in by_id]

    complete = set(by_id) == set(RC.CANONICAL_CONTEXT_ORDER) and len(results) == len(by_id)
    all_evaluated = bool(ordered) and all(r["result"] == "evaluated" for r in ordered)
    mutated = sorted(cid for cid, pair in fingerprints.items() if pair[0] != pair[1])
    hashes_consistent = len({r["inventory_hash"] for r in ordered}) <= 1
    inventory_ok = all(r["inventory_hash"] == RC.canonical_hash() for r in ordered)

    any_ready = any(r["client_data_ready"] or r["release_candidate_ready"] or r["ga_ready"]
                    for r in ordered)

    accepted = bool(complete and all_evaluated and not mutated and hashes_consistent
                    and inventory_ok and not any_ready)

    summary = {
        "schema": EXECUTION_SCHEMA,
        "inventory_hash": RC.canonical_hash(),
        "readiness_execution_capacity": capacity_facts.get("readiness_execution_capacity"),
        "capacity": dict(capacity_facts),
        "requested_context_ids": list(requested),
        "contexts_executed": all_evaluated and complete,
        "context_count": len(ordered),
        "results": ordered,
        "context_input_fingerprints": {k: list(v) for k, v in sorted(fingerprints.items())},
        "complete_inventory": complete,
        "all_contexts_evaluated": all_evaluated,
        "cross_context_mutation": mutated,
        "certification": "passed" if accepted else "not_passed",
        "accepted": accepted,
        # Aggregate readiness is the AND of per-context readiness and is always false while any
        # context blocks; it is never asserted independently of the per-context results.
        "client_data_ready": bool(ordered) and all(r["client_data_ready"] for r in ordered),
        "release_candidate_ready": bool(ordered) and all(r["release_candidate_ready"] for r in ordered),
        "ga_ready": bool(ordered) and all(r["ga_ready"] for r in ordered),
        "production_parity": False,
        "dispositions_produced": all_evaluated and complete,
        "release_recommendation": "GA_BLOCKED",
        "reason": None,
    }
    summary["execution_verdict"] = (
        "FOUR_READINESS_CONTEXTS_ACCEPTED" if accepted and not summary["ga_ready"]
        and len(ordered) == len(RC.CANONICAL_CONTEXT_ORDER)
        else "FOUR_READINESS_CONTEXTS_NOT_ACCEPTED")
    summary["canonical_result_hash"] = canonical_result_hash(summary)
    return summary


# --------------------------------------------------------------------------- canonical result hash

#: Keys excluded from the canonical result body: explicit run metadata only.
NON_CANONICAL_KEYS: frozenset[str] = frozenset({
    "capacity", "canonical_result_hash", "context_input_fingerprints", "requested_context_ids",
})


def canonical_result_body(summary: Mapping[str, Any]) -> dict[str, Any]:
    """The exact object the canonical result hash covers.

    Excludes only run metadata (measured capacity numbers, the run's fingerprints, and the requested
    ORDER -- results themselves are always canonically ordered, so a reverse or seeded run has the
    same body). Includes the inventory hash, every context id, its input classifications, control
    dispositions, blocker sets, readiness booleans and the release recommendation.
    """
    body = {k: v for k, v in summary.items() if k not in NON_CANONICAL_KEYS}
    body["results"] = [
        {k: v for k, v in result.items() if k != "contract_reconciliation"}
        for result in summary.get("results", [])
    ]
    body["readiness_execution_capacity"] = summary.get("readiness_execution_capacity")
    return body


def canonical_result_json(summary: Mapping[str, Any]) -> str:
    return json.dumps(canonical_result_body(summary), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str)


def canonical_result_hash(summary: Mapping[str, Any]) -> str:
    """Full lowercase SHA-256 over :func:`canonical_result_body`."""
    return hashlib.sha256(canonical_result_json(summary).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- CLI

def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Execute the canonical readiness contexts.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--context", help="run exactly one canonical context by id")
    group.add_argument("--all", action="store_true", help="run every canonical context (default)")
    parser.add_argument("--reverse", action="store_true", help="execute in reverse canonical order")
    parser.add_argument("--seed", type=int, default=None,
                        help="execute in deterministically seeded pseudo-random order")
    parser.add_argument("--inspect", action="store_true",
                        help="inspection mode: report the harness state without certifying; exits 0 "
                             "even when execution is unavailable")
    args = parser.parse_args(list(argv) if argv is not None else None)

    summary = run_contexts([args.context] if args.context else None,
                           reverse=args.reverse, seed=args.seed)

    if args.inspect:
        summary = dict(summary)
        summary["inspection_only"] = True
        summary["contexts_executed"] = False
        summary["accepted"] = False
        summary["certification"] = "unavailable" if summary.get("certification") != "passed" \
            else summary["certification"]

    print(json.dumps(summary, indent=2, sort_keys=True, default=str))

    if args.inspect:
        # Inspection mode never certifies, so it may exit zero -- but only because it has just
        # printed inspection_only=true, contexts_executed=false and accepted=false.
        return 0
    return 0 if summary.get("accepted") else 1


if __name__ == "__main__":
    raise SystemExit(main())
