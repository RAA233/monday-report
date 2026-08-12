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
``evaluate_context`` is *deterministic and self-contained*: observations in, canonical result out,
no clock, no network, and it launches no container, database, API, worker or browser. It is NOT
side-effect free, and claiming so would be false: the real evaluator it calls reads repository
artifacts, shells out to ``git`` to check commit/tree bindings, sets environment variables and
creates isolated temp state while probing, and caches some results process-wide -- so the first
context evaluated in a process seeds a cache the others reuse. What matters for this harness is that
those effects are confined to the evaluator's own probes and cannot start the runtime under test.

``collect_observations`` is the half that produces observations from a really-started runtime, and it
is the ONLY place *this module* launches a process. Splitting them is what makes the harness testable
without Docker: the fault battery drives ``evaluate_context`` with synthetic observations, and is
classified as ``predicate/unit mutation`` rather than as an executed context.

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

#: The accepted canonical inventory hash. PINNED to a literal on purpose: comparing results against
#: whatever the contract module computes at run time only ever proves self-consistency, so a mutated
#: contract would certify happily. A mismatch here refuses the run.
ACCEPTED_INVENTORY_HASH = "b9d78ad9e8791375a03c1ef437c4c663043b087bf60f80ca72d69a0f41787d44"

#: Registry control ids that can NEVER be PASS in any of the four contexts, whatever a run observes.
#:
#: None of the four contexts is a production deployment: the PostgreSQL contexts run the *restricted*
#: runtime, classified ``restricted_postgres_runtime_not_production_adapter``, and every context runs
#: the inline worker. But ``readiness.postgres_repository`` passes whenever the requested and active
#: backend are both PostgreSQL with a database URL -- i.e. precisely on that restricted runtime -- so
#: without this list the accepted restricted-PG runtime would promote ``production-database-adapter``,
#: a UNIVERSAL GA blocker, to PASS and the harness would certify the run. Forced BLOCKED instead.
NEVER_PROMOTABLE_CONTROL_IDS: tuple[str, ...] = (
    "production-database-adapter",
    "production-queue-adapter",
)


def universal_ga_blockers() -> tuple[str, ...]:
    """Evaluator check ids that block GA in EVERY context, DERIVED from the real registry.

    Hand-typing check ids here would drift from the registry (and would itself be a restatement of
    the control ids the runner claims never to restate).
    """
    mapping = control_check_ids()
    ids = [mapping[control_id] for control_id in NEVER_PROMOTABLE_CONTROL_IDS if control_id in mapping]
    approval = mapping.get("client-organizational-approval")
    if approval:
        ids.append(approval)
    return tuple(sorted(ids))


#: Observers this module itself implements. A result is only ever CERTIFIABLE when it came from one
#: of them: the `observer=` seam exists so the decision logic can be mutation-tested with synthetic
#: observations, and a synthetic run must never be able to reach an accepted verdict.
RECOGNISED_OBSERVERS: frozenset[str] = frozenset({
    "local_json_isolated_root",
    "restricted_postgres_runtime",
})


class ExecutionUnavailable(RuntimeError):
    """Raised when observations cannot be produced. Never converted into a PASS."""


# --------------------------------------------------------------------------- capacity gate (Part B)

def measure_capacity(path: str | None = None) -> dict[str, Any]:
    """Strictly read-only capacity facts. Launches nothing, removes nothing, changes nothing.

    Measures the volume the repository itself lives on rather than a hardcoded drive letter, so the
    gate cannot read green off one volume while the volume that actually fills is a different one.
    """
    total, _used, free = shutil.disk_usage(str(ROOT) if path is None else path)
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

    # Re-DERIVE the verdict from the raw numbers; never trust supplied booleans. Facts that omit the
    # numbers cannot be judged and are therefore blocked.
    total = observed.get("filesystem_total_bytes")
    free = observed.get("filesystem_free_bytes")
    if not isinstance(total, int) or not isinstance(free, int) or total <= 0 or free < 0:
        observed.update({"free_bytes_ok": False, "free_percentage_ok": False,
                         "measurement_error": "capacity facts omit usable byte counts",
                         "readiness_execution_capacity": "blocked"})
        return False, observed
    observed["free_bytes_ok"] = free >= CAPACITY_MIN_FREE_BYTES
    observed["free_percentage_ok"] = (free / total) >= CAPACITY_MIN_FREE_RATIO
    passed = bool(observed["free_bytes_ok"]) and bool(observed["free_percentage_ok"])
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
        # separated statuses (Part D): a refusal never executed and observed nothing, and it is
        # fail-closed -- it carries no blockers of either kind and can never be accepted.
        "context_execution_status": "refused",
        "context_observation_status": "unavailable",
        "context_specific_blockers": [],
        "global_release_blockers": [],
        "overall_GA_status": "GA_BLOCKED",
        "pg_runtime_identity": None,
        "migration_runtime_roles_distinct": None,
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
    # The mode axis needs binding too: `client_mode` feeds ga_production_configuration, so a demo
    # context observing client_mode=pass would promote that control on a self-contradiction.
    "client_mode": ("client_data_mode", ("client",)),
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

    # A caller must NEVER be able to hand us dispositions, nor an artifact-shaped input that MINTS
    # one. ``forge_report`` is exactly such an input: ga_readiness._forge_probe accepts a
    # self-consistent report and returns PASS for parser-coverage, so a hand-authored report would
    # promote a control without any real evidence. Refused outright; the probe may read the committed
    # report itself, but this harness will not carry one in.
    for forbidden in ("control_dispositions", "dispositions", "expected_control_dispositions",
                      "forge_report"):
        if observations.get(forbidden) is not None:
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

    if RC.canonical_hash() != ACCEPTED_INVENTORY_HASH:
        return _refusal(run_input, "the canonical inventory does not match the accepted hash",
                        detail={"observed": RC.canonical_hash(),
                                "accepted": ACCEPTED_INVENTORY_HASH})

    try:
        checks = GA.evaluate_blockers(dict(readiness_by_id), forge_report=None)
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
    mapping = control_check_ids()
    never_promotable = {mapping[c] for c in NEVER_PROMOTABLE_CONTROL_IDS if c in mapping}
    demoted: list[dict[str, str]] = []
    for check_id, disposition in list(dispositions.items()):
        if disposition != "PASS":
            continue
        if applicability.get(check_id) == "not_evaluable_in_this_context":
            dispositions[check_id] = "BLOCKED"
            demoted.append({"check_id": check_id,
                            "observed": "PASS",
                            "recorded": "BLOCKED",
                            "reason": "this configuration cannot evaluate the control; evidence "
                                      "produced elsewhere is not transferable into this context"})
        elif check_id in never_promotable:
            dispositions[check_id] = "BLOCKED"
            demoted.append({"check_id": check_id,
                            "observed": "PASS",
                            "recorded": "BLOCKED",
                            "reason": "none of the four contexts is a production deployment (the "
                                      "PostgreSQL contexts run the RESTRICTED runtime and every "
                                      "context runs the inline worker), so a production adapter "
                                      "control can never PASS here"})

    blocking = sorted(cid for cid, d in dispositions.items() if d in BLOCKING_DISPOSITIONS)
    # Anything neither PASS nor blocking (SKIPPED / NOT_APPLICABLE) is a warning. REVIEW_REQUIRED is
    # already blocking per the real evaluator, so it deliberately does not appear here.
    warning = sorted(cid for cid, d in dispositions.items()
                     if d != "PASS" and cid not in blocking)

    universal = universal_ga_blockers()
    unresolved_universal = [cid for cid in universal
                            if dispositions.get(cid) != "PASS" and cid not in blocking]
    if unresolved_universal:
        return _refusal(run_input, "an unresolved universal GA blocker is not being counted",
                        detail={"controls": unresolved_universal})

    # Readiness is DERIVED, and requires EVERY control to be PASS -- not merely "nothing blocking",
    # which would let a SKIPPED control pass for readiness.
    client_data_ready = bool(dispositions) and all(d == "PASS" for d in dispositions.values())
    ga_ready = client_data_ready and all(dispositions.get(c) == "PASS" for c in universal)

    # Part D separation: a context is EXECUTION-accepted when it ran and produced qualifying
    # observations, EVEN THOUGH global GA blockers remain. Split the blocking set into the two
    # meanings so a reader never mistakes a repository-wide GA blocker (production adapters,
    # organizational approval) for a failure of THIS context's own execution/observation.
    global_release_blockers = sorted(set(blocking) & set(universal))
    context_specific_blockers = sorted(set(blocking) - set(universal))

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
        # explicit, separately-named statuses (Part D): execution success is independent of GA
        "context_execution_status": "executed",
        "context_observation_status": "observations_complete",
        "context_specific_blockers": context_specific_blockers,
        "global_release_blockers": global_release_blockers,
        "overall_GA_status": "GA_BLOCKED",
        "pg_runtime_identity": observations.get("pg_runtime_identity"),
        "migration_runtime_roles_distinct": observations.get("migration_runtime_roles_distinct"),
        "local_persistence": observations.get("local_persistence"),
        "pg_persistence": observations.get("pg_persistence"),
        "workflow": observations.get("workflow"),
        "isolation": observations.get("isolation"),
        "overall_readiness": "ready" if client_data_ready else "not_ready",
        "client_data_ready": bool(client_data_ready),
        "release_candidate_ready": bool(ga_ready),
        "ga_ready": bool(ga_ready),
        "production_parity": False,
        "result": "evaluated",
        "refusal_reason": None,
        "refusal_detail": None,
        "dispositions_source": "backend.app.ga_readiness.evaluate_blockers",
        "observer": str(observations.get("observer") or "unspecified"),
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


def _seed_txn(store: Any):
    """The backend-appropriate snapshot transaction for the read-back seed: PostgresStateStore
    requires ``snapshot_transaction()`` (an unprotected write fails closed); LocalStateStore uses
    ``local_snapshot_transaction()``."""
    if type(store).__name__ == "PostgresStateStore":
        return store.snapshot_transaction()
    return store.local_snapshot_transaction()


def _client_verified_reviewer(store: Any):
    """Establish a request-scoped VERIFIED reviewer for a client-mode terminal validation outcome:
    a real active non-bootstrap user + active credential bound to the tenant, set as the current
    identity. Returns (token, reset_fn); the caller resets it. In demo mode returns (None, None)."""
    from backend.app.identity import set_current_identity, reset_current_identity
    from backend.app.schemas import AuthenticatedIdentity, Role

    user = store.create_user("rc-reviewer@readiness.test", "RC Reviewer", [Role.ADMIN])
    cred, _token = store.create_credential(user.id)
    identity = AuthenticatedIdentity(
        user_id=user.id, tenant_id=store.tenant.id, email=user.email, display_name=user.full_name,
        roles=list(user.roles), account_status="active", authentication_source="api_token",
        credential_id=cred.credential_id, credential_fingerprint=cred.token_fingerprint,
        actor_source="authenticated")
    token = set_current_identity(identity)
    return token, reset_current_identity


def _isolation_preflight(run_input: Mapping[str, Any], *, target_kind: str, target_identity: str,
                         expected_prefix: str | None = None,
                         forbidden_substrings: tuple[str, ...] = ()) -> dict[str, Any]:
    """Prove, BEFORE any mutating operation, that this context targets its OWN isolated resource and
    never reuses another context's state/database or a shared/demo/live target. Compares the
    certified (expected) target against the target actually in use and fails closed
    (ExecutionUnavailable) on any mismatch or forbidden shared reference. Returns an isolation facts
    dict on success."""
    cid = run_input["context_id"]
    problems: list[str] = []
    ti = str(target_identity)
    if cid not in RC.CANONICAL_CONTEXT_ORDER:
        problems.append(f"unknown context id {cid!r}")
    for bad in forbidden_substrings:
        if bad and bad in ti:
            problems.append(f"target references forbidden shared/live resource {bad!r}")
    if expected_prefix is not None and not ti.startswith(str(expected_prefix)):
        problems.append("actual target is not under this context's isolated root "
                        "(certified vs actual target mismatch)")
    if problems:
        raise ExecutionUnavailable(f"isolation preflight failed for {cid} [{target_kind}]: {problems}")
    return {
        "context_id": cid,
        "target_kind": target_kind,
        "certified_matches_actual": True,
        "shared_or_live_target_rejected": True,
        "isolated": True,
    }


def _pg_workflow_readback(store: Any, mode: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """PostgreSQL persisted workflow + read-back through the REAL normalized PostgresStateStore, using
    ONLY supported wrapped mutations (no direct-dict seed, no ad-hoc SQL, no RLS bypass). The
    validation task is created by the SUPPORTED application workflow -- a Critical benchmark breach via
    record_benchmark_measurement spawns a critical ValidationTask (_register_validation_task threads
    the normalized persist hook). Every critical mutation is read back from an INDEPENDENT fresh
    PostgresStateStore (a separate RLS-scoped connection), never from a response body. Returns
    (pg_persistence_facts, workflow_facts)."""
    from datetime import date
    import backend.app.store as store_mod
    from backend.app.identity import set_current_identity, reset_current_identity
    from backend.app.schemas import (AuthenticatedIdentity, BenchmarkMeasurementCreate,
                                      MondayReportCreate, Role, ValidationTaskUpdate, WorkspaceCreate)

    reader = store_mod.create_store()  # INDEPENDENT DB reader (fresh restricted-role connection)
    if type(reader).__name__ != "PostgresStateStore":
        raise ExecutionUnavailable("read-back store is not a PostgresStateStore")

    def db_view() -> dict:
        reader.refresh()
        return {
            "reports": {str(r.id): r.status for r in reader.monday_reports.values()},
            "tasks": {str(t.id): t.status for t in reader.validation_tasks.values()},
            "events": [(e.action, str(e.resource_id)) for e in reader.audit_logs],
        }

    def ecount(view: dict, action: str, rid) -> int:
        return sum(1 for a, r in view["events"] if a == action and r == str(rid))

    # MUTATION BOUNDARY: the independent reader above was the last read-only step; everything below
    # MUTATES (create_user / create_workspace / record_benchmark_measurement / ...). Mark the monotonic
    # per-attempt flag NOW so a transient connection failure from here on is NEVER retried.
    import restricted_stack_orchestration as O
    O.mark_business_mutation_started()

    # Client mode: a verified reviewer authenticates the whole workflow (terminal validation requires
    # it). Create the reviewer via the supported path, then bind the request identity.
    rev_token = None
    if mode == "client":
        user = store.create_user("rc-pgwf-reviewer@readiness.test", "RC PGWF Reviewer", [Role.ADMIN])
        cred, _tok = store.create_credential(user.id)
        ident = AuthenticatedIdentity(
            user_id=user.id, tenant_id=store.tenant.id, email=user.email,
            display_name=user.full_name, roles=list(user.roles), account_status="active",
            authentication_source="api_token", credential_id=cred.credential_id,
            credential_fingerprint=cred.token_fingerprint, actor_source="authenticated")
        rev_token = set_current_identity(ident)
    try:
        ws = store.create_workspace(WorkspaceCreate(name="rc-pgwf"))
        # a Critical drilling-rate deviation (well below the ~448.8 critical threshold) -> critical task
        store.record_benchmark_measurement(ws.id, BenchmarkMeasurementCreate(
            metric="feet_drilled_per_day", value=300.0, unit="ft/day", data_source="rc-readiness"))
        report = store.create_monday_report(MondayReportCreate(
            workspace_id=ws.id, period_start=date(2026, 7, 6), period_end=date(2026, 7, 12)))
        open_tasks = store.report_open_validation_tasks(report.id)
        task = next((t for t in open_tasks if getattr(t, "priority", None) == "critical"),
                    open_tasks[0] if open_tasks else None)
        if task is None:
            raise ExecutionUnavailable("the Critical benchmark breach did not create a validation task")
        gate_closed = bool(open_tasks)

        store.mark_report_export_blocked(report.id, "json", False, [t.id for t in open_tasks])
        v1 = db_view()
        export_status_persisted = v1["reports"].get(str(report.id)) == "review"
        export_event_count = ecount(v1, "monday_report.export_blocked", report.id)

        store.update_validation_task(task.id, ValidationTaskUpdate(status="validated"))
        v2 = db_view()
        validation_status_persisted = v2["tasks"].get(str(task.id)) == "validated"
        validation_event_count = ecount(v2, "validation_task.update", task.id)

        for rem in store.report_open_validation_tasks(report.id):
            store.update_validation_task(rem.id, ValidationTaskUpdate(status="validated"))
        gate_open = not store.report_open_validation_tasks(report.id)
        export = store.export_monday_report(report.id, "json")
        signed = bool(getattr(export, "storage_uri", None) or getattr(export, "signed_url", None)
                      or getattr(export, "download_reference", None) or getattr(export, "download_url", None))
        v3 = db_view()
        report_list_ok = str(report.id) in v3["reports"]
        report_draft_ok = getattr(reader.monday_reports.get(report.id), "report_json", None) is not None
        try:
            reader.benchmarking_status(ws.id)
            benchmarking_ok = True
        except Exception:  # noqa: BLE001
            benchmarking_ok = False
        chain_ok = reader.audit_integrity_status().status == "sealed"
    finally:
        if rev_token is not None:
            reset_current_identity(rev_token)

    contradiction = ((export_event_count and not export_status_persisted)
                     or (validation_event_count and not validation_status_persisted))
    pg = {
        "validation_decision_persisted": bool(validation_status_persisted),
        "validation_audit_event_count": int(validation_event_count),
        "blocked_export_status_persisted": bool(export_status_persisted),
        "blocked_export_audit_event_count": int(export_event_count),
        "audit_chain_valid": bool(chain_ok),
        "business_audit_contradiction": bool(contradiction),
        "validation_task_created_by": "record_benchmark_measurement_critical_breach",
        "read_back_source": "independent_fresh_postgres_store",
    }
    pg["pg_persistence_verified"] = bool(
        validation_status_persisted and validation_event_count == 1
        and export_status_persisted and export_event_count == 1
        and chain_ok and not contradiction)
    workflow = {
        "tenant_scoped_report_list": bool(report_list_ok),
        "report_draft_retrieved": bool(report_draft_ok),
        "benchmarking_observed": bool(benchmarking_ok),
        "export_gate_closed_on_unresolved_validation": bool(gate_closed),
        "validation_unlocks_export_gate": bool(gate_open),
        "export_issued": bool(export is not None),
        "signed_reference_issued": bool(signed),
        "audit_chain_valid_after_workflow": bool(chain_ok),
    }
    workflow["workflow_verified"] = bool(
        report_list_ok and report_draft_ok and benchmarking_ok and gate_closed
        and gate_open and signed and chain_ok)
    return pg, workflow


def _observe_supported_workflow(store: Any, mode: str, ws_id, report_id, open_task_id) -> dict[str, Any]:
    """Observe the supported workflow through committed store methods, reusing the read-back's seed:
    tenant-scoped report list, report draft retrieval, benchmarking status, the export gate CLOSED
    while an unresolved validation task remains, the gate UNLOCKING once it is resolved, real export
    issuance, and a signed download reference on the resulting export. All facts are DETERMINISTIC
    booleans. Returns a workflow facts dict with a ``workflow_verified`` boolean."""
    from backend.app.schemas import ValidationTaskUpdate

    # The store's committed projection already reflects the read-back's persisted mutations; no
    # out-of-band refresh (it would desync the PostgresStateStore optimistic-CAS revision).
    report_list_ok = report_id in store.monday_reports and len(store.monday_reports) >= 1
    report_draft_ok = bool(getattr(store.monday_reports.get(report_id), "report_json", None) is not None)
    try:
        store.benchmarking_status(ws_id)
        benchmarking_ok = True
    except Exception:  # noqa: BLE001 - a benchmarking failure is a workflow failure, recorded not raised
        benchmarking_ok = False

    # export gate CLOSED: the official-export gate predicate is report_open_validation_tasks(); while
    # the remaining validation task is unresolved it must report an open task that blocks the export.
    export_gate_closed_ok = bool(store.report_open_validation_tasks(report_id))

    # resolve the remaining task (verified reviewer in client mode), then the gate must UNLOCK
    reviewer_token = reviewer_reset = None
    if mode == "client":
        reviewer_token, reviewer_reset = _client_verified_reviewer(store)
    try:
        store.update_validation_task(open_task_id, ValidationTaskUpdate(status="validated"))
    finally:
        if reviewer_reset is not None and reviewer_token is not None:
            reviewer_reset(reviewer_token)

    # report_open_validation_tasks refreshes internally; no out-of-band refresh (it would desync the
    # PostgresStateStore optimistic-CAS revision and make export_monday_report raise SnapshotConflict).
    gate_open = not store.report_open_validation_tasks(report_id)
    export_unlock_ok = False
    signed_reference_ok = False
    try:
        export = store.export_monday_report(report_id, "json")
        export_unlock_ok = gate_open  # the gate opened AND the export issued
        signed_reference_ok = bool(
            getattr(export, "storage_uri", None) or getattr(export, "signed_url", None)
            or getattr(export, "download_reference", None) or getattr(export, "download_url", None))
    except Exception:  # noqa: BLE001 - recorded as a workflow failure
        pass

    chain_ok = store.audit_integrity_status().status == "sealed"
    facts = {
        "tenant_scoped_report_list": bool(report_list_ok),
        "report_draft_retrieved": bool(report_draft_ok),
        "benchmarking_observed": bool(benchmarking_ok),
        "export_gate_closed_on_unresolved_validation": bool(export_gate_closed_ok),
        "validation_unlocks_export_gate": bool(export_unlock_ok),
        "export_issued": bool(export_unlock_ok),
        "signed_reference_issued": bool(signed_reference_ok),
        "audit_chain_valid_after_workflow": bool(chain_ok),
    }
    facts["workflow_verified"] = bool(
        report_list_ok and report_draft_ok and benchmarking_ok and export_gate_closed_ok
        and export_unlock_ok and signed_reference_ok and chain_ok)
    return facts


def _persistence_readback_core(store: Any, mode: str, snapshot, *, has_revision: bool,
                               observe_workflow: bool = False) -> dict[str, Any]:
    """Shared persisted-state read-back for BOTH the local-JSON store and the restricted
    PostgresStateStore. Seeds an isolated workspace/failure/tasks/report, exercises the blocked-export
    transition and a validation decision, and asserts -- from ``snapshot()`` (a re-read of the
    persisted state, NEVER a response body) -- that each persisted together with its audit event
    exactly once, the audit chain stays sealed, and there is no business/audit contradiction. The
    revision-advance invariant is asserted only where the backend exposes a snapshot revision (local).

    ``snapshot()`` returns ``{"monday_reports":[{id,status}], "validation_tasks":[{id,status}],
    "audit_logs":[{action,resource_id}], "snapshot_revision": int?}``.
    Returns a facts dict with a ``persistence_verified`` boolean; the caller fails closed on False."""
    from backend.app.schemas import (FailureRecord, MondayReport, ValidationTask,
                                      ValidationTaskUpdate, Workspace)

    tenant_id = store.tenant.id

    def _events(snap: dict, action: str, rid) -> int:
        return sum(1 for e in snap.get("audit_logs", [])
                   if e.get("action") == action and str(e.get("resource_id")) == str(rid))

    def _rev(snap: dict):
        return int(snap.get("snapshot_revision", 0)) if has_revision else None

    # Sync the store's optimistic-CAS baseline ONCE before the first write: the preceding readiness
    # evaluation reads/refreshes the store, which can leave a stale expected revision. A single leading
    # refresh is harmless on the local backend; no refresh follows a write.
    store.refresh()
    ws = Workspace(tenant_id=tenant_id, name="rc-readback", asset="a", campaign="c")
    f1 = FailureRecord(tenant_id=tenant_id, workspace_id=ws.id, event_type="npt", severity="High",
                       summary="MWD signal loss", confidence=0.9)
    f2 = FailureRecord(tenant_id=tenant_id, workspace_id=ws.id, event_type="npt", severity="High",
                       summary="stuck pipe", confidence=0.9)
    t1 = ValidationTask(tenant_id=tenant_id, target_type="failure", target_id=f1.id,
                        reason="High-severity extracted failure requires review.", status="open")
    t2 = ValidationTask(tenant_id=tenant_id, target_type="failure", target_id=f2.id,
                        reason="High-severity extracted failure requires review.", status="open")
    report = MondayReport(tenant_id=tenant_id, workspace_id=ws.id, period_start="2026-07-06",
                          period_end="2026-07-12", report_json={"summary": "seed"}, status="draft")
    # The seed must run inside the backend's snapshot transaction: PostgresStateStore.save() fails
    # closed on an unprotected write ("PostgreSQL mutations must run inside snapshot_transaction()"),
    # which is exactly the client-data-safety guard. The transaction commits (persists) on exit.
    with _seed_txn(store):
        store.workspaces[ws.id] = ws
        store.failures[f1.id] = f1
        store.failures[f2.id] = f2
        store.validation_tasks[t1.id] = t1
        store.validation_tasks[t2.id] = t2
        store.monday_reports[report.id] = report
        store.save()  # inside the txn: marks it dirty (local) / performs the protected write (PG)
    rev0 = _rev(snapshot())

    # -- blocked-export path: status transition + export_blocked audit persist together, once --
    open_tasks = store.report_open_validation_tasks(report.id)
    store.mark_report_export_blocked(report.id, "json", False, [t.id for t in open_tasks])
    snap_b = snapshot()
    persisted_report = next(r for r in snap_b["monday_reports"] if r["id"] == str(report.id))
    rev_after_block = _rev(snap_b)

    # -- validation decision: status + validation_task.update audit persist together, once --
    # A client-mode terminal outcome requires a VERIFIED reviewer; establish one, scoped to this call.
    reviewer_token = reviewer_reset = None
    if mode == "client":
        reviewer_token, reviewer_reset = _client_verified_reviewer(store)
    try:
        store.update_validation_task(t1.id, ValidationTaskUpdate(status="validated"))
    finally:
        if reviewer_reset is not None and reviewer_token is not None:
            reviewer_reset(reviewer_token)
    snap_v = snapshot()
    persisted_task = next(t for t in snap_v["validation_tasks"] if t["id"] == str(t1.id))
    rev_after_val = _rev(snap_v)

    export_status_persisted = persisted_report["status"] == "review"
    export_event_count = _events(snap_v, "monday_report.export_blocked", report.id)
    validation_status_persisted = persisted_task["status"] == "validated"
    validation_event_count = _events(snap_v, "validation_task.update", t1.id)
    chain_status = store.audit_integrity_status().status
    contradiction = ((export_event_count and not export_status_persisted)
                     or (validation_event_count and not validation_status_persisted))
    revision_advanced = (rev_after_block > rev0 and rev_after_val > rev_after_block
                         if has_revision else None)

    facts = {
        "validation_decision_persisted": bool(validation_status_persisted),
        "validation_audit_event_count": int(validation_event_count),
        "blocked_export_status_persisted": bool(export_status_persisted),
        "blocked_export_audit_event_count": int(export_event_count),
        "audit_chain_status": str(chain_status),
        "audit_chain_valid": str(chain_status) == "sealed",
        "business_audit_contradiction": bool(contradiction),
    }
    if has_revision:
        # Only the DETERMINISTIC boolean is retained (raw revision integers would break the accepted
        # audit:readiness-contexts reproducibility invariants -- identical canonical hash across runs).
        facts["snapshot_revision_advanced"] = bool(revision_advanced)
    facts["persistence_verified"] = bool(
        validation_status_persisted and validation_event_count == 1
        and export_status_persisted and export_event_count == 1
        and facts["audit_chain_valid"] and not contradiction
        and (revision_advanced if has_revision else True))
    if observe_workflow:
        # reuse the seed: t1 is validated, t2 is still open -> exercise the export gate + unlock
        facts["workflow"] = _observe_supported_workflow(store, mode, ws.id, report.id, t2.id)
    return facts


def _local_persistence_readback(store: Any, mode: str) -> dict[str, Any]:
    """Local-JSON persisted-state read-back: assertions read from the ON-DISK state file."""
    import json as _json
    from pathlib import Path as _Path

    def snapshot() -> dict:
        return _json.loads(_Path(store.state_path).read_text(encoding="utf-8"))

    facts = _persistence_readback_core(store, mode, snapshot, has_revision=True, observe_workflow=True)
    facts["local_persistence_verified"] = facts.pop("persistence_verified")
    return facts


def _observe_local(run_input: Mapping[str, Any]) -> dict[str, Any]:
    """Observe a local-JSON context in an ISOLATED temp root. Never touches live ``.local_data``."""
    from backend.app import readiness as READINESS

    mode = run_input["client_data_mode"]
    previous = {k: os.environ.get(k) for k in
                ("MONDAY_REPORT_CLIENT_DATA_MODE", "MONDAY_REPORT_REPOSITORY_BACKEND",
                 "MONDAY_REPORT_STATE_PATH", "MONDAY_REPORT_STORAGE_ROOT",
                 "MONDAY_REPORT_EXPORT_ROOT", "MONDAY_REPORT_AUDIT_HMAC_KEY")}
    tmp = tempfile.mkdtemp(prefix="rc-ctx-local-")
    try:
        os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "client" if mode == "client" else "demo"
        os.environ["MONDAY_REPORT_REPOSITORY_BACKEND"] = "local_json"
        # Bind the store to THIS context's isolated temp root via the variables the store actually
        # reads (MONDAY_REPORT_STATE_PATH / STORAGE_ROOT / EXPORT_ROOT). The prior MONDAY_REPORT_DATA_DIR
        # was ignored by the store, so the observer silently used the shared .local_data default -- the
        # isolation preflight below now rejects exactly that.
        os.environ["MONDAY_REPORT_STATE_PATH"] = str(Path(tmp) / "state.json")
        os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(Path(tmp) / "storage")
        os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(Path(tmp) / "exports")
        # A configured audit-integrity key is required for the persisted-state read-back to be
        # coherent: the store keys its bootstrap events, and a post-refresh append must use the SAME
        # key or it is refused ("unkeyed behind a keyed suffix"). Provide a disposable isolated key
        # BEFORE the store is constructed, for both modes, so bootstrap and the read-back stay
        # consistent. It is scoped to this context's temp root and restored in the finally -- never a
        # shared or client key. (Client mode additionally requires it before any mutation.)
        os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = (
            "readiness-context-local-observer-disposable-audit-hmac-key-000000000000")
        from backend.app.store import LocalStateStore

        store = LocalStateStore()
        # ISOLATION PREFLIGHT (before any mutation): prove this context targets its OWN isolated
        # state, never shared/demo/.local_data. Fail closed on any mismatch.
        isolation = _isolation_preflight(
            run_input, target_kind="local_json_state_file", target_identity=str(store.state_path),
            expected_prefix=tmp, forbidden_substrings=(".local_data", ":8000", ":5173"))
        readiness = READINESS.evaluate_client_data_readiness(store)
        # Prove the accepted atomicity from the persisted snapshot in THIS isolated context.
        persistence = _local_persistence_readback(store, mode)
        workflow = persistence.pop("workflow", None)
        if not persistence["local_persistence_verified"]:
            raise ExecutionUnavailable(
                "local persisted-state read-back failed; the isolated LocalStateStore did not "
                f"persist a decision + its audit event atomically: {persistence}")
        if not (workflow and workflow.get("workflow_verified")):
            raise ExecutionUnavailable(f"local workflow observation failed: {workflow}")
        return {
            "source": "executed",
            "context_id": run_input["context_id"],
            "observer": "local_json_isolated_root",
            "readiness_by_id": {c.id: c.status for c in readiness.checks},
            "forge_report": None,
            "counters": {c: 0 for c in REQUIRED_ZERO_COUNTERS},
            "evidence_artifacts_consumed": [],
            "local_persistence": persistence,
            "workflow": workflow,
            "isolation": isolation,
        }
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(tmp, ignore_errors=True)


#: Generic test/PostgreSQL environment variables that MUST be cleared before the restricted stack
#: provisions its own roles, so the observed runtime can never be an externally supplied superuser
#: DSN leaking in through the environment. (This is the leak that silently promoted a superuser
#: session in an earlier run: a stray MONDAY_REPORT_TEST_DATABASE_URL bled into the launched API.)
_LEAKED_PG_ENV: tuple[str, ...] = (
    "MONDAY_REPORT_TEST_DATABASE_URL", "MONDAY_REPORT_TEST_PG_SERVER_VERSION",
    "MONDAY_REPORT_TEST_PGVECTOR_VERSION", "MONDAY_REPORT_TEST_PG_IMAGE_DIGEST",
    "MONDAY_REPORT_DATABASE_URL", "MONDAY_REPORT_REPOSITORY_BACKEND",
    "PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGSERVICE", "PGSSLMODE",
)


def _pg_runtime_identity(rt_dsn: str) -> dict[str, Any]:
    """Observe the runtime-login identity DIRECTLY on the restricted DSN the store uses.

    Read-only pg_roles / pg_class facts that prove the observed runtime is the RESTRICTED login
    (non-superuser, non-BYPASSRLS, cannot own the protected tables) and that row-level security is
    FORCED. The accepted foundation already certifies these (startup guard I01-I03/P02/P04); observing
    them again here makes the readiness observer itself load-bearing rather than trusting a sibling.
    """
    import psycopg

    with psycopg.connect(rt_dsn, connect_timeout=10, autocommit=True) as conn:
        role = conn.execute(
            "select rolsuper, rolbypassrls, rolcanlogin from pg_roles where rolname = current_user"
        ).fetchone()
        # Across the public tables that have RLS ENABLED (the protected relations): how many FORCE it,
        # and how many enable-but-do-not-force it (must be zero for "RLS is forced on them").
        forced, enabled_not_forced = conn.execute(
            "select "
            " count(*) filter (where c.relrowsecurity and c.relforcerowsecurity), "
            " count(*) filter (where c.relrowsecurity and not c.relforcerowsecurity) "
            "from pg_class c join pg_namespace n on n.oid = c.relnamespace "
            "where n.nspname = 'public' and c.relkind = 'r'"
        ).fetchone()
        owns = conn.execute(
            "select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace "
            "where n.nspname = 'public' and c.relkind = 'r' and pg_get_userbyid(c.relowner) = current_user"
        ).fetchone()[0]
        # DB-observed principal separation: the RLS-protected tables are owned by a role OTHER than
        # the runtime login. Derived from the live catalog, not from run-scoped role NAMES (which are
        # constructed with distinct prefixes and would make any name comparison a tautology).
        owned_by_other = conn.execute(
            "select count(distinct pg_get_userbyid(c.relowner)) "
            "from pg_class c join pg_namespace n on n.oid = c.relnamespace "
            "where n.nspname = 'public' and c.relkind = 'r' and c.relrowsecurity "
            "and pg_get_userbyid(c.relowner) <> current_user"
        ).fetchone()[0]
    return {
        # current_user == session_user here (no SET ROLE); rolcanlogin proves it is a LOGIN role
        "session_user_is_restricted_login": bool(role[2]),
        "runtime_not_superuser": not bool(role[0]),
        "runtime_not_bypassrls": not bool(role[1]),
        "runtime_owns_no_protected_tables": int(owns) == 0,
        "forced_rls_table_count": int(forced),
        # observed for transparency: public tables that ENABLE RLS without FORCING it. Not gated on
        # zero -- a table outside the runtime's protected write set may legitimately enable-not-force,
        # and the accepted foundation (startup guard P04) certifies the complete protected forced set.
        "rls_enabled_not_forced_count": int(enabled_not_forced),
        "rls_forced_on_protected_tables": int(forced) > 0,
        # observed at the DB: the protected tables are owned by a principal that is NOT the runtime
        "migration_owner_distinct_from_runtime": int(owned_by_other) >= 1,
    }


def _observe_postgres_live(run_input: Mapping[str, Any], mode: str, ctx: Mapping[str, Any],
                           captured: dict[str, Any]) -> None:
    """Build a real ``PostgresStateStore`` on the live restricted runtime login and evaluate
    client-data readiness against it, in this context's client-data mode. Runs inside the accepted
    foundation's ``_ON_LIVE`` hook, so the stack (disposable container, distinct migration + runtime
    login roles, migrations 0001-0007 applied by the migration login, forced RLS, external API) is
    already provisioned and will be torn down by ``run_stack`` after this returns."""
    from backend.app import readiness as READINESS
    import backend.app.store as store_mod
    import restricted_stack_orchestration as O   # attempt-local lifecycle marks (pre-mutation phase)

    rt = ctx["rt_dsn"]                         # restricted, non-superuser, non-BYPASSRLS LOGIN
    appname = f"mr-readiness-obs-{ctx['run_hash']}"
    O.mark("store_connection_started")         # the identity probe is the first pre-mutation connection
    identity = _pg_runtime_identity(rt)        # observe the runtime login BEFORE evaluating readiness

    # ENFORCE, do not merely observe: if the runtime is NOT the restricted login (superuser, or
    # BYPASSRLS, or owns protected tables, or RLS is not forced, or the migration owner is not
    # distinct, or it is not a LOGIN role), refuse. Otherwise a future foundation regression that
    # provisioned an unsafe runtime would still yield an "executed" observation. Fail-closed.
    required_true = ("session_user_is_restricted_login", "runtime_not_superuser",
                     "runtime_not_bypassrls", "runtime_owns_no_protected_tables",
                     "rls_forced_on_protected_tables", "migration_owner_distinct_from_runtime")
    unsafe = [k for k in required_true if not identity.get(k)]
    if unsafe:
        raise ExecutionUnavailable(
            "the observed PostgreSQL runtime is not the restricted login the context requires "
            f"(unsatisfied identity guarantees: {sorted(unsafe)})")

    obs_env = dict(ctx["base_env"])
    obs_env.update({
        "MONDAY_REPORT_DATABASE_URL": f"{rt}?application_name={appname}",
        "MONDAY_REPORT_REPOSITORY_BACKEND": "postgres",
        "MONDAY_REPORT_CLIENT_DATA_MODE": "client" if mode == "client" else "demo",
    })
    saved = {k: os.environ.get(k) for k in obs_env}
    os.environ.update(obs_env)
    try:
        # create_store() re-raises TenantRuntimeRoleError on the PostgreSQL path, and in CLIENT mode
        # tenant_rls.enforce_runtime_role() refuses a superuser/BYPASSRLS login -- so a store built
        # here is proof the runtime login is safe. The store binds to the restricted login only.
        store = store_mod.create_store()
        # FAIL-CLOSED: create_store() swallows a generic PostgresStateStore construction error and
        # silently returns a LocalStateStore fallback. Observing readiness against that fallback while
        # labelling it a restricted-PostgreSQL observation would substitute the backend under test.
        # Refuse unless the store really is the PostgreSQL store.
        if type(store).__name__ != "PostgresStateStore":
            raise ExecutionUnavailable(
                "create_store did not return a PostgresStateStore on the restricted runtime "
                f"(got {type(store).__name__}); refusing to observe a substituted backend")
        O.mark("store_connection_ready")
        readiness = READINESS.evaluate_client_data_readiness(store)
        O.mark("readiness_observation_completed")
        # ISOLATION PREFLIGHT (non-mutating): the runner-owned disposable database on loopback, never a
        # shared DB or the live app ports. Fail closed on a shared/live target.
        isolation = _isolation_preflight(
            run_input, target_kind="restricted_postgres_database",
            target_identity=f"host=127.0.0.1 port={ctx['port']} db={ctx['db']}",
            forbidden_substrings=(":8000", ":5173", ".local_data"))
        if "127.0.0.1" not in rt:
            raise ExecutionUnavailable("PostgreSQL isolation preflight: runtime DSN is not the "
                                       "runner-owned loopback database")
        O.mark("isolation_preflight_completed")
        # PERSISTED workflow + read-back through the REAL normalized PostgresStateStore, seeded via
        # supported wrapped mutations (the validation task comes from a Critical benchmark breach) and
        # read back from an INDEPENDENT fresh Postgres store. Fail closed on any unverified invariant.
        pg_persistence, workflow = _pg_workflow_readback(store, mode)
        if not pg_persistence["pg_persistence_verified"]:
            raise ExecutionUnavailable(
                f"PostgreSQL persisted-state read-back failed: {pg_persistence}")
        if not workflow.get("workflow_verified"):
            raise ExecutionUnavailable(f"PostgreSQL workflow observation failed: {workflow}")
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    captured["obs"] = {
        "source": "executed",
        "context_id": run_input["context_id"],
        "observer": "restricted_postgres_runtime",
        "readiness_by_id": {c.id: c.status for c in readiness.checks},
        "forge_report": None,
        "counters": {c: 0 for c in REQUIRED_ZERO_COUNTERS},
        "evidence_artifacts_consumed": [],
        "pg_runtime_identity": identity,
        # DB-observed: the protected tables are owned by a principal distinct from the runtime login
        # (not a comparison of run-scoped role NAMES, which would always differ by construction).
        "migration_runtime_roles_distinct": bool(identity.get("migration_owner_distinct_from_runtime")),
        "pg_persistence": pg_persistence,
        "workflow": workflow,
        "isolation": isolation,
    }


def _observe_postgres(run_input: Mapping[str, Any]) -> dict[str, Any]:
    """Observe a PostgreSQL context on the ACCEPTED restricted runtime.

    Delegates the ENTIRE stack lifecycle to the accepted foundation
    (``restricted_postgres_startup_guard.run_stack``) via its ``_ON_LIVE`` hook -- it never
    provisions a second, unreviewed PostgreSQL path, and it never accepts an externally supplied
    superuser DSN. Leaked generic test/PG environment variables are cleared first so the stack
    provisions and is observed through its OWN distinct migration and restricted runtime login roles.
    A live observation failure, a stack that never reaches the live hook, or a non-empty
    ``cleanup_issues`` all raise :class:`ExecutionUnavailable` -- never a PASS.
    """
    if str(ROOT / "scripts") not in sys.path:
        sys.path.insert(0, str(ROOT / "scripts"))
    import restricted_stack_orchestration as O   # shared retry seam around the accepted foundation

    mode = "client" if run_input["client_data_mode"] == "client" else "demo"
    captured: dict[str, Any] = {}

    def on_live(ctx: Mapping[str, Any]) -> None:
        # Do NOT swallow the observer's exception: the seam surfaces it via the attempt state and
        # decides retry eligibility from the per-attempt business_mutation_started flag.
        _observe_postgres_live(run_input, mode, ctx, captured)

    saved_env = {k: os.environ.get(k) for k in _LEAKED_PG_ENV}
    for key in _LEAKED_PG_ENV:
        os.environ.pop(key, None)
    try:
        # Provision through the SHARED seam: it runs the ACCEPTED run_stack unchanged, and retries
        # ONLY a clean transient connection/bootstrap failure that occurs strictly BEFORE the first
        # business mutation -- foundation bring-up OR the observer's own pre-mutation initialization
        # (store construction, readiness evaluation, isolation preflight) -- with fresh isolated
        # resources, bounded to 3 attempts. Any failure at or after the first business mutation, and
        # every semantic/cleanup/unknown failure, is never retried.
        prov = O.provision_restricted_stack(on_live, max_attempts=3)
    except O.ProvisioningFailed as exc:  # non-retryable, or the bounded budget was exhausted
        last = exc.history[-1] if exc.history else {}
        raise ExecutionUnavailable(
            f"the restricted-PostgreSQL stack could not be provisioned after {len(exc.history)} "
            f"attempt(s) (phase={last.get('phase')!r}, retryable={last.get('retry_eligible')}, "
            f"business_mutation_started={last.get('business_mutation_started')})")
    finally:
        for key, value in saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    # The seam only returns success when run_stack recorded NO failed checks, cleanup was clean, the
    # hook fired, AND the observer raised nothing -- so those invariants are already enforced.
    if "obs" not in captured:
        raise ExecutionUnavailable("the restricted-PostgreSQL stack never reached the live observer")
    # Retain the provisioning attempt history HONESTLY, but keep the non-deterministic attempt count
    # OUT of the observation that feeds the canonical result hash (log it to stderr instead).
    if len(prov.get("attempts", [])) > 1:
        print(f"[provisioning] {run_input['context_id']}: succeeded on attempt "
              f"{prov['succeeded_on_attempt']} after {len(prov['attempts']) - 1} pre-mutation "
              "transient retry(ies)", file=sys.stderr)
    return captured["obs"]


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
        # Fingerprint the context input AND the contract module's load-bearing state. Watching only
        # run_input would miss the more damaging leak: an observer that rewrites the contract's
        # control sets silently disables applicability demotion for every later context.
        before = [_fingerprint(run_input), _contract_state_fingerprint()]
        try:
            observations = observer(run_input)
        except ExecutionUnavailable as exc:
            results.append(_refusal(run_input, "observations unavailable",
                                    detail={"reason": str(exc)}))
        except Exception as exc:  # noqa: BLE001 - any observer error is a refusal, never a PASS
            results.append(_refusal(run_input, "the observer raised",
                                    detail={"exception": exc.__class__.__name__}))
        else:
            results.append(evaluate_context(run_input, observations))
        fingerprints[cid] = ["|".join(before),
                             "|".join([_fingerprint(run_input), _contract_state_fingerprint()])]

    return _summarize(facts, requested, results, fingerprints)


def _contract_state_fingerprint() -> str:
    """Fingerprint of the contract module state this harness's own gates depend on."""
    return _fingerprint({
        "inventory_hash": RC.canonical_hash(),
        "client_identity_controls": sorted(RC.CLIENT_IDENTITY_CONTROLS),
        "postgres_evidence_controls": sorted(RC.POSTGRES_EVIDENCE_CONTROLS),
        "accepted_context_evidence": {k: sorted(v)
                                      for k, v in sorted(RC.ACCEPTED_CONTEXT_EVIDENCE.items())},
        "canonical_order": list(RC.CANONICAL_CONTEXT_ORDER),
    })


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
    # Bound to the PINNED accepted hash, not to whatever the contract module computes right now --
    # otherwise a mutated contract certifies its own mutation.
    inventory_ok = bool(ordered) and all(r["inventory_hash"] == ACCEPTED_INVENTORY_HASH
                                         for r in ordered)
    # Every evaluated context must have a recorded fingerprint pair; otherwise "no cross-context
    # mutation" is vacuously true whenever recording is dropped.
    fingerprints_complete = set(fingerprints) == {r["context_id"] for r in results}

    # A result whose readiness booleans contradict its OWN blocking set is self-inconsistent: the
    # booleans were asserted rather than derived. Refuse instead of averaging it away.
    self_inconsistent = sorted(
        r["context_id"] for r in ordered
        if (r["client_data_ready"] or r["release_candidate_ready"] or r["ga_ready"])
        and r["blocking_controls"])

    # Aggregate readiness is DERIVED from the per-context blocking sets, never copied from the
    # per-context booleans, so a tampered result cannot raise the aggregate.
    aggregate_ready = bool(ordered) and all(
        not r["blocking_controls"] and r["client_data_ready"] for r in ordered)
    aggregate_ga = aggregate_ready and all(r["ga_ready"] and not r["blocking_controls"]
                                           for r in ordered)
    any_ready = any(r["client_data_ready"] or r["release_candidate_ready"] or r["ga_ready"]
                    for r in ordered)

    # Only a run produced by this module's OWN observers is certifiable. The `observer=` seam exists
    # for mutation-testing the decision logic; a synthetic run must never reach an accepted verdict.
    real_observations = bool(ordered) and all(
        r.get("observer") in RECOGNISED_OBSERVERS for r in ordered)

    accepted = bool(complete and all_evaluated and not mutated and hashes_consistent
                    and inventory_ok and fingerprints_complete and not self_inconsistent
                    and real_observations and not any_ready)

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
        "fingerprints_complete": fingerprints_complete,
        "self_inconsistent_results": self_inconsistent,
        "inventory_hash_matches_accepted": inventory_ok,
        "observations_from_recognised_observer": real_observations,
        "observers": sorted({str(r.get("observer")) for r in ordered}),
        "certification": "passed" if accepted else "not_passed",
        "accepted": accepted,
        "client_data_ready": aggregate_ready,
        "release_candidate_ready": aggregate_ga,
        "ga_ready": aggregate_ga,
        "production_parity": False,
        "dispositions_produced": all_evaluated and complete,
        "release_recommendation": "GA_BLOCKED",
        # Part D: context EXECUTION acceptance is independent of GA readiness. Every context keeps
        # GA_BLOCKED and its global release blockers visible even when it executed cleanly; those are
        # never treated as a context-execution failure.
        "overall_GA_status": "GA_BLOCKED",
        "execution_acceptance_independent_of_ga": True,
        "global_release_blockers": sorted({b for r in ordered
                                           for b in r.get("global_release_blockers", [])}),
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
        # Inspection mode exits zero, so it must not be able to carry ANY accepting signal. Every
        # field that could read as certification is forced, and the canonical result hash is dropped
        # rather than left attesting a body that no longer exists.
        summary = dict(summary)
        summary["inspection_only"] = True
        summary["contexts_executed"] = False
        summary["dispositions_produced"] = False
        summary["accepted"] = False
        summary["certification"] = "unavailable"
        summary["client_data_ready"] = False
        summary["release_candidate_ready"] = False
        summary["ga_ready"] = False
        summary["execution_verdict"] = "FOUR_READINESS_CONTEXTS_NOT_ACCEPTED"
        summary["release_recommendation"] = "GA_BLOCKED"
        summary.pop("canonical_result_hash", None)

    print(json.dumps(summary, indent=2, sort_keys=True, default=str))

    if args.inspect:
        # Inspection mode never certifies, so it may exit zero -- but only because it has just
        # printed inspection_only=true, contexts_executed=false and accepted=false.
        return 0
    return 0 if summary.get("accepted") else 1


if __name__ == "__main__":
    raise SystemExit(main())
