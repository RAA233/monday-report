"""Canonical readiness-context inventory (schema ``readiness-context-inventory.v1``).

A *readiness context* is one supported runtime configuration in which the GA control registry
(``evals/ga/blocker_registry.v1.json``) can be evaluated. Before this module the repository had
**no** context concept at all: the registry enumerated 28 controls, and readiness was evaluated in
whatever single configuration the process happened to be started in. Nothing recorded *which*
configuration produced a disposition, so a PASS observed in one configuration could be silently
reused to argue readiness in another -- for example a demo-mode UI run being read as evidence of
authenticated client-mode behaviour, or a local-JSON run being read as evidence of
database-enforced tenant isolation.

This module defines the contexts, not their execution. It is deliberately inert:

  * :func:`canonical_inventory` returns the four canonical contexts as data;
  * :func:`canonical_hash` returns a deterministic SHA-256 over that data;
  * :func:`run_context` and :func:`run_all_contexts` define the interface a future execution
    command will consume and **always** return a controlled ``certification="unavailable"`` /
    ``accepted=False`` result. They never synthesise a readiness disposition.

Executing the contexts is a separate, currently blocked increment (see
``docs/READINESS_CONTEXTS.md``): the environment-capacity gate for a real four-context run is
``free bytes >= 40 GiB`` and ``free percentage >= 15%``, and the host is far below it.

Why exactly four
----------------
The implementation supports exactly two independent binary axes, both of which are *total*
functions of the environment (every unrecognised value collapses onto a defined member, so there
is no third state):

  * client-data mode -- :func:`backend.app.readiness.client_data_mode` returns ``"client"`` when
    ``MONDAY_REPORT_CLIENT_DATA_MODE`` is one of the recognised client values, else ``"demo"``;
    mirrored by ``store._configured_client_data_mode``;
  * repository backend -- ``runtime_backends.detect_active_repository_backend`` returns exactly
    ``LOCAL_REPOSITORY_BACKEND`` (``"local_json"``) or ``POSTGRES_REPOSITORY_BACKEND``
    (``"postgres"``), and ``store.create_store`` correspondingly builds ``LocalStateStore`` or
    ``PostgresStateStore``.

The axes are independent: ``create_store`` does not read the client-data mode, and
``readiness.evaluate_client_data_readiness`` takes the mode and the active repository backend as
separate inputs, so all 2x2 combinations are representable and startable. The Cartesian product is
therefore four, and the inventory is the product -- not a number chosen in advance.

The queue backend (``inline_worker`` / ``redis``) is deliberately **not** a third axis. No accepted
evidence exists for the Redis path, ``production-queue-adapter`` is BLOCKED in every context, and
promoting an unproven adapter to an axis would multiply the inventory by unexercised
configurations. It is recorded per context as a classification instead.

Scope semantics
---------------
The schema encodes the distinctions that make a context's dispositions non-transferable:

  * a client-mode functional runtime proves authenticated identity and tenant enforcement;
  * a demo-mode dual-backend UI run proves UI/backend consistency **only** -- it is not evidence of
    authenticated client-mode UI behaviour;
  * no context claims production adapter parity;
  * valid tenant-authorization evidence v3 satisfies the tenant-authorization control **only**, and
    never migration validity, database-adapter readiness, queue-adapter readiness, or
    client-data readiness.
"""
from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Iterable, Sequence

SCHEMA_VERSION = "readiness-context-inventory.v1"
IMPLEMENTATION_VERSION = "1.0.0"

# --------------------------------------------------------------------------------------------
# Supported axes -- mirrored from the implementation, NOT from environment-variable names.
# backend.app.readiness.client_data_mode()            -> "client" | "demo"
# backend.app.runtime_backends.LOCAL/POSTGRES_...     -> "local_json" | "postgres"
# --------------------------------------------------------------------------------------------
SUPPORTED_CLIENT_DATA_MODES: tuple[str, ...] = ("demo", "client")
SUPPORTED_REPOSITORY_BACKENDS: tuple[str, ...] = ("local_json", "postgres")

#: context_id slug for each repository backend; context ids are stable and independent of the
#: display names, so renaming a display name can never silently reuse an id.
_BACKEND_SLUG: dict[str, str] = {"local_json": "local", "postgres": "postgres"}

#: Canonical, stable context ordering. The canonical hash is order-sensitive.
CANONICAL_CONTEXT_ORDER: tuple[str, ...] = (
    "demo-local",
    "demo-postgres",
    "client-local",
    "client-postgres",
)

# --------------------------------------------------------------------------------------------
# Control registry -- the 28 ids of evals/ga/blocker_registry.v1.json (registry_version v1).
# Held here so this module is self-contained; the inventory guard cross-checks this set against
# the real registry file, so neither a registry change nor an omission here can pass silently.
# --------------------------------------------------------------------------------------------
REGISTRY_VERSION = "v1"
CONTROL_IDS: tuple[str, ...] = (
    "per-user-identity",
    "rbac-role-separation",
    "tenant-authorization-enforcement",
    "verified-reviewer-identity",
    "audit-keyed-integrity",
    "audit-tail-truncation-detection",
    "correction-cross-process-atomicity",
    "migration-runner",
    "migration-validity",
    "persistence-locking-transactions",
    "ci-execution",
    "dependency-vuln-scan",
    "structured-production-logging",
    "metrics-monitoring",
    "worker-heartbeat",
    "backup-restore-drill",
    "formatted-export-provenance",
    "official-export-gate",
    "external-malware-scanner",
    "phase06-trust-boundary",
    "production-database-adapter",
    "production-queue-adapter",
    "production-configuration",
    "local-ai-runtime-reachable",
    "parser-coverage-evidence",
    "reviewed-fixture-evidence",
    "configuration-clean-client-state",
    "client-organizational-approval",
)

#: Dispositions permitted by the registry.
REGISTRY_DISPOSITIONS: tuple[str, ...] = (
    "PASS", "FAIL", "BLOCKED", "SKIPPED", "NOT_APPLICABLE", "REVIEW_REQUIRED",
)

#: The subset this contract may predict. A context definition never predicts FAIL/SKIPPED (those
#: are execution outcomes, not properties of a configuration) and never predicts REVIEW_REQUIRED
#: (that would make the prediction unfalsifiable).
PREDICTABLE_DISPOSITIONS: tuple[str, ...] = ("PASS", "BLOCKED", "NOT_APPLICABLE")

# --------------------------------------------------------------------------------------------
# Disposition rules. Expected dispositions are DERIVED from these rules, never hand-typed per
# context, so the rule is what a reviewer audits (112 hand-written cells would not be auditable).
# --------------------------------------------------------------------------------------------

#: Controls whose acceptance criteria require an authenticated client-mode identity. A demo-mode
#: run cannot evaluate them at all -- demo has no authenticated client principal to enforce.
CLIENT_IDENTITY_CONTROLS: frozenset[str] = frozenset({
    "per-user-identity",
    "rbac-role-separation",
    "tenant-authorization-enforcement",
    "verified-reviewer-identity",
})

#: Controls a local-JSON run structurally CANNOT evaluate, because the thing being certified is
#: the database itself: RLS-enforced isolation, and the migration chain. A local-JSON result must
#: never be read as evidence about them.
#:
#: Deliberately excluded, and BLOCKED rather than NOT_APPLICABLE in local contexts:
#:   * ``production-database-adapter`` -- a universal GA blocker. Marking it NOT_APPLICABLE where
#:     no database exists would read as "this context does not need one", which is false: GA
#:     requires it regardless of which context is executed.
#:   * ``persistence-locking-transactions`` -- the local JSON store has its own locking and
#:     atomicity mechanism, so a local run CAN evaluate it; it is simply not yet accepted here.
POSTGRES_EVIDENCE_CONTROLS: frozenset[str] = frozenset({
    "tenant-authorization-enforcement",
    "migration-runner",
    "migration-validity",
})

#: The ONLY place a PASS may be predicted: a control for which an accepted artifact already exists
#: AND was produced in exactly that context. Everything else is BLOCKED until executed.
#: Tenant-authorization evidence v3 was generated and accepted under client mode on the restricted
#: PostgreSQL runtime, i.e. the ``client-postgres`` context and no other.
ACCEPTED_CONTEXT_EVIDENCE: dict[str, frozenset[str]] = {
    "client-postgres": frozenset({"tenant-authorization-enforcement"}),
}

#: A predicted PASS is contingent on this precondition being met at execution time. The accepted v3
#: artifact is bound to the commit and tree that produced it; any later commit invalidates the
#: binding until the artifact is regenerated, so the prediction is explicitly conditional.
ACCEPTED_EVIDENCE_PRECONDITION = (
    "tenant-authorization evidence v3 regenerated and verified at the executed commit/tree "
    "(the accepted artifact is commit-bound and does not carry forward to a later tree)"
)

#: Scope statements attached to every context, encoding what a context's result may NOT be read as.
NON_TRANSFERABLE_SCOPE: tuple[str, ...] = (
    "a demo-mode result is never evidence of authenticated client-mode behaviour",
    "a local-JSON result is never evidence of database-enforced tenant isolation (RLS)",
    "a PostgreSQL result is never evidence of production database-adapter parity",
    "valid tenant-authorization evidence v3 satisfies the tenant-authorization control only, and "
    "never migration validity, database-adapter readiness, queue-adapter readiness, or "
    "client-data readiness",
)


def _display_name(mode: str, backend: str) -> str:
    """Display name in repository terminology; never load-bearing (ids are the identity)."""
    backend_name = "local JSON snapshot" if backend == "local_json" else "PostgreSQL (restricted runtime)"
    mode_name = "demo mode" if mode == "demo" else "client mode"
    return f"{mode_name} / {backend_name}"


def context_id_for(mode: str, backend: str) -> str:
    """Stable, lowercase, machine-readable id derived only from the axis values."""
    if mode not in SUPPORTED_CLIENT_DATA_MODES:
        raise ValueError(f"unsupported client-data mode: {mode!r}")
    if backend not in SUPPORTED_REPOSITORY_BACKENDS:
        raise ValueError(f"unsupported repository backend: {backend!r}")
    return f"{mode}-{_BACKEND_SLUG[backend]}"


def expected_disposition(context_id: str, mode: str, backend: str, control_id: str) -> str:
    """Derive one expected disposition from the documented rules (see module docstring).

    Rule order is significant and total:
      R1  demo mode cannot evaluate client-identity controls          -> NOT_APPLICABLE
      R2  local JSON cannot evaluate PostgreSQL-evidence controls     -> NOT_APPLICABLE
      R3  an accepted artifact produced in THIS context               -> PASS
      R4  otherwise: evidence not produced/accepted for this context  -> BLOCKED
    """
    if mode == "demo" and control_id in CLIENT_IDENTITY_CONTROLS:
        return "NOT_APPLICABLE"
    if backend == "local_json" and control_id in POSTGRES_EVIDENCE_CONTROLS:
        return "NOT_APPLICABLE"
    if control_id in ACCEPTED_CONTEXT_EVIDENCE.get(context_id, frozenset()):
        return "PASS"
    return "BLOCKED"


def _build_context(mode: str, backend: str) -> dict[str, Any]:
    cid = context_id_for(mode, backend)
    is_pg = backend == "postgres"
    is_client = mode == "client"
    return {
        "context_id": cid,
        "context_name": _display_name(mode, backend),
        "description": (
            f"Evaluate the GA control registry with client-data mode {mode!r} and active "
            f"repository backend {backend!r}. "
            + (
                "Authenticated client-mode enforcement is exercised."
                if is_client
                else "No authenticated client principal is exercised; demo results prove "
                     "UI/backend consistency only."
            )
            + (
                " Tenant isolation is database-enforced (RLS on the restricted runtime role)."
                if is_pg
                else " State is a local JSON snapshot; no database-enforced isolation exists."
            )
        ),
        "client_data_mode": mode,
        "repository_backend": backend,
        "database_adapter_classification": (
            "restricted_postgres_runtime_not_production_adapter" if is_pg
            else "local_json_snapshot_no_database_adapter"
        ),
        "queue_adapter_classification": "inline_worker_not_production_adapter",
        "tenant_evidence_requirement": (
            "required: tenant-authorization evidence v3 regenerated and verified at the executed "
            "commit/tree" if (is_client and is_pg)
            else "not_eligible: this context cannot produce tenant-authorization evidence v3"
        ),
        "UI_evidence_requirement": (
            "demo-mode dual-backend UI consistency evidence; NOT evidence of authenticated "
            "client-mode UI behaviour" if not is_client
            else "not_available: the UI is unusable in client mode (mutating routes return HTTP 423 "
                 "until client-data readiness is green), so no client-mode UI evidence exists"
        ),
        "migration_evidence_requirement": (
            "required: migration runner and migration validity evidence at the executed commit"
            if is_pg else "not_applicable: no database migration chain is exercised"
        ),
        "production_parity": False,
        "expected_control_dispositions": {
            control_id: expected_disposition(cid, mode, backend, control_id)
            for control_id in CONTROL_IDS
        },
        "expected_client_data_ready": False,
        "expected_release_candidate_ready": False,
        "expected_ga_ready": False,
        "accepted_evidence_precondition": (
            ACCEPTED_EVIDENCE_PRECONDITION if ACCEPTED_CONTEXT_EVIDENCE.get(cid) else None
        ),
        "non_transferable_scope": list(NON_TRANSFERABLE_SCOPE),
    }


#: Every field a context must carry, in canonical order.
REQUIRED_CONTEXT_FIELDS: tuple[str, ...] = (
    "context_id",
    "context_name",
    "description",
    "client_data_mode",
    "repository_backend",
    "database_adapter_classification",
    "queue_adapter_classification",
    "tenant_evidence_requirement",
    "UI_evidence_requirement",
    "migration_evidence_requirement",
    "production_parity",
    "expected_control_dispositions",
    "expected_client_data_ready",
    "expected_release_candidate_ready",
    "expected_ga_ready",
    "accepted_evidence_precondition",
    "non_transferable_scope",
)


def _canonical_contexts() -> list[dict[str, Any]]:
    """Build the inventory in canonical order from the Cartesian product of the supported axes."""
    by_id = {
        context_id_for(mode, backend): _build_context(mode, backend)
        for mode in SUPPORTED_CLIENT_DATA_MODES
        for backend in SUPPORTED_REPOSITORY_BACKENDS
    }
    if set(by_id) != set(CANONICAL_CONTEXT_ORDER):
        # Fail closed: the declared order and the derived product must agree exactly.
        raise ValueError("canonical order does not match the derived axis product")
    return [by_id[cid] for cid in CANONICAL_CONTEXT_ORDER]


def canonical_inventory() -> list[dict[str, Any]]:
    """The four canonical contexts, in canonical order.

    Returns a deep copy: callers (including the guards) mutate their result freely without
    corrupting the module-level definition for every later caller.
    """
    return copy.deepcopy(_canonical_contexts())


def canonical_payload(contexts: Sequence[dict[str, Any]] | None = None) -> dict[str, Any]:
    """The exact object the canonical hash is computed over.

    Contains no timestamps, no filesystem paths, and no environment-dependent values.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "implementation_version": IMPLEMENTATION_VERSION,
        "registry_version": REGISTRY_VERSION,
        "supported_client_data_modes": list(SUPPORTED_CLIENT_DATA_MODES),
        "supported_repository_backends": list(SUPPORTED_REPOSITORY_BACKENDS),
        "contexts": list(canonical_inventory() if contexts is None else contexts),
    }


def canonical_json(contexts: Sequence[dict[str, Any]] | None = None) -> str:
    """Deterministic serialisation: sorted keys, no whitespace, ASCII-escaped.

    Mapping key order is normalised by ``sort_keys``; list order is preserved, so context order is
    load-bearing and a reordered inventory yields a different hash.
    """
    return json.dumps(
        canonical_payload(contexts),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def canonical_hash(contexts: Sequence[dict[str, Any]] | None = None) -> str:
    """Full lowercase SHA-256 over :func:`canonical_json`."""
    return hashlib.sha256(canonical_json(contexts).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------------------------
# Runner interface -- DEFINED, NOT IMPLEMENTED.
#
# Part J of the increment: describe the interface the future execution command will consume
# without executing anything. Every entry point below returns a controlled unavailable result.
# None of them ever returns a simulated readiness disposition.
# --------------------------------------------------------------------------------------------

#: Reason every execution entry point is currently unavailable.
EXECUTION_UNAVAILABLE_REASON = (
    "readiness-context execution is not implemented in this increment; the contract defines the "
    "contexts only. Execution additionally requires the environment-capacity gate "
    "(free bytes >= 40 GiB and free percentage >= 15%) to pass."
)


class ReadinessContextExecutionUnavailable(RuntimeError):
    """Raised by execution helpers that must never fabricate a result."""


def build_run_input(context_id: str) -> dict[str, Any]:
    """The isolated, per-context input object a runner receives.

    Isolated by construction: a deep copy, so one context's runner can never mutate another's
    input (or the module-level definition) through a shared reference.
    """
    for context in _canonical_contexts():
        if context["context_id"] == context_id:
            return copy.deepcopy(context)
    raise ValueError(f"unknown readiness context id: {context_id!r}")


def execution_order(reverse: bool = False, seed: int | None = None) -> list[str]:
    """Context ids in the order a runner should execute them.

    Supports canonical order, reverse order, and deterministic pseudo-random order (same seed =>
    same order, on any platform and any Python build -- the permutation is derived from a SHA-256
    keyed by the seed, not from ``random``, whose stream is not a stability guarantee).
    """
    ids = list(CANONICAL_CONTEXT_ORDER)
    if seed is not None:
        ids.sort(key=lambda cid: hashlib.sha256(f"{seed}:{cid}".encode("utf-8")).hexdigest())
    if reverse:
        ids.reverse()
    return ids


def _unavailable(context_ids: Iterable[str]) -> dict[str, Any]:
    """The single controlled shape every execution entry point returns."""
    return {
        "schema_version": SCHEMA_VERSION,
        "canonical_inventory_hash": canonical_hash(),
        "requested_context_ids": list(context_ids),
        "certification": "unavailable",
        "accepted": False,
        "executed": False,
        "results": [],
        "reason": EXECUTION_UNAVAILABLE_REASON,
    }


def run_context(context_id: str, **_kwargs: Any) -> dict[str, Any]:
    """Run one context by id. Currently always unavailable; never a simulated disposition.

    The id is still validated, so a caller wiring up the future runner finds a typo immediately
    rather than receiving a plausible-looking unavailable result for a context that does not exist.
    """
    build_run_input(context_id)
    return _unavailable([context_id])


def run_all_contexts(reverse: bool = False, seed: int | None = None, **_kwargs: Any) -> dict[str, Any]:
    """Run every canonical context. Currently always unavailable."""
    return _unavailable(execution_order(reverse=reverse, seed=seed))


def serialize_result(result: dict[str, Any]) -> str:
    """Canonical result serialisation, so future runner output is comparable across runs."""
    return json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
