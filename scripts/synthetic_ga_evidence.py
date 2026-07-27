"""Hermetic synthetic GA evidence builders -- PARSER / EVALUATOR COVERAGE ONLY.

Builds evidence artifacts that the REAL validators in this repository accept, so the
parsing and evaluation paths of seven evidence-gated GA controls can be exercised with
no Docker, PostgreSQL, Redis, server, worker, browser or network service.

    ga_migration_runner                    <- output/migrations/migration-evidence.v1.json
    ga_migration_validity                  <- same artifact (+ an INDEPENDENT static blocker)
    ga_persistence_locking                 <- output/persistence/persistence-atomicity-evidence.v4.json
    ga_correction_cross_process_atomicity  <- output/persistence/normalized-correction-persistence-evidence.v4.json
    ga_postgres_adapter                    <- output/production-database-adapter/production-database-adapter-evidence.v1.json
    ga_redis_adapter                       <- output/production-queue-adapter/production-queue-adapter-evidence.v1.json
    ga_tenant_authorization                <- ALL-OF: output/tenant-rls/tenant-rls-enforcement-evidence.v2.json
                                                  AND output/tenant-authorization/tenant-authorization-evidence.v3.json

NOTHING HERE IS OPERATIONAL EVIDENCE. No validator is modified, mocked or monkeypatched;
only the module-level ``*_PATH`` constants are repointed at a temp directory. Every artifact
carries, in machine-readable form::

    "synthetic": true
    "parser_evaluator_coverage_only": true
    "real_operational_execution": false

Disclosure-key placement is NOT uniform, and the contracts force that:

* migration / persistence / normalized-correction / tenant-RLS / tenant-authorization-v3 /
  production-DATABASE-adapter  -> TOP LEVEL, and hash-covered.
* production-QUEUE-adapter     -> inside ``non_qualifying_evidence_disclosure`` (hash-covered)
  and mirrored in ``generation_metadata``. The queue contract enforces
  ``KNOWN_TOP_LEVEL_KEYS``; putting the three keys at top level is rejected with
  ``unknown top-level key(s): parser_evaluator_coverage_only, real_operational_execution,
  synthetic``.  ``non_qualifying_evidence_disclosure`` is a *known* top-level block that does
  not reject extra members and IS inside the canonical body.

WHAT THE PATH CONSTANTS DO NOT REDIRECT (see PATH_RESOLUTION_NOTES at the bottom):
git HEAD/tree, tracked-worktree cleanliness, the migration-file hashes and the
``bound_implementations`` digests are all recomputed from the real repository ROOT.
Run the builders in the same clean checkout the evaluator will read.

Run directly to reproduce the whole thing::

    python scripts/synthetic_ga_evidence.py            # writes to a fresh temp dir
    python scripts/synthetic_ga_evidence.py --outdir D:/tmp/synth
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Repo-root bootstrap (mirrors the repository's own guard scripts).
_HERE = Path(__file__).resolve()
for _candidate in (_HERE.parents[1], _HERE.parent):
    if str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from backend.app import ga_readiness as _ga                                # noqa: E402
from backend.app import production_database_adapter_evidence as _pdae      # noqa: E402
from backend.app import production_queue_adapter_evidence as _pqae        # noqa: E402
from backend.app import tenant_authorization_evidence as _tae             # noqa: E402

#: The repository root the validators themselves resolve from. All four validator modules
#: independently compute ``Path(__file__).resolve().parents[2]``, so they always agree.
REPO_ROOT: Path = Path(_ga.ROOT)

DISCLOSURE: dict[str, Any] = {
    "synthetic": True,
    "parser_evaluator_coverage_only": True,
    "real_operational_execution": False,
}

#: control -> tuple of (module dotted name, module-level PATH constant, repo-relative filename).
#: ``ga_tenant_authorization`` is an ALL-OF control and therefore carries two entries;
#: ``ga_migration_runner`` and ``ga_migration_validity`` share ONE artifact.
EVIDENCE_PATH_CONSTANTS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "ga_migration_runner": (
        ("backend.app.ga_readiness", "MIGRATION_EVIDENCE_PATH",
         "output/migrations/migration-evidence.v1.json"),
    ),
    "ga_migration_validity": (
        ("backend.app.ga_readiness", "MIGRATION_EVIDENCE_PATH",
         "output/migrations/migration-evidence.v1.json"),
    ),
    "ga_persistence_locking": (
        ("backend.app.ga_readiness", "PERSISTENCE_EVIDENCE_PATH",
         "output/persistence/persistence-atomicity-evidence.v4.json"),
    ),
    "ga_correction_cross_process_atomicity": (
        ("backend.app.ga_readiness", "NORMALIZED_EVIDENCE_PATH",
         "output/persistence/normalized-correction-persistence-evidence.v4.json"),
    ),
    "ga_postgres_adapter": (
        ("backend.app.ga_readiness", "PRODUCTION_DATABASE_ADAPTER_EVIDENCE_PATH",
         "output/production-database-adapter/production-database-adapter-evidence.v1.json"),
    ),
    "ga_redis_adapter": (
        ("backend.app.ga_readiness", "PRODUCTION_QUEUE_ADAPTER_EVIDENCE_PATH",
         "output/production-queue-adapter/production-queue-adapter-evidence.v1.json"),
    ),
    "ga_tenant_authorization": (
        ("backend.app.ga_readiness", "TENANT_RLS_EVIDENCE_PATH",
         "output/tenant-rls/tenant-rls-enforcement-evidence.v2.json"),
        ("backend.app.ga_readiness", "TENANT_AUTHORIZATION_EVIDENCE_PATH",
         "output/tenant-authorization/tenant-authorization-evidence.v3.json"),
    ),
}

#: builder key -> (ga_readiness PATH constant, repo-relative filename)
ARTIFACT_SLOTS: dict[str, tuple[str, str]] = {
    "migration": ("MIGRATION_EVIDENCE_PATH",
                  "output/migrations/migration-evidence.v1.json"),
    "persistence": ("PERSISTENCE_EVIDENCE_PATH",
                    "output/persistence/persistence-atomicity-evidence.v4.json"),
    "normalized": ("NORMALIZED_EVIDENCE_PATH",
                   "output/persistence/normalized-correction-persistence-evidence.v4.json"),
    "tenant_rls": ("TENANT_RLS_EVIDENCE_PATH",
                   "output/tenant-rls/tenant-rls-enforcement-evidence.v2.json"),
    "tenant_auth_v3": ("TENANT_AUTHORIZATION_EVIDENCE_PATH",
                       "output/tenant-authorization/tenant-authorization-evidence.v3.json"),
    "db_adapter": ("PRODUCTION_DATABASE_ADAPTER_EVIDENCE_PATH",
                   "output/production-database-adapter/production-database-adapter-evidence.v1.json"),
    "queue_adapter": ("PRODUCTION_QUEUE_ADAPTER_EVIDENCE_PATH",
                      "output/production-queue-adapter/production-queue-adapter-evidence.v1.json"),
}


# --------------------------------------------------------------------------- helpers
def _git(*args: str) -> str:
    out = subprocess.run(["git", *args], cwd=str(REPO_ROOT), capture_output=True, text=True,
                         timeout=30)
    return out.stdout.strip() if out.returncode == 0 else ""


def current_commit() -> str:
    """Full 40-hex HEAD of the repository the validators resolve from."""
    return _git("rev-parse", "HEAD")


def current_tree() -> str:
    """Full 40-hex ``HEAD^{tree}``."""
    return _git("rev-parse", "HEAD^{tree}")


def _fp(*parts: str) -> str:
    """Deterministic, non-reversible 64-hex binding fingerprint. Never derived from a secret."""
    return hashlib.sha256("|".join(("monday-report-synthetic-evidence",) + parts)
                          .encode("utf-8")).hexdigest()


def _seal_ga(payload: dict) -> dict:
    """Seal with ``ga_readiness.payload_sha256`` (canonical JSON of everything but the hash)."""
    payload.pop("payload_sha256", None)
    payload["payload_sha256"] = _ga.payload_sha256(dict(payload))
    return payload


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _baseline_versions() -> list[int]:
    import backend.app.migrations as _mig
    return [m.version for m in _mig.discover_migrations(_mig.BASELINE_DIR)]


def _passed(*names: str) -> dict[str, str]:
    return {name: "passed" for name in names}


def _prov(command: str) -> dict[str, str]:
    """A ``tenant_authorization_evidence._claim`` provenance object ({status, proven_by})."""
    return {"status": "passed", "proven_by": command}


_RLS_PROTECTED_TABLES: tuple[str, ...] = (
    "field_corrections", "validation_tasks", "audit_logs", "idempotency_records",
    "workspaces", "reports", "documents", "processing_jobs",
)


# =========================================================================== 1. migrations
def build_migration_evidence(commit: str, tree: str) -> dict:
    """``output/migrations/migration-evidence.v1.json``.

    Consumed by ``_migration_evidence_valid`` (shared gate), ``_migration_runner_probe``
    and ``_migration_validity_probe``.

    Demanded: ``status == "passed"``; a verifying ``payload_sha256``; truthy
    ``worktree_clean``; a truthy ``postgres_server_version``; ``migration_set_sha256`` equal
    to ``migrations.migration_set_sha256(discover_migrations())`` (the LEGACY set);
    ``baseline_migration_set_sha256`` equal to the same over ``BASELINE_DIR``; and truthy
    ``fresh_apply_result`` / ``rerun_result`` / ``partial_upgrade_result`` /
    ``concurrency_result`` / ``rollback_result`` / ``checksum_drift_result``.
    ``fresh_apply_result["ok"]`` must additionally be truthy for the validity probe.

    NOTE: this validator performs NO git commit/tree binding. ``git_commit``/``git_tree``
    below are informational only. The artifact's real staleness binding is the pair of
    migration-set content hashes.
    """
    import backend.app.migrations as _mig

    generated = _now()
    payload: dict[str, Any] = {
        "schema_version": "migration-evidence.v1",
        "evidence_type": "migration-runner",
        "status": "passed",
        "generated_at": _iso(generated),
        "git_commit": commit,
        "git_tree": tree,
        "worktree_clean": True,
        "repository_mode": "postgres",
        "postgres_server_version": "PostgreSQL 16 (synthetic evidence, no server executed)",
        "postgres_image_digest": "sha256:" + _fp("migration", "image-digest"),
        "runner_version": _mig.RUNNER_VERSION,
        "migration_set": "baseline",
        "migration_set_sha256": _mig.migration_set_sha256(_mig.discover_migrations()),
        "baseline_migration_set_sha256": _mig.migration_set_sha256(
            _mig.discover_migrations(_mig.BASELINE_DIR)),
        "migration_versions": _baseline_versions(),
        "fresh_apply_result": {
            "ok": True,
            "applied_versions": _baseline_versions(),
            "deterministic_order": True,
            "advisory_lock_key_stable": True,
            "per_migration_transactions": True,
            "schema_migrations_table": _mig.SCHEMA_MIGRATIONS_TABLE,
        },
        "rerun_result": {"ok": True, "applied_second_run": 0, "idempotent": True},
        "partial_upgrade_result": {
            "ok": True,
            "upgrades": [{"from_version": 0, "to_version": 7, "applied": 7},
                         {"from_version": 4, "to_version": 7, "applied": 3},
                         {"from_version": 6, "to_version": 7, "applied": 1}],
        },
        "concurrency_result": {"ok": True, "competing_runners": 2,
                               "serialized_by_advisory_lock": True, "duplicate_applications": 0},
        "rollback_result": {"ok": True, "failing_migration_rolled_back": True,
                            "schema_migrations_row_written": False},
        "checksum_drift_result": {"ok": True, "drift_detected": True, "runner_refused": True},
        "totals": {"passed": 0, "failed": 0, "skipped": 0},
        "guard_inventory_ok": True,
    }
    payload.update(DISCLOSURE)
    return _seal_ga(payload)


# ============================================================== 2. persistence atomicity v4
def build_persistence_atomicity_evidence(commit: str, tree: str) -> dict:
    """``output/persistence/persistence-atomicity-evidence.v4.json`` (``ga_persistence_locking``).

    Demanded by ``_persistence_locking_probe``: exact ``schema_version``
    ``persistence-atomicity-evidence.v4``; ``status="passed"``; verifying ``payload_sha256``;
    ``worktree_clean``; ``repository_mode="postgres"``; ``postgres_server_version`` +
    ``postgres_image_digest``; ``snapshot_scope="global"``; a ``serialization_statement``
    containing the literal ``serializes all application writers``; truthy
    ``negative_control_lost_update`` and ``protected_comparison_preserved_both``;
    ``chain_linkage_result`` / ``event_hmac_result`` / ``route_worker_command_boundary_result``
    / ``http_route_idempotency_result`` / ``concurrent_http_idempotency_result`` /
    ``uncertain_response_result`` / ``validation_route_idempotency_result`` == "passed";
    ``semantic_action_coverage_complete is True``; ``totals.failed == totals.skipped == 0``;
    a ``route_idempotency`` block with a contract version, the ``Idempotency-Key`` header, 12
    sub-results "passed", >=14 fully-passing HTTP scenarios, >=7 fully-passing validation
    scenarios, >=6 semantic actions all "passed", >=3 tested routes, >=2 concurrent client
    processes and exactly-once concurrent commit counters; STRICT git commit AND tree binding;
    and ``migration_versions`` equal to the BASELINE version list.
    """
    semantic_actions = [
        {"action": name, "route": route, "result": "passed"}
        for name, route in (
            ("correction_create", "POST /workspaces/{id}/corrections"),
            ("correction_revert", "POST /corrections/{id}/revert"),
            ("validation_outcome", "PATCH /validation-tasks/{id}"),
            ("validation_rejection", "PATCH /validation-tasks/{id}"),
            ("validation_reopen", "PATCH /validation-tasks/{id}"),
            ("report_export", "POST /reports/{id}/exports"),
        )
    ]
    payload: dict[str, Any] = {
        "schema_version": _ga.PERSISTENCE_EVIDENCE_SCHEMA,
        "evidence_type": "persistence-atomicity",
        "implementation_version": "4.0.0",
        "status": "passed",
        "generated_at": _iso(_now()),
        "git_commit": commit,
        "git_tree": tree,
        "worktree_clean": True,
        "repository_mode": "postgres",
        "postgres_server_version": "PostgreSQL 16 (synthetic evidence, no server executed)",
        "postgres_image_digest": "sha256:" + _fp("persistence", "image-digest"),
        "migration_versions": _baseline_versions(),
        "snapshot_scope": "global",
        "serialization_statement": (
            "The PostgreSQL snapshot boundary serializes all application writers; no "
            "tenant-independent concurrency is claimed."
        ),
        "negative_control_lost_update": True,
        "protected_comparison_preserved_both": True,
        "semantic_action_coverage_complete": True,
        "route_idempotency": {
            "contract_version": "route-idempotency.v2",
            "operation_key_header": "Idempotency-Key",
            "http_route_result": "passed",
            "concurrent_http_result": "passed",
            "uncertain_response_result": "passed",
            "request_hash_canonicalization_result": "passed",
            "missing_key_result": "passed",
            "conflicting_reuse_result": "passed",
            "actor_and_operation_scope_result": "passed",
            "failed_attempt_reserves_no_key_result": "passed",
            "validation_route_result": "passed",
            "validation_outcome_result": "passed",
            "validation_rejection_result": "passed",
            "validation_reopen_result": "passed",
            "http_scenarios_passed": 14,
            "http_scenario_count": 14,
            "validation_scenarios_passed": 7,
            "validation_scenario_count": 7,
            "required_semantic_action_count": 6,
            "tested_semantic_action_count": 6,
            "semantic_actions": semantic_actions,
            "tested_route_count": 3,
            "concurrent_http_client_count": 2,
            "concurrent_http_idempotency_rows": 1,
            "concurrent_http_correction_delta": 1,
        },
        "totals": {"passed": 0, "failed": 0, "skipped": 0},
        "guard_inventory_ok": True,
    }
    payload.update(_passed(
        "chain_linkage_result", "event_hmac_result", "route_worker_command_boundary_result",
        "http_route_idempotency_result", "concurrent_http_idempotency_result",
        "uncertain_response_result", "validation_route_idempotency_result",
    ))
    payload.update(DISCLOSURE)
    return _seal_ga(payload)


# ======================================================= 3. normalized correction evidence v4
_NORMALIZED_RESULT_FIELDS: tuple[str, ...] = (
    "route_groups_result", "concurrency_result", "import_result", "tenant_rls_result",
    "audit_chain_result", "hmac_result", "supersession_import_result",
    "tenant_preserving_reset_result", "verify_count_comparison_result",
    "conflict_accounting_result", "migration_0006_result", "drift_coverage_result",
    "import_concurrency_result", "rls_runtime_role_result", "rollback_reload_result",
    "transaction_isolation_result", "route_dirty_read_result", "rollback_nonpublication_result",
    "atomic_projection_swap_result", "stale_refresh_rejection_result",
    "non_owner_committed_view_result", "stale_view_elimination_result", "revision_binding_result",
    "audit_log_isolation_result", "read_coherence_result", "multi_access_coherence_result",
    "route_coherence_result", "export_coherence_result", "authorization_coherence_result",
    "worker_coherence_result", "async_task_isolation_result", "get_then_reindex_result",
    "read_view_scope_result", "publication_failure_recovery_result",
    "recursive_audit_immutability_result", "async_task_ownership_result",
)


def build_normalized_correction_evidence(commit: str, tree: str) -> dict:
    """``output/persistence/normalized-correction-persistence-evidence.v4.json``
    (``ga_correction_cross_process_atomicity``).

    Demanded by ``_correction_atomicity_probe``: exact ``schema_version``
    ``normalized-correction-persistence-evidence.v4``; ``status="passed"``; verifying
    ``payload_sha256``; ``worktree_clean``; ``repository_mode="postgres"``;
    ``postgres_server_version`` + ``postgres_image_digest``; STRICT git commit AND tree
    binding; ``migration_versions`` == the BASELINE version list AND containing 5 and 6;
    ``normalized_entities`` containing ``field_corrections`` and ``validation_tasks``; a
    ``source_of_truth`` string containing BOTH ``single write and read authority`` and
    ``WITHOUT normalized cross-process guarantees``; all 36 ``*_result`` fields == "passed";
    ``publication_model="copy_on_write"``;
    ``committed_read_view_model="request_task_scoped_pin_on_first_refresh"``;
    ``read_view_context_backend="contextvars"``; truthy ``guard_inventory_ok``;
    ``implementation_version >= 4.0.0``; ``concurrency_scenario_total >= 10``;
    ``process_total >= 10``; ``totals.failed == totals.skipped == 0``.
    """
    payload: dict[str, Any] = {
        "schema_version": _ga.NORMALIZED_EVIDENCE_SCHEMA,
        "evidence_type": "normalized-correction-persistence",
        "implementation_version": "4.0.0",
        "status": "passed",
        "generated_at": _iso(_now()),
        "git_commit": commit,
        "git_tree": tree,
        "worktree_clean": True,
        "repository_mode": "postgres",
        "postgres_server_version": "PostgreSQL 16 (synthetic evidence, no server executed)",
        "postgres_image_digest": "sha256:" + _fp("normalized", "image-digest"),
        "migration_versions": _baseline_versions(),
        "normalized_entities": ["field_corrections", "validation_tasks", "audit_logs",
                                "idempotency_records"],
        "source_of_truth": (
            "The normalized tables are the single write and read authority for corrections and "
            "validation outcomes; the JSON snapshot is excluded and marked. File and memory "
            "repository modes operate WITHOUT normalized cross-process guarantees."
        ),
        "publication_model": "copy_on_write",
        "committed_read_view_model": "request_task_scoped_pin_on_first_refresh",
        "read_view_context_backend": "contextvars",
        "guard_inventory_ok": True,
        "concurrency_scenario_total": 10,
        "process_total": 10,
        "totals": {"passed": 0, "failed": 0, "skipped": 0},
    }
    payload.update(_passed(*_NORMALIZED_RESULT_FIELDS))
    payload.update(DISCLOSURE)
    return _seal_ga(payload)


# ============================================================ 4. tenant-RLS enforcement v2
def build_tenant_rls_evidence(commit: str, tree: str) -> dict:
    """``output/tenant-rls/tenant-rls-enforcement-evidence.v2.json`` -- the RLS sub-proof half
    of the ALL-OF control ``ga_tenant_authorization``.

    Demanded by ``_tenant_rls_evidence_reasons``: exact ``schema_version``
    ``tenant-rls-enforcement-evidence.v2``; ``status="passed"``; verifying ``payload_sha256``;
    ``worktree_clean``; ``repository_mode="postgres"``; ``postgres_server_version`` +
    ``postgres_image_digest``; STRICT git commit AND tree binding; FALSY
    ``runtime_role_is_superuser`` / ``runtime_role_has_bypassrls`` /
    ``runtime_role_owner_bypass``; ``rls_forced_normalized_count >= 4``;
    ``rls_forced_table_count >= 8``; ``schema_result`` / ``roles_result`` /
    ``direct_sql_result`` / ``routes_result`` / ``worker_pool_result`` /
    ``import_admin_result`` / ``idempotency_result`` == "passed";
    ``tenant_context_mechanism == "transaction_local_guc:app.tenant_slug"``; truthy
    ``runtime_role_can_login`` and ``runtime_role_is_login_not_group``;
    ``"monday_report_app"`` in ``runtime_group_membership``; non-empty ``policy_inventory``
    AND ``policy_inventory_digest``; a ``guc_trust_model`` string containing (case-insensitive)
    ``compromise``; truthy ``guard_inventory_ok``; ``totals.failed == totals.skipped == 0``.
    """
    inventory = [
        {
            "table": table,
            "rls_enabled": True,
            "force_enabled": True,
            "policy_count": 1,
            "policies": [{"policy": f"{table}_tenant_isolation", "command": "ALL",
                          "roles": ["monday_report_app"],
                          "using": "tenant_id = current_setting('app.tenant_slug')",
                          "with_check": "tenant_id = current_setting('app.tenant_slug')"}],
        }
        for table in _RLS_PROTECTED_TABLES
    ]
    payload: dict[str, Any] = {
        "schema_version": _ga.TENANT_RLS_EVIDENCE_SCHEMA,
        "evidence_type": "tenant-rls-enforcement",
        "implementation_version": "2.0.0",
        "status": "passed",
        "generated_at": _iso(_now()),
        "git_commit": commit,
        "git_tree": tree,
        "worktree_clean": True,
        "repository_mode": "postgres",
        "postgres_server_version": "PostgreSQL 16 (synthetic evidence, no server executed)",
        "postgres_image_digest": "sha256:" + _fp("tenant-rls", "image-digest"),
        "runtime_role_is_superuser": False,
        "runtime_role_has_bypassrls": False,
        "runtime_role_owner_bypass": False,
        "runtime_role_can_login": True,
        "runtime_role_is_login_not_group": True,
        "runtime_group_membership": ["monday_report_app"],
        "rls_forced_normalized_count": 4,
        "rls_forced_table_count": len(_RLS_PROTECTED_TABLES),
        "tenant_context_mechanism": "transaction_local_guc:app.tenant_slug",
        "policy_inventory": inventory,
        "policy_inventory_digest": hashlib.sha256(
            json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "guc_trust_model": (
            "A holder of valid runtime database credentials can set app.tenant_slug. RLS protects "
            "trusted application-set context and forgotten predicates. It is not a defense against "
            "arbitrary hostile SQL using compromise of the runtime credentials."
        ),
        "guard_inventory_ok": True,
        "totals": {"passed": 0, "failed": 0, "skipped": 0},
    }
    payload.update(_passed("schema_result", "roles_result", "direct_sql_result", "routes_result",
                           "worker_pool_result", "import_admin_result", "idempotency_result"))
    payload.update(DISCLOSURE)
    return _seal_ga(payload)


# ======================================================= 5. tenant-authorization evidence v3
def build_tenant_authorization_v3_evidence(commit: str, tree: str) -> dict:
    """``output/tenant-authorization/tenant-authorization-evidence.v3.json`` -- the second half
    of the ALL-OF control ``ga_tenant_authorization``.

    Validated by ``tenant_authorization_evidence.validate``. It demands, besides the identity /
    commit / tree / clean-worktree / canonical-hash binding: an exact ``proof_scope.statement``;
    a client-mode ``functional_runtime`` with six "verified" fields and the accepted counts
    266 / 144; a demo-mode ``ui_certification`` with nine exact string fields, 10 scenarios per
    backend, 28 fault checks and six zero counters; ``postgres_environment`` binding EXACTLY 7
    migrations each with a full SHA-256; a ``classification`` block that DISCLOSES
    ``production_parity=false`` and ``eligible_for_production_adapter_evidence=false``;
    ``runtime_roles`` for both the API and the worker process; an ``rls_policy`` block with >=8
    forced protected tables, a 64-hex inventory digest, six "passed" matrices, the exact GUC
    trust disclosure and the exact connection-lifecycle scope string; 14 + 16 + 8 + 8 provenance
    objects (``{status:"passed", proven_by:"audit:..."}`` -- bare literals are rejected) across
    ``tenant_authorization`` / ``mutations`` / ``operational`` / ``audit_integrity``, plus zero
    deltas and an ``eicar_http_status`` of 422; a ``privacy`` block enumerating EXACTLY the 13
    pattern-scanned categories; seven zero ``counters``; ``bound_implementations`` carrying the
    LIVE SHA-256 of 12 repository files; the exact ``hash_limitation`` and ``composition_note``
    strings; ``source_declarations`` all with ``eligible_for_tenant_evidence=false``; a
    ``generation_execution`` attestation; and ``check_totals`` equal to ``REQUIRED_TOTALS``.

    ``bound_implementations`` is recomputed at build time from the live repository, so the
    artifact fails closed the moment any of those 12 files drifts.
    """
    import backend.app.migrations as _mig

    migrations = [
        {"version": m.version, "filename": m.path.name,
         "sha256": hashlib.sha256(m.path.read_bytes()).hexdigest()}
        for m in _mig.discover_migrations(_mig.BASELINE_DIR)
    ]
    protected = [
        {"table": table, "rls_enabled": True, "force_enabled": True,
         "policies": [f"{table}_tenant_isolation"]}
        for table in _RLS_PROTECTED_TABLES
    ]
    payload: dict[str, Any] = {
        "schema_version": _tae.SCHEMA_VERSION,
        "evidence_type": _tae.EVIDENCE_TYPE,
        "implementation_version": _tae.IMPLEMENTATION_VERSION,
        "generated_at": _iso(_now()),
        "generation_metadata": {"generator": "synthetic_ga_evidence.py", **DISCLOSURE},
        "git_commit": commit,
        "git_tree": tree,
        "worktree_clean": True,
        "proof_scope": {
            "statement": _tae.PROOF_SCOPE_STATEMENT,
            "functional_runtime_mode": "client",
            "ui_mode": "demo",
        },
        "functional_runtime": {
            "mode": "client",
            "authentication_boundary": "active",
            "persisted_credentials": "verified",
            "identity_resolution": "verified",
            "tenant_resolution": "verified",
            "RBAC": "verified",
            "verified_reviewer_enforcement": "verified",
            "restricted_postgres_runtime": "verified",
            "full_functional_matrix": "passed",
            "functional_check_count": _tae.REQUIRED_TOTALS["functional"],
            "functional_fault_check_count": _tae.REQUIRED_TOTALS["functional_faults"],
        },
        "ui_certification": {
            "local_backend": "passed",
            "restricted_postgres_backend": "passed",
            "ui_mode": "demo",
            "client_mode_ui_authentication": "not_exercised",
            "UI_login_workflow": "not_exposed",
            "tenant_switch_UI": "not_exposed",
            "corrections_UI": "API_only",
            "validation_mutation_UI": "local_state_only",
            "signed_reference_UI": "API_only",
            "backend_consistency": "passed",
            "scenario_count_per_backend": _tae.REQUIRED_TOTALS["ui_scenarios_per_backend"],
            "fault_check_count": _tae.REQUIRED_TOTALS["ui_faults"],
            "counters": {"console_error_count": 0, "uncaught_exception_count": 0,
                         "failed_business_request_count": 0, "normal_HTTP_423_count": 0,
                         "normal_HTTP_500_count": 0, "normal_HTTP_503_count": 0},
        },
        "postgres_environment": {
            "postgres_version": "PostgreSQL 16 (synthetic evidence, no server executed)",
            "pgvector_version": "0-8-0 (synthetic evidence, no server executed)",
            "approved_container_image": "pgvector/pgvector (synthetic evidence)",
            "container_image_digest": "sha256:" + _fp("tenant-auth", "image-digest"),
            "migrations": migrations,
            "migration_inventory_result": "passed",
            "migration_0007_applied": True,
        },
        "classification": {
            "principal_class": _tae.MIGRATION_PRINCIPAL_CLASS,
            "migration_superuser": True,
            "test_only_migration_principal": True,
            "production_parity": False,
            "eligible_for_production_adapter_evidence": False,
        },
        "runtime_roles": {
            "api_process": {
                "database_backend": "postgres", "store_class": "PostgresStateStore",
                "session_user_classification": "restricted runtime LOGIN", "rolcanlogin": True,
                "rolsuper": False, "rolbypassrls": False, "protected_table_owner": False,
                "runtime_group_membership": True, "local_fallback": "rejected",
            },
            "worker_process": {
                "database_backend": "postgres", "store_class": "PostgresStateStore",
                "session_user_classification": "restricted runtime LOGIN", "rolcanlogin": True,
                "rolsuper": False, "rolbypassrls": False, "protected_table_owner": False,
                "runtime_group_membership": True, "local_fallback": "rejected",
            },
            "migration_principal_used_at_runtime": False,
        },
        "rls_policy": {
            "protected_tables": protected,
            "protected_table_count": len(protected),
            "policy_count": len(protected),
            "policy_inventory_digest": hashlib.sha256(
                json.dumps(protected, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
            "RLS_read_matrix": "passed",
            "RLS_write_matrix": "passed",
            "missing_GUC_fails_closed": "passed",
            "invalid_GUC_fails_closed": "passed",
            "same_connection_transaction_switching": "passed",
            "rollback_context_clearance": "passed",
            "guc_trust_disclosure": _tae.GUC_TRUST_DISCLOSURE,
            "connection_lifecycle_scope":
                "same-connection transaction lifecycle (no application pool exercised)",
        },
        "tenant_authorization": {
            **{f: _prov("audit:restricted-postgres-runtime-isolation") for f in (
                "valid_credential", "missing_credential", "invalid_credential",
                "revoked_credential", "disabled_credential", "wrong_tenant_credential",
                "actor_spoof_rejection", "tenant_spoof_rejection", "cross_tenant_report_denial",
                "cross_tenant_correction_denial", "cross_tenant_validation_denial",
                "cross_tenant_idempotency_denial", "cross_tenant_export_denial",
                "cross_tenant_signed_reference_denial")},
            "cross_tenant_target_mutation_delta": 0,
            "cross_tenant_business_audit_delta": 0,
            "cross_tenant_idempotency_delta": 0,
            "cross_tenant_content_disclosure": 0,
        },
        "mutations": {
            **{f: _prov("audit:restricted-postgres-runtime-mutations") for f in (
                "correction_create", "correction_supersede", "correction_revert",
                "validation_approve", "validation_reject", "validation_reopen", "exact_replay",
                "lost_response_replay", "changed_body", "changed_operation", "changed_actor",
                "changed_tenant", "changed_target", "missing_key", "malformed_key",
                "concurrency_race_handling")},
            "duplicate_business_mutations": 0,
            "duplicate_business_audits": 0,
            "duplicate_idempotency_rows": 0,
            "unexpected_revision_advances": 0,
            "lost_response_replay_scope": _tae.LOST_RESPONSE_REPLAY_SCOPE,
        },
        "operational": {
            "eicar_http_status": 422,
            **{f: _prov("audit:restricted-postgres-runtime-exports") for f in (
                "blocked_row_exactly_once", "upload_blocked_audit_exactly_once",
                "unresolved_export_validation_409", "unresolved_export_not_snapshot_conflict",
                "resolved_export_formats", "signed_reference_success",
                "signed_reference_tenant_denial", "signed_reference_tamper_expiry_denial")},
            **{f: _prov("audit:restricted-postgres-runtime-worker-import") for f in (
                "external_worker_process", "worker_process_boundary_tenant_isolation",
                "worker_retry_failure_isolation", "import_assess", "import_dry_run",
                "import_execute", "import_verify", "import_tenant_scoped_digests_markers")},
            "worker_model": _tae.WORKER_MODEL,
            "worker_isolation_model": _tae.WORKER_ISOLATION_MODEL,
        },
        "audit_integrity": {
            f: _prov("audit:restricted-postgres-runtime-core") for f in (
                "boundary_use_audit_ordering", "business_audit_ordering", "hmac_verification",
                "chain_verification", "tamper_detection", "actor_attribution",
                "tenant_attribution", "operation_attribution")
        },
        "privacy": {
            "secret_scan": "clean",
            "pattern_scanned_categories": list(_tae.PATTERN_SCANNED_CATEGORIES),
            "disclosed_by_design": _tae.DISCLOSED_BY_DESIGN,
        },
        "counters": {
            "normal_functional_http_423": 0, "normal_functional_http_500": 0,
            "normal_functional_http_503": 0, "normal_worker_process_failures": 0,
            "normal_import_process_failures": 0, "required_failed_checks": 0,
            "required_skipped_checks": 0,
        },
        "bound_implementations": {rel: _tae.sha256_file(rel)
                                  for rel in _tae.BOUND_IMPLEMENTATIONS},
        "hash_limitation": _tae.HASH_LIMITATION,
        "source_declarations": {
            cmd: {"eligible_for_tenant_evidence": False, "claim_scope": cmd}
            for cmd in ("audit:restricted-postgres-runtime",
                        "audit:restricted-postgres-runtime-core",
                        "audit:restricted-postgres-runtime-mutations",
                        "audit:restricted-postgres-runtime-exports",
                        "audit:restricted-postgres-runtime-isolation",
                        "audit:restricted-postgres-runtime-worker-import",
                        "audit:dual-backend-ui")
        },
        "composition_note": _tae.COMPOSITION_NOTE,
        "generation_execution": {
            "all_proofs_executed_this_run": True,
            "rls_artifact_regenerated_this_run": True,
            "stale_capture_reuse": False,
            "strict_worktree_clean_at_generation": True,
            "generation_worktree": "synthetic hermetic builder (no proof was executed)",
        },
        "check_totals": dict(_tae.REQUIRED_TOTALS),
    }
    payload.update(DISCLOSURE)
    payload["canonical_payload_hash"] = _tae.canonical_hash(payload)
    return payload


# ================================================= 6. production database-adapter evidence v1
def _adapter_domain(kind: str, name: str, observation_class: str,
                    generated: datetime) -> dict[str, Any]:
    return {
        "status": "PASS",
        "proven_by": f"synthetic parser-coverage observation for proof domain {name}",
        "observation_class": observation_class,
        "observed_at": _iso(generated - timedelta(days=1)),
        "binding_fingerprint": _fp(kind, name),
    }


def build_production_database_adapter_evidence(commit: str, tree: str) -> dict:
    """``output/production-database-adapter/production-database-adapter-evidence.v1.json``
    (``ga_postgres_adapter``).

    Validated by ``production_database_adapter_evidence.validate``: exact schema/evidence-type/
    implementation-version identity; full-40-hex ``git_commit``/``git_tree`` equal to the CURRENT
    values AND a currently-clean tracked worktree; a matching ``canonical_payload_hash``; a
    ``generated_at`` no more than 90 days old by WALL CLOCK; a ``target`` block whose provider is
    not ``unknown``, environment is ``production`` (``staging``/``test``/``development``
    rejected), endpoint is not ``loopback``/``docker-bridge``/``unknown``, storage is not
    ``ephemeral``, with ``tls_verified`` and ``credential_rotation_configured`` true and a
    64-hex ``service_identity_fingerprint``; a ``runtime_roles`` block with five true safety
    flags and a ``policy_inventory`` whose every entry has a string classification, a positive
    policy count and ``forced=true``; a ``non_qualifying_evidence_disclosure`` carrying the
    VERBATIM restricted-runtime disclosure, every one of the 9 non-qualifying sources, and an
    EMPTY ``promoted_sources``; all 22 REQUIRED proof domains as objects with the 5 required
    fields, ``status="PASS"``, a proving ``observation_class`` (per-domain constrained for 16 of
    them), a >=12-character ``proven_by``, a 64-hex ``binding_fingerprint`` and an
    ``observed_at`` within 90 days of ``generated_at``; NO unknown domain and no
    ``point_in_time_recovery`` domain unless ``claims_point_in_time_recovery`` is set;
    ``secret_scan_clean=true``; ``production_parity=true``; and a payload that trips none of the
    5 leak patterns (DSN, IPv4, ``password:``, ``secret|api_key|token:``, provider hostname).
    """
    generated = _now()
    domains: dict[str, Any] = {}
    for name in _pdae.REQUIRED_PROOF_DOMAINS:
        required = _pdae.DOMAIN_OBSERVATION_REQUIREMENTS.get(name)
        cls = required[0] if required else "signed_operator_attestation"
        domains[name] = _adapter_domain("production-database-adapter", name, cls, generated)

    payload: dict[str, Any] = {
        "schema_version": _pdae.SCHEMA_VERSION,
        "implementation_version": _pdae.IMPLEMENTATION_VERSION,
        "evidence_type": _pdae.EVIDENCE_TYPE,
        "git_commit": commit,
        "git_tree": tree,
        "worktree_clean": True,
        "generated_at": _iso(generated),
        "generation_metadata": {"generator": "synthetic_ga_evidence.py", **DISCLOSURE},
        "claims_point_in_time_recovery": False,
        "target": {
            "provider_classification": "managed-postgresql",
            "service_identity_fingerprint": _fp("production-database-adapter", "service-identity"),
            "environment_classification": "production",
            "endpoint_classification": "private-network",
            "storage_classification": "durable-replicated",
            "tls_verified": True,
            "credential_rotation_configured": True,
        },
        "runtime_roles": {
            "runtime_not_superuser": True,
            "runtime_not_bypassrls": True,
            "runtime_not_table_owner": True,
            "rls_enabled_and_forced": True,
            "migration_principal_distinct_from_runtime": True,
            "policy_inventory": [
                {"table_classification": f"normalized:{table}", "policy_count": 1, "forced": True}
                for table in _RLS_PROTECTED_TABLES
            ],
        },
        "non_qualifying_evidence_disclosure": {
            "restricted_runtime_disclosure": _pdae.RESTRICTED_RUNTIME_DISCLOSURE,
            "non_qualifying_sources": list(_pdae.NON_QUALIFYING_EVIDENCE),
            "promoted_sources": [],
        },
        "proof_domains": domains,
        "secret_scan_clean": True,
        "production_parity": True,
    }
    payload.update(DISCLOSURE)
    payload["canonical_payload_hash"] = _pdae.canonical_hash(payload)
    return payload


# ==================================================== 7. production queue-adapter evidence v1
def build_production_queue_adapter_evidence(commit: str, tree: str) -> dict:
    """``output/production-queue-adapter/production-queue-adapter-evidence.v1.json``
    (``ga_redis_adapter``).

    Validated by ``production_queue_adapter_evidence.validate``. Same identity / binding /
    clean-tree / canonical-hash / wall-clock-freshness spine as the database adapter, plus: a
    ``target`` that additionally declares a SAFE ``eviction_policy`` (only ``noeviction`` is
    accepted -- every other value including ``unknown`` can silently discard a queued job) and
    must not claim durability on ``ephemeral-only`` storage; an ``identities`` block where no
    role is ``default-user``/``unauthenticated`` and the two runtime roles are also not
    ``administrative``, with four true separation/binding flags; a ``delivery`` block declaring
    one of the 3 allowed models (``exactly-once`` is rejected outright), a positive
    ``retry_limit`` <= 1000 that is a real ``int`` (a bool is rejected), a substantive
    ``duplicate_delivery_behavior`` and ``dead_letter_disposition``,
    ``poison_message_isolated=true`` and -- for EVERY model --
    ``idempotency_contract_compatibility_observed=true`` and ``loss_window_disclosed=true``;
    a disclosure block carrying BOTH verbatim disclosures, all 12 non-qualifying sources and an
    empty ``promoted_sources``; all 37 REQUIRED proof domains (35 of them per-domain
    observation-class-constrained, e.g. ``failover_drill`` needs ``executed_failover_drill`` and
    ``queue_reachability_ping`` can never prove anything); the conditional
    ``idempotency_interaction`` domain, REQUIRED here because this artifact declares
    ``at-least-once``; NO unknown TOP-LEVEL key (``KNOWN_TOP_LEVEL_KEYS`` is enforced -- this is
    why the three disclosure keys live inside ``non_qualifying_evidence_disclosure``);
    ``secret_scan_clean=true``; ``production_parity=true``; and 7 leak patterns, including
    ``redis://`` and ``monday-report:<key>``.
    """
    generated = _now()
    domains: dict[str, Any] = {}
    for name in _pqae.REQUIRED_PROOF_DOMAINS:
        required = _pqae.DOMAIN_OBSERVATION_REQUIREMENTS.get(name)
        cls = required[0] if required else "signed_operator_attestation"
        domains[name] = _adapter_domain("production-queue-adapter", name, cls, generated)
    # at-least-once is declared below, so the conditional domain becomes REQUIRED.
    domains["idempotency_interaction"] = _adapter_domain(
        "production-queue-adapter", "idempotency_interaction", "executed_idempotency_test",
        generated)

    payload: dict[str, Any] = {
        "schema_version": _pqae.SCHEMA_VERSION,
        "implementation_version": _pqae.IMPLEMENTATION_VERSION,
        "evidence_type": _pqae.EVIDENCE_TYPE,
        "git_commit": commit,
        "git_tree": tree,
        "worktree_clean": True,
        "generated_at": _iso(generated),
        "generation_metadata": {"generator": "synthetic_ga_evidence.py", **DISCLOSURE},
        "target": {
            "provider_classification": "managed-queue-service",
            "service_identity_fingerprint": _fp("production-queue-adapter", "service-identity"),
            "environment_classification": "production",
            "endpoint_classification": "private-network",
            "tls_verified": True,
            "credential_rotation_configured": True,
            "eviction_policy": "noeviction",
            "storage_classification": "durable-replicated",
            "durability_claimed": True,
        },
        "identities": {
            "producer_identity_classification": "dedicated-least-privilege",
            "consumer_worker_identity_classification": "dedicated-least-privilege",
            "administrative_identity_classification": "administrative",
            "administrative_distinct_from_runtime": True,
            "tenant_namespace_bound": True,
            "payload_tenant_override_rejected": True,
            "local_fallback_prevented": True,
        },
        "delivery": {
            "model": "at-least-once",
            "retry_limit": 5,
            "duplicate_delivery_behavior": (
                "A redelivered job is absorbed by the operation-key idempotency contract; the "
                "second delivery replays the recorded response and commits nothing."
            ),
            "poison_message_isolated": True,
            "dead_letter_disposition": (
                "A job exceeding the retry limit is moved to a dead-letter destination and "
                "alerted on; it never blocks the primary queue."
            ),
            "idempotency_contract_compatibility_observed": True,
            "loss_window_disclosed": True,
            "loss_window": (
                "At-least-once delivery duplicates rather than loses; the compensating mechanism "
                "is the application operation-key idempotency contract."
            ),
        },
        "non_qualifying_evidence_disclosure": {
            "worker_test_disclosure": _pqae.WORKER_TEST_DISCLOSURE,
            "static_validation_disclosure": _pqae.STATIC_VALIDATION_DISCLOSURE,
            "non_qualifying_sources": list(_pqae.NON_QUALIFYING_EVIDENCE),
            "promoted_sources": [],
            # KNOWN_TOP_LEVEL_KEYS forbids these three at top level; here they are hash-covered.
            **DISCLOSURE,
        },
        "proof_domains": domains,
        "secret_scan_clean": True,
        "production_parity": True,
    }
    payload["canonical_payload_hash"] = _pqae.canonical_hash(payload)
    return payload


# --------------------------------------------------------------------------- plumbing
BUILDERS = {
    "migration": build_migration_evidence,
    "persistence": build_persistence_atomicity_evidence,
    "normalized": build_normalized_correction_evidence,
    "tenant_rls": build_tenant_rls_evidence,
    "tenant_auth_v3": build_tenant_authorization_v3_evidence,
    "db_adapter": build_production_database_adapter_evidence,
    "queue_adapter": build_production_queue_adapter_evidence,
}

PATH_RESOLUTION_NOTES = """\
Repointing the ga_readiness *_PATH constants IS sufficient to inject all seven artifacts:
every probe re-reads its module-level constant on each call (no caching), and ga_readiness
passes its own patched Path into production_database_adapter_evidence.load_and_validate(),
production_queue_adapter_evidence.load_and_validate() and
tenant_authorization_evidence.load_and_validate(), so those modules' own EVIDENCE_PATH
constants are never consulted by evaluate_blockers().

What the path constants do NOT redirect (all recomputed from the real repository ROOT):
  * ga_readiness._git_rev / _commit_binding_reasons  -> `git rev-parse` with cwd=ga_readiness.ROOT
  * production_*_adapter_evidence.git_rev / worktree_is_clean, tenant_authorization_evidence
    .git_rev / worktree_is_clean  -> each module has its OWN ROOT and shells git itself
  * _migration_evidence_valid  -> recomputes db/migrations and db/baseline set hashes
  * _correction_atomicity_probe / _persistence_locking_probe -> recompute the baseline versions
  * tenant_authorization_evidence.sha256_file -> hashes 12 real repository files
Consequence: build and evaluate inside the SAME checkout, and keep the TRACKED tree clean.
An untracked file is harmless (all three cleanliness checks use --untracked-files=no); a dirty
tracked file flips ga_postgres_adapter, ga_redis_adapter and ga_tenant_authorization back to
BLOCKED with "the tracked worktree is dirty now".
"""


def write_artifact(path: Path, payload: dict) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    return path


def build_all(commit: str | None = None, tree: str | None = None) -> dict[str, dict]:
    commit = commit or current_commit()
    tree = tree or current_tree()
    return {key: builder(commit, tree) for key, builder in BUILDERS.items()}


def install(outdir: Path, commit: str | None = None, tree: str | None = None) -> dict[str, Path]:
    """Write all seven artifacts under ``outdir`` and repoint the ga_readiness PATH constants."""
    outdir = Path(outdir)
    written: dict[str, Path] = {}
    for key, payload in build_all(commit, tree).items():
        const, rel = ARTIFACT_SLOTS[key]
        path = write_artifact(outdir / rel, payload)
        setattr(_ga, const, path)
        written[key] = path
    return written


SEVEN_CONTROLS = ("ga_migration_runner", "ga_migration_validity", "ga_persistence_locking",
                  "ga_correction_cross_process_atomicity", "ga_postgres_adapter",
                  "ga_redis_adapter", "ga_tenant_authorization")


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--outdir", default=None,
                        help="directory for the synthetic artifacts (default: a fresh temp dir)")
    args = parser.parse_args(argv)
    outdir = Path(args.outdir) if args.outdir else Path(tempfile.mkdtemp(prefix="synthetic-ga-"))

    absent = outdir / "__absent__.json"
    for const, _rel in ARTIFACT_SLOTS.values():
        setattr(_ga, const, absent)
    baseline = {c["id"]: c["disposition"] for c in _ga.evaluate_blockers({})}

    commit, tree = current_commit(), current_tree()
    written = install(outdir, commit, tree)
    after = {c["id"]: (c["disposition"], c["detail"]) for c in _ga.evaluate_blockers({})}

    print(f"repository ROOT : {REPO_ROOT}")
    print(f"git_commit      : {commit}")
    print(f"git_tree        : {tree}")
    print(f"artifacts       : {outdir}")
    for key, path in written.items():
        print(f"    {key:15s} {path.relative_to(outdir)}")
    print("\n{:42s} {:16s} {}".format("control", "baseline", "with synthetic evidence"))
    for cid in SEVEN_CONTROLS:
        print("{:42s} {:16s} {}".format(cid, baseline[cid], after[cid][0]))
    changed = sorted(c for c in baseline if after[c][0] != baseline[c])
    print("\nchanged-control set vs all-absent baseline:")
    for cid in changed:
        print(f"    {cid}: {baseline[cid]} -> {after[cid][0]}")
    print(f"\nga_migration_validity stays BLOCKED: {after['ga_migration_validity'][1]}")
    print("\n" + PATH_RESOLUTION_NOTES)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
