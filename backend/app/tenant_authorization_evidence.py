"""Tenant-authorization evidence **v3**: canonical schema, deterministic hash, fail-closed validator.

v3 supersedes the v1/v2 tenant-RLS evidence artifacts for the ``tenant-authorization-enforcement``
control. It is a strictly larger claim: besides the database-enforced RLS proof, it binds the ACCEPTED
client-mode external functional runtime matrix, the ACCEPTED demo-mode dual-backend UI certification, the
PostgreSQL/migration environment, runtime role identity, the tenant/authorization denial matrix, the
corrections/validation/idempotency proof, the malware/export/worker/import proof, audit integrity, a
privacy scan, and the SHA-256 of every accepted proof implementation it relies on.

SCOPE HONESTY IS PART OF THE SCHEMA. The two proof sources prove different things and may never be
conflated:

  * ``functional_runtime``  -- CLIENT mode, authenticated tenant enforcement (the authoritative proof).
  * ``ui_certification``    -- DEMO mode, backend/UI consistency ONLY (never authentication proof).

v1 and v2 artifacts are REJECTED: the schema id, evidence type, and required sections differ, and the
validator requires the v3 identifiers explicitly. There is no backward-compatible acceptance path.

The validator NEVER raises on malformed input -- it returns a list of human-readable reasons, so a
corrupt or hostile artifact yields a controlled BLOCKED disposition instead of an evaluator crash.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

SCHEMA_VERSION = "tenant-authorization-evidence.v3"
IMPLEMENTATION_VERSION = "3.0.0"
EVIDENCE_TYPE = "tenant-authorization"
EVIDENCE_PATH = ROOT / "output" / "tenant-authorization" / "tenant-authorization-evidence.v3.json"

# Superseded identifiers that must NEVER satisfy the control again.
REJECTED_SCHEMA_VERSIONS = ("tenant-rls-enforcement-evidence.v1", "tenant-rls-enforcement-evidence.v2")

# Keys excluded from the canonical proof body: the hash itself plus non-deterministic generation
# metadata (timestamps / run ids). Everything else is hashed.
GENERATION_METADATA_KEYS = ("canonical_payload_hash", "generated_at", "generation_metadata")

# Required accepted totals (bound to the accepted Outcome-1 / Outcome-2 results).
REQUIRED_TOTALS = {
    "functional": 266,
    "functional_faults": 144,
    "aggregate_integrity": 37,
    "ui_scenarios_per_backend": 10,
    "ui_faults": 28,
}

# Accepted proof implementations whose SHA-256 the artifact must bind (Part M).
BOUND_IMPLEMENTATIONS = (
    "scripts/restricted_postgres_runtime_manifest.py",
    "scripts/restricted_postgres_runtime_manifest_ids.json",
    "scripts/restricted_postgres_runtime_aggregate_core.py",
    "scripts/restricted_postgres_runtime_guard.py",
    "scripts/restricted_postgres_runtime_faults_guard.py",
    "scripts/restricted_postgres_runtime_aggregate_integrity_guard.py",
    "scripts/dual_backend_ui_scenarios.mjs",
    "scripts/dual_backend_ui_guard.py",
    "scripts/dual_backend_ui_faults_guard.py",
    # the producer of the embedded RLS sub-proof, plus this contract and its generator: all three can
    # change what the artifact means, so drift in any of them must fail the artifact closed.
    "scripts/tenant_rls_enforcement_guard.py",
    "backend/app/tenant_authorization_evidence.py",
    "scripts/generate_tenant_authorization_evidence.py",
)

# Categories the generator PATTERN-SCANS. Anything disclosed by design (schema-level policy metadata)
# is recorded separately in the artifact rather than silently counted as "scanned".
PATTERN_SCANNED_CATEGORIES = (
    "DSN", "database password", "audit key", "signing key", "raw signed token", "credential",
    "raw verification nonce", "idempotency key", "run-scoped role name", "absolute path",
    "host:port pair", "Docker/volume id",
)
DISCLOSED_BY_DESIGN = (
    "RLS policy inventory carries schema-level principals (table owner, policy roles such as PUBLIC "
    "and the NOLOGIN group) because Part I requires the exact policy inventory; these are published "
    "schema facts, not credentials. Run-scoped role names, DSNs, hosts, ports and container ids are "
    "never emitted."
)
COMPOSITION_NOTE = (
    "Each accepted child proof declares eligible_for_tenant_evidence=false for ITSELF: no single child "
    "is tenant evidence. This artifact is the composition that binds them together with the RLS "
    "sub-proof, the commit/tree, and the implementation hashes; the composition -- not any child -- is "
    "what the tenant-authorization control consumes."
)
HASH_LIMITATION = (
    "canonical_payload_hash is an UNKEYED SHA-256 integrity digest over recomputable content: it "
    "detects corruption and tampering-in-place, and binds the artifact to a commit/tree and to the "
    "SHA-256 of every accepted proof implementation. It is not an authentication token and does not "
    "prove the artifact was produced by a particular execution."
)

PROOF_SCOPE_STATEMENT = (
    "The demo-mode UI certification does not prove authenticated client-mode tenant resolution. "
    "Authenticated tenant enforcement is proven by the client-mode external functional runtime matrix."
)

GUC_TRUST_DISCLOSURE = (
    "A holder of valid runtime database credentials can set app.tenant_slug. RLS protects trusted "
    "application-set context and forgotten predicates. It is not a defense against arbitrary hostile SQL "
    "using compromised runtime credentials."
)

WORKER_MODEL = "one-shot single-tenant-per-process"
WORKER_ISOLATION_MODEL = "process-boundary"
MIGRATION_PRINCIPAL_CLASS = "test-only-bootstrap-migration-admin"
LOST_RESPONSE_REPLAY_SCOPE = "server/API contract only"

SECRET_SCAN_CATEGORIES = (
    "raw verification nonce", "raw signed token", "credential", "idempotency key", "DSN",
    "database password", "audit key", "signing key", "role name", "host", "port", "Docker ID",
    "volume ID", "absolute path", "private request payload", "private export content",
)


# --------------------------------------------------------------------------- canonical hashing
def _normalize(obj):
    """Deterministic normalization: sorted mapping keys, sorted primitive lists, normalized
    booleans/numbers. Lists of mappings keep their authored order (it is semantically meaningful),
    but their contents are normalized recursively."""
    if isinstance(obj, dict):
        return {str(k): _normalize(obj[k]) for k in sorted(obj, key=str)}
    if isinstance(obj, (list, tuple)):
        items = [_normalize(v) for v in obj]
        if all(isinstance(v, (str, int, float, bool)) or v is None for v in items):
            return sorted(items, key=lambda v: (v is None, str(type(v)), str(v)))
        return items
    if isinstance(obj, bool):
        return bool(obj)
    if isinstance(obj, int):
        return int(obj)
    if isinstance(obj, float):
        # integral floats normalize to int so 266.0 and 266 hash identically
        return int(obj) if float(obj).is_integer() else float(obj)
    return obj


def canonical_body(payload: dict) -> dict:
    """The canonical proof body: the artifact minus the hash field and generation metadata."""
    return _normalize({k: v for k, v in payload.items() if k not in GENERATION_METADATA_KEYS})


def canonical_json(payload: dict) -> str:
    return json.dumps(canonical_body(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_hash(payload: dict) -> str:
    """Full 64-character lowercase SHA-256 of the canonical proof body."""
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def sha256_file(rel_path: str) -> str:
    return hashlib.sha256((ROOT / rel_path).read_bytes()).hexdigest()


def git_rev(ref: str) -> str:
    try:
        out = subprocess.run(["git", "rev-parse", ref], cwd=str(ROOT), capture_output=True, text=True, timeout=20)
        return out.stdout.strip() if out.returncode == 0 else "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def worktree_is_clean() -> bool:
    """Tracked-tree cleanliness. Untracked files (e.g. the partner docs) do not make the tree dirty
    for evidence purposes -- only tracked modifications/staged changes do."""
    try:
        out = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                             cwd=str(ROOT), capture_output=True, text=True, timeout=20)
        return out.returncode == 0 and not out.stdout.strip()
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------- fail-closed validator
def _is_full_sha(value) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(c in "0123456789abcdef" for c in value.lower())


def _int_or_none(value):
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _claim(section, field, reasons, prefix) -> None:
    """A derived claim must be a provenance object {status, proven_by}: the artifact may never assert a
    bare literal for something it did not itself observe -- it must name the accepted command that
    proves it."""
    value = section.get(field)
    if not isinstance(value, dict):
        reasons.append(f"{prefix}.{field} is not a provenance object (bare literals are not evidence)")
        return
    if value.get("status") != "passed":
        reasons.append(f"{prefix}.{field} status is not 'passed'")
    if not str(value.get("proven_by") or "").startswith("audit:"):
        reasons.append(f"{prefix}.{field} does not name the accepted command that proves it")


def validate(payload, *, current_commit=None, current_tree=None) -> list[str]:
    """Return a list of reasons the artifact must NOT satisfy tenant authorization. Empty == valid.

    Never raises: a malformed artifact yields reasons (controlled BLOCKED), not a crash.
    """
    reasons: list[str] = []
    if not isinstance(payload, dict):
        return ["tenant-authorization evidence is malformed (not an object)"]

    # ---- identity / version (v1 + v2 are explicitly rejected) ----
    sv = payload.get("schema_version")
    if sv in REJECTED_SCHEMA_VERSIONS:
        return [f"evidence schema {sv!r} is superseded; tenant authorization requires {SCHEMA_VERSION!r}"]
    if sv != SCHEMA_VERSION:
        reasons.append(f"evidence schema is {sv!r}, not {SCHEMA_VERSION!r}")
    if payload.get("evidence_type") != EVIDENCE_TYPE:
        reasons.append(f"evidence_type is {payload.get('evidence_type')!r}, not {EVIDENCE_TYPE!r}")
    if not isinstance(payload.get("implementation_version"), str) or not payload.get("implementation_version"):
        reasons.append("implementation_version is missing")

    # ---- commit / tree / clean binding (full 40-hex only) ----
    cur_commit = current_commit if current_commit is not None else git_rev("HEAD")
    cur_tree = current_tree if current_tree is not None else git_rev("HEAD^{tree}")
    ec, et = payload.get("git_commit"), payload.get("git_tree")
    if not _is_full_sha(ec):
        reasons.append("git_commit is missing, abbreviated, malformed, or not a full 40-character SHA")
    elif cur_commit != "unknown" and ec != cur_commit:
        reasons.append("evidence is bound to a different commit")
    if not _is_full_sha(et):
        reasons.append("git_tree is missing, abbreviated, malformed, or not a full 40-character SHA")
    elif cur_tree != "unknown" and et != cur_tree:
        reasons.append("evidence is stale: the tree changed after it was generated")
    if payload.get("worktree_clean") is not True:
        reasons.append("evidence was not captured from a clean worktree")
    elif not worktree_is_clean():
        # the flag is self-asserted; the tracked tree must ALSO be clean when the evidence is consumed,
        # otherwise an unbound file (store.py, main.py, ...) could be edited after generation
        reasons.append("the tracked worktree is dirty now: evidence no longer describes this tree")

    # ---- canonical hash (self-verifying, excludes only the hash + generation metadata) ----
    stored = payload.get("canonical_payload_hash")
    if not isinstance(stored, str) or len(stored) != 64 or stored != stored.lower():
        reasons.append("canonical_payload_hash is missing or not a full 64-character lowercase SHA-256")
    else:
        try:
            if canonical_hash(payload) != stored:
                reasons.append("canonical_payload_hash does not verify")
        except Exception:  # noqa: BLE001
            reasons.append("canonical payload could not be hashed (malformed proof body)")

    # ---- proof-scope honesty ----
    scope = payload.get("proof_scope")
    if not isinstance(scope, dict):
        reasons.append("proof_scope section is missing")
    else:
        if str(scope.get("statement", "")).strip() != PROOF_SCOPE_STATEMENT:
            reasons.append("proof_scope does not carry the exact demo-UI-vs-client-runtime scope statement")
        if scope.get("functional_runtime_mode") != "client":
            reasons.append("proof_scope functional_runtime_mode is not 'client'")
        if scope.get("ui_mode") != "demo":
            reasons.append("proof_scope ui_mode is not 'demo'")

    # ---- authenticated client-mode functional runtime ----
    fr = payload.get("functional_runtime")
    if not isinstance(fr, dict):
        reasons.append("functional_runtime proof is missing")
    else:
        if fr.get("mode") != "client":
            reasons.append("functional_runtime mode is not 'client' (authenticated proof required)")
        if fr.get("authentication_boundary") != "active":
            reasons.append("functional_runtime authentication_boundary is not active")
        for field in ("persisted_credentials", "identity_resolution", "tenant_resolution", "RBAC",
                      "verified_reviewer_enforcement", "restricted_postgres_runtime"):
            if fr.get(field) != "verified":
                reasons.append(f"functional_runtime.{field} is not 'verified'")
        if fr.get("full_functional_matrix") != "passed":
            reasons.append("functional_runtime full_functional_matrix is not 'passed'")
        if _int_or_none(fr.get("functional_check_count")) != REQUIRED_TOTALS["functional"]:
            reasons.append(f"functional check count is not {REQUIRED_TOTALS['functional']}")
        if _int_or_none(fr.get("functional_fault_check_count")) != REQUIRED_TOTALS["functional_faults"]:
            reasons.append(f"functional fault check count is not {REQUIRED_TOTALS['functional_faults']}")

    # ---- demo-mode dual-backend UI certification (consistency only) ----
    ui = payload.get("ui_certification")
    if not isinstance(ui, dict):
        reasons.append("ui_certification proof is missing")
    else:
        if ui.get("local_backend") != "passed":
            reasons.append("ui_certification local_backend is not 'passed'")
        if ui.get("restricted_postgres_backend") != "passed":
            reasons.append("ui_certification restricted_postgres_backend is not 'passed'")
        if ui.get("ui_mode") != "demo":
            reasons.append("ui_certification ui_mode is not 'demo' (a client-mode UI claim is an overclaim)")
        if ui.get("client_mode_ui_authentication") != "not_exercised":
            reasons.append("ui_certification falsely claims client-mode UI authentication")
        if ui.get("UI_login_workflow") != "not_exposed":
            reasons.append("ui_certification does not record the login workflow as not_exposed")
        if ui.get("tenant_switch_UI") != "not_exposed":
            reasons.append("ui_certification does not record the tenant-switch UI as not_exposed")
        if ui.get("corrections_UI") != "API_only":
            reasons.append("ui_certification does not record corrections as API_only")
        if ui.get("validation_mutation_UI") != "local_state_only":
            reasons.append("ui_certification does not record validation mutation as local_state_only")
        if ui.get("signed_reference_UI") != "API_only":
            reasons.append("ui_certification does not record signed references as API_only")
        if ui.get("backend_consistency") != "passed":
            reasons.append("ui_certification backend_consistency is not 'passed'")
        if _int_or_none(ui.get("scenario_count_per_backend")) != REQUIRED_TOTALS["ui_scenarios_per_backend"]:
            reasons.append("ui_certification scenario count per backend is not 10")
        if _int_or_none(ui.get("fault_check_count")) != REQUIRED_TOTALS["ui_faults"]:
            reasons.append("ui_certification fault check count is not 28")
        ui_counters = ui.get("counters")
        if not isinstance(ui_counters, dict):
            reasons.append("ui_certification counters are missing or malformed")
        else:
            for key in ("console_error_count", "uncaught_exception_count", "failed_business_request_count",
                        "normal_HTTP_423_count", "normal_HTTP_500_count", "normal_HTTP_503_count"):
                if _int_or_none(ui_counters.get(key)) != 0:
                    reasons.append(f"ui_certification counter {key} is missing or nonzero")

    # ---- PostgreSQL environment + migrations ----
    pg = payload.get("postgres_environment")
    if not isinstance(pg, dict):
        reasons.append("postgres_environment section is missing")
    else:
        for field in ("postgres_version", "pgvector_version", "approved_container_image",
                      "container_image_digest"):
            if not str(pg.get(field) or "").strip():
                reasons.append(f"postgres_environment.{field} is missing")
        migs = pg.get("migrations")
        if not isinstance(migs, list) or len(migs) != 7:
            reasons.append("postgres_environment does not bind exactly migrations 0001-0007")
        else:
            for entry in migs:
                if not isinstance(entry, dict) or len(str(entry.get("sha256") or "")) != 64:
                    reasons.append("a migration entry lacks a full SHA-256")
                    break
        if pg.get("migration_inventory_result") != "passed":
            reasons.append("migration inventory result is not 'passed'")
        if pg.get("migration_0007_applied") is not True:
            reasons.append("migration 0007 is not recorded as applied")

    # ---- classification honesty (never production parity / adapter eligible) ----
    cls = payload.get("classification")
    if not isinstance(cls, dict):
        reasons.append("classification section is missing")
    else:
        if cls.get("principal_class") != MIGRATION_PRINCIPAL_CLASS:
            reasons.append("migration principal_class is not the test-only bootstrap classification")
        if cls.get("migration_superuser") is not True:
            reasons.append("classification does not disclose that the migration principal is a superuser")
        if cls.get("test_only_migration_principal") is not True:
            reasons.append("classification does not mark the migration principal test-only")
        if cls.get("production_parity") is not False:
            reasons.append("classification claims production parity")
        if cls.get("eligible_for_production_adapter_evidence") is not False:
            reasons.append("classification claims production-adapter evidence eligibility")

    # ---- runtime roles / processes ----
    rr = payload.get("runtime_roles")
    if not isinstance(rr, dict):
        reasons.append("runtime_roles section is missing")
    else:
        for proc in ("api_process", "worker_process"):
            p = rr.get(proc)
            if not isinstance(p, dict):
                reasons.append(f"runtime_roles.{proc} is missing")
                continue
            if p.get("database_backend") != "postgres":
                reasons.append(f"{proc} database backend is not postgres (local fallback)")
            if p.get("store_class") != "PostgresStateStore":
                reasons.append(f"{proc} store class is not PostgresStateStore")
            if p.get("session_user_classification") != "restricted runtime LOGIN":
                reasons.append(f"{proc} session user is not the restricted runtime LOGIN")
            if p.get("rolcanlogin") is not True:
                reasons.append(f"{proc} runtime principal is not a LOGIN role")
            if p.get("rolsuper") is not False:
                reasons.append(f"{proc} runtime principal is a superuser")
            if p.get("rolbypassrls") is not False:
                reasons.append(f"{proc} runtime principal has BYPASSRLS")
            if p.get("protected_table_owner") is not False:
                reasons.append(f"{proc} runtime principal owns a protected table")
            if p.get("runtime_group_membership") is not True:
                reasons.append(f"{proc} runtime principal does not inherit the runtime group")
            if p.get("local_fallback") != "rejected":
                reasons.append(f"{proc} does not record local fallback as rejected")
        if rr.get("migration_principal_used_at_runtime") is not False:
            reasons.append("migration/bootstrap credentials were used at runtime")

    # ---- RLS + policy inventory ----
    rls = payload.get("rls_policy")
    if not isinstance(rls, dict):
        reasons.append("rls_policy section is missing")
    else:
        tables = rls.get("protected_tables")
        if not isinstance(tables, list) or len(tables) < 8:
            reasons.append("rls_policy does not carry the full protected-table inventory (>=8)")
        else:
            for t in tables:
                if not isinstance(t, dict):
                    reasons.append("a protected-table entry is malformed")
                    break
                if t.get("rls_enabled") is not True:
                    reasons.append(f"RLS is not enabled on {t.get('table')!r}")
                if t.get("force_enabled") is not True:
                    reasons.append(f"FORCE row level security is not enabled on {t.get('table')!r}")
                if not t.get("policies"):
                    reasons.append(f"no policy is recorded for {t.get('table')!r}")
        if _int_or_none(rls.get("protected_table_count")) is None or _int_or_none(rls.get("protected_table_count")) < 8:
            reasons.append("protected_table_count is missing or below 8")
        if _int_or_none(rls.get("policy_count")) is None or _int_or_none(rls.get("policy_count")) < 8:
            reasons.append("policy_count is missing or below 8")
        if len(str(rls.get("policy_inventory_digest") or "")) != 64:
            reasons.append("policy_inventory_digest is missing or not a full SHA-256")
        for field in ("RLS_read_matrix", "RLS_write_matrix", "missing_GUC_fails_closed",
                      "invalid_GUC_fails_closed", "same_connection_transaction_switching",
                      "rollback_context_clearance"):
            if rls.get(field) != "passed":
                reasons.append(f"rls_policy.{field} is not 'passed'")
        if str(rls.get("guc_trust_disclosure", "")).strip() != GUC_TRUST_DISCLOSURE:
            reasons.append("rls_policy does not carry the exact GUC trust disclosure")
        if rls.get("connection_lifecycle_scope") != "same-connection transaction lifecycle (no application pool exercised)":
            reasons.append("rls_policy overclaims an application connection-pool proof")

    # ---- tenant / authorization denial matrix ----
    ta = payload.get("tenant_authorization")
    if not isinstance(ta, dict):
        reasons.append("tenant_authorization section is missing")
    else:
        for field in ("valid_credential", "missing_credential", "invalid_credential", "revoked_credential",
                      "disabled_credential", "wrong_tenant_credential", "actor_spoof_rejection",
                      "tenant_spoof_rejection", "cross_tenant_report_denial", "cross_tenant_correction_denial",
                      "cross_tenant_validation_denial", "cross_tenant_idempotency_denial",
                      "cross_tenant_export_denial", "cross_tenant_signed_reference_denial"):
            _claim(ta, field, reasons, "tenant_authorization")
        for delta in ("cross_tenant_target_mutation_delta", "cross_tenant_business_audit_delta",
                      "cross_tenant_idempotency_delta", "cross_tenant_content_disclosure"):
            if _int_or_none(ta.get(delta)) != 0:
                reasons.append(f"tenant_authorization.{delta} is missing or nonzero")

    # ---- corrections / validation / idempotency ----
    mu = payload.get("mutations")
    if not isinstance(mu, dict):
        reasons.append("mutations section is missing")
    else:
        for field in ("correction_create", "correction_supersede", "correction_revert",
                      "validation_approve", "validation_reject", "validation_reopen",
                      "exact_replay", "lost_response_replay", "changed_body", "changed_operation",
                      "changed_actor", "changed_tenant", "changed_target", "missing_key",
                      "malformed_key", "concurrency_race_handling"):
            _claim(mu, field, reasons, "mutations")
        for delta in ("duplicate_business_mutations", "duplicate_business_audits",
                      "duplicate_idempotency_rows", "unexpected_revision_advances"):
            if _int_or_none(mu.get(delta)) != 0:
                reasons.append(f"mutations.{delta} is missing or nonzero")
        if mu.get("lost_response_replay_scope") != LOST_RESPONSE_REPLAY_SCOPE:
            reasons.append("mutations does not scope lost-response replay to the server/API contract")

    # ---- malware / export / worker / import ----
    op = payload.get("operational")
    if not isinstance(op, dict):
        reasons.append("operational (malware/export/worker/import) section is missing")
    else:
        if _int_or_none(op.get("eicar_http_status")) != 422:
            reasons.append("EICAR upload status is not 422")
        for field in ("blocked_row_exactly_once", "upload_blocked_audit_exactly_once",
                      "unresolved_export_validation_409", "unresolved_export_not_snapshot_conflict",
                      "resolved_export_formats", "signed_reference_success", "signed_reference_tenant_denial",
                      "signed_reference_tamper_expiry_denial", "external_worker_process",
                      "worker_process_boundary_tenant_isolation", "worker_retry_failure_isolation",
                      "import_assess", "import_dry_run", "import_execute", "import_verify",
                      "import_tenant_scoped_digests_markers"):
            _claim(op, field, reasons, "operational")
        if op.get("worker_model") != WORKER_MODEL:
            reasons.append("operational does not describe the one-shot single-tenant-per-process worker")
        if op.get("worker_isolation_model") != WORKER_ISOLATION_MODEL:
            reasons.append("operational overclaims same-process worker tenant switching")

    # ---- audit integrity ----
    au = payload.get("audit_integrity")
    if not isinstance(au, dict):
        reasons.append("audit_integrity section is missing")
    else:
        for field in ("boundary_use_audit_ordering", "business_audit_ordering", "hmac_verification",
                      "chain_verification", "tamper_detection", "actor_attribution",
                      "tenant_attribution", "operation_attribution"):
            _claim(au, field, reasons, "audit_integrity")

    # ---- privacy ----
    pv = payload.get("privacy")
    if not isinstance(pv, dict):
        reasons.append("privacy section is missing")
    else:
        if pv.get("secret_scan") != "clean":
            reasons.append(f"secret scan is {pv.get('secret_scan')!r}, not 'clean'")
        cats = pv.get("pattern_scanned_categories")
        if not isinstance(cats, list) or sorted(str(c) for c in cats) != sorted(PATTERN_SCANNED_CATEGORIES):
            reasons.append("privacy section does not enumerate exactly the categories actually pattern-scanned")
        if str(pv.get("disclosed_by_design", "")).strip() != DISCLOSED_BY_DESIGN:
            reasons.append("privacy section does not disclose the schema-level principals it emits by design")

    # ---- normal-counter gates + required FAIL/SKIP ----
    ct = payload.get("counters")
    if not isinstance(ct, dict):
        reasons.append("counters section is missing")
    else:
        for key in ("normal_functional_http_423", "normal_functional_http_500", "normal_functional_http_503",
                    "normal_worker_process_failures", "normal_import_process_failures",
                    "required_failed_checks", "required_skipped_checks"):
            if _int_or_none(ct.get(key)) != 0:
                reasons.append(f"counters.{key} is missing or nonzero")

    # ---- bound accepted implementations (hash drift fails closed) ----
    bi = payload.get("bound_implementations")
    if not isinstance(bi, dict):
        reasons.append("bound_implementations section is missing")
    else:
        for rel in BOUND_IMPLEMENTATIONS:
            recorded = bi.get(rel)
            if not isinstance(recorded, str) or len(recorded) != 64:
                reasons.append(f"bound_implementations lacks a full SHA-256 for {rel}")
                continue
            try:
                if sha256_file(rel) != recorded:
                    reasons.append(f"bound implementation changed since generation: {rel}")
            except Exception:  # noqa: BLE001
                reasons.append(f"bound implementation is unreadable: {rel}")

    # ---- integrity-digest honesty ----
    if str(payload.get("hash_limitation", "")).strip() != HASH_LIMITATION:
        reasons.append("artifact does not disclose that the canonical hash is an unkeyed integrity digest")

    # ---- children's own scope declarations must be carried, not silently promoted ----
    sd = payload.get("source_declarations")
    if not isinstance(sd, dict) or not sd:
        reasons.append("source_declarations section is missing (children's own scope declarations)")
    else:
        for cmd, decl in sd.items():
            if not isinstance(decl, dict):
                reasons.append(f"source_declarations.{cmd} is malformed")
                continue
            if decl.get("eligible_for_tenant_evidence") is not False:
                reasons.append(f"source_declarations.{cmd} does not record the child's own "
                               "eligible_for_tenant_evidence=false declaration")
    if str(payload.get("composition_note", "")).strip() != COMPOSITION_NOTE:
        reasons.append("artifact does not record how child proofs compose into tenant evidence")

    # ---- execution attestation: every proof executed by the generating run ----
    ge = payload.get("generation_execution")
    if not isinstance(ge, dict):
        reasons.append("generation_execution attestation is missing")
    else:
        if ge.get("all_proofs_executed_this_run") is not True:
            reasons.append("generation_execution does not attest that every proof ran in the generating run")
        if ge.get("rls_artifact_regenerated_this_run") is not True:
            reasons.append("generation_execution does not attest the RLS sub-proof was regenerated this run")
        if ge.get("stale_capture_reuse") is not False:
            reasons.append("generation_execution admits reuse of a stale capture")
        # WHERE the artifact was generated is part of the claim: the accepted RLS sub-proof defines a
        # clean worktree with a BARE `git status --porcelain` (untracked files count), so the artifact
        # must attest that the STRICT definition held in the tree that produced it.
        if ge.get("strict_worktree_clean_at_generation") is not True:
            reasons.append("generation_execution does not attest STRICT worktree cleanliness "
                           "(bare `git status --porcelain` empty) in the generating tree")
        if not str(ge.get("generation_worktree") or "").strip():
            reasons.append("generation_execution does not disclose which worktree generated the evidence")

    # ---- accepted totals ----
    totals = payload.get("check_totals")
    if not isinstance(totals, dict):
        reasons.append("check_totals section is missing")
    else:
        for key, expected in REQUIRED_TOTALS.items():
            if _int_or_none(totals.get(key)) != expected:
                reasons.append(f"check_totals.{key} is not {expected}")

    return reasons


def load_and_validate(path=None, **kwargs) -> list[str]:
    """Read the artifact and validate it. Absence/unreadability are reasons, never exceptions."""
    p = Path(path) if path is not None else EVIDENCE_PATH
    if not p.exists():
        return ["no tenant-authorization evidence v3 artifact"]
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [f"tenant-authorization evidence unreadable: {exc.__class__.__name__}"]
    return validate(payload, **kwargs)
