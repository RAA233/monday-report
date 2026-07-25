"""audit:tenant-authorization-evidence -- fail-closed mutation guard for tenant evidence v3.

Two batteries, both deterministic and Docker-free:

  * MUTATION (Part Q): a complete VALID synthetic v3 artifact is confirmed to validate first (so the
    gates are not always-fail), then every rejection category is mutated one at a time and the REAL
    contract validator (backend.app.tenant_authorization_evidence.validate) must reject it. Scope
    mutations are included: demo UI relabelled client, client functional runtime relabelled demo, the
    client authentication proof removed, UI authentication falsely claimed, the worker model changed to
    same-process switching, the connection lifecycle changed to a pool proof, production_parity true.

  * TARGETED PROBE (Part R): the REAL readiness probe is driven end-to-end with no evidence, valid v3,
    v1, v2, stale/wrong-tree, dirty-worktree, hash-tampered and scope-overclaimed artifacts, asserting
    the tenant-authorization control flips to PASS ONLY for valid v3 -- and that no unrelated control
    changes when v3 is present (migration validity BLOCKED, PostgreSQL adapter non-PASS, queue adapter
    non-PASS, client-data readiness non-ready, GA still GA_BLOCKED).

Every result carries check_id, description, mutation category, expected/observed disposition, result.
Honest scope: claim_scope=tenant-authorization-evidence-fail-closed-only; this guard proves the EVALUATOR
is fail-closed. It is not itself tenant evidence and is not readiness evidence.
"""
from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app import ga_readiness as GAR  # noqa: E402
from backend.app import tenant_authorization_evidence as TAE  # noqa: E402

checks: list[dict] = []
COMMIT, TREE = TAE.git_rev("HEAD"), TAE.git_rev("HEAD^{tree}")


def rec(cid, description, category, expected, observed, ok):
    checks.append({"check_id": cid, "description": description, "mutation_category": category,
                   "expected_disposition": expected, "observed_disposition": observed,
                   "result": "PASS" if ok else "FAIL"})


def build_valid_v3() -> dict:
    """A complete, VALID synthetic v3 artifact bound to the current clean commit/tree."""
    proc = {"database_backend": "postgres", "store_class": "PostgresStateStore",
            "session_user_classification": "restricted runtime LOGIN",
            "current_user_classification": "restricted runtime LOGIN",
            "rolcanlogin": True, "rolsuper": False, "rolbypassrls": False,
            "protected_table_owner": False, "runtime_group_membership": True,
            "local_fallback": "rejected"}
    tables = [{"schema": "public", "table": f"t{i}", "owner_classification": "migration admin",
               "rls_enabled": True, "force_enabled": True,
               "policies": [{"policy_name": f"p{i}", "command": "ALL", "permissiveness": "PERMISSIVE",
                             "roles": ["monday_report_app"], "using": "tenant_slug = current_setting(...)",
                             "with_check": "tenant_slug = current_setting(...)"}]} for i in range(8)]
    payload = {
        "schema_version": TAE.SCHEMA_VERSION, "implementation_version": TAE.IMPLEMENTATION_VERSION,
        "evidence_type": TAE.EVIDENCE_TYPE, "control": "tenant-authorization-enforcement",
        "git_commit": COMMIT, "git_tree": TREE, "worktree_clean": True,
        "generated_at": "2026-07-25T00:00:00Z",
        "proof_scope": {"statement": TAE.PROOF_SCOPE_STATEMENT,
                        "functional_runtime_mode": "client", "ui_mode": "demo"},
        "functional_runtime": {
            "mode": "client", "authentication_boundary": "active", "persisted_credentials": "verified",
            "identity_resolution": "verified", "tenant_resolution": "verified", "RBAC": "verified",
            "verified_reviewer_enforcement": "verified", "restricted_postgres_runtime": "verified",
            "full_functional_matrix": "passed", "functional_check_count": 266,
            "functional_fault_check_count": 144},
        "ui_certification": {
            "local_backend": "passed", "restricted_postgres_backend": "passed", "ui_mode": "demo",
            "client_mode_ui_authentication": "not_exercised", "UI_login_workflow": "not_exposed",
            "tenant_switch_UI": "not_exposed", "corrections_UI": "API_only",
            "validation_mutation_UI": "local_state_only", "signed_reference_UI": "API_only",
            "backend_consistency": "passed", "scenario_count_per_backend": 10, "fault_check_count": 28,
            "counters": {k: 0 for k in ("console_error_count", "uncaught_exception_count",
                                        "failed_business_request_count", "normal_HTTP_423_count",
                                        "normal_HTTP_500_count", "normal_HTTP_503_count")}},
        "postgres_environment": {
            "postgres_version": "16.4", "pgvector_version": "0.7.4",
            "approved_container_image": "pgvector/pgvector:pg16", "container_image_digest": "sha256:" + "a" * 64,
            "migrations": [{"name": f"000{i}_x.sql", "sha256": "b" * 64} for i in range(1, 8)],
            "migration_inventory_result": "passed", "migration_0007_applied": True},
        "classification": {"principal_class": TAE.MIGRATION_PRINCIPAL_CLASS, "migration_superuser": True,
                           "test_only_migration_principal": True, "production_parity": False,
                           "eligible_for_production_adapter_evidence": False},
        "runtime_roles": {"api_process": dict(proc), "worker_process": dict(proc),
                          "import_process_modes": ["assess", "dry-run", "execute", "verify"],
                          "migration_principal_used_at_runtime": False},
        "rls_policy": {
            "protected_tables": tables, "protected_table_count": 8, "policy_count": 8,
            "policy_inventory_digest": "c" * 64, "RLS_read_matrix": "passed", "RLS_write_matrix": "passed",
            "missing_GUC_fails_closed": "passed", "invalid_GUC_fails_closed": "passed",
            "same_connection_transaction_switching": "passed", "rollback_context_clearance": "passed",
            "connection_lifecycle_scope": "same-connection transaction lifecycle (no application pool exercised)",
            "guc_trust_disclosure": TAE.GUC_TRUST_DISCLOSURE},
        "tenant_authorization": {k: "passed" for k in (
            "valid_credential", "missing_credential", "invalid_credential", "revoked_credential",
            "disabled_credential", "wrong_tenant_credential", "actor_spoof_rejection",
            "tenant_spoof_rejection", "cross_tenant_report_denial", "cross_tenant_correction_denial",
            "cross_tenant_validation_denial", "cross_tenant_idempotency_denial",
            "cross_tenant_export_denial", "cross_tenant_signed_reference_denial")},
        "mutations": {k: "passed" for k in (
            "correction_create", "correction_supersede", "correction_revert", "validation_approve",
            "validation_reject", "validation_reopen", "exact_replay", "lost_response_replay",
            "changed_body", "changed_operation", "changed_actor", "changed_tenant", "changed_target",
            "missing_key", "malformed_key", "concurrency_race_handling")},
        "operational": {k: "passed" for k in (
            "blocked_row_exactly_once", "upload_blocked_audit_exactly_once",
            "unresolved_export_validation_409", "unresolved_export_not_snapshot_conflict",
            "resolved_export_formats", "signed_reference_success", "signed_reference_tenant_denial",
            "signed_reference_tamper_expiry_denial", "external_worker_process",
            "worker_process_boundary_tenant_isolation", "worker_retry_failure_isolation",
            "import_assess", "import_dry_run", "import_execute", "import_verify",
            "import_tenant_scoped_digests_markers")},
        "audit_integrity": {k: "passed" for k in (
            "boundary_use_audit_ordering", "business_audit_ordering", "hmac_verification",
            "chain_verification", "tamper_detection", "actor_attribution", "tenant_attribution",
            "operation_attribution")},
        "privacy": {"secret_scan": "clean", "scanned_categories": list(TAE.SECRET_SCAN_CATEGORIES)},
        "counters": {"normal_functional_http_423": 0, "normal_functional_http_500": 0,
                     "normal_functional_http_503": 0, "normal_worker_process_failures": 0,
                     "normal_import_process_failures": 0, "required_failed_checks": 0,
                     "required_skipped_checks": 0},
        "bound_implementations": {rel: TAE.sha256_file(rel) for rel in TAE.BOUND_IMPLEMENTATIONS},
        "check_totals": dict(TAE.REQUIRED_TOTALS),
    }
    payload["tenant_authorization"].update({
        "cross_tenant_target_mutation_delta": 0, "cross_tenant_business_audit_delta": 0,
        "cross_tenant_idempotency_delta": 0, "cross_tenant_content_disclosure": 0})
    payload["mutations"].update({
        "duplicate_business_mutations": 0, "duplicate_business_audits": 0,
        "duplicate_idempotency_rows": 0, "unexpected_revision_advances": 0,
        "lost_response_replay_scope": TAE.LOST_RESPONSE_REPLAY_SCOPE})
    payload["operational"].update({"eicar_http_status": 422, "worker_model": TAE.WORKER_MODEL,
                                   "worker_isolation_model": TAE.WORKER_ISOLATION_MODEL})
    payload["canonical_payload_hash"] = TAE.canonical_hash(payload)
    return payload


def rehash(p: dict) -> dict:
    p.pop("canonical_payload_hash", None)
    p["canonical_payload_hash"] = TAE.canonical_hash(p)
    return p


# --------------------------------------------------------------------------- mutations
def mutation(cid, category, description, mutate, *, rehash_after=True):
    p = build_valid_v3()
    mutate(p)
    if rehash_after:
        rehash(p)
    reasons = TAE.validate(p, current_commit=COMMIT, current_tree=TREE)
    rec(cid, description, category, "REJECTED", "REJECTED" if reasons else "ACCEPTED", bool(reasons))


def run() -> int:
    # ---- baseline: the valid artifact validates (gates are not always-fail) ----
    base_reasons = TAE.validate(build_valid_v3(), current_commit=COMMIT, current_tree=TREE)
    rec("EB00-baseline", "a complete valid v3 artifact validates (gates are not always-fail)",
        "baseline", "ACCEPTED", "ACCEPTED" if not base_reasons else f"REJECTED:{base_reasons[:2]}",
        not base_reasons)

    # ---- version / identity ----
    mutation("EM01-v1", "superseded-version", "a v1 artifact is rejected",
             lambda p: p.update({"schema_version": "tenant-rls-enforcement-evidence.v1"}))
    mutation("EM02-v2", "superseded-version", "a v2 artifact is rejected",
             lambda p: p.update({"schema_version": "tenant-rls-enforcement-evidence.v2"}))
    mutation("EM03-missing-schema", "missing-field", "a missing schema version is rejected",
             lambda p: p.pop("schema_version"))
    mutation("EM04-wrong-type", "wrong-evidence-type", "a wrong evidence type is rejected",
             lambda p: p.update({"evidence_type": "persistence"}))
    # ---- commit / tree / clean ----
    mutation("EM05-missing-commit", "binding", "a missing commit is rejected", lambda p: p.pop("git_commit"))
    mutation("EM06-abbrev-commit", "binding", "an abbreviated commit is rejected",
             lambda p: p.update({"git_commit": COMMIT[:12]}))
    mutation("EM07-wrong-commit", "binding", "a wrong commit is rejected",
             lambda p: p.update({"git_commit": "0" * 40}))
    mutation("EM08-missing-tree", "binding", "a missing tree is rejected", lambda p: p.pop("git_tree"))
    mutation("EM09-wrong-tree", "binding", "a wrong/stale tree is rejected",
             lambda p: p.update({"git_tree": "1" * 40}))
    mutation("EM10-dirty", "binding", "a dirty-worktree artifact is rejected",
             lambda p: p.update({"worktree_clean": False}))
    # ---- canonical hash ----
    mutation("EM11-missing-hash", "canonical-hash", "a missing canonical hash is rejected",
             lambda p: p.pop("canonical_payload_hash"), rehash_after=False)
    mutation("EM12-wrong-hash", "canonical-hash", "a tampered canonical hash is rejected",
             lambda p: p.update({"canonical_payload_hash": "d" * 64}), rehash_after=False)
    # ---- functional matrix ----
    mutation("EM13-missing-functional", "functional-proof", "a missing functional matrix is rejected",
             lambda p: p.pop("functional_runtime"))
    mutation("EM14-functional-count", "functional-proof", "a functional count != 266 is rejected",
             lambda p: p["functional_runtime"].update({"functional_check_count": 265}))
    mutation("EM15-fault-count", "functional-proof", "a functional fault count != 144 is rejected",
             lambda p: p["functional_runtime"].update({"functional_fault_check_count": 143}))
    mutation("EM16-integrity-total", "functional-proof", "an aggregate integrity total != 37 is rejected",
             lambda p: p["check_totals"].update({"aggregate_integrity": 36}))
    # ---- UI ----
    mutation("EM17-missing-ui", "ui-proof", "a missing UI result is rejected",
             lambda p: p.pop("ui_certification"))
    mutation("EM18-ui-local-fail", "ui-proof", "a failed local UI backend is rejected",
             lambda p: p["ui_certification"].update({"local_backend": "failed"}))
    mutation("EM19-ui-pg-fail", "ui-proof", "a failed PostgreSQL UI backend is rejected",
             lambda p: p["ui_certification"].update({"restricted_postgres_backend": "failed"}))
    mutation("EM20-ui-mode-client", "scope-overclaim", "a UI mode falsely reported as client is rejected",
             lambda p: p["ui_certification"].update({"ui_mode": "client"}))
    mutation("EM21-ui-auth-claimed", "scope-overclaim", "a falsely claimed client-mode UI authentication is rejected",
             lambda p: p["ui_certification"].update({"client_mode_ui_authentication": "verified"}))
    # ---- scope mutations ----
    mutation("EM22-functional-demo", "scope-overclaim", "the client functional runtime relabelled demo is rejected",
             lambda p: p["functional_runtime"].update({"mode": "demo"}))
    mutation("EM23-auth-proof-removed", "scope-overclaim", "a removed client authentication proof is rejected",
             lambda p: p["functional_runtime"].update({"authentication_boundary": "inactive"}))
    mutation("EM24-scope-statement", "scope-overclaim", "a missing/altered scope statement is rejected",
             lambda p: p["proof_scope"].update({"statement": "UI proves authenticated tenant resolution"}))
    mutation("EM25-worker-same-process", "scope-overclaim", "a same-process worker switching claim is rejected",
             lambda p: p["operational"].update({"worker_isolation_model": "same-process tenant switching"}))
    mutation("EM26-pool-claim", "scope-overclaim", "a connection-pool overclaim is rejected",
             lambda p: p["rls_policy"].update({"connection_lifecycle_scope": "application connection pool proof"}))
    mutation("EM27-production-parity", "scope-overclaim", "production_parity=true is rejected",
             lambda p: p["classification"].update({"production_parity": True}))
    mutation("EM28-adapter-eligible", "scope-overclaim", "production-adapter eligibility is rejected",
             lambda p: p["classification"].update({"eligible_for_production_adapter_evidence": True}))
    # ---- runtime roles ----
    mutation("EM29-local-backend", "runtime-identity", "a local functional backend is rejected",
             lambda p: p["runtime_roles"]["api_process"].update({"database_backend": "local"}))
    mutation("EM30-runtime-superuser", "runtime-identity", "a superuser runtime is rejected",
             lambda p: p["runtime_roles"]["api_process"].update({"rolsuper": True}))
    mutation("EM31-runtime-bypassrls", "runtime-identity", "a BYPASSRLS runtime is rejected",
             lambda p: p["runtime_roles"]["worker_process"].update({"rolbypassrls": True}))
    mutation("EM32-runtime-owner", "runtime-identity", "a protected-table-owning runtime is rejected",
             lambda p: p["runtime_roles"]["worker_process"].update({"protected_table_owner": True}))
    mutation("EM33-migration-creds", "runtime-identity", "migration credentials used at runtime are rejected",
             lambda p: p["runtime_roles"].update({"migration_principal_used_at_runtime": True}))
    # ---- RLS ----
    mutation("EM34-rls-disabled", "rls", "RLS disabled on a protected table is rejected",
             lambda p: p["rls_policy"]["protected_tables"][0].update({"rls_enabled": False}))
    mutation("EM35-force-disabled", "rls", "FORCE disabled on a protected table is rejected",
             lambda p: p["rls_policy"]["protected_tables"][1].update({"force_enabled": False}))
    mutation("EM36-missing-policy", "rls", "a protected table with no policy is rejected",
             lambda p: p["rls_policy"]["protected_tables"][2].update({"policies": []}))
    mutation("EM37-missing-trust", "rls", "a missing GUC trust disclosure is rejected",
             lambda p: p["rls_policy"].update({"guc_trust_disclosure": "isolation is absolute"}))
    # ---- counters ----
    mutation("EM38-http423", "counters", "a nonzero normal HTTP 423 is rejected",
             lambda p: p["counters"].update({"normal_functional_http_423": 1}))
    mutation("EM39-http500", "counters", "a nonzero normal HTTP 500 is rejected",
             lambda p: p["counters"].update({"normal_functional_http_500": 1}))
    mutation("EM40-http503", "counters", "a nonzero normal HTTP 503 is rejected",
             lambda p: p["counters"].update({"normal_functional_http_503": 1}))
    mutation("EM41-worker-failures", "counters", "nonzero normal worker failures are rejected",
             lambda p: p["counters"].update({"normal_worker_process_failures": 1}))
    mutation("EM42-import-failures", "counters", "nonzero normal import failures are rejected",
             lambda p: p["counters"].update({"normal_import_process_failures": 1}))
    mutation("EM43-ui-counters", "counters", "nonzero UI console/network counters are rejected",
             lambda p: p["ui_certification"]["counters"].update({"console_error_count": 1}))
    mutation("EM44-required-fail", "required-results", "any required FAIL is rejected",
             lambda p: p["counters"].update({"required_failed_checks": 1}))
    mutation("EM45-required-skip", "required-results", "any required SKIP is rejected",
             lambda p: p["counters"].update({"required_skipped_checks": 1}))
    # ---- operational / audit / privacy / bindings ----
    mutation("EM46-missing-malware", "operational-proof", "a missing malware/export proof is rejected",
             lambda p: p["operational"].update({"eicar_http_status": 200}))
    mutation("EM47-missing-audit", "audit-proof", "a missing audit HMAC/chain proof is rejected",
             lambda p: p["audit_integrity"].update({"hmac_verification": "not_run"}))
    mutation("EM48-missing-scan", "privacy", "a missing secret scan is rejected",
             lambda p: p["privacy"].pop("secret_scan"))
    mutation("EM49-dirty-scan", "privacy", "a non-clean secret scan is rejected",
             lambda p: p["privacy"].update({"secret_scan": "leaked"}))
    mutation("EM50-child-hash", "binding", "a changed accepted-proof implementation hash is rejected",
             lambda p: p["bound_implementations"].update(
                 {"scripts/dual_backend_ui_guard.py": "e" * 64}))
    mutation("EM51-malformed-section", "malformed",
             "a structurally malformed section (non-object) is rejected without crashing",
             lambda p: p.update({"rls_policy": "not-an-object"}))

    # malformed inputs must never raise
    for label, blob in (("string", "not-an-object"), ("list", [1, 2, 3]), ("none", None)):
        try:
            reasons = TAE.validate(blob, current_commit=COMMIT, current_tree=TREE)
            ok = bool(reasons)
            observed = "REJECTED" if ok else "ACCEPTED"
        except Exception as exc:  # noqa: BLE001
            ok, observed = False, f"CRASH:{type(exc).__name__}"
        rec(f"EM52-malformed-{label}", f"a malformed {label} artifact yields controlled rejection, not a crash",
            "malformed", "REJECTED", observed, ok)

    # ---- TARGETED PROBE BEHAVIOR (Part R) ----
    _probe_cases()
    return _emit()


def _probe_with(v3_payload, *, rls_valid=True):
    """Drive the REAL readiness probe with a patched evidence pair; returns the disposition."""
    orig_v3, orig_rls = GAR.TENANT_AUTHORIZATION_EVIDENCE_PATH, GAR.TENANT_RLS_EVIDENCE_PATH
    tmp = Path(tempfile.mkdtemp(prefix="mr-tae-probe-"))
    try:
        v3p = tmp / "v3.json"
        if v3_payload is not None:
            v3p.write_text(json.dumps(v3_payload), encoding="utf-8")
        GAR.TENANT_AUTHORIZATION_EVIDENCE_PATH = v3p
        if rls_valid:
            GAR.TENANT_RLS_EVIDENCE_PATH = orig_rls   # the real (freshly generated) RLS sub-proof
        else:
            GAR.TENANT_RLS_EVIDENCE_PATH = tmp / "absent.json"
        return GAR._tenant_authorization_probe()[0]
    finally:
        GAR.TENANT_AUTHORIZATION_EVIDENCE_PATH = orig_v3
        GAR.TENANT_RLS_EVIDENCE_PATH = orig_rls
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def _readiness_ids() -> list[str]:
    """Every readiness id referenced by the registry's delegated controls (favourable-input map)."""
    ids: set[str] = set()
    try:
        registry = GAR.load_registry()
        for entry in registry.get("controls", registry.get("entries", [])) or []:
            for rid in (entry.get("readiness_checks") or entry.get("readiness_ids") or []):
                ids.add(str(rid))
    except Exception:  # noqa: BLE001
        pass
    # Union with the known readiness surface so delegated controls are never "missing".
    ids.update({"demo_seed_removed", "parser_fixture_evals", "golden_fixture_coverage",
                "reviewed_fixture_attestation", "client_mode", "state_path_configured",
                "storage_root_configured", "export_root_configured", "api_key_configured",
                "signed_url_secret", "upload_size_limit", "archive_limits", "retention_policy",
                "hosted_fallback_disabled", "postgres_repository", "redis_queue", "local_llm_runtime"})
    return sorted(ids)


def _probe_cases():
    valid = build_valid_v3()
    rls_ok = GAR._tenant_rls_evidence_reasons() == []

    cases = [
        ("EP01-no-evidence", "no tenant evidence -> BLOCKED", "probe", None, "BLOCKED"),
        ("EP03-v1", "a v1 artifact -> BLOCKED", "probe",
         {**copy.deepcopy(valid), "schema_version": "tenant-rls-enforcement-evidence.v1"}, "BLOCKED"),
        ("EP04-v2", "a v2 artifact -> BLOCKED", "probe",
         {**copy.deepcopy(valid), "schema_version": "tenant-rls-enforcement-evidence.v2"}, "BLOCKED"),
        ("EP05-stale", "a stale (wrong-commit) v3 artifact -> BLOCKED", "probe",
         rehash({**copy.deepcopy(valid), "git_commit": "0" * 40}), "BLOCKED"),
        ("EP06-wrong-tree", "a wrong-tree v3 artifact -> BLOCKED", "probe",
         rehash({**copy.deepcopy(valid), "git_tree": "1" * 40}), "BLOCKED"),
        ("EP07-dirty", "a dirty-worktree v3 artifact -> BLOCKED", "probe",
         rehash({**copy.deepcopy(valid), "worktree_clean": False}), "BLOCKED"),
        ("EP08-hash-tampered", "a hash-tampered v3 artifact -> BLOCKED", "probe",
         {**copy.deepcopy(valid), "canonical_payload_hash": "f" * 64}, "BLOCKED"),
    ]
    overclaim = copy.deepcopy(valid)
    overclaim["ui_certification"]["client_mode_ui_authentication"] = "verified"
    cases.append(("EP09-scope-overclaim", "a scope-overclaiming v3 artifact -> BLOCKED", "probe",
                  rehash(overclaim), "BLOCKED"))

    for cid, desc, cat, payload, expected in cases:
        observed = _probe_with(payload)
        rec(cid, desc, cat, expected, observed, observed == expected)

    # valid v3 -> PASS (only meaningful when the real RLS sub-proof is present and valid)
    observed = _probe_with(valid)
    if rls_ok:
        rec("EP02-valid-v3", "a valid v3 artifact on the current clean tree -> tenant authorization PASS",
            "probe", "PASS", observed, observed == "PASS")
    else:
        rec("EP02-valid-v3",
            "a valid v3 artifact still BLOCKS while the RLS sub-proof artifact is absent/invalid "
            "(both proofs are required; run audit:tenant-rls-enforcement to complete it)",
            "probe", "BLOCKED", observed, observed == "BLOCKED")

    # ---- unrelated controls must not move BECAUSE tenant v3 is present (differential) ----
    # A realistic demo readiness map (mirrors the accepted GA integrity guard's shape). The test is a
    # DIFFERENTIAL: identical readiness inputs, evaluated WITHOUT and WITH the v3 artifact. Only the
    # tenant-authorization control may change; every other control must be byte-identical, and GA must
    # remain blocked in both. This is immune to whatever baseline map is chosen.
    readiness_demo = {
        "demo_seed_removed": "pass", "parser_fixture_evals": "warn", "golden_fixture_coverage": "warn",
        "reviewed_fixture_attestation": "warn", "client_mode": "warn", "state_path_configured": "pass",
        "storage_root_configured": "pass", "export_root_configured": "pass", "api_key_configured": "warn",
        "signed_url_secret": "warn", "upload_size_limit": "warn", "archive_limits": "warn",
        "retention_policy": "warn", "hosted_fallback_disabled": "pass",
    }
    orig = GAR.TENANT_AUTHORIZATION_EVIDENCE_PATH
    tmp = Path(tempfile.mkdtemp(prefix="mr-tae-unrelated-"))
    try:
        absent = tmp / "absent.json"
        present = tmp / "v3.json"
        present.write_text(json.dumps(valid), encoding="utf-8")

        GAR.TENANT_AUTHORIZATION_EVIDENCE_PATH = absent
        without = {b["id"]: b["disposition"] for b in GAR.evaluate_blockers(readiness_demo, forge_report=None)}
        GAR.TENANT_AUTHORIZATION_EVIDENCE_PATH = present
        with_v3 = {b["id"]: b["disposition"] for b in GAR.evaluate_blockers(readiness_demo, forge_report=None)}

        changed = sorted(k for k in set(without) | set(with_v3) if without.get(k) != with_v3.get(k))
        only_tenant = all(k == "ga_tenant_authorization" for k in changed)
        rec("EP10-only-tenant-control-moves",
            "introducing tenant evidence v3 changes NO control other than tenant-authorization "
            f"(changed={changed or 'none'})", "unrelated-control",
            "only ga_tenant_authorization may change", ",".join(changed) or "none", only_tenant)

        for cid, control in (("EP11-migration-validity", "ga_migration_validity"),
                             ("EP12-postgres-adapter", "ga_postgres_adapter")):
            unchanged = without.get(control) == with_v3.get(control)
            non_pass = with_v3.get(control) != "PASS"
            rec(cid, f"{control} is unchanged by tenant v3 and remains non-PASS", "unrelated-control",
                "unchanged and non-PASS",
                f"{without.get(control)}->{with_v3.get(control)}", unchanged and non_pass)

        queue_ids = sorted(k for k in with_v3 if "queue" in k or "redis" in k)
        q_ok = all(without.get(k) == with_v3.get(k) and with_v3.get(k) != "PASS" for k in queue_ids) if queue_ids else True
        rec("EP13-queue-adapter", f"queue-adapter control(s) {queue_ids or '(none in registry)'} unchanged "
            "by tenant v3 and non-PASS", "unrelated-control", "unchanged and non-PASS",
            ",".join(f"{k}:{with_v3.get(k)}" for k in queue_ids) or "none", q_ok)

        ga_blocked_without = any(v != "PASS" for v in without.values())
        ga_blocked_with = any(v != "PASS" for v in with_v3.values())
        rec("EP14-ga-blocked", "GA remains blocked both without and with tenant v3 (other controls "
            "still non-PASS); client-data readiness is not made ready by tenant evidence",
            "unrelated-control", "GA_BLOCKED both", 
            f"without={'GA_BLOCKED' if ga_blocked_without else 'GA_READY'},"
            f"with={'GA_BLOCKED' if ga_blocked_with else 'GA_READY'}",
            ga_blocked_without and ga_blocked_with)
    except Exception as exc:  # noqa: BLE001
        rec("EP10-only-tenant-control-moves", f"unrelated-control evaluation failed: {type(exc).__name__}",
            "unrelated-control", "evaluated", "ERROR", False)
    finally:
        GAR.TENANT_AUTHORIZATION_EVIDENCE_PATH = orig
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def _emit() -> int:
    ids = [c["check_id"] for c in checks]
    dups = sorted({i for i in ids if ids.count(i) > 1})
    failed = [c for c in checks if c["result"] != "PASS"]
    cats = {}
    for c in checks:
        cats[c["mutation_category"]] = cats.get(c["mutation_category"], 0) + 1
    out = {"checks": checks,
           "summary": {"passed": len(checks) - len(failed), "failed": len(failed), "skipped": 0,
                       "duplicate_ids": dups, "category_totals": cats,
                       "claim_scope": "tenant-authorization-evidence-fail-closed-only",
                       "mutation_battery": "passed" if not failed and not dups else "failed",
                       "eligible_for_tenant_evidence": False, "eligible_for_readiness": False,
                       "production_parity": False}}
    print(json.dumps(out, indent=2, default=str))
    if failed or dups:
        print(f"\nTenant-authorization evidence guard FAILED: {len(failed)} check(s), dups={dups}")
        for c in failed:
            print(f"  FAIL: {c['check_id']} -> expected {c['expected_disposition']}, "
                  f"observed {c['observed_disposition']}")
        return 1
    print(f"\nTenant-authorization evidence guard passed: {len(checks)} fail-closed proof(s)."
          "\n[claim_scope=tenant-authorization-evidence-fail-closed-only; NOT evidence/readiness eligible]")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
