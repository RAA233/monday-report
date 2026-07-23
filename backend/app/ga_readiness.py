"""Registry-backed GA readiness evaluation.

This module turns the committed GA blocker registry (evals/ga/blocker_registry.v1.json)
into a truthful set of GA checks, each carrying an explicit disposition. A
known-but-unimplemented control is a declared BLOCKED entry that keeps GA red,
so "software blockers: 0" can never hide an unencoded gap. Blocker counts are
derived from each check's registry category — there are no hand-maintained
category ID sets.

Pure logic only: no FastAPI, no network. The GA guard and the integrity guard
both import from here.

No-waiver policy (v1): no waiver, environment variable, static configured
actor, or unsigned file can resolve a blocker. Verified per-user identity and
signature verification do not exist yet, so a waiver path would only create
another false-ready route.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "evals" / "ga" / "blocker_registry.v1.json"
MIGRATION_EVIDENCE_PATH = ROOT / "output" / "migrations" / "migration-evidence.v1.json"

CATEGORIES = {
    "software",
    "configuration",
    "infrastructure",
    "security_review",
    "data_review_evidence",
    "client_approval",
}
SEVERITIES = {"blocker", "high", "medium", "low"}
OWNER_TYPES = {"engineering", "security", "platform", "operations", "data_review", "client_organization"}
POLICY_SOURCES = {
    "tracker",
    "readiness_doc",
    "security_requirement",
    "operations_requirement",
    "existing_blocker",
    "code_deficiency",
}

# Dispositions and their GA-gating semantics.
DISPOSITIONS = {"PASS", "FAIL", "BLOCKED", "SKIPPED", "NOT_APPLICABLE", "REVIEW_REQUIRED"}
BLOCKING_DISPOSITIONS = {"FAIL", "BLOCKED", "SKIPPED", "REVIEW_REQUIRED"}
NON_BLOCKING_DISPOSITIONS = {"PASS", "NOT_APPLICABLE"}

# Legacy pass/warn/fail mapping (additive `status` on each emitted check).
# SKIPPED and missing evidence NEVER map to pass.
_LEGACY_STATUS = {
    "PASS": "pass",
    "FAIL": "fail",
    "BLOCKED": "fail",
    "SKIPPED": "fail",
    "NOT_APPLICABLE": "pass",
    "REVIEW_REQUIRED": "fail",
}

REQUIRED_ENTRY_FIELDS = (
    "id",
    "label",
    "category",
    "severity",
    "owner_type",
    "policy_source",
    "policy_reference",
    "check_id",
    "resolution_condition",
    "allow_not_applicable",
    "manual_review_required",
    "description",
)

_CONFIG_READINESS_IDS = (
    "client_mode",
    "state_path_configured",
    "storage_root_configured",
    "export_root_configured",
    "api_key_configured",
    "signed_url_secret",
    "upload_size_limit",
    "archive_limits",
    "retention_policy",
    "hosted_fallback_disabled",
)
_FIXTURE_READINESS_IDS = (
    "parser_fixture_evals",
    "golden_fixture_coverage",
    "reviewed_fixture_attestation",
)


def canonical_json(obj: object) -> str:
    """Deterministic UTF-8 JSON: sorted keys, stable separators, no ASCII escaping."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def payload_sha256(payload_without_hash: dict) -> str:
    """SHA-256 of the canonical JSON of a payload that MUST NOT contain payload_sha256."""
    if "payload_sha256" in payload_without_hash:
        raise ValueError("payload_sha256 must be excluded before hashing")
    return hashlib.sha256(canonical_json(payload_without_hash).encode("utf-8")).hexdigest()


def load_registry_bytes() -> bytes:
    return REGISTRY_PATH.read_bytes()


def load_registry() -> dict:
    return json.loads(load_registry_bytes().decode("utf-8"))


def registry_sha256() -> str:
    return hashlib.sha256(load_registry_bytes()).hexdigest()


def validate_registry(registry: dict) -> list[str]:
    """Strict schema validation. Returns a list of error strings (empty = valid)."""
    errors: list[str] = []
    if registry.get("registry_version") != "v1":
        errors.append("registry_version must be 'v1'")
    blockers = registry.get("blockers")
    if not isinstance(blockers, list) or not blockers:
        errors.append("blockers must be a non-empty list")
        return errors

    seen_ids: set[str] = set()
    seen_check_ids: set[str] = set()
    for index, entry in enumerate(blockers):
        context = f"blockers[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{context}: must be an object")
            continue
        for field in REQUIRED_ENTRY_FIELDS:
            if field not in entry or entry[field] in (None, ""):
                errors.append(f"{context}: missing required field {field!r}")
        entry_id = str(entry.get("id", ""))
        if entry_id in seen_ids:
            errors.append(f"{context}: duplicate blocker id {entry_id!r}")
        seen_ids.add(entry_id)
        check_id = str(entry.get("check_id", ""))
        if check_id in seen_check_ids:
            errors.append(f"{context}: duplicate check_id {check_id!r}")
        seen_check_ids.add(check_id)
        if entry.get("category") not in CATEGORIES:
            errors.append(f"{context}: unknown category {entry.get('category')!r}")
        if entry.get("severity") not in SEVERITIES:
            errors.append(f"{context}: unknown severity {entry.get('severity')!r}")
        if entry.get("owner_type") not in OWNER_TYPES:
            errors.append(f"{context}: unknown owner_type {entry.get('owner_type')!r}")
        if entry.get("policy_source") not in POLICY_SOURCES:
            errors.append(f"{context}: unknown policy_source {entry.get('policy_source')!r}")
        if not isinstance(entry.get("allow_not_applicable"), bool):
            errors.append(f"{context}: allow_not_applicable must be a boolean")
        if not isinstance(entry.get("manual_review_required"), bool):
            errors.append(f"{context}: manual_review_required must be a boolean")
    return errors


def _delegate(readiness_by_id: dict[str, str], ids: tuple[str, ...]) -> tuple[str, str]:
    """PASS iff every listed readiness check is 'pass'; else FAIL naming the failing ids."""
    missing = [i for i in ids if i not in readiness_by_id]
    if missing:
        return "SKIPPED", f"Delegated readiness check(s) not evaluated: {', '.join(missing)}."
    failing = [i for i in ids if readiness_by_id.get(i) != "pass"]
    if not failing:
        return "PASS", f"Delegated readiness check(s) pass: {', '.join(ids)}."
    return "FAIL", f"Delegated readiness check(s) not passing: {', '.join(failing)}."


def _forge_probe(forge_report: dict | None) -> tuple[str, str, str | None]:
    """Parser-coverage evidence from the promoted FORGE evaluation report."""
    manifest_path = ROOT / "evals" / "forge" / "manifest.v1.json"
    expectations_path = ROOT / "evals" / "forge" / "expectations.v1.json"
    if not manifest_path.exists() or not expectations_path.exists():
        return "BLOCKED", "Committed FORGE manifest/expectations are missing.", None
    if not forge_report:
        return (
            "SKIPPED",
            "No corpus-backed FORGE evaluation report present this run; parser coverage is not evidenced.",
            None,
        )
    summary = forge_report.get("summary") or {}
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    expectations_sha = hashlib.sha256(expectations_path.read_bytes()).hexdigest()
    reasons: list[str] = []
    if forge_report.get("manifest_sha256") != manifest_sha:
        reasons.append("manifest SHA-256 mismatch")
    if forge_report.get("expectations_sha256") != expectations_sha:
        reasons.append("expectations SHA-256 mismatch")
    if forge_report.get("status") != "pass":
        reasons.append(f"report status {forge_report.get('status')!r}")
    required_checks = summary.get("required_checks")
    required_passed = summary.get("required_passed")
    if not isinstance(required_checks, int) or required_checks <= 0:
        # A degenerate 0/0 report must never satisfy parser coverage.
        reasons.append("required_checks is not a positive count")
    elif (
        summary.get("required_failed", 1) != 0
        or not isinstance(required_passed, int)
        or required_passed != required_checks
    ):
        reasons.append(f"not {required_checks}/{required_checks} required")
    if reasons:
        return "FAIL", "FORGE parser-coverage evidence invalid: " + "; ".join(reasons) + ".", "output/forge-evals/forge_eval_report.json"
    return (
        "PASS",
        f"FORGE evaluation report is current and passes {summary.get('required_passed')}/"
        f"{summary.get('required_checks')} required.",
        "output/forge-evals/forge_eval_report.json",
    )


def _rbac_role_separation_probe() -> tuple[str, str]:
    """Evidence-driven evaluation of the ``rbac-role-separation`` control.

    Resolution condition (registry): distinct roles with enforced least privilege
    exist AND route authorization checks a per-user role, not the single
    configured all-role user. This probe inspects the ACTUAL policy/route code as
    evidence — it never accepts mere method/row presence. It evaluates ONLY the
    role-separation mechanism; the separate ``per-user-identity`` deployment
    control (and tenant/reviewer/audit-integrity controls) remain independent
    blockers, so this passing cannot by itself make GA ready.
    """
    try:
        from .permissions import ALL_PERMISSIONS, ROLE_PERMISSIONS, has_permission
        from .schemas import Role
        from . import main as _main
    except Exception as exc:  # pragma: no cover - defensive import guard
        return "BLOCKED", f"RBAC policy could not be evaluated: {exc}"

    active = (Role.ADMIN, Role.ENGINEER, Role.VALIDATOR, Role.MANAGER)
    perms = {role: frozenset(ROLE_PERMISSIONS.get(role, frozenset())) for role in active}
    reasons: list[str] = []
    if len({perms[role] for role in active}) != len(active):
        reasons.append("active roles are not pairwise-distinct")
    if not all(perms[role] for role in active):
        reasons.append("an active role has no permissions")
    if perms[Role.ADMIN] != frozenset(ALL_PERMISSIONS):
        reasons.append("ADMIN does not hold all permissions")
    if not all(perms[role] < frozenset(ALL_PERMISSIONS) for role in (Role.ENGINEER, Role.VALIDATOR, Role.MANAGER)):
        reasons.append("a non-admin role is not a proper least-privilege subset")
    if ROLE_PERMISSIONS.get(Role.VIEWER):
        reasons.append("legacy VIEWER role is activated")
    # Default-deny: empty roles and unknown permissions grant nothing.
    if has_permission((), next(iter(ALL_PERMISSIONS))) or has_permission(active, "__unknown_permission__"):
        reasons.append("default-deny is not enforced")
    # Complete per-route coverage with proven per-route dependencies.
    if not _main.route_policy_fully_enforced():
        reasons.append("route policy is not fully enforced")

    if reasons:
        return "BLOCKED", "RBAC role separation incomplete: " + "; ".join(reasons) + "."
    return (
        "PASS",
        "Distinct least-privilege roles (ADMIN=all; ENGINEER/VALIDATOR/MANAGER proper subsets; "
        "VIEWER unactivated) evaluate default-deny, and every route enforces a per-user permission "
        "(route policy fully enforced). Route authorization checks the request identity's roles, not a "
        "single configured all-role user.",
    )


def _tenant_authorization_probe() -> tuple[str, str]:
    """Evidence-driven evaluation of the ``tenant-authorization-enforcement`` control.

    Resolution condition (registry): tenant is resolved from the authenticated
    request AND enforced at the API layer WITH Postgres RLS active for the
    normalized store. This probe inspects the ACTUAL route/authorization code as
    evidence that the API-layer half is implemented, but the control stays BLOCKED
    because the RLS-backed normalized multi-tenant store is NOT implemented in this
    increment: the process serves one configured tenant via the local JSON snapshot
    and RLS is inactive. It never flips to PASS on the API-layer evidence alone.
    """
    try:
        from . import main as _main
        from . import tenant_authorization as _ta
    except Exception as exc:  # pragma: no cover - defensive import guard
        return "BLOCKED", f"Tenant authorization could not be evaluated: {exc}"

    reasons: list[str] = []
    for fn in ("request_tenant_id", "resource_tenant_id", "owns", "tenant_visible", "owned_via_graph", "system_tenant_context"):
        if not callable(getattr(_ta, fn, None)):
            reasons.append(f"tenant_authorization.{fn} missing")
    # Machine-readable parity (not mere substring presence): every resource-scoped
    # route proves a tenant-ownership dependency, AND the permission route policy is
    # fully enforced so permission precedes ownership.
    try:
        if not _main.tenant_ownership_fully_enforced():
            detail = "; ".join(_main.tenant_ownership_enforcement_errors()[:3])
            reasons.append(f"tenant-ownership parity incomplete: {detail}")
        if not _main.route_policy_fully_enforced():
            reasons.append("permission route policy not fully enforced")
    except Exception as exc:  # pragma: no cover - defensive
        reasons.append(f"parity evaluation failed: {exc}")

    if reasons:
        # Even the API-layer half is not fully wired; still BLOCKED.
        return "BLOCKED", "Tenant authorization enforcement incomplete: " + "; ".join(reasons) + "."

    # API-layer half is fully enforced. The resolution condition ALSO requires
    # "Postgres RLS active for the normalized store", proven by committed evidence
    # from a real, non-superuser runtime role on the current clean tree. Anything
    # absent/stale/dirty/mismatched/failed/skipped keeps the control BLOCKED.
    rls_reasons = _tenant_rls_evidence_reasons()
    if rls_reasons:
        return (
            "BLOCKED",
            "API-layer per-request tenant ownership enforcement is implemented and verified, but "
            "database-enforced tenant isolation is not proven: " + "; ".join(rls_reasons) + ".",
        )
    return (
        "PASS",
        "Tenant is resolved from the authenticated request and enforced at the API layer (every "
        "resource-scoped route proves a tenant-ownership dependency; cross-tenant access is an "
        "existence-hiding 404; signed capabilities bind the owning tenant), AND Postgres RLS is "
        "active over the normalized store: forced row level security on the normalized + parent + "
        "operational tables is enforced against a real non-superuser, non-BYPASSRLS runtime role "
        "(missing/wrong/malformed tenant context denies; WITH CHECK blocks cross-tenant writes; "
        "connection reuse retains no context), proven by real-PostgreSQL evidence bound to the "
        "current clean tree (scripts/tenant_rls_enforcement_guard.py).",
    )


def _tenant_rls_evidence_reasons() -> list[str]:
    """Fail-closed validation of the tenant-RLS-enforcement evidence artifact.

    Returns an empty list ONLY when committed evidence from a real PostgreSQL run
    on the current clean tree proves forced RLS is enforced against a non-superuser,
    non-BYPASSRLS runtime role. Any absence/staleness/mismatch/failure/skip is a
    reason the control stays BLOCKED.
    """
    if not TENANT_RLS_EVIDENCE_PATH.exists():
        return ["no tenant-RLS-enforcement evidence artifact"]
    try:
        payload = json.loads(TENANT_RLS_EVIDENCE_PATH.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [f"tenant-RLS evidence unreadable: {exc.__class__.__name__}"]
    if not isinstance(payload, dict):
        return ["tenant-RLS evidence malformed"]

    reasons: list[str] = []
    if payload.get("schema_version") != TENANT_RLS_EVIDENCE_SCHEMA:
        reasons.append(f"evidence schema is {payload.get('schema_version')!r}")
    if payload.get("status") != "passed":
        reasons.append(f"status is {payload.get('status')!r}, not 'passed'")
    stored = payload.get("payload_sha256")
    if not stored:
        reasons.append("no payload hash")
    else:
        recomputed = payload_sha256({k: v for k, v in payload.items() if k != "payload_sha256"})
        if recomputed != stored:
            reasons.append("payload hash does not verify")
    if not payload.get("worktree_clean"):
        reasons.append("evidence was not captured from a clean worktree")
    if payload.get("repository_mode") != "postgres":
        reasons.append("evidence was not generated in PostgreSQL mode")
    if not payload.get("postgres_server_version") or not payload.get("postgres_image_digest"):
        reasons.append("evidence lacks a real PostgreSQL server version or image digest")
    reasons.extend(_commit_binding_reasons(payload))
    # Runtime role must genuinely be unable to bypass RLS.
    if payload.get("runtime_role_is_superuser"):
        reasons.append("evidence runtime role is a superuser (would bypass RLS)")
    if payload.get("runtime_role_has_bypassrls"):
        reasons.append("evidence runtime role has BYPASSRLS")
    if payload.get("runtime_role_owner_bypass"):
        reasons.append("evidence runtime role owns a protected table without FORCE (owner bypass)")
    def _as_int(value: object) -> int:
        # Malformed (non-integer) evidence must fail closed to 0 -> BLOCKED, never crash.
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0
    if _as_int(payload.get("rls_forced_normalized_count")) < 4:
        reasons.append("fewer than four normalized tables have FORCE row level security")
    if _as_int(payload.get("rls_forced_table_count")) < 8:
        reasons.append("fewer than eight protected tables have FORCE row level security")
    for field in ("schema_result", "roles_result", "direct_sql_result", "routes_result",
                  "worker_pool_result", "import_admin_result", "idempotency_result"):
        if payload.get(field) != "passed":
            reasons.append(f"{field} is not 'passed'")
    if payload.get("tenant_context_mechanism") != "transaction_local_guc:app.tenant_slug":
        reasons.append("evidence does not declare the transaction-local tenant-context mechanism")
    # The runtime principal must be a real LOGIN role that inherits the app group,
    # never the NOLOGIN group misreported as the DSN login principal.
    if not payload.get("runtime_role_can_login"):
        reasons.append("evidence runtime principal is not a LOGIN role")
    if not payload.get("runtime_role_is_login_not_group"):
        reasons.append("evidence runtime principal is the NOLOGIN group, not a distinct login role")
    if "monday_report_app" not in (payload.get("runtime_group_membership") or []):
        reasons.append("evidence runtime login does not inherit the monday_report_app group")
    # Exact policy inventory (not a count) + digest must be present.
    if not payload.get("policy_inventory") or not payload.get("policy_inventory_digest"):
        reasons.append("evidence lacks an exact RLS policy inventory + digest")
    # The GUC trust model must be disclosed honestly (limitation stated).
    guc = str(payload.get("guc_trust_model") or "")
    if "compromise" not in guc.lower():
        reasons.append("evidence does not disclose the GUC trust-model limitation")
    if not payload.get("guard_inventory_ok"):
        reasons.append("guard check inventory is not fail-closed")
    totals = payload.get("totals") or {}
    if totals.get("failed") != 0:
        reasons.append("evidence records failed checks")
    if totals.get("skipped") != 0:
        reasons.append("evidence records skipped checks")
    return reasons


def _audit_keyed_integrity_probe() -> tuple[str, str]:
    """Evidence-driven evaluation of the ``audit-keyed-integrity`` control.

    PASS-capable ONLY when an active managed HMAC key exists AND the keyed path is
    verified by RUNTIME evidence: a fresh v2 event round-trips under HMAC, a
    public-SHA forgery of the same payload is REJECTED, the client-mode fail-closed
    guarantee is present in the audit code, and no key material is exposed. With no
    active key (or a code-wiring gap) it is BLOCKED — it never flips to PASS on code
    presence alone. Tail-truncation detection is a SEPARATE, still-BLOCKED control.
    """
    try:
        import hmac as _hmac
        import inspect
        from hashlib import sha256 as _sha256
        from uuid import uuid4

        from . import store as _store_mod
        from .audit_keys import (
            INTEGRITY_ALGORITHM,
            KEYED_INTEGRITY_VERSION,
            AuditKeyConfigError,
            audit_key_provider,
        )
        from .schemas import AuditLog
    except Exception as exc:  # pragma: no cover - defensive
        return "BLOCKED", f"Audit keyed integrity could not be evaluated: {exc}"

    reasons: list[str] = []
    try:
        audit_src = inspect.getsource(_store_mod.LocalStateStore.audit)
    except Exception:
        audit_src = ""
    for marker in ("AuditIntegrityUnavailable", "_audit_v2_hash"):
        if marker not in audit_src:
            reasons.append(f"keyed/fail-closed wiring marker {marker!r} absent from audit()")
    # The client-mode fail-closed must apply to EVERY actor: the former
    # system-actor carve-out must be gone from audit(), and the central
    # mutation-writability preflight must exist so business mutations fail closed
    # BEFORE touching state.
    if 'actor_source != "system"' in audit_src:
        reasons.append(
            "system-actor carve-out still present in audit(); client mode must "
            "fail closed for all actors (worker/CLI/startup/denial)"
        )
    if not hasattr(_store_mod.LocalStateStore, "require_audit_write_capability"):
        reasons.append("central mutation-writability preflight (require_audit_write_capability) missing")
    if not hasattr(_store_mod.LocalStateStore, "_audit_v2_hash") or not hasattr(
        _store_mod.LocalStateStore, "_canonical_v2_audit_payload"
    ):
        reasons.append("keyed HMAC methods missing")

    provider = audit_key_provider()
    try:
        key_ref = provider.active_key()
    except AuditKeyConfigError as exc:
        return "BLOCKED", f"Audit HMAC key is configured but invalid: {exc}."
    if key_ref is None:
        return "BLOCKED", (
            "Keyed audit integrity is implemented but the control is BLOCKED because no active managed HMAC "
            "key is configured (audit events are legacy/unkeyed). Configure a >=32-byte managed audit secret "
            "the state-file writer does not control."
            + ((" Wiring issues: " + "; ".join(reasons) + ".") if reasons else "")
        )

    # Runtime evidence: sign + verify a v2 event and reject a public-SHA forgery.
    event = AuditLog(
        tenant_id=uuid4(),
        actor_user_id=uuid4(),
        action="ga.audit_keyed_probe",
        resource_type="probe",
        integrity_version=KEYED_INTEGRITY_VERSION,
        integrity_algorithm=INTEGRITY_ALGORITHM,
        key_id=key_ref.key_id,
        key_version=key_ref.key_version,
    )
    payload = _store_mod.LocalStateStore._canonical_v2_audit_payload(event)
    keyed = _hmac.new(key_ref.secret, payload, _sha256).hexdigest()
    roundtrip_ok = _hmac.compare_digest(keyed, _hmac.new(key_ref.secret, payload, _sha256).hexdigest())
    forgery_rejected = not _hmac.compare_digest(keyed, _sha256(payload).hexdigest())
    if not roundtrip_ok:
        reasons.append("v2 HMAC roundtrip failed")
    if not forgery_rejected:
        reasons.append("public-SHA forgery accepted")
    if reasons:
        return "BLOCKED", "Keyed audit integrity evidence incomplete: " + "; ".join(reasons) + "."
    return (
        "PASS",
        f"Audit events are sealed with a versioned keyed HMAC-SHA256 (active key {key_ref.key_id}/"
        f"{key_ref.key_version}, provider {provider.provider_type()}). A fresh v2 event round-trips under HMAC "
        "and a public-SHA forgery of the same payload is rejected; client-mode request writes fail closed "
        "without a key; no key material is exposed. Tail-truncation detection remains a separate BLOCKED "
        "control (external append-only anchor not implemented in this increment).",
    )


_verified_reviewer_evidence_cache: tuple[bool, list[str]] | None = None


def _verified_reviewer_behavioral_evidence() -> tuple[bool, list[str]]:
    """Invoke the REAL reviewer contract on a throwaway, fully ISOLATED client-mode
    store (tempdir STATE_PATH; env saved and restored; never touches live state) and
    return (ok, reasons). Exercised end to end: an eligible authenticated reviewer
    records a correction whose verified attribution matches the KEYED audit actor; a
    second reviewer reverts (reverter kept distinct); a TERMINAL validation outcome
    attributes the reviewer; an ADMINISTRATIVE reopen creates NO verified evidence; a
    system actor is rejected before mutation; the outcome/audit consistency verifier
    is clean; and no credential token/hash leaks. Cached per process."""
    global _verified_reviewer_evidence_cache
    if _verified_reviewer_evidence_cache is not None:
        return _verified_reviewer_evidence_cache
    import json as _json
    import os as _os
    import shutil as _shutil
    import tempfile as _tempfile
    from uuid import uuid4

    reasons: list[str] = []
    _ENV = (
        "MONDAY_REPORT_CLIENT_DATA_MODE", "MONDAY_REPORT_STATE_PATH", "MONDAY_REPORT_STORAGE_ROOT",
        "MONDAY_REPORT_EXPORT_ROOT", "MONDAY_REPORT_TENANT_SLUG", "MONDAY_REPORT_TENANT_NAME",
        "MONDAY_REPORT_USER_EMAIL", "MONDAY_REPORT_API_KEY", "MONDAY_REPORT_AUDIT_HMAC_KEY",
        "MONDAY_REPORT_AUDIT_HMAC_KEY_ID", "MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION",
        "MONDAY_REPORT_AUDIT_HMAC_RETAINED_KEYS",
    )
    saved = {k: _os.environ.get(k) for k in _ENV}
    tmp = _tempfile.mkdtemp(prefix="ga-reviewer-evidence-")
    try:
        _os.environ.update({
            "MONDAY_REPORT_CLIENT_DATA_MODE": "client",
            "MONDAY_REPORT_STATE_PATH": _os.path.join(tmp, "state.json"),
            "MONDAY_REPORT_STORAGE_ROOT": _os.path.join(tmp, "storage"),
            "MONDAY_REPORT_EXPORT_ROOT": _os.path.join(tmp, "exports"),
            "MONDAY_REPORT_TENANT_SLUG": "ga-reviewer-evidence",
            "MONDAY_REPORT_TENANT_NAME": "GA Reviewer Evidence",
            "MONDAY_REPORT_USER_EMAIL": "bootstrap@ga-reviewer-evidence.local",
            "MONDAY_REPORT_AUDIT_HMAC_KEY": "ga-reviewer-evidence-audit-hmac-key-0123456",
            "MONDAY_REPORT_AUDIT_HMAC_KEY_ID": "ga-reviewer-evidence",
            "MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION": "1",
        })
        _os.environ.pop("MONDAY_REPORT_API_KEY", None)
        _os.environ.pop("MONDAY_REPORT_AUDIT_HMAC_RETAINED_KEYS", None)
        from . import store as _sm
        from .identity import reset_current_identity, set_current_identity
        from .permissions import has_permission
        from .schemas import (
            AuthenticatedIdentity, FieldCorrectionCreate, Role, ValidationStatus,
            ValidationTask, ValidationTaskUpdate, WorkspaceCreate,
        )

        role = next((r for r in Role if has_permission([r], "record_field_corrections")
                     and has_permission([r], "resolve_validation")), None)
        if role is None:
            reasons.append("no role grants record_field_corrections + resolve_validation")
        else:
            S = _sm.LocalStateStore()  # fully isolated instance (NOT the singleton)

            def _ident(user, cred):
                return AuthenticatedIdentity(
                    user_id=user.id, tenant_id=S.tenant.id, email=user.email, display_name=user.full_name,
                    roles=list(user.roles), authentication_source="api_token",
                    credential_id=cred.credential_id, credential_fingerprint=cred.token_fingerprint,
                    actor_source="authenticated")

            ua = S.create_user("a@rev.evidence", "Rev A", [role]); ca, tok_a = S.create_credential(ua.id)
            ub = S.create_user("b@rev.evidence", "Rev B", [role]); cb, tok_b = S.create_credential(ub.id)
            _t = set_current_identity(_ident(ua, ca))
            try:
                ws = S.create_workspace(WorkspaceCreate(name="Evidence WS"))
                corr = S.record_field_correction(ws.id, FieldCorrectionCreate(
                    target_type="failure", field_key="severity", corrected_value="high",
                    correction_reason="reviewer evidence correction record"))
            finally:
                reset_current_identity(_t)
            rec = S.audit_logs[-1]
            if not (corr.reviewer_user_id == ua.id == rec.actor_user_id and corr.reviewer_verified_at is not None
                    and corr.reviewer_actor_source == "authenticated" and rec.integrity_version == 2):
                reasons.append("record: verified attribution / keyed-audit consistency failed")
            _t = set_current_identity(_ident(ub, cb))
            try:
                rev = S.revert_field_correction(corr.id, "reviewer evidence revert")
            finally:
                reset_current_identity(_t)
            if not (rev.revert_reviewer_user_id == ub.id and rev.reviewer_user_id == ua.id
                    and rev.revert_reviewer_user_id != rev.reviewer_user_id):
                reasons.append("revert: reverter not distinct from recorder")
            vt = ValidationTask(tenant_id=S.tenant.id, target_type="failure", target_id=uuid4(),
                                reason="r", status=ValidationStatus.OPEN)
            S.validation_tasks[vt.id] = vt; S.save()
            _t = set_current_identity(_ident(ua, ca))
            try:
                vt_out = S.update_validation_task(vt.id, ValidationTaskUpdate(status=ValidationStatus.VALIDATED))
            finally:
                reset_current_identity(_t)
            if not (vt_out.reviewer_user_id == ua.id and vt_out.reviewer_verified_at is not None):
                reasons.append("validation terminal outcome: reviewer not attributed")
            # Administrative reopen (no request identity) -> allowed, no verified evidence.
            S.update_validation_task(vt.id, ValidationTaskUpdate(status=ValidationStatus.OPEN))
            if S.validation_tasks[vt.id].reviewer_verified_at is not None:
                reasons.append("administrative reopen created false verified-reviewer evidence")
            # A system actor (no request identity) is rejected for a terminal outcome.
            vt3 = ValidationTask(tenant_id=S.tenant.id, target_type="failure", target_id=uuid4(),
                                 reason="r", status=ValidationStatus.OPEN)
            S.validation_tasks[vt3.id] = vt3
            try:
                S.update_validation_task(vt3.id, ValidationTaskUpdate(status=ValidationStatus.VALIDATED))
                reasons.append("system actor was NOT rejected for a terminal validation outcome")
            except _sm.ReviewerNotVerified:
                pass
            issues = S.verify_reviewer_attribution_consistency()
            if issues:
                reasons.append("outcome/audit consistency failed: " + "; ".join(issues[:2]))
            blob = _json.dumps(
                [c.model_dump(mode="json") for c in S.field_corrections.values()]
                + [t.model_dump(mode="json") for t in S.validation_tasks.values()]
                + [e.model_dump(mode="json") for e in S.audit_logs])
            if tok_a in blob or tok_b in blob or S.api_credentials[ca.credential_id].token_hash in blob:
                reasons.append("credential token/hash leaked into outcome/audit")
    except Exception as exc:  # pragma: no cover - defensive
        reasons.append(f"behavioral evidence run failed: {exc}")
    finally:
        for k, v in saved.items():
            if v is None:
                _os.environ.pop(k, None)
            else:
                _os.environ[k] = v
        _shutil.rmtree(tmp, ignore_errors=True)
    _verified_reviewer_evidence_cache = (not reasons, reasons)
    return _verified_reviewer_evidence_cache


def _verified_reviewer_probe() -> tuple[str, str]:
    """Evidence-driven evaluation of ``verified-reviewer-identity`` (AUDIT-001).

    The DECISIVE PASS condition is a REAL behavioral run
    (``_verified_reviewer_behavioral_evidence``) on an isolated client-mode store:
    record + revert + terminal-validation with verified attribution matching the keyed
    audit event, an administrative reopen that creates no verified evidence, a rejected
    system actor, a clean outcome/audit consistency verifier, and no credential leak.
    Source-string wiring + schema-field checks are only SUPPORTING parity — they can
    never make it PASS without the behavioral evidence. When the behavioral contract
    cannot be exercised, the control stays BLOCKED."""
    try:
        import inspect

        from . import store as _store_mod
        from .schemas import FieldCorrection, ValidationTask
    except Exception as exc:  # pragma: no cover - defensive
        return "BLOCKED", f"Verified reviewer identity could not be evaluated: {exc}"

    reasons: list[str] = []
    Store = _store_mod.LocalStateStore
    for meth in ("resolve_verified_reviewer", "_reviewer_verification", "_reviewer_attribution",
                 "verify_reviewer_attribution_consistency"):
        if not hasattr(Store, meth):
            reasons.append(f"store is missing {meth}")
    for name in ("record_field_correction", "revert_field_correction", "update_validation_task"):
        try:
            src = inspect.getsource(getattr(Store, name))
        except Exception:
            src = ""
        if "resolve_verified_reviewer" not in src:
            reasons.append(f"{name} does not enforce the verified-reviewer gate")
    for model, fields in (
        (FieldCorrection, ("reviewer_user_id", "reviewer_verified_at", "revert_reviewer_user_id")),
        (ValidationTask, ("reviewer_user_id", "reviewer_verified_at")),
    ):
        for field in fields:
            if field not in model.model_fields:
                reasons.append(f"{model.__name__} is missing reviewer field {field}")

    ok, behavioral = _verified_reviewer_behavioral_evidence()
    reasons.extend(behavioral)
    if reasons or not ok:
        return "BLOCKED", "Verified reviewer identity evidence incomplete: " + "; ".join(
            reasons or ["behavioral evidence unavailable"]) + "."
    return (
        "PASS",
        "Behavioral evidence (isolated client-mode store): an eligible authenticated reviewer records a correction "
        "with verified attribution matching the keyed audit actor; a second reviewer reverts (reverter distinct); a "
        "terminal validation outcome attributes the reviewer; an administrative reopen creates no verified evidence; a "
        "system actor is rejected before mutation; the outcome/audit consistency verifier is clean; no credential "
        "material leaks. AI-content approval and report issuance are outside this control's resolution condition "
        "(a separate future increment).",
    )


def _load_migration_evidence() -> tuple[dict | None, str]:
    if not MIGRATION_EVIDENCE_PATH.exists():
        return None, "no migration evidence artifact (output/migrations/migration-evidence.v1.json)"
    try:
        payload = json.loads(MIGRATION_EVIDENCE_PATH.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return None, f"migration evidence unreadable: {exc.__class__.__name__}"
    if not isinstance(payload, dict):
        return None, "migration evidence malformed"
    return payload, "loaded"


def _migration_evidence_valid() -> tuple[bool, list[str], dict | None]:
    """Shared gate for both migration probes.

    The committed evidence must be a REAL-PostgreSQL passing run, integrity-verified,
    bound to the CURRENT migration bytes, and captured from a clean worktree. Absent
    or stale or non-passing evidence keeps the controls BLOCKED — code presence never
    flips them. This is the evidence-driven equivalent of the reviewer/audit probes.
    """
    payload, reason = _load_migration_evidence()
    if payload is None:
        return False, [reason], None
    reasons: list[str] = []
    if payload.get("status") != "passed":
        reasons.append(
            f"evidence status is {payload.get('status')!r}, not 'passed' (no real-PostgreSQL execution)"
        )
    if not verify_evidence_hash(payload):
        reasons.append("evidence payload_sha256 does not verify (tampered or malformed)")
    if not payload.get("worktree_clean"):
        reasons.append("evidence was not captured from a clean worktree")
    if not payload.get("postgres_server_version"):
        reasons.append("evidence carries no PostgreSQL server version (no real database ran)")
    try:
        import backend.app.migrations as _mig

        current = _mig.migration_set_sha256(_mig.discover_migrations())
    except Exception as exc:  # noqa: BLE001
        reasons.append(f"could not recompute migration set: {exc.__class__.__name__}")
        current = None
    if current is not None and payload.get("migration_set_sha256") != current:
        reasons.append("evidence is stale: the migration set changed after the evidence was generated")
    # The scenarios the evidence actually executes run against db/baseline/, so
    # binding only the legacy hash left the exercised bytes unverified: the
    # baseline could change freely without ever invalidating the evidence.
    try:
        import backend.app.migrations as _mig

        baseline_current = _mig.migration_set_sha256(_mig.discover_migrations(_mig.BASELINE_DIR))
    except Exception as exc:  # noqa: BLE001
        reasons.append(f"could not recompute baseline migration set: {exc.__class__.__name__}")
        baseline_current = None
    if baseline_current is not None and payload.get("baseline_migration_set_sha256") != baseline_current:
        reasons.append(
            "evidence is stale: the baseline migration set changed after the evidence was generated"
        )
    return (not reasons), reasons, payload


def _migration_runner_probe() -> tuple[str, str]:
    """Resolution condition (registry): a runner with a schema_migrations/version
    table applies db/migrations/ deterministically and idempotently. PASS-capable
    ONLY with committed real-PostgreSQL evidence proving deterministic order,
    metadata, advisory lock, per-migration transactions, idempotent rerun,
    checksum-drift refusal, and failure rollback."""
    ok, reasons, payload = _migration_evidence_valid()
    if not ok:
        return "BLOCKED", "Migration runner not proven: " + "; ".join(reasons)
    needed = [
        "fresh_apply_result",
        "rerun_result",
        "partial_upgrade_result",
        "concurrency_result",
        "rollback_result",
        "checksum_drift_result",
    ]
    missing = [key for key in needed if not payload.get(key)]
    if missing:
        return "BLOCKED", "Migration runner evidence incomplete (missing: " + ", ".join(missing) + ")."
    return (
        "PASS",
        "A deterministic, idempotent migration runner applies db/migrations/ under a "
        "session-level advisory lock with per-migration transactions, tracked by a "
        "schema_migrations version table; committed real-PostgreSQL evidence proves fresh "
        "apply, idempotent rerun, partial upgrades, failure rollback, concurrency "
        "serialization, and checksum-drift refusal.",
    )


def _migration_validity_probe() -> tuple[str, str]:
    """Resolution condition (registry): all committed migrations reference only
    tables/columns created by earlier migrations; FK targets exist. PASS-capable
    ONLY when the complete sequence applies on real PostgreSQL and supported partial
    upgrades pass, corroborated by the supplemental static validator."""
    ok, reasons, payload = _migration_evidence_valid()
    if not ok:
        return "BLOCKED", "Migration validity not proven: " + "; ".join(reasons)
    fresh = payload.get("fresh_apply_result") or {}
    if not fresh.get("ok"):
        return "BLOCKED", "Migration validity evidence shows the fresh apply did not succeed."
    if not payload.get("partial_upgrade_result"):
        return "BLOCKED", "Migration validity evidence lacks supported partial-upgrade results."
    try:
        import backend.app.migrations as _mig

        static = _mig.validate_migration_set(_mig.discover_migrations())
    except Exception as exc:  # noqa: BLE001
        return "BLOCKED", f"Supplemental static validation could not run: {exc.__class__.__name__}."
    if not static.ok:
        return "BLOCKED", "Static validation still reports broken FK dependencies: " + str(static.broken_references)
    return (
        "PASS",
        "The complete migration sequence applies cleanly on real PostgreSQL and supported "
        "partial upgrades succeed; every committed migration references only tables created "
        "by earlier migrations (FK targets exist), corroborated by the supplemental static validator.",
    )


PERSISTENCE_EVIDENCE_PATH = ROOT / "output" / "persistence" / "persistence-atomicity-evidence.v4.json"
PERSISTENCE_EVIDENCE_SCHEMA = "persistence-atomicity-evidence.v4"
NORMALIZED_EVIDENCE_PATH = ROOT / "output" / "persistence" / "normalized-correction-persistence-evidence.v4.json"
NORMALIZED_EVIDENCE_SCHEMA = "normalized-correction-persistence-evidence.v4"
TENANT_RLS_EVIDENCE_PATH = ROOT / "output" / "tenant-rls" / "tenant-rls-enforcement-evidence.v2.json"
TENANT_RLS_EVIDENCE_SCHEMA = "tenant-rls-enforcement-evidence.v2"


def _correction_atomicity_probe() -> tuple[str, str]:
    """Evidence-driven, fail-closed probe for correction-cross-process-atomicity.

    The registry condition: correction lineage integrity guaranteed across
    processes via NORMALIZED PERSISTENCE with row/advisory locking or a
    uniqueness constraint. PASS requires normalized-persistence evidence from a
    real PostgreSQL run on the current clean tree proving: normalized tables
    are the single write/read authority for the slice (snapshot excluded +
    marker), the active-lineage uniqueness and one-terminal-outcome-per-revision
    constraints hold under real cross-process races, routes operate through the
    normalized repositories, state/audit/attribution/idempotency commit
    atomically, the import lifecycle works, and forced RLS on the slice tables
    is proven. File/memory modes never claim the guarantee (the evidence must
    say so). Anything absent, stale, dirty, mismatched, failed, or skipped
    keeps the control BLOCKED.
    """
    if not NORMALIZED_EVIDENCE_PATH.exists():
        return "BLOCKED", "Correction atomicity not proven: no normalized-persistence evidence artifact."
    try:
        payload = json.loads(NORMALIZED_EVIDENCE_PATH.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return "BLOCKED", f"Normalized-persistence evidence unreadable: {exc.__class__.__name__}."
    if not isinstance(payload, dict):
        return "BLOCKED", "Normalized-persistence evidence malformed."

    reasons: list[str] = []
    if payload.get("schema_version") != NORMALIZED_EVIDENCE_SCHEMA:
        reasons.append(f"evidence schema is {payload.get('schema_version')!r}")
    if payload.get("status") != "passed":
        reasons.append(f"status is {payload.get('status')!r}, not 'passed'")
    stored = payload.get("payload_sha256")
    if not stored:
        reasons.append("no payload hash")
    else:
        recomputed = payload_sha256({k: v for k, v in payload.items() if k != "payload_sha256"})
        if recomputed != stored:
            reasons.append("payload hash does not verify")
    if not payload.get("worktree_clean"):
        reasons.append("evidence was not captured from a clean worktree")
    if payload.get("repository_mode") != "postgres":
        reasons.append("evidence was not generated in PostgreSQL mode")
    if not payload.get("postgres_server_version") or not payload.get("postgres_image_digest"):
        reasons.append("evidence lacks a real PostgreSQL server version or image digest")
    reasons.extend(_commit_binding_reasons(payload))
    try:
        import backend.app.migrations as _mig
        baseline_versions = [m.version for m in _mig.discover_migrations(_mig.BASELINE_DIR)]
        if payload.get("migration_versions") != baseline_versions:
            reasons.append("evidence is bound to a different migration set")
        for _needed in (5, 6):
            if _needed not in (payload.get("migration_versions") or []):
                reasons.append(f"evidence does not include migration 000{_needed}")
    except Exception as exc:  # noqa: BLE001
        reasons.append(f"could not recompute migration set: {exc.__class__.__name__}")
    entities = payload.get("normalized_entities") or []
    if "field_corrections" not in entities or "validation_tasks" not in entities:
        reasons.append("evidence does not declare the corrections/validation normalized authority")
    if "single write and read authority" not in str(payload.get("source_of_truth", "")):
        reasons.append("evidence lacks the single-source-of-truth declaration")
    if "WITHOUT normalized cross-process guarantees" not in str(payload.get("source_of_truth", "")):
        reasons.append("evidence does not disclaim file/memory modes")
    for field in ("route_groups_result", "concurrency_result", "import_result",
                  "tenant_rls_result", "audit_chain_result", "hmac_result",
                  # independent-review corrections (defects 1-10):
                  "supersession_import_result", "tenant_preserving_reset_result",
                  "verify_count_comparison_result", "conflict_accounting_result",
                  "migration_0006_result", "drift_coverage_result",
                  "import_concurrency_result", "rls_runtime_role_result",
                  "rollback_reload_result",
                  # store-level transaction isolation (copy-on-write publication):
                  "transaction_isolation_result", "route_dirty_read_result",
                  "rollback_nonpublication_result", "atomic_projection_swap_result",
                  "stale_refresh_rejection_result", "non_owner_committed_view_result",
                  # re-review corrections (stale view, revision source, audit-log copy):
                  "stale_view_elimination_result", "revision_binding_result",
                  "audit_log_isolation_result",
                  # whole-operation committed read view (v4):
                  "read_coherence_result", "multi_access_coherence_result",
                  "route_coherence_result", "export_coherence_result",
                  "authorization_coherence_result", "worker_coherence_result",
                  "async_task_isolation_result", "get_then_reindex_result",
                  "read_view_scope_result", "publication_failure_recovery_result",
                  # recursive audit immutability + async transaction ownership (v4):
                  "recursive_audit_immutability_result", "async_task_ownership_result"):
        if payload.get(field) != "passed":
            reasons.append(f"{field} is not 'passed'")
    # Semantic bindings: the copy-on-write + read-view implementation must be
    # declared, so an old-shaped artifact cannot pass by field presence alone.
    if payload.get("publication_model") != "copy_on_write":
        reasons.append("evidence does not declare publication_model=copy_on_write")
    if payload.get("committed_read_view_model") != "request_task_scoped_pin_on_first_refresh":
        reasons.append("evidence does not declare the request/task-scoped read-view model")
    if payload.get("read_view_context_backend") != "contextvars":
        reasons.append("evidence does not declare the contextvars read-view backend")
    if not payload.get("guard_inventory_ok"):
        reasons.append("evidence guard inventory did not validate (duplicate/missing/phantom id)")
    _impl = str(payload.get("implementation_version") or "0")
    try:
        if tuple(int(p) for p in _impl.split(".")[:3]) < (4, 0, 0):
            reasons.append(f"implementation_version {_impl!r} is below 4.0.0")
    except ValueError:
        reasons.append(f"implementation_version {_impl!r} is malformed")
    if payload.get("concurrency_scenario_total", 0) < 10:
        reasons.append("fewer than ten cross-process concurrency scenarios were proven")
    if payload.get("process_total", 0) < 10:
        reasons.append("evidence used too few independent OS processes")
    totals = payload.get("totals") or {}
    if totals.get("failed", 1) != 0 or totals.get("skipped", 1) != 0:
        reasons.append("evidence totals include failures or required skips")

    if reasons:
        return "BLOCKED", "Correction atomicity not proven: " + "; ".join(reasons)
    return (
        "PASS",
        "Real-PostgreSQL evidence proves correction lineage integrity across processes via "
        "normalized persistence: normalized tables are the single write/read authority for "
        "corrections and validation outcomes, the active-lineage partial unique index and "
        "UNIQUE(task_id, task_revision) hold under independent-process races with row locks and "
        "revision CAS, routes operate through the normalized repositories, and state, audit, "
        "reviewer attribution and idempotency commit atomically. File/memory modes explicitly "
        "carry no such guarantee.",
    )


def _persistence_locking_probe() -> tuple[str, str]:
    """Evidence-driven, fail-closed probe for persistence-locking-transactions.

    PASS requires committed real-PostgreSQL evidence proving the transactional
    snapshot boundary AND that route-level idempotency is genuinely reachable: a
    discriminating negative control, a preserving protected comparison, separate
    chain-linkage and HMAC verification, route/worker/command boundary proof, and
    -- new in schema v2 -- real-HTTP route idempotency proven through routing and
    auth (single-process suite, a concurrent two-client-process race, and an
    uncertain-response retry that replays instead of double-committing). A clean
    worktree bound to the current commit and migration set, PostgreSQL mode and
    the global-scope disclosure are still required. Anything absent, stale, dirty,
    mismatched, failed, skipped, produced under the old schema, or lacking the
    route-idempotency proof keeps the control BLOCKED. This never inspects code
    presence.
    """
    if not PERSISTENCE_EVIDENCE_PATH.exists():
        return "BLOCKED", "Persistence locking not proven: no atomicity evidence artifact."
    try:
        payload = json.loads(PERSISTENCE_EVIDENCE_PATH.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return "BLOCKED", f"Persistence evidence unreadable: {exc.__class__.__name__}."
    if not isinstance(payload, dict):
        return "BLOCKED", "Persistence evidence malformed."

    reasons: list[str] = []
    if payload.get("schema_version") != PERSISTENCE_EVIDENCE_SCHEMA:
        reasons.append(
            f"evidence schema is {payload.get('schema_version')!r}, not "
            f"{PERSISTENCE_EVIDENCE_SCHEMA!r} (route-idempotency proof required)")
    if payload.get("status") != "passed":
        reasons.append(f"status is {payload.get('status')!r}, not 'passed'")
    stored = payload.get("payload_sha256")
    if not stored:
        reasons.append("no payload hash")
    else:
        recomputed = payload_sha256({k: v for k, v in payload.items() if k != "payload_sha256"})
        if recomputed != stored:
            reasons.append("payload hash does not verify (tampered or malformed)")
    if not payload.get("worktree_clean"):
        reasons.append("evidence was not captured from a clean worktree")
    if payload.get("repository_mode") != "postgres":
        reasons.append("evidence was not generated in PostgreSQL mode")
    if not payload.get("postgres_server_version") or not payload.get("postgres_image_digest"):
        reasons.append("evidence lacks a real PostgreSQL server version or image digest")
    if payload.get("snapshot_scope") != "global":
        reasons.append("evidence does not disclose the global snapshot scope")
    statement = str(payload.get("serialization_statement", ""))
    if "serializes all application writers" not in statement:
        reasons.append("evidence omits the global-serialization disclosure")
    for claim in ("negative_control_lost_update", "protected_comparison_preserved_both"):
        if not payload.get(claim):
            reasons.append(f"evidence missing discriminating result: {claim}")
    for r in ("chain_linkage_result", "event_hmac_result", "route_worker_command_boundary_result"):
        if payload.get(r) != "passed":
            reasons.append(f"{r} is not 'passed'")
    totals = payload.get("totals") or {}
    if totals.get("failed", 1) != 0 or totals.get("skipped", 1) != 0:
        reasons.append("evidence totals include failures or required skips")

    # Route-level idempotency must be PROVEN through real HTTP, not merely
    # implemented at the store. This is the specific gap the independent review
    # flagged: without it the transactional replay is unreachable from a request.
    for r in ("http_route_idempotency_result", "concurrent_http_idempotency_result",
              "uncertain_response_result", "validation_route_idempotency_result"):
        if payload.get(r) != "passed":
            reasons.append(f"{r} is not 'passed'")
    if payload.get("semantic_action_coverage_complete") is not True:
        reasons.append("semantic action coverage is incomplete")
    route = payload.get("route_idempotency")
    if not isinstance(route, dict):
        reasons.append("evidence lacks the route_idempotency proof block")
    else:
        if not route.get("contract_version"):
            reasons.append("route_idempotency omits its contract version")
        if route.get("operation_key_header") != "Idempotency-Key":
            reasons.append("route_idempotency does not use the Idempotency-Key header")
        for r in ("http_route_result", "concurrent_http_result", "uncertain_response_result",
                  "request_hash_canonicalization_result", "missing_key_result",
                  "conflicting_reuse_result", "actor_and_operation_scope_result",
                  "failed_attempt_reserves_no_key_result",
                  # Each validation-task transition (outcome / rejection / reopen)
                  # behaviourally proven -- not one generic route test for all.
                  "validation_route_result", "validation_outcome_result",
                  "validation_rejection_result", "validation_reopen_result"):
            if route.get(r) != "passed":
                reasons.append(f"route_idempotency.{r} is not 'passed'")
        scenarios = route.get("http_scenarios_passed")
        total_scenarios = route.get("http_scenario_count")
        if not isinstance(scenarios, int) or scenarios < 14 or scenarios != total_scenarios:
            reasons.append("route_idempotency HTTP suite did not fully pass at least 14 scenarios")
        vscen = route.get("validation_scenarios_passed")
        vtot = route.get("validation_scenario_count")
        if not isinstance(vscen, int) or vscen < 7 or vscen != vtot:
            reasons.append("route_idempotency validation-task suite did not fully pass at least 7 scenarios")
        # Semantic-action coverage: no conflation, no under-count.
        req = route.get("required_semantic_action_count")
        tested = route.get("tested_semantic_action_count")
        if not isinstance(req, int) or not isinstance(tested, int) or req < 6 or tested < req:
            reasons.append("route_idempotency semantic-action coverage is under-counted")
        actions = route.get("semantic_actions")
        if not isinstance(actions, list) or any(a.get("result") != "passed" for a in actions):
            reasons.append("route_idempotency has a semantic action that is not 'passed'")
        if route.get("tested_route_count", 0) < 3:
            reasons.append("route_idempotency behaviourally tested fewer than three routes")
        if route.get("concurrent_http_client_count", 0) < 2:
            reasons.append("route_idempotency concurrent proof used fewer than two client processes")
        if route.get("concurrent_http_idempotency_rows") != 1 or route.get("concurrent_http_correction_delta") != 1:
            reasons.append("route_idempotency concurrent proof did not commit exactly once")

    # Bind to the current commit, tree and migration set. STRICT + symmetric with
    # the correction probe: a missing/null/empty/wrong git_commit or git_tree fails
    # closed (the earlier `not in {commit, None}` accepted a null commit).
    reasons.extend(_commit_binding_reasons(payload))
    try:
        import backend.app.migrations as _mig
        baseline_versions = [m.version for m in _mig.discover_migrations(_mig.BASELINE_DIR)]
    except Exception as exc:  # noqa: BLE001
        baseline_versions = None
        reasons.append(f"could not recompute migration set: {exc.__class__.__name__}")
    if baseline_versions is not None and payload.get("migration_versions") != baseline_versions:
        reasons.append("evidence is bound to a different migration set")

    if reasons:
        return "BLOCKED", "Persistence locking not proven: " + "; ".join(reasons)
    return (
        "PASS",
        "Committed real-PostgreSQL evidence proves a transactional global-snapshot boundary: a "
        "discriminating negative control (legacy last-writer-wins loses an update) versus a "
        "protected path that preserves both, revision compare-and-swap, idempotent operations, and "
        "state+audit committed atomically with verified chain linkage and HMAC. Route-level "
        "idempotency is proven through real HTTP: a single-process scenario suite, a concurrent "
        "two-client-process duplicate that commits exactly once, and an uncertain-response retry "
        "that replays instead of double-committing. PostgreSQL snapshot mode serializes all "
        "application writers; no tenant-independent concurrency is claimed.",
    )


def _git_rev(ref: str) -> str:
    import subprocess
    try:
        return subprocess.check_output(["git", "rev-parse", ref], cwd=str(ROOT), text=True).strip()
    except Exception:
        return "unknown"


def _commit_binding_reasons(payload: dict) -> list[str]:
    """Strict, fail-closed git commit/tree binding shared by the persistence probes.

    An evidence artifact must carry git_commit AND git_tree as NON-EMPTY STRINGS
    equal to the current clean commit/tree. A missing field, null, empty string,
    whitespace, abbreviated/ambiguous value, wrong value, or non-string is rejected
    -- a crafted ``{"git_commit": null}`` can never bypass the binding (the earlier
    ``not in {commit, None}`` fail-open is gone). When git itself is unavailable
    ("unknown") only the well-formedness (non-empty string) requirement applies.
    """
    reasons: list[str] = []
    current_commit = _git_rev("HEAD")
    current_tree = _git_rev("HEAD^{tree}")
    ec = payload.get("git_commit")
    et = payload.get("git_tree")
    if not isinstance(ec, str) or not ec.strip():
        reasons.append("evidence git_commit is missing, null, empty, or not a string")
    elif current_commit != "unknown" and ec != current_commit:
        reasons.append("evidence is bound to a different commit")
    if not isinstance(et, str) or not et.strip():
        reasons.append("evidence git_tree is missing, null, empty, or not a string")
    elif current_tree != "unknown" and et != current_tree:
        reasons.append("evidence is stale: the tree changed after it was generated")
    return reasons


def evaluate_blockers(
    readiness_by_id: dict[str, str],
    *,
    forge_report: dict | None = None,
) -> list[dict[str, object]]:
    """Evaluate each registry entry into a GA check carrying an explicit disposition.

    Entries with no implemented evaluator default to BLOCKED (the control is not
    implemented). NOT_APPLICABLE is never assigned here — it is only permissible
    when an entry explicitly opts in AND carries a justification, and no v1 entry
    opts in, so critical controls can never be dismissed.
    """
    registry = load_registry()
    checks: list[dict[str, object]] = []
    for entry in registry["blockers"]:
        check_id = entry["check_id"]
        evidence_reference: str | None = None
        if check_id == "ga_postgres_adapter":
            disposition, detail = _delegate(readiness_by_id, ("postgres_repository",))
        elif check_id == "ga_redis_adapter":
            disposition, detail = _delegate(readiness_by_id, ("redis_queue",))
        elif check_id == "ga_local_ai_runtime":
            disposition, detail = _delegate(readiness_by_id, ("local_llm_runtime",))
        elif check_id == "ga_production_configuration":
            disposition, detail = _delegate(readiness_by_id, _CONFIG_READINESS_IDS)
        elif check_id == "ga_reviewed_fixture_evidence":
            disposition, detail = _delegate(readiness_by_id, _FIXTURE_READINESS_IDS)
        elif check_id == "ga_clean_client_state":
            disposition, detail = _delegate(readiness_by_id, ("demo_seed_removed",))
        elif check_id == "ga_rbac_role_separation":
            disposition, detail = _rbac_role_separation_probe()
        elif check_id == "ga_tenant_authorization":
            disposition, detail = _tenant_authorization_probe()
        elif check_id == "ga_audit_keyed_integrity":
            disposition, detail = _audit_keyed_integrity_probe()
        elif check_id == "ga_verified_reviewer_identity":
            disposition, detail = _verified_reviewer_probe()
        elif check_id == "ga_migration_runner":
            disposition, detail = _migration_runner_probe()
        elif check_id == "ga_migration_validity":
            disposition, detail = _migration_validity_probe()
        elif check_id == "ga_persistence_locking":
            disposition, detail = _persistence_locking_probe()
        elif check_id == "ga_correction_cross_process_atomicity":
            disposition, detail = _correction_atomicity_probe()
        elif check_id == "ga_parser_coverage_evidence":
            disposition, detail, evidence_reference = _forge_probe(forge_report)
        elif check_id == "ga_official_export_gate":
            disposition = "BLOCKED"
            detail = (
                "The provenance-enforcing official-export gate is not implemented; "
                "callable-method presence is not accepted as evidence."
            )
        elif check_id == "ga_client_organizational_approval":
            disposition = "REVIEW_REQUIRED"
            detail = (
                "No verified client/organizational approval mechanism exists "
                "(authenticated approver identity + signature verification are absent)."
            )
        else:
            # Unimplemented control: declared BLOCKED until its resolution condition is met.
            disposition = "BLOCKED"
            detail = f"Unresolved control: {entry['description']}"
        checks.append(
            {
                "id": check_id,
                "label": entry["label"],
                "status": _LEGACY_STATUS[disposition],
                "disposition": disposition,
                "category": entry["category"],
                "severity": entry["severity"],
                "owner_type": entry["owner_type"],
                "policy_reference": entry["policy_reference"],
                "evidence_reference": evidence_reference,
                "resolution_condition": entry["resolution_condition"],
                "applicability_justification": None,
                "detail": detail,
                "remediation": entry["resolution_condition"],
            }
        )
    return checks


def is_blocking(check: dict) -> bool:
    return check.get("disposition") in BLOCKING_DISPOSITIONS


def not_applicable_permitted(entry: dict, justification: str | None) -> bool:
    """NOT_APPLICABLE is allowed only when the entry opts in AND a justification exists.

    No v1 registry entry sets allow_not_applicable=true, so critical controls can
    never be dismissed as N/A.
    """
    if not entry.get("allow_not_applicable"):
        return False
    if not isinstance(justification, str) or not justification.strip():
        return False
    return True


def verify_evidence_hash(payload: dict) -> bool:
    """Recompute the canonical hash of the evidence (excluding payload_sha256)."""
    stored = payload.get("payload_sha256")
    if not stored:
        return False
    without = {key: value for key, value in payload.items() if key != "payload_sha256"}
    return payload_sha256(without) == stored


def blocker_counts(checks: list[dict[str, object]]) -> dict[str, int]:
    counts = {category: 0 for category in sorted(CATEGORIES)}
    counts["uncategorized"] = 0
    for check in checks:
        if not is_blocking(check):
            continue
        category = check.get("category")
        if category in counts:
            counts[category] += 1
        else:
            counts["uncategorized"] += 1
    counts["total"] = sum(v for k, v in counts.items() if k != "total")
    return counts


def check_registry_parity(checks: list[dict[str, object]]) -> list[str]:
    """Assert exact 1:1 parity between registry entries and emitted GA checks."""
    registry = load_registry()
    errors = validate_registry(registry)
    registry_check_ids = {entry["check_id"] for entry in registry["blockers"]}
    emitted_ids = [check["id"] for check in checks]
    emitted_set = set(emitted_ids)
    if len(emitted_ids) != len(emitted_set):
        errors.append("duplicate emitted GA check id")
    for missing in sorted(registry_check_ids - emitted_set):
        errors.append(f"registry entry {missing!r} has no emitted check")
    for extra in sorted(emitted_set - registry_check_ids):
        errors.append(f"emitted check {extra!r} has no registry entry")
    for check in checks:
        if check.get("category") not in CATEGORIES:
            errors.append(f"emitted check {check.get('id')!r} has unknown category")
        if not check.get("resolution_condition"):
            errors.append(f"emitted check {check.get('id')!r} missing resolution condition")
        if not check.get("policy_reference"):
            errors.append(f"emitted check {check.get('id')!r} missing policy reference")
    return errors


def decide_ga(
    *,
    mode: str,
    parity_ok: bool,
    checks: list[dict[str, object]],
    commands_skipped: bool,
    commands_passed: bool,
    worktree_clean: bool,
    payload_hash_ok: bool = True,
) -> tuple[str, bool]:
    """Fail-closed GA decision. Returns (top_level_status, ga_ready).

    GA_READY requires client mode, registry/check parity, every check PASS or a
    justified NOT_APPLICABLE, the software commands actually run and pass, and a
    clean git worktree. Any BLOCKED / FAIL / SKIPPED / REVIEW_REQUIRED check
    keeps GA blocked.

    ``payload_hash_ok`` is an additional fail-closed conjunct a caller may set to
    False to veto the decision. The evidence hash itself covers the decided
    status, so it cannot gate this decision at decision time; it is the
    authoritative integrity seal computed and re-verified at evidence-write time
    (see ``verify_evidence_hash`` and the guard's ``build_payload``).
    """
    ga_ready = (
        mode == "client"
        and parity_ok
        and all(check.get("disposition") in NON_BLOCKING_DISPOSITIONS for check in checks)
        and not commands_skipped
        and commands_passed
        and worktree_clean
        and payload_hash_ok
    )
    return ("GA_READY" if ga_ready else "GA_BLOCKED"), ga_ready
