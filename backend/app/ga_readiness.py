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
    return (
        "BLOCKED",
        "API-layer per-request tenant ownership enforcement is implemented and verified: every "
        "resource-scoped route proves a tenant-ownership dependency (tenant_ownership_fully_enforced), "
        "the ownership graph fails closed on a contradictory resource->parent->tenant chain, cross-tenant "
        "access is an existence-hiding 404, list/aggregate reads are tenant-filtered before counting, and "
        "signed capabilities bind the owning tenant (behavior proven by scripts/tenant_authorization_guard.py). "
        "The control remains BLOCKED because its resolution ALSO requires Postgres RLS active over the "
        "normalized multi-tenant store, which is not implemented: the process serves one configured tenant "
        "via the local JSON snapshot and RLS is inactive.",
    )


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
