from __future__ import annotations

import json
import os
import re
from pathlib import Path
from statistics import mean
from typing import Literal
from uuid import UUID

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from .auth import API_KEY_HEADER, api_key_configured, api_key_valid
from .identity import (
    get_current_identity,
    get_request_context,
    reset_current_identity,
    reset_request_context,
    set_current_identity,
    set_request_context,
)
from .permissions import ALL_PERMISSIONS
from .limits import max_upload_bytes, upload_too_large
from .local_ai import evaluate_local_ai_status
from .ai import (
    DETERMINISTIC_PROVIDER,
    GroundedContext,
    dedupe_citations,
    resolve_ai_provider,
    validate_citations,
)
from .ai.online_egress import online_test_connection
from . import online_ai_settings
from .retention import retention_days
from .schemas import (
    ActivitySegment,
    AuditIntegrityStatus,
    AuditLog,
    AnomalyEvent,
    AuthenticatedIdentity,
    CredentialAdminView,
    CredentialCreateResponse,
    Role,
    StoredApiCredential,
    UserAdminView,
    UserCreateRequest,
    BenchmarkConfigResponse,
    BenchmarkMeasurementCreate,
    BenchmarkValue,
    BenchmarkValueUpdate,
    BenchmarkingStatus,
    CasingString,
    ChatRequest,
    ChatResponse,
    ClientDataReadiness,
    DiagnosticDismissRequest,
    DashboardSummary,
    DocumentChunk,
    FailureRecord,
    FieldCorrection,
    FieldCorrectionCreate,
    FieldCorrectionRevert,
    HydraulicObservation,
    LocalAIStatus,
    OnlineAiConfigView,
    OnlineAiSettingsRequest,
    OnlineTestConnectionResult,
    ProviderStatusView,
    MondayReport,
    MondayReportCreate,
    ParsedDocument,
    ProcessingJob,
    ProcessingStatus,
    ReportDraftResponse,
    ReportExport,
    RetentionRunResult,
    RuntimeBackendStatus,
    SessionResponse,
    SignedUrlResponse,
    SurveyStation,
    UploadCompleteRequest,
    UploadCreate,
    UploadCreateResponse,
    UploadFileRecord,
    ValidationTask,
    ValidationTaskUpdate,
    Workspace,
    WorkspaceCreate,
)
from .corrections_registry import (
    CorrectionValidationError,
    correctable_field_catalog,
    validate_correction,
)
from . import idempotency
from .readiness import client_data_mode, evaluate_client_data_readiness
from .verification_boundary import verification_context, verification_run_fingerprint
from .runtime_backends import runtime_backend_status
from .signed_urls import create_signed_token, signing_secret_configured, verify_signed_token
from .store import store, IdempotencyConflict, ReviewerNotVerified, SnapshotConflict
from .audit_keys import AuditIntegrityUnavailable, audit_key_provider
from .tenant_authorization import owned_via_graph, owns, request_tenant_id

app = FastAPI(
    title="Monday Report API",
    version="0.1.0",
    description="Local-AI-first API scaffold for rig-report intelligence.",
)

# Local dev convenience origins. Used ONLY when no explicit allowlist is
# configured AND the deployment is not in protected client mode.
_CORS_DEV_DEFAULT_ORIGINS = ("http://127.0.0.1:5173", "http://localhost:5173")


def cors_allowed_origins() -> list[str]:
    """Resolve the browser CORS allowlist as an EXPLICIT list (never a wildcard).

    Contract:
    - ``MONDAY_REPORT_CORS_ORIGINS`` (comma-separated) is the single lever. When
      set, its exact origins are the allowlist in EVERY mode -- no implicit dev
      origin is appended, so an isolated deployment can allow only its own
      frontend origin and nothing else.
    - When it is unset/blank:
        * demo/local mode falls back to the localhost:5173 dev origins for
          convenience;
        * protected client mode FAILS CLOSED with an empty list -- no browser
          origin is trusted until one is configured. It never silently permits
          :5173 and never widens to ``*`` (a credentialed wildcard is invalid
          anyway).
    """
    configured = [
        origin.strip()
        for origin in os.getenv("MONDAY_REPORT_CORS_ORIGINS", "").split(",")
        # A wildcard is never a valid explicit origin: with credentialed CORS a
        # configured "*" would make Starlette reflect ANY requesting origin.
        # Dropping such entries keeps the promise above enforced, not aspirational
        # -- and in client mode a lone "*" therefore resolves to the fail-closed
        # empty allowlist rather than to everyone.
        if origin.strip() and "*" not in origin
    ]
    if configured:
        return configured
    if client_data_mode() == "client":
        return []
    return list(_CORS_DEV_DEFAULT_ORIGINS)


app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(AuditIntegrityUnavailable)
async def _audit_integrity_unavailable_handler(request: Request, exc: AuditIntegrityUnavailable) -> JSONResponse:
    # A protected mutation could not seal its audit event because the active HMAC
    # key is unavailable (client mode). audit() fails BEFORE append/save, so nothing
    # was persisted. Return a stable service-unavailable error.
    return JSONResponse(status_code=503, content={"detail": "Audit integrity key is unavailable"})


@app.exception_handler(ReviewerNotVerified)
async def _reviewer_not_verified_handler(request: Request, exc: ReviewerNotVerified) -> JSONResponse:
    # A reviewer-controlled outcome (field correction / validation) was attempted in
    # client mode by a non-verified actor. The store fails closed BEFORE any outcome
    # mutation or audit append. Return a stable authorization error; no reviewer
    # detail is leaked.
    return JSONResponse(status_code=403, content={"detail": "Verified reviewer required"})


@app.exception_handler(idempotency.IdempotencyKeyError)
async def _idempotency_key_error_handler(request: Request, exc: idempotency.IdempotencyKeyError) -> JSONResponse:
    # A mutating route required an Idempotency-Key that was absent or malformed.
    # The context is never published, so no mutation runs. The message describes the
    # header contract only; it carries no request, actor or data detail.
    return JSONResponse(status_code=400, content={"detail": exc.message})


@app.exception_handler(IdempotencyConflict)
async def _idempotency_conflict_handler(request: Request, exc: IdempotencyConflict) -> JSONResponse:
    # An operation key was reused for a materially different request (different
    # request body, operation kind, or actor). This is a conflict, not a replay:
    # the store refuses to let one caller ride another's committed result. Nothing
    # was mutated. Return a stable 409; leak no stored request or actor detail.
    return JSONResponse(
        status_code=409,
        content={"detail": "Idempotency-Key was already used for a different request"},
    )


@app.exception_handler(SnapshotConflict)
async def _snapshot_conflict_handler(request: Request, exc: SnapshotConflict) -> JSONResponse:
    # A durable mutation lost a compare-and-swap race or timed out on the snapshot
    # lock. Nothing partial was committed (rollback discards both state and audit).
    # Retryable conflicts (lock timeout, serialization) map to 503 and DO invite a
    # retry -- the same request may succeed once contention clears. A definite
    # non-retryable loss (stale revision, idempotency-key conflict) maps to 409 and
    # must NOT invite a retry: replaying the identical request cannot change the
    # outcome, and telling the caller to "please retry" is misleading. Neither
    # message leaks a DSN, driver, role, revision number, SQL, or filesystem path.
    if exc.retryable:
        return JSONResponse(
            status_code=503,
            content={"detail": "Snapshot write conflict; please retry"},
        )
    return JSONResponse(
        status_code=409,
        content={"detail": "Snapshot write conflict"},
    )


def _best_effort_audit(*args, **kwargs) -> None:
    """Write an audit event but never turn an already-rejected auth response into a
    500 if the audit HMAC key is unavailable. Used only on middleware auth-rejection
    paths; it still never writes an unkeyed event in client mode (audit() fails
    closed and this swallows only that failure). On the transactional PostgreSQL
    backend a direct audit runs in its own snapshot transaction; a transient
    snapshot conflict there (lock timeout under contention) is likewise swallowed --
    best-effort means the rejection response wins over the rejection audit."""
    try:
        store.audit(*args, **kwargs)
    except (AuditIntegrityUnavailable, SnapshotConflict):
        pass


# Genuinely public, unauthenticated surfaces. Only minimal liveness is exempt.
# Operational/security reads (runtime backends, local-AI details, audit-integrity)
# and DETAILED client-data readiness are NO LONGER exempt — detailed readiness
# exposes blocker ids, dispositions, remediation, deployment mode, and configured
# paths, so it requires authentication + view_runtime_status. `/health` remains
# the minimal public liveness/load-balancer probe.
CLIENT_AUTH_EXEMPT_PATHS = {
    "/health",
}
# MC1: the ONLY requests that stay available in client mode without a valid active
# audit key. Minimal health/liveness + CORS preflight. Everything else (protected
# reads, mutations, denials, docs, readiness detail, and signed downloads) fails
# closed with a stable 503 before any auth/routing/business/audit.
CLIENT_NO_KEY_PUBLIC_PATHS = {
    "/health",
}
# Interactive API documentation is public in demo/local mode but is disabled
# (404) in client mode unless the request resolves to an administrator.
DOCS_PATHS = {"/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"}


@app.middleware("http")
async def enforce_client_api_key(request: Request, call_next):
    # MC1: in client mode, EVERY non-public request requires a valid active audit
    # key. Without one, fail closed with a stable 503 BEFORE authentication,
    # authorization, routing, or any business/audit attempt — so no denial or legacy
    # audit event is written, no protected data is disclosed, and signed-capability
    # issuance/redemption is blocked. Only the narrow public allow-list (minimal
    # health/liveness + CORS preflight) remains available without a key.
    if (
        client_data_mode() == "client"
        and not _client_no_key_public(request)
        and not store._active_audit_key_available()
    ):
        return JSONResponse(
            status_code=503,
            content={"detail": "Audit integrity key is unavailable"},
        )

    if _client_auth_exempt(request):
        return await call_next(request)

    supplied_key = request.headers.get(API_KEY_HEADER)
    mode = client_data_mode()

    if mode == "client":
        if not api_key_configured():
            _best_effort_audit(
                "api.auth_blocked",
                "api",
                None,
                {"reason": "api_key_not_configured", "path": request.url.path, "method": request.method},
            )
            return JSONResponse(
                status_code=503,
                content={"detail": "Client API key is not configured"},
            )
        # Client mode requires an ACTIVE PERSISTED PER-USER credential. The
        # legacy configured shared key and any bootstrap-only credential are
        # rejected (allow_shared_key_bootstrap=False) — the shared key is NOT a
        # client-mode administrator. Identity is resolved exclusively server-side
        # from the presented credential; client-supplied identity headers are
        # never trusted.
        identity = store.resolve_request_identity(supplied_key, allow_shared_key_bootstrap=False)
        if identity is None:
            _best_effort_audit(
                "api.auth_blocked",
                "api",
                None,
                {"reason": "invalid_or_missing_api_key", "path": request.url.path, "method": request.method},
            )
            return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})
    else:
        # Demo/local mode does not enforce auth, but every request still carries
        # a request-scoped actor: a per-user token if a valid one is presented,
        # otherwise the explicit in-memory demo_bootstrap identity (local
        # compatibility only).
        identity = (
            store.resolve_request_identity(supplied_key, allow_shared_key_bootstrap=True)
            or store.demo_bootstrap_identity()
        )

    # Client-mode interactive docs are hidden from non-administrators.
    if mode == "client" and request.url.path in DOCS_PATHS:
        if identity is None or Role.ADMIN not in identity.roles:
            return JSONResponse(status_code=404, content={"detail": "Not Found"})

    identity_token = set_current_identity(identity)
    context_token = set_request_context(request.method, request.url.path)
    try:
        return await call_next(request)
    finally:
        # Request cleanup: clear the request-scoped identity + context so they
        # never leak to another request or to worker/system operations.
        reset_current_identity(identity_token)
        reset_request_context(context_token)


@app.middleware("http")
async def coherent_read_view(request: Request, call_next):
    # Structural whole-operation read-coherence boundary. Every request runs inside
    # ONE committed read view, so all of its store reads -- identity resolution,
    # authorization/_tenant_owned, domain reads, and response serialization --
    # observe a single committed generation. Registered AFTER enforce_client_api_key
    # so it is the OUTERMOST http middleware and its view is already active when that
    # inner middleware resolves identity. The view pins the freshly refreshed
    # generation on the route's first store.refresh() and clears on request exit
    # (the ContextVar is scoped per asyncio task / per threadpool request copy, so it
    # can never leak to a reused pooled thread). File/memory mode makes this a no-op.
    with store.committed_read_view():
        return await call_next(request)


def _client_auth_exempt(request: Request) -> bool:
    if request.method == "OPTIONS":
        return True
    if request.url.path in CLIENT_AUTH_EXEMPT_PATHS:
        return True
    return request.method == "GET" and request.url.path.startswith("/signed/")


def _client_no_key_public(request: Request) -> bool:
    """Narrow allow-list that remains available in client mode even without a valid
    active audit key: CORS preflight + minimal health/liveness only. Every other
    request — protected reads, mutations, denials, docs, readiness detail, and
    signed-capability issuance/redemption — fails closed with a stable 503 (MC1)."""
    if request.method == "OPTIONS":
        return True
    return request.url.path in CLIENT_NO_KEY_PUBLIC_PATHS


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "monday-report-api"}


@app.get("/auth/session", response_model=SessionResponse)
def session() -> SessionResponse:
    store.refresh()
    identity = get_current_identity()
    # Non-secret identity context only: roles, permissions, authentication
    # source, credential id/fingerprint, account status. Never the token/hash.
    permissions = store.permission_map(identity) if identity is not None else {}
    return SessionResponse(
        tenant=store.tenant,
        user=store.user,
        authenticated_identity=identity,
        permissions=permissions,
    )


@app.get("/readiness/client-data", response_model=ClientDataReadiness)
def client_data_readiness() -> ClientDataReadiness:
    # Detailed readiness (blocker ids, dispositions, remediation, mode) is an
    # operational status surface: authenticated + view_runtime_status only.
    # Minimal public liveness is served by /health.
    require_permission("view_runtime_status")
    return evaluate_client_data_readiness(store)


@app.get("/runtime/backends", response_model=RuntimeBackendStatus)
def runtime_backends() -> RuntimeBackendStatus:
    require_permission("view_runtime_status")
    return runtime_backend_status(evaluate_client_data_readiness(store), store)


@app.get("/local-ai/status", response_model=LocalAIStatus)
def local_ai_status() -> LocalAIStatus:
    require_permission("view_runtime_status")
    store.refresh()
    status = evaluate_local_ai_status(store.tenant.local_llm_policy)
    # active_provider reflects the RESOLVER's decision (config), never mere reachability:
    # "local-model" only when the operator has validly selected the loopback local model.
    return status.model_copy(update={"active_provider": resolve_ai_provider(DETERMINISTIC_PROVIDER).name()})


@app.get("/ai/provider-status", response_model=ProviderStatusView)
def ai_provider_status() -> ProviderStatusView:
    # Chat-role-readable provenance so the Ask surface is honest for EVERY role that can
    # chat (never a false "no external calls" claim): which engine writes answers now.
    require_permission("generate_reports")
    return ProviderStatusView(active_provider=resolve_ai_provider(DETERMINISTIC_PROVIDER).name())


def _endpoint_host(base_url: str) -> str:
    try:
        from urllib.parse import urlsplit

        return (urlsplit(base_url).hostname or "").lower()
    except ValueError:
        return ""


def _online_config_view() -> OnlineAiConfigView:
    settings = online_ai_settings.get_active()
    if settings is None:
        return OnlineAiConfigView(
            configured=False,
            storage_available=online_ai_settings.storage_available(),
            detail="No online AI provider is configured.",
        )
    return OnlineAiConfigView(
        configured=True,
        provider=settings.provider,
        base_url=settings.base_url,
        model=settings.model,
        has_key=bool(settings.api_key),  # never the key itself
        updated_at=settings.updated_at or None,
        storage_available=True,
        detail="An online AI provider is configured.",
    )


@app.get("/online-ai/config", response_model=OnlineAiConfigView)
def online_ai_config() -> OnlineAiConfigView:
    require_permission("view_runtime_status")
    return _online_config_view()


@app.post("/online-ai/config", response_model=OnlineAiConfigView)
def save_online_ai_config(payload: OnlineAiSettingsRequest) -> OnlineAiConfigView:
    require_admin()
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    existing = online_ai_settings.get_active()
    created = existing.created_at if existing is not None else now
    settings = online_ai_settings.OnlineAiSettings(
        provider=payload.provider.strip(),
        base_url=payload.base_url.strip(),
        model=payload.model.strip(),
        api_key=payload.api_key,
        created_at=created,
        updated_at=now,
    )
    try:
        online_ai_settings.save(settings)
    except online_ai_settings.OnlineSettingsUnavailable as exc:
        raise HTTPException(status_code=503, detail="Secure secret storage is unavailable on this system.") from exc
    # Audit with SAFE metadata only — never the API key.
    _best_effort_audit(
        "online_ai.config.updated",
        "tenant",
        store.tenant.id,
        {
            "provider": settings.provider,
            "model": settings.model,
            "endpoint_host": _endpoint_host(settings.base_url),
            "has_key": bool(settings.api_key),
        },
    )
    return _online_config_view()


@app.delete("/online-ai/config", response_model=OnlineAiConfigView)
def delete_online_ai_config() -> OnlineAiConfigView:
    require_admin()
    online_ai_settings.delete()
    _best_effort_audit("online_ai.config.removed", "tenant", store.tenant.id, {"removed": True})
    return _online_config_view()


@app.post("/online-ai/test-connection", response_model=OnlineTestConnectionResult)
def test_online_ai_connection(payload: OnlineAiSettingsRequest) -> OnlineTestConnectionResult:
    require_admin()
    # A fixed one-token probe with NO workspace evidence; returns a status class only.
    status_class, detail = online_test_connection(
        payload.base_url.strip(), payload.model.strip(), payload.api_key
    )
    _best_effort_audit(
        "online_ai.test_connection",
        "tenant",
        store.tenant.id,
        {"endpoint_host": _endpoint_host(payload.base_url), "status": status_class},  # never the key
    )
    return OnlineTestConnectionResult(status=status_class, detail=detail)


def require_client_data_ready(operation: str, resource_type: str, resource_id: UUID | None = None) -> None:
    if client_data_mode() != "client":
        return
    readiness = evaluate_client_data_readiness(store)
    if readiness.ready:
        return
    verification = verification_context()
    if verification["verification_isolation_active"]:
        # Provably-isolated disposable verification stack (see verification_boundary):
        # allow the real client-mode request path to EXECUTE so tenant isolation,
        # authentication, RBAC, verified-reviewer enforcement, forced RLS on the
        # restricted runtime role, and the idempotency contract can be proven.
        # Readiness is NOT certified (readiness.ready stays False) and NO GA control
        # is made to pass -- this only skips the unrelated release-readiness 423
        # lock, only here, only under the full isolation conjunction plus the
        # database-side attestation.
        #
        # A readiness relaxation MUST be durably audited. Use the FAIL-CLOSED audit
        # primitive (never best-effort): if the event cannot be committed -- missing
        # audit key, HMAC failure, snapshot/transaction failure, or a store that
        # cannot durably record it -- do NOT relax the gate.
        try:
            store.audit(
                "client_data.verification_isolation_execution",
                resource_type,
                resource_id,
                {
                    "operation": operation,
                    "readiness_status": readiness.status,
                    # A safe short fingerprint of the run id (never the raw value),
                    # binding this boundary use to the specific verification run.
                    "verification_run": verification_run_fingerprint(),
                    **verification,
                },
            )
        except Exception:  # noqa: BLE001 - any audit failure fails the relaxation closed
            raise HTTPException(status_code=503, detail="Client data readiness checks are failing")
        return
    blocking_checks = [check.id for check in readiness.checks if check.status == "fail"]
    warning_checks = [check.id for check in readiness.checks if check.status == "warn"]
    _best_effort_audit(
        "client_data.operation_blocked",
        resource_type,
        resource_id,
        {
            "operation": operation,
            "readiness_status": readiness.status,
            "blocking_checks": blocking_checks,
            "warning_checks": warning_checks,
        },
    )
    raise HTTPException(status_code=423, detail="Client data readiness checks are failing")


def _establish_idempotency(
    request: Request,
    *,
    operation_kind: str,
    target_ids: dict[str, object],
    body: object,
    optional: bool = False,
) -> object:
    """Publish a request-scoped idempotency context for the mutation about to run.

    MUST be called only AFTER authentication, authorization, resource ownership
    and request validation have all passed, so the operation key binds to a fully
    accepted request and the canonical hash covers validated input only (never raw
    bytes, credentials or timestamps). The persistence layer reads this context
    and threads it into ``snapshot_transaction``.

    The ``Idempotency-Key`` header is required when the active store enforces
    transactional persistence (PostgreSQL); a missing or malformed key then fails
    closed with HTTP 400 *before* any mutation. Under the local demo backend the
    header is honoured when supplied and otherwise omitted, since that backend has
    no commit boundary to replay against.

    ``optional=True`` relaxes the requirement for routes whose creation path is
    ALSO driven by clients that do not send the header (e.g. the report-generation
    UI): a missing key then preserves the pre-idempotency behaviour (the mutation
    runs and creates a new entity) on BOTH backends, while a *supplied* key is
    still validated and made replay-safe. It never weakens a supplied key.

    Returns a reset token (or ``None``). The caller MUST pass it to
    :func:`_reset_idempotency` in a ``finally`` so the context never leaks to
    another request.
    """
    header_values = list(request.headers.getlist(idempotency.HEADER_NAME))
    if not header_values and (optional or not store.request_idempotency_required()):
        return None
    actor = get_current_identity()
    context = idempotency.build_context(
        header_values=header_values,
        operation_kind=operation_kind,
        target_ids=target_ids,
        body=body,
        actor_id=actor.user_id if actor is not None else None,
    )
    return idempotency.set_context(context)


def _reset_idempotency(token: object) -> None:
    if token is not None:
        idempotency.reset_context(token)  # type: ignore[arg-type]


def _active_request_identity() -> AuthenticatedIdentity | None:
    """The resolved request identity if it is present and active, else None.
    Default-deny: a missing or disabled identity yields no permissions."""
    identity = get_current_identity()
    if identity is None or identity.account_status != "active":
        return None
    return identity


def _audit_permission_denied(action: str, permission: str, identity: AuthenticatedIdentity | None) -> None:
    method, path = get_request_context() or (None, None)
    # Best-effort: a permission denial is a REJECTION (no business mutation), so an
    # unavailable audit key must not turn a 403 into a 503 — and no unkeyed event is
    # written. Fail-closed applies to business mutations, not rejection audits.
    _best_effort_audit(
        action,
        "tenant",
        store.tenant.id,
        {
            "permission": permission,
            "method": method,
            "route": path,
            "actor_source": identity.actor_source if identity else None,
            "reason": "no_active_identity" if identity is None else "role_not_permitted",
        },
    )


def require_permission(permission: str) -> None:
    """Default-deny route permission gate driven by the generic permission policy.
    A missing/disabled identity or a role lacking the permission is denied."""
    identity = _active_request_identity()
    if identity is None or not store.has_permission(permission, identity):
        _audit_permission_denied("permission_denied", permission, identity)
        raise HTTPException(status_code=403, detail=f"Missing permission: {permission}")


def require_benchmark_permission(permission: str) -> None:
    # Retained for the Benchmarking routes; delegates to the same generic policy.
    identity = _active_request_identity()
    if identity is None or not store.has_permission(permission, identity):
        _audit_permission_denied("benchmark.permission_denied", permission, identity)
        raise HTTPException(status_code=403, detail=f"Missing permission: {permission}")


# ---------------------------------------------------------------------------
# Per-request tenant + workspace resource-ownership enforcement.
#
# The route permission gate (require_permission / require_benchmark_permission)
# runs FIRST and denies a missing/disabled identity or a role lacking the
# permission (403) before any resource is looked up — so no unauthorized caller
# can distinguish existence. AFTER the permission gate, a resource lookup is
# additionally gated on tenant ownership: a resource that exists but belongs to
# another tenant is treated EXACTLY like a missing resource (existence-hiding
# 404), so a cross-tenant caller can never tell "does not exist" from "exists in
# another tenant". The request tenant is resolved solely from the server-side
# identity; client-supplied tenant input is never trusted (no route accepts one).
# ---------------------------------------------------------------------------
def _request_tenant_id() -> UUID:
    """The request identity's tenant. The route permission gate has already denied
    a missing/disabled identity, so an active tenant is normally present; as
    defense-in-depth an unresolved tenant DENIES (403) — a missing identity must
    never be silently promoted to system/all-tenant access."""
    tenant_id = request_tenant_id()
    if tenant_id is None:
        _audit_permission_denied("tenant_denied", "__tenant__", _active_request_identity())
        raise HTTPException(status_code=403, detail="No tenant context for request")
    return tenant_id


def _audit_cross_tenant_denied(resource_type: str, resource_id: UUID | None) -> None:
    """Record a cross-tenant access denial with the REQUEST tenant context only.
    The foreign owner's tenant is never disclosed in the metadata (no cross-tenant
    detail); only the caller-supplied resource id, resource type, and the request
    method/route are recorded. The audit tenant_id/actor is the request's own."""
    method, path = get_request_context() or (None, None)
    _best_effort_audit(
        "authz.cross_tenant_denied",
        resource_type,
        resource_id,
        {"method": method, "route": path, "reason": "resource_not_in_request_tenant"},
    )


# Resource -> parent collection map for the ownership graph. A resource that
# carries one of these parent links is owned only when the linked parent exists in
# the SAME request tenant (see tenant_authorization.owned_via_graph). This is the
# store-backed resolver; the ownership logic itself lives in the authority module.
_OWNERSHIP_COLLECTIONS = {
    "workspace_id": lambda: store.workspaces,
    "upload_id": lambda: store.uploads,
    "file_id": lambda: store.files,
    "document_id": lambda: store.parsed_documents,
    "report_id": lambda: store.monday_reports,
    "measurement_id": lambda: store.benchmark_measurements,
}


def _resolve_parent(attr: str, parent_id):
    getter = _OWNERSHIP_COLLECTIONS.get(attr)
    return getter().get(parent_id) if getter is not None else None


def _owned(resource, tenant_id) -> bool:
    """Full ownership-graph check: the resource's own tenant_id AND every present
    parent link (workspace/upload/file/document/report/measurement) must resolve to
    the request tenant. A contradictory or broken parent chain fails closed, so a
    record is never accepted just because its direct tenant field happens to match."""
    return owned_via_graph(resource, tenant_id, _resolve_parent)


def _tenant_owned(resource, resource_type: str, resource_id: UUID, detail: str):
    """Return the resource iff it belongs to the request tenant by the full
    ownership graph.

    A missing resource, a cross-tenant resource, OR a resource whose parent chain
    contradicts its direct tenant_id all raise the SAME 404 with the SAME detail
    (existence-hiding). A genuine not-owned hit on an existing resource is audited
    with request-tenant context; a plain missing resource keeps the prior no-audit
    behavior."""
    tenant_id = _request_tenant_id()
    if resource is None:
        raise HTTPException(status_code=404, detail=detail)
    if not _owned(resource, tenant_id):
        _audit_cross_tenant_denied(resource_type, resource_id)
        raise HTTPException(status_code=404, detail=detail)
    return resource


def _tenant_items(items) -> list:
    """Filter a resource iterable to the request tenant by the full ownership graph
    (list/aggregate scoping): each item's own tenant_id AND its parent chain must
    resolve to the request tenant, so a contradictory child is excluded, not just
    a foreign-stamped row."""
    tenant_id = _request_tenant_id()
    return [item for item in items if _owned(item, tenant_id)]


def require_admin() -> AuthenticatedIdentity:
    """Administrator-only gate for identity/credential provisioning."""
    identity = _active_request_identity()
    if identity is None or Role.ADMIN not in identity.roles:
        _best_effort_audit(
            "auth.admin_denied",
            "tenant",
            store.tenant.id,
            {"reason": "no_active_identity" if identity is None else "not_admin"},
        )
        raise HTTPException(status_code=403, detail="Administrator role required")
    return identity


def _user_admin_view(user) -> UserAdminView:
    return UserAdminView(
        id=user.id,
        tenant_id=user.tenant_id,
        email=user.email,
        full_name=user.full_name,
        roles=list(user.roles),
        account_status=user.account_status,
        is_bootstrap=user.is_bootstrap,
    )


def _credential_admin_view(credential: StoredApiCredential) -> CredentialAdminView:
    return CredentialAdminView(
        credential_id=credential.credential_id,
        user_id=credential.user_id,
        tenant_id=credential.tenant_id,
        token_fingerprint=credential.token_fingerprint,
        status=credential.status,
        authentication_source=credential.authentication_source,
        created_at=credential.created_at,
        revoked_at=credential.revoked_at,
        last_used_at=credential.last_used_at,
    )


@app.get("/auth/users", response_model=list[UserAdminView])
def list_users_endpoint() -> list[UserAdminView]:
    require_admin()
    return [_user_admin_view(user) for user in store.list_users()]


@app.post("/auth/users", response_model=UserAdminView, status_code=status.HTTP_201_CREATED)
def create_user_endpoint(payload: UserCreateRequest) -> UserAdminView:
    require_admin()
    try:
        user = store.create_user(payload.email, payload.full_name, payload.roles)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _user_admin_view(user)


@app.post(
    "/auth/users/{user_id}/credentials",
    response_model=CredentialCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_credential_endpoint(user_id: UUID) -> CredentialCreateResponse:
    require_admin()
    try:
        credential, raw_token = store.create_credential(user_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown user")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    # The raw token is returned exactly once here and is never persisted,
    # logged, or audited.
    return CredentialCreateResponse(
        credential_id=credential.credential_id,
        user_id=credential.user_id,
        token_fingerprint=credential.token_fingerprint,
        token=raw_token,
        created_at=credential.created_at,
    )


@app.get("/auth/credentials", response_model=list[CredentialAdminView])
def list_credentials_endpoint() -> list[CredentialAdminView]:
    require_admin()
    return [_credential_admin_view(credential) for credential in store.list_credentials()]


@app.post("/auth/credentials/{credential_id}/revoke", response_model=CredentialAdminView)
def revoke_credential_endpoint(credential_id: UUID) -> CredentialAdminView:
    require_admin()
    try:
        credential = store.revoke_credential(credential_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown credential")
    return _credential_admin_view(credential)


# ---------------------------------------------------------------------------
# Route access inventory (complete route-level RBAC).
#
# Every API route is classified as exactly one of the four approved categories:
#   public              - no API credential (liveness/readiness/framework docs)
#                         or a signed-capability download.
#   authenticated_read  - authenticated, read-only, benign, no granular permission.
#   permission_required - a specific permission gate (enforcement_status
#                         "enforced"; "pending" means a sensitive route that is not
#                         yet enforced and keeps rbac-role-separation blocked).
#   system_internal     - internal/worker-only surface.
# Sensitive mutations may only be permission_required or system_internal. Each
# row also records an `auth_mechanism` (none | api_credential | signed_capability
# | internal_process) — this is metadata, not a fifth category.
# ---------------------------------------------------------------------------
ROUTE_ACCESS_CLASSIFICATIONS = {
    "public",
    "authenticated_read",
    "permission_required",
    "system_internal",
}
ROUTE_ENFORCEMENT_STATUSES = {"enforced", "pending"}
AUTH_MECHANISMS = {"none", "api_credential", "signed_capability", "internal_process"}
ADMIN_PERMISSION = "__admin__"
# The generic permission policy is the source of truth for known permissions.
KNOWN_PERMISSIONS = set(ALL_PERMISSIONS)


def _public(mechanism: str = "none") -> dict[str, str]:
    return {"classification": "public", "auth_mechanism": mechanism}


def _authenticated_read() -> dict[str, str]:
    return {"classification": "authenticated_read", "auth_mechanism": "api_credential"}


def _enforced(permission: str) -> dict[str, str]:
    return {
        "classification": "permission_required",
        "permission": permission,
        "enforcement_status": "enforced",
        "auth_mechanism": "api_credential",
    }


ROUTE_ACCESS_POLICY: dict[tuple[str, str], dict[str, str]] = {
    # --- public: minimal liveness and framework docs (docs are additionally
    #     hidden from non-admins in client mode by the middleware) ---
    ("GET", "/health"): _public(),
    ("GET", "/docs"): _public(),
    ("GET", "/docs/oauth2-redirect"): _public(),
    ("GET", "/openapi.json"): _public(),
    ("GET", "/redoc"): _public(),
    # --- public: signed-capability downloads (gated by an expiring, resource-bound
    #     signed token, verified in the handler; see docs/ROUTE_RBAC.md) ---
    ("GET", "/signed/report-exports/{export_id}"): _public("signed_capability"),
    ("GET", "/signed/upload-files/{file_id}"): _public("signed_capability"),
    # --- authenticated_read: benign authenticated reads (no granular permission) ---
    ("GET", "/auth/session"): _authenticated_read(),
    ("GET", "/field-corrections/registry"): _authenticated_read(),
    # --- permission_required / enforced: operational & security reads ---
    ("GET", "/readiness/client-data"): _enforced("view_runtime_status"),
    ("GET", "/runtime/backends"): _enforced("view_runtime_status"),
    ("GET", "/local-ai/status"): _enforced("view_runtime_status"),
    # Chat-role-readable provenance; operator-gated online config read + admin-gated writes.
    ("GET", "/ai/provider-status"): _enforced("generate_reports"),
    ("GET", "/online-ai/config"): _enforced("view_runtime_status"),
    ("POST", "/online-ai/config"): _enforced(ADMIN_PERMISSION),
    ("DELETE", "/online-ai/config"): _enforced(ADMIN_PERMISSION),
    ("POST", "/online-ai/test-connection"): _enforced(ADMIN_PERMISSION),
    ("GET", "/audit-logs"): _enforced("view_audit_history"),
    ("GET", "/audit-logs/integrity"): _enforced("view_audit_history"),
    # --- permission_required / enforced: workspace/source/report reads ---
    ("GET", "/workspaces"): _enforced("view_workspaces"),
    ("GET", "/documents"): _enforced("view_source_documents"),
    ("GET", "/documents/{document_id}/chunks"): _enforced("view_source_documents"),
    ("GET", "/failures"): _enforced("view_source_documents"),
    ("GET", "/uploads/{upload_id}/files"): _enforced("view_source_documents"),
    ("GET", "/processing-jobs"): _enforced("view_processing_status"),
    ("GET", "/validation-tasks"): _enforced("view_validation_queue"),
    ("GET", "/monday-reports"): _enforced("view_reports"),
    ("GET", "/dashboards/summary"): _enforced("view_reports"),
    ("GET", "/workspaces/{workspace_id}/report-draft"): _enforced("view_reports"),
    # --- permission_required / enforced: mutations ---
    ("POST", "/workspaces"): _enforced("manage_workspaces"),
    ("POST", "/uploads"): _enforced("manage_uploads"),
    ("POST", "/uploads/direct"): _enforced("manage_uploads"),
    ("POST", "/uploads/{upload_id}/complete"): _enforced("manage_uploads"),
    ("POST", "/chat/messages"): _enforced("generate_reports"),
    ("POST", "/monday-reports"): _enforced("generate_reports"),
    ("POST", "/monday-reports/{report_id}/exports/{export_format}"): _enforced("issue_client_reports"),
    ("POST", "/report-exports/{export_id}/signed-url"): _enforced("export_evidence"),
    ("POST", "/upload-files/{file_id}/signed-url"): _enforced("export_evidence"),
    ("POST", "/retention/run"): _enforced("run_retention"),
    ("PATCH", "/validation-tasks/{task_id}"): _enforced("resolve_validation"),
    # --- permission_required / enforced: Benchmarking (preserved) ---
    ("GET", "/benchmarking/config"): _enforced("view_benchmarks"),
    ("PATCH", "/benchmarking/values/{benchmark_id}"): _enforced("manage_benchmark_config"),
    ("GET", "/workspaces/{workspace_id}/benchmarking"): _enforced("view_benchmarks"),
    ("POST", "/workspaces/{workspace_id}/benchmarking/measurements"): _enforced("review_anomalies"),
    ("PATCH", "/benchmarking/anomalies/{anomaly_id}/diagnostics/{action_id}/dismiss"): _enforced("dismiss_anomalies"),
    # --- permission_required / enforced: field corrections (preserved) ---
    ("POST", "/workspaces/{workspace_id}/field-corrections"): _enforced("record_field_corrections"),
    ("GET", "/workspaces/{workspace_id}/field-corrections"): _enforced("view_field_corrections"),
    ("POST", "/field-corrections/{correction_id}/revert"): _enforced("record_field_corrections"),
    # --- permission_required / enforced: identity/credential administration ---
    ("GET", "/auth/users"): _enforced(ADMIN_PERMISSION),
    ("POST", "/auth/users"): _enforced(ADMIN_PERMISSION),
    ("POST", "/auth/users/{user_id}/credentials"): _enforced(ADMIN_PERMISSION),
    ("GET", "/auth/credentials"): _enforced(ADMIN_PERMISSION),
    ("POST", "/auth/credentials/{credential_id}/revoke"): _enforced(ADMIN_PERMISSION),
}

_SENSITIVE_MUTATION_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# Public is minimal and allow-listed: liveness, the pre-auth readiness gate,
# framework docs (client-mode-gated by the middleware), and signed downloads.
_ALLOWED_PUBLIC_ROUTES = {
    ("GET", "/health"),
    ("GET", "/docs"),
    ("GET", "/docs/oauth2-redirect"),
    ("GET", "/openapi.json"),
    ("GET", "/redoc"),
    ("GET", "/signed/report-exports/{export_id}"),
    ("GET", "/signed/upload-files/{file_id}"),
}
_SIGNED_CAPABILITY_ROUTES = {
    ("GET", "/signed/report-exports/{export_id}"),
    ("GET", "/signed/upload-files/{file_id}"),
}


def audited_routes() -> list[tuple[str, str]]:
    """Enumerate the app's real (method, path) routes, excluding HEAD/OPTIONS."""
    seen: set[tuple[str, str]] = set()
    for route in app.routes:
        methods = getattr(route, "methods", None) or set()
        path = getattr(route, "path", None)
        if path is None:
            continue
        for method in methods:
            if method in {"HEAD", "OPTIONS"}:
                continue
            seen.add((method, path))
    return sorted(seen)


def _main_source() -> str:
    return Path(__file__).read_text(encoding="utf-8")


def _route_dependency_present(entry: dict[str, str], source: str) -> bool:
    """Static proof that the declared permission gate is wired somewhere in the
    route layer. The behavioral guard proves per-route enforcement."""
    permission = entry.get("permission")
    if permission == ADMIN_PERMISSION:
        return "require_admin()" in source
    return (
        f'require_permission("{permission}")' in source
        or f'require_benchmark_permission("{permission}")' in source
    )


def _mechanism_compatible(classification: str, mechanism: str, is_mutation: bool) -> bool:
    if classification == "public":
        return mechanism in {"none", "signed_capability"}
    if classification in {"authenticated_read", "permission_required"}:
        return mechanism == "api_credential"
    if classification == "system_internal":
        return mechanism == "internal_process"
    return False


def validate_route_access_policy() -> list[str]:
    """Return a list of route-policy errors (empty when the policy is consistent
    and security-appropriate)."""
    errors: list[str] = []
    routes = set(audited_routes())
    source = _main_source()
    for method, path in sorted(routes):
        entry = ROUTE_ACCESS_POLICY.get((method, path))
        if entry is None:
            errors.append(f"route {method} {path} has no access classification")
            continue
        classification = entry.get("classification")
        if classification not in ROUTE_ACCESS_CLASSIFICATIONS:
            errors.append(f"route {method} {path} has unknown classification {classification!r}")
            continue
        mechanism = entry.get("auth_mechanism", "api_credential")
        if mechanism not in AUTH_MECHANISMS:
            errors.append(f"route {method} {path} has unknown auth_mechanism {mechanism!r}")
        is_mutation = method in _SENSITIVE_MUTATION_METHODS
        if classification == "public":
            if is_mutation:
                errors.append(f"sensitive mutation {method} {path} must not be classified public")
            if (method, path) not in _ALLOWED_PUBLIC_ROUTES:
                errors.append(f"route {method} {path} is not an approved public route")
            if mechanism == "signed_capability" and (method, path) not in _SIGNED_CAPABILITY_ROUTES:
                errors.append(f"route {method} {path} claims signed_capability but is not a signed route")
        if classification == "authenticated_read" and is_mutation:
            errors.append(f"sensitive mutation {method} {path} must not be classified authenticated_read")
        if classification == "permission_required":
            status = entry.get("enforcement_status")
            if status not in ROUTE_ENFORCEMENT_STATUSES:
                errors.append(f"permission_required route {method} {path} has invalid enforcement_status {status!r}")
            elif status == "enforced":
                permission = entry.get("permission")
                if not permission:
                    errors.append(f"enforced route {method} {path} has no permission")
                elif permission != ADMIN_PERMISSION and permission not in KNOWN_PERMISSIONS:
                    errors.append(f"route {method} {path} references unknown permission {permission!r}")
                elif not _route_dependency_present(entry, source):
                    errors.append(f"enforced route {method} {path} does not invoke its permission dependency")
            elif status == "pending" and entry.get("permission"):
                errors.append(f"pending route {method} {path} must not claim an enforced permission")
        if not _mechanism_compatible(classification, mechanism, is_mutation):
            errors.append(f"route {method} {path} auth_mechanism {mechanism!r} incompatible with {classification!r}")
    # Signed-capability routes must be read-only.
    for method, path in _SIGNED_CAPABILITY_ROUTES:
        if method not in {"GET", "HEAD"}:
            errors.append(f"signed_capability route {method} {path} must be GET/HEAD only")
    # Every policy entry must correspond to a real route (no stale rows).
    for method, path in ROUTE_ACCESS_POLICY:
        if (method, path) not in routes:
            errors.append(f"policy row {method} {path} does not match any route")
    return errors


def pending_permission_routes() -> list[tuple[str, str]]:
    """Sensitive routes classified permission_required but not yet enforced."""
    return sorted(
        (method, path)
        for (method, path), entry in ROUTE_ACCESS_POLICY.items()
        if entry.get("classification") == "permission_required" and entry.get("enforcement_status") == "pending"
    )


def route_policy_fully_enforced() -> bool:
    """True ONLY when the route policy is complete AND security-appropriate:
    zero policy errors (parity, categories, auth mechanisms, signed-capability,
    minimal public set), zero pending routes, and every enforced permission_required
    route proves its permission dependency. Not merely "no pending rows"."""
    if validate_route_access_policy():
        return False
    if pending_permission_routes():
        return False
    source = _main_source()
    for (method, path), entry in ROUTE_ACCESS_POLICY.items():
        if entry.get("classification") == "permission_required" and entry.get("enforcement_status") == "enforced":
            if not _route_dependency_present(entry, source):
                return False
    return True


# ---------------------------------------------------------------------------
# Per-route tenant-ownership PARITY.
#
# Every route that reads/mutates a specific tenant-ownable resource (by path-param
# id, a resource-bearing body, or a per-tenant list/aggregate) MUST invoke a
# tenant-ownership dependency in its handler. Routes NOT listed are public,
# tenant-global config/status (readiness/runtime/local-ai/retention/audit-integrity/
# benchmarking-config/field-corrections-registry), server-stamped creates with no
# foreign lookup (POST /workspaces), identity administration (admin-gated,
# configured-tenant only), or signed-capability downloads (tenant bound in the
# token and re-checked at redemption). This mirrors route_policy_fully_enforced()
# for the permission layer and gives the readiness probe machine-readable evidence.
# ---------------------------------------------------------------------------
TENANT_OWNERSHIP_ROUTES: dict[tuple[str, str], str] = {
    ("GET", "/workspaces"): "filter",
    ("GET", "/documents"): "filter",
    ("GET", "/failures"): "filter",
    ("GET", "/processing-jobs"): "filter",
    ("GET", "/validation-tasks"): "filter",
    ("GET", "/monday-reports"): "filter",
    ("GET", "/audit-logs"): "filter",
    ("GET", "/dashboards/summary"): "filter",
    ("GET", "/uploads/{upload_id}/files"): "owned",
    ("GET", "/documents/{document_id}/chunks"): "owned",
    ("GET", "/workspaces/{workspace_id}/report-draft"): "owned",
    ("POST", "/uploads"): "owned",
    ("POST", "/uploads/direct"): "owned",
    ("POST", "/uploads/{upload_id}/complete"): "owned",
    ("POST", "/chat/messages"): "owned",
    ("POST", "/monday-reports"): "owned",
    ("POST", "/monday-reports/{report_id}/exports/{export_format}"): "owned",
    ("POST", "/report-exports/{export_id}/signed-url"): "owned",
    ("POST", "/upload-files/{file_id}/signed-url"): "owned",
    ("PATCH", "/validation-tasks/{task_id}"): "owned",
    ("PATCH", "/benchmarking/values/{benchmark_id}"): "owned",
    ("GET", "/workspaces/{workspace_id}/benchmarking"): "owned",
    ("POST", "/workspaces/{workspace_id}/benchmarking/measurements"): "owned",
    ("PATCH", "/benchmarking/anomalies/{anomaly_id}/diagnostics/{action_id}/dismiss"): "owned",
    ("POST", "/workspaces/{workspace_id}/field-corrections"): "owned",
    ("GET", "/workspaces/{workspace_id}/field-corrections"): "owned",
    ("POST", "/field-corrections/{correction_id}/revert"): "owned",
}
_TENANT_DEP_MARKERS = ("_tenant_owned(", "_tenant_items(", "_owned(", "owns(")


def _handler_segments(source: str) -> dict[tuple[str, str], str]:
    """Map (METHOD, path) -> the handler's source text, by scanning @app decorators
    (tolerant of multi-line decorators). A segment runs to the next decorator."""
    matches = list(re.finditer(r'@app\.(get|post|patch|put|delete)\(\s*"([^"]+)"', source))
    segments: dict[tuple[str, str], str] = {}
    for index, match in enumerate(matches):
        key = (match.group(1).upper(), match.group(2))
        end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
        segments[key] = source[match.start():end]
    return segments


def tenant_ownership_enforcement_errors() -> list[str]:
    """Return the list of tenant-ownership parity violations: a resource-scoped
    route whose handler invokes NO tenant-ownership dependency, or a stale entry."""
    source = _main_source()
    segments = _handler_segments(source)
    routes = set(audited_routes())
    errors: list[str] = []
    for (method, path) in sorted(TENANT_OWNERSHIP_ROUTES):
        if (method, path) not in routes:
            errors.append(f"tenant-ownership route {method} {path} does not match any route")
            continue
        body = segments.get((method, path), "")
        if not any(marker in body for marker in _TENANT_DEP_MARKERS):
            errors.append(f"resource route {method} {path} lacks a tenant-ownership dependency")
    return errors


def tenant_ownership_fully_enforced() -> bool:
    """True iff every resource-scoped route proves a tenant-ownership dependency."""
    return not tenant_ownership_enforcement_errors()


@app.get("/workspaces", response_model=list[Workspace])
def list_workspaces() -> list[Workspace]:
    require_permission("view_workspaces")
    store.refresh()
    return _tenant_items(store.workspaces.values())


@app.post("/workspaces", response_model=Workspace, status_code=status.HTTP_201_CREATED)
def create_workspace(payload: WorkspaceCreate) -> Workspace:
    require_permission("manage_workspaces")
    return store.create_workspace(payload)


@app.post("/uploads", response_model=UploadCreateResponse, status_code=status.HTTP_201_CREATED)
def create_upload(payload: UploadCreate) -> UploadCreateResponse:
    store.refresh()
    require_permission("manage_uploads")
    require_client_data_ready("upload.create", "workspace", payload.workspace_id)
    _tenant_owned(store.workspaces.get(payload.workspace_id), "workspace", payload.workspace_id, "Workspace not found")
    if upload_too_large(payload.byte_size):
        store.audit(
            "upload.rejected",
            "workspace",
            payload.workspace_id,
            {
                "reason": "max_upload_bytes_exceeded",
                "file_name": payload.file_name,
                "byte_size": payload.byte_size,
                "max_upload_bytes": max_upload_bytes(),
            },
        )
        raise HTTPException(status_code=413, detail=f"Upload exceeds {max_upload_bytes()} byte limit")
    upload, file_record, signed_url = store.create_upload(payload)
    return UploadCreateResponse(upload=upload, file=file_record, signed_url=signed_url)


@app.post("/uploads/direct", response_model=UploadCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_direct_upload(
    workspace_id: UUID = Form(...),
    file_name: str = Form(""),
    source_type: Literal["zip", "folder", "files"] = Form("files"),
    file: UploadFile = File(...),
) -> UploadCreateResponse:
    # Authorization first and in every mode (a non-admin per-user token must be
    # denied in demo mode too), before any workspace-existence disclosure.
    require_permission("manage_uploads")
    if client_data_mode() == "client":
        require_client_data_ready("upload.direct", "workspace", workspace_id)
    else:
        store.refresh()
    _tenant_owned(store.workspaces.get(workspace_id), "workspace", workspace_id, "Workspace not found")

    original_name = file_name or file.filename or "upload.bin"
    content = await file.read()
    if upload_too_large(len(content)):
        store.audit(
            "upload.rejected",
            "workspace",
            workspace_id,
            {
                "reason": "max_upload_bytes_exceeded",
                "file_name": original_name,
                "byte_size": len(content),
                "max_upload_bytes": max_upload_bytes(),
            },
        )
        raise HTTPException(status_code=413, detail=f"Upload exceeds {max_upload_bytes()} byte limit")
    # Persist durably inside create_uploaded_file's own mutation boundary (save=True)
    # rather than following it with a bare store.save(). On the transactional
    # PostgreSQL backend a direct store.save() outside a snapshot transaction fails
    # closed (SnapshotConflict), and the blocked record + upload.blocked audit are
    # already committed by this call's wrapper regardless of the branch taken -- so a
    # trailing save() was both redundant and fatal (a non-retryable 409). The clean
    # branch commits again in complete_upload; a second durable commit is harmless.
    upload, file_record, signed_url = store.create_uploaded_file(
        workspace_id=workspace_id,
        file_name=original_name,
        mime_type=file.content_type or "application/octet-stream",
        source_type=source_type,
        content=content,
        refresh=False,
        save=True,
    )
    if file_record.malware_status == "blocked":
        # The block and its upload.blocked audit are already durable; reject.
        raise HTTPException(status_code=422, detail="Upload blocked by malware scanner")
    upload = store.complete_upload(upload.id, [file_record.id], refresh=False)
    return UploadCreateResponse(
        upload=upload,
        file=store.files[file_record.id],
        signed_url=signed_url,
    )


@app.post("/uploads/{upload_id}/complete")
def complete_upload(upload_id: UUID, payload: UploadCompleteRequest) -> dict[str, str]:
    store.refresh()
    require_permission("manage_uploads")
    _tenant_owned(store.uploads.get(upload_id), "upload", upload_id, "Upload not found")
    require_client_data_ready("upload.complete", "upload", upload_id)
    for file_id in payload.file_ids:
        if file_id not in store.files:
            raise HTTPException(status_code=404, detail=f"File not found: {file_id}")
        file_record = store.files[file_id]
        if file_record.upload_id != upload_id:
            store.audit(
                "upload.complete_rejected",
                "upload",
                upload_id,
                {
                    "reason": "file_upload_mismatch",
                    "file_id": str(file_id),
                    "file_upload_id": str(file_record.upload_id),
                },
            )
            raise HTTPException(status_code=409, detail=f"File does not belong to upload: {file_id}")
    upload = store.complete_upload(upload_id, payload.file_ids)
    return {"upload_id": str(upload.id), "status": upload.status}


@app.get("/uploads/{upload_id}/files", response_model=list[UploadFileRecord])
def list_upload_files(upload_id: UUID) -> list[UploadFileRecord]:
    store.refresh()
    require_permission("view_source_documents")
    _tenant_owned(store.uploads.get(upload_id), "upload", upload_id, "Upload not found")
    require_client_data_ready("upload.files.list", "upload", upload_id)
    # The upload is tenant-owned; each returned file must ALSO carry the request
    # tenant's stamp (fail closed on a divergent child, do not trust FK inheritance).
    tenant_id = _request_tenant_id()
    return [file for file in store.files.values() if file.upload_id == upload_id and owns(file, tenant_id)]


@app.get("/processing-jobs", response_model=list[ProcessingJob])
def list_processing_jobs(
    upload_id: UUID | None = None,
    status_filter: ProcessingStatus | None = None,
) -> list[ProcessingJob]:
    store.refresh()
    require_permission("view_processing_status")
    require_client_data_ready("processing_jobs.list", "processing_job", None)
    jobs = _tenant_items(store.jobs.values())
    if upload_id:
        jobs = [job for job in jobs if job.upload_id == upload_id]
    if status_filter:
        jobs = [job for job in jobs if job.status == status_filter]
    return jobs


@app.get("/documents", response_model=list[ParsedDocument])
def list_documents(workspace_id: UUID | None = None) -> list[ParsedDocument]:
    store.refresh()
    require_permission("view_source_documents")
    require_client_data_ready("documents.list", "workspace", workspace_id)
    documents = _tenant_items(store.parsed_documents.values())
    if workspace_id:
        documents = [document for document in documents if document.workspace_id == workspace_id]
    return documents


@app.get("/documents/{document_id}/chunks", response_model=list[DocumentChunk])
def list_document_chunks(document_id: UUID) -> list[DocumentChunk]:
    store.refresh()
    require_permission("view_source_documents")
    _tenant_owned(store.parsed_documents.get(document_id), "parsed_document", document_id, "Document not found")
    require_client_data_ready("documents.chunks.list", "parsed_document", document_id)
    # The document is tenant-owned; each returned chunk must ALSO carry the request
    # tenant's stamp (fail closed on a divergent child, do not trust FK inheritance).
    tenant_id = _request_tenant_id()
    chunks = [
        chunk for chunk in store.document_chunks.values()
        if chunk.document_id == document_id and owns(chunk, tenant_id)
    ]
    return sorted(chunks, key=lambda item: item.ordinal)


@app.get("/audit-logs", response_model=list[AuditLog])
def list_audit_logs(limit: int = 50) -> list[AuditLog]:
    require_permission("view_audit_history")
    store.refresh()
    bounded_limit = min(max(limit, 1), 200)
    return list(reversed(_tenant_items(store.audit_logs)))[:bounded_limit]


@app.get("/audit-logs/integrity", response_model=AuditIntegrityStatus)
def audit_log_integrity() -> AuditIntegrityStatus:
    require_permission("view_audit_history")
    return store.audit_integrity_status()


@app.post("/retention/run", response_model=RetentionRunResult)
def run_retention(apply: bool = False) -> RetentionRunResult:
    store.refresh()
    require_permission("run_retention")
    require_client_data_ready("retention.run", "tenant", store.tenant.id)
    return store.run_retention(retention_days(), apply=apply)


@app.get("/validation-tasks", response_model=list[ValidationTask])
def list_validation_tasks() -> list[ValidationTask]:
    store.refresh()
    require_permission("view_validation_queue")
    require_client_data_ready("validation_tasks.list", "validation_task", None)
    return _tenant_items(store.validation_tasks.values())


@app.patch("/validation-tasks/{task_id}", response_model=ValidationTask)
def update_validation_task(task_id: UUID, payload: ValidationTaskUpdate, request: Request) -> ValidationTask:
    store.refresh()
    require_permission("resolve_validation")
    _tenant_owned(store.validation_tasks.get(task_id), "validation_task", task_id, "Validation task not found")
    require_client_data_ready("validation_task.update", "validation_task", task_id)
    # Establish the idempotency context only after auth/ownership/readiness pass,
    # so a rejected request never reserves the key.
    token = _establish_idempotency(
        request,
        operation_kind="validation_task.update",
        target_ids={"task_id": task_id},
        body=payload,
    )
    try:
        return store.update_validation_task(task_id, payload)
    finally:
        _reset_idempotency(token)


@app.post(
    "/workspaces/{workspace_id}/field-corrections",
    response_model=FieldCorrection,
    status_code=status.HTTP_201_CREATED,
)
def create_field_correction(workspace_id: UUID, payload: FieldCorrectionCreate, request: Request) -> FieldCorrection:
    # Hold the correction lock across the WHOLE handler so no concurrent
    # correction request's refresh() can clobber this in-flight append on the
    # shared store singleton (re-entrant with record_field_correction's lock).
    with store.field_correction_lock:
        store.refresh()
        # Authorization first: an unauthorized caller must get 403 whether or not
        # the workspace exists (no existence/readiness disclosure).
        require_permission("record_field_corrections")
        _tenant_owned(store.workspaces.get(workspace_id), "workspace", workspace_id, "Workspace not found")
        require_client_data_ready("field_correction.record", "workspace", workspace_id)
        # Only a registered correctable field may be corrected; unknown or
        # sensitive fields (audit/identity/tenant/recommendation/Benchmarking/
        # parser/source-provenance/validation/config/immutable) are rejected.
        try:
            validate_correction(
                payload.target_type,
                payload.field_key,
                payload.source_value,
                payload.corrected_value,
                payload.correction_reason,
            )
        except CorrectionValidationError as exc:
            raise HTTPException(status_code=422, detail={"code": exc.code, "message": exc.message})
        # Establish idempotency only after validation, so a rejected request never
        # reserves the key.
        token = _establish_idempotency(
            request,
            operation_kind="field_correction.record",
            target_ids={"workspace_id": workspace_id},
            body=payload,
        )
        try:
            return store.record_field_correction(workspace_id, payload)
        finally:
            _reset_idempotency(token)


@app.get("/field-corrections/registry")
def field_correction_registry() -> list[dict[str, object]]:
    return correctable_field_catalog()


@app.get("/workspaces/{workspace_id}/field-corrections", response_model=list[FieldCorrection])
def list_field_corrections(workspace_id: UUID, active_only: bool = False) -> list[FieldCorrection]:
    store.refresh()
    # Authorization first: an unauthorized caller must get 403 whether or not the
    # workspace exists (no existence/readiness disclosure).
    require_permission("view_field_corrections")
    _tenant_owned(store.workspaces.get(workspace_id), "workspace", workspace_id, "Workspace not found")
    require_client_data_ready("field_correction.list", "workspace", workspace_id)
    return store.list_field_corrections(workspace_id, active_only=active_only)


@app.post("/field-corrections/{correction_id}/revert", response_model=FieldCorrection)
def revert_field_correction(correction_id: UUID, payload: FieldCorrectionRevert, request: Request) -> FieldCorrection:
    with store.field_correction_lock:
        store.refresh()
        # Authorization first: an unauthorized caller must get 403 whether or not
        # the correction exists (no existence/readiness disclosure).
        require_permission("record_field_corrections")
        _tenant_owned(store.field_corrections.get(correction_id), "field_correction", correction_id, "Field correction not found")
        require_client_data_ready("field_correction.revert", "field_correction", correction_id)
        token = _establish_idempotency(
            request,
            operation_kind="field_correction.revert",
            target_ids={"correction_id": correction_id},
            body=payload,
        )
        try:
            return store.revert_field_correction(correction_id, payload.revert_reason)
        except ValueError as exc:
            # A business rejection (e.g. already reverted) rolls back before commit,
            # so the key is NOT reserved and the caller may correct and retry.
            raise HTTPException(status_code=409, detail=str(exc))
        finally:
            _reset_idempotency(token)


@app.get("/dashboards/summary", response_model=DashboardSummary)
def dashboard_summary(workspace_id: UUID | None = None) -> DashboardSummary:
    store.refresh()
    require_permission("view_reports")
    require_client_data_ready("dashboard.summary", "workspace", workspace_id)
    failures = _tenant_items(store.failures.values())
    if workspace_id:
        failures = [failure for failure in failures if failure.workspace_id == workspace_id]
    confidences = [failure.confidence for failure in failures]
    return DashboardSummary(
        total_failures=len(failures),
        total_npt_hours=sum(failure.npt_hours for failure in failures),
        validation_backlog=len(
            [task for task in _tenant_items(store.validation_tasks.values()) if task.status.value == "open"]
        ),
        high_or_critical_failures=len(
            [failure for failure in failures if failure.severity in {"High", "Critical"}]
        ),
        average_confidence=mean(confidences) if confidences else 0,
    )


@app.get("/failures", response_model=list[FailureRecord])
def list_failures(workspace_id: UUID | None = None) -> list[FailureRecord]:
    store.refresh()
    require_permission("view_source_documents")
    require_client_data_ready("failures.list", "workspace", workspace_id)
    failures = _tenant_items(store.failures.values())
    if workspace_id:
        failures = [failure for failure in failures if failure.workspace_id == workspace_id]
    return failures


@app.get("/benchmarking/config", response_model=BenchmarkConfigResponse)
def benchmarking_config() -> BenchmarkConfigResponse:
    store.refresh()
    require_benchmark_permission("view_benchmarks")
    return BenchmarkConfigResponse(
        benchmark_values=_tenant_items(store.benchmark_values.values()),
        anomaly_rules=_tenant_items(store.anomaly_rules.values()),
        permissions=store.benchmark_permissions(),
    )


@app.patch("/benchmarking/values/{benchmark_id}", response_model=BenchmarkValue)
def update_benchmark_value(benchmark_id: UUID, payload: BenchmarkValueUpdate) -> BenchmarkValue:
    store.refresh()
    require_benchmark_permission("manage_benchmark_config")
    _tenant_owned(store.benchmark_values.get(benchmark_id), "benchmark_value", benchmark_id, "Benchmark value not found")
    return store.update_benchmark_value(benchmark_id, payload)


@app.get("/workspaces/{workspace_id}/benchmarking", response_model=BenchmarkingStatus)
def workspace_benchmarking(workspace_id: UUID) -> BenchmarkingStatus:
    store.refresh()
    # Authorization first: never disclose workspace existence or readiness state
    # to an unauthorized caller.
    require_benchmark_permission("view_benchmarks")
    # Tenant-ownership gate: a workspace that is missing OR owned by another tenant
    # is treated identically (existence-hiding) — configuration-only status with no
    # workspace-specific data. The benchmarking status builder is tenant-scoped in
    # the store, so a foreign workspace_id surfaces none of another tenant's
    # measurements or anomalies.
    tenant_id = _request_tenant_id()
    workspace = store.workspaces.get(workspace_id)
    if not _owned(workspace, tenant_id):
        # Missing and cross-tenant are treated identically to the CALLER (config-only
        # 200, existence-hiding). A genuine cross-tenant probe against an EXISTING but
        # foreign workspace is additionally recorded as authz.cross_tenant_denied,
        # consistent with the rest of the surface; a truly-missing workspace writes none.
        if workspace is not None:
            _audit_cross_tenant_denied("workspace", workspace_id)
        require_client_data_ready("benchmarking.status", "workspace", workspace_id)
        store.audit(
            "benchmarking.workspace_missing_status",
            "workspace",
            workspace_id,
            {"detail": "Returning configuration-only benchmark status for missing workspace."},
        )
        return store._build_benchmarking_status(workspace_id)
    require_client_data_ready("benchmarking.status", "workspace", workspace_id)
    try:
        return store.benchmarking_status(workspace_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/workspaces/{workspace_id}/benchmarking/measurements", response_model=BenchmarkingStatus)
def create_benchmark_measurement(
    workspace_id: UUID,
    payload: BenchmarkMeasurementCreate,
) -> BenchmarkingStatus:
    store.refresh()
    require_benchmark_permission("review_anomalies")
    _tenant_owned(store.workspaces.get(workspace_id), "workspace", workspace_id, "Workspace not found")
    require_client_data_ready("benchmarking.measurement.create", "workspace", workspace_id)
    try:
        return store.record_benchmark_measurement(workspace_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.patch("/benchmarking/anomalies/{anomaly_id}/diagnostics/{action_id}/dismiss", response_model=AnomalyEvent)
def dismiss_benchmark_diagnostic(
    anomaly_id: UUID,
    action_id: UUID,
    payload: DiagnosticDismissRequest,
) -> AnomalyEvent:
    store.refresh()
    require_benchmark_permission("dismiss_anomalies")
    if not payload.reason.strip():
        raise HTTPException(status_code=422, detail="Dismissal reason is required")
    _tenant_owned(store.anomaly_events.get(anomaly_id), "anomaly_event", anomaly_id, "anomaly_not_found")
    try:
        return store.dismiss_diagnostic_action(anomaly_id, action_id, payload.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def report_draft_depth_hint(source_text: str, label: str) -> str:
    patterns = [
        rf"\b{label}\D{{0,24}}([0-9]{{1,3}}(?:,[0-9]{{3}})+|[0-9]{{4,6}})\s*(?:ft|feet|')?",
        rf"\b([0-9]{{1,3}}(?:,[0-9]{{3}})+|[0-9]{{4,6}})\s*(?:ft|feet|')?\s*{label}\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, source_text, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def report_draft_hole_hint(source_text: str) -> str:
    match = re.search(r"\b(26|17\.5|16|12\.25|8\.5|6\.125)\s*(?:in|inch|\"|hole)\b", source_text, flags=re.IGNORECASE)
    return f"{match.group(1)} in" if match else ""


def report_draft_mud_hint(source_text: str) -> str:
    match = re.search(r"\b([0-9]{1,2}(?:\.[0-9])?)\s*(?:ppg|lb/gal)\b", source_text, flags=re.IGNORECASE)
    return f"{match.group(1)} ppg" if match else ""


def report_draft_pdf_profiles(documents: list) -> list[dict[str, object]]:
    return store.collect_report_profiles_from_documents(documents)


def report_draft_profile_field(profiles: list[dict[str, object]], field: str) -> str:
    for profile in profiles:
        fields = profile.get("fields")
        if not isinstance(fields, dict):
            continue
        value = fields.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def report_draft_profile_section(profiles: list[dict[str, object]], section: str) -> str:
    for profile in profiles:
        sections = profile.get("sections")
        if not isinstance(sections, dict):
            continue
        value = sections.get(section)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def report_draft_profile_note(profiles: list[dict[str, object]]) -> str | None:
    if not profiles:
        return None
    profile = profiles[0]
    document_type = str(profile.get("document_type", "pdf_report")).replace("_", " ")
    confidence = profile.get("confidence", 0)
    field_count = profile.get("field_count", 0)
    section_count = profile.get("section_count", 0)
    return f"PDF report profile: {document_type}, confidence {confidence}, {field_count} field(s), {section_count} section(s)."


@app.get("/workspaces/{workspace_id}/report-draft", response_model=ReportDraftResponse)
def report_draft(workspace_id: UUID) -> ReportDraftResponse:
    store.refresh()
    require_permission("view_reports")
    # Reuse the object resolved by the ownership check instead of re-indexing the
    # collection: with the request read view both accesses hit one pinned
    # generation, and reusing the resolved object removes the get-then-index step
    # entirely (belt-and-suspenders against a concurrent delete).
    workspace = _tenant_owned(
        store.workspaces.get(workspace_id), "workspace", workspace_id, "Workspace not found")
    require_client_data_ready("report_draft.generate", "workspace", workspace_id)
    # Report-draft input is tenant-scoped: the workspace is owned, and every record
    # fed into the draft must ALSO carry the request tenant's stamp (fail closed on a
    # contradictory foreign record that happens to carry this workspace_id).
    tenant_id = _request_tenant_id()
    documents = sorted(
        [document for document in store.parsed_documents.values() if document.workspace_id == workspace_id and owns(document, tenant_id)],
        key=lambda item: item.created_at,
        reverse=True,
    )
    chunks = sorted(
        [chunk for chunk in store.document_chunks.values() if chunk.workspace_id == workspace_id and owns(chunk, tenant_id) and chunk.text.strip()],
        key=lambda item: item.created_at,
        reverse=True,
    )
    failures = sorted(
        [failure for failure in store.failures.values() if failure.workspace_id == workspace_id and owns(failure, tenant_id)],
        key=lambda item: (
            {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(item.severity, 0),
            item.npt_hours,
            item.confidence,
        ),
        reverse=True,
    )
    open_tasks = store._open_validation_tasks_for_workspace(workspace_id)
    source_text = " ".join(chunk.text[:1200] for chunk in chunks[:20])
    document_titles = [document.title for document in documents[:6]]
    pdf_profiles = report_draft_pdf_profiles(documents)
    citations = dedupe_citations(
        store.parsed_citations_for_workspace(workspace_id, limit=8)
        + [citation for failure in failures for citation in failure.citations]
    )
    top_failure = failures[0] if failures else None
    total_npt = sum(failure.npt_hours for failure in failures)
    evidence_scope = f"{len(documents)} parsed document(s), {len(chunks)} chunk(s), {len(citations)} citation(s)"
    latest_source = ", ".join(document_titles[:3]) if document_titles else "no parsed source titles available"
    present_from_pdf = report_draft_profile_section(pdf_profiles, "present_operations")
    next_from_pdf = report_draft_profile_section(pdf_profiles, "next_operations")
    safety_from_pdf = report_draft_profile_section(pdf_profiles, "safety")
    casing_from_pdf = report_draft_profile_section(pdf_profiles, "casing")
    bha_from_pdf = report_draft_profile_section(pdf_profiles, "bha")
    survey_from_pdf = report_draft_profile_section(pdf_profiles, "survey")

    if top_failure:
        present_prefix = f"{present_from_pdf} " if present_from_pdf else ""
        present_ops = (
            f"{present_prefix}Source-backed review covers {evidence_scope}. Highest-risk extracted item: "
            f"{top_failure.event_type} - {top_failure.summary} "
            f"({top_failure.npt_hours:.1f} hr NPT, {top_failure.severity})."
        )
    else:
        present_prefix = f"{present_from_pdf} " if present_from_pdf else ""
        present_ops = (
            f"{present_prefix}Source-backed review covers {evidence_scope}. No structured failure records are extracted yet; "
            "complete source review before client issue."
        )

    risk_items = [
        f"{failure.severity}: {failure.summary} ({failure.npt_hours:.1f} hr NPT)"
        for failure in failures[:3]
    ]
    if open_tasks:
        risk_items.append(f"{len(open_tasks)} open validation task(s) must be closed before official export.")
    for label, note in [("Casing", casing_from_pdf), ("BHA", bha_from_pdf), ("Survey", survey_from_pdf)]:
        if note:
            risk_items.append(f"{label} source note: {note}")
    risks = " ".join(risk_items) if risk_items else "No extracted high-risk item is available; confirm source coverage and safety barriers."
    evidence_summary = [
        f"Latest sources: {latest_source}.",
        f"Failure scope: {len(failures)} record(s), {total_npt:.1f} total NPT hour(s).",
        "Official outputs remain validation-gated and citation-backed.",
    ]
    profile_note = report_draft_profile_note(pdf_profiles)
    if profile_note:
        evidence_summary.insert(1, profile_note)
    casing_source_rows = store.casing_rows_from_profiles(pdf_profiles)
    casing_rows = casing_source_rows if casing_source_rows else store.reference_casing_rows()
    activity_source_rows = store.activity_rows_from_profiles(pdf_profiles)
    activity_rows = activity_source_rows if activity_source_rows else store.reference_activity_rows()
    casing_program = store.casing_program_from_rows(casing_rows)
    operations_log = store.operations_log_from_rows(activity_rows)
    casing_strings = [CasingString(**row) for row in casing_rows]
    activity_timeline = [ActivitySegment(**row) for row in activity_rows]
    schematic_source = "source" if (casing_source_rows or activity_source_rows) else "reference"
    # Survey stations are source-only: no reference fallback rows exist, so an
    # empty list plus survey_source="none" is the honest no-evidence state.
    survey_source_rows = store.survey_rows_from_profiles(pdf_profiles)
    survey_stations = [SurveyStation(**row) for row in survey_source_rows]
    survey_source = "source" if survey_source_rows else "none"
    survey_truncated = store.survey_truncation_from_profiles(pdf_profiles)
    # Calculated trajectory geometry (minimum curvature v1) lives in a separate
    # block; source survey rows above remain untouched.
    trajectory_calculation = store.trajectory_from_survey_rows(survey_source_rows)
    trajectory_source = "calculated" if trajectory_calculation else "none"
    # Source-derived hydraulics observations (deterministic_hydraulics v1):
    # informational, review-required, and never coupled to the recommended-only
    # Hydraulics/T&D diagnostics or Benchmarking.
    hydraulics_source_rows = store.hydraulics_rows_from_profiles(pdf_profiles)
    hydraulics_observations = [HydraulicObservation(**row) for row in hydraulics_source_rows]
    hydraulics_source = "source" if hydraulics_source_rows else "none"
    hydraulics_truncated = store.hydraulics_truncation_from_profiles(pdf_profiles)

    response = ReportDraftResponse(
        workspace_id=workspace_id,
        report_no=report_draft_profile_field(pdf_profiles, "report_no") or f"MR-SRC-{len(documents):03d}",
        well=report_draft_profile_field(pdf_profiles, "well") or workspace.asset or workspace.name,
        rig=report_draft_profile_field(pdf_profiles, "rig") or workspace.name,
        operator=report_draft_profile_field(pdf_profiles, "operator") or store.tenant.name or "Monday Report",
        phase=workspace.campaign or "Source-backed morning report",
        hole_size=report_draft_profile_field(pdf_profiles, "hole_size") or report_draft_hole_hint(source_text),
        md_ft=report_draft_profile_field(pdf_profiles, "md_ft") or report_draft_depth_hint(source_text, "md"),
        tvd_ft=report_draft_profile_field(pdf_profiles, "tvd_ft") or report_draft_depth_hint(source_text, "tvd"),
        mud_weight=report_draft_profile_field(pdf_profiles, "mud_weight") or report_draft_mud_hint(source_text),
        present_ops=present_ops,
        next_ops=(
            f"{next_from_pdf} Validate source citations and export only after validation closure."
            if next_from_pdf
            else (
                "Normalize the latest source reports into well/job information, present operations, drilling parameters, "
                "mud/BHA/survey, casing, timeline, NPT, risks, and approvals; then export only after validation closure."
            )
        ),
        safety=safety_from_pdf
        or (
            "Confirm BOP, well-control, pressure-control barriers, lifting exposure, and HSE observations against "
            "the latest daily report before client issue."
        ),
        risks=risks,
        casing_program=casing_program,
        operations_log=operations_log,
        casing_strings=casing_strings,
        activity_timeline=activity_timeline,
        schematic_source=schematic_source,
        survey_stations=survey_stations,
        survey_source=survey_source,
        trajectory=trajectory_calculation,
        trajectory_source=trajectory_source,
        hydraulics_observations=hydraulics_observations,
        hydraulics_source=hydraulics_source,
        field_corrections=store.list_field_corrections(workspace_id, active_only=True),
        evidence_summary=evidence_summary,
        source_document_count=len(documents),
        source_chunk_count=len(chunks),
        failure_count=len(failures),
        open_validation_tasks=len(open_tasks),
        citation_count=len(citations),
        validation_gate="review_required" if open_tasks else "clear",
        citations=citations,
        confidence_notes=[
            "Draft is generated from parsed workspace evidence, structured failures, and validation tasks.",
            "Depth, hole, mud, casing, BHA, survey, and safety values must be confirmed against source citations.",
            "Client-mode use remains blocked until readiness checks pass.",
        ],
    )
    store.audit(
        "report_draft.generate",
        "workspace",
        workspace_id,
        {
            "documents": response.source_document_count,
            "chunks": response.source_chunk_count,
            "failures": response.failure_count,
            "open_validation_tasks": response.open_validation_tasks,
            "citations": response.citation_count,
            "schematic_source": schematic_source,
            "casing_source_rows": len(casing_source_rows),
            "casing_reference_rows": 0 if casing_source_rows else len(casing_rows),
            "timeline_source_rows": len(activity_source_rows),
            "timeline_reference_rows": 0 if activity_source_rows else len(activity_rows),
            "survey_source": survey_source,
            "survey_source_rows": len(survey_source_rows),
            "survey_conflict_rows": sum(1 for row in survey_source_rows if row.get("conflict")),
            "survey_truncated": survey_truncated,
            "trajectory_source": trajectory_source,
            "trajectory_method": f"{trajectory_calculation.method} {trajectory_calculation.method_version}"
            if trajectory_calculation
            else "none",
            "trajectory_review_state": trajectory_calculation.review_state if trajectory_calculation else "none",
            "trajectory_segments": trajectory_calculation.segment_count if trajectory_calculation else 0,
            "trajectory_intervals": trajectory_calculation.interval_count if trajectory_calculation else 0,
            "trajectory_eligible_stations": trajectory_calculation.eligible_station_count if trajectory_calculation else 0,
            "trajectory_skipped_total": sum(
                trajectory_calculation.skips.model_dump().values()
            )
            if trajectory_calculation
            else 0,
            "trajectory_reference": (
                f"tvd:{trajectory_calculation.coordinate_reference.tvd},"
                f"ns:{trajectory_calculation.coordinate_reference.north_south},"
                f"ew:{trajectory_calculation.coordinate_reference.east_west}"
            )
            if trajectory_calculation
            else "none",
            "hydraulics_source": hydraulics_source,
            "hydraulics_source_rows": len(hydraulics_source_rows),
            "hydraulics_conflict_rows": sum(1 for row in hydraulics_source_rows if row.get("conflict")),
            "hydraulics_review_rows": sum(1 for row in hydraulics_source_rows if row.get("review_flag")),
            "hydraulics_observed_rows": sum(
                1 for row in hydraulics_source_rows if row.get("observation_status") == "observed"
            ),
            "hydraulics_planned_rows": sum(
                1 for row in hydraulics_source_rows if row.get("observation_status") == "planned"
            ),
            "hydraulics_unknown_rows": sum(
                1 for row in hydraulics_source_rows if row.get("observation_status") == "unknown"
            ),
            "hydraulics_truncated": hydraulics_truncated,
            "hydraulics_parser": "deterministic_hydraulics v1",
            "report_profiles": len(pdf_profiles),
            "parser_version": "pdf_report_profile_v1",
        },
    )
    return response


@app.post("/chat/messages", response_model=ChatResponse)
def chat(payload: ChatRequest) -> ChatResponse:
    store.refresh()
    require_permission("generate_reports")
    require_client_data_ready("chat.message", "workspace", payload.workspace_id)
    # Tenant-scope every collection the chat answer is derived from: a workspace_id
    # belonging to another tenant surfaces none of that tenant's failures/documents.
    tenant_id = _request_tenant_id()
    failures = [
        failure for failure in store.failures.values()
        if failure.workspace_id == payload.workspace_id and owns(failure, tenant_id)
    ]
    documents = [
        document for document in store.parsed_documents.values()
        if document.workspace_id == payload.workspace_id and owns(document, tenant_id)
    ]
    chunk_count = sum(document.chunk_count for document in documents)
    citations = dedupe_citations(
        store.parsed_citations_for_workspace(payload.workspace_id)
        + [citation for failure in failures for citation in failure.citations]
    )
    open_tasks = store._open_validation_tasks_for_workspace(payload.workspace_id)
    try:
        benchmark_status = store.benchmarking_status(payload.workspace_id)
    except (KeyError, ValueError):
        benchmark_status = None

    store.audit(
        "chat.message",
        "workspace",
        payload.workspace_id,
        {"prompt": payload.content[:180], "mode": "local_ai_api_scaffold"},
    )

    # Grounding is backend-owned and stays here; the provider only turns the grounded
    # context into the answer. Phase 1 uses the built-in DeterministicProvider (no
    # model, no network) so behavior is byte-identical to the previous inline handler.
    context = GroundedContext(
        content=payload.content,
        workspace_id=payload.workspace_id,
        failures=failures,
        documents=documents,
        chunk_count=chunk_count,
        base_citations=citations,
        open_tasks=open_tasks,
        benchmark_status=benchmark_status,
    )
    # Every citation the deterministic branches can emit is drawn from this grounded
    # set (the workspace's citations plus each active anomaly's supporting citations),
    # so validation is a proven no-op today; it exists to stop a future provider from
    # introducing a source that was never retrieved.
    allowed_citations = list(citations) + [
        citation
        for anomaly in (benchmark_status.active_anomalies if benchmark_status is not None else [])
        for citation in anomaly.supporting_citations
    ]
    # Server/operator-controlled provider selection. Unless the process environment
    # explicitly (and validly) selects the loopback local model, this is the built-in
    # deterministic provider. The deterministic provider passed in is the patchable
    # module global, so a deterministic failure still surfaces; a *local model* failure
    # falls back to deterministic inside the provider. Citations remain backend-owned
    # and are validated below regardless of which provider produced the answer.
    provider = resolve_ai_provider(DETERMINISTIC_PROVIDER)
    response = provider.generate(context)
    response.citations = validate_citations(response.citations, allowed_citations)
    return response


@app.post("/monday-reports", response_model=MondayReport, status_code=status.HTTP_201_CREATED)
def create_monday_report(payload: MondayReportCreate, request: Request) -> MondayReport:
    store.refresh()
    require_permission("generate_reports")
    _tenant_owned(store.workspaces.get(payload.workspace_id), "workspace", payload.workspace_id, "Workspace not found")
    require_client_data_ready("monday_report.create", "workspace", payload.workspace_id)
    # Honour an Idempotency-Key when supplied so a retried/replayed POST returns the
    # ORIGINAL report (no duplicate row, no second monday_report.create audit event),
    # and a same-key-different-body request fails closed (409). Established only AFTER
    # auth/ownership/readiness pass, so a rejected request never reserves the key. The
    # key is OPTIONAL here (unlike the reviewer-mutation routes): report generation is
    # also driven by the UI, which does not send the header, so a missing key preserves
    # the prior behaviour and creates a new report on both backends.
    token = _establish_idempotency(
        request,
        operation_kind="monday_report.create",
        target_ids={"workspace_id": payload.workspace_id},
        body=payload,
        optional=True,
    )
    try:
        return store.create_monday_report(payload)
    finally:
        _reset_idempotency(token)


@app.get("/monday-reports", response_model=list[MondayReport])
def list_monday_reports(workspace_id: UUID | None = None) -> list[MondayReport]:
    store.refresh()
    require_permission("view_reports")
    require_client_data_ready("monday_reports.list", "workspace", workspace_id)
    reports = _tenant_items(store.monday_reports.values())
    if workspace_id:
        reports = [report for report in reports if report.workspace_id == workspace_id]
    return reports


@app.post("/monday-reports/{report_id}/exports/{export_format}", response_model=ReportExport)
def export_monday_report(
    report_id: UUID,
    export_format: Literal["json", "csv", "html", "pdf", "xlsx"],
    allow_unresolved_validation: bool = False,
) -> ReportExport:
    store.refresh()
    require_permission("issue_client_reports")
    report = _tenant_owned(
        store.monday_reports.get(report_id), "monday_report", report_id, "Monday Report not found")
    require_client_data_ready("monday_report.export", "monday_report", report_id)
    open_tasks = store.report_open_validation_tasks(report_id)
    if open_tasks and (not allow_unresolved_validation or client_data_mode() == "client"):
        # The review transition and the export_blocked audit event persist together
        # or roll back together (one wrapped snapshot transaction) -- a 409 refusal
        # never leaves one without the other, even under a concurrent writer.
        store.mark_report_export_blocked(
            report_id,
            export_format,
            allow_unresolved_validation,
            [task.id for task in open_tasks],
        )
        raise HTTPException(status_code=409, detail="Report has unresolved validation tasks")
    if open_tasks and allow_unresolved_validation:
        store.audit(
            "monday_report.export_override",
            "monday_report",
            report_id,
            {
                "format": export_format,
                "open_validation_tasks": len(open_tasks),
                "validation_task_ids": [str(task.id) for task in open_tasks],
            },
        )
    try:
        return store.export_monday_report(report_id, export_format)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/report-exports/{export_id}/signed-url", response_model=SignedUrlResponse)
def create_report_export_signed_url(export_id: UUID, request: Request) -> SignedUrlResponse:
    store.refresh()
    require_permission("export_evidence")
    report_export = _tenant_owned(store.report_exports.get(export_id), "report_export", export_id, "Report export not found")
    if client_data_mode() == "client" and not signing_secret_configured():
        store.audit(
            "report_export.signed_url_blocked",
            "report_export",
            export_id,
            {"reason": "missing_signing_secret_client_mode"},
        )
        raise HTTPException(status_code=409, detail="Signing secret is required in client data mode")
    require_client_data_ready("report_export.signed_url", "report_export", export_id)

    token, expires_at = create_signed_token(
        export_id, "report_export_download", tenant_id=report_export.tenant_id
    )
    path = f"/signed/report-exports/{export_id}?token={token}"
    url = str(request.base_url).rstrip("/") + path
    store.audit(
        "report_export.signed_url",
        "report_export",
        export_id,
        {
            "report_id": str(report_export.report_id),
            "format": report_export.format,
            "expires_at": expires_at.isoformat(),
        },
    )
    return SignedUrlResponse(url=url, expires_at=expires_at)


@app.get("/signed/report-exports/{export_id}")
def download_report_export(export_id: UUID, token: str) -> Response:
    # The signed token is the SOLE authorization for this public route. Verify it
    # FIRST — before any resource lookup, readiness gate, or audit side effect —
    # so an unauthenticated caller with an invalid/garbage token cannot probe
    # resource existence (404 vs 403 oracle) or trigger audit writes.
    if not verify_signed_token(token, export_id, "report_export_download"):
        raise HTTPException(status_code=403, detail="Invalid or expired signed URL")
    store.refresh()
    if export_id not in store.report_exports:
        raise HTTPException(status_code=404, detail="Report export not found")
    if client_data_mode() == "client" and not signing_secret_configured():
        store.audit(
            "report_export.download_blocked",
            "report_export",
            export_id,
            {"reason": "missing_signing_secret_client_mode"},
        )
        raise HTTPException(status_code=409, detail="Signing secret is required in client data mode")
    require_client_data_ready("report_export.download", "report_export", export_id)

    report_export = store.report_exports[export_id]
    # Tenant capability binding: the token must bind THIS resource's tenant. A token
    # minted for another tenant's export cannot redeem this one (existence-hiding 404).
    if not verify_signed_token(token, export_id, "report_export_download", tenant_id=report_export.tenant_id):
        raise HTTPException(status_code=404, detail="Report export not found")
    export_path = store.export_path_from_uri(report_export.storage_uri)
    if export_path is None or not export_path.exists():
        raise HTTPException(status_code=404, detail="Export artifact not found")
    try:
        content = export_path.read_bytes()
    except OSError as exc:
        raise HTTPException(status_code=404, detail="Export artifact not readable") from exc

    media_types = {
        "json": "application/json",
        "csv": "text/csv",
        "html": "text/html",
        "pdf": "application/pdf",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }
    store.audit(
        "report_export.download",
        "report_export",
        export_id,
        {
            "report_id": str(report_export.report_id),
            "format": report_export.format,
            "sha256": report_export.sha256,
        },
    )
    return Response(
        content=content,
        media_type=media_types.get(report_export.format, "application/octet-stream"),
        headers={"Content-Disposition": f'attachment; filename="monday_report.{report_export.format}"'},
    )


@app.post("/upload-files/{file_id}/signed-url", response_model=SignedUrlResponse)
def create_upload_file_signed_url(file_id: UUID, request: Request) -> SignedUrlResponse:
    store.refresh()
    require_permission("export_evidence")
    file_record = _tenant_owned(store.files.get(file_id), "file", file_id, "Upload file not found")
    if client_data_mode() == "client" and not signing_secret_configured():
        store.audit(
            "upload_file.signed_url_blocked",
            "upload_file",
            file_id,
            {"reason": "missing_signing_secret_client_mode"},
        )
        raise HTTPException(status_code=409, detail="Signing secret is required in client data mode")
    require_client_data_ready("upload_file.signed_url", "upload_file", file_id)
    if file_record.malware_status == "blocked" or not file_record.storage_uri.startswith("object://"):
        raise HTTPException(status_code=409, detail="Upload file is not downloadable")

    token, expires_at = create_signed_token(file_id, "upload_file_download", tenant_id=file_record.tenant_id)
    path = f"/signed/upload-files/{file_id}?token={token}"
    url = str(request.base_url).rstrip("/") + path
    store.audit(
        "upload_file.signed_url",
        "file",
        file_id,
        {
            "upload_id": str(file_record.upload_id),
            "original_path": file_record.original_path,
            "expires_at": expires_at.isoformat(),
        },
    )
    return SignedUrlResponse(url=url, expires_at=expires_at)


@app.get("/signed/upload-files/{file_id}")
def download_upload_file(file_id: UUID, token: str) -> Response:
    # The signed token is the SOLE authorization for this public route. Verify it
    # FIRST — before any resource lookup, readiness gate, or audit side effect —
    # so an unauthenticated caller with an invalid/garbage token cannot probe
    # resource existence (404 vs 403 oracle) or trigger audit writes.
    if not verify_signed_token(token, file_id, "upload_file_download"):
        raise HTTPException(status_code=403, detail="Invalid or expired signed URL")
    store.refresh()
    if file_id not in store.files:
        raise HTTPException(status_code=404, detail="Upload file not found")
    if client_data_mode() == "client" and not signing_secret_configured():
        store.audit(
            "upload_file.download_blocked",
            "upload_file",
            file_id,
            {"reason": "missing_signing_secret_client_mode"},
        )
        raise HTTPException(status_code=409, detail="Signing secret is required in client data mode")
    require_client_data_ready("upload_file.download", "upload_file", file_id)

    file_record = store.files[file_id]
    # Tenant capability binding: the token must bind THIS resource's tenant. A token
    # minted for another tenant's file cannot redeem this one (existence-hiding 404).
    if not verify_signed_token(token, file_id, "upload_file_download", tenant_id=file_record.tenant_id):
        raise HTTPException(status_code=404, detail="Upload file not found")
    if file_record.malware_status == "blocked" or not file_record.storage_uri.startswith("object://"):
        raise HTTPException(status_code=409, detail="Upload file is not downloadable")
    file_path = store.file_path_from_uri(file_record.storage_uri)
    if file_path is None or not file_path.exists():
        raise HTTPException(status_code=404, detail="Upload file artifact not found")
    try:
        content = file_path.read_bytes()
    except OSError as exc:
        raise HTTPException(status_code=404, detail="Upload file artifact not readable") from exc

    store.audit(
        "upload_file.download",
        "file",
        file_id,
        {
            "upload_id": str(file_record.upload_id),
            "original_path": file_record.original_path,
            "sha256": file_record.sha256,
        },
    )
    return Response(
        content=content,
        media_type=file_record.mime_type or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{attachment_filename(file_record.original_path, "source-file")}"'},
    )


def attachment_filename(original_path: str, fallback: str) -> str:
    candidate = original_path.replace("\\", "/").split("/")[-1].strip() or fallback
    safe = "".join(character if character.isalnum() or character in "._-" else "_" for character in candidate)
    return safe[:120] or fallback


