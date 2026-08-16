from __future__ import annotations

from datetime import date, datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class Role(str, Enum):
    ADMIN = "admin"
    ENGINEER = "engineer"
    VALIDATOR = "validator"
    MANAGER = "manager"
    VIEWER = "viewer"


class ProcessingStatus(str, Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETE = "complete"
    FAILED = "failed"


class ValidationStatus(str, Enum):
    OPEN = "open"
    VALIDATED = "validated"
    REJECTED = "rejected"
    CONFLICT = "conflict"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Tenant(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    slug: str
    local_llm_policy: dict[str, Any] = Field(
        default_factory=lambda: {
            "mode": "local_first",
            "hosted_fallback_enabled": False,
            "allowed_local_runtimes": ["ollama", "lm_studio"],
        }
    )


class User(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    email: str
    full_name: str
    roles: list[Role] = Field(default_factory=list)
    # Additive identity-foundation fields (default-compatible with old snapshots).
    account_status: Literal["active", "disabled"] = "active"
    is_bootstrap: bool = False


# --- Authenticated identity foundation -------------------------------------
# A bounded first slice: opaque per-user credentials resolved server-side to a
# request-scoped identity. This is NOT complete multi-tenant authorization,
# complete route-level RBAC, or verified reviewer identity — those remain
# declared blockers in evals/ga/blocker_registry.v1.json.
AccountStatus = Literal["active", "disabled"]
CredentialStatus = Literal["active", "revoked"]
# `demo_bootstrap` is an explicit local/compatibility identity, NOT a verified
# human per-user identity.
ActorSource = Literal["authenticated", "demo_bootstrap", "system"]
AuthenticationSource = Literal["api_token", "shared_key_bootstrap", "system"]


class StoredApiCredential(BaseModel):
    """Persisted per-user API credential. Only a hash + fingerprint are stored;
    the raw token exists only at creation time and is never persisted."""

    credential_id: UUID = Field(default_factory=uuid4)
    user_id: UUID
    tenant_id: UUID
    token_hash: str
    token_fingerprint: str
    status: CredentialStatus = "active"
    authentication_source: AuthenticationSource = "api_token"
    created_at: datetime = Field(default_factory=utc_now)
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None


class AuthenticatedIdentity(BaseModel):
    """Request-scoped identity resolved from a presented credential. Not
    persisted; carries no secret material."""

    user_id: UUID
    tenant_id: UUID
    email: str
    display_name: str
    roles: list[Role] = Field(default_factory=list)
    account_status: AccountStatus = "active"
    authentication_source: AuthenticationSource
    credential_id: UUID | None = None
    credential_fingerprint: str | None = None
    actor_source: ActorSource


class UserCreateRequest(BaseModel):
    email: str = Field(min_length=3, max_length=200)
    full_name: str = Field(min_length=1, max_length=200)
    roles: list[Role] = Field(min_length=1)


class UserAdminView(BaseModel):
    id: UUID
    tenant_id: UUID
    email: str
    full_name: str
    roles: list[Role]
    account_status: AccountStatus
    is_bootstrap: bool


class CredentialAdminView(BaseModel):
    credential_id: UUID
    user_id: UUID
    tenant_id: UUID
    token_fingerprint: str
    status: CredentialStatus
    authentication_source: AuthenticationSource
    created_at: datetime
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None


class CredentialCreateResponse(BaseModel):
    credential_id: UUID
    user_id: UUID
    token_fingerprint: str
    # The raw token is returned exactly once at creation and never again.
    token: str
    created_at: datetime
    note: str = "Store this token now; it is shown once and cannot be retrieved again."


class SessionResponse(BaseModel):
    tenant: Tenant
    user: User
    # Additive identity context for the resolved request identity.
    authenticated_identity: AuthenticatedIdentity | None = None
    permissions: dict[str, bool] = Field(default_factory=dict)


class WorkspaceCreate(BaseModel):
    name: str
    asset: str | None = None
    campaign: str | None = None
    period_start: date | None = None
    period_end: date | None = None


class Workspace(WorkspaceCreate):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    status: Literal["active", "archived"] = "active"
    created_at: datetime = Field(default_factory=utc_now)


class UploadCreate(BaseModel):
    workspace_id: UUID
    file_name: str
    byte_size: int = Field(ge=0)
    mime_type: str = "application/octet-stream"
    source_type: Literal["zip", "folder", "files"] = "zip"


class UploadFileRecord(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    upload_id: UUID
    original_path: str
    storage_uri: str
    sha256: str
    mime_type: str
    byte_size: int
    status: ProcessingStatus = ProcessingStatus.QUEUED
    malware_status: Literal["pending", "clean", "blocked"] = "pending"


class Upload(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    workspace_id: UUID
    submitted_by: UUID
    source_type: Literal["zip", "folder", "files"]
    status: ProcessingStatus = ProcessingStatus.QUEUED
    created_at: datetime = Field(default_factory=utc_now)


class UploadCreateResponse(BaseModel):
    upload: Upload
    file: UploadFileRecord
    signed_url: str


class UploadCompleteRequest(BaseModel):
    file_ids: list[UUID]


class ProcessingJob(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    upload_id: UUID
    file_id: UUID | None = None
    job_type: str
    status: ProcessingStatus = ProcessingStatus.QUEUED
    attempts: int = 0
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class ParsedDocument(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    workspace_id: UUID
    upload_id: UUID
    file_id: UUID
    title: str
    parser_name: str
    status: ProcessingStatus = ProcessingStatus.QUEUED
    text_preview: str = ""
    chunk_count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class DocumentChunk(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    workspace_id: UUID
    upload_id: UUID
    file_id: UUID
    document_id: UUID
    ordinal: int
    text: str
    locator_type: str
    locator: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0, le=1, default=0.7)
    created_at: datetime = Field(default_factory=utc_now)


class Citation(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    file_id: UUID | None = None
    locator_type: str
    locator: dict[str, Any] = Field(default_factory=dict)
    snippet: str
    confidence: float = Field(ge=0, le=1)


class BenchmarkValue(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    benchmark_name: str
    metric: str
    value: float
    unit: str
    performance_category: str
    data_source: str
    effective_date: date
    dataset_version: str
    last_updated: datetime = Field(default_factory=utc_now)
    approval_status: Literal["draft", "approved", "retired"] = "approved"


class BenchmarkValueUpdate(BaseModel):
    value: float | None = None
    unit: str | None = None
    performance_category: str | None = None
    data_source: str | None = None
    effective_date: date | None = None
    dataset_version: str | None = None
    approval_status: Literal["draft", "approved", "retired"] | None = None
    reason: str


class AnomalyRule(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    name: str
    metric: str
    severity: Literal["Advisory", "Warning", "Critical"]
    benchmark_name: str
    threshold_mode: Literal["below_benchmark", "below_percent_of_benchmark"]
    threshold_percent: float | None = None
    diagnostic_modules: list[str] = Field(default_factory=list)
    approval_status: Literal["draft", "approved", "retired"] = "approved"
    last_updated: datetime = Field(default_factory=utc_now)


class BenchmarkMeasurement(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    workspace_id: UUID
    metric: str
    value: float
    unit: str
    data_source: str
    data_timestamp: datetime
    confidence_status: Literal["high", "medium", "low", "manual", "stale", "conflicting", "missing"] = "high"
    source_type: str = "manual"
    source_identifier: str = "manual-entry"
    dataset_version: str = "manual-v1"
    citations: list[Citation] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class BenchmarkMeasurementCreate(BaseModel):
    metric: str
    value: float
    unit: str
    data_source: str
    data_timestamp: datetime | None = None
    confidence_status: Literal["high", "medium", "low", "manual", "stale", "conflicting", "missing"] = "high"
    source_type: str = "manual"
    source_identifier: str = "manual-entry"
    dataset_version: str = "manual-v1"
    moc_reference: str | None = None


class BenchmarkComparison(BaseModel):
    metric: str
    benchmark_name: str
    current_value: float | None = None
    current_unit: str
    benchmark_value: float | None = None
    benchmark_unit: str
    absolute_variance: float | None = None
    percentage_variance: float | None = None
    performance_status: Literal[
        "Above benchmark",
        "Within expected range",
        "Below benchmark",
        "Critical deviation",
        "Insufficient data",
        "Stale data",
    ]
    supporting_source: str
    data_timestamp: datetime | None = None
    confidence_status: str


class DiagnosticAction(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    module: Literal["Hydraulics", "Torque & Drag"]
    status: Literal["Recommended", "Queued", "Running", "Completed", "Failed", "Dismissed"] = "Recommended"
    reason: str
    authorized_user: str | None = None
    timestamp: datetime = Field(default_factory=utc_now)
    dismissal_reason: str | None = None


class DiagnosticDismissRequest(BaseModel):
    reason: str


class AnomalyEvent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    workspace_id: UUID
    measurement_id: UUID | None = None
    metric: str
    severity: Literal["Advisory", "Warning", "Critical"]
    performance_status: str
    current_value: float
    unit: str
    threshold_value: float
    threshold_unit: str
    rule_id: UUID
    rule_name: str
    summary: str
    benchmark_evidence: dict[str, Any] = Field(default_factory=dict)
    supporting_citations: list[Citation] = Field(default_factory=list)
    diagnostic_actions: list[DiagnosticAction] = Field(default_factory=list)
    moc_reference: str | None = None
    status: Literal["active", "dismissed", "resolved"] = "active"
    created_at: datetime = Field(default_factory=utc_now)


class AiReportStatement(BaseModel):
    category: Literal[
        "Measured fact",
        "Calculated result",
        "Inferred explanation",
        "Risk assessment",
        "Recommended action",
    ]
    text: str
    review_status: Literal["review_required", "accepted", "rejected"] = "review_required"
    source_reference: str | None = None


class KeyDecision(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    workspace_id: UUID
    decision_timestamp: datetime
    decision_type: str
    title: str
    operational_context: str
    decision_made: str
    decision_owner: str
    supporting_evidence: list[Citation] = Field(default_factory=list)
    expected_impact: str
    actual_impact: str | None = None
    affected_depth_or_interval: str | None = None
    related_risks: list[str] = Field(default_factory=list)
    moc_reference: str | None = None
    approval_status: Literal["draft", "review", "approved", "rejected"] = "review"


class BenchmarkingStatus(BaseModel):
    workspace_id: UUID
    generated_at: datetime = Field(default_factory=utc_now)
    current_ft_per_day: float | None = None
    seven_day_average_ft_per_day: float | None = None
    gordon_average_benchmark: float | None = None
    noble_top_quartile_benchmark: float | None = None
    comparisons: list[BenchmarkComparison] = Field(default_factory=list)
    active_anomalies: list[AnomalyEvent] = Field(default_factory=list)
    historical_anomalies: list[AnomalyEvent] = Field(default_factory=list)
    benchmark_values: list[BenchmarkValue] = Field(default_factory=list)
    anomaly_rules: list[AnomalyRule] = Field(default_factory=list)
    seven_day_trend: list[dict[str, Any]] = Field(default_factory=list)
    likely_operational_contributors: list[str] = Field(default_factory=list)
    recommended_diagnostic_actions: list[DiagnosticAction] = Field(default_factory=list)
    supporting_evidence_references: list[str] = Field(default_factory=list)
    ai_interpretation: list[AiReportStatement] = Field(default_factory=list)
    permissions: dict[str, bool] = Field(default_factory=dict)


class BenchmarkConfigResponse(BaseModel):
    benchmark_values: list[BenchmarkValue] = Field(default_factory=list)
    anomaly_rules: list[AnomalyRule] = Field(default_factory=list)
    permissions: dict[str, bool] = Field(default_factory=dict)


class FailureRecord(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    workspace_id: UUID
    event_type: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    summary: str
    company: str = "unknown"
    tool_type: str = "unknown"
    tool_serial: str = "unknown"
    npt_hours: float = 0
    confidence: float = Field(ge=0, le=1)
    validation_status: ValidationStatus = ValidationStatus.OPEN
    citations: list[Citation] = Field(default_factory=list)


class ValidationTask(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    target_type: Literal["failure", "npt_event", "company", "tool", "citation", "file", "anomaly_event", "ai_statement"]
    target_id: UUID
    reason: str
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    status: ValidationStatus = ValidationStatus.OPEN
    resolution_note: str | None = None
    # Verified-reviewer attribution (AUDIT-001): the authenticated human who last
    # resolved/updated this task, copied server-side (never client-supplied).
    # reviewer_verified_at is set ONLY when the reviewer passed verification
    # (see FieldCorrection); a demo-bootstrap action is labelled but left unverified.
    reviewer_user_id: UUID | None = None
    reviewer_credential_id: UUID | None = None
    reviewer_credential_fingerprint: str | None = None
    reviewer_roles: list[Role] = Field(default_factory=list)
    reviewer_actor_source: Literal["configured", "authenticated", "demo_bootstrap", "system"] | None = None
    reviewer_verified_at: datetime | None = None
    created_at: datetime = Field(default_factory=utc_now)


class ValidationTaskUpdate(BaseModel):
    status: ValidationStatus
    resolution_note: str | None = None


# Field-level correction & review-provenance foundation.
#
# A FieldCorrection is a versioned overlay record: it captures an actor's
# correction to a registered extracted field WITHOUT overwriting the
# source-derived value or its lineage. The original extracted value is
# preserved on the record (source_value) and the underlying parsed
# document/profile is never mutated. Re-correcting the same field supersedes
# the prior record (a version chain) and reverting flips status, so a full
# who/what/from/to/when/why trail is retrievable.
#
# This is versioned history stored in the tenant snapshot, NOT an immutable
# append-only event log: superseding and reverting update the `status`/linkage
# of an already-persisted record. A tamper-resistant immutable-event model
# (and cross-process atomicity via normalized persistence) is tracked follow-up
# work; AUDIT-004 is a foundation, not fully closed.
#
# `actor_*` fields record the resolved request actor. With the authenticated
# identity foundation, a correction made by an authenticated request records
# `actor_source="authenticated"` (or `demo_bootstrap` for the local bootstrap
# identity); older records remain `configured`. A *verified reviewer identity*
# with review-role eligibility and review-workflow coverage remains a separate
# declared blocker — the presence of an authenticated actor alone does not
# resolve it.
FieldCorrectionTargetType = Literal[
    "report_field",
    "casing_string",
    "survey_station",
    "hydraulics_observation",
    "activity_segment",
    "failure",
]


class FieldCorrection(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    workspace_id: UUID
    target_type: FieldCorrectionTargetType
    field_key: str
    source_value: str | None = None
    corrected_value: str | None = None
    correction_reason: str
    actor_user_id: UUID
    actor_email: str
    actor_roles: list[Role] = Field(default_factory=list)
    # "configured" remains the default for old records; an authenticated request
    # records "authenticated"/"demo_bootstrap", a worker/CLI action "system".
    actor_source: Literal["configured", "authenticated", "demo_bootstrap", "system"] = "configured"
    actor_credential_fingerprint: str | None = None
    status: Literal["active", "superseded", "reverted"] = "active"
    supersedes_id: UUID | None = None
    superseded_by_id: UUID | None = None
    revert_reason: str | None = None
    # Verified-reviewer attribution (AUDIT-001): the request-scoped authenticated
    # human who RECORDED this correction, copied server-side (never client-supplied).
    # reviewer_verified_at is set ONLY when the reviewer passed verification
    # (authenticated + active non-bootstrap user + active credential + tenant-bound +
    # permission-eligible); a demo-bootstrap action is labelled but left unverified.
    reviewer_user_id: UUID | None = None
    reviewer_credential_id: UUID | None = None
    reviewer_credential_fingerprint: str | None = None
    reviewer_roles: list[Role] = Field(default_factory=list)
    reviewer_actor_source: Literal["configured", "authenticated", "demo_bootstrap", "system"] | None = None
    reviewer_verified_at: datetime | None = None
    # The reviewer who REVERTED (distinct from the recorder), set on revert.
    revert_reviewer_user_id: UUID | None = None
    revert_reviewer_credential_fingerprint: str | None = None
    revert_reviewer_roles: list[Role] = Field(default_factory=list)
    revert_reviewer_actor_source: Literal["configured", "authenticated", "demo_bootstrap", "system"] | None = None
    revert_reviewer_verified_at: datetime | None = None
    created_at: datetime = Field(default_factory=utc_now)


class FieldCorrectionCreate(BaseModel):
    target_type: FieldCorrectionTargetType
    field_key: str = Field(max_length=120)
    source_value: str | None = Field(default=None, max_length=200)
    corrected_value: str | None = Field(default=None, max_length=200)
    correction_reason: str = Field(min_length=1, max_length=500)


class FieldCorrectionRevert(BaseModel):
    revert_reason: str = Field(min_length=1, max_length=500)


class ChatRequest(BaseModel):
    workspace_id: UUID
    content: str
    filters: dict[str, Any] = Field(default_factory=dict)


class ChatWorkflowStep(BaseModel):
    step: str
    status: Literal["ready", "active", "blocked", "complete", "watch"]
    detail: str
    command: str | None = None


class ChatInsightCard(BaseModel):
    label: str
    value: str
    detail: str
    tone: Literal["good", "warning", "danger", "info"] = "info"


class ChatRiskItem(BaseModel):
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    detail: str
    mitigation: str


class ChatToolAction(BaseModel):
    label: str
    prompt: str
    detail: str
    kind: Literal["plan", "draft", "schematic", "audit", "export", "source"] = "plan"


class ChatResponse(BaseModel):
    answer: str
    citations: list[Citation] = Field(default_factory=list)
    followups: list[str] = Field(default_factory=list)
    confidence_notes: list[str] = Field(default_factory=list)
    export_actions: list[str] = Field(default_factory=list)
    workflow_steps: list[ChatWorkflowStep] = Field(default_factory=list)
    insight_cards: list[ChatInsightCard] = Field(default_factory=list)
    risk_register: list[ChatRiskItem] = Field(default_factory=list)
    tool_actions: list[ChatToolAction] = Field(default_factory=list)


class CasingString(BaseModel):
    """A single reviewed casing string for the well schematic.

    Rows either come from parsed source evidence (``source="source"`` with a
    ``page`` and ``confidence``) or are explicit reference geometry that a
    reviewer must confirm against the daily drilling report (``source="reference"``).
    Missing values stay missing; nothing is invented.
    """

    name: str = Field(min_length=1)
    od: str | None = None
    top_ft: float | None = Field(default=None, ge=0)
    shoe_ft: float | None = Field(default=None, ge=0)
    status: str | None = None
    source: Literal["source", "reference"]
    page: int | None = Field(default=None, ge=1)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class ActivitySegment(BaseModel):
    """A single reviewed 24-hour activity segment for the morning report.

    ``source="source"`` rows are parsed from timed source evidence with a
    ``page``/``confidence``; ``source="reference"`` rows are generic fallback
    guidance that must be confirmed against the DDR.
    """

    time: str = Field(min_length=1)
    activity: str = Field(min_length=1)
    source: Literal["source", "reference"]
    page: int | None = Field(default=None, ge=1)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class SurveyStation(BaseModel):
    """A single directional survey station extracted from source evidence.

    Survey stations are **source extraction only**: every row comes from an
    uploaded document (``source="source"`` with a ``page`` and ``confidence``).
    There is deliberately no reference fallback — fabricating generic survey
    geometry would be unsafe, so "no evidence" is represented by an empty list
    with ``survey_source="none"``. Optional engineering values (TVD, DLS,
    displacements) are populated only when explicitly present in the source;
    nothing is calculated or inferred.
    """

    measured_depth_ft: float = Field(ge=0)
    inclination_deg: float | None = Field(default=None, ge=0, le=180)
    azimuth_deg: float | None = Field(default=None, ge=0, le=360)
    true_vertical_depth_ft: float | None = Field(default=None, ge=0)
    dogleg_severity_dp100ft: float | None = Field(default=None, ge=0)
    north_south_ft: float | None = None
    east_west_ft: float | None = None
    station_id: str | None = None
    survey_type: str | None = None
    source: Literal["source"]
    page: int | None = Field(default=None, ge=1)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    conflict: bool = False


class TrajectoryCoordinateReference(BaseModel):
    """Per-axis anchoring mode for calculated trajectory positions.

    ``source_absolute`` means the axis starts from a source-stated value at the
    anchor station; ``relative_first_station`` values are offsets from the first
    calculated station and must never be presented as absolute well coordinates;
    ``none`` means nothing was calculable for that axis.
    """

    tvd: Literal["source_absolute", "relative_first_station", "none"]
    north_south: Literal["source_absolute", "relative_first_station", "none"]
    east_west: Literal["source_absolute", "relative_first_station", "none"]


class TrajectoryAnchor(BaseModel):
    measured_depth_ft: float = Field(ge=0)
    tvd_ft: float | None = None
    north_south_ft: float | None = None
    east_west_ft: float | None = None
    source_page: int | None = Field(default=None, ge=1)


class TrajectoryInterval(BaseModel):
    """One calculated minimum-curvature interval between two source stations.

    ``source="calculated"`` — this is derived geometry, never source evidence;
    ``input_confidence_min`` is the lowest source-extraction confidence among
    the two input stations, not a statement about numerical accuracy.
    """

    md_start_ft: float = Field(ge=0)
    md_end_ft: float = Field(ge=0)
    start_station_id: str | None = None
    end_station_id: str | None = None
    survey_type: str | None = None
    segment: int = Field(ge=1)
    dogleg_deg: float = Field(ge=0)
    dls_deg_per_100ft: float = Field(ge=0)
    ratio_factor: float = Field(ge=1.0)
    delta_tvd_ft: float
    delta_ns_ft: float
    delta_ew_ft: float
    source_pages: list[int] = Field(default_factory=list)
    input_confidence_min: float | None = Field(default=None, ge=0.0, le=1.0)
    source: Literal["calculated"]
    method: Literal["minimum_curvature"]
    method_version: str


class CalculatedTrajectoryStation(BaseModel):
    """Cumulative calculated position projected from a source station."""

    measured_depth_ft: float = Field(ge=0)
    tvd_ft: float
    north_south_ft: float
    east_west_ft: float
    # Lateral displacement magnitude from this station's own segment anchor
    # (never a global origin); unsigned, display-only.
    horizontal_displacement_ft: float = Field(ge=0)
    source_station_id: str | None = None
    source_page: int | None = Field(default=None, ge=1)
    segment: int = Field(ge=1)
    survey_type: str | None = None
    coordinate_reference: TrajectoryCoordinateReference
    source: Literal["calculated"]


class TrajectorySkipSummary(BaseModel):
    conflict: int = Field(default=0, ge=0)
    missing_inclination: int = Field(default=0, ge=0)
    missing_azimuth: int = Field(default=0, ge=0)
    invalid_numeric: int = Field(default=0, ge=0)
    zero_md_interval: int = Field(default=0, ge=0)
    decreasing_md: int = Field(default=0, ge=0)
    survey_type_boundary: int = Field(default=0, ge=0)
    antipodal_singularity: int = Field(default=0, ge=0)
    truncated: int = Field(default=0, ge=0)


class TrajectoryCalculation(BaseModel):
    """Minimum-curvature calculation block — structurally separate from source.

    Source survey stations are never modified; every value here carries
    calculated provenance and ``review_state="review_required"``. This is a
    deterministic drafting aid, not certified directional-survey software
    (see docs/TRAJECTORY_CALCULATION.md).
    """

    method: Literal["minimum_curvature"]
    method_version: str
    review_state: Literal["review_required"] = "review_required"
    coordinate_reference: TrajectoryCoordinateReference
    anchor: TrajectoryAnchor | None = None
    source_station_count: int = Field(ge=0)
    eligible_station_count: int = Field(ge=0)
    segment_count: int = Field(ge=0)
    interval_count: int = Field(ge=0)
    intervals: list[TrajectoryInterval] = Field(default_factory=list)
    stations: list[CalculatedTrajectoryStation] = Field(default_factory=list)
    skips: TrajectorySkipSummary = Field(default_factory=TrajectorySkipSummary)
    input_confidence_min: float | None = Field(default=None, ge=0.0, le=1.0)


class HydraulicObservation(BaseModel):
    """A single source-derived hydraulics observation.

    Source extraction only: values come from explicitly labelled source text or
    tables with explicit, recognized units — nothing is calculated, inferred,
    or converted ambiguously. Observations are informational and review-
    required; Hydraulics and Torque & Drag diagnostics remain recommended-only
    and are never created, triggered, or altered by extraction. "No evidence"
    is an empty list with ``hydraulics_source="none"`` — there is no fallback.
    """

    measurement: Literal[
        "flow_rate",
        "standpipe_pressure",
        "mud_weight",
        "ecd",
        "plastic_viscosity",
        "yield_point",
        "pump_rate",
        "nozzle_configuration",
    ]
    value: float | None = None
    unit: str | None = None
    source_value_text: str = Field(min_length=1)
    source_unit: str | None = None
    observation_status: Literal["observed", "planned", "unknown"] = "unknown"
    equipment_label: str | None = None
    fluid_system_label: str | None = None
    context_note: str | None = None
    activity_time: str | None = None
    activity_time_source_text: str | None = None
    parser_method: Literal["deterministic_hydraulics"] = "deterministic_hydraulics"
    parser_version: str = "v1"
    source: Literal["source"]
    page: int | None = Field(default=None, ge=1)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    conflict: bool = False
    review_flag: bool = False
    review_reason: str | None = None


class ReportDraftResponse(BaseModel):
    workspace_id: UUID
    generated_at: datetime = Field(default_factory=utc_now)
    report_date: date = Field(default_factory=lambda: utc_now().date())
    report_no: str
    well: str
    rig: str
    operator: str
    phase: str
    hole_size: str
    md_ft: str
    tvd_ft: str
    mud_weight: str
    present_ops: str
    next_ops: str
    safety: str
    risks: str
    casing_program: str
    operations_log: str
    casing_strings: list[CasingString] = Field(default_factory=list)
    activity_timeline: list[ActivitySegment] = Field(default_factory=list)
    schematic_source: Literal["source", "reference"] = "reference"
    survey_stations: list[SurveyStation] = Field(default_factory=list)
    survey_source: Literal["source", "none"] = "none"
    trajectory: TrajectoryCalculation | None = None
    trajectory_source: Literal["calculated", "none"] = "none"
    hydraulics_observations: list[HydraulicObservation] = Field(default_factory=list)
    hydraulics_source: Literal["source", "none"] = "none"
    # Active reviewer corrections surfaced as review-required overlays; they
    # never overwrite the source-derived values above.
    field_corrections: list[FieldCorrection] = Field(default_factory=list)
    evidence_summary: list[str] = Field(default_factory=list)
    source_document_count: int
    source_chunk_count: int
    failure_count: int
    open_validation_tasks: int
    citation_count: int
    validation_gate: Literal["clear", "review_required"]
    citations: list[Citation] = Field(default_factory=list)
    confidence_notes: list[str] = Field(default_factory=list)


class DashboardSummary(BaseModel):
    total_failures: int
    total_npt_hours: float
    validation_backlog: int
    high_or_critical_failures: int
    average_confidence: float


class ClientDataReadinessCheck(BaseModel):
    id: str
    label: str
    status: Literal["pass", "warn", "fail"]
    detail: str
    remediation: str
    # Additive, optional GA-integrity metadata (legacy consumers ignore these).
    disposition: Literal[
        "PASS", "FAIL", "BLOCKED", "SKIPPED", "NOT_APPLICABLE", "REVIEW_REQUIRED"
    ] | None = None
    category: (
        Literal[
            "software",
            "configuration",
            "infrastructure",
            "security_review",
            "data_review_evidence",
            "client_approval",
        ]
        | None
    ) = None
    severity: Literal["blocker", "high", "medium", "low"] | None = None
    owner_type: (
        Literal["engineering", "security", "platform", "operations", "data_review", "client_organization"]
        | None
    ) = None
    policy_reference: str | None = None
    evidence_reference: str | None = None
    resolution_condition: str | None = None
    applicability_justification: str | None = None


class ClientDataReadiness(BaseModel):
    mode: Literal["demo", "client"]
    status: Literal["ready", "not_ready"]
    ready: bool
    generated_at: datetime = Field(default_factory=utc_now)
    checks: list[ClientDataReadinessCheck] = Field(default_factory=list)


class LocalAIStatus(BaseModel):
    runtime: Literal["ollama", "lm_studio", "unconfigured"]
    configured: bool
    reachable: bool
    model_available: bool = False
    endpoint: str | None = None
    model: str | None = None
    hosted_fallback_enabled: bool = False
    detail: str
    # Which provider actually answers Ask right now, from the server-side resolver's
    # decision (not reachability): "deterministic" (built-in analysis) or "local-model".
    active_provider: str = "deterministic"


class ProviderStatusView(BaseModel):
    # Minimal, chat-role-readable provenance: which engine writes answers right now.
    # "deterministic" | "local-model" | "online-api". Readable by anyone who can chat so
    # the Ask surface is honest for every role (never a false "no external calls" claim).
    active_provider: str = "deterministic"


class OnlineAiConfigView(BaseModel):
    # Non-secret view of the optional Online AI config. The API key is NEVER included —
    # only ``has_key`` reports whether one is stored.
    configured: bool = False
    provider: str | None = None
    base_url: str | None = None
    model: str | None = None
    has_key: bool = False
    updated_at: str | None = None
    storage_available: bool = True
    detail: str = ""


class OnlineAiSettingsRequest(BaseModel):
    provider: str
    base_url: str
    model: str
    api_key: str


class OnlineTestConnectionResult(BaseModel):
    # status ∈ connected | auth_failed | rate_limited | unavailable | misconfigured.
    # Never carries a raw provider body, exception, or the API key.
    status: str
    detail: str


class RuntimeBackendStatus(BaseModel):
    requested_repository_backend: str
    active_repository_backend: str
    database_url_configured: bool
    repository_ready: bool
    requested_queue_backend: str
    active_queue_backend: str
    redis_url_configured: bool
    queue_ready: bool
    client_data_ready: bool
    blocking_checks: list[str] = Field(default_factory=list)


class MondayReportCreate(BaseModel):
    workspace_id: UUID
    period_start: date
    period_end: date


class MondayReport(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    workspace_id: UUID
    period_start: date
    period_end: date
    status: Literal["draft", "review", "approved", "exported"] = "draft"
    report_json: dict[str, Any]
    created_at: datetime = Field(default_factory=utc_now)


class ReportExport(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    report_id: UUID
    format: Literal["json", "csv", "html", "pdf", "xlsx"]
    storage_uri: str
    sha256: str
    byte_size: int
    created_at: datetime = Field(default_factory=utc_now)


class SignedUrlResponse(BaseModel):
    url: str
    expires_at: datetime


class RetentionRunResult(BaseModel):
    mode: Literal["dry_run", "applied"]
    retention_days: int
    cutoff: datetime
    uploads: int = 0
    upload_files: int = 0
    processing_jobs: int = 0
    parsed_documents: int = 0
    document_chunks: int = 0
    failures: int = 0
    validation_tasks: int = 0
    monday_reports: int = 0
    report_exports: int = 0
    storage_objects: int = 0
    export_objects: int = 0


class AuditLog(BaseModel):
    # FROZEN: a sealed audit entry is immutable. The working projection shares
    # published entry OBJECTS by reference (the audit_logs list is shallow-copied
    # per transaction), so making the entry itself immutable is what keeps that
    # copy provably safe -- an attempt to reassign any field of an entry already in
    # the published projection raises instead of silently corrupting it. New entries
    # are built complete (entry_hash via model_copy) before being appended.
    model_config = ConfigDict(frozen=True)

    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    actor_user_id: UUID
    action: str
    resource_type: str
    resource_id: UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    previous_hash: str | None = None
    entry_hash: str | None = None
    # Additive actor provenance (default None/[] for old snapshots).
    actor_source: str | None = None
    actor_roles: list[Role] = Field(default_factory=list)
    actor_credential_fingerprint: str | None = None
    # Additive versioned-integrity envelope (default None for legacy/v1 events).
    # A v2 event sets integrity_version=2 and records the HMAC algorithm + the key
    # id/version used to seal it; verification selects the key by these fields.
    # Legacy events keep integrity_version=None and remain unkeyed SHA-256.
    integrity_version: int | None = None
    integrity_algorithm: str | None = None
    key_id: str | None = None
    key_version: int | None = None


class AuditIntegrityStatus(BaseModel):
    # `status` is preserved additively for existing consumers: "sealed" means the
    # hash chain is intact (keyed OR legacy) — it is NOT a claim of keying. The
    # keyed distinction lives in `integrity_state` and the counts below.
    status: Literal["empty", "sealed", "legacy", "broken"]
    total_events: int
    hashed_events: int
    legacy_events: int
    broken_events: int
    latest_hash: str | None = None
    detail: str
    # Additive versioned-integrity view (legacy consumers ignore these).
    # `integrity_state`: empty | legacy_valid | mixed_valid | keyed_valid | broken |
    # key_unavailable. legacy_valid/mixed_valid are NOT fully keyed.
    integrity_state: (
        Literal["empty", "legacy_valid", "mixed_valid", "keyed_valid", "broken", "key_unavailable"] | None
    ) = None
    legacy_event_count: int = 0
    keyed_event_count: int = 0
    active_key_id: str | None = None
    active_key_version: int | None = None
    unknown_key_versions: list[str] = Field(default_factory=list)
    first_broken_event_id: str | None = None
