from __future__ import annotations

from datetime import date, datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


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


class SessionResponse(BaseModel):
    tenant: Tenant
    user: User


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
    created_at: datetime = Field(default_factory=utc_now)


class ValidationTaskUpdate(BaseModel):
    status: ValidationStatus
    resolution_note: str | None = None


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


class AuditIntegrityStatus(BaseModel):
    status: Literal["empty", "sealed", "legacy", "broken"]
    total_events: int
    hashed_events: int
    legacy_events: int
    broken_events: int
    latest_hash: str | None = None
    detail: str
