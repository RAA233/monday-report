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
    target_type: Literal["failure", "npt_event", "company", "tool", "citation", "file"]
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
