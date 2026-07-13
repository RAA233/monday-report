from __future__ import annotations

import json
import os
import re
from statistics import mean
from typing import Literal
from uuid import UUID

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from .auth import API_KEY_HEADER, api_key_configured, api_key_valid
from .limits import max_upload_bytes, upload_too_large
from .local_ai import evaluate_local_ai_status
from .retention import retention_days
from .schemas import (
    AuditIntegrityStatus,
    AuditLog,
    ChatRequest,
    ChatResponse,
    ClientDataReadiness,
    DashboardSummary,
    DocumentChunk,
    FailureRecord,
    LocalAIStatus,
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
    UploadCompleteRequest,
    UploadCreate,
    UploadCreateResponse,
    UploadFileRecord,
    ValidationTask,
    ValidationTaskUpdate,
    Workspace,
    WorkspaceCreate,
)
from .readiness import client_data_mode, evaluate_client_data_readiness
from .runtime_backends import runtime_backend_status
from .signed_urls import create_signed_token, signing_secret_configured, verify_signed_token
from .store import store

app = FastAPI(
    title="Monday Report API",
    version="0.1.0",
    description="Local-AI-first API scaffold for rig-report intelligence.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        *[
            origin.strip()
            for origin in os.getenv("MONDAY_REPORT_CORS_ORIGINS", "").split(",")
            if origin.strip()
        ],
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


CLIENT_AUTH_EXEMPT_PATHS = {
    "/health",
    "/readiness/client-data",
    "/runtime/backends",
    "/local-ai/status",
    "/audit-logs/integrity",
}


@app.middleware("http")
async def enforce_client_api_key(request: Request, call_next):
    if _client_auth_exempt(request):
        return await call_next(request)
    if client_data_mode() != "client":
        return await call_next(request)

    if not api_key_configured():
        store.audit(
            "api.auth_blocked",
            "api",
            None,
            {"reason": "api_key_not_configured", "path": request.url.path, "method": request.method},
        )
        return JSONResponse(
            status_code=503,
            content={"detail": "Client API key is not configured"},
        )

    supplied_key = request.headers.get(API_KEY_HEADER)
    if not api_key_valid(supplied_key):
        store.audit(
            "api.auth_blocked",
            "api",
            None,
            {"reason": "invalid_or_missing_api_key", "path": request.url.path, "method": request.method},
        )
        return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})

    return await call_next(request)


def _client_auth_exempt(request: Request) -> bool:
    if request.method == "OPTIONS":
        return True
    if request.url.path in CLIENT_AUTH_EXEMPT_PATHS:
        return True
    return request.method == "GET" and request.url.path.startswith("/signed/")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "monday-report-api"}


@app.get("/auth/session", response_model=SessionResponse)
def session() -> SessionResponse:
    store.refresh()
    return SessionResponse(tenant=store.tenant, user=store.user)


@app.get("/readiness/client-data", response_model=ClientDataReadiness)
def client_data_readiness() -> ClientDataReadiness:
    return evaluate_client_data_readiness(store)


@app.get("/runtime/backends", response_model=RuntimeBackendStatus)
def runtime_backends() -> RuntimeBackendStatus:
    return runtime_backend_status(evaluate_client_data_readiness(store), store)


@app.get("/local-ai/status", response_model=LocalAIStatus)
def local_ai_status() -> LocalAIStatus:
    store.refresh()
    return evaluate_local_ai_status(store.tenant.local_llm_policy)


def require_client_data_ready(operation: str, resource_type: str, resource_id: UUID | None = None) -> None:
    if client_data_mode() != "client":
        return
    readiness = evaluate_client_data_readiness(store)
    if readiness.ready:
        return
    blocking_checks = [check.id for check in readiness.checks if check.status == "fail"]
    warning_checks = [check.id for check in readiness.checks if check.status == "warn"]
    store.audit(
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


@app.get("/workspaces", response_model=list[Workspace])
def list_workspaces() -> list[Workspace]:
    store.refresh()
    return list(store.workspaces.values())


@app.post("/workspaces", response_model=Workspace, status_code=status.HTTP_201_CREATED)
def create_workspace(payload: WorkspaceCreate) -> Workspace:
    return store.create_workspace(payload)


@app.post("/uploads", response_model=UploadCreateResponse, status_code=status.HTTP_201_CREATED)
def create_upload(payload: UploadCreate) -> UploadCreateResponse:
    store.refresh()
    require_client_data_ready("upload.create", "workspace", payload.workspace_id)
    if payload.workspace_id not in store.workspaces:
        raise HTTPException(status_code=404, detail="Workspace not found")
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
    if client_data_mode() == "client":
        require_client_data_ready("upload.direct", "workspace", workspace_id)
    else:
        store.refresh()
    if workspace_id not in store.workspaces:
        raise HTTPException(status_code=404, detail="Workspace not found")

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
    upload, file_record, signed_url = store.create_uploaded_file(
        workspace_id=workspace_id,
        file_name=original_name,
        mime_type=file.content_type or "application/octet-stream",
        source_type=source_type,
        content=content,
        refresh=False,
        save=False,
    )
    if file_record.malware_status == "blocked":
        store.save()
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
    if upload_id not in store.uploads:
        raise HTTPException(status_code=404, detail="Upload not found")
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
    if upload_id not in store.uploads:
        raise HTTPException(status_code=404, detail="Upload not found")
    require_client_data_ready("upload.files.list", "upload", upload_id)
    return [file for file in store.files.values() if file.upload_id == upload_id]


@app.get("/processing-jobs", response_model=list[ProcessingJob])
def list_processing_jobs(
    upload_id: UUID | None = None,
    status_filter: ProcessingStatus | None = None,
) -> list[ProcessingJob]:
    store.refresh()
    require_client_data_ready("processing_jobs.list", "processing_job", None)
    jobs = list(store.jobs.values())
    if upload_id:
        jobs = [job for job in jobs if job.upload_id == upload_id]
    if status_filter:
        jobs = [job for job in jobs if job.status == status_filter]
    return jobs


@app.get("/documents", response_model=list[ParsedDocument])
def list_documents(workspace_id: UUID | None = None) -> list[ParsedDocument]:
    store.refresh()
    require_client_data_ready("documents.list", "workspace", workspace_id)
    documents = list(store.parsed_documents.values())
    if workspace_id:
        documents = [document for document in documents if document.workspace_id == workspace_id]
    return documents


@app.get("/documents/{document_id}/chunks", response_model=list[DocumentChunk])
def list_document_chunks(document_id: UUID) -> list[DocumentChunk]:
    store.refresh()
    if document_id not in store.parsed_documents:
        raise HTTPException(status_code=404, detail="Document not found")
    require_client_data_ready("documents.chunks.list", "parsed_document", document_id)
    chunks = [chunk for chunk in store.document_chunks.values() if chunk.document_id == document_id]
    return sorted(chunks, key=lambda item: item.ordinal)


@app.get("/audit-logs", response_model=list[AuditLog])
def list_audit_logs(limit: int = 50) -> list[AuditLog]:
    store.refresh()
    bounded_limit = min(max(limit, 1), 200)
    return list(reversed(store.audit_logs))[:bounded_limit]


@app.get("/audit-logs/integrity", response_model=AuditIntegrityStatus)
def audit_log_integrity() -> AuditIntegrityStatus:
    return store.audit_integrity_status()


@app.post("/retention/run", response_model=RetentionRunResult)
def run_retention(apply: bool = False) -> RetentionRunResult:
    store.refresh()
    require_client_data_ready("retention.run", "tenant", store.tenant.id)
    return store.run_retention(retention_days(), apply=apply)


@app.get("/validation-tasks", response_model=list[ValidationTask])
def list_validation_tasks() -> list[ValidationTask]:
    store.refresh()
    require_client_data_ready("validation_tasks.list", "validation_task", None)
    return list(store.validation_tasks.values())


@app.patch("/validation-tasks/{task_id}", response_model=ValidationTask)
def update_validation_task(task_id: UUID, payload: ValidationTaskUpdate) -> ValidationTask:
    store.refresh()
    if task_id not in store.validation_tasks:
        raise HTTPException(status_code=404, detail="Validation task not found")
    require_client_data_ready("validation_task.update", "validation_task", task_id)
    return store.update_validation_task(task_id, payload)


@app.get("/dashboards/summary", response_model=DashboardSummary)
def dashboard_summary(workspace_id: UUID | None = None) -> DashboardSummary:
    store.refresh()
    require_client_data_ready("dashboard.summary", "workspace", workspace_id)
    failures = list(store.failures.values())
    if workspace_id:
        failures = [failure for failure in failures if failure.workspace_id == workspace_id]
    confidences = [failure.confidence for failure in failures]
    return DashboardSummary(
        total_failures=len(failures),
        total_npt_hours=sum(failure.npt_hours for failure in failures),
        validation_backlog=len(
            [task for task in store.validation_tasks.values() if task.status.value == "open"]
        ),
        high_or_critical_failures=len(
            [failure for failure in failures if failure.severity in {"High", "Critical"}]
        ),
        average_confidence=mean(confidences) if confidences else 0,
    )


@app.get("/failures", response_model=list[FailureRecord])
def list_failures(workspace_id: UUID | None = None) -> list[FailureRecord]:
    store.refresh()
    require_client_data_ready("failures.list", "workspace", workspace_id)
    failures = list(store.failures.values())
    if workspace_id:
        failures = [failure for failure in failures if failure.workspace_id == workspace_id]
    return failures


def chat_insight_cards(failures: list[FailureRecord], documents: list, chunk_count: int, open_tasks: int) -> list[dict[str, str]]:
    high_count = len([failure for failure in failures if failure.severity in {"High", "Critical"}])
    total_npt = sum(failure.npt_hours for failure in failures)
    return [
        {
            "label": "Evidence",
            "value": f"{len(documents)} docs / {chunk_count} chunks",
            "detail": "Parsed source scope available to the local analyst.",
            "tone": "good" if documents else "warning",
        },
        {
            "label": "Failures",
            "value": f"{len(failures)} records",
            "detail": f"{high_count} high/critical item(s), {total_npt:.1f} NPT hours.",
            "tone": "danger" if high_count else "info",
        },
        {
            "label": "Validation Gate",
            "value": "clear" if open_tasks == 0 else f"{open_tasks} open",
            "detail": "Official exports remain validation-gated in client mode.",
            "tone": "good" if open_tasks == 0 else "warning",
        },
        {
            "label": "Export Stack",
            "value": "PDF XLSX HTML CSV JSON",
            "detail": "Signed exports are available after the approval gate.",
            "tone": "info",
        },
    ]


def chat_workflow_steps(open_tasks: int, documents: list, failures: list[FailureRecord]) -> list[dict[str, str]]:
    gate_status = "ready" if open_tasks == 0 else "blocked"
    return [
        {
            "step": "Ingest",
            "status": "complete" if documents else "watch",
            "detail": "Parse uploaded reports, tables, email notes, OCR text, and source locators.",
            "command": "Show parsed source evidence",
        },
        {
            "step": "Extract",
            "status": "complete" if failures else "watch",
            "detail": "Create structured failures, NPT, company/tool attribution, confidence, and citations.",
            "command": "Show high-NPT failures",
        },
        {
            "step": "Plan",
            "status": "ready",
            "detail": "Map evidence into normal daily-report sections, casing, risk, and next 24 hr plan.",
            "command": "Plan next morning report",
        },
        {
            "step": "Draft",
            "status": "ready",
            "detail": "Generate client-readable Monday Report language while preserving source-backed constraints.",
            "command": "Create draft report",
        },
        {
            "step": "Schematic",
            "status": "ready",
            "detail": "Render casing strings, hole sections, current depth, shoe depths, and risk markers.",
            "command": "Build casing schematic",
        },
        {
            "step": "Export",
            "status": gate_status,
            "detail": "Package signed PDF/XLSX/HTML/CSV/JSON artifacts after validation closure.",
            "command": "Generate Monday Report",
        },
    ]


def chat_risk_register(open_tasks: int, documents: list, failures: list[FailureRecord]) -> list[dict[str, str]]:
    total_npt = sum(failure.npt_hours for failure in failures)
    high_count = len([failure for failure in failures if failure.severity in {"High", "Critical"}])
    risks = [
        {
            "title": "Validation backlog",
            "severity": "high" if open_tasks else "low",
            "detail": f"{open_tasks} validation task(s) are open.",
            "mitigation": "Close or countersign validation tasks before official issue.",
        },
        {
            "title": "Evidence coverage",
            "severity": "medium" if not documents else "low",
            "detail": f"{len(documents)} parsed document(s) are available for this workspace.",
            "mitigation": "Import the latest DDR, BHA, mud, survey, and service-company files before client signoff.",
        },
        {
            "title": "Operational severity",
            "severity": "high" if high_count or total_npt >= 8 else "medium",
            "detail": f"{high_count} high/critical item(s), {total_npt:.1f} NPT hour(s).",
            "mitigation": "Prioritize high-NPT failures and confirm company/tool attribution with citations.",
        },
    ]
    return risks


def chat_tool_actions() -> list[dict[str, str]]:
    return [
        {
            "label": "Plan DDR",
            "prompt": "Plan next morning report",
            "detail": "Build the normal report section map and approval path.",
            "kind": "plan",
        },
        {
            "label": "Draft Report",
            "prompt": "Create draft report",
            "detail": "Generate report language using current evidence and validation status.",
            "kind": "draft",
        },
        {
            "label": "Draw Schematic",
            "prompt": "Build casing schematic",
            "detail": "Create casing, hole-section, depth, and risk-marker instructions.",
            "kind": "schematic",
        },
        {
            "label": "Audit Gate",
            "prompt": "Show unresolved validation tasks",
            "detail": "Review blockers before official export.",
            "kind": "audit",
        },
    ]


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


def report_draft_casing_program(source_text: str) -> str:
    if re.search(r"\b(casing|shoe|liner|cement)\b", source_text, flags=re.IGNORECASE):
        status = "Source confirm"
    else:
        status = "Reference"
    return "\n".join(
        [
            f"Conductor | 20 in | 0 | 130 | {status}",
            f"Surface | 13.375 in | 0 | 1629 | {status}",
            f"Intermediate | 9.625 in | 0 | 6500 | {status}",
            f"Production | 7 in | 0 | 10987 | {status}",
        ]
    )


def report_draft_operations_log(document_titles: list[str], failure_count: int, open_task_count: int) -> str:
    latest_sources = ", ".join(document_titles[:3]) if document_titles else "no parsed source titles yet"
    return "\n".join(
        [
            f"00:00-06:00 | Review latest source package: {latest_sources}.",
            f"06:00-12:00 | Reconcile {failure_count} extracted failure/NPT record(s) with citations.",
            "12:00-18:00 | Confirm drilling parameters, mud/BHA/survey, casing, and safety barriers from source evidence.",
            f"18:00-24:00 | Close {open_task_count} validation task(s) before issuing branded PDF/XLSX outputs.",
        ]
    )


def report_draft_pdf_profiles(documents: list) -> list[dict[str, object]]:
    profiles: list[dict[str, object]] = []
    for document in documents:
        metadata = getattr(document, "metadata", {})
        if not isinstance(metadata, dict):
            continue
        parser_metadata = metadata.get("parser", {})
        if not isinstance(parser_metadata, dict):
            continue
        profile = parser_metadata.get("report_profile")
        if isinstance(profile, dict):
            profiles.append(profile)
    return sorted(
        profiles,
        key=lambda item: (
            float(item.get("confidence", 0)) if isinstance(item.get("confidence"), (int, float)) else 0,
            int(item.get("field_count", 0)) if isinstance(item.get("field_count"), int) else 0,
            int(item.get("section_count", 0)) if isinstance(item.get("section_count"), int) else 0,
        ),
        reverse=True,
    )


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
    if workspace_id not in store.workspaces:
        raise HTTPException(status_code=404, detail="Workspace not found")
    require_client_data_ready("report_draft.generate", "workspace", workspace_id)

    workspace = store.workspaces[workspace_id]
    documents = sorted(
        [document for document in store.parsed_documents.values() if document.workspace_id == workspace_id],
        key=lambda item: item.created_at,
        reverse=True,
    )
    chunks = sorted(
        [chunk for chunk in store.document_chunks.values() if chunk.workspace_id == workspace_id and chunk.text.strip()],
        key=lambda item: item.created_at,
        reverse=True,
    )
    failures = sorted(
        [failure for failure in store.failures.values() if failure.workspace_id == workspace_id],
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
    time_from_pdf = report_draft_profile_section(pdf_profiles, "time_breakdown")

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
    operations_log = report_draft_operations_log(document_titles, len(failures), len(open_tasks))
    if time_from_pdf:
        operations_log = f"00:00-06:00 | {time_from_pdf}\n" + "\n".join(operations_log.splitlines()[1:])

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
        casing_program=report_draft_casing_program(source_text),
        operations_log=operations_log,
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
        },
    )
    return response


@app.post("/chat/messages", response_model=ChatResponse)
def chat(payload: ChatRequest) -> ChatResponse:
    store.refresh()
    require_client_data_ready("chat.message", "workspace", payload.workspace_id)
    failures = [
        failure for failure in store.failures.values() if failure.workspace_id == payload.workspace_id
    ]
    documents = [
        document for document in store.parsed_documents.values() if document.workspace_id == payload.workspace_id
    ]
    chunk_count = sum(document.chunk_count for document in documents)
    normalized = payload.content.lower()
    citations = dedupe_citations(
        store.parsed_citations_for_workspace(payload.workspace_id)
        + [citation for failure in failures for citation in failure.citations]
    )
    open_tasks = store._open_validation_tasks_for_workspace(payload.workspace_id)
    insight_cards = chat_insight_cards(failures, documents, chunk_count, len(open_tasks))
    workflow_steps = chat_workflow_steps(len(open_tasks), documents, failures)
    risk_register = chat_risk_register(len(open_tasks), documents, failures)
    tool_actions = chat_tool_actions()

    store.audit(
        "chat.message",
        "workspace",
        payload.workspace_id,
        {"prompt": payload.content[:180], "mode": "local_ai_api_scaffold"},
    )

    wants_report_workflow = any(
        term in normalized
        for term in [
            "monday report",
            "morning report",
            "daily report",
            "generate",
            "draft",
            "schematic",
            "plan",
            "execute",
            "client package",
            "export",
        ]
    )
    if wants_report_workflow:
        validation_phrase = (
            f"{len(open_tasks)} validation task(s) must close before official issue"
            if open_tasks
            else "validation gate is clear for official export"
        )
        return ChatResponse(
            answer=(
                f"Draft Monday Report workflow is ready from {len(failures)} extracted failures and "
                f"{sum(failure.npt_hours for failure in failures):.1f} NPT hours. "
                "Plan: normalize the source daily-report format into well/job information, present operations, drilling parameters, mud/BHA/survey, casing, timeline, NPT, risks, and approvals. "
                "Execute: generate the branded report, render the well schematic, attach citations, then export PDF/XLSX/HTML/CSV/JSON after the approval gate. "
                f"Current gate: {validation_phrase}."
            ),
            citations=citations,
            followups=[
                "Plan next morning report",
                "Build casing schematic",
                "Create draft report",
                "Show unresolved validation tasks",
            ],
            confidence_notes=[
                "Response uses local source chunks plus structured failure data.",
                "AI may plan and draft immediately, but official exports stay blocked by validation policy.",
            ],
            workflow_steps=workflow_steps,
            insight_cards=insight_cards,
            risk_register=risk_register,
            tool_actions=tool_actions,
            export_actions=[
                "monday_report_pdf",
                "monday_report_xlsx",
                "monday_report_html",
                "monday_report_csv",
                "monday_report_json",
            ],
        )

    if any(term in normalized for term in ["uploaded", "parsed", "source", "evidence", "file"]):
        return ChatResponse(
            answer=(
                f"Parsed evidence is available from {len(documents)} uploaded document(s) "
                f"with {chunk_count} source chunk(s). The worker stores chunk lineage by file, "
                "upload, workspace, and tenant before local AI extraction runs."
            ),
            citations=citations,
            followups=["Show unresolved validation tasks", "Generate Monday Report"],
            confidence_notes=["This answer uses parser-worker chunks plus seeded structured failure data."],
            workflow_steps=workflow_steps,
            insight_cards=insight_cards,
            risk_register=risk_register,
            tool_actions=tool_actions,
        )

    if "npt" in normalized:
        return ChatResponse(
            answer=(
                f"Current extracted evidence shows {sum(failure.npt_hours for failure in failures):.1f} "
                "NPT hours linked to failure records."
            ),
            citations=citations,
            followups=["Break NPT down by company", "Show high-NPT failures"],
            workflow_steps=workflow_steps,
            insight_cards=insight_cards,
            risk_register=risk_register,
            tool_actions=tool_actions,
        )

    return ChatResponse(
        answer=(
            f"I found {len(failures)} extracted failure record(s). "
            "The current executable slice is API-ready for local AI extraction workers."
        ),
        citations=citations,
        followups=["What failed this week?", "Which company caused most NPT?", "Generate Monday Report"],
        workflow_steps=workflow_steps,
        insight_cards=insight_cards,
        risk_register=risk_register,
        tool_actions=tool_actions,
    )


@app.post("/monday-reports", response_model=MondayReport, status_code=status.HTTP_201_CREATED)
def create_monday_report(payload: MondayReportCreate) -> MondayReport:
    store.refresh()
    if payload.workspace_id not in store.workspaces:
        raise HTTPException(status_code=404, detail="Workspace not found")
    require_client_data_ready("monday_report.create", "workspace", payload.workspace_id)
    return store.create_monday_report(payload)


@app.get("/monday-reports", response_model=list[MondayReport])
def list_monday_reports(workspace_id: UUID | None = None) -> list[MondayReport]:
    store.refresh()
    require_client_data_ready("monday_reports.list", "workspace", workspace_id)
    reports = list(store.monday_reports.values())
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
    if report_id not in store.monday_reports:
        raise HTTPException(status_code=404, detail="Monday Report not found")
    require_client_data_ready("monday_report.export", "monday_report", report_id)
    open_tasks = store.report_open_validation_tasks(report_id)
    if open_tasks and (not allow_unresolved_validation or client_data_mode() == "client"):
        report = store.monday_reports[report_id]
        report.status = "review"
        if isinstance(report.report_json, dict):
            report.report_json["validation"] = {
                "open_tasks": len(open_tasks),
                "status": "requires_review",
            }
        store.audit(
            "monday_report.export_blocked",
            "monday_report",
            report_id,
            {
                "format": export_format,
                "open_validation_tasks": len(open_tasks),
                "override_requested": allow_unresolved_validation,
                "validation_task_ids": [str(task.id) for task in open_tasks],
            },
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
    if export_id not in store.report_exports:
        raise HTTPException(status_code=404, detail="Report export not found")
    if client_data_mode() == "client" and not signing_secret_configured():
        store.audit(
            "report_export.signed_url_blocked",
            "report_export",
            export_id,
            {"reason": "missing_signing_secret_client_mode"},
        )
        raise HTTPException(status_code=409, detail="Signing secret is required in client data mode")
    require_client_data_ready("report_export.signed_url", "report_export", export_id)

    token, expires_at = create_signed_token(export_id, "report_export_download")
    path = f"/signed/report-exports/{export_id}?token={token}"
    url = str(request.base_url).rstrip("/") + path
    report_export = store.report_exports[export_id]
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
    if not verify_signed_token(token, export_id, "report_export_download"):
        raise HTTPException(status_code=403, detail="Invalid or expired signed URL")

    report_export = store.report_exports[export_id]
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
    if file_id not in store.files:
        raise HTTPException(status_code=404, detail="Upload file not found")
    if client_data_mode() == "client" and not signing_secret_configured():
        store.audit(
            "upload_file.signed_url_blocked",
            "upload_file",
            file_id,
            {"reason": "missing_signing_secret_client_mode"},
        )
        raise HTTPException(status_code=409, detail="Signing secret is required in client data mode")
    require_client_data_ready("upload_file.signed_url", "upload_file", file_id)
    file_record = store.files[file_id]
    if file_record.malware_status == "blocked" or not file_record.storage_uri.startswith("object://"):
        raise HTTPException(status_code=409, detail="Upload file is not downloadable")

    token, expires_at = create_signed_token(file_id, "upload_file_download")
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
    if not verify_signed_token(token, file_id, "upload_file_download"):
        raise HTTPException(status_code=403, detail="Invalid or expired signed URL")

    file_record = store.files[file_id]
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


def dedupe_citations(citations: list) -> list:
    seen: set[str] = set()
    unique = []
    for citation in citations:
        key = json.dumps(
            {
                "file_id": str(citation.file_id) if citation.file_id else None,
                "locator_type": citation.locator_type,
                "locator": citation.locator,
                "snippet": citation.snippet,
            },
            sort_keys=True,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(citation)
    return unique[:8]
