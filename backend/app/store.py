from __future__ import annotations

import json
import mimetypes
import os
import re
import sys
import time
import zipfile
import zlib
import xml.etree.ElementTree as ET
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
from hashlib import sha256
from io import BytesIO, StringIO
from pathlib import Path
from uuid import UUID, uuid4
from xml.sax.saxutils import escape as xml_escape

from .archive_limits import max_zip_entries, max_zip_uncompressed_bytes
from .audit_safety import sanitize_audit_metadata
from .malware import MalwareScanResult, scan_upload_content
from .ocr import extract_ocr_text
from .queue_backend import (
    active_queue_backend,
    enqueue_processing_job,
    pop_processing_job_ids,
    sync_processing_queue,
)
from .runtime_backends import (
    LOCAL_REPOSITORY_BACKEND,
    POSTGRES_REPOSITORY_BACKEND,
    database_url,
    requested_repository_backend,
)
from .schemas import (
    AuditIntegrityStatus,
    AuditLog,
    Citation,
    DocumentChunk,
    FailureRecord,
    MondayReport,
    ParsedDocument,
    ProcessingJob,
    ProcessingStatus,
    ReportExport,
    RetentionRunResult,
    Role,
    Tenant,
    Upload,
    UploadCreate,
    UploadFileRecord,
    User,
    ValidationStatus,
    ValidationTask,
    ValidationTaskUpdate,
    Workspace,
    WorkspaceCreate,
)

INVALID_STORAGE_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')
RESERVED_STORAGE_NAMES = {
    "AUX",
    "CON",
    "NUL",
    "PRN",
    *{f"COM{index}" for index in range(1, 10)},
    *{f"LPT{index}" for index in range(1, 10)},
}
TEXT_FILE_EXTENSIONS = {".json", ".log", ".md", ".text", ".txt"}
CSV_FILE_EXTENSIONS = {".csv"}
WORD_FILE_EXTENSIONS = {".docx"}
EXCEL_FILE_EXTENSIONS = {".xlsx"}
EMAIL_FILE_EXTENSIONS = {".eml"}
IMAGE_FILE_EXTENSIONS = {".bmp", ".jpeg", ".jpg", ".png", ".tif", ".tiff"}
ZIP_MIME_TYPES = {"application/zip", "application/x-zip-compressed", "multipart/x-zip"}
ARCHIVE_REJECTION_RESULTS = {"invalid_zip", "zip_too_many_entries", "zip_too_large"}
PDF_STREAM_PATTERN = re.compile(rb"<<(?P<header>.*?)>>\s*stream\r?\n(?P<body>.*?)\r?\nendstream", re.DOTALL)
STATE_READ_RETRIES = 5
STATE_READ_RETRY_DELAY_SECONDS = 0.03
STATE_REPLACE_RETRIES = 5
STATE_REPLACE_RETRY_DELAY_SECONDS = 0.03


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _summary_sentence(failures: list[FailureRecord], fallback: str) -> str:
    if not failures:
        return fallback
    top_failures = sorted(failures, key=lambda item: (item.npt_hours, item.confidence), reverse=True)[:3]
    fragments = [
        f"{failure.event_type} from {failure.company} ({failure.npt_hours:g} NPT hrs)"
        for failure in top_failures
    ]
    return "Primary operational focus: " + "; ".join(fragments) + "."


class LocalStateStore:
    """Durable local store for the executable MVP scaffold.

    This keeps API and worker state shared through a JSON file while the real
    PostgreSQL/Redis repository layer is being built. It intentionally mirrors
    the tenant-owned tables in the migration so later replacement is direct.
    """

    def __init__(self) -> None:
        self.repository_backend = getattr(self, "repository_backend", LOCAL_REPOSITORY_BACKEND)
        self.queue_backend = active_queue_backend()
        default_path = Path.cwd() / ".local_data" / "monday_report_state.json"
        default_storage_root = Path.cwd() / ".local_data" / "storage"
        default_export_root = Path.cwd() / ".local_data" / "exports"
        self.state_path = Path(os.getenv("MONDAY_REPORT_STATE_PATH", default_path))
        self.storage_root = Path(os.getenv("MONDAY_REPORT_STORAGE_ROOT", default_storage_root))
        self.export_root = Path(os.getenv("MONDAY_REPORT_EXPORT_ROOT", default_export_root))
        self.tenant = self._configured_tenant()
        self.user = self._configured_user(self.tenant.id)
        self.workspaces: dict[UUID, Workspace] = {}
        self.uploads: dict[UUID, Upload] = {}
        self.files: dict[UUID, UploadFileRecord] = {}
        self.jobs: dict[UUID, ProcessingJob] = {}
        self.parsed_documents: dict[UUID, ParsedDocument] = {}
        self.document_chunks: dict[UUID, DocumentChunk] = {}
        self.failures: dict[UUID, FailureRecord] = {}
        self.validation_tasks: dict[UUID, ValidationTask] = {}
        self.monday_reports: dict[UUID, MondayReport] = {}
        self.report_exports: dict[UUID, ReportExport] = {}
        self.audit_logs: list[AuditLog] = []

        if self._state_exists():
            self.refresh()
            if self._contains_demo_seed():
                self._reset_clean_bootstrap()
                self.save()
        else:
            self._seed()
            self.save()

    def _state_exists(self) -> bool:
        return self.state_path.exists()

    def _contains_demo_seed(self) -> bool:
        return any(log.action == "state.seed" for log in self.audit_logs)

    def _reset_clean_bootstrap(self) -> None:
        self.tenant = self._configured_tenant()
        self.user = self._configured_user(self.tenant.id)
        self.workspaces.clear()
        self.uploads.clear()
        self.files.clear()
        self.jobs.clear()
        self.parsed_documents.clear()
        self.document_chunks.clear()
        self.failures.clear()
        self.validation_tasks.clear()
        self.monday_reports.clear()
        self.report_exports.clear()
        self.audit_logs.clear()
        self._seed()

    @staticmethod
    def _configured_tenant() -> Tenant:
        return Tenant(
            name=os.getenv("MONDAY_REPORT_TENANT_NAME", "Monday Report Tenant"),
            slug=os.getenv("MONDAY_REPORT_TENANT_SLUG", "monday-report"),
        )

    @staticmethod
    def _configured_user(tenant_id: UUID) -> User:
        return User(
            tenant_id=tenant_id,
            email=os.getenv("MONDAY_REPORT_USER_EMAIL", "operator@monday-report.invalid"),
            full_name=os.getenv("MONDAY_REPORT_USER_FULL_NAME", "Monday Report Operator"),
            roles=[Role.ADMIN, Role.ENGINEER, Role.VALIDATOR],
        )

    def refresh(self) -> None:
        payload = self._read_state_payload()
        if payload is None:
            return

        self.tenant = Tenant.model_validate(payload["tenant"])
        self.user = User.model_validate(payload["user"])
        self.workspaces = self._load_map(Workspace, payload.get("workspaces", []))
        self.uploads = self._load_map(Upload, payload.get("uploads", []))
        self.files = self._load_map(UploadFileRecord, payload.get("files", []))
        self.jobs = self._load_map(ProcessingJob, payload.get("jobs", []))
        self.parsed_documents = self._load_map(ParsedDocument, payload.get("parsed_documents", []))
        self.document_chunks = self._load_map(DocumentChunk, payload.get("document_chunks", []))
        self.failures = self._load_map(FailureRecord, payload.get("failures", []))
        self.validation_tasks = self._load_map(ValidationTask, payload.get("validation_tasks", []))
        self.monday_reports = self._load_map(MondayReport, payload.get("monday_reports", []))
        self.report_exports = self._load_map(ReportExport, payload.get("report_exports", []))
        self.audit_logs = [AuditLog.model_validate(item) for item in payload.get("audit_logs", [])]

    def save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = self._state_payload()
        tmp_path = self.state_path.with_name(f"{self.state_path.name}.{os.getpid()}.{uuid4().hex}.tmp")
        try:
            tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            self._replace_state_file(tmp_path)
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass

    def _state_payload(self) -> dict[str, object]:
        payload = {
            "tenant": self.tenant.model_dump(mode="json"),
            "user": self.user.model_dump(mode="json"),
            "workspaces": self._dump_map(self.workspaces),
            "uploads": self._dump_map(self.uploads),
            "files": self._dump_map(self.files),
            "jobs": self._dump_map(self.jobs),
            "parsed_documents": self._dump_map(self.parsed_documents),
            "document_chunks": self._dump_map(self.document_chunks),
            "failures": self._dump_map(self.failures),
            "validation_tasks": self._dump_map(self.validation_tasks),
            "monday_reports": self._dump_map(self.monday_reports),
            "report_exports": self._dump_map(self.report_exports),
            "audit_logs": [item.model_dump(mode="json") for item in self.audit_logs],
        }
        return payload

    def _read_state_payload(self) -> dict[str, object] | None:
        for attempt in range(STATE_READ_RETRIES):
            try:
                return json.loads(self.state_path.read_text(encoding="utf-8"))
            except FileNotFoundError:
                return None
            except (json.JSONDecodeError, OSError):
                if attempt == STATE_READ_RETRIES - 1:
                    raise
                time.sleep(STATE_READ_RETRY_DELAY_SECONDS)
        return None

    def _replace_state_file(self, tmp_path: Path) -> None:
        for attempt in range(STATE_REPLACE_RETRIES):
            try:
                tmp_path.replace(self.state_path)
                return
            except OSError:
                if attempt == STATE_REPLACE_RETRIES - 1:
                    raise
                time.sleep(STATE_REPLACE_RETRY_DELAY_SECONDS)

    def _seed(self) -> None:
        workspace = Workspace(
            tenant_id=self.tenant.id,
            name=os.getenv(
                "MONDAY_REPORT_DEFAULT_WORKSPACE_NAME",
                "Client workspace",
            ),
            asset=os.getenv("MONDAY_REPORT_DEFAULT_ASSET", "client asset"),
            campaign=os.getenv(
                "MONDAY_REPORT_DEFAULT_CAMPAIGN",
                "client campaign",
            ),
        )
        self.workspaces[workspace.id] = workspace
        self.audit("workspace.create", "workspace", workspace.id, {"name": workspace.name}, save=False)

        self.audit(
            "state.bootstrap",
            "tenant",
            self.tenant.id,
            {"store": self.repository_backend, "demo_seed": False},
            save=False,
        )

    def create_workspace(self, payload: WorkspaceCreate) -> Workspace:
        self.refresh()
        workspace = Workspace(tenant_id=self.tenant.id, **payload.model_dump())
        self.workspaces[workspace.id] = workspace
        self.audit("workspace.create", "workspace", workspace.id, {"name": workspace.name})
        return workspace

    def create_upload(self, payload: UploadCreate) -> tuple[Upload, UploadFileRecord, str]:
        self.refresh()
        upload = Upload(
            tenant_id=self.tenant.id,
            workspace_id=payload.workspace_id,
            submitted_by=self.user.id,
            source_type=payload.source_type,
        )
        safe_parts = self._safe_storage_parts(payload.file_name)
        digest = sha256(f"{upload.id}:{payload.file_name}:{payload.byte_size}".encode()).hexdigest()
        file_record = UploadFileRecord(
            tenant_id=self.tenant.id,
            upload_id=upload.id,
            original_path=payload.file_name,
            storage_uri=f"object://{self.tenant.slug}/uploads/{upload.id}/{'/'.join(safe_parts)}",
            sha256=digest,
            mime_type=payload.mime_type,
            byte_size=payload.byte_size,
        )
        self.uploads[upload.id] = upload
        self.files[file_record.id] = file_record
        self.audit("upload.create", "upload", upload.id, {"file_name": payload.file_name})
        return upload, file_record, f"local-upload://{file_record.id}"

    def create_uploaded_file(
        self,
        workspace_id: UUID,
        file_name: str,
        mime_type: str,
        source_type: str,
        content: bytes,
    ) -> tuple[Upload, UploadFileRecord, str]:
        self.refresh()
        upload = Upload(
            tenant_id=self.tenant.id,
            workspace_id=workspace_id,
            submitted_by=self.user.id,
            source_type=source_type,  # type: ignore[arg-type]
        )
        safe_parts = self._safe_storage_parts(file_name)
        digest = sha256(content).hexdigest()
        scan_result = scan_upload_content(file_name, mime_type, content)
        if scan_result.status == "blocked":
            storage_uri = f"blocked://{self.tenant.slug}/uploads/{upload.id}/{'/'.join(safe_parts)}"
            storage_path_detail = None
            file_status = ProcessingStatus.FAILED
            malware_status = "blocked"
        else:
            relative_storage_path = Path(self.tenant.slug) / "uploads" / str(upload.id)
            for part in safe_parts:
                relative_storage_path /= part
            storage_path = self.storage_root / relative_storage_path
            storage_path.parent.mkdir(parents=True, exist_ok=True)
            storage_path.write_bytes(content)
            storage_uri = f"object://{self.tenant.slug}/uploads/{upload.id}/{'/'.join(safe_parts)}"
            storage_path_detail = str(storage_path.relative_to(self.storage_root))
            file_status = ProcessingStatus.QUEUED
            malware_status = "clean"

        file_record = UploadFileRecord(
            tenant_id=self.tenant.id,
            upload_id=upload.id,
            original_path=file_name,
            storage_uri=storage_uri,
            sha256=digest,
            mime_type=mime_type or "application/octet-stream",
            byte_size=len(content),
            status=file_status,
            malware_status=malware_status,
        )
        upload.status = ProcessingStatus.FAILED if scan_result.status == "blocked" else ProcessingStatus.QUEUED
        self.uploads[upload.id] = upload
        self.files[file_record.id] = file_record
        self.audit(
            "upload.blocked" if scan_result.status == "blocked" else "upload.create",
            "upload",
            upload.id,
            {
                "file_name": file_name,
                "byte_size": len(content),
                "sha256": digest,
                "storage_uri": storage_uri,
                "storage_path": storage_path_detail,
                "malware_scan": {
                    "scanner": scan_result.scanner,
                    "status": scan_result.status,
                    "reason": scan_result.reason,
                },
            },
        )
        return upload, file_record, f"local-storage://{file_record.id}"

    def complete_upload(self, upload_id: UUID, file_ids: list[UUID]) -> Upload:
        self.refresh()
        upload = self.uploads[upload_id]
        upload.status = ProcessingStatus.PROCESSING
        created_job_ids: list[str] = []
        reused_job_ids: list[str] = []
        duplicate_file_ids: list[str] = []
        seen_file_ids: set[UUID] = set()

        for file_id in file_ids:
            if file_id in seen_file_ids:
                duplicate_file_ids.append(str(file_id))
                self.audit(
                    "upload.complete_duplicate_file",
                    "upload",
                    upload.id,
                    {"file_id": str(file_id)},
                    save=False,
                )
                continue
            seen_file_ids.add(file_id)
            file_record = self.files[file_id]
            if file_record.upload_id != upload.id:
                self.audit(
                    "upload.complete_rejected",
                    "upload",
                    upload.id,
                    {
                        "reason": "file_upload_mismatch",
                        "file_id": str(file_record.id),
                        "file_upload_id": str(file_record.upload_id),
                    },
                    save=False,
                )
                continue

            existing_job = self._existing_processing_job(upload.id, file_record.id)
            if existing_job is not None:
                reused_job_ids.append(str(existing_job.id))
                continue

            storage_path = self._storage_path_from_uri(file_record.storage_uri)
            if storage_path is None or not storage_path.exists():
                file_record.status = ProcessingStatus.FAILED
                file_record.malware_status = "pending"
                self.audit(
                    "upload_file.missing_storage",
                    "file",
                    file_record.id,
                    {
                        "upload_id": str(upload.id),
                        "file_id": str(file_record.id),
                        "storage_uri": file_record.storage_uri,
                        "file_name": file_record.original_path,
                    },
                    save=False,
                )
                continue

            scan_result = scan_upload_content(file_record.original_path, file_record.mime_type, storage_path.read_bytes())
            file_record.malware_status = "blocked" if scan_result.status == "blocked" else "clean"
            if scan_result.status == "blocked":
                file_record.status = ProcessingStatus.FAILED
                self.audit(
                    "upload.blocked",
                    "upload",
                    upload.id,
                    {
                        "file_id": str(file_record.id),
                        "file_name": file_record.original_path,
                        "malware_scan": {
                            "scanner": scan_result.scanner,
                            "status": scan_result.status,
                            "reason": scan_result.reason,
                        },
                    },
                    save=False,
                )
                continue
            job = ProcessingJob(
                tenant_id=self.tenant.id,
                upload_id=upload.id,
                file_id=file_record.id,
                job_type="scan_parse_classify_extract",
                payload={"storage_uri": file_record.storage_uri},
            )
            self.jobs[job.id] = job
            self._enqueue_processing_job(job.id)
            created_job_ids.append(str(job.id))

        if created_job_ids or reused_job_ids:
            self._sync_upload_job_status(upload.id)
        else:
            upload.status = ProcessingStatus.FAILED

        self.audit(
            "upload.complete",
            "upload",
            upload.id,
            {
                "file_ids": [str(item) for item in file_ids],
                "job_ids": created_job_ids,
                "reused_job_ids": reused_job_ids,
                "duplicate_file_ids": duplicate_file_ids,
            },
        )
        return upload

    def process_queued_jobs(self) -> int:
        self.refresh()
        processed = 0
        processed_upload_ids: set[UUID] = set()
        redis_job_ids = self._redis_processing_job_ids()

        for job in self.jobs.values():
            if job.status != ProcessingStatus.QUEUED:
                continue
            if redis_job_ids is not None and job.id not in redis_job_ids:
                continue

            job.attempts += 1
            parse_result = self._parse_job_file(job)
            extraction_result = {"failure_ids": [], "validation_task_ids": []}
            if parse_result["ok"]:
                document_ids = parse_result.get("document_ids", [])
                extraction_result = self._extract_failures_for_documents(
                    job.upload_id,
                    document_ids if isinstance(document_ids, list) else [],
                )
            if parse_result["ok"]:
                job.status = ProcessingStatus.COMPLETE
            else:
                job.status = ProcessingStatus.FAILED
            job.payload = {
                **job.payload,
                "worker": "worker:once",
                "result": parse_result["result"],
                "parser_name": parse_result.get("parser_name"),
                "chunks_created": parse_result.get("chunks_created", 0),
                "failures_created": len(extraction_result["failure_ids"]),
            }
            if job.file_id and job.file_id in self.files:
                self.files[job.file_id].status = job.status
            processed_upload_ids.add(job.upload_id)
            processed += 1
            if parse_result["ok"]:
                document_ids = parse_result.get("document_ids", [])
                if parse_result.get("archive_entries") is not None:
                    self.audit(
                        "archive.expand_complete",
                        "upload",
                        job.upload_id,
                        {
                            "job_id": str(job.id),
                            "file_id": str(job.file_id) if job.file_id else None,
                            "entries": parse_result.get("archive_entries", 0),
                            "child_file_ids": parse_result.get("child_file_ids", []),
                        },
                        save=False,
                    )
                document_chunk_counts = parse_result.get("document_chunk_counts", {})
                for document_id in document_ids if isinstance(document_ids, list) else []:
                    parsed_document = self.parsed_documents.get(document_id)
                    self.audit(
                        "document.parse_complete",
                        "parsed_document",
                        document_id,
                        {
                            "job_id": str(job.id),
                            "upload_id": str(job.upload_id),
                            "file_id": str(job.file_id) if job.file_id else None,
                            "parser_name": (
                                parsed_document.parser_name if parsed_document else parse_result.get("parser_name")
                            ),
                            "chunks_created": (
                                document_chunk_counts.get(str(document_id), parse_result.get("chunks_created", 0))
                                if isinstance(document_chunk_counts, dict)
                                else parse_result.get("chunks_created", 0)
                            ),
                        },
                        save=False,
                    )
                for failure_id in extraction_result["failure_ids"]:
                    self.audit(
                        "failure.extract_complete",
                        "failure",
                        failure_id,
                        {
                            "job_id": str(job.id),
                            "upload_id": str(job.upload_id),
                            "validation_task_ids": [str(item) for item in extraction_result["validation_task_ids"]],
                        },
                        save=False,
                    )
                if parse_result.get("result") == "ocr_routed":
                    self.audit(
                        "ocr.route",
                        "file",
                        job.file_id,
                        {
                            "job_id": str(job.id),
                            "upload_id": str(job.upload_id),
                            "document_ids": [str(item) for item in parse_result.get("document_ids", [])],
                            "validation_task_ids": [
                                str(item) for item in parse_result.get("validation_task_ids", [])
                            ],
                            "source_parser_name": parse_result.get("source_parser_name"),
                            "routing_reason": parse_result.get("routing_reason"),
                        },
                        save=False,
                    )
                if parse_result.get("result") == "ocr_extracted":
                    self.audit(
                        "ocr.extract_complete",
                        "file",
                        job.file_id,
                        {
                            "job_id": str(job.id),
                            "upload_id": str(job.upload_id),
                            "document_ids": [str(item) for item in parse_result.get("document_ids", [])],
                            "source_parser_name": parse_result.get("source_parser_name"),
                            "routing_reason": parse_result.get("routing_reason"),
                            "parser_name": parse_result.get("parser_name"),
                            "chunks_created": parse_result.get("chunks_created", 0),
                        },
                        save=False,
                    )
                self.audit(
                    "processing_job.complete",
                    "processing_job",
                    job.id,
                    {"upload_id": str(job.upload_id), "file_id": str(job.file_id) if job.file_id else None},
                    save=False,
                )
            else:
                if parse_result.get("result") in ARCHIVE_REJECTION_RESULTS:
                    self.audit(
                        "archive.rejected",
                        "upload",
                        job.upload_id,
                        {
                            "job_id": str(job.id),
                            "file_id": str(job.file_id) if job.file_id else None,
                            "reason": parse_result["result"],
                            "parser_name": parse_result.get("parser_name"),
                            "archive_entries": parse_result.get("archive_entries"),
                            "uncompressed_bytes": parse_result.get("uncompressed_bytes"),
                            "max_zip_entries": parse_result.get("max_zip_entries"),
                            "max_zip_uncompressed_bytes": parse_result.get("max_zip_uncompressed_bytes"),
                        },
                        save=False,
                    )
                self.audit(
                    "processing_job.failed",
                    "processing_job",
                    job.id,
                    {
                        "upload_id": str(job.upload_id),
                        "file_id": str(job.file_id) if job.file_id else None,
                        "reason": parse_result["result"],
                    },
                    save=False,
                )

        for upload_id in processed_upload_ids:
            self._sync_upload_job_status(upload_id, audit_terminal=True)

        if processed:
            self.save()
        return processed

    def _enqueue_processing_job(self, job_id: UUID) -> None:
        if self.queue_backend != "redis":
            return
        enqueue_processing_job(job_id)

    def _redis_processing_job_ids(self) -> set[UUID] | None:
        self.queue_backend = active_queue_backend()
        if self.queue_backend != "redis":
            return None
        queued_job_ids = [job.id for job in self.jobs.values() if job.status == ProcessingStatus.QUEUED]
        sync_processing_queue(queued_job_ids)
        return set(pop_processing_job_ids())

    def parsed_citations_for_workspace(self, workspace_id: UUID, limit: int = 6) -> list[Citation]:
        self.refresh()
        chunks = [
            chunk
            for chunk in self.document_chunks.values()
            if chunk.workspace_id == workspace_id and chunk.text.strip()
        ]
        chunks.sort(key=lambda item: item.created_at, reverse=True)
        return [
            Citation(
                file_id=chunk.file_id,
                locator_type=chunk.locator_type,
                locator=chunk.locator,
                snippet=chunk.text[:240],
                confidence=chunk.confidence,
            )
            for chunk in chunks[:limit]
        ]

    def update_validation_task(self, task_id: UUID, payload: ValidationTaskUpdate) -> ValidationTask:
        self.refresh()
        task = self.validation_tasks[task_id]
        previous_status = task.status
        task.status = payload.status
        task.resolution_note = payload.resolution_note

        if task.target_type == "failure" and task.target_id in self.failures:
            self.failures[task.target_id].validation_status = payload.status

        self.audit(
            "validation_task.update",
            "validation_task",
            task.id,
            {
                "target_type": task.target_type,
                "target_id": str(task.target_id),
                "from": previous_status.value,
                "to": payload.status.value,
                "resolution_note": payload.resolution_note,
            },
        )
        return task

    def create_monday_report(self, payload) -> MondayReport:
        self.refresh()
        failures = [
            failure for failure in self.failures.values() if failure.workspace_id == payload.workspace_id
        ]
        open_tasks = self._open_validation_tasks_for_workspace(payload.workspace_id)
        total_npt = sum(failure.npt_hours for failure in failures)
        high_failures = [failure for failure in failures if failure.severity in {"High", "Critical"}]
        workspace = self.workspaces[payload.workspace_id]
        parsed_documents = [
            document
            for document in self.parsed_documents.values()
            if document.workspace_id == payload.workspace_id
        ]
        citation_count = sum(len(failure.citations) for failure in failures)
        validated_count = sum(1 for failure in failures if failure.validation_status == ValidationStatus.VALIDATED)
        average_confidence = (
            sum(failure.confidence for failure in failures) / len(failures)
            if failures
            else 0
        )
        report = MondayReport(
            tenant_id=self.tenant.id,
            workspace_id=payload.workspace_id,
            period_start=payload.period_start,
            period_end=payload.period_end,
            status="review" if open_tasks else "draft",
            report_json={
                "title": "Monday Report",
                "period": {
                    "start": payload.period_start.isoformat(),
                    "end": payload.period_end.isoformat(),
                },
                "workspace": {
                    "name": workspace.name,
                    "asset": workspace.asset,
                    "campaign": workspace.campaign,
                },
                "generated_at": utc_iso(),
                "metrics": {
                    "failure_count": len(failures),
                    "high_or_critical_failures": len(high_failures),
                    "total_npt_hours": round(total_npt, 2),
                    "validated_failures": validated_count,
                    "open_validation_tasks": len(open_tasks),
                    "citation_count": citation_count,
                    "parsed_documents": len(parsed_documents),
                    "average_confidence": round(average_confidence, 3),
                },
                "executive_summary": [
                    {
                        "text": (
                            f"{len(failures)} extracted failure(s), {len(high_failures)} high/critical item(s), "
                            f"and {total_npt:.1f} NPT hour(s) are currently in scope."
                        ),
                        "confidence": 0.82,
                    }
                ],
                "failure_summary": [failure.model_dump(mode="json") for failure in failures],
                "validation": {
                    "open_tasks": len(open_tasks),
                    "status": "requires_review" if open_tasks else "ready_for_approval",
                    "validated_failures": validated_count,
                },
                "source_coverage": {
                    "documents": len(parsed_documents),
                    "citations": citation_count,
                    "document_titles": [document.title for document in parsed_documents[:12]],
                },
                "morning_report": {
                    "present_operations": _summary_sentence(
                        failures,
                        "No extracted failures in scope; continue source-backed monitoring before client issue.",
                    ),
                    "next_24_hours": [
                        "Resolve or confirm every open validation task before issuing an official report.",
                        "Review cited source files for high-severity or high-NPT events.",
                        "Update casing, BHA, mud, survey, and activity timeline sections from the latest DDR evidence.",
                    ],
                    "casing_schematic": [
                        {"name": "Conductor", "od": "20 in", "top_ft": 0, "shoe_ft": 130, "status": "reference"},
                        {"name": "Surface", "od": "13.375 in", "top_ft": 0, "shoe_ft": 1629, "status": "reference"},
                        {"name": "Intermediate", "od": "9.625 in", "top_ft": 0, "shoe_ft": 6500, "status": "plan"},
                        {"name": "Production", "od": "7 in", "top_ft": 0, "shoe_ft": 10987, "status": "plan"},
                    ],
                    "activity_timeline": [
                        {
                            "time": "00:00-06:00",
                            "activity": "Review overnight source evidence and validate extracted NPT/failure records.",
                        },
                        {
                            "time": "06:00-12:00",
                            "activity": "Confirm safety, well-control, casing, and BHA status for morning handover.",
                        },
                        {
                            "time": "12:00-18:00",
                            "activity": "Close validation gaps, attach source citations, and update recommended actions.",
                        },
                        {
                            "time": "18:00-24:00",
                            "activity": "Prepare branded Monday Report export package after approval gate passes.",
                        },
                    ],
                },
                "data_quality_notes": [
                    "Official exports are blocked until validation tasks are closed.",
                    "Casing and timeline sections use the FORGE-style daily-report structure and should be source-confirmed before client issue.",
                ],
            },
        )
        self.monday_reports[report.id] = report
        self.audit(
            "monday_report.create",
            "monday_report",
            report.id,
            {
                "workspace_id": str(payload.workspace_id),
                "failures": len(failures),
                "open_validation_tasks": len(open_tasks),
            },
        )
        return report

    def report_open_validation_tasks(self, report_id: UUID) -> list[ValidationTask]:
        self.refresh()
        report = self.monday_reports[report_id]
        return self._open_validation_tasks_for_workspace(report.workspace_id)

    def run_retention(self, retention_days: int, apply: bool = False) -> RetentionRunResult:
        self.refresh()
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        expired_upload_ids = {
            upload.id for upload in self.uploads.values() if upload.created_at < cutoff
        }
        expired_file_ids = {
            file.id for file in self.files.values() if file.upload_id in expired_upload_ids
        }
        expired_job_ids = {
            job.id
            for job in self.jobs.values()
            if job.upload_id in expired_upload_ids or job.created_at < cutoff
        }
        expired_document_ids = {
            document.id
            for document in self.parsed_documents.values()
            if document.upload_id in expired_upload_ids or document.created_at < cutoff
        }
        expired_chunk_ids = {
            chunk.id
            for chunk in self.document_chunks.values()
            if chunk.document_id in expired_document_ids or chunk.upload_id in expired_upload_ids
        }
        expired_upload_id_text = {str(item) for item in expired_upload_ids}
        expired_failure_ids = {
            failure.id
            for failure in self.failures.values()
            if any(citation.locator.get("upload_id") in expired_upload_id_text for citation in failure.citations)
        }
        expired_validation_task_ids = {
            task.id for task in self.validation_tasks.values() if task.target_id in expired_failure_ids
        }
        expired_report_ids = {
            report.id for report in self.monday_reports.values() if report.created_at < cutoff
        }
        expired_export_ids = {
            report_export.id
            for report_export in self.report_exports.values()
            if report_export.report_id in expired_report_ids or report_export.created_at < cutoff
        }
        storage_paths = [
            path
            for file_id in expired_file_ids
            if (path := self.file_path_from_uri(self.files[file_id].storage_uri)) is not None
        ]
        export_paths = [
            path
            for export_id in expired_export_ids
            if (path := self.export_path_from_uri(self.report_exports[export_id].storage_uri)) is not None
        ]

        result = RetentionRunResult(
            mode="applied" if apply else "dry_run",
            retention_days=retention_days,
            cutoff=cutoff,
            uploads=len(expired_upload_ids),
            upload_files=len(expired_file_ids),
            processing_jobs=len(expired_job_ids),
            parsed_documents=len(expired_document_ids),
            document_chunks=len(expired_chunk_ids),
            failures=len(expired_failure_ids),
            validation_tasks=len(expired_validation_task_ids),
            monday_reports=len(expired_report_ids),
            report_exports=len(expired_export_ids),
            storage_objects=len(storage_paths),
            export_objects=len(export_paths),
        )

        if not apply:
            return result

        for path in storage_paths + export_paths:
            self._delete_managed_file(path)
        self._drop_many(self.document_chunks, expired_chunk_ids)
        self._drop_many(self.parsed_documents, expired_document_ids)
        self._drop_many(self.jobs, expired_job_ids)
        self._drop_many(self.files, expired_file_ids)
        self._drop_many(self.uploads, expired_upload_ids)
        self._drop_many(self.validation_tasks, expired_validation_task_ids)
        self._drop_many(self.failures, expired_failure_ids)
        self._drop_many(self.report_exports, expired_export_ids)
        self._drop_many(self.monday_reports, expired_report_ids)
        self.audit(
            "retention.apply",
            "tenant",
            self.tenant.id,
            result.model_dump(mode="json"),
            save=False,
        )
        self.save()
        return result

    @staticmethod
    def _drop_many(items: dict[UUID, object], item_ids: set[UUID]) -> None:
        for item_id in item_ids:
            items.pop(item_id, None)

    @staticmethod
    def _delete_managed_file(path: Path) -> None:
        if not path.exists() or not path.is_file():
            return
        path.unlink()
        current = path.parent
        while current.exists() and not any(current.iterdir()):
            try:
                current.rmdir()
            except OSError:
                break
            current = current.parent

    def export_monday_report(self, report_id: UUID, export_format: str) -> ReportExport:
        self.refresh()
        report = self.monday_reports[report_id]
        existing_export = self._existing_report_export(report.id, export_format)
        if existing_export is not None:
            existing_path = self.export_path_from_uri(existing_export.storage_uri)
            if existing_path is not None and existing_path.exists():
                existing_content = existing_path.read_bytes()
                if (
                    sha256(existing_content).hexdigest() == existing_export.sha256
                    and len(existing_content) == existing_export.byte_size
                ):
                    report.status = "exported"
                    self.audit(
                        "monday_report.export_reused",
                        "monday_report",
                        report.id,
                        {
                            "format": export_format,
                            "report_export_id": str(existing_export.id),
                            "sha256": existing_export.sha256,
                            "byte_size": existing_export.byte_size,
                        },
                    )
                    return existing_export

        if export_format == "json":
            content = json.dumps(report.report_json, indent=2).encode("utf-8")
            extension = "json"
        elif export_format == "csv":
            content = self._render_report_csv(report).encode("utf-8")
            extension = "csv"
        elif export_format == "html":
            content = self._render_report_html(report).encode("utf-8")
            extension = "html"
        elif export_format == "pdf":
            content = self._render_report_pdf(report)
            extension = "pdf"
        elif export_format == "xlsx":
            content = self._render_report_xlsx(report)
            extension = "xlsx"
        else:
            raise ValueError(f"Unsupported export format: {export_format}")

        digest = sha256(content).hexdigest()
        relative_path = Path(self.tenant.slug) / "reports" / str(report.id) / f"monday_report.{extension}"
        export_path = self.export_root / relative_path
        export_path.parent.mkdir(parents=True, exist_ok=True)
        export_path.write_bytes(content)
        report.status = "exported"

        report_export = ReportExport(
            tenant_id=self.tenant.id,
            report_id=report.id,
            format=export_format,  # type: ignore[arg-type]
            storage_uri=f"export://{self.tenant.slug}/reports/{report.id}/monday_report.{extension}",
            sha256=digest,
            byte_size=len(content),
        )
        self.report_exports[report_export.id] = report_export
        self.audit(
            "monday_report.export",
            "monday_report",
            report.id,
            {"format": export_format, "sha256": digest, "byte_size": len(content)},
        )
        return report_export

    def _open_validation_tasks_for_workspace(self, workspace_id: UUID) -> list[ValidationTask]:
        failure_ids = {
            failure.id
            for failure in self.failures.values()
            if failure.workspace_id == workspace_id
        }
        return [
            task
            for task in self.validation_tasks.values()
            if task.target_type == "failure"
            and task.target_id in failure_ids
            and task.status == ValidationStatus.OPEN
        ]

    def export_path_from_uri(self, storage_uri: str) -> Path | None:
        if not storage_uri.startswith("export://"):
            return None
        parts = [part for part in storage_uri.removeprefix("export://").split("/") if part]
        if not parts:
            return None
        path = self.export_root
        for part in parts:
            path /= part
        root = self.export_root.resolve()
        resolved = path.resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            return None
        return resolved

    def file_path_from_uri(self, storage_uri: str) -> Path | None:
        return self._storage_path_from_uri(storage_uri)

    @staticmethod
    def _render_report_csv(report: MondayReport) -> str:
        lines = ["event_type,severity,company,tool_type,tool_serial,npt_hours,confidence,validation_status,summary"]
        for failure in report.report_json.get("failure_summary", []):
            fields = [
                failure.get("event_type", ""),
                failure.get("severity", ""),
                failure.get("company", ""),
                failure.get("tool_type", ""),
                failure.get("tool_serial", ""),
                str(failure.get("npt_hours", 0)),
                str(failure.get("confidence", 0)),
                failure.get("validation_status", ""),
                failure.get("summary", ""),
            ]
            lines.append(",".join(f'"{str(field).replace(chr(34), chr(34) + chr(34))}"' for field in fields))
        return "\n".join(lines) + "\n"

    @staticmethod
    def _render_report_html(report: MondayReport) -> str:
        summary = report.report_json.get("executive_summary", [])
        failures = report.report_json.get("failure_summary", [])
        metrics = report.report_json.get("metrics", {})
        validation = report.report_json.get("validation", {})
        source_coverage = report.report_json.get("source_coverage", {})
        morning_report = report.report_json.get("morning_report", {})
        casing = morning_report.get("casing_schematic", []) if isinstance(morning_report, dict) else []
        timeline = morning_report.get("activity_timeline", []) if isinstance(morning_report, dict) else []
        notes = report.report_json.get("data_quality_notes", [])
        summary_items = "".join(f"<li>{xml_escape(str(item.get('text', '')))}</li>" for item in summary)
        metric_cards = "".join(
            (
                "<article>"
                f"<span>{xml_escape(label)}</span>"
                f"<strong>{xml_escape(str(value))}</strong>"
                "</article>"
            )
            for label, value in [
                ("Failures", metrics.get("failure_count", len(failures))),
                ("High/Critical", metrics.get("high_or_critical_failures", 0)),
                ("NPT Hours", metrics.get("total_npt_hours", 0)),
                ("Validated", metrics.get("validated_failures", 0)),
                ("Open Reviews", metrics.get("open_validation_tasks", validation.get("open_tasks", 0))),
                ("Citations", metrics.get("citation_count", source_coverage.get("citations", 0))),
            ]
        )
        failure_rows = "".join(
            (
                "<tr>"
                f"<td>{xml_escape(str(failure.get('event_type', '')))}</td>"
                f"<td>{xml_escape(str(failure.get('severity', '')))}</td>"
                f"<td>{xml_escape(str(failure.get('company', '')))}</td>"
                f"<td>{xml_escape(str(failure.get('tool_type', '')))}</td>"
                f"<td>{xml_escape(str(failure.get('npt_hours', 0)))}</td>"
                f"<td>{xml_escape(str(failure.get('validation_status', '')))}</td>"
                "</tr>"
            )
            for failure in failures
        )
        if not failure_rows:
            failure_rows = "<tr><td colspan=\"7\">No extracted failures in scope.</td></tr>"
        casing_rows = "".join(
            (
                "<tr>"
                f"<td>{xml_escape(str(item.get('name', '')))}</td>"
                f"<td>{xml_escape(str(item.get('od', '')))}</td>"
                f"<td>{xml_escape(str(item.get('top_ft', '')))}</td>"
                f"<td>{xml_escape(str(item.get('shoe_ft', '')))}</td>"
                f"<td>{xml_escape(str(item.get('status', '')))}</td>"
                "</tr>"
            )
            for item in casing
            if isinstance(item, dict)
        )
        timeline_rows = "".join(
            (
                "<tr>"
                f"<td>{xml_escape(str(item.get('time', '')))}</td>"
                f"<td>{xml_escape(str(item.get('activity', '')))}</td>"
                "</tr>"
            )
            for item in timeline
            if isinstance(item, dict)
        )
        notes_items = "".join(f"<li>{xml_escape(str(note))}</li>" for note in notes)
        period = report.report_json.get("period", {})
        start = xml_escape(str(period.get("start", "")))
        end = xml_escape(str(period.get("end", "")))
        validation_status = xml_escape(str(validation.get("status", "unknown")).replace("_", " ").title())
        return (
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>Monday Report</title>"
            "<style>"
            "body{font-family:Inter,Arial,sans-serif;margin:0;color:#17202a;background:#f4f6f8}"
            ".sheet{max-width:1080px;margin:24px auto;background:white;border:1px solid #d8e0e7}"
            "header{display:flex;justify-content:space-between;gap:16px;padding:24px;border-bottom:5px solid #0e7490;background:#f8fbfd}"
            "h1,h2,h3,p{margin:0}h1{font-size:28px}.muted{color:#647384}.band{display:flex;justify-content:space-between;padding:10px 24px;background:#101820;color:white;font-weight:700}"
            ".metrics{display:grid;grid-template-columns:repeat(6,1fr);border-bottom:1px solid #d8e0e7}.metrics article{padding:12px;border-right:1px solid #d8e0e7}.metrics span{display:block;color:#647384;font-size:11px;text-transform:uppercase}.metrics strong{font-size:18px}"
            "section{padding:20px 24px;border-bottom:1px solid #d8e0e7}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}"
            "table{border-collapse:collapse;width:100%;margin-top:10px}td,th{border:1px solid #d1d5db;padding:8px;text-align:left;vertical-align:top;font-size:13px}"
            "th{background:#101820;color:white}.pill{display:inline-block;border:1px solid #bde8d5;background:#e4f7ef;color:#047857;border-radius:999px;padding:5px 9px;font-size:12px;font-weight:700}"
            "ul{margin:10px 0 0 18px;padding:0;line-height:1.5}@media(max-width:820px){.metrics,.grid{grid-template-columns:1fr}.band,header{display:block}}"
            "</style></head><body><main class=\"sheet\">"
            "<header><div><p class=\"muted\">Monday Report</p><h1>Morning Operations Report</h1></div>"
            f"<span class=\"pill\">{validation_status}</span></header>"
            f"<div class=\"band\"><span>Period: {start} to {end}</span><span>Official export package</span></div>"
            f"<div class=\"metrics\">{metric_cards}</div>"
            f"<section><h2>Executive Summary</h2><ul>{summary_items}</ul></section>"
            "<section class=\"grid\"><div><h2>Present Operations</h2>"
            f"<p>{xml_escape(str(morning_report.get('present_operations', 'No operations entered.') if isinstance(morning_report, dict) else 'No operations entered.'))}</p></div>"
            f"<div><h2>Data Quality Notes</h2><ul>{notes_items}</ul></div></section>"
            "<section><h2>Failure Summary</h2><table><thead><tr><th>Event</th><th>Severity</th><th>Company</th>"
            "<th>Tool</th><th>NPT Hours</th><th>Confidence</th><th>Validation</th></tr></thead>"
            f"<tbody>{failure_rows}</tbody></table></section>"
            "<section class=\"grid\"><div><h2>Casing Schematic</h2><table><thead><tr><th>Name</th><th>OD</th><th>Top ft</th><th>Shoe ft</th><th>Status</th></tr></thead>"
            f"<tbody>{casing_rows}</tbody></table></div>"
            "<div><h2>24 Hr Activity Timeline</h2><table><thead><tr><th>Time</th><th>Activity</th></tr></thead>"
            f"<tbody>{timeline_rows}</tbody></table></div></section>"
            "</main></body></html>"
        )

    @staticmethod
    def _render_report_pdf(report: MondayReport) -> bytes:
        try:
            return LocalStateStore._render_report_pdf_reportlab(report)
        except ImportError:
            return LocalStateStore._render_report_pdf_basic(report)

    @staticmethod
    def _render_report_pdf_reportlab(report: MondayReport) -> bytes:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.48 * inch,
            leftMargin=0.48 * inch,
            topMargin=0.48 * inch,
            bottomMargin=0.48 * inch,
            title="Monday Report",
        )
        base = getSampleStyleSheet()
        styles = {
            "title": ParagraphStyle(
                "MondayReportTitle",
                parent=base["Title"],
                fontName="Helvetica-Bold",
                fontSize=22,
                leading=27,
                alignment=TA_LEFT,
                textColor=colors.HexColor("#111827"),
            ),
            "h2": ParagraphStyle(
                "MondayReportH2",
                parent=base["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=12,
                leading=15,
                textColor=colors.HexColor("#111827"),
                spaceBefore=6,
                spaceAfter=5,
            ),
            "body": ParagraphStyle(
                "MondayReportBody",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=8.5,
                leading=11,
                textColor=colors.HexColor("#374151"),
            ),
            "small": ParagraphStyle(
                "MondayReportSmall",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=7.2,
                leading=8.5,
                textColor=colors.HexColor("#475569"),
            ),
            "th": ParagraphStyle(
                "MondayReportTH",
                fontName="Helvetica-Bold",
                fontSize=7,
                leading=8.2,
                textColor=colors.white,
            ),
            "td": ParagraphStyle(
                "MondayReportTD",
                fontName="Helvetica",
                fontSize=6.7,
                leading=8.1,
                textColor=colors.HexColor("#111827"),
            ),
        }

        period = report.report_json.get("period", {})
        metrics = report.report_json.get("metrics", {})
        summary = report.report_json.get("executive_summary", [])
        failures = report.report_json.get("failure_summary", [])
        validation = report.report_json.get("validation", {})
        morning_report = report.report_json.get("morning_report", {})
        source_coverage = report.report_json.get("source_coverage", {})
        notes = report.report_json.get("data_quality_notes", [])
        story: list[object] = [
            Paragraph("Monday Report - Morning Operations Report", styles["title"]),
            Paragraph(
                f"Period {period.get('start', '')} to {period.get('end', '')} | "
                f"Validation: {str(validation.get('status', 'unknown')).replace('_', ' ').title()}",
                styles["small"],
            ),
            Spacer(1, 0.14 * inch),
            LocalStateStore._pdf_table(
                [
                    ["Failures", "High/Critical", "NPT Hours", "Validated", "Open Reviews", "Citations"],
                    [
                        str(metrics.get("failure_count", len(failures))),
                        str(metrics.get("high_or_critical_failures", 0)),
                        str(metrics.get("total_npt_hours", 0)),
                        str(metrics.get("validated_failures", 0)),
                        str(metrics.get("open_validation_tasks", validation.get("open_tasks", 0))),
                        str(metrics.get("citation_count", source_coverage.get("citations", 0))),
                    ],
                ],
                [1.15 * inch] * 6,
                styles,
            ),
            Spacer(1, 0.12 * inch),
            Paragraph("Executive Summary", styles["h2"]),
        ]
        story.extend(Paragraph(str(item.get("text", "")), styles["body"]) for item in summary)
        story.extend(
            [
                Paragraph("Present Operations", styles["h2"]),
                Paragraph(
                    str(
                        morning_report.get("present_operations", "No operations entered.")
                        if isinstance(morning_report, dict)
                        else "No operations entered."
                    ),
                    styles["body"],
                ),
                Paragraph("Failure Summary", styles["h2"]),
                LocalStateStore._pdf_table(
                    [["Event", "Severity", "Company", "Tool", "NPT", "Confidence", "Validation"]]
                    + [
                        [
                            str(failure.get("event_type", "")),
                            str(failure.get("severity", "")),
                            str(failure.get("company", "")),
                            str(failure.get("tool_type", "")),
                            str(failure.get("npt_hours", 0)),
                            str(failure.get("confidence", 0)),
                            str(failure.get("validation_status", "")),
                        ]
                        for failure in failures
                    ]
                    or [["Event", "Severity", "Company", "Tool", "NPT", "Confidence", "Validation"], ["No extracted failures", "", "", "", "", "", ""]],
                    [1.15 * inch, 0.7 * inch, 1.1 * inch, 0.8 * inch, 0.5 * inch, 0.7 * inch, 0.9 * inch],
                    styles,
                ),
                Paragraph("Casing Schematic", styles["h2"]),
                LocalStateStore._pdf_table(
                    [["Name", "OD", "Top ft", "Shoe ft", "Status"]]
                    + [
                        [
                            str(item.get("name", "")),
                            str(item.get("od", "")),
                            str(item.get("top_ft", "")),
                            str(item.get("shoe_ft", "")),
                            str(item.get("status", "")),
                        ]
                        for item in (morning_report.get("casing_schematic", []) if isinstance(morning_report, dict) else [])
                        if isinstance(item, dict)
                    ],
                    [1.25 * inch, 1.0 * inch, 0.9 * inch, 0.9 * inch, 1.2 * inch],
                    styles,
                ),
                Paragraph("24 Hr Activity Timeline", styles["h2"]),
                LocalStateStore._pdf_table(
                    [["Time", "Activity"]]
                    + [
                        [str(item.get("time", "")), str(item.get("activity", ""))]
                        for item in (morning_report.get("activity_timeline", []) if isinstance(morning_report, dict) else [])
                        if isinstance(item, dict)
                    ],
                    [1.15 * inch, 5.25 * inch],
                    styles,
                ),
                Paragraph("Data Quality Notes", styles["h2"]),
            ]
        )
        story.extend(Paragraph(f"- {note}", styles["body"]) for note in notes)
        doc.build(story)
        content = buffer.getvalue()
        if content.startswith(b"%PDF-1.3"):
            content = b"%PDF-1.4" + content[len(b"%PDF-1.3"):]
        return content

    @staticmethod
    def _pdf_table(rows: list[list[object]], widths: list[float], styles: dict[str, object]) -> Table:
        from reportlab.lib import colors
        from reportlab.platypus import Paragraph, Table, TableStyle

        if len(rows) == 1:
            rows.append([""] * len(rows[0]))
        data = []
        for row_index, row in enumerate(rows):
            style = styles["th"] if row_index == 0 else styles["td"]
            data.append([Paragraph(xml_escape(str(cell)), style) for cell in row])
        table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#101820")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        return table

    @staticmethod
    def _render_report_pdf_basic(report: MondayReport) -> bytes:
        period = report.report_json.get("period", {})
        summary = report.report_json.get("executive_summary", [])
        failures = report.report_json.get("failure_summary", [])
        lines = [
            "Monday Report",
            f"Period: {period.get('start', '')} to {period.get('end', '')}",
            "",
            "Executive Summary",
        ]
        lines.extend(str(item.get("text", "")) for item in summary)
        lines.extend(["", "Failure Summary"])
        if failures:
            for failure in failures:
                lines.append(
                    " | ".join(
                        [
                            str(failure.get("event_type", "")),
                            str(failure.get("severity", "")),
                            str(failure.get("company", "")),
                            str(failure.get("tool_type", "")),
                            f"{failure.get('npt_hours', 0)} NPT hrs",
                            str(failure.get("validation_status", "")),
                        ]
                    )
                )
        else:
            lines.append("No extracted failures in scope.")

        commands = ["BT", "/F1 12 Tf", "50 760 Td", "14 TL"]
        for line in lines[:48]:
            commands.append(f"({LocalStateStore._pdf_escape(line[:112])}) Tj")
            commands.append("T*")
        commands.append("ET")
        stream = "\n".join(commands).encode("latin-1", errors="replace")
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            (
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
            ),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
        ]

        pdf = b"%PDF-1.4\n"
        offsets = [0]
        for index, item in enumerate(objects, start=1):
            offsets.append(len(pdf))
            pdf += f"{index} 0 obj\n".encode("ascii") + item + b"\nendobj\n"
        xref_offset = len(pdf)
        pdf += f"xref\n0 {len(objects) + 1}\n".encode("ascii")
        pdf += b"0000000000 65535 f \n"
        for offset in offsets[1:]:
            pdf += f"{offset:010d} 00000 n \n".encode("ascii")
        pdf += (
            b"trailer\n"
            + f"<< /Size {len(objects) + 1} /Root 1 0 R >>\n".encode("ascii")
            + b"startxref\n"
            + str(xref_offset).encode("ascii")
            + b"\n%%EOF\n"
        )
        return pdf

    @staticmethod
    def _render_report_xlsx(report: MondayReport) -> bytes:
        failures = report.report_json.get("failure_summary", [])
        metrics = report.report_json.get("metrics", {})
        validation = report.report_json.get("validation", {})
        source_coverage = report.report_json.get("source_coverage", {})
        morning_report = report.report_json.get("morning_report", {})
        notes = report.report_json.get("data_quality_notes", [])
        rows: list[list[object]] = [
            ["Monday Report"],
            [
                "Period",
                f"{report.report_json.get('period', {}).get('start', '')} to "
                f"{report.report_json.get('period', {}).get('end', '')}",
            ],
            ["Validation", validation.get("status", "")],
            [],
            ["Metrics"],
            ["Failures", metrics.get("failure_count", len(failures))],
            ["High/Critical", metrics.get("high_or_critical_failures", 0)],
            ["NPT Hours", metrics.get("total_npt_hours", 0)],
            ["Validated", metrics.get("validated_failures", 0)],
            ["Open Reviews", metrics.get("open_validation_tasks", validation.get("open_tasks", 0))],
            ["Citations", metrics.get("citation_count", source_coverage.get("citations", 0))],
            [],
            ["Executive Summary"],
            *[["Summary", item.get("text", ""), item.get("confidence", "")] for item in report.report_json.get("executive_summary", [])],
            [],
            [
                "Event",
                "Severity",
                "Company",
                "Tool",
                "Serial",
                "NPT Hours",
                "Confidence",
                "Validation",
                "Summary",
            ],
        ]
        for failure in failures:
            rows.append(
                [
                    failure.get("event_type", ""),
                    failure.get("severity", ""),
                    failure.get("company", ""),
                    failure.get("tool_type", ""),
                    failure.get("tool_serial", ""),
                    failure.get("npt_hours", 0),
                    failure.get("confidence", 0),
                    failure.get("validation_status", ""),
                failure.get("summary", ""),
                ]
            )
        rows.extend(
            [
                [],
                ["Casing Schematic"],
                ["Name", "OD", "Top ft", "Shoe ft", "Status"],
            ]
        )
        rows.extend(
            [
                [
                    item.get("name", ""),
                    item.get("od", ""),
                    item.get("top_ft", ""),
                    item.get("shoe_ft", ""),
                    item.get("status", ""),
                ]
                for item in (morning_report.get("casing_schematic", []) if isinstance(morning_report, dict) else [])
                if isinstance(item, dict)
            ]
        )
        rows.extend(
            [
                [],
                ["24 Hr Activity Timeline"],
                ["Time", "Activity"],
            ]
        )
        rows.extend(
            [
                [item.get("time", ""), item.get("activity", "")]
                for item in (morning_report.get("activity_timeline", []) if isinstance(morning_report, dict) else [])
                if isinstance(item, dict)
            ]
        )
        rows.extend([[], ["Data Quality Notes"]])
        rows.extend([["Note", note] for note in notes])

        sheet_rows = []
        for row_index, row in enumerate(rows, start=1):
            cells = []
            for column_index, value in enumerate(row, start=1):
                ref = f"{LocalStateStore._xlsx_column_name(column_index)}{row_index}"
                if isinstance(value, int | float) and not isinstance(value, bool):
                    cells.append(f'<c r="{ref}"><v>{value}</v></c>')
                else:
                    cells.append(
                        f'<c r="{ref}" t="inlineStr"><is><t>{xml_escape(str(value))}</t></is></c>'
                    )
            sheet_rows.append(f'<row r="{row_index}">{"".join(cells)}</row>')

        sheet_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<sheetData>'
            f'{"".join(sheet_rows)}'
            '</sheetData></worksheet>'
        )
        workbook_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="Failures" sheetId="1" r:id="rId1"/></sheets></workbook>'
        )
        rels_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="xl/workbook.xml"/></Relationships>'
        )
        workbook_rels_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            'Target="worksheets/sheet1.xml"/></Relationships>'
        )
        content_types_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            '</Types>'
        )

        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as workbook:
            workbook.writestr("[Content_Types].xml", content_types_xml)
            workbook.writestr("_rels/.rels", rels_xml)
            workbook.writestr("xl/workbook.xml", workbook_xml)
            workbook.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml)
            workbook.writestr("xl/worksheets/sheet1.xml", sheet_xml)
        return buffer.getvalue()

    @staticmethod
    def _pdf_escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    @staticmethod
    def _xlsx_column_name(index: int) -> str:
        name = ""
        while index:
            index, remainder = divmod(index - 1, 26)
            name = chr(65 + remainder) + name
        return name

    def _parse_job_file(self, job: ProcessingJob) -> dict[str, object]:
        if not job.file_id or job.file_id not in self.files:
            return {"ok": False, "result": "file_missing"}

        file_record = self.files[job.file_id]
        upload = self.uploads.get(file_record.upload_id)
        if upload is None:
            return {"ok": False, "result": "upload_missing"}

        storage_path = self._storage_path_from_uri(file_record.storage_uri)
        if storage_path is None or not storage_path.exists():
            return {"ok": False, "result": "storage_object_missing"}

        content = storage_path.read_bytes()
        if self._is_zip_file(file_record):
            return self._expand_zip_archive(job, upload, file_record, content)

        return self._parse_file_content(upload, file_record, content)

    def _parse_file_content(
        self,
        upload: Upload,
        file_record: UploadFileRecord,
        content: bytes,
        parent_file_id: UUID | None = None,
    ) -> dict[str, object]:
        parser_name, text, parser_metadata = self._extract_text(file_record, content)
        parse_result = "parsed"
        source_parser_name = parser_name
        routing_reason = self._ocr_routing_reason(file_record)
        if not text:
            if self._should_route_to_ocr(file_record, parser_name):
                ocr_result = extract_ocr_text(file_record.original_path, file_record.mime_type, content)
                if ocr_result.ok:
                    parser_name = "ocr_text_v1"
                    text = ocr_result.text
                    parser_metadata = {
                        **parser_metadata,
                        "extraction": "ocr_text",
                        "engine": ocr_result.engine,
                        "ocr_status": "extracted",
                        "source_parser_name": source_parser_name,
                        "routing_reason": routing_reason,
                        "pages": ocr_result.pages,
                        "page_count": len(ocr_result.pages),
                    }
                    parse_result = "ocr_extracted"
                else:
                    parser_metadata = {
                        **parser_metadata,
                        "ocr_status": "unavailable",
                        "ocr_detail": ocr_result.detail,
                    }
                    return self._route_file_to_ocr(upload, file_record, parent_file_id, parser_name, parser_metadata)
            else:
                return {"ok": False, "result": "no_text_extracted", "parser_name": parser_name}

        chunk_records = self._chunk_records(text, parser_name, parser_metadata)
        public_parser_metadata = self._public_parser_metadata(parser_metadata)
        document = ParsedDocument(
            tenant_id=self.tenant.id,
            workspace_id=upload.workspace_id,
            upload_id=upload.id,
            file_id=file_record.id,
            title=file_record.original_path,
            parser_name=parser_name,
            status=ProcessingStatus.COMPLETE,
            text_preview=text[:280],
            chunk_count=len(chunk_records),
            metadata={
                "mime_type": file_record.mime_type,
                "byte_size": file_record.byte_size,
                "sha256": file_record.sha256,
                "parent_file_id": str(parent_file_id) if parent_file_id else None,
                "parser": public_parser_metadata,
            },
        )
        self.parsed_documents[document.id] = document

        locator_type = self._source_locator_type(parser_name)
        for ordinal, chunk_record in enumerate(chunk_records, start=1):
            chunk_text = str(chunk_record.get("text", ""))
            chunk = DocumentChunk(
                tenant_id=self.tenant.id,
                workspace_id=upload.workspace_id,
                upload_id=upload.id,
                file_id=file_record.id,
                document_id=document.id,
                ordinal=ordinal,
                text=chunk_text,
                locator_type=locator_type,
                locator=self._chunk_locator(
                    locator_type,
                    parser_name,
                    parser_metadata,
                    upload.id,
                    document.id,
                    file_record.original_path,
                    ordinal,
                    chunk_record,
                ),
                confidence=0.72 if locator_type == "pdf" else 0.86,
            )
            self.document_chunks[chunk.id] = chunk

        return {
            "ok": True,
            "result": parse_result,
            "parser_name": parser_name,
            "source_parser_name": source_parser_name,
            "routing_reason": routing_reason,
            "chunks_created": len(chunk_records),
            "document_ids": [document.id],
            "document_id": document.id,
            "document_chunk_counts": {str(document.id): len(chunk_records)},
            "file_ids": [str(file_record.id)],
        }

    def _route_file_to_ocr(
        self,
        upload: Upload,
        file_record: UploadFileRecord,
        parent_file_id: UUID | None,
        source_parser_name: str,
        parser_metadata: dict[str, object],
    ) -> dict[str, object]:
        routing_reason = (
            "scanned_pdf_or_image_only"
            if Path(file_record.original_path).suffix.lower() == ".pdf"
            else "image_file"
        )
        document = ParsedDocument(
            tenant_id=self.tenant.id,
            workspace_id=upload.workspace_id,
            upload_id=upload.id,
            file_id=file_record.id,
            title=file_record.original_path,
            parser_name="ocr_route_v1",
            status=ProcessingStatus.QUEUED,
            text_preview="",
            chunk_count=0,
            metadata={
                "mime_type": file_record.mime_type,
                "byte_size": file_record.byte_size,
                "sha256": file_record.sha256,
                "parent_file_id": str(parent_file_id) if parent_file_id else None,
                "parser": {
                    **parser_metadata,
                    "extraction": "ocr_required",
                    "source_parser_name": source_parser_name,
                    "routing_reason": routing_reason,
                    "ocr_status": "queued",
                    "ocr_engine": "unconfigured",
                },
            },
        )
        self.parsed_documents[document.id] = document
        task = ValidationTask(
            tenant_id=self.tenant.id,
            target_type="file",
            target_id=file_record.id,
            reason=(
                "Source file requires OCR before text extraction, citation mapping, and Monday Report "
                "evidence can be considered complete."
            ),
            priority="medium",
        )
        self.validation_tasks[task.id] = task
        return {
            "ok": True,
            "result": "ocr_routed",
            "parser_name": "ocr_route_v1",
            "source_parser_name": source_parser_name,
            "routing_reason": routing_reason,
            "chunks_created": 0,
            "document_ids": [document.id],
            "document_id": document.id,
            "document_chunk_counts": {str(document.id): 0},
            "file_ids": [str(file_record.id)],
            "validation_task_ids": [task.id],
        }

    def _expand_zip_archive(
        self,
        job: ProcessingJob,
        upload: Upload,
        archive_file: UploadFileRecord,
        content: bytes,
    ) -> dict[str, object]:
        try:
            archive = zipfile.ZipFile(BytesIO(content))
        except zipfile.BadZipFile:
            return {"ok": False, "result": "invalid_zip", "parser_name": "zip_v1"}

        entries = [info for info in archive.infolist() if not info.is_dir()]
        uncompressed_bytes = sum(info.file_size for info in entries)
        zip_entry_limit = max_zip_entries()
        zip_byte_limit = max_zip_uncompressed_bytes()
        if len(entries) > zip_entry_limit:
            return {
                "ok": False,
                "result": "zip_too_many_entries",
                "parser_name": "zip_v1",
                "archive_entries": len(entries),
                "max_zip_entries": zip_entry_limit,
            }
        if uncompressed_bytes > zip_byte_limit:
            return {
                "ok": False,
                "result": "zip_too_large",
                "parser_name": "zip_v1",
                "archive_entries": len(entries),
                "uncompressed_bytes": uncompressed_bytes,
                "max_zip_uncompressed_bytes": zip_byte_limit,
            }

        parsed_documents: list[UUID] = []
        child_file_ids: list[str] = []
        document_chunk_counts: dict[str, int] = {}
        chunks_created = 0
        unsupported_entries = 0

        for info in entries:
            safe_parts = self._safe_storage_parts(info.filename)
            if not safe_parts:
                continue
            entry_bytes = archive.read(info)
            entry_digest = sha256(entry_bytes).hexdigest()
            entry_path = "/".join(safe_parts)
            scan_result = scan_upload_content(entry_path, mimetypes.guess_type(entry_path)[0] or "", entry_bytes)
            if scan_result.status == "blocked":
                child_file = UploadFileRecord(
                    tenant_id=self.tenant.id,
                    upload_id=upload.id,
                    original_path=f"{archive_file.original_path}/{entry_path}",
                    storage_uri=(
                        f"blocked://{self.tenant.slug}/uploads/{upload.id}/extracted/"
                        f"{archive_file.id}/{entry_path}"
                    ),
                    sha256=entry_digest,
                    mime_type=mimetypes.guess_type(entry_path)[0] or "application/octet-stream",
                    byte_size=len(entry_bytes),
                    status=ProcessingStatus.FAILED,
                    malware_status="blocked",
                )
                self.files[child_file.id] = child_file
                child_file_ids.append(str(child_file.id))
                unsupported_entries += 1
                self.audit(
                    "malware.blocked",
                    "file",
                    child_file.id,
                    {
                        "upload_id": str(upload.id),
                        "archive_file_id": str(archive_file.id),
                        "entry_path": entry_path,
                        "sha256": entry_digest,
                        "malware_scan": {
                            "scanner": scan_result.scanner,
                            "status": scan_result.status,
                            "reason": scan_result.reason,
                        },
                    },
                    save=False,
                )
                continue
            storage_uri = (
                f"object://{self.tenant.slug}/uploads/{upload.id}/extracted/"
                f"{archive_file.id}/{entry_path}"
            )
            storage_path = self._storage_path_from_uri(storage_uri)
            if storage_path is None:
                unsupported_entries += 1
                continue
            storage_path.parent.mkdir(parents=True, exist_ok=True)
            storage_path.write_bytes(entry_bytes)

            guessed_mime_type = mimetypes.guess_type(entry_path)[0] or "application/octet-stream"
            child_file = UploadFileRecord(
                tenant_id=self.tenant.id,
                upload_id=upload.id,
                original_path=f"{archive_file.original_path}/{entry_path}",
                storage_uri=storage_uri,
                sha256=entry_digest,
                mime_type=guessed_mime_type,
                byte_size=len(entry_bytes),
                malware_status="clean",
            )
            self.files[child_file.id] = child_file
            child_file_ids.append(str(child_file.id))

            parse_result = self._parse_file_content(upload, child_file, entry_bytes, archive_file.id)
            if parse_result["ok"]:
                child_file.status = ProcessingStatus.COMPLETE
                document_ids = parse_result.get("document_ids", [])
                if isinstance(document_ids, list):
                    parsed_documents.extend(document_ids)
                child_chunk_counts = parse_result.get("document_chunk_counts", {})
                if isinstance(child_chunk_counts, dict):
                    document_chunk_counts.update(child_chunk_counts)
                chunks_created += int(parse_result.get("chunks_created", 0))
            else:
                child_file.status = ProcessingStatus.FAILED
                unsupported_entries += 1

        if not parsed_documents:
            return {
                "ok": False,
                "result": "zip_no_supported_entries",
                "parser_name": "zip_v1",
                "archive_entries": len(entries),
                "child_file_ids": child_file_ids,
            }

        return {
            "ok": True,
            "result": "zip_expanded",
            "parser_name": "zip_v1",
            "chunks_created": chunks_created,
            "document_ids": parsed_documents,
            "document_chunk_counts": document_chunk_counts,
            "archive_entries": len(entries),
            "child_file_ids": child_file_ids,
            "unsupported_entries": unsupported_entries,
        }

    def _extract_failures_for_documents(
        self,
        upload_id: UUID,
        document_ids: list[UUID],
    ) -> dict[str, list[UUID]]:
        if not document_ids:
            return {"failure_ids": [], "validation_task_ids": []}

        upload = self.uploads.get(upload_id)
        if upload is None or self._failure_exists_for_upload(upload_id, "MWD signal loss"):
            return {"failure_ids": [], "validation_task_ids": []}

        chunks = [
            chunk
            for chunk in self.document_chunks.values()
            if chunk.document_id in document_ids and chunk.text.strip()
        ]
        evidence_text = " ".join(chunk.text for chunk in chunks)
        normalized = evidence_text.lower()

        if "mwd" not in normalized or "signal loss" not in normalized:
            return {"failure_ids": [], "validation_task_ids": []}

        evidence_chunks = [
            chunk
            for chunk in chunks
            if "mwd" in chunk.text.lower()
            or "npt_hours" in chunk.text.lower()
            or "signal loss" in chunk.text.lower()
        ][:4]
        citations = [
            Citation(
                file_id=chunk.file_id,
                locator_type=chunk.locator_type,
                locator=chunk.locator,
                snippet=chunk.text[:240],
                confidence=chunk.confidence,
            )
            for chunk in evidence_chunks
        ]
        failure = FailureRecord(
            tenant_id=self.tenant.id,
            workspace_id=upload.workspace_id,
            event_type="MWD signal loss",
            severity="High",
            summary="MWD signal loss caused a pull out of hole and tool replacement.",
            company=self._extract_company(evidence_text),
            tool_type="MWD",
            tool_serial="unknown",
            npt_hours=self._extract_npt_hours(evidence_text),
            confidence=0.78,
            validation_status=ValidationStatus.OPEN,
            citations=citations,
        )
        self.failures[failure.id] = failure
        task = ValidationTask(
            tenant_id=self.tenant.id,
            target_type="failure",
            target_id=failure.id,
            reason="Extracted MWD signal-loss failure requires reviewer confirmation before Monday Report export.",
            priority="high",
        )
        self.validation_tasks[task.id] = task
        return {"failure_ids": [failure.id], "validation_task_ids": [task.id]}

    def _failure_exists_for_upload(self, upload_id: UUID, event_type: str) -> bool:
        upload_id_text = str(upload_id)
        for failure in self.failures.values():
            if failure.event_type != event_type:
                continue
            for citation in failure.citations:
                if citation.locator.get("upload_id") == upload_id_text:
                    return True
        return False

    def _existing_processing_job(self, upload_id: UUID, file_id: UUID) -> ProcessingJob | None:
        for job in self.jobs.values():
            if (
                job.upload_id == upload_id
                and job.file_id == file_id
                and job.job_type == "scan_parse_classify_extract"
            ):
                return job
        return None

    def _existing_report_export(self, report_id: UUID, export_format: str) -> ReportExport | None:
        for report_export in self.report_exports.values():
            if report_export.report_id == report_id and report_export.format == export_format:
                return report_export
        return None

    def _sync_upload_job_status(self, upload_id: UUID, audit_terminal: bool = False) -> None:
        upload = self.uploads.get(upload_id)
        if upload is None:
            return
        upload_jobs = [job for job in self.jobs.values() if job.upload_id == upload_id]
        if not upload_jobs:
            return

        terminal_statuses = {ProcessingStatus.COMPLETE, ProcessingStatus.FAILED}
        previous_status = upload.status
        if any(job.status not in terminal_statuses for job in upload_jobs):
            upload.status = ProcessingStatus.PROCESSING
            return

        if all(job.status == ProcessingStatus.COMPLETE for job in upload_jobs):
            upload.status = ProcessingStatus.COMPLETE
            if audit_terminal and previous_status != ProcessingStatus.COMPLETE:
                self.audit("upload.processing_complete", "upload", upload_id, save=False)
            return

        upload.status = ProcessingStatus.FAILED
        if audit_terminal and previous_status != ProcessingStatus.FAILED:
            self.audit(
                "upload.processing_failed",
                "upload",
                upload_id,
                {
                    "failed_jobs": sum(job.status == ProcessingStatus.FAILED for job in upload_jobs),
                    "complete_jobs": sum(job.status == ProcessingStatus.COMPLETE for job in upload_jobs),
                    "total_jobs": len(upload_jobs),
                },
                save=False,
            )

    @staticmethod
    def _extract_company(text: str) -> str:
        match = re.search(r"\d{4}-\d{2}-\d{2},([^,]+),[^,]*signal loss", text, re.IGNORECASE)
        if match:
            candidate = match.group(1).strip()
            if LocalStateStore._valid_extracted_company(candidate):
                return candidate
        for labeled_match in re.finditer(r"\bcompany\s*[:=]\s*([^\n\r,;]+)", text, re.IGNORECASE):
            candidate = labeled_match.group(1).strip()
            if LocalStateStore._valid_extracted_company(candidate):
                return candidate
        company_before_signal_patterns = (
            r"\d{4}-\d{2}-\d{2}\s+([A-Z][A-Za-z0-9&.\- ]{2,80}?)\s+(?:MWD|LWD|RSS|mud motor|motor|bit)?\s*signal loss",
            r"(?:^|[:.;]\s*)([A-Z][A-Za-z0-9&.\- ]{2,80}?)\s+(?:MWD|LWD|RSS|mud motor|motor|bit)?\s*signal loss",
        )
        for pattern in company_before_signal_patterns:
            for evidence_match in re.finditer(pattern, text):
                candidate = evidence_match.group(1).strip()
                if LocalStateStore._valid_extracted_company(candidate):
                    return candidate
        return "unknown"

    @staticmethod
    def _valid_extracted_company(value: str) -> bool:
        normalized = value.strip().lower()
        return bool(normalized) and normalized not in {"company", "unknown", "n/a", "none", "-"}

    @staticmethod
    def _extract_npt_hours(text: str) -> float:
        match = re.search(
            r"npt_hours\s+\d{4}-\d{2}-\d{2},[^,]+,[^,]+,([0-9]+(?:\.[0-9]+)?)",
            text,
            re.IGNORECASE,
        )
        if match:
            return float(match.group(1))
        if "npt" in text.lower():
            candidates = [float(value) for value in re.findall(r"\b([0-9]+(?:\.[0-9]+)?)\b", text)]
            if candidates:
                return candidates[-1]
        return 0.0

    def _storage_path_from_uri(self, storage_uri: str) -> Path | None:
        if not storage_uri.startswith("object://"):
            return None
        parts = [part for part in storage_uri.removeprefix("object://").split("/") if part]
        if not parts:
            return None
        path = self.storage_root
        for part in parts:
            path /= part
        root = self.storage_root.resolve()
        resolved = path.resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            return None
        return resolved

    def _scan_file_record(self, file_record: UploadFileRecord) -> MalwareScanResult:
        storage_path = self._storage_path_from_uri(file_record.storage_uri)
        if storage_path is None or not storage_path.exists():
            return MalwareScanResult("clean", "builtin_baseline", "storage_object_unavailable")
        return scan_upload_content(file_record.original_path, file_record.mime_type, storage_path.read_bytes())

    @staticmethod
    def _is_zip_file(file_record: UploadFileRecord) -> bool:
        suffix = Path(file_record.original_path).suffix.lower()
        return suffix == ".zip" or file_record.mime_type.lower() in ZIP_MIME_TYPES

    @staticmethod
    def _should_route_to_ocr(file_record: UploadFileRecord, parser_name: str) -> bool:
        suffix = Path(file_record.original_path).suffix.lower()
        mime_type = file_record.mime_type.lower()
        return (
            suffix in IMAGE_FILE_EXTENSIONS
            or mime_type.startswith("image/")
            or (parser_name == "pdf_text_v1" and (suffix == ".pdf" or mime_type == "application/pdf"))
        )

    @staticmethod
    def _ocr_routing_reason(file_record: UploadFileRecord) -> str:
        return "scanned_pdf_or_image_only" if Path(file_record.original_path).suffix.lower() == ".pdf" else "image_file"

    @staticmethod
    def _source_locator_type(parser_name: str) -> str:
        return {
            "csv_text_v1": "csv",
            "docx_text_v1": "word",
            "email_text_v1": "email",
            "ocr_text_v1": "image",
            "pdf_text_v1": "pdf",
            "xlsx_text_v1": "excel",
        }.get(parser_name, "text")

    @staticmethod
    def _chunk_locator(
        locator_type: str,
        parser_name: str,
        parser_metadata: dict[str, object],
        upload_id: UUID,
        document_id: UUID,
        file_path: str,
        ordinal: int,
        chunk_context: dict[str, object] | None = None,
    ) -> dict[str, object]:
        locator: dict[str, object] = {
            "chunk": ordinal,
            "file_path": file_path,
            "upload_id": str(upload_id),
            "document_id": str(document_id),
            "parser_name": parser_name,
        }
        extraction = parser_metadata.get("extraction")
        if extraction:
            locator["extraction"] = extraction
        if locator_type == "pdf":
            page = chunk_context.get("page") if chunk_context else None
            locator["page"] = page if isinstance(page, int) and page > 0 else 1
            page_count = parser_metadata.get("page_count")
            if isinstance(page_count, int) and page_count > 0:
                locator["page_count"] = page_count
            table_number = chunk_context.get("table") if chunk_context else None
            row_start = chunk_context.get("row_start") if chunk_context else None
            row_end = chunk_context.get("row_end") if chunk_context else None
            if isinstance(table_number, int) and table_number > 0:
                locator["table"] = table_number
            if isinstance(row_start, int) and row_start > 0:
                locator["row_start"] = row_start
            if isinstance(row_end, int) and row_end > 0:
                locator["row_end"] = row_end
        elif locator_type == "image":
            page = chunk_context.get("page") if chunk_context else None
            if isinstance(page, int) and page > 0:
                locator["page"] = page
            engine = parser_metadata.get("engine")
            if isinstance(engine, str) and engine:
                locator["ocr_engine"] = engine
            locator["ocr_status"] = str(parser_metadata.get("ocr_status", "extracted"))
        elif locator_type == "csv":
            locator["row_start"] = 1
            row_count = parser_metadata.get("row_count")
            if isinstance(row_count, int) and row_count > 0:
                locator["row_end"] = row_count
        elif locator_type == "excel":
            locator["sheet"] = "workbook"
        elif locator_type == "word":
            locator["section"] = "body"
        elif locator_type == "email":
            locator["part"] = "body"
            subject = parser_metadata.get("subject")
            if isinstance(subject, str) and subject:
                locator["subject"] = subject[:160]
        return locator

    @staticmethod
    def _extract_text(file_record: UploadFileRecord, content: bytes) -> tuple[str, str, dict[str, object]]:
        suffix = Path(file_record.original_path).suffix.lower()
        mime_type = file_record.mime_type.lower()
        if suffix in CSV_FILE_EXTENSIONS or "csv" in mime_type:
            parser_name = "csv_text_v1"
            raw_text = content.decode("utf-8", errors="ignore")
            metadata: dict[str, object] = {
                "extraction": "csv_rows",
                "row_count": LocalStateStore._count_nonempty_lines(raw_text),
            }
        elif suffix in TEXT_FILE_EXTENSIONS or mime_type.startswith("text/"):
            parser_name = "plain_text_v1"
            raw_text = content.decode("utf-8", errors="ignore")
            metadata: dict[str, object] = {"extraction": "plain_text"}
        elif suffix in WORD_FILE_EXTENSIONS:
            parser_name = "docx_text_v1"
            raw_text = LocalStateStore._extract_docx_text(content)
            metadata = {"extraction": "word_document_xml"}
        elif suffix in EXCEL_FILE_EXTENSIONS:
            parser_name = "xlsx_text_v1"
            raw_text = LocalStateStore._extract_xlsx_text(content)
            metadata = {"extraction": "worksheet_rows"}
        elif suffix in EMAIL_FILE_EXTENSIONS or mime_type == "message/rfc822":
            parser_name = "email_text_v1"
            raw_text = LocalStateStore._extract_email_text(content)
            metadata = {
                "extraction": "email_body",
                "subject": LocalStateStore._extract_email_subject(content),
            }
        elif suffix == ".pdf" or mime_type == "application/pdf":
            parser_name = "pdf_text_v1"
            raw_text, pdf_metadata = LocalStateStore._extract_pdf_text(content)
            metadata = {
                "extraction": "embedded_text",
                **pdf_metadata,
            }
        else:
            return "unsupported_probe_v1", "", {"extraction": "unsupported"}

        clean_text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]+", " ", raw_text)
        clean_text = re.sub(r"\s+", " ", clean_text).strip()
        return parser_name, clean_text, metadata

    @staticmethod
    def _chunk_records(text: str, parser_name: str, parser_metadata: dict[str, object]) -> list[dict[str, object]]:
        if parser_name in {"pdf_text_v1", "ocr_text_v1"}:
            pages = parser_metadata.get("pages")
            if isinstance(pages, list):
                records: list[dict[str, object]] = []
                for page in pages:
                    if not isinstance(page, dict):
                        continue
                    page_number = page.get("page")
                    page_text = page.get("text")
                    if not isinstance(page_number, int) or not isinstance(page_text, str):
                        continue
                    for chunk_text in LocalStateStore._chunk_text(page_text):
                        records.append({"text": chunk_text, "page": page_number})
                tables = parser_metadata.get("tables")
                if parser_name == "pdf_text_v1" and isinstance(tables, list):
                    for table in tables:
                        if not isinstance(table, dict):
                            continue
                        records.extend(LocalStateStore._pdf_table_chunk_records(table))
                if records:
                    return records
        return [{"text": chunk_text} for chunk_text in LocalStateStore._chunk_text(text)]

    @staticmethod
    def _public_parser_metadata(parser_metadata: dict[str, object]) -> dict[str, object]:
        public_metadata: dict[str, object] = {}
        for key, value in parser_metadata.items():
            if key == "pages" and isinstance(value, list):
                public_metadata["page_text_lengths"] = [
                    {"page": item.get("page"), "characters": len(item.get("text", ""))}
                    for item in value
                    if isinstance(item, dict)
                ]
                continue
            if key == "tables" and isinstance(value, list):
                public_metadata["tables"] = [
                    {
                        "page": item.get("page"),
                        "table": item.get("table"),
                        "row_count": item.get("row_count"),
                        "column_count": item.get("column_count"),
                    }
                    for item in value
                    if isinstance(item, dict)
                ]
                public_metadata["table_count"] = len(public_metadata["tables"])
                continue
            public_metadata[key] = value
        return public_metadata

    @staticmethod
    def _pdf_table_chunk_records(table: dict[str, object]) -> list[dict[str, object]]:
        page = table.get("page")
        table_number = table.get("table")
        rows = table.get("rows")
        if not isinstance(page, int) or not isinstance(table_number, int) or not isinstance(rows, list):
            return []

        header = rows[0] if rows and isinstance(rows[0], list) else []
        records: list[dict[str, object]] = []
        for index, row in enumerate(rows, start=1):
            if not isinstance(row, list) or not any(str(cell).strip() for cell in row):
                continue
            row_text = LocalStateStore._pdf_table_row_text(header, row)
            if not row_text:
                continue
            records.append(
                {
                    "text": f"PDF table {table_number} row {index}: {row_text}",
                    "page": page,
                    "table": table_number,
                    "row_start": index,
                    "row_end": index,
                }
            )
        return records

    @staticmethod
    def _pdf_table_row_text(header: object, row: list[object]) -> str:
        cells = [str(cell).strip() for cell in row]
        if isinstance(header, list) and len(header) == len(row):
            pairs = [
                f"{str(column).strip()}: {value}"
                for column, value in zip(header, cells)
                if str(column).strip() and value
            ]
            if pairs:
                return "; ".join(pairs)
        return " | ".join(value for value in cells if value)

    @staticmethod
    def _count_nonempty_lines(text: str) -> int:
        return sum(1 for line in text.splitlines() if line.strip())

    @staticmethod
    def _extract_docx_text(content: bytes) -> str:
        try:
            with zipfile.ZipFile(BytesIO(content)) as document:
                xml_text = document.read("word/document.xml")
        except (KeyError, zipfile.BadZipFile):
            return ""

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return ""

        texts = [node.text or "" for node in root.iter() if node.tag.endswith("}t")]
        return " ".join(text for text in texts if text.strip())

    @staticmethod
    def _extract_xlsx_text(content: bytes) -> str:
        try:
            with zipfile.ZipFile(BytesIO(content)) as workbook:
                shared_strings = LocalStateStore._xlsx_shared_strings(workbook)
                worksheet_names = sorted(
                    name
                    for name in workbook.namelist()
                    if name.startswith("xl/worksheets/") and name.endswith(".xml")
                )
                rows: list[str] = []
                for worksheet_name in worksheet_names:
                    rows.extend(LocalStateStore._xlsx_worksheet_rows(workbook.read(worksheet_name), shared_strings))
        except (KeyError, zipfile.BadZipFile):
            return ""
        return " ".join(rows)

    @staticmethod
    def _xlsx_shared_strings(workbook: zipfile.ZipFile) -> list[str]:
        try:
            root = ET.fromstring(workbook.read("xl/sharedStrings.xml"))
        except (KeyError, ET.ParseError):
            return []
        values: list[str] = []
        for item in root:
            parts = [node.text or "" for node in item.iter() if node.tag.endswith("}t")]
            values.append("".join(parts))
        return values

    @staticmethod
    def _xlsx_worksheet_rows(xml_text: bytes, shared_strings: list[str]) -> list[str]:
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return []
        rows: list[str] = []
        for row in root.iter():
            if not row.tag.endswith("}row"):
                continue
            values: list[str] = []
            for cell in row:
                if not cell.tag.endswith("}c"):
                    continue
                cell_type = cell.attrib.get("t", "")
                value_node = next((node for node in cell if node.tag.endswith("}v")), None)
                inline_node = next((node for node in cell if node.tag.endswith("}is")), None)
                if cell_type == "inlineStr" and inline_node is not None:
                    values.append("".join(node.text or "" for node in inline_node.iter() if node.tag.endswith("}t")))
                elif value_node is not None and value_node.text is not None:
                    if cell_type == "s" and value_node.text.isdigit():
                        index = int(value_node.text)
                        values.append(shared_strings[index] if index < len(shared_strings) else value_node.text)
                    else:
                        values.append(value_node.text)
            if any(value.strip() for value in values):
                rows.append(" ".join(values))
        return rows

    @staticmethod
    def _extract_email_text(content: bytes) -> str:
        message = BytesParser(policy=policy.default).parsebytes(content)
        parts = [
            f"Subject: {message.get('subject', '')}",
            f"From: {message.get('from', '')}",
            f"To: {message.get('to', '')}",
        ]
        if message.is_multipart():
            for part in message.walk():
                if part.get_content_type() == "text/plain":
                    parts.append(str(part.get_content()))
        elif message.get_content_type() == "text/plain":
            parts.append(str(message.get_content()))
        return " ".join(part for part in parts if part.strip())

    @staticmethod
    def _extract_email_subject(content: bytes) -> str:
        message = BytesParser(policy=policy.default).parsebytes(content)
        return str(message.get("subject", "")).strip()

    @staticmethod
    def _extract_pdf_text(content: bytes) -> tuple[str, dict[str, object]]:
        pymupdf_text, pymupdf_metadata = LocalStateStore._extract_pdf_text_with_pymupdf(content)
        if pymupdf_text.strip():
            return pymupdf_text, {
                "engine": "pymupdf",
                **pymupdf_metadata,
            }

        if "pymupdf_error" not in pymupdf_metadata:
            return "", {
                "engine": "pymupdf",
                **pymupdf_metadata,
            }

        fallback_text = LocalStateStore._extract_pdf_text_from_streams(content)
        fallback_metadata = {
            "engine": "pdf_stream_fallback",
            "page_count": pymupdf_metadata.get("page_count", LocalStateStore._pdf_page_count(content)),
            "pages_with_text": 1 if fallback_text.strip() else 0,
        }
        if "pymupdf_error" in pymupdf_metadata:
            fallback_metadata["pymupdf_error"] = pymupdf_metadata["pymupdf_error"]
        return fallback_text, fallback_metadata

    @staticmethod
    def _extract_pdf_text_with_pymupdf(content: bytes) -> tuple[str, dict[str, object]]:
        try:
            import fitz  # type: ignore[import-not-found]
        except ImportError:
            return "", {"page_count": LocalStateStore._pdf_page_count(content), "pymupdf_error": "ImportError"}

        try:
            with fitz.open(stream=content, filetype="pdf") as document:
                pages: list[dict[str, object]] = []
                tables: list[dict[str, object]] = []
                for page_index, page in enumerate(document, start=1):
                    page_text = page.get_text("text").strip()
                    if page_text:
                        pages.append({"page": page_index, "text": page_text})
                    tables.extend(LocalStateStore._extract_pdf_page_tables(page, page_index))
                text_parts = [str(page["text"]) for page in pages]
                text_parts.extend(LocalStateStore._pdf_table_preview_text(table) for table in tables)
                return (
                    "\n".join(part for part in text_parts if part.strip()),
                    {
                        "page_count": document.page_count,
                        "pages_with_text": len(pages),
                        "pages": pages,
                        "tables": tables,
                        "table_count": len(tables),
                    },
                )
        except Exception as exc:
            return "", {"page_count": LocalStateStore._pdf_page_count(content), "pymupdf_error": exc.__class__.__name__}

    @staticmethod
    def _extract_pdf_page_tables(page: object, page_number: int) -> list[dict[str, object]]:
        try:
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                table_result = page.find_tables()  # type: ignore[attr-defined]
            raw_tables = getattr(table_result, "tables", [])
        except Exception:
            return []

        tables: list[dict[str, object]] = []
        for table_index, table in enumerate(raw_tables, start=1):
            try:
                raw_rows = table.extract()
            except Exception:
                continue
            rows = LocalStateStore._normalize_pdf_table_rows(raw_rows)
            if len(rows) < 2:
                continue
            column_count = max((len(row) for row in rows), default=0)
            tables.append(
                {
                    "page": page_number,
                    "table": table_index,
                    "row_count": len(rows),
                    "column_count": column_count,
                    "rows": rows,
                }
            )
        return tables

    @staticmethod
    def _normalize_pdf_table_rows(raw_rows: object) -> list[list[str]]:
        if not isinstance(raw_rows, list):
            return []
        rows: list[list[str]] = []
        for raw_row in raw_rows:
            if not isinstance(raw_row, list):
                continue
            row = [str(cell or "").strip() for cell in raw_row]
            if any(row):
                rows.append(row)
        return rows

    @staticmethod
    def _pdf_table_preview_text(table: dict[str, object]) -> str:
        rows = table.get("rows")
        page = table.get("page")
        table_number = table.get("table")
        if not isinstance(rows, list):
            return ""
        row_texts = [
            LocalStateStore._pdf_table_row_text(rows[0], row)
            for row in rows
            if isinstance(row, list)
        ]
        prefix = f"PDF table {table_number} page {page}:"
        return f"{prefix} {' '.join(text for text in row_texts if text)}"

    @staticmethod
    def _extract_pdf_text_from_streams(content: bytes) -> str:
        stream_texts: list[str] = []
        for match in PDF_STREAM_PATTERN.finditer(content):
            header = match.group("header")
            body = match.group("body").strip(b"\r\n")
            if b"/FlateDecode" in header:
                try:
                    body = zlib.decompress(body)
                except zlib.error:
                    continue
            stream_text = body.decode("latin-1", errors="ignore")
            stream_texts.extend(LocalStateStore._extract_pdf_stream_text(stream_text))

        if not stream_texts:
            fallback_text = content.decode("latin-1", errors="ignore")
            stream_texts.extend(LocalStateStore._extract_pdf_stream_text(fallback_text))

        return " ".join(text for text in stream_texts if text.strip())

    @staticmethod
    def _extract_pdf_stream_text(stream_text: str) -> list[str]:
        if not any(operator in stream_text for operator in ("Tj", "TJ", "'", '"')):
            return []
        texts = [
            LocalStateStore._decode_pdf_literal(match.group(0))
            for match in re.finditer(r"\((?:\\.|[^\\()])*\)", stream_text)
        ]
        for match in re.finditer(r"<([0-9A-Fa-f\s]+)>", stream_text):
            raw_hex = re.sub(r"\s+", "", match.group(1))
            if len(raw_hex) < 2 or len(raw_hex) % 2:
                continue
            try:
                raw_bytes = bytes.fromhex(raw_hex)
            except ValueError:
                continue
            if raw_bytes.startswith(b"\xfe\xff"):
                texts.append(raw_bytes[2:].decode("utf-16-be", errors="ignore"))
            else:
                texts.append(raw_bytes.decode("utf-8", errors="ignore") or raw_bytes.decode("latin-1", errors="ignore"))
        return [text for text in texts if text.strip()]

    @staticmethod
    def _decode_pdf_literal(value: str) -> str:
        inner = value[1:-1]
        decoded: list[str] = []
        index = 0
        escape_map = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "(": "(", ")": ")", "\\": "\\"}
        while index < len(inner):
            character = inner[index]
            if character != "\\":
                decoded.append(character)
                index += 1
                continue
            index += 1
            if index >= len(inner):
                break
            escaped = inner[index]
            if escaped in "\r\n":
                while index < len(inner) and inner[index] in "\r\n":
                    index += 1
                continue
            if escaped in "01234567":
                octal = escaped
                index += 1
                while index < len(inner) and len(octal) < 3 and inner[index] in "01234567":
                    octal += inner[index]
                    index += 1
                decoded.append(chr(int(octal, 8)))
                continue
            decoded.append(escape_map.get(escaped, escaped))
            index += 1
        return "".join(decoded)

    @staticmethod
    def _pdf_page_count(content: bytes) -> int:
        return max(1, len(re.findall(rb"/Type\s*/Page\b", content)))

    @staticmethod
    def _chunk_text(text: str, target_size: int = 900) -> list[str]:
        words = text.split()
        chunks: list[str] = []
        current: list[str] = []
        current_size = 0

        for word in words:
            next_size = current_size + len(word) + (1 if current else 0)
            if current and next_size > target_size:
                chunks.append(" ".join(current))
                current = [word]
                current_size = len(word)
            else:
                current.append(word)
                current_size = next_size

        if current:
            chunks.append(" ".join(current))

        return chunks

    def audit(
        self,
        action: str,
        resource_type: str,
        resource_id: UUID | None = None,
        metadata: dict | None = None,
        save: bool = True,
    ) -> None:
        previous_hash = self._audit_chain_hash(self.audit_logs[-1]) if self.audit_logs else None
        audit_log = AuditLog(
            tenant_id=self.tenant.id,
            actor_user_id=self.user.id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            metadata=sanitize_audit_metadata(metadata),
            previous_hash=previous_hash,
        )
        audit_log.entry_hash = self._audit_event_hash(audit_log)
        self.audit_logs.append(audit_log)
        if save:
            self.save()

    def audit_integrity_status(self) -> AuditIntegrityStatus:
        self.refresh()
        total_events = len(self.audit_logs)
        hashed_events = 0
        legacy_events = 0
        broken_events = 0
        previous_chain_hash: str | None = None

        for event in self.audit_logs:
            expected_hash = self._audit_event_hash(event)
            if event.entry_hash:
                hashed_events += 1
                if event.entry_hash != expected_hash:
                    broken_events += 1
                if event.previous_hash != previous_chain_hash:
                    broken_events += 1
                previous_chain_hash = event.entry_hash
            else:
                legacy_events += 1
                previous_chain_hash = expected_hash

        if total_events == 0:
            status = "empty"
            detail = "No audit events are recorded."
        elif broken_events:
            status = "broken"
            detail = f"{broken_events} audit integrity issue(s) detected."
        elif legacy_events:
            status = "legacy"
            detail = f"{legacy_events} legacy audit event(s) predate hash-chain sealing."
        else:
            status = "sealed"
            detail = "All audit events are hash-chain sealed."

        return AuditIntegrityStatus(
            status=status,  # type: ignore[arg-type]
            total_events=total_events,
            hashed_events=hashed_events,
            legacy_events=legacy_events,
            broken_events=broken_events,
            latest_hash=previous_chain_hash,
            detail=detail,
        )

    def _audit_chain_hash(self, event: AuditLog) -> str:
        return event.entry_hash or self._audit_event_hash(event)

    @staticmethod
    def _audit_event_hash(event: AuditLog) -> str:
        payload = {
            "id": str(event.id),
            "tenant_id": str(event.tenant_id),
            "actor_user_id": str(event.actor_user_id),
            "action": event.action,
            "resource_type": event.resource_type,
            "resource_id": str(event.resource_id) if event.resource_id else None,
            "metadata": event.metadata,
            "created_at": event.created_at.isoformat(),
            "previous_hash": event.previous_hash,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _dump_map(items: dict[UUID, object]) -> list[dict]:
        return [item.model_dump(mode="json") for item in items.values()]

    @staticmethod
    def _load_map(model, items: list[dict]) -> dict[UUID, object]:
        loaded = [model.model_validate(item) for item in items]
        return {item.id: item for item in loaded}

    @staticmethod
    def _safe_storage_parts(file_name: str) -> list[str]:
        parts: list[str] = []
        for raw_part in file_name.replace("\\", "/").split("/"):
            cleaned = INVALID_STORAGE_CHARS.sub("_", raw_part).strip().strip(".")
            if not cleaned:
                continue
            base_name = cleaned.split(".", 1)[0].upper()
            if base_name in RESERVED_STORAGE_NAMES:
                cleaned = f"_{cleaned}"
            parts.append(cleaned[:120])
        return parts or ["upload.bin"]


class PostgresStateStore(LocalStateStore):
    """PostgreSQL-backed MVP state repository with tenant-scoped RLS.

    The application data model still uses the LocalStateStore domain methods,
    but the durable state payload is stored in PostgreSQL instead of a local
    JSON file. This is the first active repository adapter for client-mode
    readiness and keeps the migration path small while normalized repositories
    continue to mature.
    """

    repository_backend = POSTGRES_REPOSITORY_BACKEND
    STATE_TABLE = "monday_report_state_snapshots"

    def __init__(self, url: str) -> None:
        self.database_url = url
        self._ensure_repository_schema()
        super().__init__()

    def _state_exists(self) -> bool:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                self._set_tenant_scope(cursor)
                cursor.execute(
                    f"select 1 from {self.STATE_TABLE} where tenant_slug = %s limit 1",
                    (self.tenant.slug,),
                )
                return cursor.fetchone() is not None

    def _read_state_payload(self) -> dict[str, object] | None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                self._set_tenant_scope(cursor)
                cursor.execute(
                    f"select payload from {self.STATE_TABLE} where tenant_slug = %s",
                    (self.tenant.slug,),
                )
                row = cursor.fetchone()
                if row is None:
                    return None
                payload = row[0]
                return payload if isinstance(payload, dict) else json.loads(str(payload))

    def save(self) -> None:
        from psycopg.types.json import Jsonb

        payload = self._state_payload()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                self._set_tenant_scope(cursor)
                cursor.execute(
                    f"""
                    insert into {self.STATE_TABLE} (tenant_slug, tenant_id, payload)
                    values (%s, %s, %s)
                    on conflict (tenant_slug)
                    do update set
                      tenant_id = excluded.tenant_id,
                      payload = excluded.payload,
                      updated_at = now()
                    """,
                    (self.tenant.slug, self.tenant.id, Jsonb(payload)),
                )

    def _ensure_repository_schema(self) -> None:
        statements = [
            f"""
            create table if not exists {self.STATE_TABLE} (
              tenant_slug text primary key,
              tenant_id uuid not null,
              payload jsonb not null,
              created_at timestamptz not null default now(),
              updated_at timestamptz not null default now()
            )
            """,
            f"alter table {self.STATE_TABLE} enable row level security",
            f"alter table {self.STATE_TABLE} force row level security",
            f"drop policy if exists tenant_isolation_{self.STATE_TABLE} on {self.STATE_TABLE}",
            f"""
            create policy tenant_isolation_{self.STATE_TABLE}
            on {self.STATE_TABLE}
            using (tenant_slug = current_setting('app.tenant_slug', true))
            with check (tenant_slug = current_setting('app.tenant_slug', true))
            """,
        ]
        with self._connect() as connection:
            with connection.cursor() as cursor:
                for statement in statements:
                    cursor.execute(statement)

    def _connect(self):
        import psycopg

        return psycopg.connect(self.database_url, connect_timeout=2)

    def _set_tenant_scope(self, cursor) -> None:
        cursor.execute("select set_config('app.tenant_slug', %s, true)", (self.tenant.slug,))


def create_store() -> LocalStateStore:
    if requested_repository_backend() == POSTGRES_REPOSITORY_BACKEND and database_url():
        try:
            return PostgresStateStore(database_url())
        except Exception as exc:  # noqa: BLE001 - app must start so readiness can report the blocker.
            print(
                f"WARN: PostgreSQL repository unavailable; falling back to local JSON: {exc.__class__.__name__}",
                file=sys.stderr,
            )
    return LocalStateStore()


store = create_store()
