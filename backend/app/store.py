from __future__ import annotations

import json
import math
import mimetypes
import os
import re
import sys
import threading
import time
import zipfile
import zlib
import xml.etree.ElementTree as ET
from contextlib import redirect_stderr, redirect_stdout
from datetime import date, datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
from hashlib import sha256
from io import BytesIO, StringIO
from pathlib import Path
from uuid import UUID, uuid4
from xml.sax.saxutils import escape as xml_escape

from .archive_limits import max_zip_entries, max_zip_uncompressed_bytes
from .audit_safety import sanitize_audit_metadata
from .auth import (
    api_key_configured,
    api_key_valid,
    generate_api_token,
    hash_token,
    is_well_formed_token,
    token_fingerprint,
    tokens_match,
)
from .identity import get_current_identity
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
    AiReportStatement,
    AuditIntegrityStatus,
    AuditLog,
    AnomalyEvent,
    AnomalyRule,
    AuthenticatedIdentity,
    StoredApiCredential,
    BenchmarkComparison,
    BenchmarkMeasurement,
    BenchmarkMeasurementCreate,
    BenchmarkValue,
    BenchmarkValueUpdate,
    BenchmarkingStatus,
    Citation,
    DiagnosticAction,
    DocumentChunk,
    FailureRecord,
    FieldCorrection,
    FieldCorrectionCreate,
    KeyDecision,
    MondayReport,
    ParsedDocument,
    ProcessingJob,
    ProcessingStatus,
    ReportExport,
    RetentionRunResult,
    Role,
    Tenant,
    TrajectoryCalculation,
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
from .trajectory import calculate_trajectory

INVALID_STORAGE_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')
UNSAFE_TEXT_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]+")
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
FEET_DRILLED_PER_DAY = "feet_drilled_per_day"

# Reference (non-extracted) schematic geometry. These rows are shown only when no
# source evidence is available and are always labelled source="reference" so they
# can never be mistaken for values extracted from an uploaded daily drilling report.
REFERENCE_CASING_STRINGS = [
    {"name": "Conductor", "od": "20 in", "top_ft": 0.0, "shoe_ft": 130.0},
    {"name": "Surface", "od": "13.375 in", "top_ft": 0.0, "shoe_ft": 1629.0},
    {"name": "Intermediate", "od": "9.625 in", "top_ft": 0.0, "shoe_ft": 6500.0},
    {"name": "Production", "od": "7 in", "top_ft": 0.0, "shoe_ft": 10987.0},
]
REFERENCE_HOLE_SECTIONS = [
    {"hole_size": "17.5 in", "interval_ft": "0-1,629", "status": "surface hole reference"},
    {"hole_size": "12.25 in", "interval_ft": "1,629-6,500", "status": "intermediate hole plan"},
    {"hole_size": "8.5 in", "interval_ft": "6,500-10,987", "status": "production hole plan"},
]
REFERENCE_ACTIVITY_TIMELINE = [
    {"time": "00:00-06:00", "activity": "Review overnight source evidence, benchmark performance, and validate extracted NPT/failure records."},
    {"time": "06:00-12:00", "activity": "Confirm safety, well-control, casing, and BHA status for morning handover."},
    {"time": "12:00-18:00", "activity": "Close validation gaps, attach source citations, and update recommended actions."},
    {"time": "18:00-24:00", "activity": "Prepare branded Monday Report export package after approval gate passes."},
]

BENCHMARK_METRICS = [
    FEET_DRILLED_PER_DAY,
    "dogleg_severity",
    "lateral_percentage",
    "slide_rotate_performance",
    "drilling_hours",
    "trip_time",
    "nonproductive_time",
    "directional_plan_adherence",
]
BENCHMARK_SEED_VALUES = [
    {
        "benchmark_name": "Gordon average",
        "metric": FEET_DRILLED_PER_DAY,
        "value": 528.0,
        "unit": "ft/day",
        "performance_category": "average",
        "data_source": "Approved operator benchmark seed",
        "dataset_version": "seed-2026-07",
    },
    {
        "benchmark_name": "Noble top-quartile",
        "metric": FEET_DRILLED_PER_DAY,
        "value": 588.0,
        "unit": "ft/day",
        "performance_category": "top-quartile",
        "data_source": "Approved market benchmark seed",
        "dataset_version": "seed-2026-07",
    },
]
BENCHMARK_RULE_SEEDS = [
    {
        "name": "Top-quartile performance gap",
        "metric": FEET_DRILLED_PER_DAY,
        "severity": "Advisory",
        "benchmark_name": "Noble top-quartile",
        "threshold_mode": "below_benchmark",
        "threshold_percent": None,
        "diagnostic_modules": [],
    },
    {
        "name": "Below approved average drilling rate",
        "metric": FEET_DRILLED_PER_DAY,
        "severity": "Warning",
        "benchmark_name": "Gordon average",
        "threshold_mode": "below_benchmark",
        "threshold_percent": None,
        "diagnostic_modules": [],
    },
    {
        "name": "Critical drilling-rate deviation",
        "metric": FEET_DRILLED_PER_DAY,
        "severity": "Critical",
        "benchmark_name": "Gordon average",
        "threshold_mode": "below_percent_of_benchmark",
        "threshold_percent": 85.0,
        "diagnostic_modules": ["Hydraulics", "Torque & Drag"],
    },
]


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
        self.benchmark_values: dict[UUID, BenchmarkValue] = {}
        self.anomaly_rules: dict[UUID, AnomalyRule] = {}
        self.benchmark_measurements: dict[UUID, BenchmarkMeasurement] = {}
        self.anomaly_events: dict[UUID, AnomalyEvent] = {}
        self.key_decisions: dict[UUID, KeyDecision] = {}
        self.field_corrections: dict[UUID, FieldCorrection] = {}
        # Authenticated-identity foundation: server-side user records and their
        # per-user API credentials (only hashes + fingerprints are stored).
        self.users: dict[UUID, User] = {}
        self.api_credentials: dict[UUID, StoredApiCredential] = {}
        # Serializes identity provisioning/revocation on the shared singleton.
        self.identity_lock = threading.RLock()
        # Serializes the WHOLE field-correction route (refresh -> checks ->
        # record/revert -> save) within one process, so a concurrent handler's
        # refresh() cannot clobber an in-flight append on this shared singleton.
        # Re-entrant so the store methods can re-acquire it. This makes the
        # single-active-lineage-and-no-lost-write invariant safe in-process;
        # cross-process atomicity still requires normalized persistence
        # (Phase 04) — the local JSON snapshot is last-writer-wins across
        # processes.
        self.field_correction_lock = threading.RLock()
        self.audit_logs: list[AuditLog] = []

        if self._state_exists():
            self.refresh()
            if self._contains_demo_seed():
                self._reset_clean_bootstrap()
                self.save()
        else:
            self._seed()
            self.save()
        if self._ensure_benchmarking_defaults():
            self.save()
        # NOTE: the demo bootstrap identity is derived in memory (see
        # demo_bootstrap_identity); it is intentionally NOT persisted on import,
        # construction, start, reload, health, or route access. A user is
        # persisted ONLY through an explicit provisioning operation
        # (create_user / the identity_admin CLI).

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
        self.field_corrections.clear()
        self.users.clear()
        self.api_credentials.clear()
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

    # ------------------------------------------------------------------
    # Authenticated-identity foundation.
    #
    # This is a BOUNDED first slice: opaque per-user credentials are resolved
    # server-side to a request-scoped identity, wired to the existing role/
    # permission policy and audit actor. It is NOT complete multi-tenant
    # authorization, complete route-level RBAC, or verified reviewer identity —
    # those remain declared blockers in evals/ga/blocker_registry.v1.json.
    # ------------------------------------------------------------------
    def _identity_from_user(
        self,
        user: User,
        *,
        actor_source: str,
        authentication_source: str,
        credential: StoredApiCredential | None = None,
    ) -> AuthenticatedIdentity:
        return AuthenticatedIdentity(
            user_id=user.id,
            tenant_id=user.tenant_id,
            email=user.email,
            display_name=user.full_name,
            roles=list(user.roles),
            account_status=user.account_status,
            authentication_source=authentication_source,  # type: ignore[arg-type]
            credential_id=credential.credential_id if credential else None,
            credential_fingerprint=credential.token_fingerprint if credential else None,
            actor_source=actor_source,  # type: ignore[arg-type]
        )

    def demo_bootstrap_identity(self) -> AuthenticatedIdentity:
        # The demo bootstrap identity mirrors the CURRENT configured user
        # (store.user), so its roles reflect the live configured identity.
        return self._identity_from_user(
            self.user, actor_source="demo_bootstrap", authentication_source="shared_key_bootstrap"
        )

    def resolve_request_identity(
        self, token: str | None, *, allow_shared_key_bootstrap: bool
    ) -> AuthenticatedIdentity | None:
        """Resolve a presented credential to a request identity, or None.

        Identity comes exclusively from the credential and server-side records;
        client-asserted identity is never trusted. Malformed/oversized tokens are
        rejected before any hash/compare. A persisted per-user credential is
        accepted only when it is active, its user is active, and both are bound to
        the configured tenant.

        The legacy configured shared key resolves to the labelled ``demo_bootstrap``
        identity ONLY when ``allow_shared_key_bootstrap`` is True (local/demo
        compatibility). In client mode the caller passes False, so the shared key
        (and any bootstrap-only credential) is rejected — a client-mode request
        must present an active persisted per-user credential.
        """
        # 1) Persisted per-user credential (works in both modes).
        if is_well_formed_token(token):
            candidate_hash = hash_token(token)  # type: ignore[arg-type]
            for credential in list(self.api_credentials.values()):
                if credential.status != "active":
                    continue
                # Bootstrap-only credentials never authenticate in client mode.
                if not allow_shared_key_bootstrap and credential.authentication_source != "api_token":
                    continue
                if not tokens_match(candidate_hash, credential.token_hash):
                    continue
                user = self.users.get(credential.user_id)
                if user is None or user.account_status != "active":
                    return None
                if user.tenant_id != self.tenant.id or credential.tenant_id != self.tenant.id:
                    return None
                if not allow_shared_key_bootstrap and user.is_bootstrap:
                    return None
                actor_source = (
                    "demo_bootstrap"
                    if credential.authentication_source == "shared_key_bootstrap"
                    else "authenticated"
                )
                return self._identity_from_user(
                    user,
                    actor_source=actor_source,
                    authentication_source=credential.authentication_source,
                    credential=credential,
                )
        # 2) Legacy configured shared key -> demo_bootstrap, LOCAL/DEMO ONLY.
        if allow_shared_key_bootstrap and token is not None and api_key_valid(token):
            return self.demo_bootstrap_identity()
        return None

    def current_identity(self) -> AuthenticatedIdentity:
        """The request-scoped identity, or an explicit system actor for
        worker/CLI operations that run outside any request."""
        request_identity = get_current_identity()
        if request_identity is not None:
            return request_identity
        return AuthenticatedIdentity(
            user_id=self.user.id,
            tenant_id=self.tenant.id,
            email=self.user.email,
            display_name=self.user.full_name,
            roles=list(self.user.roles),
            account_status="active",
            authentication_source="system",
            credential_id=None,
            credential_fingerprint=None,
            actor_source="system",
        )

    def create_user(self, email: str, full_name: str, roles: list[Role]) -> User:
        with self.identity_lock:
            self.refresh()
            normalized = [Role(role) for role in roles]
            if not normalized:
                raise ValueError("At least one role is required.")
            # VIEWER is intentionally not enabled in this increment.
            if Role.VIEWER in normalized:
                raise ValueError("The VIEWER role is not enabled in this increment.")
            user = User(
                tenant_id=self.tenant.id,
                email=email,
                full_name=full_name,
                roles=normalized,
                account_status="active",
                is_bootstrap=False,
            )
            self.users[user.id] = user
            self.audit(
                "auth.user.create",
                "user",
                user.id,
                {"roles": [role.value for role in normalized], "account_status": "active"},
            )
            return user

    def set_user_status(self, user_id: UUID, account_status: str) -> User:
        with self.identity_lock:
            self.refresh()
            user = self.users.get(user_id)
            if user is None:
                raise KeyError("Unknown user.")
            if account_status not in {"active", "disabled"}:
                raise ValueError("Invalid account status.")
            user.account_status = account_status  # type: ignore[assignment]
            self.audit("auth.user.status", "user", user.id, {"account_status": account_status})
            return user

    def list_users(self) -> list[User]:
        self.refresh()
        return list(self.users.values())

    def get_user(self, user_id: UUID) -> User | None:
        self.refresh()
        return self.users.get(user_id)

    def create_credential(self, user_id: UUID) -> tuple[StoredApiCredential, str]:
        """Provision a per-user credential. Returns the stored record and the
        RAW token, which is returned to the caller exactly once and never
        persisted, logged, or audited."""
        with self.identity_lock:
            self.refresh()
            user = self.users.get(user_id)
            if user is None:
                raise KeyError("Unknown user.")
            if user.tenant_id != self.tenant.id:
                raise ValueError("User is not in the configured tenant.")
            raw_token = generate_api_token()
            credential = StoredApiCredential(
                user_id=user.id,
                tenant_id=user.tenant_id,
                token_hash=hash_token(raw_token),
                token_fingerprint=token_fingerprint(raw_token),
                status="active",
                authentication_source="api_token",
            )
            self.api_credentials[credential.credential_id] = credential
            self.audit(
                "auth.credential.create",
                "api_credential",
                credential.credential_id,
                {"user_id": str(user.id), "fingerprint": credential.token_fingerprint},
            )
            return credential, raw_token

    def revoke_credential(self, credential_id: UUID) -> StoredApiCredential:
        with self.identity_lock:
            self.refresh()
            credential = self.api_credentials.get(credential_id)
            if credential is None:
                raise KeyError("Unknown credential.")
            if credential.status == "revoked":
                return credential  # idempotent
            credential.status = "revoked"
            credential.revoked_at = datetime.now(timezone.utc)
            self.audit(
                "auth.credential.revoke",
                "api_credential",
                credential.credential_id,
                {"user_id": str(credential.user_id), "fingerprint": credential.token_fingerprint},
            )
            return credential

    def list_credentials(self) -> list[StoredApiCredential]:
        self.refresh()
        return list(self.api_credentials.values())

    def has_non_bootstrap_identity(self) -> bool:
        """True iff at least one active non-bootstrap user has an active
        credential. Used as evidence that per-user identity is more than the
        local bootstrap; never satisfied by an env flag alone."""
        active_users = {
            user.id
            for user in self.users.values()
            if user.account_status == "active" and not user.is_bootstrap
        }
        return any(
            credential.status == "active" and credential.user_id in active_users
            for credential in self.api_credentials.values()
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
        self.benchmark_values = self._load_map(BenchmarkValue, payload.get("benchmark_values", []))
        self.anomaly_rules = self._load_map(AnomalyRule, payload.get("anomaly_rules", []))
        self.benchmark_measurements = self._load_map(
            BenchmarkMeasurement,
            payload.get("benchmark_measurements", []),
        )
        self.anomaly_events = self._load_map(AnomalyEvent, payload.get("anomaly_events", []))
        self.key_decisions = self._load_map(KeyDecision, payload.get("key_decisions", []))
        self.field_corrections = self._load_map(FieldCorrection, payload.get("field_corrections", []))
        # Additive identity collections: old snapshots load as empty and are
        # bootstrapped on init.
        self.users = self._load_map(User, payload.get("users", []))
        self.api_credentials = {
            credential.credential_id: credential
            for credential in (
                StoredApiCredential.model_validate(item)
                for item in payload.get("api_credentials", [])
            )
        }
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
            "benchmark_values": self._dump_map(self.benchmark_values),
            "anomaly_rules": self._dump_map(self.anomaly_rules),
            "benchmark_measurements": self._dump_map(self.benchmark_measurements),
            "anomaly_events": self._dump_map(self.anomaly_events),
            "key_decisions": self._dump_map(self.key_decisions),
            "field_corrections": self._dump_map(self.field_corrections),
            "users": self._dump_map(self.users),
            "api_credentials": [
                credential.model_dump(mode="json") for credential in self.api_credentials.values()
            ],
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

    def _ensure_benchmarking_defaults(self, audit_seed: bool = True) -> bool:
        changed = False
        today = date(2026, 7, 14)
        for seed in BENCHMARK_SEED_VALUES:
            exists = any(
                item.benchmark_name == seed["benchmark_name"]
                and item.metric == seed["metric"]
                for item in self.benchmark_values.values()
            )
            if exists:
                continue
            benchmark = BenchmarkValue(
                tenant_id=self.tenant.id,
                benchmark_name=str(seed["benchmark_name"]),
                metric=str(seed["metric"]),
                value=float(seed["value"]),
                unit=str(seed["unit"]),
                performance_category=str(seed["performance_category"]),
                data_source=str(seed["data_source"]),
                effective_date=today,
                dataset_version=str(seed["dataset_version"]),
            )
            self.benchmark_values[benchmark.id] = benchmark
            changed = True

        for seed in BENCHMARK_RULE_SEEDS:
            exists = any(
                item.name == seed["name"] and item.metric == seed["metric"]
                for item in self.anomaly_rules.values()
            )
            if exists:
                continue
            rule = AnomalyRule(
                tenant_id=self.tenant.id,
                name=str(seed["name"]),
                metric=str(seed["metric"]),
                severity=seed["severity"],  # type: ignore[arg-type]
                benchmark_name=str(seed["benchmark_name"]),
                threshold_mode=seed["threshold_mode"],  # type: ignore[arg-type]
                threshold_percent=seed["threshold_percent"],  # type: ignore[arg-type]
                diagnostic_modules=list(seed["diagnostic_modules"]),  # type: ignore[arg-type]
            )
            self.anomaly_rules[rule.id] = rule
            changed = True

        if changed and audit_seed:
            self.audit(
                "benchmark_config.seed",
                "benchmark_config",
                self.tenant.id,
                {
                    "benchmarks": [
                        {
                            "name": item.benchmark_name,
                            "metric": item.metric,
                            "value": item.value,
                            "unit": item.unit,
                            "dataset_version": item.dataset_version,
                        }
                        for item in self.benchmark_values.values()
                    ],
                    "rules": [item.name for item in self.anomaly_rules.values()],
                },
                save=False,
            )
        return changed

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
        *,
        refresh: bool = True,
        save: bool = True,
    ) -> tuple[Upload, UploadFileRecord, str]:
        if refresh:
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
            save=save,
        )
        return upload, file_record, f"local-storage://{file_record.id}"

    def complete_upload(self, upload_id: UUID, file_ids: list[UUID], *, refresh: bool = True) -> Upload:
        if refresh:
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

    def process_queued_jobs(self, upload_id: UUID | None = None, max_jobs: int | None = None) -> int:
        self.refresh()
        processed = 0
        processed_upload_ids: set[UUID] = set()
        redis_job_ids = None if upload_id is not None else self._redis_processing_job_ids(max_jobs=max_jobs)

        for job in self.jobs.values():
            if job.status != ProcessingStatus.QUEUED:
                continue
            if upload_id is not None and job.upload_id != upload_id:
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
            if max_jobs is not None and processed >= max_jobs:
                break

        for upload_id in processed_upload_ids:
            self._sync_upload_job_status(upload_id, audit_terminal=True)

        if processed:
            self.save()
        return processed

    def _enqueue_processing_job(self, job_id: UUID) -> None:
        if self.queue_backend != "redis":
            return
        enqueue_processing_job(job_id)

    def _redis_processing_job_ids(self, max_jobs: int | None = None) -> set[UUID] | None:
        self.queue_backend = active_queue_backend()
        if self.queue_backend != "redis":
            return None
        queued_job_ids = [job.id for job in self.jobs.values() if job.status == ProcessingStatus.QUEUED]
        sync_processing_queue(queued_job_ids)
        return set(pop_processing_job_ids(limit=max_jobs or 100))

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

    # ------------------------------------------------------------------
    # Field-level correction & review-provenance foundation.
    #
    # Corrections are versioned overlay records (versioned history in the
    # tenant snapshot, NOT an immutable append-only event log). They capture
    # who/what/from/to/when/why for a correction to a REGISTERED extracted
    # field without ever mutating the source-derived value or its lineage.
    # Re-correcting the same (workspace, target_type, field_key) supersedes the
    # prior active record (a version chain, updating its status/linkage);
    # reverting flips status without destroying history. `actor_*` fields
    # record the configured actor context, not a verified per-user reviewer.
    #
    # The whole correction route (refresh -> checks -> record/revert -> save)
    # is serialized in-process by field_correction_lock so the single-active-
    # lineage-and-no-lost-write invariant holds under threadpool concurrency;
    # cross-process atomicity requires normalized persistence (Phase 04).
    # Recording never creates anomalies, benchmark measurements,
    # failures, or validation tasks — the Benchmarking and recommended-only
    # diagnostic boundaries are untouched.
    # ------------------------------------------------------------------
    def record_field_correction(
        self, workspace_id: UUID, payload: FieldCorrectionCreate
    ) -> FieldCorrection:
        with self.field_correction_lock:
            self.refresh()
            prior = self._active_field_correction(workspace_id, payload.target_type, payload.field_key)
            identity = self.current_identity()
            correction = FieldCorrection(
                tenant_id=self.tenant.id,
                workspace_id=workspace_id,
                target_type=payload.target_type,
                field_key=payload.field_key,
                source_value=payload.source_value,
                corrected_value=payload.corrected_value,
                correction_reason=payload.correction_reason,
                actor_user_id=identity.user_id,
                actor_email=identity.email,
                actor_roles=list(identity.roles),
                actor_source=identity.actor_source,
                actor_credential_fingerprint=identity.credential_fingerprint,
                supersedes_id=prior.id if prior else None,
            )
            if prior is not None:
                prior.status = "superseded"
                prior.superseded_by_id = correction.id
            self.field_corrections[correction.id] = correction
            # Audit metadata carries attribution + shape only. Raw source/
            # corrected values and the free-text reason are never written to the
            # audit log; only booleans, lengths, and stable identifiers are
            # recorded. audit() persists the correction state and the audit
            # event in one save(), so they cannot diverge in-process.
            self.audit(
                "field_correction.record",
                "field_correction",
                correction.id,
                {
                    "workspace_id": str(workspace_id),
                    "target_type": correction.target_type,
                    "field_key": correction.field_key,
                    "source_present": correction.source_value is not None,
                    "corrected_present": correction.corrected_value is not None,
                    "value_changed": correction.source_value != correction.corrected_value,
                    "reason_length": len(correction.correction_reason),
                    "supersedes": str(prior.id) if prior else None,
                },
            )
            return correction

    def revert_field_correction(self, correction_id: UUID, revert_reason: str) -> FieldCorrection:
        with self.field_correction_lock:
            self.refresh()
            correction = self.field_corrections[correction_id]
            if correction.status != "active":
                raise ValueError("Only an active correction can be reverted.")
            correction.status = "reverted"
            correction.revert_reason = revert_reason
            self.audit(
                "field_correction.revert",
                "field_correction",
                correction.id,
                {
                    "workspace_id": str(correction.workspace_id),
                    "target_type": correction.target_type,
                    "field_key": correction.field_key,
                    "revert_reason_length": len(revert_reason),
                },
            )
            return correction

    def list_field_corrections(
        self, workspace_id: UUID, active_only: bool = False
    ) -> list[FieldCorrection]:
        corrections = [
            correction
            for correction in self.field_corrections.values()
            if correction.workspace_id == workspace_id and correction.tenant_id == self.tenant.id
        ]
        if active_only:
            corrections = [item for item in corrections if item.status == "active"]
        return sorted(corrections, key=lambda item: item.created_at)

    def _active_field_correction(
        self, workspace_id: UUID, target_type: str, field_key: str
    ) -> FieldCorrection | None:
        for correction in self.field_corrections.values():
            if (
                correction.workspace_id == workspace_id
                and correction.tenant_id == self.tenant.id
                and correction.target_type == target_type
                and correction.field_key == field_key
                and correction.status == "active"
            ):
                return correction
        return None

    # Historical Benchmarking/field-correction permission keys, preserved for
    # existing consumers. The generic backend.app.permissions policy is the
    # authorization authority; this returns its verdict for these keys.
    _LEGACY_BENCHMARK_PERMISSION_KEYS = (
        "view_benchmarks",
        "manage_benchmark_config",
        "review_anomalies",
        "dismiss_anomalies",
        "run_diagnostics",
        "approve_ai_content",
        "issue_client_reports",
        "export_evidence",
        "edit_decision_records",
        "view_audit_history",
        "record_field_corrections",
        "view_field_corrections",
    )

    def benchmark_permissions(self, identity: AuthenticatedIdentity | None = None) -> dict[str, bool]:
        """Backward-compatibility wrapper. Delegates to the generic permission
        policy (default-deny; no all-role fallback) and returns the historical
        Benchmarking/field-correction permission shape."""
        from .permissions import has_permission

        source = identity if identity is not None else self.current_identity()
        return {
            key: has_permission(source.roles, key)
            for key in self._LEGACY_BENCHMARK_PERMISSION_KEYS
        }

    def permission_map(self, identity: AuthenticatedIdentity | None = None) -> dict[str, bool]:
        """The full {permission: bool} verdict for the request identity's roles."""
        from .permissions import permission_map

        source = identity if identity is not None else self.current_identity()
        return permission_map(source.roles)

    def has_permission(self, permission: str, identity: AuthenticatedIdentity | None = None) -> bool:
        from .permissions import has_permission

        source = identity if identity is not None else self.current_identity()
        return has_permission(source.roles, permission)

    def update_benchmark_value(self, benchmark_id: UUID, payload: BenchmarkValueUpdate) -> BenchmarkValue:
        self.refresh()
        benchmark = self.benchmark_values[benchmark_id]
        previous = benchmark.model_dump(mode="json")
        for field in [
            "value",
            "unit",
            "performance_category",
            "data_source",
            "effective_date",
            "dataset_version",
            "approval_status",
        ]:
            value = getattr(payload, field)
            if value is not None:
                setattr(benchmark, field, value)
        benchmark.last_updated = datetime.now(timezone.utc)
        self.audit(
            "benchmark_config.update",
            "benchmark_value",
            benchmark.id,
            {
                "previous_value": previous,
                "new_value": benchmark.model_dump(mode="json"),
                "reason": payload.reason,
            },
        )
        return benchmark

    def record_benchmark_measurement(
        self,
        workspace_id: UUID,
        payload: BenchmarkMeasurementCreate,
    ) -> BenchmarkingStatus:
        self.refresh()
        if workspace_id not in self.workspaces:
            raise KeyError("workspace_not_found")
        citation = Citation(
            locator_type="benchmark_measurement",
            locator={
                "source_type": payload.source_type,
                "source_identifier": payload.source_identifier,
                "dataset_version": payload.dataset_version,
            },
            snippet=(
                f"{payload.metric} measured at {payload.value:g} {payload.unit} "
                f"from {payload.data_source}."
            ),
            confidence=0.9 if payload.confidence_status in {"high", "manual"} else 0.65,
        )
        measurement = BenchmarkMeasurement(
            tenant_id=self.tenant.id,
            workspace_id=workspace_id,
            metric=payload.metric,
            value=payload.value,
            unit=payload.unit,
            data_source=payload.data_source,
            data_timestamp=payload.data_timestamp or datetime.now(timezone.utc),
            confidence_status=payload.confidence_status,
            source_type=payload.source_type,
            source_identifier=payload.source_identifier,
            dataset_version=payload.dataset_version,
            citations=[citation],
        )
        self.benchmark_measurements[measurement.id] = measurement
        self.audit(
            "benchmark_measurement.create",
            "benchmark_measurement",
            measurement.id,
            {
                "workspace_id": str(workspace_id),
                "metric": measurement.metric,
                "value": measurement.value,
                "unit": measurement.unit,
                "data_source": measurement.data_source,
                "data_timestamp": measurement.data_timestamp.isoformat(),
            },
            save=False,
        )
        self._evaluate_anomaly_rules(measurement, moc_reference=payload.moc_reference)
        self.save()
        return self._build_benchmarking_status(workspace_id)

    def benchmarking_status(self, workspace_id: UUID) -> BenchmarkingStatus:
        self.refresh()
        if workspace_id not in self.workspaces:
            raise KeyError("workspace_not_found")
        return self._build_benchmarking_status(workspace_id)

    def dismiss_diagnostic_action(
        self,
        anomaly_id: UUID,
        action_id: UUID,
        reason: str,
    ) -> AnomalyEvent:
        self.refresh()
        if anomaly_id not in self.anomaly_events:
            raise KeyError("anomaly_not_found")
        anomaly = self.anomaly_events[anomaly_id]
        matching = next((item for item in anomaly.diagnostic_actions if item.id == action_id), None)
        if matching is None:
            raise KeyError("diagnostic_action_not_found")
        previous = matching.status
        matching.status = "Dismissed"
        matching.authorized_user = self.user.email
        matching.timestamp = datetime.now(timezone.utc)
        matching.dismissal_reason = reason
        self.audit(
            "diagnostic_action.dismiss",
            "anomaly_event",
            anomaly.id,
            {
                "action_id": str(action_id),
                "module": matching.module,
                "from": previous,
                "to": matching.status,
                "authorized_user": self.user.email,
                "reason": reason,
            },
        )
        return anomaly

    def _build_benchmarking_status(self, workspace_id: UUID) -> BenchmarkingStatus:
        measurements = [
            item
            for item in self.benchmark_measurements.values()
            if item.workspace_id == workspace_id
        ]
        current = self._latest_measurement(workspace_id, FEET_DRILLED_PER_DAY)
        trend_measurements = sorted(
            [item for item in measurements if item.metric == FEET_DRILLED_PER_DAY],
            key=lambda item: item.data_timestamp,
        )[-7:]
        normalized_trend = [
            {
                "timestamp": item.data_timestamp.isoformat(),
                "value": round(self._normalize_value(item.value, item.unit, "ft/day"), 2),
                "unit": "ft/day",
                "confidence_status": item.confidence_status,
            }
            for item in trend_measurements
        ]
        seven_day_average = (
            round(sum(item["value"] for item in normalized_trend) / len(normalized_trend), 2)
            if normalized_trend
            else None
        )
        benchmark_values = [
            item
            for item in self.benchmark_values.values()
            if item.approval_status == "approved"
        ]
        comparisons = self._benchmark_comparisons(workspace_id)
        active_anomalies = [
            item
            for item in self.anomaly_events.values()
            if item.workspace_id == workspace_id and item.status == "active"
        ]
        historical_anomalies = [
            item
            for item in self.anomaly_events.values()
            if item.workspace_id == workspace_id and item.status != "active"
        ]
        diagnostic_actions = [
            action
            for anomaly in active_anomalies
            for action in anomaly.diagnostic_actions
        ]
        gordon = self._benchmark_by_name("Gordon average", FEET_DRILLED_PER_DAY)
        noble = self._benchmark_by_name("Noble top-quartile", FEET_DRILLED_PER_DAY)
        return BenchmarkingStatus(
            workspace_id=workspace_id,
            current_ft_per_day=(
                round(self._normalize_value(current.value, current.unit, "ft/day"), 2)
                if current
                else None
            ),
            seven_day_average_ft_per_day=seven_day_average,
            gordon_average_benchmark=gordon.value if gordon else None,
            noble_top_quartile_benchmark=noble.value if noble else None,
            comparisons=comparisons,
            active_anomalies=active_anomalies,
            historical_anomalies=historical_anomalies,
            benchmark_values=benchmark_values,
            anomaly_rules=[
                item for item in self.anomaly_rules.values() if item.approval_status == "approved"
            ],
            seven_day_trend=normalized_trend,
            likely_operational_contributors=self._likely_operational_contributors(active_anomalies, comparisons),
            recommended_diagnostic_actions=diagnostic_actions,
            supporting_evidence_references=self._benchmark_source_references(workspace_id),
            ai_interpretation=self._benchmark_ai_interpretation(comparisons, active_anomalies),
            permissions=self.benchmark_permissions(),
        )

    def _benchmark_comparisons(self, workspace_id: UUID) -> list[BenchmarkComparison]:
        rows: list[BenchmarkComparison] = []
        for metric in BENCHMARK_METRICS:
            measurement = self._latest_measurement(workspace_id, metric)
            metric_benchmarks = [
                item
                for item in self.benchmark_values.values()
                if item.metric == metric and item.approval_status == "approved"
            ]
            if not metric_benchmarks:
                rows.append(
                    BenchmarkComparison(
                        metric=metric,
                        benchmark_name="No approved benchmark",
                        current_value=measurement.value if measurement else None,
                        current_unit=measurement.unit if measurement else "not available",
                        benchmark_value=None,
                        benchmark_unit="not configured",
                        performance_status="Insufficient data",
                        supporting_source=measurement.data_source if measurement else "No measurement or approved benchmark configured",
                        data_timestamp=measurement.data_timestamp if measurement else None,
                        confidence_status=measurement.confidence_status if measurement else "missing",
                    )
                )
                continue
            for benchmark in metric_benchmarks:
                rows.append(self._comparison_for_benchmark(measurement, benchmark))
        return rows

    def _comparison_for_benchmark(
        self,
        measurement: BenchmarkMeasurement | None,
        benchmark: BenchmarkValue,
    ) -> BenchmarkComparison:
        if measurement is None:
            return BenchmarkComparison(
                metric=benchmark.metric,
                benchmark_name=benchmark.benchmark_name,
                current_value=None,
                current_unit=benchmark.unit,
                benchmark_value=benchmark.value,
                benchmark_unit=benchmark.unit,
                performance_status="Insufficient data",
                supporting_source=benchmark.data_source,
                confidence_status="missing",
            )
        normalized_current = self._normalize_value(measurement.value, measurement.unit, benchmark.unit)
        absolute_variance = normalized_current - benchmark.value
        percentage_variance = (absolute_variance / benchmark.value * 100) if benchmark.value else 0
        status = self._comparison_status(measurement, benchmark, normalized_current, percentage_variance)
        return BenchmarkComparison(
            metric=benchmark.metric,
            benchmark_name=benchmark.benchmark_name,
            current_value=round(normalized_current, 2),
            current_unit=benchmark.unit,
            benchmark_value=benchmark.value,
            benchmark_unit=benchmark.unit,
            absolute_variance=round(absolute_variance, 2),
            percentage_variance=round(percentage_variance, 2),
            performance_status=status,
            supporting_source=f"{measurement.data_source}; benchmark {benchmark.data_source} {benchmark.dataset_version}",
            data_timestamp=measurement.data_timestamp,
            confidence_status=measurement.confidence_status,
        )

    def _comparison_status(
        self,
        measurement: BenchmarkMeasurement,
        benchmark: BenchmarkValue,
        normalized_current: float,
        percentage_variance: float,
    ) -> str:
        age = datetime.now(timezone.utc) - measurement.data_timestamp
        if measurement.confidence_status == "missing":
            return "Insufficient data"
        if measurement.confidence_status == "stale" or age > timedelta(days=2):
            return "Stale data"
        critical_rule = next(
            (
                rule
                for rule in self.anomaly_rules.values()
                if rule.metric == benchmark.metric
                and rule.severity == "Critical"
                and rule.approval_status == "approved"
            ),
            None,
        )
        critical_threshold = (
            self._threshold_for_rule(critical_rule)
            if critical_rule is not None
            else None
        )
        if critical_threshold is not None and normalized_current < critical_threshold:
            return "Critical deviation"
        if percentage_variance < -5:
            return "Below benchmark"
        if abs(percentage_variance) <= 5:
            return "Within expected range"
        return "Above benchmark"

    def _evaluate_anomaly_rules(
        self,
        measurement: BenchmarkMeasurement,
        *,
        moc_reference: str | None = None,
    ) -> None:
        for rule in self.anomaly_rules.values():
            if rule.metric != measurement.metric or rule.approval_status != "approved":
                continue
            threshold = self._threshold_for_rule(rule)
            benchmark = self._benchmark_by_name(rule.benchmark_name, rule.metric)
            if threshold is None or benchmark is None:
                continue
            current = self._normalize_value(measurement.value, measurement.unit, benchmark.unit)
            if current >= threshold:
                continue
            existing = self._matching_anomaly_event(measurement.id, rule.id)
            if existing is not None:
                continue
            actions = [
                DiagnosticAction(
                    module=module,  # type: ignore[arg-type]
                    reason=(
                        f"{rule.name}: current {current:.1f} {benchmark.unit} "
                        f"is below {threshold:.1f} {benchmark.unit}."
                    ),
                )
                for module in rule.diagnostic_modules
            ]
            anomaly = AnomalyEvent(
                tenant_id=self.tenant.id,
                workspace_id=measurement.workspace_id,
                measurement_id=measurement.id,
                metric=measurement.metric,
                severity=rule.severity,
                performance_status=(
                    "Critical deviation" if rule.severity == "Critical" else "Below benchmark"
                ),
                current_value=round(current, 2),
                unit=benchmark.unit,
                threshold_value=round(threshold, 2),
                threshold_unit=benchmark.unit,
                rule_id=rule.id,
                rule_name=rule.name,
                summary=(
                    f"{rule.severity}: {measurement.metric.replace('_', ' ')} "
                    f"{current:.1f} {benchmark.unit} is below {rule.benchmark_name} threshold "
                    f"{threshold:.1f} {benchmark.unit}."
                ),
                benchmark_evidence={
                    "benchmark_name": benchmark.benchmark_name,
                    "benchmark_value": benchmark.value,
                    "benchmark_unit": benchmark.unit,
                    "data_source": benchmark.data_source,
                    "dataset_version": benchmark.dataset_version,
                    "approval_status": benchmark.approval_status,
                    "effective_date": benchmark.effective_date.isoformat(),
                },
                supporting_citations=measurement.citations,
                diagnostic_actions=actions,
                moc_reference=moc_reference,
            )
            self.anomaly_events[anomaly.id] = anomaly
            self.audit(
                "benchmark_anomaly.create",
                "anomaly_event",
                anomaly.id,
                {
                    "workspace_id": str(measurement.workspace_id),
                    "metric": anomaly.metric,
                    "severity": anomaly.severity,
                    "current_value": anomaly.current_value,
                    "threshold_value": anomaly.threshold_value,
                    "rule": anomaly.rule_name,
                    "diagnostic_modules": [item.module for item in actions],
                    "moc_reference": moc_reference,
                },
                save=False,
            )
            if rule.severity == "Critical":
                task = ValidationTask(
                    tenant_id=self.tenant.id,
                    target_type="anomaly_event",
                    target_id=anomaly.id,
                    reason=(
                        "Critical benchmark deviation requires review before client issue "
                        "and Management of Change export."
                    ),
                    priority="critical",
                )
                self.validation_tasks[task.id] = task
                self.audit(
                    "risk_watchlist.add",
                    "anomaly_event",
                    anomaly.id,
                    {
                        "validation_task_id": str(task.id),
                        "severity": anomaly.severity,
                        "status": anomaly.performance_status,
                    },
                    save=False,
                )

    def _threshold_for_rule(self, rule: AnomalyRule | None) -> float | None:
        if rule is None:
            return None
        benchmark = self._benchmark_by_name(rule.benchmark_name, rule.metric)
        if benchmark is None:
            return None
        if rule.threshold_mode == "below_benchmark":
            return benchmark.value
        if rule.threshold_percent is None:
            return None
        return benchmark.value * (rule.threshold_percent / 100)

    def _benchmark_by_name(self, benchmark_name: str, metric: str) -> BenchmarkValue | None:
        return next(
            (
                item
                for item in self.benchmark_values.values()
                if item.benchmark_name == benchmark_name
                and item.metric == metric
                and item.approval_status == "approved"
            ),
            None,
        )

    def _latest_measurement(self, workspace_id: UUID, metric: str) -> BenchmarkMeasurement | None:
        measurements = [
            item
            for item in self.benchmark_measurements.values()
            if item.workspace_id == workspace_id and item.metric == metric
        ]
        if not measurements:
            return None
        return max(measurements, key=lambda item: (item.data_timestamp, item.created_at))

    def _matching_anomaly_event(self, measurement_id: UUID, rule_id: UUID) -> AnomalyEvent | None:
        return next(
            (
                item
                for item in self.anomaly_events.values()
                if item.measurement_id == measurement_id and item.rule_id == rule_id
            ),
            None,
        )

    @staticmethod
    def _normalize_value(value: float, source_unit: str, target_unit: str) -> float:
        source = source_unit.strip().lower()
        target = target_unit.strip().lower()
        if source == target:
            return value
        if source in {"m/day", "meter/day", "meters/day"} and target == "ft/day":
            return value * 3.28084
        if source == "ft/day" and target in {"m/day", "meter/day", "meters/day"}:
            return value / 3.28084
        if source in {"hr", "hrs", "hour", "hours"} and target in {"hr", "hrs", "hour", "hours"}:
            return value
        if source in {"%", "percent"} and target in {"%", "percent"}:
            return value
        raise ValueError(f"Unsupported unit conversion: {source_unit} to {target_unit}")

    @staticmethod
    def _likely_operational_contributors(
        anomalies: list[AnomalyEvent],
        comparisons: list[BenchmarkComparison],
    ) -> list[str]:
        if any(item.severity == "Critical" for item in anomalies):
            return [
                "Hydraulics efficiency, hole cleaning, bit/BHA response, or drilling parameter limits may be contributing; treat as risk assessment.",
                "Torque and drag trend should be reviewed before changing operating parameters.",
            ]
        if any(item.performance_status == "Below benchmark" for item in comparisons):
            return [
                "Performance is below at least one approved benchmark; verify data freshness before assigning operational cause.",
            ]
        return ["No benchmark-driven contributor is inferred from the current approved measurements."]

    def _benchmark_source_references(self, workspace_id: UUID) -> list[str]:
        measurements = [
            item
            for item in self.benchmark_measurements.values()
            if item.workspace_id == workspace_id
        ]
        references = [
            f"{item.source_type}:{item.source_identifier} ({item.metric}, {item.data_timestamp.isoformat()})"
            for item in sorted(measurements, key=lambda value: value.data_timestamp, reverse=True)[:8]
        ]
        references.extend(
            f"{item.benchmark_name} {item.dataset_version} ({item.data_source})"
            for item in self.benchmark_values.values()
            if item.approval_status == "approved"
        )
        return references

    @staticmethod
    def _benchmark_ai_interpretation(
        comparisons: list[BenchmarkComparison],
        anomalies: list[AnomalyEvent],
    ) -> list[AiReportStatement]:
        current_rows = [item for item in comparisons if item.current_value is not None]
        statements: list[AiReportStatement] = []
        if current_rows:
            first = current_rows[0]
            statements.append(
                AiReportStatement(
                    category="Measured fact",
                    text=f"Current {first.metric.replace('_', ' ')} is {first.current_value:g} {first.current_unit}.",
                    source_reference=first.supporting_source,
                )
            )
        if comparisons:
            row = comparisons[0]
            if row.absolute_variance is not None:
                statements.append(
                    AiReportStatement(
                        category="Calculated result",
                        text=(
                            f"Variance against {row.benchmark_name} is {row.absolute_variance:g} "
                            f"{row.benchmark_unit} ({row.percentage_variance:g}%)."
                        ),
                        source_reference=row.supporting_source,
                    )
                )
        if anomalies:
            critical = next((item for item in anomalies if item.severity == "Critical"), anomalies[0])
            statements.extend(
                [
                    AiReportStatement(
                        category="Risk assessment",
                        text=f"{critical.summary} This is a benchmark-driven risk flag, not a confirmed root cause.",
                        source_reference=critical.rule_name,
                    ),
                    AiReportStatement(
                        category="Recommended action",
                        text="Review Hydraulics and Torque & Drag diagnostics before changing drilling parameters.",
                        source_reference=critical.rule_name,
                    ),
                ]
            )
        else:
            statements.append(
                AiReportStatement(
                    category="Inferred explanation",
                    text="No active benchmark anomaly is inferred from approved current measurements.",
                    source_reference="benchmarking_status",
                )
            )
        return statements

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
        benchmark_status = self._build_benchmarking_status(payload.workspace_id)
        active_benchmark_anomalies = [
            anomaly for anomaly in benchmark_status.active_anomalies if anomaly.status == "active"
        ]
        report_profiles = LocalStateStore.collect_report_profiles_from_documents(parsed_documents)
        casing_rows = self.casing_rows_from_profiles(report_profiles)
        casing_source = "source" if casing_rows else "reference"
        if not casing_rows:
            casing_rows = self.reference_casing_rows()
        activity_rows = self.activity_rows_from_profiles(report_profiles)
        if not activity_rows:
            activity_rows = self.reference_activity_rows()
        if casing_source == "source":
            hole_sections = self.hole_sections_from_casing_rows(casing_rows) or [dict(section) for section in REFERENCE_HOLE_SECTIONS]
        else:
            hole_sections = [dict(section) for section in REFERENCE_HOLE_SECTIONS]
        casing_schematic_rows = [
            {
                "name": row.get("name"),
                "od": row.get("od"),
                "top_ft": row.get("top_ft"),
                "shoe_ft": row.get("shoe_ft"),
                "status": row.get("status"),
                "source": row.get("source"),
                "page": row.get("page"),
                "confidence": row.get("confidence"),
            }
            for row in casing_rows
        ]
        activity_timeline_rows = [
            {
                "time": row.get("time"),
                "activity": row.get("activity"),
                "source": row.get("source"),
                "page": row.get("page"),
                "confidence": row.get("confidence"),
            }
            for row in activity_rows
        ]
        # Survey stations are source-only: shared rows with the report draft,
        # an empty list when no evidence exists, and never a fabricated
        # reference fallback.
        survey_rows = self.survey_rows_from_profiles(report_profiles)
        survey_source = "source" if survey_rows else "none"
        survey_station_rows = [
            {
                "measured_depth_ft": row.get("measured_depth_ft"),
                "inclination_deg": row.get("inclination_deg"),
                "azimuth_deg": row.get("azimuth_deg"),
                "true_vertical_depth_ft": row.get("true_vertical_depth_ft"),
                "dogleg_severity_dp100ft": row.get("dogleg_severity_dp100ft"),
                "north_south_ft": row.get("north_south_ft"),
                "east_west_ft": row.get("east_west_ft"),
                "station_id": row.get("station_id"),
                "survey_type": row.get("survey_type"),
                "source": row.get("source"),
                "page": row.get("page"),
                "confidence": row.get("confidence"),
                "conflict": row.get("conflict"),
            }
            for row in survey_rows
        ]
        # Calculated trajectory geometry lives in a structurally separate block
        # built from the same shared survey rows as the report draft; source
        # station values above are never modified and Benchmarking is never
        # auto-populated from calculated DLS.
        trajectory_calculation = self.trajectory_from_survey_rows(survey_rows)
        trajectory_source = "calculated" if trajectory_calculation else "none"
        # Source-derived hydraulics observations: informational and
        # review-required; Hydraulics/T&D diagnostics remain recommended-only
        # and are never created or altered by extraction.
        hydraulics_rows = self.hydraulics_rows_from_profiles(report_profiles)
        hydraulics_source = "source" if hydraulics_rows else "none"
        report = MondayReport(
            tenant_id=self.tenant.id,
            workspace_id=payload.workspace_id,
            period_start=payload.period_start,
            period_end=payload.period_end,
            status="review" if open_tasks else "draft",
            report_json={
                "title": "Monday Report",
                "report_format_version": "MR-DDR-2",
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
                    "benchmark_comparisons": len(benchmark_status.comparisons),
                    "active_benchmark_anomalies": len(active_benchmark_anomalies),
                },
                "executive_summary": [
                    {
                        "text": (
                            f"{len(failures)} extracted failure(s), {len(high_failures)} high/critical item(s), "
                            f"and {total_npt:.1f} NPT hour(s) are currently in scope."
                        ),
                        "confidence": 0.82,
                    },
                    {
                        "text": (
                            "Market benchmark review: "
                            f"current ft/day is {benchmark_status.current_ft_per_day if benchmark_status.current_ft_per_day is not None else 'missing'}, "
                            f"seven-day average is {benchmark_status.seven_day_average_ft_per_day if benchmark_status.seven_day_average_ft_per_day is not None else 'missing'}, "
                            f"and {len(active_benchmark_anomalies)} active benchmark anomaly/anomalies require review."
                        ),
                        "confidence": 0.78,
                    }
                ],
                "failure_summary": [failure.model_dump(mode="json") for failure in failures],
                "benchmarking": benchmark_status.model_dump(mode="json"),
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
                    "standard_daily_report": [
                        {
                            "section": "Well / Job Information",
                            "status": "ready",
                            "detail": f"{workspace.name} | {workspace.asset} | {workspace.campaign}",
                        },
                        {
                            "section": "Present Operations",
                            "status": "draft",
                            "detail": "Summarized from extracted failure evidence and source-backed daily-report notes.",
                        },
                        {
                            "section": "Drilling Parameters",
                            "status": "source-confirm",
                            "detail": "MD/TVD, hole size, survey trend, flow rate, RPM, WOB, torque, and SPP should be confirmed from the latest DDR.",
                        },
                        {
                            "section": "Mud, BHA, Survey, and Bit",
                            "status": "source-confirm",
                            "detail": "Mud weight/properties, active BHA, bit run, MWD/LWD/RSS status, and survey quality require source confirmation.",
                        },
                        {
                            "section": "NPT / Failures",
                            "status": "ready" if failures else "monitor",
                            "detail": f"{len(failures)} extracted failure(s), {total_npt:.1f} NPT hour(s), {len(high_failures)} high/critical item(s).",
                        },
                        {
                            "section": "Next 24 Hr Plan",
                            "status": "approval-gated",
                            "detail": "Actions remain gated by validation closure and source-citation review.",
                        },
                    ],
                    "casing_schematic": casing_schematic_rows,
                    "casing_schematic_source": casing_source,
                    "well_schematic": {
                        "surface_equipment": [
                            "Wellhead and BOP status must be verified from the latest morning report.",
                            "Casing, cement, pressure-test, and shoe-integrity notes are held for source confirmation.",
                        ],
                        "hole_sections": hole_sections,
                        "risk_markers": [
                            "MWD/LWD/RSS signal quality",
                            "Torque, drag, ECD, and lost-circulation indicators",
                            "Casing-point readiness and cementing dependencies",
                        ],
                    },
                    "activity_timeline": activity_timeline_rows,
                    "survey_stations": survey_station_rows,
                    "survey_source": survey_source,
                    "trajectory_calculation": trajectory_calculation.model_dump(mode="json")
                    if trajectory_calculation
                    else None,
                    "trajectory_source": trajectory_source,
                    "hydraulics_observations": hydraulics_rows,
                    "hydraulics_source": hydraulics_source,
                    "market_benchmark": {
                        "current_ft_per_day": benchmark_status.current_ft_per_day,
                        "seven_day_average_ft_per_day": benchmark_status.seven_day_average_ft_per_day,
                        "gordon_average_benchmark": benchmark_status.gordon_average_benchmark,
                        "noble_top_quartile_benchmark": benchmark_status.noble_top_quartile_benchmark,
                        "current_dls": self._latest_measurement(payload.workspace_id, "dogleg_severity").value
                        if self._latest_measurement(payload.workspace_id, "dogleg_severity")
                        else None,
                        "comparisons": [item.model_dump(mode="json") for item in benchmark_status.comparisons],
                        "seven_day_trend": benchmark_status.seven_day_trend,
                        "active_anomalies": [item.model_dump(mode="json") for item in active_benchmark_anomalies],
                        "likely_operational_contributors": benchmark_status.likely_operational_contributors,
                        "recommended_diagnostic_actions": [
                            item.model_dump(mode="json") for item in benchmark_status.recommended_diagnostic_actions
                        ],
                        "supporting_evidence_references": benchmark_status.supporting_evidence_references,
                        "ai_interpretation": [
                            item.model_dump(mode="json") for item in benchmark_status.ai_interpretation
                        ],
                    },
                    "safety_and_ai_watchlist": {
                        "safety_concerns": [
                            "Confirm well-control, BOP, and pressure-control notes against the latest DDR."
                        ],
                        "operational_anomalies": [item.summary for item in active_benchmark_anomalies],
                        "data_quality_issues": [
                            item.metric
                            for item in benchmark_status.comparisons
                            if item.performance_status in {"Insufficient data", "Stale data"}
                        ],
                        "benchmark_deviations": [
                            item.model_dump(mode="json")
                            for item in benchmark_status.comparisons
                            if item.performance_status in {"Below benchmark", "Critical deviation"}
                        ],
                        "ai_generated_observations": [
                            item.model_dump(mode="json") for item in benchmark_status.ai_interpretation
                        ],
                        "unresolved_decisions": [
                            "No approved decision record is linked yet."
                            if not self.key_decisions
                            else f"{len(self.key_decisions)} decision record(s) available for review."
                        ],
                        "forward_looking_risks": benchmark_status.likely_operational_contributors,
                        "recommended_follow_up_actions": [
                            action.reason for action in benchmark_status.recommended_diagnostic_actions
                        ],
                    },
                    "current_operations": {
                        "current_hole_section": "Confirm from latest DDR or directional plan.",
                        "current_depth": "Confirm MD/TVD from source records.",
                        "directional_plan": "Compare approved plan to as-drilled trajectory before client issue.",
                        "active_anomalies": [item.summary for item in active_benchmark_anomalies],
                        "required_decisions": [
                            "Review critical benchmark deviations before issuing client report."
                        ]
                        if active_benchmark_anomalies
                        else [],
                    },
                    "next_operations": {
                        "planned_target": "Source-confirm next target/depth interval.",
                        "bha_status": "Confirm active BHA status and tool limits.",
                        "operational_limits": "Confirm WOB, RPM, flow, torque, drag, and ECD limits.",
                        "benchmark_deviations": [
                            item.performance_status
                            for item in benchmark_status.comparisons
                            if item.performance_status in {"Below benchmark", "Critical deviation"}
                        ],
                        "identified_risks": benchmark_status.likely_operational_contributors,
                    },
                    "handover_notes": {
                        "current_well_status": "Source-backed report draft requires reviewer confirmation.",
                        "work_completed": "Summarize from timeline and parsed source records.",
                        "open_risks": benchmark_status.likely_operational_contributors,
                        "pending_decisions": ["Close AI observations and benchmark anomaly review states."],
                        "next_critical_operation": "Confirm from approved drilling program.",
                        "changed_information": [
                            "Benchmark measurements, anomaly rules, and diagnostic recommendations are audited when updated."
                        ],
                    },
                    "key_decisions_and_impact": [
                        item.model_dump(mode="json")
                        for item in self.key_decisions.values()
                        if item.workspace_id == payload.workspace_id
                    ],
                    "source_citations": {
                        "benchmark_evidence": benchmark_status.supporting_evidence_references,
                        "material_claim_warning": (
                            "Material claims without citations must remain in review before client issue."
                        ),
                    },
                    "management_of_change_evidence": {
                        "benchmark_values_used": [
                            item.model_dump(mode="json") for item in benchmark_status.benchmark_values
                        ],
                        "variance_calculations": [
                            item.model_dump(mode="json") for item in benchmark_status.comparisons
                        ],
                        "triggered_anomaly_rules": [
                            item.model_dump(mode="json") for item in active_benchmark_anomalies
                        ],
                        "diagnostic_recommendations": [
                            item.model_dump(mode="json") for item in benchmark_status.recommended_diagnostic_actions
                        ],
                        "audit_actions": [
                            "benchmark_measurement.create",
                            "benchmark_anomaly.create",
                            "risk_watchlist.add",
                            "diagnostic_action.dismiss",
                        ],
                    },
                    "ai_execution_plan": [
                        {
                            "step": "Plan",
                            "owner": "Local AI analyst",
                            "status": "ready",
                            "action": "Classify source reports into well/job, operations, drilling parameters, mud/BHA, casing, timeline, NPT, and approvals.",
                        },
                        {
                            "step": "Draft",
                            "owner": "Report Studio",
                            "status": "ready",
                            "action": "Generate normal daily-report text while preserving the original report order and source-backed language.",
                        },
                        {
                            "step": "Draw",
                            "owner": "Schematic engine",
                            "status": "ready",
                            "action": "Render casing strings, hole sections, current depth, and risk markers for quick morning review.",
                        },
                        {
                            "step": "Execute",
                            "owner": "Validation gate",
                            "status": "blocked" if open_tasks else "ready",
                            "action": "Export client-ready PDF/XLSX/HTML/CSV/JSON only after validation tasks and citation checks are closed.",
                        },
                    ],
                    "client_issue_checklist": [
                        "Every NPT/failure item has source citation and confidence.",
                        "Casing, BHA, mud, survey, and time breakdown match the latest DDR evidence.",
                        "Open validation tasks are resolved or explicitly countersigned.",
                        "Exports are hashed, signed, and retained in the audit ledger.",
                    ],
                },
                "data_quality_notes": [
                    "Official exports are blocked until validation tasks are closed.",
                    "Casing and timeline sections use the FORGE-style daily-report structure and should be source-confirmed before client issue.",
                    "AI benchmark interpretation is review-required and must not be presented as confirmed root cause.",
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
        anomaly_ids = {
            anomaly.id
            for anomaly in self.anomaly_events.values()
            if anomaly.workspace_id == workspace_id
        }
        return [
            task
            for task in self.validation_tasks.values()
            if (
                (task.target_type == "failure" and task.target_id in failure_ids)
                or (task.target_type == "anomaly_event" and task.target_id in anomaly_ids)
            )
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
        lines.append("")
        lines.append("benchmark_metric,benchmark_name,current_value,benchmark_value,absolute_variance,percentage_variance,status,source")
        benchmarking = report.report_json.get("benchmarking", {})
        comparisons = benchmarking.get("comparisons", []) if isinstance(benchmarking, dict) else []
        for comparison in comparisons:
            if not isinstance(comparison, dict):
                continue
            fields = [
                comparison.get("metric", ""),
                comparison.get("benchmark_name", ""),
                comparison.get("current_value", ""),
                comparison.get("benchmark_value", ""),
                comparison.get("absolute_variance", ""),
                comparison.get("percentage_variance", ""),
                comparison.get("performance_status", ""),
                comparison.get("supporting_source", ""),
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
        benchmarking = report.report_json.get("benchmarking", {})
        casing = morning_report.get("casing_schematic", []) if isinstance(morning_report, dict) else []
        timeline = morning_report.get("activity_timeline", []) if isinstance(morning_report, dict) else []
        benchmark_comparisons = benchmarking.get("comparisons", []) if isinstance(benchmarking, dict) else []
        benchmark_anomalies = benchmarking.get("active_anomalies", []) if isinstance(benchmarking, dict) else []
        benchmark_ai = benchmarking.get("ai_interpretation", []) if isinstance(benchmarking, dict) else []
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
                f"<td>{xml_escape(str(failure.get('confidence', 0)))}</td>"
                f"<td>{xml_escape(str(failure.get('validation_status', '')))}</td>"
                "</tr>"
            )
            for failure in failures
        )
        if not failure_rows:
            failure_rows = "<tr><td colspan=\"7\">No extracted failures in scope.</td></tr>"
        benchmark_rows = "".join(
            (
                "<tr>"
                f"<td>{xml_escape(str(item.get('metric', '')))}</td>"
                f"<td>{xml_escape(str(item.get('benchmark_name', '')))}</td>"
                f"<td>{xml_escape(str(item.get('current_value', '')))}</td>"
                f"<td>{xml_escape(str(item.get('benchmark_value', '')))}</td>"
                f"<td>{xml_escape(str(item.get('absolute_variance', '')))}</td>"
                f"<td>{xml_escape(str(item.get('percentage_variance', '')))}</td>"
                f"<td>{xml_escape(str(item.get('performance_status', '')))}</td>"
                "</tr>"
            )
            for item in benchmark_comparisons
            if isinstance(item, dict)
        )
        if not benchmark_rows:
            benchmark_rows = "<tr><td colspan=\"7\">No approved benchmark comparison is available.</td></tr>"
        anomaly_items = "".join(
            f"<li>{xml_escape(str(item.get('summary', '')))}</li>"
            for item in benchmark_anomalies
            if isinstance(item, dict)
        )
        ai_items = "".join(
            f"<li><strong>{xml_escape(str(item.get('category', '')))}:</strong> {xml_escape(str(item.get('text', '')))}</li>"
            for item in benchmark_ai
            if isinstance(item, dict)
        )
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
        standard_sections = (
            morning_report.get("standard_daily_report", []) if isinstance(morning_report, dict) else []
        )
        standard_rows = "".join(
            (
                "<tr>"
                f"<td>{xml_escape(str(item.get('section', '')))}</td>"
                f"<td>{xml_escape(str(item.get('status', '')))}</td>"
                f"<td>{xml_escape(str(item.get('detail', '')))}</td>"
                "</tr>"
            )
            for item in standard_sections
            if isinstance(item, dict)
        )
        well_schematic = morning_report.get("well_schematic", {}) if isinstance(morning_report, dict) else {}
        hole_sections = well_schematic.get("hole_sections", []) if isinstance(well_schematic, dict) else []
        hole_rows = "".join(
            (
                "<tr>"
                f"<td>{xml_escape(str(item.get('hole_size', '')))}</td>"
                f"<td>{xml_escape(str(item.get('interval_ft', '')))}</td>"
                f"<td>{xml_escape(str(item.get('status', '')))}</td>"
                "</tr>"
            )
            for item in hole_sections
            if isinstance(item, dict)
        )
        surface_items = "".join(
            f"<li>{xml_escape(str(item))}</li>"
            for item in (well_schematic.get("surface_equipment", []) if isinstance(well_schematic, dict) else [])
        )
        risk_items = "".join(
            f"<li>{xml_escape(str(item))}</li>"
            for item in (well_schematic.get("risk_markers", []) if isinstance(well_schematic, dict) else [])
        )
        plan_rows = "".join(
            (
                "<tr>"
                f"<td>{xml_escape(str(item.get('step', '')))}</td>"
                f"<td>{xml_escape(str(item.get('owner', '')))}</td>"
                f"<td>{xml_escape(str(item.get('status', '')))}</td>"
                f"<td>{xml_escape(str(item.get('action', '')))}</td>"
                "</tr>"
            )
            for item in (morning_report.get("ai_execution_plan", []) if isinstance(morning_report, dict) else [])
            if isinstance(item, dict)
        )
        checklist_items = "".join(
            f"<li>{xml_escape(str(item))}</li>"
            for item in (morning_report.get("client_issue_checklist", []) if isinstance(morning_report, dict) else [])
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
            ".schematic-drawing{display:grid;grid-template-columns:110px 1fr;gap:14px;margin-top:12px}.wellbore{position:relative;min-height:260px;border-left:10px solid #0e7490;border-right:10px solid #0e7490;border-bottom:10px solid #b45309;background:#f8fbfd}.wellbore span{position:absolute;left:22px;right:22px;border-top:2px dashed #647384;color:#334155;font-size:12px;font-weight:700}.wellbore .s1{top:16%}.wellbore .s2{top:55%}.wellbore .s3{bottom:8%}.schematic-notes{font-size:13px}.checklist{columns:2}"
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
            "<section><h2>Standard Daily Report Format</h2><table><thead><tr><th>Section</th><th>Status</th><th>Detail</th></tr></thead>"
            f"<tbody>{standard_rows}</tbody></table></section>"
            "<section><h2>Market Benchmark</h2><table><thead><tr><th>Metric</th><th>Benchmark</th><th>Current</th><th>Benchmark Value</th><th>Variance</th><th>Variance %</th><th>Status</th></tr></thead>"
            f"<tbody>{benchmark_rows}</tbody></table><h3>Active Anomalies</h3><ul>{anomaly_items or '<li>No active benchmark anomalies.</li>'}</ul>"
            f"<h3>AI Interpretation Review</h3><ul>{ai_items}</ul></section>"
            "<section><h2>Failure Summary</h2><table><thead><tr><th>Event</th><th>Severity</th><th>Company</th>"
            "<th>Tool</th><th>NPT Hours</th><th>Confidence</th><th>Validation</th></tr></thead>"
            f"<tbody>{failure_rows}</tbody></table></section>"
            "<section class=\"grid\"><div><h2>Casing Schematic</h2><table><thead><tr><th>Name</th><th>OD</th><th>Top ft</th><th>Shoe ft</th><th>Status</th></tr></thead>"
            f"<tbody>{casing_rows}</tbody></table></div>"
            "<div><h2>24 Hr Activity Timeline</h2><table><thead><tr><th>Time</th><th>Activity</th></tr></thead>"
            f"<tbody>{timeline_rows}</tbody></table></div></section>"
            "<section><h2>Well Schematic</h2><div class=\"schematic-drawing\"><div class=\"wellbore\"><span class=\"s1\">Surface shoe</span><span class=\"s2\">Intermediate shoe</span><span class=\"s3\">Planned TD</span></div>"
            f"<div class=\"schematic-notes\"><h3>Surface / Control Notes</h3><ul>{surface_items}</ul><h3>Risk Markers</h3><ul>{risk_items}</ul></div></div>"
            f"<table><thead><tr><th>Hole Size</th><th>Interval ft</th><th>Status</th></tr></thead><tbody>{hole_rows}</tbody></table></section>"
            "<section><h2>AI Plan &amp; Execution</h2><table><thead><tr><th>Step</th><th>Owner</th><th>Status</th><th>Action</th></tr></thead>"
            f"<tbody>{plan_rows}</tbody></table><h3>Client Issue Checklist</h3><ul class=\"checklist\">{checklist_items}</ul></section>"
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
        benchmarking = report.report_json.get("benchmarking", {})
        source_coverage = report.report_json.get("source_coverage", {})
        notes = report.report_json.get("data_quality_notes", [])
        standard_sections = (
            morning_report.get("standard_daily_report", []) if isinstance(morning_report, dict) else []
        )
        benchmark_comparisons = benchmarking.get("comparisons", []) if isinstance(benchmarking, dict) else []
        benchmark_anomalies = benchmarking.get("active_anomalies", []) if isinstance(benchmarking, dict) else []
        benchmark_ai = benchmarking.get("ai_interpretation", []) if isinstance(benchmarking, dict) else []
        well_schematic = morning_report.get("well_schematic", {}) if isinstance(morning_report, dict) else {}
        hole_sections = well_schematic.get("hole_sections", []) if isinstance(well_schematic, dict) else []
        ai_plan = morning_report.get("ai_execution_plan", []) if isinstance(morning_report, dict) else []
        checklist = morning_report.get("client_issue_checklist", []) if isinstance(morning_report, dict) else []
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
                Paragraph("Standard Daily Report Format", styles["h2"]),
                LocalStateStore._pdf_table(
                    [["Section", "Status", "Detail"]]
                    + [
                        [
                            str(item.get("section", "")),
                            str(item.get("status", "")),
                            str(item.get("detail", "")),
                        ]
                        for item in standard_sections
                        if isinstance(item, dict)
                    ],
                    [1.65 * inch, 1.05 * inch, 3.8 * inch],
                    styles,
                ),
                Paragraph("Market Benchmark", styles["h2"]),
                LocalStateStore._pdf_table(
                    [["Metric", "Benchmark", "Current", "Bench", "Variance", "%", "Status"]]
                    + [
                        [
                            str(item.get("metric", "")),
                            str(item.get("benchmark_name", "")),
                            str(item.get("current_value", "")),
                            str(item.get("benchmark_value", "")),
                            str(item.get("absolute_variance", "")),
                            str(item.get("percentage_variance", "")),
                            str(item.get("performance_status", "")),
                        ]
                        for item in benchmark_comparisons
                        if isinstance(item, dict)
                    ],
                    [1.1 * inch, 1.2 * inch, 0.7 * inch, 0.7 * inch, 0.75 * inch, 0.5 * inch, 1.2 * inch],
                    styles,
                ),
                Paragraph("Benchmark Anomalies", styles["h2"]),
            ]
        )
        if benchmark_anomalies:
            story.extend(
                Paragraph(str(item.get("summary", "")), styles["body"])
                for item in benchmark_anomalies
                if isinstance(item, dict)
            )
        else:
            story.append(Paragraph("No active benchmark anomalies.", styles["body"]))
        story.extend(
            [
                Paragraph("AI Interpretation Review", styles["h2"]),
            ]
        )
        story.extend(
            Paragraph(
                f"{item.get('category', '')}: {item.get('text', '')}",
                styles["body"],
            )
            for item in benchmark_ai
            if isinstance(item, dict)
        )
        story.extend(
            [
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
                Paragraph("Well Schematic", styles["h2"]),
                Paragraph(
                    "Surface / control notes: "
                    + "; ".join(str(item) for item in (well_schematic.get("surface_equipment", []) if isinstance(well_schematic, dict) else [])),
                    styles["body"],
                ),
                Paragraph(
                    "Risk markers: "
                    + "; ".join(str(item) for item in (well_schematic.get("risk_markers", []) if isinstance(well_schematic, dict) else [])),
                    styles["body"],
                ),
                LocalStateStore._pdf_table(
                    [["Hole Size", "Interval ft", "Status"]]
                    + [
                        [
                            str(item.get("hole_size", "")),
                            str(item.get("interval_ft", "")),
                            str(item.get("status", "")),
                        ]
                        for item in hole_sections
                        if isinstance(item, dict)
                    ],
                    [1.3 * inch, 1.4 * inch, 3.8 * inch],
                    styles,
                ),
                Paragraph("AI Plan & Execution", styles["h2"]),
                LocalStateStore._pdf_table(
                    [["Step", "Owner", "Status", "Action"]]
                    + [
                        [
                            str(item.get("step", "")),
                            str(item.get("owner", "")),
                            str(item.get("status", "")),
                            str(item.get("action", "")),
                        ]
                        for item in ai_plan
                        if isinstance(item, dict)
                    ],
                    [0.75 * inch, 1.2 * inch, 0.8 * inch, 3.75 * inch],
                    styles,
                ),
                Paragraph("Client Issue Checklist", styles["h2"]),
            ]
        )
        story.extend(Paragraph(f"- {item}", styles["body"]) for item in checklist)
        story.extend(
            [
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
        morning_report = report.report_json.get("morning_report", {})
        benchmarking = report.report_json.get("benchmarking", {})
        standard_sections = (
            morning_report.get("standard_daily_report", []) if isinstance(morning_report, dict) else []
        )
        well_schematic = morning_report.get("well_schematic", {}) if isinstance(morning_report, dict) else {}
        ai_plan = morning_report.get("ai_execution_plan", []) if isinstance(morning_report, dict) else []
        benchmark_comparisons = benchmarking.get("comparisons", []) if isinstance(benchmarking, dict) else []
        lines = [
            "Monday Report",
            f"Period: {period.get('start', '')} to {period.get('end', '')}",
            "",
            "Executive Summary",
        ]
        lines.extend(str(item.get("text", "")) for item in summary)
        lines.extend(["", "Standard Daily Report Format"])
        lines.extend(
            f"{item.get('section', '')}: {item.get('status', '')} - {item.get('detail', '')}"
            for item in standard_sections
            if isinstance(item, dict)
        )
        lines.extend(["", "Market Benchmark"])
        lines.extend(
            f"{item.get('metric', '')}: {item.get('current_value', '')} vs {item.get('benchmark_name', '')} {item.get('benchmark_value', '')} - {item.get('performance_status', '')}"
            for item in benchmark_comparisons
            if isinstance(item, dict)
        )
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
        lines.extend(["", "Well Schematic"])
        lines.extend(
            f"{item.get('hole_size', '')}: {item.get('interval_ft', '')} - {item.get('status', '')}"
            for item in (well_schematic.get("hole_sections", []) if isinstance(well_schematic, dict) else [])
            if isinstance(item, dict)
        )
        lines.extend(["", "AI Plan & Execution"])
        lines.extend(
            f"{item.get('step', '')}: {item.get('status', '')} - {item.get('action', '')}"
            for item in ai_plan
            if isinstance(item, dict)
        )

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
        benchmarking = report.report_json.get("benchmarking", {})
        notes = report.report_json.get("data_quality_notes", [])
        standard_sections = (
            morning_report.get("standard_daily_report", []) if isinstance(morning_report, dict) else []
        )
        benchmark_comparisons = benchmarking.get("comparisons", []) if isinstance(benchmarking, dict) else []
        benchmark_anomalies = benchmarking.get("active_anomalies", []) if isinstance(benchmarking, dict) else []
        benchmark_ai = benchmarking.get("ai_interpretation", []) if isinstance(benchmarking, dict) else []
        well_schematic = morning_report.get("well_schematic", {}) if isinstance(morning_report, dict) else {}
        ai_plan = morning_report.get("ai_execution_plan", []) if isinstance(morning_report, dict) else []
        rows: list[list[object]] = [
            ["Monday Report"],
            ["Format Version", report.report_json.get("report_format_version", "MR-DDR-1")],
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
            ["Standard Daily Report Format"],
            ["Section", "Status", "Detail"],
        ]
        rows.extend(
            [
                [item.get("section", ""), item.get("status", ""), item.get("detail", "")]
                for item in standard_sections
                if isinstance(item, dict)
            ]
        )
        rows.extend(
            [
                [],
                ["Market Benchmark"],
                ["Metric", "Benchmark", "Current", "Benchmark Value", "Variance", "Variance %", "Status", "Source"],
            ]
        )
        rows.extend(
            [
                [
                    item.get("metric", ""),
                    item.get("benchmark_name", ""),
                    item.get("current_value", ""),
                    item.get("benchmark_value", ""),
                    item.get("absolute_variance", ""),
                    item.get("percentage_variance", ""),
                    item.get("performance_status", ""),
                    item.get("supporting_source", ""),
                ]
                for item in benchmark_comparisons
                if isinstance(item, dict)
            ]
        )
        rows.extend([[], ["Benchmark Anomalies"], ["Severity", "Summary", "Rule", "MOC Reference"]])
        rows.extend(
            [
                [
                    item.get("severity", ""),
                    item.get("summary", ""),
                    item.get("rule_name", ""),
                    item.get("moc_reference", ""),
                ]
                for item in benchmark_anomalies
                if isinstance(item, dict)
            ]
        )
        rows.extend([[], ["AI Interpretation Review"], ["Category", "Review Status", "Text", "Source"]])
        rows.extend(
            [
                [
                    item.get("category", ""),
                    item.get("review_status", ""),
                    item.get("text", ""),
                    item.get("source_reference", ""),
                ]
                for item in benchmark_ai
                if isinstance(item, dict)
            ]
        )
        rows.extend(
            [
                [],
                ["Failure Summary"],
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
        )
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
        rows.extend(
            [
                [],
                ["Well Schematic"],
                ["Surface / Control Notes"],
            ]
        )
        rows.extend(
            [
                ["Note", item]
                for item in (well_schematic.get("surface_equipment", []) if isinstance(well_schematic, dict) else [])
            ]
        )
        rows.extend(
            [
                [],
                ["Hole Sections"],
                ["Hole Size", "Interval ft", "Status"],
            ]
        )
        rows.extend(
            [
                [item.get("hole_size", ""), item.get("interval_ft", ""), item.get("status", "")]
                for item in (well_schematic.get("hole_sections", []) if isinstance(well_schematic, dict) else [])
                if isinstance(item, dict)
            ]
        )
        rows.extend(
            [
                [],
                ["Risk Markers"],
            ]
        )
        rows.extend(
            [
                ["Risk", item]
                for item in (well_schematic.get("risk_markers", []) if isinstance(well_schematic, dict) else [])
            ]
        )
        rows.extend(
            [
                [],
                ["AI Plan & Execution"],
                ["Step", "Owner", "Status", "Action"],
            ]
        )
        rows.extend(
            [
                [item.get("step", ""), item.get("owner", ""), item.get("status", ""), item.get("action", "")]
                for item in ai_plan
                if isinstance(item, dict)
            ]
        )
        rows.extend(
            [
                [],
                ["Client Issue Checklist"],
            ]
        )
        rows.extend(
            [
                ["Check", item]
                for item in (morning_report.get("client_issue_checklist", []) if isinstance(morning_report, dict) else [])
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

        explicit_patterns = (
            r"\bnpt\s*(?:hours?|hrs?|hr)?\s*[:=]\s*([0-9]+(?:\.[0-9]+)?)\b",
            r"\bnon[- ]productive\s*time\s*[:=]\s*([0-9]+(?:\.[0-9]+)?)\s*(?:hours?|hrs?|hr)?\b",
            r"\b(?:npt|non[- ]productive\s*time)\b.{0,48}?\b([0-9]+(?:\.[0-9]+)?)\s*(?:hours?|hrs?|hr)\b",
            r"\b([0-9]+(?:\.[0-9]+)?)\s*(?:hours?|hrs?|hr)\b.{0,48}?\b(?:npt|non[- ]productive\s*time)\b",
        )
        for pattern in explicit_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return float(match.group(1))

        if "npt" in text.lower():
            candidates: list[float] = []
            for value, unit in re.findall(
                r"\b([0-9]+(?:\.[0-9]+)?)\s*(ft|feet|in|inch|ppg|psi|bbl|rpm|gpm)?\b",
                text,
                re.IGNORECASE,
            ):
                if unit:
                    continue
                number = float(value)
                if 0 < number <= 240:
                    candidates.append(number)
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
            if chunk_context:
                for key in ["field", "label", "section"]:
                    value = chunk_context.get(key)
                    if isinstance(value, str) and value.strip():
                        locator[key] = value.strip()[:120]
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

        return parser_name, LocalStateStore._clean_extracted_text(raw_text), metadata

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
                    page_text = LocalStateStore._clean_extracted_text(page_text)
                    for chunk_text in LocalStateStore._chunk_text(page_text):
                        records.append({"text": chunk_text, "page": page_number})
                tables = parser_metadata.get("tables")
                if parser_name == "pdf_text_v1" and isinstance(tables, list):
                    for table in tables:
                        if not isinstance(table, dict):
                            continue
                        records.extend(LocalStateStore._pdf_table_chunk_records(table))
                report_profile = parser_metadata.get("report_profile")
                if parser_name == "pdf_text_v1" and isinstance(report_profile, dict):
                    records.extend(LocalStateStore._pdf_report_profile_chunk_records(report_profile))
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
        cells = [LocalStateStore._clean_extracted_text(str(cell)) for cell in row]
        if isinstance(header, list) and len(header) == len(row):
            pairs = [
                f"{LocalStateStore._clean_extracted_text(str(column))}: {value}"
                for column, value in zip(header, cells)
                if LocalStateStore._clean_extracted_text(str(column)) and value
            ]
            if pairs:
                return "; ".join(pairs)
        return " | ".join(value for value in cells if value)

    @staticmethod
    def _extract_pdf_report_profile(
        pages: list[dict[str, object]],
        tables: list[dict[str, object]],
    ) -> dict[str, object] | None:
        page_lines = LocalStateStore._pdf_page_lines(pages)
        full_text = "\n".join(line for _, line in page_lines)
        lower_text = full_text.lower()
        fields: dict[str, str] = {}
        field_sources: dict[str, dict[str, object]] = {}
        sections: dict[str, str] = {}
        section_sources: dict[str, dict[str, object]] = {}

        field_specs: dict[str, list[tuple[str, str]]] = {
            "report_no": [
                ("report no", r"\b(?:report\s*(?:no\.?|number|#)|ddr\s*(?:no\.?|#)?)\s*[:#-]\s*([A-Za-z0-9._/-]{1,40})"),
            ],
            "well": [
                # Well names may legitimately carry bracketed pad codes, lease
                # hashes, and ampersands; capture stops before an adjacent
                # `Label:`/`Label#` field boundary on the same line.
                (
                    "well",
                    r"\b(?:well|well name)\s*[:#-]\s*"
                    r"((?:(?!\s*\b(?:rig(?:\s*name)?|operator|company|report\s*(?:no\.?|number|#)?|api|field|job|md|tvd|date)\s*[:#])"
                    r"[A-Za-z0-9()\[\]#&/_ .-]){2,80})",
                ),
            ],
            "rig": [
                ("rig", r"\b(?:rig|rig name)\s*[:#-]\s*([A-Za-z0-9()/_ .-]{2,80})"),
            ],
            "operator": [
                ("operator", r"\b(?:operator|company representative)\s*[:#-]\s*([A-Za-z0-9()/_ .-]{2,80})"),
            ],
            "hole_size": [
                ("hole size", r"\b(?:hole\s*size|hole)\s*[:#-]?\s*([0-9]{1,2}(?:\.[0-9]{1,3})?)\s*(?:in|inch|\")"),
            ],
            "md_ft": [
                ("md", r"\b(?:md|measured depth)\s*[:#-]?\s*([0-9]{1,3}(?:,[0-9]{3})+|[0-9]{4,6}(?:\.[0-9]+)?)\s*(?:ft|feet|')?"),
            ],
            "tvd_ft": [
                ("tvd", r"\b(?:tvd|true vertical depth)\s*[:#-]?\s*([0-9]{1,3}(?:,[0-9]{3})+|[0-9]{4,6}(?:\.[0-9]+)?)\s*(?:ft|feet|')?"),
            ],
            "mud_weight": [
                ("mud weight", r"\b(?:mud\s*(?:weight|wt|density)|mw)\s*[:#-]?\s*([0-9]{1,2}(?:\.[0-9]+)?)\s*(?:ppg|lb/gal)"),
            ],
        }
        for field, specs in field_specs.items():
            match = LocalStateStore._match_pdf_profile_line(page_lines, specs)
            if match:
                fields[field] = match["value"]
                field_sources[field] = {
                    "page": match["page"],
                    "label": match["label"],
                    "confidence": 0.9,
                }

        section_specs: dict[str, list[tuple[str, str]]] = {
            "present_operations": [
                ("present operations", r"\b(?:present operations?|current operations?|operations summary)\s*[:#-]\s*(.{8,260})"),
            ],
            "next_operations": [
                ("next operations", r"\b(?:next operations?|next 24\s*hr plan|next 24 hours?|plan forward)\s*[:#-]\s*(.{8,260})"),
            ],
            "safety": [
                ("safety", r"\b(?:safety|hse|well control)\s*[:#-]\s*(.{8,260})"),
            ],
            "casing": [
                ("casing", r"\b(?:casing|casing status|casing program)\s*[:#-]\s*(.{8,260})"),
            ],
            "bha": [
                ("bha", r"\b(?:bha|bottom hole assembly|bit and bha)\s*[:#-]\s*(.{8,260})"),
            ],
            "survey": [
                ("survey", r"\b(?:survey|survey data|directional survey)\s*[:#-]\s*(.{8,260})"),
            ],
            "time_breakdown": [
                ("time breakdown", r"\b(?:time breakdown|24\s*hr activity|activity timeline)\s*[:#-]\s*(.{8,260})"),
            ],
        }
        for section, specs in section_specs.items():
            match = LocalStateStore._match_pdf_profile_line(page_lines, specs, max_length=260, trim_delimiters=False)
            if match:
                sections[section] = match["value"]
                section_sources[section] = {
                    "page": match["page"],
                    "label": match["label"],
                    "confidence": 0.82,
                }

        section_presence = {
            # The DDR acronym must stand alone as a word: plain substring
            # containment matched inside unrelated words such as "address".
            "daily_drilling_report": "daily drilling report" in lower_text
            or bool(re.search(r"\bddr\b", lower_text)),
            "well_job_info": any(marker in lower_text for marker in ["well", "rig", "operator"]),
            "drilling_parameters": any(marker in lower_text for marker in ["hole size", "mud weight", "tvd", "measured depth"]),
            "mud_bha_survey": any(marker in lower_text for marker in ["mud", "bha", "survey", "mwd", "lwd"]),
            "casing": "casing" in lower_text or "shoe" in lower_text,
            "time_breakdown": "time breakdown" in lower_text or "24 hr" in lower_text or "activity timeline" in lower_text,
            "npt": "npt" in lower_text or any(LocalStateStore._pdf_table_mentions(table, ["npt", "non-productive"]) for table in tables),
        }
        casing_strings = LocalStateStore._extract_casing_strings(page_lines)
        activity_timeline = LocalStateStore._extract_activity_timeline(page_lines, tables)
        survey_stations, survey_truncated = LocalStateStore._extract_survey_stations(page_lines, tables)
        hydraulics_observations, hydraulics_truncated = LocalStateStore._extract_hydraulics_observations(
            page_lines, tables
        )
        structured_score = (
            len(casing_strings) + len(activity_timeline) + len(survey_stations) + len(hydraulics_observations)
        )
        marker_score = sum(1 for value in section_presence.values() if value)
        field_score = len(fields) + len(sections)
        if field_score < 2 and marker_score < 2 and structured_score < 2:
            return None
        confidence = min(
            0.97,
            0.35 + field_score * 0.045 + marker_score * 0.035 + structured_score * 0.02,
        )
        # Completion detection uses positive heading evidence only: the phrase
        # (DAILY COMPLETION REPORT / WELL COMPLETION REPORT / COMPLETION
        # REPORT) must appear in the first page's header region. Incidental
        # completion mentions in narrative never veto classification,
        # filenames are never consulted, and an explicit DDR heading always
        # wins. The veto applies only to the generic marker-score fallback;
        # no new document type is minted.
        first_page_lines = [line for page_number, line in page_lines if page_number == 1]
        heading_region = " ".join(first_page_lines[:12]).lower()
        if section_presence["daily_drilling_report"]:
            document_type = "daily_drilling_report"
        elif "completion report" in heading_region:
            document_type = "pdf_report"
        elif marker_score >= 4:
            document_type = "daily_drilling_report"
        else:
            document_type = "pdf_report"
        return {
            "profile_version": "pdf_report_profile_v1",
            "document_type": document_type,
            "confidence": round(confidence, 3),
            "field_count": len(fields),
            "section_count": len(sections),
            "fields": fields,
            "field_sources": field_sources,
            "sections": sections,
            "section_sources": section_sources,
            "section_presence": section_presence,
            "casing_strings": casing_strings,
            "activity_timeline": activity_timeline,
            # Additive pdf_report_profile_v1 extension: structured survey stations.
            "survey_stations": survey_stations,
            "survey_truncated": survey_truncated,
            # Additive extension: source-derived hydraulics observations
            # (deterministic_hydraulics v1; explicit units only).
            "hydraulics_observations": hydraulics_observations,
            "hydraulics_truncated": hydraulics_truncated,
        }

    @staticmethod
    def _extract_casing_strings(page_lines: list[tuple[int, str]]) -> list[dict[str, object]]:
        """Deterministically parse casing-string rows from source lines.

        Emits one row per casing string that states an outside diameter and/or a
        setting/shoe depth. Nothing is inferred: rows without an OD or a depth are
        dropped rather than back-filled with assumed values.
        """
        casing_terms = ("conductor", "surface", "intermediate", "production", "liner", "casing")
        rows: list[dict[str, object]] = []
        seen: set[tuple[str, str, object]] = set()
        for page_number, line in page_lines:
            lower_line = line.lower()
            if not any(term in lower_line for term in casing_terms):
                continue
            # A leading `Casing:`/`Liner:` label grants casing context to every
            # semicolon-delimited segment on this logical line only; the
            # context never leaks into later lines.
            label_context = bool(
                re.match(r"\s*(?:casing(?:\s+(?:program|status))?|liner)\s*[:#-]", line, flags=re.IGNORECASE)
            )
            segments = re.split(
                r";|(?:,\s*(?=(?:conductor|surface|intermediate|production|liner)))",
                line,
                flags=re.IGNORECASE,
            )
            for segment in segments:
                parsed = LocalStateStore._parse_casing_segment(
                    segment.strip(" ."), page_number, label_context=label_context
                )
                if not parsed:
                    continue
                key = (str(parsed["name"]).lower(), str(parsed.get("od") or ""), parsed.get("shoe_ft"))
                if key in seen:
                    continue
                seen.add(key)
                rows.append(parsed)
                if len(rows) >= 12:
                    return rows
        return rows

    @staticmethod
    def _parse_casing_segment(
        segment: str, page_number: int, label_context: bool = False
    ) -> dict[str, object] | None:
        if not segment:
            return None
        lower = segment.lower()
        # Hard negatives: bit, pipe, BHA, nozzle, and pipe-handling narrative
        # is never a casing string, whatever adjectives or depths it carries.
        if re.search(
            r"\b(?:pdc|bits?|nozzles?|jets?|drill\s*pipe|drillpipe|hwdp|bha|stands?|hole\s*opener"
            r"|lay(?:ing|ed)?\s*down|laid\s*down|pick(?:ing|ed)?\s*up|wear\s*bushing"
            r"|casing\s*(?:point|readiness|crew|tools))\b",
            lower,
        ):
            return None
        name_match = re.search(r"\b(conductor|surface|intermediate|production|liner)\b", lower)
        if name_match:
            name = name_match.group(1).title()
        elif "casing" in lower:
            name = "Casing"
        else:
            return None
        # Positive casing context is required: a hole-section adjective, a
        # diameter, or a depth alone never makes a casing row.
        positive_context = (
            label_context
            or bool(re.search(r"\b(?:conductor|surface|intermediate|production)\s+(?:casing|liner|string)\b", lower))
            or bool(
                re.search(r"\b(?:casing|liner)\b", lower)
                and re.search(r"\b(?:ran|run|set|cemented|cement|landed|rih)\b", lower)
            )
            or bool(re.search(r"\bshoe\b", lower))
            or bool(
                re.search(r"\b(?:planned|proposed)\b", lower) and re.search(r"\b(?:casing|liner)\b", lower)
            )
        )
        if not positive_context:
            return None
        od = None
        fraction_match = re.search(
            r"\b([0-9]{1,2})[\s-]+([0-9]{1,2})\s*/\s*([0-9]{1,2})\s*(?:in\b|inch|\")",
            segment,
            flags=re.IGNORECASE,
        )
        decimal_match = re.search(
            r"(?<![/\d.])([0-9]{1,2}(?:\.[0-9]{1,3})?)\s*(?:in\b|inch|\")",
            segment,
            flags=re.IGNORECASE,
        )
        # Mixed fractions are complete diameters (12 1/4 -> 12.25); the
        # decimal matcher can never re-match a fraction denominator, and the
        # leftmost stated size wins when both forms appear.
        if fraction_match and (not decimal_match or fraction_match.start() <= decimal_match.start()):
            denominator = int(fraction_match.group(3))
            if denominator:
                od = f"{int(fraction_match.group(1)) + int(fraction_match.group(2)) / denominator:g} in"
        elif decimal_match:
            od = f"{decimal_match.group(1)} in"
        shoe_ft = LocalStateStore._parse_depth_to_ft(segment)
        # A depth is a shoe/set depth only with explicit association or inside
        # a casing-labelled line; arbitrary apostrophe depths never qualify.
        if shoe_ft is not None and not label_context and not re.search(
            r"\b(?:shoe|set|landed|planned|proposed)\b", lower
        ):
            shoe_ft = None
        if od is None and shoe_ft is None:
            return None
        if re.search(r"\b(set|shoe|run|cemented|cement)\b", lower):
            status = "set"
        elif re.search(r"\b(planned|plan|proposed|forecast|future)\b", lower):
            status = "planned"
        else:
            status = "reported"
        confidence = round(0.6 + (0.2 if od else 0.0) + (0.15 if shoe_ft is not None else 0.0), 3)
        return {
            "name": name,
            "od": od,
            "top_ft": None,
            "shoe_ft": shoe_ft,
            "status": status,
            "page": page_number,
            "confidence": confidence,
        }

    @staticmethod
    def _parse_depth_to_ft(text: str) -> float | None:
        feet = re.search(
            r"([0-9]{1,3}(?:,[0-9]{3})+|[0-9]{3,6}(?:\.[0-9]+)?)\s*(?:ft\b|feet\b|')",
            text,
            flags=re.IGNORECASE,
        )
        if feet:
            try:
                return float(feet.group(1).replace(",", ""))
            except ValueError:
                return None
        metres = re.search(
            r"([0-9]{2,4}(?:\.[0-9]+)?)\s*(?:m\b|metre|meter|metres|meters)\b",
            text,
            flags=re.IGNORECASE,
        )
        if metres:
            try:
                return round(float(metres.group(1)) * 3.28084, 1)
            except ValueError:
                return None
        return None

    @staticmethod
    def _extract_activity_timeline(
        page_lines: list[tuple[int, str]],
        tables: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        """Deterministically parse timed 24-hour activity rows from source lines/tables.

        Only explicit time ranges (e.g. ``00:00-06:00``) are extracted; narrative
        without times is never converted into fabricated timed rows.
        """
        rows: list[dict[str, object]] = []
        seen: set[tuple[str, str]] = set()
        range_pattern = re.compile(r"([0-9]{1,2}:[0-5][0-9])\s*[-–—]\s*([0-9]{1,2}:[0-5][0-9])\s*[|:\-]?\s*(.+)")
        for page_number, line in page_lines:
            match = range_pattern.search(line)
            if not match:
                continue
            start, end = match.group(1), match.group(2)
            if not LocalStateStore._valid_time_range(start, end):
                continue
            activity = match.group(3).strip(" .|-")[:160].strip()
            if not activity:
                continue
            time_label = f"{LocalStateStore._normalize_clock(start)}-{LocalStateStore._normalize_clock(end)}"
            key = (time_label, activity.lower())
            if key in seen:
                continue
            seen.add(key)
            rows.append({"time": time_label, "activity": activity, "page": page_number, "confidence": 0.82})
            if len(rows) >= 12:
                break
        if not rows:
            rows = LocalStateStore._activity_rows_from_tables(tables)
        LocalStateStore._flag_overlapping_activities(rows)
        return rows

    @staticmethod
    def _activity_rows_from_tables(tables: list[dict[str, object]]) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        seen: set[tuple[str, str]] = set()
        for table in tables:
            table_rows = table.get("rows") if isinstance(table, dict) else None
            page = table.get("page") if isinstance(table, dict) else None
            if not isinstance(table_rows, list):
                continue
            for table_row in table_rows:
                if not isinstance(table_row, list) or len(table_row) < 2:
                    continue
                time_cell = str(table_row[0]).strip()
                time_match = re.match(r"^([0-9]{1,2}:[0-5][0-9])\s*[-–—]\s*([0-9]{1,2}:[0-5][0-9])$", time_cell)
                if not time_match or not LocalStateStore._valid_time_range(time_match.group(1), time_match.group(2)):
                    continue
                activity = " ".join(str(cell).strip() for cell in table_row[1:] if str(cell).strip())[:160].strip()
                if not activity:
                    continue
                time_label = f"{LocalStateStore._normalize_clock(time_match.group(1))}-{LocalStateStore._normalize_clock(time_match.group(2))}"
                key = (time_label, activity.lower())
                if key in seen:
                    continue
                seen.add(key)
                rows.append({
                    "time": time_label,
                    "activity": activity,
                    "page": page if isinstance(page, int) and page > 0 else 1,
                    "confidence": 0.8,
                })
        return rows

    @staticmethod
    def _flag_overlapping_activities(rows: list[dict[str, object]]) -> None:
        ordered: list[tuple[int, int, dict[str, object]]] = []
        for row in rows:
            parts = str(row.get("time", "")).split("-")
            if len(parts) != 2:
                continue
            start = LocalStateStore._clock_minutes(parts[0])
            end = LocalStateStore._clock_minutes(parts[1])
            if start is None or end is None:
                continue
            ordered.append((start, end, row))
        ordered.sort(key=lambda item: item[0])
        for index in range(1, len(ordered)):
            previous = ordered[index - 1]
            current = ordered[index]
            if current[0] < previous[1]:
                for _, _, row in (previous, current):
                    row["confidence"] = min(float(row.get("confidence", 0.8)), 0.5)
                    row["conflict"] = True

    @staticmethod
    def _clock_minutes(value: str) -> int | None:
        match = re.match(r"^\s*([0-9]{1,2}):([0-5][0-9])\s*$", str(value))
        if not match:
            return None
        hours = int(match.group(1))
        minutes = int(match.group(2))
        if hours > 24 or (hours == 24 and minutes > 0):
            return None
        return hours * 60 + minutes

    @staticmethod
    def _normalize_clock(value: str) -> str:
        match = re.match(r"^\s*([0-9]{1,2}):([0-5][0-9])\s*$", str(value))
        if not match:
            return str(value).strip()
        return f"{int(match.group(1)):02d}:{match.group(2)}"

    @staticmethod
    def _valid_time_range(start: str, end: str) -> bool:
        start_minutes = LocalStateStore._clock_minutes(start)
        end_minutes = LocalStateStore._clock_minutes(end)
        if start_minutes is None or end_minutes is None:
            return False
        return 0 <= start_minutes < end_minutes <= 24 * 60

    # ------------------------------------------------------------------
    # Directional survey-station extraction (source-only; no derivation).
    # ------------------------------------------------------------------

    _SURVEY_HEADER_FIELDS: tuple[tuple[str, str], ...] = (
        ("md", r"^(?:md|measured\s*depth)\b"),
        ("inclination", r"^(?:inc|incl|inclination)\b"),
        ("azimuth", r"^(?:azimuth|azm|azi|az)\b"),
        ("tvd", r"^(?:tvd|true\s*vertical\s*depth)\b"),
        ("dls", r"^(?:dls|dogleg)\b"),
        ("ns", r"^(?:n/?s|north(?:ing)?|north\s*/?\s*south)\b"),
        ("ew", r"^(?:e/?w|east(?:ing)?|east\s*/?\s*west)\b"),
        ("station", r"^(?:station|survey\s*(?:no|#|id)?|no\.?|#)$"),
        ("survey_type", r"^(?:type|survey\s*type|plan(?:ned)?/?actual)\b"),
    )

    @staticmethod
    def _extract_survey_stations(
        page_lines: list[tuple[int, str]],
        tables: list[dict[str, object]],
    ) -> tuple[list[dict[str, object]], bool]:
        """Deterministically parse directional survey stations from source evidence.

        Source extraction only: rows are read from recognized survey tables
        (native PDF tables or delimited text lines under a survey header) and
        from explicitly labelled inline narrative (``MD .. Inc .. Azi ..``).
        A row is emitted only when it has a valid measured depth plus a valid
        inclination or azimuth. Nothing is calculated, interpolated, or
        back-filled; unsupported input yields no rows. Returns the rows plus a
        truncation flag when the deterministic 200-row cap was applied.
        """
        row_cap = 200
        collected: list[dict[str, object]] = []
        for table in tables:
            collected.extend(LocalStateStore._survey_rows_from_table(table))
        collected.extend(LocalStateStore._survey_rows_from_lines(page_lines))
        rows = LocalStateStore._finalize_survey_rows(collected)
        truncated = len(rows) > row_cap
        if truncated:
            rows = rows[:row_cap]
        return rows, truncated

    @staticmethod
    def _map_survey_columns(cells: list[str]) -> tuple[dict[str, int], dict[str, str]]:
        """Map header cells to survey fields and per-column depth units.

        Depth columns default to canonical feet; an explicit metre marker in
        the header (``(m)``/``metre``) switches that column to metres. A header
        is accepted only when it names MD plus inclination or azimuth.
        """
        columns: dict[str, int] = {}
        units: dict[str, str] = {}
        for index, raw_cell in enumerate(cells):
            cell = str(raw_cell).strip().lower()
            if not cell:
                continue
            for field, pattern in LocalStateStore._SURVEY_HEADER_FIELDS:
                if field in columns:
                    continue
                if re.search(pattern, cell):
                    columns[field] = index
                    if field in {"md", "tvd", "ns", "ew"}:
                        if re.search(r"\(m\)|\bmetres?\b|\bmeters?\b", cell):
                            units[field] = "m"
                        else:
                            units[field] = "ft"
                    break
        if "md" not in columns or ("inclination" not in columns and "azimuth" not in columns):
            return {}, {}
        return columns, units

    _DOT_GROUPED_DEPTH_PATTERN = re.compile(r"^[0-9]{1,3}(?:\.[0-9]{3})+$")

    @staticmethod
    def _promote_dot_grouped_depth(raw_token: str, parsed_value: float, paired_tvd_ft: float) -> float:
        """Scoped dot-thousands disambiguation for explicitly foot-marked MD tokens.

        A token shaped ``D{1,3}(.DDD)+`` is only a *candidate* thousands
        representation. It is promoted solely when the same source record
        pairs it with an explicit-foot TVD that the decimal reading would
        impossibly undercut while the thousands reading restores the normal
        same-datum relationship. This is a source-token disambiguation aid,
        never an engineering acceptance rule: it is never applied to
        inclination, azimuth, or DLS, never without same-record
        corroboration, and insufficient evidence preserves the ordinary
        decimal interpretation unchanged.
        """
        if not LocalStateStore._DOT_GROUPED_DEPTH_PATTERN.match(raw_token):
            return parsed_value
        thousands = float(raw_token.replace(".", ""))
        if parsed_value < paired_tvd_ft <= thousands:
            return thousands
        return parsed_value

    @staticmethod
    def _survey_cell_float(cell: object) -> float | None:
        text = str(cell).strip()
        if not text or text in {"-", "--", "—", "n/a", "na"}:
            return None
        match = re.search(r"-?[0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]+)?|-?[0-9]+(?:\.[0-9]+)?", text)
        if not match:
            return None
        try:
            return float(match.group(0).replace(",", ""))
        except ValueError:
            return None

    @staticmethod
    def _survey_depth_from_cell(cell: object, unit: str) -> float | None:
        value = LocalStateStore._survey_cell_float(cell)
        if value is None:
            return None
        text = str(cell).lower()
        # An explicit unit inside the cell overrides the header/column unit.
        if re.search(r"[0-9]\s*m\b|\bmetres?\b|\bmeters?\b", text):
            unit = "m"
        elif re.search(r"\bft\b|\bfeet\b|'", text):
            unit = "ft"
        if unit == "m":
            return round(value * 3.28084, 1)
        return value

    @staticmethod
    def _parse_survey_cells(
        cells: list[str],
        columns: dict[str, int],
        units: dict[str, str],
        page: int,
        base_confidence: float,
    ) -> dict[str, object] | None:
        def cell_at(field: str) -> str | None:
            index = columns.get(field)
            if index is None or index >= len(cells):
                return None
            return str(cells[index]).strip()

        md_cell = cell_at("md") or ""
        md = LocalStateStore._survey_depth_from_cell(md_cell, units.get("md", "ft"))
        inclination = LocalStateStore._survey_cell_float(cell_at("inclination"))
        azimuth = LocalStateStore._survey_cell_float(cell_at("azimuth"))
        tvd = LocalStateStore._survey_depth_from_cell(cell_at("tvd") or "", units.get("tvd", "ft"))
        if md is not None and tvd is not None:
            # Same-row dot-thousands disambiguation for an explicitly
            # foot-marked MD cell; see _promote_dot_grouped_depth.
            dot_grouped_cell = re.match(
                r"^\s*([0-9]{1,3}(?:\.[0-9]{3})+)\s*(?:ft\b|feet\b|')\s*$", md_cell, flags=re.IGNORECASE
            )
            if dot_grouped_cell:
                md = LocalStateStore._promote_dot_grouped_depth(dot_grouped_cell.group(1), md, tvd)
        dls = LocalStateStore._survey_cell_float(cell_at("dls"))
        ns = LocalStateStore._survey_depth_from_cell(cell_at("ns") or "", units.get("ns", "ft"))
        ew = LocalStateStore._survey_depth_from_cell(cell_at("ew") or "", units.get("ew", "ft"))
        station_cell = cell_at("station")
        type_cell = cell_at("survey_type")
        return LocalStateStore._validated_survey_row(
            md=md,
            inclination=inclination,
            azimuth=azimuth,
            tvd=tvd,
            dls=dls,
            ns=ns,
            ew=ew,
            station_id=station_cell or None,
            survey_type=(type_cell or "").strip().lower() or None,
            page=page,
            base_confidence=base_confidence,
        )

    @staticmethod
    def _validated_survey_row(
        *,
        md: float | None,
        inclination: float | None,
        azimuth: float | None,
        tvd: float | None,
        dls: float | None,
        ns: float | None,
        ew: float | None,
        station_id: str | None,
        survey_type: str | None,
        page: int,
        base_confidence: float,
    ) -> dict[str, object] | None:
        """Validate ranges and units; invalid rows are dropped, never repaired."""
        if md is None or md < 0:
            return None
        if inclination is not None and not (0.0 <= inclination <= 180.0):
            return None
        if azimuth is not None and not (0.0 <= azimuth <= 360.0):
            return None
        if inclination is None and azimuth is None:
            return None
        if tvd is not None and tvd < 0:
            tvd = None
        if dls is not None and dls < 0:
            dls = None
        # Deterministic confidence: table/narrative base plus increments for
        # each explicitly present field; clamped below 1.0 and reduced to
        # <= 0.5 later when the row participates in a conflict.
        confidence = base_confidence
        if inclination is not None and azimuth is not None:
            confidence += 0.1
        if tvd is not None:
            confidence += 0.05
        if dls is not None:
            confidence += 0.05
        if ns is not None:
            confidence += 0.02
        if ew is not None:
            confidence += 0.02
        return {
            "measured_depth_ft": round(md, 1),
            "inclination_deg": inclination,
            "azimuth_deg": azimuth,
            "true_vertical_depth_ft": tvd,
            "dogleg_severity_dp100ft": dls,
            "north_south_ft": ns,
            "east_west_ft": ew,
            "station_id": station_id,
            "survey_type": survey_type,
            "page": page if isinstance(page, int) and page > 0 else 1,
            "confidence": round(min(confidence, 0.95), 3),
            "conflict": False,
        }

    @staticmethod
    def _survey_rows_from_table(table: dict[str, object]) -> list[dict[str, object]]:
        table_rows = table.get("rows") if isinstance(table, dict) else None
        page = table.get("page") if isinstance(table, dict) else None
        if not isinstance(table_rows, list):
            return []
        rows: list[dict[str, object]] = []
        columns: dict[str, int] = {}
        units: dict[str, str] = {}
        for table_row in table_rows:
            if not isinstance(table_row, list):
                continue
            cells = [str(cell) for cell in table_row]
            if not columns:
                columns, units = LocalStateStore._map_survey_columns(cells)
                continue
            parsed = LocalStateStore._parse_survey_cells(
                cells,
                columns,
                units,
                page if isinstance(page, int) and page > 0 else 1,
                base_confidence=0.6,
            )
            if parsed:
                rows.append(parsed)
        return rows

    @staticmethod
    def _survey_rows_from_lines(page_lines: list[tuple[int, str]]) -> list[dict[str, object]]:
        """Parse survey rows from delimited text lines and labelled narrative.

        Text tables must start with a recognizable header line (MD plus
        inclination or azimuth); data lines reuse that header's column map
        until a line no longer parses. Narrative rows require explicit
        ``MD``/``Inc``/``Azi`` labels so arbitrary numbers are never lifted
        from general prose.
        """
        rows: list[dict[str, object]] = []
        columns: dict[str, int] = {}
        units: dict[str, str] = {}
        for page_number, line in page_lines:
            # Labelled narrative first: a header line never attaches numbers to
            # its labels, so this cannot swallow real header rows, while a
            # narrative row would otherwise be misread as a header.
            inline = LocalStateStore._parse_inline_survey_line(line, page_number)
            if inline:
                rows.append(inline)
                continue
            cells = LocalStateStore._split_survey_line(line)
            if len(cells) >= 2:
                header_columns, header_units = LocalStateStore._map_survey_columns(cells)
                if header_columns:
                    columns, units = header_columns, header_units
                    continue
            if columns:
                parsed = LocalStateStore._parse_survey_cells(
                    cells,
                    columns,
                    units,
                    page_number,
                    base_confidence=0.6,
                )
                if parsed:
                    rows.append(parsed)
                    continue
                md_index = columns.get("md")
                md_cell = cells[md_index] if md_index is not None and md_index < len(cells) else ""
                if LocalStateStore._survey_cell_float(md_cell) is not None:
                    # Data-shaped row that failed validation: drop the row but
                    # keep the table window open for the remaining rows.
                    continue
                columns, units = {}, {}
        return rows

    @staticmethod
    def _split_survey_line(line: str) -> list[str]:
        if "|" in line:
            return [cell.strip() for cell in line.split("|")]
        return [cell for cell in re.split(r"\s{1,}", line.strip()) if cell]

    @staticmethod
    def _parse_inline_survey_line(line: str, page_number: int) -> dict[str, object] | None:
        md_match = re.search(
            r"\bmd\s*[:=]?\s*([0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]+)?|[0-9]+(?:\.[0-9]+)?(?:\.[0-9]{3})*)\s*(m\b|ft\b|feet\b|')?",
            line,
            flags=re.IGNORECASE,
        )
        inc_match = re.search(
            r"\b(?:inc|inclination)\s*[:=]?\s*([0-9]+(?:\.[0-9]+)?)",
            line,
            flags=re.IGNORECASE,
        )
        azi_match = re.search(
            r"\b(?:azimuth|azm|azi|az)\s*[:=]?\s*([0-9]+(?:\.[0-9]+)?)",
            line,
            flags=re.IGNORECASE,
        )
        if not md_match or (not inc_match and not azi_match):
            return None
        raw_md = md_match.group(1)
        if raw_md.count(".") > 1:
            # Multi-group dot tokens (e.g. 9.524.100) are ambiguous between a
            # dot-thousands and a mixed-separator reading. They are never
            # guessed and never crash extraction: the inline row is skipped
            # rather than fabricated.
            return None
        md = float(raw_md.replace(",", ""))
        unit_token = md_match.group(2)
        unit = (unit_token or "ft").lower()
        if unit == "m":
            md = round(md * 3.28084, 1)
        tvd_match = re.search(
            r"\btvd\s*[:=]?\s*([0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]+)?|[0-9]+(?:\.[0-9]+)?)\s*(ft\b|feet\b|')?",
            line,
            flags=re.IGNORECASE,
        )
        tvd = float(tvd_match.group(1).replace(",", "")) if tvd_match else None
        # Dot-thousands disambiguation only with same-line corroboration:
        # explicit foot markers on both MD and TVD in one labelled record.
        if unit_token is not None and unit != "m" and tvd_match is not None and tvd_match.group(2) and tvd is not None:
            md = LocalStateStore._promote_dot_grouped_depth(raw_md, md, tvd)
        dls_match = re.search(r"\bdls\s*[:=]?\s*([0-9]+(?:\.[0-9]+)?)", line, flags=re.IGNORECASE)
        return LocalStateStore._validated_survey_row(
            md=md,
            inclination=float(inc_match.group(1)) if inc_match else None,
            azimuth=float(azi_match.group(1)) if azi_match else None,
            tvd=tvd,
            dls=float(dls_match.group(1)) if dls_match else None,
            ns=None,
            ew=None,
            station_id=None,
            survey_type=None,
            page=page_number,
            base_confidence=0.55,
        )

    @staticmethod
    def _finalize_survey_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
        """Deduplicate, order, and flag conflicts deterministically.

        Exact repeats (same MD/inc/azi/type) collapse to one row. Distinct
        rows sharing an MD are retained but flagged as conflicts with reduced
        confidence, and decreasing MD within one survey type in source order
        is flagged the same way. Conflicting evidence is surfaced, never
        silently merged or discarded.
        """
        deduped: list[dict[str, object]] = []
        seen: set[tuple[object, object, object, object]] = set()
        for row in rows:
            key = (
                row.get("measured_depth_ft"),
                row.get("inclination_deg"),
                row.get("azimuth_deg"),
                row.get("survey_type"),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(row)

        last_md_by_type: dict[object, float] = {}
        for row in deduped:
            md = float(row["measured_depth_ft"])
            survey_type = row.get("survey_type")
            previous = last_md_by_type.get(survey_type)
            if previous is not None and md < previous:
                row["conflict"] = True
            last_md_by_type[survey_type] = max(previous or 0.0, md)

        by_md: dict[tuple[object, object], list[dict[str, object]]] = {}
        for row in deduped:
            by_md.setdefault((row.get("measured_depth_ft"), row.get("survey_type")), []).append(row)
        for group in by_md.values():
            if len(group) > 1:
                for row in group:
                    row["conflict"] = True
        for row in deduped:
            if row.get("conflict"):
                confidence = row.get("confidence")
                row["confidence"] = round(min(float(confidence), 0.5), 3) if isinstance(confidence, (int, float)) else 0.5

        deduped.sort(
            key=lambda row: (
                float(row.get("measured_depth_ft", 0.0)),
                str(row.get("survey_type") or ""),
                int(row.get("page") or 0),
            )
        )
        return deduped

    # ------------------------------------------------------------------
    # Hydraulics observation extraction (deterministic_hydraulics v1).
    # Source extraction only with explicit recognized units; no hydraulic
    # calculation, no recommendation coupling, no Benchmarking writes.
    # ------------------------------------------------------------------

    HYDRAULICS_PARSER_METHOD = "deterministic_hydraulics"
    HYDRAULICS_PARSER_VERSION = "v1"

    # measurement -> (label regex, {unit regex -> (canonical unit, factor)})
    _HYDRAULIC_MEASUREMENTS: dict[str, tuple[str, dict[str, tuple[str, float]]]] = {
        "flow_rate": (
            r"(?:flow\s*rate|pump\s*output|flow)",
            {
                r"gpm|gal/min": ("gpm", 1.0),
                r"l/min|lpm|litres?/min|liters?/min": ("gpm", 1.0 / 3.785411784),
            },
        ),
        "standpipe_pressure": (
            r"(?:standpipe\s*pressure|spp)",
            {
                r"psi": ("psi", 1.0),
                r"kpa": ("psi", 0.1450377377),
            },
        ),
        "mud_weight": (
            r"(?:mud\s*(?:weight|wt|density)|mw)",
            {
                r"ppg|lb/gal": ("ppg", 1.0),
                r"sg|s\.g\.": ("ppg", 8.345404452),
            },
        ),
        "ecd": (
            r"(?:equivalent\s*circulating\s*density|ecd)",
            {
                r"ppg|lb/gal": ("ppg", 1.0),
                r"sg|s\.g\.": ("ppg", 8.345404452),
            },
        ),
        "plastic_viscosity": (
            r"(?:plastic\s*viscosity|pv)",
            {r"cp": ("cP", 1.0)},
        ),
        "yield_point": (
            r"(?:yield\s*point|yp)",
            {r"lbf?/100\s*ft2|lbf?/100\s*ft²|lb/100ft2": ("lbf/100ft2", 1.0)},
        ),
        "pump_rate": (
            r"(?:pump\s*rate|pump\s*speed|strokes)",
            {r"spm|strokes?/min": ("spm", 1.0)},
        ),
    }

    # Documented review triggers: generous order-of-magnitude bands used only
    # to set review_flag on structurally valid values. They are NOT engineering
    # acceptance thresholds; flagged rows are always retained.
    _HYDRAULIC_REVIEW_BANDS: dict[str, tuple[float, float]] = {
        "flow_rate": (0.0, 5000.0),
        "standpipe_pressure": (0.0, 10000.0),
        "mud_weight": (1.0, 30.0),
        "ecd": (1.0, 30.0),
        "plastic_viscosity": (0.0, 200.0),
        "yield_point": (0.0, 200.0),
        "pump_rate": (0.0, 400.0),
    }

    @staticmethod
    def _extract_hydraulics_observations(
        page_lines: list[tuple[int, str]],
        tables: list[dict[str, object]],
    ) -> tuple[list[dict[str, object]], bool]:
        """Deterministically parse labelled hydraulics observations.

        Emits an observation only for an explicitly labelled measurement with
        an explicit recognized unit (nozzle configuration is text-only).
        Multiple labelled measurements on one line are all captured. Unitless
        or ambiguous values (e.g. bare ``MW 1.15``) are never converted or
        emitted. Returns (rows, truncated).
        """
        row_cap = 100
        collected: list[dict[str, object]] = []
        for page_number, line in page_lines:
            collected.extend(LocalStateStore._hydraulics_from_line(line, page_number, base_confidence=0.55))
        for table in tables:
            collected.extend(LocalStateStore._hydraulics_from_table(table))
        rows = LocalStateStore._finalize_hydraulics_rows(collected)
        truncated = len(rows) > row_cap
        if truncated:
            rows = rows[:row_cap]
        return rows, truncated

    @staticmethod
    def _hydraulics_line_context(line: str) -> dict[str, object]:
        lower = line.lower()
        time_match = re.search(r"\b([01]?\d|2[0-3]):[0-5]\d(?:\s*-\s*(?:[01]?\d|2[0-3]):[0-5]\d)?\b", line)
        equipment_match = re.search(r"\bpump\s*(?:no\.?\s*)?([0-9]+|[a-z])\b", lower)
        fluid_match = re.search(r"\b(active|kill|reserve|pill)\s*(?:mud|fluid|system|pit)\b", lower)
        if re.search(r"\b(planned|programme?d?|proposed|plan)\b", lower):
            status = "planned"
        elif re.search(r"\b(observed|measured|actual|recorded)\b", lower):
            status = "observed"
        else:
            status = "unknown"
        return {
            "activity_time": LocalStateStore._normalize_clock(time_match.group(0).split("-")[0]) if time_match else None,
            "activity_time_source_text": time_match.group(0) if time_match else None,
            "equipment_label": f"Pump {equipment_match.group(1).upper()}" if equipment_match else None,
            "fluid_system_label": f"{fluid_match.group(1)} mud" if fluid_match else None,
            "observation_status": status,
        }

    @staticmethod
    def _hydraulics_from_line(line: str, page_number: int, base_confidence: float) -> list[dict[str, object]]:
        context = LocalStateStore._hydraulics_line_context(line)
        rows: list[dict[str, object]] = []
        # Nozzle configuration is captured verbatim: no numeric value, no TFA,
        # no inferred count or sizes.
        nozzle_match = re.search(r"\bnozzles?(?:\s*configuration)?\s*[:=]\s*([0-9][^.;|]{0,60})", line, flags=re.IGNORECASE)
        if nozzle_match:
            rows.append(
                LocalStateStore._hydraulic_row(
                    measurement="nozzle_configuration",
                    value=None,
                    unit=None,
                    source_value_text=nozzle_match.group(1).strip(),
                    source_unit=None,
                    context=context,
                    page=page_number,
                    confidence=base_confidence + 0.05,
                )
            )
        for measurement, (label_pattern, units) in LocalStateStore._HYDRAULIC_MEASUREMENTS.items():
            for match in re.finditer(
                rf"\b{label_pattern}\b\s*[:=]?\s*(-?[0-9][0-9,]*(?:\.[0-9]+)?)\s*([a-z/\.²%0-9 ]{{0,14}})",
                line,
                flags=re.IGNORECASE,
            ):
                row = LocalStateStore._hydraulic_value_row(
                    measurement, match.group(1), match.group(2), units, context, page_number, base_confidence
                )
                if row:
                    rows.append(row)
        return rows

    @staticmethod
    def _hydraulic_value_row(
        measurement: str,
        value_text: str,
        unit_text: str,
        units: dict[str, tuple[str, float]],
        context: dict[str, object],
        page_number: int,
        base_confidence: float,
    ) -> dict[str, object] | None:
        matched_unit: str | None = None
        canonical: tuple[str, float] | None = None
        trimmed_unit = unit_text.strip().lower()
        for unit_pattern, target in units.items():
            unit_match = re.match(rf"^(?:{unit_pattern})\b", trimmed_unit)
            if unit_match:
                matched_unit = unit_match.group(0)
                canonical = target
                break
        if canonical is None or matched_unit is None:
            # Explicit units only: unitless or unrecognized-unit values are
            # never converted, emitted, or guessed.
            return None
        try:
            raw_value = float(value_text.replace(",", ""))
        except ValueError:
            return None
        if not math.isfinite(raw_value):
            return None
        if raw_value < 0:
            # Structurally impossible for every supported measurement.
            return None
        normalized = raw_value * canonical[1]
        return LocalStateStore._hydraulic_row(
            measurement=measurement,
            value=round(normalized, 2),
            unit=canonical[0],
            source_value_text=f"{value_text} {matched_unit}".strip(),
            source_unit=matched_unit,
            context=context,
            page=page_number,
            confidence=base_confidence,
        )

    @staticmethod
    def _hydraulic_row(
        *,
        measurement: str,
        value: float | None,
        unit: str | None,
        source_value_text: str,
        source_unit: str | None,
        context: dict[str, object],
        page: int,
        confidence: float,
    ) -> dict[str, object]:
        review_flag = False
        review_reason = None
        band = LocalStateStore._HYDRAULIC_REVIEW_BANDS.get(measurement)
        if band and isinstance(value, (int, float)) and not (band[0] <= value <= band[1]):
            review_flag = True
            review_reason = "source value requires review"
        adjusted = confidence
        if context.get("observation_status") != "unknown":
            adjusted += 0.05
        if context.get("activity_time"):
            adjusted += 0.05
        return {
            "measurement": measurement,
            "value": value,
            "unit": unit,
            "source_value_text": source_value_text,
            "source_unit": source_unit,
            "observation_status": context.get("observation_status", "unknown"),
            "equipment_label": context.get("equipment_label"),
            "fluid_system_label": context.get("fluid_system_label"),
            "context_note": None,
            "activity_time": context.get("activity_time"),
            "activity_time_source_text": context.get("activity_time_source_text"),
            "parser_method": LocalStateStore.HYDRAULICS_PARSER_METHOD,
            "parser_version": LocalStateStore.HYDRAULICS_PARSER_VERSION,
            "page": page if isinstance(page, int) and page > 0 else 1,
            "confidence": round(min(adjusted, 0.95), 3),
            "conflict": False,
            "review_flag": review_flag,
            "review_reason": review_reason,
        }

    @staticmethod
    def _hydraulics_from_table(table: dict[str, object]) -> list[dict[str, object]]:
        table_rows = table.get("rows") if isinstance(table, dict) else None
        page = table.get("page") if isinstance(table, dict) else None
        if not isinstance(table_rows, list) or not table_rows:
            return []
        header = table_rows[0]
        if not isinstance(header, list):
            return []
        columns: dict[int, tuple[str, dict[str, tuple[str, float]], str | None]] = {}
        time_column: int | None = None
        for index, raw_cell in enumerate(header):
            cell = str(raw_cell).strip().lower()
            if re.match(r"^time\b", cell):
                time_column = index
                continue
            for measurement, (label_pattern, units) in LocalStateStore._HYDRAULIC_MEASUREMENTS.items():
                if re.match(rf"^{label_pattern}\b", cell):
                    header_unit = None
                    unit_match = re.search(r"\(([^)]+)\)", cell)
                    if unit_match:
                        header_unit = unit_match.group(1).strip()
                    columns[index] = (measurement, units, header_unit)
                    break
        if not columns:
            return []
        rows: list[dict[str, object]] = []
        for table_row in table_rows[1:]:
            if not isinstance(table_row, list):
                continue
            context = {
                "activity_time": None,
                "activity_time_source_text": None,
                "equipment_label": None,
                "fluid_system_label": None,
                "observation_status": "unknown",
            }
            if time_column is not None and time_column < len(table_row):
                time_text = str(table_row[time_column]).strip()
                time_match = re.match(r"^([01]?\d|2[0-3]):[0-5]\d$", time_text)
                if time_match:
                    context["activity_time"] = LocalStateStore._normalize_clock(time_text)
                    context["activity_time_source_text"] = time_text
                elif time_text:
                    context["activity_time_source_text"] = time_text
            for index, (measurement, units, header_unit) in columns.items():
                if index >= len(table_row):
                    continue
                cell_text = str(table_row[index]).strip()
                if not cell_text:
                    continue
                row = LocalStateStore._hydraulic_value_row(
                    measurement, cell_text, header_unit or "", units, context, page if isinstance(page, int) else 1, 0.6
                )
                if row:
                    rows.append(row)
        return rows

    @staticmethod
    def _finalize_hydraulics_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
        """Deduplicate exact repeats and flag same-context conflicts.

        The conflict key includes measurement, time, status, equipment, and
        fluid system — Pump 1 vs Pump 2, active vs kill mud, and planned vs
        observed values are legitimately different contexts and never conflict
        merely because their values differ.
        """
        deduped: list[dict[str, object]] = []
        seen: set[tuple] = set()
        for row in rows:
            identity = (
                row.get("measurement"),
                row.get("value"),
                row.get("source_value_text"),
                row.get("observation_status"),
                row.get("equipment_label"),
                row.get("fluid_system_label"),
                row.get("activity_time"),
            )
            if identity in seen:
                continue
            seen.add(identity)
            deduped.append(row)
        by_context: dict[tuple, list[dict[str, object]]] = {}
        for row in deduped:
            key = (
                row.get("measurement"),
                row.get("activity_time"),
                row.get("observation_status"),
                row.get("equipment_label"),
                row.get("fluid_system_label"),
            )
            by_context.setdefault(key, []).append(row)
        for group in by_context.values():
            values = {row.get("value") for row in group if row.get("value") is not None}
            if len(values) > 1:
                for row in group:
                    row["conflict"] = True
                    confidence = row.get("confidence")
                    row["confidence"] = (
                        round(min(float(confidence), 0.5), 3) if isinstance(confidence, (int, float)) else 0.5
                    )
        deduped.sort(
            key=lambda row: (
                str(row.get("measurement")),
                str(row.get("activity_time") or ""),
                int(row.get("page") or 0),
            )
        )
        return deduped

    @staticmethod
    def _pdf_page_lines(pages: list[dict[str, object]]) -> list[tuple[int, str]]:
        lines: list[tuple[int, str]] = []
        for page in pages:
            page_number = page.get("page")
            text = page.get("text")
            if not isinstance(page_number, int) or not isinstance(text, str):
                continue
            for line in text.splitlines():
                clean_line = LocalStateStore._clean_extracted_text(line)
                if clean_line:
                    lines.append((page_number, clean_line))
        return lines

    @staticmethod
    def _match_pdf_profile_line(
        page_lines: list[tuple[int, str]],
        patterns: list[tuple[str, str]],
        max_length: int = 120,
        trim_delimiters: bool = True,
    ) -> dict[str, object] | None:
        for page_number, line in page_lines:
            for label, pattern in patterns:
                match = re.search(pattern, line, flags=re.IGNORECASE)
                if not match:
                    continue
                value = LocalStateStore._clean_report_profile_value(
                    match.group(1), max_length=max_length, trim_delimiters=trim_delimiters
                )
                if value:
                    return {"page": page_number, "label": label, "value": value}
        return None

    @staticmethod
    def _clean_report_profile_value(value: str, max_length: int = 120, trim_delimiters: bool = True) -> str:
        cleaned = LocalStateStore._clean_extracted_text(value)
        cleaned = re.split(
            r"\b(?:report no|well|rig|operator|hole size|md|tvd|mud weight|present operations|next operations|safety|casing|bha|survey|time breakdown)\b\s*[:#-]",
            cleaned,
            maxsplit=1,
            flags=re.IGNORECASE,
        )[0].strip(" .;|")
        cleaned = cleaned[:max_length].strip(" .;|")
        if trim_delimiters:
            cleaned = LocalStateStore._trim_unbalanced_delimiters(cleaned)
        return cleaned

    @staticmethod
    def _trim_unbalanced_delimiters(value: str) -> str:
        """Remove demonstrably unmatched trailing bracket artifacts only.

        Balanced bracketed suffixes are legitimate field content and are kept
        byte-identical; an unmatched trailing opener (with everything after
        it) or a lone unmatched trailing closer is a truncation artifact and
        is dropped. Never a blanket bracket trim.
        """
        for opener, closer in (("[", "]"), ("(", ")")):
            while value.count(opener) > value.count(closer):
                cut = value.rfind(opener)
                if cut < 0:
                    break
                value = value[:cut].rstrip(" .;|-")
            while value.endswith(closer) and value.count(closer) > value.count(opener):
                value = value[:-1].rstrip(" .;|-")
        return value

    @staticmethod
    def _pdf_table_mentions(table: dict[str, object], markers: list[str]) -> bool:
        rows = table.get("rows")
        if not isinstance(rows, list):
            return False
        text = " ".join(
            " ".join(str(cell) for cell in row)
            for row in rows
            if isinstance(row, list)
        ).lower()
        return any(marker in text for marker in markers)

    @staticmethod
    def _pdf_report_profile_chunk_records(profile: dict[str, object]) -> list[dict[str, object]]:
        field_sources = profile.get("field_sources")
        section_sources = profile.get("section_sources")
        fields = profile.get("fields")
        sections = profile.get("sections")
        records: list[dict[str, object]] = []
        if isinstance(fields, dict):
            for field, value in fields.items():
                if not isinstance(field, str) or not isinstance(value, str) or not value.strip():
                    continue
                source = field_sources.get(field, {}) if isinstance(field_sources, dict) else {}
                page = source.get("page") if isinstance(source, dict) else None
                label = source.get("label") if isinstance(source, dict) else None
                records.append(
                    {
                        "text": f"PDF report field {LocalStateStore._humanize_report_key(field)}: {value}",
                        "page": page if isinstance(page, int) and page > 0 else 1,
                        "field": field,
                        "label": str(label or field),
                        "section": "well_job_information",
                    }
                )
        if isinstance(sections, dict):
            for section, value in sections.items():
                if not isinstance(section, str) or not isinstance(value, str) or not value.strip():
                    continue
                source = section_sources.get(section, {}) if isinstance(section_sources, dict) else {}
                page = source.get("page") if isinstance(source, dict) else None
                label = source.get("label") if isinstance(source, dict) else None
                records.append(
                    {
                        "text": f"PDF report section {LocalStateStore._humanize_report_key(section)}: {value}",
                        "page": page if isinstance(page, int) and page > 0 else 1,
                        "field": section,
                        "label": str(label or section),
                        "section": section,
                    }
                )
        casing_strings = profile.get("casing_strings")
        if isinstance(casing_strings, list):
            for row in casing_strings:
                if not isinstance(row, dict):
                    continue
                name = str(row.get("name") or "").strip()
                if not name:
                    continue
                shoe = row.get("shoe_ft")
                detail = [
                    part
                    for part in [
                        str(row.get("od") or "").strip(),
                        f"shoe {shoe:g} ft" if isinstance(shoe, (int, float)) else "",
                        str(row.get("status") or "").strip(),
                    ]
                    if part
                ]
                page = row.get("page")
                records.append(
                    {
                        "text": f"PDF casing string {name}: {', '.join(detail)}" if detail else f"PDF casing string {name}",
                        "page": page if isinstance(page, int) and page > 0 else 1,
                        "field": "casing_string",
                        "label": name,
                        "section": "casing_schematic",
                    }
                )
        activity_timeline = profile.get("activity_timeline")
        if isinstance(activity_timeline, list):
            for row in activity_timeline:
                if not isinstance(row, dict):
                    continue
                time_label = str(row.get("time") or "").strip()
                activity = str(row.get("activity") or "").strip()
                if not time_label or not activity:
                    continue
                page = row.get("page")
                records.append(
                    {
                        "text": f"PDF activity {time_label}: {activity}",
                        "page": page if isinstance(page, int) and page > 0 else 1,
                        "field": "activity_timeline",
                        "label": time_label,
                        "section": "activity_timeline",
                    }
                )
        survey_stations = profile.get("survey_stations")
        if isinstance(survey_stations, list):
            for row in survey_stations:
                if not isinstance(row, dict):
                    continue
                md = row.get("measured_depth_ft")
                if not isinstance(md, (int, float)):
                    continue
                detail = [
                    part
                    for part in [
                        f"inc {row['inclination_deg']:g} deg" if isinstance(row.get("inclination_deg"), (int, float)) else "",
                        f"azi {row['azimuth_deg']:g} deg" if isinstance(row.get("azimuth_deg"), (int, float)) else "",
                        f"tvd {row['true_vertical_depth_ft']:g} ft"
                        if isinstance(row.get("true_vertical_depth_ft"), (int, float))
                        else "",
                        f"dls {row['dogleg_severity_dp100ft']:g} deg/100ft"
                        if isinstance(row.get("dogleg_severity_dp100ft"), (int, float))
                        else "",
                        "conflict" if row.get("conflict") else "",
                    ]
                    if part
                ]
                page = row.get("page")
                label = f"MD {md:g} ft"
                records.append(
                    {
                        "text": f"PDF survey station {label}: {', '.join(detail)}" if detail else f"PDF survey station {label}",
                        "page": page if isinstance(page, int) and page > 0 else 1,
                        "field": "survey_station",
                        "label": label,
                        "section": "survey_stations",
                    }
                )
        hydraulics_observations = profile.get("hydraulics_observations")
        if isinstance(hydraulics_observations, list):
            for row in hydraulics_observations:
                if not isinstance(row, dict):
                    continue
                measurement = str(row.get("measurement") or "").strip()
                source_text = str(row.get("source_value_text") or "").strip()
                if not measurement or not source_text:
                    continue
                context_bits = [
                    part
                    for part in [
                        str(row.get("equipment_label") or ""),
                        str(row.get("fluid_system_label") or ""),
                        str(row.get("observation_status") or "") if row.get("observation_status") != "unknown" else "",
                        str(row.get("activity_time") or ""),
                    ]
                    if part
                ]
                page = row.get("page")
                label = LocalStateStore._humanize_report_key(measurement)
                suffix = f" ({', '.join(context_bits)})" if context_bits else ""
                records.append(
                    {
                        "text": f"PDF hydraulics {label}: {source_text}{suffix}",
                        "page": page if isinstance(page, int) and page > 0 else 1,
                        "field": "hydraulic_observation",
                        "label": label,
                        "section": "hydraulics_observations",
                    }
                )
        return records

    @staticmethod
    def _humanize_report_key(value: str) -> str:
        return value.replace("_", " ").strip().title()

    @staticmethod
    def _as_float(value: object) -> float | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return float(value)
        return None

    @staticmethod
    def collect_report_profiles_from_documents(documents: list) -> list[dict[str, object]]:
        """Select and rank the PDF report profiles for a set of parsed documents.

        Single source of profile-selection logic shared by the report-draft
        endpoint and Monday Report assembly so they can never disagree.
        """
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
                float(item.get("confidence", 0)) if isinstance(item.get("confidence"), (int, float)) else 0.0,
                int(item.get("field_count", 0)) if isinstance(item.get("field_count"), int) else 0,
                int(item.get("section_count", 0)) if isinstance(item.get("section_count"), int) else 0,
            ),
            reverse=True,
        )

    @staticmethod
    def _casing_rows_from_profile(profile: dict[str, object]) -> list[dict[str, object]]:
        rows = profile.get("casing_strings") if isinstance(profile, dict) else None
        result: list[dict[str, object]] = []
        if not isinstance(rows, list):
            return result
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name") or "").strip()
            if not name:
                continue
            result.append(
                {
                    "name": name,
                    "od": str(row["od"]).strip() if row.get("od") else None,
                    "top_ft": LocalStateStore._as_float(row.get("top_ft")),
                    "shoe_ft": LocalStateStore._as_float(row.get("shoe_ft")),
                    "status": str(row["status"]).strip() if row.get("status") else "reported",
                    "source": "source",
                    "page": row.get("page") if isinstance(row.get("page"), int) else None,
                    "confidence": LocalStateStore._as_float(row.get("confidence")),
                }
            )
        return result

    @staticmethod
    def casing_rows_from_profiles(profiles: list[dict[str, object]]) -> list[dict[str, object]]:
        for profile in profiles:
            rows = LocalStateStore._casing_rows_from_profile(profile)
            if rows:
                return rows
        return []

    @staticmethod
    def _activity_rows_from_profile(profile: dict[str, object]) -> list[dict[str, object]]:
        rows = profile.get("activity_timeline") if isinstance(profile, dict) else None
        result: list[dict[str, object]] = []
        if not isinstance(rows, list):
            return result
        for row in rows:
            if not isinstance(row, dict):
                continue
            time_label = str(row.get("time") or "").strip()
            activity = str(row.get("activity") or "").strip()
            if not time_label or not activity:
                continue
            result.append(
                {
                    "time": time_label,
                    "activity": activity,
                    "source": "source",
                    "page": row.get("page") if isinstance(row.get("page"), int) else None,
                    "confidence": LocalStateStore._as_float(row.get("confidence")),
                }
            )
        return result

    @staticmethod
    def activity_rows_from_profiles(profiles: list[dict[str, object]]) -> list[dict[str, object]]:
        for profile in profiles:
            rows = LocalStateStore._activity_rows_from_profile(profile)
            if rows:
                return rows
        return []

    @staticmethod
    def _survey_rows_from_profile(profile: dict[str, object]) -> list[dict[str, object]]:
        rows = profile.get("survey_stations") if isinstance(profile, dict) else None
        result: list[dict[str, object]] = []
        if not isinstance(rows, list):
            return result
        for row in rows:
            if not isinstance(row, dict):
                continue
            md = LocalStateStore._as_float(row.get("measured_depth_ft"))
            if md is None or md < 0:
                continue
            result.append(
                {
                    "measured_depth_ft": md,
                    "inclination_deg": LocalStateStore._as_float(row.get("inclination_deg")),
                    "azimuth_deg": LocalStateStore._as_float(row.get("azimuth_deg")),
                    "true_vertical_depth_ft": LocalStateStore._as_float(row.get("true_vertical_depth_ft")),
                    "dogleg_severity_dp100ft": LocalStateStore._as_float(row.get("dogleg_severity_dp100ft")),
                    "north_south_ft": LocalStateStore._as_float(row.get("north_south_ft")),
                    "east_west_ft": LocalStateStore._as_float(row.get("east_west_ft")),
                    "station_id": str(row["station_id"]).strip() if row.get("station_id") else None,
                    "survey_type": str(row["survey_type"]).strip() if row.get("survey_type") else None,
                    "source": "source",
                    "page": row.get("page") if isinstance(row.get("page"), int) else None,
                    "confidence": LocalStateStore._as_float(row.get("confidence")),
                    "conflict": bool(row.get("conflict")),
                }
            )
        return result

    @staticmethod
    def survey_rows_from_profiles(profiles: list[dict[str, object]]) -> list[dict[str, object]]:
        """Shared survey-row selection for report draft and Monday Report JSON.

        Uses the same deterministically ranked profiles as the casing/timeline
        builders (already workspace-scoped by the caller) and takes the first
        profile that yields valid stations. Survey stations have **no**
        reference fallback — no evidence means an empty list.
        """
        for profile in profiles:
            rows = LocalStateStore._survey_rows_from_profile(profile)
            if rows:
                return rows
        return []

    @staticmethod
    def survey_truncation_from_profiles(profiles: list[dict[str, object]]) -> bool:
        for profile in profiles:
            if LocalStateStore._survey_rows_from_profile(profile):
                return bool(profile.get("survey_truncated"))
        return False

    @staticmethod
    def _hydraulics_rows_from_profile(profile: dict[str, object]) -> list[dict[str, object]]:
        rows = profile.get("hydraulics_observations") if isinstance(profile, dict) else None
        result: list[dict[str, object]] = []
        if not isinstance(rows, list):
            return result
        for row in rows:
            if not isinstance(row, dict):
                continue
            measurement = str(row.get("measurement") or "").strip()
            source_text = str(row.get("source_value_text") or "").strip()
            if not measurement or not source_text:
                continue
            result.append(
                {
                    "measurement": measurement,
                    "value": LocalStateStore._as_float(row.get("value")),
                    "unit": str(row["unit"]).strip() if row.get("unit") else None,
                    "source_value_text": source_text,
                    "source_unit": str(row["source_unit"]).strip() if row.get("source_unit") else None,
                    "observation_status": str(row.get("observation_status") or "unknown"),
                    "equipment_label": str(row["equipment_label"]).strip() if row.get("equipment_label") else None,
                    "fluid_system_label": str(row["fluid_system_label"]).strip() if row.get("fluid_system_label") else None,
                    "context_note": str(row["context_note"]).strip() if row.get("context_note") else None,
                    "activity_time": str(row["activity_time"]).strip() if row.get("activity_time") else None,
                    "activity_time_source_text": str(row["activity_time_source_text"]).strip()
                    if row.get("activity_time_source_text")
                    else None,
                    "parser_method": LocalStateStore.HYDRAULICS_PARSER_METHOD,
                    "parser_version": LocalStateStore.HYDRAULICS_PARSER_VERSION,
                    "source": "source",
                    "page": row.get("page") if isinstance(row.get("page"), int) else None,
                    "confidence": LocalStateStore._as_float(row.get("confidence")),
                    "conflict": bool(row.get("conflict")),
                    "review_flag": bool(row.get("review_flag")),
                    "review_reason": str(row["review_reason"]).strip() if row.get("review_reason") else None,
                }
            )
        return result

    @staticmethod
    def hydraulics_rows_from_profiles(profiles: list[dict[str, object]]) -> list[dict[str, object]]:
        """Shared hydraulics-row selection for report draft and Monday Report JSON.

        Same workspace-scoped, deterministically ranked profiles as the other
        builders; first profile with observations wins. No fallback exists —
        no evidence means an empty list (``hydraulics_source="none"``).
        """
        for profile in profiles:
            rows = LocalStateStore._hydraulics_rows_from_profile(profile)
            if rows:
                return rows
        return []

    @staticmethod
    def hydraulics_truncation_from_profiles(profiles: list[dict[str, object]]) -> bool:
        for profile in profiles:
            if LocalStateStore._hydraulics_rows_from_profile(profile):
                return bool(profile.get("hydraulics_truncated"))
        return False

    @staticmethod
    def trajectory_from_survey_rows(survey_rows: list[dict[str, object]]) -> TrajectoryCalculation | None:
        """Shared minimum-curvature calculation for draft and Monday Report JSON.

        Feeds the already workspace-scoped source survey rows into the pure
        trajectory module (backend/app/trajectory.py) and maps the result into
        the calculation schema. Source rows are never modified; when no interval
        is calculable the caller receives ``None`` and reports
        ``trajectory_source="none"``. Calculated DLS is never written into
        Benchmarking measurements.
        """
        if not survey_rows:
            return None
        result = calculate_trajectory(survey_rows)
        if not result.get("interval_count"):
            return None
        return TrajectoryCalculation(**result)

    @staticmethod
    def reference_casing_rows() -> list[dict[str, object]]:
        return [
            {
                "name": row["name"],
                "od": row["od"],
                "top_ft": float(row["top_ft"]),
                "shoe_ft": float(row["shoe_ft"]),
                "status": "reference",
                "source": "reference",
                "page": None,
                "confidence": None,
            }
            for row in REFERENCE_CASING_STRINGS
        ]

    @staticmethod
    def reference_activity_rows() -> list[dict[str, object]]:
        return [
            {
                "time": row["time"],
                "activity": row["activity"],
                "source": "reference",
                "page": None,
                "confidence": None,
            }
            for row in REFERENCE_ACTIVITY_TIMELINE
        ]

    @staticmethod
    def casing_program_from_rows(rows: list[dict[str, object]]) -> str:
        lines: list[str] = []
        for row in rows:
            top = row.get("top_ft")
            shoe = row.get("shoe_ft")
            top_str = f"{top:g}" if isinstance(top, (int, float)) else "0"
            shoe_str = f"{shoe:g}" if isinstance(shoe, (int, float)) else "0"
            lines.append(
                f"{row.get('name', 'Casing')} | {row.get('od') or 'OD not set'} | {top_str} | {shoe_str} | {row.get('status') or 'reported'}"
            )
        return "\n".join(lines)

    @staticmethod
    def operations_log_from_rows(rows: list[dict[str, object]]) -> str:
        return "\n".join(f"{row.get('time', '24 hr')} | {row.get('activity', '')}" for row in rows)

    @staticmethod
    def hole_sections_from_casing_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
        """Direct, deterministic projection of reviewed casing rows into hole sections.

        Uses only the casing name and its top/shoe depths (already reviewed by this
        increment) so the well schematic cannot contradict the casing schematic. No
        bit size or new engineering value is inferred.
        """
        sections: list[dict[str, object]] = []
        previous_shoe = 0.0
        for row in rows:
            shoe = row.get("shoe_ft")
            if not isinstance(shoe, (int, float)):
                continue
            top = row.get("top_ft")
            interval_top = top if isinstance(top, (int, float)) else previous_shoe
            sections.append(
                {
                    "hole_size": f"{row.get('name', 'Casing')} casing section",
                    "interval_ft": f"{interval_top:,.0f}-{shoe:,.0f}",
                    "status": f"derived from {row.get('name', 'casing')} casing evidence",
                }
            )
            previous_shoe = shoe
        return sections

    @staticmethod
    def _clean_extracted_text(text: str) -> str:
        without_controls = UNSAFE_TEXT_CONTROL_CHARS.sub(" ", text)
        return re.sub(r"\s+", " ", without_controls).strip()

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
                report_profile = LocalStateStore._extract_pdf_report_profile(pages, tables)
                metadata: dict[str, object] = {
                    "page_count": document.page_count,
                    "pages_with_text": len(pages),
                    "pages": pages,
                    "tables": tables,
                    "table_count": len(tables),
                }
                if report_profile is not None:
                    metadata["report_profile"] = report_profile
                return (
                    "\n".join(part for part in text_parts if part.strip()),
                    metadata,
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
        identity = self.current_identity()
        previous_hash = self._audit_chain_hash(self.audit_logs[-1]) if self.audit_logs else None
        audit_log = AuditLog(
            tenant_id=self.tenant.id,
            actor_user_id=identity.user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            metadata=sanitize_audit_metadata(metadata),
            previous_hash=previous_hash,
            actor_source=identity.actor_source,
            actor_roles=list(identity.roles),
            actor_credential_fingerprint=identity.credential_fingerprint,
        )
        # entry_hash payload is intentionally unchanged (actor_user_id is already
        # sealed) so existing sealed chains still verify; keyed integrity remains
        # a separate declared blocker.
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

        payload = self._postgres_safe_json(self._state_payload())
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

    @classmethod
    def _postgres_safe_json(cls, value):
        if isinstance(value, str):
            return UNSAFE_TEXT_CONTROL_CHARS.sub(" ", value)
        if isinstance(value, list):
            return [cls._postgres_safe_json(item) for item in value]
        if isinstance(value, dict):
            return {key: cls._postgres_safe_json(item) for key, item in value.items()}
        return value

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
