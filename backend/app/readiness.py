from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .archive_limits import archive_limits_configured, max_zip_entries, max_zip_uncompressed_bytes
from .audit_safety import sanitize_audit_metadata
from .auth import api_key_configured
from .fixture_evals import evaluate_parser_fixture_eval_readiness
from .fixtures import evaluate_golden_fixture_readiness
from .limits import max_upload_bytes, upload_limit_configured
from .local_ai import evaluate_local_ai_status
from .malware import evaluate_malware_scanner_status
from .retention import retention_configured, retention_days
from .runtime_backends import INLINE_QUEUE_BACKEND, LOCAL_REPOSITORY_BACKEND, POSTGRES_REPOSITORY_BACKEND, REDIS_QUEUE_BACKEND
from .schemas import ClientDataReadiness, ClientDataReadinessCheck
from .signed_urls import signing_secret_configured


CLIENT_DATA_MODE_ENV = "MONDAY_REPORT_CLIENT_DATA_MODE"
CLIENT_READY_VALUES = {"1", "true", "yes", "client", "production", "prod", "real"}


def client_data_mode() -> str:
    raw_value = os.getenv(CLIENT_DATA_MODE_ENV, "demo").strip().lower()
    return "client" if raw_value in CLIENT_READY_VALUES else "demo"


def evaluate_client_data_readiness(store: Any) -> ClientDataReadiness:
    store.refresh()
    mode = client_data_mode()
    strict = mode == "client"
    repo_root = Path.cwd().resolve()
    active_repository_backend = getattr(store, "repository_backend", LOCAL_REPOSITORY_BACKEND)
    active_queue_backend = getattr(store, "queue_backend", INLINE_QUEUE_BACKEND)
    checks: list[ClientDataReadinessCheck] = []

    def add(
        check_id: str,
        label: str,
        passed: bool,
        detail: str,
        remediation: str,
        *,
        strict_failure: bool = True,
    ) -> None:
        if passed:
            status = "pass"
        elif strict and strict_failure:
            status = "fail"
        else:
            status = "warn"
        checks.append(
            ClientDataReadinessCheck(
                id=check_id,
                label=label,
                status=status,
                detail=detail,
                remediation=remediation,
            )
        )

    add(
        "client_mode",
        "Client data mode",
        mode == "client",
        f"{CLIENT_DATA_MODE_ENV} is {mode!r}.",
        f"Set {CLIENT_DATA_MODE_ENV}=client only after all readiness checks pass.",
        strict_failure=False,
    )

    demo_seed_present = any(log.action == "state.seed" for log in store.audit_logs)
    demo_identity_present = (
        store.tenant.slug == "northstar"
        or store.user.email.endswith("@monday-report.local")
        or store.user.full_name.lower().startswith("demo ")
    )
    add(
        "demo_seed_removed",
        "Demo tenant and seed data",
        not demo_seed_present and not demo_identity_present,
        "Demo seed state or demo user identity is present."
        if demo_seed_present or demo_identity_present
        else "No demo seed marker or demo user identity detected.",
        "Start client environments from a clean state path and provision the real tenant/user identity.",
    )

    state_path = store.state_path.resolve()
    state_configured = bool(os.getenv("MONDAY_REPORT_STATE_PATH"))
    state_outside_repo = not is_relative_to(state_path, repo_root)
    state_uses_postgres = active_repository_backend == POSTGRES_REPOSITORY_BACKEND
    add(
        "state_path_configured",
        "State path",
        state_uses_postgres or (state_configured and state_outside_repo),
        (
            "State is stored in the active PostgreSQL repository."
            if state_uses_postgres
            else f"State path is {state_path}."
        ),
        "Set MONDAY_REPORT_STATE_PATH to a protected path outside the repository, or replace local JSON with PostgreSQL.",
    )

    storage_root = store.storage_root.resolve()
    storage_configured = bool(os.getenv("MONDAY_REPORT_STORAGE_ROOT"))
    storage_outside_repo = not is_relative_to(storage_root, repo_root)
    add(
        "storage_root_configured",
        "Upload storage root",
        storage_configured and storage_outside_repo,
        f"Upload storage root is {storage_root}.",
        "Set MONDAY_REPORT_STORAGE_ROOT to encrypted tenant-scoped storage outside the repository.",
    )

    export_root = store.export_root.resolve()
    export_configured = bool(os.getenv("MONDAY_REPORT_EXPORT_ROOT"))
    export_outside_repo = not is_relative_to(export_root, repo_root)
    add(
        "export_root_configured",
        "Export storage root",
        export_configured and export_outside_repo,
        f"Export storage root is {export_root}.",
        "Set MONDAY_REPORT_EXPORT_ROOT to encrypted tenant-scoped export storage outside the repository.",
    )

    add(
        "hosted_fallback_disabled",
        "Hosted LLM fallback",
        store.tenant.local_llm_policy.get("hosted_fallback_enabled") is False,
        f"Hosted fallback enabled: {store.tenant.local_llm_policy.get('hosted_fallback_enabled')}.",
        "Keep hosted fallback disabled unless the tenant explicitly approves hosted model use.",
    )

    add(
        "api_key_configured",
        "Client API key",
        api_key_configured(),
        "Client API key is configured." if api_key_configured() else "Client API key is not configured.",
        "Set MONDAY_REPORT_API_KEY to at least 24 random characters and send it in the X-Monday-Report-Key header.",
    )

    add(
        "signed_url_secret",
        "Signed URL secret",
        signing_secret_configured(),
        "Signing secret is configured." if signing_secret_configured() else "Signing secret is not configured.",
        "Set MONDAY_REPORT_SIGNING_SECRET to at least 32 random characters before exposing uploads or exports.",
    )

    add(
        "upload_size_limit",
        "Upload size limit",
        upload_limit_configured(),
        f"Maximum upload size is {max_upload_bytes()} bytes.",
        "Set MONDAY_REPORT_MAX_UPLOAD_BYTES to the approved per-package intake limit for the client environment.",
    )

    add(
        "archive_limits",
        "Archive package limits",
        archive_limits_configured(),
        f"ZIP entry limit is {max_zip_entries()}; uncompressed byte limit is {max_zip_uncompressed_bytes()}.",
        "Set MONDAY_REPORT_MAX_ZIP_ENTRIES and MONDAY_REPORT_MAX_ZIP_UNCOMPRESSED_BYTES to approved tenant intake limits.",
    )

    add(
        "retention_policy",
        "Retention policy",
        retention_configured(),
        f"Retention is {retention_days()} day(s).",
        "Set MONDAY_REPORT_RETENTION_DAYS to the approved tenant retention window before client data testing.",
    )

    add(
        "official_export_gate",
        "Official report export gate",
        callable(getattr(store, "report_open_validation_tasks", None)),
        "Exports are blocked while validation tasks remain open; client mode disallows unresolved overrides.",
        "Keep the validation gate enabled and audit monday_report.export_blocked before releasing official reports.",
    )

    repository_backend = os.getenv("MONDAY_REPORT_REPOSITORY_BACKEND", "local_json")
    database_url = os.getenv("MONDAY_REPORT_DATABASE_URL") or os.getenv("DATABASE_URL")
    add(
        "postgres_repository",
        "PostgreSQL repository",
        repository_backend == "postgres" and active_repository_backend == "postgres" and bool(database_url),
        (
            f"Requested repository backend is {repository_backend!r}; active adapter is "
            f"{active_repository_backend!r}; database URL configured: {bool(database_url)}."
        ),
        "Implement and activate the PostgreSQL/RLS repository adapter; environment variables alone must not certify real client data readiness.",
    )

    queue_backend = os.getenv("MONDAY_REPORT_QUEUE_BACKEND", "inline_worker")
    redis_url = os.getenv("MONDAY_REPORT_REDIS_URL") or os.getenv("REDIS_URL")
    add(
        "redis_queue",
        "Redis-backed worker queue",
        queue_backend == REDIS_QUEUE_BACKEND and active_queue_backend == REDIS_QUEUE_BACKEND and bool(redis_url),
        (
            f"Requested queue backend is {queue_backend!r}; active worker is "
            f"{active_queue_backend!r}; Redis URL configured: {bool(redis_url)}."
        ),
        "Implement and activate the Redis-backed queue worker; environment variables alone must not certify high-volume client package processing.",
    )

    local_ai_status = evaluate_local_ai_status(store.tenant.local_llm_policy)
    add(
        "local_llm_runtime",
        "Local AI runtime",
        local_ai_status.configured and local_ai_status.reachable and local_ai_status.model_available,
        (
            f"{local_ai_status.runtime} endpoint is reachable with model {local_ai_status.model!r}."
            if local_ai_status.reachable and local_ai_status.model_available
            else local_ai_status.detail
        ),
        "Install the pinned local model, configure OLLAMA_HOST or LM_STUDIO_BASE_URL, and keep hosted fallback disabled before client extraction.",
    )

    add(
        "parser_coverage",
        "Production parser coverage",
        os.getenv("MONDAY_REPORT_PRODUCTION_PARSERS", "").lower() in {"1", "true", "yes"},
        "Current executable parser covers ZIP, text, CSV, DOCX, XLSX, EML, PyMuPDF-backed embedded PDF text, native PDF table rows, page-aware locators, OCR routing, and configured local Tesseract OCR extraction.",
        "Set MONDAY_REPORT_PRODUCTION_PARSERS=true only after parser/OCR fixture evals and production OCR configuration pass.",
    )

    parser_eval_readiness = evaluate_parser_fixture_eval_readiness()
    add(
        "parser_fixture_evals",
        "Parser/OCR fixture evals",
        parser_eval_readiness.ready,
        parser_eval_readiness.detail,
        parser_eval_readiness.remediation,
    )

    fixture_readiness = evaluate_golden_fixture_readiness()
    add(
        "golden_fixture_coverage",
        "Golden fixture coverage",
        fixture_readiness.ready,
        fixture_readiness.detail,
        fixture_readiness.remediation,
    )
    add(
        "reviewed_fixture_attestation",
        "Reviewed fixture attestation",
        fixture_readiness.reviewed_attestation,
        fixture_readiness.attestation_detail,
        "Replace generated smoke fixtures with a reviewed anonymized client fixture manifest before approving real client data.",
    )

    malware_status = evaluate_malware_scanner_status()
    add(
        "malware_scanner",
        "Malware scanning",
        malware_status.ready,
        malware_status.detail,
        "Set MONDAY_REPORT_MALWARE_SCANNER=builtin for baseline blocking, or wire an external scanner adapter before selecting clamav/custom.",
    )

    add(
        "audit_trail",
        "Audit trail",
        len(store.audit_logs) > 0,
        f"{len(store.audit_logs)} audit event(s) are currently recorded.",
        "Keep audit logging enabled and move audit records to PostgreSQL before client data testing.",
        strict_failure=False,
    )

    audit_integrity = store.audit_integrity_status()
    add(
        "audit_hash_chain",
        "Audit hash chain",
        audit_integrity.status == "sealed",
        audit_integrity.detail,
        "Start client environments with hash-chain sealed audit logs and investigate any broken audit integrity immediately.",
    )

    redaction_probe = sanitize_audit_metadata({"prompt": "client confidential prompt"})
    add(
        "audit_metadata_redaction",
        "Audit metadata redaction",
        isinstance(redaction_probe.get("prompt"), dict) and redaction_probe["prompt"].get("redacted") is True,
        "Sensitive audit metadata is redacted before sealing.",
        "Keep audit metadata redaction enabled so prompts, filenames, tokens, and client identifiers are not written raw.",
    )

    ready = mode == "client" and all(check.status == "pass" for check in checks)
    return ClientDataReadiness(
        mode=mode,  # type: ignore[arg-type]
        status="ready" if ready else "not_ready",
        ready=ready,
        checks=checks,
    )


def client_uploads_allowed(store: Any) -> bool:
    if client_data_mode() != "client":
        return True
    return evaluate_client_data_readiness(store).ready


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
