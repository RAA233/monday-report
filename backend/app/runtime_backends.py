from __future__ import annotations

import os
from dataclasses import dataclass

from .schemas import ClientDataReadiness, RuntimeBackendStatus


LOCAL_REPOSITORY_BACKEND = "local_json"
POSTGRES_REPOSITORY_BACKEND = "postgres"
INLINE_QUEUE_BACKEND = "inline_worker"
REDIS_QUEUE_BACKEND = "redis"


@dataclass(frozen=True)
class BackendProbe:
    ready: bool
    detail: str


def requested_repository_backend() -> str:
    return os.getenv("MONDAY_REPORT_REPOSITORY_BACKEND", LOCAL_REPOSITORY_BACKEND).strip().lower()


def database_url() -> str:
    return (os.getenv("MONDAY_REPORT_DATABASE_URL") or os.getenv("DATABASE_URL") or "").strip()


def requested_queue_backend() -> str:
    return os.getenv("MONDAY_REPORT_QUEUE_BACKEND", INLINE_QUEUE_BACKEND).strip().lower()


def redis_url() -> str:
    return (os.getenv("MONDAY_REPORT_REDIS_URL") or os.getenv("REDIS_URL") or "").strip()


def postgres_probe() -> BackendProbe:
    url = database_url()
    if not url:
        return BackendProbe(False, "database URL is not configured")
    try:
        import psycopg
    except ImportError:
        return BackendProbe(False, "psycopg is not installed")
    try:
        with psycopg.connect(url, connect_timeout=2) as connection:
            with connection.cursor() as cursor:
                cursor.execute("select 1")
                cursor.fetchone()
    except Exception as exc:  # noqa: BLE001 - operator readiness should preserve connection detail.
        return BackendProbe(False, f"PostgreSQL connection failed: {exc.__class__.__name__}")
    return BackendProbe(True, "PostgreSQL connection succeeded")


def redis_probe() -> BackendProbe:
    url = redis_url()
    if not url:
        return BackendProbe(False, "Redis URL is not configured")
    try:
        import redis
    except ImportError:
        return BackendProbe(False, "redis Python package is not installed")
    try:
        client = redis.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2)
        client.ping()
    except Exception as exc:  # noqa: BLE001 - operator readiness should preserve connection detail.
        return BackendProbe(False, f"Redis connection failed: {exc.__class__.__name__}")
    return BackendProbe(True, "Redis connection succeeded")


def detect_active_repository_backend() -> str:
    if requested_repository_backend() == POSTGRES_REPOSITORY_BACKEND and postgres_probe().ready:
        return POSTGRES_REPOSITORY_BACKEND
    return LOCAL_REPOSITORY_BACKEND


def detect_active_queue_backend() -> str:
    if requested_queue_backend() == REDIS_QUEUE_BACKEND and redis_probe().ready:
        return REDIS_QUEUE_BACKEND
    return INLINE_QUEUE_BACKEND


def runtime_backend_status(readiness: ClientDataReadiness, store: object | None = None) -> RuntimeBackendStatus:
    requested_repo = requested_repository_backend()
    database_url_configured = bool(database_url())
    requested_queue = requested_queue_backend()
    redis_url_configured = bool(redis_url())
    active_repo = getattr(store, "repository_backend", None) or detect_active_repository_backend()
    active_queue = getattr(store, "queue_backend", None) or detect_active_queue_backend()
    blocking_checks = [check.id for check in readiness.checks if check.status == "fail"]

    return RuntimeBackendStatus(
        requested_repository_backend=requested_repo,
        active_repository_backend=active_repo,
        database_url_configured=database_url_configured,
        repository_ready=(
            requested_repo == POSTGRES_REPOSITORY_BACKEND
            and active_repo == POSTGRES_REPOSITORY_BACKEND
            and database_url_configured
        ),
        requested_queue_backend=requested_queue,
        active_queue_backend=active_queue,
        redis_url_configured=redis_url_configured,
        queue_ready=(
            requested_queue == REDIS_QUEUE_BACKEND
            and active_queue == REDIS_QUEUE_BACKEND
            and redis_url_configured
        ),
        client_data_ready=readiness.ready,
        blocking_checks=blocking_checks,
    )
