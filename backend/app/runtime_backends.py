from __future__ import annotations

import os

from .schemas import ClientDataReadiness, RuntimeBackendStatus


ACTIVE_REPOSITORY_BACKEND = "local_json"
ACTIVE_QUEUE_BACKEND = "inline_worker"


def runtime_backend_status(readiness: ClientDataReadiness) -> RuntimeBackendStatus:
    requested_repository_backend = os.getenv("MONDAY_REPORT_REPOSITORY_BACKEND", "local_json")
    database_url_configured = bool(os.getenv("MONDAY_REPORT_DATABASE_URL") or os.getenv("DATABASE_URL"))
    requested_queue_backend = os.getenv("MONDAY_REPORT_QUEUE_BACKEND", "inline_worker")
    redis_url_configured = bool(os.getenv("MONDAY_REPORT_REDIS_URL") or os.getenv("REDIS_URL"))
    blocking_checks = [check.id for check in readiness.checks if check.status == "fail"]

    return RuntimeBackendStatus(
        requested_repository_backend=requested_repository_backend,
        active_repository_backend=ACTIVE_REPOSITORY_BACKEND,
        database_url_configured=database_url_configured,
        repository_ready=(
            requested_repository_backend == "postgres"
            and ACTIVE_REPOSITORY_BACKEND == "postgres"
            and database_url_configured
        ),
        requested_queue_backend=requested_queue_backend,
        active_queue_backend=ACTIVE_QUEUE_BACKEND,
        redis_url_configured=redis_url_configured,
        queue_ready=(
            requested_queue_backend == "redis"
            and ACTIVE_QUEUE_BACKEND == "redis"
            and redis_url_configured
        ),
        client_data_ready=readiness.ready,
        blocking_checks=blocking_checks,
    )
