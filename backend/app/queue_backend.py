from __future__ import annotations

import os
from uuid import UUID

from .runtime_backends import REDIS_QUEUE_BACKEND, detect_active_queue_backend, redis_url


DEFAULT_QUEUE_KEY = "monday-report:processing-jobs"
DEFAULT_QUEUE_SET_KEY = "monday-report:processing-jobs:queued"


def active_queue_backend() -> str:
    return detect_active_queue_backend()


def enqueue_processing_job(job_id: UUID) -> None:
    if active_queue_backend() != REDIS_QUEUE_BACKEND:
        return
    client = _redis_client()
    job_value = str(job_id)
    set_key = _queue_set_key()
    if client.sadd(set_key, job_value):
        client.rpush(_queue_key(), job_value)


def sync_processing_queue(job_ids: list[UUID]) -> None:
    if active_queue_backend() != REDIS_QUEUE_BACKEND:
        return
    for job_id in job_ids:
        enqueue_processing_job(job_id)


def pop_processing_job_ids(limit: int = 100) -> list[UUID]:
    if active_queue_backend() != REDIS_QUEUE_BACKEND:
        return []
    client = _redis_client()
    queue_key = _queue_key()
    set_key = _queue_set_key()
    job_ids: list[UUID] = []
    for _ in range(limit):
        value = client.lpop(queue_key)
        if value is None:
            break
        job_value = value.decode("utf-8") if isinstance(value, bytes) else str(value)
        client.srem(set_key, job_value)
        try:
            job_ids.append(UUID(job_value))
        except ValueError:
            continue
    return job_ids


def _redis_client():
    import redis

    return redis.Redis.from_url(redis_url(), socket_connect_timeout=2, socket_timeout=2)


def _queue_key() -> str:
    return os.getenv("MONDAY_REPORT_REDIS_QUEUE_KEY", DEFAULT_QUEUE_KEY)


def _queue_set_key() -> str:
    return os.getenv("MONDAY_REPORT_REDIS_QUEUE_SET_KEY", DEFAULT_QUEUE_SET_KEY)
