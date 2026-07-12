from __future__ import annotations

import os
from uuid import UUID

from .store import store


def run_once() -> dict[str, int]:
    """Process queued ingestion jobs once.

    The store pipeline performs ZIP extraction, parser/OCR routing, chunking,
    failure extraction, citation mapping, and validation routing.
    """

    return {
        "processed": store.process_queued_jobs(
            upload_id=_worker_upload_id(),
            max_jobs=_worker_max_jobs(),
        )
    }


def _worker_upload_id() -> UUID | None:
    value = os.getenv("MONDAY_REPORT_WORKER_UPLOAD_ID")
    return UUID(value) if value else None


def _worker_max_jobs() -> int | None:
    value = os.getenv("MONDAY_REPORT_WORKER_MAX_JOBS")
    if not value:
        return None
    parsed = int(value)
    return parsed if parsed > 0 else None


if __name__ == "__main__":
    result = run_once()
    print(f"Processed {result['processed']} Monday Report job(s).")
