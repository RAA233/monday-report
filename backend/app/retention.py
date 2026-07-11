from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone


RETENTION_DAYS_ENV = "MONDAY_REPORT_RETENTION_DAYS"
DEFAULT_RETENTION_DAYS = 365


def retention_days() -> int:
    raw_value = os.getenv(RETENTION_DAYS_ENV, "").strip()
    if not raw_value:
        return DEFAULT_RETENTION_DAYS
    try:
        parsed = int(raw_value)
    except ValueError:
        return DEFAULT_RETENTION_DAYS
    return max(parsed, 1)


def retention_configured() -> bool:
    return bool(os.getenv(RETENTION_DAYS_ENV, "").strip())


def retention_cutoff() -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=retention_days())
