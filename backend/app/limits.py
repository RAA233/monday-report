from __future__ import annotations

import os


MAX_UPLOAD_BYTES_ENV = "MONDAY_REPORT_MAX_UPLOAD_BYTES"
DEFAULT_MAX_UPLOAD_BYTES = 100 * 1024 * 1024


def max_upload_bytes() -> int:
    raw_value = os.getenv(MAX_UPLOAD_BYTES_ENV, "").strip()
    if not raw_value:
        return DEFAULT_MAX_UPLOAD_BYTES
    try:
        parsed = int(raw_value)
    except ValueError:
        return DEFAULT_MAX_UPLOAD_BYTES
    return max(parsed, 1)


def upload_limit_configured() -> bool:
    return bool(os.getenv(MAX_UPLOAD_BYTES_ENV, "").strip())


def upload_too_large(byte_size: int) -> bool:
    return byte_size > max_upload_bytes()
