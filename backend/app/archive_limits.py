from __future__ import annotations

import os


MAX_ZIP_ENTRIES_ENV = "MONDAY_REPORT_MAX_ZIP_ENTRIES"
MAX_ZIP_UNCOMPRESSED_BYTES_ENV = "MONDAY_REPORT_MAX_ZIP_UNCOMPRESSED_BYTES"
DEFAULT_MAX_ZIP_ENTRIES = 200
DEFAULT_MAX_ZIP_UNCOMPRESSED_BYTES = 100 * 1024 * 1024


def max_zip_entries() -> int:
    return _positive_int_from_env(MAX_ZIP_ENTRIES_ENV, DEFAULT_MAX_ZIP_ENTRIES)


def max_zip_uncompressed_bytes() -> int:
    return _positive_int_from_env(
        MAX_ZIP_UNCOMPRESSED_BYTES_ENV,
        DEFAULT_MAX_ZIP_UNCOMPRESSED_BYTES,
    )


def archive_limits_configured() -> bool:
    return (
        _valid_positive_int_env(MAX_ZIP_ENTRIES_ENV)
        and _valid_positive_int_env(MAX_ZIP_UNCOMPRESSED_BYTES_ENV)
    )


def _positive_int_from_env(name: str, default: int) -> int:
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return default
    try:
        value = int(raw_value)
    except ValueError:
        return default
    return value if value > 0 else default


def _valid_positive_int_env(name: str) -> bool:
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return False
    try:
        return int(raw_value) > 0
    except ValueError:
        return False
