from __future__ import annotations

import hmac
import os


API_KEY_ENV = "MONDAY_REPORT_API_KEY"
API_KEY_HEADER = "x-monday-report-key"
MIN_API_KEY_LENGTH = 24


def api_key_configured() -> bool:
    return len(os.getenv(API_KEY_ENV, "")) >= MIN_API_KEY_LENGTH


def api_key_valid(supplied_key: str | None) -> bool:
    expected_key = os.getenv(API_KEY_ENV, "")
    return bool(supplied_key) and api_key_configured() and hmac.compare_digest(supplied_key, expected_key)
