from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Any


MAX_AUDIT_STRING_LENGTH = 240
MAX_AUDIT_LIST_ITEMS = 20
MAX_AUDIT_DEPTH = 6
SENSITIVE_KEYS = {
    "api_key",
    "content",
    "email",
    "file_name",
    "filename",
    "full_name",
    "key",
    "name",
    "original_path",
    "password",
    "path",
    "prompt",
    "secret",
    "signed_url",
    "snippet",
    "storage_path",
    "storage_uri",
    "token",
    "url",
}
SENSITIVE_KEY_FRAGMENTS = ("token", "secret", "password", "api_key")
EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
LONG_TOKEN_PATTERN = re.compile(r"\b[A-Za-z0-9_-]{32,}\b")


def sanitize_audit_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    if not metadata:
        return {}
    sanitized = _sanitize_value(metadata, key=None, depth=0)
    return sanitized if isinstance(sanitized, dict) else {"value": sanitized}


def _sanitize_value(value: Any, key: str | None, depth: int) -> Any:
    if depth > MAX_AUDIT_DEPTH:
        return {"redacted": True, "reason": "max_depth"}
    if _sensitive_key(key):
        return _redacted_value(value, "sensitive_key")
    if isinstance(value, dict):
        return {
            str(item_key): _sanitize_value(item_value, str(item_key), depth + 1)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        items = [_sanitize_value(item, key=None, depth=depth + 1) for item in value[:MAX_AUDIT_LIST_ITEMS]]
        if len(value) > MAX_AUDIT_LIST_ITEMS:
            items.append({"truncated": len(value) - MAX_AUDIT_LIST_ITEMS})
        return items
    if isinstance(value, str):
        return _sanitize_string(value)
    return value


def _sanitize_string(value: str) -> str | dict[str, Any]:
    if EMAIL_PATTERN.search(value) or LONG_TOKEN_PATTERN.search(value):
        return _redacted_value(value, "sensitive_pattern")
    if len(value) > MAX_AUDIT_STRING_LENGTH:
        return {
            "truncated": True,
            "prefix": value[:MAX_AUDIT_STRING_LENGTH],
            "length": len(value),
            "sha256": sha256(value.encode("utf-8")).hexdigest(),
        }
    return value


def _sensitive_key(key: str | None) -> bool:
    if key is None:
        return False
    normalized = key.lower()
    return normalized in SENSITIVE_KEYS or any(fragment in normalized for fragment in SENSITIVE_KEY_FRAGMENTS)


def _redacted_value(value: Any, reason: str) -> dict[str, Any]:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return {
        "redacted": True,
        "reason": reason,
        "length": len(canonical),
        "sha256": sha256(canonical.encode("utf-8")).hexdigest(),
    }
