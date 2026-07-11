from __future__ import annotations

import base64
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID


SIGNING_SECRET_ENV = "MONDAY_REPORT_SIGNING_SECRET"
DEMO_SIGNING_SECRET = "monday-report-demo-signing-secret-not-for-client-data"


def signing_secret_configured() -> bool:
    return len(os.getenv(SIGNING_SECRET_ENV, "")) >= 32


def create_signed_token(resource_id: UUID, purpose: str, ttl_seconds: int = 900) -> tuple[str, datetime]:
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    payload = {
        "resource_id": str(resource_id),
        "purpose": purpose,
        "exp": int(expires_at.timestamp()),
    }
    encoded_payload = _urlsafe_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = _signature(encoded_payload.encode("ascii"))
    return f"{encoded_payload}.{signature}", expires_at


def verify_signed_token(token: str, resource_id: UUID, purpose: str) -> bool:
    try:
        encoded_payload, supplied_signature = token.split(".", 1)
        expected_signature = _signature(encoded_payload.encode("ascii"))
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return False
        payload = json.loads(_urlsafe_decode(encoded_payload).decode("utf-8"))
        return (
            payload.get("resource_id") == str(resource_id)
            and payload.get("purpose") == purpose
            and int(payload.get("exp", 0)) >= int(datetime.now(timezone.utc).timestamp())
        )
    except (ValueError, json.JSONDecodeError, TypeError):
        return False


def _signature(payload: bytes) -> str:
    return _urlsafe_encode(hmac.new(_effective_secret().encode("utf-8"), payload, sha256).digest())


def _effective_secret() -> str:
    return os.getenv(SIGNING_SECRET_ENV, "") or DEMO_SIGNING_SECRET


def _urlsafe_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _urlsafe_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
