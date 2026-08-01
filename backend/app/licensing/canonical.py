"""Canonical serialization shared by license, activation, update, and evidence
documents. Deterministic: sorted keys, minimal separators, UTF-8, no NaN."""
from __future__ import annotations

import hashlib
import json


def canonical_bytes(document: dict) -> bytes:
    """Serialize a JSON document canonically (sorted keys, compact separators)."""

    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def canonical_hash(document: dict) -> str:
    """SHA-256 hex digest of the canonical serialization."""

    return hashlib.sha256(canonical_bytes(document)).hexdigest()


def signing_view(document: dict, *, exclude: tuple[str, ...] = ("signature",)) -> dict:
    """The portion of a document covered by its signature (everything except the
    signature field itself)."""

    return {key: value for key, value in document.items() if key not in exclude}
