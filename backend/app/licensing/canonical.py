"""Canonical serialization shared by license, activation, update, and evidence
documents. Deterministic: sorted keys, minimal separators, UTF-8, no NaN."""
from __future__ import annotations

import hashlib
import json


class CanonicalizationError(ValueError):
    """Raised when a document cannot be canonically serialized (e.g. a lone
    surrogate). Callers translate this into a typed rejection reason rather
    than letting a UnicodeEncodeError escape."""


def canonical_bytes(document: dict) -> bytes:
    """Serialize a JSON document canonically (sorted keys, compact separators)."""

    try:
        return json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (UnicodeEncodeError, ValueError, TypeError) as exc:
        raise CanonicalizationError(str(exc)) from exc


def canonical_hash(document: dict) -> str:
    """SHA-256 hex digest of the canonical serialization."""

    return hashlib.sha256(canonical_bytes(document)).hexdigest()


def signing_view(document: dict, *, exclude: tuple[str, ...] = ("signature",)) -> dict:
    """The portion of a document covered by its signature (everything except the
    signature field itself)."""

    return {key: value for key, value in document.items() if key not in exclude}
