"""Request-boundary idempotency for mutating routes.

The transactional snapshot store can accept an ``operation_id`` and replay a
committed result, but that capability is only meaningful if a real request
supplies the key. This module is the request boundary: a route validates the
``Idempotency-Key`` header, computes a deterministic hash of the *validated
semantic request* (never raw bytes, never credentials or timestamps), and
publishes an :class:`IdempotencyContext` in a request-scoped ``ContextVar``. The
PostgreSQL mutation wrapper consumes that context and threads it into
``snapshot_transaction``.

Nothing here authenticates: the key is an idempotency token, not a credential.
The full key is never logged; only a short irreversible fingerprint is exposed
for correlation.
"""
from __future__ import annotations

import contextvars
import hashlib
import json
import os
import re
from dataclasses import dataclass
from uuid import UUID

HEADER_NAME = "Idempotency-Key"
CONTRACT_VERSION = "1.0.0"

# Test-only: names the exact operation key whose response should be "lost" after
# its mutation has already committed, so a retry with the same key must replay
# the committed result instead of mutating a second time. It is refused outright
# in client mode, so it can never alter behaviour in a client/production
# deployment even if the variable were somehow present.
LOST_RESPONSE_ENV = "MONDAY_REPORT_TEST_LOST_RESPONSE_KEY"

MIN_KEY_LENGTH = 8
MAX_KEY_LENGTH = 200
# URL-safe token characters. Deliberately excludes whitespace and control chars.
_KEY_RE = re.compile(r"^[A-Za-z0-9._~\-]+$")


class IdempotencyKeyError(ValueError):
    """A supplied idempotency key is missing or malformed (maps to HTTP 400)."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class LostResponseSimulation(RuntimeError):
    """Test-only signal: the mutation committed but the response was 'lost'.

    Raised by :func:`simulate_lost_response` after a real commit to reproduce a
    crashed/dropped response. There is no HTTP handler for it, so the client sees
    a generic server error exactly as it would on a real network failure; the
    point is that the committed operation is now replayable by its key.
    """


@dataclass(frozen=True)
class IdempotencyContext:
    operation_id: str
    operation_kind: str
    request_hash: str
    actor_id: UUID | None

    def fingerprint(self) -> str:
        """Short irreversible id for logs/correlation. Never the raw key."""
        return hashlib.sha256(self.operation_id.encode("utf-8")).hexdigest()[:12]


_context: contextvars.ContextVar[IdempotencyContext | None] = contextvars.ContextVar(
    "monday_report_idempotency_context", default=None
)


def current() -> IdempotencyContext | None:
    return _context.get()


def set_context(ctx: IdempotencyContext) -> contextvars.Token:
    return _context.set(ctx)


def reset_context(token: contextvars.Token) -> None:
    try:
        _context.reset(token)
    except (ValueError, LookupError):
        _context.set(None)


def clear_context() -> None:
    _context.set(None)


def validate_key(values: list[str]) -> str:
    """Validate the raw header value(s). Fails closed with a controlled error.

    Rejects: absent, empty, too short, too long, illegal characters, and repeated
    headers carrying different values. Never raises a raw framework exception.
    """
    present = [v for v in values if v is not None]
    if not present or not present[0].strip():
        raise IdempotencyKeyError(f"{HEADER_NAME} header is required for this operation")
    distinct = {v.strip() for v in present}
    if len(distinct) > 1:
        raise IdempotencyKeyError(f"conflicting {HEADER_NAME} headers")
    key = present[0].strip()
    if len(key) < MIN_KEY_LENGTH:
        raise IdempotencyKeyError(f"{HEADER_NAME} must be at least {MIN_KEY_LENGTH} characters")
    if len(key) > MAX_KEY_LENGTH:
        raise IdempotencyKeyError(f"{HEADER_NAME} must be at most {MAX_KEY_LENGTH} characters")
    if not _KEY_RE.match(key):
        raise IdempotencyKeyError(f"{HEADER_NAME} contains unsupported characters")
    return key


def _canonical(value: object) -> object:
    """Recursively normalise to a JSON-stable form (sorted keys applied at dump)."""
    if hasattr(value, "model_dump"):
        return _canonical(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return {str(k): _canonical(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    if isinstance(value, UUID):
        return str(value)
    return value


def canonical_request_hash(operation_kind: str, target_ids: dict[str, object], body: object) -> str:
    """Deterministic SHA-256 over the validated semantic request.

    Stable across JSON key order, whitespace, equivalent validated
    representations, process restarts and platforms. Includes the operation kind,
    path resource identifiers and the validated body. Excludes credentials,
    headers and any server-generated timestamp.
    """
    document = {
        "op": operation_kind,
        "targets": {str(k): (str(v) if v is not None else None)
                    for k, v in sorted(target_ids.items())},
        "body": _canonical(body),
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_context(
    *,
    header_values: list[str],
    operation_kind: str,
    target_ids: dict[str, object],
    body: object,
    actor_id: UUID | None,
) -> IdempotencyContext:
    """Validate the key and build the request-scoped context.

    The operation id is the validated key itself, tenant-scoped by the
    idempotency table's primary key. Distinct actors and distinct operation kinds
    that reuse the same key are surfaced as conflicts by the store's replay check
    (which compares the stored actor and operation kind), so a key is owned by the
    first (actor, operation, request) that committed it.
    """
    key = validate_key(header_values)
    request_hash = canonical_request_hash(operation_kind, target_ids, body)
    return IdempotencyContext(
        operation_id=key,
        operation_kind=operation_kind,
        request_hash=request_hash,
        actor_id=actor_id,
    )


def simulate_lost_response(operation_id: str) -> None:
    """Test-only hook: if armed for ``operation_id``, raise *after* the commit.

    Arming requires the env var to name this exact operation key AND the runtime
    NOT to be in client mode. Both conditions must hold, so the hook is inert in
    any client/production deployment: production never sets the variable, and even
    if it were set the client-mode refusal below stops it from ever firing. When
    it does fire (tests only) the mutation has already committed, so the caller's
    lost response is indistinguishable from a real crash and a same-key retry
    replays the committed result.
    """
    armed = os.getenv(LOST_RESPONSE_ENV)
    if not armed or armed != operation_id:
        return
    # Deferred import avoids an import cycle and keeps this module dependency-free
    # for its unit tests.
    from .readiness import client_data_mode

    if client_data_mode() == "client":
        return
    raise LostResponseSimulation("post-commit response loss (test hook)")
