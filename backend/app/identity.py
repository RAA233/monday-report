"""Request-scoped authenticated identity.

The active identity for the current request is held in a ``ContextVar`` so it is
isolated per request/task and never shared through a process-global. The auth
middleware sets it at the start of each request and resets it in a ``finally``,
so concurrent requests with different users retain different actors and no
context leaks between requests. Worker/CLI operations run with no request
identity set; callers fall back to an explicit ``system`` actor.
"""
from __future__ import annotations

import contextvars

from .schemas import AuthenticatedIdentity

_current_identity: contextvars.ContextVar[AuthenticatedIdentity | None] = contextvars.ContextVar(
    "monday_report_current_identity", default=None
)
# Request method + normalized path, for permission-denial audit context only.
_request_context: contextvars.ContextVar[tuple[str, str] | None] = contextvars.ContextVar(
    "monday_report_request_context", default=None
)


def set_request_context(method: str, path: str) -> contextvars.Token:
    return _request_context.set((method, path))


def reset_request_context(token: contextvars.Token) -> None:
    try:
        _request_context.reset(token)
    except (ValueError, LookupError):
        _request_context.set(None)


def get_request_context() -> tuple[str, str] | None:
    return _request_context.get()


def set_current_identity(identity: AuthenticatedIdentity | None) -> contextvars.Token:
    """Set the request identity and return a reset token."""
    return _current_identity.set(identity)


def reset_current_identity(token: contextvars.Token) -> None:
    """Reset the request identity to its previous value (request cleanup)."""
    try:
        _current_identity.reset(token)
    except (ValueError, LookupError):
        # Token from a different context (defensive); clear to be safe.
        _current_identity.set(None)


def get_current_identity() -> AuthenticatedIdentity | None:
    """Return the request-scoped identity, or None outside a request."""
    return _current_identity.get()
