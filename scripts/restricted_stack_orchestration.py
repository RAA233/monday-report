"""Shared orchestration seam around the ACCEPTED restricted-PostgreSQL foundation
(``restricted_postgres_startup_guard.run_stack``), with a narrow retry boundary that extends through
the observer's PRE-MUTATION initialization phase.

Diagnosis (scripts/provisioning_reliability_probe.py) established the dominant failure: a connection
to the freshly-provisioned server is refused/closed during early bring-up, surfacing as
``OperationalError: connection failed`` -- an intermittent, load-sensitive transient. It occurs both
before the observer hook fires (foundation connection) AND inside the observer's own PRE-mutation
initialization (store construction, readiness evaluation, isolation preflight), before any business
or audit mutation. Both are safely retryable with a fresh isolated stack; anything at or after the
first business mutation is NOT.

Attempt-local lifecycle state is held in a ``contextvars.ContextVar`` (NOT a module-global bool), so
it is reset per attempt and cannot leak across threads / concurrent execution contexts.
``business_mutation_started`` is monotonic: once set (immediately before the first wrapped mutation)
it never reverts within that attempt, and any failure thereafter is non-retryable.

Never weakens a run_stack check; never suppresses a semantic failure; never reuses a failed stack or
its evidence; bounded to 3 attempts. Emits only redacted classifications.
"""
from __future__ import annotations

import contextvars
import re
import time
from typing import Any, Callable

DEFAULT_MAX_ATTEMPTS = 3
# Bounded backoff before attempts 2 and 3. A longer settle lets the Docker daemon finish tearing down
# the prior disposable container before a fresh one is created, which shrinks the next container's
# first-init race window and materially lowers the retry's own failure rate. Still strictly bounded.
_BACKOFF_SECONDS = (6.0, 14.0)

#: Transient connection/bootstrap classes that are retryable ONLY before the first business mutation.
_TRANSIENT_MARKERS = (
    "server closed the connection",
    "connection failed",
    "could not connect",
    "connection refused",
    "the database system is starting up",
    "the database system is not yet accepting connections",
    "container not ready",
    "operationalerror",
)

LIFECYCLE_PHASES = (
    "foundation_started", "foundation_ready", "observer_entered",
    "store_connection_started", "store_connection_ready",
    "readiness_observation_completed", "isolation_preflight_completed",
    "business_mutation_started", "business_mutation_completed",
    "cleanup_started", "cleanup_completed",
)


class ProvisioningAttempt:
    """Attempt-local lifecycle state. Never shared: one instance per attempt, bound to a ContextVar."""

    def __init__(self, attempt_number: int):
        self.attempt_number = attempt_number
        self._flags: dict[str, bool] = {p: False for p in LIFECYCLE_PHASES}
        self.observer_exception: tuple[str, str] | None = None  # (class, redacted-text)

    def mark(self, phase: str) -> None:
        if phase not in self._flags:
            raise KeyError(phase)
        # monotonic: a phase flag, once True, never reverts within this attempt
        self._flags[phase] = True

    def reached(self, phase: str) -> bool:
        return self._flags[phase]

    @property
    def business_mutation_started(self) -> bool:
        return self._flags["business_mutation_started"]

    def snapshot(self) -> dict:
        return {"attempt": self.attempt_number,
                "reached": [p for p in LIFECYCLE_PHASES if self._flags[p]]}


_CURRENT_ATTEMPT: contextvars.ContextVar[ProvisioningAttempt | None] = contextvars.ContextVar(
    "restricted_stack_provisioning_attempt", default=None)


def current_attempt() -> ProvisioningAttempt | None:
    return _CURRENT_ATTEMPT.get()


def mark(phase: str) -> None:
    """Mark a lifecycle phase on the CURRENT attempt (no-op outside an attempt context)."""
    a = _CURRENT_ATTEMPT.get()
    if a is not None:
        a.mark(phase)


def mark_business_mutation_started() -> None:
    """Called by the observer IMMEDIATELY before its first wrapped business mutation. Monotonic."""
    mark("business_mutation_started")


class ProvisioningFailed(RuntimeError):
    def __init__(self, history: list[dict]):
        self.history = history
        last = history[-1] if history else {}
        super().__init__(f"restricted stack provisioning failed after {len(history)} attempt(s); "
                         f"last phase={last.get('phase')!r} retryable={last.get('retry_eligible')}")


def _redact(text: str) -> str:
    text = re.sub(r"postgres(?:ql)?://[^\s\"']+", "<dsn>", text or "", flags=re.I)
    text = re.sub(r"mr_(?:rt|mig)_[0-9a-f]+", "<role>", text or "")
    text = re.sub(r"mr-verif[a-z-]*[0-9a-f]+", "<resource>", text or "")
    text = re.sub(r"127\.0\.0\.1[:,]?\s*port\s*\d+|:\d{2,5}\b", "<endpoint>", text or "", flags=re.I)
    text = re.sub(r"[A-Za-z]:\\[^\s\"']+", "<path>", text or "")
    return (text or "")[:120]


def _failure_text(checks: list[dict], exc_text: str, obs_exc: tuple[str, str] | None) -> str:
    parts = [exc_text or ""]
    if obs_exc:
        parts.append(obs_exc[1])
    for c in checks:
        if not c.get("ok") and not c.get("skipped"):
            parts.append(str(c.get("detail", "")))
    return " ".join(parts)


def _classify(attempt: ProvisioningAttempt, checks: list[dict], result: dict,
              exc_text: str, obs_exc: tuple[str, str] | None) -> dict:
    text = _failure_text(checks, exc_text, obs_exc)
    low = text.lower()
    if result.get("cleanup_issues"):
        return {"phase": "cleanup", "failure_class": "cleanup-not-verified",
                "retry_eligible": False, "timeout_class": "none",
                "business_mutation_started": attempt.business_mutation_started}
    # ANY failure at or after the first business mutation is non-retryable, regardless of text.
    if attempt.business_mutation_started:
        return {"phase": "business-or-post-mutation", "failure_class": _redact(text) or "post-mutation",
                "retry_eligible": False, "timeout_class": "none", "business_mutation_started": True}
    # pre-mutation: a GENUINE semantic provisioning check failure is never retryable. Exclude checks
    # recorded as "aborted:" -- when a transient connection error aborts run_stack, its handler marks
    # every UNREACHED check (incl. P03/P04/I0x) as "aborted: OperationalError ...". Those are a cascade
    # of the real transient, NOT genuine migration/role/RLS/identity failures, and must not suppress
    # the retry. A genuine semantic failure has a real assertion detail, not an "aborted:" prefix.
    def _genuine_semantic(c: dict) -> bool:
        return (any(str(c.get("id", "")).startswith(pref) for pref in ("P02", "P03", "P04", "I0"))
                and not str(c.get("detail", "")).lstrip().lower().startswith("aborted:"))
    semantic = any(_genuine_semantic(c) for c in checks
                   if not c.get("ok") and not c.get("skipped"))
    is_transient = any(m in low for m in _TRANSIENT_MARKERS)
    timeout = "readiness-timeout" if "container not ready" in low else "none"
    if is_transient and not semantic:
        # infrastructure-transient BEFORE any mutation -> retryable (this includes an observer-stage
        # store/readiness/preflight connection failure, since business_mutation_started is False)
        return {"phase": "pre-mutation-transient-connection",
                "failure_class": _redact(text) or "transient-connection",
                "retry_eligible": True, "timeout_class": timeout,
                "business_mutation_started": False}
    if semantic:
        return {"phase": "migration-role-rls-identity", "failure_class": _redact(text) or "semantic",
                "retry_eligible": False, "timeout_class": "none", "business_mutation_started": False}
    return {"phase": "unknown", "failure_class": _redact(text) or "unknown",
            "retry_eligible": False, "timeout_class": "none",
            "business_mutation_started": False}


def provision_restricted_stack(
    on_live: Callable[[dict], None] | None = None,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    guard_module: Any = None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    """Provision the accepted restricted stack, retrying ONLY a clean transient connection/bootstrap
    failure that occurs strictly BEFORE the first business mutation (foundation OR observer-stage
    initialization), with fresh isolation each attempt. Returns
    ``{"result", "succeeded_on_attempt", "attempts"}`` on success; raises :class:`ProvisioningFailed`
    with the full redacted history otherwise. The observer's exception is surfaced to this seam via
    the attempt state -- the observer must NOT swallow it."""
    G = guard_module
    if G is None:
        import restricted_postgres_startup_guard as _G
        G = _G

    history: list[dict] = []
    for attempt_n in range(1, max_attempts + 1):
        attempt = ProvisioningAttempt(attempt_n)
        token = _CURRENT_ATTEMPT.set(attempt)

        def _wrapped(ctx: dict) -> None:
            attempt.mark("observer_entered")
            if on_live is not None:
                try:
                    on_live(ctx)
                except Exception as exc:  # noqa: BLE001 - surfaced via attempt state, not re-raised
                    attempt.observer_exception = (exc.__class__.__name__,
                                                  _redact(f"{exc.__class__.__name__}: {exc}"))

        prev_hook = getattr(G, "_ON_LIVE", None)
        G._ON_LIVE = _wrapped
        G.checks[:] = []
        G.http_statuses[:] = []
        exc_text = ""
        try:
            attempt.mark("foundation_started")
            result = G.run_stack()
        except Exception as exc:  # noqa: BLE001 - a hard provisioning failure
            exc_text = f"{exc.__class__.__name__}: {exc}"
            result = {"cleanup_issues": ["aborted before return"], "container_created": True}
        finally:
            G._ON_LIVE = prev_hook
            _CURRENT_ATTEMPT.reset(token)

        checks = list(G.checks)
        failed = [c for c in checks if not c.get("ok") and not c.get("skipped")]
        obs_exc = attempt.observer_exception
        success = (not exc_text) and (not failed) and (not result.get("cleanup_issues")) \
            and (on_live is None or attempt.reached("observer_entered")) and (obs_exc is None)
        if success:
            history.append({"attempt": attempt_n, "result": "success"})
            return {"result": result, "succeeded_on_attempt": attempt_n, "attempts": history}

        cls = _classify(attempt, checks, result, exc_text, obs_exc)
        cls["attempt"] = attempt_n
        cls["result"] = "failure"
        history.append(cls)
        if not cls["retry_eligible"] or attempt_n == max_attempts:
            raise ProvisioningFailed(history)
        sleep(_BACKOFF_SECONDS[min(attempt_n - 1, len(_BACKOFF_SECONDS) - 1)])

    raise ProvisioningFailed(history)  # defensive; unreachable
