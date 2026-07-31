"""Shared orchestration seam around the ACCEPTED restricted-PostgreSQL foundation
(``restricted_postgres_startup_guard.run_stack``).

Diagnosis (see scripts/provisioning_reliability_probe.py) established the dominant failure phase:
after the container's ``pg_isready`` passes, the official Postgres image restarts its server during
first-time initialisation and CLOSES a subsequent connection -- surfacing as
``OperationalError: connection failed: ... server closed the connection`` during EARLY provisioning,
BEFORE any business mutation. That is a transient provisioning condition.

This seam adds a NARROW, bounded retry ONLY for that class, with fresh isolation every attempt. It
never weakens a run_stack check, never suppresses a semantic failure, never reuses a failed stack or
its evidence, and never retries once the business hook (``_ON_LIVE``) has fired. A single shared
helper serves the generator, observers and certifier so retry logic is not duplicated.

Retry eligibility (ALL required):
  * the business hook had NOT fired (no business mutation occurred);
  * the failure is an explicitly classified transient provisioning condition;
  * run_stack reported NO cleanup issues (the failed attempt was fully cleaned);
  * a fresh attempt gets an entirely new container/port/database/role/state (run_stack allocates a new
    run_hash each call, so this holds by construction).

NEVER retried: migration / role / RLS / identity / attestation semantic failures, observer/business
assertion failures (hook fired), cleanup failures, or any unknown failure. Bounded to max 3 attempts.
Emits only redacted classifications; no credentials/DSNs/roles/ids/paths.
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]

DEFAULT_MAX_ATTEMPTS = 3
_BACKOFF_SECONDS = (2.0, 5.0)  # bounded backoff before attempts 2 and 3

#: Transient, retryable-ONLY-before-mutation provisioning conditions (server-readiness / bootstrap
#: race). Matched against the redacted failure text, case-insensitively.
_TRANSIENT_MARKERS = (
    "server closed the connection",
    "connection failed",
    "could not connect",
    "connection refused",
    "the database system is starting up",
    "container not ready",
    "operationalerror",
)


class ProvisioningFailed(RuntimeError):
    """Raised when provisioning could not succeed within the retry budget, or failed for a
    non-retryable (semantic/observer/cleanup/unknown) reason. Carries the full redacted history."""

    def __init__(self, history: list[dict]):
        self.history = history
        last = history[-1] if history else {}
        super().__init__(f"restricted stack provisioning failed after {len(history)} attempt(s); "
                         f"last phase={last.get('phase')!r} class={last.get('failure_class')!r} "
                         f"retryable={last.get('retry_eligible')}")


def _redact(text: str) -> str:
    text = re.sub(r"postgres(?:ql)?://[^\s\"']+", "<dsn>", text or "", flags=re.I)
    text = re.sub(r"mr_(?:rt|mig)_[0-9a-f]+", "<role>", text or "")
    text = re.sub(r"mr-verif[a-z-]*[0-9a-f]+", "<resource>", text or "")
    text = re.sub(r"127\.0\.0\.1[:,]?\s*port\s*\d+|:\d{2,5}\b", "<endpoint>", text or "", flags=re.I)
    text = re.sub(r"[A-Za-z]:\\[^\s\"']+", "<path>", text or "")
    return (text or "")[:120]


def _failure_text(checks: list[dict], exc_text: str) -> str:
    parts = [exc_text or ""]
    for c in checks:
        if not c.get("ok") and not c.get("skipped"):
            parts.append(str(c.get("detail", "")))
    return " ".join(parts)


def _classify(hook_fired: bool, checks: list[dict], result: dict, exc_text: str) -> dict:
    """Return {phase, failure_class, retry_eligible, timeout_class} -- redacted."""
    cleanup_issues = bool(result.get("cleanup_issues"))
    text = _failure_text(checks, exc_text)
    low = text.lower()
    if cleanup_issues:
        return {"phase": "cleanup", "failure_class": "cleanup-not-verified",
                "retry_eligible": False, "timeout_class": "none"}
    if hook_fired:
        # a failure after the business hook fired is an observer/business/application failure
        return {"phase": "observer-or-business", "failure_class": _redact(text) or "post-hook-failure",
                "retry_eligible": False, "timeout_class": "none"}
    # provisioning failed before any business mutation -> transient only if it matches the class
    is_transient = any(m in low for m in _TRANSIENT_MARKERS)
    # a SEMANTIC provisioning check failing (migration/role/RLS/identity) with no transient marker is
    # never retryable
    semantic = any(str(c.get("id", "")).startswith(pref)
                   for c in checks if not c.get("ok") and not c.get("skipped")
                   for pref in ("P02", "P03", "P04", "I0"))
    timeout = "readiness-timeout" if "container not ready" in low else "none"
    if is_transient and not semantic:
        return {"phase": "server-readiness-or-bootstrap-race",
                "failure_class": _redact(text) or "transient-connection-race",
                "retry_eligible": True, "timeout_class": timeout}
    if semantic:
        return {"phase": "migration-role-rls-identity", "failure_class": _redact(text) or "semantic",
                "retry_eligible": False, "timeout_class": "none"}
    return {"phase": "unknown", "failure_class": _redact(text) or "unknown",
            "retry_eligible": False, "timeout_class": "none"}


def provision_restricted_stack(
    on_live: Callable[[dict], None] | None = None,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    guard_module: Any = None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    """Provision the accepted restricted stack, retrying ONLY a clean transient provisioning race.

    Returns ``{"result": <run_stack result>, "succeeded_on_attempt": n, "attempts": <history>}`` on
    success. Raises :class:`ProvisioningFailed` (with the full redacted history) otherwise. Every
    attempt runs the ACCEPTED ``run_stack`` unchanged, with a fresh run_hash / container / port /
    database / state; a failed attempt's stack and evidence are never reused.
    """
    G = guard_module
    if G is None:
        import restricted_postgres_startup_guard as _G
        G = _G

    history: list[dict] = []
    for attempt in range(1, max_attempts + 1):
        hook_fired = {"v": False}

        def _wrapped(ctx: dict) -> None:
            hook_fired["v"] = True
            if on_live is not None:
                on_live(ctx)

        prev_hook = getattr(G, "_ON_LIVE", None)
        G._ON_LIVE = _wrapped
        G.checks[:] = []
        G.http_statuses[:] = []
        exc_text = ""
        try:
            result = G.run_stack()
        except Exception as exc:  # noqa: BLE001 - classified, never re-raised raw
            exc_text = f"{exc.__class__.__name__}: {exc}"
            result = {"cleanup_issues": ["aborted before return"], "container_created": True}
        finally:
            G._ON_LIVE = prev_hook

        checks = list(G.checks)
        failed = [c for c in checks if not c.get("ok") and not c.get("skipped")]
        success = (not exc_text) and (not failed) and (not result.get("cleanup_issues")) \
            and (on_live is None or hook_fired["v"])
        if success:
            history.append({"attempt": attempt, "result": "success"})
            return {"result": result, "succeeded_on_attempt": attempt, "attempts": history}

        cls = _classify(hook_fired["v"], checks, result, exc_text)
        cls["attempt"] = attempt
        cls["result"] = "failure"
        history.append(cls)
        if not cls["retry_eligible"] or attempt == max_attempts:
            raise ProvisioningFailed(history)
        # bounded backoff; the next run_stack allocates entirely fresh isolated resources
        sleep(_BACKOFF_SECONDS[min(attempt - 1, len(_BACKOFF_SECONDS) - 1)])

    raise ProvisioningFailed(history)  # unreachable; defensive
