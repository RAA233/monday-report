"""Hard verification-isolation preflight (Part E).

Every mutating integration command — ``phase_audit``, ``e2e_mvp``, UI workflows
that mutate, screenshot/report workflows, worker launches, and ``audit:all`` —
must call :func:`assert_isolated` BEFORE any request or mutation. It FAILS CLOSED
when the environment is not explicitly isolated from the live runtime, so a
misconfigured run can never touch the live API (port 8000), the live web dev
server (port 5173), or the live ``.local_data`` state.

Rules:
* Verification/CI mode (``CI=true`` or ``MONDAY_REPORT_VERIFICATION_MODE=1``, which
  is the default posture for these commands) REQUIRES full isolation and permits
  no live default. A missing or live-pointing variable aborts before any network
  activity.
* A narrowly explicit local override (``MONDAY_REPORT_ALLOW_LIVE_TARGET=1``) is
  honored ONLY for intentional manual demo testing and ONLY when ``CI`` is not
  ``true``. It never applies in CI, and never excuses an API/web PID collision
  with the live process.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

LIVE_API_PORT = 8000
LIVE_WEB_PORT = 5173
LIVE_STATE_MARKER = ".local_data"


class VerificationIsolationError(RuntimeError):
    """Raised (fail-closed) when a mutating command is not isolated from live."""


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def is_ci() -> bool:
    return _truthy(os.environ.get("CI"))


def _port(url: str | None) -> int | None:
    if not url:
        return None
    try:
        return urlsplit(url if "//" in url else f"//{url}").port
    except ValueError:
        return None


def live_override_allowed() -> bool:
    """Explicit manual-demo override — never honored under CI."""
    return (not is_ci()) and _truthy(os.environ.get("MONDAY_REPORT_ALLOW_LIVE_TARGET"))


def check_isolation(
    *,
    state_path: str | None = None,
    storage_root: str | None = None,
    export_root: str | None = None,
    api_base: str | None = None,
    web_base: str | None = None,
    live_api_pid: int | None = None,
    self_api_pid: int | None = None,
) -> list[str]:
    """Return the list of isolation violations (empty == isolated). Reads the
    environment for any argument left as ``None``."""
    state_path = state_path if state_path is not None else os.environ.get("MONDAY_REPORT_STATE_PATH")
    storage_root = storage_root if storage_root is not None else os.environ.get("MONDAY_REPORT_STORAGE_ROOT")
    export_root = export_root if export_root is not None else os.environ.get("MONDAY_REPORT_EXPORT_ROOT")
    api_base = api_base if api_base is not None else os.environ.get("MONDAY_REPORT_API_BASE")
    web_base = web_base if web_base is not None else os.environ.get("MONDAY_REPORT_WEB_BASE")

    reasons: list[str] = []
    # All THREE persistence roots are configured independently and each defaults
    # into the live .local_data (store.py). Checking only the state path left
    # uploaded client bytes and generated exports writing into the live tree.
    for var, value in (
        ("MONDAY_REPORT_STATE_PATH", state_path),
        ("MONDAY_REPORT_STORAGE_ROOT", storage_root),
        ("MONDAY_REPORT_EXPORT_ROOT", export_root),
    ):
        if not value:
            reasons.append(f"{var} is not set")
        elif LIVE_STATE_MARKER in str(value).replace("\\", "/"):
            reasons.append(f"{var} resolves to live {LIVE_STATE_MARKER}")

    if not api_base:
        reasons.append("MONDAY_REPORT_API_BASE is not set")
    elif _port(api_base) == LIVE_API_PORT:
        reasons.append(f"MONDAY_REPORT_API_BASE resolves to live port {LIVE_API_PORT}")

    if not web_base:
        reasons.append("MONDAY_REPORT_WEB_BASE is not set")
    elif _port(web_base) == LIVE_WEB_PORT:
        reasons.append(f"MONDAY_REPORT_WEB_BASE resolves to live port {LIVE_WEB_PORT}")

    if live_api_pid is not None and self_api_pid is not None and int(live_api_pid) == int(self_api_pid):
        reasons.append("isolated API PID equals the live API PID")
    return reasons


def _pid_collision(reasons: list[str]) -> bool:
    return any("PID" in reason for reason in reasons)


def assert_isolated(*, context: str = "verification", **kwargs) -> None:
    """Abort (fail-closed) unless the environment is isolated from the live runtime.

    A PID collision with the live API is NEVER excused, even by the manual override.
    """
    reasons = check_isolation(**kwargs)
    if not reasons:
        return
    if live_override_allowed() and not _pid_collision(reasons):
        return
    raise VerificationIsolationError(
        f"[{context}] refusing to run against a non-isolated target (fail-closed): "
        + "; ".join(reasons)
        + ". Point the run at an isolated stack: MONDAY_REPORT_STATE_PATH, "
        f"MONDAY_REPORT_STORAGE_ROOT and MONDAY_REPORT_EXPORT_ROOT (none under "
        f"{LIVE_STATE_MARKER}), MONDAY_REPORT_API_BASE (port != {LIVE_API_PORT}), "
        f"MONDAY_REPORT_WEB_BASE (port != {LIVE_WEB_PORT}). A manual live-demo run "
        "outside CI may set MONDAY_REPORT_ALLOW_LIVE_TARGET=1."
    )


def _main(argv: list[str] | None = None) -> int:
    """CLI so non-Python runners (e.g. the .mjs UI suite) can reuse one preflight."""
    import argparse

    parser = argparse.ArgumentParser(prog="verification_isolation")
    parser.add_argument("--context", default="verification")
    args = parser.parse_args(argv)
    try:
        assert_isolated(context=args.context)
    except VerificationIsolationError as exc:
        print(str(exc))
        return 2
    print(f"[{args.context}] verification isolation OK")
    return 0


def resolve_listen_pid(port: int) -> int | None:
    """Best-effort: PID owning the TCP listener on ``port`` (Windows), else None."""
    import subprocess

    try:
        out = subprocess.check_output(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                f"(Get-NetTCPConnection -LocalPort {int(port)} -State Listen "
                f"-ErrorAction SilentlyContinue | Select-Object -First 1).OwningProcess",
            ],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=15,
        ).strip()
        return int(out) if out.isdigit() else None
    except Exception:
        return None


if __name__ == "__main__":
    import sys as _sys
    raise SystemExit(_main(_sys.argv[1:]))
