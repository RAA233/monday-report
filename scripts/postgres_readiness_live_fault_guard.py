"""audit:postgres-readiness-live-fault -- DETERMINISTIC live fault injection at the connection-
readiness boundary (needs Docker). Uses the accepted foundation's _STABLE_SQL_PROBE hook to force
specific Layer-1 outcomes on a REAL restricted stack, proving the layering:

  * a transient Layer-1 failure on the FIRST fresh stack -> the foundation fails closed for that stack;
    the OUTER contract (max 3) tries a fresh stack; the Layer-1 probe succeeds there -> one outer retry,
    final success, business mutation begins exactly once;
  * a non-transient (auth) Layer-1 failure -> no connection retry AND no outer retry (classified
    non-transient) -> fails closed.

Does not rely on naturally-occurring flakiness. Prints JSON; exits non-zero on failure. Emits no
credentials/DSNs/roles/ids/paths.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str = "", extra=None) -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "detail": detail, **({"extra": extra} if extra is not None else {})})


def docker_available() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=40).returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _clear_env():
    import os
    for k in ("MONDAY_REPORT_TEST_DATABASE_URL", "MONDAY_REPORT_DATABASE_URL",
              "MONDAY_REPORT_REPOSITORY_BACKEND", "MONDAY_REPORT_STATE_PATH",
              "PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE"):
        os.environ.pop(k, None)


def transient_then_recover() -> None:
    """A transient Layer-1 failure on the first fresh stack -> outer retry -> success on the next."""
    import restricted_postgres_startup_guard as G
    import restricted_stack_orchestration as O

    calls = {"n": 0}
    real = G.wait_for_stable_sql_connection

    def injected(dsn):
        calls["n"] += 1
        if calls["n"] == 1:
            # deterministic transient deadline-exhaustion on the FIRST fresh stack (carries a transient
            # marker so the outer contract may try a fresh stack)
            raise RuntimeError("transient: could not connect a stable SQL session before the readiness "
                               "deadline; connection failed to stabilize")
        return real(dsn)   # a genuine stable-SQL probe on the fresh outer-retry stack

    hook_fired = {"n": 0}
    _clear_env()
    prev = getattr(G, "_STABLE_SQL_PROBE", None)
    G._STABLE_SQL_PROBE = injected
    try:
        out = O.provision_restricted_stack(lambda ctx: hook_fired.__setitem__("n", hook_fired["n"] + 1),
                                           max_attempts=3)
        attempts = out.get("attempts", [])
        rec("LF01 transient-layer1-then-outer-retry-success",
            out.get("succeeded_on_attempt") == 2 and len(attempts) == 2
            and attempts[0].get("phase") == "pre-mutation-transient-connection"
            and hook_fired["n"] == 1,
            "a transient Layer-1 failure on the first stack triggers exactly one fresh outer stack "
            "that succeeds; the business hook fires exactly once", extra={"outer_attempts": len(attempts)})
    except O.ProvisioningFailed as e:
        rec("LF01 transient-layer1-then-outer-retry-success", False,
            f"unexpectedly failed closed: {e.history[-1].get('phase')}")
    finally:
        G._STABLE_SQL_PROBE = prev


def auth_not_retried() -> None:
    """A non-transient (auth) Layer-1 failure -> no connection retry and no outer retry."""
    import restricted_postgres_startup_guard as G
    import restricted_stack_orchestration as O

    calls = {"n": 0}

    def injected(dsn):
        calls["n"] += 1
        raise RuntimeError("non-transient SQL-connect failure before bootstrap (class=auth, "
                           "OperationalError)")

    _clear_env()
    prev = getattr(G, "_STABLE_SQL_PROBE", None)
    G._STABLE_SQL_PROBE = injected
    try:
        try:
            O.provision_restricted_stack(lambda ctx: None, max_attempts=3)
            rec("LF02 auth-layer1-not-retried", False, "an auth Layer-1 failure was not failed closed")
        except O.ProvisioningFailed as e:
            # exactly one outer attempt (no outer retry); the probe was invoked once per stack
            rec("LF02 auth-layer1-not-retried",
                len(e.history) == 1 and not e.history[0].get("retry_eligible") and calls["n"] == 1,
                "a non-transient (auth) Layer-1 failure fails closed with no connection retry and no "
                "outer retry", extra={"outer_attempts": len(e.history), "probe_calls": calls["n"]})
    finally:
        G._STABLE_SQL_PROBE = prev


def main() -> int:
    if not docker_available():
        rec("LF00 docker-available", False, "Docker unavailable; live fault tests cannot run")
    else:
        transient_then_recover()
        auth_not_retried()
    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "postgres_readiness_live_fault",
        "claim_scope": "deterministic-live-readiness-faults",
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2, sort_keys=True))
    return 0 if passed == len(CHECKS) and CHECKS else 1


if __name__ == "__main__":
    raise SystemExit(main())
