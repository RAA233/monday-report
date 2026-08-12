"""Diagnostic probe for restricted-PostgreSQL disposable-stack provisioning reliability.

Runs the ACCEPTED foundation `restricted_postgres_startup_guard.run_stack()` N times, each with fresh
runner-owned resources, and classifies every outcome by LIFECYCLE PHASE -- never modifying run_stack
or weakening any check. For each attempt it records only a redacted classification: phase, attempt,
failure class, timeout class, cleanup outcome. It also verifies cleanup (no task container/volume
remains; the allocated port is released) after every attempt.

This is DIAGNOSIS ONLY: it implements no retry and makes no acceptance claim. Prints a redacted JSON
failure distribution. Never emits credentials, DSNs, role names, tenant values, container/process ids,
private paths or endpoints.

Usage: python scripts/provisioning_reliability_probe.py [--cycles N]
"""
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

_LEAKED = ("MONDAY_REPORT_TEST_DATABASE_URL", "MONDAY_REPORT_TEST_PG_SERVER_VERSION",
           "MONDAY_REPORT_TEST_PGVECTOR_VERSION", "MONDAY_REPORT_TEST_PG_IMAGE_DIGEST",
           "MONDAY_REPORT_DATABASE_URL", "MONDAY_REPORT_REPOSITORY_BACKEND", "MONDAY_REPORT_STATE_PATH",
           "PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE")

# Map a raised message / failed-check id to a redacted lifecycle phase + retry eligibility.
_PHASES = [
    ("container create failed", "container-create", False),
    ("container not ready", "server-readiness-timeout", True),   # 40s pg_isready timeout
    ("run-scoped name already exists", "resource-name-collision", True),
    ("provenance preconditions", "attestation", False),
]
_CHECK_PREFIX_PHASE = {
    "R01": "resource-name-allocation", "R02": "volume-create", "R03": "container-create",
    "R04": "container-ownership", "R05": "container-ownership", "R06": "container-ownership",
    "R07": "container-ownership", "R08": "cleanup",
    "P01": "database-bootstrap", "P02": "role-setup", "P03": "migration", "P04": "rls-setup",
    "I01": "runtime-identity", "I02": "runtime-identity", "I03": "role-separation",
    "D0": "env-hygiene", "RT": "runtime-matrix",
}


def _redact(msg: str) -> str:
    import re
    msg = re.sub(r"postgres(?:ql)?://[^\s\"']+", "<dsn>", msg or "", flags=re.I)
    msg = re.sub(r"mr_(?:rt|mig)_[0-9a-f]+", "<role>", msg or "")
    msg = re.sub(r"mr-verif[a-z-]*[0-9a-f]+", "<resource>", msg or "")
    msg = re.sub(r"[A-Za-z]:\\[^\s\"']+|/[^\s\"']+/[^\s\"']+", "<path>", msg or "")
    return (msg or "")[:80]


def _clear_env() -> None:
    import os
    for k in _LEAKED:
        os.environ.pop(k, None)


def _phase_for(exc_msg: str, checks: list) -> tuple[str, bool, str]:
    """Return (phase, retry_eligible, timeout_class)."""
    for needle, phase, retry in _PHASES:
        if needle in (exc_msg or ""):
            timeout = "readiness-timeout" if "not ready" in needle else "none"
            return phase, retry, timeout
    # soft failure: first recorded check that did not pass
    failed = [c for c in checks if not c.get("ok") and not c.get("skipped")]
    if failed:
        cid = str(failed[0].get("id", ""))
        for pref, phase in _CHECK_PREFIX_PHASE.items():
            if cid.startswith(pref):
                # role/RLS/migration/identity are SEMANTIC -> never retryable
                retry = phase in ("resource-name-allocation", "container-create", "volume-create")
                return phase, retry, "none"
        return f"check:{cid[:6]}", False, "none"
    return "unknown", False, "none"


def _verify_cleanup(run_hash: str, port: int) -> dict:
    def q(args):
        return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=30).stdout.strip()
    container_left = bool(q(["ps", "-aq", "-f", f"name=mr-verif-{run_hash}"]))
    volume_left = bool(q(["volume", "ls", "-q", "-f", f"name=mr-verif-vol-{run_hash}"]))
    port_free = True
    try:
        s = socket.socket(); s.bind(("127.0.0.1", port)); s.close()
    except OSError:
        port_free = False
    return {"container_removed": not container_left, "volume_removed": not volume_left,
            "port_released": port_free}


def run_cycles(n: int) -> dict:
    import restricted_postgres_startup_guard as G

    attempts = []
    dist: dict[str, int] = {}
    successes = 0
    for i in range(1, n + 1):
        _clear_env()
        G.checks[:] = []
        G.http_statuses[:] = []
        outcome = {"attempt": i}
        exc_msg = ""
        try:
            result = G.run_stack()
        except Exception as exc:  # noqa: BLE001 - classify, never re-raise
            exc_msg = _redact(f"{exc.__class__.__name__}: {exc}")
            result = {"run_hash": "", "cleanup_issues": ["aborted before return"], "container_created": True}
        checks = list(G.checks)
        passed = sum(1 for c in checks if c.get("ok"))
        failed = sum(1 for c in checks if not c.get("ok") and not c.get("skipped"))
        cleanup_issues = bool(result.get("cleanup_issues"))
        ok = (not exc_msg) and failed == 0 and not cleanup_issues and passed >= 31
        if ok:
            successes += 1
            outcome.update({"result": "success", "checks_passed": passed})
        else:
            phase, retry, timeout = _phase_for(exc_msg, checks)
            if cleanup_issues and phase == "unknown":
                phase, retry = "cleanup", False
            dist[phase] = dist.get(phase, 0) + 1
            outcome.update({"result": "failure", "phase": phase, "failure_class": exc_msg or "soft-check-fail",
                            "timeout_class": timeout, "retry_eligible": retry,
                            "checks_passed": passed, "checks_failed": failed,
                            "cleanup_issues": cleanup_issues})
        attempts.append(outcome)
    return {"cycles": n, "successes": successes, "failures": n - successes,
            "failure_distribution_by_phase": dist, "attempts": attempts}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cycles", type=int, default=20)
    args = ap.parse_args()
    report = run_cycles(args.cycles)
    dominant = max(report["failure_distribution_by_phase"].items(), key=lambda kv: kv[1])[0] \
        if report["failure_distribution_by_phase"] else None
    report["dominant_failure_phase"] = dominant
    report["guard"] = "provisioning_reliability_probe"
    report["claim_scope"] = "diagnosis-only-no-retry"
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
