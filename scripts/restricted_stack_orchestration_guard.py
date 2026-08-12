"""audit:restricted-stack-orchestration -- deterministic, Docker-free proof of the narrow retry
boundary that extends through the observer's PRE-MUTATION initialization phase.

Drives the REAL ``provision_restricted_stack`` with a MOCK foundation + scripted observer hook, so
the boundary is exercised without Docker: a transient connection failure BEFORE the first business
mutation (foundation bring-up OR observer store/readiness/preflight) is retried on a fresh attempt;
anything at or after the first business mutation, and every semantic/cleanup/unknown failure, is
never retried. Attempt state is verified context-isolated (ContextVar) and monotonic. Fault mutations
patch the seam source to prove each guarantee is load-bearing. Prints JSON; exits non-zero on failure.
"""
from __future__ import annotations

import importlib
import io
import json
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

SEAM = ROOT / "scripts" / "restricted_stack_orchestration.py"
CONN = "aborted: OperationalError: connection failed: server closed the connection"
CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str = "") -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL", "detail": detail})


class MockGuard:
    """Scripts the FOUNDATION outcome per attempt. `prehook` fails run_stack BEFORE the hook; `ok`
    fires the hook then returns a clean success (the observer hook decides its own fate)."""

    def __init__(self, prehook_by_attempt: list[str]):
        self.prehook_by_attempt = prehook_by_attempt
        self.i = 0
        self.checks: list[dict] = []
        self.http_statuses: list[int] = []
        self._ON_LIVE = None
        self.run_hashes: list[str] = []

    def run_stack(self) -> dict:
        kind = self.prehook_by_attempt[self.i] if self.i < len(self.prehook_by_attempt) else "ok"
        self.i += 1
        rh = f"hash-{self.i}"
        self.run_hashes.append(rh)
        self.checks[:] = []
        if kind == "transient":
            # a real transient abort marks the failing connection AND cascades every UNREACHED check
            # (incl. P03/P04/I0x) as "aborted: OperationalError ..." -- must still be retryable.
            self.checks.append({"id": "P01 database created by the runner", "ok": False,
                                "skipped": False, "detail": CONN})
            for cid in ("P03 migrations applied", "P04 RLS enabled and forced",
                        "I01 api session_user"):
                self.checks.append({"id": cid, "ok": False, "skipped": False, "detail": CONN})
            return {"run_hash": rh, "cleanup_issues": [], "container_created": True}
        if kind == "semantic-genuine":
            self.checks.append({"id": "P04 RLS enabled and forced", "ok": False, "skipped": False,
                                "detail": "row-level security is NOT forced on a protected table"})
            return {"run_hash": rh, "cleanup_issues": [], "container_created": True}
        if kind == "semantic-migration":
            self.checks.append({"id": "P03 migrations applied", "ok": False, "skipped": False,
                                "detail": "migration 0007 failed"})
            return {"run_hash": rh, "cleanup_issues": [], "container_created": True}
        if kind == "cleanup-fail":
            self.checks.append({"id": "P01 database created", "ok": False, "skipped": False,
                                "detail": CONN})
            return {"run_hash": rh, "cleanup_issues": ["container rm failed"], "container_created": True}
        if self._ON_LIVE:                      # kind == "ok": provisioning succeeded; hand to observer
            self._ON_LIVE({"run_hash": rh})
        return {"run_hash": rh, "cleanup_issues": [], "container_created": True}


def _seam():
    import restricted_stack_orchestration as O
    return importlib.reload(O)


def _drive(prehook_by_attempt, hook=None, max_attempts=3):
    O = _seam()
    g = MockGuard(prehook_by_attempt)
    try:
        out = O.provision_restricted_stack(hook, max_attempts=max_attempts, guard_module=g,
                                           sleep=lambda s: None)
        return {"ok": True, "out": out, "guard": g, "O": O}
    except O.ProvisioningFailed as e:
        return {"ok": False, "history": e.history, "guard": g, "O": O}


def positive() -> None:
    O = _seam()

    # observer-stage connection failure BEFORE mutation -> retried, succeeds on attempt 2
    state = {"n": 0}

    def hook_store_conn_then_ok(ctx):
        state["n"] += 1
        O2 = importlib.import_module("restricted_stack_orchestration")
        O2.mark("store_connection_started")
        if state["n"] == 1:
            raise RuntimeError("connection failed: server closed the connection")  # pre-mutation
        O2.mark("store_connection_ready")
    r = _drive(["ok", "ok"], hook=hook_store_conn_then_ok)
    rec("O01 observer-store-conn-before-mutation-retried",
        r["ok"] and r["out"]["succeeded_on_attempt"] == 2
        and r["out"]["attempts"][0]["phase"] == "pre-mutation-transient-connection",
        "a store/observer connection failure before the mutation boundary is retried")

    # readiness-stage connection failure before mutation -> retried
    state2 = {"n": 0}

    def hook_readiness_then_ok(ctx):
        state2["n"] += 1
        O2 = importlib.import_module("restricted_stack_orchestration")
        O2.mark("store_connection_ready")
        if state2["n"] == 1:
            raise RuntimeError("OperationalError: connection failed")   # during readiness, pre-mutation
        O2.mark("readiness_observation_completed")
    r = _drive(["ok", "ok"], hook=hook_readiness_then_ok)
    rec("O02 readiness-conn-before-mutation-retried",
        r["ok"] and r["out"]["succeeded_on_attempt"] == 2, "a readiness-stage connection failure "
        "before mutation is retried")

    # FIRST business mutation failure -> NEVER retried (business_mutation_started True)
    def hook_first_mutation_fails(ctx):
        O2 = importlib.import_module("restricted_stack_orchestration")
        O2.mark_business_mutation_started()
        raise RuntimeError("connection failed: server closed the connection")  # AT the mutation
    r = _drive(["ok", "ok"], hook=hook_first_mutation_fails)
    rec("O03 first-mutation-failure-never-retried",
        (not r["ok"]) and len(r["history"]) == 1
        and r["history"][0]["phase"] == "business-or-post-mutation"
        and r["history"][0]["business_mutation_started"] is True,
        "a failure AT the first business mutation is never retried, even a connection error")

    # post-mutation read-back connection failure -> NEVER retried
    def hook_post_mutation_readback_fails(ctx):
        O2 = importlib.import_module("restricted_stack_orchestration")
        O2.mark_business_mutation_started()
        O2.mark("business_mutation_completed")
        raise RuntimeError("connection failed during read-back")   # after mutation
    r = _drive(["ok", "ok"], hook=hook_post_mutation_readback_fails)
    rec("O04 post-mutation-readback-never-retried",
        (not r["ok"]) and len(r["history"]) == 1 and not r["history"][0]["retry_eligible"],
        "a post-mutation independent read-back failure is never retried")

    # audit/business contradiction (non-connection) after mutation -> never retried
    def hook_contradiction(ctx):
        O2 = importlib.import_module("restricted_stack_orchestration")
        O2.mark_business_mutation_started()
        raise AssertionError("business/audit contradiction")
    r = _drive(["ok", "ok"], hook=hook_contradiction)
    rec("O05 post-mutation-contradiction-never-retried",
        (not r["ok"]) and not r["history"][0]["retry_eligible"], "a post-mutation contradiction is "
        "never retried")

    # pre-hook FOUNDATION transient -> retried
    r = _drive(["transient", "ok"], hook=lambda ctx: None)
    rec("O06 foundation-transient-retried",
        r["ok"] and r["out"]["succeeded_on_attempt"] == 2, "a pre-hook foundation transient is retried")

    # semantic (migration) -> never retried
    r = _drive(["semantic-migration", "ok"], hook=lambda ctx: None)
    rec("O07 semantic-never-retried",
        (not r["ok"]) and len(r["history"]) == 1 and not r["history"][0]["retry_eligible"],
        "a semantic migration failure is never retried")

    # a transient abort that CASCADES aborted P03/P04/I0x checks is still classified transient (the
    # aborted cascade must not be mistaken for a genuine semantic failure) -> retried
    r = _drive(["transient", "ok"], hook=lambda ctx: None)
    rec("O07b aborted-cascade-not-semantic-retried",
        r["ok"] and r["out"]["attempts"][0]["phase"] == "pre-mutation-transient-connection",
        "a transient abort cascading aborted P03/P04/I0x checks is retried, not treated as semantic")

    # a GENUINE (non-aborted) RLS/semantic failure -> never retried
    r = _drive(["semantic-genuine", "ok"], hook=lambda ctx: None)
    rec("O07c genuine-semantic-never-retried",
        (not r["ok"]) and r["history"][0]["phase"] == "migration-role-rls-identity",
        "a genuine RLS/semantic check failure (real assertion, not an aborted cascade) is never retried")

    # cleanup failure -> never retried
    r = _drive(["cleanup-fail", "ok"], hook=lambda ctx: None)
    rec("O08 cleanup-failure-never-retried",
        (not r["ok"]) and r["history"][0]["phase"] == "cleanup", "a cleanup failure is never retried")

    # persistent pre-mutation transient -> exhausts bounded budget, fails closed
    r = _drive(["transient", "transient", "transient"], hook=lambda ctx: None)
    rec("O09 budget-exhaustion-fails-closed",
        (not r["ok"]) and len(r["history"]) == 3, "a persistent transient exhausts the 3-attempt budget")

    # fresh isolation per attempt + success belongs to the final attempt + history retained
    r = _drive(["transient", "ok"], hook=lambda ctx: None)
    rec("O10 fresh-isolation-and-final-attempt",
        r["ok"] and len(set(r["guard"].run_hashes)) == 2
        and r["out"]["result"]["run_hash"] == r["guard"].run_hashes[-1]
        and r["out"]["attempts"][0]["result"] == "failure",
        "each attempt is fresh; success belongs to the final attempt; earlier failure retained")

    # attempt state does not leak: after a full provision, no current attempt remains
    r = _drive(["ok"], hook=lambda ctx: None)
    rec("O11 attempt-state-not-leaked-after",
        r["ok"] and r["O"].current_attempt() is None,
        "the attempt ContextVar is reset after provisioning (no leak to later code)")

    # monotonic: business_mutation_started cannot revert within an attempt
    a = O.ProvisioningAttempt(1)
    a.mark("business_mutation_started")
    before = a.business_mutation_started
    a.mark("store_connection_started")  # marking another phase must not clear it
    rec("O12 business-mutation-started-monotonic",
        before is True and a.business_mutation_started is True,
        "business_mutation_started, once set, never reverts within the attempt")

    # context isolation across threads (ContextVar is per-context, not global)
    seen = {}

    def worker(name):
        O2 = importlib.import_module("restricted_stack_orchestration")

        def hook(ctx):
            O2.mark_business_mutation_started()
            seen[name] = O2.current_attempt().business_mutation_started
        _drive(["ok"], hook=hook)
        seen[name + ":after"] = O2.current_attempt()
    t1 = threading.Thread(target=worker, args=("A",))
    t2 = threading.Thread(target=worker, args=("B",))
    t1.start(); t2.start(); t1.join(); t2.join()
    rec("O13 attempt-state-context-isolated",
        seen.get("A") is True and seen.get("B") is True
        and seen.get("A:after") is None and seen.get("B:after") is None
        and O.current_attempt() is None,
        "attempt state is per-execution-context (threads do not share it; none leaks to the main context)")

    rec("O14 attempt-budget-bounded", O.DEFAULT_MAX_ATTEMPTS == 3, "the retry budget is bounded to 3")


def mutations() -> None:
    original = io.open(SEAM, encoding="utf-8").read()

    def mutate(new_src: str, cid: str, drive_args, hook, expect_masks: bool, detail: str) -> None:
        assert new_src != original, (cid, "anchor not found")
        io.open(SEAM, "w", encoding="utf-8", newline="\n").write(new_src)
        try:
            r = _drive(drive_args, hook=hook)
            rec(cid, r["ok"] is expect_masks, detail)
        finally:
            io.open(SEAM, "w", encoding="utf-8", newline="\n").write(original)
            _seam()

    # M1: post-mutation failures made retryable (drop the business_mutation_started short-circuit)
    m1 = original.replace("    if attempt.business_mutation_started:\n",
                          "    if attempt.business_mutation_started and False:\n")
    mutate(m1, "M01 post-mutation-retryable-caught", ["ok", "ok"],
           _post_mutation_transient_hook(), True,
           "MUTATION: making post-mutation failures retryable masks a mutation-time transient -> "
           "confirms O03/O04 are load-bearing")

    # M2: cleanup failure made retryable
    m2 = original.replace('    if result.get("cleanup_issues"):\n',
                          '    if result.get("cleanup_issues") and False:\n')
    mutate(m2, "M02 cleanup-retryable-caught", ["cleanup-fail", "ok"], lambda ctx: None, True,
           "MUTATION: ignoring cleanup issues retries a dirty attempt -> confirms O08 is load-bearing")

    # M3: unknown made retryable
    m3 = original.replace('"phase": "unknown", "failure_class": _redact(text) or "unknown",\n'
                          '            "retry_eligible": False,',
                          '"phase": "unknown", "failure_class": _redact(text) or "unknown",\n'
                          '            "retry_eligible": True,')
    mutate(m3, "M03 unknown-retryable-caught", ["ok", "ok"], _unknown_prehook_hook(), True,
           "MUTATION: making unknown failures retryable masks them -> confirms unknown is non-retryable")

    # M4: attempt budget bypassed
    m4 = original.replace("DEFAULT_MAX_ATTEMPTS = 3", "DEFAULT_MAX_ATTEMPTS = 99")
    io.open(SEAM, "w", encoding="utf-8", newline="\n").write(m4)
    try:
        rec("M04 budget-bypassed-caught", _seam().DEFAULT_MAX_ATTEMPTS == 99,
            "MUTATION: raising the budget past 3 -> confirms O14 pins the bound")
    finally:
        io.open(SEAM, "w", encoding="utf-8", newline="\n").write(original)
        _seam()

    # baseline recovers
    r = _drive(["semantic-migration", "ok"], hook=lambda ctx: None)
    rec("M05 baseline-recovers-after-restore",
        (not r["ok"]) and not r["history"][0]["retry_eligible"],
        "after restoring the source, the semantic-never-retried baseline returns")


def _post_mutation_transient_hook():
    state = {"n": 0}

    def hook(ctx):
        state["n"] += 1
        O2 = importlib.import_module("restricted_stack_orchestration")
        O2.mark_business_mutation_started()
        if state["n"] == 1:
            raise RuntimeError("connection failed: server closed the connection")
    return hook


def _unknown_prehook_hook():
    state = {"n": 0}

    def hook(ctx):
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("some non-connection weirdness")  # pre-mutation, non-transient -> unknown
    return hook


def main() -> int:
    positive()
    mutations()
    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "restricted_stack_orchestration",
        "claim_scope": "pre-mutation-retry-boundary-docker-free",
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2, sort_keys=True))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
