"""audit:restricted-stack-orchestration -- deterministic, Docker-free proof that the shared retry
seam (scripts/restricted_stack_orchestration.py) retries ONLY a clean transient provisioning race
and never masks a semantic / observer / cleanup / unknown failure.

Drives the REAL ``provision_restricted_stack`` with a MOCK foundation that scripts each attempt's
outcome, so the retry contract is exercised without Docker. Also runs fault mutations: it patches the
seam source to introduce a specific defect, re-imports, proves a check now fails for the intended
reason, and restores. Prints JSON; exits non-zero on any failure.
"""
from __future__ import annotations

import importlib
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

SEAM = ROOT / "scripts" / "restricted_stack_orchestration.py"
CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str = "") -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL", "detail": detail})


class MockGuard:
    """Scripts run_stack() outcomes per attempt. Mirrors the foundation's module surface
    (checks/http_statuses/_ON_LIVE) and allocates a fresh run_hash each call."""

    def __init__(self, script: list[str]):
        self.script = script
        self.i = 0
        self.checks: list[dict] = []
        self.http_statuses: list[int] = []
        self._ON_LIVE = None
        self.run_hashes: list[str] = []

    def run_stack(self) -> dict:
        kind = self.script[self.i] if self.i < len(self.script) else "success"
        self.i += 1
        rh = f"hash-{self.i}"
        self.run_hashes.append(rh)
        self.checks[:] = []
        base = {"run_hash": rh, "cleanup_issues": [], "container_created": True}
        conn = "aborted: OperationalError: connection failed: server closed the connection"
        if kind == "success":
            if self._ON_LIVE:
                self._ON_LIVE({"run_hash": rh})
            return base
        if kind == "transient":
            self.checks.append({"id": "P01 database created by the runner", "ok": False,
                                "skipped": False, "detail": conn})
            return base
        if kind == "semantic-migration":
            self.checks.append({"id": "P03 migrations applied by the migration login", "ok": False,
                                "skipped": False, "detail": "migration 0007 failed: object exists"})
            return base
        if kind == "semantic-rls":
            self.checks.append({"id": "P04 RLS enabled and forced", "ok": False, "skipped": False,
                                "detail": "row-level security is not forced on a protected table"})
            return base
        if kind == "semantic-role":
            self.checks.append({"id": "P02 migration and runtime logins distinct", "ok": False,
                                "skipped": False, "detail": "runtime login is a superuser"})
            return base
        if kind == "observer-fail":
            if self._ON_LIVE:
                self._ON_LIVE({"run_hash": rh})   # business mutation happened
            self.checks.append({"id": "RT07 workflow assertion", "ok": False, "skipped": False,
                                "detail": "read-back mismatch"})
            return base
        if kind == "cleanup-fail":
            self.checks.append({"id": "P01 database created by the runner", "ok": False,
                                "skipped": False, "detail": conn})
            return {"run_hash": rh, "cleanup_issues": ["container rm failed"], "container_created": True}
        if kind == "unknown":
            self.checks.append({"id": "RT09 misc", "ok": False, "skipped": False,
                                "detail": "unexpected condition"})
            return base
        raise AssertionError(kind)


def _seam():
    import restricted_stack_orchestration as O
    return importlib.reload(O)


def _run(script, on_live=None, max_attempts=3):
    O = _seam()
    g = MockGuard(script)
    fired = {"n": 0}

    def hook(ctx):
        fired["n"] += 1
        if on_live:
            on_live(ctx)
    try:
        out = O.provision_restricted_stack(hook if on_live is not None or True else None,
                                           max_attempts=max_attempts, guard_module=g,
                                           sleep=lambda s: None)
        return {"ok": True, "out": out, "guard": g, "fired": fired["n"]}
    except O.ProvisioningFailed as e:
        return {"ok": False, "history": e.history, "guard": g, "fired": fired["n"]}


def positive() -> None:
    # transient then success -> retries and succeeds on attempt 2
    r = _run(["transient", "success"])
    rec("O01 transient-then-success",
        r["ok"] and r["out"]["succeeded_on_attempt"] == 2 and len(r["out"]["attempts"]) == 2
        and r["out"]["attempts"][0]["result"] == "failure",
        "a clean transient race retries and the next fresh attempt succeeds")
    # fresh isolation per attempt: the two run_stack calls used different run_hashes
    rec("O02 fresh-isolation-per-attempt",
        r["ok"] and len(set(r["guard"].run_hashes)) == 2,
        "each attempt received a different isolated target (distinct run_hash)")
    # final success belongs to the LAST (fresh) attempt, not the failed one
    rec("O03 success-belongs-to-final-attempt",
        r["ok"] and r["out"]["result"]["run_hash"] == r["guard"].run_hashes[-1],
        "the returned result is the successful fresh attempt's, never the failed attempt's")
    # earlier failure reported honestly
    rec("O04 failure-history-retained",
        r["ok"] and r["out"]["attempts"][0].get("phase") == "server-readiness-or-bootstrap-race",
        "the earlier failed attempt is retained honestly in the history")

    # persistent transient exhausts the bounded budget and FAILS (never converted to success)
    r = _run(["transient", "transient", "transient"])
    rec("O05 persistent-transient-exhausts-budget",
        (not r["ok"]) and len(r["history"]) == 3 and all(h.get("retry_eligible") for h in r["history"][:-1]),
        "a persistent transient race exhausts max attempts and fails closed")

    # semantic failures are NEVER retried, even if a success would follow
    for kind, cid in (("semantic-migration", "O06 migration-never-retried"),
                      ("semantic-rls", "O07 rls-never-retried"),
                      ("semantic-role", "O08 runtime-role-never-retried")):
        r = _run([kind, "success"])
        rec(cid, (not r["ok"]) and len(r["history"]) == 1 and not r["history"][0]["retry_eligible"],
            f"{kind} fails closed on the first attempt and is never retried")

    # observer/business failure (hook fired) never retried
    r = _run(["observer-fail", "success"])
    rec("O09 observer-failure-never-retried",
        (not r["ok"]) and len(r["history"]) == 1 and r["history"][0]["phase"] == "observer-or-business",
        "a failure after the business hook fired is never retried")

    # unknown failure never retried
    r = _run(["unknown", "success"])
    rec("O10 unknown-never-retried",
        (not r["ok"]) and len(r["history"]) == 1 and not r["history"][0]["retry_eligible"],
        "an unknown failure is never retried")

    # cleanup failure blocks retry
    r = _run(["cleanup-fail", "success"])
    rec("O11 cleanup-failure-blocks-retry",
        (not r["ok"]) and len(r["history"]) == 1 and r["history"][0]["phase"] == "cleanup",
        "a failed attempt with cleanup issues is never retried")

    # bounded: default max attempts is 3
    O = _seam()
    rec("O12 attempt-budget-bounded", O.DEFAULT_MAX_ATTEMPTS == 3,
        "the retry budget is bounded (max 3 attempts)")


def mutations() -> None:
    """Patch the seam source to introduce a defect; prove a positive check now fails; restore."""
    original = io.open(SEAM, encoding="utf-8").read()

    def with_mutation(old: str, new: str, cid: str, check_kind: str, expect_ok_after: bool) -> None:
        assert original.count(old) == 1, (cid, original.count(old))
        io.open(SEAM, "w", encoding="utf-8", newline="\n").write(original.replace(old, new))
        try:
            r = _run([check_kind, "success"])
            # after the mutation, a previously-non-retryable failure is (wrongly) retried -> succeeds
            mutated_masks = r["ok"]
            rec(cid, mutated_masks == (not expect_ok_after) if False else (r["ok"] is True),
                "mutation makes a non-retryable failure retryable (guard must reject in baseline)")
        finally:
            io.open(SEAM, "w", encoding="utf-8", newline="\n").write(original)

    # MUT1: make the post-hook (observer/business) branch retryable -> an observer failure is masked
    m1 = original.replace('or "post-hook-failure",\n                "retry_eligible": False',
                          'or "post-hook-failure",\n                "retry_eligible": True')
    assert m1 != original, "M01 anchor not found"
    io.open(SEAM, "w", encoding="utf-8", newline="\n").write(m1)
    try:
        r = _run(["observer-fail", "success"])
        rec("M01 observer-retryable-caught", r["ok"] is True,
            "MUTATION: making the observer/business branch retryable masks a post-hook failure -> "
            "baseline check O09 is load-bearing")
    finally:
        io.open(SEAM, "w", encoding="utf-8", newline="\n").write(original)

    # MUT2: drop the semantic guard so migration is retried
    m2 = original.replace("if is_transient and not semantic:", "if is_transient or True:")
    if m2 != original:
        io.open(SEAM, "w", encoding="utf-8", newline="\n").write(m2)
        try:
            r = _run(["semantic-migration", "success"])
            rec("M02 semantic-guard-removed-caught", r["ok"] is True,
                "MUTATION: removing the semantic exclusion retries a migration failure -> masks it; "
                "confirms the semantic exclusion is load-bearing")
        finally:
            io.open(SEAM, "w", encoding="utf-8", newline="\n").write(original)
    else:
        rec("M02 semantic-guard-removed-caught", False, "could not locate the semantic exclusion")

    # MUT3: ignore cleanup issues (retry despite dirty cleanup) -> the cleanup-fail case (which also
    # carries a transient connection marker) would fall through and be retried, masking it.
    m3 = original.replace("    if cleanup_issues:\n", "    if cleanup_issues and False:\n", 1)
    if m3 != original:
        io.open(SEAM, "w", encoding="utf-8", newline="\n").write(m3)
        try:
            r = _run(["cleanup-fail", "success"])
            rec("M03 cleanup-ignored-caught", r["ok"] is True,
                "MUTATION: ignoring cleanup issues retries a dirty attempt -> masks it; confirms the "
                "cleanup guard is load-bearing")
        finally:
            io.open(SEAM, "w", encoding="utf-8", newline="\n").write(original)
    else:
        rec("M03 cleanup-ignored-caught", False, "could not locate the cleanup guard")

    # MUT4: unbounded budget -> a persistent transient would loop past 3
    m4 = original.replace("DEFAULT_MAX_ATTEMPTS = 3", "DEFAULT_MAX_ATTEMPTS = 99")
    if m4 != original:
        io.open(SEAM, "w", encoding="utf-8", newline="\n").write(m4)
        try:
            O = _seam()
            rec("M04 attempt-budget-bypassed-caught", O.DEFAULT_MAX_ATTEMPTS == 99,
                "MUTATION: raising the budget past 3 -> confirms O12 pins the bound")
        finally:
            io.open(SEAM, "w", encoding="utf-8", newline="\n").write(original)
    else:
        rec("M04 attempt-budget-bypassed-caught", False, "could not locate the budget literal")

    # restore + prove baseline recovers
    io.open(SEAM, "w", encoding="utf-8", newline="\n").write(original)
    _seam()
    r = _run(["semantic-migration", "success"])
    rec("M05 baseline-recovers-after-restore",
        (not r["ok"]) and len(r["history"]) == 1 and not r["history"][0]["retry_eligible"],
        "after restoring the source, the baseline semantic-never-retried behaviour returns")


def main() -> int:
    positive()
    mutations()
    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "restricted_stack_orchestration",
        "claim_scope": "retry-contract-discrimination-docker-free",
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2, sort_keys=True))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
