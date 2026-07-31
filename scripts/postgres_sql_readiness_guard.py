"""audit:postgres-sql-readiness -- deterministic, Docker-free proof of the Layer-1 connection-stability
probe (``restricted_postgres_startup_guard.wait_for_stable_sql_connection``).

Drives the REAL helper with a MOCK psycopg that scripts connection outcomes, so the retry/deadline
contract is exercised without Docker: a transient connection-establishment failure is polled until a
real ``SELECT 1`` succeeds within a bounded deadline; authentication / permission / missing-object /
unknown failures fail closed with no retry; the deadline is bounded; the connection is always closed;
the history is redacted. Source mutations prove each guarantee is load-bearing. Also asserts
structurally that the probe runs BEFORE any semantic bootstrap in run_stack. Prints JSON; exits
non-zero on failure.
"""
from __future__ import annotations

import ast
import importlib
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

GUARD = ROOT / "scripts" / "restricted_postgres_startup_guard.py"
CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str = "") -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL", "detail": detail})


class FakeConn:
    def __init__(self):
        self.closed = False
        self.executed = []

    def execute(self, sql):
        self.executed.append(sql)

    def close(self):
        self.closed = True


class FakePsycopg:
    """Scripts psycopg.connect() outcomes: 'ok' | 'transient' | 'auth' | 'perm' | 'unknown'."""

    def __init__(self, script: list[str]):
        self.script = script
        self.i = 0
        self.conns: list[FakeConn] = []

    def connect(self, dsn, autocommit=True, connect_timeout=5):
        kind = self.script[self.i] if self.i < len(self.script) else "ok"
        self.i += 1
        if kind == "ok":
            c = FakeConn()
            self.conns.append(c)
            return c
        if kind == "transient":
            raise RuntimeError("connection failed: server closed the connection")
        if kind == "timeout":
            raise RuntimeError("connection to server at \"h\" failed: timeout expired")
        if kind == "auth":
            raise RuntimeError("password authentication failed for user")
        if kind == "perm":
            raise RuntimeError("permission denied for database")
        raise ValueError("some unexpected internal error")


def _with_fake(script, **kw):
    """Run wait_for_stable_sql_connection with a fake psycopg; returns (result-or-exc, fake)."""
    G = importlib.import_module("restricted_postgres_startup_guard")
    fake = FakePsycopg(script)
    saved = sys.modules.get("psycopg")
    sys.modules["psycopg"] = fake
    try:
        try:
            hist = G.wait_for_stable_sql_connection("postgresql://x:y@127.0.0.1:5/z", **kw)
            return {"ok": True, "history": hist, "fake": fake}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "exc": exc, "fake": fake}
    finally:
        if saved is not None:
            sys.modules["psycopg"] = saved
        else:
            sys.modules.pop("psycopg", None)


def positive() -> None:
    # pg_isready ok, first SQL connect transiently closes, later connection succeeds
    r = _with_fake(["transient", "ok"], deadline_seconds=5.0, poll_seconds=0.01)
    rec("SR01 transient-then-connected",
        r["ok"] and [h["outcome"] for h in r["history"]] == ["transient", "connected"],
        "a transient first connect is polled until a real SELECT 1 succeeds")

    # multiple transient failures succeed before the deadline
    r = _with_fake(["transient", "transient", "transient", "ok"], deadline_seconds=5.0, poll_seconds=0.01)
    rec("SR02 multiple-transient-then-connected",
        r["ok"] and r["history"][-1]["outcome"] == "connected" and len(r["history"]) == 4,
        "several transient failures recover before the deadline")

    # transient failures exhaust the deadline and fail closed
    r = _with_fake(["transient"] * 50, deadline_seconds=0.05, poll_seconds=0.02)
    rec("SR03 deadline-exhaustion-fails-closed",
        (not r["ok"]) and "deadline" in str(r["exc"]).lower(),
        "persistent transient failures exhaust the bounded deadline and fail closed")

    # authentication failure is NOT retried
    r = _with_fake(["auth", "ok"], deadline_seconds=5.0, poll_seconds=0.01)
    rec("SR04 auth-not-retried",
        (not r["ok"]) and r["fake"].i == 1 and "non-transient" in str(r["exc"]).lower(),
        "an authentication failure fails closed on the first attempt, never retried")

    # permission failure is NOT retried
    r = _with_fake(["perm", "ok"], deadline_seconds=5.0, poll_seconds=0.01)
    rec("SR05 permission-not-retried",
        (not r["ok"]) and r["fake"].i == 1, "a permission failure is never retried")

    # unknown error is NOT retried
    r = _with_fake(["unknown", "ok"], deadline_seconds=5.0, poll_seconds=0.01)
    rec("SR06 unknown-not-retried",
        (not r["ok"]) and r["fake"].i == 1, "an unknown error is never retried")

    # successful probe closes its connection
    r = _with_fake(["ok"], deadline_seconds=5.0, poll_seconds=0.01)
    rec("SR07 success-closes-connection",
        r["ok"] and r["fake"].conns and all(c.closed for c in r["fake"].conns)
        and r["fake"].conns[-1].executed == ["select 1"],
        "the successful probe runs SELECT 1 and closes the connection")

    # transient recovery still closes the eventually-opened connection
    r = _with_fake(["transient", "ok"], deadline_seconds=5.0, poll_seconds=0.01)
    rec("SR08 recovered-connection-closed",
        r["ok"] and all(c.closed for c in r["fake"].conns) and len(r["fake"].conns) == 1,
        "after a transient recovery, the opened connection is closed cleanly")

    # attempt history is redacted (no DSN / password / port substrings)
    r = _with_fake(["transient", "ok"], deadline_seconds=5.0, poll_seconds=0.01)
    blob = json.dumps(r["history"])
    rec("SR09 history-redacted",
        "postgresql://" not in blob and ":y@" not in blob and "127.0.0.1" not in blob,
        "the returned attempt history carries no DSN/credential/endpoint")

    # a libpq connect_timeout expiry ("timeout expired") is transient and recovers
    r = _with_fake(["timeout", "ok"], deadline_seconds=5.0, poll_seconds=0.01)
    rec("SR11 connect-timeout-expiry-transient",
        r["ok"] and [h["outcome"] for h in r["history"]] == ["transient", "connected"],
        "a libpq connect_timeout expiry during slow bring-up is transient and recovers")

    # STRUCTURAL: the stability probe runs BEFORE any semantic bootstrap in run_stack
    src = io.open(GUARD, encoding="utf-8").read()
    tree = ast.parse(src)
    run_stack = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "run_stack")
    probe_line = mig_line = None
    for n in ast.walk(run_stack):
        if isinstance(n, ast.Call):
            fn = n.func
            if isinstance(fn, ast.Name) and fn.id == "wait_for_stable_sql_connection" and probe_line is None:
                probe_line = n.lineno
            if isinstance(fn, ast.Attribute) and fn.attr == "apply_migrations" and mig_line is None:
                mig_line = n.lineno
    rec("SR10 probe-before-semantic-bootstrap",
        probe_line is not None and mig_line is not None and probe_line < mig_line,
        "the SQL-stability probe is invoked before migrations/roles (semantic bootstrap)")


def mutations() -> None:
    original = io.open(GUARD, encoding="utf-8").read()

    def run_mutation(new_src: str, cid: str, script, expect_masks: bool, detail: str, **kw) -> None:
        assert new_src != original, (cid, "anchor not found")
        io.open(GUARD, "w", encoding="utf-8", newline="\n").write(new_src)
        importlib.reload(sys.modules["restricted_postgres_startup_guard"])  # activate the mutation
        try:
            r = _with_fake(script, **kw)
            rec(cid, (r["ok"] is expect_masks), detail)
        finally:
            io.open(GUARD, "w", encoding="utf-8", newline="\n").write(original)
            importlib.import_module("restricted_postgres_startup_guard")
            importlib.reload(sys.modules["restricted_postgres_startup_guard"])

    # M1: auth made retryable -> auth failure would be polled to success (masked)
    m1 = original.replace('if klass != "transient":\n', 'if klass not in ("transient", "auth"):\n')
    run_mutation(m1, "M01 auth-retryable-caught", ["auth", "ok"], True,
                 "MUTATION: retrying auth failures masks them -> SR04 is load-bearing",
                 deadline_seconds=5.0, poll_seconds=0.01)

    # M2: unknown made retryable
    m2 = original.replace('        klass = _classify_connect_error(str(exc))\n',
                          '        klass = "transient"  # mutated\n')
    run_mutation(m2, "M02 unknown-retryable-caught", ["unknown", "ok"], True,
                 "MUTATION: classifying everything transient masks unknown -> SR06 is load-bearing",
                 deadline_seconds=5.0, poll_seconds=0.01)

    # M3: connection not closed
    m3 = original.replace("            finally:\n                conn.close()   # close cleanly",
                          "            finally:\n                pass  # mutated: not closed")
    if m3 != original:
        io.open(GUARD, "w", encoding="utf-8", newline="\n").write(m3)
        importlib.reload(sys.modules["restricted_postgres_startup_guard"])
        try:
            r = _with_fake(["ok"], deadline_seconds=5.0, poll_seconds=0.01)
            rec("M03 connection-not-closed-caught",
                r["ok"] and not all(c.closed for c in r["fake"].conns),
                "MUTATION: dropping conn.close() leaves the connection open -> SR07 is load-bearing")
        finally:
            io.open(GUARD, "w", encoding="utf-8", newline="\n").write(original)
            importlib.reload(sys.modules["restricted_postgres_startup_guard"])
    else:
        rec("M03 connection-not-closed-caught", False, "anchor not found")

    # M4: deadline bypassed (success after deadline) -> persistent transient would loop unbounded;
    # simulate by removing the deadline check so it would not fail closed within the deadline.
    m4 = original.replace("            if elapsed + poll_seconds >= deadline_seconds:\n",
                          "            if False and elapsed + poll_seconds >= deadline_seconds:\n")
    if m4 != original:
        io.open(GUARD, "w", encoding="utf-8", newline="\n").write(m4)
        importlib.reload(sys.modules["restricted_postgres_startup_guard"])
        try:
            # a bounded script that ends in ok -> with the deadline removed it still returns ok even
            # though the deadline should have tripped first; prove the baseline WOULD have failed.
            r = _with_fake(["transient"] * 6 + ["ok"], deadline_seconds=0.05, poll_seconds=0.02)
            rec("M04 deadline-bypassed-caught", r["ok"] is True,
                "MUTATION: removing the deadline check lets a would-be-exhausted probe succeed -> "
                "SR03 is load-bearing")
        finally:
            io.open(GUARD, "w", encoding="utf-8", newline="\n").write(original)
            importlib.reload(sys.modules["restricted_postgres_startup_guard"])
    else:
        rec("M04 deadline-bypassed-caught", False, "anchor not found")

    # baseline recovers
    importlib.reload(sys.modules["restricted_postgres_startup_guard"])
    r = _with_fake(["auth", "ok"], deadline_seconds=5.0, poll_seconds=0.01)
    rec("M05 baseline-recovers-after-restore",
        (not r["ok"]) and r["fake"].i == 1,
        "after restoring the source, auth-never-retried baseline returns")


def main() -> int:
    positive()
    mutations()
    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "postgres_sql_readiness",
        "claim_scope": "layer1-sql-readiness-docker-free",
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2, sort_keys=True))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
