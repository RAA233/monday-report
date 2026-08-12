"""Guard for the HTTP disposition of a lost snapshot write (no database required).

A durable PostgreSQL mutation that loses its compare-and-swap race, or is refused
because it ran outside a protected transaction, raises ``SnapshotConflict``. The
API turns that into an HTTP response, and the *wording* of that response is a
contract:

* A **retryable** conflict (lock timeout, serialization failure) is a transient
  loss. It maps to **503** and may legitimately invite the caller to retry -- the
  identical request can succeed once contention clears.
* A **non-retryable** conflict (a definite stale-revision loss, an idempotency-key
  conflict, or the fail-closed refusal of an unprotected write) maps to **409**
  and must **not** invite a retry: replaying the identical request cannot change
  the outcome, so "please retry" would be actively misleading. This is the exact
  mislabel that let the malware-upload route's redundant ``store.save()`` surface
  as a "please retry" 409 -- a client that obeyed it would loop forever.

Neither response may leak a DSN, driver, host, port, role, revision number, SQL
fragment or filesystem path: the ``SnapshotConflict`` message is internal.

These are pure properties of the wired exception handlers, so no database is
needed and the guard never SKIPS. Run: ``python scripts/snapshot_conflict_semantics_guard.py``
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Isolate ALL state to a throwaway directory BEFORE importing the app, so building
# the store singleton at import can never touch the operator's live .local_data.
_scratch = Path(tempfile.gettempdir()) / f"mr-snapconf-{uuid.uuid4().hex[:8]}"
for _sub in ("state", "storage", "exports"):
    (_scratch / _sub).mkdir(parents=True, exist_ok=True)
os.environ["MONDAY_REPORT_REPOSITORY_BACKEND"] = "local"
os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
os.environ["MONDAY_REPORT_STATE_PATH"] = str(_scratch / "state" / "state.json")
os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(_scratch / "storage")
os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(_scratch / "exports")
os.environ["CI"] = "true"

checks: list[dict] = []


def record(name: str, ok: bool, detail: object = "") -> None:
    checks.append({"name": name, "ok": bool(ok), "detail": detail})


# Sensitive tokens that must never appear in any client-facing conflict body.
_SECRETS = (
    "postgresql://", "postgres://", "password", "secret", "127.0.0.1", "5432",
    "revision", "4711", "c:\\", "/users/", "snapshot_transaction", "for update",
    "advisory", "select ", "app.tenant", "role ", "pg_",
)


def _call(handler, exc) -> tuple[int, str]:
    resp = asyncio.run(handler(None, exc))
    body = json.loads(bytes(resp.body).decode("utf-8"))
    return resp.status_code, str(body.get("detail", ""))


def main() -> int:
    from backend.app.main import _snapshot_conflict_handler, _idempotency_conflict_handler
    from backend.app.store import SnapshotConflict, IdempotencyConflict

    # -- retryable conflict -> 503, retry is invited --------------------------
    s, d = _call(_snapshot_conflict_handler, SnapshotConflict("snapshot lock timeout", retryable=True))
    record("01 a retryable snapshot conflict maps to HTTP 503", s == 503, {"status": s, "detail": d})
    record("02 the 503 body invites a retry", "retry" in d.lower(), {"detail": d})

    # -- non-retryable conflict -> 409, retry is NOT invited ------------------
    s, d = _call(_snapshot_conflict_handler, SnapshotConflict("stale revision", retryable=False))
    record("03 a non-retryable snapshot conflict maps to HTTP 409", s == 409, {"status": s, "detail": d})
    record("04 the 409 body does NOT invite a retry (the exact malware-route mislabel)",
           "retry" not in d.lower(), {"detail": d})
    record("05 the 409 body is a stable, controlled message", d == "Snapshot write conflict", {"detail": d})

    # -- the two dispositions must materially diverge -------------------------
    s409, d409 = _call(_snapshot_conflict_handler, SnapshotConflict("stale revision", retryable=False))
    s503, d503 = _call(_snapshot_conflict_handler, SnapshotConflict("lock timeout", retryable=True))
    record("06 retryable and non-retryable produce a different status AND a different body",
           s409 != s503 and d409 != d503,
           {"non_retryable": [s409, d409], "retryable": [s503, d503]})

    # -- the fail-closed refusal of an unprotected write is non-retryable -----
    # This is the real SnapshotConflict the removed store.save() produced. Its
    # verbose internal reason must collapse to the same controlled 409 body.
    refusal = SnapshotConflict(
        "refusing an unprotected snapshot write: PostgreSQL mutations must run "
        "inside snapshot_transaction()", retryable=False)
    s, d = _call(_snapshot_conflict_handler, refusal)
    record("07 the fail-closed unprotected-write refusal maps to 409 without a retry hint",
           s == 409 and d == "Snapshot write conflict" and "retry" not in d.lower(),
           {"status": s, "detail": d})

    # -- redaction: a message embedding sensitive detail must not echo it -----
    leaky = SnapshotConflict(
        "stale revision 4711 on postgresql://app:secret@127.0.0.1:5432/db for tenant "
        "role monday_report_app at C:\\Users\\ops\\.local_data via SELECT ... FOR UPDATE",
        retryable=False)
    s, d = _call(_snapshot_conflict_handler, leaky)
    leaked = [t for t in _SECRETS if t in d.lower()]
    record("08 the 409 body leaks no DSN, credential, host, port, revision, role, SQL or path",
           s == 409 and not leaked, {"detail": d, "leaked_tokens": leaked})

    leaky_r = SnapshotConflict(
        "serialization failure on postgresql://u:p@dbhost:5432/app pg_advisory_xact_lock",
        retryable=True)
    s, d = _call(_snapshot_conflict_handler, leaky_r)
    leaked_r = [t for t in _SECRETS if t in d.lower()]
    record("09 the 503 body likewise leaks no driver, DSN or lock detail",
           s == 503 and not leaked_r, {"detail": d, "leaked_tokens": leaked_r})

    # -- idempotency conflict handler: stable 409, no stored-request leak -----
    idem = IdempotencyConflict(
        "operation op-abc reused for actor 11111111-2222-3333 with body {well: SECRETVALUE}")
    s, d = _call(_idempotency_conflict_handler, idem)
    idem_leaked = any(t in d for t in ("op-abc", "SECRETVALUE", "11111111"))
    record("10 an idempotency-key conflict maps to a stable 409", s == 409, {"status": s, "detail": d})
    record("11 the idempotency 409 body echoes no stored operation id, actor or request body",
           not idem_leaked, {"detail": d})

    passed = [c for c in checks if c["ok"]]
    failed = [c for c in checks if not c["ok"]]
    print(json.dumps({"checks": checks,
                      "summary": {"passed": len(passed), "failed": len(failed), "skipped": 0}},
                     indent=2, default=str))
    if failed:
        print(f"\nSnapshot-conflict semantics guard FAILED: {len(failed)} failing check(s).")
        for c in failed:
            print(f"  FAIL: {c['name']} -> {c['detail']}")
        return 1
    print(f"\nSnapshot-conflict semantics guard passed: {len(passed)} check(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
