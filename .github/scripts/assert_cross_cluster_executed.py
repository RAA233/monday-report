#!/usr/bin/env python3
"""Fail-closed assertion that verification_boundary check 41 ACTUALLY EXECUTED.

`verification_boundary_guard.py` check 41 ("an attestation CLONED to another
cluster does not activate") is a real security boundary. When the second,
independent Postgres cluster is absent (``MONDAY_REPORT_TEST_DATABASE_URL_B``
unset, non-loopback, or a different database name) the guard records that check
``skipped=True, ok=True`` and still exits 0 -- a SILENT PASS. In CI we provision
cluster B on purpose, so a skipped check 41 means the cross-cluster boundary was
never exercised and MUST fail the job.

This gate is RED (exit 1) when:
  * the guard exited non-zero (a real check failed -- diagnose it),
  * no parseable JSON verdict with a ``checks`` array is present,
  * check 41 is absent from the verdict,
  * check 41 is recorded ``skipped`` (cross-cluster evidence not exercised),
  * check 41 is recorded not-``ok`` (the boundary did not hold).

It does NOT weaken the guard; it only refuses to accept a skipped cross-cluster
result as coverage.

Usage:
    python .github/scripts/assert_cross_cluster_executed.py <vb_log> <exit_code>
"""

from __future__ import annotations

import json
import sys

CHECK_41_PREFIX = "41 "


def _fail(msg: str) -> int:
    print(f"CROSS-CLUSTER GATE: RED -- {msg}")
    print(
        "verification_boundary check 41 (cross-cluster attestation rejection) must "
        "EXECUTE against the second Postgres cluster (MONDAY_REPORT_TEST_DATABASE_URL_B). "
        "A skipped/absent/failed check 41 is not coverage. Diagnose above; do NOT "
        "weaken the guard or drop the second cluster to make this pass."
    )
    return 1


def _iter_toplevel_json_blocks(text: str):
    """Yield every parseable top-level ``{...}`` block (column-0 braces)."""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line == "{":
            start = i
        elif line == "}" and start is not None:
            block = "\n".join(lines[start : i + 1])
            start = None
            try:
                yield json.loads(block)
            except json.JSONDecodeError:
                continue


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        return _fail(f"usage: {argv[0]} <vb_log> <exit_code>")

    log_path, exit_code_raw = argv[1], argv[2]
    try:
        exit_code = int(exit_code_raw)
    except ValueError:
        return _fail(f"exit_code argument is not an integer: {exit_code_raw!r}")

    # A non-zero guard exit means a real check failed -- that is a RED to diagnose,
    # never something this gate should paper over.
    if exit_code != 0:
        return _fail(
            f"verification_boundary_guard exited {exit_code} (a real check failed)."
        )

    try:
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return _fail(f"cannot read verification-boundary log {log_path!r}: {exc}")

    verdicts = [b for b in _iter_toplevel_json_blocks(text) if isinstance(b, dict) and "checks" in b]
    if not verdicts:
        return _fail("no parseable JSON verdict with a 'checks' array found")

    checks = verdicts[-1].get("checks") or []
    matches = [c for c in checks if str(c.get("name", "")).startswith(CHECK_41_PREFIX)]
    if not matches:
        return _fail("check 41 (cross-cluster) is absent from the verdict")
    if len(matches) != 1:
        return _fail(f"expected exactly one check 41, found {len(matches)}")

    c41 = matches[0]
    if c41.get("skipped") is True:
        return _fail(
            "check 41 was SKIPPED -- the second cluster "
            "(MONDAY_REPORT_TEST_DATABASE_URL_B) was not exercised. "
            f"detail: {c41.get('detail')!r}"
        )
    if c41.get("ok") is not True:
        return _fail(f"check 41 did not hold (ok={c41.get('ok')!r}); the boundary failed")

    print(
        "CROSS-CLUSTER GATE: GREEN -- check 41 EXECUTED against the second cluster "
        f"and the boundary held: {c41.get('name')!r}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
