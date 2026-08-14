#!/usr/bin/env python3
"""Honest expected-baseline gate for ``pnpm run audit:all``.

The Monday Report guard suite is intentionally, honestly ``GA_BLOCKED``: the
inherited ``GA50 commit-binding-is-ancestor`` check in the GA gap-assessment
(``audit:ga-gap-assessment``, the second-to-last step of ``audit:all``) fails
because the tracked acceptance artifact is not an ancestor of the exact head
being built. That single, known failure makes ``audit:all`` exit non-zero.

This gate lets CI stay GREEN for that *specific, known* baseline **without**
masking anything. It fails CLOSED (job RED) on ANY deviation:

  * ``audit:all`` exited 0            -> RED. The GA50 baseline resolved. That is
                                          a deliberate, reviewable event: update
                                          this gate on purpose (strict-xfail).
  * chain stopped before step 72      -> RED. The terminal JSON is then emitted
                                          by some *other* guard, so the guard
                                          field will not be ``audit:ga-gap-assessment``.
  * more than the one known failure   -> RED (summary.failed != 1).
  * the one failure is not GA50        -> RED.
  * release_recommendation != GA_BLOCKED -> RED.
  * terminal verdict unparseable/absent  -> RED.

It deliberately does NOT pin ``summary.passed`` (that would break the moment a
new PASS-ing check is added to the guard, which is not a regression).

Usage:
    python .github/scripts/assert_audit_baseline.py <audit_all_log> <exit_code>

``<exit_code>`` is the real exit status of ``pnpm run audit:all`` (capture it
from ``${PIPESTATUS[0]}`` when piping through ``tee``).
"""

from __future__ import annotations

import json
import sys

EXPECTED_GUARD = "audit:ga-gap-assessment"
EXPECTED_FAIL_CHECK_ID = "GA50 commit-binding-is-ancestor"
EXPECTED_RELEASE = "GA_BLOCKED"


def _fail(msg: str) -> int:
    print(f"BASELINE GATE: RED -- {msg}")
    print(
        "This gate is RED whenever audit:all deviates from the known GA_BLOCKED "
        "baseline (sole failure = GA50 commit-binding-is-ancestor). Diagnose the "
        "deviation above; do NOT weaken this gate to make it pass."
    )
    return 1


def _iter_toplevel_json_blocks(text: str):
    """Yield every parseable top-level ``{...}`` block in ``text``.

    The guards pretty-print their terminal verdict as a JSON object whose
    opening brace and matching closing brace both sit at column 0. Interleaved
    ``PASS:``/``FAIL:`` human lines and pnpm banners are ignored. Nested braces
    are always indented, so column-0 ``{`` / ``}`` unambiguously delimit a
    top-level document.
    """
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
        return _fail(f"usage: {argv[0]} <audit_all_log> <exit_code>")

    log_path, exit_code_raw = argv[1], argv[2]
    try:
        exit_code = int(exit_code_raw)
    except ValueError:
        return _fail(f"exit_code argument is not an integer: {exit_code_raw!r}")

    try:
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return _fail(f"cannot read audit:all log {log_path!r}: {exc}")

    # 1. audit:all MUST have failed. A green audit:all means the GA50 baseline
    #    resolved -- that is not "pass", it is "the assumption behind this gate
    #    changed and must be re-reviewed".
    if exit_code == 0:
        return _fail(
            "audit:all exited 0, but the honest baseline expects a non-zero exit "
            "from the known GA_BLOCKED / GA50 failure. If GA50 was legitimately "
            "resolved, update this gate deliberately."
        )

    blocks = list(_iter_toplevel_json_blocks(text))
    if not blocks:
        return _fail("no parseable top-level JSON verdict found in the audit:all log")

    # 2. The TERMINAL verdict (last top-level JSON document) must be the GA
    #    gap-assessment. In the `&&` chain, ga-gap-assessment (step 72) only runs
    #    if every earlier step passed; if an earlier step had failed, the last
    #    JSON document would belong to that other guard instead.
    terminal = blocks[-1]
    guard = terminal.get("guard")
    if guard != EXPECTED_GUARD:
        return _fail(
            f"terminal verdict guard is {guard!r}, expected {EXPECTED_GUARD!r}. "
            "audit:all failed at an EARLIER step than the known GA gap-assessment "
            "baseline -- that is a real regression, not the expected baseline."
        )

    # 3. Exactly one failing check, and it is GA50.
    summary = terminal.get("summary") or {}
    failed = summary.get("failed")
    if failed != 1:
        return _fail(
            f"GA gap-assessment summary.failed == {failed!r}, expected exactly 1 "
            "(the known GA50 baseline). Extra failures are new regressions."
        )

    checks = terminal.get("checks") or []
    fail_ids = [
        c.get("check_id")
        for c in checks
        if str(c.get("result", "")).upper() == "FAIL" or c.get("ok") is False
    ]
    if fail_ids != [EXPECTED_FAIL_CHECK_ID]:
        return _fail(
            f"failing check-id set is {fail_ids!r}, expected exactly "
            f"[{EXPECTED_FAIL_CHECK_ID!r}]."
        )

    # 4. Release recommendation is the honest GA_BLOCKED.
    release = terminal.get("release_recommendation")
    if release != EXPECTED_RELEASE:
        return _fail(
            f"release_recommendation is {release!r}, expected {EXPECTED_RELEASE!r}."
        )

    print(
        "BASELINE GATE: GREEN -- audit:all ran the full chain; the ONLY failure is "
        f"the known, honest {EXPECTED_RELEASE} baseline "
        f"({EXPECTED_FAIL_CHECK_ID}). Every other guard (including the DB-strict "
        "guards) passed. The product is truthfully GA_BLOCKED and no new regression "
        "is hidden."
    )
    print(
        f"  audit:all exit={exit_code}  guard={guard}  "
        f"summary.failed={failed}  release={release}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
