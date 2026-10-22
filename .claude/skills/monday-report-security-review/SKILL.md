---
name: monday-report-security-review
description: >-
  Independent adversarial security review for Monday Report increments. INVOKE
  when reviewing a change for acceptance, acting as the independent reviewer, or
  deciding whether evidence actually proves a security property. Triggers:
  "review this PR", "is this ready to merge", "0C/0H", "counterexample",
  "code defect vs evidence defect", "the guard says it passes". Enforces
  builder != reviewer and RAW 0C/0H acceptance.
---

# Monday Report — adversarial security review

Acceptance is earned by an **independent, fresh-context** reviewer who re-derives
the property and tries to break it — never by the builder's own say-so.

## Rules
- **Builder != reviewer.** The person/agent who wrote the change does not certify
  it. Review from a fresh context: read the diff at the **exact head that will
  merge**, re-derive what "correct" means from the resolution condition, then
  attack it. A review of an earlier head does not carry forward. See
  [[monday-report-git-pr]].
- **RAW 0C/0H is the bar**: zero Critical, zero High findings, raw (not "after
  mitigations we'll do later"). Lows may be recorded and deferred.
- **Construct and EXECUTE counterexamples.** Don't reason that a control holds —
  build the malicious input and run it: cross-tenant IDOR (must be existence-
  hiding 404), idempotency-key replay (no double write), forged/truncated audit
  event (must be detected), permission bypass (default-deny), signed-URL tamper,
  EICAR/macro upload (blocked), path traversal in storage keys.

## Code defect vs evidence defect (name which one)
This project's recurring failure mode is an **evidence defect**: the check
measures something *adjacent* to the real call, or a verifier certifies a property
it did not observe. Distinguish precisely:
- **Code defect** — the behavior is wrong (a lost write, a missing tenant compare,
  an unkeyed audit append).
- **Evidence defect** — the code may be fine but the proof is invalid: measuring
  `payload->'monday_reports'` (a deliberately-blanked projection) instead of the
  authority table; a regex/lexical check standing in for execution scope; a
  screenshot standing in for a persisted effect; a guard that passes against a
  proxy rather than the real route/head/context.
- **Never let a verifier certify a property it did not observe.** If the probe
  didn't execute the real route and read the real effect, the property is
  unproven — regardless of a green result. Expect a fix to be incomplete along a
  new axis; re-review the next head rather than trusting the previous pass.

## What to check every time
- Fail-closed defaults intact (503/403/404-existence-hiding, default-deny RBAC,
  client-mode key required).
- Tenant boundary: request tenant only from server identity; parent-link graph
  fails closed; lists tenant-filtered before counting. See [[monday-report-backend-api]].
- Audit integrity: keyed HMAC, no unkeyed append after keying, redaction (no raw
  source/corrected/reason leakage). See [[monday-report-evidence-certification]].
- Secrets: no credentials/keys in snapshot, logs, errors, or evidence.
- Evidence binding: bound to the exact head/tree/context; stale evidence fails
  closed. See [[monday-report-evidence-certification]].

## Non-goals / safety
- A green guard is not acceptance; independent execution of counterexamples is.
- Do not self-approve, and do not accept "presence of a method" as proof.
- Windows/offline privilege claims need live-elevated proof — see
  [[monday-report-offline-windows]].
