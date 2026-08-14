---
name: monday-report-evidence-certification
description: >-
  Evidence binding, fail-closed certification, and stale-evidence handling for
  Monday Report. INVOKE when generating/validating evidence artifacts, binding
  proof to a head/tree/context, or reasoning about audit integrity and
  reproducibility. Triggers: "generate/verify evidence", "canonical hash", "bind
  to commit/tree", "stale evidence", "reproducible from a clean checkout",
  "exact-head seal", "audit HMAC".
---

# Monday Report — evidence & certification

Evidence is a machine-checkable artifact bound to an exact source state and
context. It fails closed. It is not the same as author commentary.

## Binding & fail-closed rules
- Evidence binds the **full 40-char commit and tree**, a **strict clean-worktree
  attestation re-checked at validation time**, a **verified canonical payload
  hash**, and the evaluated **context**. A mismatch on any of these fails closed.
- **Reproducible from the TRACKED repo alone.** The `fresh_checkout_no_local_evidence`
  context is authoritative because a fresh clone can reproduce it; a
  `verified_environment` context that depends on a gitignored machine-local
  artifact is *disclosed, not relied upon*.
- **Regenerate from a pristine worktree** so CRLF never smudges the digests:
  `.gitattributes` pins source formats to `eol=lf` precisely because tenant-authz
  evidence and the restricted-runtime manifest hash **raw file bytes**. Never
  relax it. See [[monday-report-git-pr]], [[monday-report-database]].
- **Missing evidence → BLOCKED, not PASS.** Artifacts under `output/` are
  gitignored, so a fresh checkout correctly falls back to BLOCKED (fail-closed,
  not a regression). SKIPPED / missing-evidence / missing-commands **never count
  as pass**.

## Live-authority rules
- Evidence must reflect what a probe **actually observed** on the real route /
  head / context. A verifier must never certify a property it did not observe
  (no callable-method-presence, no source-string, no proxy). See
  [[monday-report-security-review]].
- Measure at the **authority**: report persistence at `monday_report_norm_reports`
  (not the deliberately-blanked `payload->'monday_reports'`); count the norm
  tables post-cutover. See [[monday-report-backend-api]].
- **Exact-head final seal**: acceptance re-runs at the exact head that merges; no
  commit follows a successful acceptance review. A stale review is void.

## Audit integrity (what evidence can and cannot claim)
- The audit chain is sealed with a **versioned keyed HMAC-SHA256** (managed key id
  + version, rotation-aware); `integrity_state`
  (`legacy_valid`/`mixed_valid`/`keyed_valid`/`key_unavailable`/`broken`) is the
  display authority; the legacy `status="sealed"` is linkage-only, never shown as
  keyed. Forward-only: once a keyed event exists, a later unkeyed append is
  refused. Guards: `audit:integrity`, `audit:audit-keyed-integrity`,
  `audit:redaction`.
- Honest scope: HMAC proves **authenticity of recorded events, not transactional
  consistency**, and adds **no external anchor**, so **tail truncation stays
  undetected** (`audit-tail-truncation-detection` is a declared blocker; a
  same-process checkpoint is explicitly rejected as a substitute).

## GA evidence artifacts
- The GA gap assessment (`docs/GA_GAP_ASSESSMENT.v2.json`, built by
  `pnpm run ga:gap-assessment`, verified by `audit:ga-gap-assessment`) is a
  **generated status assessment** (`is_evidence=false`), bound to its source
  commit/tree with a canonical payload hash and source-file hashes. Its
  author-supplied prose is **not** derived from any evaluator; the machine-derived
  fields govern where they disagree. It is bound to a *specific* commit — read the
  live registry/guards for current dispositions, not a snapshot's tallies. See
  [[monday-report-release-ga]].
- Other bound artifacts: tenant-authorization evidence
  (`ga:tenant-authorization-evidence`, `audit:tenant-authorization-evidence`,
  `audit:evidence-reproducibility`) and the production adapter profile evidence
  (`ga:production-database-profile-evidence`, `ga:production-queue-profile-evidence`).

## Non-goals / safety
- Never fabricate or hand-edit an evidence artifact, DSN, drill, or attestation to
  flip a verdict. Never present author commentary as machine-derived evidence.
- Offline/Windows privilege evidence requires live elevation — see
  [[monday-report-offline-windows]].
