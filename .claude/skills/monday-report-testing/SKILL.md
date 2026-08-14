---
name: monday-report-testing
description: >-
  Test and guard design for Monday Report — unit/integration/e2e/fault/adversarial,
  black-box effect-level evidence, isolation requirements, and the audit:* guard
  catalog. INVOKE when writing/running guards or tests, or deciding what evidence
  proves a behavior. Triggers: "write a test/guard", "prove this works",
  "audit:all", "isolated stack", "flaky/false pass", "does the test check the real
  effect".
---

# Monday Report — testing & guards

Verification is guard-driven: one `scripts/*_guard.py` (a few `.mjs`) per
capability, chained by `pnpm run audit:all`. Prefer effect-level, black-box proof.

## Layers
- **Portable/static guards** (no live server): most `audit:*` — RBAC, tenant
  authz, idempotency semantics, redaction, malware, storage paths, schema/variant,
  GA-gap. Run individually or via `audit:all`.
- **Integration/e2e**: `pnpm run test:e2e` (`scripts/e2e_mvp.py`, real
  upload→worker→parse→validate→export→signed-download pipeline).
- **UI e2e**: `pnpm run test:ui` (`scripts/ui_redesign_e2e.mjs`, Playwright) — see
  [[monday-report-frontend]].
- **Live DB/runtime**: `audit:restricted-postgres-runtime-*` family,
  `audit:report-create-persistence`, `audit:tenant-rls-enforcement` — need a real
  disposable PostgreSQL. See [[monday-report-database]].
- **Fault batteries**: many guards ship a paired `*-faults` / `F00..Fnn` battery
  that proves each refusal is load-bearing (e.g. the report-create-persistence
  F01 reproduces the exact lost-write signature: 201 + audit event + NO normalized
  row). A Docker-less run reports UNAVAILABLE, never a false pass.

## Isolation is mandatory (shared machine)
- Live/mutating guards must target an **isolated stack**: state/storage/export
  roots **outside the repo**, API port ≠ 8000, web port ≠ 5173, never `.local_data`.
  `scripts/verification_isolation.py` (`audit:verification-isolation`) fails closed
  before any mutating command can hit the live API/web/`.local_data`.
- **Solo-run rule**: a machine-wide process watcher / port assumptions mean some
  live batteries **false-fail under concurrency**. Do not launch a heavy battery
  while another writer's live PR is running on the same machine; when in doubt,
  restrict validation to read-only command resolution. See [[monday-report-ops]].

## Effect-level, black-box evidence (avoid proxy tests)
- Prove behavior by **observable effects**: HTTP status, persisted rows in the
  **authority** table (`monday_report_norm_reports`, not `payload->'monday_reports'`),
  the keyed audit chain, signed-URL redemption — not by asserting a source string
  or that a method is callable. The GA evaluators explicitly refuse
  callable-method presence as evidence.
- Include **adversarial counterexamples**: cross-tenant access must 404
  (existence-hiding), replay of a used idempotency key must not double-write, a
  truncated audit chain / forged event must be detected, EICAR-style content must
  block. Construct and execute the counterexample; don't assume.
- **Mutation controls**: after every mutating guard, confirm the mutation both
  happened (positive) and cannot happen when denied (negative), and that audit +
  business state moved together (or neither did).

## Non-goals / safety
- Never run `test:ui`/live guards against the live servers or `.local_data`.
- A passing self-authored test is not independent acceptance — see
  [[monday-report-security-review]].
- Don't certify a property a probe did not actually observe — see
  [[monday-report-evidence-certification]].
