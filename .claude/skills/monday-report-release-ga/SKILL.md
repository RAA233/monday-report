---
name: monday-report-release-ga
description: >-
  GA readiness gate, blocker registry, production-acceptance distinctions, and
  release verdict meanings for Monday Report. INVOKE for GA readiness, release
  decisions, or interpreting BLOCKED / NOT_ACCEPTED / READY. Triggers: "is it GA
  ready", "GA blockers", "release candidate", "why still blocked with Postgres +
  Redis", "production acceptance", "what does NOT_ACCEPTED mean".
---

# Monday Report — release / GA readiness

GA is a **truthful, registry-backed gate**, not a checklist you can talk past.
Current posture: **GA_BLOCKED** (and stays blocked even with PostgreSQL + Redis
provisioned).

## The registry & gate
- Every known GA blocker is a committed entry in
  `evals/ga/blocker_registry.v1.json` (**28 controls**) with category / severity /
  owner / resolution condition. The gate emits one check per entry with an explicit
  disposition: `PASS` / `FAIL` / `BLOCKED` / `SKIPPED` / `NOT_APPLICABLE` /
  `REVIEW_REQUIRED`. Commands: `pnpm run ga:readiness` (strict),
  `pnpm run audit:ga-readiness`, `audit:ga-readiness-integrity`,
  `pnpm run ga:gap-assessment` → `docs/GA_GAP_ASSESSMENT.v2.json`
  (`audit:ga-gap-assessment`). Backend: `backend/app/ga_readiness.py`
  (`evaluate_blockers`), `backend/app/readiness_contexts.py`.
- **Stale/insufficient evidence fails closed**: evidence is bound to a clean
  commit/tree with a canonical self-hash + redacted paths; `SKIPPED` /
  missing-evidence / missing-commands **never count as pass**; **`--skip-commands`
  can never yield `GA_READY`**; no waiver resolves a blocker in this registry
  version. A fresh checkout with no local evidence artifact is the authoritative
  context and correctly falls back to BLOCKED. See [[monday-report-evidence-certification]].
- A known-but-unimplemented control (CI, backup, structured logging, metrics,
  worker heartbeat, external malware scanner, tail-truncation anchor, Phase 06
  trust boundary, export provenance) is a declared **BLOCKED** entry, so the gate
  reports truthful non-zero counts.

## Verdict meanings
- **BLOCKED** — a control's resolution condition is not met (or not evaluable /
  missing evidence). The gate stays GA_BLOCKED.
- **NOT_ACCEPTED** — for the production DB/queue adapters specifically:
  **contract/behavioral acceptance is NOT production acceptance.** The static
  contracts are ACCEPTED and a behavioral tier is proven on disposable Docker, yet
  `ga_postgres_adapter` and `ga_redis_adapter` remain BLOCKED /
  `PRODUCTION_*_ADAPTER_NOT_ACCEPTED` until real-production-target evidence exists
  (named non-loopback target, verified TLS, executed drills, clean secret scan).
  See [[monday-report-database]], [[monday-report-queue]].
- **READY** — every registry control PASSes at the exact head from reproducible
  evidence. Not the current state.
- Controls currently PASS-capable include `rbac-role-separation` and
  `verified-reviewer-identity` (evidence-driven behavioral probes); `per-user-identity`
  and `tenant-authorization` are implemented at the API layer but stay declared
  blockers (no behavioral evaluator / DB-RLS not proven respectively). Read the
  **live** gate for current dispositions — a committed gap-assessment snapshot is
  bound to a past commit.

## Readiness contexts
- The four readiness contexts = (`demo`|`client`) × (`local_json`→`local`|`postgres`):
  `demo-local`, `demo-postgres`, `client-local`, `client-postgres`. Queue backend
  is deliberately **not** a third axis. The real four-context run is capacity-gated
  (≥40 GiB free and ≥15%); it is currently `FOUR_READINESS_CONTEXTS_NOT_ACCEPTED`.
  Client-identity controls can't be evaluated in demo; DB/RLS/migration controls
  can't be evaluated on `local_json` (they stay BLOCKED, not N/A).

## Release/packaging flow (operator-supplied governance)
- The offline commercial release progresses **package → E1 → E2 → final seal**,
  where E1/E2 are distinct trust-surface/environment gates and the final seal is an
  exact-head re-run with no following commit. This flow governs the offline edition
  on separate branches — it is **not** represented in this main tree. See
  [[monday-report-offline-windows]], [[monday-report-evidence-certification]].

## Non-goals / safety
- Never self-approve a client/organizational approval control (EXTERNAL — must
  never be self-approved). Never fabricate evidence to reach READY. Never let
  committing YAML/a method flip a BLOCKED control. See [[monday-report-ci]],
  [[monday-report-security-review]].
