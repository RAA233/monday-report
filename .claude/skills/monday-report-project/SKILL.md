---
name: monday-report-project
description: >-
  Monday Report repository map and orientation. INVOKE FIRST on any task in this
  repo when you need to know where code lives, which frontend/backend is
  canonical, what the key package scripts are, the integration strategy, or how
  to pick the correct next task. Triggers: "where is X", "how is this project
  laid out", "what should I work on next", "run the audits", starting any new
  increment.
---

# Monday Report — project map & orientation

Monday Report drafts source-cited morning/Monday drilling reports from rig
evidence (DDR/PDF/ZIP uploads), with human validation and audited, gated
exports. Local-AI-first, tenant-scoped, fail-closed.

## Stack & canonical entry points
- **Frontend**: Vite + React 19 + TypeScript. The **canonical and only** entry is
  `src/redesign/main.tsx`, loaded by root `index.html` on **port 5173**
  (`vite.config.ts`, `strictPort`). The retired v1 entry and the `5174`/
  `redesign.html` dual document are **gone** — do not resurrect them. See
  [[monday-report-frontend]].
- **Backend**: FastAPI under `backend/app/` (`main.py` app; `dev:api` runs
  `uvicorn backend.app.main:app` on **127.0.0.1:8000**). Worker entry
  `python -m backend.app.worker` (`worker:once`). See [[monday-report-backend-api]].
- **DB design**: `db/schema.sql` (flattened, non-authoritative). Migrations in
  `db/migrations/` (immutable legacy set) and `db/baseline/` (corrected
  fresh-install set). See [[monday-report-database]].
- **Guards/tools**: `scripts/*_guard.py` (+ a few `.mjs`). Docs in `docs/`.
  GA registry in `evals/ga/blocker_registry.v1.json`. FORGE evals in `evals/forge/`.

## Important directories
- `src/redesign/` — shell (`shell/`), pages (`pages/`), router (`router.tsx`),
  shared client state (`lib/workspace.tsx`). `src/lib/` — API client (`api.ts`)
  + display helpers. `src/data/` — committed program data. `src/styles/` tokens.
- `backend/app/` — routes/auth/tenant/persistence/adapters/migrations/readiness.
- `scripts/` — one guard per capability; `audit:all` chains them.
- `docs/` — spec, execution plan, per-feature contracts (RBAC, tenant authz,
  audit integrity, migrations, readiness contexts, GA readiness integrity).

## Key package scripts (verified in package.json)
- `pnpm run dev` / `dev:api` / `worker:once` — run the app.
- `pnpm run build` — `tsc && vite build`.
- `pnpm run test:ui` (= `test:ui-redesign`, `scripts/ui_redesign_e2e.mjs`) — UI
  gate; refuses the live stack (needs isolated state/ports). See [[monday-report-testing]].
- `pnpm run test:e2e` — `scripts/e2e_mvp.py` upload→worker→export pipeline.
- `pnpm run audit:all` — the full guard chain (build/e2e/security/persistence/
  readiness/GA-gap). Run after meaningful changes.
- `pnpm run ga:readiness` (strict) / `audit:ga-readiness` — GA gate. See
  [[monday-report-release-ga]].

## Architecture boundaries (respect these)
- Demo mode = local JSON store; **client mode** = PostgreSQL/RLS state + Redis
  queue + API key + signing secret + reviewed evidence, and **fails closed**.
- Normalized PostgreSQL tables are the **write/read authority** for migrated
  entities (e.g. `monday_report_norm_reports`), NOT the tenant snapshot payload.
- Tenant scoping is enforced at the API layer (existence-hiding 404 on
  cross-tenant); DB-enforced RLS over the normalized store is still a declared
  blocker. See [[monday-report-backend-api]], [[monday-report-database]].
- Production DB and queue adapters are **NOT_ACCEPTED** until real-target
  evidence exists; contract acceptance ≠ adapter acceptance. See
  [[monday-report-database]], [[monday-report-queue]].

## Integration strategy
Each increment is a focused branch/worktree with its own guards, reviewed by an
independent fresh-context reviewer, then merged via an ordinary merge commit —
never rebased/force-pushed after publish. Stacked PRs build on their base PR's
frozen head. See [[monday-report-git-pr]].

## How to determine the correct next task
1. Read `docs/PROJECT_TRACKER.md` "Clear Tracker Snapshot" → Next Action column,
   and the dated increment sections (latest first).
2. Check the GA gate: `evals/ga/blocker_registry.v1.json` + the current gap
   assessment; open blockers carry `recommended_sequence`. The gate is
   `GA_BLOCKED` and stays so even with PostgreSQL+Redis provisioned.
3. Pick a single blocker or roadmap lane; do it in its own branch with guards +
   independent review. Never bundle unrelated controls.

## Non-goals / safety
- Read-only validation here does NOT mean run heavy batteries casually — the
  machine is shared; see [[monday-report-testing]] and [[monday-report-ops]].
- Never invent facts about unmerged branches; this tree (main) is the authority.
- Never access protected partner-status paths — see [[monday-report-protected-files]].
