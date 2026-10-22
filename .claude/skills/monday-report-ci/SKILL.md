---
name: monday-report-ci
description: >-
  CI expectations for Monday Report — GitHub Actions, hermetic fast gates, the
  disposable-Postgres service for strict DB audit, and workflow-only PR
  discipline. INVOKE when adding/discussing CI, the ci-execution GA blocker, or
  automation of audit:all. Triggers: ".github/workflows", "CI", "GitHub Actions",
  "run audit:all on push", "disposable Postgres in CI", "dependency scan".
  NOTE: no CI exists in this repo yet.
---

# Monday Report — CI

## Current state: CI does NOT exist
- **There is no `.github` directory anywhere in the repository** (verified). The
  guard battery runs only locally. The GA control `ga_ci_execution` is therefore
  **BLOCKED**.
- Resolving it requires a **committed workflow AND an observed run for the exact
  commit with no required job skipped, bound to an immutable run identifier**.
  **Committing YAML alone must not flip the control** — an unexecuted workflow is
  not evidence. See [[monday-report-release-ga]], [[monday-report-evidence-certification]].
- The CI gap **must stay on the roadmap** (`docs/PROJECT_TRACKER.md`,
  `evals/ga/blocker_registry.v1.json`). Do not quietly drop it.

## What a future workflow must do
- On every push / PR: `pnpm install` (frozen lockfile), `pnpm run build`
  (`tsc && vite build`), and **`pnpm run audit:all`** (the full guard chain), plus
  the corpus-backed FORGE evaluation (`audit:forge-eval-spec`; `audit:forge-evals`
  reports SKIPPED without the local corpus, never PASS). Block merges on failure.
- **Hermetic fast gates**: the portable `audit:*` guards need no services and
  should run as fast, deterministic jobs.
- **Disposable PostgreSQL service** for the strict DB audits: the live
  `audit:restricted-postgres-runtime-*` / migration-runner / RLS / report-create-
  persistence guards need a throwaway **PostgreSQL 16 with pgvector**
  (`pgvector/pgvector:pg16` — `0001` needs the `vector` extension). Provide it as a
  CI service (mirrors `docker-compose.client.yml`), state/storage/export roots
  outside the workspace, ports ≠ 8000/5173. See [[monday-report-database]],
  [[monday-report-testing]].
- **Dependency vulnerability scan** (`pip-audit` + `pnpm audit`, pinned lockfiles,
  severity policy) — its own GA control (`ga_dependency_vuln_scan`) depends on CI
  execution.

## Workflow-only PR discipline
- A CI/workflow PR changes CI config only; it must not alter application code or
  evidence semantics as a side effect. Keep it minimal and reviewable, ordinary
  merge commit, independent review. See [[monday-report-git-pr]].

## Non-goals / safety
- Do not claim CI is "done" by committing a workflow; the control needs an
  observed, non-skipped run bound to an immutable run id.
- Do not disable/skip required jobs to get green. `--skip-commands` can never
  yield GA_READY.
