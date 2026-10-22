# Monday Report — project skill index

**Project-level skills** (in this directory, `monday-report-*`) describe THIS
repository: its concrete files, guards, verdicts, and safety rules. **User-level
skills** are generic, reusable techniques that apply to any project. When both
fit, invoke the project skill for the Monday-Report specifics and lean on the
user-level skill for the general method.

Skills reference each other with `[[skill-name]]`. Start with
[[monday-report-project]] for orientation on any new task.

## Task → project skill

| When the task is about… | Invoke | One-line trigger |
|---|---|---|
| Repo layout, "where is X", picking the next task, running the audits | `monday-report-project` | Orientation / project map — invoke first. |
| Branching, commits, merges, rebase/force-push, worktrees, stacked PRs, review flow | `monday-report-git-pr` | Any git/worktree/PR action; ordinary-merge-only, single-writer. |
| Endpoints, auth/RBAC, tenant/IDOR, idempotency, persistence, audit events | `monday-report-backend-api` | FastAPI backend + normalized authority + verification. |
| Schema, migrations, checksum drift, RLS, runtime-role safety, production-DB adapter | `monday-report-database` | PostgreSQL / migrations / RLS; production DB stays NOT_ACCEPTED. |
| Worker/queue, retry/DLQ, delivery semantics, production-queue adapter | `monday-report-queue` | Queue/worker; production queue stays NOT_ACCEPTED. |
| UI pages/routing/state/mutations, build, UI tests, screenshots | `monday-report-frontend` | Canonical Vite entry (5173); no v1/dual entry. |
| Writing/running guards & tests, effect-level proof, isolation, fault batteries | `monday-report-testing` | `audit:*` guards, `test:ui`/`test:e2e`, isolated stack. |
| Reviewing a change for acceptance, counterexamples, 0C/0H | `monday-report-security-review` | Independent fresh-context adversarial review. |
| Offline edition, Windows/ACL/SID/reparse, DPAPI, elevation, bootstrap | `monday-report-offline-windows` | Live-elevation trust model; #30/#39–#42 FROZEN; PR #43 model. |
| Evidence artifacts, head/tree binding, stale evidence, audit HMAC, exact-head seal | `monday-report-evidence-certification` | Fail-closed, reproducible-from-tracked-repo certification. |
| CI, GitHub Actions, hermetic gates, disposable Postgres service, dependency scan | `monday-report-ci` | No CI exists yet; `ga_ci_execution` stays BLOCKED. |
| GA readiness, blockers, release verdicts, production acceptance | `monday-report-release-ga` | Registry gate (28 controls); GA_BLOCKED; BLOCKED/NOT_ACCEPTED/READY. |
| Host/Docker, capacity, Admin/Windows human steps, secrets, runbooks | `monday-report-ops` | Operator boundaries; no host repair/cleanup without authorization. |
| Anything possibly partner-status / protected / off-limits | `monday-report-protected-files` | Never access; only state non-access. Operator supplies paths. |

All 14 project skills appear above. `monday-report-protected-files` also governs
every other skill — consult it whenever a path might be protected.

## Project ↔ user-level skill pairings

Project-level = Monday-Report-specific. User-level = generic reusable technique.

| Project skill | Generic user-level counterpart(s) |
|---|---|
| `monday-report-git-pr` | `secure-git-pr-workflow` |
| `monday-report-backend-api` | `backend-api-engineering` |
| `monday-report-database` | `postgres-verification` |
| `monday-report-queue` | `backend-api-engineering`, `black-box-test-design` |
| `monday-report-frontend` | `frontend-vite-engineering` |
| `monday-report-testing` | `black-box-test-design`, `verification-environment` |
| `monday-report-security-review` | `adversarial-security-review` |
| `monday-report-offline-windows` | `windows-security-boundary-analysis`, `offline-evidence-certification` |
| `monday-report-evidence-certification` | `evidence-integrity`, `offline-evidence-certification` |
| `monday-report-ci` | `ci-release-engineering` |
| `monday-report-release-ga` | `ci-release-engineering`, `evidence-integrity` |
| `monday-report-ops` | `operator-runbook-validation` |
| `monday-report-protected-files` | (no generic counterpart — project-specific governance) |
| `monday-report-project` | (orientation; no generic counterpart) |

Generic user-level skills referenced above: `windows-security-boundary-analysis`,
`offline-evidence-certification`, `verification-environment`,
`secure-git-pr-workflow`, `backend-api-engineering`, `postgres-verification`,
`frontend-vite-engineering`, `adversarial-security-review`,
`ci-release-engineering`, `black-box-test-design`, `evidence-integrity`,
`operator-runbook-validation`.
