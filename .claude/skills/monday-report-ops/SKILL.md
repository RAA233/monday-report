---
name: monday-report-ops
description: >-
  Operator/runbook boundaries for Monday Report — human-only Admin/Windows
  actions, host/Docker repair authorization, shared-machine capacity, and
  secret handling. INVOKE before any host-level, Docker, capacity, or
  credential-touching action, or when validating a runbook. Triggers: "start
  Docker", "fix the DB container", "clean up the host", "capacity/disk", "set the
  secret/API key", "run the operator step", "provision credentials".
---

# Monday Report — operations & runbooks

Engineering verifies; the **operator** performs host- and credential-level
actions. Keep that boundary sharp — this is a shared machine with concurrent
writers.

## Human-only / operator boundaries
- **Do not enter credentials, passwords, API keys, signing secrets, or tokens**,
  and do not create accounts or authenticate as a user. Provisioning per-user
  credentials is done by the operator via admin routes (`/auth/users`,
  `/auth/credentials`) or the `python -m backend.app.identity_admin` CLI — describe
  the step; don't perform the secret entry. See [[monday-report-backend-api]].
- **Windows/Admin actions** (elevation, ACL changes, scheduled tasks, service/
  registry changes) are operator work and require live elevation on the target
  host — never claim them from a non-elevated context. See [[monday-report-offline-windows]].
- Keep secrets out of Git, logs, errors, and evidence.

## Host / Docker / cleanup — require explicit authorization
- **Do not repair Docker Desktop, restart services, or mutate the host** without
  explicit authorization for that exact action. (Known issue: Docker Desktop can
  die on stale AF_UNIX sockets; the remedy is an operator step, not an automatic
  one.)
- **No host cleanup** on your own initiative — do not delete containers, volumes,
  images, temp dirs, or the gitignored `output/`, `.local_data/`, `*_Daily_Reports/`
  without being told. These may be another writer's evidence.
- Disposable DB/queue for local client mode come from `docker-compose.client.yml`
  (Postgres, Redis). Bringing them up is fine when the task needs them; tearing
  down shared infra is not.

## Capacity & shared-machine rules
- Concurrent PR writers share this machine and a **machine-wide process watcher**;
  heavy live guard batteries can **false-fail under concurrency**. Do not launch a
  long battery while another writer's live PR is running; prefer read-only command
  resolution when validation is all that's needed. See [[monday-report-testing]].
- The real four-readiness-context run is **capacity-gated** (≥40 GiB free and
  ≥15%). Respect it; don't force a run that the gate declines. See
  [[monday-report-release-ga]].
- Stay inside your assigned worktree; never operate in another's. See
  [[monday-report-git-pr]], [[monday-report-protected-files]].

## Runbook validation
- Validate a runbook by resolving that its commands/paths exist and its
  preconditions/fail-closed behavior hold — **not** by executing destructive or
  host-mutating steps. Backup/restore and failover are **executed drills** owned by
  operations (declared GA blockers until evidenced). See [[monday-report-evidence-certification]].

## Non-goals / safety
- Never perform financial, account, or irreversible host actions autonomously.
- Never fabricate operational evidence (backup/restore/failover/capacity). Surface
  the step for the operator instead.
