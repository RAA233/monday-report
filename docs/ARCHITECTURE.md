# Architecture

A newcomer's map. Deeper design notes for each subsystem live in the sibling
files in this directory.

---

## The shape of it

```
  ┌──────────────────────────────────────────────────────────────┐
  │  Browser — React 19 + TypeScript, Vite                       │
  │  src/redesign/   20 routes, one canonical interface          │
  └───────────────────────────┬──────────────────────────────────┘
                              │  fetch, same-origin in packaged builds
                              ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  FastAPI — backend/app/main.py  (48 routes)                  │
  │                                                              │
  │   request → identity resolution (server-side, opaque cred)   │
  │           → RBAC permission check   (default-deny)           │
  │           → tenant authorisation    (existence-hiding 404)   │
  │           → handler                                          │
  │           → audit append            (HMAC-SHA256 chained)    │
  └───────────────────────────┬──────────────────────────────────┘
                              ▼
         ┌────────────────────┴─────────────────────┐
         ▼                                          ▼
  LocalStateStore                          PostgreSQL + Redis
  backend/app/store.py                     optional, "client mode"
  durable JSON in .local_data/             migrations + forced RLS
  ← THE DEFAULT                            inline worker → Redis queue
```

The order of those four middleware steps is load-bearing. Permission is checked
**before** any resource lookup so a 404 cannot leak existence, and tenant
comparison happens **after** permission so a cross-tenant probe is
indistinguishable from a miss.

---

## Where to look for what

| You care about | Start here |
|---|---|
| HTTP routes, request flow | `backend/app/main.py` (2,228 lines, 48 routes) |
| Storage, parsers, exports, audit chain | `backend/app/store.py` (**8,591 lines** — see warning) |
| Request/response contracts | `backend/app/schemas.py` |
| Permissions and roles | `backend/app/permissions.py` (23 permissions) + `docs/ROUTE_RBAC.md` |
| Tenant isolation | `backend/app/tenant_authorization.py`, `tenant_rls.py` + `docs/TENANT_AUTHORIZATION.md` |
| Audit integrity | `backend/app/audit_keys.py`, `audit_safety.py` + `docs/AUDIT_INTEGRITY.md` |
| Well trajectory maths | `backend/app/trajectory.py` + `docs/TRAJECTORY_CALCULATION.md` |
| Migrations | `backend/app/migrations.py`, `db/` + `docs/POSTGRES_MIGRATIONS.md` |
| AI providers | `backend/app/ai/` (6 modules) |
| Offline runtime + licensing | `backend/app/offline_runtime.py`, `backend/app/licensing/` |
| GA gate logic | `backend/app/ga_readiness.py`, `evals/ga/blocker_registry.v1.json` |
| Frontend | `src/redesign/` — `router.tsx`, `pages/`, `shell/`, `components/` |
| The test suite | `scripts/*_guard.py` (117 of them) |

> ### ⚠ `store.py` is 8,591 lines
> It is ~45% of the backend and mixes the snapshot store, all parsers, export
> rendering, and the audit chain. This is known, tracked debt
> ([ROADMAP](ROADMAP.md#technical-debt)). Prefer adding a new module over
> growing it.

---

## Key design decisions

Understanding these five explains most of the code.

### 1. Local-first by default

The default backend is a durable JSON store in `.local_data/`, shared between
API and worker. No database, no Docker, no Redis to run the product.
PostgreSQL + Redis activate only in approved "client mode".

`/runtime/backends` exposes **requested** vs **active** adapters, specifically
so that setting `POSTGRES_URL` cannot make the system *claim* PostgreSQL while
actually running on JSON. Defaults are `local_json` + `inline_worker`.

### 2. Nothing is asserted without provenance

Every extracted value carries a page-level citation and a confidence. Three
rules follow from this and are enforced by guards:

- **Calculated never overwrites source.** Trajectory values render side by side
  with source values.
- **Gaps stay gaps.** Conflicting or missing survey stations are skipped, never
  interpolated or bridged.
- **A model never owns a citation.** The AI seam produces prose; provenance
  comes from deterministic extraction. An online provider is default-off.

### 3. Fail closed, and never silently

The audit chain is forward-only keyed: once a keyed event exists, appending an
unkeyed one is refused. In client mode, no business mutation persists without
audit-write capability — the check runs *before* state is touched. Read-only
degradation (e.g. an expired offline licence) returns `423` with a typed reason
rather than a silent no-op.

### 4. Verification is effect-level, and the oracles are themselves tested

Guards assert observed effects, never the subject's own stdout. 13 of the 117
are `*_faults_guard.py` twins that seed a defect and **require the paired guard
to refuse** — mutation testing of the test. A guard that cannot fail is treated
as a bug, so the ratio is a gap, not a design choice
([ROADMAP](ROADMAP.md#good-first-contributions)).

### 5. Incompleteness is data, not a comment

Zero `TODO`s by policy. Unfinished work is 28 registry entries with severity,
owner, a `policy_reference` pointing at the deficiency, and a
`resolution_condition`. The gate reading them cannot be waived.

---

## Request lifecycle, concretely

A validated field correction, start to finish:

1. **Identity** — the `x-monday-report-key` credential is resolved *server-side*
   to a request-scoped identity. Client-supplied identity headers are ignored.
   No all-tenant fallback; a missing identity denies.
2. **Permission** — the route's declared permission is checked against the
   role→permission matrix. Default-deny. A denial writes a redacted audit event.
3. **Tenant** — the resource is loaded, and its `tenant_id` compared to the
   request tenant. A mismatch returns the **same** 404 as a miss.
4. **Registry check** — only fields in the corrections registry are
   correctable; unknown or sensitive fields return a stable 422.
5. **Mutation** — the correction is written as a *versioned overlay*. The
   original source value is preserved; re-correcting supersedes, reverting keeps
   history.
6. **Audit** — a redacted, hash-chained, HMAC-sealed event records
   who/what/when/why without leaking source, corrected value, or reason text.

---

## Frontend

One canonical interface in `src/redesign/` (the earlier v1 was retired and
deleted). 20 routes, all implemented — the project deleted its own
`PendingStage` placeholder component and asserts in
`shell/navigation.ts` that nothing listed renders a placeholder.

Three behaviours worth knowing, each guard-enforced:

- **Navigation never triggers an audited read.** Loading a well's draft is an
  explicit, disclosed button press, not a side effect of routing.
- **Navigation never appends `permission_denied`.** Reads are permission-gated
  before they are attempted.
- **Mutation honesty.** Only a proven 4xx claims "not recorded". Anything else
  reports the outcome as unknown rather than guessing.

`vite.config.ts` carries a `redesignHistoryFallback` plugin so deep-route
refresh works in dev *and* preview, including `/app/*` paths whose last segment
contains a dot (report ids like `MR-1.2`). Classification runs on the pathname
only — testing the raw URL made any query-string request look like an asset.

---

## Verification topology

```
pnpm run audit:all        77 sequential steps, expects exactly 1 failure (GA50)
  ├── audit_harness_guard        a meta-guard over the harness itself
  ├── ~70 subsystem guards       effect-level, named check ids
  └── ga_gap_assessment{,_faults}

CI (.github/workflows/ci.yml) — 3 jobs
  ├── fast-hermetic          build + typecheck, no services
  ├── strict-audit-postgres  audit:all against TWO disposable pgvector clusters
  │                          (the second proves cross-cluster rejection really ran)
  └── windows-deterministic  py-compile, PowerShell parse, offline self-test
```

CI asserts the **exact** expected outcome — steps 1–76 pass, step 77 fails on
`GA50`, verdict `GA_BLOCKED`. A green `audit:all` turns CI **red** on purpose.

45 `audit:*` scripts sit outside the chain (restricted-Postgres matrix,
behavioural adapter tiers, readiness contexts, offline guards). Wiring them up
is a tracked roadmap item.

---

## Data model notes

- `db/migrations/0001–0007` — the **immutable legacy set**. `0003` references
  tables no earlier migration creates, so this sequence is deliberately
  un-appliable; checksums are recorded over raw bytes and must not drift.
- `db/baseline/0001–0007` — the **corrected fresh-install set**, FK targets
  retargeted to `workspaces` / `monday_reports`. Applies cleanly.
- `db/schema.sql` — a flattened convenience view. **Not authoritative.**
- `0001` requires the `vector` extension, hence `pgvector/pgvector:pg16` in CI
  rather than stock `postgres:16`.

`.gitattributes` pins `eol=lf` on all text. This is not cosmetic: migration
checksums and evidence hashes are computed over raw bytes, so CRLF smudging on
Windows breaks migrations and makes evidence unreproducible. Do not change it.
