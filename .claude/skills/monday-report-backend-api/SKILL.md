---
name: monday-report-backend-api
description: >-
  FastAPI backend architecture, auth/tenant boundaries, normalized report
  authority, idempotency, persistence, and API verification for Monday Report.
  INVOKE for any backend route/auth/tenant/persistence/idempotency work or when
  verifying API behavior. Triggers: "add/change an endpoint", "auth/RBAC",
  "tenant/IDOR", "idempotency key", "lost write", "audit event", "which guard
  proves route X".
---

# Monday Report — backend API

FastAPI app in `backend/app/`. Run: `pnpm run dev:api`
(`uvicorn backend.app.main:app` on 127.0.0.1:8000). Worker: `pnpm run worker:once`.

## App assembly (`backend/app/main.py`)
- **Single FastAPI app**, `app = FastAPI(...)`. **No `APIRouter`/`include_router`** —
  every route is a decorator on `app`. Middleware order (last added = outermost):
  1. `CORSMiddleware` — origins from `cors_allowed_origins()`, an **explicit
     allowlist, never `*`**; client mode **fails closed to `[]`**. Guard:
     `audit:cors-origin`.
  2. `enforce_client_api_key` — client mode: every non-public request needs a
     valid active audit key (else stable **503**) AND an active persisted per-user
     credential (`store.resolve_request_identity(..., allow_shared_key_bootstrap=False)`).
  3. `coherent_read_view` — wraps each request in one `store.committed_read_view()`.
     Guard: `audit:read-coherence`.
- Exception handlers map domain errors: `AuditIntegrityUnavailable`→503,
  `ReviewerNotVerified`→403, `IdempotencyKeyError`→400, `IdempotencyConflict`→409,
  `SnapshotConflict`→503/409.
- Only `GET /health` is public. Representative routes: `/auth/session`,
  `/auth/users`, `/auth/credentials`, `/readiness/client-data`, `/runtime/backends`,
  `/workspaces`, `/uploads` + `/uploads/direct`, `/documents`, `/audit-logs` +
  `/audit-logs/integrity`, `/validation-tasks`, `/field-corrections/*`,
  `/monday-reports` + `/monday-reports/{id}/exports/{format}`, signed-URL routes.

## Auth & RBAC (per-route permissions, not role lists)
- `auth.py` = credential primitives: opaque tokens, `hash_token()` SHA-256 +
  optional pepper, constant-time compare, non-secret fingerprints (raw token
  returned once, never logged/audited).
- `identity.py` — request identity + `(method, path)` in `ContextVar`s, set by
  middleware, reset in `finally`; `None` outside a request (worker uses explicit
  `system` actor).
- `permissions.py` is the **single authorization authority**: stable permission
  ids, `ROLE_PERMISSIONS` matrix (ADMIN=all; ENGINEER/VALIDATOR/MANAGER proper
  subsets; **VIEWER intentionally empty**), **default-deny** on unknown role/perm.
  Enforced per route via `require_permission(...)`/`require_admin()`. Permission
  is checked **before** any resource lookup (no existence leak). Guards:
  `audit:auth`, `audit:identity-rbac`, `audit:route-rbac`. See docs/ROUTE_RBAC.md.

## Tenant authorization (API layer)
- `tenant_authorization.py`: request tenant comes **only** from server-side
  identity (`request_tenant_id()` → `None` denies; never system/all-tenant). After
  the permission gate, every resource route compares the resource `tenant_id` (and
  every parent link via `owned_via_graph`) to the request tenant; a missing OR
  cross-tenant resource is hidden behind the **same existence-hiding 404**; lists
  are tenant-filtered before counting; cross-tenant attempts are audited. No route
  accepts a client-supplied tenant. Guards: `audit:tenant-authorization`,
  `audit:tenant-authorization-evidence`. DB-level RLS is separate — see
  [[monday-report-database]].

## Normalized report authority
- On PostgreSQL, `repositories.py` is the **single write/read authority** for
  reports/corrections/validation via normalized tables
  (`monday_report_norm_reports`, `..._field_corrections`, `..._validation_tasks`,
  `..._validation_outcomes` append-only). **Measure migrated entities at the norm
  tables — NOT `payload->'monday_reports'`**, which `normalized_import.py`
  deliberately blanks post-cutover (authority marker). Guards:
  `audit:report-create-persistence`, `audit:normalized-correction-persistence`.

## Idempotency & persistence
- `idempotency.py`: `Idempotency-Key` header; `canonical_request_hash` over the
  validated semantic request (op + path ids + validated body) — **excludes raw
  bytes, credentials, headers, timestamps**. Established **after** authn/authz/
  ownership pass; required when the store enforces transactional persistence.
- `store.py` `snapshot_transaction(...)` is the commit boundary: business row +
  its snapshot-owned **audit event** + idempotency record + snapshot **revision
  (CAS)** commit or roll back as one unit. Replay re-reads the committed entity;
  a reused key with a different request/actor → `IdempotencyConflict` (409).
  `repositories.py` writes run on the store's open txn connection (never their own
  txn): global advisory lock → per-row `SELECT ... FOR UPDATE`.
- Audit writes fail closed in client mode without an active HMAC key. See
  [[monday-report-evidence-certification]].

## Verifying backend work
- Fast/portable: `audit:auth`, `audit:route-rbac`, `audit:tenant-authorization`,
  `audit:report-create-idempotency`, `audit:persistence-atomicity`,
  `audit:snapshot-conflict-semantics`, `audit:malware`, `audit:redaction`.
- Live/DB-backed (isolated stack only): the `audit:restricted-postgres-runtime-*`
  family + `audit:report-create-persistence`. Full chain: `audit:all`.
- Prove behavior with black-box effects (HTTP status + persisted rows + audit
  chain), not source-string checks. See [[monday-report-testing]].

## Non-goals / safety
- Do not weaken fail-closed defaults (503/403/404-existence-hiding). Do not add a
  client-supplied tenant/identity path. Do not claim DB RLS from API-layer proof.
