# Route-Level RBAC Enforcement

This document describes the **route-level role-based access control (RBAC)** layer
in Monday Report: a single generic authorization authority (`backend/app/permissions.py`),
a grounded permission registry, a conservative role → permission matrix, and an
enforced inventory covering **every** API route.

It is a **bounded authorization increment** built on the merged authenticated-identity
foundation (see [`AUTHENTICATED_IDENTITY.md`](AUTHENTICATED_IDENTITY.md)). It is
**not** multi-tenant resource authorization, verified reviewer workflow, or keyed
audit integrity — those remain declared blockers in
`evals/ga/blocker_registry.v1.json`, and the readiness gate stays **`GA_BLOCKED`**.

## What existed before

- The only fine-grained authorization in the codebase was **Benchmarking-specific**:
  `store.benchmark_permissions()` returned a 12-key boolean map, and only the
  `/benchmarking/*` and `/field-corrections/*` routes consulted it. Identity
  administration (`/auth/users*`) was admin-gated.
- **Every other privileged route** (workspaces, uploads, documents, chunks,
  failures, processing jobs, validation queue, reports, exports, audit logs,
  runtime/backends, local-ai status, retention) was reachable by **any
  authenticated caller** — in client mode a single valid credential was
  sufficient; there was no per-route permission requirement.
- There was no route inventory proving which routes were public, which required a
  permission, and which were system-internal — so a newly added route silently
  inherited "authenticated is enough."

## Authorization authority: `backend/app/permissions.py`

`permissions.py` is now the **single authorization authority**. It defines:

- **23 stable permission identifiers** (string constants + an `ALL_PERMISSIONS`
  frozenset). The 12 historical Benchmarking/field-correction keys are preserved
  **exactly** (name and role mapping); 11 route-grounded keys were added for the
  rest of the surface.
- **`ROLE_PERMISSIONS`** — the role → permission matrix (below).
- **Default-deny evaluation**: `has_permission(roles, permission)` returns `False`
  for an unknown permission, an empty/unknown role set, or a role that simply
  lacks the permission. `permissions_for_roles(roles)` is the deterministic union.
  `permission_map(roles)` is the stable `{permission: bool}` view over all 23
  permissions used by `/auth/session`.

`store.benchmark_permissions()` is now a **thin compatibility wrapper** that
delegates to `permissions.has_permission` for exactly the historical 12 keys, so
the Benchmarking contract (shape and values) is byte-for-byte unchanged.

`ADMIN_ONLY = "__admin__"` is a sentinel used by the route inventory to mark
routes gated by role (identity/credential administration) rather than by a
permission grant; it is **not** a member of `ALL_PERMISSIONS`.

### Permission registry (23)

Preserved (12): `view_benchmarks`, `manage_benchmark_config`, `review_anomalies`,
`dismiss_anomalies`, `run_diagnostics`, `approve_ai_content`, `issue_client_reports`,
`export_evidence`, `edit_decision_records`, `view_audit_history`,
`record_field_corrections`, `view_field_corrections`.

Added (11): `view_workspaces`, `manage_workspaces`, `view_source_documents`,
`manage_uploads`, `view_processing_status`, `view_validation_queue`,
`resolve_validation`, `view_reports`, `generate_reports`, `view_runtime_status`,
`run_retention`.

## Role → permission matrix

Only the four active roles are used. The legacy **`VIEWER` role is intentionally
NOT activated** and receives an empty permission set. Grants are conservative and
route-grounded; where repository evidence does not establish a permission for a
role, it is **denied**.

| Permission | ADMIN | ENGINEER | VALIDATOR | MANAGER |
|---|:---:|:---:|:---:|:---:|
| view_benchmarks | ✓ | ✓ | ✓ | ✓ |
| manage_benchmark_config | ✓ |  |  | ✓ |
| review_anomalies | ✓ | ✓ | ✓ | ✓ |
| dismiss_anomalies | ✓ |  | ✓ | ✓ |
| run_diagnostics | ✓ | ✓ |  | ✓ |
| approve_ai_content | ✓ |  | ✓ | ✓ |
| issue_client_reports | ✓ |  |  | ✓ |
| export_evidence | ✓ | ✓ |  | ✓ |
| edit_decision_records | ✓ | ✓ |  | ✓ |
| view_audit_history | ✓ |  | ✓ | ✓ |
| record_field_corrections | ✓ | ✓ | ✓ | ✓ |
| view_field_corrections | ✓ | ✓ | ✓ | ✓ |
| view_workspaces | ✓ | ✓ | ✓ | ✓ |
| manage_workspaces | ✓ |  |  | ✓ |
| view_source_documents | ✓ | ✓ | ✓ | ✓ |
| manage_uploads | ✓ | ✓ |  |  |
| view_processing_status | ✓ | ✓ | ✓ | ✓ |
| view_validation_queue | ✓ |  | ✓ |  |
| resolve_validation | ✓ |  | ✓ |  |
| view_reports | ✓ | ✓ | ✓ | ✓ |
| generate_reports | ✓ | ✓ |  | ✓ |
| view_runtime_status | ✓ |  |  | ✓ |
| run_retention | ✓ |  |  |  |

`ADMIN` holds all 23. `VIEWER` holds none.

Design rationale for the conservative separations:

- **VALIDATOR** owns the validation queue (`view_validation_queue`,
  `resolve_validation`) and AI approval (`approve_ai_content`) but **cannot
  upload** (`manage_uploads`) or **generate/issue reports** — a validator reviews
  evidence, it does not author or ingest it.
- **ENGINEER** ingests and drafts (`manage_uploads`, `generate_reports`,
  `run_diagnostics`) but **cannot approve AI content, resolve validations, issue
  client reports, or view audit history** — separation of preparer from approver.
- **MANAGER** can issue client reports and view runtime/audit status but **cannot
  upload or resolve validations**.
- **`run_retention`** (destructive lifecycle) and identity administration are
  **ADMIN-only**.

## Route inventory & enforcement (`ROUTE_ACCESS_POLICY` in `backend/app/main.py`)

Every route is classified in `ROUTE_ACCESS_POLICY` with a `classification` and an
`auth_mechanism`:

- **Classifications**: `public`, `authenticated_read`, `permission_required`,
  `system_internal`.
- **Auth mechanisms**: `none`, `api_credential`, `signed_capability`,
  `internal_process`.

Current inventory (48 routes):

- **public (7)**: `/health` (minimal liveness only — `{status, service}`, no
  secrets or paths), the four API-docs routes (`/docs`, `/redoc`,
  `/openapi.json`, `/docs/oauth2-redirect` — hidden with 404 from non-admins in
  client mode), and the **two signed-capability download routes**
  (`auth_mechanism = signed_capability`).
- **authenticated_read (2)**: `/auth/session`, `/field-corrections/registry` —
  any authenticated caller, no specific permission.
- **permission_required (39)**: every privileged read and every mutation, each
  bound to exactly one permission (or `__admin__` for identity administration).
  This includes **`/readiness/client-data`** — the DETAILED client-data readiness
  report (blocker ids, dispositions, remediation, deployment mode, and configured
  paths) is **not** public; it requires `view_runtime_status`. Only the minimal
  `/health` liveness stays public, and readiness detail no longer embeds absolute
  filesystem paths.

`route_policy_fully_enforced()` is stricter than a row-status check: it requires
`validate_route_access_policy()` to return **zero errors**, **zero `pending`**
rows, **and** that every `permission_required` route can be **proven** to carry
its declared guard by static inspection of `main.py` source (the referenced
`require_permission("…")` / `require_benchmark_permission("…")` / `require_admin()`
call is present in the handler). Category, auth-mechanism compatibility, the
minimal-public allow-list, and signed-capability GET-only constraints are all
validated. An unknown permission id, a public mutation, or an unclassified new
route makes the policy **not** fully enforced.

### Signed-capability routes

The two download routes are `public` + `signed_capability`: they are **not**
gated by a credential/permission because the **signed URL itself is the
capability** — it is resource-bound (issued for one resource id), purpose-bound,
expiring (TTL), and method-restricted (GET only). The token is minted only by an
authenticated, permission-gated issuing route (`export_evidence` /
`issue_client_reports`) and **verified FIRST** in the download handler — before
any resource lookup, readiness gate, or audit side effect — so an unauthenticated
caller with an invalid token cannot probe resource existence (no 404-vs-403
oracle) or trigger audit writes. The inventory enforces that signed-capability
routes are read-only.

## Enforcement mechanics

- The auth middleware resolves the request identity, sets it in a request-scoped
  `ContextVar`, and also records the request **method + path** in a second
  `ContextVar` (`identity.set_request_context`) used only for denial audit
  context. Both are reset in `finally`.
- `require_permission(permission)` denies (HTTP **403**) when there is no identity
  or `store.has_permission(permission, identity)` is `False`. **Permission is
  checked before any resource lookup**, so an unauthorized caller cannot probe
  resource existence (no 404-vs-403 leak).
- Every denial writes a redacted audit event (`permission_denied`, or
  `benchmark.permission_denied` for Benchmarking routes) carrying the
  `permission`, `route`, `method`, `actor_source`, and `reason`. No credential,
  token, or request body is recorded (the existing audit redaction applies).

## Readiness

The `rbac-role-separation` GA control is now **evidence-driven PASS**. Its
registry resolution condition — *"distinct roles with enforced least privilege
exist and route authorization checks a per-user role, not the single configured
all-role user"* — is satisfied, so `ga_readiness._rbac_role_separation_probe()`
inspects the ACTUAL policy/route code (distinct least-privilege role matrix with
ADMIN=all and proper non-admin subsets, VIEWER unactivated, default-deny
evaluation, and `route_policy_fully_enforced()`) rather than defaulting to
BLOCKED. The **blocker registry is unchanged** — only the evaluator probe became
evidence-based. This control evaluates the role-separation **mechanism** only; the
separate `per-user-identity` **deployment** control, multi-tenant authorization,
verified reviewer identity, and audit-integrity blockers are untouched and remain
BLOCKED, so **GA remains `GA_BLOCKED`** (resolving one control never leaks
`GA_READY`).

### Reserved permissions

Three permissions preserved from the historical `benchmark_permissions` DTO —
`run_diagnostics`, `approve_ai_content`, `edit_decision_records` — are held by
roles but not yet wired to a route (their workflows are not yet implemented). They
are reserved capabilities in the stable permission surface; a granted-but-unchecked
permission authorizes nothing. They will bind to routes when those workflows land.

### Known follow-up

Denial audit events are unbounded by design (every authorization failure is
recorded for intrusion detection). Rate-limiting/retention for auth-failure floods
is an operational/audit-hardening follow-up tracked outside this increment.

## Tests

`scripts/route_rbac_guard.py` (`pnpm run audit:route-rbac`, also chained into
`audit:all`) asserts 100+ cases: policy structure and parity, the role/permission
matrix, denial of every mutation for roles lacking the permission, denial of
privileged reads, signed-capability behavior (resource-bound, expiring,
method-restricted, token-verified-first with no existence oracle and no audit
write), permission-before-lookup ordering (unauthorized callers get the same 403
for existing and nonexistent resources; authorized callers reach 404), minimal
public `/health` and gated detailed readiness (unauthenticated 401 / wrong-role
403 / admin 200, no path leak), client-mode docs hidden from non-admins, redacted
denial audit with correct permission/route/method, the evidence-driven
`rbac-role-separation` PASS, and regression that tenant/reviewer/audit-integrity
blockers stay BLOCKED and GA stays `GA_BLOCKED`.

## Non-goals (explicitly out of scope for this increment)

Multi-tenant resource authorization (a caller with a permission is still not
scoped to *their* tenant's resources here), verified reviewer workflow, keyed
audit integrity, and any persistence redesign. These remain declared blockers.

> **Update:** a later increment adds **API-layer tenant resource authorization**
> on top of route RBAC — after the permission gate, every resource route now
> compares the looked-up resource's `tenant_id` to the request tenant and hides
> cross-tenant resources behind an existence-hiding 404. See
> [`TENANT_AUTHORIZATION.md`](TENANT_AUTHORIZATION.md). Multi-tenant **storage**,
> normalized persistence, and **Postgres RLS** remain out of scope, so
> `tenant-authorization-enforcement` stays a declared blocker and GA stays
> `GA_BLOCKED`.
