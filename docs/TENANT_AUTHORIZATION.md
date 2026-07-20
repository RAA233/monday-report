# Tenant resource authorization (API layer)

This increment closes an API-layer **IDOR** gap: every entity already carried a
`tenant_id` and the authenticated request already resolved a `tenant_id`, but no
handler ever compared the two — so any authenticated caller could read or mutate a
resource belonging to another tenant simply by knowing its UUID. This change makes
the per-request tenant the enforced ownership boundary at the API layer.

It is a **bounded** slice. It is NOT multi-tenant storage, workspace
membership/ACLs, normalized Postgres persistence, or Postgres RLS. The process
still serves one configured tenant via the local JSON snapshot; those larger
controls remain declared GA blockers (see below).

## The authority: `backend/app/tenant_authorization.py`

A single, dependency-light module answers one question — *does this looked-up
resource belong to the tenant of the authenticated request?*

- `request_tenant_id()` — the request tenant, resolved **only** from the
  server-side authenticated identity (`identity.tenant_id`). It returns `None`
  when there is no active request identity and **never** falls back to a
  configured/system/all-tenant id. Absence of identity resolves to absence of
  access, never to system access.
- `resource_tenant_id(resource)` / `owns(resource, tenant_id)` — default-deny
  ownership predicate: a missing resource, an unknown request tenant, or a
  resource with no stamped tenant all deny.
- `tenant_visible(items, tenant_id)` — tenant filter for list/aggregate reads;
  an unknown tenant yields an empty list, never the full cross-tenant set.
- `SystemTenantContext` / `system_tenant_context(tenant_id, operation)` — an
  **explicit** context for worker/CLI/system operations that run outside a
  request. It requires an operation label, so a non-request tenant access is
  intentional and auditable — never implicit. Request handlers never construct
  it; they use `request_tenant_id()`.

Client-supplied tenant input is never trusted: no route accepts a tenant
identifier, and nothing in the authorization path reads a tenant from a request
body, query string, or header.

## Enforcement at the route layer (`backend/app/main.py`)

The order for every resource route is:

1. **authenticate** (middleware resolves the request identity),
2. **permission** (`require_permission` / `require_benchmark_permission`) — a
   missing/disabled identity or a role lacking the permission is denied **403**
   *before any resource lookup*, so no unauthorized caller can probe existence,
3. **lookup + tenant ownership graph** — `_tenant_owned(resource, …)` returns the
   resource only if it is owned by the request tenant **through the full ownership
   graph** (`tenant_authorization.owned_via_graph`): the resource's own `tenant_id`
   AND every present parent link (`workspace_id`/`upload_id`/`file_id`/
   `document_id`/`report_id`/`measurement_id`) must resolve to the request tenant.
   A record whose direct `tenant_id` matches but whose parent chain points at
   another tenant — a contradictory or broken chain — **fails closed**, never
   accepted because one field matches. A resource that is missing **or** not owned
   raises the **same 404 with the same body** (existence-hiding: a caller can never
   distinguish "does not exist" from "exists in another tenant"),
4. **operation**.

List, aggregate, and dashboard reads are tenant-filtered with `_tenant_items()`
(also graph-aware, so a contradictory child is excluded, not just a foreign-stamped
row): `/workspaces`, `/documents`, `/failures`, `/processing-jobs`,
`/validation-tasks`, `/monday-reports`, `/audit-logs`, `/benchmarking/config`,
`/dashboards/summary`, the chat evidence set, and the report-draft /
generated-report inputs — filtering happens **before** any count/sum/extrema, so
no list surfaces another tenant's rows and no aggregate counts them. The
benchmarking status builder in `backend/app/store.py` is fully tenant-scoped
(measurements, anomaly events, **approved benchmark values and rules**, comparisons,
Gordon/Noble extrema, and source references), so a foreign `workspace_id` on the
configuration-only path — and a foreign approved benchmark value in the shared
store — surfaces none of another tenant's data.

A per-route **parity** function, `main.tenant_ownership_fully_enforced()` (mirroring
`route_policy_fully_enforced()` for the permission layer), statically proves that
every resource-scoped route invokes a tenant-ownership dependency; the readiness
probe consumes it as machine-readable evidence.

Server-side stamping is unchanged and already correct: every create path stamps
`tenant_id=self.tenant.id`. Because all `tenant_id` fields already existed on the
schemas, this increment adds **no** schema field and performs **no** startup
backfill.

## Signed capabilities bind the tenant (`backend/app/signed_urls.py`)

Signed download tokens now carry the owning `tenant_id` in the signed, tamper-
evident payload:

- **Issuance** (`/report-exports/{id}/signed-url`,
  `/upload-files/{id}/signed-url`) is tenant-gated — a caller cannot mint a
  capability for another tenant's resource (404) — and binds the request tenant
  into the token.
- **Redemption** (the public `/signed/...` routes) verifies the token signature,
  resource, purpose, and expiry **first** (before any resource lookup or audit
  side effect, preserving the existing no-oracle ordering), then re-checks the
  token's bound tenant against the looked-up resource's own tenant. A token
  minted for one tenant's resource can never redeem another tenant's resource.

## Denial audit (tenant context, no leakage)

A genuine cross-tenant access attempt (the resource exists but is owned by another
tenant) writes an `authz.cross_tenant_denied` audit event stamped with the
**request's** tenant and actor. The metadata records only the caller-supplied
resource id/type and the request method/route — never the foreign owner's tenant
or any other cross-tenant detail. A truly-missing resource writes no such event.

## Readiness disposition (stays BLOCKED)

The GA blocker `tenant-authorization-enforcement`
(`evals/ga/blocker_registry.v1.json`) remains **BLOCKED** and GA remains
**GA_BLOCKED**. Its resolution condition requires tenant enforcement at the API
layer **and** Postgres RLS active over the normalized store. This increment
delivers the API-layer half only; the RLS-backed normalized multi-tenant store is
out of scope. The evidence-driven `_tenant_authorization_probe()` in
`backend/app/ga_readiness.py` inspects the actual route/authorization code, requires
`tenant_ownership_fully_enforced()` and `route_policy_fully_enforced()` (machine-
readable per-route parity, not mere substring presence), confirms the API-layer
enforcement is wired, and reports BLOCKED with that context — it never flips to PASS
on the API-layer evidence alone, and the registry is not weakened.

## Verification

`scripts/tenant_authorization_guard.py` (`pnpm run audit:tenant-authorization`,
also chained into `audit:all`) stands up the app with injected foreign tenant-B
fixtures and proves, across **90** behavioral vectors: the module's default-deny
ownership logic; the ownership graph fails closed on a contradictory
resource→parent→tenant chain and on a divergent child stamp; cross-tenant single-
resource access is an existence-hiding 404 across every route family while same-
tenant access succeeds; list/aggregate/dashboard/report-draft/generated-report reads
exclude foreign **and contradictory** rows before counting; the benchmarking status
excludes a foreign approved benchmark value; per-route tenant-ownership parity holds
(and fails when a resource route drops its dependency); signed capabilities bind the
tenant at issuance and redemption and a legacy unbound token is rejected; child
creation copies the parent tenant and a client body cannot override it; the request
identity context is isolated per request and resets after an exception; cross-tenant
denials are audited with request-tenant context and no foreign detail; an old
snapshot loads with no tenant-field backfill written; and the increment closes no
other GA blocker (route-level RBAC intact, GA still GA_BLOCKED).

## Explicitly out of scope (still declared blockers)

- Multi-tenant storage / a `tenants` collection (single configured tenant).
- Workspace membership or per-resource ACLs beyond tenant ownership.
- Normalized Postgres persistence and **Postgres RLS activation**.
- Verified reviewer identity and keyed audit-chain integrity (separate blockers).
