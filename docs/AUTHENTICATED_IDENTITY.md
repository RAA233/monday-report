# Authenticated Identity Foundation

This document describes the **bounded first slice** of authenticated identity in
Monday Report: opaque per-user credentials resolved server-side to a
request-scoped identity, wired to the existing role/permission policy and audit
actor. It is a **foundation** — it is **not** complete multi-tenant
authorization, complete route-level RBAC, or verified reviewer identity. Those
remain declared blockers in `evals/ga/blocker_registry.v1.json`, and the
readiness gate stays **`GA_BLOCKED`**.

> **See also:** complete route-level RBAC — the generic authorization authority
> (`backend/app/permissions.py`) that permission-gates every privileged read and
> mutation on top of this identity foundation — is documented separately in
> [`ROUTE_RBAC.md`](ROUTE_RBAC.md). Multi-tenant resource authorization and
> verified reviewer identity remain out of scope there too.

## What existed before

- A single shared `MONDAY_REPORT_API_KEY` authenticated **every** request (in
  client mode). Demo mode enforced no auth at all.
- Requests did not resolve a per-user identity; permission checks and the audit
  actor used one process-global configured user that held all roles.
- Field corrections recorded `actor_source="configured"`.
- Client-supplied workspace IDs were not associated with a request identity, and
  there was no credential revocation or account-disable mechanism (no per-user
  credentials existed to store).

## Credential model

`StoredApiCredential` (persisted) carries: `credential_id`, `user_id`,
`tenant_id`, `token_hash`, `token_fingerprint`, `status` (`active`/`revoked`),
`authentication_source`, `created_at`, `revoked_at`, `last_used_at`.

### Token storage and secret handling

- Tokens are generated server-side from **≥32 random bytes**
  (`secrets.token_urlsafe(32)`).
- Only a **deterministic SHA-256 hash** (domain-separated, with an optional
  server pepper `MONDAY_REPORT_CREDENTIAL_PEPPER`) is persisted, plus a short
  **non-secret fingerprint** derived from an independent domain-separated hash.
- The **raw token is never persisted, returned after creation, logged, put in
  audit metadata, or included in readiness evidence or screenshots**.
- Credential hashes are compared with a **constant-time** comparison
  (`hmac.compare_digest`). Malformed or unreasonably long tokens are rejected
  **before** any lookup.

## Credential transport

Credentials are presented in the existing `X-Monday-Report-Key` header. The
value is now an **opaque per-user token resolved to a user**, not a global
identity bypass. The server **never trusts** client-supplied identity fields
(`X-User-Id`, `X-User-Email`, `X-Role`, `X-Tenant`, or client-supplied
actor/permission fields). Identity is resolved **exclusively** from the
presented credential and server-side records.

## Bootstrap compatibility and client-mode restriction

- **Demo/local mode:** the configured user is exposed as an explicit
  `demo_bootstrap` administrator, derived **in memory** (never persisted — see
  "No startup persistence"). The existing shared key and existing local clients
  continue to work; every request still carries a request-scoped actor.
  `demo_bootstrap` is **not** verified per-user identity and is **not** suitable
  for client mode.
- **Client mode:** the legacy configured shared key and any bootstrap-only
  credential are **rejected** (HTTP 401). There is **no** client-mode shared-key
  administrator. A client-mode request must present an **active persisted
  non-bootstrap per-user credential** whose user is active and whose user and
  credential are both bound to the configured tenant, with server-side roles.
  When no such credential exists, the client-mode server **fails closed** (all
  authenticated routes 401) and readiness stays blocked. No environment flag can
  re-enable a global client-mode administrator.

## Secure initial provisioning

Because client mode rejects the shared key, the first client administrator is
provisioned **out-of-band** with the local CLI (no unauthenticated network
bootstrap route exists):

```
python -m backend.app.identity_admin create-user \
    --email admin@client.example --full-name "Client Admin" \
    --role admin --confirm-tenant <tenant-slug> --yes
python -m backend.app.identity_admin create-credential \
    --user-id <uuid> --confirm-tenant <tenant-slug> --yes
python -m backend.app.identity_admin revoke-credential --credential-id <uuid> --yes
```

The CLI runs locally against the configured state, operates only through the
validated store methods, never embeds a default credential, returns the raw
token **once** (only its hash + fingerprint are stored, audited without the raw
token), enforces `--confirm-tenant` against the configured tenant slug, and
requires an interactive confirmation or the non-interactive `--yes` flag.

## No startup persistence

The demo bootstrap identity is derived in memory from the configured local
settings. A user is persisted **only** through an explicit provisioning
operation (`create_user` / the CLI). Importing the store, constructing the app,
starting or reloading the server, running `/health`, or viewing a route
**never** writes a user or credential to the snapshot.

## Request-scoped identity

The auth middleware resolves the presented credential and sets the identity in a
`ContextVar` for the duration of the request, resetting it in a `finally`
(request cleanup). This keeps identity **request-scoped**: two concurrent
requests with different users retain different actors, permission results do not
leak between requests, and worker/CLI operations that run outside any request
use an explicit **`system`** actor. `store.user` is **not** mutated to represent
the current request.

## Existing roles only

Only the existing repository roles are used: `ADMIN`, `ENGINEER`, `VALIDATOR`,
`MANAGER`. The `VIEWER` role is intentionally **not** enabled in this increment,
and no new organizational roles were invented.

## Permission evaluation

`store.benchmark_permissions(identity)` derives permissions from the **resolved
request identity's roles**. Enforcement is **default-deny**: a missing identity,
a disabled identity, an empty role list, an unknown role, or an unknown
permission all deny; there is **no all-role fallback**, and client-supplied roles
are ignored.

## Route-policy inventory

`ROUTE_ACCESS_POLICY` in `backend/app/main.py` classifies **every** route as
exactly one of the four approved categories: `public`, `authenticated_read`,
`permission_required`, or `system_internal`. A `permission_required` row carries
an `enforcement_status`:

- **`enforced`** — the route calls a `require_*` dependency with a named
  permission (a `benchmark_permissions()` key, or `__admin__` for
  identity/credential administration).
- **`pending`** — the route is sensitive and **must** be permission-gated but is
  **not yet** enforced. A pending route does **not** count as protected.

`validate_route_access_policy()` fails if a route lacks a classification; a
sensitive mutation (POST/PUT/PATCH/DELETE) is classified `public` or
`authenticated_read`; an `enforced` row lacks or names an unknown permission; a
`pending` row claims an enforced permission; or a policy row does not match a
real route. `route_policy_fully_enforced()` is **False** while any `pending`
route exists, and `pending_permission_routes()` lists them. Because pending
routes remain, **`rbac-role-separation` stays a declared blocker** —
route-level RBAC is **not** complete. `audit:identity-rbac` enforces all of this.

## Tenant boundary (this increment)

API-layer tenant resource authorization is delivered by a later increment
(`docs/TENANT_AUTHORIZATION.md`): once an identity is resolved, every resource
route compares the looked-up resource's `tenant_id` to the request tenant and
hides cross-tenant resources behind an existence-hiding 404. Full multi-tenant
**storage** and **Postgres RLS** remain out of scope and a declared blocker. This
slice enforces the existing **configured-tenant boundary** at authentication: a
credential is valid only when
`credential.tenant_id == user.tenant_id == configured runtime tenant_id`. A
credential for another tenant, a user for another tenant, a credential/user
tenant mismatch, a missing tenant binding, or a client-supplied tenant override
is rejected. **`tenant-authorization-enforcement` stays BLOCKED** — this is a
single-tenant boundary foundation only.

## Actor provenance

Audit events and field corrections record the resolved request actor:
authenticated user id, tenant id, roles, `actor_source`
(`authenticated`/`demo_bootstrap`/`system`), and a non-secret credential
fingerprint. They never record the raw token, the token hash, correction source/
corrected values, correction reason text, or secret environment values. The
audit `entry_hash` payload is intentionally unchanged (the actor user id is
already sealed), so existing sealed chains still verify — **keyed/tamper-evident
audit integrity remains a separate declared blocker**. The presence of an
authenticated actor alone does **not** resolve `verified-reviewer-identity`:
review-role eligibility and review-workflow coverage remain separately required.
This is now **delivered for correction/validation outcomes** — see
`docs/VERIFIED_REVIEWER_ATTRIBUTION.md` (`audit:verified-reviewer`);
`ga_verified_reviewer_identity` is evidence-driven **PASS** while the other
blockers keep `ga:readiness` at `GA_BLOCKED`.

## Credential provisioning and revocation

Administrator-only endpoints (`require_admin`, i.e. an active identity with the
`ADMIN` role):

- `GET /auth/users`, `POST /auth/users` (create a user with roles)
- `POST /auth/users/{user_id}/credentials` (generate a token — returned **once**,
  only its hash stored, audited without the raw token)
- `GET /auth/credentials`, `POST /auth/credentials/{credential_id}/revoke`
  (revocation is idempotent, takes effect immediately, and never reveals token
  material)
- `GET /auth/session` returns only **non-secret** identity context (user id,
  tenant id, email/display name, roles, permissions, authentication source,
  credential id/fingerprint, account status) — never the token or its hash.

## Readiness behavior

This increment **closes no GA blocker**. `per-user-identity`,
`rbac-role-separation`, `tenant-authorization-enforcement`, and
`verified-reviewer-identity` all remain declared `BLOCKED`/`REVIEW_REQUIRED` in
the registry (resolution conditions unchanged), and `ga:readiness` remains
**`GA_BLOCKED`**. Per-user identity evidence is credential-driven
(`store.has_non_bootstrap_identity()`), never a flag.

## Persistence and migration limitation

Users and credentials are stored as additive collections in the existing local
JSON / Postgres JSONB snapshot; old snapshots load with empty identity
collections and are bootstrapped on init. **Normalized identity tables** (the
`users`/`roles`/`permissions` tables in `db/schema.sql`), a migration runner, and
cross-process transactional guarantees remain part of the persistence/migration
blocker (Phase 04) — not claimed complete here. `last_used_at` tracking is
best-effort and not written on the hot authentication path.

## Security limitations

- Identity is server-resolved from the credential, never a client-asserted
  header (no impersonation via headers).
- Default-deny RBAC with per-user roles (no privilege escalation via a missing
  role); disabled users and revoked credentials are denied on the next request.
- The single-tenant boundary is enforced, but full cross-tenant/workspace
  authorization (IDOR protection) is **not** delivered here.
- The audit chain is unkeyed (a separate blocker); the demo bootstrap identity is
  a labelled compatibility path, not verified human identity.
- No interactive session/password login, SSO, or production identity-provider
  integration is delivered.

## Follow-up sequence

1. Full tenant/workspace authorization (IDOR protection, tenant-filtered
   list/read/write) — closes `tenant-authorization-enforcement`.
2. Verified reviewer attribution (review-role eligibility + workflow coverage) —
   closes `verified-reviewer-identity`.
3. Complete route-level RBAC coverage — closes `rbac-role-separation`.
4. Keyed/tamper-evident audit integrity; normalized identity persistence +
   migration runner (Phase 04); interactive session login / SSO.
