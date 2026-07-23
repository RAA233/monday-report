# Tenant RLS Enforcement — database-enforced tenant isolation for the normalized slice

Status: **implemented in `feat/tenant-rls-enforcement`; the `tenant-authorization-enforcement`
GA control becomes PASS-capable only with valid RLS evidence. Release stays GA_BLOCKED.**

This increment adds the **database-enforcement half** of the existing
`tenant-authorization-enforcement` control. The API-layer half (per-request tenant
resolved from the authenticated identity and enforced by `backend/app/tenant_authorization.py`
with existence-hiding ownership checks) already shipped. Its registry resolution condition
is, verbatim:

> Tenant is resolved from the authenticated request and enforced at the API layer
> (with Postgres RLS active for the normalized store).

So RLS is **part of this same control**, not a new one. This increment does **not** modify
the registry; it makes the existing control PASS-capable by proving the "Postgres RLS active"
clause with committed evidence from a real, non-superuser runtime role.

Out of scope (explicitly not in this increment): the production PostgreSQL adapter being the
live runtime (`production-database-adapter` stays non-PASS), Redis, backup/restore, CI,
deployment, and `migration-validity` (still BLOCKED on the legacy `0003` FK). This increment
adds no new release control.

## 1. Authoritative tenant context

The database tenant context is a **verified server value**. It is derived only from:

- the **authenticated identity** (`get_current_identity().tenant_id/slug`, resolved
  server-side from the presented credential — never from client input), which for this
  single-configured-tenant-per-process store always equals `store.tenant`;
- an **authorized workspace/report/task relationship** (the `tenant_authorization` ownership
  graph already gates every resource-scoped route);
- an **explicit worker job ownership** context (jobs are stamped with `tenant_id` at enqueue
  time; the worker processes the configured tenant's snapshot under the store's own
  transaction, which sets the context);
- an **explicit, audited administrative operation** (the migration/admin connection — a
  separate DSN/role — used only by operator tooling, never by an HTTP request).

The database tenant context is **never** derived from: a request payload tenant field, a query
parameter, an unverified header, the idempotency key, a client-selected role, or stale pooled
connection state. (The store never reads a tenant from the request body/query/header; it stamps
writes with `self.tenant.id` and scopes reads with explicit `tenant_id/tenant_slug` predicates.)

## 2. Mechanism — transaction-local GUC `app.tenant_slug`

The context is applied as a **transaction-local** PostgreSQL setting:

```sql
select set_config('app.tenant_slug', :verified_tenant_slug, true);  -- is_local => true
```

`app.tenant_slug` is the **existing, wired, tested** convention (the task permits following
repository conventions). Every enforced RLS policy on the Postgres-active tables
(`monday_report_state_snapshots` 0002, `monday_report_idempotency_records` 0004, and the four
`monday_report_norm_*` tables 0005) keys on `current_setting('app.tenant_slug', true)` with both
`USING` and `WITH CHECK`, and every table is `ENABLE`d **and** `FORCE`d. `current_setting(...,
true)` returns `NULL` when the GUC is unset, and `tenant_slug` is `NOT NULL`, so a connection
without the context set matches **no** rows and can write **no** rows — fail-closed by construction.

We deliberately do **not** switch to `app.tenant_id`. The unused `db/schema.sql` reference keys
on `app.tenant_id`, but nothing in the runtime sets it; adopting it would require rewriting every
applied policy, the store, the import tool, and a data path — strictly more risk for no isolation
benefit. `tenant_slug` is FK-bound to `tenant_id` by the composite `(tenant_id, tenant_slug) →
tenants(id, slug)` foreign keys added in 0006, so the slug cannot diverge from the id.

### GUC trust model (what RLS-with-a-GUC does and does not defend)

RLS keyed on the `app.tenant_slug` GUC is a **defense-in-depth** boundary at the database, not
an absolute one. It **does** defend against:

- a **missing** context (unset GUC → `NULL` → every policy denies);
- a query that **forgets the tenant predicate** (RLS still scopes results to the set slug);
- **route/payload/header tenant spoofing** (the slug is derived from authenticated server state
  — the store never reads a tenant from client input).

It **does not** defend against **total compromise of, or arbitrary SQL execution as, the trusted
runtime principal**: a connected SQL principal *can* execute `SELECT set_config('app.tenant_slug',
'<another-valid-tenant>', true)` and read that tenant's rows. This is inherent to any
application-set-GUC RLS design and is verified empirically by the guard (check 47). RLS therefore
**reduces blast radius** and enforces the API-layer tenant boundary at the database, but is not a
hard boundary against a fully compromised runtime role. That is precisely why the runtime role is
**least-privilege, non-superuser, non-`BYPASSRLS`, and non-owner**, why cross-tenant administrative
work uses a **separate** role, and why this remains one control within a still-`GA_BLOCKED` product
rather than a claim of complete multi-tenant isolation. The evidence records this limitation in a
`guc_trust_model` field; the readiness probe rejects evidence that omits the disclosure.

### Context contract (enforced)

1. Context is set on the **same connection and transaction** the repository uses
   (`repositories.Pg*Repository` reuse `store._txn['connection']`; non-owner reads use
   `store._connect()` + `_apply_tenant_scope`).
2. Context is set **before the first tenant-sensitive query** (immediately after `BEGIN`, before
   the advisory lock and the `FOR UPDATE` read).
3. Context is **transaction-local** (`is_local => true`).
4. **Missing** context → the RLS policy denies (no row visible/writable).
5. **Invalid/empty/mismatched** context → denied; additionally the store now **verifies**
   `current_setting('app.tenant_slug')` equals the intended slug and is non-empty immediately
   after setting it, and raises `TenantContextError` if not (defense in depth against a silently
   dropped GUC).
6. **Rollback clears** context (transaction-local settings are discarded on rollback).
7. **Commit clears** context (transaction-local settings do not outlive the transaction).
8. **Pool reuse** cannot retain the previous tenant: the store uses **connect-per-operation**
   (no pool); each connection is opened fresh and `close()`d in `finally`. Even under a
   hypothetical pool, a transaction-local GUC is gone at transaction end, and a fresh transaction
   with no `set_config` sees `NULL` → deny.
9. **Nested repository calls** run on the owning transaction's connection and therefore share the
   already-set context.
10. Nested calls **cannot replace** the tenant: repositories never call `set_config`; only the
    store's transaction boundary sets it, once, from `self.tenant.slug`.
11. A **different actor/task cannot inherit** another context: ownership is a `contextvars`
    token (`_txn_owner`), so only the opening execution context can use the transaction's
    connection; every other context opens its own connection with its own context.
12. **Administrative bypass is explicit, narrow, and audited** — see §4.

## 3. Role separation (protected mode)

Protected PostgreSQL mode distinguishes two roles by two DSN env vars (the seam already exists):

- **Migration/admin role** — `MONDAY_REPORT_MIGRATIONS_DATABASE_URL`. May run schema migrations
  and manage policies/roles; typically owns the tables. Used only by the explicit operator
  command `python -m backend.app.migrations` (never on API startup) and by any deliberate
  cross-tenant administrative operation.
- **Runtime application role** — `MONDAY_REPORT_DATABASE_URL`. Must be
  `rolsuper = false` and `rolbypassrls = false`, must not own the protected tables in a way that
  bypasses RLS, and must not equal the migration role. Granted only schema `USAGE`, sequence
  `USAGE`, and `SELECT/INSERT/UPDATE/DELETE` on the tenant-scoped tables it uses (plus `SELECT`
  on `tenants`/`workspaces` for FK/joins). Granted **no** superuser, `BYPASSRLS`, database or
  schema ownership, role creation, or migration privilege.

Migration `0007_tenant_rls_enforcement.sql` provisions a **NOLOGIN group role**
`monday_report_app` carrying exactly this least-privilege grant set (a NOLOGIN group so no
password is embedded in SQL), re-asserts `FORCE ROW LEVEL SECURITY` on the four normalized
tables (idempotent; self-contained), and documents that operators create a **LOGIN** runtime
role that `INHERIT`s `monday_report_app` and is neither superuser nor `BYPASSRLS` nor the owner.

### Runtime configuration validation (fail-closed)

At `PostgresStateStore` construction in protected mode, the store now measures the runtime
connection's role and **rejects** (raising a redacted `TenantRuntimeRoleError`, refusing to
start the protected store) when the runtime role is a superuser, has `BYPASSRLS`, owns a
protected table that is not `FORCE`d (owner-bypass), equals the migration role, or when a
required forced-RLS policy is absent. The error text names only the failed property — never a
password, DSN, host, or role secret. Demo/local mode is unchanged and makes **no** claim of
database tenant enforcement.

`FORCE ROW LEVEL SECURITY` is required so that even the table **owner** is subject to the
policy; a superuser or `BYPASSRLS` role still bypasses RLS (foreign-key checks always bypass
RLS), which is exactly why those roles are rejected for the runtime and why the evidence is only
credible when produced by a real non-superuser runtime role.

## 4. Administrative bypass

There is **no runtime administrative cross-tenant bypass**. Cross-tenant operations are performed
only through the separate migration/admin connection by explicit operator tooling — not reachable
from any HTTP payload, header, or query parameter, and not from the runtime application role. This
is the safest posture (no bypass surface to leak through a pooled connection). The guard proves
the absence: no runtime code path enables a cross-tenant read, and the runtime role cannot switch
tenants (a `set_config` to a foreign slug still yields only that foreign tenant's rows — never a
union — and the runtime only ever sets its own configured slug).

## 5. Evidence and readiness

`scripts/tenant_rls_enforcement_guard.py` (wired as `audit:tenant-rls-enforcement`, and into
`audit:all`) proves the full matrix against a real disposable PostgreSQL using a **real
non-superuser runtime login role** — schema/roles/direct-SQL/routes/worker/pool/import/inventory
— and, with `--emit-evidence`, writes
`output/tenant-rls/tenant-rls-enforcement-evidence.v1.json` bound to the git commit/tree, a clean
worktree, the real PostgreSQL server version, and the image digest.

`backend/app/ga_readiness.py::_tenant_authorization_probe` keeps its API-layer parity checks and,
additionally, loads that evidence: the control flips to **PASS only** when the API-layer half is
fully enforced **and** the evidence proves forced RLS is enforced against a non-superuser,
non-`BYPASSRLS`, non-owner-bypass runtime role (all `*_result` fields `passed`, `failed == 0`,
`skipped == 0`, `runtime_role_is_superuser == false`, `runtime_role_has_bypassrls == false`,
`rls_forced_table_count >= 4`, commit/tree/worktree/PG-version/digest bindings valid). Without
the evidence the control stays **BLOCKED**. `production-database-adapter` remains non-PASS and
`migration-validity` remains BLOCKED; **GA remains GA_BLOCKED**.
