-- 0007_tenant_rls_enforcement.sql
--
-- Database-enforced tenant isolation for the normalized persistence slice.
--
-- The four normalized tables (0005), the global state snapshot (0002) and the
-- idempotency records (0004) already ENABLE + FORCE row level security with a
-- tenant_isolation policy keyed on current_setting('app.tenant_slug', true)
-- (USING + WITH CHECK, fail-closed when the GUC is unset). This migration closes
-- the remaining gaps that let a mis-provisioned runtime connection bypass that
-- isolation:
--
--   1. Provision a dedicated, least-privilege NON-LOGIN application group role
--      `monday_report_app`. Operators create a LOGIN runtime role that INHERITs
--      it; that runtime role is NEITHER a superuser NOR BYPASSRLS NOR the table
--      owner, so FORCE row level security is actually enforced against it. The
--      group role is NOLOGIN so no password is embedded in SQL.
--
--   2. Extend forced RLS to the two foundation parent tables the normalized slice
--      writes through the runtime role: `tenants` and `workspaces`. Migration 0001
--      ENABLEs RLS on them but leaves the tenant_isolation policy as a commented
--      template, so a non-owner role would be denied ALL access (default-deny) and
--      could not perform the ensure-exists upserts that the composite tenant FKs
--      (0006) require. Here we add real FORCEd policies keyed to the same
--      app.tenant_slug GUC so the runtime role can manage exactly its own tenant
--      and workspace rows and nothing else.
--
--   3. Re-assert FORCE row level security on the four normalized tables so this
--      migration is a self-contained declaration of the enforced-RLS guarantee
--      (idempotent; 0005 already forces them).
--
-- This migration references only tables/columns created by earlier migrations
-- (tenants/workspaces from 0001; the normalized tables from 0005). It creates no
-- new tables. Superuser and BYPASSRLS roles still bypass RLS (and foreign-key
-- checks always bypass RLS) -- which is exactly why the runtime role must be
-- neither, enforced at application startup (backend/app/tenant_rls.py) and proven
-- by scripts/tenant_rls_enforcement_guard.py against a real non-superuser role.

-- 1) Least-privilege application group role (NOLOGIN, NOSUPERUSER, NOBYPASSRLS).
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'monday_report_app') then
    create role monday_report_app nologin nosuperuser nobypassrls
      nocreatedb nocreaterole noreplication inherit;
  end if;
end
$$;

-- Ensure the role never accumulates unsafe attributes even if it pre-existed.
-- Re-assert ONLY the security-critical attributes; deliberately do NOT touch
-- LOGIN here, so a re-run cannot strip LOGIN from a role an operator may have
-- provisioned as their runtime login role (the group role is created NOLOGIN
-- above, which is the intended default).
alter role monday_report_app nosuperuser nobypassrls nocreatedb nocreaterole
  noreplication;

-- 2) Forced tenant isolation on the parent tables the normalized slice writes.
--    tenants: gate directly on the slug (tenants.slug is the tenant identifier).
alter table tenants enable row level security;
alter table tenants force row level security;
drop policy if exists tenant_isolation_tenants on tenants;
create policy tenant_isolation_tenants on tenants
  using (slug = current_setting('app.tenant_slug', true))
  with check (slug = current_setting('app.tenant_slug', true));

--    workspaces: it carries tenant_id (uuid) but not the slug, so gate on the
--    tenant row selected by the current slug. The subquery reads `tenants`, which
--    is itself now restricted to the current tenant, so it resolves to exactly the
--    current tenant's id (or nothing when the GUC is unset -> deny).
alter table workspaces enable row level security;
alter table workspaces force row level security;
drop policy if exists tenant_isolation_workspaces on workspaces;
create policy tenant_isolation_workspaces on workspaces
  using (tenant_id = (select t.id from tenants t
                      where t.slug = current_setting('app.tenant_slug', true)))
  with check (tenant_id = (select t.id from tenants t
                           where t.slug = current_setting('app.tenant_slug', true)));

-- 3) Re-assert FORCE on the four normalized tables (idempotent; declared by 0005).
alter table monday_report_norm_reports force row level security;
alter table monday_report_norm_field_corrections force row level security;
alter table monday_report_norm_validation_tasks force row level security;
alter table monday_report_norm_validation_outcomes force row level security;

-- 4) Least-privilege grants for the runtime application role. Only schema USAGE,
--    sequence USAGE, and table DML on the tenant-scoped tables this slice uses.
--    No superuser, no BYPASSRLS, no ownership, no CREATE, no DDL, no migration
--    privilege. RLS (above) still constrains every row the role can see/write.
grant usage on schema public to monday_report_app;

grant select, insert, update, delete on
  tenants,
  workspaces,
  monday_report_state_snapshots,
  monday_report_idempotency_records,
  monday_report_norm_reports,
  monday_report_norm_field_corrections,
  monday_report_norm_validation_tasks,
  monday_report_norm_validation_outcomes
  to monday_report_app;

grant usage, select on all sequences in schema public to monday_report_app;
