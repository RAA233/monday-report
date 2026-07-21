-- Active MVP repository adapter state table.
-- This table lets the current Monday Report API run from PostgreSQL instead
-- of local JSON while normalized table repositories are expanded.

create table if not exists monday_report_state_snapshots (
  tenant_slug text primary key,
  tenant_id uuid not null,
  payload jsonb not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table monday_report_state_snapshots enable row level security;
alter table monday_report_state_snapshots force row level security;

drop policy if exists tenant_isolation_monday_report_state_snapshots on monday_report_state_snapshots;

create policy tenant_isolation_monday_report_state_snapshots
on monday_report_state_snapshots
using (tenant_slug = current_setting('app.tenant_slug', true))
with check (tenant_slug = current_setting('app.tenant_slug', true));
