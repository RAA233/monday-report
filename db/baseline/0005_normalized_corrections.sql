-- Normalized correction persistence (Phase 04 vertical slice).
--
-- In PostgreSQL mode these tables are the single write and read authority for
-- Monday Reports, field corrections, and validation tasks/outcomes; the global
-- snapshot no longer stores those entities (its keys are emptied and a marker
-- records the cutover). Typed columns carry every field that participates in
-- keys, relationships, lifecycle, revision, uniqueness, attribution or RLS;
-- `doc` holds the complete canonical entity so reconstruction is deterministic
-- and cannot drift from the application schema (consistency is guard-verified).
--
-- Lineage integrity across processes is DATABASE-enforced:
--   * one ACTIVE correction per (tenant, workspace, target_type, field_key)
--     via a partial unique index — the uniqueness constraint the registry
--     condition for correction-cross-process-atomicity names;
--   * one terminal validation outcome per task revision via UNIQUE;
--   * row locks + revision compare-and-swap inside the protected transaction.
--
-- No cascading deletes: deleting a referenced tenant/workspace/task is blocked
-- so audit-relevant records can never be erased transitively. Audit events are
-- referenced by UUID (`audit_event_id`) into the snapshot-owned HMAC-chained
-- audit log; the payload is never duplicated and a relational FK is not
-- compatible with that design.
--
-- RLS follows the established pattern (0002/0004): ENABLE + FORCE with a
-- tenant_isolation policy on `app.tenant_slug`, which the application already
-- sets transaction-locally on every transaction and read connection.

-- Composite-FK anchor: workspace rows are keyed (id, tenant_id) so child rows
-- can enforce tenant/workspace consistency in one constraint.
create unique index if not exists workspaces_id_tenant_uidx
  on workspaces (id, tenant_id);

create table if not exists monday_report_norm_reports (
  id uuid primary key,
  tenant_id uuid not null references tenants(id),
  tenant_slug text not null,
  workspace_id uuid not null,
  status text not null,
  revision bigint not null default 0,
  doc jsonb not null,
  audit_event_id uuid,
  operation_id text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint norm_reports_status_valid
    check (status in ('draft', 'review', 'approved', 'exported')),
  constraint norm_reports_revision_non_negative check (revision >= 0),
  constraint norm_reports_workspace_tenant_fk
    foreign key (workspace_id, tenant_id) references workspaces (id, tenant_id)
);

create index if not exists norm_reports_workspace_idx
  on monday_report_norm_reports (tenant_id, workspace_id);

create table if not exists monday_report_norm_field_corrections (
  id uuid primary key,
  tenant_id uuid not null references tenants(id),
  tenant_slug text not null,
  workspace_id uuid not null,
  target_type text not null,
  field_key text not null,
  status text not null,
  supersedes_id uuid references monday_report_norm_field_corrections(id),
  superseded_by_id uuid references monday_report_norm_field_corrections(id),
  actor_user_id uuid not null,
  reviewer_user_id uuid,
  revision bigint not null default 0,
  doc jsonb not null,
  audit_event_id uuid,
  operation_id text,
  created_at timestamptz not null default now(),
  reverted_at timestamptz,
  updated_at timestamptz not null default now(),
  constraint norm_corrections_status_valid
    check (status in ('active', 'superseded', 'reverted')),
  constraint norm_corrections_revision_non_negative check (revision >= 0),
  constraint norm_corrections_field_key_present check (length(field_key) > 0),
  constraint norm_corrections_workspace_tenant_fk
    foreign key (workspace_id, tenant_id) references workspaces (id, tenant_id)
);

-- THE lineage-integrity uniqueness constraint: at most one ACTIVE correction
-- per registered field coordinate. Two processes racing to correct the same
-- field cannot both commit an active record — the second violates this index
-- inside its own transaction and rolls back completely.
create unique index if not exists norm_corrections_one_active_uidx
  on monday_report_norm_field_corrections (tenant_id, workspace_id, target_type, field_key)
  where status = 'active';

create index if not exists norm_corrections_lineage_idx
  on monday_report_norm_field_corrections (tenant_id, workspace_id, target_type, field_key);

create table if not exists monday_report_norm_validation_tasks (
  id uuid primary key,
  tenant_id uuid not null references tenants(id),
  tenant_slug text not null,
  target_type text not null,
  target_id uuid not null,
  status text not null,
  revision bigint not null default 0,
  reviewer_user_id uuid,
  doc jsonb not null,
  audit_event_id uuid,
  operation_id text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint norm_tasks_status_valid
    check (status in ('open', 'validated', 'rejected', 'conflict')),
  constraint norm_tasks_revision_non_negative check (revision >= 0)
);

create index if not exists norm_tasks_tenant_status_idx
  on monday_report_norm_validation_tasks (tenant_id, status);

-- Terminal review outcomes are append-only history rows. UNIQUE(task_id,
-- task_revision) makes a second terminal outcome for the same task revision
-- impossible: whichever transaction commits second violates the constraint and
-- rolls back (state, audit event, idempotency record and all).
create table if not exists monday_report_norm_validation_outcomes (
  id uuid primary key,
  task_id uuid not null references monday_report_norm_validation_tasks(id),
  tenant_id uuid not null references tenants(id),
  tenant_slug text not null,
  task_revision bigint not null,
  outcome text not null,
  reviewer_user_id uuid not null,
  reviewer_verified boolean not null default false,
  audit_event_id uuid,
  operation_id text,
  reviewed_at timestamptz not null default now(),
  constraint norm_outcomes_terminal_only
    check (outcome in ('validated', 'rejected', 'conflict')),
  constraint norm_outcomes_revision_non_negative check (task_revision >= 0),
  constraint norm_outcomes_one_per_revision unique (task_id, task_revision)
);

create index if not exists norm_outcomes_tenant_idx
  on monday_report_norm_validation_outcomes (tenant_id, task_id);

-- Forced tenant isolation, same pattern and GUC as the snapshot and
-- idempotency tables. A connection without app.tenant_slug set sees nothing.
alter table monday_report_norm_reports enable row level security;
alter table monday_report_norm_reports force row level security;
drop policy if exists tenant_isolation_norm_reports on monday_report_norm_reports;
create policy tenant_isolation_norm_reports on monday_report_norm_reports
  using (tenant_slug = current_setting('app.tenant_slug', true))
  with check (tenant_slug = current_setting('app.tenant_slug', true));

alter table monday_report_norm_field_corrections enable row level security;
alter table monday_report_norm_field_corrections force row level security;
drop policy if exists tenant_isolation_norm_field_corrections on monday_report_norm_field_corrections;
create policy tenant_isolation_norm_field_corrections on monday_report_norm_field_corrections
  using (tenant_slug = current_setting('app.tenant_slug', true))
  with check (tenant_slug = current_setting('app.tenant_slug', true));

alter table monday_report_norm_validation_tasks enable row level security;
alter table monday_report_norm_validation_tasks force row level security;
drop policy if exists tenant_isolation_norm_validation_tasks on monday_report_norm_validation_tasks;
create policy tenant_isolation_norm_validation_tasks on monday_report_norm_validation_tasks
  using (tenant_slug = current_setting('app.tenant_slug', true))
  with check (tenant_slug = current_setting('app.tenant_slug', true));

alter table monday_report_norm_validation_outcomes enable row level security;
alter table monday_report_norm_validation_outcomes force row level security;
drop policy if exists tenant_isolation_norm_validation_outcomes on monday_report_norm_validation_outcomes;
create policy tenant_isolation_norm_validation_outcomes on monday_report_norm_validation_outcomes
  using (tenant_slug = current_setting('app.tenant_slug', true))
  with check (tenant_slug = current_setting('app.tenant_slug', true));
