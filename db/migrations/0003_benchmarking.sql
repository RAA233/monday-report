-- Monday Report benchmarking and Management of Change evidence model.
-- Runtime currently persists through monday_report_state_snapshots; these
-- tenant-owned tables define the normalized repository target.

create table if not exists benchmark_providers (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  name text not null,
  provider_type text not null,
  approval_status text not null default 'approved',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, name)
);

create table if not exists benchmark_datasets (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  provider_id uuid references benchmark_providers(id),
  name text not null,
  dataset_version text not null,
  data_source text not null,
  effective_date date not null,
  approval_status text not null default 'approved',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, name, dataset_version)
);

create table if not exists benchmark_metrics (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  metric text not null,
  display_name text not null,
  canonical_unit text not null,
  created_at timestamptz not null default now(),
  unique (tenant_id, metric)
);

create table if not exists benchmark_values (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  dataset_id uuid references benchmark_datasets(id),
  metric_id uuid references benchmark_metrics(id),
  benchmark_name text not null,
  value numeric(14,4) not null,
  unit text not null,
  performance_category text not null,
  data_source text not null,
  effective_date date not null,
  dataset_version text not null,
  approval_status text not null default 'approved',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists benchmark_measurements (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  workspace_id uuid references workspaces(id),
  metric text not null,
  value numeric(14,4) not null,
  unit text not null,
  data_source text not null,
  data_timestamp timestamptz not null,
  confidence_status text not null,
  source_type text not null,
  source_identifier text not null,
  dataset_version text not null,
  created_at timestamptz not null default now()
);

create table if not exists anomaly_rules (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  metric text not null,
  name text not null,
  severity text not null,
  benchmark_name text not null,
  threshold_mode text not null,
  threshold_percent numeric(8,4),
  diagnostic_modules text[] not null default '{}',
  approval_status text not null default 'approved',
  updated_at timestamptz not null default now()
);

create table if not exists anomaly_events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  workspace_id uuid references workspaces(id),
  measurement_id uuid references benchmark_measurements(id),
  rule_id uuid references anomaly_rules(id),
  metric text not null,
  severity text not null,
  performance_status text not null,
  current_value numeric(14,4) not null,
  unit text not null,
  threshold_value numeric(14,4) not null,
  threshold_unit text not null,
  summary text not null,
  benchmark_evidence jsonb not null default '{}'::jsonb,
  moc_reference text,
  status text not null default 'active',
  created_at timestamptz not null default now()
);

create table if not exists diagnostic_actions (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  anomaly_event_id uuid not null references anomaly_events(id) on delete cascade,
  module text not null,
  status text not null default 'Recommended',
  reason text not null,
  authorized_user_id uuid references users(id),
  dismissal_reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists key_decisions (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  workspace_id uuid references workspaces(id),
  decision_timestamp timestamptz not null,
  decision_type text not null,
  title text not null,
  operational_context text not null,
  decision_made text not null,
  decision_owner text not null,
  expected_impact text not null,
  actual_impact text,
  affected_depth_or_interval text,
  related_risks jsonb not null default '[]'::jsonb,
  moc_reference text,
  approval_status text not null default 'review',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists decision_impacts (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  key_decision_id uuid not null references key_decisions(id) on delete cascade,
  expected_impact text not null,
  actual_impact text,
  evidence jsonb not null default '[]'::jsonb,
  approval_status text not null default 'review',
  created_at timestamptz not null default now()
);

create table if not exists report_approvals (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  report_id uuid references monday_reports(id),
  approval_state text not null,
  approved_by uuid references users(id),
  reason text,
  created_at timestamptz not null default now()
);

alter table benchmark_providers enable row level security;
alter table benchmark_datasets enable row level security;
alter table benchmark_metrics enable row level security;
alter table benchmark_values enable row level security;
alter table benchmark_measurements enable row level security;
alter table anomaly_rules enable row level security;
alter table anomaly_events enable row level security;
alter table diagnostic_actions enable row level security;
alter table key_decisions enable row level security;
alter table decision_impacts enable row level security;
alter table report_approvals enable row level security;

create index if not exists idx_benchmark_values_tenant_metric on benchmark_values (tenant_id, benchmark_name, metric_id);
create index if not exists idx_measurements_tenant_workspace_metric on benchmark_measurements (tenant_id, workspace_id, metric, data_timestamp desc);
create index if not exists idx_anomaly_events_tenant_status on anomaly_events (tenant_id, status, severity, created_at desc);
create index if not exists idx_key_decisions_tenant_workspace_time on key_decisions (tenant_id, workspace_id, decision_timestamp desc);
