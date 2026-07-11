-- Monday Report MVP schema.
-- All tenant-owned tables carry tenant_id and are intended to run with PostgreSQL RLS.

create extension if not exists pgcrypto;
create extension if not exists vector;

create table tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  region text not null default 'us',
  plan text not null default 'enterprise-trial',
  encryption_key_ref text,
  retention_policy jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table users (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  email citext not null,
  full_name text not null,
  auth_provider_id text,
  status text not null default 'active',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, email)
);

create table roles (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  name text not null,
  description text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, name)
);

create table permissions (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  role_id uuid not null references roles(id),
  resource text not null,
  action text not null,
  created_at timestamptz not null default now(),
  unique (role_id, resource, action)
);

create table projects (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  name text not null,
  operator text,
  asset text,
  campaign text,
  status text not null default 'active',
  source_confidence numeric(4,3) not null default 1,
  validation_status text not null default 'validated',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table wells (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  project_id uuid references projects(id),
  name text not null,
  field text,
  country text,
  basin text,
  block text,
  spud_date date,
  aliases text[] not null default '{}',
  source_confidence numeric(4,3) not null default 1,
  validation_status text not null default 'validated',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, name)
);

create table rigs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  name text not null,
  rig_number text,
  contractor text,
  rig_type text,
  source_confidence numeric(4,3) not null default 1,
  validation_status text not null default 'validated',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, name)
);

create table companies (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  canonical_name text not null,
  aliases text[] not null default '{}',
  role_types text[] not null default '{}',
  source_confidence numeric(4,3) not null default 1,
  validation_status text not null default 'needs_review',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, canonical_name)
);

create table file_uploads (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  project_id uuid references projects(id),
  source text not null,
  submitted_by uuid references users(id),
  manifest jsonb not null default '{}'::jsonb,
  status text not null default 'queued',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table reports (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  project_id uuid references projects(id),
  well_id uuid references wells(id),
  rig_id uuid references rigs(id),
  upload_id uuid references file_uploads(id),
  report_type text not null,
  report_date date,
  title text,
  source_confidence numeric(4,3) not null default 0,
  validation_status text not null default 'needs_review',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table report_files (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  upload_id uuid references file_uploads(id),
  report_id uuid references reports(id),
  original_path text not null,
  storage_uri text not null,
  sha256 text not null,
  mime_type text,
  byte_size bigint not null default 0,
  parse_status text not null default 'queued',
  parser_version text,
  source_confidence numeric(4,3) not null default 1,
  validation_status text not null default 'validated',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, sha256)
);

create table report_pages (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  report_file_id uuid not null references report_files(id),
  page_number int,
  sheet_name text,
  row_start int,
  row_end int,
  text_content text,
  layout jsonb not null default '{}'::jsonb,
  ocr_quality numeric(4,3),
  source_confidence numeric(4,3) not null default 0,
  validation_status text not null default 'needs_review',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table report_chunks (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  report_page_id uuid not null references report_pages(id),
  chunk_text text not null,
  chunk_metadata jsonb not null default '{}'::jsonb,
  embedding vector(1536),
  tsv tsvector generated always as (to_tsvector('english', coalesce(chunk_text, ''))) stored,
  source_confidence numeric(4,3) not null default 0,
  validation_status text not null default 'needs_review',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table tools (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  tool_type text not null,
  manufacturer text,
  model text,
  size_label text,
  aliases text[] not null default '{}',
  source_confidence numeric(4,3) not null default 0,
  validation_status text not null default 'needs_review',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table tool_instances (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  tool_id uuid references tools(id),
  provider_company_id uuid references companies(id),
  serial_number text not null,
  configuration jsonb not null default '{}'::jsonb,
  source_confidence numeric(4,3) not null default 0,
  validation_status text not null default 'needs_review',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, serial_number)
);

create table drilling_sections (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  well_id uuid references wells(id),
  hole_size_in numeric(6,3),
  casing_size_in numeric(6,3),
  section_name text,
  depth_in_md_ft numeric(12,2),
  depth_out_md_ft numeric(12,2),
  formation text,
  source_confidence numeric(4,3) not null default 0,
  validation_status text not null default 'needs_review',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table bha_runs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  well_id uuid references wells(id),
  rig_id uuid references rigs(id),
  drilling_section_id uuid references drilling_sections(id),
  bha_number text,
  run_number text,
  depth_in_md_ft numeric(12,2),
  depth_out_md_ft numeric(12,2),
  run_hours numeric(10,2),
  source_confidence numeric(4,3) not null default 0,
  validation_status text not null default 'needs_review',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  project_id uuid references projects(id),
  report_id uuid references reports(id),
  well_id uuid references wells(id),
  rig_id uuid references rigs(id),
  drilling_section_id uuid references drilling_sections(id),
  bha_run_id uuid references bha_runs(id),
  event_type text not null,
  summary text not null,
  event_start timestamptz,
  event_end timestamptz,
  depth_md_ft numeric(12,2),
  severity text not null default 'Medium',
  source_confidence numeric(4,3) not null default 0,
  validation_status text not null default 'needs_review',
  extraction_method text not null default 'ai',
  extractor_version text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table failures (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  event_id uuid not null references events(id) on delete cascade,
  company_id uuid references companies(id),
  tool_instance_id uuid references tool_instances(id),
  failure_mode text,
  failed_component text,
  mechanism text,
  root_cause text,
  contributing_factors text[],
  corrective_action text,
  recommendation text,
  source_confidence numeric(4,3) not null default 0,
  validation_status text not null default 'needs_review',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table npt_events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  event_id uuid not null references events(id) on delete cascade,
  npt_hours numeric(10,2) not null default 0,
  category text,
  responsible_company_id uuid references companies(id),
  cost_impact_usd numeric(14,2),
  source_confidence numeric(4,3) not null default 0,
  validation_status text not null default 'needs_review',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table citations (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  event_id uuid references events(id) on delete cascade,
  report_file_id uuid references report_files(id),
  report_page_id uuid references report_pages(id),
  page_number int,
  sheet_name text,
  row_number int,
  text_snippet text not null,
  bbox jsonb,
  source_confidence numeric(4,3) not null default 0,
  validation_status text not null default 'needs_review',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table validation_tasks (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  object_type text not null,
  object_id uuid not null,
  reason text not null,
  priority int not null default 3,
  assigned_to uuid references users(id),
  status text not null default 'open',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table chat_sessions (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  project_id uuid references projects(id),
  user_id uuid references users(id),
  title text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table chat_messages (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  chat_session_id uuid not null references chat_sessions(id),
  role text not null,
  content text not null,
  answer_json jsonb,
  model_name text,
  model_version text,
  source_confidence numeric(4,3) not null default 0,
  validation_status text not null default 'needs_review',
  created_at timestamptz not null default now()
);

create table risk_scores (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  target_type text not null,
  target_id uuid not null,
  score numeric(6,3) not null,
  drivers jsonb not null default '[]'::jsonb,
  model_version text not null,
  source_confidence numeric(4,3) not null default 0,
  validation_status text not null default 'needs_review',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table processing_jobs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  upload_id uuid references file_uploads(id),
  job_type text not null,
  status text not null default 'queued',
  retry_count int not null default 0,
  error_message text,
  timings jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table export_jobs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  requested_by uuid references users(id),
  format text not null,
  filters jsonb not null default '{}'::jsonb,
  status text not null default 'queued',
  output_uri text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table audit_logs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  actor_user_id uuid references users(id),
  action text not null,
  resource_type text not null,
  resource_id uuid,
  ip_address inet,
  user_agent text,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index idx_events_tenant_type_date on events (tenant_id, event_type, event_start);
create index idx_events_tenant_validation on events (tenant_id, validation_status, severity);
create index idx_failures_tenant_company on failures (tenant_id, company_id);
create index idx_npt_tenant_hours on npt_events (tenant_id, npt_hours desc);
create index idx_report_chunks_tsv on report_chunks using gin (tsv);
create index idx_report_chunks_embedding on report_chunks using hnsw (embedding vector_cosine_ops);
create index idx_audit_logs_tenant_created on audit_logs (tenant_id, created_at desc);

alter table users enable row level security;
alter table projects enable row level security;
alter table wells enable row level security;
alter table rigs enable row level security;
alter table companies enable row level security;
alter table file_uploads enable row level security;
alter table reports enable row level security;
alter table report_files enable row level security;
alter table report_pages enable row level security;
alter table report_chunks enable row level security;
alter table tools enable row level security;
alter table tool_instances enable row level security;
alter table drilling_sections enable row level security;
alter table bha_runs enable row level security;
alter table events enable row level security;
alter table failures enable row level security;
alter table npt_events enable row level security;
alter table citations enable row level security;
alter table validation_tasks enable row level security;
alter table chat_sessions enable row level security;
alter table chat_messages enable row level security;
alter table risk_scores enable row level security;
alter table processing_jobs enable row level security;
alter table export_jobs enable row level security;
alter table audit_logs enable row level security;

-- Application code should set: select set_config('app.tenant_id', '<tenant uuid>', true);
create policy tenant_isolation_users on users
  using (tenant_id::text = current_setting('app.tenant_id', true));

create policy tenant_isolation_projects on projects
  using (tenant_id::text = current_setting('app.tenant_id', true));

create policy tenant_isolation_events on events
  using (tenant_id::text = current_setting('app.tenant_id', true));

create policy tenant_isolation_report_chunks on report_chunks
  using (tenant_id::text = current_setting('app.tenant_id', true));

create policy tenant_isolation_audit_logs on audit_logs
  using (tenant_id::text = current_setting('app.tenant_id', true));

-- Repeat the same policy shape for every tenant-owned table in production migrations.
