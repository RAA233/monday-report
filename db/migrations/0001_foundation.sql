-- Monday Report foundation migration.
-- This is the first executable database slice: tenant, RBAC, workspace,
-- upload, file inventory, processing jobs, validation, chat, report, audit.

create extension if not exists pgcrypto;
create extension if not exists citext;
create extension if not exists vector;

create table if not exists tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text not null unique,
  region text not null default 'us',
  plan text not null default 'enterprise-trial',
  local_llm_policy jsonb not null default '{"mode":"local_first","hosted_fallback_enabled":false}'::jsonb,
  retention_days int not null default 365,
  encryption_key_ref text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  email citext not null,
  full_name text not null,
  auth_provider_id text,
  status text not null default 'active',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, email)
);

create table if not exists roles (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  name text not null,
  permissions jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, name)
);

create table if not exists user_roles (
  tenant_id uuid not null references tenants(id) on delete cascade,
  user_id uuid not null references users(id) on delete cascade,
  role_id uuid not null references roles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (user_id, role_id)
);

create table if not exists workspaces (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  name text not null,
  asset text,
  campaign text,
  period_start date,
  period_end date,
  status text not null default 'active',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists uploads (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  workspace_id uuid not null references workspaces(id) on delete cascade,
  submitted_by uuid references users(id),
  source_type text not null,
  status text not null default 'queued',
  manifest jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists files (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  upload_id uuid not null references uploads(id) on delete cascade,
  original_path text not null,
  storage_uri text not null,
  sha256 text not null,
  mime_type text not null default 'application/octet-stream',
  byte_size bigint not null default 0,
  status text not null default 'queued',
  malware_status text not null default 'pending',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, sha256)
);

create table if not exists processing_jobs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  upload_id uuid references uploads(id) on delete cascade,
  file_id uuid references files(id) on delete cascade,
  job_type text not null,
  status text not null default 'queued',
  attempts int not null default 0,
  max_attempts int not null default 3,
  error text,
  payload jsonb not null default '{}'::jsonb,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists parsed_documents (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  workspace_id uuid not null references workspaces(id) on delete cascade,
  upload_id uuid not null references uploads(id) on delete cascade,
  file_id uuid not null references files(id) on delete cascade,
  title text not null,
  parser_name text not null,
  status text not null default 'queued',
  text_preview text not null default '',
  chunk_count int not null default 0,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists document_chunks (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  workspace_id uuid not null references workspaces(id) on delete cascade,
  upload_id uuid not null references uploads(id) on delete cascade,
  file_id uuid not null references files(id) on delete cascade,
  document_id uuid not null references parsed_documents(id) on delete cascade,
  ordinal int not null,
  text text not null,
  locator_type text not null,
  locator jsonb not null default '{}'::jsonb,
  confidence numeric(4,3) not null default 0.7,
  tsv tsvector generated always as (to_tsvector('english', coalesce(text, ''))) stored,
  created_at timestamptz not null default now()
);

create table if not exists failures (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  workspace_id uuid not null references workspaces(id) on delete cascade,
  event_type text not null,
  severity text not null,
  summary text not null,
  company text not null default 'unknown',
  tool_type text not null default 'unknown',
  tool_serial text not null default 'unknown',
  npt_hours numeric(10,2) not null default 0,
  confidence numeric(4,3) not null default 0,
  validation_status text not null default 'open',
  citations jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists validation_tasks (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  target_type text not null,
  target_id uuid not null,
  reason text not null,
  priority text not null default 'medium',
  status text not null default 'open',
  assigned_to uuid references users(id),
  reviewed_by uuid references users(id),
  resolution_note text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists chat_sessions (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  workspace_id uuid not null references workspaces(id) on delete cascade,
  user_id uuid references users(id),
  title text not null default 'Monday Report chat',
  filters jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists chat_messages (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  chat_session_id uuid not null references chat_sessions(id) on delete cascade,
  role text not null,
  content text not null,
  retrieval_trace jsonb not null default '{}'::jsonb,
  citation_ids uuid[] not null default '{}',
  model_name text,
  created_at timestamptz not null default now()
);

create table if not exists monday_reports (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  workspace_id uuid not null references workspaces(id) on delete cascade,
  period_start date not null,
  period_end date not null,
  status text not null default 'draft',
  report_json jsonb not null default '{}'::jsonb,
  pdf_uri text,
  excel_uri text,
  generated_by uuid references users(id),
  approved_by uuid references users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists report_exports (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  report_id uuid not null references monday_reports(id) on delete cascade,
  format text not null,
  storage_uri text not null,
  sha256 text not null,
  byte_size bigint not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists audit_logs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  actor_user_id uuid references users(id),
  action text not null,
  resource_type text not null,
  resource_id uuid,
  ip_address inet,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_workspaces_tenant_status on workspaces(tenant_id, status);
create index if not exists idx_uploads_tenant_workspace on uploads(tenant_id, workspace_id);
create index if not exists idx_files_tenant_upload on files(tenant_id, upload_id);
create index if not exists idx_processing_jobs_tenant_status on processing_jobs(tenant_id, status, job_type);
create index if not exists idx_parsed_documents_workspace on parsed_documents(tenant_id, workspace_id, created_at desc);
create index if not exists idx_document_chunks_document on document_chunks(tenant_id, document_id, ordinal);
create index if not exists idx_document_chunks_tsv on document_chunks using gin(tsv);
create index if not exists idx_failures_workspace_status on failures(tenant_id, workspace_id, validation_status);
create index if not exists idx_failures_npt on failures(tenant_id, npt_hours desc);
create index if not exists idx_validation_tasks_tenant_status on validation_tasks(tenant_id, status, priority);
create index if not exists idx_chat_messages_tenant_session on chat_messages(tenant_id, chat_session_id);
create index if not exists idx_monday_reports_tenant_period on monday_reports(tenant_id, workspace_id, period_start);
create index if not exists idx_report_exports_tenant_report on report_exports(tenant_id, report_id, created_at desc);
create index if not exists idx_audit_logs_tenant_created on audit_logs(tenant_id, created_at desc);

alter table users enable row level security;
alter table roles enable row level security;
alter table user_roles enable row level security;
alter table workspaces enable row level security;
alter table uploads enable row level security;
alter table files enable row level security;
alter table processing_jobs enable row level security;
alter table parsed_documents enable row level security;
alter table document_chunks enable row level security;
alter table failures enable row level security;
alter table validation_tasks enable row level security;
alter table chat_sessions enable row level security;
alter table chat_messages enable row level security;
alter table monday_reports enable row level security;
alter table report_exports enable row level security;
alter table audit_logs enable row level security;

-- Apply this policy pattern to all tenant-owned tables in production:
-- create policy tenant_isolation_<table_name> on <table_name>
--   using (tenant_id = current_setting('app.tenant_id')::uuid)
--   with check (tenant_id = current_setting('app.tenant_id')::uuid);
