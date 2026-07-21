-- Transactional snapshot metadata and durable idempotency records.
--
-- The application snapshot is a single GLOBAL row. Concurrent writers previously
-- read it on one connection and wrote it blindly on another, so a committed
-- write could be destroyed by a slower writer that had read the same earlier
-- state. `revision` is the compare-and-swap token that makes that impossible:
-- a mutation reads revision N under a row lock and commits only via
-- `... WHERE revision = N`, so a stale writer updates zero rows and is rejected.
--
-- The idempotency table lets a retried operation return its committed result
-- instead of applying a second time. It deliberately stores a HASH of the
-- canonical request rather than the request itself: retry safety needs to know
-- whether two requests are equivalent, not what they contained. No credential,
-- secret or private payload is duplicated here.

alter table monday_report_state_snapshots
  add column if not exists revision bigint not null default 0;

alter table monday_report_state_snapshots
  alter column updated_at set not null;

-- A revision can only ever move forward from zero.
alter table monday_report_state_snapshots
  drop constraint if exists monday_report_state_snapshots_revision_non_negative;
alter table monday_report_state_snapshots
  add constraint monday_report_state_snapshots_revision_non_negative
  check (revision >= 0);

create table if not exists monday_report_idempotency_records (
  tenant_slug text not null,
  operation_id text not null,
  operation_kind text not null,
  actor_id uuid,
  request_hash text not null,
  committed_revision bigint not null,
  result_kind text,
  result_identifier text,
  created_at timestamptz not null default now(),
  -- One committed result per operation id within its scope. This is the
  -- constraint that makes a concurrent duplicate commit exactly once: the
  -- second inserter violates it inside its own transaction and rolls back.
  primary key (tenant_slug, operation_id),
  constraint monday_report_idempotency_request_hash_present
    check (length(request_hash) > 0),
  constraint monday_report_idempotency_revision_valid
    check (committed_revision > 0)
);

-- Supports replay lookup scoped by actor, so one authenticated user cannot
-- replay another user's operation id.
create index if not exists monday_report_idempotency_actor_idx
  on monday_report_idempotency_records (tenant_slug, actor_id, operation_id);

alter table monday_report_idempotency_records enable row level security;
alter table monday_report_idempotency_records force row level security;

drop policy if exists tenant_isolation_monday_report_idempotency_records
  on monday_report_idempotency_records;
create policy tenant_isolation_monday_report_idempotency_records
  on monday_report_idempotency_records
  using (tenant_slug = current_setting('app.tenant_slug', true))
  with check (tenant_slug = current_setting('app.tenant_slug', true));
