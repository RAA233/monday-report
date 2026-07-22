-- Normalized lineage & tenant integrity hardening (forward-only over 0005).
--
-- Migration 0005 enforced the one-active-per-coordinate index and the terminal
-- outcome uniqueness. Independent review confirmed several relationships were
-- only application-enforced and therefore bypassable by a defective code path
-- or a superuser/BYPASSRLS connection (foreign-key checks always bypass RLS):
--   * supersession self-links (supersedes_id / superseded_by_id) used ID alone,
--     so a link could cross tenant, cross coordinate, self-reference, or branch;
--   * outcome -> task and every normalized row -> tenant carried tenant_id and
--     tenant_slug as unconstrained parallel fields that could diverge (a row
--     with tenant A's id but tenant B's slug satisfied the RLS WITH CHECK).
--
-- This migration adds the strongest COMPATIBLE database constraints. It creates
-- no tables and alters no prior migration; it only adds anchors, composite
-- foreign keys, exclusion-of-branching unique indexes, and CHECKs.
--
-- Audit references (audit_event_id) remain a durable UUID reference into the
-- snapshot-owned HMAC-chained audit log, NOT a database foreign key (the audit
-- log is not a relational table on this backend). Rows created by the running
-- application carry a non-null reference; rows introduced by the one-time import
-- cutover are recorded by the marker's import-batch audit reference and may
-- carry a null per-row reference. This is enforced behaviourally (guard-tested),
-- and this file deliberately does NOT claim database-enforced referential
-- integrity for it.

-- ---------------------------------------------------------------- tenants ----
-- Composite anchor so (tenant_id, tenant_slug) on every normalized row can be
-- bound to the tenant's real (id, slug); prevents id/slug divergence.
create unique index if not exists tenants_id_slug_uidx on tenants (id, slug);

alter table monday_report_norm_reports
  add constraint norm_reports_tenant_slug_fk
  foreign key (tenant_id, tenant_slug) references tenants (id, slug);

alter table monday_report_norm_field_corrections
  add constraint norm_corrections_tenant_slug_fk
  foreign key (tenant_id, tenant_slug) references tenants (id, slug);

alter table monday_report_norm_validation_tasks
  add constraint norm_tasks_tenant_slug_fk
  foreign key (tenant_id, tenant_slug) references tenants (id, slug);

alter table monday_report_norm_validation_outcomes
  add constraint norm_outcomes_tenant_slug_fk
  foreign key (tenant_id, tenant_slug) references tenants (id, slug);

-- ----------------------------------------------------- correction lineage ----
-- Anchor carrying id + tenant + coordinate so the supersession self-links can be
-- constrained to the SAME tenant and field coordinate via composite FKs.
create unique index if not exists norm_corrections_lineage_anchor_uidx
  on monday_report_norm_field_corrections
  (id, tenant_id, workspace_id, target_type, field_key);

-- A supersession link may only connect two corrections that share tenant AND the
-- (workspace, target_type, field_key) coordinate. With MATCH SIMPLE a NULL link
-- column skips the check, so unlinked corrections are unaffected.
alter table monday_report_norm_field_corrections
  add constraint norm_corrections_supersedes_same_coord_fk
  foreign key (supersedes_id, tenant_id, workspace_id, target_type, field_key)
  references monday_report_norm_field_corrections
    (id, tenant_id, workspace_id, target_type, field_key);

alter table monday_report_norm_field_corrections
  add constraint norm_corrections_superseded_by_same_coord_fk
  foreign key (superseded_by_id, tenant_id, workspace_id, target_type, field_key)
  references monday_report_norm_field_corrections
    (id, tenant_id, workspace_id, target_type, field_key);

-- No self-reference.
alter table monday_report_norm_field_corrections
  add constraint norm_corrections_no_self_supersedes
  check (supersedes_id is null or supersedes_id <> id);
alter table monday_report_norm_field_corrections
  add constraint norm_corrections_no_self_superseded_by
  check (superseded_by_id is null or superseded_by_id <> id);

-- No branching: each predecessor is superseded at most once, and each successor
-- supersedes at most one predecessor (a linear chain per coordinate).
create unique index if not exists norm_corrections_supersedes_unique
  on monday_report_norm_field_corrections (tenant_id, supersedes_id)
  where supersedes_id is not null;
create unique index if not exists norm_corrections_superseded_by_unique
  on monday_report_norm_field_corrections (tenant_id, superseded_by_id)
  where superseded_by_id is not null;

-- target_type participates in the one-active coordinate, so an empty value would
-- silently evade the one-active invariant for the intended field.
alter table monday_report_norm_field_corrections
  add constraint norm_corrections_target_type_present check (length(target_type) > 0);

-- ------------------------------------------------ validation task/outcome ----
-- Anchor so outcome -> task can bind tenant identity, not just task id.
create unique index if not exists norm_tasks_id_tenant_uidx
  on monday_report_norm_validation_tasks (id, tenant_id);

alter table monday_report_norm_validation_outcomes
  add constraint norm_outcomes_task_tenant_fk
  foreign key (task_id, tenant_id)
  references monday_report_norm_validation_tasks (id, tenant_id);

alter table monday_report_norm_validation_tasks
  add constraint norm_tasks_target_type_present check (length(target_type) > 0);
