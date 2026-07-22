"""Normalized PostgreSQL repositories for the correction-persistence slice.

In PostgreSQL mode these repositories are the single write and read authority
for Monday Reports, field corrections, and validation tasks/outcomes (see
docs/NORMALIZED_CORRECTION_PERSISTENCE.md). They deliberately do NOT open
connections or transactions of their own for mutations: every write executes on
the store's open snapshot-transaction connection, so a normalized row, its
audit event (snapshot-owned), its idempotency record, and the snapshot revision
commit or roll back together. Reads outside a transaction use a dedicated
connection with the tenant scope applied.

Lock-order rule (documented in the design note): the caller already holds the
GLOBAL snapshot advisory lock before any repository mutation; repositories then
take NORMALIZED row locks (``select ... for update``) ordered by table then id.
No repository ever acquires the global lock itself, so the order is always
global -> rows and deadlock-free.

Typed columns are written from the entity; ``doc`` stores the complete
canonical Pydantic serialization, so ``load*`` reconstruction is deterministic
(``Model.model_validate(doc)``) and cannot drift from the application schema.
"""
from __future__ import annotations

from typing import Protocol
from uuid import UUID

from psycopg.types.json import Jsonb

from .schemas import FieldCorrection, MondayReport, ValidationTask

REPORTS_TABLE = "monday_report_norm_reports"
CORRECTIONS_TABLE = "monday_report_norm_field_corrections"
TASKS_TABLE = "monday_report_norm_validation_tasks"
OUTCOMES_TABLE = "monday_report_norm_validation_outcomes"

# Terminal review outcomes recorded as append-only outcome rows.
TERMINAL_OUTCOMES = ("validated", "rejected", "conflict")


class StaleRevisionError(RuntimeError):
    """An expected entity revision no longer matches the committed row."""


class ReportRepository(Protocol):
    def load(self, report_id: UUID) -> MondayReport | None: ...
    def load_all(self) -> list[MondayReport]: ...
    def create(self, report: MondayReport, *, audit_event_id: UUID | None,
               operation_id: str | None) -> None: ...
    def update(self, report: MondayReport, *, audit_event_id: UUID | None,
               operation_id: str | None, expected_revision: int | None = None) -> int: ...


class FieldCorrectionRepository(Protocol):
    def load(self, correction_id: UUID) -> FieldCorrection | None: ...
    def load_all(self) -> list[FieldCorrection]: ...
    def lock_lineage(self, workspace_id: UUID, target_type: str, field_key: str) -> list[UUID]: ...
    def create(self, correction: FieldCorrection, *, superseded: FieldCorrection | None,
               audit_event_id: UUID | None, operation_id: str | None) -> None: ...
    def revert(self, correction: FieldCorrection, *, audit_event_id: UUID | None,
               operation_id: str | None, expected_revision: int | None = None) -> int: ...


class ValidationTaskRepository(Protocol):
    def load(self, task_id: UUID) -> ValidationTask | None: ...
    def load_all(self) -> list[ValidationTask]: ...
    def lock(self, task_id: UUID) -> int | None: ...
    def create(self, task: ValidationTask, *, audit_event_id: UUID | None,
               operation_id: str | None) -> None: ...
    def transition(self, task: ValidationTask, *, previous_status: str,
                   is_review_outcome: bool, reviewer_verified: bool,
                   audit_event_id: UUID | None, operation_id: str | None,
                   expected_revision: int | None = None) -> int: ...


class _PgRepositoryBase:
    """Shared plumbing: cursors on the owning transaction or a scoped read."""

    def __init__(self, store) -> None:
        self._store = store

    # -- connection discipline ------------------------------------------------
    def _txn_connection(self):
        if not self._store._owns_txn():
            raise RuntimeError(
                "normalized repository mutations must run inside the protected "
                "snapshot transaction (global lock first; see lock-order rule)"
            )
        return self._store._txn["connection"]

    def _read_rows(self, sql: str, params: tuple) -> list[tuple]:
        if self._store._owns_txn():
            with self._txn_connection().cursor() as cursor:
                cursor.execute(sql, params)
                return cursor.fetchall()
        with self._store._connect() as connection:
            with connection.cursor() as cursor:
                self._store._set_tenant_scope(cursor)
                cursor.execute(sql, params)
                return cursor.fetchall()

    @property
    def _tenant_id(self):
        return self._store.tenant.id

    @property
    def _tenant_slug(self) -> str:
        return self._store.tenant.slug

    def _ensure_anchor_rows(self, workspace_id: UUID | None) -> None:
        """Upsert the tenant (and workspace) FK anchor rows.

        Tenants and workspaces remain snapshot-owned; these rows are a
        deterministic projection (id/name/slug from the authority) that exists
        only so the slice's foreign keys are enforceable. Never deleted here.
        """
        with self._txn_connection().cursor() as cursor:
            # Keep slug current on conflict too: the composite tenant FK
            # (tenant_id, tenant_slug) -> tenants(id, slug) added in migration
            # 0006 requires the anchor's slug to match the slug written on every
            # normalized row, so a stale anchor slug must not linger.
            cursor.execute(
                "insert into tenants (id, name, slug) values (%s, %s, %s) "
                "on conflict (id) do update set name = excluded.name, slug = excluded.slug",
                (self._tenant_id, self._store.tenant.name, self._tenant_slug),
            )
            if workspace_id is not None:
                workspace = self._store.workspaces.get(workspace_id)
                name = workspace.name if workspace is not None else "workspace"
                cursor.execute(
                    "insert into workspaces (id, tenant_id, name) values (%s, %s, %s) "
                    "on conflict (id) do update set name = excluded.name",
                    (workspace_id, self._tenant_id, name),
                )


class PgReportRepository(_PgRepositoryBase):
    def load(self, report_id: UUID) -> MondayReport | None:
        rows = self._read_rows(
            f"select doc from {REPORTS_TABLE} where tenant_id = %s and id = %s",
            (self._tenant_id, report_id))
        return MondayReport.model_validate(rows[0][0]) if rows else None

    def load_all(self) -> list[MondayReport]:
        rows = self._read_rows(
            f"select doc from {REPORTS_TABLE} where tenant_id = %s order by created_at, id",
            (self._tenant_id,))
        return [MondayReport.model_validate(r[0]) for r in rows]

    def create(self, report: MondayReport, *, audit_event_id: UUID | None,
               operation_id: str | None) -> None:
        self._ensure_anchor_rows(report.workspace_id)
        with self._txn_connection().cursor() as cursor:
            cursor.execute(
                f"insert into {REPORTS_TABLE} (id, tenant_id, tenant_slug, workspace_id, "
                f"status, revision, doc, audit_event_id, operation_id, created_at, updated_at) "
                f"values (%s, %s, %s, %s, %s, 0, %s, %s, %s, %s, %s)",
                (report.id, self._tenant_id, self._tenant_slug, report.workspace_id,
                 report.status, Jsonb(self._store._postgres_safe_json(report.model_dump(mode="json"))),
                 audit_event_id, operation_id, report.created_at, report.created_at),
            )

    def update(self, report: MondayReport, *, audit_event_id: UUID | None,
               operation_id: str | None, expected_revision: int | None = None) -> int:
        with self._txn_connection().cursor() as cursor:
            cursor.execute(
                f"select revision from {REPORTS_TABLE} where tenant_id = %s and id = %s for update",
                (self._tenant_id, report.id))
            row = cursor.fetchone()
            if row is None:
                raise StaleRevisionError("report row missing for update")
            current = int(row[0])
            if expected_revision is not None and current != expected_revision:
                raise StaleRevisionError("report revision is stale")
            cursor.execute(
                f"update {REPORTS_TABLE} set status = %s, revision = %s, doc = %s, "
                f"audit_event_id = %s, operation_id = %s, updated_at = now() "
                f"where tenant_id = %s and id = %s",
                (report.status, current + 1,
                 Jsonb(self._store._postgres_safe_json(report.model_dump(mode="json"))),
                 audit_event_id, operation_id, self._tenant_id, report.id),
            )
            return current + 1


class PgFieldCorrectionRepository(_PgRepositoryBase):
    def load(self, correction_id: UUID) -> FieldCorrection | None:
        rows = self._read_rows(
            f"select doc from {CORRECTIONS_TABLE} where tenant_id = %s and id = %s",
            (self._tenant_id, correction_id))
        return FieldCorrection.model_validate(rows[0][0]) if rows else None

    def load_all(self) -> list[FieldCorrection]:
        rows = self._read_rows(
            f"select doc from {CORRECTIONS_TABLE} where tenant_id = %s order by created_at, id",
            (self._tenant_id,))
        return [FieldCorrection.model_validate(r[0]) for r in rows]

    def lock_lineage(self, workspace_id: UUID, target_type: str, field_key: str) -> list[UUID]:
        """Row-lock the ACTIVE lineage for a field coordinate (may be empty)."""
        with self._txn_connection().cursor() as cursor:
            cursor.execute(
                f"select id from {CORRECTIONS_TABLE} where tenant_id = %s and workspace_id = %s "
                f"and target_type = %s and field_key = %s and status = 'active' "
                f"order by id for update",
                (self._tenant_id, workspace_id, target_type, field_key))
            return [r[0] for r in cursor.fetchall()]

    def create(self, correction: FieldCorrection, *, superseded: FieldCorrection | None,
               audit_event_id: UUID | None, operation_id: str | None) -> None:
        self._ensure_anchor_rows(correction.workspace_id)
        with self._txn_connection().cursor() as cursor:
            # Constraint-safe three-step order, all in the one open transaction:
            # 1. demote the prior ACTIVE row (frees the one-active partial
            #    unique index BEFORE the insert),
            # 2. insert the new correction,
            # 3. back-link superseded_by_id (a self-referential FK, so its
            #    target row must exist before this check runs).
            if superseded is not None:
                cursor.execute(
                    f"update {CORRECTIONS_TABLE} set status = 'superseded', doc = %s, "
                    f"revision = revision + 1, updated_at = now() "
                    f"where tenant_id = %s and id = %s",
                    (Jsonb(self._store._postgres_safe_json(superseded.model_dump(mode="json"))),
                     self._tenant_id, superseded.id),
                )
            cursor.execute(
                f"insert into {CORRECTIONS_TABLE} (id, tenant_id, tenant_slug, workspace_id, "
                f"target_type, field_key, status, supersedes_id, actor_user_id, "
                f"reviewer_user_id, revision, doc, audit_event_id, operation_id, "
                f"created_at, updated_at) "
                f"values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 0, %s, %s, %s, %s, %s)",
                (correction.id, self._tenant_id, self._tenant_slug, correction.workspace_id,
                 correction.target_type, correction.field_key, correction.status,
                 correction.supersedes_id, correction.actor_user_id,
                 correction.reviewer_user_id,
                 Jsonb(self._store._postgres_safe_json(correction.model_dump(mode="json"))),
                 audit_event_id, operation_id, correction.created_at, correction.created_at),
            )
            if superseded is not None:
                cursor.execute(
                    f"update {CORRECTIONS_TABLE} set superseded_by_id = %s "
                    f"where tenant_id = %s and id = %s",
                    (correction.id, self._tenant_id, superseded.id),
                )

    def revert(self, correction: FieldCorrection, *, audit_event_id: UUID | None,
               operation_id: str | None, expected_revision: int | None = None) -> int:
        with self._txn_connection().cursor() as cursor:
            cursor.execute(
                f"select revision from {CORRECTIONS_TABLE} where tenant_id = %s and id = %s for update",
                (self._tenant_id, correction.id))
            row = cursor.fetchone()
            if row is None:
                raise StaleRevisionError("correction row missing for revert")
            current = int(row[0])
            if expected_revision is not None and current != expected_revision:
                raise StaleRevisionError("correction revision is stale")
            cursor.execute(
                f"update {CORRECTIONS_TABLE} set status = %s, doc = %s, revision = %s, "
                f"reverted_at = now(), audit_event_id = %s, operation_id = %s, updated_at = now() "
                f"where tenant_id = %s and id = %s",
                (correction.status,
                 Jsonb(self._store._postgres_safe_json(correction.model_dump(mode="json"))),
                 current + 1, audit_event_id, operation_id, self._tenant_id, correction.id),
            )
            return current + 1


class PgValidationTaskRepository(_PgRepositoryBase):
    def load(self, task_id: UUID) -> ValidationTask | None:
        rows = self._read_rows(
            f"select doc from {TASKS_TABLE} where tenant_id = %s and id = %s",
            (self._tenant_id, task_id))
        return ValidationTask.model_validate(rows[0][0]) if rows else None

    def load_all(self) -> list[ValidationTask]:
        rows = self._read_rows(
            f"select doc from {TASKS_TABLE} where tenant_id = %s order by created_at, id",
            (self._tenant_id,))
        return [ValidationTask.model_validate(r[0]) for r in rows]

    def lock(self, task_id: UUID) -> int | None:
        """Row-lock a task and return its committed revision (None if absent)."""
        with self._txn_connection().cursor() as cursor:
            cursor.execute(
                f"select revision from {TASKS_TABLE} where tenant_id = %s and id = %s for update",
                (self._tenant_id, task_id))
            row = cursor.fetchone()
            return int(row[0]) if row else None

    def create(self, task: ValidationTask, *, audit_event_id: UUID | None,
               operation_id: str | None) -> None:
        self._ensure_anchor_rows(None)
        with self._txn_connection().cursor() as cursor:
            cursor.execute(
                f"insert into {TASKS_TABLE} (id, tenant_id, tenant_slug, target_type, "
                f"target_id, status, revision, reviewer_user_id, doc, audit_event_id, "
                f"operation_id, created_at, updated_at) "
                f"values (%s, %s, %s, %s, %s, %s, 0, %s, %s, %s, %s, %s, %s)",
                (task.id, self._tenant_id, self._tenant_slug, task.target_type,
                 task.target_id, task.status.value, task.reviewer_user_id,
                 Jsonb(self._store._postgres_safe_json(task.model_dump(mode="json"))),
                 audit_event_id, operation_id, task.created_at, task.created_at),
            )

    def transition(self, task: ValidationTask, *, previous_status: str,
                   is_review_outcome: bool, reviewer_verified: bool,
                   audit_event_id: UUID | None, operation_id: str | None,
                   expected_revision: int | None = None) -> int:
        from uuid import uuid4

        with self._txn_connection().cursor() as cursor:
            cursor.execute(
                f"select revision from {TASKS_TABLE} where tenant_id = %s and id = %s for update",
                (self._tenant_id, task.id))
            row = cursor.fetchone()
            if row is None:
                raise StaleRevisionError("validation task row missing for transition")
            current = int(row[0])
            if expected_revision is not None and current != expected_revision:
                raise StaleRevisionError("validation task revision is stale")
            new_revision = current + 1
            cursor.execute(
                f"update {TASKS_TABLE} set status = %s, revision = %s, reviewer_user_id = %s, "
                f"doc = %s, audit_event_id = %s, operation_id = %s, updated_at = now() "
                f"where tenant_id = %s and id = %s",
                (task.status.value, new_revision, task.reviewer_user_id,
                 Jsonb(self._store._postgres_safe_json(task.model_dump(mode="json"))),
                 audit_event_id, operation_id, self._tenant_id, task.id),
            )
            if is_review_outcome and task.status.value in TERMINAL_OUTCOMES:
                # Append-only outcome history; UNIQUE(task_id, task_revision)
                # forbids a second terminal outcome for the same revision.
                cursor.execute(
                    f"insert into {OUTCOMES_TABLE} (id, task_id, tenant_id, tenant_slug, "
                    f"task_revision, outcome, reviewer_user_id, reviewer_verified, "
                    f"audit_event_id, operation_id) "
                    f"values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (uuid4(), task.id, self._tenant_id, self._tenant_slug, new_revision,
                     task.status.value,
                     task.reviewer_user_id if task.reviewer_user_id is not None
                     else self._store.current_identity().user_id,
                     reviewer_verified, audit_event_id, operation_id),
                )
            return new_revision


def prune_missing_rows(store) -> dict[str, int]:
    """Delete normalized rows whose entities are gone from in-memory state.

    Retention apply and the demo-seed self-wipe REMOVE migrated entities from
    the in-memory dicts. On the postgres backend those dicts are loaded FROM
    the normalized tables, so the rows must be deleted in the SAME protected
    transaction — otherwise every purged entity resurrects on the next
    refresh and the audited retention/wipe result is false. Runs only inside
    the owning snapshot transaction (global lock already held; see the
    lock-order rule). FK-safe order: outcomes -> tasks -> corrections ->
    reports. Returns deleted-row counts per table.
    """
    base = _PgRepositoryBase(store)
    keep_tasks = list(store.validation_tasks.keys())
    keep_corrections = list(store.field_corrections.keys())
    keep_reports = list(store.monday_reports.keys())
    deleted: dict[str, int] = {}
    with base._txn_connection().cursor() as cursor:
        for table, key_column, keep in (
            (OUTCOMES_TABLE, "task_id", keep_tasks),
            (TASKS_TABLE, "id", keep_tasks),
            (CORRECTIONS_TABLE, "id", keep_corrections),
            (REPORTS_TABLE, "id", keep_reports),
        ):
            cursor.execute(
                f"delete from {table} where tenant_id = %s and not ({key_column} = any(%s))",
                (base._tenant_id, keep))
            deleted[table] = cursor.rowcount
    return deleted


def count_tenant_rows(store) -> dict[str, int]:
    """Count this tenant's rows in each normalized table (owning txn scope).

    Used to VERIFY the demo-seed reset actually deleted the preserved tenant's
    rows before reseeding. Runs on the transaction connection so it observes
    the just-executed prune within the same protected transaction.
    """
    base = _PgRepositoryBase(store)
    counts: dict[str, int] = {}
    with base._txn_connection().cursor() as cursor:
        for table in (REPORTS_TABLE, CORRECTIONS_TABLE, TASKS_TABLE, OUTCOMES_TABLE):
            cursor.execute(
                f"select count(*) from {table} where tenant_id = %s", (base._tenant_id,))
            counts[table] = int(cursor.fetchone()[0])
    return counts


def normalized_drift_report(store) -> list[str]:
    """Detect typed-column vs canonical-doc drift on the normalized tables.

    The doc column is the deterministic canonical serialization; the typed
    columns exist for keys/constraints/RLS. They are written together in one
    statement, so ANY divergence indicates tampering or a defect. Returns a
    list of redacted references (table:id:field), empty when consistent.
    """
    drift: list[str] = []
    checks = {
        REPORTS_TABLE: (("status", "status"), ("workspace_id", "workspace_id"),
                        ("tenant_id", "tenant_id")),
        CORRECTIONS_TABLE: (("status", "status"), ("workspace_id", "workspace_id"),
                            ("target_type", "target_type"), ("field_key", "field_key"),
                            ("superseded_by_id", "superseded_by_id"),
                            ("tenant_id", "tenant_id")),
        TASKS_TABLE: (("status", "status"), ("target_type", "target_type"),
                      ("tenant_id", "tenant_id")),
    }
    with store._connect() as connection:
        with connection.cursor() as cursor:
            store._set_tenant_scope(cursor)
            for table, pairs in checks.items():
                columns = ", ".join(column for column, _ in pairs)
                cursor.execute(f"select id, doc, {columns} from {table} where tenant_id = %s",
                               (store.tenant.id,))
                for row in cursor.fetchall():
                    row_id, doc = row[0], row[1]
                    for index, (column, doc_field) in enumerate(pairs):
                        typed = row[2 + index]
                        doc_value = doc.get(doc_field)
                        if str(typed) != str(doc_value):
                            drift.append(f"{table}:{row_id}:{column}")
    return drift
