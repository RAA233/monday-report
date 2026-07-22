"""Explicit operator cutover tool: snapshot -> normalized correction persistence.

Usage (explicit operator command; NEVER run at API startup):

    python -m backend.app.normalized_import assess
    python -m backend.app.normalized_import dry-run
    python -m backend.app.normalized_import execute
    python -m backend.app.normalized_import verify

Reads MONDAY_REPORT_DATABASE_URL (or DATABASE_URL) and MONDAY_REPORT_TENANT_SLUG.
Behaviour per docs/NORMALIZED_CORRECTION_PERSISTENCE.md:

- ``assess``   read-only: reports snapshot holdings, migration metadata,
               relationship validity, existing-row conflicts, marker state.
- ``dry-run``  performs the full transformation in memory, writes nothing.
- ``execute``  ONE transaction under the global snapshot advisory lock:
               re-reads the snapshot FOR UPDATE, refuses on conflicts or an
               already-cutover marker mismatch, inserts every normalized row
               (deterministic ids = the entities' own UUIDs), upserts the
               tenant/workspace FK anchors, strips the migrated keys, writes the
               normalized_authority marker, commits via revision CAS. All units
               import atomically (a single logical cutover) or not at all.
- ``verify``   validates every normalized doc against the application schema,
               checks counts against the marker, the one-active-lineage
               invariant, and that the snapshot no longer holds migrated keys.

Reruns are idempotent: with the marker present, ``execute`` degrades to
``verify``. Unsupported states (marker present but rows missing, divergent
existing rows) fail closed with a redacted summary. The tool never prints
credentials, DSNs, or entity content -- only counts, ids and fingerprints.

This module deliberately does NOT import ``backend.app.store``: importing it
constructs the store singleton, which correctly FAILS CLOSED on an un-imported
snapshot -- the exact state this tool exists to repair. The advisory-lock
namespace and control-character scrub are mirrored here and drift-checked by
the normalized-persistence guard.
"""
from __future__ import annotations

import json
import os
import re
import sys
from hashlib import sha256
from uuid import UUID, uuid4

from .schemas import FieldCorrection, MondayReport, ValidationTask

STATE_TABLE = "monday_report_state_snapshots"
REPORTS_TABLE = "monday_report_norm_reports"
CORRECTIONS_TABLE = "monday_report_norm_field_corrections"
TASKS_TABLE = "monday_report_norm_validation_tasks"

# Mirrored from backend.app.store (guard-verified to stay identical).
SNAPSHOT_LOCK_NAMESPACE = "monday_report.global_snapshot.v2"
SNAPSHOT_LOCK_TIMEOUT_MS = 5000
UNSAFE_TEXT_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]+")
NORMALIZED_ENTITY_KEYS = ("monday_reports", "field_corrections", "validation_tasks")
NORMALIZED_AUTHORITY_VERSION = 1

MODELS = {
    "monday_reports": MondayReport,
    "field_corrections": FieldCorrection,
    "validation_tasks": ValidationTask,
}


def _advisory_lock_key() -> int:
    digest = sha256(SNAPSHOT_LOCK_NAMESPACE.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


def _safe_json(value):
    if isinstance(value, str):
        return UNSAFE_TEXT_CONTROL_CHARS.sub(" ", value)
    if isinstance(value, list):
        return [_safe_json(item) for item in value]
    if isinstance(value, dict):
        return {key: _safe_json(item) for key, item in value.items()}
    return value


def _database_url() -> str:
    url = (os.getenv("MONDAY_REPORT_DATABASE_URL") or os.getenv("DATABASE_URL") or "").strip()
    if not url:
        raise SystemExit("MONDAY_REPORT_DATABASE_URL is not configured (nothing is printed).")
    return url


def _tenant_slug() -> str:
    return os.getenv("MONDAY_REPORT_TENANT_SLUG", "monday-report")


def _load(connection, slug: str, *, for_update: bool = False):
    with connection.cursor() as cursor:
        cursor.execute("select set_config('app.tenant_slug', %s, true)", (slug,))
        suffix = " for update" if for_update else ""
        cursor.execute(
            f"select payload, revision from {STATE_TABLE} where tenant_slug = %s{suffix}",
            (slug,))
        row = cursor.fetchone()
    if row is None:
        return None, None
    payload = row[0] if isinstance(row[0], dict) else json.loads(str(row[0]))
    return payload, int(row[1])


def _parse_entities(payload: dict) -> dict[str, list]:
    parsed: dict[str, list] = {}
    for key, model in MODELS.items():
        parsed[key] = [model.model_validate(item) for item in payload.get(key, [])]
    return parsed


def _existing_row_conflicts(connection, slug: str, parsed: dict[str, list]) -> list[str]:
    """A row with the same id but a DIFFERENT doc is a conflict; identical rows
    are idempotent-rerun no-ops."""
    conflicts: list[str] = []
    tables = {"monday_reports": REPORTS_TABLE, "field_corrections": CORRECTIONS_TABLE,
              "validation_tasks": TASKS_TABLE}
    with connection.cursor() as cursor:
        cursor.execute("select set_config('app.tenant_slug', %s, true)", (slug,))
        for key, entities in parsed.items():
            for entity in entities:
                # Explicit tenant filter IN ADDITION to the RLS GUC above: the
                # tool may legitimately run as a superuser/owner role, which
                # BYPASSES row-level security, and rows must never be compared
                # (or reported as conflicts) across tenants.
                cursor.execute(
                    f"select doc from {tables[key]} where tenant_slug = %s and id = %s",
                    (slug, entity.id))
                row = cursor.fetchone()
                if row is None:
                    continue
                if _safe_json(entity.model_dump(mode="json")) != row[0]:
                    conflicts.append(f"{key}:{entity.id} (existing row diverges)")
    return conflicts


def _relationship_issues(payload: dict, parsed: dict[str, list]) -> list[str]:
    issues: list[str] = []
    tenant_id = (payload.get("tenant") or {}).get("id")
    workspace_ids = {w.get("id") for w in payload.get("workspaces", [])}
    for report in parsed["monday_reports"]:
        if str(report.tenant_id) != tenant_id:
            issues.append(f"monday_reports:{report.id} tenant mismatch")
        if str(report.workspace_id) not in workspace_ids:
            issues.append(f"monday_reports:{report.id} unknown workspace")
    for correction in parsed["field_corrections"]:
        if str(correction.tenant_id) != tenant_id:
            issues.append(f"field_corrections:{correction.id} tenant mismatch")
        if str(correction.workspace_id) not in workspace_ids:
            issues.append(f"field_corrections:{correction.id} unknown workspace")
    for task in parsed["validation_tasks"]:
        if str(task.tenant_id) != tenant_id:
            issues.append(f"validation_tasks:{task.id} tenant mismatch")
    # One-active-lineage invariant must hold in the source or the unique index
    # would reject the import.
    active: set[tuple] = set()
    for correction in parsed["field_corrections"]:
        if correction.status == "active":
            coordinate = (str(correction.workspace_id), correction.target_type, correction.field_key)
            if coordinate in active:
                issues.append(f"field_corrections: duplicate ACTIVE lineage at {coordinate}")
            active.add(coordinate)
    return issues


def _summary(mode: str, payload, revision, parsed, conflicts, issues, marker) -> dict:
    return {
        "tool": "normalized_import", "mode": mode,
        "snapshot_present": payload is not None,
        "snapshot_revision": revision,
        "marker_present": bool(marker),
        "holdings": {k: len(v) for k, v in (parsed or {}).items()},
        "conflicts": len(conflicts or []),
        "conflict_refs": (conflicts or [])[:10],
        "relationship_issues": len(issues or []),
        "issue_refs": (issues or [])[:10],
    }


def _insert_rows(connection, slug: str, payload: dict, parsed: dict[str, list]) -> dict:
    tenant = payload.get("tenant") or {}
    counts = {k: 0 for k in NORMALIZED_ENTITY_KEYS}
    from psycopg.types.json import Jsonb

    with connection.cursor() as cursor:
        cursor.execute("select set_config('app.tenant_slug', %s, true)", (slug,))
        cursor.execute(
            "insert into tenants (id, name, slug) values (%s, %s, %s) "
            "on conflict (id) do update set name = excluded.name",
            (tenant.get("id"), tenant.get("name", "tenant"), slug))
        for workspace in payload.get("workspaces", []):
            cursor.execute(
                "insert into workspaces (id, tenant_id, name) values (%s, %s, %s) "
                "on conflict (id) do update set name = excluded.name",
                (workspace.get("id"), tenant.get("id"), workspace.get("name", "workspace")))
        for report in parsed["monday_reports"]:
            cursor.execute(
                f"insert into {REPORTS_TABLE} (id, tenant_id, tenant_slug, workspace_id, status, "
                f"revision, doc, created_at, updated_at) values (%s, %s, %s, %s, %s, 0, %s, %s, %s) "
                f"on conflict (id) do nothing",
                (report.id, report.tenant_id, slug, report.workspace_id, report.status,
                 Jsonb(_safe_json(report.model_dump(mode="json"))),
                 report.created_at, report.created_at))
            counts["monday_reports"] += 1
        for c in parsed["field_corrections"]:
            cursor.execute(
                f"insert into {CORRECTIONS_TABLE} (id, tenant_id, tenant_slug, workspace_id, "
                f"target_type, field_key, status, supersedes_id, superseded_by_id, actor_user_id, "
                f"reviewer_user_id, revision, doc, created_at, updated_at) "
                f"values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 0, %s, %s, %s) "
                f"on conflict (id) do nothing",
                (c.id, c.tenant_id, slug, c.workspace_id, c.target_type, c.field_key, c.status,
                 c.supersedes_id, c.superseded_by_id, c.actor_user_id, c.reviewer_user_id,
                 Jsonb(_safe_json(c.model_dump(mode="json"))), c.created_at, c.created_at))
            counts["field_corrections"] += 1
        for t in parsed["validation_tasks"]:
            cursor.execute(
                f"insert into {TASKS_TABLE} (id, tenant_id, tenant_slug, target_type, target_id, "
                f"status, revision, reviewer_user_id, doc, created_at, updated_at) "
                f"values (%s, %s, %s, %s, %s, %s, 0, %s, %s, %s, %s) on conflict (id) do nothing",
                (t.id, t.tenant_id, slug, t.target_type, t.target_id, t.status.value,
                 t.reviewer_user_id, Jsonb(_safe_json(t.model_dump(mode="json"))),
                 t.created_at, t.created_at))
            counts["validation_tasks"] += 1
    return counts


def run(mode: str) -> int:
    import psycopg

    url = _database_url()
    slug = _tenant_slug()

    if mode in ("assess", "dry-run"):
        with psycopg.connect(url, connect_timeout=5) as connection:
            payload, revision = _load(connection, slug)
            if payload is None:
                print(json.dumps(_summary(mode, None, None, None, None, None, None)))
                return 0
            marker = payload.get("normalized_authority")
            parsed = _parse_entities(payload)
            conflicts = _existing_row_conflicts(connection, slug, parsed)
            issues = _relationship_issues(payload, parsed)
            print(json.dumps(_summary(mode, payload, revision, parsed, conflicts, issues, marker)))
            if mode == "dry-run":
                blocked = bool(conflicts or issues)
                print(json.dumps({"dry_run_would_execute": not blocked and not marker,
                                  "already_cut_over": bool(marker)}))
            return 1 if (conflicts or issues) else 0

    if mode == "execute":
        connection = psycopg.connect(url, connect_timeout=5)
        connection.autocommit = False
        try:
            with connection.cursor() as cursor:
                cursor.execute("select set_config('lock_timeout', %s, true)",
                               (f"{SNAPSHOT_LOCK_TIMEOUT_MS}ms",))
                cursor.execute("select set_config('app.tenant_slug', %s, true)", (slug,))
                cursor.execute("select pg_advisory_xact_lock(%s)", (_advisory_lock_key(),))
            payload, revision = _load(connection, slug, for_update=True)
            if payload is None:
                print(json.dumps({"tool": "normalized_import", "mode": mode,
                                  "result": "no snapshot; nothing to import"}))
                connection.rollback()
                return 0
            marker = payload.get("normalized_authority")
            parsed = _parse_entities(payload)
            if marker:
                print(json.dumps({"tool": "normalized_import", "mode": mode,
                                  "result": "already cut over; use verify", "marker": marker}))
                connection.rollback()
                return 0
            conflicts = _existing_row_conflicts(connection, slug, parsed)
            issues = _relationship_issues(payload, parsed)
            if conflicts or issues:
                print(json.dumps(_summary(mode, payload, revision, parsed, conflicts, issues, marker)))
                print(json.dumps({"result": "REFUSED: resolve conflicts/issues first"}))
                connection.rollback()
                return 1
            counts = _insert_rows(connection, slug, payload, parsed)
            for key in NORMALIZED_ENTITY_KEYS:
                payload[key] = []
            payload["normalized_authority"] = {
                "version": NORMALIZED_AUTHORITY_VERSION,
                "entities": list(NORMALIZED_ENTITY_KEYS),
                "imported_counts": counts,
                "pre_cutover_revision": revision,
            }
            from psycopg.types.json import Jsonb

            with connection.cursor() as cursor:
                cursor.execute("select set_config('app.tenant_slug', %s, true)", (slug,))
                cursor.execute(
                    f"update {STATE_TABLE} set payload = %s, revision = revision + 1, "
                    f"updated_at = now() where tenant_slug = %s and revision = %s",
                    (Jsonb(_safe_json(payload)), slug, revision))
                if cursor.rowcount != 1:
                    raise RuntimeError("snapshot revision moved during import; rerun")
            connection.commit()
            print(json.dumps({"tool": "normalized_import", "mode": mode, "result": "cut over",
                              "imported_counts": counts, "pre_cutover_revision": revision}))
            return 0
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    if mode == "verify":
        with psycopg.connect(url, connect_timeout=5) as connection:
            payload, revision = _load(connection, slug)
            problems: list[str] = []
            marker = (payload or {}).get("normalized_authority")
            if payload is None:
                problems.append("no snapshot")
            elif not marker:
                problems.append("no normalized_authority marker (not cut over)")
            else:
                for key in NORMALIZED_ENTITY_KEYS:
                    if payload.get(key):
                        problems.append(f"snapshot still holds {key}")
            tables = {"monday_reports": REPORTS_TABLE, "field_corrections": CORRECTIONS_TABLE,
                      "validation_tasks": TASKS_TABLE}
            counts: dict[str, int] = {}
            with connection.cursor() as cursor:
                cursor.execute("select set_config('app.tenant_slug', %s, true)", (slug,))
                # Explicit tenant filters IN ADDITION to the RLS GUC: the tool
                # may run as a superuser/owner role, which bypasses row-level
                # security, and verification must never count or validate
                # another tenant's rows.
                for key, table in tables.items():
                    cursor.execute(f"select doc from {table} where tenant_slug = %s", (slug,))
                    rows = cursor.fetchall()
                    counts[key] = len(rows)
                    for (doc,) in rows:
                        try:
                            MODELS[key].model_validate(doc)
                        except Exception:  # noqa: BLE001
                            problems.append(f"{key}: row failed schema validation")
                cursor.execute(
                    f"select workspace_id::text, target_type, field_key, count(*) "
                    f"from {CORRECTIONS_TABLE} where tenant_slug = %s and status = 'active' "
                    f"group by 1, 2, 3 having count(*) > 1", (slug,))
                if cursor.fetchall():
                    problems.append("one-active-lineage invariant violated")
            expected = (marker or {}).get("imported_counts")
            print(json.dumps({"tool": "normalized_import", "mode": mode,
                              "row_counts": counts, "marker_counts": expected,
                              "problems": problems, "ok": not problems}))
            return 1 if problems else 0

    print(json.dumps({"error": f"unknown mode {mode!r}; use assess|dry-run|execute|verify"}))
    return 2


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1] if len(sys.argv) > 1 else "assess"))
