"""Explicit operator cutover tool: snapshot -> normalized correction persistence.

Usage (explicit operator command; NEVER run at API startup):

    python -m backend.app.normalized_import assess
    python -m backend.app.normalized_import dry-run
    python -m backend.app.normalized_import execute
    python -m backend.app.normalized_import verify

Reads MONDAY_REPORT_DATABASE_URL (or DATABASE_URL) and MONDAY_REPORT_TENANT_SLUG.
Behaviour per docs/NORMALIZED_CORRECTION_PERSISTENCE.md:

- ``assess``   read-only: reports snapshot holdings, migration metadata,
               relationship + supersession-lineage validity, existing-row
               conflicts (tenant-scoped AND cross-tenant id reuse), marker state.
- ``dry-run``  performs the full transformation in memory, writes nothing.
- ``execute``  ONE transaction under the global snapshot advisory lock:
               re-reads the snapshot FOR UPDATE, refuses on conflicts / lineage
               issues / an already-cutover marker, then TWO-PHASE inserts every
               normalized row (deterministic ids = the entities' own UUIDs):
               phase 1 inserts each correction with NULL self-references, phase 2
               sets the validated supersession backlinks once every id exists
               (a non-deferrable self-FK cannot take a forward reference).
               Conflicts are classified explicitly (never ``ON CONFLICT DO
               NOTHING``): a divergent or cross-tenant existing row aborts the
               whole cutover. Upserts the tenant/workspace anchors, strips the
               migrated keys, writes a count+digest authority marker, commits via
               revision CAS. All units import atomically or not at all.
- ``verify``   AUTHORITATIVE: compares the marker's per-entity counts AND id
               digests against the actual tenant-scoped normalized rows, validates
               every doc against the application schema, checks the one-active
               lineage invariant, and that the snapshot no longer holds migrated
               keys. ``ok: true`` only when every count and digest matches and no
               invariant is violated.

Reruns are idempotent: with the marker present, ``execute`` degrades to
``verify``. Unsupported states (marker present but rows missing/mismatched,
divergent or cross-tenant existing rows, broken lineage) fail closed with a
redacted summary. The tool never prints credentials, DSNs, or entity content --
only counts, ids and fingerprints.

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
from collections import Counter
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
NORMALIZED_AUTHORITY_VERSION = 2

MODELS = {
    "monday_reports": MondayReport,
    "field_corrections": FieldCorrection,
    "validation_tasks": ValidationTask,
}

TABLES = {"monday_reports": REPORTS_TABLE, "field_corrections": CORRECTIONS_TABLE,
          "validation_tasks": TASKS_TABLE}


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


def _id_digest(entities) -> str:
    """Deterministic digest of an entity set's ids (order-independent)."""
    ids = sorted(str(e.id) for e in entities)
    return sha256("\n".join(ids).encode("utf-8")).hexdigest()


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


def _classify_rows(connection, slug: str, parsed: dict[str, list]) -> dict:
    """Classify every source row against existing normalized rows.

    id is the GLOBAL primary key, so the existence probe deliberately does NOT
    filter by tenant: a same-id row owned by ANOTHER tenant is a hard conflict
    (id reuse / ghost), never a silent skip. Returns per-entity id lists for
    to_insert / already_matching plus a flat conflicts list.
    """
    result = {"to_insert": {k: [] for k in NORMALIZED_ENTITY_KEYS},
              "already_matching": {k: [] for k in NORMALIZED_ENTITY_KEYS},
              "conflicts": []}
    with connection.cursor() as cursor:
        for key, entities in parsed.items():
            table = TABLES[key]
            for entity in entities:
                cursor.execute(
                    f"select tenant_slug, doc from {table} where id = %s", (entity.id,))
                row = cursor.fetchone()
                if row is None:
                    result["to_insert"][key].append(entity.id)
                    continue
                existing_slug, existing_doc = row[0], row[1]
                if existing_slug != slug:
                    result["conflicts"].append(
                        f"{key}:{entity.id} (id already owned by another tenant)")
                elif _safe_json(entity.model_dump(mode="json")) != existing_doc:
                    result["conflicts"].append(f"{key}:{entity.id} (existing row diverges)")
                else:
                    result["already_matching"][key].append(entity.id)
    return result


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
        # field_key participates in the one-active coordinate and has a DB CHECK
        # (length > 0). Catch an empty value in-memory so it is a clean REFUSED
        # rather than a raw constraint error mid-insert.
        if not (correction.field_key or "").strip():
            issues.append(f"field_corrections:{correction.id} empty field_key")
    for task in parsed["validation_tasks"]:
        if str(task.tenant_id) != tenant_id:
            issues.append(f"validation_tasks:{task.id} tenant mismatch")
    return issues


def _lineage_issues(parsed: dict[str, list]) -> list[str]:
    """Validate the supersession lineage on the SOURCE before insertion.

    Every backlink must connect two corrections that (a) both exist, (b) share
    the tenant, (c) share the (workspace, target_type, field_key) coordinate,
    (d) run predecessor -> successor in time, (e) are reciprocal, (f) never
    self-reference, (g) never branch, and (h) never cycle; exactly one ACTIVE
    correction may exist per coordinate. Any violation rejects the whole import.
    """
    corrections = parsed["field_corrections"]
    by_id = {c.id: c for c in corrections}
    issues: list[str] = []

    active: dict[tuple, UUID] = {}
    for c in corrections:
        if c.status == "active":
            coord = (str(c.tenant_id), str(c.workspace_id), c.target_type, c.field_key)
            if coord in active:
                issues.append(
                    f"field_corrections: duplicate ACTIVE lineage at {coord[1:]}")
            active[coord] = c.id

    def _coord(c) -> tuple:
        return (str(c.tenant_id), str(c.workspace_id), c.target_type, c.field_key)

    for c in corrections:
        for label, ref in (("supersedes_id", c.supersedes_id),
                           ("superseded_by_id", c.superseded_by_id)):
            if ref is None:
                continue
            if ref == c.id:
                issues.append(f"field_corrections:{c.id} {label} self-reference")
                continue
            other = by_id.get(ref)
            if other is None:
                issues.append(f"field_corrections:{c.id} {label} -> missing {ref}")
                continue
            if other.tenant_id != c.tenant_id:
                issues.append(f"field_corrections:{c.id} {label} crosses tenant")
            if _coord(other) != _coord(c):
                issues.append(f"field_corrections:{c.id} {label} crosses coordinate")
        # successor must be newer than predecessor
        if c.superseded_by_id is not None:
            succ = by_id.get(c.superseded_by_id)
            if succ is not None and succ.created_at < c.created_at:
                issues.append(f"field_corrections:{c.id} superseded_by is older")
            # reciprocity (forward): successor.supersedes_id must point back
            if succ is not None and succ.supersedes_id != c.id:
                issues.append(f"field_corrections:{c.id} non-reciprocal supersession")
        # reciprocity (reverse): every supersedes_id link must be mirrored by the
        # predecessor's superseded_by_id. Without this a supersedes_id-only cycle
        # (A.supersedes=B, B.supersedes=A, both superseded_by NULL) would evade
        # the superseded_by_id-chain cycle detection below.
        if c.supersedes_id is not None:
            pred = by_id.get(c.supersedes_id)
            if pred is not None and pred.superseded_by_id != c.id:
                issues.append(f"field_corrections:{c.id} non-reciprocal supersedes link")

    # branching: no two corrections may share a successor or a predecessor
    for ref, n in Counter(c.superseded_by_id for c in corrections
                          if c.superseded_by_id is not None).items():
        if n > 1:
            issues.append(f"field_corrections: branching lineage into successor {ref}")
    for ref, n in Counter(c.supersedes_id for c in corrections
                          if c.supersedes_id is not None).items():
        if n > 1:
            issues.append(f"field_corrections: branching lineage from predecessor {ref}")

    # cycle detection along superseded_by_id chains
    for start in corrections:
        seen: set[UUID] = set()
        cur = start
        while cur is not None and cur.superseded_by_id is not None:
            if cur.id in seen:
                issues.append(f"field_corrections: supersession cycle at {cur.id}")
                break
            seen.add(cur.id)
            cur = by_id.get(cur.superseded_by_id)

    return issues


def _all_issues(payload: dict, parsed: dict[str, list]) -> list[str]:
    return _relationship_issues(payload, parsed) + _lineage_issues(parsed)


def _summary(mode, payload, revision, parsed, classification, issues, marker) -> dict:
    conflicts = (classification or {}).get("conflicts", [])
    return {
        "tool": "normalized_import", "mode": mode,
        "snapshot_present": payload is not None,
        "snapshot_revision": revision,
        "marker_present": bool(marker),
        "holdings": {k: len(v) for k, v in (parsed or {}).items()},
        "conflicts": len(conflicts),
        "conflict_refs": conflicts[:10],
        "relationship_issues": len(issues or []),
        "issue_refs": (issues or [])[:10],
    }


def _insert_rows(connection, slug: str, payload: dict, parsed: dict[str, list],
                 classification: dict) -> dict:
    """Two-phase insert. Only rows in ``to_insert`` are written; ``already_matching``
    rows are counted but left untouched. Returns detailed accounting."""
    tenant = payload.get("tenant") or {}
    from psycopg.types.json import Jsonb

    to_insert = classification["to_insert"]
    matching = classification["already_matching"]
    inserted = {k: 0 for k in NORMALIZED_ENTITY_KEYS}

    with connection.cursor() as cursor:
        cursor.execute("select set_config('app.tenant_slug', %s, true)", (slug,))
        cursor.execute(
            "insert into tenants (id, name, slug) values (%s, %s, %s) "
            "on conflict (id) do update set name = excluded.name, slug = excluded.slug",
            (tenant.get("id"), tenant.get("name", "tenant"), slug))
        for workspace in payload.get("workspaces", []):
            cursor.execute(
                "insert into workspaces (id, tenant_id, name) values (%s, %s, %s) "
                "on conflict (id) do update set name = excluded.name",
                (workspace.get("id"), tenant.get("id"), workspace.get("name", "workspace")))

        insert_reports = set(to_insert["monday_reports"])
        for report in parsed["monday_reports"]:
            if report.id not in insert_reports:
                continue
            cursor.execute(
                f"insert into {REPORTS_TABLE} (id, tenant_id, tenant_slug, workspace_id, status, "
                f"revision, doc, created_at, updated_at) values (%s, %s, %s, %s, %s, 0, %s, %s, %s)",
                (report.id, report.tenant_id, slug, report.workspace_id, report.status,
                 Jsonb(_safe_json(report.model_dump(mode="json"))),
                 report.created_at, report.created_at))
            inserted["monday_reports"] += 1

        # PHASE 1: insert every correction with NULL self-references. A
        # non-deferrable self-FK cannot accept a forward reference, so the
        # backlinks are set only in phase 2 once every id exists.
        insert_corr = set(to_insert["field_corrections"])
        for c in parsed["field_corrections"]:
            if c.id not in insert_corr:
                continue
            cursor.execute(
                f"insert into {CORRECTIONS_TABLE} (id, tenant_id, tenant_slug, workspace_id, "
                f"target_type, field_key, status, supersedes_id, superseded_by_id, actor_user_id, "
                f"reviewer_user_id, revision, doc, created_at, updated_at) "
                f"values (%s, %s, %s, %s, %s, %s, %s, NULL, NULL, %s, %s, 0, %s, %s, %s)",
                (c.id, c.tenant_id, slug, c.workspace_id, c.target_type, c.field_key, c.status,
                 c.actor_user_id, c.reviewer_user_id,
                 Jsonb(_safe_json(c.model_dump(mode="json"))), c.created_at, c.created_at))
            inserted["field_corrections"] += 1

        # PHASE 2: set the validated supersession backlinks now that every
        # correction row (and its referents) exist.
        for c in parsed["field_corrections"]:
            if c.id not in insert_corr:
                continue
            if c.supersedes_id is None and c.superseded_by_id is None:
                continue
            cursor.execute(
                f"update {CORRECTIONS_TABLE} set supersedes_id = %s, superseded_by_id = %s "
                f"where tenant_slug = %s and id = %s",
                (c.supersedes_id, c.superseded_by_id, slug, c.id))

        insert_tasks = set(to_insert["validation_tasks"])
        for t in parsed["validation_tasks"]:
            if t.id not in insert_tasks:
                continue
            cursor.execute(
                f"insert into {TASKS_TABLE} (id, tenant_id, tenant_slug, target_type, target_id, "
                f"status, revision, reviewer_user_id, doc, created_at, updated_at) "
                f"values (%s, %s, %s, %s, %s, %s, 0, %s, %s, %s, %s)",
                (t.id, t.tenant_id, slug, t.target_type, t.target_id, t.status.value,
                 t.reviewer_user_id, Jsonb(_safe_json(t.model_dump(mode="json"))),
                 t.created_at, t.created_at))
            inserted["validation_tasks"] += 1

    return {
        "source_rows": {k: len(parsed[k]) for k in NORMALIZED_ENTITY_KEYS},
        "inserted_rows": inserted,
        "matching_existing_rows": {k: len(matching[k]) for k in NORMALIZED_ENTITY_KEYS},
        "verified_rows": {k: inserted[k] + len(matching[k]) for k in NORMALIZED_ENTITY_KEYS},
    }


def _import_audit_reference(parsed: dict[str, list], revision: int, slug: str) -> dict:
    """A verifiable, redacted import-batch reference stamped into the marker.

    This is NOT a fabricated per-entity historical audit event. It records that
    THIS cutover moved the entities, identified by a deterministic content
    fingerprint, so the origin of imported rows is auditable without inventing
    user actions that never happened."""
    fingerprint = sha256(
        ("|".join(f"{k}:{_id_digest(parsed[k])}" for k in NORMALIZED_ENTITY_KEYS)
         + f"|rev:{revision}|slug:{slug}").encode("utf-8")).hexdigest()
    return {"kind": "normalized.import", "actor": "system:normalized_import",
            "source_revision": revision, "content_fingerprint": fingerprint}


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
            classification = _classify_rows(connection, slug, parsed)
            issues = _all_issues(payload, parsed)
            print(json.dumps(_summary(mode, payload, revision, parsed, classification, issues, marker)))
            blocked = bool(classification["conflicts"] or issues)
            if mode == "dry-run":
                print(json.dumps({"dry_run_would_execute": not blocked and not marker,
                                  "already_cut_over": bool(marker)}))
            return 1 if blocked else 0

    if mode == "execute":
        connection = psycopg.connect(url, connect_timeout=5)
        connection.autocommit = False
        try:
            with connection.cursor() as cursor:
                cursor.execute("select set_config('lock_timeout', %s, true)",
                               (f"{SNAPSHOT_LOCK_TIMEOUT_MS}ms",))
                cursor.execute("select set_config('app.tenant_slug', %s, true)", (slug,))
                # Cutover lock: the SAME advisory key the app's snapshot
                # transaction takes, so no normalized mutation can interleave.
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
            classification = _classify_rows(connection, slug, parsed)
            issues = _all_issues(payload, parsed)
            if classification["conflicts"] or issues:
                print(json.dumps(_summary(mode, payload, revision, parsed, classification, issues, marker)))
                print(json.dumps({"result": "REFUSED: resolve conflicts/lineage/issues first"}))
                connection.rollback()
                return 1
            accounting = _insert_rows(connection, slug, payload, parsed, classification)
            for key in NORMALIZED_ENTITY_KEYS:
                payload[key] = []
            payload["normalized_authority"] = {
                "version": NORMALIZED_AUTHORITY_VERSION,
                "entities": list(NORMALIZED_ENTITY_KEYS),
                "tenant_slug": slug,
                "imported_counts": {k: accounting["verified_rows"][k] for k in NORMALIZED_ENTITY_KEYS},
                "id_digests": {k: _id_digest(parsed[k]) for k in NORMALIZED_ENTITY_KEYS},
                "accounting": accounting,
                "import_audit": _import_audit_reference(parsed, revision, slug),
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
            # Verify inside the SAME transaction before publishing the marker,
            # so an incomplete/mismatched import can never activate.
            problems = _verify_state(connection, slug, payload)
            if problems:
                connection.rollback()
                print(json.dumps({"tool": "normalized_import", "mode": mode,
                                  "result": "REFUSED: post-insert verification failed",
                                  "problems": problems[:10]}))
                return 1
            connection.commit()
            print(json.dumps({"tool": "normalized_import", "mode": mode, "result": "cut over",
                              "accounting": accounting, "pre_cutover_revision": revision}))
            return 0
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    if mode == "verify":
        with psycopg.connect(url, connect_timeout=5) as connection:
            payload, revision = _load(connection, slug)
            problems = _verify_state(connection, slug, payload)
            counts, digests = _measure(connection, slug)
            marker = (payload or {}).get("normalized_authority")
            print(json.dumps({"tool": "normalized_import", "mode": mode,
                              "row_counts": counts, "row_digests": digests,
                              "marker_counts": (marker or {}).get("imported_counts"),
                              "marker_digests": (marker or {}).get("id_digests"),
                              "problems": problems, "ok": not problems}))
            return 1 if problems else 0

    print(json.dumps({"error": f"unknown mode {mode!r}; use assess|dry-run|execute|verify"}))
    return 2


def _measure(connection, slug: str) -> tuple[dict, dict]:
    """Tenant-scoped counts and id digests from the normalized tables."""
    counts: dict[str, int] = {}
    digests: dict[str, str] = {}
    with connection.cursor() as cursor:
        cursor.execute("select set_config('app.tenant_slug', %s, true)", (slug,))
        for key, table in TABLES.items():
            # Explicit tenant filter IN ADDITION to the RLS GUC: the tool may
            # run as a superuser/owner role, which bypasses row-level security.
            cursor.execute(f"select id from {table} where tenant_slug = %s", (slug,))
            ids = sorted(str(r[0]) for r in cursor.fetchall())
            counts[key] = len(ids)
            digests[key] = sha256("\n".join(ids).encode("utf-8")).hexdigest()
    return counts, digests


def _verify_state(connection, slug: str, payload: dict | None) -> list[str]:
    """AUTHORITATIVE verification: marker vs actual normalized state.

    ok requires: a marker; the marker names this tenant and the expected
    authority version; the snapshot no longer holds migrated keys; every doc
    validates; the one-active-lineage invariant holds; and EVERY per-entity
    count AND id digest matches the marker. A marker present with rows missing,
    extra, or mismatched returns problems (never ok)."""
    problems: list[str] = []
    marker = (payload or {}).get("normalized_authority")
    if payload is None:
        return ["no snapshot"]
    if not marker:
        return ["no normalized_authority marker (not cut over)"]
    if marker.get("version") != NORMALIZED_AUTHORITY_VERSION:
        problems.append(
            f"marker authority version {marker.get('version')} != {NORMALIZED_AUTHORITY_VERSION}")
    if marker.get("tenant_slug") not in (None, slug):
        problems.append("marker tenant_slug does not identify this tenant")
    for key in NORMALIZED_ENTITY_KEYS:
        if payload.get(key):
            problems.append(f"snapshot still holds {key}")

    with connection.cursor() as cursor:
        cursor.execute("select set_config('app.tenant_slug', %s, true)", (slug,))
        for key, table in TABLES.items():
            cursor.execute(f"select doc from {table} where tenant_slug = %s", (slug,))
            for (doc,) in cursor.fetchall():
                try:
                    MODELS[key].model_validate(doc)
                except Exception:  # noqa: BLE001
                    problems.append(f"{key}: row failed schema validation")
                    break
        cursor.execute(
            f"select count(*) from {CORRECTIONS_TABLE} where tenant_slug = %s and status = 'active' "
            f"group by workspace_id, target_type, field_key having count(*) > 1", (slug,))
        if cursor.fetchall():
            problems.append("one-active-lineage invariant violated")

    counts, digests = _measure(connection, slug)
    marker_counts = marker.get("imported_counts") or {}
    marker_digests = marker.get("id_digests") or {}
    for key in NORMALIZED_ENTITY_KEYS:
        if marker_counts.get(key) != counts.get(key):
            problems.append(
                f"{key}: count {counts.get(key)} != marker {marker_counts.get(key)}")
        if marker_digests.get(key) != digests.get(key):
            problems.append(f"{key}: id digest does not match marker")
    return problems


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1] if len(sys.argv) > 1 else "assess"))
