"""Deterministic, idempotent PostgreSQL migration runner for Monday Report.

This module owns the *migration foundation*: it discovers the numbered SQL
migrations in ``db/migrations/``, records each applied version in a dedicated
``schema_migrations`` metadata table, and applies pending migrations under a
whole-run session-level advisory lock with per-migration transactions.

Scope and honest limitations
-----------------------------
* The runner applies a numbered ``.sql`` set chosen by ``--set``: ``legacy``
  (``db/migrations/``, immutable; its ``0003`` references tables no earlier legacy
  migration creates, so the legacy sequence is un-appliable and its validity stays
  BLOCKED) or ``baseline`` (``db/baseline/``, the corrected fresh-install sequence).
  It does **not** apply ``db/schema.sql`` (a divergent, flattened design reference
  that is *not* the authoritative sequence; see ``docs/POSTGRES_MIGRATIONS.md``).
* It is an **explicit** operator command (``python -m backend.app.migrations``);
  it is **never** run automatically on API startup.
* The supplemental static validator (:func:`validate_migration_set`) is a narrow
  regex heuristic with documented limitations — it is *supplemental only*. The
  source of truth for migration validity is a **real PostgreSQL execution**
  (exercised by ``scripts/migration_runner_guard.py``).
* This increment does **not** deliver normalized persistence, active RLS,
  transactional business/audit atomicity, or backup/restore. Those remain
  separate BLOCKED controls.

The module imports cleanly without a database driver or server present; the
``psycopg`` driver is imported lazily only when a database operation runs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# Repo root: backend/app/migrations.py -> parents[2] == repo root.
ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = ROOT / "db" / "migrations"
# Corrected fresh-install baseline (db/baseline/) kept separate from the immutable
# legacy sequence (db/migrations/). See docs/POSTGRES_MIGRATIONS.md.
BASELINE_DIR = ROOT / "db" / "baseline"
MIGRATION_SETS = {"legacy": MIGRATIONS_DIR, "baseline": BASELINE_DIR}

# Runner contract version. Recorded in schema_migrations.runner_version and in
# the evidence artifact. Bump on a behavioral change to the runner.
RUNNER_VERSION = "1.0.0"

# Filename contract (Part E): NNNN_description.sql, zero-padded 4-digit version,
# lowercase snake description, unique version, deterministic order by version.
FILENAME_RE = re.compile(r"^(\d{4})_([a-z0-9][a-z0-9_]*)\.sql$")

# Stable, app-specific 64-bit advisory-lock key (Part H). Derived deterministically
# from a fixed namespace string so every process contends on the SAME lock; it is
# NOT random and NOT environment-derived. pg_advisory_lock takes a bigint.
ADVISORY_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"monday_report.schema_migrations.v1").digest()[:8],
    "big",
    signed=True,
)

SCHEMA_MIGRATIONS_TABLE = "schema_migrations"

# The metadata table is intentionally minimal and stores NO credentials, NO
# absolute paths, and NO client data (Part F).
_CREATE_SCHEMA_MIGRATIONS = f"""
create table if not exists {SCHEMA_MIGRATIONS_TABLE} (
  version integer primary key,
  filename text not null,
  checksum_sha256 text not null,
  applied_at timestamptz not null default now(),
  execution_ms integer not null,
  runner_version text not null
)
"""


class MigrationError(RuntimeError):
    """Base class for migration-runner failures."""


class MigrationFilenameError(MigrationError):
    """A file in db/migrations/ violates the filename contract."""


class MigrationSequenceError(MigrationError):
    """The migration set is not a valid, unique, ordered sequence."""


class MigrationChecksumError(MigrationError):
    """An already-applied migration's on-disk checksum no longer matches the
    checksum recorded in schema_migrations (drift)."""


class MigrationApplyError(MigrationError):
    """A migration's SQL failed to apply; the transaction was rolled back and
    no metadata row was written."""


@dataclass(frozen=True)
class Migration:
    version: int
    description: str
    filename: str
    path: Path
    sql: str
    checksum_sha256: str

    @property
    def byte_length(self) -> int:
        return len(self.sql.encode("utf-8"))


@dataclass
class ApplyResult:
    ok: bool
    applied: list[dict] = field(default_factory=list)
    skipped: list[int] = field(default_factory=list)
    drift: list[dict] = field(default_factory=list)
    error: dict | None = None
    server_version: str | None = None

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "applied": self.applied,
            "skipped": self.skipped,
            "drift": self.drift,
            "error": self.error,
            "server_version": self.server_version,
        }


# --------------------------------------------------------------------------- #
# Discovery + filename/sequence contract (Parts C, E)
# --------------------------------------------------------------------------- #
def discover_migrations(migrations_dir: Path | None = None) -> list[Migration]:
    """Return the ordered, validated migration sequence.

    Enforces the filename contract, unique versions, and a deterministic order
    (ascending version). Reads each file as UTF-8 and computes a stable SHA-256
    over the raw bytes.
    """
    directory = migrations_dir or MIGRATIONS_DIR
    if not directory.is_dir():
        raise MigrationSequenceError(f"migrations directory not found: {directory.name}")

    migrations: list[Migration] = []
    seen_versions: dict[int, str] = {}
    for path in sorted(directory.glob("*.sql")):
        match = FILENAME_RE.match(path.name)
        if not match:
            raise MigrationFilenameError(
                f"{path.name!r} does not match the NNNN_description.sql contract"
            )
        version = int(match.group(1))
        if version in seen_versions:
            raise MigrationSequenceError(
                f"duplicate migration version {version:04d}: "
                f"{seen_versions[version]!r} and {path.name!r}"
            )
        seen_versions[version] = path.name
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:  # pragma: no cover - contract guard
            raise MigrationFilenameError(f"{path.name!r} is not valid UTF-8: {exc}") from exc
        migrations.append(
            Migration(
                version=version,
                description=match.group(2),
                filename=path.name,
                path=path,
                sql=text,
                checksum_sha256=hashlib.sha256(raw).hexdigest(),
            )
        )

    migrations.sort(key=lambda m: m.version)
    return migrations


def migration_set_sha256(migrations: list[Migration]) -> str:
    """Stable digest binding the whole migration set to the evidence artifact.

    Computed over the canonical (version, filename, checksum) triples so it is
    independent of filesystem ordering and carries no absolute paths.
    """
    canonical = json.dumps(
        [[m.version, m.filename, m.checksum_sha256] for m in migrations],
        separators=(",", ":"),
        sort_keys=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Supplemental static validator (Part K) — narrow heuristic, documented limits.
# --------------------------------------------------------------------------- #
_CREATE_TABLE_RE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?\"?([a-z_][a-z0-9_]*)\"?", re.IGNORECASE
)
# References inside a CREATE TABLE body: `references <target> (`.
_REFERENCES_RE = re.compile(
    r"references\s+\"?([a-z_][a-z0-9_]*)\"?\s*\(", re.IGNORECASE
)


@dataclass
class StaticValidationResult:
    ok: bool
    created_tables: list[str]
    broken_references: list[dict]
    limitations: list[str]

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "created_tables": self.created_tables,
            "broken_references": self.broken_references,
            "limitations": self.limitations,
        }


def validate_migration_set(migrations: list[Migration]) -> StaticValidationResult:
    """Heuristic, supplemental structural check of the migration sequence.

    Confirms — by regex, not by parsing SQL — that every ``references
    <table>(...)`` foreign-key target is a table created by the same or an
    EARLIER migration. This catches the class of defect where a migration
    references a table no prior migration creates (the migration-validity gap).

    LIMITATIONS (documented on purpose; see Part K): this is not a SQL parser.
    It does not resolve schemas/search_path, ALTER TABLE ADD CONSTRAINT added
    later, quoted/mixed-case identifiers beyond the simple form, column-level
    correctness, RLS/policy validity, or execution order within a file. It can
    produce false negatives. It NEVER establishes validity on its own — a real
    PostgreSQL execution (:mod:`scripts.migration_runner_guard`) is the source
    of truth.
    """
    created: list[str] = []
    created_set: set[str] = set()
    broken: list[dict] = []
    for migration in migrations:
        # Tables created by THIS migration become available to references within
        # the same migration (a table may reference an earlier table in the same
        # file). We register this migration's creates before checking its refs so
        # intra-migration self/forward references to sibling tables validate.
        this_creates = _CREATE_TABLE_RE.findall(migration.sql)
        for name in this_creates:
            lowered = name.lower()
            if lowered not in created_set:
                created_set.add(lowered)
                created.append(lowered)
        for target in _REFERENCES_RE.findall(migration.sql):
            if target.lower() not in created_set:
                broken.append(
                    {
                        "version": migration.version,
                        "filename": migration.filename,
                        "missing_target": target.lower(),
                    }
                )
    limitations = [
        "Regex heuristic, not a SQL parser: may miss ALTER TABLE ADD CONSTRAINT, "
        "schema-qualified targets, and column-level errors.",
        "Does not evaluate RLS policies, defaults, generated columns, or extensions.",
        "Supplemental only: real PostgreSQL execution is the source of truth for validity.",
    ]
    return StaticValidationResult(
        ok=not broken,
        created_tables=created,
        broken_references=broken,
        limitations=limitations,
    )


# --------------------------------------------------------------------------- #
# Database operations (Parts F, G, H, I) — psycopg imported lazily.
# --------------------------------------------------------------------------- #
def _connect(database_url: str):
    import psycopg  # lazy: module must import without a driver/server.

    return psycopg.connect(database_url, autocommit=True, connect_timeout=5)


def _server_version(conn) -> str:
    row = conn.execute("show server_version").fetchone()
    return str(row[0]) if row else "unknown"


def _ensure_schema_migrations(conn) -> None:
    conn.execute(_CREATE_SCHEMA_MIGRATIONS)


def _applied_rows(conn) -> dict[int, dict]:
    _ensure_schema_migrations(conn)
    rows = conn.execute(
        f"select version, filename, checksum_sha256, execution_ms, runner_version "
        f"from {SCHEMA_MIGRATIONS_TABLE} order by version"
    ).fetchall()
    result: dict[int, dict] = {}
    for version, filename, checksum, execution_ms, runner_version in rows:
        result[int(version)] = {
            "version": int(version),
            "filename": filename,
            "checksum_sha256": checksum,
            "execution_ms": int(execution_ms),
            "runner_version": runner_version,
        }
    return result


def _detect_drift(migrations: list[Migration], applied: dict[int, dict]) -> list[dict]:
    """Applied migrations whose on-disk checksum no longer matches what was
    recorded. The checksum in schema_migrations is NEVER rewritten (Part F)."""
    by_version = {m.version: m for m in migrations}
    drift: list[dict] = []
    for version, row in applied.items():
        migration = by_version.get(version)
        if migration is None:
            drift.append(
                {
                    "version": version,
                    "stored_checksum": row["checksum_sha256"],
                    "current_checksum": None,
                    "reason": "applied migration missing from db/migrations/",
                }
            )
        elif migration.checksum_sha256 != row["checksum_sha256"]:
            drift.append(
                {
                    "version": version,
                    "stored_checksum": row["checksum_sha256"],
                    "current_checksum": migration.checksum_sha256,
                    "reason": "on-disk checksum differs from applied checksum",
                }
            )
    return drift


def apply_migrations(database_url: str, *, migrations_dir: Path | None = None) -> ApplyResult:
    """Apply all pending migrations deterministically and idempotently.

    Contract:
    * Acquires a whole-run **session-level** advisory lock (Part H); released in
      ``finally``. A session lock (not xact-level) is held across the per-migration
      transactions on the same connection and does not rely solely on the PK.
    * Rejects the run if any already-applied migration's checksum has drifted
      (Part F) — before applying anything new.
    * Applies each pending migration in its OWN transaction: BEGIN -> run SQL ->
      insert metadata row -> COMMIT (Part I). On failure: ROLLBACK, no metadata
      row, and STOP (later migrations are not attempted).
    * Re-running with nothing pending is a no-op (idempotent).
    """
    migrations = discover_migrations(migrations_dir)
    result = ApplyResult(ok=True)
    # Connection establishment sits INSIDE the guarded region: a connect failure
    # raises driver text carrying host, port and username, which previously
    # escaped as an unredacted traceback because `_connect` was called before
    # the try block.
    try:
        conn = _connect(database_url)
    except Exception as exc:  # noqa: BLE001 - surface a redacted failure.
        result.ok = False
        result.error = {"version": None, "filename": None, "message": _redact(str(exc))}
        return result
    lock_acquired = False
    try:
        result.server_version = _server_version(conn)
        conn.execute("select pg_advisory_lock(%s)", (ADVISORY_LOCK_KEY,))
        lock_acquired = True

        applied = _applied_rows(conn)
        drift = _detect_drift(migrations, applied)
        if drift:
            result.ok = False
            result.drift = drift
            result.error = {
                "version": drift[0]["version"],
                "message": "checksum drift on an already-applied migration; refusing to apply",
            }
            return result

        for migration in migrations:
            if migration.version in applied:
                result.skipped.append(migration.version)
                continue
            started = time.perf_counter()
            try:
                with conn.transaction():
                    # Multi-statement migration body runs via the simple protocol
                    # (no params) so all statements in the file execute in-order.
                    conn.execute(migration.sql)
                    execution_ms = int((time.perf_counter() - started) * 1000)
                    conn.execute(
                        f"insert into {SCHEMA_MIGRATIONS_TABLE} "
                        f"(version, filename, checksum_sha256, execution_ms, runner_version) "
                        f"values (%s, %s, %s, %s, %s)",
                        (
                            migration.version,
                            migration.filename,
                            migration.checksum_sha256,
                            execution_ms,
                            RUNNER_VERSION,
                        ),
                    )
            except Exception as exc:  # noqa: BLE001 - surface a redacted failure.
                result.ok = False
                result.error = {
                    "version": migration.version,
                    "filename": migration.filename,
                    "message": _redact(str(exc)),
                }
                return result
            result.applied.append(
                {
                    "version": migration.version,
                    "filename": migration.filename,
                    "checksum_sha256": migration.checksum_sha256,
                    "execution_ms": execution_ms,
                }
            )
        return result
    finally:
        if lock_acquired:
            try:
                conn.execute("select pg_advisory_unlock(%s)", (ADVISORY_LOCK_KEY,))
            except Exception:  # noqa: BLE001 - unlock best-effort; session close frees it.
                pass
        conn.close()


def migration_status(
    database_url: str | None, *, migrations_dir: Path | None = None
) -> dict:
    """Report applied vs pending versions, checksums, and drift.

    With no database URL, reports only the on-disk migration set (offline).
    """
    migrations = discover_migrations(migrations_dir)
    on_disk = [
        {
            "version": m.version,
            "filename": m.filename,
            "checksum_sha256": m.checksum_sha256,
            "byte_length": m.byte_length,
        }
        for m in migrations
    ]
    report: dict = {
        "runner_version": RUNNER_VERSION,
        "migration_set_sha256": migration_set_sha256(migrations),
        "migration_count": len(migrations),
        "on_disk": on_disk,
        "database_reachable": False,
        "applied": [],
        "pending": [m.version for m in migrations],
        "drift": [],
    }
    if not database_url:
        return report
    conn = _connect(database_url)
    try:
        report["server_version"] = _server_version(conn)
        applied = _applied_rows(conn)
        report["database_reachable"] = True
        report["applied"] = sorted(applied.keys())
        report["pending"] = [m.version for m in migrations if m.version not in applied]
        report["drift"] = _detect_drift(migrations, applied)
    finally:
        conn.close()
    return report


# --------------------------------------------------------------------------- #
# Redaction (Part M/N): never surface DSNs, passwords, or absolute paths.
# --------------------------------------------------------------------------- #
_DSN_RE = re.compile(r"(postgres(?:ql)?://)[^ \t\n\"']*", re.IGNORECASE)
# Every libpq keyword that can carry a credential or a network location.
_KEYWORD_RE = re.compile(
    r"\b(password|passfile|user|host|hostaddr|port|dbname)=[^ \t\n\"']*", re.IGNORECASE
)
# libpq reports the network location and the account as free-form PROSE, e.g.
#   connection to server at "10.0.0.5", port 6543 failed: FATAL: ... for user "appuser"
# Keyword-only redaction left all of that in the message.
_LIBPQ_SERVER_RE = re.compile(
    r"(connection to server(?: at)?\s*)\"[^\"]*\"(\s*,\s*port\s+\d+)?", re.IGNORECASE
)
_LIBPQ_USER_RE = re.compile(r"(\bfor user\s+)\"[^\"]*\"", re.IGNORECASE)
# A real Windows path has ONE backslash after the drive letter. The previous
# pattern required two, so no genuine Windows path was ever redacted.
# Quoted paths first: a real Windows path often contains spaces
# ("C:\Program Files\..."), which the unquoted pattern would truncate at the space
# and leave the remainder visible.
_QUOTED_WINPATH_RE = re.compile(r"\"[A-Za-z]:\\[^\"]*\"")
_WINPATH_RE = re.compile(r"[A-Za-z]:\\[^ \t\n\"']*")
_POSIXPATH_RE = re.compile(r"/[^ \t\n\"']{3,}")


def _redact(message: str) -> str:
    """Strip DSNs, credentials, network locations and absolute paths from an error.

    Applied to every failure surfaced by this module — including failures to
    establish the connection, whose driver text carries host, port and username.
    """
    # Substitute the WHOLE DSN with a slash-free token so the path rules below
    # cannot chew into the placeholder.
    redacted = _DSN_RE.sub("<redacted-dsn>", message)
    redacted = _LIBPQ_SERVER_RE.sub(r"\1<redacted>", redacted)
    redacted = _LIBPQ_USER_RE.sub(r"\1<redacted>", redacted)
    redacted = _KEYWORD_RE.sub(lambda m: f"{m.group(1)}=<redacted>", redacted)
    redacted = _QUOTED_WINPATH_RE.sub('"<path>"', redacted)
    redacted = _WINPATH_RE.sub("<path>", redacted)
    redacted = _POSIXPATH_RE.sub("<path>", redacted)
    return redacted


# --------------------------------------------------------------------------- #
# CLI (Part G) — explicit operator command; NOT run on API startup.
# --------------------------------------------------------------------------- #
def _resolve_database_url(arg_url: str | None) -> str | None:
    if arg_url:
        return arg_url
    import os

    return os.environ.get("MONDAY_REPORT_MIGRATIONS_DATABASE_URL") or os.environ.get(
        "DATABASE_URL"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m backend.app.migrations",
        description="Deterministic PostgreSQL migration runner for Monday Report.",
    )
    parser.add_argument("command", choices=("apply", "status", "validate"))
    parser.add_argument(
        "--set",
        dest="migration_set",
        choices=tuple(MIGRATION_SETS),
        default="legacy",
        help="Which migration set to operate on: 'legacy' (db/migrations/, immutable, "
        "0003 un-appliable) or 'baseline' (db/baseline/, corrected fresh-install). Default: legacy.",
    )
    parser.add_argument(
        "--database-url",
        default=None,
        help="PostgreSQL DSN. Falls back to MONDAY_REPORT_MIGRATIONS_DATABASE_URL "
        "or DATABASE_URL. The value is never echoed.",
    )
    args = parser.parse_args(argv)
    mig_dir = MIGRATION_SETS[args.migration_set]

    if args.command == "validate":
        migrations = discover_migrations(mig_dir)
        static = validate_migration_set(migrations)
        print(
            json.dumps(
                {
                    "command": "validate",
                    "set": args.migration_set,
                    "migration_count": len(migrations),
                    "static_validation": static.to_dict(),
                    "note": "Static validation is supplemental; real PostgreSQL "
                    "execution is the source of truth for migration validity.",
                },
                indent=2,
            )
        )
        return 0 if static.ok else 1

    database_url = _resolve_database_url(args.database_url)

    if args.command == "status":
        report = migration_status(database_url, migrations_dir=mig_dir)
        print(json.dumps({"set": args.migration_set, **report}, indent=2))
        return 0

    # apply
    if not database_url:
        print(
            json.dumps(
                {
                    "command": "apply",
                    "ok": False,
                    "error": "no database URL provided (use --database-url or "
                    "MONDAY_REPORT_MIGRATIONS_DATABASE_URL)",
                },
                indent=2,
            )
        )
        return 2
    result = apply_migrations(database_url, migrations_dir=mig_dir)
    print(json.dumps({"command": "apply", "set": args.migration_set, **result.to_dict()}, indent=2))
    return 0 if result.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
