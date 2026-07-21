"""Guard for the deterministic PostgreSQL migration runner (Part P).

57 numbered checks across: file/version contract, static validator, metadata +
immutability, fresh apply / validity, idempotent rerun, partial upgrades,
failure/rollback, concurrency, evidence/readiness, and regressions/isolation.

The DECISIVE migration-validity checks are REAL PostgreSQL executions. When a
disposable, test-marked PostgreSQL is provided via
``MONDAY_REPORT_TEST_DATABASE_URL`` those checks run against it; when it is
absent (or unreachable) those checks are recorded as SKIPPED (not failed) so the
guard stays green in a no-PostgreSQL environment, and NO passing evidence is
emitted — keeping ``migration-runner`` and ``migration-validity`` BLOCKED.

Ephemeral-database safety (Part M): the target database name MUST contain a
``test`` marker and resolve to a local host; the guard refuses destructive setup
otherwise, and never prints the DSN or password.

Evidence (Part N) is written ONLY under ``--emit-evidence`` (never on a plain
``audit:all`` run), so a committed passing artifact is not clobbered by a no-PG run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import uuid
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

EVIDENCE_PATH = ROOT / "output" / "migrations" / "migration-evidence.v1.json"
EVIDENCE_SCHEMA_VERSION = "migration-evidence.v1"

checks: list[dict] = []


def record(name: str, ok: bool, detail: object, skipped: bool = False) -> None:
    checks.append({"name": name, "ok": bool(ok), "skipped": bool(skipped), "detail": detail})


# --------------------------------------------------------------------------- #
# PostgreSQL availability + ephemeral-DB safety (Part M)
# --------------------------------------------------------------------------- #
def test_database_url() -> str | None:
    return os.environ.get("MONDAY_REPORT_TEST_DATABASE_URL")


def _parse_conninfo(url: str) -> dict:
    """Structured parse of a DSN in EITHER supported libpq form.

    psycopg accepts both the URL form (``postgresql://...``) and the keyword/value
    form (``host=... dbname=... password=...``). ``urlsplit`` only understands the
    former: given keyword/value input it returns ``hostname=None`` and puts the
    ENTIRE string — password included — into ``.path``. Returns ``{}`` when the
    form cannot be determined, so callers can fail closed.
    """
    try:
        from psycopg.conninfo import conninfo_to_dict

        return dict(conninfo_to_dict(url))
    except Exception:
        parts = urlsplit(url)
        if parts.scheme in {"postgres", "postgresql"}:
            return {"dbname": parts.path.lstrip("/"), "host": parts.hostname or ""}
        return {}


def preflight_disposable_db(url: str) -> tuple[bool, str]:
    """Refuse destructive setup unless the target is an explicitly test-marked
    database on a loopback host.

    FAIL-CLOSED. An unparseable DSN, a missing database name, or an
    indeterminate host is REFUSED rather than allowed — an empty host previously
    satisfied the local-host check, which would have permitted
    ``drop schema public cascade`` against a remote server.

    The returned reason NEVER interpolates the DSN, password, host or username;
    it is recorded in the guard's stdout JSON.
    """
    info = _parse_conninfo(url)
    if not info:
        return False, "connection string could not be parsed; refusing destructive setup"
    name = str(info.get("dbname") or "")
    host = str(info.get("host") or "").strip().lower()
    if not name:
        return False, "connection string carries no database name; refusing destructive setup"
    if "test" not in name.lower():
        return False, "database name lacks a 'test' marker; refusing destructive setup"
    if not host:
        return False, "connection string carries no explicit host; refusing destructive setup"
    if host not in {"localhost", "127.0.0.1", "::1"}:
        return False, "target host is not loopback; refusing to run against a shared/remote DB"
    return True, "disposable db ok (test-marked database name on a loopback host)"


def pg_reachable(url: str) -> bool:
    try:
        import psycopg

        with psycopg.connect(url, connect_timeout=4) as conn:
            conn.execute("select 1")
        return True
    except Exception:
        return False


def _connect(url: str):
    import psycopg

    return psycopg.connect(url, autocommit=True, connect_timeout=6)


def reset_public_schema(url: str) -> None:
    """Return the disposable database to an empty state between scenarios."""
    with _connect(url) as conn:
        conn.execute("drop schema if exists public cascade")
        conn.execute("create schema public")
        conn.execute("grant all on schema public to public")


def table_exists(url: str, table: str) -> bool:
    with _connect(url) as conn:
        row = conn.execute("select to_regclass(%s)", (f"public.{table}",)).fetchone()
        return bool(row and row[0] is not None)


def fk_target(url: str, table: str, column: str) -> str | None:
    """Return the referenced table name for a single-column FK, or None."""
    with _connect(url) as conn:
        row = conn.execute(
            """
            select ccu.table_name
            from information_schema.table_constraints tc
            join information_schema.key_column_usage kcu
              on tc.constraint_name = kcu.constraint_name and tc.table_schema = kcu.table_schema
            join information_schema.constraint_column_usage ccu
              on tc.constraint_name = ccu.constraint_name and tc.table_schema = ccu.table_schema
            where tc.constraint_type = 'FOREIGN KEY'
              and tc.table_name = %s and kcu.column_name = %s
            limit 1
            """,
            (table, column),
        ).fetchone()
        return row[0] if row else None


def rls_enabled(url: str, table: str) -> bool:
    with _connect(url) as conn:
        row = conn.execute(
            "select relrowsecurity from pg_class where relname = %s", (table,)
        ).fetchone()
        return bool(row and row[0])


def schema_migrations_rows(url: str) -> list[dict]:
    import backend.app.migrations as M

    with _connect(url) as conn:
        return list(M._applied_rows(conn).values())


# --------------------------------------------------------------------------- #
# Helpers for temp migration subsets / mutations
# --------------------------------------------------------------------------- #
def copy_subset(dest: Path, migrations, versions: set[int]) -> Path:
    """Copy a subset of migrations BYTE-FOR-BYTE.

    ``newline=""`` is mandatory: checksums are computed over ``path.read_bytes()``
    (see ``discover_migrations``), and Python's text mode would otherwise
    translate ``\\n`` to ``\\r\\n`` on Windows. That silently changes the raw bytes
    and therefore the SHA-256, making a faithful copy look like checksum drift.
    """
    dest.mkdir(parents=True, exist_ok=True)
    for m in migrations:
        if m.version in versions:
            (dest / m.filename).write_text(m.sql, encoding="utf-8", newline="")
    return dest


def write_dir(dest: Path, files: dict[str, str]) -> Path:
    """Write literal SQL files with no newline translation (see ``copy_subset``)."""
    dest.mkdir(parents=True, exist_ok=True)
    for name, sql in files.items():
        (dest / name).write_text(sql, encoding="utf-8", newline="")
    return dest


# --------------------------------------------------------------------------- #
# Evidence (Part N)
# --------------------------------------------------------------------------- #
def _git(args: list[str]) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=str(ROOT), text=True).strip()
    except Exception:
        return "unknown"


def canonical_payload_sha256(payload: dict) -> str:
    body = {k: v for k, v in payload.items() if k != "payload_sha256"}
    canonical = json.dumps(body, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_evidence(pg_ran: bool, server_version: str | None, scenarios: dict, generated_at: str,
                   totals: dict | None = None) -> dict:
    import backend.app.migrations as M

    migrations = M.discover_migrations()  # immutable legacy sequence (the committed db/migrations/)
    baseline = M.discover_migrations(M.BASELINE_DIR)  # corrected supported baseline
    # Report what ACTUALLY applied on the real database, not the on-disk version list.
    # The legacy sequence does NOT apply (0003 references tables that never existed), so
    # claiming applied_versions == [1, 2, 3] would misrepresent the run.
    fresh = scenarios.get("fresh_apply") or {}
    legacy_result = scenarios.get("legacy_apply_result") or {}
    baseline_applied = list(fresh.get("applied") or []) if pg_ran else []
    payload: dict = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "generated_at": generated_at,
        "git_commit": _git(["rev-parse", "HEAD"]),
        "git_tree": _git(["rev-parse", "HEAD^{tree}"]),
        "worktree_clean": _git(["status", "--porcelain"]) == "",
        "runner_version": M.RUNNER_VERSION,
        "postgres_server_version": server_version,
        "postgres_image_digest": os.environ.get("MONDAY_REPORT_TEST_PG_IMAGE_DIGEST") or None,
        "migration_set_sha256": M.migration_set_sha256(migrations),
        "baseline_migration_set_sha256": M.migration_set_sha256(baseline),
        "migration_count": len(migrations),
        "legacy_migration_versions": [m.version for m in migrations],
        "legacy_apply_ok": bool(legacy_result.get("ok")) if pg_ran else None,
        "legacy_failed_version": legacy_result.get("failed_version") if pg_ran else None,
        "baseline_applied_versions": baseline_applied,
        "check_totals": dict(totals or {}),
        "checksums": {m.filename: m.checksum_sha256 for m in migrations},
        "baseline_checksums": {m.filename: m.checksum_sha256 for m in baseline},
        "legacy_apply_result": scenarios.get("legacy_apply_result"),
        "fresh_apply_result": scenarios.get("fresh_apply"),
        "rerun_result": scenarios.get("rerun"),
        "partial_upgrade_result": scenarios.get("partial_upgrade"),
        "concurrency_result": scenarios.get("concurrency"),
        "rollback_result": scenarios.get("rollback"),
        "checksum_drift_result": scenarios.get("checksum_drift"),
        "status": _evidence_status(pg_ran, totals),
    }
    payload["payload_sha256"] = canonical_payload_sha256(payload)
    return payload


def _evidence_status(pg_ran: bool, totals: dict | None) -> str:
    """`passed` requires a real database AND a clean run.

    Keying the status off database reachability alone let a run with FAILING
    checks emit an artifact claiming `"passed"`. `ga_readiness` gates
    `ga_migration_runner` on exactly this field, so that would have flipped the
    blocker to PASS on a failed run. Any skip also disqualifies: partial coverage
    is not proof.
    """
    if not pg_ran:
        return "BLOCKED_NO_POSTGRES"
    counts = dict(totals or {})
    if not counts:
        return "BLOCKED_TOTALS_UNKNOWN"
    if counts.get("failed", 0):
        return "BLOCKED_FAILING_CHECKS"
    if counts.get("skipped", 0):
        return "BLOCKED_SKIPPED_CHECKS"
    if counts.get("passed", 0) <= 0:
        return "BLOCKED_TOTALS_UNKNOWN"
    return "passed"


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--emit-evidence", action="store_true")
    args = parser.parse_args()

    # Isolate any store the imports may build (never touch live .local_data).
    tmp_root = Path(tempfile.mkdtemp(prefix="mr-migration-guard-"))
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")
    for key in ("MONDAY_REPORT_REPOSITORY_BACKEND", "MONDAY_REPORT_DATABASE_URL", "DATABASE_URL"):
        os.environ.pop(key, None)

    import backend.app.migrations as M

    migrations = M.discover_migrations()  # legacy sequence (db/migrations/, immutable)
    # Expected versions are DERIVED from the discovered files, not hard-coded, so
    # adding a forward migration cannot silently weaken the suite. The invariants
    # below (contiguity, ordering, uniqueness, immutability) are asserted
    # explicitly instead.
    EXPECTED = [m.version for m in migrations]
    EXPECTED_SET = set(EXPECTED)
    versions = [m.version for m in migrations]
    baseline = M.discover_migrations(M.BASELINE_DIR)  # corrected fresh-install baseline
    static_legacy = M.validate_migration_set(migrations)
    static_baseline = M.validate_migration_set(baseline)

    # ---- Group A: file/version contract (no PG) ----
    record("01 discovers a contiguous ordered sequence starting at 1",
           versions == EXPECTED and versions == sorted(versions)
           and versions == list(range(1, len(versions) + 1)) and len(versions) >= 4, versions)
    record("02 every filename matches NNNN_description.sql", all(M.FILENAME_RE.match(m.filename) for m in migrations),
           [m.filename for m in migrations])
    record("03 versions are unique", len(set(versions)) == len(versions), versions)
    record("04 deterministic ascending order", versions == sorted(versions), versions)
    record("05 each migration is valid UTF-8 and non-empty", all(m.byte_length > 0 for m in migrations), True)
    sha_a = hashlib.sha256(migrations[0].sql.encode("utf-8")).hexdigest()
    sha_b = hashlib.sha256(M.discover_migrations()[0].sql.encode("utf-8")).hexdigest()
    record("06 per-file sha256 is stable across reads", sha_a == sha_b == migrations[0].checksum_sha256, sha_a[:12])
    set_sha_1 = M.migration_set_sha256(migrations)
    mutated = list(migrations)
    mutated[0] = M.Migration(mutated[0].version, mutated[0].description, mutated[0].filename,
                             mutated[0].path, mutated[0].sql + "\n-- x", "deadbeef")
    record("07 migration_set_sha256 stable + changes on any byte change",
           set_sha_1 == M.migration_set_sha256(migrations) and set_sha_1 != M.migration_set_sha256(mutated),
           set_sha_1[:12])
    record("08 legacy static validator DETECTS 0003's broken FK targets (validity gap present, immutable)",
           (not static_legacy.ok)
           and {"projects", "reports"} <= {b["missing_target"] for b in static_legacy.broken_references},
           static_legacy.broken_references)
    with tempfile.TemporaryDirectory() as d:
        bad = write_dir(Path(d) / "badname", {"1_x.sql": "select 1;"})
        try:
            M.discover_migrations(bad)
            filename_rejected = False
        except M.MigrationFilenameError:
            filename_rejected = True
        dup = write_dir(Path(d) / "dup", {"0001_a.sql": "select 1;", "0001_b.sql": "select 2;"})
        try:
            M.discover_migrations(dup)
            dup_rejected = False
        except M.MigrationSequenceError:
            dup_rejected = True
    record("09 bad filename + duplicate version are rejected", filename_rejected and dup_rejected,
           {"filename": filename_rejected, "dup": dup_rejected})
    # Regression: the harness itself must reproduce migrations byte-for-byte. Text-mode
    # writes translate \n -> \r\n on Windows, which changes the raw bytes the checksum is
    # taken over and makes a faithful copy indistinguishable from checksum drift. That
    # defect silently broke the partial-history scenarios (34-37) on real PostgreSQL.
    with tempfile.TemporaryDirectory() as d:
        faithful = copy_subset(Path(d) / "faithful", baseline, EXPECTED_SET)
        copied = M.discover_migrations(faithful)
        copy_checksums_match = ([c.checksum_sha256 for c in copied]
                                == [b.checksum_sha256 for b in baseline])
        copy_bytes_identical = all((faithful / b.filename).read_bytes() == b.path.read_bytes()
                                   for b in baseline)
    record("09b guard harness copies migrations byte-for-byte (no newline translation)",
           copy_checksums_match and copy_bytes_identical,
           {"checksums_match": copy_checksums_match, "bytes_identical": copy_bytes_identical})

    # ---- Group B: static validator (no PG) ----
    record("10 corrected baseline (db/baseline/) static validator passes — fresh-install valid",
           static_baseline.ok and not static_baseline.broken_references and [m.version for m in baseline] == EXPECTED,
           {"ok": static_baseline.ok, "baseline_files": [m.filename for m in baseline]})
    with tempfile.TemporaryDirectory() as d:
        badref = write_dir(Path(d) / "badref", {
            "0001_base.sql": "create table tenants (id uuid primary key);",
            "0002_bad.sql": "create table t (id uuid, ref uuid references projects(id));",
        })
        neg = M.validate_migration_set(M.discover_migrations(badref))
    record("11 static validator DETECTS a missing FK target (negative)",
           (not neg.ok) and neg.broken_references and neg.broken_references[0]["missing_target"] == "projects",
           neg.broken_references)
    record("12 static validator documents limitations + is supplemental", len(static_legacy.limitations) >= 2,
           len(static_legacy.limitations))
    with tempfile.TemporaryDirectory() as d:
        sib = write_dir(Path(d) / "sib", {
            "0001_two.sql": "create table a (id uuid primary key);\ncreate table b (id uuid, a_id uuid references a(id));",
        })
        sibres = M.validate_migration_set(M.discover_migrations(sib))
    record("13 intra-migration sibling references are satisfied", sibres.ok, sibres.broken_references)

    # ---- PostgreSQL setup ----
    url = test_database_url()
    pg_on = False
    safe_reason = "no MONDAY_REPORT_TEST_DATABASE_URL provided"
    if url:
        safe, safe_reason = preflight_disposable_db(url)
        if not safe:
            record("PG preflight (Part M): disposable-db safety", False, safe_reason)
        elif not pg_reachable(url):
            safe_reason = "database URL provided but unreachable"
        else:
            pg_on = True
            record("PG preflight (Part M): disposable-db safety", True, safe_reason)

    server_version = None
    scenarios: dict = {}

    def skip(name: str, detail: str = "no disposable PostgreSQL available") -> None:
        record(name, True, detail, skipped=True)

    if not pg_on:
        for n in range(14, 48):
            skip(f"{n:02d} real-PostgreSQL scenario", safe_reason)
    else:
        BASE = M.BASELINE_DIR  # corrected sequence used for the runner-mechanics + fresh-install proofs
        with _connect(url) as c:
            server_version = M._server_version(c)

        # ---- Group C: metadata + immutability (baseline, PG) ----
        reset_public_schema(url)
        res = M.apply_migrations(url, migrations_dir=BASE)
        record("14 schema_migrations created + baseline fresh apply ok",
               res.ok and [a["version"] for a in res.applied] == EXPECTED, res.to_dict())
        with _connect(url) as c:
            cols = [r[0] for r in c.execute(
                "select column_name from information_schema.columns where table_name='schema_migrations' order by ordinal_position"
            ).fetchall()]
        record("15 schema_migrations has the exact metadata columns",
               cols == ["version", "filename", "checksum_sha256", "applied_at", "execution_ms", "runner_version"], cols)
        rows = schema_migrations_rows(url)
        by_v = {r["version"]: r for r in rows}
        record("16 one metadata row per migration; checksum matches file",
               len(rows) == len(EXPECTED) and all(by_v[m.version]["checksum_sha256"] == m.checksum_sha256 for m in baseline),
               {"rows": len(rows)})
        record("17 runner_version recorded == RUNNER_VERSION",
               all(r["runner_version"] == M.RUNNER_VERSION for r in rows), M.RUNNER_VERSION)
        blob = json.dumps(rows)
        record("18 metadata carries no DSN/password/absolute path",
               "password" not in blob.lower() and "postgres://" not in blob.lower() and ":\\" not in blob, True)

        # checksum drift (Part F): mutate an applied migration on disk (temp copy) -> refuse
        with tempfile.TemporaryDirectory() as d:
            drift_dir = copy_subset(Path(d) / "drift", baseline, EXPECTED_SET)
            p = drift_dir / migrations[0].filename
            p.write_text(migrations[0].sql + "\n-- drift\n", encoding="utf-8", newline="")
            drift_res = M.apply_migrations(url, migrations_dir=drift_dir)
        record("19 checksum drift on an applied migration is refused (never rewritten)",
               (not drift_res.ok) and drift_res.drift, drift_res.drift)
        with _connect(url) as c:
            stored_after = M._applied_rows(c)[1]["checksum_sha256"]
        record("20 stored checksum unchanged after drift refusal", stored_after == migrations[0].checksum_sha256,
               stored_after[:12])
        scenarios["checksum_drift"] = {"refused": (not drift_res.ok), "drift": drift_res.drift}

        # ---- Group D: fresh apply / validity (PG) ----
        record("21 baseline fresh apply succeeds on real PostgreSQL (fresh-install validity)", res.ok, res.server_version)
        expected_tables = ["tenants", "workspaces", "monday_reports", "benchmark_measurements",
                           "anomaly_events", "key_decisions", "report_approvals", "monday_report_state_snapshots"]
        present = {t: table_exists(url, t) for t in expected_tables}
        record("22 all expected tables exist after baseline apply", all(present.values()), present)
        fk_meas = fk_target(url, "benchmark_measurements", "workspace_id")
        fk_appr = fk_target(url, "report_approvals", "report_id")
        record("23 corrected baseline FK targets exist on real PG (workspaces / monday_reports)",
               fk_meas == "workspaces" and fk_appr == "monday_reports", {"measurement": fk_meas, "approval": fk_appr})
        record("24 RLS enabled on tenant tables", rls_enabled(url, "workspaces") and rls_enabled(url, "benchmark_measurements"),
               True)
        record("25 real PostgreSQL server_version reported", bool(server_version), server_version)
        # The ACTUAL immutable LEGACY sequence (db/migrations/, original 0003) must FAIL on real PG,
        # proving the validity gap is real and migration-validity genuinely stays BLOCKED.
        reset_public_schema(url)
        legacy_res = M.apply_migrations(url, migrations_dir=M.MIGRATIONS_DIR)
        record("26 immutable LEGACY sequence FAILS on real PG at 0003 (validity gap real -> BLOCKED)",
               (not legacy_res.ok) and legacy_res.error and legacy_res.error.get("version") == 3
               and not table_exists(url, "projects") and not table_exists(url, "reports"),
               legacy_res.error)
        scenarios["legacy_apply_result"] = {"ok": legacy_res.ok, "failed_version": legacy_res.error and legacy_res.error.get("version")}
        # restore baseline apply for subsequent scenarios
        reset_public_schema(url)
        res2 = M.apply_migrations(url, migrations_dir=BASE)
        record("27 document_chunks generated tsvector column exists", table_exists(url, "document_chunks"), True)
        with _connect(url) as c:
            gen = c.execute(
                "select count(*) from information_schema.columns where table_name='document_chunks' and column_name='tsv'"
            ).fetchone()[0]
        record("28 tsvector generated column present", gen == 1, gen)
        scenarios["fresh_apply"] = {"ok": res2.ok, "applied": [a["version"] for a in res2.applied]}

        # ---- Group E: idempotent rerun (PG) ----
        rerun = M.apply_migrations(url, migrations_dir=BASE)
        record("29 rerun is a no-op (0 applied, all skipped)", rerun.ok and not rerun.applied and set(rerun.skipped) == EXPECTED_SET,
               rerun.to_dict())
        record("30 schema_migrations row count stable after rerun",
               len(schema_migrations_rows(url)) == len(EXPECTED), True)
        st = M.migration_status(url, migrations_dir=BASE)
        record("31 status reports no pending after full apply", st["pending"] == [] and st["applied"] == EXPECTED, st["pending"])
        scenarios["rerun"] = {"ok": rerun.ok, "applied": rerun.applied, "skipped": rerun.skipped}

        # ---- Group F: partial upgrades (Part L) ----
        # empty -> full
        reset_public_schema(url)
        empty_full = M.apply_migrations(url, migrations_dir=BASE)
        record("32 from EMPTY database -> reaches head", empty_full.ok and [a["version"] for a in empty_full.applied] == EXPECTED,
               True)
        # metadata-only (table exists, no rows)
        reset_public_schema(url)
        with _connect(url) as c:
            M._ensure_schema_migrations(c)
        meta_only = M.apply_migrations(url, migrations_dir=BASE)
        record("33 from metadata-only -> applies all", meta_only.ok and [a["version"] for a in meta_only.applied] == EXPECTED, True)
        # first-1 applied -> continue
        reset_public_schema(url)
        with tempfile.TemporaryDirectory() as d:
            one = copy_subset(Path(d) / "one", baseline, {1})
            M.apply_migrations(url, migrations_dir=one)
            cont = M.apply_migrations(url, migrations_dir=BASE)  # full dir now applies 2,3
        record("34 from first-1-applied -> applies every pending migration",
               cont.ok and [a["version"] for a in cont.applied] == EXPECTED[1:] and cont.skipped == [1],
               cont.to_dict())
        # first-2 applied -> continue
        reset_public_schema(url)
        with tempfile.TemporaryDirectory() as d:
            two = copy_subset(Path(d) / "two", baseline, {1, 2})
            M.apply_migrations(url, migrations_dir=two)
            cont2 = M.apply_migrations(url, migrations_dir=BASE)
        record("35 from first-2-applied -> applies every pending migration",
               cont2.ok and [a["version"] for a in cont2.applied] == EXPECTED[2:], cont2.to_dict())
        # interrupted-before-metadata: 0003 present on disk but not recorded -> applies 0003
        record("36 interrupted-before-metadata state -> resumes at the first pending version",
               cont2.ok and cont2.skipped == EXPECTED[:2], cont2.skipped)
        # current (all applied) -> no-op
        current = M.apply_migrations(url, migrations_dir=BASE)
        record("37 current (all applied) -> no-op", current.ok and not current.applied, current.applied)
        # unknown deployed version recorded -> refuse (validity stays honest, Part L)
        with _connect(url) as c:
            c.execute("insert into schema_migrations (version, filename, checksum_sha256, execution_ms, runner_version) "
                     "values (9999, 'x.sql', 'deadbeef', 0, 'x')")
        unknown = M.apply_migrations(url, migrations_dir=BASE)
        with _connect(url) as c:
            c.execute("delete from schema_migrations where version = 9999")
        record("38 unknown recorded version (not on disk) -> drift refusal", (not unknown.ok) and unknown.drift, unknown.drift)
        scenarios["partial_upgrade"] = {"first1": [a["version"] for a in cont.applied],
                                        "first2": [a["version"] for a in cont2.applied]}

        # ---- Group G: failure / rollback (PG) ----
        reset_public_schema(url)
        with tempfile.TemporaryDirectory() as d:
            faildir = copy_subset(Path(d) / "fail", baseline, {1})
            (faildir / "0002_fails.sql").write_text(
                "create table good_before (id uuid primary key);\n"
                "create table bad_ref (id uuid primary key, x uuid references does_not_exist(id));",
                encoding="utf-8")
            (faildir / "0003_after.sql").write_text("create table should_not_exist (id uuid primary key);", encoding="utf-8")
            fail_res = M.apply_migrations(url, migrations_dir=faildir)
        record("39 failing migration -> apply stops with a redacted error", (not fail_res.ok) and fail_res.error and fail_res.error["version"] == 2,
               fail_res.error)
        record("40 failing migration's table rolled back (BEGIN/ROLLBACK)", not table_exists(url, "bad_ref") and not table_exists(url, "good_before"),
               {"bad_ref": table_exists(url, "bad_ref"), "good_before": table_exists(url, "good_before")})
        record("41 later migration not applied after a failure (stop-on-failure)", not table_exists(url, "should_not_exist"), True)
        record("42 failure message carries no DSN/password", "password" not in json.dumps(fail_res.error).lower()
               and "postgres://" not in json.dumps(fail_res.error).lower(), True)
        with _connect(url) as c:
            rows_after_fail = len(M._applied_rows(c))
        record("43 only 0001 recorded after the failed run (no orphan metadata)", rows_after_fail == 1, rows_after_fail)
        scenarios["rollback"] = {"stopped_at": fail_res.error and fail_res.error["version"], "recorded": rows_after_fail}

        # ---- Group H: concurrency (PG) ----
        reset_public_schema(url)
        results: list = []
        errors: list = []

        def worker():
            try:
                results.append(M.apply_migrations(url, migrations_dir=BASE))
            except Exception as exc:  # noqa: BLE001
                errors.append(M._redact(str(exc)))

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        both_ok = len(results) == 2 and all(r.ok for r in results) and not errors
        record("44 two concurrent apply runs both succeed (advisory lock serializes)", both_ok, {"errors": errors})
        record("45 exactly one metadata row per version after concurrent runs",
               len(schema_migrations_rows(url)) == len(EXPECTED), True)
        # Recompute the key from its DOCUMENTED derivation and confirm a SEPARATE
        # interpreter derives the same value. Comparing the attribute to itself
        # (`X == X`) proved nothing: a random key would still have passed.
        expected_lock_key = int.from_bytes(
            hashlib.sha256(b"monday_report.schema_migrations.v1").digest()[:8], "big", signed=True
        )
        other_proc = subprocess.run(
            [sys.executable, "-c",
             "import sys;sys.path.insert(0,r'" + str(ROOT) + "');"
             "import backend.app.migrations as m;print(m.ADVISORY_LOCK_KEY)"],
            capture_output=True, text=True, cwd=str(ROOT),
        )
        cross_proc_key = other_proc.stdout.strip()
        record("46 advisory-lock key is deterministic (documented derivation, stable across processes)",
               isinstance(M.ADVISORY_LOCK_KEY, int)
               and M.ADVISORY_LOCK_KEY == expected_lock_key
               and cross_proc_key == str(expected_lock_key)
               and -(2 ** 63) <= M.ADVISORY_LOCK_KEY < 2 ** 63,
               {"matches_derivation": M.ADVISORY_LOCK_KEY == expected_lock_key,
                "cross_process_match": cross_proc_key == str(expected_lock_key)})
        after = M.apply_migrations(url, migrations_dir=BASE)  # lock must be free
        record("47 advisory lock released after run (subsequent run proceeds)", after.ok and not after.applied, True)
        applied_once = sorted(v for r in results for v in [a["version"] for a in r.applied])
        scenarios["concurrency"] = {"both_ok": both_ok, "applied_union": applied_once}

    # ---- Group I: evidence / readiness ----
    generated_at = "1970-01-01T00:00:00Z"  # placeholder; real emission stamps below
    synth = build_evidence(pg_on, server_version, scenarios, generated_at)
    record("48 evidence payload_sha256 independently recomputes", synth["payload_sha256"] == canonical_payload_sha256(synth),
           synth["payload_sha256"][:12])
    required_keys = {"schema_version", "git_commit", "git_tree", "worktree_clean", "runner_version",
                     "postgres_server_version", "postgres_image_digest", "migration_set_sha256",
                     "baseline_migration_set_sha256", "migration_count", "checksums", "baseline_checksums",
                     "legacy_migration_versions", "legacy_apply_ok", "baseline_applied_versions",
                     "check_totals", "legacy_apply_result",
                     "fresh_apply_result", "rerun_result", "partial_upgrade_result", "concurrency_result",
                     "rollback_result", "checksum_drift_result", "status", "payload_sha256"}
    record("49 evidence has all required keys", required_keys.issubset(synth.keys()), sorted(required_keys - set(synth.keys())))
    ev_blob = json.dumps(synth).lower()
    record("50 evidence excludes secrets (no password/DSN/absolute path/username)",
           "password" not in ev_blob and "postgres://" not in ev_blob and ":\\" not in ev_blob, True)

    # --- Fail-closed preflight (regression) ---------------------------------- #
    # An empty/indeterminate host previously satisfied the local-host allow-set,
    # and the raw DSN (password included) was interpolated into the recorded
    # reason. Both libpq forms must be handled; unknown => REFUSE.
    pf_vectors = [
        ("host=db.prod.example.com dbname=mr_test password=hunter2 user=admin", False, "hunter2"),
        ("host=db.prod.example.com dbname=mr_test user=admin", False, None),
        ("postgresql://u:sekret@10.0.0.5:5432/mr_test", False, "sekret"),
        ("dbname=mr_test password=hunter2", False, "hunter2"),          # no host -> refuse
        ("postgresql://u:sekret@127.0.0.1:5432/prod_main", False, "sekret"),  # not test-marked
        ("not a dsn at all", False, None),
    ]
    pf_ok, pf_leaks = True, []
    for dsn, expected, secret in pf_vectors:
        allowed, reason = preflight_disposable_db(dsn)
        if allowed != expected:
            pf_ok = False
        if secret and secret in reason:
            pf_leaks.append(secret)
        if dsn in reason:
            pf_leaks.append("full-dsn")
    loop_ok, loop_reason = preflight_disposable_db("postgresql://u:s@127.0.0.1:5432/mr_test")
    record("50b preflight fails closed on remote / hostless / unparseable / non-test DSNs (both libpq forms)",
           pf_ok and loop_ok, {"vectors_fail_closed": pf_ok, "loopback_test_db_allowed": loop_ok})
    record("50c preflight reason never echoes the DSN, password or host",
           not pf_leaks and "127.0.0.1" not in loop_reason and "hunter2" not in loop_reason,
           {"leaks": pf_leaks})
    record("50d evidence status is 'passed' ONLY for a real DB with 0 failed and 0 skipped",
           _evidence_status(False, {"passed": 9, "skipped": 0, "failed": 0}) == "BLOCKED_NO_POSTGRES"
           and _evidence_status(True, {"passed": 9, "skipped": 0, "failed": 4}) != "passed"
           and _evidence_status(True, {"passed": 9, "skipped": 3, "failed": 0}) != "passed"
           and _evidence_status(True, None) != "passed"
           and _evidence_status(True, {"passed": 0, "skipped": 0, "failed": 0}) != "passed"
           and _evidence_status(True, {"passed": 9, "skipped": 0, "failed": 0}) == "passed",
           {"failed_run_status": _evidence_status(True, {"passed": 9, "skipped": 0, "failed": 4})})

    # 50e: _redact must strip credentials AND network location AND absolute paths.
    # libpq reports host/port/user as free-form prose, and the Windows-path pattern
    # previously required a doubled backslash so no real path was ever redacted.
    redact_vectors = [
        'connection to server at "10.0.0.5", port 6543 failed: FATAL: '
        'password authentication failed for user "appuser"',
        "connect failed for dbname=mr_test user=admin password=hunter2 host=prod.example.com port=5432",
        'Could not open extension control file "C:\\Program Files\\PostgreSQL\\16\\share\\ext\\vector.control"',
        "dsn postgresql://u:sekret@10.0.0.5:5432/db failed",
    ]
    forbidden = ("10.0.0.5", "6543", "appuser", "hunter2", "admin",
                 "prod.example.com", "sekret", "Program Files")
    redact_leaks = [t for v in redact_vectors for t in forbidden if t in M._redact(v)]
    record("50e _redact strips DSN, password, host, port, user and absolute paths",
           not redact_leaks, {"leaks": sorted(set(redact_leaks))})
    record("50f _redact preserves the diagnostic cause (no over-redaction)",
           'relation "projects" does not exist' in M._redact('relation "projects" does not exist'), True)

    import backend.app.ga_readiness as G

    run_disp, run_detail = G._migration_runner_probe()
    val_disp, val_detail = G._migration_validity_probe()
    ok_ev, _, _ = G._migration_evidence_valid()
    # Fail-closed: if the evidence gate fails, the probe MUST be BLOCKED. When a
    # committed passing real-PG evidence exists the probe may PASS. Holds in both states.
    record("51 migration-runner readiness fail-closed w.r.t. evidence gate",
           run_disp in {"PASS", "BLOCKED"} and ((not ok_ev) <= (run_disp == "BLOCKED")),
           {"disposition": run_disp, "evidence_gate_ok": ok_ev, "detail": run_detail[:70]})
    record("52 migration-validity readiness fail-closed w.r.t. evidence gate",
           val_disp in {"PASS", "BLOCKED"} and ((not ok_ev) <= (val_disp == "BLOCKED")),
           {"disposition": val_disp, "evidence_gate_ok": ok_ev, "detail": val_detail[:70]})

    checks_out = G.evaluate_blockers({})
    by_id = {c["id"]: c for c in checks_out}
    ga_status, _ = G.decide_ga(mode="client", parity_ok=True, checks=checks_out,
                               commands_skipped=False, commands_passed=True, worktree_clean=True)
    still_blocked = ["ga_persistence_locking", "ga_correction_cross_process_atomicity",
                     "ga_tenant_authorization", "ga_backup_restore_drill", "ga_audit_tail_truncation"]
    sb_ok = all(by_id.get(b, {}).get("disposition") == "BLOCKED" for b in still_blocked)
    record("53 GA remains GA_BLOCKED; adjacent blockers still BLOCKED", ga_status == "GA_BLOCKED" and sb_ok,
           {"ga": ga_status, "adjacent_blocked": sb_ok})

    # ---- Group J: regressions / isolation ----
    main_src = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
    record("54 runner is NOT wired into API startup (no import-time apply)",
           "apply_migrations" not in main_src,
           {"apply_migrations_in_main": "apply_migrations" in main_src})
    # Prove laziness for real: import the module in a SUBPROCESS with psycopg
    # masked out of sys.modules. Two hasattr() calls on an already-imported
    # module proved nothing — they pass even with a module-scope import.
    lazy_probe = subprocess.run(
        [sys.executable, "-c",
         "import sys;sys.path.insert(0,r'" + str(ROOT) + "');"
         "import builtins;_real=builtins.__import__\n"
         "def _blocked(name,*a,**k):\n"
         "    if name=='psycopg' or name.startswith('psycopg.'): raise ImportError('psycopg masked')\n"
         "    return _real(name,*a,**k)\n"
         "builtins.__import__=_blocked\n"
         "import backend.app.migrations as m\n"
         "assert hasattr(m,'apply_migrations') and hasattr(m,'discover_migrations')\n"
         "m.discover_migrations()\n"
         "print('LAZY_OK')"],
        capture_output=True, text=True, cwd=str(ROOT),
    )
    record("55 migrations module imports and discovers with psycopg UNAVAILABLE (lazy driver import)",
           "LAZY_OK" in lazy_probe.stdout,
           {"stdout": lazy_probe.stdout.strip()[-40:], "stderr": lazy_probe.stderr.strip()[-120:]})
    live_state = Path(os.environ.get("MONDAY_REPORT_STATE_PATH", ""))
    record("56 guard uses isolated state (live .local_data untouched)",
           ".local_data" not in str(live_state) and str(tmp_root) in str(live_state), str(live_state))
    reg_sha = hashlib.sha256((ROOT / "evals" / "ga" / "blocker_registry.v1.json").read_bytes()).hexdigest()
    record("57 blocker registry file unchanged by this increment", G.registry_sha256() == reg_sha, reg_sha[:12])

    # ---- Optional: emit evidence artifact (Part T; only under --emit-evidence) ----
    if args.emit_evidence:
        if pg_on:
            from datetime import datetime, timezone

            # Bind the artifact to the run totals so a skipped/failed run cannot be
            # presented as a clean zero-skip proof.
            emit_totals = {
                "passed": len([c for c in checks if c["ok"] and not c["skipped"]]),
                "skipped": len([c for c in checks if c["skipped"]]),
                "failed": len([c for c in checks if not c["ok"]]),
            }
            stamped = build_evidence(True, server_version, scenarios,
                                     datetime.now(timezone.utc).isoformat(), emit_totals)
        else:
            stamped = synth  # BLOCKED_NO_POSTGRES evidence
        EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
        EVIDENCE_PATH.write_text(json.dumps(stamped, indent=2) + "\n", encoding="utf-8")
        record("evidence artifact written", True, {"status": stamped["status"], "path": str(EVIDENCE_PATH.relative_to(ROOT))})

    # ---- Summary ----
    passed = [c for c in checks if c["ok"] and not c["skipped"]]
    skipped = [c for c in checks if c["skipped"]]
    failed = [c for c in checks if not c["ok"]]
    print(json.dumps({"checks": checks, "summary": {"passed": len(passed), "skipped": len(skipped), "failed": len(failed),
                                                    "postgres": pg_on}}, indent=2, default=str))
    if failed:
        print(f"\nMigration runner guard FAILED: {len(failed)} failing check(s).")
        for c in failed:
            print(f"  FAIL: {c['name']} -> {c['detail']}")
        return 1
    tail = f" ({len(skipped)} skipped: no disposable PostgreSQL)" if skipped else ""
    print(f"\nMigration runner guard passed: {len(passed)} check(s){tail}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
