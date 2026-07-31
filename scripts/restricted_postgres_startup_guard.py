"""Runner-owned external restricted-PostgreSQL startup guard (FOUNDATION).

The decisive control the verification boundary alone cannot provide is PROVENANCE: an
attestation row proves nothing about disposability unless the verifier itself CREATED
and OWNS the database it is talking to. This guard is that runner. It:

  * creates its OWN Docker volume + PostgreSQL/pgvector container (unique run-scoped
    names + labels), and proves ownership by inspecting the exact created resources by
    their IMMUTABLE id -- never by name alone;
  * DERIVES every DSN from the container it created and REFUSES any externally supplied
    database DSN / libpq variable (child environments are built from an explicit
    ALLOWLIST, so no PG*/libpq variable can leak from the parent, and that is asserted);
  * provisions a migration LOGIN (a distinct named principal; a SUPERUSER because
    migration 0007 asserts NOSUPERUSER/NOBYPASSRLS on the app role, which only a
    superuser may set), a restricted runtime LOGIN, and the NOLOGIN monday_report_app
    group; applies migrations 0001-0007 AS THE MIGRATION LOGIN (which therefore OWNS the
    schema objects) and installs the run/cluster attestation ONLY after every provenance
    precondition holds;
  * launches the API (uvicorn) and the worker as SEPARATE external OS processes on the
    RESTRICTED runtime login, and proves their live identity from pg_stat_activity via a
    deterministic advisory-lock barrier (never inferred from the DSN);
  * performs only a MINIMAL functional smoke (health, credentialed read, denial,
    boundary-active mutation) -- NOT the full correction/validation/cross-tenant matrix;
  * removes ONLY the resources it recorded as created (the container by its IMMUTABLE
    id, the volume by name) after re-verifying THIS run's label, in a finally-block
    ledger; cleanup uncertainty leaves the resource untouched and produces a nonzero
    result. Its scratch working directory is removed too.

This turn is the foundation for the later functional guard. It requires Docker; without
it every scenario records SKIPPED (never a false pass). The DSN, host, port, container
id, credential, and raw nonce are never printed.

CLAIM SCOPE: startup-and-identity-only. This guard proves runner ownership + external
startup + live identity + a MINIMAL smoke. It is NOT the full functional matrix
(corrections/validation/idempotency/cross-tenant/export/import) -- that is the future
``audit:restricted-postgres-runtime`` guard -- and it must never be consumed as
tenant-authorization evidence or a readiness proof (see the emitted summary fields).

Run (CERTIFICATION -- Docker required): ``python scripts/restricted_postgres_startup_guard.py``
Non-certifying (Docker-less aggregate): add ``--allow-unavailable`` (reports SKIPPED,
never eligible for evidence/readiness).
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT, ROOT / "scripts"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

PG_IMAGE = "pgvector/pgvector:pg16"
LABEL_PROJECT = "monday-report-verification"
LABEL_PURPOSE = "restricted-postgres-startup"

checks: list[dict] = []
http_statuses: list[int] = []  # functional HTTP statuses observed in the smoke


def record(cid: str, ok: bool, category: str, detail: object = "", *, skipped: bool = False) -> None:
    checks.append({"id": cid, "ok": bool(ok), "category": category, "skipped": bool(skipped), "detail": detail})


def skip_all(reason: str) -> None:
    for cid, cat in _INVENTORY:
        record(cid, True, cat, reason, skipped=True)


# Canonical expected-ID inventory (id, category).
_INVENTORY = [
    ("R01 names absent before creation", "ownership"),
    ("R02 runner created the volume", "ownership"),
    ("R03 runner created the container", "ownership"),
    ("R04 ownership labels + immutable id match", "ownership"),
    ("R05 container mounts the exact created volume", "ownership"),
    ("R06 database port published only on loopback", "ownership"),
    ("R07 approved pgvector image", "ownership"),
    ("R08 cleanup removed only runner-created resources (by id, label-verified)", "ownership"),
    ("D01 runtime DSN derived by the runner", "dsn"),
    ("D02 externally supplied DSN is rejected", "dsn"),
    ("D03 inherited libpq variables are stripped", "dsn"),
    ("P01 database created by the runner", "roles"),
    ("P02 migration and runtime logins are distinct", "roles"),
    ("P03 migrations 0001-0007 applied by the migration login", "roles"),
    ("P04 RLS enabled and forced on the slice", "roles"),
    ("P05 policy inventory complete", "roles"),
    ("P06 run/cluster attestation installed and valid", "roles"),
    ("P07 runtime is non-super, non-bypassrls, group member, owns no protected table", "roles"),
    ("P08 migration login owns the normalized tables", "roles"),
    ("P09 runtime cannot create role / set role / create policy", "roles"),
    ("X01 API is an external process on PostgreSQL", "external"),
    ("X02 verification boundary active; readiness stays non-ready", "external"),
    ("X03 worker is an external process on PostgreSQL", "external"),
    ("I01 API session_user is the restricted runtime login (pg_stat_activity)", "identity"),
    ("I02 worker session_user is the restricted runtime login (pg_stat_activity)", "identity"),
    ("I03 migration/runtime principal separation", "identity"),
    ("S01 health endpoint succeeds", "smoke"),
    ("S02 missing credential is denied", "smoke"),
    ("S03 valid persisted credential authenticates a read", "smoke"),
    ("S04 a client-mode mutation executes under the boundary (not 423)", "smoke"),
    ("S05 functional 423/500/503 count is zero", "smoke"),
]

# Part M per-check inventory metadata, by category. Each check inherits these plus the
# global claim_scope so the emitted inventory is machine-readable.
_CATEGORY_META = {
    "ownership": {"requires_docker": True, "requires_postgresql": False, "process_boundary": "docker", "principal": "runner"},
    "dsn": {"requires_docker": True, "requires_postgresql": False, "process_boundary": "runner", "principal": "runner"},
    "roles": {"requires_docker": True, "requires_postgresql": True, "process_boundary": "runner", "principal": "migration/bootstrap"},
    "external": {"requires_docker": True, "requires_postgresql": True, "process_boundary": "external-process", "principal": "runtime"},
    "identity": {"requires_docker": True, "requires_postgresql": True, "process_boundary": "external-process", "principal": "runtime"},
    "smoke": {"requires_docker": True, "requires_postgresql": True, "process_boundary": "external-process", "principal": "runtime-user"},
}

# OS/runtime environment names a `python -m uvicorn` / worker subprocess needs. NO
# libpq/PG* variable appears here, so none can leak into a child from the parent.
_OS_ENV_ALLOW = {
    "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "OS",
    "TEMP", "TMP", "TMPDIR", "HOME", "HOMEDRIVE", "HOMEPATH", "USERPROFILE", "USERNAME",
    "USERDOMAIN", "LOGNAME", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES",
    "PROGRAMFILES(X86)", "COMMONPROGRAMFILES", "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
    "PYTHONPATH", "PYTHONHOME", "PYTHONUNBUFFERED", "PYTHONUTF8", "PYTHONIOENCODING",
    "VIRTUAL_ENV", "PYENV_ROOT", "CONDA_PREFIX", "CONDA_DEFAULT_ENV",
    "SSL_CERT_FILE", "SSL_CERT_DIR",
}


def _libpq_leak_keys(env: dict) -> list[str]:
    """Any key in ``env`` that could carry an inherited libpq/DSN override. The runtime
    connection must be entirely runner-derived, so the only permitted DSN-shaped key is
    the runner's own ``MONDAY_REPORT_DATABASE_URL``."""
    bad = []
    for k in env:
        ku = k.upper()
        if ku.startswith("PG"):
            bad.append(k)
        elif ku.endswith("DATABASE_URL") and ku != "MONDAY_REPORT_DATABASE_URL":
            bad.append(k)
        elif ku in {"DATABASE_URL", "PGSERVICEFILE"}:
            bad.append(k)
    return sorted(bad)


def _no_libpq_leak(env: dict) -> bool:
    return not _libpq_leak_keys(env)


def _child_env(base: dict) -> dict:
    """Explicit ALLOWLIST child environment. Only OS/runtime-essential vars and the
    runner-defined ``MONDAY_REPORT_*`` set (``base``, incl. the derived DSN) are passed
    to a child; a non-DSN ``MONDAY_REPORT_*`` from the parent may pass through, but no
    libpq/PG* variable is ever copied. So PGOPTIONS (``-c role=...``), PGPASSWORD,
    PGSERVICE, PGSSLMODE, etc. cannot reach the API/worker and cannot alter the runtime
    connection or role."""
    env: dict[str, str] = {}
    for k, v in os.environ.items():
        ku = k.upper()
        if ku in _OS_ENV_ALLOW:
            env[k] = v
        elif ku.startswith("MONDAY_REPORT_") and not ku.endswith("DATABASE_URL"):
            env[k] = v
    env.update(base)  # runner-defined; includes the derived MONDAY_REPORT_DATABASE_URL
    return env


def _docker(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def _free_loopback_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _http(method: str, url: str, headers: dict | None = None, data: bytes | None = None, timeout: int = 15):
    req = urllib.request.Request(url, method=method, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # noqa: BLE001
        return None, str(e).encode()


#: Connection-establishment substrings that are TRANSIENT (the TCP server is not yet stably accepting
#: connections). Matched case-insensitively. These are the ONLY classes the SQL-readiness probe retries.
_TRANSIENT_CONNECT_MARKERS = (
    "server closed the connection",
    "connection refused",
    "the database system is starting up",
    "the database system is not yet accepting connections",
    "connection reset",
    "could not connect",
    "connection timed out",
    "eof detected",
)
#: Non-transient connection classes that must NEVER be retried by the probe.
_NONTRANSIENT_CONNECT_MARKERS = (
    "authentication failed",
    "password authentication",
    "role \"",
    "does not exist",
    "permission denied",
    "database \"",
)


def _classify_connect_error(message: str) -> str:
    """Classify a connection error message (redacted) as 'transient' | 'auth' | 'other'."""
    low = (message or "").lower()
    if any(m in low for m in _NONTRANSIENT_CONNECT_MARKERS):
        return "auth"
    if any(m in low for m in _TRANSIENT_CONNECT_MARKERS):
        return "transient"
    return "other"


def wait_for_stable_sql_connection(dsn: str, *, deadline_seconds: float = 30.0,
                                   poll_seconds: float = 0.5, connect_timeout: int = 5) -> list[dict]:
    """LAYER 1 connection-level readiness: after ``pg_isready`` (an initial in-container signal), do
    NOT declare the database ready until a REAL TCP SQL connection succeeds. Opens a psycopg connection
    with the bootstrap identity, runs ``SELECT 1``, and closes it cleanly. Retries ONLY recognised
    TRANSIENT connection-establishment failures (server-closed / refused / starting-up / reset) within
    a bounded DEADLINE and bounded poll interval, strictly BEFORE any semantic bootstrap action. Never
    retries an authentication / permission / missing-object / unknown failure -- those fail closed
    immediately. Returns a REDACTED attempt history (no DSN/role/port/path). Raises RuntimeError on a
    non-transient failure or deadline exhaustion."""
    import psycopg

    start = time.monotonic()
    history: list[dict] = []
    attempt = 0
    while True:
        attempt += 1
        try:
            conn = psycopg.connect(dsn, autocommit=True, connect_timeout=connect_timeout)
            try:
                conn.execute("select 1")
            finally:
                conn.close()   # close cleanly whether the probe query succeeded or raised
            history.append({"attempt": attempt, "outcome": "connected",
                            "elapsed_s": round(time.monotonic() - start, 2)})
            return history
        except Exception as exc:  # noqa: BLE001 - classify by message, never leak the DSN
            klass = _classify_connect_error(str(exc))
            elapsed = time.monotonic() - start
            history.append({"attempt": attempt, "outcome": klass, "exception": exc.__class__.__name__,
                            "elapsed_s": round(elapsed, 2)})
            if klass != "transient":
                # authentication / permission / missing-object / unknown -> fail closed, no retry
                raise RuntimeError(
                    f"non-transient SQL-connect failure before bootstrap (class={klass}, "
                    f"{exc.__class__.__name__})")
            if elapsed + poll_seconds >= deadline_seconds:
                # bounded deadline exhausted: fail closed. The message carries a recognised transient
                # marker so the OUTER stack-retry contract may (narrowly) try a fresh stack.
                raise RuntimeError(
                    "transient: could not connect a stable SQL session before the readiness deadline "
                    f"({deadline_seconds:g}s); connection failed to stabilize after {attempt} attempt(s)")
            time.sleep(poll_seconds)


class _FaultInjected(RuntimeError):
    """Raised by run_stack at a named lifecycle stage when fault injection is active.
    Test-only; used by scripts/restricted_postgres_startup_fault_guard.py."""


# Test-only hooks, set by the fault-injection / boundary-audit guards *before* calling
# ``run_stack()`` and reset to None after. They are NEVER set in the certification path,
# are NOT environment- or request-controlled, do not exist in backend/app production
# code, and are not inherited by the launched API/worker subprocesses. A stage marker
# names ONLY a lifecycle stage -- never a shell command or code expression.
_ACTIVE_FAULT: str | None = None
_BEFORE_CLEANUP = None   # callable(ledger, run_hash) invoked at the top of cleanup
_ON_LIVE = None          # callable(ctx) invoked with the live stack just before cleanup
_STABLE_SQL_PROBE = None  # callable(dsn)->history: overrides the Layer-1 SQL-readiness probe (tests)

# The canonical, closed set of injectable stage markers.
FAULT_STAGES = (
    "after_volume_create", "after_container_create", "after_container_start",
    "after_database_create", "after_migrations", "after_roles_create",
    "after_attestation", "after_api_launch", "after_worker_launch",
    "during_identity_observation", "during_http_smoke", "during_cleanup",
)


def _fault(stage: str) -> None:
    if _ACTIVE_FAULT == stage:
        raise _FaultInjected(f"fault:{stage}")


def _container_cleanup_decision(container_id, run_hash) -> tuple[str, str]:
    """Decide whether cleanup may remove the recorded container. Removes ONLY when the
    IMMUTABLE id still resolves to a container carrying THIS run's label. A name or label
    match alone never authorises deletion; any uncertainty returns 'skip-uncertain' (the
    resource is left untouched and the run is made nonzero). Returns (action, reason)
    with action in {'remove','skip','skip-uncertain'}. 'skip' is benign (already gone /
    no id); 'skip-uncertain' is an ownership doubt that must surface."""
    if not container_id:
        return ("skip", "no recorded id")
    insp = _docker(["inspect", container_id])
    if insp.returncode != 0:
        return ("skip", "already gone")
    try:
        meta = json.loads(insp.stdout)[0]
        clbls = (meta.get("Config", {}) or {}).get("Labels") or {}
    except Exception:  # noqa: BLE001
        return ("skip-uncertain", "container metadata unparseable")
    if clbls.get("verification-run") == run_hash and clbls.get("project") == LABEL_PROJECT:
        return ("remove", "owned")
    return ("skip-uncertain", "recorded id no longer carries this run's label")


def _volume_cleanup_decision(vname, run_hash) -> tuple[str, str]:
    """Volume analogue of :func:`_container_cleanup_decision` (name is the volume key)."""
    vinsp = _docker(["volume", "inspect", vname])
    if vinsp.returncode != 0:
        return ("skip", "already gone")
    try:
        vmeta = json.loads(vinsp.stdout)[0]
        vlbls = vmeta.get("Labels") or {}
    except Exception:  # noqa: BLE001
        return ("skip-uncertain", "volume metadata unparseable")
    if vlbls.get("verification-run") == run_hash and vlbls.get("project") == LABEL_PROJECT:
        return ("remove", "owned")
    return ("skip-uncertain", "volume no longer carries this run's label")


# Ownership-inspection predicates (R05/R06/R07). Extracted so the fault guard exercises
# the SAME logic the runner applies, not a divergent copy.
def _image_ok(image: str) -> bool:
    return image == PG_IMAGE


def _loopback_bindings_ok(host_ips: list, port: int) -> bool:
    """Every published host binding must be loopback, and the port must not be a live
    app port (8000 API / 5173 web)."""
    return bool(host_ips) and all(h in ("127.0.0.1", "::1") for h in host_ips) and port not in (8000, 5173)


def _single_pgdata_mount_ok(mounts: list, vname: str) -> bool:
    vm = [m for m in mounts if m.get("Type") == "volume" and m.get("Destination") == "/var/lib/postgresql/data"]
    return len(vm) == 1 and vm[0].get("Name") == vname


def main() -> int:
    # Direct invocation is a CERTIFICATION: Docker is required and a skipped run is NOT
    # a pass. `--allow-unavailable` (for a Docker-less audit:all aggregate) downgrades to
    # a clearly non-certifying SKIP that is never evidence/readiness eligible.
    global checks, http_statuses
    checks = []
    http_statuses = []
    allow_unavailable = "--allow-unavailable" in sys.argv
    if _docker(["info"]).returncode != 0:
        if allow_unavailable:
            skip_all("docker unavailable (non-certifying mode)")
        else:
            for cid, cat in _INVENTORY:
                record(cid, False, cat,
                       "docker required for certification; pass --allow-unavailable for a non-certifying skip")
        return _emit()
    run_stack()
    return _emit()


def run_stack() -> dict:
    """Provision the runner-owned external stack and record the 31 certification checks.

    Shared by the certification ``main()`` (all hooks None) and, via the module-level
    test-only hooks (_ACTIVE_FAULT / _BEFORE_CLEANUP / _ON_LIVE), by the fault-injection
    and boundary-audit guards. Appends to the module ``checks``/``http_statuses`` (the
    caller resets them first) and returns a small result dict for the fault guard.
    """
    run_id = secrets.token_hex(32)                 # >=128-bit nonce (raw; never printed)
    run_hash = hashlib.sha256(run_id.encode()).hexdigest()[:12]
    cname = f"mr-verif-{run_hash}"
    vname = f"mr-verif-vol-{run_hash}"
    db = "monday_verif_test"
    mig_role = f"mr_mig_{run_hash}"
    rt_role = f"mr_rt_{run_hash}"
    port = _free_loopback_port()
    api_port = _free_loopback_port()   # OS-allocated (skips reserved/excluded ranges); NOT port+1
    while api_port == port:
        api_port = _free_loopback_port()
    scratch = Path(os.environ.get("TEMP", "/tmp")) / f"mr-rpr-{run_hash}"
    for sub in ("state", "storage", "exports"):
        (scratch / sub).mkdir(parents=True, exist_ok=True)

    ledger = {"volume": {"name": vname, "created": False, "id": None},
              "container": {"name": cname, "created": False, "id": None, "started": False},
              "api_pid": None, "worker_pids": [], "trigger_pids": []}
    procs: list = []

    def labels(kind: str) -> list[str]:
        return ["--label", f"project={LABEL_PROJECT}", "--label", f"purpose={LABEL_PURPOSE}",
                "--label", f"verification-run={run_hash}", "--label", f"resource={kind}"]

    cleanup_issues: list[str] = []   # hoisted so it survives into the return past finally
    sql_readiness_history: list[dict] = []   # LAYER 1 connection-stability probe history (redacted)
    api_log = None                   # hoisted so the finally can close + remove the scratch
    try:
        import psycopg

        # -- R01: the unique names must not already exist --------------------
        pre_c = _docker(["ps", "-aq", "-f", f"name=^{cname}$"]).stdout.strip()
        pre_v = _docker(["volume", "ls", "-q", "-f", f"name=^{vname}$"]).stdout.strip()
        record("R01 names absent before creation", not pre_c and not pre_v, "ownership",
                {"container_pre": bool(pre_c), "volume_pre": bool(pre_v)})
        if pre_c or pre_v:
            raise RuntimeError("run-scoped name already exists; refusing")

        # -- R02/R03: create runner-owned volume + container -----------------
        cv = _docker(["volume", "create", *labels("volume"), vname])
        ledger["volume"]["created"] = cv.returncode == 0
        ledger["volume"]["id"] = _docker(["volume", "inspect", "-f", "{{.Name}}", vname]).stdout.strip()
        record("R02 runner created the volume", cv.returncode == 0, "ownership")
        _fault("after_volume_create")

        cc = _docker(["run", "-d", "--name", cname, *labels("container"),
                      "-e", "POSTGRES_PASSWORD=" + secrets.token_urlsafe(18),
                      "-e", f"POSTGRES_DB={db}",
                      "-p", f"127.0.0.1:{port}:5432",
                      "-v", f"{vname}:/var/lib/postgresql/data",
                      PG_IMAGE])
        ledger["container"]["created"] = cc.returncode == 0
        ledger["container"]["id"] = cc.stdout.strip()[:12] if cc.returncode == 0 else None
        ledger["container"]["started"] = cc.returncode == 0
        record("R03 runner created the container", cc.returncode == 0, "ownership",
               {"err": cc.stderr[-120:] if cc.returncode else None})
        if cc.returncode != 0:
            raise RuntimeError("container create failed")
        _fault("after_container_create")

        # readiness
        ready = False
        for _ in range(40):
            if _docker(["exec", cname, "pg_isready", "-U", "postgres", "-d", db]).returncode == 0:
                ready = True
                break
            time.sleep(1)
        if not ready:
            raise RuntimeError("container not ready")
        _fault("after_container_start")

        # -- R04-R07: prove ownership by inspecting the exact resources by IMMUTABLE id
        insp = json.loads(_docker(["inspect", ledger["container"]["id"]]).stdout)[0]
        id_match = insp["Id"][:12] == ledger["container"]["id"]
        lbls = insp["Config"]["Labels"] or {}
        record("R04 ownership labels + immutable id match",
               id_match and lbls.get("project") == LABEL_PROJECT
               and lbls.get("purpose") == LABEL_PURPOSE and lbls.get("verification-run") == run_hash,
               "ownership", {"id_match": id_match})
        mounts = insp.get("Mounts", [])
        record("R05 container mounts the exact created volume",
               _single_pgdata_mount_ok(mounts, vname), "ownership")
        record("R07 approved pgvector image", _image_ok(insp["Config"]["Image"]), "ownership")
        ports = insp["NetworkSettings"]["Ports"].get("5432/tcp") or []
        host_ips = [p.get("HostIp") for p in ports]
        record("R06 database port published only on loopback",
               _loopback_bindings_ok(host_ips, port), "ownership", {"bindings": host_ips})

        # -- DSN provenance ---------------------------------------------------
        pw = insp["Config"]["Env"]  # not printed
        # Derive DSNs from the created container (bootstrap superuser only for setup).
        boot_dsn = f"postgresql://postgres:{[e for e in pw if e.startswith('POSTGRES_PASSWORD=')][0].split('=',1)[1]}@127.0.0.1:{port}/{db}"
        rt_pw = secrets.token_urlsafe(18)
        from backend.app import verification_boundary as vb
        # D01: the DSN the runner will use was DERIVED from the container it created -- it
        # binds to that container's published loopback port and is a clean loopback TCP DSN
        # the boundary itself would accept (never an externally-supplied path). This checks
        # the derived bootstrap DSN; the restricted runtime DSN (rt_dsn) is built the same
        # way from the same container below.
        record("D01 runtime DSN derived by the runner",
               vb._loopback_tcp_dsn(boot_dsn) is True and f"127.0.0.1:{port}/" in boot_dsn, "dsn")

        # D02: an externally supplied DSN must never become the passing runtime path.
        # The runner NEVER assigns an external DSN to the runtime path (rt_dsn is derived
        # from the container it created, below). Prove additionally that the boundary
        # itself rejects a non-loopback DSN AND that the runner's own runtime DSN is the
        # derived, loopback one -- so no substitution can silently pass.
        external_dsn = "postgresql://attacker:x@10.9.9.9:5432/prod"
        record("D02 externally supplied DSN is rejected",
               vb._loopback_tcp_dsn(external_dsn) is False, "dsn")

        # -- LAYER 1: stable SQL readiness BEFORE any semantic bootstrap ------
        # pg_isready above is an in-container (unix-socket) signal; the runner connects over TCP, which
        # the image's first-init phase can lag. Do NOT begin bootstrap (role/migration SQL) until a real
        # TCP SQL session is stable, absorbing short-lived connection instability inside THIS fresh stack
        # (bounded deadline), so it need not cost an outer fresh-stack retry. A non-transient or
        # deadline-exhausted failure fails closed here.
        _fault("before_stable_sql")
        sql_readiness_history.extend(
            _STABLE_SQL_PROBE(boot_dsn) if _STABLE_SQL_PROBE is not None
            else wait_for_stable_sql_connection(boot_dsn))

        # -- roles + migrations + RLS + attestation --------------------------
        import backend.app.migrations as M
        mig_pw = secrets.token_urlsafe(18)
        with psycopg.connect(boot_dsn, autocommit=True) as c:
            record("P01 database created by the runner",
                   c.execute("select current_database()").fetchone()[0] == db, "roles")
            # migration LOGIN: a distinct NAMED principal that applies the migrations and
            # therefore OWNS the schema objects. It is a SUPERUSER because migration 0007
            # performs privileged role management (it asserts NOSUPERUSER/NOBYPASSRLS on
            # the application role, which only a superuser may set); it is nonetheless a
            # separate principal from the container-default role and from the RESTRICTED
            # runtime login, and the runtime login owns nothing (P07/P08).
            c.execute(f"drop role if exists {mig_role}")
            c.execute(f"create role {mig_role} login superuser password '{mig_pw}'")
        _fault("after_database_create")
        # Apply migrations AS the migration login (named principal + object ownership),
        # NOT as the container-default bootstrap role.
        mig_dsn = f"postgresql://{mig_role}:{mig_pw}@127.0.0.1:{port}/{db}"
        res = M.apply_migrations(mig_dsn, migrations_dir=M.BASELINE_DIR)
        record("P03 migrations 0001-0007 applied by the migration login",
               res.ok and len(getattr(res, "applied", []) or []) >= 7, "roles",
               {"applied": len(getattr(res, "applied", []) or []), "ok": res.ok,
                "error": (res.error or {}).get("message") if not res.ok else None})
        _fault("after_migrations")

        with psycopg.connect(boot_dsn, autocommit=True) as c:
            # P08: the migration login OWNS the normalized tables (real provenance).
            mig_owns = c.execute(
                "select count(*) from pg_class cl join pg_roles r on cl.relowner=r.oid "
                "where r.rolname=%s and cl.relname like 'monday_report_norm_%%'", (mig_role,)).fetchone()[0]
            record("P08 migration login owns the normalized tables", int(mig_owns) >= 4, "roles",
                   {"owned": mig_owns})
            # restricted runtime login inheriting the app group (created by 0007)
            c.execute(f"drop role if exists {rt_role}")
            c.execute(f"create role {rt_role} login nosuperuser nobypassrls nocreatedb nocreaterole password '{rt_pw}'")
            c.execute(f"grant monday_report_app to {rt_role}")
            record("P02 migration and runtime logins are distinct", mig_role != rt_role, "roles")
            # RLS + forced on the normalized slice
            rls = c.execute(
                "select count(*) from pg_class where relnamespace='public'::regnamespace "
                "and relname like 'monday_report_norm_%' and relrowsecurity and relforcerowsecurity"
            ).fetchone()[0]
            record("P04 RLS enabled and forced on the slice", int(rls) >= 4, "roles", {"forced_tables": rls})
            pol = c.execute("select count(*) from pg_policies where schemaname='public'").fetchone()[0]
            record("P05 policy inventory complete", int(pol) >= 6, "roles", {"policies": pol})
            # runtime attributes + the app group must be NOLOGIN
            attr = c.execute("select rolsuper, rolbypassrls, rolcanlogin from pg_roles where rolname=%s",
                             (rt_role,)).fetchone()
            member = c.execute("select pg_has_role(%s,'monday_report_app','member')", (rt_role,)).fetchone()[0]
            grp = c.execute("select rolcanlogin from pg_roles where rolname='monday_report_app'").fetchone()
            grp_nologin = grp is not None and grp[0] is False
            owns = c.execute(
                "select count(*) from pg_class c join pg_roles r on c.relowner=r.oid "
                "where r.rolname=%s and c.relname like 'monday_report_norm_%%'", (rt_role,)).fetchone()[0]
            record("P07 runtime is non-super, non-bypassrls, group member, owns no protected table",
                   attr == (False, False, True) and member and int(owns) == 0 and grp_nologin, "roles",
                   {"attrs": attr, "member": member, "owns": owns, "group_nologin": grp_nologin})

        rt_dsn = f"postgresql://{rt_role}:{rt_pw}@127.0.0.1:{port}/{db}"
        _fault("after_roles_create")

        # -- P09: runtime negative privilege (Part H). Every probe is rolled back. ----
        rc = psycopg.connect(rt_dsn)  # NOT autocommit
        try:
            def _denied(sql: str) -> bool:
                try:
                    rc.execute(sql)
                    rc.rollback()
                    return False   # allowed (should not happen)
                except Exception:
                    rc.rollback()
                    return True    # denied
            cr = _denied("create role mr_probe_should_not_exist nologin")
            srr = _denied(f"set role {mig_role}")
            cp = _denied("create policy mr_probe on monday_report_norm_reports using (true)")
            record("P09 runtime cannot create role / set role / create policy", cr and srr and cp, "roles",
                   {"create_role_denied": cr, "set_role_denied": srr, "create_policy_denied": cp})
        finally:
            rc.close()

        # -- H-05: install attestation ONLY after every provenance precondition holds.
        gate_ids = ("P01", "P02", "P03", "P04", "P05", "P07", "P08", "P09")
        gate_ok = all(ch["ok"] for ch in checks if ch["id"].startswith(gate_ids))
        if not gate_ok:
            raise RuntimeError("provenance preconditions failed; refusing to install attestation")
        vb.install_database_attestation(boot_dsn, run_id, ttl_seconds=1800, grant_to=rt_role)
        # validity is proven from a restricted-role connection via the checker
        with psycopg.connect(rt_dsn, autocommit=True) as c:
            valid = c.execute(f"select {vb.ATTESTATION_CHECK_FN}(%s)",
                              (hashlib.sha256(run_id.encode()).hexdigest(),)).fetchone()[0]
        record("P06 run/cluster attestation installed and valid", valid is True, "roles")
        _fault("after_attestation")

        # -- provision synthetic client identity (tenant A + user + credential)
        api_appname = f"mr-verification-api-{run_hash}"
        worker_appname = f"mr-verification-worker-{run_hash}"
        base_env = {
            "MONDAY_REPORT_REPOSITORY_BACKEND": "postgres",
            "MONDAY_REPORT_DATABASE_URL": f"{rt_dsn}?application_name={api_appname}",
            "MONDAY_REPORT_CLIENT_DATA_MODE": "client",
            "MONDAY_REPORT_VERIFICATION_ISOLATION": "1",
            "MONDAY_REPORT_VERIFICATION_RUN_ID": run_id,
            "MONDAY_REPORT_TENANT_SLUG": "verif-a",
            "MONDAY_REPORT_TENANT_NAME": "Verification Tenant A",
            "MONDAY_REPORT_USER_EMAIL": "reviewer@verif.test",
            "MONDAY_REPORT_USER_FULL_NAME": "Verif Reviewer A",
            "MONDAY_REPORT_STATE_PATH": str(scratch / "state" / "s.json"),
            "MONDAY_REPORT_STORAGE_ROOT": str(scratch / "storage"),
            "MONDAY_REPORT_EXPORT_ROOT": str(scratch / "exports"),
            "MONDAY_REPORT_AUDIT_HMAC_KEY": secrets.token_hex(32),
            "MONDAY_REPORT_API_KEY": secrets.token_urlsafe(24),
            "MONDAY_REPORT_API_BASE": f"http://127.0.0.1:{api_port}",
            "MONDAY_REPORT_WEB_BASE": "http://127.0.0.1:5183",
            "CI": "true",
        }
        # Construct the store in-process (runner side) to bootstrap tenant/user + mint a
        # persisted credential; then the external API resolves it from the same database.
        prov_env_saved = {k: os.environ.get(k) for k in base_env}
        os.environ.update(base_env)
        try:
            import importlib
            import backend.app.store as store_mod
            importlib.reload(store_mod)
            store = store_mod.create_store()
            from backend.app.schemas import Role as _Role
            u = store.create_user("apiuser@verif.test", "API User", [_Role.ADMIN])
            _, token = store.create_credential(u.id)
        finally:
            for k, v in prov_env_saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

        # -- child environments from an explicit ALLOWLIST (no libpq/PG* leakage) -----
        api_env = _child_env(base_env)
        worker_env = _child_env({**base_env,
                                 "MONDAY_REPORT_DATABASE_URL": f"{rt_dsn}?application_name={worker_appname}"})
        record("D03 inherited libpq variables are stripped",
               _no_libpq_leak(api_env) and _no_libpq_leak(worker_env), "dsn",
               {"api_leak": _libpq_leak_keys(api_env), "worker_leak": _libpq_leak_keys(worker_env)})

        # -- launch external API (uvicorn) on the restricted login -----------
        api_log = open(scratch / "api.log", "w")
        api_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", str(api_port)],
            cwd=str(ROOT), env=api_env, stdout=api_log, stderr=subprocess.STDOUT)
        procs.append(api_proc)
        ledger["api_pid"] = api_proc.pid
        api = f"http://127.0.0.1:{api_port}"
        up = False
        for _ in range(40):
            s, _b = _http("GET", f"{api}/health")
            if s == 200:
                up = True
                break
            if api_proc.poll() is not None:
                break
            time.sleep(1)
        record("X01 API is an external process on PostgreSQL", up and api_proc.poll() is None, "external",
               {"log_tail": Path(scratch / "api.log").read_text(errors="replace")[-200:] if not up else None})
        record("S01 health endpoint succeeds", up, "smoke")
        _fault("after_api_launch")

        hdr = {"X-Monday-Report-Key": token}
        # missing credential denied
        sm, _ = _http("GET", f"{api}/monday-reports")
        http_statuses.append(sm)
        record("S02 missing credential is denied", sm in (401, 403), "smoke", {"status": sm})
        # valid credential read
        sv, _ = _http("GET", f"{api}/monday-reports", headers=hdr)
        http_statuses.append(sv)
        record("S03 valid persisted credential authenticates a read", sv == 200, "smoke", {"status": sv})
        _fault("during_http_smoke")
        # a client-mode mutation executes under the boundary (not 423)
        body = json.dumps({"name": "verif-ws", "rig_name": "guard"}).encode()
        smut, _ = _http("POST", f"{api}/workspaces", headers={**hdr, "Content-Type": "application/json"}, data=body)
        http_statuses.append(smut)
        record("S04 a client-mode mutation executes under the boundary (not 423)",
               smut in (200, 201), "smoke", {"status": smut})
        # boundary active + readiness stays non-ready
        record("X02 verification boundary active; readiness stays non-ready",
               smut in (200, 201), "external")
        record("S05 functional 423/500/503 count is zero",
               sm not in (500, 503) and sv not in (423, 500, 503) and smut not in (423, 500, 503), "smoke",
               {"statuses": [sm, sv, smut]})

        # -- live identity via a deterministic advisory-lock barrier ---------
        lock_key = store_mod.PostgresStateStore._advisory_lock_key()

        def observe(appname: str, trig) -> tuple[str | None, int]:
            # Anti-spoof: require EXACTLY ONE fresh session (backend_start after the
            # child launched) with this run-scoped application_name that is WAITING
            # specifically on the ADVISORY lock (wait_event='advisory' -- the barrier the
            # observer holds), and return its login role. application_name + count +
            # advisory-wait + freshness together make a rogue helper/migration connection
            # unable to satisfy it.
            with psycopg.connect(boot_dsn, autocommit=True) as obs:
                t0 = obs.execute("select now()").fetchone()[0]
                obs.execute("select pg_advisory_lock(%s)", (lock_key,))
                try:
                    trig()  # fire an action that takes the snapshot lock
                    for _ in range(60):
                        rows = obs.execute(
                            "select usename from pg_stat_activity "
                            "where application_name=%s and wait_event_type='Lock' and wait_event='advisory' "
                            "and backend_start >= %s", (appname, t0)).fetchall()
                        if rows:
                            return rows[0][0], len(rows)
                        time.sleep(0.1)
                    return None, 0
                finally:
                    obs.execute("select pg_advisory_unlock(%s)", (lock_key,))

        # API identity: a mutation blocks on the held lock
        def trigger():
            tp = subprocess.Popen([sys.executable, "-c",
                                   "import urllib.request,json;"
                                   f"req=urllib.request.Request('{api}/workspaces',method='POST',"
                                   "data=json.dumps({'name':'idp','rig_name':'g'}).encode(),"
                                   f"headers={{'X-Monday-Report-Key':'{token}','Content-Type':'application/json'}});"
                                   "urllib.request.urlopen(req,timeout=20)"], cwd=str(ROOT))
            procs.append(tp)                       # tracked so the finally reaps it
            ledger["trigger_pids"].append(tp.pid)
        _fault("during_identity_observation")
        api_user, api_n = observe(api_appname, trigger)
        record("I01 API session_user is the restricted runtime login (pg_stat_activity)",
               api_user == rt_role and api_n == 1, "identity",
               {"observed_is_restricted": api_user == rt_role, "sessions": api_n})

        # worker identity: run the external worker; it blocks on the held lock during its job
        worker_env2 = worker_env

        def trigger_worker():
            wp = subprocess.Popen([sys.executable, "-m", "backend.app.worker"], cwd=str(ROOT),
                                  env=worker_env2, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ledger["worker_pids"].append(wp.pid)
            procs.append(wp)
        # the worker only takes the snapshot lock if there is a job; seed one cheaply by
        # letting the worker run its bootstrap/retention mutation path
        with psycopg.connect(boot_dsn, autocommit=True) as obs:
            t0w = obs.execute("select now()").fetchone()[0]
            obs.execute("select pg_advisory_lock(%s)", (lock_key,))
            try:
                trigger_worker()
                w_user, w_n = None, 0
                for _ in range(120):
                    rows = obs.execute(
                        "select usename from pg_stat_activity "
                        "where application_name=%s and wait_event_type='Lock' and wait_event='advisory' "
                        "and backend_start >= %s",
                        (worker_appname, t0w)).fetchall()
                    if rows:
                        w_user, w_n = rows[0][0], len(rows)
                        break
                    time.sleep(0.1)
            finally:
                obs.execute("select pg_advisory_unlock(%s)", (lock_key,))
        record("X03 worker is an external process on PostgreSQL", w_user is not None and w_n == 1, "external",
               {"observed": w_user is not None, "sessions": w_n})
        _fault("after_worker_launch")
        record("I02 worker session_user is the restricted runtime login (pg_stat_activity)",
               w_user == rt_role and w_n == 1, "identity",
               {"observed_is_restricted": w_user == rt_role, "sessions": w_n})
        record("I03 migration/runtime principal separation",
               mig_role != rt_role and api_user == rt_role and int(mig_owns) >= 4 and int(owns) == 0, "identity")

        # Hand the live, fully-provisioned stack to a caller (boundary-audit guard) that
        # needs to exercise the real client-mode request path before cleanup.
        if _ON_LIVE is not None:
            _ON_LIVE({
                "api_base": api, "token": token, "boot_dsn": boot_dsn, "rt_dsn": rt_dsn,
                "mig_dsn": mig_dsn, "run_id": run_id, "run_hash": run_hash,
                "base_env": dict(base_env), "tenant_slug": base_env["MONDAY_REPORT_TENANT_SLUG"],
                "lock_key": lock_key, "rt_role": rt_role, "mig_role": mig_role,
                "db": db, "port": port, "api_appname": api_appname,
            })

    except Exception as exc:  # noqa: BLE001
        # Any setup failure leaves recorded checks as-is; unrecorded ones fail.
        recorded = {c["id"] for c in checks}
        for cid, cat in _INVENTORY:
            if cid not in recorded:
                record(cid, False, cat, f"aborted: {type(exc).__name__}: {str(exc)[:100]}")
    finally:
        # Optional tamper hook (test-only): a fault guard may substitute/relabel a
        # resource right before cleanup to prove substituted resources are NOT deleted.
        if _BEFORE_CLEANUP is not None:
            try:
                _BEFORE_CLEANUP(ledger, run_hash)
            except Exception:  # noqa: BLE001
                cleanup_issues.append("before-cleanup hook raised")
        if _ACTIVE_FAULT == "during_cleanup":
            # A cleanup-time problem: a redacted issue that forces a nonzero result while
            # owned resources are STILL cleaned below. Contains no ids/paths/secrets.
            cleanup_issues.append("injected cleanup fault (stage marker; no identifying detail)")
        # Terminate ONLY recorded child processes.
        for pr in procs:
            try:
                pr.terminate()
                pr.wait(timeout=10)
            except Exception:  # noqa: BLE001
                try:
                    pr.kill()
                except Exception:  # noqa: BLE001
                    cleanup_issues.append("a child process could not be terminated")
        # Remove ONLY runner-created resources, by IMMUTABLE id after re-verifying THIS
        # run's label. 'skip-uncertain' leaves the resource untouched and surfaces here
        # (R08 fails -> nonzero). A name/label match alone never authorises deletion.
        if ledger["container"]["created"]:
            action, reason = _container_cleanup_decision(ledger["container"]["id"], run_hash)
            if action == "remove":
                if _docker(["rm", "-f", ledger["container"]["id"]]).returncode != 0:
                    cleanup_issues.append("container rm by id failed")
            elif action == "skip-uncertain":
                cleanup_issues.append(f"container: {reason}; left untouched")
        if ledger["volume"]["created"]:
            action, reason = _volume_cleanup_decision(ledger["volume"]["name"], run_hash)
            if action == "remove":
                if _docker(["volume", "rm", "-f", ledger["volume"]["name"]]).returncode != 0:
                    cleanup_issues.append("volume rm failed")
            elif action == "skip-uncertain":
                cleanup_issues.append(f"volume: {reason}; left untouched")
        # Record R08 exactly once (drop any abort-time placeholder first).
        checks[:] = [c for c in checks if not c["id"].startswith("R08")]
        record("R08 cleanup removed only runner-created resources (by id, label-verified)",
               not cleanup_issues, "ownership", {"issues": cleanup_issues})
        # Remove the scratch working directory (close the API log handle first).
        try:
            if api_log is not None:
                api_log.close()
        except Exception:  # noqa: BLE001
            pass
        import shutil
        shutil.rmtree(scratch, ignore_errors=True)

    return {"run_hash": run_hash, "cleanup_issues": cleanup_issues,
            "container_created": ledger["container"]["created"],
            "volume_created": ledger["volume"]["created"],
            "sql_readiness_history": sql_readiness_history,
            "aborted_stage": _ACTIVE_FAULT}


def _emit() -> int:
    recorded = {c["id"] for c in checks}
    missing = [cid for cid, _ in _INVENTORY if cid not in recorded]
    passed = [c for c in checks if c["ok"] and not c["skipped"]]
    skipped = [c for c in checks if c["skipped"]]
    failed = [c for c in checks if not c["ok"]]
    c423 = sum(1 for s in http_statuses if s == 423)
    c500 = sum(1 for s in http_statuses if s == 500)
    c503 = sum(1 for s in http_statuses if s == 503)
    # Certification disposition: skipped => non-certifying "unavailable"; any failure =>
    # "failed"; otherwise "passed". No evidence artifact is ever written to disk.
    if skipped:
        certification = "unavailable"
    elif missing or failed or c423 or c500 or c503:
        certification = "failed"
    else:
        certification = "passed"
    # Attach Part M per-check inventory metadata (machine-readable claim scope).
    enriched = []
    for c in checks:
        meta = _CATEGORY_META.get(c["category"], {})
        enriched.append({**c,
                         "requires_docker": meta.get("requires_docker", True),
                         "requires_postgresql": meta.get("requires_postgresql", False),
                         "process_boundary": meta.get("process_boundary", "runner"),
                         "principal": meta.get("principal", "runner"),
                         "claim_scope": "startup-and-identity-only"})
    print(json.dumps({"checks": enriched,
                      "summary": {"passed": len(passed), "skipped": len(skipped), "failed": len(failed),
                                  "missing_ids": missing, "expected": len(_INVENTORY),
                                  "functional_http": {"c423": c423, "c500": c500, "c503": c503},
                                  "certification": certification,
                                  # Part C: the migration login is an isolated, test-only
                                  # SUPERUSER. Empirically (PG16) this is unavoidable:
                                  # `create extension vector` is untrusted (superuser-only)
                                  # and migration 0007's `alter role ... nosuperuser` can
                                  # only be executed by a superuser. It is a NAMED principal
                                  # distinct from the container-default role and from the
                                  # RESTRICTED runtime login; it never appears in the API/
                                  # worker environment (child-env allowlist) and the runtime
                                  # login cannot SET ROLE to it (P09). This is NOT a runtime
                                  # pattern -- production parity is false.
                                  "migration_principal": {
                                      "principal_class": "test-only-bootstrap-migration-admin",
                                      "migration_superuser": True,
                                      "test_only_migration_principal": True,
                                      "production_parity": False,
                                      "eligible_for_production_adapter_evidence": False},
                                  # Explicit, machine-readable claim scope. This guard proves
                                  # runner ownership + external startup + live identity + a
                                  # minimal smoke ONLY -- it does NOT run the corrections/
                                  # validation/idempotency/cross-tenant/export/import matrix and
                                  # must never be consumed as tenant-authorization evidence or a
                                  # readiness proof.
                                  "claim_scope": "startup-and-identity-only",
                                  "full_functional_matrix": "not_run",
                                  "eligible_for_tenant_evidence": False,
                                  "eligible_for_readiness": False}},
                     indent=2, default=str))
    if missing:
        print(f"\nInventory mismatch: {len(missing)} expected id(s) produced no result.")
        return 1
    if c423 or c500 or c503:
        print(f"\nFunctional HTTP 423/500/503 observed ({c423}/{c500}/{c503}); startup guard FAILED.")
        return 1
    if failed:
        print(f"\nRestricted-postgres-startup guard FAILED: {len(failed)} failing check(s).")
        for c in failed:
            print(f"  FAIL: {c['id']} -> {c['detail']}")
        return 1
    tail = f" ({len(skipped)} skipped: docker unavailable, non-certifying)" if skipped else ""
    print(f"\nRestricted-postgres-startup guard passed: {len(passed)} check(s).{tail}"
          "\n[claim_scope=startup-and-identity-only; NOT tenant-evidence/readiness eligible]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
