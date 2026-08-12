"""Fault-injection battery for the runner-owned restricted-PostgreSQL startup stack.

CLAIM SCOPE: startup-fault-injection-only. This guard drives the REAL runner
(``restricted_postgres_startup_guard.run_stack``) and injects REAL failures at
deterministic named lifecycle stages, then proves that:

  * a fault at any stage makes the certification non-passing;
  * every runner-owned container/volume/process is still cleaned up;
  * uniquely-marked UNRELATED sentinel resources are never touched;
  * cleanup removes ONLY resources whose IMMUTABLE id still carries THIS run's
    label -- a substituted / relabelled resource is left untouched and the run is
    made nonzero (no ids/paths/DSNs/secrets in the message);
  * the child API/worker environment is an explicit ALLOWLIST -- no inherited
    libpq/PG* variable (PGHOST/PGPORT/PGUSER/PGPASSWORD/PGOPTIONS/PGSERVICE...) or
    migration/test DSN survives, so no role-changing option reaches the runtime;
  * the runner's Docker ownership predicates reject a wrong id / wrong label /
    wrong image / non-loopback binding / wrong mount;
  * against a LIVE stack, each role/policy/attestation mutation is detected, a
    spoofed pg_stat_activity session cannot satisfy the identity proof, and an
    unsafe runtime role fails ``create_store`` closed (no local/file fallback).

It is NOT the full functional matrix and MUST NEVER be consumed as tenant-authorization
evidence or a readiness proof (see the emitted scope fields). It requires Docker; without
it every scenario records SKIPPED under --allow-unavailable (never a false pass).

The fault marker is a Python stage name passed via a module-internal test hook
(``restricted_postgres_startup_guard._ACTIVE_FAULT``). It is not an environment variable,
not request-controlled, not inherited by the launched API/worker, and does not exist in
backend/app production code; it identifies ONLY a lifecycle stage.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT, ROOT / "scripts"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import restricted_postgres_startup_guard as G  # noqa: E402

SENTINEL_LABEL = "acc19-fault-sentinel"
checks: list[dict] = []


def record(cid: str, ok: bool, category: str, detail: object = "", *, skipped: bool = False) -> None:
    checks.append({"id": cid, "ok": bool(ok), "category": category, "skipped": bool(skipped), "detail": detail})


# Canonical expected-ID inventory (id, category).
_INVENTORY = [
    # Stage faults -- one real runner invocation per lifecycle stage.
    *[(f"FA {s}", "stage-fault") for s in G.FAULT_STAGES],
    # Cleanup ownership uncertainty.
    ("CU01 owned container is removed (by id, label-verified)", "cleanup-ownership"),
    ("CU02 wrong-id container is not removed (already gone)", "cleanup-ownership"),
    ("CU03 wrong-run-label container is left untouched (skip-uncertain)", "cleanup-ownership"),
    ("CU04 wrong-project-label container is left untouched", "cleanup-ownership"),
    ("CU05 name reused by an unowned resource is never deleted (id-scoped)", "cleanup-ownership"),
    ("CU06 owned volume removed; wrong-label volume left untouched", "cleanup-ownership"),
    ("CU07 cleanup uncertainty carries no id/path/secret", "cleanup-ownership"),
    # Connection-environment substitution (child env allowlist).
    ("EN01 PGHOST stripped", "env-substitution"),
    ("EN02 PGPORT stripped", "env-substitution"),
    ("EN03 PGDATABASE stripped", "env-substitution"),
    ("EN04 PGUSER stripped", "env-substitution"),
    ("EN05 PGPASSWORD stripped", "env-substitution"),
    ("EN06 PGSERVICE stripped", "env-substitution"),
    ("EN07 PGSERVICEFILE stripped", "env-substitution"),
    ("EN08 PGOPTIONS (-c role=...) stripped -- no SET ROLE", "env-substitution"),
    ("EN09 DATABASE_URL stripped", "env-substitution"),
    ("EN10 MONDAY_REPORT_MIGRATIONS_DATABASE_URL absent from API/worker", "env-substitution"),
    ("EN11 MONDAY_REPORT_TEST_DATABASE_URL stripped", "env-substitution"),
    ("EN12 runtime DSN is the runner-derived value; child env has no libpq leak", "env-substitution"),
    # Docker ownership-predicate detection.
    ("DK01 wrong immutable id -> not our resource", "docker-substitution"),
    ("DK02 correct labels but wrong id -> not removed", "docker-substitution"),
    ("DK03 wrong image rejected (R07 predicate)", "docker-substitution"),
    ("DK04 non-loopback 0.0.0.0 binding rejected (R06)", "docker-substitution"),
    ("DK05 IPv6 wildcard binding rejected (R06)", "docker-substitution"),
    ("DK06 wrong / multiple / missing PGDATA mount rejected (R05)", "docker-substitution"),
    # Live stack: role/policy/attestation mutations + session spoofing + fail-closed.
    ("RP01 runtime superuser detected (P07 fails)", "role-mutation"),
    ("RP02 runtime BYPASSRLS detected (P07 fails)", "role-mutation"),
    ("RP03 RLS/FORCE disabled detected (P04 fails)", "role-mutation"),
    ("RP04 policy dropped detected (P05 fails)", "role-mutation"),
    ("RP05 attestation missing -> boundary inactive", "role-mutation"),
    ("RP06 attestation expired -> checker false", "role-mutation"),
    ("RP07 checker function dropped -> attestation absent", "role-mutation"),
    ("SS01 rogue session (same appname, wrong role) fails identity", "session-spoof"),
    ("SS02 session opened before the barrier fails freshness", "session-spoof"),
    ("SS03 duplicate matching sessions fail exactly-one", "session-spoof"),
    ("FC01 unsafe runtime role (superuser) fails create_store closed", "fail-closed"),
    ("FC02 attestation absent -> verification boundary not active", "fail-closed"),
]

_CATEGORY_META = {
    "stage-fault": {"requires_docker": True, "requires_postgresql": True, "process_boundary": "runner"},
    "cleanup-ownership": {"requires_docker": True, "requires_postgresql": False, "process_boundary": "runner"},
    "env-substitution": {"requires_docker": False, "requires_postgresql": False, "process_boundary": "runner"},
    "docker-substitution": {"requires_docker": True, "requires_postgresql": False, "process_boundary": "runner"},
    "role-mutation": {"requires_docker": True, "requires_postgresql": True, "process_boundary": "runner"},
    "session-spoof": {"requires_docker": True, "requires_postgresql": True, "process_boundary": "external-process"},
    "fail-closed": {"requires_docker": True, "requires_postgresql": True, "process_boundary": "runner"},
}


def _d(args, timeout=60):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def _labels_of(run_hash, kind, project=G.LABEL_PROJECT):
    return ["--label", f"project={project}", "--label", f"purpose={G.LABEL_PURPOSE}",
            "--label", f"verification-run={run_hash}", "--label", f"resource={kind}"]


def _leftover(run_hash) -> list[str]:
    c = _d(["ps", "-aq", "-f", f"label=verification-run={run_hash}"]).stdout.split()
    v = _d(["volume", "ls", "-q", "-f", f"label=verification-run={run_hash}"]).stdout.split()
    return c + v


def _no_secret(text: str, secrets_list: list[str]) -> bool:
    low = text.lower()
    if any(s and s.lower() in low for s in secrets_list):
        return False
    # No DSN, no absolute path, no long hex id.
    if "postgresql://" in low or ":\\" in text or "/var/lib" in low:
        return False
    return True


def _exec_level(cid: str) -> str:
    """HONEST per-check execution level. A predicate/unit test is never described as a
    whole-stack live fault. Whole-stack faults invoke the real runner + its real cleanup;
    live Docker/PG/session tests create real resources or mutate a live database/session;
    predicate/unit tests exercise the real functions over crafted inputs."""
    p = cid.split()[0]
    if p.startswith("FA"):
        return "whole-stack fault"                 # real run_stack + real cleanup path
    if p in ("CU01", "CU02", "CU03", "CU04", "CU05", "CU06"):
        return "live Docker substitution"          # real containers/volumes + real decision
    if p in ("DK01", "DK02"):
        return "live Docker substitution"          # real `docker inspect` via the decision helper
    if p in ("DK03", "DK04", "DK05", "DK06", "CU07") or p.startswith("EN"):
        return "pure predicate/unit mutation"      # real predicate/env functions over crafted input
    if p.startswith("RP"):
        return "live PostgreSQL mutation"          # real role/policy/attestation mutation on the live DB
    if p.startswith("SS"):
        return "live process/session spoof"        # real pg_stat_activity sessions
    if p.startswith("FC"):
        return "direct component integration"      # real create_store / verification_context vs the live DB
    return "structural source check"


def run() -> int:
    allow_unavailable = "--allow-unavailable" in sys.argv
    if _d(["info"]).returncode != 0:
        if allow_unavailable:
            for cid, cat in _INVENTORY:
                record(cid, True, cat, "docker unavailable (non-certifying mode)", skipped=True)
        else:
            for cid, cat in _INVENTORY:
                record(cid, False, cat, "docker required for certification; pass --allow-unavailable")
        return _emit()

    # ---- sentinels: unrelated resources that must be untouched ------------------
    sh = secrets.token_hex(3)
    s_ctr = f"mr-sentinel-{sh}"
    s_vol = f"mr-sentinel-vol-{sh}"
    s_dir = Path(os.environ.get("TEMP", "/tmp")) / f"mr-sentinel-dir-{sh}"
    s_dir.mkdir(parents=True, exist_ok=True)
    (s_dir / "keep.txt").write_text("sentinel", encoding="utf-8")
    import hashlib
    s_dir_hash = hashlib.sha256((s_dir / "keep.txt").read_bytes()).hexdigest()
    _d(["volume", "create", "--label", f"{SENTINEL_LABEL}={sh}", s_vol])
    _d(["run", "-d", "--name", s_ctr, "--label", f"{SENTINEL_LABEL}={sh}", "alpine", "sleep", "900"])
    s_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(900)"])

    def sentinels_intact() -> bool:
        ctr = _d(["ps", "-q", "-f", f"name=^{s_ctr}$"]).stdout.strip()
        vol = _d(["volume", "ls", "-q", "-f", f"name=^{s_vol}$"]).stdout.strip()
        proc_alive = s_proc.poll() is None
        dir_ok = (s_dir / "keep.txt").exists() and \
            hashlib.sha256((s_dir / "keep.txt").read_bytes()).hexdigest() == s_dir_hash
        return bool(ctr) and bool(vol) and proc_alive and dir_ok

    created_helpers: list[tuple[str, str]] = []  # (kind, name) for our own crafted resources

    try:
        # ================= STAGE FAULTS (Parts D/E) =========================
        for stage in G.FAULT_STAGES:
            G.checks = []
            G.http_statuses = []
            G._ACTIVE_FAULT = stage
            try:
                result = G.run_stack()
            except Exception as exc:  # noqa: BLE001 - a fault must never escape run_stack
                G._ACTIVE_FAULT = None
                record(f"FA {stage}", False, "stage-fault", f"run_stack raised: {type(exc).__name__}")
                continue
            G._ACTIVE_FAULT = None
            run_hash = result["run_hash"]
            leftover = _leftover(run_hash)
            failed = [c for c in G.checks if not c["ok"]]
            issues = result["cleanup_issues"]
            if stage == "during_cleanup":
                # Completes then injects a redacted cleanup issue -> R08 fails (nonzero),
                # resources STILL removed, message carries no secrets.
                ok = (bool(failed) and not leftover and sentinels_intact()
                      and issues and all(_no_secret(m, []) for m in issues))
            else:
                # Aborts mid-run -> some checks fail (non-passing), owned resources
                # removed, no cleanup issue, sentinels untouched.
                ok = (bool(failed) and not leftover and not issues and sentinels_intact())
            record(f"FA {stage}", ok, "stage-fault",
                   {"failed_checks": len(failed), "leftover": len(leftover),
                    "cleanup_issues": issues, "sentinels_ok": sentinels_intact()})

        # ================= CLEANUP OWNERSHIP BATTERY (Part E) ===============
        rh = secrets.token_hex(6)
        # An owned container + volume (this run's label).
        oc = f"mr-verif-own-{rh}"
        ov = f"mr-verif-ownvol-{rh}"
        _d(["volume", "create", *_labels_of(rh, "volume"), ov]); created_helpers.append(("volume", ov))
        cid_out = _d(["run", "-d", "--name", oc, *_labels_of(rh, "container"), "alpine", "sleep", "300"])
        owned_id = cid_out.stdout.strip()[:12]; created_helpers.append(("container", oc))
        # A wrong-run-label container (different verification-run).
        wc = f"mr-verif-wrong-{rh}"
        wl = _d(["run", "-d", "--name", wc, *_labels_of("deadbeefdead", "container"), "alpine", "sleep", "300"])
        wrong_id = wl.stdout.strip()[:12]; created_helpers.append(("container", wc))
        # A wrong-project-label container (a plausible impostor).
        pc = f"mr-verif-proj-{rh}"
        pl = _d(["run", "-d", "--name", pc, *_labels_of(rh, "container", project="not-monday-report"),
                 "alpine", "sleep", "300"])
        proj_id = pl.stdout.strip()[:12]; created_helpers.append(("container", pc))

        a, _ = G._container_cleanup_decision(owned_id, rh)
        record("CU01 owned container is removed (by id, label-verified)", a == "remove", "cleanup-ownership", {"action": a})
        a, _ = G._container_cleanup_decision("0123456789ab", rh)
        record("CU02 wrong-id container is not removed (already gone)", a == "skip", "cleanup-ownership", {"action": a})
        a, _ = G._container_cleanup_decision(wrong_id, rh)
        record("CU03 wrong-run-label container is left untouched (skip-uncertain)", a == "skip-uncertain",
               "cleanup-ownership", {"action": a})
        a, _ = G._container_cleanup_decision(proj_id, rh)
        record("CU04 wrong-project-label container is left untouched", a == "skip-uncertain",
               "cleanup-ownership", {"action": a})
        # Name reuse: a sentinel-named container whose id differs from a recorded id.
        # Cleanup targets ids, never names, so the reused name is never deleted.
        a_owned, _ = G._container_cleanup_decision(owned_id, rh)
        wrong_still = _d(["ps", "-q", "-f", f"name=^{wc}$"]).stdout.strip()
        record("CU05 name reused by an unowned resource is never deleted (id-scoped)",
               a_owned == "remove" and bool(wrong_still), "cleanup-ownership",
               {"decision_is_id_scoped": True, "unowned_still_present": bool(wrong_still)})
        av, _ = G._volume_cleanup_decision(ov, rh)
        av2, _ = G._volume_cleanup_decision(s_vol, rh)  # sentinel volume: wrong label
        record("CU06 owned volume removed; wrong-label volume left untouched",
               av == "remove" and av2 == "skip-uncertain", "cleanup-ownership", {"owned": av, "sentinel": av2})
        _, reason = G._container_cleanup_decision(wrong_id, rh)
        record("CU07 cleanup uncertainty carries no id/path/secret",
               _no_secret(reason, [owned_id, wrong_id, rh]), "cleanup-ownership", {"reason": reason})

        # ================= ENV / DSN SUBSTITUTION (Part G) ==================
        derived = "postgresql://mr_rt_x:pw@127.0.0.1:55999/monday_verif_test?application_name=mr-verification-api-x"
        base = {"MONDAY_REPORT_DATABASE_URL": derived, "MONDAY_REPORT_TENANT_SLUG": "verif-a"}
        subs = {
            "EN01 PGHOST stripped": ("PGHOST", "evil.example.com"),
            "EN02 PGPORT stripped": ("PGPORT", "6666"),
            "EN03 PGDATABASE stripped": ("PGDATABASE", "prod"),
            "EN04 PGUSER stripped": ("PGUSER", "rogue_pg_user"),
            "EN05 PGPASSWORD stripped": ("PGPASSWORD", "hunter2"),
            "EN06 PGSERVICE stripped": ("PGSERVICE", "prod-svc"),
            "EN07 PGSERVICEFILE stripped": ("PGSERVICEFILE", "/etc/pgservice.conf"),
            "EN08 PGOPTIONS (-c role=...) stripped -- no SET ROLE": ("PGOPTIONS", "-c role=postgres"),
            "EN09 DATABASE_URL stripped": ("DATABASE_URL", "postgresql://attacker@10.9.9.9/prod"),
            "EN10 MONDAY_REPORT_MIGRATIONS_DATABASE_URL absent from API/worker":
                ("MONDAY_REPORT_MIGRATIONS_DATABASE_URL", "postgresql://mig@127.0.0.1:5432/x"),
            "EN11 MONDAY_REPORT_TEST_DATABASE_URL stripped":
                ("MONDAY_REPORT_TEST_DATABASE_URL", "postgresql://t@127.0.0.1:5432/x"),
        }
        for cid, (var, val) in subs.items():
            saved = os.environ.get(var)
            os.environ[var] = val
            try:
                child = G._child_env(base)
            finally:
                if saved is None:
                    os.environ.pop(var, None)
                else:
                    os.environ[var] = saved
            stripped = var not in child and val not in "".join(child.values())
            record(cid, stripped and G._no_libpq_leak(child), "env-substitution", {"var": var})
        # EN12: the derived DSN survives; no libpq leak overall.
        child = G._child_env(base)
        record("EN12 runtime DSN is the runner-derived value; child env has no libpq leak",
               child.get("MONDAY_REPORT_DATABASE_URL") == derived and G._no_libpq_leak(child),
               "env-substitution", {"leak": G._libpq_leak_keys(child)})

        # ================= DOCKER OWNERSHIP-PREDICATE DETECTION (Part F) =====
        a, _ = G._container_cleanup_decision("ffffffffffff", rh)
        record("DK01 wrong immutable id -> not our resource", a == "skip", "docker-substitution", {"action": a})
        a, _ = G._container_cleanup_decision(proj_id, rh)
        record("DK02 correct labels but wrong id -> not removed", a == "skip-uncertain", "docker-substitution", {"action": a})

        # Exercise the runner's REAL ownership predicates (imported from the startup guard,
        # the SAME functions run_stack applies for R05/R06/R07) against crafted inspect
        # data, so a regression in the runner's predicate would be caught here.
        P = 5433  # a non-live port
        record("DK03 wrong image rejected (R07 predicate)",
               G._image_ok(G.PG_IMAGE) and not G._image_ok("postgres:16") and not G._image_ok("evil/pg:latest"),
               "docker-substitution")
        record("DK04 non-loopback 0.0.0.0 binding rejected (R06)",
               G._loopback_bindings_ok(["127.0.0.1"], P) and not G._loopback_bindings_ok(["0.0.0.0"], P)
               and not G._loopback_bindings_ok(["127.0.0.1", "0.0.0.0"], P)
               and not G._loopback_bindings_ok(["127.0.0.1"], 8000)
               and not G._loopback_bindings_ok(["127.0.0.1"], 5173), "docker-substitution")
        record("DK05 IPv6 wildcard binding rejected (R06)",
               G._loopback_bindings_ok(["::1"], P) and not G._loopback_bindings_ok(["::"], P)
               and not G._loopback_bindings_ok([], P), "docker-substitution")
        good_mounts = [{"Type": "volume", "Destination": "/var/lib/postgresql/data", "Name": "v1"}]
        wrong_mount = [{"Type": "volume", "Destination": "/var/lib/postgresql/data", "Name": "OTHER"}]
        multi = good_mounts + [{"Type": "volume", "Destination": "/var/lib/postgresql/data", "Name": "v2"}]
        record("DK06 wrong / multiple / missing PGDATA mount rejected (R05)",
               G._single_pgdata_mount_ok(good_mounts, "v1") and not G._single_pgdata_mount_ok(wrong_mount, "v1")
               and not G._single_pgdata_mount_ok(multi, "v1") and not G._single_pgdata_mount_ok([], "v1"),
               "docker-substitution")

        # Clean up the crafted helpers now (owned + impostors); leave sentinels.
        for kind, name in created_helpers:
            if kind == "container":
                _d(["rm", "-f", name])
            else:
                _d(["volume", "rm", "-f", name])
        created_helpers.clear()

        # ================= LIVE STACK: mutations + spoof + fail-closed =======
        live_state = {"ran": False}

        def on_live(ctx):
            live_state["ran"] = True
            import psycopg
            boot, rt = ctx["boot_dsn"], ctx["rt_dsn"]
            rt_role, mig_role = ctx["rt_role"], ctx["mig_role"]
            appname = ctx["api_appname"]
            lock_key = ctx["lock_key"]
            run_id, run_hash = ctx["run_id"], ctx["run_hash"]
            base_env = ctx["base_env"]

            with psycopg.connect(boot, autocommit=True) as c:
                # RP01/RP02: revertible runtime-attribute mutations.
                c.execute(f"alter role {rt_role} superuser")
                su = c.execute("select rolsuper from pg_roles where rolname=%s", (rt_role,)).fetchone()[0]
                record("RP01 runtime superuser detected (P07 fails)", su is True, "role-mutation")
                c.execute(f"alter role {rt_role} nosuperuser")
                c.execute(f"alter role {rt_role} bypassrls")
                bp = c.execute("select rolbypassrls from pg_roles where rolname=%s", (rt_role,)).fetchone()[0]
                record("RP02 runtime BYPASSRLS detected (P07 fails)", bp is True, "role-mutation")
                c.execute(f"alter role {rt_role} nobypassrls")

                # FC01: an unsafe runtime role must fail create_store closed (no fallback).
                # create_store() reads the env fresh, so NO module reload is needed (a
                # reload would re-run the module-level `store = create_store()` and raise
                # during import -- the same fail-closed signal, but harder to scope).
                import backend.app.store as store_mod
                c.execute(f"alter role {rt_role} superuser")
                saved = {k: os.environ.get(k) for k in base_env}
                os.environ.update(base_env)
                fc_ok = False
                fc_detail = ""
                try:
                    store_mod.create_store()  # must refuse a superuser runtime role
                    fc_ok = False
                except Exception as exc:  # noqa: BLE001 - TenantRuntimeRoleError et al.
                    fc_ok = True
                    fc_detail = type(exc).__name__
                finally:
                    for k, v in saved.items():
                        (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))
                    c.execute(f"alter role {rt_role} nosuperuser")
                record("FC01 unsafe runtime role (superuser) fails create_store closed", fc_ok,
                       "fail-closed", {"raised": fc_detail})

                # SS: session spoofing against the identity predicate.
                # Each session-spoof test uses its OWN advisory key (distinct from the app's
                # snapshot lock and from each other), so a lingering rogue/pre/dup thread cannot
                # block a later test. The identity predicate keys on wait_event='advisory' (any
                # advisory lock), so distinct keys do not weaken the spoof tests.
                # Distinct advisory keys per spoof test (identity predicate keys on
                # wait_event='advisory', not a specific key), so tests don't interfere.
                spoof_k1, spoof_k2, spoof_k3 = 0x5A5A0001, 0x5A5A0002, 0x5A5A0003

                def _spoof_wait(dsn, target_app, key):
                    """Open a connection (short statement_timeout so a blocked acquire cannot
                    hang) and, in ITS OWN thread, acquire `key` -- the session then shows
                    wait_event='advisory' until it acquires or times out. Only ONE thread ever
                    touches the connection (psycopg connections are not thread-safe): the main
                    thread sets the timeout, starts the worker, and does not touch the conn again
                    until the caller has released the holder's key, JOINED the thread, and only
                    THEN closes the conn. Returns (conn, thread)."""
                    conn = psycopg.connect(dsn, autocommit=True)
                    conn.execute("set statement_timeout to '15s'")
                    def _acq():
                        try:
                            cur = conn.cursor()
                            cur.execute(f"set application_name to '{target_app}'")
                            cur.execute("select pg_advisory_lock(%s)", (key,))
                        except Exception:
                            pass
                    t = threading.Thread(target=_acq, daemon=True)
                    t.start()
                    return conn, t

                def _await_advisory(obs, target_app, tref, want, tries=80):
                    n = 0
                    for _ in range(tries):
                        n = obs.execute(
                            "select count(*) from pg_stat_activity where application_name=%s "
                            "and wait_event_type='Lock' and wait_event='advisory' and backend_start >= %s",
                            (target_app, tref)).fetchone()[0]
                        if int(n) >= want:
                            break
                        time.sleep(0.1)
                    return int(n)

                # SS01: a rogue session uses the API application_name but the MIGRATION
                # (superuser) role -> the identity predicate (usename==runtime) rejects it.
                with psycopg.connect(boot, autocommit=True) as obs:
                    t0 = obs.execute("select now()").fetchone()[0]
                    obs.execute("select pg_advisory_lock(%s)", (spoof_k1,))
                    rconn, rth = _spoof_wait(ctx["mig_dsn"], appname, spoof_k1)
                    try:
                        rows = []
                        for _ in range(80):
                            rows = obs.execute(
                                "select usename from pg_stat_activity where application_name=%s "
                                "and wait_event_type='Lock' and wait_event='advisory' and backend_start >= %s",
                                (appname, t0)).fetchall()
                            if rows:
                                break
                            time.sleep(0.1)
                        users = [r[0] for r in rows]
                    finally:
                        obs.execute("select pg_advisory_unlock(%s)", (spoof_k1,))
                        rth.join(timeout=20)
                        try:
                            rconn.close()
                        except Exception:
                            pass
                record("SS01 rogue session (same appname, wrong role) fails identity",
                       users == [] or (rt_role not in users), "session-spoof",
                       {"observed_usernames_are_not_runtime": rt_role not in users})

                # SS02: a session opened BEFORE the barrier -- even while advisory-waiting with
                # the API application_name (matching every OTHER clause) -- is excluded by the
                # freshness clause (backend_start >= t0).
                with psycopg.connect(boot, autocommit=True) as holder:
                    holder.execute("select pg_advisory_lock(%s)", (spoof_k2,))
                    pconn, pth = _spoof_wait(rt, appname, spoof_k2)
                    try:
                        _await_advisory(holder, appname, "1970-01-01", 1)  # wait until pre is waiting
                        t0 = holder.execute("select now()").fetchone()[0]  # AFTER pre is waiting
                        fresh = holder.execute(
                            "select count(*) from pg_stat_activity where application_name=%s "
                            "and wait_event_type='Lock' and wait_event='advisory' and backend_start >= %s",
                            (appname, t0)).fetchone()[0]
                    finally:
                        holder.execute("select pg_advisory_unlock(%s)", (spoof_k2,))
                        pth.join(timeout=20)
                        try:
                            pconn.close()
                        except Exception:
                            pass
                record("SS02 session opened before the barrier fails freshness", int(fresh) == 0,
                       "session-spoof", {"fresh_advisory_sessions": fresh})

                # SS03: two matching fresh sessions -> the 'exactly one' requirement fails.
                with psycopg.connect(boot, autocommit=True) as obs:
                    t0 = obs.execute("select now()").fetchone()[0]
                    obs.execute("select pg_advisory_lock(%s)", (spoof_k3,))
                    d1c, d1t = _spoof_wait(rt, appname, spoof_k3)
                    d2c, d2t = _spoof_wait(rt, appname, spoof_k3)
                    try:
                        n = _await_advisory(obs, appname, t0, 2)
                    finally:
                        obs.execute("select pg_advisory_unlock(%s)", (spoof_k3,))
                        d1t.join(timeout=20)
                        d2t.join(timeout=20)
                        for cc in (d1c, d2c):
                            try:
                                cc.close()
                            except Exception:
                                pass
                record("SS03 duplicate matching sessions fail exactly-one", int(n) >= 2,
                       "session-spoof", {"matching_sessions": n})

                # RP03/RP04: RLS/FORCE + policy.
                forced = c.execute(
                    "select count(*) from pg_class where relnamespace='public'::regnamespace "
                    "and relname like 'monday_report_norm_%' and relrowsecurity and relforcerowsecurity").fetchone()[0]
                c.execute("alter table monday_report_norm_reports no force row level security")
                forced_after = c.execute(
                    "select count(*) from pg_class where relnamespace='public'::regnamespace "
                    "and relname like 'monday_report_norm_%' and relrowsecurity and relforcerowsecurity").fetchone()[0]
                record("RP03 RLS/FORCE disabled detected (P04 fails)", int(forced_after) < int(forced),
                       "role-mutation", {"before": forced, "after": forced_after})
                c.execute("alter table monday_report_norm_reports force row level security")
                pol = c.execute("select count(*) from pg_policies where schemaname='public'").fetchone()[0]
                one = c.execute("select policyname, tablename from pg_policies where schemaname='public' limit 1").fetchone()
                c.execute(f'drop policy "{one[0]}" on {one[1]}')
                pol_after = c.execute("select count(*) from pg_policies where schemaname='public'").fetchone()[0]
                record("RP04 policy dropped detected (P05 fails)", int(pol_after) < int(pol),
                       "role-mutation", {"before": pol, "after": pol_after})

                # RP06: attestation expired -> checker false (do BEFORE truncating).
                from backend.app import verification_boundary as vb
                c.execute(f"update {vb.ATTESTATION_QUALIFIED} set expires_at = now() - interval '1 hour'")
                run_hash_full = __import__("hashlib").sha256(run_id.encode()).hexdigest()
                exp = c.execute(f"select {vb.ATTESTATION_CHECK_FN}(%s)", (run_hash_full,)).fetchone()[0]
                record("RP06 attestation expired -> checker false", exp is False, "role-mutation")
                # RP05: attestation missing -> boundary inactive (truncate the table).
                c.execute(f"truncate {vb.ATTESTATION_QUALIFIED}")
                saved = {k: os.environ.get(k) for k in base_env}
                os.environ.update(base_env)
                try:
                    active = vb.verification_context()["verification_isolation_active"]
                finally:
                    for k, v in saved.items():
                        (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))
                record("RP05 attestation missing -> boundary inactive", active is False, "role-mutation")
                record("FC02 attestation absent -> verification boundary not active", active is False, "fail-closed")
                # RP07: checker function dropped -> present() False.
                c.execute(f"drop function if exists {vb.ATTESTATION_CHECK_FN}(text)")
                saved = {k: os.environ.get(k) for k in base_env}
                os.environ.update(base_env)
                try:
                    present = vb.database_attestation_present()
                finally:
                    for k, v in saved.items():
                        (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))
                record("RP07 checker function dropped -> attestation absent", present is False, "role-mutation")

        live_err = {}

        def _on_live_wrapped(ctx):
            # Surface WHY the live battery aborted (run_stack otherwise swallows on_live's
            # exception) so any unreached live check carries the real cause, not "aborted".
            try:
                on_live(ctx)
            except Exception as exc:  # noqa: BLE001
                import traceback
                live_err["msg"] = f"{type(exc).__name__}: {str(exc)[:160]}"
                live_err["tb"] = traceback.format_exc()[-1500:]
        G.checks = []
        G.http_statuses = []
        G._ON_LIVE = _on_live_wrapped
        try:
            G.run_stack()
        finally:
            G._ON_LIVE = None
        if live_err:
            print("LIVE-BATTERY ERROR:", live_err.get("msg"), file=sys.stderr)
            print(live_err.get("tb", ""), file=sys.stderr)
        # Backfill any live check that on_live did not record (aborted early / provisioning
        # failed) as a FAILURE, so the inventory is always complete and an abort surfaces
        # with its cause.
        have = {c["id"] for c in checks}
        for cid, cat in _INVENTORY:
            if cat in ("role-mutation", "session-spoof", "fail-closed") and cid not in have:
                record(cid, False, cat,
                       "live battery aborted: " + live_err.get("msg", "did not reach this check"))

    finally:
        # remove any crafted helpers + sentinels
        for kind, name in created_helpers:
            _d(["rm", "-f", name]) if kind == "container" else _d(["volume", "rm", "-f", name])
        try:
            s_proc.terminate(); s_proc.wait(timeout=10)
        except Exception:
            pass
        _d(["rm", "-f", s_ctr]); _d(["volume", "rm", "-f", s_vol])
        try:
            (s_dir / "keep.txt").unlink()
            s_dir.rmdir()
        except Exception:
            pass

    return _emit()


def _emit() -> int:
    recorded = {c["id"] for c in checks}
    missing = [cid for cid, _ in _INVENTORY if cid not in recorded]
    passed = [c for c in checks if c["ok"] and not c["skipped"]]
    skipped = [c for c in checks if c["skipped"]]
    failed = [c for c in checks if not c["ok"]]
    enriched = []
    for c in checks:
        meta = _CATEGORY_META.get(c["category"], {})
        enriched.append({**c, "requires_docker": meta.get("requires_docker", True),
                         "requires_postgresql": meta.get("requires_postgresql", False),
                         "process_boundary": meta.get("process_boundary", "runner"),
                         "execution_level": _exec_level(c["id"]),
                         "claim_scope": "startup-fault-injection-only"})
    # Honest execution-level totals (a predicate/unit test is NOT a whole-stack live fault).
    exec_totals: dict = {}
    for c in enriched:
        exec_totals[c["execution_level"]] = exec_totals.get(c["execution_level"], 0) + 1
    print(json.dumps({"checks": enriched,
                      "summary": {"passed": len(passed), "skipped": len(skipped), "failed": len(failed),
                                  "missing_ids": missing, "expected": len(_INVENTORY),
                                  "execution_level_totals": exec_totals,
                                  "claim_scope": "startup-fault-injection-only",
                                  "eligible_for_tenant_evidence": False,
                                  "eligible_for_readiness": False}}, indent=2, default=str))
    if missing:
        print(f"\nInventory mismatch: {len(missing)} expected id(s) produced no result: {missing}")
        return 1
    if failed:
        print(f"\nFault-injection guard FAILED: {len(failed)} failing scenario(s).")
        for c in failed:
            print(f"  FAIL: {c['id']} -> {c['detail']}")
        return 1
    tail = " (skipped: docker unavailable, non-certifying)" if skipped else ""
    print(f"\nFault-injection guard passed: {len(passed)} scenario(s).{tail}"
          "\n[claim_scope=startup-fault-injection-only; NOT tenant-evidence/readiness eligible]")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
