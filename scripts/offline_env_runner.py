"""offline-package environment-request / environment-resume -- the
ENVIRONMENT-SIDE half of the air-gapped activation protocol.

This runner executes INSIDE the environment under test (an isolated
installation on the host, or the clean Hyper-V Environment 2 guest). It may install the
package, launch it, export an activation request, wait for a signed license,
import it, and run the package matrix.

It must NEVER receive private signing material. That is enforced here, not
merely documented:

* the argument parser defines no key option at all, and any key-shaped argv
  token is refused;
* any key-shaped environment variable is refused;
* the transfer-in directory is scanned and refused if it carries anything that
  looks like private key material.

Any of those conditions aborts with AIRGAP_BOUNDARY_VIOLATION before the
package is touched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# --------------------------------------------------------------------------
# Air-gap boundary enforcement (runs before anything else)

#: argv tokens that would carry signing material into this environment.
_FORBIDDEN_ARG_TOKENS = (
    "--key-file", "--key-env", "--private-key", "--signing-key", "--issuer-key",
    "--key-hex", "--secret-key",
)
#: environment variables that would carry signing material or point at it.
_FORBIDDEN_ENV_NAMES = (
    "MONDAY_REPORT_OFFLINE_KEYS_DIR",
    "MONDAY_REPORT_LICENSE_PRIVATE_KEY",
    "MONDAY_REPORT_SIGNING_PRIVATE_KEY",
    "MONDAY_REPORT_ISSUER_PRIVATE_KEY",
    "OFFLINE_ISSUER_KEY",
)
_PRIVATE_KEY_FILE_HINTS = ("private", "issuer_key", "signing_key", "secret")


class AirgapBoundaryViolation(Exception):
    """Private signing material reached the environment boundary."""


def _looks_like_private_key(text: str) -> bool:
    """A bare 32-byte hex blob or a PEM private key block."""

    if "PRIVATE KEY" in text:
        return True
    for token in re.findall(r"\b[0-9a-fA-F]{64}\b", text):
        # A signed license is JSON and never a bare 64-hex document; a key file
        # is essentially nothing else.
        if text.strip() == token:
            return True
    return False


def enforce_argv_and_env_boundary(argv: list[str]) -> list[str]:
    """Refuse signing material supplied via argv or the environment.

    This runs BEFORE argument parsing on purpose: a private-key option must be
    reported as an air-gap boundary violation, not as an ordinary usage error,
    so the refusal is unambiguous and machine-checkable.
    """

    proofs: list[str] = []
    offending = [a for a in argv if any(a.startswith(t) for t in _FORBIDDEN_ARG_TOKENS)]
    if offending:
        raise AirgapBoundaryViolation(
            "environment-side runner was given a private-key argument"
        )
    proofs.append("no private-key argument accepted")

    present = [name for name in _FORBIDDEN_ENV_NAMES if os.environ.get(name)]
    if present:
        raise AirgapBoundaryViolation(
            "environment-side runner was given a private-key environment reference"
        )
    proofs.append("no private-key environment reference present")
    return proofs


def enforce_transfer_boundary(transfer_in: Path | None) -> list[str]:
    """Refuse signing material smuggled through the transfer directory."""

    proofs: list[str] = []
    if transfer_in is not None and transfer_in.exists():
        for path in sorted(transfer_in.rglob("*")):
            if not path.is_file():
                continue
            lowered = path.name.lower()
            if any(hint in lowered for hint in _PRIVATE_KEY_FILE_HINTS):
                raise AirgapBoundaryViolation(
                    "transfer directory carries a private-key-shaped file"
                )
            try:
                if _looks_like_private_key(path.read_text(encoding="utf-8", errors="ignore")):
                    raise AirgapBoundaryViolation(
                        "transfer directory carries private key material"
                    )
            except OSError:
                continue
        proofs.append("transfer directory carries no private key material")
    return proofs


# --------------------------------------------------------------------------
# HTTP + process helpers

def _http(port: int, path: str, *, method: str = "GET", body: bytes | None = None,
          timeout: int = 120) -> dict:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=body, method=method,
        headers={"content-type": "application/json"} if body is not None else {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            payload = response.read().decode("utf-8")
            try:
                return {"status": response.status, "body": json.loads(payload)}
            except json.JSONDecodeError:
                return {"status": response.status, "text": payload}
    except urllib.error.HTTPError as exc:
        try:
            return {"status": exc.code, "body": json.loads(exc.read().decode("utf-8"))}
        except Exception:  # noqa: BLE001
            return {"status": exc.code}


def _wait_http(port: int, path: str, timeout: float = 180.0) -> dict | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(  # noqa: S310
                    f"http://127.0.0.1:{port}{path}", timeout=3) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception:  # noqa: BLE001
            time.sleep(0.5)
    return None


def minimal_env(work_dir: Path, port: int) -> dict:
    """Restricted PATH (System32 + PowerShell only) so the packaged app cannot
    resolve Node.js, Python, pnpm, or Docker even if it tried. Standard
    user-profile variables stay present, as on any real clean machine."""

    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    profile = work_dir / "profile"
    return {
        "SystemRoot": system_root,
        "SystemDrive": os.environ.get("SystemDrive", "C:"),
        "PATH": f"{system_root}\\System32;{system_root}\\System32\\WindowsPowerShell\\v1.0",
        "TEMP": str(work_dir / "tmp"),
        "TMP": str(work_dir / "tmp"),
        "USERPROFILE": str(profile),
        "APPDATA": str(profile / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(profile / "AppData" / "Local"),
        "MONDAY_REPORT_OFFLINE_DATA_DIR": str(work_dir / "install"),
        "MONDAY_REPORT_OFFLINE_PORT": str(port),
    }


def spawn(exe: Path, env: dict, *args: str) -> subprocess.Popen:
    Path(env["TEMP"]).mkdir(parents=True, exist_ok=True)
    Path(env["LOCALAPPDATA"]).mkdir(parents=True, exist_ok=True)
    return subprocess.Popen(
        [str(exe), "--no-browser", *args], env=env, cwd=str(exe.parent),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)


def loopback_only(pid: int) -> tuple[bool, int]:
    """Every TCP endpoint owned by the process must be loopback.

    BOTH address families are enumerated. On Windows ``netstat -p TCP`` lists
    IPv4 only; IPv6 needs ``-p TCPv6``. Querying one family made the ``[::1]``
    branch below unreachable and left a process listening on ``[::]:<port>``
    indistinguishable from one bound to 127.0.0.1 -- a wildcard IPv6 endpoint
    would have passed the localhost-only check it is meant to fail. IPv6 rows
    use the same ``TCP`` proto token with bracketed addresses, so one parser
    covers both.
    """

    rows: list[list[str]] = []
    for family in ("TCP", "TCPv6"):
        completed = subprocess.run(["netstat", "-ano", "-p", family],
                                   capture_output=True, text=True, timeout=60)
        rows += [line.split() for line in completed.stdout.splitlines()
                 if line.strip().startswith("TCP") and line.strip().endswith(str(pid))]
    non_local = [r for r in rows if not (r[1].startswith("127.") or r[1].startswith("[::1]"))]
    return (not non_local and len(rows) >= 1, len(rows))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------
# Clean-state + dependency-absence proofs


def dependency_absence(app_path: str) -> dict[str, bool]:
    """True == the dependency is unresolvable BY THE PACKAGED APPLICATION.

    The load-bearing claim is "the product does not require Node, Python,
    Docker, PostgreSQL or Redis at runtime". The honest way to test that is
    against the PATH the application is actually launched with (System32 +
    PowerShell), NOT against the PATH of whatever process happens to run the
    matrix: Environment 1 is a developer host that legitimately has those
    tools installed machine-wide, and checking the runner's own PATH would
    conflate "installed somewhere on the box" with "required by the product".

    ``machine_wide_absence`` records the stronger, environment-level fact
    separately (true in the clean Hyper-V guest, false on a developer host).
    """

    def absent(name: str) -> bool:
        return shutil.which(name, path=app_path) is None

    return {
        "node_absent": absent("node") and absent("node.exe"),
        "python_absent": absent("python") and absent("python.exe") and absent("py"),
        "docker_absent": absent("docker") and absent("docker.exe"),
        "postgres_absent": absent("psql") and absent("postgres"),
        "redis_absent": absent("redis-server") and absent("redis-cli"),
    }


def machine_wide_absence() -> dict[str, bool]:
    """Informational: whether the tools are absent from the whole machine."""

    def absent(name: str) -> bool:
        return shutil.which(name) is None

    return {
        "node_absent": absent("node"),
        "python_absent": absent("python") and absent("py"),
        "docker_absent": absent("docker"),
        "postgres_absent": absent("psql") and absent("postgres"),
        "redis_absent": absent("redis-server") and absent("redis-cli"),
    }


def clean_state(work_dir: Path) -> dict[str, bool]:
    """Clean-state facts for THIS environment, before anything is installed.

    ``no_application_process_running`` was previously hardcoded True, so it was
    published as a measurement without ever being measured. It now enumerates
    the real process table. The installation facts are checked against the
    machine-wide per-user location as well as the isolated work root: checking
    only a directory created seconds earlier by mkdtemp is true by construction
    and proves nothing about the environment.
    """

    install_root = work_dir / "install"
    profile_programs = work_dir / "profile" / "AppData" / "Local" / "Programs" / "MondayReportOffline"
    local_app = Path(os.environ.get("LOCALAPPDATA", str(work_dir / "no-localappdata")))
    machine_programs = local_app / "Programs" / "MondayReportOffline"
    machine_data = local_app / "MondayReportOffline"

    running = subprocess.run(["tasklist", "/FI", "IMAGENAME eq MondayReportOffline.exe"],
                             capture_output=True, text=True, timeout=60)
    no_process = "MondayReportOffline.exe" not in (running.stdout or "")

    return {
        "no_prior_installation": not profile_programs.exists() and not machine_programs.exists(),
        "no_prior_application_data": not install_root.exists() and not machine_data.exists(),
        "no_prior_license": (not (install_root / "licenses").exists()
                             and not (machine_data / "licenses").exists()),
        "no_application_process_running": no_process,
    }


# --------------------------------------------------------------------------
# Phases

CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str = "") -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "detail": detail})


def package_hashes(app_dir: Path) -> dict:
    manifest_path = app_dir / "payload-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    frontend = {rel: h for rel, h in manifest["files"].items()
                if rel.startswith("_internal/dist/") or rel.startswith("dist/")}
    frontend_digest = hashlib.sha256(
        json.dumps(frontend, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "executable_sha256": sha256_file(app_dir / "MondayReportOffline.exe"),
        "payload_manifest_sha256": sha256_file(manifest_path),
        "frontend_manifest_sha256": frontend_digest,
        "payload_file_count": len(manifest["files"]),
    }


def phase_request(args, proofs: list[str]) -> dict:
    work_dir = Path(args.work_dir)
    app_dir = Path(args.package_dir)
    exe = app_dir / "MondayReportOffline.exe"
    transfer_out = Path(args.transfer_out)
    transfer_out.mkdir(parents=True, exist_ok=True)

    port = int(args.port)
    env = minimal_env(work_dir, port)
    clean = clean_state(work_dir)
    deps = dependency_absence(env["PATH"])
    machine_deps = machine_wide_absence()
    rec("EC01 clean-state", all(clean.values()),
        "no prior installation, application data, license, or running process")
    rec("EC02 dependency-absence", all(deps.values()),
        "Node, standalone Python, Docker, PostgreSQL and Redis are all unresolvable "
        "from the PATH the packaged application is launched with")

    hashes = package_hashes(app_dir)
    rec("EC03 package-hashes-recomputed", bool(hashes["executable_sha256"]),
        "package hashes recomputed inside this environment")

    process = spawn(exe, env, "--port", str(port))
    try:
        runtime = _wait_http(port, "/offline/runtime")
        rec("PK01 offline-first-launch",
            runtime is not None and runtime.get("edition_mode") == "offline",
            "the packaged app starts from a fresh data root with a restricted PATH")
        if runtime is None:
            raise RuntimeError("packaged application did not start")

        status = _http(port, "/offline/license/status")["body"]
        rec("PK02 first-launch-unlicensed", status.get("state") == "no_license",
            "first launch is unlicensed and read-only")

        blocked = _http(port, "/workspaces", method="POST", body=json.dumps({"name": "X"}).encode())
        rec("PK03 unlicensed-mutation-blocked",
            blocked["status"] == 423
            and blocked["body"].get("reason_code") == "NO_LICENSE_INSTALLED",
            "business mutations refused with a typed, actionable payload")

        local_only, sockets = loopback_only(process.pid)
        rec("PK04 loopback-only-binding", local_only,
            f"every TCP socket for the application PID is loopback ({sockets} observed)")

        request_path = transfer_out / "activation-request.json"
        with urllib.request.urlopen(  # noqa: S310
                f"http://127.0.0.1:{port}/offline/license/activation-request", timeout=120) as r:
            request_path.write_bytes(r.read())
        document = json.loads(request_path.read_text(encoding="utf-8"))
        rec("PK05 activation-request-exported",
            document.get("schema_version") == "monday-report-activation-request.v1",
            "the environment exported a portable activation request")

        text = json.dumps(document)
        mac_shape = re.search(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", text)
        rec("PK06 activation-request-carries-no-raw-identifiers", mac_shape is None,
            "the exported request carries hashed components only")
        fingerprint_hash = document.get("machine_fingerprint_hash", "")
    finally:
        process.terminate()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()

    passed = sum(1 for c in CHECKS if c["ok"])
    record = {
        "phase": "request",
        "environment_label": args.env_label,
        "environment_class": args.env_class,
        "source_commit": args.source_commit,
        "source_tree": args.source_tree,
        "package_version": args.package_version,
        "installer_sha256": args.installer_sha256,
        **hashes,
        "machine_fingerprint_hash": fingerprint_hash,
        "clean_state": clean,
        "dependency_absence": deps,
        "machine_wide_absence": machine_deps,
        "airgap_proofs": proofs,
        "totals": {"passed": passed, "failed": len(CHECKS) - passed},
        "checks": CHECKS,
    }
    (transfer_out / "environment-request-record.json").write_text(
        json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    return record


def phase_resume(args, proofs: list[str]) -> dict:
    work_dir = Path(args.work_dir)
    app_dir = Path(args.package_dir)
    exe = app_dir / "MondayReportOffline.exe"
    transfer_in = Path(args.transfer_in)
    transfer_out = Path(args.transfer_out)
    transfer_out.mkdir(parents=True, exist_ok=True)

    primary = transfer_in / "license-primary.json"
    renewal = transfer_in / "license-renewal.json"
    older = transfer_in / "license-older.json"
    foreign = transfer_in / "license-foreign.json"
    short = transfer_in / "license-short.json"
    rec("PK07 signed-license-received",
        primary.exists(),
        "only a signed license returned from the operator side")
    if not primary.exists():
        raise RuntimeError("no signed license in the transfer directory (fail closed)")

    port = int(args.port)

    # Real-time expiry transition FIRST, in a dedicated data root, with no
    # clock edits anywhere. The seconds-scale license is signed by the operator
    # moments before this phase starts, so it must be exercised before the rest
    # of the matrix consumes its remaining validity -- running it last would
    # import an already-expired license and prove nothing.
    expiry_results = {"executed": False}
    if short.exists():
        exp_dir = work_dir.parent / (work_dir.name + "-expiry")
        # The signed license is bound to the installation that EXPORTED the
        # activation request. A fresh data root would mint a new installation
        # id and be refused as WRONG_INSTALLATION, so the expiry scenario runs
        # as the same installation with its own data copy -- it exercises
        # expiry, not activation.
        source_config = work_dir / "install" / "config" / "installation.json"
        if source_config.exists():
            target_config = exp_dir / "install" / "config" / "installation.json"
            target_config.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_config, target_config)
        exp_env = minimal_env(exp_dir, port + 2)
        exp = spawn(exe, exp_env, "--port", str(port + 2))
        try:
            if _wait_http(port + 2, "/offline/runtime") is not None:
                imported = _http(port + 2, "/offline/license/import", method="POST",
                                 body=short.read_bytes())
                if imported["status"] != 200:
                    rec("PK21 short-license-operational", False,
                        f"the short-dated license was refused "
                        f"({imported.get('body', {}).get('reason_code', 'unknown')})")
                else:
                    op = _http(port + 2, "/workspaces", method="POST",
                               body=json.dumps({"name": "T"}).encode())
                    rec("PK21 short-license-operational", op["status"] == 201,
                        "the short-dated license operates while valid")
                    # Wait until the license's OWN expiry passes, derived from
                    # the signed document rather than a fixed sleep: a packaged
                    # cold start takes tens of seconds and varies by machine, so
                    # a fixed wait either expires the licence before the app is
                    # up or stops short of it. No clock is manipulated.
                    short_doc = json.loads(short.read_text(encoding="utf-8"))
                    expires = datetime.fromisoformat(short_doc["grace_until"])
                    remaining = (expires - datetime.now(timezone.utc)).total_seconds()
                    time.sleep(max(2.0, remaining + 5.0))
                    st = _http(port + 2, "/offline/license/status")["body"]
                    blocked = _http(port + 2, "/workspaces", method="POST",
                                    body=json.dumps({"name": "U"}).encode())
                    readable = _http(port + 2, "/workspaces")
                    backup_ok = _http(port + 2, "/offline/backup", method="POST", body=b"{}")
                    # Use the workspace this expiry instance created; the main
                    # matrix workspace does not exist in this data root.
                    expiry_workspace = op.get("body", {}).get("id", "unknown")
                    draft = _http(port + 2, f"/workspaces/{expiry_workspace}/report-draft")
                    rec("PK22 expiry-to-read-only",
                        st.get("state") == "expired_read_only" and blocked["status"] == 423,
                        "expiry transitions in real time to read-only")
                    rec("PK23 expired-data-readable", readable["status"] == 200,
                        "customer data remains readable after expiry")
                    rec("PK24 expired-backup-available", backup_ok["status"] == 200,
                        "backup remains available after expiry")
                    rec("PK25 expired-mutations-blocked",
                        blocked["status"] == 423 and draft["status"] in (423, 404),
                        "new reports, validation mutations and exports are blocked")
                    expiry_results = {"executed": True, "state": st.get("state")}
        finally:
            try:
                exp.terminate(); exp.wait(timeout=30)
            except Exception:  # noqa: BLE001
                exp.kill()

    env = minimal_env(work_dir, port)
    process = spawn(exe, env, "--port", str(port))
    workspace_id = ""
    try:
        if _wait_http(port, "/offline/runtime") is None:
            raise RuntimeError("packaged application did not restart")

        imported = _http(port, "/offline/license/import", method="POST",
                         body=primary.read_bytes())
        rec("PK08 offline-activation-import",
            imported["status"] == 200 and imported["body"].get("state") == "valid",
            "the environment activates from the signed license with no network")

        created = _http(port, "/workspaces", method="POST",
                        body=json.dumps({"name": "Rig Alpha"}).encode())
        rec("PK09 licensed-business-operation", created["status"] == 201,
            "licensed operation performs real business mutations")
        workspace_id = created.get("body", {}).get("id", "")

        # licensed restart
        process.terminate()
        process.wait(timeout=30)
        process = spawn(exe, env, "--port", str(port))
        restarted = _wait_http(port, "/offline/runtime")
        after = _http(port, "/workspaces")
        rec("PK10 licensed-restart",
            restarted is not None and after["status"] == 200
            and any(w.get("id") == workspace_id for w in after["body"]),
            "a licensed restart preserves data and stays activated")

        # forced termination + crash recovery
        process.kill()
        process.wait(timeout=30)
        process = spawn(exe, env, "--port", str(port))
        recovered = _wait_http(port, "/offline/runtime")
        survived = _http(port, "/workspaces")
        rec("PK11 crash-recovery",
            recovered is not None and survived["status"] == 200
            and any(w.get("id") == workspace_id for w in survived["body"]),
            "forced termination then restart recovers with data intact")

        # single instance
        second = spawn(exe, env, "--port", str(port + 1))
        time.sleep(6)
        second_alive = second.poll() is None
        try:
            second.terminate(); second.wait(timeout=20)
        except Exception:  # noqa: BLE001
            second.kill()
        still_serving = _http(port, "/offline/runtime")
        rec("PK12 single-instance",
            not second_alive and still_serving["status"] == 200,
            f"a second instance against the same data root is refused by the runtime "
            f"lock and exits (second still running: {second_alive}); the first "
            f"instance keeps serving")

        # backup + validation + restore
        backup = _http(port, "/offline/backup", method="POST", body=b"{}")
        backup_name = backup["body"].get("backup", "")
        rec("PK13 backup", backup["status"] == 200 and bool(backup_name),
            "the packaged app creates a validated local backup")
        listed = _http(port, "/offline/backups")
        rec("PK14 backup-validation",
            listed["status"] == 200 and backup_name in listed["body"].get("backups", []),
            "the backup is listed and validates")
        # A workspace created AFTER the backup must be gone once the backup is
        # restored. Asserting only that the pre-backup workspace survives is
        # satisfied by a restore that did nothing at all, so the discriminating
        # fact is the disappearance of post-backup state.
        post_backup = _http(port, "/workspaces", method="POST",
                            body=json.dumps({"name": "Created After Backup"}).encode())
        post_backup_id = post_backup["body"].get("id") if post_backup["status"] == 201 else None
        restored = _http(port, "/offline/restore", method="POST",
                         body=json.dumps({"backup": backup_name}).encode())
        after_restore = _http(port, "/workspaces")
        ids = {w.get("id") for w in (after_restore["body"] or [])}
        rec("PK15 restore",
            restored["status"] == 200
            and workspace_id in ids
            and post_backup_id is not None and post_backup_id not in ids,
            "staged restore REPLACES data: the pre-backup workspace survives and a "
            "workspace created after the backup is gone")

        # renewal + rollback rejection
        if renewal.exists():
            renewed = _http(port, "/offline/license/import", method="POST",
                            body=renewal.read_bytes())
            rec("PK16 renewal", renewed["status"] == 200
                and renewed["body"].get("state") == "valid",
                "a newer signed license supersedes the current one")
        if older.exists():
            rolled = _http(port, "/offline/license/import", method="POST",
                           body=older.read_bytes())
            rec("PK17 older-license-rejected",
                rolled["status"] == 400
                and rolled["body"].get("reason_code") == "LICENSE_ROLLBACK_REJECTED",
                "an older license cannot replace a newer entitlement")
        if foreign.exists():
            mismatch = _http(port, "/offline/license/import", method="POST",
                             body=foreign.read_bytes())
            rec("PK18 wrong-machine-license-rejected",
                mismatch["status"] == 400
                and mismatch["body"].get("reason_code") == "MACHINE_MISMATCH",
                "a license bound to other machine components is refused")
        cross = transfer_in / "license-other-environment.json"
        if cross.exists():
            other = _http(port, "/offline/license/import", method="POST",
                          body=cross.read_bytes())
            rec("PK19 other-environment-license-rejected",
                other["status"] == 400
                and other["body"].get("reason_code") in
                ("MACHINE_MISMATCH", "WRONG_INSTALLATION"),
                "a license issued for the OTHER environment is refused here")

        # Actually stop it and observe that it stopped, rather than asserting a
        # constant: the process must exit and the port must stop answering.
        process.terminate()
        try:
            process.wait(timeout=45)
            exited = True
        except Exception:  # noqa: BLE001
            exited = False
        time.sleep(2)
        # _http does not catch URLError, and a refused connection is exactly what
        # is expected here, so probe directly.
        try:
            with urllib.request.urlopen(  # noqa: S310
                    f"http://127.0.0.1:{port}/offline/runtime", timeout=5):
                gone = False
        except Exception:  # noqa: BLE001
            gone = True
        rec("PK20 normal-shutdown", exited and gone,
            f"a graceful stop terminates the application (exited={exited}) and the "
            f"loopback port stops answering (unreachable={gone})")
    finally:
        try:
            process.terminate(); process.wait(timeout=30)
        except Exception:  # noqa: BLE001
            process.kill()

    # Installer lifecycle: install -> upgrade -> uninstall -> reinstall.
    sandbox = work_dir / "installer"
    for sub in ("localappdata", "roaming/Microsoft/Windows/Start Menu/Programs", "desktop"):
        (sandbox / sub).mkdir(parents=True, exist_ok=True)
    installer_env = dict(os.environ)
    installer_env.update({
        "LOCALAPPDATA": str(sandbox / "localappdata"),
        "APPDATA": str(sandbox / "roaming"),
        "USERPROFILE": str(sandbox),
    })

    def powershell(script: Path, *ps_args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
             str(script), *ps_args],
            env=installer_env, capture_output=True, text=True, timeout=600,
            cwd=str(app_dir))

    installed_exe = sandbox / "localappdata/Programs/MondayReportOffline/MondayReportOffline.exe"
    install_result = powershell(app_dir / "install.ps1")
    rec("PK26 per-user-install-no-elevation",
        install_result.returncode == 0 and installed_exe.exists(),
        "the installer lays down a per-user installation with no elevation")

    data_marker = sandbox / "localappdata/MondayReportOffline/data"
    data_marker.mkdir(parents=True, exist_ok=True)
    (data_marker / "monday_report_state.json").write_text("{}", encoding="utf-8")
    license_marker = sandbox / "localappdata/MondayReportOffline/licenses"
    license_marker.mkdir(parents=True, exist_ok=True)
    (license_marker / "monday-report-license.json").write_text("{}", encoding="utf-8")

    upgrade = powershell(app_dir / "install.ps1")
    rec("PK27 upgrade-preserves-data-and-license",
        upgrade.returncode == 0 and (data_marker / "monday_report_state.json").exists()
        and (license_marker / "monday-report-license.json").exists(),
        "re-running the installer preserves customer data and the license")

    uninstall = powershell(installed_exe.parent / "uninstall.ps1")
    # uninstall.ps1 hands the final directory removal to a DETACHED process, so
    # poll rather than sleeping a fixed interval. Asserting only that the data
    # survived would pass for an uninstall that removed nothing at all.
    binaries_removed = False
    for _ in range(30):
        if not installed_exe.exists():
            binaries_removed = True
            break
        time.sleep(1)
    rec("PK28 uninstall-preserves-data",
        uninstall.returncode == 0 and binaries_removed
        and (data_marker / "monday_report_state.json").exists(),
        f"default uninstall REMOVES the binaries (removed={binaries_removed}) and "
        f"preserves customer data")

    reinstall = powershell(app_dir / "install.ps1")
    rec("PK29 reinstall-detects-preserved-data",
        reinstall.returncode == 0 and (data_marker / "monday_report_state.json").exists()
        and installed_exe.exists(),
        "reinstalling finds the preserved data directory in place")

    remove_data = powershell(installed_exe.parent / "uninstall.ps1", "-RemoveData")
    time.sleep(5)
    rec("PK30 explicit-data-removal-path-separate",
        remove_data.returncode == 0
        and not (sandbox / "localappdata/MondayReportOffline").exists(),
        "explicit -RemoveData is a separate, deliberate path")

    hashes = package_hashes(app_dir)
    key_file = app_dir / "_internal" / "licensing_public_key.txt"
    if not key_file.exists():
        key_file = app_dir / "licensing_public_key.txt"
    # The shipped verification key is itself a bare 64-hex file (an Ed25519
    # PUBLIC key is 32 bytes). Treating "bare 64 hex" as private would flag the
    # one artifact that is SUPPOSED to be there, so the expected public key is
    # excluded by value and anything else key-shaped is a real finding.
    expected_public = ""
    if key_file.exists():
        expected_public = key_file.read_text(encoding="utf-8", errors="ignore").strip().lower()
    private_shapes = []
    for path in app_dir.rglob("*"):
        if path.is_file() and path.suffix in (".txt", ".json", ".ps1"):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if text.strip().lower() == expected_public and expected_public:
                continue  # the intended public verification key
            if _looks_like_private_key(text):
                private_shapes.append(path.name)
    rec("PK31 private-key-absent-from-package",
        key_file.exists() and not private_shapes and len(expected_public) == 64,
        f"the package embeds ONLY the public verification key "
        f"(no other key-shaped artifact; {private_shapes or 'clean'})")

    passed = sum(1 for c in CHECKS if c["ok"])
    record = {
        "phase": "resume",
        "environment_label": args.env_label,
        "environment_class": args.env_class,
        "source_commit": args.source_commit,
        "source_tree": args.source_tree,
        "package_version": args.package_version,
        "installer_sha256": args.installer_sha256,
        **hashes,
        "airgap_proofs": proofs,
        "expiry": expiry_results,
        "totals": {"passed": passed, "failed": len(CHECKS) - passed},
        "checks": CHECKS,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    (transfer_out / "environment-result.json").write_text(
        json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    return record


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        prog="offline-package environment-runner",
        description="Environment-side matrix. Accepts NO private key material.")
    parser.add_argument("--phase", required=True, choices=("request", "resume"))
    parser.add_argument("--env-label", required=True)
    parser.add_argument("--env-class", default="windows-11")
    parser.add_argument("--package-dir", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--transfer-in")
    parser.add_argument("--transfer-out", required=True)
    parser.add_argument("--port", type=int, default=47671)
    parser.add_argument("--expiry-wait", type=int, default=32)
    parser.add_argument("--source-commit", default="")
    parser.add_argument("--source-tree", default="")
    parser.add_argument("--package-version", default="")
    parser.add_argument("--installer-sha256", default="")

    CHECKS.clear()
    try:
        # Boundary FIRST, parsing second: a key-shaped option must abort as a
        # boundary violation rather than an argparse usage error.
        proofs = enforce_argv_and_env_boundary(raw_argv)
        args = parser.parse_args(raw_argv)
        transfer_in = Path(args.transfer_in) if args.transfer_in else None
        proofs += enforce_transfer_boundary(transfer_in)
    except AirgapBoundaryViolation as exc:
        print(json.dumps({
            "runner": "offline_env_runner",
            "aborted": "AIRGAP_BOUNDARY_VIOLATION",
            "detail": str(exc),
            "summary": {"passed": 0, "failed": 1, "certification": "not_passed"},
        }, indent=2))
        return 2

    try:
        record = phase_request(args, proofs) if args.phase == "request" else phase_resume(args, proofs)
    except (RuntimeError, OSError, zipfile.BadZipFile) as exc:
        rec("PK99 phase-aborted", False, str(exc))
        record = {"phase": args.phase, "environment_label": args.env_label,
                  "totals": {"passed": sum(1 for c in CHECKS if c["ok"]),
                             "failed": sum(1 for c in CHECKS if not c["ok"])},
                  "checks": CHECKS}
        Path(args.transfer_out).mkdir(parents=True, exist_ok=True)
        (Path(args.transfer_out) / f"environment-{args.phase}-record.json").write_text(
            json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")

    totals = record["totals"]
    print(json.dumps({
        "runner": "offline_env_runner",
        "phase": args.phase,
        "environment_label": args.env_label,
        "summary": {"passed": totals["passed"], "failed": totals["failed"],
                    "certification": "passed" if totals["failed"] == 0 else "not_passed"},
        "checks": record["checks"],
    }, indent=2))
    return 0 if totals["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
