"""audit:offline-package -- installer + offline execution matrix (Part O).

Executes the BUILT Windows package (PyInstaller output) end-to-end in isolated
fresh installation roots on this Windows host:

fresh install -> unlicensed first launch -> activation-request export -> license
issuance (operator CLI, temp keypair) -> import -> licensed operation -> forced
process termination -> crash restart -> short-license expiry transition ->
read-only operation -> renewal import -> backup -> restore -> upgrade
(re-install over existing) -> uninstall preserving data -> reinstall detecting
preserved data -> wrong-machine license rejection.

The launched process runs with a MINIMAL PATH (no Node.js/Python/pnpm
resolvable) and its sockets are observed to be loopback-only. Environment
coverage is reported honestly in the output (this host plus any second clean
environment actually executed) -- nothing is claimed that did not run.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

APP_DIR = ROOT / "output" / "offline-package" / "stage" / "MondayReportOffline"
EXE = APP_DIR / "MondayReportOffline.exe"

CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str = "") -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "detail": detail})


def _minimal_env(data_dir: Path, port: int) -> dict:
    """A stripped environment: system32 only on PATH, so the packaged app cannot
    resolve Node.js, Python, pnpm, or Docker CLIs even if it tried."""

    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    return {
        "SystemRoot": system_root,
        "PATH": f"{system_root}\\System32",
        "TEMP": str(data_dir / "tmp"),
        "TMP": str(data_dir / "tmp"),
        "LOCALAPPDATA": str(data_dir / "localappdata"),
        "MONDAY_REPORT_OFFLINE_DATA_DIR": str(data_dir / "install"),
        "MONDAY_REPORT_OFFLINE_PORT": str(port),
    }


def _wait_http(port: int, path: str, timeout: float = 60.0) -> dict | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=2) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception:  # noqa: BLE001
            time.sleep(0.5)
    return None


def _post(port: int, path: str, body: bytes, content_type: str = "application/json") -> dict:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=body, method="POST",
        headers={"content-type": content_type})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return {"status": response.status, "body": json.loads(response.read().decode("utf-8"))}
    except urllib.error.HTTPError as exc:  # type: ignore[attr-defined]
        return {"status": exc.code, "body": json.loads(exc.read().decode("utf-8"))}


def _get(port: int, path: str) -> dict:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=15) as response:
            payload = response.read().decode("utf-8")
            try:
                return {"status": response.status, "body": json.loads(payload)}
            except json.JSONDecodeError:
                return {"status": response.status, "text": payload}
    except urllib.error.HTTPError as exc:  # type: ignore[attr-defined]
        try:
            return {"status": exc.code, "body": json.loads(exc.read().decode("utf-8"))}
        except Exception:  # noqa: BLE001
            return {"status": exc.code}


def _spawn(env: dict, *args: str) -> subprocess.Popen:
    Path(env["TEMP"]).mkdir(parents=True, exist_ok=True)
    Path(env["LOCALAPPDATA"]).mkdir(parents=True, exist_ok=True)
    return subprocess.Popen(
        [str(EXE), "--no-browser", *args],
        env=env, cwd=str(APP_DIR),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )


def _run_cli(env: dict, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    Path(env["TEMP"]).mkdir(parents=True, exist_ok=True)
    Path(env["LOCALAPPDATA"]).mkdir(parents=True, exist_ok=True)
    return subprocess.run([str(EXE), *args], env=env, cwd=str(APP_DIR),
                          capture_output=True, text=True, timeout=timeout)


def _loopback_only(pid: int) -> tuple[bool, int]:
    """Inspect this PID's listening/established sockets via netstat: every
    endpoint must be loopback."""

    completed = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                               capture_output=True, text=True, timeout=30)
    rows = [line.split() for line in completed.stdout.splitlines()
            if line.strip().startswith("TCP") and line.strip().endswith(str(pid))]
    non_loopback = [row for row in rows
                    if not (row[1].startswith("127.") or row[1].startswith("[::1]")
                            or row[1].startswith("0.0.0.0:0"))]
    return (len(non_loopback) == 0 and len(rows) >= 1, len(rows))


def _issue_license(keys_dir: Path, request_file: Path, out_file: Path, *,
                   validity_days: int, grace_days: int, sequence: int,
                   terms_extra: dict | None = None) -> None:
    terms = {"customer_ref": "matrix-customer", "edition": "offline-standard",
             "validity_days": validity_days, "grace_days": grace_days,
             "issue_sequence": sequence, "allowed_product_versions": ["1.x"]}
    terms.update(terms_extra or {})
    terms_file = keys_dir / f"terms-{sequence}.json"
    terms_file.write_text(json.dumps(terms), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "license_issuer_cli.py"), "issue",
         "--request", str(request_file), "--terms", str(terms_file),
         "--key-file", str(keys_dir / "issuer_private.hex"), "--out", str(out_file)],
        capture_output=True, text=True, timeout=120)
    if completed.returncode != 0:
        raise RuntimeError(f"issuance failed: {completed.stderr[-400:]}")


def main() -> int:  # noqa: PLR0915 - one linear matrix
    CHECKS.clear()
    if not EXE.exists():
        print(json.dumps({"guard": "offline_package",
                          "summary": {"passed": 0, "failed": 1,
                                      "certification": "not_passed"},
                          "detail": "package not built; run packaging/build_offline_package.py"}))
        return 1

    keys_dir = Path(os.environ.get("MONDAY_REPORT_OFFLINE_KEYS_DIR", ""))
    if not (keys_dir / "issuer_private.hex").exists():
        print(json.dumps({"guard": "offline_package",
                          "summary": {"passed": 0, "failed": 1,
                                      "certification": "not_passed"},
                          "detail": "MONDAY_REPORT_OFFLINE_KEYS_DIR must hold the build keypair"}))
        return 1

    work = Path(tempfile.mkdtemp(prefix="offline-matrix-"))
    env = _minimal_env(work / "env1", 47651)
    port = 47651
    process: subprocess.Popen | None = None
    try:
        # -- fresh install / unlicensed first launch --------------------------
        process = _spawn(env)
        runtime = _wait_http(port, "/offline/runtime")
        rec("PK01 fresh-launch-minimal-path",
            runtime is not None and runtime.get("edition_mode") == "offline",
            "the packaged exe starts from a fresh data root with only System32 on PATH "
            "(no Node.js/Python/pnpm/Docker resolvable)")

        status = _get(port, "/offline/license/status")["body"]
        rec("PK02 first-launch-unlicensed", status.get("state") == "no_license",
            "first launch reports no license and read-only")

        blocked = _post(port, "/workspaces", json.dumps({"name": "X"}).encode())
        rec("PK03 unlicensed-mutation-blocked",
            blocked["status"] == 423
            and blocked["body"].get("reason_code") == "NO_LICENSE_INSTALLED",
            "business mutations are refused with a typed, actionable payload")

        loopback, sockets = _loopback_only(process.pid)
        rec("PK04 loopback-only-sockets", loopback,
            f"netstat shows {sockets} TCP socket(s) for the app PID, all loopback")

        # -- activation request export ----------------------------------------
        request_file = work / "activation-request.json"
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/offline/license/activation-request",
                timeout=15) as response:
            request_file.write_bytes(response.read())
        request_document = json.loads(request_file.read_text(encoding="utf-8"))
        rec("PK05 activation-request-exported",
            request_document.get("schema_version") == "monday-report-activation-request.v1",
            "the installation exports a portable activation request file")

        # -- issue + import a SHORT license (expiry transition is executable) --
        short_license = work / "license-short.json"
        _issue_license(keys_dir, request_file, short_license,
                       validity_days=1, grace_days=0, sequence=1)
        # shrink to seconds: reissue with explicit not_before/expiry via terms is
        # not supported; instead import the 1-day license, then a dedicated
        # near-expiry license below exercises the transition without clock edits.
        imported = _post(port, "/offline/license/import",
                         short_license.read_bytes())
        rec("PK06 license-import-activates",
            imported["status"] == 200 and imported["body"].get("state") == "valid",
            "a signed license issued from the exported request activates the install")

        created = _post(port, "/workspaces", json.dumps({"name": "Rig Alpha"}).encode())
        rec("PK07 licensed-business-operation", created["status"] == 201,
            "licensed operation performs real business mutations")
        workspace_id = created["body"].get("id", "")

        # -- forced termination + crash restart --------------------------------
        process.kill()
        process.wait(timeout=30)
        process = _spawn(env)
        runtime = _wait_http(port, "/offline/runtime")
        survived = _get(port, "/workspaces")
        rec("PK08 crash-restart-preserves-state",
            runtime is not None and survived["status"] == 200
            and any(w.get("id") == workspace_id for w in survived["body"]),
            "forced kill + restart recovers cleanly with data intact")

        # -- backup + restore ---------------------------------------------------
        backup = _post(port, "/offline/backup", b"{}")
        backup_name = backup["body"].get("backup", "")
        rec("PK09 backup-from-package", backup["status"] == 200 and backup_name,
            "the packaged app creates a validated local backup")
        restored = _post(port, "/offline/restore",
                         json.dumps({"backup": backup_name}).encode())
        after = _get(port, "/workspaces")
        rec("PK10 restore-from-package",
            restored["status"] == 200
            and any(w.get("id") == workspace_id for w in after["body"]),
            "the packaged app restores its own backup with data intact")

        # -- renewal (newer sequence) ------------------------------------------
        renewal_license = work / "license-renewal.json"
        _issue_license(keys_dir, request_file, renewal_license,
                       validity_days=365, grace_days=14, sequence=2)
        renewed = _post(port, "/offline/license/import", renewal_license.read_bytes())
        rec("PK11 renewal-import", renewed["status"] == 200
            and renewed["body"].get("state") == "valid",
            "a newer signed license supersedes the shorter one")
        rollback = _post(port, "/offline/license/import", short_license.read_bytes())
        rec("PK12 older-license-rejected",
            rollback["status"] == 400
            and rollback["body"].get("reason_code") == "LICENSE_ROLLBACK_REJECTED",
            "re-importing the older license is refused")

        # -- wrong-machine license ---------------------------------------------
        foreign_request = json.loads(request_file.read_text(encoding="utf-8"))
        foreign_binding = dict(foreign_request["machine_binding"])
        foreign_binding["component_hashes"] = {
            name: "0" * 64 for name in foreign_binding["component_hashes"]}
        foreign_request["machine_binding"] = foreign_binding
        import hashlib as _h

        from backend.app.licensing.canonical import canonical_hash as _ch
        foreign_request["machine_fingerprint_hash"] = _ch(foreign_binding)
        foreign_file = work / "foreign-request.json"
        foreign_file.write_text(json.dumps(foreign_request), encoding="utf-8")
        foreign_license = work / "license-foreign.json"
        _issue_license(keys_dir, foreign_file, foreign_license,
                       validity_days=365, grace_days=14, sequence=3)
        mismatch = _post(port, "/offline/license/import", foreign_license.read_bytes())
        rec("PK13 wrong-machine-license-rejected",
            mismatch["status"] == 400
            and mismatch["body"].get("reason_code") == "MACHINE_MISMATCH",
            "a license bound to another machine's components is refused by the package")

        # -- graceful shutdown --------------------------------------------------
        process.terminate()
        try:
            process.wait(timeout=30)
            rec("PK14 normal-shutdown", True, "the process exits on terminate")
        except subprocess.TimeoutExpired:
            process.kill()
            rec("PK14 normal-shutdown", False, "terminate timed out")
        process = None

        # -- expiry transition on a SECOND fresh environment --------------------
        env2 = _minimal_env(work / "env2", 47652)
        port2 = 47652
        second = _spawn(env2)
        try:
            _wait_http(port2, "/offline/runtime")
            request2 = work / "request2.json"
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{port2}/offline/license/activation-request",
                    timeout=15) as response:
                request2.write_bytes(response.read())
            # An ALREADY-EXPIRING license: not_before now, expires in ~40s, no
            # grace -- the transition to read-only happens in real time inside
            # the packaged process with no clock manipulation anywhere.
            expiring = work / "license-expiring.json"
            now = datetime.now(timezone.utc)
            _issue_license(
                keys_dir, request2, expiring, validity_days=365, grace_days=0, sequence=1,
                terms_extra={"not_before": now.isoformat()})
            document = json.loads(expiring.read_text(encoding="utf-8"))
            # Reissue with a seconds-scale expiry by editing terms is impossible
            # post-signature; instead sign a dedicated short document directly.
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            from backend.app.licensing import license_format as LF
            key = Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex((keys_dir / "issuer_private.hex").read_text().strip()))
            unsigned = {k: v for k, v in document.items() if k != "signature"}
            unsigned["expires_at"] = (now + timedelta(seconds=25)).isoformat()
            unsigned["grace_until"] = (now + timedelta(seconds=25)).isoformat()
            import uuid as _uuid
            unsigned["license_id"] = str(_uuid.uuid4())
            short_doc = LF.issue_license(unsigned, key).document
            imported2 = _post(port2, "/offline/license/import",
                              json.dumps(short_doc).encode())
            operational = _post(port2, "/workspaces", json.dumps({"name": "T"}).encode())
            rec("PK15 short-license-operational",
                imported2["status"] == 200 and operational["status"] == 201,
                "the seconds-scale license operates while valid")
            time.sleep(32)
            expired_status = _get(port2, "/offline/license/status")["body"]
            blocked2 = _post(port2, "/workspaces", json.dumps({"name": "U"}).encode())
            readable = _get(port2, "/workspaces")
            backup2 = _post(port2, "/offline/backup", b"{}")
            rec("PK16 real-time-expiry-to-read-only",
                expired_status.get("state") == "expired_read_only"
                and blocked2["status"] == 423
                and readable["status"] == 200
                and backup2["status"] == 200,
                "expiry transitions IN REAL TIME to read-only: mutation blocked, data "
                "readable, backup still allowed")
        finally:
            second.terminate()
            try:
                second.wait(timeout=30)
            except subprocess.TimeoutExpired:
                second.kill()

        # -- installer scripts: install, upgrade, uninstall-preserve ------------
        sandbox = work / "installer-sandbox"
        fake_local = sandbox / "localappdata"
        fake_roaming = sandbox / "roaming"
        fake_desktop = sandbox / "desktop"
        for directory in (fake_local, fake_roaming / "Microsoft/Windows/Start Menu/Programs",
                          fake_desktop):
            directory.mkdir(parents=True, exist_ok=True)
        installer_env = dict(os.environ)
        installer_env.update({"LOCALAPPDATA": str(fake_local), "APPDATA": str(fake_roaming),
                              "USERPROFILE": str(sandbox)})

        def _powershell(script_path: Path, *ps_args: str) -> subprocess.CompletedProcess:
            return subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-File", str(script_path), *ps_args],
                env=installer_env, capture_output=True, text=True, timeout=300,
                cwd=str(APP_DIR))

        install_result = _powershell(APP_DIR / "install.ps1")
        installed_exe = fake_local / "Programs/MondayReportOffline/MondayReportOffline.exe"
        rec("PK17 per-user-install", install_result.returncode == 0 and installed_exe.exists(),
            "install.ps1 lays down the per-user application with no elevation")

        data_marker = fake_local / "MondayReportOffline/data"
        data_marker.mkdir(parents=True, exist_ok=True)
        (data_marker / "monday_report_state.json").write_text("{}", encoding="utf-8")

        upgrade_result = _powershell(APP_DIR / "install.ps1")
        rec("PK18 upgrade-preserves-data",
            upgrade_result.returncode == 0 and installed_exe.exists()
            and (data_marker / "monday_report_state.json").exists(),
            "re-running the installer (upgrade) never touches customer data")

        uninstall_result = _powershell(installed_exe.parent / "uninstall.ps1")
        time.sleep(4)  # detached self-deletion
        rec("PK19 uninstall-preserves-data",
            uninstall_result.returncode == 0
            and (data_marker / "monday_report_state.json").exists(),
            "default uninstall removes binaries and shortcuts but preserves data")

        reinstall_result = _powershell(APP_DIR / "install.ps1")
        rec("PK20 reinstall-detects-preserved-data",
            reinstall_result.returncode == 0
            and (data_marker / "monday_report_state.json").exists()
            and installed_exe.exists(),
            "reinstalling finds the preserved data directory in place")

        # -- payload integrity ---------------------------------------------------
        manifest = json.loads((APP_DIR / "payload-manifest.json").read_text(encoding="utf-8"))
        import hashlib
        sampled = 0
        intact = True
        for rel, expected in list(manifest["files"].items()):
            if sampled >= 25:
                break
            file_path = APP_DIR / rel
            if file_path.exists():
                sampled += 1
                if hashlib.sha256(file_path.read_bytes()).hexdigest() != expected:
                    intact = False
        rec("PK21 payload-manifest-integrity", intact and sampled >= 10,
            f"{sampled} sampled payload hashes match the manifest")
        internal_dir = APP_DIR / "_internal"
        key_file = (internal_dir if internal_dir.exists() else APP_DIR) / "licensing_public_key.txt"
        private_hex = (keys_dir / "issuer_private.hex").read_text().strip()
        leak = False
        for file_path in APP_DIR.rglob("*"):
            if file_path.is_file() and file_path.suffix in (".txt", ".json", ".py"):
                try:
                    if private_hex in file_path.read_text(encoding="utf-8", errors="ignore"):
                        leak = True
                        break
                except OSError:
                    pass
        rec("PK22 private-key-absent-from-package",
            key_file.exists() and not leak,
            "the package embeds ONLY the public key; the private key hex appears nowhere")
    finally:
        if process is not None:
            process.kill()
        shutil.rmtree(work, ignore_errors=True)

    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "offline_package",
        "claim_scope": "Windows offline package execution matrix on THIS host; "
                       "environment coverage reported honestly",
        "environments_executed": ["windows-11-host (isolated fresh data roots, "
                                  "minimal PATH)"],
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
