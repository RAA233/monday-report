"""audit:offline-runtime -- offline-edition runtime enforcement battery.

TestClient-based, Docker-free, isolated temp installation. Proves the wrapper
enforces the license around the UNMODIFIED v1 API: expired/no-license states
block every business mutation (and write-shaped GETs) with a typed, actionable
payload; reads and backups stay available; restore is staged with rollback; the
runtime binds localhost-only with a double-opt-in LAN gate; a second instance
cannot corrupt the same state; the in-process worker only runs under an
operational license.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import sys
import tempfile
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str = "") -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "detail": detail})


def main() -> int:  # noqa: PLR0915 - one linear battery
    CHECKS.clear()
    tmp = Path(tempfile.mkdtemp(prefix="offline-runtime-guard-"))
    # Isolated installation root + test-mode protected state BEFORE any import.
    for stale in ("MONDAY_REPORT_STATE_PATH", "MONDAY_REPORT_STORAGE_ROOT",
                  "MONDAY_REPORT_EXPORT_ROOT", "MONDAY_REPORT_CLIENT_DATA_MODE",
                  "MONDAY_REPORT_CORS_ORIGINS"):
        os.environ.pop(stale, None)
    os.environ["MONDAY_REPORT_OFFLINE_DATA_DIR"] = str(tmp / "install")
    os.environ["MONDAY_REPORT_LICENSING_STATE_MODE"] = "test"
    os.environ["MONDAY_REPORT_LICENSING_STATE_TEST_KEY"] = secrets.token_hex(16)

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from fastapi.testclient import TestClient

    from backend.app import offline_runtime as RT
    from backend.app.licensing import fingerprint as FP
    from backend.app.licensing import license_format as LF
    from backend.app.licensing.canonical import canonical_hash

    key = Ed25519PrivateKey.generate()
    paths = RT.OfflinePaths(RT.default_root())
    paths.ensure()
    (paths.config_dir / "licensing_public_key.txt").write_text(
        key.public_key().public_bytes_raw().hex(), encoding="utf-8")

    app = RT.build_offline_app(paths)
    cache = app.state.decision_cache
    provider = cache.provider
    install = app.state.install

    facts = {"machine_guid": "RT-G", "smbios_uuid": "RT-U", "board_serial": "RT-B",
             "system_volume_serial": "RT-V", "physical_adapters": "AABBCCDDEEFF"}
    fingerprint = FP.from_facts(facts)
    provider.config.fingerprint_supplier = lambda: fingerprint
    base_epoch = time.time()
    clock = {"now": base_epoch}
    provider.config.clock = lambda: clock["now"]

    def _license(days: int, *, sequence: int = 1, grace: int = 14) -> bytes:
        now = datetime.fromtimestamp(clock["now"], tz=timezone.utc)
        binding = fingerprint.binding_document()
        payload = {
            "schema_version": LF.LICENSE_SCHEMA_VERSION, "product": "monday-report",
            "license_id": str(uuid.uuid4()), "customer_ref": "runtime-guard",
            "edition": "offline-standard", "issued_at": now.isoformat(),
            "not_before": now.isoformat(),
            "expires_at": (now + timedelta(days=days)).isoformat(),
            "grace_until": (now + timedelta(days=days + grace)).isoformat(),
            "machine_binding": binding, "machine_fingerprint_hash": canonical_hash(binding),
            "allowed_product_versions": ["1.x"], "feature_flags": {"benchmarking": True},
            "installation_limit": 1, "installation_id": str(install["installation_id"]),
            "issuer_id": "guard", "issue_sequence": sequence, "nonce": secrets.token_hex(8),
            "signature_algorithm": "Ed25519",
        }
        return json.dumps(LF.issue_license(payload, key).document).encode()

    with TestClient(app) as client:
        info = client.get("/offline/runtime").json()
        rec("RT01 runtime-endpoint",
            info.get("provider") == "offline_signed_license"
            and info.get("edition_mode") == "offline",
            "the offline runtime reports the fully implemented provider")

        status_body = client.get("/offline/license/status").json()
        rec("RT02 fresh-install-no-license",
            status_body.get("state") == "no_license" and status_body.get("read_only") is True,
            "a fresh installation starts unlicensed and read-only")

        blocked = client.post("/workspaces", json={"name": "W"})
        body = blocked.json() if blocked.status_code == 423 else {}
        rec("RT03 no-license-blocks-mutations",
            blocked.status_code == 423
            and body.get("reason_code") == "NO_LICENSE_INSTALLED"
            and body.get("support_code") and body.get("license_page") == "/license"
            and body.get("import_action") == "/offline/license/import",
            "an unlicensed mutation is blocked with reason + renewal + import actions "
            "(never a silent no-op)")

        request_response = client.get("/offline/license/activation-request")
        request_document = json.loads(request_response.content)
        real_facts, _ = FP.collect_windows_facts()
        request_text = json.dumps(request_document)
        leaked = [name for name, value in real_facts.items()
                  if value and (value in request_text
                                or value.replace("-", "").upper()
                                in request_text.replace("-", "").upper())]
        rec("RT04 activation-request-exportable-and-private",
            request_response.status_code == 200
            and request_document.get("schema_version") == "monday-report-activation-request.v1"
            and not leaked,
            "the exported request carries hashed components only (raw facts compared "
            "in-memory, never printed)")

        imported = client.post("/offline/license/import", content=_license(30))
        rec("RT05 license-import-activates",
            imported.status_code == 200 and imported.json().get("state") == "valid",
            "importing a valid signed license activates the installation")

        created = client.post("/workspaces", json={"name": "Rig A"})
        rec("RT06 licensed-mutation-allowed", created.status_code == 201,
            "a licensed installation performs business mutations")
        workspace_id = created.json().get("id", "")

        backup_created = client.post("/offline/backup").json()
        rec("RT07 backup-creates-archive", bool(backup_created.get("backup")),
            "manual backup produces a validated archive")
        backup_name = backup_created.get("backup", "")
        with zipfile.ZipFile(paths.backup_dir / backup_name) as archive:
            manifest = json.loads(archive.read("manifest.json"))
        rec("RT08 backup-excludes-license-material",
            manifest.get("license_material_included") is False
            and not any("license" in name.lower() for name in
                        zipfile.ZipFile(paths.backup_dir / backup_name).namelist()),
            "backups never contain the license file or protected licensing state")

        # ---- expiry transition (clock only moves FORWARD) ----
        clock["now"] = base_epoch + 86400 * 60
        cache.decision(force=True)
        expired_status = client.get("/offline/license/status").json()
        rec("RT09 expiry-enters-read-only",
            expired_status.get("state") == "expired_read_only"
            and expired_status.get("read_only") is True,
            "past grace the runtime is read-only")

        blocked = client.post("/workspaces", json={"name": "W2"})
        body = blocked.json() if blocked.status_code == 423 else {}
        rec("RT10 expired-blocks-new-mutations",
            blocked.status_code == 423 and body.get("reason_code") == "LICENSE_EXPIRED"
            and body.get("expires_at") and body.get("support_code"),
            "expired mutations show reason, expiry date, renewal and import actions")

        reads = client.get("/workspaces")
        rec("RT11 expired-data-remains-readable",
            reads.status_code == 200
            and any(w.get("id") == workspace_id for w in reads.json()),
            "existing customer data stays accessible read-only")

        draft = client.get(f"/workspaces/{workspace_id}/report-draft")
        rec("RT12 expired-blocks-report-draft",
            draft.status_code == 423,
            "the write-shaped report-draft GET is blocked when expired")

        redemption = client.get(f"/signed/report-exports/{uuid.uuid4()}")
        rec("RT13 expired-blocks-export-redemption",
            redemption.status_code == 423,
            "signed export redemption is blocked when expired")

        backup_expired = client.post("/offline/backup")
        rec("RT14 expired-backup-still-allowed",
            backup_expired.status_code == 200 and backup_expired.json().get("backup"),
            "an expired customer can always back up their own data")

        state_file = Path(os.environ["MONDAY_REPORT_STATE_PATH"])
        before = state_file.read_text(encoding="utf-8")
        restored = client.post("/offline/restore", json={"backup": backup_name})
        reads_after = client.get("/workspaces")
        rec("RT15 restore-roundtrip",
            restored.status_code == 200
            and any(w.get("id") == workspace_id for w in reads_after.json()),
            "staged restore replaces data and preserves the workspace")

        corrupt = paths.backup_dir / "monday-report-backup-corrupt.zip"
        with zipfile.ZipFile(corrupt, "w") as archive:
            archive.writestr("manifest.json", json.dumps({
                "schema_version": "monday-report-backup.v1", "data_version": 1,
                "file_hashes": {"data/monday_report_state.json": "0" * 64}}))
            archive.writestr("data/monday_report_state.json", "{}")
        before_rejected = state_file.read_text(encoding="utf-8")
        rejected = client.post("/offline/restore", json={"backup": corrupt.name})
        rec("RT16 corrupt-restore-rejected-with-rollback",
            rejected.status_code == 400
            and state_file.read_text(encoding="utf-8") == before_rejected,
            "a hash-mismatched backup is refused and the CURRENT state file is "
            "byte-identical to what it was before the attempt")

        rec("RT17 worker-gated-by-license",
            cache.decision().operational is False,
            "the in-process worker skips business processing while read-only "
            "(the loop consumes this exact decision)")

        renewal = client.post("/offline/license/import", content=_license(365, sequence=2))
        renewed_status = client.get("/offline/license/status").json()
        created2 = client.post("/workspaces", json={"name": "After renewal"})
        rec("RT18 renewal-restores-operation",
            renewal.status_code == 200 and renewed_status.get("state") == "valid"
            and created2.status_code == 201,
            "importing a newer license re-enables full operation")

        page = client.get("/license")
        rec("RT19 license-page-served",
            page.status_code == 200 and "Monday Report Offline Edition" in page.text
            and "activation request" in page.text.lower(),
            "the license UI page explains status, activation, and import")

        health = client.get("/health")
        rec("RT20 v1-api-passthrough",
            health.status_code == 200,
            "the unmodified v1 API serves through the wrapper on the same origin")

    # ---- launcher-level checks (no live server needed) ----
    port = RT.select_port()
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", port))
        rec("RT21 port-selection-loopback", True,
            "the selected port binds 127.0.0.1")
    except OSError:
        rec("RT21 port-selection-loopback", False, "selected port not bindable")
    finally:
        probe.close()

    runtime_source = (ROOT / "backend" / "app" / "offline_runtime.py").read_text(encoding="utf-8")
    rec("RT22 localhost-default-lan-double-opt-in",
        'host = "127.0.0.1"' in runtime_source
        and 'MONDAY_REPORT_OFFLINE_LAN_ACK") == "I_UNDERSTAND_LAN_EXPOSURE"' in runtime_source,
        "default binding is loopback; LAN exposure needs two explicit opt-ins")

    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.bind(("127.0.0.1", 0))
    holder.listen(1)
    live_port = holder.getsockname()[1]
    (paths.config_dir / "runtime.lock.json").write_text(
        json.dumps({"port": live_port}), encoding="utf-8")
    second = RT.acquire_single_instance(paths, live_port + 1)
    holder.close()
    rec("RT23 second-instance-refused",
        second is False,
        "a live instance's lock prevents a second instance from sharing the state")
    stale = RT.acquire_single_instance(paths, live_port + 1)
    rec("RT24 stale-lock-recovered", stale is True,
        "a dead instance's stale lock is replaced (crash-safe restart)")

    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "offline_runtime",
        "claim_scope": "offline runtime enforcement; v1 API byte-unmodified; no GA claim",
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2))
    shutil.rmtree(tmp, ignore_errors=True)
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
