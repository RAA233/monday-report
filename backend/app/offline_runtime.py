"""Monday Report OFFLINE EDITION runtime.

A localhost-only wrapper that serves the prebuilt frontend and the existing v1
API from one origin, enforces the signed offline license around every business
mutation, runs the local worker in-process, and owns installation paths,
backups, restore, single-instance locking, and the license UI. It never binds a
public interface by default and requires no Internet, Node.js, Docker,
PostgreSQL, or Redis at runtime.

Nothing in ``backend/app/main.py`` or the store changes: enforcement wraps the
existing app from the outside so v1 behavior stays byte-identical.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import socket
import sys
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from .licensing.activation import build_activation_request
from .licensing.contract import PRODUCT_VERSION, LicenseDecision, ReasonCode
from .licensing.fingerprint import collect_fingerprint, redacted_diagnostic
from .licensing.offline_provider import (
    LicenseImportError,
    OfflineProviderConfig,
    OfflineSignedLicenseProvider,
)
from .licensing.update_format import CURRENT_DATA_VERSION

BACKUP_SCHEMA_VERSION = "monday-report-backup.v1"
DEFAULT_PORT_RANGE = tuple(range(47613, 47631))
_DECISION_TTL_SECONDS = 5.0

#: GET paths that are WRITES or licensed deliverable flows — blocked when the
#: decision is read-only, in addition to every mutating method.
_READ_ONLY_BLOCKED_GET_PREFIXES = (
    "/signed/report-exports/",
    "/signed/upload-files/",
)
_READ_ONLY_BLOCKED_GET_SUFFIXES = ("/report-draft",)


# ---------------------------------------------------------------------------
# Installation paths and secrets


@dataclass(frozen=True)
class OfflinePaths:
    root: Path

    @property
    def config_dir(self) -> Path:
        return self.root / "config"

    @property
    def data_dir(self) -> Path:
        return self.root / "data"

    @property
    def license_dir(self) -> Path:
        return self.root / "licenses"

    @property
    def log_dir(self) -> Path:
        return self.root / "logs"

    @property
    def backup_dir(self) -> Path:
        return self.root / "backups"

    @property
    def tmp_dir(self) -> Path:
        return self.root / "tmp"

    def ensure(self) -> None:
        for path in (
            self.config_dir,
            self.data_dir,
            self.license_dir,
            self.log_dir,
            self.backup_dir,
            self.tmp_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)


def default_root() -> Path:
    override = os.getenv("MONDAY_REPORT_OFFLINE_DATA_DIR")
    if override:
        return Path(override)
    local_appdata = os.getenv("LOCALAPPDATA")
    base = Path(local_appdata) if local_appdata else Path.home() / "AppData" / "Local"
    return base / "MondayReportOffline"


def _load_or_create_install_config(paths: OfflinePaths) -> dict:
    config_path = paths.config_dir / "installation.json"
    if config_path.exists():
        return json.loads(config_path.read_text(encoding="utf-8"))
    config = {
        "schema_version": "monday-report-installation.v1",
        "installation_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "product_version": PRODUCT_VERSION,
        "data_version": CURRENT_DATA_VERSION,
        "signing_secret": secrets.token_hex(32),
        "audit_hmac_key": secrets.token_hex(32),
    }
    config_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = config_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(config, indent=2), encoding="utf-8")
    os.replace(tmp, config_path)
    return config


def _wire_environment(paths: OfflinePaths, install: dict) -> None:
    """Point the existing store at the offline data layout BEFORE it is
    imported. Existing explicit env values win so tests can override."""

    defaults = {
        "MONDAY_REPORT_STATE_PATH": str(paths.data_dir / "monday_report_state.json"),
        "MONDAY_REPORT_STORAGE_ROOT": str(paths.data_dir / "storage"),
        "MONDAY_REPORT_EXPORT_ROOT": str(paths.data_dir / "exports"),
        "MONDAY_REPORT_CLIENT_DATA_MODE": "demo",  # offline-local single-user mode
        "MONDAY_REPORT_REPOSITORY_BACKEND": "local_json",
        "MONDAY_REPORT_QUEUE_BACKEND": "inline_worker",
        "MONDAY_REPORT_SIGNING_SECRET": install["signing_secret"],
        "MONDAY_REPORT_AUDIT_HMAC_KEY": install["audit_hmac_key"],
        "MONDAY_REPORT_AUDIT_HMAC_KEY_ID": "offline-primary",
        "MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION": "1",
        "MONDAY_REPORT_CORS_ORIGINS": "",  # same-origin only
    }
    for key, value in defaults.items():
        os.environ.setdefault(key, value)


def load_public_key(paths: OfflinePaths) -> bytes | None:
    """The embedded PUBLIC verification key (hex). Installed beside the
    application; the private key never exists on a customer machine."""

    override = os.getenv("MONDAY_REPORT_LICENSE_PUBLIC_KEY_FILE", "")
    candidates = [
        *( [Path(override)] if override else [] ),
        paths.config_dir / "licensing_public_key.txt",
        Path(getattr(sys, "_MEIPASS", str(Path(__file__).resolve().parent)))
        / "licensing_public_key.txt",
    ]
    for candidate in candidates:
        if candidate.is_file():
            try:
                return bytes.fromhex(candidate.read_text(encoding="utf-8").strip())
            except ValueError:
                continue
    return None


# ---------------------------------------------------------------------------
# Provider assembly


@lru_cache(maxsize=1)
def cached_machine_fingerprint():
    """Machine facts are stable for the lifetime of the process, but collecting
    them spawns several PowerShell CIM queries. The runtime therefore collects
    ONCE per process — every license evaluation and activation export reuses
    the hashes. A hardware change is picked up on the next application start."""

    return collect_fingerprint()


def build_provider(paths: OfflinePaths, install: dict) -> OfflineSignedLicenseProvider | None:
    public_key = load_public_key(paths)
    if public_key is None:
        return None
    return OfflineSignedLicenseProvider(
        OfflineProviderConfig(
            license_path=paths.license_dir / "monday-report-license.json",
            state_primary_path=paths.config_dir / "license_state.bin",
            state_secondary_path=paths.data_dir / ".license_state.bin",
            public_key=public_key,
            installation_id=str(install["installation_id"]),
            fingerprint_supplier=cached_machine_fingerprint,
        )
    )


class DecisionCache:
    """Small TTL cache so per-request enforcement stays cheap."""

    def __init__(self, provider: OfflineSignedLicenseProvider | None) -> None:
        self.provider = provider
        self._lock = threading.Lock()
        self._decision: LicenseDecision | None = None
        self._at = 0.0

    def decision(self, *, force: bool = False) -> LicenseDecision:
        from .licensing.contract import LicenseState

        if self.provider is None:
            return LicenseDecision(
                state=LicenseState.PROVIDER_UNAVAILABLE,
                reason=ReasonCode.PROVIDER_NOT_IMPLEMENTED,
                read_only=True,
                support_code="MR-LIC-KEY-120",
            )
        with self._lock:
            now = time.monotonic()
            if force or self._decision is None or now - self._at > _DECISION_TTL_SECONDS:
                self._decision = self.provider.evaluate()
                self._at = now
            return self._decision


# ---------------------------------------------------------------------------
# Backup / restore


def create_backup(paths: OfflinePaths, install: dict) -> dict:
    """Manual local backup: customer data only. The license file and protected
    licensing state are EXCLUDED by design — a license is machine-bound, so a
    backup restored on another machine still requires that machine's own
    license. Always allowed, including after expiry."""

    paths.ensure()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = paths.backup_dir / f"monday-report-backup-{stamp}.zip"
    entries: list[tuple[Path, str]] = []
    state_file = Path(os.environ["MONDAY_REPORT_STATE_PATH"])
    if state_file.exists():
        entries.append((state_file, "data/monday_report_state.json"))
    for root_env, arc_root in (
        ("MONDAY_REPORT_STORAGE_ROOT", "storage"),
        ("MONDAY_REPORT_EXPORT_ROOT", "exports"),
    ):
        root = Path(os.environ[root_env])
        if root.exists():
            for file_path in sorted(root.rglob("*")):
                if file_path.is_file():
                    entries.append((file_path, f"{arc_root}/{file_path.relative_to(root).as_posix()}"))

    hashes: dict[str, str] = {}
    with zipfile.ZipFile(backup_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for file_path, arcname in entries:
            data = file_path.read_bytes()
            hashes[arcname] = hashlib.sha256(data).hexdigest()
            archive.writestr(arcname, data)
        manifest = {
            "schema_version": BACKUP_SCHEMA_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "product_version": PRODUCT_VERSION,
            "data_version": CURRENT_DATA_VERSION,
            "installation_id": install["installation_id"],
            "file_hashes": hashes,
            "license_material_included": False,
        }
        archive.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
    return {"backup": backup_path.name, "files": len(entries)}


def validate_backup(archive_path: Path) -> dict:
    with zipfile.ZipFile(archive_path) as archive:
        names = set(archive.namelist())
        if "manifest.json" not in names:
            raise ValueError("backup manifest missing")
        manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
        if manifest.get("schema_version") != BACKUP_SCHEMA_VERSION:
            raise ValueError("unsupported backup schema")
        if int(manifest.get("data_version", 0)) > CURRENT_DATA_VERSION:
            raise ValueError("backup requires a newer application version")
        for arcname, expected in dict(manifest.get("file_hashes", {})).items():
            if arcname not in names:
                raise ValueError(f"backup entry missing: {arcname}")
            if hashlib.sha256(archive.read(arcname)).hexdigest() != expected:
                raise ValueError(f"backup entry hash mismatch: {arcname}")
        if "data/monday_report_state.json" in names:
            json.loads(archive.read("data/monday_report_state.json").decode("utf-8"))
    return manifest


def restore_backup(paths: OfflinePaths, archive_path: Path) -> dict:
    """Staged restore: validate → extract to an isolated temp dir → move the
    current data aside → swap in → roll back on failure. Restoring replaces
    existing customer data; it never executes licensed business operations, so
    it remains available after expiry."""

    manifest = validate_backup(archive_path)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stage = paths.tmp_dir / f"restore-{stamp}"
    stage.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.namelist():
            if member == "manifest.json":
                continue
            target = stage / member
            if not str(target.resolve()).startswith(str(stage.resolve())):
                raise ValueError("backup entry escapes the restore stage")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(member))

    state_file = Path(os.environ["MONDAY_REPORT_STATE_PATH"])
    storage_root = Path(os.environ["MONDAY_REPORT_STORAGE_ROOT"])
    export_root = Path(os.environ["MONDAY_REPORT_EXPORT_ROOT"])
    aside = paths.tmp_dir / f"pre-restore-{stamp}"
    aside.mkdir(parents=True, exist_ok=True)
    moved: list[tuple[Path, Path]] = []
    try:
        for current, name in ((state_file, "state.json"), (storage_root, "storage"), (export_root, "exports")):
            if current.exists():
                parked = aside / name
                shutil.move(str(current), str(parked))
                moved.append((current, parked))
        staged_state = stage / "data" / "monday_report_state.json"
        if staged_state.exists():
            state_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(staged_state), str(state_file))
        for source_name, destination in (("storage", storage_root), ("exports", export_root)):
            staged_dir = stage / source_name
            if staged_dir.exists():
                shutil.move(str(staged_dir), str(destination))
            else:
                destination.mkdir(parents=True, exist_ok=True)
    except Exception:
        for original, parked in reversed(moved):
            if parked.exists():
                if original.exists():
                    shutil.rmtree(original, ignore_errors=True)
                shutil.move(str(parked), str(original))
        raise
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return {"restored_from": archive_path.name, "backup_created_at": manifest.get("created_at")}


# ---------------------------------------------------------------------------
# ASGI application


def _blocked_payload(decision: LicenseDecision) -> dict:
    return {
        "blocked": True,
        "reason_code": decision.reason.value,
        "license_state": decision.state.value,
        "expires_at": decision.expires_at,
        "grace_until": decision.grace_until,
        "renewal_action": "Renew the license and import the new license file.",
        "license_page": "/license",
        "import_action": "/offline/license/import",
        "support_code": decision.support_code,
        "detail": "This action requires an active Monday Report license. Existing data "
        "remains readable and backups remain available.",
    }


def _is_blocked_request(method: str, path: str, decision: LicenseDecision) -> bool:
    if decision.operational:
        return False
    if path.startswith("/offline/") or path in ("/license", "/health", "/") or path.startswith(
        "/assets/"
    ):
        return False
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return True
    if method == "GET":
        if any(path.startswith(prefix) for prefix in _READ_ONLY_BLOCKED_GET_PREFIXES):
            return True
        if any(path.endswith(suffix) for suffix in _READ_ONLY_BLOCKED_GET_SUFFIXES):
            return True
    return False


_LICENSE_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Monday Report — License</title>
<style>
body{font-family:Segoe UI,system-ui,sans-serif;margin:2rem auto;max-width:44rem;padding:0 1rem;color:#16211c}
h1{font-size:1.4rem} .card{border:1px solid #c9d2cd;border-radius:8px;padding:1rem;margin:1rem 0}
.state{font-weight:600} button{padding:.5rem 1rem;border:1px solid #16211c;background:#fff;border-radius:6px;cursor:pointer}
code{background:#eef2ef;padding:.1rem .3rem;border-radius:4px}
</style></head><body>
<h1>Monday Report Offline Edition — License</h1>
<div class="card"><div>Status: <span class="state" id="state">loading…</span></div>
<div id="detail"></div><div>Support code: <code id="support"></code></div></div>
<div class="card"><h2>Activation request</h2>
<p>Export the activation request file and send it to your Monday Report contact
through your approved channel. It contains only hashed machine facts.</p>
<button onclick="window.location='/offline/license/activation-request'">Download activation request</button></div>
<div class="card"><h2>Import license</h2>
<input type="file" id="file"><button onclick="importLicense()">Import license file</button>
<div id="importResult"></div></div>
<script>
async function refresh(){
  const r = await fetch('/offline/license/status'); const d = await r.json();
  document.getElementById('state').textContent = d.state + ' (' + d.reason_code + ')';
  document.getElementById('support').textContent = d.support_code;
  document.getElementById('detail').textContent =
    (d.expires_at ? 'Expires: ' + d.expires_at + '. ' : '') +
    (d.grace_until ? 'Grace until: ' + d.grace_until + '.' : '');
}
async function importLicense(){
  const f = document.getElementById('file').files[0];
  if(!f){ return; }
  const r = await fetch('/offline/license/import', {method:'POST', body: await f.text(),
    headers:{'content-type':'application/json'}});
  const d = await r.json();
  document.getElementById('importResult').textContent = JSON.stringify(d);
  refresh();
}
refresh();
</script></body></html>"""


def build_offline_app(paths: OfflinePaths | None = None):
    """Assemble the wrapper app. Importing this function's result imports the
    existing backend app with the offline environment already wired."""

    from starlette.staticfiles import StaticFiles

    paths = paths or OfflinePaths(default_root())
    paths.ensure()
    install = _load_or_create_install_config(paths)
    _wire_environment(paths, install)

    from . import worker as worker_module
    from .main import app as inner_app

    provider = build_provider(paths, install)
    cache = DecisionCache(provider)

    offline_app = FastAPI(title="Monday Report Offline Edition", docs_url=None, redoc_url=None)
    offline_app.state.paths = paths
    offline_app.state.install = install
    offline_app.state.decision_cache = cache

    @offline_app.middleware("http")
    async def license_enforcement(request: Request, call_next):
        decision = cache.decision()
        if _is_blocked_request(request.method, request.url.path, decision):
            return JSONResponse(status_code=423, content=_blocked_payload(decision))
        return await call_next(request)

    @offline_app.get("/offline/license/status")
    async def license_status():
        decision = cache.decision(force=True)
        body = {
            "state": decision.state.value,
            "reason_code": decision.reason.value,
            "edition": decision.edition,
            "feature_flags": decision.feature_flags,
            "issued_at": decision.issued_at,
            "not_before": decision.not_before,
            "expires_at": decision.expires_at,
            "grace_until": decision.grace_until,
            "read_only": decision.read_only,
            "renewal_sequence": decision.renewal_sequence,
            "license_id": decision.license_id,
            "support_code": decision.support_code,
            "product_version": PRODUCT_VERSION,
        }
        if decision.machine_binding is not None:
            body["machine_binding"] = redacted_diagnostic(decision.machine_binding)
        return body

    @offline_app.get("/offline/license/activation-request")
    async def activation_request():
        document = build_activation_request(
            cached_machine_fingerprint(),
            installation_id=str(install["installation_id"]),
            requested_edition="offline-standard",
        )
        return Response(
            content=json.dumps(document, indent=2, sort_keys=True),
            media_type="application/json",
            headers={
                "content-disposition": "attachment; filename=monday-report-activation-request.json"
            },
        )

    @offline_app.post("/offline/license/import")
    async def license_import(request: Request):
        if provider is None:
            return JSONResponse(
                status_code=503,
                content={"imported": False, "reason_code": "PROVIDER_NOT_IMPLEMENTED",
                         "detail": "licensing public key is not installed"},
            )
        raw = await request.body()
        try:
            decision = provider.import_license(raw)
        except LicenseImportError as exc:
            return JSONResponse(
                status_code=400,
                content={"imported": False, "reason_code": exc.reason.value, "detail": exc.detail},
            )
        cache.decision(force=True)
        return {"imported": True, "state": decision.state.value, "expires_at": decision.expires_at}

    @offline_app.post("/offline/backup")
    async def backup_now():
        return create_backup(paths, install)

    @offline_app.get("/offline/backups")
    async def list_backups():
        return {
            "backups": sorted(p.name for p in paths.backup_dir.glob("monday-report-backup-*.zip"))
        }

    @offline_app.post("/offline/restore")
    async def restore(request: Request):
        payload = await request.json()
        name = str(payload.get("backup", ""))
        candidate = (paths.backup_dir / name).resolve()
        if not str(candidate).startswith(str(paths.backup_dir.resolve())) or not candidate.exists():
            return JSONResponse(status_code=404, content={"detail": "backup not found"})
        try:
            result = restore_backup(paths, candidate)
        except (ValueError, OSError, zipfile.BadZipFile) as exc:
            return JSONResponse(status_code=400, content={"detail": f"restore rejected: {exc}"})
        return result

    @offline_app.get("/offline/runtime")
    async def runtime_info():
        return {
            "product_version": PRODUCT_VERSION,
            "data_version": CURRENT_DATA_VERSION,
            "edition_mode": "offline",
            "provider": provider.provider_kind() if provider else "public-key-missing",
        }

    @offline_app.get("/license")
    async def license_page():
        return HTMLResponse(_LICENSE_PAGE)

    # Prebuilt frontend (same origin). The packaged layout ships dist/ beside
    # the executable; a source checkout uses the repo's dist build.
    dist_dir = Path(
        os.getenv(
            "MONDAY_REPORT_OFFLINE_DIST",
            str(Path(getattr(sys, "_MEIPASS", str(Path(__file__).resolve().parents[2]))) / "dist"),
        )
    )
    index_file = dist_dir / "index.html"
    if (dist_dir / "assets").exists():
        offline_app.mount("/assets", StaticFiles(directory=str(dist_dir / "assets")), name="assets")

    def _index_response() -> HTMLResponse:
        if index_file.exists():
            return HTMLResponse(index_file.read_text(encoding="utf-8"))
        return HTMLResponse(
            "<h1>Monday Report Offline Edition</h1><p>Frontend assets missing; the API "
            "and <a href='/license'>license page</a> remain available.</p>"
        )

    @offline_app.get("/")
    async def frontend_index():
        return _index_response()

    # Client-side (BrowserRouter) deep routes. The canonical frontend owns the
    # entire ``/app`` subtree (``/app``, ``/app/reports``,
    # ``/app/reports/<id>/draft`` — report ids may contain dots). The dev/preview
    # server rewrites these to index.html via the vite history-fallback plugin;
    # the packaged runtime reproduces exactly that contract so a full-document
    # load or refresh of any deep route re-enters the SPA with the URL intact.
    # ``/app`` is not an API prefix, and these routes are registered BEFORE the
    # v1 mount, so nothing in the existing API is shadowed.
    @offline_app.get("/app")
    async def spa_root():
        return _index_response()

    @offline_app.get("/app/{spa_path:path}")
    async def spa_deep_route(spa_path: str):
        return _index_response()

    def _serve_dist_file(name: str, media_type: str) -> Response:
        candidate = dist_dir / name
        if candidate.exists():
            return Response(content=candidate.read_bytes(), media_type=media_type)
        return Response(status_code=404)

    @offline_app.get("/favicon.svg")
    async def frontend_favicon():
        return _serve_dist_file("favicon.svg", "image/svg+xml")

    @offline_app.get("/vite.svg")
    async def frontend_icon():
        return _serve_dist_file("vite.svg", "image/svg+xml")

    # Everything else (the entire v1 API) is served by the existing app.
    offline_app.mount("", inner_app)

    # In-process worker: processes queued jobs only under an operational
    # license, so expired installations never execute new business operations.
    stop_event = threading.Event()
    offline_app.state.worker_stop = stop_event

    def _worker_loop() -> None:
        while not stop_event.wait(2.0):
            try:
                if cache.decision().operational:
                    worker_module.run_once()
            except Exception:  # noqa: BLE001 - the worker loop must survive
                time.sleep(1.0)

    worker_thread = threading.Thread(target=_worker_loop, name="offline-worker", daemon=True)
    offline_app.state.worker_thread = worker_thread

    @offline_app.on_event("startup")
    async def _start_worker():
        if not worker_thread.is_alive():
            worker_thread.start()

    @offline_app.on_event("shutdown")
    async def _stop_worker():
        stop_event.set()

    return offline_app


# ---------------------------------------------------------------------------
# Launcher: port selection, single instance, browser


def select_port(preferred: int | None = None) -> int:
    candidates = [preferred] if preferred else list(DEFAULT_PORT_RANGE)
    for candidate in candidates:
        if candidate is None:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("127.0.0.1", candidate))
                return candidate
            except OSError:
                continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _existing_instance_port(paths: OfflinePaths) -> int | None:
    lock_file = paths.config_dir / "runtime.lock.json"
    if not lock_file.exists():
        return None
    try:
        payload = json.loads(lock_file.read_text(encoding="utf-8"))
        port = int(payload.get("port", 0))
    except (json.JSONDecodeError, ValueError, OSError):
        return None
    if not port:
        return None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0):
            return port
    except OSError:
        return None


def acquire_single_instance(paths: OfflinePaths, port: int) -> bool:
    """One instance per installation: a live lock file wins; a stale one is
    replaced. Prevents two processes from mutating the same local state."""

    existing = _existing_instance_port(paths)
    if existing is not None:
        return False
    lock_file = paths.config_dir / "runtime.lock.json"
    lock_file.write_text(
        json.dumps({"port": port, "started_at": datetime.now(timezone.utc).isoformat()}),
        encoding="utf-8",
    )
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="monday-report-offline")
    parser.add_argument("--port", type=int)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--backup", action="store_true")
    parser.add_argument("--restore", metavar="BACKUP_NAME")
    parser.add_argument("--activation-request", metavar="OUT_FILE")
    parser.add_argument("--import-license", metavar="LICENSE_FILE")
    args = parser.parse_args(argv)

    paths = OfflinePaths(default_root())
    paths.ensure()
    install = _load_or_create_install_config(paths)
    _wire_environment(paths, install)

    if args.status:
        cache = DecisionCache(build_provider(paths, install))
        decision = cache.decision(force=True)
        print(json.dumps({"state": decision.state.value, "reason": decision.reason.value,
                          "expires_at": decision.expires_at, "support_code": decision.support_code},
                         indent=2))
        return 0
    if args.backup:
        print(json.dumps(create_backup(paths, install), indent=2))
        return 0
    if args.restore:
        print(json.dumps(restore_backup(paths, paths.backup_dir / args.restore), indent=2))
        return 0
    if args.activation_request:
        document = build_activation_request(
            cached_machine_fingerprint(),
            installation_id=str(install["installation_id"]),
            requested_edition="offline-standard",
        )
        Path(args.activation_request).write_text(
            json.dumps(document, indent=2, sort_keys=True), encoding="utf-8"
        )
        print(json.dumps({"written": args.activation_request}, indent=2))
        return 0
    if args.import_license:
        provider = build_provider(paths, install)
        if provider is None:
            print(json.dumps({"imported": False, "detail": "licensing public key missing"}))
            return 1
        try:
            decision = provider.import_license(Path(args.import_license).read_bytes())
        except LicenseImportError as exc:
            print(json.dumps({"imported": False, "reason_code": exc.reason.value,
                              "detail": exc.detail}, indent=2))
            return 1
        print(json.dumps({"imported": True, "state": decision.state.value}, indent=2))
        return 0

    # Localhost-only by default. LAN exposure requires BOTH explicit opt-ins
    # AND authenticated client mode — the loopback trust boundary is what makes
    # unauthenticated demo mode safe, so publishing to a LAN without
    # credentials is refused rather than silently allowed.
    host = "127.0.0.1"
    if (
        os.getenv("MONDAY_REPORT_OFFLINE_LAN") == "1"
        and os.getenv("MONDAY_REPORT_OFFLINE_LAN_ACK") == "I_UNDERSTAND_LAN_EXPOSURE"
    ):
        from .auth import api_key_configured

        if os.environ.get("MONDAY_REPORT_CLIENT_DATA_MODE") != "client" or not api_key_configured():
            print(json.dumps({
                "refused": "lan_mode_requires_authentication",
                "detail": "LAN mode requires MONDAY_REPORT_CLIENT_DATA_MODE=client and a "
                          "configured MONDAY_REPORT_API_KEY; refusing to publish an "
                          "unauthenticated API to the network.",
            }))
            return 2
        host = "0.0.0.0"  # documented, double-opt-in + authenticated only

    env_port = os.getenv("MONDAY_REPORT_OFFLINE_PORT")
    port = select_port(args.port or (int(env_port) if env_port else None))
    if not acquire_single_instance(paths, port):
        existing = _existing_instance_port(paths)
        print(json.dumps({"already_running": True, "url": f"http://127.0.0.1:{existing}/"}))
        if not args.no_browser and existing:
            import webbrowser

            webbrowser.open(f"http://127.0.0.1:{existing}/")
        return 0

    app = build_offline_app(paths)
    if not args.no_browser:
        import webbrowser

        threading.Timer(1.5, lambda: webbrowser.open(f"http://127.0.0.1:{port}/")).start()

    import uvicorn

    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
