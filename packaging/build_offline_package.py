"""Build the Windows-first Monday Report Offline Edition package.

Steps:
1. Build the frontend with a SAME-ORIGIN API base (``VITE_API_BASE_URL=""``)
   so the packaged backend serves UI + API from one localhost origin.
2. Run PyInstaller with ``packaging/pyinstaller_offline.spec``.
3. Install the customer-facing PUBLIC verification key (``--public-key``) into
   the package. The private key is never read, never required, never present.
4. Assemble installer collateral (install/uninstall scripts, version metadata),
   write a SHA-256 payload manifest, and zip the package.

Output lands in the gitignored ``output/offline-package/`` directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.licensing.contract import PRODUCT_VERSION  # noqa: E402
from backend.app.licensing.update_format import CURRENT_DATA_VERSION  # noqa: E402

OUTPUT_DIR = ROOT / "output" / "offline-package"


def _run(command: list[str], *, env: dict | None = None) -> None:
    # Windows launcher shims (corepack/pnpm) are .cmd files -- resolve the real
    # executable path so CreateProcess can spawn it.
    resolved = shutil.which(command[0])
    if resolved:
        command = [resolved, *command[1:]]
    completed = subprocess.run(command, cwd=str(ROOT), env=env, capture_output=True, text=True)
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout[-4000:] + "\n" + completed.stderr[-4000:] + "\n")
        raise SystemExit(f"step failed: {' '.join(command[:3])}")


def build_frontend(skip: bool) -> None:
    if skip and (ROOT / "dist" / "index.html").exists():
        return
    env = dict(os.environ)
    env["CI"] = "true"
    env["VITE_API_BASE_URL"] = ""  # same-origin: the offline backend serves the UI
    _run(["corepack", "pnpm", "run", "build"], env=env)


def run_pyinstaller() -> Path:
    _run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
          "--distpath", str(OUTPUT_DIR / "stage"),
          "--workpath", str(OUTPUT_DIR / "work"),
          str(ROOT / "packaging" / "pyinstaller_offline.spec")])
    return OUTPUT_DIR / "stage" / "MondayReportOffline"


def assemble(app_dir: Path, public_key_file: Path) -> Path:
    public_key_hex = public_key_file.read_text(encoding="utf-8").strip()
    if len(bytes.fromhex(public_key_hex)) != 32:
        raise SystemExit("public key must be 32 Ed25519 public bytes (hex)")
    internal = app_dir / "_internal"
    key_target_dir = internal if internal.exists() else app_dir
    (key_target_dir / "licensing_public_key.txt").write_text(public_key_hex, encoding="utf-8")

    for script in ("install.ps1", "uninstall.ps1"):
        shutil.copy2(ROOT / "packaging" / "installer" / script, app_dir / script)

    version_metadata = {
        "product": "monday-report",
        "edition": "offline",
        "product_version": PRODUCT_VERSION,
        "data_version": CURRENT_DATA_VERSION,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "public_key_fingerprint": hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:16],
    }
    (app_dir / "version.json").write_text(json.dumps(version_metadata, indent=2), encoding="utf-8")

    manifest: dict[str, str] = {}
    for file_path in sorted(app_dir.rglob("*")):
        if file_path.is_file() and file_path.name != "payload-manifest.json":
            manifest[file_path.relative_to(app_dir).as_posix()] = hashlib.sha256(
                file_path.read_bytes()
            ).hexdigest()
    (app_dir / "payload-manifest.json").write_text(
        json.dumps({"schema_version": "monday-report-payload-manifest.v1",
                    "product_version": PRODUCT_VERSION, "files": manifest},
                   indent=2, sort_keys=True),
        encoding="utf-8",
    )

    archive_base = OUTPUT_DIR / f"MondayReportOffline-{PRODUCT_VERSION}-win64"
    archive = Path(shutil.make_archive(str(archive_base), "zip", root_dir=app_dir.parent,
                                       base_dir=app_dir.name))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    summary = {
        "package": archive.name,
        "installer_sha256": digest,
        "app_dir": str(app_dir),
        "payload_files": len(manifest),
        "product_version": PRODUCT_VERSION,
        "public_key_fingerprint": version_metadata["public_key_fingerprint"],
    }
    (OUTPUT_DIR / "build-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return archive


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build_offline_package")
    parser.add_argument("--public-key", required=True,
                        help="hex file of the CUSTOMER-FACING PUBLIC verification key")
    parser.add_argument("--reuse-frontend", action="store_true",
                        help="skip the frontend build when dist/ already exists")
    args = parser.parse_args(argv)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    build_frontend(skip=args.reuse_frontend)
    app_dir = run_pyinstaller()
    assemble(app_dir, Path(args.public_key))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
