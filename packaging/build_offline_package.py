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
# This file lives in ``packaging/`` which collides with the PyPI ``packaging``
# package, so import the sibling helper by its bare name from this directory rather
# than as ``packaging.frontend_same_origin`` (which would resolve to the PyPI lib).
_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from backend.app.licensing.contract import PRODUCT_VERSION  # noqa: E402
from backend.app.licensing.update_format import CURRENT_DATA_VERSION  # noqa: E402
from frontend_same_origin import (  # noqa: E402
    FORBIDDEN_FRONTEND_API_BASES,
    assert_frontend_same_origin,
    production_frontend_env,
    reject_reuse_frontend_for_production,
)

OUTPUT_DIR = ROOT / "output" / "offline-package"


def _git(*args: str) -> str:
    """Best-effort git query against the source tree (never fatal)."""

    try:
        completed = subprocess.run(
            ["git", "-C", str(ROOT), *args], capture_output=True, text=True, timeout=30
        )
        return completed.stdout.strip() if completed.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _frontend_build_id(dist_dir: Path) -> dict:
    """Deterministic fingerprint of the PREBUILT frontend that is bundled.

    A digest over the sorted ``relpath:sha256`` of every dist file, plus the
    asset filenames Vite emitted (each carries a content hash), so a change to
    any shipped byte changes the recorded id.
    """

    entries: list[str] = []
    assets: list[str] = []
    for file_path in sorted(dist_dir.rglob("*")):
        if not file_path.is_file():
            continue
        rel = file_path.relative_to(dist_dir).as_posix()
        entries.append(f"{rel}:{hashlib.sha256(file_path.read_bytes()).hexdigest()}")
        if rel.startswith("assets/"):
            assets.append(rel)
    build_id = hashlib.sha256("\n".join(entries).encode("utf-8")).hexdigest() if entries else ""
    return {"frontend_build_id": build_id, "asset_files": sorted(assets), "dist_files": len(entries)}


def _bundled_dependencies() -> dict:
    """Capture the interpreter version and the installed dependency set that the
    frozen package is built from (``pip freeze``)."""

    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pip", "freeze", "--all"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        frozen = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    except (OSError, subprocess.SubprocessError):
        frozen = []
    return {
        "python_version": sys.version.split()[0],
        "python_implementation": sys.implementation.name,
        "python_full": sys.version.replace("\n", " "),
        "pip_freeze": frozen,
        "pip_freeze_count": len(frozen),
    }


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


def _resolve_node() -> str:
    node = shutil.which("node")
    if not node:
        raise SystemExit("node is required to build the frontend and was not found on PATH")
    return node


def _run_ok(command: list[str], *, env: dict | None = None) -> bool:
    """Like ``_run`` but returns success instead of raising, so a primary build
    attempt can fall back to an alternate invocation without aborting."""
    resolved = shutil.which(command[0])
    if resolved:
        command = [resolved, *command[1:]]
    completed = subprocess.run(command, cwd=str(ROOT), env=env, capture_output=True, text=True)
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout[-2000:] + "\n" + completed.stderr[-2000:] + "\n")
    return completed.returncode == 0


def build_frontend(skip: bool) -> None:
    if skip and (ROOT / "dist" / "index.html").exists():
        return
    env = production_frontend_env()
    # Primary path: the package.json "build" script (tsc && vite build) via pnpm.
    if _run_ok(["corepack", "pnpm", "run", "build"], env=env):
        return
    # Fallback: corepack/pnpm launcher shims can fail with EPERM on some Windows
    # shells. Run the SAME build (tsc typecheck, then vite build) directly through
    # node with the SAME production env. Fail closed if this path also fails.
    node = _resolve_node()
    _run([node, str(ROOT / "node_modules" / "typescript" / "bin" / "tsc")], env=env)
    _run([node, str(ROOT / "node_modules" / "vite" / "bin" / "vite.js"), "build"], env=env)


# The same-origin invariants live in a dependency-free module so the audit-chain
# guard can import them without dragging in the app's crypto dependencies.


def run_pyinstaller() -> Path:
    _run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
          "--distpath", str(OUTPUT_DIR / "stage"),
          "--workpath", str(OUTPUT_DIR / "work"),
          str(ROOT / "packaging" / "pyinstaller_offline.spec")])
    return OUTPUT_DIR / "stage" / "MondayReportOffline"


def assemble(app_dir: Path, public_key_file: Path, *, key_label: str = "unspecified") -> Path:
    # Fail closed BEFORE embedding the key / zipping: the shipped SPA must reach its
    # own backend same-origin. This catches a dev-configured (``:8000``) dist that a
    # reuse or a leaked env var could otherwise smuggle into the package.
    same_origin_assets = assert_frontend_same_origin(app_dir)
    public_key_hex = public_key_file.read_text(encoding="utf-8").strip()
    if len(bytes.fromhex(public_key_hex)) != 32:
        raise SystemExit("public key must be 32 Ed25519 public bytes (hex)")
    internal = app_dir / "_internal"
    key_target_dir = internal if internal.exists() else app_dir
    (key_target_dir / "licensing_public_key.txt").write_text(public_key_hex, encoding="utf-8")

    for script in ("install.ps1", "uninstall.ps1"):
        shutil.copy2(ROOT / "packaging" / "installer" / script, app_dir / script)

    frontend = _frontend_build_id(ROOT / "dist")
    runtime = _bundled_dependencies()
    version_metadata = {
        "product": "monday-report",
        "edition": "offline",
        "product_version": PRODUCT_VERSION,
        "data_version": CURRENT_DATA_VERSION,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": _git("rev-parse", "HEAD"),
        "source_tree": _git("rev-parse", "HEAD^{tree}"),
        "source_branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "source_dirty": bool(_git("status", "--porcelain")),
        "runtime": runtime,
        "frontend": frontend,
        "frontend_same_origin_assets_scanned": same_origin_assets,
        # Public-key IDENTITY needed to verify licenses. The private signing key
        # is never read, never required, and never present in the package.
        "license_public_key": public_key_hex,
        "public_key_fingerprint": hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:16],
        "license_key_label": key_label,
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
        "data_version": CURRENT_DATA_VERSION,
        "source_commit": version_metadata["source_commit"],
        "source_tree": version_metadata["source_tree"],
        "source_branch": version_metadata["source_branch"],
        "source_dirty": version_metadata["source_dirty"],
        "python_version": runtime["python_version"],
        "bundled_dependency_count": runtime["pip_freeze_count"],
        "frontend_build_id": frontend["frontend_build_id"],
        "frontend_dist_files": frontend["dist_files"],
        "license_public_key": public_key_hex,
        "public_key_fingerprint": version_metadata["public_key_fingerprint"],
        "license_key_label": key_label,
    }
    (OUTPUT_DIR / "build-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return archive


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build_offline_package")
    parser.add_argument("--public-key", required=True,
                        help="hex file of the CUSTOMER-FACING PUBLIC verification key")
    parser.add_argument("--key-label", default="unspecified",
                        help="provenance label for the embedded PUBLIC key recorded in the "
                             "manifest, e.g. TEST or production. Never the private key.")
    parser.add_argument("--reuse-frontend", action="store_true",
                        help="skip the frontend build when dist/ already exists")
    args = parser.parse_args(argv)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    reject_reuse_frontend_for_production(args.key_label, args.reuse_frontend)
    build_frontend(skip=args.reuse_frontend)
    app_dir = run_pyinstaller()
    assemble(app_dir, Path(args.public_key), key_label=args.key_label)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
