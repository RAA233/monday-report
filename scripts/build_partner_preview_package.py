from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STAGING_ROOT = ROOT / "output" / "partner-preview" / "MondayReportPartnerPreview"
PACKAGE_DIR = ROOT / "output" / "package"
PACKAGE_ZIP = PACKAGE_DIR / "Monday_Report_Partner_Preview.zip"


def main() -> int:
    args = parse_args()
    if not args.skip_build:
        run_build()
    if not (ROOT / "dist" / "index.html").exists():
        print("FAIL: dist/index.html is missing. Run pnpm run build first.", file=sys.stderr)
        return 1

    reset_staging()
    copy_tree(ROOT / "dist", STAGING_ROOT / "dist")
    copy_tree(ROOT / "backend", STAGING_ROOT / "backend", ignore={"__pycache__"})
    copy_tree(ROOT / "db", STAGING_ROOT / "db")
    copy_tree(ROOT / "scripts", STAGING_ROOT / "scripts", ignore={"__pycache__"})
    copy_tree(ROOT / "docs", STAGING_ROOT / "docs")
    copy_file(ROOT / "README.md", STAGING_ROOT / "README.md")
    copy_file(ROOT / ".env.example", STAGING_ROOT / "config" / "partner.env.example")
    write_launcher_scripts()
    write_partner_readme()
    write_sample_import_package()
    write_package_manifest()
    zip_staging()
    digest = sha256_file(PACKAGE_ZIP)
    print(f"Wrote {PACKAGE_ZIP}")
    print(f"SHA256 {digest}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the single-file Monday Report partner preview ZIP.")
    parser.add_argument("--skip-build", action="store_true", help="Use the existing dist/ build.")
    return parser.parse_args()


def run_build() -> None:
    corepack = shutil.which("corepack") or shutil.which("corepack.cmd")
    if corepack:
        result = subprocess.run([corepack, "pnpm", "run", "build"], cwd=ROOT, text=True, check=False)
    else:
        result = subprocess.run("corepack pnpm run build", cwd=ROOT, text=True, check=False, shell=True)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def reset_staging() -> None:
    resolved = STAGING_ROOT.resolve()
    output_root = (ROOT / "output").resolve()
    if output_root not in resolved.parents:
        raise RuntimeError(f"Refusing to reset unexpected staging path: {resolved}")
    if STAGING_ROOT.exists():
        shutil.rmtree(STAGING_ROOT)
    STAGING_ROOT.mkdir(parents=True, exist_ok=True)
    PACKAGE_DIR.mkdir(parents=True, exist_ok=True)


def copy_tree(source: Path, target: Path, ignore: set[str] | None = None) -> None:
    ignore = ignore or set()

    def ignore_names(_: str, names: list[str]) -> set[str]:
        ignored = {name for name in names if name in ignore}
        ignored.update({"node_modules", ".git", ".pytest_cache"})
        return ignored

    shutil.copytree(source, target, ignore=ignore_names)


def copy_file(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def write_launcher_scripts() -> None:
    write_text(
        STAGING_ROOT / "Start-MondayReport.ps1",
        r"""param(
  [switch]$SkipModelPull
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Runtime = Join-Path $Root ".runtime"
$Venv = Join-Path $Runtime "venv"
$Python = Join-Path $Venv "Scripts\python.exe"
$ProcessFile = Join-Path $Runtime "monday-report-processes.json"

New-Item -ItemType Directory -Force -Path $Runtime | Out-Null
if (!(Test-Path $Python)) {
  python -m venv $Venv
}

& $Python -m pip install --upgrade pip
& $Python -m pip install -r (Join-Path $Root "backend\requirements.txt")

$env:MONDAY_REPORT_CLIENT_DATA_MODE = "demo"
$env:MONDAY_REPORT_STATE_PATH = Join-Path $Runtime "data\monday_report_state.json"
$env:MONDAY_REPORT_STORAGE_ROOT = Join-Path $Runtime "data\storage"
$env:MONDAY_REPORT_EXPORT_ROOT = Join-Path $Runtime "data\exports"
$env:MONDAY_REPORT_MALWARE_SCANNER = "builtin"
$env:MONDAY_REPORT_LOCAL_LLM_RUNTIME = "ollama"
$env:MONDAY_REPORT_LOCAL_LLM_MODEL = "gemma4:e2b"
$env:OLLAMA_HOST = "http://127.0.0.1:11434"
$env:MONDAY_REPORT_HOSTED_FALLBACK_ENABLED = "false"

if (!$SkipModelPull) {
  $ollama = Get-Command ollama -ErrorAction SilentlyContinue
  if ($ollama) {
    $models = (& ollama list 2>$null) -join "`n"
    if ($LASTEXITCODE -eq 0 -and $models -notmatch "gemma4:e2b") {
      Write-Host "Pulling default local AI model gemma4:e2b with Ollama..."
      & ollama pull gemma4:e2b
    }
  } else {
    Write-Warning "Ollama is not installed or not on PATH. Install Ollama and run: ollama pull gemma4:e2b"
  }
}

$api = Start-Process -FilePath $Python -ArgumentList @("-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", "8000") -WorkingDirectory $Root -WindowStyle Hidden -PassThru
$worker = Start-Process -FilePath $Python -ArgumentList @("scripts\partner_worker_loop.py") -WorkingDirectory $Root -WindowStyle Hidden -PassThru
$web = Start-Process -FilePath $Python -ArgumentList @("-m", "http.server", "5173", "--bind", "127.0.0.1", "--directory", "dist") -WorkingDirectory $Root -WindowStyle Hidden -PassThru

@{
  api = $api.Id
  worker = $worker.Id
  web = $web.Id
  started_at = (Get-Date).ToString("o")
} | ConvertTo-Json | Set-Content -Encoding UTF8 -Path $ProcessFile

Start-Sleep -Seconds 3
Start-Process "http://127.0.0.1:5173/"
Write-Host "Monday Report partner preview is running at http://127.0.0.1:5173/"
Write-Host "Default local AI model: gemma4:e2b via Ollama."
Write-Host "Sample import package: samples\monday_report_demo_package.zip"
Write-Host "Stop it with .\Stop-MondayReport.ps1"
""",
    )
    write_text(
        STAGING_ROOT / "Stop-MondayReport.ps1",
        r"""$ErrorActionPreference = "SilentlyContinue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProcessFile = Join-Path $Root ".runtime\monday-report-processes.json"
if (!(Test-Path $ProcessFile)) {
  Write-Host "No Monday Report process file found."
  exit 0
}
$processes = Get-Content -Raw -Path $ProcessFile | ConvertFrom-Json
@($processes.api, $processes.worker, $processes.web) | ForEach-Object {
  if ($_ -and (Get-Process -Id $_ -ErrorAction SilentlyContinue)) {
    Stop-Process -Id $_ -Force
  }
}
Remove-Item -Path $ProcessFile -Force
Write-Host "Monday Report partner preview stopped."
""",
    )
    write_text(
        STAGING_ROOT / "Run-ImportExport-Smoke.ps1",
        r"""$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = Join-Path $Root ".runtime\venv\Scripts\python.exe"
if (!(Test-Path $Python)) {
  throw "Runtime not installed. Run .\Start-MondayReport.ps1 first."
}
& $Python scripts\e2e_mvp.py
""",
    )
    write_text(
        STAGING_ROOT / "Start-MondayReport.bat",
        "@echo off\r\npowershell -ExecutionPolicy Bypass -File \"%~dp0Start-MondayReport.ps1\"\r\npause\r\n",
    )


def write_partner_readme() -> None:
    write_text(
        STAGING_ROOT / "README_PARTNER_TESTING.md",
        """# Monday Report Partner Preview

This ZIP is a local demo/testing build for Monday Report. It is not approved for real client data.

## Start

1. Install Python 3.11+.
2. Install Ollama if you want local AI responses.
3. Run `Start-MondayReport.bat` or PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\\Start-MondayReport.ps1
```

The launcher starts the API, static web app, and a local worker loop. It uses Ollama with `gemma4:e2b` as the default model and attempts `ollama pull gemma4:e2b` when Ollama is available.

## Test Import

Open `http://127.0.0.1:5173/`, go to Uploads, and import:

`samples/monday_report_demo_package.zip`

The worker loop processes queued uploads every few seconds.

## Test Export

Use the validation queue to validate extracted items, then create and export the Monday Report as JSON, CSV, HTML, PDF, or XLSX. Export downloads are served through signed local URLs.

## Smoke Test

With the app running:

```powershell
.\\Run-ImportExport-Smoke.ps1
```

## Stop

```powershell
.\\Stop-MondayReport.ps1
```
""",
    )


def write_sample_import_package() -> None:
    if str(ROOT / "scripts") not in sys.path:
        sys.path.insert(0, str(ROOT / "scripts"))
    from phase_audit import build_zip_fixture  # noqa: PLC0415

    sample_path = STAGING_ROOT / "samples" / "monday_report_demo_package.zip"
    sample_path.parent.mkdir(parents=True, exist_ok=True)
    sample_path.write_bytes(build_zip_fixture())


def write_package_manifest() -> None:
    manifest = {
        "name": "Monday Report Partner Preview",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "default_local_ai_runtime": "ollama",
        "default_local_ai_model": "gemma4:e2b",
        "entrypoint": "Start-MondayReport.bat",
        "real_client_data": False,
    }
    write_text(STAGING_ROOT / "package-manifest.json", json.dumps(manifest, indent=2))


def zip_staging() -> None:
    if PACKAGE_ZIP.exists():
        PACKAGE_ZIP.unlink()
    with zipfile.ZipFile(PACKAGE_ZIP, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(STAGING_ROOT.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(STAGING_ROOT.parent))


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
