from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ZIP = ROOT / "output" / "package" / "Monday_Report_Partner_Preview.zip"


def main() -> int:
    checks: list[dict[str, object]] = []
    result = subprocess.run(
        [sys.executable, "scripts/build_partner_preview_package.py", "--skip-build"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    checks.append(
        assert_check(
            "Partner preview package builds",
            result.returncode == 0 and PACKAGE_ZIP.exists() and PACKAGE_ZIP.stat().st_size > 0,
            {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr},
        )
    )

    entries: set[str] = set()
    manifest: dict[str, object] = {}
    if PACKAGE_ZIP.exists():
        with zipfile.ZipFile(PACKAGE_ZIP) as archive:
            entries = set(archive.namelist())
            manifest = json.loads(archive.read("MondayReportPartnerPreview/package-manifest.json").decode("utf-8"))

    required_entries = {
        "MondayReportPartnerPreview/Start-MondayReport.bat",
        "MondayReportPartnerPreview/Start-MondayReport.ps1",
        "MondayReportPartnerPreview/Stop-MondayReport.ps1",
        "MondayReportPartnerPreview/Run-ImportExport-Smoke.ps1",
        "MondayReportPartnerPreview/README_PARTNER_TESTING.md",
        "MondayReportPartnerPreview/dist/index.html",
        "MondayReportPartnerPreview/backend/app/main.py",
        "MondayReportPartnerPreview/backend/requirements.txt",
        "MondayReportPartnerPreview/scripts/partner_worker_loop.py",
        "MondayReportPartnerPreview/scripts/partner_preview_server.py",
        "MondayReportPartnerPreview/samples/monday_report_demo_package.zip",
        "MondayReportPartnerPreview/config/partner.env.example",
    }
    checks.append(
        assert_check(
            "Partner preview package has required files",
            required_entries.issubset(entries),
            sorted(required_entries - entries),
        )
    )
    checks.append(
        assert_check(
            "Partner preview defaults to Gemma 4 E2B",
            manifest.get("default_local_ai_runtime") == "ollama"
            and manifest.get("default_local_ai_model") == "gemma4:e2b",
            manifest,
        )
    )
    checks.append(
        assert_check(
            "Partner preview contains import/export smoke launcher",
            "MondayReportPartnerPreview/Run-ImportExport-Smoke.ps1" in entries
            and "MondayReportPartnerPreview/samples/monday_report_demo_package.zip" in entries,
            "smoke launcher and sample package present",
        )
    )

    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")
    return 1 if any(not check["ok"] for check in checks) else 0


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    raise SystemExit(main())
