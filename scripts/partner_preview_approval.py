from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ZIP = ROOT / "output" / "package" / "Monday_Report_Partner_Preview.zip"
APPROVAL_JSON = ROOT / "output" / "package" / "Monday_Report_Partner_Preview_APPROVAL.json"
APPROVAL_MD = ROOT / "output" / "package" / "Monday_Report_Partner_Preview_APPROVAL.md"
APPROVED_SCOPE = "partner_demo_testing_only"
STALE_BRANDING_NEEDLES = ("Ara" + "mco", "Rig" + "Intel", "rig-report-" + "intelligence-saas")


def main() -> int:
    args = parse_args()
    result = build_approval()
    if not args.verify_only:
        APPROVAL_JSON.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        APPROVAL_MD.write_text(render_markdown(result), encoding="utf-8")

    status = "APPROVED" if result["approved"] else "NOT APPROVED"
    print(f"{status}: {result['scope']} - {result['summary']}")
    print(f"Package: {result['package']['path']}")
    print(f"SHA256: {result['package']['sha256']}")
    if not args.verify_only:
        print(f"Approval JSON: {APPROVAL_JSON}")
        print(f"Approval MD: {APPROVAL_MD}")
    return 0 if result["approved"] else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Approve the current Monday Report partner preview package.")
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify approval criteria without writing approval artifacts.",
    )
    return parser.parse_args()


def build_approval() -> dict[str, object]:
    checks = [
        package_exists_check(),
        package_required_entries_check(),
        package_manifest_check(),
        source_branding_check(),
        package_branding_check(),
    ]
    approved = all(check["status"] == "pass" for check in checks)
    package_info = {
        "path": str(PACKAGE_ZIP),
        "sha256": sha256_file(PACKAGE_ZIP) if PACKAGE_ZIP.exists() else None,
        "byte_size": PACKAGE_ZIP.stat().st_size if PACKAGE_ZIP.exists() else 0,
    }
    return {
        "approved": approved,
        "scope": APPROVED_SCOPE,
        "summary": (
            "Partner preview package is approved for demo/testing with synthetic data only."
            if approved
            else "Partner preview package failed one or more approval checks."
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "package": package_info,
        "default_local_ai": {
            "runtime": "ollama",
            "model": "gemma4:e2b",
            "hosted_fallback": False,
        },
        "real_client_data": {
            "approved": False,
            "reason": "Real-client readiness still requires production infrastructure, security config, parser/OCR fixture evidence, and local extraction evals.",
        },
        "checks": checks,
    }


def package_exists_check() -> dict[str, object]:
    return check("package_exists", PACKAGE_ZIP.exists() and PACKAGE_ZIP.stat().st_size > 0, str(PACKAGE_ZIP))


def package_required_entries_check() -> dict[str, object]:
    required_entries = {
        "MondayReportPartnerPreview/Start-MondayReport.bat",
        "MondayReportPartnerPreview/Start-MondayReport.ps1",
        "MondayReportPartnerPreview/Stop-MondayReport.ps1",
        "MondayReportPartnerPreview/Run-ImportExport-Smoke.ps1",
        "MondayReportPartnerPreview/README_PARTNER_TESTING.md",
        "MondayReportPartnerPreview/dist/index.html",
        "MondayReportPartnerPreview/backend/app/main.py",
        "MondayReportPartnerPreview/scripts/partner_worker_loop.py",
        "MondayReportPartnerPreview/samples/monday_report_demo_package.zip",
        "MondayReportPartnerPreview/package-manifest.json",
    }
    entries = package_entries()
    missing = sorted(required_entries - entries)
    return check("package_required_entries", not missing, {"missing": missing, "entry_count": len(entries)})


def package_manifest_check() -> dict[str, object]:
    manifest = read_package_manifest()
    ok = (
        manifest.get("default_local_ai_runtime") == "ollama"
        and manifest.get("default_local_ai_model") == "gemma4:e2b"
        and manifest.get("real_client_data") is False
        and manifest.get("entrypoint") == "Start-MondayReport.bat"
    )
    return check("package_manifest", ok, manifest)


def source_branding_check() -> dict[str, object]:
    result = subprocess.run(
        [
            "rg",
            "-n",
            "|".join(STALE_BRANDING_NEEDLES),
            "--hidden",
            "-g",
            "!node_modules/**",
            "-g",
            "!dist/**",
            "-g",
            "!output/**",
            "-g",
            "!.git/**",
            ".",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return check(
        "source_branding_scan",
        result.returncode == 1 and not result.stdout.strip(),
        {"returncode": result.returncode, "stdout": result.stdout[:500], "stderr": result.stderr[:500]},
    )


def package_branding_check() -> dict[str, object]:
    hits: list[dict[str, str]] = []
    if PACKAGE_ZIP.exists():
        with zipfile.ZipFile(PACKAGE_ZIP) as archive:
            for info in archive.infolist():
                if info.is_dir() or info.file_size > 2_000_000:
                    continue
                suffix = Path(info.filename).suffix.lower()
                if suffix not in {".txt", ".md", ".json", ".py", ".ps1", ".bat", ".html", ".css", ".js", ".ts", ".tsx", ".sql", ".example"} and "README" not in info.filename:
                    continue
                try:
                    text = archive.read(info).decode("utf-8")
                except UnicodeDecodeError:
                    continue
                for needle in STALE_BRANDING_NEEDLES:
                    if needle in text:
                        hits.append({"file": info.filename, "needle": needle})
    return check("package_branding_scan", not hits, hits)


def package_entries() -> set[str]:
    if not PACKAGE_ZIP.exists():
        return set()
    with zipfile.ZipFile(PACKAGE_ZIP) as archive:
        return set(archive.namelist())


def read_package_manifest() -> dict[str, object]:
    if not PACKAGE_ZIP.exists():
        return {}
    with zipfile.ZipFile(PACKAGE_ZIP) as archive:
        try:
            return json.loads(archive.read("MondayReportPartnerPreview/package-manifest.json").decode("utf-8"))
        except (KeyError, json.JSONDecodeError, UnicodeDecodeError):
            return {}


def check(check_id: str, ok: bool, detail: object) -> dict[str, object]:
    return {"id": check_id, "status": "pass" if ok else "fail", "detail": detail}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def render_markdown(result: dict[str, object]) -> str:
    package = result["package"] if isinstance(result["package"], dict) else {}
    checks = result["checks"] if isinstance(result["checks"], list) else []
    lines = [
        "# Monday Report Partner Preview Approval",
        "",
        f"Status: {'APPROVED' if result['approved'] else 'NOT APPROVED'}",
        f"Scope: `{result['scope']}`",
        f"Generated: `{result['generated_at']}`",
        "",
        "## Package",
        "",
        f"- Path: `{package.get('path')}`",
        f"- SHA256: `{package.get('sha256')}`",
        f"- Byte size: `{package.get('byte_size')}`",
        "",
        "## Local AI",
        "",
        "- Runtime: `ollama`",
        "- Default model: `gemma4:e2b`",
        "- Hosted fallback: `false`",
        "",
        "## Data Posture",
        "",
        "- Approved for partner demo/testing with synthetic data only.",
        "- Not approved for real client data.",
        "",
        "## Checks",
        "",
    ]
    for item in checks:
        if isinstance(item, dict):
            lines.append(f"- {item.get('status', 'fail').upper()}: `{item.get('id')}`")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
