from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.fixture_evals import PARSER_EVAL_REPORT_ENV, evaluate_parser_fixture_eval_readiness  # noqa: E402
from backend.app.fixtures import REQUIRED_GOLDEN_FIXTURE_FAMILIES  # noqa: E402
from parser_fixture_eval_guard import build_eval_fixtures, write_fake_ocr  # noqa: E402


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-parser-eval-cli-") as tmp:
        tmp_root = Path(tmp)
        fixture_root = tmp_root / "fixture-set"
        manifest = write_manifest(fixture_root)
        output_without_ocr = tmp_root / "parser-eval-without-ocr.json"
        output_with_ocr = tmp_root / "parser-eval-with-ocr.json"

        no_ocr = run_generator(manifest, output_without_ocr, tmp_root / "no-ocr-state", ocr_command=None)
        no_ocr_report = read_json(output_without_ocr)
        scanned_no_ocr = case_for(no_ocr_report, "scanned_pdf")
        checks.append(
            assert_check(
                "Parser eval report generator fails scanned fixture without OCR",
                no_ocr.returncode == 1
                and no_ocr_report.get("status") == "fail"
                and scanned_no_ocr.get("status") == "fail",
                {
                    "returncode": no_ocr.returncode,
                    "stdout": no_ocr.stdout,
                    "stderr": no_ocr.stderr,
                    "scanned_case": scanned_no_ocr,
                },
            )
        )

        fake_ocr = write_fake_ocr(tmp_root)
        with_ocr = run_generator(
            manifest,
            output_with_ocr,
            tmp_root / "with-ocr-state",
            ocr_command=f'"{sys.executable}" "{fake_ocr}"',
        )
        passing_report = read_json(output_with_ocr)
        checks.append(
            assert_check(
                "Parser eval report generator writes passing report with configured OCR",
                with_ocr.returncode == 0
                and passing_report.get("status") == "pass"
                and len(passing_report.get("cases", [])) == len(REQUIRED_GOLDEN_FIXTURE_FAMILIES)
                and all(case.get("status") == "pass" for case in passing_report.get("cases", [])),
                {
                    "returncode": with_ocr.returncode,
                    "stdout": with_ocr.stdout,
                    "stderr": with_ocr.stderr,
                    "summary": passing_report.get("summary"),
                },
            )
        )

        os.environ[PARSER_EVAL_REPORT_ENV] = str(output_with_ocr)
        readiness = evaluate_parser_fixture_eval_readiness()
        checks.append(
            assert_check(
                "Generated report certifies parser/OCR eval readiness",
                readiness.ready
                and f"{len(REQUIRED_GOLDEN_FIXTURE_FAMILIES)}/{len(REQUIRED_GOLDEN_FIXTURE_FAMILIES)}"
                in readiness.detail,
                readiness,
            )
        )

    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")
    return 1 if any(not check["ok"] for check in checks) else 0


def write_manifest(root: Path) -> Path:
    fixtures = build_eval_fixtures()
    families = []
    for fixture in fixtures:
        evidence_path = root / fixture.file_name
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_bytes(fixture.content)
        expected: dict[str, object]
        if fixture.expected_parser:
            expected = {
                "parser": fixture.expected_parser,
                "locator_type": fixture.expected_locator,
            }
            if fixture.expected_failure:
                expected["failure_extracted"] = True
            if fixture.duplicate_of:
                expected["duplicate_sha256_of"] = fixture.duplicate_of
        else:
            expected = {
                "job_status": "failed",
                "job_result": fixture.expected_job_result,
            }
        families.append(
            {
                "id": fixture.family,
                "evidence_files": [fixture.file_name],
                "expected": expected,
            }
        )

    manifest = root / "golden-fixture-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "fixture_set": "parser-eval-cli-guard",
                "fixture_mode": "anonymized_client",
                "families": families,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return manifest


def run_generator(manifest: Path, output: Path, state_root: Path, ocr_command: str | None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["MONDAY_REPORT_OCR_ENGINE"] = "tesseract" if ocr_command else ""
    if ocr_command:
        env["MONDAY_REPORT_TESSERACT_CMD"] = ocr_command
    else:
        env.pop("MONDAY_REPORT_TESSERACT_CMD", None)
    env.pop(PARSER_EVAL_REPORT_ENV, None)

    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "generate_parser_fixture_eval_report.py"),
            "--manifest",
            str(manifest),
            "--output",
            str(output),
            "--state-root",
            str(state_root),
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def case_for(report: dict, family: str) -> dict:
    for item in report.get("cases", []):
        if item.get("family") == family:
            return item
    return {}


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
