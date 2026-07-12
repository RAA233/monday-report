from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.fixtures import ANONYMIZED_CLIENT_FIXTURE_MODE  # noqa: E402
from parser_fixture_eval_guard import build_eval_fixtures, write_fake_ocr  # noqa: E402


DEFAULT_OUTPUT = ROOT / "output" / "golden-fixtures" / "anonymized"


def main() -> int:
    args = parse_args()
    output_root = Path(args.output).expanduser().resolve()
    fixture_root = output_root / "fixtures"
    fixture_root.mkdir(parents=True, exist_ok=True)
    top_level_attestation = build_attestation(args.reviewed_by, args.review_note)
    family_classification = top_level_attestation["classification"]

    families: list[dict[str, object]] = []
    for fixture in build_eval_fixtures():
        evidence_path = output_root / fixture.file_name
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
                "attestation": {
                    "classification": family_classification,
                    "contains_client_confidential_data": False,
                },
            }
        )

    manifest = {
        "fixture_set": "monday-report-generated-anonymized-fixtures",
        "fixture_mode": ANONYMIZED_CLIENT_FIXTURE_MODE,
        "attestation": top_level_attestation,
        "families": families,
    }
    manifest_path = output_root / "golden-fixture-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    ocr_dir = output_root / "tools"
    ocr_dir.mkdir(parents=True, exist_ok=True)
    fake_ocr = write_fake_ocr(ocr_dir)

    print(f"Wrote anonymized fixture manifest: {manifest_path}")
    print(f"Wrote fixture OCR shim: {fake_ocr}")
    print(f"Set MONDAY_REPORT_GOLDEN_FIXTURE_MANIFEST={manifest_path}")
    print(f"Set MONDAY_REPORT_OCR_ENGINE=tesseract")
    print(f"Set MONDAY_REPORT_TESSERACT_CMD=\"{sys.executable}\" \"{fake_ocr}\"")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a generated anonymized Monday Report golden fixture pack.")
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Output directory for generated anonymized fixture files and manifest.",
    )
    parser.add_argument(
        "--reviewed-by",
        default="",
        help="Reviewer name to write a reviewed anonymized-client attestation.",
    )
    parser.add_argument(
        "--review-note",
        default="Local readiness review confirmed generated fixtures contain no client-confidential data.",
        help="Review note to include when --reviewed-by is set.",
    )
    return parser.parse_args()


def build_attestation(reviewed_by: str, review_note: str) -> dict[str, object]:
    reviewer = reviewed_by.strip()
    if not reviewer:
        return {
            "classification": "generated_anonymized_engineering_fixture",
            "contains_client_confidential_data": False,
            "purpose": "client-readiness parser/OCR gate smoke evidence",
        }
    return {
        "classification": "reviewed_anonymized_client_fixture",
        "review_status": "approved",
        "reviewed_by": reviewer,
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "contains_client_confidential_data": False,
        "purpose": "client-readiness parser/OCR gate evidence",
        "review_note": review_note,
    }


if __name__ == "__main__":
    sys.exit(main())
