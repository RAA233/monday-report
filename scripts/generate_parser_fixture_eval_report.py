from __future__ import annotations

import argparse
import json
import mimetypes
import os
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.fixture_evals import PARSER_EVAL_REPORT_ENV  # noqa: E402
from backend.app.fixtures import (  # noqa: E402
    ANONYMIZED_CLIENT_FIXTURE_MODE,
    GOLDEN_FIXTURE_MANIFEST_ENV,
    REQUIRED_GOLDEN_FIXTURE_FAMILIES,
)


DEFAULT_OUTPUT = ROOT / "output" / "parser-evals" / "parser_fixture_eval_report.json"
REQUIRED_IDS = tuple(family_id for family_id, _ in REQUIRED_GOLDEN_FIXTURE_FAMILIES)
MIME_OVERRIDES = {
    ".csv": "text/csv",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".eml": "message/rfc822",
    ".pdf": "application/pdf",
    ".txt": "text/plain",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".zip": "application/zip",
}


@dataclass(frozen=True)
class ManifestFamily:
    family_id: str
    evidence_files: tuple[str, ...]
    expected: dict[str, Any]
    notes: str | None = None


def main() -> int:
    args = parse_args()
    manifest_path = resolve_manifest_path(args.manifest)
    output_path = Path(args.output).expanduser().resolve()

    if manifest_path is None:
        print(
            f"FAIL: provide --manifest or set {GOLDEN_FIXTURE_MANIFEST_ENV}.",
            file=sys.stderr,
        )
        return 2
    if not manifest_path.exists():
        print(f"FAIL: manifest does not exist: {manifest_path}", file=sys.stderr)
        return 2

    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: manifest is not readable JSON: {exc}", file=sys.stderr)
        return 2

    if args.state_root:
        state_root = Path(args.state_root).expanduser().resolve()
        state_root.mkdir(parents=True, exist_ok=True)
        report = run_eval(payload, manifest_path, state_root)
    else:
        with tempfile.TemporaryDirectory(prefix="monday-report-parser-eval-report-") as tmp:
            report = run_eval(payload, manifest_path, Path(tmp))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    status = str(report.get("status", "fail"))
    summary = report.get("summary", {})
    print(
        "Wrote parser/OCR eval report "
        f"{output_path} status={status} "
        f"cases={summary.get('case_count')} processed_jobs={summary.get('processed_jobs')}"
    )
    if status == "pass":
        print(f"Set {PARSER_EVAL_REPORT_ENV}={output_path}")
        return 0
    return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a parser/OCR eval report from an anonymized Monday Report golden fixture manifest."
    )
    parser.add_argument(
        "--manifest",
        default=os.getenv(GOLDEN_FIXTURE_MANIFEST_ENV, "").strip(),
        help=f"Path to the golden fixture manifest. Defaults to {GOLDEN_FIXTURE_MANIFEST_ENV}.",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Path for the generated parser/OCR eval report JSON.",
    )
    parser.add_argument(
        "--state-root",
        default="",
        help="Optional isolated state root for debugging. Defaults to a temporary directory.",
    )
    return parser.parse_args()


def resolve_manifest_path(value: str) -> Path | None:
    cleaned = value.strip()
    if not cleaned:
        return None
    return Path(cleaned).expanduser().resolve()


def run_eval(payload: dict[str, Any], manifest_path: Path, state_root: Path) -> dict[str, Any]:
    configure_isolated_environment(state_root)

    from backend.app.main import app
    from backend.app.store import store

    client = TestClient(app)
    workspace = next(iter(store.workspaces.values()))
    manifest_root = manifest_path.parent
    manifest_families = parse_manifest_families(payload)
    input_ids = tuple(family.family_id for family in manifest_families)
    family_map = {family.family_id: family for family in manifest_families}

    uploaded_file_ids: dict[str, list[UUID]] = {family_id: [] for family_id in REQUIRED_IDS}
    upload_errors: dict[str, list[dict[str, Any]]] = {family_id: [] for family_id in REQUIRED_IDS}

    for family in manifest_families:
        if family.family_id not in uploaded_file_ids:
            uploaded_file_ids[family.family_id] = []
            upload_errors[family.family_id] = []
        for evidence_value in family.evidence_files:
            evidence_path = resolve_evidence_path(evidence_value, manifest_root)
            if not evidence_path.exists() or not evidence_path.is_file():
                upload_errors[family.family_id].append(
                    {
                        "file": report_file_label(evidence_value),
                        "status_code": None,
                        "detail": "evidence file does not exist",
                    }
                )
                continue
            response = upload_fixture_file(client, workspace.id, evidence_value, evidence_path)
            if response.status_code == 201:
                uploaded_file_ids[family.family_id].append(UUID(response.json()["file"]["id"]))
            else:
                upload_errors[family.family_id].append(
                    {
                        "file": report_file_label(evidence_value),
                        "status_code": response.status_code,
                        "detail": response_detail(response),
                    }
                )

    processed_jobs = process_all_jobs(store)
    store.refresh()

    cases = [
        build_case(store, family_map.get(family_id), family_id, uploaded_file_ids, upload_errors)
        for family_id in REQUIRED_IDS
    ]
    for family in manifest_families:
        if family.family_id not in REQUIRED_IDS:
            cases.append(
                {
                    "id": f"case-{family.family_id}",
                    "family": family.family_id,
                    "status": "fail",
                    "files": [report_file_label(item) for item in family.evidence_files],
                    "observed": {},
                    "checks": [
                        {
                            "name": "known_required_family",
                            "status": "fail",
                            "detail": f"{family.family_id!r} is not a required fixture family.",
                        }
                    ],
                }
            )

    mode = str(payload.get("fixture_mode", "")).strip().lower()
    mode_ok = mode == ANONYMIZED_CLIENT_FIXTURE_MODE
    duplicate_ids = sorted({family_id for family_id in input_ids if input_ids.count(family_id) > 1})
    manifest_checks = [
        {
            "name": "fixture_mode",
            "status": "pass" if mode_ok else "fail",
            "detail": (
                f"fixture_mode is {ANONYMIZED_CLIENT_FIXTURE_MODE!r}"
                if mode_ok
                else f"fixture_mode must be {ANONYMIZED_CLIENT_FIXTURE_MODE!r}, got {mode!r}"
            ),
        },
        {
            "name": "unique_family_ids",
            "status": "pass" if not duplicate_ids else "fail",
            "detail": duplicate_ids or "all manifest family ids are unique",
        },
    ]
    all_case_checks = [check for case in cases for check in case.get("checks", [])]
    status = (
        "pass"
        if all(check.get("status") == "pass" for check in manifest_checks + all_case_checks)
        and len(cases) >= len(REQUIRED_IDS)
        else "fail"
    )
    return {
        "fixture_set": str(payload.get("fixture_set") or manifest_path.stem),
        "fixture_mode": mode or None,
        "status": status,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/generate_parser_fixture_eval_report.py",
        "manifest": {
            "path": str(manifest_path),
            "required_family_count": len(REQUIRED_IDS),
            "input_family_count": len(manifest_families),
        },
        "summary": {
            "case_count": len(cases),
            "passed_cases": sum(1 for case in cases if case.get("status") == "pass"),
            "failed_cases": sum(1 for case in cases if case.get("status") != "pass"),
            "processed_jobs": processed_jobs,
            "readiness_env": PARSER_EVAL_REPORT_ENV,
        },
        "manifest_checks": manifest_checks,
        "cases": cases,
    }


def configure_isolated_environment(state_root: Path) -> None:
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
    os.environ["MONDAY_REPORT_DISABLE_DEMO_SEED"] = "true"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Parser Eval Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "parser-eval"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "parser-eval@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Parser Eval Runner"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Parser/OCR eval workspace"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(state_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(state_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(state_root / "exports")
    os.environ.pop(PARSER_EVAL_REPORT_ENV, None)


def parse_manifest_families(payload: dict[str, Any]) -> list[ManifestFamily]:
    families = payload.get("families", [])
    if not isinstance(families, list):
        return []

    parsed: list[ManifestFamily] = []
    for item in families:
        if not isinstance(item, dict):
            continue
        family_id = str(item.get("id", "")).strip().lower()
        if not family_id:
            continue
        evidence = item.get("evidence_files", item.get("evidence", []))
        if isinstance(evidence, str):
            evidence_files = (evidence,)
        elif isinstance(evidence, list):
            evidence_files = tuple(str(value).strip() for value in evidence if str(value).strip())
        else:
            evidence_files = ()
        expected = item.get("expected", {})
        parsed.append(
            ManifestFamily(
                family_id=family_id,
                evidence_files=evidence_files,
                expected=expected if isinstance(expected, dict) else {},
                notes=str(item.get("notes")) if item.get("notes") else None,
            )
        )
    return parsed


def upload_fixture_file(client: TestClient, workspace_id: UUID, evidence_value: str, path: Path):
    source_type = "zip" if path.suffix.lower() == ".zip" else "files"
    return client.post(
        "/uploads/direct",
        data={
            "workspace_id": str(workspace_id),
            "file_name": upload_original_path(evidence_value, path),
            "source_type": source_type,
        },
        files={"file": (path.name, path.read_bytes(), guess_mime_type(path))},
    )


def process_all_jobs(store: Any) -> int:
    total = 0
    for _ in range(25):
        processed = store.process_queued_jobs()
        total += processed
        if processed == 0:
            return total
    return total


def build_case(
    store: Any,
    family: ManifestFamily | None,
    family_id: str,
    uploaded_file_ids: dict[str, list[UUID]],
    upload_errors: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    if family is None:
        return {
            "id": f"case-{family_id}",
            "family": family_id,
            "status": "fail",
            "files": [],
            "observed": {},
            "checks": [
                {"name": "manifest_family_present", "status": "fail", "detail": "family missing from manifest"}
            ],
        }

    case_file_ids = expanded_case_file_ids(store, uploaded_file_ids.get(family_id, []))
    documents = [
        document for document in store.parsed_documents.values() if document.file_id in case_file_ids
    ]
    chunks = [chunk for chunk in store.document_chunks.values() if chunk.file_id in case_file_ids]
    jobs = [job for job in store.jobs.values() if job.file_id in case_file_ids]
    file_records = [file_record for file_id, file_record in store.files.items() if file_id in case_file_ids]
    failures = [
        failure
        for failure in store.failures.values()
        if any(citation.file_id in case_file_ids for citation in failure.citations)
    ]

    parser_names = sorted({document.parser_name for document in documents})
    locator_types = sorted({chunk.locator_type for chunk in chunks})
    job_statuses = sorted({job.status.value for job in jobs})
    job_results = sorted({str(job.payload.get("result")) for job in jobs if job.payload.get("result") is not None})
    checks = [
        {
            "name": "manifest_family_present",
            "status": "pass",
            "detail": "family present in manifest",
        },
        {
            "name": "evidence_files_present",
            "status": "pass" if family.evidence_files else "fail",
            "detail": [report_file_label(item) for item in family.evidence_files],
        },
        {
            "name": "uploads_accepted",
            "status": "pass"
            if len(uploaded_file_ids.get(family_id, [])) == len(family.evidence_files) and not upload_errors.get(family_id)
            else "fail",
            "detail": {
                "accepted": len(uploaded_file_ids.get(family_id, [])),
                "expected": len(family.evidence_files),
                "errors": upload_errors.get(family_id, []),
            },
        },
    ]
    add_expected_checks(checks, family, parser_names, locator_types, chunks, failures, jobs, store, case_file_ids, uploaded_file_ids)

    return {
        "id": f"case-{family_id}",
        "family": family_id,
        "status": "pass" if all(check["status"] == "pass" for check in checks) else "fail",
        "files": [report_file_label(item) for item in family.evidence_files],
        "notes": family.notes,
        "observed": {
            "parser_names": parser_names,
            "locator_types": locator_types,
            "chunk_count": len(chunks),
            "job_statuses": job_statuses,
            "job_results": job_results,
            "failure_count": len(failures),
            "sha256": sorted({file_record.sha256 for file_record in file_records}),
        },
        "checks": checks,
    }


def add_expected_checks(
    checks: list[dict[str, Any]],
    family: ManifestFamily,
    parser_names: list[str],
    locator_types: list[str],
    chunks: list[Any],
    failures: list[Any],
    jobs: list[Any],
    store: Any,
    case_file_ids: set[UUID],
    uploaded_file_ids: dict[str, list[UUID]],
) -> None:
    expected = family.expected
    if not expected:
        checks.append(
            {
                "name": "expected_contract_present",
                "status": "fail",
                "detail": "family expected contract is missing",
            }
        )
        return

    expected_parser = expected.get("parser")
    if expected_parser:
        checks.append(
            {
                "name": "expected_parser",
                "status": "pass" if expected_parser in parser_names else "fail",
                "detail": {"expected": expected_parser, "observed": parser_names},
            }
        )

    expected_locator = expected.get("locator_type")
    if expected_locator:
        checks.append(
            {
                "name": "expected_locator",
                "status": "pass" if expected_locator in locator_types else "fail",
                "detail": {"expected": expected_locator, "observed": locator_types},
            }
        )

    if expected_parser or expected_locator:
        checks.append(
            {
                "name": "chunks_created",
                "status": "pass" if chunks else "fail",
                "detail": len(chunks),
            }
        )

    if "failure_extracted" in expected:
        should_extract = bool(expected.get("failure_extracted"))
        ok = bool(failures) if should_extract else not failures
        checks.append(
            {
                "name": "failure_extracted",
                "status": "pass" if ok else "fail",
                "detail": {"expected": should_extract, "observed": len(failures)},
            }
        )

    expected_job_status = expected.get("job_status")
    if expected_job_status:
        observed = sorted({job.status.value for job in jobs})
        checks.append(
            {
                "name": "expected_job_status",
                "status": "pass" if expected_job_status in observed else "fail",
                "detail": {"expected": expected_job_status, "observed": observed},
            }
        )

    expected_job_result = expected.get("job_result")
    if expected_job_result:
        observed = sorted({str(job.payload.get("result")) for job in jobs if job.payload.get("result") is not None})
        checks.append(
            {
                "name": "expected_job_result",
                "status": "pass" if expected_job_result in observed else "fail",
                "detail": {"expected": expected_job_result, "observed": observed},
            }
        )

    duplicate_of = expected.get("duplicate_sha256_of")
    if duplicate_of:
        own_sha = family_sha256_values(store, case_file_ids)
        reference_file_ids = expanded_case_file_ids(store, uploaded_file_ids.get(str(duplicate_of).strip().lower(), []))
        reference_sha = family_sha256_values(store, reference_file_ids)
        checks.append(
            {
                "name": "duplicate_sha256",
                "status": "pass" if bool(own_sha & reference_sha) else "fail",
                "detail": {
                    "duplicate_of": duplicate_of,
                    "matched": sorted(own_sha & reference_sha),
                },
            }
        )


def expanded_case_file_ids(store: Any, root_file_ids: list[UUID]) -> set[UUID]:
    case_file_ids = set(root_file_ids)
    upload_ids = {
        store.files[file_id].upload_id
        for file_id in root_file_ids
        if file_id in store.files
    }
    for file_id, file_record in store.files.items():
        if file_record.upload_id in upload_ids:
            case_file_ids.add(file_id)
    return case_file_ids


def family_sha256_values(store: Any, file_ids: set[UUID]) -> set[str]:
    return {
        file_record.sha256
        for file_id, file_record in store.files.items()
        if file_id in file_ids and file_record.sha256
    }


def resolve_evidence_path(value: str, manifest_root: Path) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else manifest_root / path


def upload_original_path(evidence_value: str, path: Path) -> str:
    candidate = Path(evidence_value)
    if candidate.is_absolute():
        return path.name
    return evidence_value.replace("\\", "/")


def report_file_label(value: str) -> str:
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate.name
    return value.replace("\\", "/")


def guess_mime_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in MIME_OVERRIDES:
        return MIME_OVERRIDES[suffix]
    guessed, _ = mimetypes.guess_type(path.name)
    return guessed or "application/octet-stream"


def response_detail(response: Any) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text


if __name__ == "__main__":
    sys.exit(main())
