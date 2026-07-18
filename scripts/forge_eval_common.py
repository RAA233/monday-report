"""Shared helpers for the FORGE evaluation guard family.

The committed manifest/expectations under evals/forge/ are the reviewed
authority; these helpers validate that specification portably (no corpus
required) and evaluate reviewed checks against real extraction surfaces.
Nothing here imports the backend app, so spec validation stays corpus-free
and side-effect free.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "evals" / "forge" / "manifest.v1.json"
EXPECTATIONS_PATH = ROOT / "evals" / "forge" / "expectations.v1.json"
OUTPUT_DIR = ROOT / "output" / "forge-evals"
DEFAULT_CORPUS_ROOT = ROOT / "16A(78)-32_Daily_Reports"
CORPUS_ROOT_ENV = "MONDAY_REPORT_FORGE_CORPUS_ROOT"

ALLOWED_CHECK_TYPES = {
    "equals",
    "approximately_equals",
    "contains_row",
    "row_count",
    "absent",
    "source_state",
    "evidence_present",
}
ALLOWED_EXTRACTORS = {
    "report_profile",
    "casing_strings",
    "activity_timeline",
    "survey_stations",
    "hydraulics_observations",
    "report_draft",
}
ALLOWED_SOURCE_STATES = {"source", "reference", "none", "calculated"}
ALLOWED_REPORT_FAMILIES = {"drilling", "completion"}
MAX_STRING_LENGTH = 400
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ABSOLUTE_PATH_PATTERN = re.compile(r"(^[A-Za-z]:[\\/])|(\\\\)|(^//)|(^/(?:home|Users)/)")
SECRET_PATTERN = re.compile(
    r"password|api[_-]?key|secret|bearer\s|private key|authorization:", re.IGNORECASE
)


def resolve_corpus_root() -> Path:
    override = os.getenv(CORPUS_ROOT_ENV, "").strip()
    return Path(override) if override else DEFAULT_CORPUS_ROOT


def load_manifest() -> dict[str, Any]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def load_expectations() -> dict[str, Any]:
    return json.loads(EXPECTATIONS_PATH.read_text(encoding="utf-8"))


def iter_strings(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        found.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            found.extend(iter_strings(key))
            found.extend(iter_strings(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(iter_strings(item))
    return found


def _relative_path_errors(path_value: str, context: str) -> list[str]:
    errors: list[str] = []
    if ABSOLUTE_PATH_PATTERN.search(path_value):
        errors.append(f"{context}: absolute path is not allowed: {path_value!r}")
    if "\\" in path_value:
        errors.append(f"{context}: backslash separators are not allowed: {path_value!r}")
    if ".." in path_value.split("/"):
        errors.append(f"{context}: parent traversal is not allowed: {path_value!r}")
    return errors


def validate_spec(manifest: dict[str, Any], expectations: dict[str, Any]) -> list[str]:
    """Portable specification validation. Returns a list of error strings."""

    errors: list[str] = []

    if manifest.get("manifest_version") != "v1":
        errors.append("manifest: manifest_version must be 'v1'")
    if not str(manifest.get("corpus_id", "")).strip():
        errors.append("manifest: corpus_id is required")
    if manifest.get("selection_method") != "reviewed_stratified_fixed_set":
        errors.append("manifest: selection_method must be 'reviewed_stratified_fixed_set'")

    documents = manifest.get("documents")
    if not isinstance(documents, list) or not documents:
        errors.append("manifest: documents must be a non-empty list")
        documents = []

    doc_ids: set[str] = set()
    sha_by_doc: dict[str, str] = {}
    pages_by_doc: dict[str, int] = {}
    seen_shas: set[str] = set()
    for index, doc in enumerate(documents):
        context = f"manifest.documents[{index}]"
        doc_id = str(doc.get("document_id", "")).strip()
        if not doc_id:
            errors.append(f"{context}: document_id is required")
        elif doc_id in doc_ids:
            errors.append(f"{context}: duplicate document_id {doc_id!r}")
        doc_ids.add(doc_id)

        relative_path = str(doc.get("relative_path", ""))
        if not relative_path:
            errors.append(f"{context}: relative_path is required")
        errors.extend(_relative_path_errors(relative_path, context))

        sha = str(doc.get("sha256", ""))
        if not SHA256_PATTERN.match(sha):
            errors.append(f"{context}: sha256 must be 64 lowercase hex characters")
        elif sha in seen_shas:
            errors.append(f"{context}: duplicate sha256 {sha[:12]}…")
        seen_shas.add(sha)
        sha_by_doc[doc_id] = sha

        page_count = doc.get("page_count")
        if not isinstance(page_count, int) or page_count < 1:
            errors.append(f"{context}: page_count must be a positive integer")
        else:
            pages_by_doc[doc_id] = page_count

        if doc.get("report_family") not in ALLOWED_REPORT_FAMILIES:
            errors.append(f"{context}: report_family must be one of {sorted(ALLOWED_REPORT_FAMILIES)}")
        if not str(doc.get("format_variant", "")).strip():
            errors.append(f"{context}: format_variant is required")
        if not str(doc.get("selection_reason", "")).strip():
            errors.append(f"{context}: selection_reason is required")

    if expectations.get("expectations_version") != "v1":
        errors.append("expectations: expectations_version must be 'v1'")
    if expectations.get("manifest_version") != manifest.get("manifest_version"):
        errors.append("expectations: manifest_version must match the manifest")
    if expectations.get("corpus_id") != manifest.get("corpus_id"):
        errors.append("expectations: corpus_id must match the manifest")

    checks = expectations.get("checks")
    if not isinstance(checks, list) or not checks:
        errors.append("expectations: checks must be a non-empty list")
        checks = []

    check_ids: set[str] = set()
    covered_docs: set[str] = set()
    for index, entry in enumerate(checks):
        context = f"expectations.checks[{index}]"
        check_id = str(entry.get("check_id", "")).strip()
        if not check_id:
            errors.append(f"{context}: check_id is required")
        elif check_id in check_ids:
            errors.append(f"{context}: duplicate check_id {check_id!r}")
        check_ids.add(check_id)

        doc_id = str(entry.get("document_id", ""))
        if doc_id not in doc_ids:
            errors.append(f"{context}: unknown document_id {doc_id!r} (orphan expectation)")
        else:
            if entry.get("required") is True:
                covered_docs.add(doc_id)
            if entry.get("document_sha256") != sha_by_doc.get(doc_id):
                errors.append(f"{context}: document_sha256 does not match the manifest entry")
            page = entry.get("page")
            max_page = pages_by_doc.get(doc_id, 1)
            if not isinstance(page, int) or page < 1 or page > max_page:
                errors.append(f"{context}: page must be within 1..{max_page}")

        if entry.get("extractor") not in ALLOWED_EXTRACTORS:
            errors.append(f"{context}: extractor must be one of {sorted(ALLOWED_EXTRACTORS)}")

        check_type = entry.get("check_type")
        if check_type not in ALLOWED_CHECK_TYPES:
            errors.append(f"{context}: unsupported check_type {check_type!r}")

        target = str(entry.get("target", ""))
        if not (target.startswith("profile.") or target.startswith("draft.")):
            errors.append(f"{context}: target must start with 'profile.' or 'draft.'")

        if not isinstance(entry.get("required"), bool):
            errors.append(f"{context}: required must be a boolean")

        review = entry.get("review")
        if not isinstance(review, dict):
            errors.append(f"{context}: review metadata is required")
        else:
            if review.get("review_status") != "reviewed":
                errors.append(f"{context}: review_status must be 'reviewed'")
            if not isinstance(review.get("reviewed_source_page"), int):
                errors.append(f"{context}: reviewed_source_page must be an integer")
            if not str(review.get("review_note", "")).strip():
                errors.append(f"{context}: review_note is required")

        if check_type == "equals":
            if "expected" not in entry:
                errors.append(f"{context}: equals requires expected")
        elif check_type == "approximately_equals":
            if not isinstance(entry.get("expected"), (int, float)) or isinstance(entry.get("expected"), bool):
                errors.append(f"{context}: approximately_equals requires a numeric expected value")
            tolerance = entry.get("tolerance")
            if not isinstance(tolerance, (int, float)) or isinstance(tolerance, bool) or tolerance < 0:
                errors.append(f"{context}: approximately_equals requires tolerance >= 0")
        elif check_type == "contains_row":
            expected_row = entry.get("expected_row")
            if not isinstance(expected_row, dict) or not expected_row:
                errors.append(f"{context}: contains_row requires a non-empty expected_row")
            else:
                for field, spec in expected_row.items():
                    if isinstance(spec, dict):
                        value = spec.get("value")
                        tolerance = spec.get("tolerance")
                        if not isinstance(value, (int, float)) or isinstance(value, bool):
                            errors.append(f"{context}: expected_row.{field} value must be numeric")
                        if (
                            not isinstance(tolerance, (int, float))
                            or isinstance(tolerance, bool)
                            or tolerance < 0
                        ):
                            errors.append(f"{context}: expected_row.{field} tolerance must be >= 0")
        elif check_type == "row_count":
            expected = entry.get("expected")
            if not isinstance(expected, int) or isinstance(expected, bool) or expected < 0:
                errors.append(f"{context}: row_count requires a non-negative integer expected value")
        elif check_type == "absent":
            if "expected" in entry or "expected_row" in entry:
                errors.append(f"{context}: absent must not define an expected value")
        elif check_type == "source_state":
            if entry.get("expected") not in ALLOWED_SOURCE_STATES:
                errors.append(f"{context}: source_state expected must be one of {sorted(ALLOWED_SOURCE_STATES)}")
        elif check_type == "evidence_present":
            if not isinstance(entry.get("expected"), int) or isinstance(entry.get("expected"), bool):
                errors.append(f"{context}: evidence_present requires an integer expected page")

    for doc_id in sorted(doc_ids):
        if doc_id and doc_id not in covered_docs:
            errors.append(f"expectations: document {doc_id!r} has no required expectation coverage")

    for payload_name, payload in (("manifest", manifest), ("expectations", expectations)):
        for text in iter_strings(payload):
            if len(text) > MAX_STRING_LENGTH:
                errors.append(
                    f"{payload_name}: string longer than {MAX_STRING_LENGTH} characters "
                    "(copied prose is not allowed)"
                )
            if ABSOLUTE_PATH_PATTERN.search(text) or "\\" in text:
                errors.append(f"{payload_name}: absolute or machine-local path fragment found: {text[:60]!r}")
            if SECRET_PATTERN.search(text):
                errors.append(f"{payload_name}: secret-like content found: {text[:60]!r}")

    return errors


def _normalize_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        cleaned = value.replace(",", "").replace(" ", "").strip()
        try:
            return float(cleaned)
        except ValueError:
            return None
    return None


def resolve_target(surfaces: dict[str, Any], target: str) -> Any:
    current: Any = surfaces
    for part in target.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _matches_field(row_value: Any, spec: Any) -> bool:
    if isinstance(spec, dict):
        expected = float(spec["value"])
        tolerance = float(spec["tolerance"])
        actual = _normalize_number(row_value)
        return actual is not None and abs(actual - expected) <= tolerance
    if isinstance(spec, (int, float)) and not isinstance(spec, bool):
        actual = _normalize_number(row_value)
        return actual is not None and abs(actual - float(spec)) <= 1e-9
    return row_value == spec


def evaluate_check(entry: dict[str, Any], surfaces: dict[str, Any]) -> dict[str, Any]:
    """Evaluate one reviewed expectation against real extraction surfaces."""

    check_type = entry["check_type"]
    target = entry["target"]
    value = resolve_target(surfaces, target)
    passed = False
    extracted: Any = value

    if check_type == "equals":
        passed = value == entry["expected"]
    elif check_type == "approximately_equals":
        actual = _normalize_number(value)
        passed = actual is not None and abs(actual - float(entry["expected"])) <= float(entry["tolerance"])
        extracted = value
    elif check_type == "contains_row":
        rows = value if isinstance(value, list) else []
        passed = any(
            all(_matches_field(row.get(field), spec) for field, spec in entry["expected_row"].items())
            for row in rows
            if isinstance(row, dict)
        )
        extracted = rows
    elif check_type == "row_count":
        rows = value if isinstance(value, list) else []
        passed = len(rows) == entry["expected"]
        extracted = len(rows)
    elif check_type == "absent":
        if isinstance(value, list):
            passed = len(value) == 0
            extracted = value
        else:
            passed = value is None or value == ""
            extracted = value
    elif check_type == "source_state":
        passed = value == entry["expected"]
    elif check_type == "evidence_present":
        rows = value if isinstance(value, list) else []
        passed = any(isinstance(row, dict) and row.get("page") == entry["expected"] for row in rows)
        extracted = [row.get("page") for row in rows if isinstance(row, dict)]

    return {
        "check_id": entry["check_id"],
        "document_id": entry["document_id"],
        "page": entry["page"],
        "extractor": entry["extractor"],
        "check_type": check_type,
        "target": target,
        "expected": entry.get("expected", entry.get("expected_row")),
        "tolerance": entry.get("tolerance"),
        "extracted": extracted,
        "required": entry["required"],
        "result": "pass" if passed else "fail",
        "review_note": entry["review"]["review_note"],
    }


def summarize_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Promotion semantics: exact required-check pass counting, no thresholds.

    Optional (informational) checks are counted separately and can never mask
    a required failure.
    """

    required = [item for item in results if item["required"]]
    optional = [item for item in results if not item["required"]]
    required_failed = [item for item in required if item["result"] == "fail"]
    optional_failed = [item for item in optional if item["result"] == "fail"]
    return {
        "total_checks": len(results),
        "required_checks": len(required),
        "required_passed": len(required) - len(required_failed),
        "required_failed": len(required_failed),
        "optional_checks": len(optional),
        "optional_passed": len(optional) - len(optional_failed),
        "optional_failed": len(optional_failed),
        "promotion_complete": bool(required) and not required_failed,
    }


def scan_for_path_leaks(payload: Any) -> list[str]:
    leaks: list[str] = []
    for text in iter_strings(payload):
        if ABSOLUTE_PATH_PATTERN.search(text) or "\\" in text:
            leaks.append(text[:80])
    return leaks
