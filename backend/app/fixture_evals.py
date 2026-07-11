from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .fixtures import REQUIRED_GOLDEN_FIXTURE_FAMILIES


PARSER_EVAL_REPORT_ENV = "MONDAY_REPORT_PARSER_EVAL_REPORT"


@dataclass(frozen=True)
class ParserFixtureEvalReadiness:
    ready: bool
    detail: str
    remediation: str
    report_path: str | None
    covered_families: tuple[str, ...]
    missing_families: tuple[str, ...]
    failed_families: tuple[str, ...]
    invalid_families: tuple[str, ...]


def evaluate_parser_fixture_eval_readiness() -> ParserFixtureEvalReadiness:
    required_ids = tuple(fixture_id for fixture_id, _ in REQUIRED_GOLDEN_FIXTURE_FAMILIES)
    remediation = (
        "Run parser/OCR evals on the anonymized golden fixture manifest and set "
        f"{PARSER_EVAL_REPORT_ENV} to the generated passing report."
    )
    report_value = os.getenv(PARSER_EVAL_REPORT_ENV, "").strip()
    if not report_value:
        return ParserFixtureEvalReadiness(
            ready=False,
            detail=f"{PARSER_EVAL_REPORT_ENV} is not configured; 0/{len(required_ids)} fixture families have passing evals.",
            remediation=remediation,
            report_path=None,
            covered_families=(),
            missing_families=required_ids,
            failed_families=(),
            invalid_families=(),
        )

    report_path = Path(report_value).expanduser().resolve()
    if not report_path.exists():
        return ParserFixtureEvalReadiness(
            ready=False,
            detail=f"Parser/OCR eval report does not exist: {report_path}.",
            remediation=remediation,
            report_path=str(report_path),
            covered_families=(),
            missing_families=required_ids,
            failed_families=(),
            invalid_families=(),
        )

    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return ParserFixtureEvalReadiness(
            ready=False,
            detail=f"Parser/OCR eval report is not readable JSON: {exc}.",
            remediation=remediation,
            report_path=str(report_path),
            covered_families=(),
            missing_families=required_ids,
            failed_families=(),
            invalid_families=(),
        )

    report_status = str(payload.get("status", "")).strip().lower()
    cases = payload.get("cases", [])
    case_items = cases if isinstance(cases, list) else []
    passed_ids: set[str] = set()
    failed_ids: set[str] = set()
    invalid_ids: set[str] = set()
    required_set = set(required_ids)

    for item in case_items:
        family_id = _family_id(item)
        if not family_id:
            continue
        if family_id not in required_set:
            invalid_ids.add(family_id)
            continue
        if _case_passes(item):
            passed_ids.add(family_id)
        else:
            failed_ids.add(family_id)

    failed_ids -= passed_ids
    covered = tuple(fixture_id for fixture_id in required_ids if fixture_id in passed_ids)
    missing = tuple(fixture_id for fixture_id in required_ids if fixture_id not in passed_ids and fixture_id not in failed_ids)
    failed = tuple(fixture_id for fixture_id in required_ids if fixture_id in failed_ids)
    invalid = tuple(sorted(invalid_ids))
    ready = report_status == "pass" and len(covered) == len(required_ids) and not failed and not invalid

    status_detail = "report status pass" if report_status == "pass" else f"report status is {report_status!r}"
    missing_detail = f"; missing evals: {', '.join(missing)}" if missing else ""
    failed_detail = f"; failed evals: {', '.join(failed)}" if failed else ""
    invalid_detail = f"; invalid eval families: {', '.join(invalid)}" if invalid else ""
    return ParserFixtureEvalReadiness(
        ready=ready,
        detail=(
            f"Parser/OCR eval report {report_path} covers {len(covered)}/{len(required_ids)} "
            f"required families with passing checks; {status_detail}{missing_detail}{failed_detail}{invalid_detail}."
        ),
        remediation=remediation,
        report_path=str(report_path),
        covered_families=covered,
        missing_families=missing,
        failed_families=failed,
        invalid_families=invalid,
    )


def _family_id(item: Any) -> str | None:
    if not isinstance(item, dict):
        return None
    value = item.get("family") or item.get("id")
    return str(value).strip().lower() if value else None


def _case_passes(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    if str(item.get("status", "")).strip().lower() != "pass":
        return False
    checks = item.get("checks", [])
    if not isinstance(checks, list) or not checks:
        return False
    for check in checks:
        if not isinstance(check, dict) or str(check.get("status", "")).strip().lower() != "pass":
            return False
    return True
