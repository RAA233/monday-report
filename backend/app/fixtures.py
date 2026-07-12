from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


GOLDEN_FIXTURE_MANIFEST_ENV = "MONDAY_REPORT_GOLDEN_FIXTURE_MANIFEST"
ANONYMIZED_CLIENT_FIXTURE_MODE = "anonymized_client"
REVIEWED_CLIENT_FIXTURE_CLASSIFICATION = "reviewed_anonymized_client_fixture"
APPROVED_FIXTURE_REVIEW_STATUSES = {"approved", "reviewed"}

REQUIRED_GOLDEN_FIXTURE_FAMILIES: tuple[tuple[str, str], ...] = (
    ("ddr", "DDR"),
    ("bha", "BHA report"),
    ("mwd_lwd", "MWD/LWD report"),
    ("rss", "RSS report"),
    ("mud_motor", "Mud motor report"),
    ("bit_record", "Bit record"),
    ("mud_report", "Mud report"),
    ("npt_report", "NPT report"),
    ("scanned_pdf", "Scanned PDF"),
    ("excel_workbook", "Excel workbook"),
    ("email_with_attachment", "Email with attachment"),
    ("corrupted_file", "Corrupted file"),
    ("duplicate_file", "Duplicate file"),
)


@dataclass(frozen=True)
class GoldenFixtureReadiness:
    ready: bool
    detail: str
    remediation: str
    manifest_path: str | None
    fixture_mode: str | None
    reviewed_attestation: bool
    attestation_detail: str
    covered_families: tuple[str, ...]
    missing_families: tuple[str, ...]
    invalid_families: tuple[str, ...]


def evaluate_golden_fixture_readiness() -> GoldenFixtureReadiness:
    manifest_value = os.getenv(GOLDEN_FIXTURE_MANIFEST_ENV, "").strip()
    required_ids = tuple(fixture_id for fixture_id, _ in REQUIRED_GOLDEN_FIXTURE_FAMILIES)
    remediation = (
        "Create a reviewed anonymized client golden fixture manifest with real files for every "
        "required family before enabling real client package intake."
    )
    if not manifest_value:
        return GoldenFixtureReadiness(
            ready=False,
            detail=(
                f"{GOLDEN_FIXTURE_MANIFEST_ENV} is not configured; "
                f"0/{len(required_ids)} required fixture families are covered."
            ),
            remediation=remediation,
            manifest_path=None,
            fixture_mode=None,
            reviewed_attestation=False,
            attestation_detail=f"{GOLDEN_FIXTURE_MANIFEST_ENV} is not configured.",
            covered_families=(),
            missing_families=required_ids,
            invalid_families=(),
        )

    manifest_path = Path(manifest_value).expanduser().resolve()
    if not manifest_path.exists():
        return GoldenFixtureReadiness(
            ready=False,
            detail=f"Golden fixture manifest does not exist: {manifest_path}.",
            remediation=remediation,
            manifest_path=str(manifest_path),
            fixture_mode=None,
            reviewed_attestation=False,
            attestation_detail="Golden fixture manifest is not available for attestation review.",
            covered_families=(),
            missing_families=required_ids,
            invalid_families=(),
        )

    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return GoldenFixtureReadiness(
            ready=False,
            detail=f"Golden fixture manifest is not readable JSON: {exc}.",
            remediation=remediation,
            manifest_path=str(manifest_path),
            fixture_mode=None,
            reviewed_attestation=False,
            attestation_detail="Golden fixture manifest is not readable for attestation review.",
            covered_families=(),
            missing_families=required_ids,
            invalid_families=(),
        )

    fixture_mode = str(payload.get("fixture_mode", "")).strip().lower()
    reviewed_attestation, attestation_detail = _reviewed_attestation(payload)
    families = payload.get("families", [])
    family_items = families if isinstance(families, list) else []
    covered_ids: set[str] = set()
    invalid_ids: set[str] = set()
    for item in family_items:
        family_id = _family_id(item)
        if not family_id:
            continue
        if _family_has_existing_evidence(item, manifest_path.parent):
            covered_ids.add(family_id)
        else:
            invalid_ids.add(family_id)

    required_set = set(required_ids)
    unknown_ids = set(covered_ids | invalid_ids) - required_set
    invalid_ids = (invalid_ids & required_set) | unknown_ids
    covered_required = tuple(fixture_id for fixture_id in required_ids if fixture_id in covered_ids)
    missing_required = tuple(fixture_id for fixture_id in required_ids if fixture_id not in covered_ids)
    invalid_sorted = tuple(sorted(invalid_ids))
    mode_ok = fixture_mode == ANONYMIZED_CLIENT_FIXTURE_MODE
    ready = mode_ok and not missing_required and not invalid_sorted

    mode_detail = (
        "anonymized client mode"
        if mode_ok
        else f"fixture_mode must be {ANONYMIZED_CLIENT_FIXTURE_MODE!r}, got {fixture_mode!r}"
    )
    invalid_detail = f"; invalid families: {', '.join(invalid_sorted)}" if invalid_sorted else ""
    missing_detail = f"; missing families: {', '.join(missing_required)}" if missing_required else ""
    return GoldenFixtureReadiness(
        ready=ready,
        detail=(
            f"Golden fixture manifest {manifest_path} covers {len(covered_required)}/{len(required_ids)} "
            f"required families; {mode_detail}{missing_detail}{invalid_detail}."
        ),
        remediation=remediation,
        manifest_path=str(manifest_path),
        fixture_mode=fixture_mode or None,
        reviewed_attestation=reviewed_attestation,
        attestation_detail=attestation_detail,
        covered_families=covered_required,
        missing_families=missing_required,
        invalid_families=invalid_sorted,
    )


def required_fixture_family_labels() -> dict[str, str]:
    return dict(REQUIRED_GOLDEN_FIXTURE_FAMILIES)


def _family_id(item: Any) -> str | None:
    if not isinstance(item, dict):
        return None
    value = item.get("id")
    return str(value).strip().lower() if value else None


def _family_has_existing_evidence(item: Any, manifest_root: Path) -> bool:
    if not isinstance(item, dict):
        return False
    evidence = item.get("evidence_files", item.get("evidence", []))
    if isinstance(evidence, str):
        evidence_items = [evidence]
    elif isinstance(evidence, list):
        evidence_items = [str(value) for value in evidence if str(value).strip()]
    else:
        evidence_items = []
    if not evidence_items:
        return False
    for value in evidence_items:
        evidence_path = Path(value).expanduser()
        if not evidence_path.is_absolute():
            evidence_path = manifest_root / evidence_path
        if not evidence_path.exists() or not evidence_path.is_file():
            return False
    return True


def _reviewed_attestation(payload: dict[str, Any]) -> tuple[bool, str]:
    attestation = payload.get("attestation")
    if not isinstance(attestation, dict):
        return False, "Golden fixture manifest is missing a top-level attestation block."

    classification = str(attestation.get("classification", "")).strip().lower()
    review_status = str(attestation.get("review_status") or attestation.get("status") or "").strip().lower()
    reviewed_by = str(attestation.get("reviewed_by", "")).strip()
    reviewed_at = str(attestation.get("reviewed_at", "")).strip()
    contains_confidential = attestation.get("contains_client_confidential_data")

    ready = (
        classification == REVIEWED_CLIENT_FIXTURE_CLASSIFICATION
        and review_status in APPROVED_FIXTURE_REVIEW_STATUSES
        and bool(reviewed_by)
        and bool(reviewed_at)
        and contains_confidential is False
    )
    if ready:
        return (
            True,
            f"Reviewed anonymized client fixture attestation approved by {reviewed_by} at {reviewed_at}.",
        )

    missing: list[str] = []
    if classification != REVIEWED_CLIENT_FIXTURE_CLASSIFICATION:
        missing.append(f"classification={REVIEWED_CLIENT_FIXTURE_CLASSIFICATION!r}")
    if review_status not in APPROVED_FIXTURE_REVIEW_STATUSES:
        missing.append("review_status='approved'")
    if not reviewed_by:
        missing.append("reviewed_by")
    if not reviewed_at:
        missing.append("reviewed_at")
    if contains_confidential is not False:
        missing.append("contains_client_confidential_data=false")
    return False, "Fixture attestation is not approved for real client data; missing " + ", ".join(missing) + "."
