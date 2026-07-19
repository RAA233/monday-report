"""Correctable-field registry for the field-level correction foundation.

A reviewer correction may only target a field that appears in this centralized
registry. Free-form field keys and unrestricted JSON paths are rejected, and
audit-chain, identity, tenant/ownership, recommendation, Benchmarking, parser,
source-provenance, validation-gate, model/prompt, and immutable-identifier
fields are never correctable (they are simply absent from the registry, and an
unknown key returns a stable validation error).

Corrections are overlay records only: nothing here mutates a parsed document,
report profile, or source value. The registry additionally declares, per field,
whether the corrected value may enter the Report Draft overlay and whether it
may enter the official report JSON (the latter is `False` for every field in
this foundation slice — applying corrections to official output is a separate,
approval-gated increment).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Literal

CorrectableValueType = Literal["string", "numeric_text"]

MAX_CORRECTED_VALUE_LENGTH = 200
MAX_SOURCE_VALUE_LENGTH = 200
MAX_CORRECTION_REASON_LENGTH = 500

# Control characters (except tab/newline/carriage-return) are rejected outright.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class CorrectionValidationError(ValueError):
    """Raised when a correction payload violates the registry contract."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class CorrectableField:
    target_type: str
    field_key: str
    label: str
    value_type: CorrectableValueType
    nullable: bool
    max_length: int
    enters_draft: bool
    enters_final_json: bool
    requires_approval: bool


def _field(
    target_type: str,
    field_key: str,
    label: str,
    value_type: CorrectableValueType,
    *,
    nullable: bool = False,
    max_length: int = MAX_CORRECTED_VALUE_LENGTH,
    enters_draft: bool = True,
    enters_final_json: bool = False,
    requires_approval: bool = False,
) -> CorrectableField:
    return CorrectableField(
        target_type=target_type,
        field_key=field_key,
        label=label,
        value_type=value_type,
        nullable=nullable,
        max_length=max_length,
        enters_draft=enters_draft,
        enters_final_json=enters_final_json,
        requires_approval=requires_approval,
    )


# The correctable surface for this foundation is the report-identity scalar
# fields of the draft. Casing/survey/hydraulics row-level correction and
# official-JSON application are deliberately deferred to later increments and
# are therefore NOT registered here (any attempt returns a stable error).
_REGISTERED_FIELDS: tuple[CorrectableField, ...] = (
    _field("report_field", "report_no", "Report number", "string"),
    _field("report_field", "well", "Well name", "string"),
    _field("report_field", "rig", "Rig name", "string"),
    _field("report_field", "operator", "Operator", "string"),
    _field("report_field", "phase", "Well phase", "string"),
    _field("report_field", "hole_size", "Hole size", "numeric_text"),
    _field("report_field", "md_ft", "Measured depth (ft)", "numeric_text"),
    _field("report_field", "tvd_ft", "True vertical depth (ft)", "numeric_text"),
    _field("report_field", "mud_weight", "Mud weight", "numeric_text"),
)

CORRECTABLE_FIELDS: dict[tuple[str, str], CorrectableField] = {
    (field.target_type, field.field_key): field for field in _REGISTERED_FIELDS
}


def correctable_field_catalog() -> list[dict[str, object]]:
    """Return the registry as a serializable catalog for operator discovery."""
    return [
        {
            "target_type": field.target_type,
            "field_key": field.field_key,
            "label": field.label,
            "value_type": field.value_type,
            "nullable": field.nullable,
            "max_length": field.max_length,
            "enters_draft": field.enters_draft,
            "enters_final_json": field.enters_final_json,
            "requires_approval": field.requires_approval,
        }
        for field in _REGISTERED_FIELDS
    ]


def _reject_control_chars(name: str, value: str | None) -> None:
    if value is not None and _CONTROL_CHARS.search(value):
        raise CorrectionValidationError(
            "control_characters", f"{name} contains disallowed control characters."
        )


def _validate_value(field: CorrectableField, name: str, value: str | None) -> None:
    if value is None:
        if not field.nullable:
            raise CorrectionValidationError("null_not_allowed", f"{name} may not be null for this field.")
        return
    if not isinstance(value, str):
        raise CorrectionValidationError("type_mismatch", f"{name} must be a string value.")
    if len(value) > field.max_length:
        raise CorrectionValidationError(
            "too_long", f"{name} exceeds the {field.max_length}-character limit for this field."
        )
    _reject_control_chars(name, value)
    if field.value_type == "numeric_text":
        cleaned = value.replace(",", "").replace(" ", "").strip()
        # Strip a trailing unit token (e.g. "8620 ft", "10.2 ppg") before parsing.
        cleaned = re.sub(r"(?i)(ft|feet|m|ppg|in|inch)$", "", cleaned).strip()
        try:
            parsed = float(cleaned) if cleaned else float("nan")
        except ValueError:
            raise CorrectionValidationError(
                "not_numeric", f"{name} must be a finite number for this field."
            )
        if not math.isfinite(parsed):
            raise CorrectionValidationError(
                "not_finite", f"{name} must be a finite number (NaN/infinity rejected)."
            )


def validate_correction(
    target_type: str,
    field_key: str,
    source_value: str | None,
    corrected_value: str | None,
    correction_reason: str,
) -> CorrectableField:
    """Validate a correction payload against the registry.

    Returns the matched CorrectableField, or raises CorrectionValidationError
    (a ValueError) with a stable ``code`` when the field is not correctable or
    a value violates the field contract.
    """
    field = CORRECTABLE_FIELDS.get((target_type, field_key))
    if field is None:
        raise CorrectionValidationError(
            "unknown_field",
            f"Field '{field_key}' on '{target_type}' is not a registered correctable field.",
        )
    if not isinstance(correction_reason, str) or not correction_reason.strip():
        raise CorrectionValidationError("reason_required", "A correction reason is required.")
    if len(correction_reason) > MAX_CORRECTION_REASON_LENGTH:
        raise CorrectionValidationError(
            "reason_too_long",
            f"The correction reason exceeds the {MAX_CORRECTION_REASON_LENGTH}-character limit.",
        )
    _reject_control_chars("correction_reason", correction_reason)
    if source_value is not None and len(source_value) > MAX_SOURCE_VALUE_LENGTH:
        raise CorrectionValidationError(
            "source_too_long", f"The source value exceeds the {MAX_SOURCE_VALUE_LENGTH}-character limit."
        )
    _reject_control_chars("source_value", source_value)
    _validate_value(field, "corrected_value", corrected_value)
    return field
