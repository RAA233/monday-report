"""``monday-report-activation-request.v1`` — air-gapped activation.

The installation exports a request file carrying ONLY hashed machine binding
material plus opaque installation metadata — no raw hardware identifiers, no
customer data. The operator combines it with commercial terms (supplied outside
the repository) and the external private key to issue a signed license, which
the customer imports manually. No Internet connection is involved anywhere.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timezone

from .canonical import canonical_hash
from .contract import PRODUCT_NAME, PRODUCT_VERSION, ReasonCode
from .fingerprint import Fingerprint
from .license_format import LicenseFormatError, parse_timestamp

ACTIVATION_SCHEMA_VERSION = "monday-report-activation-request.v1"

REQUIRED_FIELDS = frozenset(
    {
        "schema_version",
        "product",
        "installation_id",
        "machine_binding",
        "machine_fingerprint_hash",
        "product_version",
        "requested_edition",
        "request_nonce",
        "request_timestamp",
    }
)

#: Raw-identifier shapes that must NEVER appear in an activation request.
_FORBIDDEN_KEYS = ("mac", "serial", "uuid_raw", "hostname", "username", "volume")


def build_activation_request(
    fingerprint: Fingerprint,
    *,
    installation_id: str,
    requested_edition: str,
) -> dict:
    """Build the exportable request document (hashes only)."""

    binding = fingerprint.binding_document()
    return {
        "schema_version": ACTIVATION_SCHEMA_VERSION,
        "product": PRODUCT_NAME,
        "installation_id": str(installation_id),
        "machine_binding": binding,
        "machine_fingerprint_hash": canonical_hash(binding),
        "product_version": PRODUCT_VERSION,
        "requested_edition": str(requested_edition),
        "request_nonce": secrets.token_hex(16),
        "request_timestamp": datetime.now(timezone.utc).isoformat(),
    }


def validate_activation_request(document: dict) -> dict:
    """Operator-side validation before issuance. Rejects wrong schema/product,
    missing/unknown fields, raw-identifier leakage, and malformed bindings."""

    if not isinstance(document, dict):
        raise LicenseFormatError(ReasonCode.PAYLOAD_MALFORMED, "request is not an object")
    if document.get("schema_version") != ACTIVATION_SCHEMA_VERSION:
        raise LicenseFormatError(ReasonCode.SCHEMA_UNSUPPORTED, "unsupported request schema")
    if document.get("product") != PRODUCT_NAME:
        raise LicenseFormatError(ReasonCode.WRONG_PRODUCT, "request is for a different product")
    missing = REQUIRED_FIELDS - set(document)
    if missing:
        raise LicenseFormatError(ReasonCode.FIELD_MISSING, f"missing fields: {sorted(missing)}")
    unknown = set(document) - REQUIRED_FIELDS
    if unknown:
        raise LicenseFormatError(ReasonCode.UNKNOWN_FIELD, f"unknown fields: {sorted(unknown)}")
    binding = document.get("machine_binding")
    if not isinstance(binding, dict) or not isinstance(binding.get("component_hashes"), dict):
        raise LicenseFormatError(ReasonCode.PAYLOAD_MALFORMED, "machine_binding malformed")
    for name, value in binding["component_hashes"].items():
        if len(str(value)) != 64 or not all(c in "0123456789abcdef" for c in str(value)):
            raise LicenseFormatError(
                ReasonCode.PAYLOAD_MALFORMED,
                f"component '{name}' is not a SHA-256 hash — raw identifiers are not accepted",
            )
    lowered_keys = {str(key).lower() for key in binding["component_hashes"]}
    for key in lowered_keys:
        for forbidden in _FORBIDDEN_KEYS:
            if key == forbidden:
                raise LicenseFormatError(
                    ReasonCode.PAYLOAD_MALFORMED, "raw identifier component name rejected"
                )
    if document.get("machine_fingerprint_hash") != canonical_hash(binding):
        raise LicenseFormatError(
            ReasonCode.PAYLOAD_MALFORMED, "fingerprint hash does not commit to binding"
        )
    parse_timestamp(document["request_timestamp"], "request_timestamp")
    return document
