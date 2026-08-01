"""``monday-report-license.v1`` — the signed offline license document.

Ed25519 over the canonical serialization of the payload (everything except the
``signature`` field), via the established audited ``cryptography`` library. The
application embeds ONLY the public verification key; signing happens exclusively
in the operator issuance CLI outside customer installations.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import CanonicalizationError, canonical_bytes, canonical_hash, signing_view
from .contract import PRODUCT_NAME, ReasonCode

LICENSE_SCHEMA_VERSION = "monday-report-license.v1"
SIGNATURE_ALGORITHM = "Ed25519"

#: Exact field set of a v1 license. Unknown fields are REJECTED (a signed
#: document must not smuggle unvalidated content); missing fields are rejected.
REQUIRED_FIELDS = frozenset(
    {
        "schema_version",
        "product",
        "license_id",
        "customer_ref",
        "edition",
        "issued_at",
        "not_before",
        "expires_at",
        "grace_until",
        "machine_binding",
        "machine_fingerprint_hash",
        "allowed_product_versions",
        "feature_flags",
        "installation_limit",
        "installation_id",
        "issuer_id",
        "issue_sequence",
        "nonce",
        "signature_algorithm",
        "signature",
    }
)

MACHINE_BINDING_FIELDS = frozenset(
    {"fingerprint_version", "component_hashes", "match_threshold", "strong_components"}
)

#: Clock slack for "issued in the future" rejection (legitimate small skew
#: between the issuing operator machine and the customer machine).
FUTURE_ISSUE_SLACK_SECONDS = 6 * 3600


class LicenseFormatError(Exception):
    """Raised with a typed ReasonCode when a license document is unusable."""

    def __init__(self, reason: ReasonCode, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def parse_timestamp(value: str, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise LicenseFormatError(
            ReasonCode.PAYLOAD_MALFORMED, f"{field_name} is not an ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise LicenseFormatError(
            ReasonCode.PAYLOAD_MALFORMED, f"{field_name} must carry an explicit UTC offset"
        )
    return parsed.astimezone(timezone.utc)


def _require_structure(document: dict) -> None:
    if not isinstance(document, dict):
        raise LicenseFormatError(ReasonCode.PAYLOAD_MALFORMED, "license is not an object")
    if document.get("schema_version") != LICENSE_SCHEMA_VERSION:
        raise LicenseFormatError(
            ReasonCode.SCHEMA_UNSUPPORTED,
            "unsupported license schema version",
        )
    if document.get("product") != PRODUCT_NAME:
        raise LicenseFormatError(ReasonCode.WRONG_PRODUCT, "license is for a different product")
    missing = REQUIRED_FIELDS - set(document)
    if missing:
        raise LicenseFormatError(
            ReasonCode.FIELD_MISSING, f"missing required fields: {sorted(missing)}"
        )
    unknown = set(document) - REQUIRED_FIELDS
    if unknown:
        raise LicenseFormatError(
            ReasonCode.UNKNOWN_FIELD, f"unknown fields rejected: {sorted(unknown)}"
        )
    binding = document.get("machine_binding")
    if not isinstance(binding, dict) or set(binding) != set(MACHINE_BINDING_FIELDS):
        raise LicenseFormatError(
            ReasonCode.PAYLOAD_MALFORMED, "machine_binding has the wrong field set"
        )
    if not isinstance(binding.get("component_hashes"), dict) or not binding["component_hashes"]:
        raise LicenseFormatError(
            ReasonCode.PAYLOAD_MALFORMED, "machine_binding.component_hashes must be non-empty"
        )
    if document.get("signature_algorithm") != SIGNATURE_ALGORITHM:
        raise LicenseFormatError(
            ReasonCode.WRONG_ALGORITHM, "unsupported signature algorithm"
        )
    if not isinstance(document.get("issue_sequence"), int) or document["issue_sequence"] < 1:
        raise LicenseFormatError(
            ReasonCode.PAYLOAD_MALFORMED, "issue_sequence must be a positive integer"
        )
    if not isinstance(document.get("allowed_product_versions"), list) or not document[
        "allowed_product_versions"
    ]:
        raise LicenseFormatError(
            ReasonCode.PAYLOAD_MALFORMED, "allowed_product_versions must be a non-empty list"
        )
    if not isinstance(document.get("feature_flags"), dict):
        raise LicenseFormatError(ReasonCode.PAYLOAD_MALFORMED, "feature_flags must be an object")
    # The fingerprint-hash commitment must match the binding it summarizes, so a
    # tampered binding cannot hide behind an untouched summary hash (and vice
    # versa) even before signature verification reporting.
    if document.get("machine_fingerprint_hash") != canonical_hash(binding):
        raise LicenseFormatError(
            ReasonCode.PAYLOAD_MALFORMED,
            "machine_fingerprint_hash does not commit to machine_binding",
        )


def verify_signature(document: dict, public_key_bytes: bytes) -> None:
    """Verify the Ed25519 signature over the canonical signing view."""

    try:
        signature = base64.b64decode(str(document.get("signature", "")), validate=True)
    except Exception as exc:  # noqa: BLE001 - normalize every decode failure
        raise LicenseFormatError(
            ReasonCode.SIGNATURE_INVALID, "signature is not valid base64"
        ) from exc
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except Exception as exc:  # noqa: BLE001
        raise LicenseFormatError(
            ReasonCode.WRONG_SIGNING_KEY, "embedded public key is malformed"
        ) from exc
    try:
        message = canonical_bytes(signing_view(document))
    except CanonicalizationError as exc:
        raise LicenseFormatError(
            ReasonCode.PAYLOAD_MALFORMED, "license is not canonically serializable"
        ) from exc
    try:
        public_key.verify(signature, message)
    except InvalidSignature as exc:
        raise LicenseFormatError(
            ReasonCode.SIGNATURE_INVALID, "signature does not verify over the canonical payload"
        ) from exc


def validate_document(document: dict, public_key_bytes: bytes) -> dict:
    """Structural + cryptographic validation. Returns the document on success.

    Time, machine-binding, version-eligibility, and rollback enforcement live in
    the provider — this function proves the document is authentic and well
    formed.
    """

    _require_structure(document)
    verify_signature(document, public_key_bytes)
    # Parse every timestamp now so a signed-but-malformed value is caught once.
    for field_name in ("issued_at", "not_before", "expires_at", "grace_until"):
        parse_timestamp(document[field_name], field_name)
    return document


def version_eligible(product_version: str, allowed: list[str]) -> bool:
    """Exact match or ``MAJOR.x`` / ``MAJOR.MINOR.x`` wildcard eligibility."""

    for pattern in allowed:
        pattern = str(pattern).strip()
        if pattern == product_version:
            return True
        if pattern.endswith(".x"):
            prefix = pattern[: -len("x")]
            if product_version.startswith(prefix):
                return True
    return False


@dataclass(frozen=True)
class IssuedLicense:
    document: dict
    canonical_payload_hash: str


def issue_license(
    payload: dict,
    private_key: Ed25519PrivateKey,
) -> IssuedLicense:
    """Operator-side signing. ``payload`` is the full unsigned document (every
    REQUIRED_FIELD except ``signature``)."""

    unsigned = dict(payload)
    unsigned.pop("signature", None)
    document = dict(unsigned)
    document["signature"] = base64.b64encode(
        private_key.sign(canonical_bytes(signing_view(document)))
    ).decode("ascii")
    public_bytes = private_key.public_key().public_bytes_raw()
    validate_document(document, public_bytes)
    return IssuedLicense(document=document, canonical_payload_hash=canonical_hash(document))
