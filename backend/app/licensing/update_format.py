"""``monday-report-update.v1`` — signed OFFLINE update package manifest.

Verification only (no automatic Internet update checks exist in this product).
An update ships as a payload archive plus this signed manifest; the installed
application refuses unsigned, tampered, downgraded-below-floor, incompatible,
wrong-product, or wrong-key updates.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_bytes, signing_view
from .contract import PRODUCT_NAME, ReasonCode
from .license_format import LicenseFormatError, SIGNATURE_ALGORITHM

UPDATE_SCHEMA_VERSION = "monday-report-update.v1"

#: Data-format revision of the local state this build reads/writes. An update
#: whose ``minimum_compatible_data_version`` exceeds it must be refused.
CURRENT_DATA_VERSION = 1

REQUIRED_FIELDS = frozenset(
    {
        "schema_version",
        "product",
        "product_version",
        "minimum_compatible_data_version",
        "prohibited_below_version",
        "payload_sha256",
        "signature_algorithm",
        "signature",
    }
)


def _version_tuple(value: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in str(value).split("."))
    except ValueError as exc:
        raise LicenseFormatError(ReasonCode.PAYLOAD_MALFORMED, "malformed version string") from exc


def verify_update_manifest(
    manifest: dict,
    payload_bytes: bytes,
    public_key_bytes: bytes,
    *,
    installed_version: str,
    current_data_version: int = CURRENT_DATA_VERSION,
) -> dict:
    """Full offline update acceptance check. Raises LicenseFormatError with a
    typed reason on every rejection path."""

    if not isinstance(manifest, dict):
        raise LicenseFormatError(ReasonCode.PAYLOAD_MALFORMED, "manifest is not an object")
    if manifest.get("schema_version") != UPDATE_SCHEMA_VERSION:
        raise LicenseFormatError(ReasonCode.SCHEMA_UNSUPPORTED, "unsupported update schema")
    if manifest.get("product") != PRODUCT_NAME:
        raise LicenseFormatError(ReasonCode.WRONG_PRODUCT, "update is for a different product")
    missing = REQUIRED_FIELDS - set(manifest)
    if missing:
        raise LicenseFormatError(ReasonCode.FIELD_MISSING, f"missing fields: {sorted(missing)}")
    unknown = set(manifest) - REQUIRED_FIELDS
    if unknown:
        raise LicenseFormatError(ReasonCode.UNKNOWN_FIELD, f"unknown fields: {sorted(unknown)}")
    if manifest.get("signature_algorithm") != SIGNATURE_ALGORITHM:
        raise LicenseFormatError(ReasonCode.WRONG_ALGORITHM, "unsupported signature algorithm")

    try:
        signature = base64.b64decode(str(manifest.get("signature", "")), validate=True)
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature, canonical_bytes(signing_view(manifest))
        )
    except (InvalidSignature, ValueError, Exception) as exc:  # noqa: BLE001
        if isinstance(exc, InvalidSignature):
            raise LicenseFormatError(
                ReasonCode.SIGNATURE_INVALID, "update signature does not verify"
            ) from exc
        raise LicenseFormatError(
            ReasonCode.SIGNATURE_INVALID, "update signature is malformed"
        ) from exc

    if hashlib.sha256(payload_bytes).hexdigest() != str(manifest["payload_sha256"]):
        raise LicenseFormatError(
            ReasonCode.SIGNATURE_INVALID, "payload hash does not match the signed manifest"
        )

    target = _version_tuple(manifest["product_version"])
    floor = _version_tuple(manifest["prohibited_below_version"])
    if target < floor:
        raise LicenseFormatError(
            ReasonCode.PRODUCT_VERSION_NOT_PERMITTED,
            "update version is below the signed prohibition floor",
        )
    if target < _version_tuple(installed_version):
        raise LicenseFormatError(
            ReasonCode.PRODUCT_VERSION_NOT_PERMITTED,
            "update is older than the installed version",
        )
    if int(manifest["minimum_compatible_data_version"]) > int(current_data_version):
        raise LicenseFormatError(
            ReasonCode.PRODUCT_VERSION_NOT_PERMITTED,
            "update requires a newer local data version",
        )
    return manifest


def load_and_verify_update(
    manifest_path: Path,
    payload_path: Path,
    public_key_bytes: bytes,
    *,
    installed_version: str,
) -> dict:
    import json

    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    payload = Path(payload_path).read_bytes()
    return verify_update_manifest(
        manifest, payload, public_key_bytes, installed_version=installed_version
    )
