"""``OfflineSignedLicenseProvider`` — the fully implemented offline edition
provider: signed license file + machine binding + protected state + typed
normalized decisions. Never raises from ``evaluate``.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .contract import (
    LicenseDecision,
    LicenseProvider,
    LicenseState,
    PRODUCT_VERSION,
    ReasonCode,
)
from .fingerprint import Fingerprint, collect_fingerprint, evaluate_binding
from .license_format import (
    FUTURE_ISSUE_SLACK_SECONDS,
    LicenseFormatError,
    parse_timestamp,
    validate_document,
    version_eligible,
)
from .state_guard import LicensingState, StateGuard, StateIntegrityError

#: "Expiring soon" advisory window.
EXPIRING_SOON_SECONDS = 14 * 24 * 3600

_SUPPORT_CODES = {
    LicenseState.VALID: "MR-LIC-OK-000",
    LicenseState.EXPIRING_SOON: "MR-LIC-EXP-010",
    LicenseState.GRACE: "MR-LIC-EXP-020",
    LicenseState.EXPIRED_READ_ONLY: "MR-LIC-EXP-030",
    LicenseState.MACHINE_MISMATCH: "MR-LIC-BIND-040",
    LicenseState.INVALID_SIGNATURE: "MR-LIC-SIG-050",
    LicenseState.CORRUPT_LICENSE: "MR-LIC-FMT-060",
    LicenseState.UNSUPPORTED_LICENSE_VERSION: "MR-LIC-FMT-061",
    LicenseState.PRODUCT_VERSION_NOT_PERMITTED: "MR-LIC-VER-070",
    LicenseState.NOT_YET_VALID: "MR-LIC-TIME-080",
    LicenseState.CLOCK_ROLLBACK_DETECTED: "MR-LIC-TIME-081",
    LicenseState.STATE_TAMPERED: "MR-LIC-STATE-090",
    LicenseState.NO_LICENSE: "MR-LIC-NONE-100",
    LicenseState.PROVIDER_UNAVAILABLE: "MR-LIC-PROV-110",
}

_FORMAT_REASON_TO_STATE = {
    ReasonCode.SCHEMA_UNSUPPORTED: LicenseState.UNSUPPORTED_LICENSE_VERSION,
    ReasonCode.SIGNATURE_INVALID: LicenseState.INVALID_SIGNATURE,
    ReasonCode.WRONG_SIGNING_KEY: LicenseState.INVALID_SIGNATURE,
    ReasonCode.WRONG_ALGORITHM: LicenseState.INVALID_SIGNATURE,
}


class LicenseImportError(Exception):
    """Raised by ``import_license`` with a typed reason (import refused; the
    currently installed license, if any, is left untouched)."""

    def __init__(self, reason: ReasonCode, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass
class OfflineProviderConfig:
    license_path: Path
    state_primary_path: Path
    state_secondary_path: Path
    public_key: bytes
    installation_id: str
    fingerprint_supplier: Callable[[], Fingerprint] = collect_fingerprint
    clock: Callable[[], float] = time.time


def _blocked(state: LicenseState, reason: ReasonCode, **extra) -> LicenseDecision:
    return LicenseDecision(
        state=state,
        reason=reason,
        read_only=True,
        support_code=_SUPPORT_CODES.get(state, "MR-LIC-UNK-999"),
        **extra,
    )


class OfflineSignedLicenseProvider(LicenseProvider):
    def __init__(self, config: OfflineProviderConfig) -> None:
        self.config = config
        self._guard = StateGuard(config.state_primary_path, config.state_secondary_path)

    def provider_kind(self) -> str:
        return "offline_signed_license"

    # -- evaluation ---------------------------------------------------------

    def evaluate(self) -> LicenseDecision:
        try:
            return self._evaluate()
        except Exception:  # noqa: BLE001 - the decision surface never raises
            return _blocked(LicenseState.STATE_TAMPERED, ReasonCode.STATE_INTEGRITY_FAILURE)

    def _evaluate(self) -> LicenseDecision:
        config = self.config
        if not config.license_path.exists():
            return _blocked(LicenseState.NO_LICENSE, ReasonCode.NO_LICENSE_INSTALLED)

        try:
            document = json.loads(config.license_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return _blocked(LicenseState.CORRUPT_LICENSE, ReasonCode.PAYLOAD_MALFORMED)

        try:
            validate_document(document, config.public_key)
        except LicenseFormatError as exc:
            return _blocked(
                _FORMAT_REASON_TO_STATE.get(exc.reason, LicenseState.CORRUPT_LICENSE), exc.reason
            )

        issued_at = parse_timestamp(document["issued_at"], "issued_at")
        not_before = parse_timestamp(document["not_before"], "not_before")
        expires_at = parse_timestamp(document["expires_at"], "expires_at")
        grace_until = parse_timestamp(document["grace_until"], "grace_until")
        now_epoch = float(config.clock())
        now = datetime.fromtimestamp(now_epoch, tz=timezone.utc)

        # Protected state: fail closed on corruption; detect clock rollback.
        try:
            state = self._guard.load(license_issued_epoch=issued_at.timestamp())
        except StateIntegrityError:
            return _blocked(LicenseState.STATE_TAMPERED, ReasonCode.STATE_INTEGRITY_FAILURE)
        if StateGuard.rollback_detected(state, now_epoch):
            return self._decision_with_times(
                document,
                _blocked(LicenseState.CLOCK_ROLLBACK_DETECTED, ReasonCode.CLOCK_ROLLBACK_DETECTED),
            )
        # Expiry is judged against the MONOTONIC trusted clock, never the bare
        # system clock. The 48h tolerance exists only to avoid declaring hard
        # rollback on legitimate drift/NTP corrections — it must NOT hand back
        # licensed operation. Without this, a clock parked just inside the
        # tolerance below an already-passed grace_until would restore full
        # operation indefinitely (each evaluation looks like ordinary drift).
        effective_epoch = max(now_epoch, state.highest_trusted_epoch)
        effective_now = datetime.fromtimestamp(effective_epoch, tz=timezone.utc)
        # A license file with a LOWER sequence than the recorded lineage means an
        # old entitlement was copied back over a newer one.
        if state.license_id and (
            int(document["issue_sequence"]) < state.issue_sequence
            or (
                int(document["issue_sequence"]) == state.issue_sequence
                and str(document["license_id"]) != state.license_id
            )
        ):
            return self._decision_with_times(
                document,
                _blocked(LicenseState.STATE_TAMPERED, ReasonCode.LICENSE_ROLLBACK_REJECTED),
            )

        if str(document["installation_id"]) != str(config.installation_id):
            return self._decision_with_times(
                document, _blocked(LicenseState.MACHINE_MISMATCH, ReasonCode.WRONG_INSTALLATION)
            )

        fingerprint = config.fingerprint_supplier()
        binding = evaluate_binding(fingerprint, document["machine_binding"])
        if not binding.matched:
            return self._decision_with_times(
                document,
                _blocked(
                    LicenseState.MACHINE_MISMATCH,
                    ReasonCode.MACHINE_MISMATCH,
                    machine_binding=binding,
                ),
            )

        if not version_eligible(PRODUCT_VERSION, list(document["allowed_product_versions"])):
            return self._decision_with_times(
                document,
                _blocked(
                    LicenseState.PRODUCT_VERSION_NOT_PERMITTED,
                    ReasonCode.PRODUCT_VERSION_NOT_PERMITTED,
                    machine_binding=binding,
                ),
            )

        if issued_at.timestamp() > now_epoch + FUTURE_ISSUE_SLACK_SECONDS:
            return self._decision_with_times(
                document,
                _blocked(
                    LicenseState.NOT_YET_VALID,
                    ReasonCode.LICENSE_FUTURE_ISSUED,
                    machine_binding=binding,
                ),
            )
        if now < not_before:
            return self._decision_with_times(
                document,
                _blocked(
                    LicenseState.NOT_YET_VALID,
                    ReasonCode.LICENSE_NOT_YET_VALID,
                    machine_binding=binding,
                ),
            )

        if effective_now <= expires_at:
            state_kind = (
                LicenseState.EXPIRING_SOON
                if (expires_at - effective_now).total_seconds() <= EXPIRING_SOON_SECONDS
                else LicenseState.VALID
            )
            reason = (
                ReasonCode.EXPIRING_SOON
                if state_kind is LicenseState.EXPIRING_SOON
                else ReasonCode.OK
            )
            read_only = False
        elif effective_now <= grace_until:
            state_kind, reason, read_only = (
                LicenseState.GRACE,
                ReasonCode.IN_GRACE_PERIOD,
                False,
            )
        else:
            state_kind, reason, read_only = (
                LicenseState.EXPIRED_READ_ONLY,
                ReasonCode.LICENSE_EXPIRED,
                True,
            )

        # Successful validation advances the trusted clock lineage.
        state.license_id = str(document["license_id"])
        state.issue_sequence = max(state.issue_sequence, int(document["issue_sequence"]))
        StateGuard.advance(state, now_epoch)
        try:
            self._guard.persist(state)
        except (StateIntegrityError, OSError):
            return _blocked(LicenseState.STATE_TAMPERED, ReasonCode.STATE_INTEGRITY_FAILURE)

        decision = LicenseDecision(
            state=state_kind,
            reason=reason,
            edition=str(document["edition"]),
            feature_flags={str(k): bool(v) for k, v in document["feature_flags"].items()},
            issued_at=document["issued_at"],
            not_before=document["not_before"],
            expires_at=document["expires_at"],
            grace_until=document["grace_until"],
            machine_binding=binding,
            product_version_eligible=True,
            renewal_sequence=int(document["issue_sequence"]),
            license_id=str(document["license_id"]),
            read_only=read_only,
            support_code=_SUPPORT_CODES[state_kind],
        )
        return decision

    @staticmethod
    def _decision_with_times(document: dict, blocked: LicenseDecision) -> LicenseDecision:
        """Blocked decisions still surface the safe display facts (dates,
        edition, license id) so the UI can explain itself."""

        return LicenseDecision(
            state=blocked.state,
            reason=blocked.reason,
            edition=str(document.get("edition", "none")),
            issued_at=document.get("issued_at"),
            not_before=document.get("not_before"),
            expires_at=document.get("expires_at"),
            grace_until=document.get("grace_until"),
            machine_binding=blocked.machine_binding,
            renewal_sequence=int(document.get("issue_sequence", 0)),
            license_id=str(document.get("license_id", "")),
            read_only=True,
            support_code=blocked.support_code,
        )

    # -- import / renewal ---------------------------------------------------

    def import_license(self, raw: bytes) -> LicenseDecision:
        """Validate and install a license file (activation or renewal).

        Refuses rollback (older sequence), wrong installation, wrong machine,
        wrong product, bad signatures, and expired candidates. A valid NEWER
        license atomically supersedes the current one.
        """

        config = self.config
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LicenseImportError(ReasonCode.PAYLOAD_MALFORMED, "not a JSON document") from exc
        try:
            validate_document(document, config.public_key)
        except LicenseFormatError as exc:
            raise LicenseImportError(exc.reason, exc.detail) from exc

        if str(document["installation_id"]) != str(config.installation_id):
            raise LicenseImportError(
                ReasonCode.WRONG_INSTALLATION, "license belongs to a different installation"
            )
        fingerprint = config.fingerprint_supplier()
        binding = evaluate_binding(fingerprint, document["machine_binding"])
        if not binding.matched:
            raise LicenseImportError(
                ReasonCode.MACHINE_MISMATCH, "license does not match this machine"
            )
        if not version_eligible(PRODUCT_VERSION, list(document["allowed_product_versions"])):
            raise LicenseImportError(
                ReasonCode.PRODUCT_VERSION_NOT_PERMITTED,
                "license does not permit this product version",
            )

        now_epoch = float(config.clock())
        issued_at = parse_timestamp(document["issued_at"], "issued_at")
        grace_until = parse_timestamp(document["grace_until"], "grace_until")
        if issued_at.timestamp() > now_epoch + FUTURE_ISSUE_SLACK_SECONDS:
            raise LicenseImportError(
                ReasonCode.LICENSE_FUTURE_ISSUED, "license is issued in the future"
            )

        try:
            state = self._guard.load(license_issued_epoch=issued_at.timestamp())
        except StateIntegrityError as exc:
            raise LicenseImportError(ReasonCode.STATE_INTEGRITY_FAILURE, str(exc)) from exc
        # Import uses the SAME monotonic trusted clock as evaluation, so a clock
        # parked below the recorded lineage cannot make an expired license
        # importable again.
        if grace_until.timestamp() < max(now_epoch, state.highest_trusted_epoch):
            raise LicenseImportError(ReasonCode.LICENSE_EXPIRED, "license is already expired")
        incoming_sequence = int(document["issue_sequence"])
        if state.license_id and incoming_sequence < state.issue_sequence:
            raise LicenseImportError(
                ReasonCode.LICENSE_ROLLBACK_REJECTED,
                "an older license cannot replace a newer one",
            )
        if (
            state.license_id
            and incoming_sequence == state.issue_sequence
            and str(document["license_id"]) != state.license_id
        ):
            raise LicenseImportError(
                ReasonCode.LICENSE_ROLLBACK_REJECTED,
                "a different license with the same sequence is rejected",
            )

        config.license_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = config.license_path.with_suffix(config.license_path.suffix + ".tmp")
        tmp.write_bytes(raw)
        import os

        os.replace(tmp, config.license_path)

        state.license_id = str(document["license_id"])
        state.issue_sequence = max(state.issue_sequence, incoming_sequence)
        StateGuard.advance(state, now_epoch)
        self._guard.persist(state)
        return self.evaluate()
