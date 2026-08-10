"""Licensing abstraction shared by the Offline, SaaS, and Hybrid editions.

Business logic consumes ONLY the normalized :class:`LicenseDecision` produced by
a :class:`LicenseProvider`. Nothing outside this package may parse license
files, inspect machine facts, or interpret presentation strings — enforcement
keys off the typed :class:`ReasonCode` and the derived capability booleans, so a
later SaaS provider plugs in without rewriting business logic.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


PRODUCT_NAME = "monday-report"
#: Product version used for license eligibility checks and update manifests.
PRODUCT_VERSION = "1.0.0"


class LicenseState(str, Enum):
    """Normalized license lifecycle states surfaced to the UI."""

    VALID = "valid"
    EXPIRING_SOON = "expiring_soon"
    GRACE = "grace"
    EXPIRED_READ_ONLY = "expired_read_only"
    MACHINE_MISMATCH = "machine_mismatch"
    INVALID_SIGNATURE = "invalid_signature"
    CORRUPT_LICENSE = "corrupt_license"
    UNSUPPORTED_LICENSE_VERSION = "unsupported_license_version"
    PRODUCT_VERSION_NOT_PERMITTED = "product_version_not_permitted"
    NOT_YET_VALID = "not_yet_valid"
    CLOCK_ROLLBACK_DETECTED = "clock_rollback_detected"
    STATE_TAMPERED = "state_tampered"
    NO_LICENSE = "no_license"
    PROVIDER_UNAVAILABLE = "provider_unavailable"


class ReasonCode(str, Enum):
    """Stable typed reason codes. Enforcement and tests key off these values —
    never off presentation strings."""

    OK = "OK"
    EXPIRING_SOON = "EXPIRING_SOON"
    IN_GRACE_PERIOD = "IN_GRACE_PERIOD"
    LICENSE_EXPIRED = "LICENSE_EXPIRED"
    LICENSE_NOT_YET_VALID = "LICENSE_NOT_YET_VALID"
    LICENSE_FUTURE_ISSUED = "LICENSE_FUTURE_ISSUED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    WRONG_SIGNING_KEY = "WRONG_SIGNING_KEY"
    WRONG_ALGORITHM = "WRONG_ALGORITHM"
    SCHEMA_UNSUPPORTED = "SCHEMA_UNSUPPORTED"
    PAYLOAD_MALFORMED = "PAYLOAD_MALFORMED"
    FIELD_MISSING = "FIELD_MISSING"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    MACHINE_MISMATCH = "MACHINE_MISMATCH"
    MACHINE_FACTS_UNAVAILABLE = "MACHINE_FACTS_UNAVAILABLE"
    PRODUCT_VERSION_NOT_PERMITTED = "PRODUCT_VERSION_NOT_PERMITTED"
    WRONG_PRODUCT = "WRONG_PRODUCT"
    WRONG_INSTALLATION = "WRONG_INSTALLATION"
    CLOCK_ROLLBACK_DETECTED = "CLOCK_ROLLBACK_DETECTED"
    LICENSE_ROLLBACK_REJECTED = "LICENSE_ROLLBACK_REJECTED"
    STATE_INTEGRITY_FAILURE = "STATE_INTEGRITY_FAILURE"
    NO_LICENSE_INSTALLED = "NO_LICENSE_INSTALLED"
    PROVIDER_NOT_IMPLEMENTED = "PROVIDER_NOT_IMPLEMENTED"


class BindingConfidence(str, Enum):
    """Redacted machine-binding confidence class. Never carries component
    values."""

    STRONG = "strong"
    REDUCED_VIRTUAL_MACHINE = "reduced_virtual_machine"
    DEGRADED_FEW_COMPONENTS = "degraded_few_components"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class MachineBindingResult:
    """Redacted result of comparing the local fingerprint to a license binding.

    Reports only counts and classes — component values never leave the
    fingerprint module.
    """

    fingerprint_version: str
    eligible_components: int
    matched_components: int
    required_matches: int
    strong_component_matched: bool
    confidence: BindingConfidence
    matched: bool


@dataclass(frozen=True)
class LicenseDecision:
    """The single normalized decision every runtime consumer receives."""

    state: LicenseState
    reason: ReasonCode
    edition: str = "none"
    feature_flags: dict[str, bool] = field(default_factory=dict)
    issued_at: str | None = None
    not_before: str | None = None
    expires_at: str | None = None
    grace_until: str | None = None
    machine_binding: MachineBindingResult | None = None
    product_version_eligible: bool = False
    renewal_sequence: int = 0
    license_id: str | None = None
    #: True when only reads, backups, and license/renewal actions are allowed.
    read_only: bool = True
    #: Support reference code shown with every blocked action (never contains
    #: machine facts or customer identifiers).
    support_code: str = ""

    @property
    def operational(self) -> bool:
        """Full licensed operation (including grace) — mutations permitted."""

        return self.state in (
            LicenseState.VALID,
            LicenseState.EXPIRING_SOON,
            LicenseState.GRACE,
        )


class LicenseProvider(ABC):
    """Edition-agnostic provider interface.

    ``OfflineSignedLicenseProvider`` is fully implemented in this task. The SaaS
    and hybrid providers are explicit fail-closed placeholders so business logic
    never grows offline-only assumptions.
    """

    @abstractmethod
    def evaluate(self) -> LicenseDecision:
        """Return the current normalized license decision. Must never raise."""

    @abstractmethod
    def provider_kind(self) -> str:
        """Stable provider identifier for diagnostics (no secrets)."""


class SaaSSubscriptionProvider(LicenseProvider):
    """Future SaaS subscription check. NOT implemented in this task — fails
    closed with a typed reason instead of pretending to be licensed."""

    def provider_kind(self) -> str:
        return "saas_subscription_placeholder"

    def evaluate(self) -> LicenseDecision:
        return LicenseDecision(
            state=LicenseState.PROVIDER_UNAVAILABLE,
            reason=ReasonCode.PROVIDER_NOT_IMPLEMENTED,
            read_only=True,
            support_code="MR-LIC-SAAS-000",
        )


class HybridOfflineLeaseProvider(LicenseProvider):
    """Future hybrid (online lease + offline fallback) provider. NOT implemented
    in this task — fails closed with a typed reason."""

    def provider_kind(self) -> str:
        return "hybrid_offline_lease_placeholder"

    def evaluate(self) -> LicenseDecision:
        return LicenseDecision(
            state=LicenseState.PROVIDER_UNAVAILABLE,
            reason=ReasonCode.PROVIDER_NOT_IMPLEMENTED,
            read_only=True,
            support_code="MR-LIC-HYBRID-000",
        )
