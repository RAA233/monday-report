"""Versioned HMAC key provider for audit-chain integrity.

Provides the managed secret(s) used to compute keyed HMAC audit hashes. Key
material is NEVER persisted to the snapshot, audit events, source control,
generated evidence, logs, or error responses — only non-secret metadata (key id,
key version, provider type, a one-way fingerprint) is ever exposed. This module is
the bounded key-provider contract only; it is NOT a key-management service and
performs no automatic rotation scheduling.

Threat-model note (see docs/AUDIT_INTEGRITY.md): the application process that
signs an event necessarily reads the active key, so keyed HMAC protects snapshot
integrity against actors who can alter the state file but do NOT possess the audit
secret. It does not protect against a compromised application process that can read
the key, a malicious administrator holding both state and secret, tail truncation,
deletion of the entire keyed suffix, rollback to an older snapshot, or external
audit-log destruction.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from dataclasses import dataclass, field

MIN_KEY_BYTES = 32
INTEGRITY_ALGORITHM = "HMAC-SHA256"
KEYED_INTEGRITY_VERSION = 2

ACTIVE_KEY_ENV = "MONDAY_REPORT_AUDIT_HMAC_KEY"
ACTIVE_KEY_ID_ENV = "MONDAY_REPORT_AUDIT_HMAC_KEY_ID"
ACTIVE_KEY_VERSION_ENV = "MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION"
# Optional retained VERIFICATION-ONLY keys for rotation:
# JSON list of {"key_id": str, "key_version": int, "secret": str}.
RETAINED_KEYS_ENV = "MONDAY_REPORT_AUDIT_HMAC_RETAINED_KEYS"
DEFAULT_KEY_ID = "audit-primary"


class AuditKeyConfigError(ValueError):
    """Configured audit key material is invalid: too short, malformed encoding,
    non-integer version, or a duplicate key id/version with a different secret."""


class AuditIntegrityUnavailable(RuntimeError):
    """A keyed audit event cannot be written because the active HMAC key is
    unavailable in a mode that requires it (client mode). Callers MUST NOT persist
    any business-state mutation when this is raised (fail closed, before mutation)."""


@dataclass(frozen=True)
class AuditKeyRef:
    """A resolved key: id + version + raw secret. The secret is used only to
    compute/verify HMAC and is never serialized or logged."""

    key_id: str
    key_version: int
    # repr=False so the raw secret never leaks via repr()/logging/traceback frames.
    secret: bytes = field(repr=False)

    def fingerprint(self) -> str:
        """A one-way, non-secret fingerprint (truncated SHA-256 of the key). Safe
        to surface in status/evidence; not reversible to the key."""
        return hashlib.sha256(self.secret).hexdigest()[:16]


def _decode_secret(raw: str) -> bytes:
    """Decode a configured secret to raw bytes: strict base64 when that yields at
    least MIN_KEY_BYTES, otherwise the UTF-8 bytes of the string. Deterministic."""
    raw = raw.strip()
    try:
        decoded = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
        if len(decoded) >= MIN_KEY_BYTES:
            return decoded
    except (binascii.Error, ValueError):
        pass
    return raw.encode("utf-8")


class AuditKeyProvider:
    """Bounded provider interface. ``active_key`` is the current signing key; older
    versions are retained for VERIFICATION ONLY (never used to sign new events)."""

    def active_key(self) -> AuditKeyRef | None:
        raise NotImplementedError

    def key_for(self, key_id: str, key_version: int) -> AuditKeyRef | None:
        raise NotImplementedError

    def available_versions(self) -> list[tuple[str, int]]:
        raise NotImplementedError

    def provider_type(self) -> str:
        raise NotImplementedError

    def is_available(self) -> bool:
        """True iff a valid active key is configured. A misconfigured key
        (short/malformed) is treated as unavailable (never as a valid key)."""
        try:
            return self.active_key() is not None
        except AuditKeyConfigError:
            return False

    def active_metadata(self) -> dict[str, object] | None:
        """Non-secret metadata for the active key, or None. Never includes the
        secret."""
        try:
            ref = self.active_key()
        except AuditKeyConfigError:
            return None
        if ref is None:
            return None
        return {
            "key_id": ref.key_id,
            "key_version": ref.key_version,
            "provider_type": self.provider_type(),
            "fingerprint": ref.fingerprint(),
        }


class EnvAuditKeyProvider(AuditKeyProvider):
    """Environment/secret-injected provider. Reads the active key and optional
    retained verification-only keys from environment variables. Nothing persists."""

    def provider_type(self) -> str:
        return "environment"

    def _active_ref(self) -> AuditKeyRef | None:
        raw = os.getenv(ACTIVE_KEY_ENV, "").strip()
        if not raw:
            return None
        secret = _decode_secret(raw)
        if len(secret) < MIN_KEY_BYTES:
            raise AuditKeyConfigError(f"audit HMAC key must be at least {MIN_KEY_BYTES} bytes")
        key_id = (os.getenv(ACTIVE_KEY_ID_ENV, DEFAULT_KEY_ID).strip() or DEFAULT_KEY_ID)
        raw_version = os.getenv(ACTIVE_KEY_VERSION_ENV, "1").strip() or "1"
        try:
            key_version = int(raw_version)
        except ValueError:
            raise AuditKeyConfigError("audit HMAC key version must be an integer")
        if key_version < 1:
            raise AuditKeyConfigError("audit HMAC key version must be >= 1")
        return AuditKeyRef(key_id, key_version, secret)

    def _all_refs(self) -> dict[tuple[str, int], AuditKeyRef]:
        refs: dict[tuple[str, int], AuditKeyRef] = {}
        active = self._active_ref()
        if active is not None:
            refs[(active.key_id, active.key_version)] = active
        raw = os.getenv(RETAINED_KEYS_ENV, "").strip()
        if raw:
            try:
                items = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise AuditKeyConfigError(f"invalid retained-keys JSON: {exc}")
            if not isinstance(items, list):
                raise AuditKeyConfigError("retained keys must be a JSON list")
            for item in items:
                try:
                    key_id = str(item["key_id"])
                    key_version = int(item["key_version"])
                    secret = _decode_secret(str(item["secret"]))
                except (KeyError, TypeError, ValueError) as exc:
                    raise AuditKeyConfigError(f"invalid retained key entry: {exc}")
                if len(secret) < MIN_KEY_BYTES:
                    raise AuditKeyConfigError(
                        f"retained key {key_id}/{key_version} must be at least {MIN_KEY_BYTES} bytes"
                    )
                identity = (key_id, key_version)
                if identity in refs and refs[identity].secret != secret:
                    raise AuditKeyConfigError(
                        f"duplicate key id/version with a different secret: {key_id}/{key_version}"
                    )
                refs[identity] = AuditKeyRef(key_id, key_version, secret)
        return refs

    def active_key(self) -> AuditKeyRef | None:
        return self._active_ref()

    def key_for(self, key_id: str, key_version: int) -> AuditKeyRef | None:
        return self._all_refs().get((key_id, key_version))

    def available_versions(self) -> list[tuple[str, int]]:
        return sorted(self._all_refs().keys())


_provider: AuditKeyProvider = EnvAuditKeyProvider()


def audit_key_provider() -> AuditKeyProvider:
    """The process-wide audit key provider (environment-backed).

    Consistency model (per-append snapshot): the environment is read on every
    ``active_key()`` / ``key_for()`` call, and ``store.audit()`` resolves the active
    key EXACTLY ONCE per event under ``audit_lock`` — so a single audit event is
    always sealed under one key id/version and can never be split across a rotation.
    A rotation (changing the ``MONDAY_REPORT_AUDIT_HMAC_*`` variables) takes effect
    deterministically at the NEXT event boundary; the previous version, if retained
    for verification, keeps verifying older events. There is no per-PROCESS snapshot:
    a multi-event logical operation may span a rotation, which is acceptable because
    each event self-describes its key and this store does not provide multi-event
    transactional atomicity (see docs/AUDIT_INTEGRITY.md — persistence/transaction
    blockers remain unresolved)."""
    return _provider
