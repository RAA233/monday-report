"""Protected local licensing state: bounded clock-rollback detection and
monotonic renewal lineage.

The state carries ONLY non-sensitive facts (schema version, license id, highest
seen issue sequence, highest trusted wall-clock, last validation wall-clock, a
write counter, and a tamper-evident integrity value). It is persisted as TWO
independent copies (machine-config dir + user-data dir), each protected on
Windows by DPAPI (``CryptProtectData`` with app-specific entropy) so another
user account or offline edit breaks decryption. Deleting ONE copy does not
reset the clock — the surviving copy wins by write counter. Corrupted state
fails closed. All timestamps are UTC epochs, so timezone changes and system
sleep never trigger false rollback.

Honest limitation (documented, not hidden): offline licensing DETERS
unauthorized copying; it cannot make client-controlled hardware impossible to
modify. Deleting every state copy in the same pass resets the rollback lineage
to the license's own issue time — the detection is bounded, not perfect.
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .canonical import canonical_bytes, canonical_hash

STATE_SCHEMA_VERSION = "mr-license-state.v1"

#: Backward clock movement tolerated before rollback is declared (legitimate
#: RTC drift, NTP corrections, dual-boot clock skew).
CLOCK_ROLLBACK_TOLERANCE_SECONDS = 48 * 3600

_DPAPI_ENTROPY = b"monday-report-license-state.v1"


class StateIntegrityError(Exception):
    """Raised when every present state copy fails integrity — fail closed."""


def _protect_mode() -> str:
    """``dpapi`` on Windows; the executable test mode must be selected
    explicitly and never silently replaces DPAPI on a customer machine."""

    if os.getenv("MONDAY_REPORT_LICENSING_STATE_MODE") == "test":
        return "test"
    if sys.platform == "win32":
        return "dpapi"
    raise StateIntegrityError("no protected storage mechanism available on this platform")


def _dpapi_protect(data: bytes) -> bytes:
    import ctypes
    import ctypes.wintypes as wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _blob(raw: bytes) -> DATA_BLOB:
        buffer = ctypes.create_string_buffer(raw, len(raw))
        return DATA_BLOB(len(raw), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))

    inp = _blob(data)
    entropy = _blob(_DPAPI_ENTROPY)
    out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(inp), None, ctypes.byref(entropy), None, None, 0x1, ctypes.byref(out)
    ):  # 0x1 = CRYPTPROTECT_UI_FORBIDDEN
        raise StateIntegrityError("DPAPI protect failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def _dpapi_unprotect(data: bytes) -> bytes:
    import ctypes
    import ctypes.wintypes as wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _blob(raw: bytes) -> DATA_BLOB:
        buffer = ctypes.create_string_buffer(raw, len(raw))
        return DATA_BLOB(len(raw), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))

    inp = _blob(data)
    entropy = _blob(_DPAPI_ENTROPY)
    out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(inp), None, ctypes.byref(entropy), None, None, 0x1, ctypes.byref(out)
    ):
        raise StateIntegrityError("DPAPI unprotect failed (tampered or foreign state)")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def _test_key() -> bytes:
    key = os.getenv("MONDAY_REPORT_LICENSING_STATE_TEST_KEY", "")
    if len(key) < 16:
        raise StateIntegrityError("test state mode requires a test key")
    return key.encode("utf-8")


def _seal(document: dict) -> bytes:
    body = dict(document)
    body["integrity"] = canonical_hash({"seal": STATE_SCHEMA_VERSION, "body": {k: v for k, v in body.items() if k != "integrity"}})
    raw = canonical_bytes(body)
    if _protect_mode() == "dpapi":
        return _dpapi_protect(raw)
    import hashlib
    import hmac as hmac_mod

    mac = hmac_mod.new(_test_key(), raw, hashlib.sha256).hexdigest()
    return json.dumps({"mode": "test", "auth_tag": mac, "body": body}).encode("utf-8")


def _unseal(blob: bytes) -> dict:
    if _protect_mode() == "dpapi":
        raw = _dpapi_unprotect(blob)
        body = json.loads(raw.decode("utf-8"))
    else:
        import hashlib
        import hmac as hmac_mod

        envelope = json.loads(blob.decode("utf-8"))
        body = envelope.get("body", {})
        expected = hmac_mod.new(_test_key(), canonical_bytes(body), hashlib.sha256).hexdigest()
        if not hmac_mod.compare_digest(expected, str(envelope.get("auth_tag", ""))):
            raise StateIntegrityError("state MAC mismatch (tampered)")
    expected_integrity = canonical_hash(
        {"seal": STATE_SCHEMA_VERSION, "body": {k: v for k, v in body.items() if k != "integrity"}}
    )
    if body.get("integrity") != expected_integrity:
        raise StateIntegrityError("state integrity value mismatch (tampered)")
    if body.get("schema_version") != STATE_SCHEMA_VERSION:
        raise StateIntegrityError("unsupported state schema")
    return body


@dataclass
class LicensingState:
    license_id: str
    issue_sequence: int
    highest_trusted_epoch: float
    last_validation_epoch: float
    write_counter: int
    reset_detected: bool = False

    def document(self) -> dict:
        return {
            "schema_version": STATE_SCHEMA_VERSION,
            "license_id": self.license_id,
            "issue_sequence": self.issue_sequence,
            "highest_trusted_epoch": self.highest_trusted_epoch,
            "last_validation_epoch": self.last_validation_epoch,
            "write_counter": self.write_counter,
        }


class StateGuard:
    """Dual-copy protected state with rollback checks."""

    def __init__(self, primary_path: Path, secondary_path: Path) -> None:
        self.paths = (Path(primary_path), Path(secondary_path))

    def _read_copy(self, path: Path) -> LicensingState | None:
        blob = path.read_bytes()
        body = _unseal(blob)
        return LicensingState(
            license_id=str(body.get("license_id", "")),
            issue_sequence=int(body.get("issue_sequence", 0)),
            highest_trusted_epoch=float(body.get("highest_trusted_epoch", 0.0)),
            last_validation_epoch=float(body.get("last_validation_epoch", 0.0)),
            write_counter=int(body.get("write_counter", 0)),
        )

    def load(self, *, license_issued_epoch: float | None) -> LicensingState:
        """Load the best surviving copy; fail closed when every PRESENT copy is
        corrupt; initialize (anchored to the license issue time) only when NO
        copy exists at all."""

        candidates: list[LicensingState] = []
        present = 0
        for path in self.paths:
            if not path.exists():
                continue
            present += 1
            try:
                state = self._read_copy(path)
            except (StateIntegrityError, OSError, ValueError, json.JSONDecodeError):
                continue
            if state is not None:
                candidates.append(state)
        if candidates:
            return max(candidates, key=lambda s: s.write_counter)
        if present:
            raise StateIntegrityError("every present licensing state copy failed integrity")
        anchor = float(license_issued_epoch) if license_issued_epoch else time.time()
        return LicensingState(
            license_id="",
            issue_sequence=0,
            highest_trusted_epoch=anchor,
            last_validation_epoch=0.0,
            write_counter=0,
            reset_detected=license_issued_epoch is not None,
        )

    def persist(self, state: LicensingState) -> None:
        state.write_counter += 1
        blob = _seal(state.document())
        for path in self.paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_bytes(blob)
            os.replace(tmp, path)

    @staticmethod
    def rollback_detected(state: LicensingState, now_epoch: float) -> bool:
        return now_epoch + CLOCK_ROLLBACK_TOLERANCE_SECONDS < state.highest_trusted_epoch

    @staticmethod
    def advance(state: LicensingState, now_epoch: float) -> None:
        state.highest_trusted_epoch = max(state.highest_trusted_epoch, now_epoch)
        state.last_validation_epoch = now_epoch
