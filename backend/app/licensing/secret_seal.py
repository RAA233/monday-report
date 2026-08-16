"""DPAPI-sealed secrets for the Online AI provider's API key.

Reuses Windows DPAPI (CryptProtectData/CryptUnprotectData) exactly as the licensing
state does, but with a DISTINCT entropy so the online-key crypto domain is separate
from licensing state. ``state_guard`` is left byte-untouched. The plaintext key is
NEVER written to disk, env, logs, or audit — only the sealed blob is persisted, and
the key exists in cleartext only briefly in process memory while a request is made.

Two backends, version-tagged so a blob names its own format:
  * ``D1`` — production DPAPI (Windows only). This is the ONLY backend used on the
    product platform: win32 ALWAYS selects DPAPI, a leaked test-mode env is ignored
    there, and a ``T1`` blob is refused in DPAPI mode.
  * ``T1`` — a stdlib HMAC-keystream test backend, reachable ONLY on non-Windows AND
    only when an explicit test env is set. It is non-plaintext (keystream XOR + HMAC
    tag) so the "never plaintext at rest" property is testable on Linux CI, but it can
    never be reached on the Windows product.

DPAPI here (as in state_guard) protects against OTHER Windows users and offline/foreign
machine theft, but NOT against malware running as the SAME user on the same machine.
That bounds the at-rest threat model of the stored key.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import sys

#: Distinct from state_guard's ``monday-report-license-state.v1`` — separate domain.
SECRET_SEAL_ENTROPY = b"monday-report-online-api-key.v1"
SEAL_TEST_MODE_ENV = "MONDAY_REPORT_ONLINE_AI_SEAL_MODE"     # "test" enables T1 (non-win32 only)
SEAL_TEST_KEY_ENV = "MONDAY_REPORT_ONLINE_AI_SEAL_TEST_KEY"  # >= 16 chars

_D1 = b"D1"
_T1 = b"T1"
_TAG_LEN = 2


class SecretSealUnavailable(RuntimeError):
    """No protected secret store is available on this platform (e.g. non-Windows
    without the explicit test backend)."""


class SecretUnsealError(RuntimeError):
    """A sealed blob could not be unsealed — foreign machine/user, tamper, wrong key,
    or a test blob presented to the production backend. Callers fail closed."""


def _backend() -> str:
    """Windows ALWAYS uses DPAPI: a leaked test-mode env never downgrades a real key on
    the product platform. The test backend is reachable only off-Windows + explicit env."""
    if sys.platform == "win32":
        return "dpapi"
    if os.getenv(SEAL_TEST_MODE_ENV) == "test":
        return "test"
    return "unavailable"


def seal_available() -> bool:
    return _backend() in ("dpapi", "test")


# --- DPAPI (production) -----------------------------------------------------

def _dpapi(data: bytes, *, protect: bool) -> bytes:
    import ctypes
    import ctypes.wintypes as wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def blob(raw: bytes) -> DATA_BLOB:
        buffer = ctypes.create_string_buffer(raw, len(raw))
        return DATA_BLOB(len(raw), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))

    inp = blob(data)
    entropy = blob(SECRET_SEAL_ENTROPY)
    out = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    if not fn(ctypes.byref(inp), None, ctypes.byref(entropy), None, None, 0x1, ctypes.byref(out)):
        # 0x1 = CRYPTPROTECT_UI_FORBIDDEN
        raise SecretUnsealError("DPAPI operation failed (foreign state, tamper, or unavailable)")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


# --- HMAC-keystream test backend (non-Windows CI only) ----------------------

def _test_key() -> bytes:
    key = os.getenv(SEAL_TEST_KEY_ENV, "")
    if len(key) < 16:
        raise SecretSealUnavailable("test seal mode requires a >= 16-char test key")
    return key.encode("utf-8")


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        counter += 1
    return bytes(out[:length])


def _test_seal(plaintext: bytes) -> bytes:
    # Per-seal random nonce so two sealings under one test key are not a two-time pad.
    key = _test_key()
    nonce = os.urandom(16)
    keystream = _keystream(key, nonce, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))
    tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    return nonce + tag + ciphertext


def _test_unseal(body: bytes) -> bytes:
    key = _test_key()
    nonce, tag, ciphertext = body[:16], body[16:48], body[48:]
    if len(nonce) != 16 or len(tag) != 32 or not hmac.compare_digest(
        tag, hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    ):
        raise SecretUnsealError("test seal MAC mismatch (tamper or wrong key)")
    keystream = _keystream(key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, keystream))


# --- public API -------------------------------------------------------------

def seal_secret(plaintext: bytes) -> bytes:
    """Seal ``plaintext`` (the API-key-bearing record) to a version-tagged blob. Raises
    ``SecretSealUnavailable`` if no protected store exists on this platform."""
    backend = _backend()
    if backend == "dpapi":
        return _D1 + _dpapi(plaintext, protect=True)
    if backend == "test":
        return _T1 + _test_seal(plaintext)
    raise SecretSealUnavailable("no protected secret store on this platform")


def unseal_secret(blob: bytes) -> bytes:
    """Recover the plaintext from a sealed blob. Fails closed (``SecretUnsealError``) on a
    foreign/tampered blob, and — in production DPAPI mode — refuses a ``T1`` test blob."""
    backend = _backend()
    tag = bytes(blob[:_TAG_LEN])
    if backend == "dpapi":
        if tag != _D1:
            raise SecretUnsealError("refusing a non-DPAPI sealed blob in production")
        return _dpapi(blob[_TAG_LEN:], protect=False)
    if backend == "test":
        if tag != _T1:
            raise SecretUnsealError("test backend refuses a non-test sealed blob")
        return _test_unseal(blob[_TAG_LEN:])
    raise SecretSealUnavailable("no protected secret store on this platform")
