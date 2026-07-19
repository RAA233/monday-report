from __future__ import annotations

import hashlib
import hmac
import os
import secrets


API_KEY_ENV = "MONDAY_REPORT_API_KEY"
API_KEY_HEADER = "x-monday-report-key"
MIN_API_KEY_LENGTH = 24

# Per-user credential parameters.
CREDENTIAL_TOKEN_BYTES = 32  # >= 32 random bytes of entropy per the contract.
MIN_TOKEN_LENGTH = 24
MAX_TOKEN_LENGTH = 512  # reject unreasonably long tokens before any lookup.
# Optional server-side pepper mixed into the credential hash. It is not required
# (the token itself carries >= 32 bytes of entropy) but strengthens at-rest
# hashes if configured. It is never returned or logged.
CREDENTIAL_PEPPER_ENV = "MONDAY_REPORT_CREDENTIAL_PEPPER"


def api_key_configured() -> bool:
    return len(os.getenv(API_KEY_ENV, "")) >= MIN_API_KEY_LENGTH


def api_key_valid(supplied_key: str | None) -> bool:
    expected_key = os.getenv(API_KEY_ENV, "")
    return bool(supplied_key) and api_key_configured() and hmac.compare_digest(supplied_key, expected_key)


def generate_api_token() -> str:
    """Generate a high-entropy opaque per-user credential token."""
    return secrets.token_urlsafe(CREDENTIAL_TOKEN_BYTES)


def is_well_formed_token(token: str | None) -> bool:
    """Cheap structural validation performed BEFORE any credential lookup, so a
    malformed or unreasonably long token never reaches the hash/compare path."""
    if not token or not isinstance(token, str):
        return False
    if len(token) < MIN_TOKEN_LENGTH or len(token) > MAX_TOKEN_LENGTH:
        return False
    # Opaque tokens are URL-safe base64 (secrets.token_urlsafe) plus the legacy
    # configured key; restrict to a conservative printable set.
    return all(32 <= ord(ch) <= 126 for ch in token)


def _pepper() -> bytes:
    return os.getenv(CREDENTIAL_PEPPER_ENV, "").encode("utf-8")


def hash_token(token: str) -> str:
    """Deterministic cryptographic hash of a credential token for at-rest
    storage and lookup. The raw token is never persisted."""
    digest = hashlib.sha256()
    digest.update(b"monday-report/credential/v1:")
    digest.update(_pepper())
    digest.update(b":")
    digest.update(token.encode("utf-8"))
    return digest.hexdigest()


def token_fingerprint(token: str) -> str:
    """Short, non-secret, domain-separated identifier for a credential. It is
    derived independently from the auth hash so exposing it never leaks the
    token or the stored hash."""
    digest = hashlib.sha256(b"monday-report/fingerprint/v1:" + token.encode("utf-8")).hexdigest()
    return f"cred_{digest[:12]}"


def tokens_match(candidate_hash: str, stored_hash: str) -> bool:
    """Constant-time comparison of credential hashes."""
    return hmac.compare_digest(candidate_hash, stored_hash)
