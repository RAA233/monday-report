"""Schemas and cryptographic helpers for the dual-principal offline acceptance
protocol.

WHY THIS EXISTS
---------------
The previous acceptance chain was author-controlled end to end: the authoring
process computed the results, the hashes, the seals AND the verdict. An
independent review demonstrated the consequence -- replacing ``ENVIRONMENT_2``
with a verbatim copy of ``ENVIRONMENT_1``, changing only ``environment_class``
and ``fingerprint_identity_digest``, and resealing the author-controlled hashes
passed the public validator with zero reasons and yielded
``offline_commercial_package: PASS``. Nothing in the chain required a fact the
author could not manufacture.

This module supplies the fact the author cannot manufacture: an Ed25519
signature from a key held by a SEPARATE Windows principal whose credential the
authoring process never learned.

SOURCE INTEGRITY IS ESTABLISHED UPSTREAM, NOT HERE (Offline Edition v2).
This module is the cryptographic plumbing -- signing, verification, domain
separation, whole-document hashing, principal digests -- and it is
mechanism-agnostic about HOW the reviewer came to trust the source bytes it
attests. In v2 that trust is established before this module is reached: the
reviewer executes only from a flat, git-free copy verified against a per-file
SHA-256 manifest whose root hash the operator pinned into the reviewer trust
directory (see scripts/offline_export_manifest.py and
scripts/offline_reviewer_execute.py::_head_binding_reasons). The
``source_commit``/``source_tree`` fields the attestation binds are the
operator-recorded provenance carried in that manifest -- reconciled against the
verified bytes, never queried from a repository inside the boundary.

WHAT IS AND IS NOT CLAIMED
--------------------------
Claimed: the authoring process cannot produce a valid attestation, because it
cannot create a reviewer logon session and therefore cannot decrypt the
DPAPI-protected review key. This defeats self-grading, accidental artifact
substitution, and author-process forgery.

NOT claimed, and never to be written as though it were:

* Resistance to a host administrator who takes ownership of the reviewer
  account. That is the declared non-goal. An administrative password reset
  destroys the DPAPI master-key chain, so the review key becomes permanently
  undecryptable -- the failure mode is denial, not silent forgery.
* That a signature proves the matrices executed. It proves the review key signed
  a set of values. Execution evidence is the issuance witness plus the
  reviewer-measured primitives, and even then see the residual below.
* That the reviewer independently verified the results. THE REVIEWER EXECUTES
  CODE THE AUTHOR WROTE. An author-committed runner that emitted an all-PASS
  check list without executing anything would produce genuine hashes and a
  genuine signature over fabricated facts. The tool hashes record WHICH binary
  ran, never that it was honest. Honesty of that code rests on human review of
  the attested commit. This is the protocol's real residual.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .licensing.canonical import CanonicalizationError, canonical_bytes, canonical_hash

TRUST_ROOT_SCHEMA = "offline-review-trust-root.v1"
TRANSCRIPT_SCHEMA = "offline-environment-execution-transcript.v1"
ATTESTATION_SCHEMA = "offline-independent-review-attestation.v1"
WITNESS_SCHEMA = "offline-review-issuance-witness.v1"

#: Domain separators. A value signed for one purpose must never verify for
#: another, and a hash chained for one purpose must never collide with another.
DOMAIN_ATTESTATION = "monday-report/offline-review-attestation/v1"
DOMAIN_TRANSCRIPT = "monday-report/offline-execution-transcript/v1"
DOMAIN_CHAIN = "monday-report/offline-check-chain/v1"
DOMAIN_WITNESS = "monday-report/offline-issuance-witness/v1"

HEX64 = re.compile(r"[0-9a-f]{64}")
HEX32 = re.compile(r"[0-9a-f]{32}")
HEX16 = re.compile(r"[0-9a-f]{16}")

#: Every field an execution transcript must carry. Absence is a rejection, not a
#: default: a transcript that omits a fact asserts nothing about it, and the
#: validator must not silently treat "missing" as "fine".
REQUIRED_TRANSCRIPT_FIELDS = (
    "schema_version",
    "environment_label",
    "environment_class",
    "source_commit",
    "source_tree",
    "package_version",
    "installer_sha256",
    "executable_sha256",
    "payload_manifest_sha256",
    "frontend_manifest_sha256",
    "public_key_fingerprint",
    "matrix_tool_hash",
    "matrix_start_challenge",
    "matrix_completion_challenge",
    "ordered_check_result_hash",
    "raw_transcript_hash",
    "environment_result_hash",
    "machine_binding",
    "machine_fingerprint_hash",
    "fingerprint_identity_digest",
    "issuance_witness",
    "offline",
    "localhost_only",
    "dependency_absence",
    "cross_license_rejected",
    "backup_restore",
    "expiry_read_only",
    "upgrade",
    "uninstall_reinstall",
    "totals",
    "checks",
)

#: Boolean outcomes every environment must have actually demonstrated.
REQUIRED_TRANSCRIPT_TRUTHS = (
    "offline",
    "localhost_only",
    "dependency_absence",
    "cross_license_rejected",
    "backup_restore",
    "expiry_read_only",
    "upgrade",
    "uninstall_reinstall",
)

REQUIRED_ATTESTATION_FIELDS = (
    "schema_version",
    "reviewer_key_fingerprint",
    "reviewer_principal_digest",
    "author_principal_digest",
    "source_commit",
    "source_tree",
    "package_version",
    "installer_sha256",
    "executable_sha256",
    "payload_manifest_sha256",
    "frontend_manifest_sha256",
    "public_key_fingerprint",
    "environment_transcript_hashes",
    "environment_result_hashes",
    "cross_environment_proof_hash",
    "evidence_body_digest",
    "validator_source_digest",
    "audit_all_step_digest",
    "review_tool_hashes",
    "review_started_at",
    "review_completed_at",
    "review_nonce",
    "review_verdict",
    "review_reason_codes",
    "signature",
)

#: The only verdict string the reviewer may sign that permits acceptance.
REVIEW_VERDICT_ACCEPT = "INDEPENDENT_REVIEW_ACCEPT"
REVIEW_VERDICT_REJECT = "INDEPENDENT_REVIEW_REJECT"


class AttestationError(ValueError):
    """Raised when a document cannot be signed or verified as specified."""


def key_fingerprint(public_key_bytes: bytes) -> str:
    """Fingerprint DERIVED from the key bytes.

    Never accept a fingerprint as a free string alongside a key: that lets a
    document name one identity while carrying another. The licence format makes
    the same commitment for machine bindings.
    """

    if not isinstance(public_key_bytes, (bytes, bytearray)) or len(public_key_bytes) != 32:
        raise AttestationError("an Ed25519 public key is exactly 32 bytes")
    return hashlib.sha256(bytes(public_key_bytes)).hexdigest()[:16]


def principal_digest(sid: str, salt: str) -> str:
    """Salted digest of a Windows SID.

    Raw SIDs are never persisted. The digest is recomputed from a LIVE SID
    lookup at validation time -- comparing two stored digests would reduce
    "two distinct principals" to "two hex strings differ", which is the exact
    shape of the defect this protocol exists to close.
    """

    if not sid or not sid.startswith("S-1-"):
        raise AttestationError("a Windows SID is required")
    if not salt:
        raise AttestationError("a principal salt is required")
    return hashlib.sha256(f"{salt}|{sid}".encode("utf-8")).hexdigest()


def chain_check_results(start_challenge: str, outputs: list[str]) -> str:
    """Ordering chain over check outputs: c_0 = start, c_i = H(domain||c_i-1||out_i).

    This establishes ORDER WITHIN a run. It is deliberately NOT presented as
    anti-replay: every input is a deterministic function of files on disk, so
    anyone holding those files can recompute it. The anti-replay anchor is the
    issuance witness, which binds a reviewer nonce to an author signature at a
    known time inside a seconds-scale licence lifetime.
    """

    if not HEX64.fullmatch(start_challenge or ""):
        raise AttestationError("start challenge must be a 64-hex digest")
    current = start_challenge
    for output in outputs:
        current = hashlib.sha256(
            f"{DOMAIN_CHAIN}|{current}|{output}".encode("utf-8")).hexdigest()
    return current


def transcript_signing_view(transcript: dict) -> dict:
    return {k: v for k, v in transcript.items() if k != "transcript_hash"}


def transcript_hash(transcript: dict) -> str:
    """Whole-document hash. Binding is ALWAYS by whole-document hash, never by a
    field allowlist -- an allowlist leaves everything outside it as free text,
    which is precisely how a copied environment block passed the old chain."""

    try:
        return canonical_hash(
            {"domain": DOMAIN_TRANSCRIPT, "body": transcript_signing_view(transcript)})
    except CanonicalizationError as exc:
        raise AttestationError(str(exc)) from exc


def attestation_signing_payload(attestation: dict) -> bytes:
    body = {k: v for k, v in attestation.items() if k != "signature"}
    try:
        return canonical_bytes({"domain": DOMAIN_ATTESTATION, "body": body})
    except CanonicalizationError as exc:
        raise AttestationError(str(exc)) from exc


def witness_signing_payload(witness: dict) -> bytes:
    body = {k: v for k, v in witness.items() if k != "signature"}
    try:
        return canonical_bytes({"domain": DOMAIN_WITNESS, "body": body})
    except CanonicalizationError as exc:
        raise AttestationError(str(exc)) from exc


def sign_attestation(attestation: dict, private_key: Ed25519PrivateKey) -> dict:
    signed = {k: v for k, v in attestation.items() if k != "signature"}
    signed["signature"] = private_key.sign(
        attestation_signing_payload(signed)).hex()
    return signed


def verify_attestation(attestation: dict, public_key_bytes: bytes) -> list[str]:
    """Return every reason the attestation is not a valid signed statement.

    Empty list means the signature verifies AND the document is shaped as this
    tier requires. Callers must not treat a shape failure as a signature pass.
    """

    reasons: list[str] = []
    if not isinstance(attestation, dict):
        return ["attestation is not an object"]
    if attestation.get("schema_version") != ATTESTATION_SCHEMA:
        reasons.append("attestation carries the wrong schema version")

    missing = [f for f in REQUIRED_ATTESTATION_FIELDS if f not in attestation]
    if missing:
        reasons.append(f"attestation is missing required fields: {','.join(sorted(missing))}")
    unknown = [k for k in attestation if k not in REQUIRED_ATTESTATION_FIELDS]
    if unknown:
        reasons.append(f"attestation carries unknown fields: {','.join(sorted(unknown))}")
    if missing or unknown:
        return reasons  # shape must be exact before any value is trusted

    signature = attestation.get("signature", "")
    if not re.fullmatch(r"[0-9a-f]{128}", str(signature)):
        reasons.append("attestation signature is missing or malformed")
        return reasons

    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes(public_key_bytes))
    except (ValueError, TypeError):
        return reasons + ["the trusted review public key is unusable"]

    try:
        public_key.verify(bytes.fromhex(str(signature)),
                          attestation_signing_payload(attestation))
    except (InvalidSignature, ValueError):
        reasons.append("attestation signature does not verify against the pinned review key")
        return reasons

    # The document names a key; it must be THE key, not merely A key. Otherwise
    # a document could name one identity while verifying under another.
    named = str(attestation.get("reviewer_key_fingerprint", ""))
    if named != key_fingerprint(bytes(public_key_bytes)):
        reasons.append("attestation names a different review key than the pinned trust root")

    verdict = attestation.get("review_verdict")
    if verdict not in (REVIEW_VERDICT_ACCEPT, REVIEW_VERDICT_REJECT):
        reasons.append("attestation carries an unrecognised review verdict")
    return reasons


def verify_witness(witness: dict, issuer_public_key_bytes: bytes) -> list[str]:
    """Verify an issuance witness: the AUTHOR's statement, signed with the
    licence-issuer key, that it saw a specific activation request at a specific
    time in response to a nonce the REVIEWER minted.

    This is the anti-replay anchor. The reviewer cannot mint it (no issuer key);
    the author cannot pre-date it (the nonce did not exist); and the licence
    issued alongside it is seconds-scale, so an old witness cannot certify a
    later run.
    """

    reasons: list[str] = []
    if not isinstance(witness, dict):
        return ["issuance witness is not an object"]
    if witness.get("schema_version") != WITNESS_SCHEMA:
        reasons.append("issuance witness carries the wrong schema version")
    for field in ("review_nonce", "activation_request_hash", "issued_at",
                  "expiry_seconds", "signature"):
        if field not in witness:
            reasons.append(f"issuance witness is missing {field}")
    if reasons:
        return reasons

    signature = str(witness.get("signature", ""))
    if not re.fullmatch(r"[0-9a-f]{128}", signature):
        return ["issuance witness signature is malformed"]
    try:
        Ed25519PublicKey.from_public_bytes(bytes(issuer_public_key_bytes)).verify(
            bytes.fromhex(signature), witness_signing_payload(witness))
    except (InvalidSignature, ValueError, TypeError):
        reasons.append("issuance witness signature does not verify against the issuer key")
    return reasons


def validate_transcript_shape(transcript: Any) -> list[str]:
    """Shape and internal-consistency reasons for one execution transcript."""

    reasons: list[str] = []
    if not isinstance(transcript, dict):
        return ["transcript is not an object"]
    if transcript.get("schema_version") != TRANSCRIPT_SCHEMA:
        reasons.append("transcript carries the wrong schema version")

    missing = [f for f in REQUIRED_TRANSCRIPT_FIELDS if f not in transcript]
    if missing:
        reasons.append(f"transcript is missing required fields: {','.join(sorted(missing))}")
        return reasons

    for field in ("installer_sha256", "executable_sha256", "payload_manifest_sha256",
                  "frontend_manifest_sha256", "matrix_tool_hash",
                  "matrix_start_challenge", "matrix_completion_challenge",
                  "ordered_check_result_hash", "raw_transcript_hash",
                  "environment_result_hash", "machine_fingerprint_hash",
                  "source_tree", "source_commit"):
        if not HEX64.fullmatch(str(transcript.get(field, ""))):
            reasons.append(f"transcript {field} is not a 64-hex digest")
    if not HEX32.fullmatch(str(transcript.get("fingerprint_identity_digest", ""))):
        reasons.append("transcript fingerprint_identity_digest is not a 32-hex digest")
    if not HEX16.fullmatch(str(transcript.get("public_key_fingerprint", ""))):
        reasons.append("transcript public_key_fingerprint is not a 16-hex fingerprint")

    # The identity digest must be DERIVED from the binding the transcript
    # carries, not asserted beside it. Asserting it is what allowed a copied
    # environment to claim a distinct machine by editing one string.
    binding = transcript.get("machine_binding")
    if not isinstance(binding, dict) or not binding:
        reasons.append("transcript carries no machine binding")
    else:
        try:
            derived = canonical_hash(binding)
        except CanonicalizationError as exc:
            reasons.append(f"machine binding is not canonicalizable: {exc}")
            derived = None
        if derived is not None:
            if derived != str(transcript.get("machine_fingerprint_hash", "")):
                reasons.append("machine_fingerprint_hash does not match the recorded binding")
            if derived[:32] != str(transcript.get("fingerprint_identity_digest", "")):
                reasons.append("fingerprint_identity_digest does not derive from the binding")

    for truth in REQUIRED_TRANSCRIPT_TRUTHS:
        if transcript.get(truth) is not True:
            reasons.append(f"transcript does not demonstrate {truth}")

    totals = transcript.get("totals")
    if not isinstance(totals, dict):
        reasons.append("transcript carries no totals")
    else:
        if int(totals.get("failed", 1)) != 0:
            reasons.append("transcript records failed checks")
        if int(totals.get("passed", 0)) <= 0:
            reasons.append("transcript records no passing checks")

    checks = transcript.get("checks")
    if not isinstance(checks, list) or not checks:
        reasons.append("transcript carries no ordered check list")
    else:
        if isinstance(totals, dict) and int(totals.get("passed", -1)) != len(
                [c for c in checks if isinstance(c, dict) and c.get("ok") is True]):
            reasons.append("transcript totals disagree with the ordered check list")
        # The completion challenge must re-derive from the recorded chain.
        try:
            outputs = [str(c.get("id", "")) + "=" + str(c.get("ok", "")) for c in checks
                       if isinstance(c, dict)]
            expected = chain_check_results(
                str(transcript.get("matrix_start_challenge", "")), outputs)
        except AttestationError as exc:
            reasons.append(f"check chain cannot be recomputed: {exc}")
            expected = None
        if expected is not None and expected != str(
                transcript.get("matrix_completion_challenge", "")):
            reasons.append("matrix_completion_challenge does not re-derive from the check chain")
    return reasons
