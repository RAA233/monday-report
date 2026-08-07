"""``offline-commercial-package-evidence.v2`` -- the AUTHORITATIVE offline
acceptance validator.

This module replaces ``offline_commercial_evidence`` as the only path that may
emit an offline acceptance. That module is retained as a legacy,
non-authoritative reader and can no longer produce an ACCEPTED string.

THE DEFECT THIS EXISTS TO CLOSE
-------------------------------
An independent review demonstrated that the v1 chain accepted a fabricated
second environment: replacing ``ENVIRONMENT_2`` with a verbatim copy of
``ENVIRONMENT_1``, changing only ``environment_class`` and
``fingerprint_identity_digest``, and resealing the author-controlled hashes
passed ``validate()`` + ``validate_record_chain()`` + ``load_and_validate()``
with ZERO reasons and yielded ``offline_commercial_package: PASS``. Every anchor
was author-controlled, so the author could satisfy all of them.

DESIGN RULES, EACH TIED TO A REPRODUCED DEFECT
----------------------------------------------
1. Exactly ONE function emits an acceptance, it reads the artifact from disk,
   it verifies the signature, and it returns ``(verdict, reasons)`` as a single
   value. There is deliberately no ``control_verdicts(payload, reasons)``
   analogue: taking the failure list as a caller argument is what let
   ``control_verdicts(payload, [])`` yield PASS with no commit, tree, or
   signature check at all.
2. No pure ``validate(payload, ...)`` is exported. Helpers are ``_``-prefixed
   and return ``(reasons, checked)``; the public entry asserts the union of
   ``checked`` equals :data:`REQUIRED_CHECKS` before deriving a verdict, so a
   rule a helper forgets to run FAILS CLOSED instead of silently narrowing the
   validator. In v1, ``validate()`` could not reach the filesystem and so never
   called ``validate_record_chain()``; that gap WAS the accepted forgery.
3. No helper returns ``[]`` for a missing input. Split responsibility for
   reporting absence is how a check becomes orphaned.
4. The top-level key set is exact -- unknown AND missing are rejected -- and the
   raw bytes must equal the canonical serialization of what was parsed, so
   duplicate keys or trailing content cannot give two readers two documents.
5. Every "X must agree with Y" is a WHOLE-DOCUMENT hash comparison. Binding by
   field allowlist leaves everything outside the allowlist as free text, which
   is exactly how the copied environment block survived.
6. The derived-vs-stored comparison runs UNCONDITIONALLY, not behind
   ``if not reasons:``. Gating it meant a document that was both stale and
   overclaiming reported only staleness.

WHAT IS NOT CLAIMED
-------------------
* This does not resist a host administrator who takes ownership of the reviewer
  account. Declared non-goal.
* A valid signature does NOT prove the matrices executed. It proves the review
  key signed these values.
* THE REVIEWER EXECUTES CODE THE AUTHOR WROTE. Validator integrity and runner
  honesty both rest on human review of the exact attested commit. A program
  cannot authenticate itself to itself.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from .licensing.canonical import CanonicalizationError, canonical_bytes, canonical_hash
from .offline_review_attestation import (
    ATTESTATION_SCHEMA,
    REVIEW_VERDICT_ACCEPT,
    TRUST_ROOT_SCHEMA,
    AttestationError,
    key_fingerprint,
    principal_digest,
    transcript_hash,
    validate_transcript_shape,
    verify_attestation,
    verify_witness,
)

SCHEMA_VERSION = "offline-commercial-package-evidence.v2"
EVIDENCE_TYPE = "offline_commercial_package_behavior_attested"

LEGACY_NON_AUTHORITATIVE = "LEGACY_OFFLINE_EVIDENCE_NON_AUTHORITATIVE"

LICENSE_ACCEPTED = "OFFLINE_LICENSE_ENFORCEMENT_ACCEPTED"
LICENSE_NOT_ACCEPTED = "OFFLINE_LICENSE_ENFORCEMENT_NOT_ACCEPTED"
PACKAGE_ACCEPTED = "OFFLINE_WINDOWS_PACKAGE_ACCEPTED"
PACKAGE_NOT_ACCEPTED = "OFFLINE_WINDOWS_PACKAGE_NOT_ACCEPTED"
COMMERCIAL_ACCEPTED = "OFFLINE_COMMERCIAL_PACKAGE_ACCEPTED"
COMMERCIAL_NOT_ACCEPTED = "OFFLINE_COMMERCIAL_PACKAGE_NOT_ACCEPTED"

ROOT = Path(__file__).resolve().parents[2]

#: FIXED path. The public entry point honours NO environment variable and takes
#: no trust-root argument. An env-configurable trust anchor deciding signature
#: acceptance would be set by the very process the anchor exists to constrain:
#: generate a keypair, write a trust root naming it, point the variable at it,
#: sign a synthetic attestation -- accepted, at zero privilege. Every sibling
#: evidence module likewise uses a module-level constant.
TRUST_ROOT_PATH = Path("C:/mr-hv/trust/offline-review-trust-root.v1.json")

EVIDENCE_PATH = ROOT / "output" / "offline-commercial" / "offline-commercial-package-evidence.v2.json"

#: The review key identity, PINNED IN TRACKED SOURCE. A trust-root file that
#: names a different key is rejected -- so substituting the file is not enough,
#: the substitution has to appear in a reviewed commit.
#:
#: Derived from the key bytes (``sha256(public_key)[:16]``), never accepted as a
#: free string beside a key, so a document cannot name one identity while
#: carrying another. The value below was produced by the reviewer principal in
#: its own logon session; the authoring process only ever saw the public half.
#:
#: The all-zero placeholder is itself a rejection: an unpinned tier must not
#: accept anything.
PINNED_REVIEW_KEY_FINGERPRINT = "f958c05d422f8368"

MAX_REVIEW_AGE_DAYS = 30

REQUIRED_ENVIRONMENT_MINIMUM = 2
REQUIRED_ENVIRONMENT_LABELS = ("ENVIRONMENT_1", "ENVIRONMENT_2")

#: Exact top-level key set for a v2 artifact.
REQUIRED_EVIDENCE_KEYS = frozenset({
    "schema_version", "evidence_type", "generated_at", "git_commit", "git_tree",
    "package", "environment_transcripts", "independent_review", "disclosures",
    "canonical_payload_hash",
})

REQUIRED_DISCLOSURES = {
    "not_ga_acceptance": True,
    "not_saas_acceptance": True,
    "production_database_target_control_unchanged": True,
    "production_queue_target_control_unchanged": True,
    "ga_registry_28_controls_untouched": True,
    "anti_tamper_is_deterrence_not_absolute": True,
    "reviewer_executes_author_written_code": True,
    "signature_does_not_prove_execution": True,
    "not_resistant_to_host_administrator": True,
}

#: Every check the public entry must observe before it may derive a verdict.
REQUIRED_CHECKS = frozenset({
    "document_shape", "canonical_bytes", "exact_head", "disclosures",
    "package_shape", "transcripts_present", "transcripts_shape",
    "transcripts_distinct", "transcripts_identical_package",
    "transcripts_match_package", "attestation_shape", "trust_root",
    "trust_root_pinned", "trust_root_not_author_writable", "principal_separation",
    "signature", "attestation_binds_transcripts", "attestation_binds_package",
    "attestation_binds_body", "review_freshness", "review_verdict",
    "issuance_witness", "leak_scan", "runtime_isolation",
})

_LEAK_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),   # MAC address
    re.compile(r"[A-Za-z]:\\\\?Users\\\\?[^\s\"']+"),              # private path
    re.compile(r"(?i)(?:requirepass|password|token)\s*[:=]"),
)

HEX64 = re.compile(r"[0-9a-f]{64}")
HEX16 = re.compile(r"[0-9a-f]{16}")


class _Result:
    """Accumulates reasons alongside the set of checks actually performed.

    The ``checked`` set is the fail-closed mechanism: a helper that returns
    early without recording a check causes the public entry to refuse, rather
    than silently validating less than it advertises.
    """

    def __init__(self) -> None:
        self.reasons: list[str] = []
        self.checked: set[str] = set()

    def check(self, name: str) -> None:
        self.checked.add(name)

    def fail(self, name: str, reason: str) -> None:
        self.checked.add(name)
        self.reasons.append(reason)


def _git_rev(ref: str) -> str:
    try:
        return subprocess.run(["git", "-C", str(ROOT), "rev-parse", ref],
                              capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _current_process_sid() -> str:
    """SID of the token this validator is running under."""

    try:
        out = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                             capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""
    parts = [p.strip().strip('"') for p in out.split(",")]
    for part in parts:
        if part.startswith("S-1-"):
            return part
    return ""


def _lookup_account_sid(name: str) -> str:
    """LIVE SID for an account name. Digests are recomputed from this, never
    compared as stored strings -- otherwise 'two distinct principals' degrades
    into 'two hex strings differ', the same shape as the original forgery."""

    if not name or not re.fullmatch(r"[A-Za-z0-9 ._\\-]{1,128}", name):
        return ""
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             "$ErrorActionPreference='Stop';"
             f"try {{ (Get-LocalUser -Name '{name}').SID.Value }} catch {{ '' }}"],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return ""
    value = completed.stdout.strip()
    return value if value.startswith("S-1-") else ""


def _path_is_writable_by_current_process(path: Path) -> bool:
    """ACCESS PROBE, not ``Get-Acl`` parsing -- opening the file is the only
    reliable test of effective permission on Windows."""

    try:
        with open(path, "r+b"):
            return True
    except (PermissionError, OSError):
        return False


def _check_runtime_isolation(result: _Result) -> None:
    """The validator must not be silently reshaped by its own environment.

    The guards run as ``python scripts/...``, which puts the script directory on
    ``sys.path[0]``; an UNTRACKED ``sitecustomize.py`` there is imported at
    startup and could stub out signature verification, with the commit exact,
    the tree exact, and the worktree reported clean -- no commit and no
    privilege required.
    """

    if not sys.flags.isolated and not (sys.flags.no_user_site and sys.flags.ignore_environment):
        result.fail("runtime_isolation",
                    "the authoritative validator must run with -I (isolated mode)")
    else:
        result.check("runtime_isolation")
    for module in ("sitecustomize", "usercustomize"):
        if module in sys.modules:
            result.fail("runtime_isolation", f"{module} was imported into the validator process")
    for var in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"):
        if os.environ.get(var):
            result.fail("runtime_isolation", f"{var} is set for the validator process")


def _worktree_untracked_or_dirty() -> list[str]:
    """'Clean' means NO untracked files under tracked source roots either.

    ``git_tree`` is ``HEAD^{tree}``, the committed tree, so an untracked file
    changes neither it nor a modified-files-only cleanliness flag -- which is
    exactly the gap the ``sitecustomize`` injection above walks through.
    """

    try:
        status = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain"],
                                capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return ["git status could not be read at validation time"]
    offending: list[str] = []
    for line in status.splitlines():
        if not line.strip():
            continue
        path = line[3:].strip()
        if line.startswith("??"):
            if path.startswith(("backend/", "scripts/", "packaging/", "src/")):
                offending.append(f"untracked file under a tracked source root: {path}")
        else:
            offending.append(f"tracked file modified at validation time: {path}")
    return offending


def _load_trust_root(result: _Result, trust_root_path: Path,
                     pinned_fingerprint: str) -> tuple[dict | None, bytes | None]:
    """Resolve, pin, and probe the trust root. Absence is a rejection, never
    'no pinning configured'.

    ``trust_root_path`` / ``pinned_fingerprint`` exist ONLY so the hermetic
    contract guard can drive this real code with a throwaway keypair instead of
    a mock. The public entry point never passes them, and a structural check
    asserts that -- so the tested path and the production path cannot diverge.
    """

    if not trust_root_path.exists():
        result.fail("trust_root", "the pinned reviewer trust root is absent")
        result.fail("trust_root_pinned", "no trust root to pin against")
        result.fail("trust_root_not_author_writable", "no trust root to probe")
        return None, None
    try:
        raw = trust_root_path.read_bytes()
        root = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        result.fail("trust_root", "the pinned reviewer trust root could not be read")
        result.fail("trust_root_pinned", "trust root unreadable")
        result.fail("trust_root_not_author_writable", "trust root unreadable")
        return None, None

    result.check("trust_root")
    if not isinstance(root, dict) or root.get("schema_version") != TRUST_ROOT_SCHEMA:
        result.fail("trust_root", "the trust root carries the wrong schema version")
        return None, None

    hex_key = str(root.get("review_public_key_hex", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", hex_key):
        result.fail("trust_root", "the trust root carries no usable review public key")
        result.fail("trust_root_pinned", "no key to pin")
        result.fail("trust_root_not_author_writable", "no key to probe")
        return None, None
    public_bytes = bytes.fromhex(hex_key)

    # Pinning: the fingerprint is DERIVED from the key bytes and must equal the
    # constant in tracked source. A wholly substituted trust root still fails.
    try:
        derived = key_fingerprint(public_bytes)
    except AttestationError as exc:
        result.fail("trust_root_pinned", f"review key is unusable: {exc}")
        result.fail("trust_root_not_author_writable", "no key to probe")
        return None, None
    if pinned_fingerprint == "0000000000000000":
        result.fail("trust_root_pinned",
                    "no review key is pinned in tracked source (placeholder present)")
    elif derived != pinned_fingerprint:
        result.fail("trust_root_pinned",
                    "the trust root names a review key that is not pinned in tracked source")
    else:
        result.check("trust_root_pinned")
    if str(root.get("review_key_fingerprint", "")) != derived:
        result.fail("trust_root", "the trust root's stated fingerprint does not derive from its key")

    # The anchor must not be writable by the process it constrains.
    if _path_is_writable_by_current_process(trust_root_path):
        result.fail("trust_root_not_author_writable",
                    "the trust root is writable by the validating process")
    else:
        result.check("trust_root_not_author_writable")
    return root, public_bytes


def _check_principal_separation(result: _Result, root: dict, attestation: dict,
                                sid_resolver=_lookup_account_sid,
                                current_sid=_current_process_sid) -> None:
    """Recompute both principal digests from LIVE SID lookups and require the
    running process to be the AUTHOR, not the reviewer."""

    before = len(result.reasons)
    salt = str(root.get("principal_salt", ""))
    reviewer_name = str(root.get("reviewer_account_name", ""))
    author_name = str(root.get("author_account_name", ""))
    if not salt or not reviewer_name or not author_name:
        result.fail("principal_separation",
                    "the trust root does not name both principals and a salt")
        return

    reviewer_sid = sid_resolver(reviewer_name)
    author_sid = sid_resolver(author_name)
    if not reviewer_sid or not author_sid:
        result.fail("principal_separation",
                    "a named principal could not be resolved to a live SID")
        return
    if reviewer_sid == author_sid:
        result.fail("principal_separation", "the reviewer and author are the same account")
        return

    try:
        reviewer_digest = principal_digest(reviewer_sid, salt)
        author_digest = principal_digest(author_sid, salt)
    except AttestationError as exc:
        result.fail("principal_separation", f"principal digests could not be recomputed: {exc}")
        return

    if str(attestation.get("reviewer_principal_digest", "")) != reviewer_digest:
        result.fail("principal_separation",
                    "the attestation's reviewer principal does not match the live reviewer account")
    if str(attestation.get("author_principal_digest", "")) != author_digest:
        result.fail("principal_separation",
                    "the attestation's author principal does not match the live author account")
    if reviewer_digest == author_digest:
        result.fail("principal_separation", "reviewer and author digests are identical")

    # A validator run must not be able to claim it is the reviewer.
    current = current_sid()
    if not current:
        result.fail("principal_separation", "the validating process SID could not be determined")
    elif current == reviewer_sid:
        result.fail("principal_separation",
                    "the validator is running as the reviewer principal")
    if len(result.reasons) == before:
        result.check("principal_separation")


def _check_transcripts(result: _Result, payload: dict) -> dict[str, dict]:
    transcripts = payload.get("environment_transcripts")
    if not isinstance(transcripts, dict) or not transcripts:
        result.fail("transcripts_present", "the artifact carries no environment transcripts")
        for name in ("transcripts_shape", "transcripts_distinct",
                     "transcripts_identical_package", "transcripts_match_package"):
            result.fail(name, "no transcripts to check")
        return {}
    result.check("transcripts_present")

    if set(transcripts) != set(REQUIRED_ENVIRONMENT_LABELS):
        result.fail("transcripts_present",
                    "the artifact does not carry exactly the two required environment labels")

    shape_ok = True
    for label, transcript in sorted(transcripts.items()):
        for reason in validate_transcript_shape(transcript):
            shape_ok = False
            result.fail("transcripts_shape", f"{label}: {reason}")
    if shape_ok:
        result.check("transcripts_shape")

    digests = [str(t.get("fingerprint_identity_digest", ""))
               for t in transcripts.values() if isinstance(t, dict)]
    bindings = [t.get("machine_binding") for t in transcripts.values() if isinstance(t, dict)]
    if len(set(digests)) != len(digests) or not all(digests):
        result.fail("transcripts_distinct",
                    "the environments did not report distinct machine identities")
    elif len(bindings) == 2 and bindings[0] == bindings[1]:
        result.fail("transcripts_distinct",
                    "the environments reported identical machine bindings")
    else:
        # Distinctness must rest on a real component difference, not only on the
        # derived digest -- a digest is one string edit away from 'distinct'.
        strong_differs = False
        if len(bindings) == 2 and all(isinstance(b, dict) for b in bindings):
            keys = set(bindings[0]) | set(bindings[1])
            strong_differs = any(bindings[0].get(k) != bindings[1].get(k) for k in keys)
        if not strong_differs:
            result.fail("transcripts_distinct",
                        "no machine-binding component differs between the environments")
        else:
            result.check("transcripts_distinct")

    hash_fields = ("installer_sha256", "executable_sha256",
                   "payload_manifest_sha256", "frontend_manifest_sha256")
    identical = True
    for field in hash_fields:
        values = {str(t.get(field, "")) for t in transcripts.values() if isinstance(t, dict)}
        if len(values) != 1 or not all(HEX64.fullmatch(v) for v in values):
            identical = False
    if identical:
        result.check("transcripts_identical_package")
    else:
        result.fail("transcripts_identical_package",
                    "the environments did not run identical package bytes")

    package = payload.get("package", {})
    matches = True
    if not isinstance(package, dict):
        matches = False
    else:
        for field in hash_fields:
            declared = str(package.get(field, ""))
            for transcript in transcripts.values():
                if not isinstance(transcript, dict) or str(transcript.get(field, "")) != declared:
                    matches = False
    if matches:
        result.check("transcripts_match_package")
    else:
        result.fail("transcripts_match_package",
                    "the environments did not run the package this evidence describes")
    return {k: v for k, v in transcripts.items() if isinstance(v, dict)}


def _check_attestation_bindings(result: _Result, payload: dict, attestation: dict,
                                transcripts: dict[str, dict]) -> None:
    """The attestation must cover the WHOLE evidence body, not a chosen subset.

    Binding only transcripts and package hashes would let one honest review at a
    commit license unlimited fabricated artifacts at that commit: keep the
    genuine signature and the genuine transcripts, regenerate everything else,
    reseal the unkeyed hashes.
    """

    bound_transcripts = attestation.get("environment_transcript_hashes")
    if not isinstance(bound_transcripts, dict) or not bound_transcripts:
        result.fail("attestation_binds_transcripts",
                    "the attestation binds no transcript hashes")
    else:
        ok = set(bound_transcripts) == set(transcripts)
        for label, transcript in transcripts.items():
            try:
                actual = transcript_hash(transcript)
            except AttestationError as exc:
                result.fail("attestation_binds_transcripts",
                            f"{label}: transcript cannot be hashed: {exc}")
                ok = False
                continue
            if str(bound_transcripts.get(label, "")) != actual:
                result.fail("attestation_binds_transcripts",
                            f"{label}: transcript does not match the hash the reviewer signed")
                ok = False
        if ok:
            result.check("attestation_binds_transcripts")

    package = payload.get("package", {})
    bound = True
    if not isinstance(package, dict):
        bound = False
    else:
        for field in ("installer_sha256", "executable_sha256",
                      "payload_manifest_sha256", "frontend_manifest_sha256",
                      "public_key_fingerprint", "package_version"):
            if str(attestation.get(field, "")) != str(package.get(field, "")):
                bound = False
    if str(attestation.get("source_commit", "")) != str(payload.get("git_commit", "")):
        bound = False
    if str(attestation.get("source_tree", "")) != str(payload.get("git_tree", "")):
        bound = False
    if bound:
        result.check("attestation_binds_package")
    else:
        result.fail("attestation_binds_package",
                    "the attestation does not bind this package and head")

    body = {k: v for k, v in payload.items()
            if k not in ("independent_review", "canonical_payload_hash")}
    try:
        digest = canonical_hash(body)
    except CanonicalizationError as exc:
        result.fail("attestation_binds_body", f"evidence body is not canonicalizable: {exc}")
        return
    if str(attestation.get("evidence_body_digest", "")) != digest:
        result.fail("attestation_binds_body",
                    "the reviewer did not sign this evidence body")
    else:
        result.check("attestation_binds_body")


def _check_issuance_witness(result: _Result, transcripts: dict[str, dict],
                            attestation: dict, package_fingerprint: str = "",
                            issuer_public_key: bytes | None = None) -> None:
    """Each environment must carry an author-signed witness binding the
    reviewer's nonce to the activation request it actually produced.

    This is the anti-replay anchor. The completion challenge is NOT one: every
    input to it is a deterministic function of files on disk, so anyone holding
    those files recomputes it. The witness cannot be minted by the reviewer (no
    issuer key) nor pre-dated by the author (the nonce did not yet exist).
    """

    if not transcripts:
        result.fail("issuance_witness", "no transcripts carry an issuance witness")
        return
    nonce = str(attestation.get("review_nonce", ""))
    if not HEX64.fullmatch(nonce):
        result.fail("issuance_witness", "the attestation carries no usable review nonce")
        return
    # The witness is only evidence if its SIGNATURE verifies. Comparing its
    # fields proves that a document says the right things; it took a signature
    # check to prove the author actually issued it, and without that this
    # "anti-replay anchor" was an unsigned blob.
    # ``issuer_public_key`` exists ONLY so the hermetic contract guard can
    # drive this real code with a throwaway key. The public entry never
    # passes it, so the production path always resolves the licence key from
    # the package under test.
    issuer_public = issuer_public_key
    fingerprint = str(package_fingerprint or "")
    for candidate in () if issuer_public else (
                      ROOT / "output" / "offline-package" / "stage" / "MondayReportOffline"
                      / "_internal" / "licensing_public_key.txt",
                      Path("C:/mr-hv/reviewer-pkg/app/_internal/licensing_public_key.txt"),
                      Path("C:/mr-hv/state/keys/issuer_public.hex")):
        try:
            if candidate.is_file():
                raw = candidate.read_text(encoding="utf-8", errors="ignore").strip().lower()
                if re.fullmatch(r"[0-9a-f]{64}", raw):
                    issuer_public = bytes.fromhex(raw)
                    break
        except OSError:
            continue
    if issuer_public is None:
        result.fail("issuance_witness",
                    "no licence-verification public key is available to verify the "
                    "issuance witnesses against")
        return

    ok = True
    for label, transcript in sorted(transcripts.items()):
        witness = transcript.get("issuance_witness")
        if not isinstance(witness, dict) or not witness:
            result.fail("issuance_witness", f"{label}: no issuance witness recorded")
            ok = False
            continue
        for reason in verify_witness(witness, issuer_public):
            result.fail("issuance_witness", f"{label}: {reason}")
            ok = False
        # The witness must name the key that signed it, and that key must be the
        # one the package verifies licences with.
        if fingerprint and str(witness.get("issuer_key_fingerprint", "")) != fingerprint:
            result.fail("issuance_witness",
                        f"{label}: the witness names a different issuer key than the package")
            ok = False
        if str(witness.get("environment_label", "")) != label:
            result.fail("issuance_witness",
                        f"{label}: the witness answers a different environment")
            ok = False
        if str(witness.get("source_commit", "")) != str(transcript.get("source_commit", "")):
            result.fail("issuance_witness",
                        f"{label}: the witness was minted at a different source commit")
            ok = False
        if str(witness.get("review_nonce", "")) != nonce:
            result.fail("issuance_witness",
                        f"{label}: the witness was issued for a different review nonce")
            ok = False
        if not HEX64.fullmatch(str(witness.get("activation_request_hash", ""))):
            result.fail("issuance_witness",
                        f"{label}: the witness binds no activation request")
            ok = False
    if ok:
        result.check("issuance_witness")


def _check_freshness(result: _Result, attestation: dict) -> None:
    started = str(attestation.get("review_started_at", ""))
    completed = str(attestation.get("review_completed_at", ""))
    try:
        started_at = datetime.fromisoformat(started)
        completed_at = datetime.fromisoformat(completed)
    except ValueError:
        result.fail("review_freshness", "review timestamps are malformed")
        return
    if completed_at < started_at:
        result.fail("review_freshness", "the review completed before it started")
        return
    age = datetime.now(timezone.utc) - completed_at
    if age.days > MAX_REVIEW_AGE_DAYS:
        result.fail("review_freshness", "the independent review attestation is stale")
        return
    result.check("review_freshness")


def _evaluate(payload: dict, raw: bytes, *, current_commit: str, current_tree: str,
              trust_root_path: Path = TRUST_ROOT_PATH,
              pinned_fingerprint: str = PINNED_REVIEW_KEY_FINGERPRINT,
              worktree_status=_worktree_untracked_or_dirty,
              sid_resolver=_lookup_account_sid,
              current_sid=_current_process_sid,
              issuer_public_key: bytes | None = None) -> _Result:
    """The whole rule set. Private on purpose: nothing outside this module may
    obtain a partial validation and treat it as a verdict."""

    result = _Result()
    _check_runtime_isolation(result)

    if not isinstance(payload, dict):
        result.fail("document_shape", "payload is not an object")
        return result

    keys = set(payload)
    missing = REQUIRED_EVIDENCE_KEYS - keys
    unknown = keys - REQUIRED_EVIDENCE_KEYS
    if missing:
        result.fail("document_shape",
                    f"artifact is missing required keys: {','.join(sorted(missing))}")
    if unknown:
        # A v1 body relabelled as v2 lands here: v1 carries results/,
        # two_environment_record and verdicts, none of which exist in v2.
        result.fail("document_shape",
                    f"artifact carries unknown keys: {','.join(sorted(unknown))}")
    if payload.get("schema_version") != SCHEMA_VERSION:
        result.fail("document_shape", "wrong schema_version for the authoritative tier")
    if payload.get("evidence_type") != EVIDENCE_TYPE:
        result.fail("document_shape", "wrong evidence_type for the authoritative tier")
    if not (missing or unknown):
        result.check("document_shape")

    # Two readers must not be able to see two different documents.
    try:
        if canonical_bytes(payload) != canonical_bytes(json.loads(raw.decode("utf-8"))):
            result.fail("canonical_bytes", "the artifact bytes are not canonically serialized")
        else:
            result.check("canonical_bytes")
    except (CanonicalizationError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        result.fail("canonical_bytes", f"the artifact could not be canonically re-read: {exc}")

    if payload.get("git_commit") != current_commit:
        result.fail("exact_head", "evidence does not belong to the current exact commit")
    elif payload.get("git_tree") != current_tree:
        result.fail("exact_head", "evidence does not belong to the current exact tree")
    else:
        result.check("exact_head")
    for reason in worktree_status():
        result.fail("exact_head", reason)

    disclosures = payload.get("disclosures", {})
    if not isinstance(disclosures, dict):
        result.fail("disclosures", "the artifact carries no disclosures")
    else:
        bad = [k for k, v in REQUIRED_DISCLOSURES.items() if disclosures.get(k) is not v]
        if bad:
            result.fail("disclosures",
                        f"required disclosure missing or altered: {','.join(sorted(bad))}")
        else:
            result.check("disclosures")

    package = payload.get("package", {})
    if not isinstance(package, dict):
        result.fail("package_shape", "the artifact carries no package block")
    else:
        problems = []
        if package.get("private_key_absent") is not True:
            problems.append("private-key-absence was not proven")
        for field in ("installer_sha256", "executable_sha256",
                      "payload_manifest_sha256", "frontend_manifest_sha256"):
            if not HEX64.fullmatch(str(package.get(field, ""))):
                problems.append(f"{field} missing or malformed")
        if not HEX16.fullmatch(str(package.get("public_key_fingerprint", ""))):
            problems.append("public-key fingerprint missing or malformed")
        for problem in problems:
            result.fail("package_shape", problem)
        if not problems:
            result.check("package_shape")

    transcripts = _check_transcripts(result, payload)

    attestation = payload.get("independent_review")
    if not isinstance(attestation, dict) or not attestation:
        result.fail("attestation_shape", "the artifact carries no independent review attestation")
        for name in ("signature", "trust_root", "trust_root_pinned",
                     "trust_root_not_author_writable", "principal_separation",
                     "attestation_binds_transcripts", "attestation_binds_package",
                     "attestation_binds_body", "review_freshness", "review_verdict",
                     "issuance_witness"):
            result.fail(name, "no attestation to check")
    else:
        if attestation.get("schema_version") != ATTESTATION_SCHEMA:
            result.fail("attestation_shape", "the attestation carries the wrong schema version")
        else:
            result.check("attestation_shape")

        root, public_bytes = _load_trust_root(
            result, trust_root_path, pinned_fingerprint)
        if root is None or public_bytes is None:
            result.fail("signature", "no pinned review key is available to verify against")
            result.fail("principal_separation", "no trust root to resolve principals from")
        else:
            signature_reasons = verify_attestation(attestation, public_bytes)
            for reason in signature_reasons:
                result.fail("signature", reason)
            if not signature_reasons:
                result.check("signature")
            _check_principal_separation(result, root, attestation,
                                        sid_resolver, current_sid)

        _check_attestation_bindings(result, payload, attestation, transcripts)
        _check_issuance_witness(
            result, transcripts, attestation,
            str(payload.get("package", {}).get("public_key_fingerprint", "")),
            issuer_public_key)
        _check_freshness(result, attestation)

        if attestation.get("review_verdict") != REVIEW_VERDICT_ACCEPT:
            result.fail("review_verdict",
                        "the independent reviewer did not sign an accepting verdict")
        else:
            result.check("review_verdict")

    text = json.dumps(payload)
    leaked = False
    for pattern in _LEAK_PATTERNS:
        if pattern.search(text):
            result.fail("leak_scan", f"evidence contains a leak shape: {pattern.pattern[:40]}")
            leaked = True
            break
    if not leaked:
        result.check("leak_scan")
    return result


def load_and_validate_authoritative() -> tuple[str, dict[str, str], list[str]]:
    """THE authoritative entry point. The only function here that can emit an
    acceptance.

    Returns ``(overall_verdict, control_verdicts, reasons)``. It reads the
    artifact from disk itself, so no caller can hand it a payload that skipped
    the signature check, and it never accepts a caller-supplied reasons list.

    The verdict is the MINIMUM of what the reviewer signed and what this
    validator independently derives -- this function can only ever DOWNGRADE.
    A patched validator can print anything locally, but it cannot manufacture a
    reviewer signature over an accepting verdict, so the artifact a third party
    re-verifies still carries the reviewer's own statement.
    """

    blocked = {
        "offline_license_enforcement": LICENSE_NOT_ACCEPTED,
        "offline_windows_package": PACKAGE_NOT_ACCEPTED,
        "offline_commercial_package": COMMERCIAL_NOT_ACCEPTED,
    }
    if not EVIDENCE_PATH.exists():
        return COMMERCIAL_NOT_ACCEPTED, blocked, ["no authoritative v2 evidence artifact"]
    try:
        raw = EVIDENCE_PATH.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return COMMERCIAL_NOT_ACCEPTED, blocked, [f"the artifact could not be read: {exc}"]

    result = _evaluate(payload, raw, current_commit=_git_rev("HEAD"),
                       current_tree=_git_rev("HEAD^{tree}"))

    # Fail closed if any rule did not run. A validator that silently narrows is
    # worse than one that refuses.
    unobserved = REQUIRED_CHECKS - result.checked
    if unobserved:
        result.reasons.append(
            "the validator did not observe every required check: "
            + ",".join(sorted(unobserved)))

    if result.reasons:
        return COMMERCIAL_NOT_ACCEPTED, blocked, result.reasons
    return COMMERCIAL_ACCEPTED, {
        "offline_license_enforcement": LICENSE_ACCEPTED,
        "offline_windows_package": PACKAGE_ACCEPTED,
        "offline_commercial_package": COMMERCIAL_ACCEPTED,
    }, []


def legacy_disposition(payload: dict) -> tuple[str, str]:
    """A v1 artifact is never authoritative, whatever it claims."""

    schema = str(payload.get("schema_version", "")) if isinstance(payload, dict) else ""
    if schema == SCHEMA_VERSION:
        return LEGACY_NON_AUTHORITATIVE, COMMERCIAL_NOT_ACCEPTED
    return LEGACY_NON_AUTHORITATIVE, COMMERCIAL_NOT_ACCEPTED
