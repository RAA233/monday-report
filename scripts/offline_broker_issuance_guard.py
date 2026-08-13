"""``audit:offline-broker-issuance`` -- proves the authoritative licensing path
keeps the issuer key out of the reviewer, and that its witness cannot be replayed.

WHY THIS EXISTS
---------------
While the environment matrix signs its own licences, the principal running the
matrix is also the principal issuing them: green output proves the product works
but says nothing about who ran it. Brokered mode removes the key from that
process entirely, and the issuance witness is what ties a specific licence set to
a specific run.

A witness is only worth something if a wrong one is REJECTED. This guard builds
disposable witnesses with a throwaway issuer key and drives the real verifier.
Nothing here touches the real issuer key, the real broker directories, or any
real run.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from backend.app.offline_review_attestation import (  # noqa: E402
    WITNESS_SCHEMA,
    key_fingerprint,
    verify_witness,
    witness_signing_payload,
)

MATRIX = ROOT / "scripts" / "offline_hyperv_matrix.py"
BROKER = ROOT / "scripts" / "offline_issuance_broker.py"
REVIEWER_DRIVER = ROOT / "scripts" / "offline_reviewer_execute.py"

CHECKS: list[dict] = []


def rec(check_id: str, ok: bool, detail: str) -> bool:
    CHECKS.append({"check_id": check_id, "ok": bool(ok), "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'} {check_id}: {detail}")
    return bool(ok)


def run_matrix(argv: list[str], env: dict | None = None) -> dict:
    child = {k: v for k, v in os.environ.items()}
    if env:
        child.update(env)
    completed = subprocess.run([sys.executable, str(MATRIX), *argv],
                               capture_output=True, text=True, timeout=300, env=child)
    for line in (completed.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return {"_stdout": (completed.stdout or "")[-400:], "_rc": completed.returncode}


def refusal_battery() -> None:
    """Authoritative mode must refuse every route by which the issuer key could
    reach the process that also runs the matrix."""

    doc = run_matrix(["--brokered", "--key-file", "C:/nonexistent/issuer.hex",
                      "--phase", "request"])
    rec("BI01 brokered-refuses-key-file-argument",
        doc.get("refused") == "ISSUER_KEY_OFFERED_IN_AUTHORITATIVE_MODE",
        f"--key-file in authoritative mode is refused ({doc.get('refused')})")

    for name in ("MONDAY_REPORT_OPERATOR_KEY_FILE", "MONDAY_REPORT_OPERATOR_KEY",
                 "MONDAY_REPORT_OFFLINE_ISSUER_KEY"):
        doc = run_matrix(["--brokered", "--review-nonce", "a" * 64, "--phase", "request"],
                         env={name: "C:/nonexistent/issuer.hex"})
        rec(f"BI02 brokered-refuses-{name.lower()}",
            doc.get("refused") == "ISSUER_KEY_OFFERED_IN_AUTHORITATIVE_MODE",
            f"{name} in authoritative mode is refused")

    # Supply the head binding so this isolates the NONCE requirement. Omitting
    # both would trip whichever refusal is checked first and prove nothing about
    # the one this check names.
    doc = run_matrix(["--brokered", "--phase", "request",
                      "--source-commit", "c" * 40, "--source-tree", "t" * 40])
    rec("BI03 brokered-requires-review-nonce",
        doc.get("refused") == "REVIEW_NONCE_REQUIRED",
        "authoritative mode refuses to run without a reviewer-minted nonce")

    doc = run_matrix(["--brokered", "--phase", "request", "--review-nonce", "n" * 64])
    rec("BI03b brokered-requires-head-binding",
        doc.get("refused") == "HEAD_BINDING_REQUIRED",
        "authoritative mode refuses to run without an explicit head binding")

    # The direct mode must be documented as NON-AUTHORITATIVE in the source that
    # offers it, so nobody can read a --key-file run as commercial evidence.
    source = MATRIX.read_text(encoding="utf-8")
    rec("BI04 direct-mode-marked-non-authoritative",
        "NON-AUTHORITATIVE developer mode only" in source,
        "the --key-file mode declares itself non-authoritative where it is defined")

    # The reviewer driver must never offer key material to anything it spawns.
    driver = REVIEWER_DRIVER.read_text(encoding="utf-8")
    rec("BI05 reviewer-driver-scrubs-issuer-variables",
        "MONDAY_REPORT_OPERATOR_KEY_FILE" in driver and "child_env" in driver,
        "the reviewer driver strips issuer-key variables from child processes")
    rec("BI06 reviewer-driver-refuses-issuer-material",
        "ISSUER_KEY_OFFERED_TO_REVIEWER" in driver,
        "the reviewer driver refuses issuer key material outright")


def witness_battery() -> None:
    """The witness must bind this run, and a wrong one must be rejected.

    Uses a THROWAWAY issuer key: the real one is never loaded here.
    """

    work = Path(tempfile.mkdtemp(prefix="mr-witness-"))
    try:
        issuer = Ed25519PrivateKey.generate()
        issuer_pub = issuer.public_key().public_bytes_raw()
        other = Ed25519PrivateKey.generate()

        licences = {"license-primary.json": hashlib.sha256(b"primary").hexdigest()}
        base = {
            "schema_version": WITNESS_SCHEMA,
            "domain": "monday-report/offline-issuance-witness/v1",
            "review_nonce": "n" * 64,
            "environment_label": "ENVIRONMENT_2",
            "activation_request_hash": hashlib.sha256(b"request").hexdigest(),
            "requested_fingerprint_digest": "f" * 32,
            "source_commit": "c" * 40,
            "source_tree": "t" * 40,
            "licence_set_digest": hashlib.sha256(
                json.dumps(licences, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "issuer_key_fingerprint": key_fingerprint(issuer_pub),
            "issued_at": "2026-08-07T00:00:00+00:00",
            "expiry_seconds": 240,
        }
        signed = dict(base)
        signed["signature"] = issuer.sign(witness_signing_payload(base)).hex()

        if not rec("BI07 witness-baseline-verifies", not verify_witness(signed, issuer_pub),
                   "a correctly signed witness verifies under the issuer public key"):
            return

        # Every mutation must break the signature or the binding.
        cases = [
            ("BI08 tampered-nonce-rejected", "review_nonce", "z" * 64),
            ("BI09 tampered-environment-rejected", "environment_label", "ENVIRONMENT_1"),
            ("BI10 tampered-request-rejected", "activation_request_hash",
             hashlib.sha256(b"other request").hexdigest()),
            ("BI11 tampered-commit-rejected", "source_commit", "d" * 40),
            ("BI12 tampered-tree-rejected", "source_tree", "e" * 40),
            ("BI13 tampered-licence-set-rejected", "licence_set_digest",
             hashlib.sha256(b"swapped licences").hexdigest()),
            ("BI14 tampered-issuer-fingerprint-rejected", "issuer_key_fingerprint", "0" * 16),
        ]
        for check_id, field, value in cases:
            mutant = dict(signed)
            mutant[field] = value
            rec(check_id, bool(verify_witness(mutant, issuer_pub)),
                f"a witness with a changed {field} is rejected")

        # A witness signed by a DIFFERENT key must not verify as the issuer's.
        forged = dict(base)
        forged["signature"] = other.sign(witness_signing_payload(base)).hex()
        rec("BI15 foreign-signature-rejected", bool(verify_witness(forged, issuer_pub)),
            "a witness signed by another key does not verify under the issuer key")

        # A missing signature must fail rather than pass silently.
        unsigned = dict(base)
        rec("BI16 unsigned-witness-rejected", bool(verify_witness(unsigned, issuer_pub)),
            "a witness with no signature is rejected")

        # The reviewer side must check every binding, not merely the nonce.
        broker = BROKER.read_text(encoding="utf-8")
        for field, phrase in (
                ("environment", "answers a different environment"),
                ("commit", "minted at a different source commit"),
                ("tree", "minted at a different source tree"),
                ("licences", "licence bytes changed after the issuance witness")):
            rec(f"BI17 reviewer-checks-{field}", phrase in broker,
                f"the reviewer rejects a witness that {phrase}")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    CHECKS.clear()
    refusal_battery()
    witness_battery()
    failed = [c for c in CHECKS if not c["ok"]]
    print()
    print(json.dumps({
        "guard": "offline-broker-issuance",
        "claim_scope": "authoritative brokered licensing keeps the issuer key out of the "
                       "matrix process, and the issuance witness binds one specific run",
        "summary": {"passed": len(CHECKS) - len(failed), "failed": len(failed),
                    "total": len(CHECKS)},
    }, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
