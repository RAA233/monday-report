"""Licence-issuance rendezvous between the reviewer and the author.

WHY THIS EXISTS
---------------
The reviewer must EXECUTE the environment matrices, and the reviewer must NOT
hold the licence-issuer private key. Those two requirements collide in the
existing orchestration: ``offline_two_environment_matrix`` requires the operator
key and forwards it to ``offline_hyperv_matrix``, which signs in-process. Handing
the reviewer that orchestrator hands it the issuer key and collapses the very
separation the reviewer exists to create.

So signing moves out of the reviewer's process entirely. The reviewer writes an
activation request into a drop directory it may write and the author may only
read, then blocks. The author -- in its own context, outside every tested
environment -- privacy-validates the request, signs a licence, and writes it into
a second drop directory the author may write and the reviewer may only read.

The reviewer therefore OBSERVES that signing happened elsewhere: it never holds
the key, and the licence it imports arrived from a directory it cannot write.

ANTI-REPLAY
-----------
Each rendezvous also produces an ``offline-review-issuance-witness.v1``: the
author's signed statement, made with the ISSUER key, that it saw this exact
activation request in response to a nonce the REVIEWER minted. The reviewer
cannot mint it (no issuer key) and the author cannot pre-date it (the nonce did
not exist yet). This is the anti-replay anchor; the transcript's completion
challenge is not one, because every input to that is a deterministic function of
files already on disk.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

XCHG_ROOT = Path(os.environ.get("MONDAY_REPORT_OFFLINE_XCHG", r"C:\mr-hv\xchg"))
REQUEST_DIR = XCHG_ROOT / "requests"
LICENCE_DIR = XCHG_ROOT / "licences"

#: Set in the reviewer's environment. Its presence means "you may not sign; ask".
BROKER_FLAG = "MONDAY_REPORT_OFFLINE_ISSUER_BROKER"

DEFAULT_TIMEOUT_SECONDS = 900
POLL_SECONDS = 1.0


def brokered() -> bool:
    return os.environ.get(BROKER_FLAG, "") == "1"


def request_bundle(*, request: Path, transfer_in: Path, sequence: int, nonce: str,
                   label: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> dict:
    """REVIEWER SIDE. Publish an activation request and block for the licence set.

    Never signs, never holds a key, and accepts licences only from the
    author-owned drop directory it cannot write.
    """

    REQUEST_DIR.mkdir(parents=True, exist_ok=True)
    ticket = f"{label}-seq{sequence}"
    payload = json.loads(request.read_text(encoding="utf-8"))
    envelope = {
        "schema_version": "offline-issuance-ticket.v1",
        "ticket": ticket,
        "sequence": sequence,
        "review_nonce": nonce,
        "environment_label": label,
        "activation_request": payload,
    }
    (REQUEST_DIR / f"{ticket}.json").write_text(
        json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8")

    answer_dir = LICENCE_DIR / ticket
    witness_path = LICENCE_DIR / f"{ticket}.witness.json"
    done = answer_dir / ".complete"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if done.exists() and witness_path.exists():
            break
        refused = LICENCE_DIR / f"{ticket}.refused.json"
        if refused.exists():
            raise ValueError(f"the author refused to issue for {ticket}: "
                             f"{refused.read_text(encoding='utf-8')[:200]}")
        time.sleep(POLL_SECONDS)
    else:
        raise TimeoutError(f"the author did not issue licences for {ticket} in time")

    witness = json.loads(witness_path.read_text(encoding="utf-8"))
    if str(witness.get("review_nonce", "")) != nonce:
        raise ValueError("the issuance witness answers a different review nonce")
    if str(witness.get("activation_request_hash", "")) != _canonical_request_hash(payload):
        raise ValueError("the issuance witness binds a different activation request")

    transfer_in.mkdir(parents=True, exist_ok=True)
    copied = []
    for licence in sorted(answer_dir.glob("license-*.json")):
        (transfer_in / licence.name).write_bytes(licence.read_bytes())
        copied.append(licence.name)
    return {"ticket": ticket, "licences": copied, "witness": witness}


def _canonical_request_hash(request: dict) -> str:
    from backend.app.licensing.canonical import canonical_hash
    return canonical_hash(request)


def serve_once(*, key_file: Path, expiry_seconds: int) -> list[str]:
    """AUTHOR SIDE. Answer every pending ticket exactly once.

    Runs in the author's own context, outside both tested environments -- the
    property the reviewer records. Delegates to the existing audited bundle
    builder rather than reimplementing issuance, so the licences the reviewer
    imports are produced by exactly the same code path as before.
    """

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from backend.app.offline_review_attestation import (
        WITNESS_SCHEMA, witness_signing_payload)
    sys.path.insert(0, str(ROOT / "scripts"))
    from offline_package_matrix import build_license_bundle  # type: ignore
    from offline_operator_issue import assess_request_privacy  # type: ignore

    LICENCE_DIR.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(key_file.read_text(encoding="utf-8").strip()))

    answered: list[str] = []
    for ticket_path in sorted(REQUEST_DIR.glob("*.json")):
        ticket = ticket_path.stem
        answer_dir = LICENCE_DIR / ticket
        if (answer_dir / ".complete").exists():
            continue
        envelope = json.loads(ticket_path.read_text(encoding="utf-8"))
        request = envelope["activation_request"]

        # Privacy is validated BEFORE anything is signed: the author must never
        # bless a request carrying raw machine identifiers.
        problems = assess_request_privacy(request)
        if problems:
            (LICENCE_DIR / f"{ticket}.refused.json").write_text(
                json.dumps({"refused": problems}, indent=2), encoding="utf-8")
            continue

        answer_dir.mkdir(parents=True, exist_ok=True)
        staged = answer_dir / "request.json"
        staged.write_text(json.dumps(request, indent=2, sort_keys=True), encoding="utf-8")
        results = build_license_bundle(request_path=staged, transfer_in=answer_dir,
                                       key_file=key_file, expiry_seconds=expiry_seconds)
        if not all(results.values()):
            (LICENCE_DIR / f"{ticket}.refused.json").write_text(
                json.dumps({"refused": "bundle incomplete", "results": results}, indent=2),
                encoding="utf-8")
            continue

        witness = {
            "schema_version": WITNESS_SCHEMA,
            "review_nonce": str(envelope.get("review_nonce", "")),
            "activation_request_hash": _canonical_request_hash(request),
            "issued_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
            "expiry_seconds": int(expiry_seconds),
        }
        witness["signature"] = private.sign(witness_signing_payload(witness)).hex()
        (LICENCE_DIR / f"{ticket}.witness.json").write_text(
            json.dumps(witness, indent=2, sort_keys=True), encoding="utf-8")
        (answer_dir / ".complete").write_text("ok", encoding="utf-8")
        answered.append(ticket)
    return answered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="offline issuance broker (author side)")
    parser.add_argument("--key-file", required=True,
                        help="operator private key -- AUTHOR SIDE ONLY, never the reviewer's")
    parser.add_argument("--expiry-seconds", type=int, default=240)
    parser.add_argument("--serve-seconds", type=int, default=0,
                        help="keep answering for this long; 0 answers once and exits")
    args = parser.parse_args(argv)

    if brokered():
        print(json.dumps({"refused": "BROKER_FLAG_SET_IN_ISSUER_CONTEXT",
                          "detail": "the issuer must not run in the reviewer's environment"}))
        return 3

    key_file = Path(args.key_file)
    if not key_file.is_file():
        print(json.dumps({"error": "operator key file not found"}))
        return 2

    deadline = time.monotonic() + max(0, args.serve_seconds)
    answered: list[str] = []
    while True:
        answered.extend(serve_once(key_file=key_file, expiry_seconds=args.expiry_seconds))
        if time.monotonic() >= deadline:
            break
        time.sleep(POLL_SECONDS)
    print(json.dumps({"guard": "offline-issuance-broker", "answered": answered}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
