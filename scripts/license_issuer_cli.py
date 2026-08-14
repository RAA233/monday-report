"""Operator-side license issuance CLI (NEVER shipped in the customer package).

Reads the Ed25519 private signing key ONLY from an explicit protected file path
(``--key-file``) or a process-local environment reference (``--key-env NAME``,
where NAME is the name of an environment variable holding the key hex). The
private key is never printed, never logged, never written anywhere except the
operator-chosen keygen output path, and never generated automatically inside a
customer installation.

Commands:
  keygen  --private-out PATH --public-out PATH
  issue   --request FILE --terms FILE (--key-file PATH | --key-env NAME) --out FILE
  inspect --license FILE --public-key PATH
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from backend.app.licensing import license_format as LF  # noqa: E402
from backend.app.licensing.activation import validate_activation_request  # noqa: E402
from backend.app.licensing.canonical import canonical_hash  # noqa: E402
from backend.app.licensing.contract import PRODUCT_NAME  # noqa: E402


def _load_private_key(args: argparse.Namespace) -> Ed25519PrivateKey:
    if getattr(args, "key_file", None):
        key_hex = Path(args.key_file).read_text(encoding="utf-8").strip()
    elif getattr(args, "key_env", None):
        key_hex = os.environ.get(args.key_env, "").strip()
        if not key_hex:
            raise SystemExit(f"environment reference '{args.key_env}' is empty")
    else:
        raise SystemExit("a private key source (--key-file or --key-env) is required")
    try:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex))
    except ValueError as exc:
        raise SystemExit("private key material is malformed") from exc


def cmd_keygen(args: argparse.Namespace) -> int:
    private_out = Path(args.private_out)
    public_out = Path(args.public_out)
    if private_out.exists() and not args.force:
        raise SystemExit("refusing to overwrite an existing private key (use --force)")
    key = Ed25519PrivateKey.generate()
    private_out.parent.mkdir(parents=True, exist_ok=True)
    private_out.write_text(key.private_bytes_raw().hex(), encoding="utf-8")
    try:  # restrict to the operator account where the platform supports it
        os.chmod(private_out, 0o600)
    except OSError:
        pass
    public_out.parent.mkdir(parents=True, exist_ok=True)
    public_out.write_text(key.public_key().public_bytes_raw().hex(), encoding="utf-8")
    print(json.dumps({
        "written": {"private_key": str(private_out), "public_key": str(public_out)},
        "note": "embed ONLY the public key in the application package",
    }, indent=2))
    return 0


def cmd_issue(args: argparse.Namespace) -> int:
    request = validate_activation_request(
        json.loads(Path(args.request).read_text(encoding="utf-8"))
    )
    terms = json.loads(Path(args.terms).read_text(encoding="utf-8"))
    private_key = _load_private_key(args)

    issued_at = datetime.now(timezone.utc)
    validity_days = int(terms.get("validity_days", 365))
    grace_days = int(terms.get("grace_days", 14))
    expires_at = issued_at + timedelta(days=validity_days)
    payload = {
        "schema_version": LF.LICENSE_SCHEMA_VERSION,
        "product": PRODUCT_NAME,
        "license_id": str(uuid.uuid4()),
        "customer_ref": str(terms.get("customer_ref", "unspecified")),
        "edition": str(terms.get("edition", request["requested_edition"])),
        "issued_at": issued_at.isoformat(),
        "not_before": str(terms.get("not_before", issued_at.isoformat())),
        "expires_at": expires_at.isoformat(),
        "grace_until": (expires_at + timedelta(days=grace_days)).isoformat(),
        "machine_binding": request["machine_binding"],
        "machine_fingerprint_hash": canonical_hash(request["machine_binding"]),
        "allowed_product_versions": list(terms.get("allowed_product_versions", ["1.x"])),
        "feature_flags": dict(terms.get("feature_flags", {})),
        "installation_limit": int(terms.get("installation_limit", 1)),
        "installation_id": request["installation_id"],
        "issuer_id": str(terms.get("issuer_id", "monday-report-licensing")),
        "issue_sequence": int(terms.get("issue_sequence", 1)),
        "nonce": secrets.token_hex(16),
        "signature_algorithm": LF.SIGNATURE_ALGORITHM,
    }
    issued = LF.issue_license(payload, private_key)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(issued.document, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "written": str(out),
        "license_id": issued.document["license_id"],
        "expires_at": issued.document["expires_at"],
        "issue_sequence": issued.document["issue_sequence"],
        "canonical_payload_hash": issued.canonical_payload_hash,
    }, indent=2))
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    public_key = bytes.fromhex(Path(args.public_key).read_text(encoding="utf-8").strip())
    document = json.loads(Path(args.license).read_text(encoding="utf-8"))
    LF.validate_document(document, public_key)
    print(json.dumps({
        "valid_structure_and_signature": True,
        "license_id": document["license_id"],
        "edition": document["edition"],
        "expires_at": document["expires_at"],
        "issue_sequence": document["issue_sequence"],
    }, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="license_issuer_cli")
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen")
    keygen.add_argument("--private-out", required=True)
    keygen.add_argument("--public-out", required=True)
    keygen.add_argument("--force", action="store_true")
    keygen.set_defaults(fn=cmd_keygen)

    issue = sub.add_parser("issue")
    issue.add_argument("--request", required=True)
    issue.add_argument("--terms", required=True)
    issue.add_argument("--key-file")
    issue.add_argument("--key-env")
    issue.add_argument("--out", required=True)
    issue.set_defaults(fn=cmd_issue)

    inspect = sub.add_parser("inspect")
    inspect.add_argument("--license", required=True)
    inspect.add_argument("--public-key", required=True)
    inspect.set_defaults(fn=cmd_inspect)

    args = parser.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
