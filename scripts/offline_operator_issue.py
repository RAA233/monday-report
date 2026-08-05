"""offline-license issue-test-license -- the OPERATOR-SIDE half of the
air-gapped activation protocol.

This is the ONLY component that ever touches private signing material. It runs
on the operator host, OUTSIDE every tested environment (outside Windows Sandbox
and outside any installed application directory). It reads an activation
request that an environment exported, validates its schema and privacy posture,
signs a license with a key read from an explicit protected source, and writes
ONLY the signed license back to the transfer directory.

It never writes, echoes, or copies private key material anywhere, and it never
searches for keys: the key source must be named explicitly.
"""
from __future__ import annotations

import argparse
import json
import re
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

#: Shapes that must never appear in an activation request reaching the operator.
_RAW_IDENTIFIER_PATTERNS = (
    re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),      # MAC address
    re.compile(r"[A-Za-z]:\\\\?Users\\\\?[A-Za-z0-9_.-]+"),           # private path
    re.compile(r"(?i)\"(?:mac|hostname|username|serial|volume)\"\s*:"),
)


class OperatorRefusal(Exception):
    """The operator refuses to sign this request."""


def assess_request_privacy(document: dict) -> list[str]:
    """Return every reason the request is not safe to sign (empty = clean)."""

    problems: list[str] = []
    text = json.dumps(document)
    for pattern in _RAW_IDENTIFIER_PATTERNS:
        if pattern.search(text):
            problems.append("activation request carries a raw-identifier shape")
            break
    binding = document.get("machine_binding", {})
    for name, value in dict(binding.get("component_hashes", {})).items():
        if not re.fullmatch(r"[0-9a-f]{64}", str(value)):
            problems.append(f"component '{name}' is not a SHA-256 digest")
    return problems


def load_private_key(*, key_file: str | None, key_env: str | None) -> Ed25519PrivateKey:
    """Read the signing key from an EXPLICIT protected source only. No search,
    no defaults, no directory scanning."""

    import os

    if key_file and key_env:
        raise OperatorRefusal("specify exactly one of --key-file / --key-env")
    if key_file:
        material = Path(key_file).read_text(encoding="utf-8").strip()
    elif key_env:
        material = os.environ.get(key_env, "").strip()
        if not material:
            raise OperatorRefusal(f"environment reference '{key_env}' is empty")
    else:
        raise OperatorRefusal("a private key source (--key-file or --key-env) is required")
    try:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(material))
    except ValueError as exc:
        raise OperatorRefusal("private key material is malformed") from exc


def issue_for_request(
    request: dict,
    private_key: Ed25519PrivateKey,
    *,
    validity_days: int = 365,
    grace_days: int = 14,
    issue_sequence: int = 1,
    edition: str | None = None,
    allowed_product_versions: list[str] | None = None,
    not_before: str | None = None,
    expires_at_override: str | None = None,
    now: datetime | None = None,
) -> dict:
    """Build and sign a license bound to the requesting environment."""

    issued_at = now or datetime.now(timezone.utc)
    expires = (
        datetime.fromisoformat(expires_at_override)
        if expires_at_override
        else issued_at + timedelta(days=validity_days)
    )
    binding = request["machine_binding"]
    payload = {
        "schema_version": LF.LICENSE_SCHEMA_VERSION,
        "product": PRODUCT_NAME,
        "license_id": str(uuid.uuid4()),
        "customer_ref": "operator-test-issuance",
        "edition": edition or str(request.get("requested_edition", "offline-standard")),
        "issued_at": issued_at.isoformat(),
        "not_before": not_before or issued_at.isoformat(),
        "expires_at": expires.isoformat(),
        "grace_until": (expires + timedelta(days=grace_days)).isoformat(),
        "machine_binding": binding,
        "machine_fingerprint_hash": canonical_hash(binding),
        "allowed_product_versions": list(allowed_product_versions or ["1.x"]),
        "feature_flags": {"benchmarking": True},
        "installation_limit": 1,
        "installation_id": request["installation_id"],
        "issuer_id": "offline-operator",
        "issue_sequence": int(issue_sequence),
        "nonce": secrets.token_hex(16),
        "signature_algorithm": LF.SIGNATURE_ALGORITHM,
    }
    return LF.issue_license(payload, private_key).document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="offline-license issue-test-license",
        description="Operator-side signing. Runs OUTSIDE every tested environment.",
    )
    parser.add_argument("--request", required=True, help="activation-request file from the environment")
    parser.add_argument("--out", required=True, help="signed license output (transfer directory)")
    parser.add_argument("--key-file", help="explicit protected path holding the private key hex")
    parser.add_argument("--key-env", help="name of an environment variable holding the key hex")
    parser.add_argument("--validity-days", type=int, default=365)
    parser.add_argument("--grace-days", type=int, default=14)
    parser.add_argument("--issue-sequence", type=int, default=1)
    parser.add_argument("--expires-at", help="explicit ISO-8601 expiry (overrides --validity-days)")
    parser.add_argument("--not-before", help="explicit ISO-8601 not-before")
    parser.add_argument("--allowed-versions", default="1.x", help="comma-separated eligibility list")
    args = parser.parse_args(argv)

    try:
        request = json.loads(Path(args.request).read_text(encoding="utf-8"))
        validate_activation_request(request)
        problems = assess_request_privacy(request)
        if problems:
            raise OperatorRefusal("; ".join(problems))
        private_key = load_private_key(key_file=args.key_file, key_env=args.key_env)
        document = issue_for_request(
            request,
            private_key,
            validity_days=args.validity_days,
            grace_days=args.grace_days,
            issue_sequence=args.issue_sequence,
            allowed_product_versions=[v.strip() for v in args.allowed_versions.split(",") if v.strip()],
            not_before=args.not_before,
            expires_at_override=args.expires_at,
        )
    except (OperatorRefusal, LF.LicenseFormatError) as exc:
        print(json.dumps({"issued": False, "refused": str(exc)}, indent=2))
        return 1

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
    # Only non-secret facts are reported. The private key is never echoed.
    print(json.dumps({
        "issued": True,
        "wrote": out.name,
        "license_id": document["license_id"],
        "issue_sequence": document["issue_sequence"],
        "expires_at": document["expires_at"],
        "bound_installation": "opaque",
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
