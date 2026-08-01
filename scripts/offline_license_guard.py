"""audit:offline-license -- the Part-N licensing/security fault battery.

Executable, load-bearing, Docker-free. Exercises the signed license format,
machine binding, activation privacy, expiry/grace/read-only, clock and license
rollback, protected-state integrity, renewal monotonicity, the offline update
manifest, and private-key hygiene. Includes SOURCE-MUTATION cycles: for each
injected defect the baseline passes, the defect makes the battery fail for the
intended reason (proving the checks are load-bearing), and the pristine source
passes again. Mutations run against a COPY of the licensing package -- tracked
source is never modified.
"""
from __future__ import annotations

import importlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("MONDAY_REPORT_LICENSING_STATE_MODE", "test")
os.environ.setdefault("MONDAY_REPORT_LICENSING_STATE_TEST_KEY", secrets.token_hex(16))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from backend.app.licensing import activation as ACT  # noqa: E402
from backend.app.licensing import fingerprint as FP  # noqa: E402
from backend.app.licensing import license_format as LF  # noqa: E402
from backend.app.licensing import update_format as UF  # noqa: E402
from backend.app.licensing.canonical import canonical_bytes, canonical_hash, signing_view  # noqa: E402
from backend.app.licensing.contract import LicenseState, ReasonCode  # noqa: E402
from backend.app.licensing.offline_provider import (  # noqa: E402
    LicenseImportError,
    OfflineProviderConfig,
    OfflineSignedLicenseProvider,
)

CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str = "") -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "detail": detail})


FACTS = {
    "machine_guid": "11111111-2222-3333-4444-555555555555",
    "smbios_uuid": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
    "board_serial": "BOARD-0042",
    "system_volume_serial": "1A2B3C4D",
    "physical_adapters": "AABBCCDDEEFF",
}
OTHER_FACTS = {
    "machine_guid": "99999999-8888-7777-6666-555555555550",
    "smbios_uuid": "FFFFFFFF-1111-2222-3333-444444444440",
    "board_serial": "BOARD-9999",
    "system_volume_serial": "9Z8Y7X6W",
    "physical_adapters": "AABBCCDDEEFF",  # SAME MAC -- the collision case
}


def _payload(binding: dict, *, now: datetime, days: int = 365, grace: int = 14,
             sequence: int = 1, installation: str = "inst-guard",
             versions: list[str] | None = None, edition: str = "offline-standard") -> dict:
    return {
        "schema_version": LF.LICENSE_SCHEMA_VERSION,
        "product": "monday-report",
        "license_id": str(uuid.uuid4()),
        "customer_ref": "customer-opaque-token",
        "edition": edition,
        "issued_at": now.isoformat(),
        "not_before": now.isoformat(),
        "expires_at": (now + timedelta(days=days)).isoformat(),
        "grace_until": (now + timedelta(days=days + grace)).isoformat(),
        "machine_binding": binding,
        "machine_fingerprint_hash": canonical_hash(binding),
        "allowed_product_versions": versions or ["1.x"],
        "feature_flags": {"benchmarking": True},
        "installation_limit": 1,
        "installation_id": installation,
        "issuer_id": "guard-issuer",
        "issue_sequence": sequence,
        "nonce": secrets.token_hex(16),
        "signature_algorithm": LF.SIGNATURE_ALGORITHM,
    }


def _provider(tmp: Path, pub: bytes, fingerprint: FP.Fingerprint, *, clock=None,
              installation: str = "inst-guard", tag: str = "a") -> OfflineSignedLicenseProvider:
    return OfflineSignedLicenseProvider(OfflineProviderConfig(
        license_path=tmp / f"license-{tag}.json",
        state_primary_path=tmp / f"state-{tag}-1.bin",
        state_secondary_path=tmp / f"state-{tag}-2.bin",
        public_key=pub,
        installation_id=installation,
        fingerprint_supplier=lambda: fingerprint,
        clock=clock or time.time,
    ))


def format_and_binding_battery(tmp: Path) -> None:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw()
    fp = FP.from_facts(FACTS)
    now = datetime.now(timezone.utc)
    issued = LF.issue_license(_payload(fp.binding_document(), now=now), key)
    raw = json.dumps(issued.document).encode()

    provider = _provider(tmp, pub, fp, tag="fmt")
    decision = provider.import_license(raw)
    rec("LG01 valid-license-accepted",
        decision.state is LicenseState.VALID and not decision.read_only,
        "a correctly signed machine-matching license activates full operation")

    tampered = dict(issued.document)
    tampered["edition"] = "enterprise-unpaid"
    try:
        provider.import_license(json.dumps(tampered).encode())
        rec("LG02 modified-payload-rejected", False, "tampered payload accepted")
    except LicenseImportError as exc:
        rec("LG02 modified-payload-rejected", exc.reason is ReasonCode.SIGNATURE_INVALID,
            "payload tampering breaks the signature")

    resigned = dict(issued.document)
    resigned["signature"] = issued.document["signature"][:-4] + "AAA="
    try:
        provider.import_license(json.dumps(resigned).encode())
        rec("LG03 modified-signature-rejected", False, "corrupted signature accepted")
    except LicenseImportError as exc:
        rec("LG03 modified-signature-rejected", exc.reason is ReasonCode.SIGNATURE_INVALID,
            "a corrupted signature is rejected")

    wrong_key_provider = _provider(
        tmp, Ed25519PrivateKey.generate().public_key().public_bytes_raw(), fp, tag="wk")
    try:
        wrong_key_provider.import_license(raw)
        rec("LG04 wrong-public-key-rejected", False, "foreign key accepted")
    except LicenseImportError as exc:
        rec("LG04 wrong-public-key-rejected", exc.reason is ReasonCode.SIGNATURE_INVALID,
            "a license signed by a different key never verifies")

    forged = _payload(fp.binding_document(), now=now)
    forged_doc = dict(forged)
    forged_doc["signature"] = "Zm9yZ2VkLXNpZ25hdHVyZS1ub3QtcmVhbA=="
    try:
        LF.validate_document(forged_doc, pub)
        rec("LG05 forgery-without-private-key-rejected", False, "unsigned forgery accepted")
    except LF.LicenseFormatError as exc:
        rec("LG05 forgery-without-private-key-rejected",
            exc.reason is ReasonCode.SIGNATURE_INVALID,
            "a license cannot be forged without the private key")

    other = FP.from_facts(OTHER_FACTS)
    other_provider = _provider(tmp, pub, other, tag="other")
    try:
        other_provider.import_license(raw)
        rec("LG06 copied-license-other-machine-rejected", False, "copied license activated")
    except LicenseImportError as exc:
        rec("LG06 copied-license-other-machine-rejected",
            exc.reason is ReasonCode.MACHINE_MISMATCH,
            "a copied license does not activate a different machine")

    binding_eval = FP.evaluate_binding(other, issued.document["machine_binding"])
    rec("LG07 mac-only-collision-not-sufficient",
        not binding_eval.matched and not binding_eval.strong_component_matched
        and binding_eval.matched_components >= 1,
        "a machine sharing ONLY the MAC component never matches (no strong component)")

    changed = dict(FACTS)
    changed["physical_adapters"] = "FFEEDDCCBBAA"  # replaced network adapter
    changed_provider = _provider(tmp, pub, FP.from_facts(changed), tag="fmt")
    decision = changed_provider.evaluate()
    rec("LG08 minor-hardware-change-tolerated",
        decision.state is LicenseState.VALID,
        "one approved component change keeps a legitimate installation usable")

    two_changed = dict(changed)
    two_changed["board_serial"] = "BOARD-NEW"
    two_changed["system_volume_serial"] = "REIMAGED1"
    below = _provider(tmp, pub, FP.from_facts(two_changed), tag="fmt").evaluate()
    rec("LG09 threshold-mismatch-rejected",
        below.state is LicenseState.MACHINE_MISMATCH,
        "changes beyond the documented threshold stop matching")

    diag = FP.redacted_diagnostic(binding_eval)
    raw_values = [v for v in FACTS.values()] + [v for v in OTHER_FACTS.values()]
    diag_text = json.dumps(diag)
    rec("LG10 binding-diagnostic-redacted",
        set(diag) == {"fingerprint_version", "eligible_components", "binding_confidence", "match"}
        and not any(value in diag_text for value in raw_values),
        "the diagnostic reports only version/count/class/verdict")

    wrong_install = _provider(tmp, pub, fp, installation="inst-OTHER", tag="wi")
    try:
        wrong_install.import_license(raw)
        rec("LG11 wrong-installation-rejected", False, "wrong installation accepted")
    except LicenseImportError as exc:
        rec("LG11 wrong-installation-rejected", exc.reason is ReasonCode.WRONG_INSTALLATION,
            "a license for another installation id is refused")

    for cid, mutate, reason in (
        ("LG12 unknown-field-rejected", lambda d: d.update(extra_grant="yes"),
         ReasonCode.UNKNOWN_FIELD),
        ("LG13 missing-field-rejected", lambda d: d.pop("expires_at"), ReasonCode.FIELD_MISSING),
        ("LG14 wrong-schema-rejected", lambda d: d.update(schema_version="other-license.v9"),
         ReasonCode.SCHEMA_UNSUPPORTED),
        ("LG15 wrong-algorithm-rejected", lambda d: d.update(signature_algorithm="RSA-PKCS1"),
         ReasonCode.WRONG_ALGORITHM),
        ("LG16 wrong-product-rejected", lambda d: d.update(product="other-product"),
         ReasonCode.WRONG_PRODUCT),
    ):
        candidate = dict(issued.document)
        mutate(candidate)
        try:
            LF.validate_document(candidate, pub)
            rec(cid, False, "invalid document accepted")
        except LF.LicenseFormatError as exc:
            rec(cid, exc.reason is reason, f"rejected with {exc.reason.value}")

    version_locked = LF.issue_license(
        _payload(fp.binding_document(), now=now, versions=["0.9.x"]), key)
    locked_provider = _provider(tmp, pub, fp, tag="vl")
    try:
        locked_provider.import_license(json.dumps(version_locked.document).encode())
        rec("LG17 product-version-eligibility-enforced", False, "ineligible version accepted")
    except LicenseImportError as exc:
        rec("LG17 product-version-eligibility-enforced",
            exc.reason is ReasonCode.PRODUCT_VERSION_NOT_PERMITTED,
            "a license for other product versions is refused")


def time_and_state_battery(tmp: Path) -> None:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw()
    fp = FP.from_facts(FACTS)
    base_epoch = time.time()
    now = datetime.now(timezone.utc)
    issued = LF.issue_license(_payload(fp.binding_document(), now=now, days=30, grace=14), key)
    raw = json.dumps(issued.document).encode()

    provider = _provider(tmp, pub, fp, tag="time")
    provider.import_license(raw)

    grace_clock = base_epoch + 86400 * 35
    grace = _provider(tmp, pub, fp, clock=lambda: grace_clock, tag="time").evaluate()
    rec("LG18 grace-period-full-operation",
        grace.state is LicenseState.GRACE and not grace.read_only
        and grace.reason is ReasonCode.IN_GRACE_PERIOD,
        "grace keeps full operation with a visible renewal reason")

    expired_clock = base_epoch + 86400 * 60
    expired = _provider(tmp, pub, fp, clock=lambda: expired_clock, tag="time").evaluate()
    rec("LG19 expired-enters-read-only",
        expired.state is LicenseState.EXPIRED_READ_ONLY and expired.read_only
        and expired.reason is ReasonCode.LICENSE_EXPIRED,
        "past grace the decision is read-only, never destructive")

    rollback = _provider(tmp, pub, fp, clock=lambda: base_epoch, tag="time").evaluate()
    rec("LG20 clock-rollback-detected",
        rollback.state is LicenseState.CLOCK_ROLLBACK_DETECTED
        and rollback.reason is ReasonCode.CLOCK_ROLLBACK_DETECTED,
        "large backward movement after a trusted validation is detected")

    drift = _provider(tmp, pub, fp, clock=lambda: expired_clock - 3600, tag="time").evaluate()
    rec("LG21 minor-drift-tolerated",
        drift.state is not LicenseState.CLOCK_ROLLBACK_DETECTED,
        "one hour of backward drift stays within tolerance")

    tz_before = os.environ.get("TZ")
    try:
        os.environ["TZ"] = "Pacific/Kiritimati"  # UTC+14 -- worst-case shift
        if hasattr(time, "tzset"):
            time.tzset()
        shifted = _provider(tmp, pub, fp, clock=lambda: expired_clock + 60, tag="time").evaluate()
        rec("LG22 timezone-change-no-false-state",
            shifted.state in (LicenseState.EXPIRED_READ_ONLY,),
            "UTC-epoch comparisons make timezone changes irrelevant")
    finally:
        if tz_before is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = tz_before
        if hasattr(time, "tzset"):
            time.tzset()

    fresh = _provider(tmp, pub, fp, tag="nbf")
    future_start = _payload(fp.binding_document(), now=now)
    future_start["not_before"] = (now + timedelta(days=7)).isoformat()
    nbf = LF.issue_license(future_start, key)
    fresh.import_license(json.dumps(nbf.document).encode())
    nbf_decision = fresh.evaluate()
    rec("LG23 not-before-enforced",
        nbf_decision.state is LicenseState.NOT_YET_VALID
        and nbf_decision.reason is ReasonCode.LICENSE_NOT_YET_VALID,
        "a not-yet-valid license does not operate early")

    future_issue = _payload(fp.binding_document(), now=now + timedelta(days=30))
    fut = LF.issue_license(future_issue, key)
    fut_provider = _provider(tmp, pub, fp, tag="fut")
    try:
        fut_provider.import_license(json.dumps(fut.document).encode())
        rec("LG24 future-issued-rejected", False, "future-issued license accepted")
    except LicenseImportError as exc:
        rec("LG24 future-issued-rejected", exc.reason is ReasonCode.LICENSE_FUTURE_ISSUED,
            "a license issued in the future is refused")

    renewal_provider = _provider(tmp, pub, fp, tag="renew")
    first = LF.issue_license(_payload(fp.binding_document(), now=now, sequence=3), key)
    renewal_provider.import_license(json.dumps(first.document).encode())
    newer = LF.issue_license(_payload(fp.binding_document(), now=now, days=730, sequence=4), key)
    upgraded = renewal_provider.import_license(json.dumps(newer.document).encode())
    rec("LG25 newer-renewal-supersedes",
        upgraded.state is LicenseState.VALID and upgraded.renewal_sequence == 4,
        "a valid newer license supersedes the older one safely")
    older = LF.issue_license(_payload(fp.binding_document(), now=now, sequence=2), key)
    try:
        renewal_provider.import_license(json.dumps(older.document).encode())
        rec("LG26 older-renewal-rejected", False, "older renewal accepted")
    except LicenseImportError as exc:
        rec("LG26 older-renewal-rejected", exc.reason is ReasonCode.LICENSE_ROLLBACK_REJECTED,
            "an older license cannot replace a newer entitlement")
    renewal_provider.config.license_path.write_text(
        json.dumps(older.document), encoding="utf-8")
    swapped = renewal_provider.evaluate()
    rec("LG27 on-disk-license-rollback-detected",
        swapped.state is LicenseState.STATE_TAMPERED
        and swapped.reason is ReasonCode.LICENSE_ROLLBACK_REJECTED,
        "swapping an old license file back is detected at evaluation")

    guard_provider = _provider(tmp, pub, fp, tag="state")
    guard_provider.import_license(json.dumps(
        LF.issue_license(_payload(fp.binding_document(), now=now), key).document).encode())
    primary = guard_provider.config.state_primary_path
    secondary = guard_provider.config.state_secondary_path
    primary.write_bytes(b"corrupted-not-a-state-blob")
    secondary.write_bytes(b"corrupted-not-a-state-blob")
    corrupt = guard_provider.evaluate()
    rec("LG28 corrupt-state-fails-closed",
        corrupt.state is LicenseState.STATE_TAMPERED
        and corrupt.reason is ReasonCode.STATE_INTEGRITY_FAILURE,
        "corrupted protected state blocks instead of resetting")

    lineage = _provider(tmp, pub, fp, clock=lambda: expired_clock, tag="lineage")
    lineage.import_license(json.dumps(
        LF.issue_license(_payload(fp.binding_document(),
                                  now=datetime.fromtimestamp(expired_clock, tz=timezone.utc),
                                  days=30), key).document).encode())
    lineage.config.state_primary_path.unlink()
    survived = _provider(tmp, pub, fp, clock=lambda: base_epoch, tag="lineage").evaluate()
    rec("LG29 single-state-copy-deletion-survives",
        survived.state is LicenseState.CLOCK_ROLLBACK_DETECTED,
        "deleting ONE state copy does not silently reset the trusted clock")


def activation_privacy_battery() -> None:
    fp = FP.from_facts(FACTS)
    request = ACT.build_activation_request(
        fp, installation_id="inst-priv", requested_edition="offline-standard")
    ACT.validate_activation_request(request)
    text = json.dumps(request)
    leaked = [value for value in FACTS.values()
              if value in text or value.replace("-", "") in text.replace("-", "")]
    rec("LG30 activation-request-no-raw-identifiers", not leaked,
        "the request carries only hashed components")
    hashes = set(request["machine_binding"]["component_hashes"].values())
    rec("LG31 activation-request-hashes-only",
        all(len(h) == 64 and set(h) <= set("0123456789abcdef") for h in hashes),
        "every component is a SHA-256 digest")
    raw_named = dict(request)
    raw_named["machine_binding"] = dict(request["machine_binding"])
    raw_named["machine_binding"]["component_hashes"] = {"mac": "AA-BB-CC-DD-EE-FF"}  # leak-test fixture
    try:
        ACT.validate_activation_request(raw_named)
        rec("LG32 raw-identifier-request-rejected", False, "raw identifier accepted")
    except LF.LicenseFormatError:
        rec("LG32 raw-identifier-request-rejected", True,
            "operator-side validation refuses raw identifier material")


def update_battery(tmp: Path) -> None:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw()
    payload_bytes = b"update-payload-demo-bytes"
    import hashlib

    manifest = {
        "schema_version": UF.UPDATE_SCHEMA_VERSION,
        "product": "monday-report",
        "product_version": "1.1.0",
        "minimum_compatible_data_version": 1,
        "prohibited_below_version": "1.0.0",
        "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        "signature_algorithm": "Ed25519",
    }
    manifest["signature"] = __import__("base64").b64encode(
        key.sign(canonical_bytes(signing_view(manifest)))).decode()
    accepted = UF.verify_update_manifest(manifest, payload_bytes, pub, installed_version="1.0.0")
    rec("LG33 signed-update-accepted", accepted is manifest, "a valid signed update verifies")

    unsigned = dict(manifest)
    unsigned["signature"] = ""
    cases = [
        ("LG34 unsigned-update-rejected", unsigned, payload_bytes, pub, "1.0.0"),
        ("LG35 tampered-update-rejected", manifest, payload_bytes + b"x", pub, "1.0.0"),
        ("LG36 downgrade-update-rejected", manifest, payload_bytes, pub, "1.2.0"),
        ("LG37 wrong-key-update-rejected", manifest, payload_bytes,
         Ed25519PrivateKey.generate().public_key().public_bytes_raw(), "1.0.0"),
    ]
    for cid, m, p, k, installed in cases:
        try:
            UF.verify_update_manifest(m, p, k, installed_version=installed)
            rec(cid, False, "invalid update accepted")
        except LF.LicenseFormatError as exc:
            rec(cid, True, f"rejected with {exc.reason.value}")

    incompatible = dict(manifest)
    incompatible["minimum_compatible_data_version"] = 99
    incompatible["signature"] = __import__("base64").b64encode(
        key.sign(canonical_bytes(signing_view(incompatible)))).decode()
    try:
        UF.verify_update_manifest(incompatible, payload_bytes, pub, installed_version="1.0.0")
        rec("LG38 incompatible-data-version-rejected", False, "incompatible update accepted")
    except LF.LicenseFormatError as exc:
        rec("LG38 incompatible-data-version-rejected",
            exc.reason is ReasonCode.PRODUCT_VERSION_NOT_PERMITTED,
            "an update needing a newer data version is refused")

    wrong_product = dict(manifest)
    wrong_product["product"] = "other-product"
    wrong_product["signature"] = __import__("base64").b64encode(
        key.sign(canonical_bytes(signing_view(wrong_product)))).decode()
    try:
        UF.verify_update_manifest(wrong_product, payload_bytes, pub, installed_version="1.0.0")
        rec("LG39 wrong-product-update-rejected", False, "wrong product accepted")
    except LF.LicenseFormatError as exc:
        rec("LG39 wrong-product-update-rejected", exc.reason is ReasonCode.WRONG_PRODUCT,
            "an update for a different product is refused")


def key_hygiene_battery() -> None:
    tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files"],
                             capture_output=True, text=True, timeout=30).stdout.split()
    offenders: list[str] = []
    for rel in tracked:
        path = ROOT / rel
        # Secret-SCANNER definitions (and this guard's own pattern literals)
        # legitimately contain leak SHAPES as self-tests — the same exclusion
        # those scanners apply to themselves. Their behavior is proven by the
        # seeded self-tests, not by scanning their definitions.
        if "secret_scan" in path.name or path.name == Path(__file__).name:
            continue
        if path.suffix in (".py", ".ts", ".tsx", ".json", ".md", ".txt", ".ps1", ".iss",
                           ".spec", ".mjs") and path.exists():
            text = path.read_text(encoding="utf-8", errors="replace")
            if "BEGIN PRIVATE KEY" in text or "BEGIN RSA PRIVATE KEY" in text:
                offenders.append(rel)
    rec("LG40 no-private-key-in-repository", not offenders,
        f"tracked sources contain no private key blocks ({offenders or 'clean'})")

    issuer_text = (ROOT / "scripts" / "license_issuer_cli.py").read_text(encoding="utf-8")
    rec("LG41 issuer-never-prints-private-key",
        "private_bytes_raw().hex()" in issuer_text
        and "print" not in [line.strip()[:5] for line in issuer_text.splitlines()
                            if "private_bytes_raw" in line],
        "the issuance CLI writes the private key only to the operator path")
    runtime_text = (ROOT / "backend" / "app" / "offline_runtime.py").read_text(encoding="utf-8")
    licensing_dir = ROOT / "backend" / "app" / "licensing"
    generates = []
    for path in licensing_dir.glob("*.py"):
        if "Ed25519PrivateKey.generate" in path.read_text(encoding="utf-8"):
            generates.append(path.name)
    rec("LG42 no-keygen-inside-application",
        not generates and "Ed25519PrivateKey.generate" not in runtime_text,
        "no application/runtime module can create a signing key")


# ---------------------------------------------------------------------------
# Source-mutation cycles (load-bearing proof)

_MUTATIONS = [
    {
        "id": "MUT01 signature-verification-disabled",
        "file": "license_format.py",
        "old": "        public_key.verify(signature, message)",
        "new": "        pass  # MUTATED: signature check disabled",
        "probe": "tamper_accepted",
    },
    {
        "id": "MUT02 strong-component-requirement-dropped",
        "file": "fingerprint.py",
        "old": "    is_match = version_ok and strong_matched and matched >= threshold",
        "new": "    is_match = version_ok and matched >= 1  # MUTATED",
        "probe": "mac_only_accepted",
    },
    {
        "id": "MUT03 clock-rollback-check-disabled",
        "file": "state_guard.py",
        "old": "        return now_epoch + CLOCK_ROLLBACK_TOLERANCE_SECONDS < state.highest_trusted_epoch",
        "new": "        return False  # MUTATED",
        "probe": "rollback_undetected",
    },
    {
        "id": "MUT04 renewal-monotonicity-dropped",
        "file": "offline_provider.py",
        "old": "        if state.license_id and incoming_sequence < state.issue_sequence:",
        "new": "        if False:  # MUTATED",
        "probe": "old_renewal_accepted",
    },
]

_PROBE_SCRIPT = r"""
import json, os, secrets, sys, time, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, sys.argv[1])  # the mutated package parent
probe = sys.argv[2]
tmp = Path(sys.argv[3])
os.environ["MONDAY_REPORT_LICENSING_STATE_MODE"] = "test"
os.environ["MONDAY_REPORT_LICENSING_STATE_TEST_KEY"] = "mutation-probe-key-123456"

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from licmut import fingerprint as FP, license_format as LF
from licmut.canonical import canonical_hash
from licmut.contract import LicenseState, ReasonCode
from licmut.offline_provider import (LicenseImportError, OfflineProviderConfig,
                                     OfflineSignedLicenseProvider)

FACTS = {"machine_guid": "G1", "smbios_uuid": "U1", "board_serial": "B1",
         "system_volume_serial": "V1", "physical_adapters": "AABBCCDDEEFF"}
key = Ed25519PrivateKey.generate()
pub = key.public_key().public_bytes_raw()
fp = FP.from_facts(FACTS)
now = datetime.now(timezone.utc)

def payload(seq=1, days=365):
    b = fp.binding_document()
    return {"schema_version": LF.LICENSE_SCHEMA_VERSION, "product": "monday-report",
            "license_id": str(uuid.uuid4()), "customer_ref": "c", "edition": "offline-standard",
            "issued_at": now.isoformat(), "not_before": now.isoformat(),
            "expires_at": (now + timedelta(days=days)).isoformat(),
            "grace_until": (now + timedelta(days=days + 14)).isoformat(),
            "machine_binding": b, "machine_fingerprint_hash": canonical_hash(b),
            "allowed_product_versions": ["1.x"], "feature_flags": {},
            "installation_limit": 1, "installation_id": "inst-m", "issuer_id": "i",
            "issue_sequence": seq, "nonce": secrets.token_hex(8),
            "signature_algorithm": "Ed25519"}

def provider(fingerprint=fp, clock=None, tag="p"):
    return OfflineSignedLicenseProvider(OfflineProviderConfig(
        license_path=tmp / f"lic-{tag}.json", state_primary_path=tmp / f"s1-{tag}.bin",
        state_secondary_path=tmp / f"s2-{tag}.bin", public_key=pub,
        installation_id="inst-m", fingerprint_supplier=lambda: fingerprint,
        clock=clock or time.time))

issued = LF.issue_license(payload(), key)
raw = json.dumps(issued.document).encode()
defect = False

if probe == "tamper_accepted":
    doc = dict(issued.document); doc["edition"] = "stolen"
    try:
        provider().import_license(json.dumps(doc).encode()); defect = True
    except LicenseImportError:
        defect = False
elif probe == "mac_only_accepted":
    other = FP.from_facts({"machine_guid": "GX", "smbios_uuid": "UX", "board_serial": "BX",
                           "system_volume_serial": "VX", "physical_adapters": "AABBCCDDEEFF"})
    result = FP.evaluate_binding(other, issued.document["machine_binding"])
    defect = result.matched
elif probe == "rollback_undetected":
    base = time.time()
    p = provider(clock=lambda: base + 86400 * 40, tag="r")
    p.import_license(json.dumps(LF.issue_license(payload(days=90), key).document).encode())
    back = provider(clock=lambda: base, tag="r").evaluate()
    defect = back.state is not LicenseState.CLOCK_ROLLBACK_DETECTED
elif probe == "old_renewal_accepted":
    p = provider(tag="q")
    p.import_license(json.dumps(LF.issue_license(payload(seq=5), key).document).encode())
    try:
        p.import_license(json.dumps(LF.issue_license(payload(seq=2), key).document).encode())
        defect = True
    except LicenseImportError:
        defect = False

print(json.dumps({"defect_effective": defect}))
"""


def mutation_cycles(tmp: Path) -> None:
    source_dir = ROOT / "backend" / "app" / "licensing"
    for mutation in _MUTATIONS:
        work = Path(tempfile.mkdtemp(prefix="licmut-"))
        package_dir = work / "licmut"
        shutil.copytree(source_dir, package_dir)
        probe_file = work / "probe.py"
        probe_file.write_text(_PROBE_SCRIPT, encoding="utf-8")
        invocation = {"count": 0}

        def run_probe() -> bool:
            # A FRESH state directory per invocation: licensing state (license
            # lineage, trusted clock) must never leak between the baseline,
            # mutated, and restored runs.
            invocation["count"] += 1
            state_tmp = work / f"state-{invocation['count']}"
            state_tmp.mkdir()
            completed = subprocess.run(
                [sys.executable, str(probe_file), str(work), mutation["probe"], str(state_tmp)],
                capture_output=True, text=True, timeout=120)
            if completed.returncode != 0:
                raise RuntimeError(f"probe crashed: {completed.stderr[-500:]}")
            return bool(json.loads(completed.stdout.strip().splitlines()[-1])["defect_effective"])

        try:
            baseline_defect = run_probe()
            target = package_dir / mutation["file"]
            original = target.read_text(encoding="utf-8")
            if mutation["old"] not in original:
                rec(mutation["id"], False, "mutation anchor line not found")
                continue
            target.write_text(original.replace(mutation["old"], mutation["new"], 1),
                              encoding="utf-8")
            for cache in package_dir.glob("__pycache__/*"):
                cache.unlink()
            mutated_defect = run_probe()
            target.write_text(original, encoding="utf-8")
            for cache in package_dir.glob("__pycache__/*"):
                cache.unlink()
            restored_defect = run_probe()
            rec(mutation["id"],
                (not baseline_defect) and mutated_defect and (not restored_defect),
                "baseline passes -> defect makes the guard fail for the intended reason -> "
                "restored source passes again")
        except RuntimeError as exc:
            rec(mutation["id"], False, str(exc))
        finally:
            shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    CHECKS.clear()
    tmp = Path(tempfile.mkdtemp(prefix="offline-license-guard-"))
    try:
        format_and_binding_battery(tmp)
        time_and_state_battery(tmp)
        activation_privacy_battery()
        update_battery(tmp)
        key_hygiene_battery()
        mutation_cycles(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "offline_license",
        "claim_scope": "offline licensing enforcement battery; no production/SaaS/GA claim",
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
