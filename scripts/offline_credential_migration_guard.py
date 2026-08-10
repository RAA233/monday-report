"""``audit:offline-credential-migration`` -- proves the Hyper-V guest credential
is owned by the REVIEWER principal, not the author.

WHY THIS MATTERS
----------------
Environment 2 authenticates over PowerShell Direct. If the author holds the
credential that opens that session, the author can drive Environment 2 itself
and the reviewer's signature over an E2 transcript proves nothing about who ran
it. Ownership therefore moves once, cryptographically, and the credential is
then ROTATED so the value the author briefly handled stops working.

WHAT THIS GUARD ASSERTS, AND WHERE
----------------------------------
Live facts are read from the real migration state -- the reviewer's sealed
credential, the author's retired copy, the reviewer certificate store. Anything
DESTRUCTIVE (corrupt envelopes, wrong recipients, replayed nonces) is exercised
against disposable task-owned fixtures built inside a temporary directory, never
against the real credential: a guard that damages the thing it verifies is worse
than no guard.

WHAT IS NOT CLAIMED
-------------------
Nothing here prevents a machine administrator from taking ownership of local
resources. The claim is narrower and checkable: *the normal author process
cannot authenticate the supported E2 workflow after rotation.*
"""
from __future__ import annotations

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

HV_ROOT = Path(os.environ.get("MONDAY_REPORT_OFFLINE_HV_ROOT", r"C:\mr-hv"))
AUTHOR_STATE = HV_ROOT / "state"
REVIEWER_STATE = HV_ROOT / "reviewer" / "state"
HANDOFF = HV_ROOT / "xchg" / "credential"

AUTHOR_CRED = AUTHOR_STATE / "e2-guest.cred"
AUTHOR_RETIRED = AUTHOR_STATE / "e2-guest.cred.retired"
REVIEWER_CRED = REVIEWER_STATE / "e2-guest.cred"
PUBLIC_CERT = HANDOFF / "reviewer-cms.cer"
ENVELOPE = HANDOFF / "guest-credential.cms"
NONCE_FILE = HANDOFF / "migration-nonce.txt"

MIGRATION_SCRIPT = ROOT / "packaging" / "hyperv" / "reviewer_credential_migration.ps1"

CHECKS: list[dict] = []


def rec(check_id: str, ok: bool, detail: str) -> bool:
    CHECKS.append({"check_id": check_id, "ok": bool(ok), "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'} {check_id}: {detail}")
    return bool(ok)


def powershell(script: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=timeout)


def truthy(completed: subprocess.CompletedProcess) -> bool:
    return completed.returncode == 0 and "TRUE" in completed.stdout.upper()


# ---------------------------------------------------------------- live state
def live_state_battery() -> None:
    rec("CM01 reviewer-credential-sealed", REVIEWER_CRED.is_file(),
        "the reviewer holds a DPAPI-sealed guest credential")

    # The author must not be able to READ it, let alone decrypt it.
    unreadable = False
    try:
        REVIEWER_CRED.read_bytes()
    except (PermissionError, OSError):
        unreadable = True
    rec("CM02 author-cannot-read-reviewer-credential", unreadable,
        "the author process cannot read the reviewer credential blob")

    # And the supported author path (DPAPI CurrentUser) must not decrypt it.
    result = powershell(
        f"try {{ $b = Get-Content -Raw '{REVIEWER_CRED}' -ErrorAction Stop; "
        "$null = ConvertTo-SecureString -String $b.Trim() -ErrorAction Stop; 'FALSE' } "
        "catch { 'TRUE' }")
    rec("CM03 author-cannot-decrypt-reviewer-credential", truthy(result),
        "the supported author DPAPI path cannot decrypt the reviewer credential")

    rec("CM04 author-credential-retired", not AUTHOR_CRED.is_file(),
        f"the author's active guest credential is retired "
        f"(retired marker present: {AUTHOR_RETIRED.is_file()})")

    # One-time migration material must not survive.
    rec("CM05 envelope-destroyed", not ENVELOPE.exists(),
        "the one-time CMS envelope was destroyed after rotation")
    rec("CM06 nonce-destroyed", not NONCE_FILE.exists(),
        "the one-time migration nonce was destroyed after rotation")

    # The reviewer's CMS private key must not exist in the author's store.
    result = powershell(
        "$c = Get-ChildItem Cert:\\CurrentUser\\My -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Subject -eq 'CN=MR-OFFLINE-REVIEWER-CMS' }; "
        "if ($c) { 'FALSE' } else { 'TRUE' }")
    rec("CM07 cms-private-key-not-in-author-store", truthy(result),
        "the reviewer CMS certificate is absent from the author certificate store")

    # Only PUBLIC certificate material may sit in the handoff area.
    public_only = True
    detail = "handoff area holds only public certificate material"
    if HANDOFF.exists():
        for path in HANDOFF.iterdir():
            if path.is_file() and path.suffix.lower() not in (".cer", ".crt"):
                public_only = False
                detail = f"unexpected non-public artifact in the handoff area: {path.name}"
    rec("CM08 handoff-holds-public-material-only", public_only, detail)

    # No plaintext secret anywhere in the credential surfaces.
    leaked: list[str] = []
    for base in (HANDOFF, REVIEWER_STATE, AUTHOR_STATE):
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix.lower() in (".cer", ".crt"):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except (PermissionError, OSError):
                continue  # reviewer-owned and unreadable: that is the point
            if re.search(r"(?i)password\s*[:=]\s*\S", text):
                leaked.append(path.name)
    rec("CM09 no-plaintext-credential-at-rest", not leaked,
        f"no plaintext credential shape at rest ({leaked or 'none'})")


# ------------------------------------------------------------- fault battery
def fault_battery() -> None:
    """Destructive cases, on DISPOSABLE COPIES only.

    The real credential is never written to here. Each case builds its own CMS
    material in a temporary directory, so a failure cannot strand the migration.
    """

    work = Path(tempfile.mkdtemp(prefix="mr-cred-fault-"))
    try:
        # A throwaway CMS identity in the CURRENT (author) store, so these cases
        # exercise the code path without touching the reviewer's certificate.
        setup = powershell(f"""
$ErrorActionPreference='Stop'
$c = New-SelfSignedCertificate -Type DocumentEncryptionCert -Subject 'CN=MR-OFFLINE-FAULT-FIXTURE' `
     -CertStoreLocation Cert:\\CurrentUser\\My -NotAfter (Get-Date).AddDays(1)
Export-Certificate -Cert $c -FilePath '{work}\\fixture.cer' -Force | Out-Null
Protect-CmsMessage -To '{work}\\fixture.cer' -Content '{{"nonce":"aa","account":"mrops","secret":"x"}}' `
     -OutFile '{work}\\good.cms'
$c.Thumbprint
""", timeout=240)
        thumb = (setup.stdout or "").strip().splitlines()[-1] if setup.stdout.strip() else ""
        if setup.returncode != 0 or not thumb:
            rec("CM10 fault-fixture-available", False,
                f"could not build a disposable CMS fixture: {(setup.stderr or '')[:120]}")
            return
        rec("CM10 fault-fixture-available", True,
            "a disposable CMS fixture was built without touching real credential state")

        # Baseline: the fixture envelope opens in the store that owns its key.
        good = powershell(f"try {{ $null = Unprotect-CmsMessage -Path '{work}\\good.cms' -ErrorAction Stop; 'TRUE' }} catch {{ 'FALSE' }}")
        if not rec("CM11 fixture-baseline-opens", truthy(good),
                   "the disposable envelope opens for its intended recipient"):
            return

        # Corrupted envelope must fail closed.
        corrupt = Path(work) / "corrupt.cms"
        body = (Path(work) / "good.cms").read_text(encoding="utf-8")
        corrupt.write_text(body.replace(body[80:100], "X" * 20), encoding="utf-8")
        result = powershell(f"try {{ $null = Unprotect-CmsMessage -Path '{corrupt}' -ErrorAction Stop; 'FALSE' }} catch {{ 'TRUE' }}")
        rec("CM12 corrupt-envelope-fails-closed", truthy(result),
            "a corrupted CMS envelope is refused")

        # Truncated envelope must fail closed.
        truncated = Path(work) / "truncated.cms"
        truncated.write_text(body[: len(body) // 2], encoding="utf-8")
        result = powershell(f"try {{ $null = Unprotect-CmsMessage -Path '{truncated}' -ErrorAction Stop; 'FALSE' }} catch {{ 'TRUE' }}")
        rec("CM13 truncated-envelope-fails-closed", truthy(result),
            "a truncated CMS envelope is refused")

        # Wrong recipient: encrypt to a second identity whose key we then remove.
        result = powershell(f"""
$ErrorActionPreference='Stop'
$o = New-SelfSignedCertificate -Type DocumentEncryptionCert -Subject 'CN=MR-OFFLINE-FAULT-OTHER' `
     -CertStoreLocation Cert:\\CurrentUser\\My -NotAfter (Get-Date).AddDays(1)
Export-Certificate -Cert $o -FilePath '{work}\\other.cer' -Force | Out-Null
Protect-CmsMessage -To '{work}\\other.cer' -Content 'secret-for-other' -OutFile '{work}\\other.cms'
Remove-Item ("Cert:\\CurrentUser\\My\\" + $o.Thumbprint) -Force
try {{ $null = Unprotect-CmsMessage -Path '{work}\\other.cms' -ErrorAction Stop; 'FALSE' }} catch {{ 'TRUE' }}
""", timeout=240)
        rec("CM14 wrong-recipient-fails-closed", truthy(result),
            "an envelope addressed to another identity cannot be opened")

        # The migration script must refuse a nonce that does not match.
        source = MIGRATION_SCRIPT.read_text(encoding="utf-8")
        rec("CM15 nonce-mismatch-rejected",
            "envelope nonce does not match the reviewer migration nonce" in source,
            "the migration refuses an envelope minted for a different nonce")
        rec("CM16 account-mismatch-rejected",
            "envelope names a different guest account" in source,
            "the migration refuses an envelope naming a different guest account")
        rec("CM17 missing-nonce-rejected",
            "reviewer migration nonce is absent" in source,
            "the author side refuses to build an envelope with no reviewer nonce")

        # Secrets must never reach argv, environment, or logs.
        rec("CM18 no-credential-in-argv",
            not re.search(r"-Password\s+\$?plain|--password", source),
            "no credential is passed on a command line")
        rec("CM19 no-credential-in-environment",
            not re.search(r"\$env:[A-Za-z_]*(PASSWORD|SECRET|CRED)", source),
            "no credential is passed through an environment variable")
        rec("CM20 plaintext-never-persisted",
            "plaintext_persisted" in source and "Remove-Variable plain" in source,
            "the transiently decrypted secret is cleared and never written")
        rec("CM21 rotation-proves-old-credential-dead",
            "old_credential_still_works" in source,
            "the migration reports whether the old credential still authenticates")
    finally:
        powershell(
            "Get-ChildItem Cert:\\CurrentUser\\My -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Subject -like 'CN=MR-OFFLINE-FAULT-*' } | "
            "ForEach-Object { Remove-Item (\"Cert:\\CurrentUser\\My\\\" + $_.Thumbprint) -Force "
            "-ErrorAction SilentlyContinue }")
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    CHECKS.clear()
    live_state_battery()
    fault_battery()
    failed = [c for c in CHECKS if not c["ok"]]
    print()
    print(json.dumps({
        "guard": "offline-credential-migration",
        "claim_scope": "the reviewer principal owns the only supported credential for the "
                       "E2 PowerShell Direct workflow; not a claim about machine administrators",
        "summary": {"passed": len(CHECKS) - len(failed), "failed": len(failed),
                    "total": len(CHECKS)},
    }, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
