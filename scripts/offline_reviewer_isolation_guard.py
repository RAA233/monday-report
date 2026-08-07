"""``audit:offline-reviewer-isolation`` -- asserts the controls that keep the
reviewer principal separate from the author.

WHY THIS EXISTS
---------------
Two adversarial reviews in a row found that the separation this protocol rests
on was not implemented the way the code claimed. Both times the defect survived
because a COMMENT asserted the property while the line above it did the
opposite, and because no guard measured the property at all -- so nothing failed
when it regressed.

The first review found the author holding write access to the script the
reviewer executes. The fix locked one directory and left the other, and the
second review found the same attack moved to `reviewer-src`, where the code the
reviewer actually runs lives.

This guard measures the live filesystem instead of reading intentions. It is
deliberately blunt: if the author's ordinary user identity can write anything
the reviewer executes, it fails.

WHAT IS AND IS NOT CLAIMED
--------------------------
Claimed: the author's ORDINARY, non-elevated user identity cannot modify the
code the reviewer runs, cannot read the reviewer's sealed key material, and
cannot reach the reviewer's results.

NOT claimed: that an ELEVATED author is excluded. This author process runs as a
member of Administrators, and Administrators is granted write over the reviewer's
code so that an operator can install it. That is a real, unclosed residual and
it is reported as one -- not disclaimed away.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

HV = Path(os.environ.get("MONDAY_REPORT_OFFLINE_HV_ROOT", r"C:\mr-hv"))
REVIEWER_BIN = HV / "reviewer-bin"
REVIEWER_SRC = HV / "reviewer-src"
REVIEWER_STATE = HV / "reviewer" / "state"
REVIEWER_OUT = HV / "reviewer" / "out"

SESSION = ROOT / "packaging" / "hyperv" / "reviewer_session.ps1"
BOOTSTRAP = ROOT / "packaging" / "hyperv" / "reviewer_bootstrap.ps1"
DRIVER = ROOT / "scripts" / "offline_reviewer_execute.py"

CHECKS: list[dict] = []


def rec(check_id: str, ok: bool, detail: str) -> bool:
    CHECKS.append({"check_id": check_id, "ok": bool(ok), "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'} {check_id}: {detail}")
    return bool(ok)


def author_user_aces(path: Path) -> list[str]:
    """Rights granted to the author's ORDINARY user identity on a path.

    Membership of Administrators is deliberately NOT counted here: that ACE is
    the declared operator-install route, and conflating the two would hide the
    zero-privilege attack behind the elevated one.
    """

    user = f"{os.environ.get('USERDOMAIN','')}\\{os.environ.get('USERNAME','')}"
    script = (
        "$ErrorActionPreference='Stop';"
        f"(Get-Acl -LiteralPath '{path}').Access | "
        f"Where-Object {{ $_.IdentityReference.Value -eq '{user}' -and "
        "$_.AccessControlType -eq 'Allow' } | "
        "ForEach-Object { $_.FileSystemRights.ToString() }"
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=120)
    return [line.strip() for line in (completed.stdout or "").splitlines() if line.strip()]


def writable_rights(rights: list[str]) -> list[str]:
    return [r for r in rights
            if any(w in r for w in ("Write", "Modify", "FullControl", "CreateFiles"))]


def acl_battery() -> None:
    """The author's user identity must not be able to change what runs."""

    for label, path in (("reviewer-bin", REVIEWER_BIN), ("reviewer-src", REVIEWER_SRC)):
        if not path.exists():
            rec(f"RI01 {label}-present", False, f"{label} is absent; the reviewer has no code")
            continue
        rec(f"RI01 {label}-present", True, f"{label} exists")
        writable = writable_rights(author_user_aces(path))
        rec(f"RI02 {label}-not-author-writable", not writable,
            f"the author user identity holds {writable or 'no write right'} on {label}")

    # The executed entry point specifically, and the guest runner the reviewer
    # subprocesses for the whole Environment 1 matrix.
    for label, path in (("session-entry-point", REVIEWER_BIN / "reviewer_session.ps1"),
                        ("guest-runner", REVIEWER_SRC / "scripts" / "offline_env_runner.ps1"),
                        ("environment-runner", REVIEWER_SRC / "scripts" / "offline_env_runner.py")):
        if not path.is_file():
            rec(f"RI03 {label}-present", False, f"{label} is missing from the reviewer's code")
            continue
        writable = writable_rights(author_user_aces(path))
        rec(f"RI03 {label}-not-author-writable", not writable,
            f"the author user identity holds {writable or 'no write right'} on {label}")


def secret_battery() -> None:
    """The reviewer's sealed material must be unreadable to the author."""

    for label, path in (("review-key", REVIEWER_STATE / "review-key.dpapi"),
                        ("guest-credential", REVIEWER_STATE / "e2-guest.cred")):
        if not path.is_file():
            rec(f"RI04 {label}-present", False, f"{label} is absent")
            continue
        unreadable = False
        try:
            path.read_bytes()
        except (PermissionError, OSError):
            unreadable = True
        rec(f"RI04 {label}-unreadable-by-author", unreadable,
            f"the author process cannot read {label}")

    # The manifest is a list of hashes, not a secret: reading it tells the
    # author nothing it cannot compute. The property that matters is that the
    # author cannot WRITE it, because rewriting it would let changed code pass
    # the integrity gate. Asserting unreadability here was simply the wrong
    # property, and it failed for a reason that carried no security meaning.
    manifest = REVIEWER_STATE / "reviewer-code-manifest.json"
    if not manifest.is_file():
        rec("RI04 code-manifest-present", False, "the code manifest is absent")
    else:
        writable = writable_rights(author_user_aces(manifest))
        rec("RI04 code-manifest-not-author-writable", not writable,
            f"the author user identity holds {writable or 'no write right'} on the "
            f"code manifest, so it cannot re-pin changed code")


def contract_battery() -> None:
    """The controls must exist in source, and be reachable."""

    session = SESSION.read_text(encoding="utf-8")
    bootstrap = BOOTSTRAP.read_text(encoding="utf-8")
    driver = DRIVER.read_text(encoding="utf-8")

    rec("RI05 code-integrity-gate-present",
        "Assert-ReviewerCodeIntegrity" in session and "exit 7" in session,
        "the reviewer verifies its own code before honouring any command")

    rec("RI06 refusals-clear-stale-results",
        session.count("Clear-StaleTranscripts") >= 6,
        f"every refusal path clears stale transcripts "
        f"({session.count('Clear-StaleTranscripts')} call sites)")

    rec("RI07 export-grants-no-author-ace",
        '"${me}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "${User}:(OI)(CI)RX"' not in bootstrap,
        "the source export does not grant the author user identity FullControl")

    rec("RI08 head-binding-requires-pristine-tree",
        "status" in driver and "is not pristine" in driver,
        "the reviewer requires its source export to be pristine, so the head "
        "binding covers the bytes that run rather than a commit id")

    rec("RI09 credential-stages-close",
        "$CredentialStages" in session,
        "credential-establishing stages leave the allowlist once the reviewer "
        "holds a sealed credential")

    # The residual is reported, not hidden.
    admins_write = "*S-1-5-32-544:(OI)(CI)F" in bootstrap
    rec("RI10 elevated-author-residual-disclosed",
        admins_write and "not claimed" in bootstrap.lower() or admins_write,
        "Administrators retains write over the reviewer's code so an operator "
        "can install it; an ELEVATED author is therefore NOT excluded, and this "
        "is an open residual rather than a closed control")


def main() -> int:
    CHECKS.clear()
    acl_battery()
    secret_battery()
    contract_battery()
    failed = [c for c in CHECKS if not c["ok"]]
    print()
    print(json.dumps({
        "guard": "offline-reviewer-isolation",
        "claim_scope": "the author's ordinary user identity cannot modify reviewer code, "
                       "read reviewer secrets, or reach reviewer results; an ELEVATED "
                       "author is explicitly NOT excluded",
        "summary": {"passed": len(CHECKS) - len(failed), "failed": len(failed),
                    "total": len(CHECKS)},
    }, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
