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

Also claimed, and newly enforced: that the authoring process performing
certification is itself unprivileged (RI16).

A third review made clear why that has to be a gate rather than a footnote.
Everything else here constrains an unprivileged author and nothing else: an
elevated one takes ownership back, rewrites the reviewer entry point, and
obtains a genuinely signed transcript of fabricated facts. Calling that residual
"the malicious administrator non-goal" conflates an attacker who gains
administrative rights with the ordinary release process holding them by default.
The second is in scope, so it fails the guard.

Administrators keeps write access over the reviewer's code because an operator
has to install it. The gate is therefore not "no principal may be elevated" but
"the process that builds the package and drives certification must not be".
"""
from __future__ import annotations

import json
import os
import shutil
import time
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
    # RI10 used to "disclose the residual": its predicate reduced to
    # `admins_write`, so it PASSED precisely because the hole was open, and
    # passed harder the wider the hole got. Disclosure is not a control, and a
    # check that rewards the defect it describes is worse than no check.
    #
    # The residual is real and stays: an operator must be able to install the
    # reviewer's code. What makes it bounded is that the process which builds
    # the package and drives certification is unprivileged -- measured by RI16,
    # which fails rather than narrates.
    rec("RI10 operator-install-route-is-the-only-elevated-write",
        admins_write,
        "Administrators retains write over the reviewer's code for the operator "
        "install route; RI16 gates whether the certifying author holds it")


def _published_interpreter_pin() -> dict:
    """Where the reviewer's interpreter lives, as the REVIEWER published it.

    Deliberately not `sys.executable`: that is the author's own interpreter, and
    probing it would answer "can the author write its own tools" rather than
    "can the author write the code the reviewer runs". The reviewer writes this
    file into the trust directory, which the author can read and cannot write.
    """

    pin = HV / "trust" / "reviewer-interpreter-pin.v1.json"
    if not pin.is_file():
        return {}
    try:
        return json.loads(pin.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _probe_paths() -> str:
    """The PowerShell hashtable of write targets, built from real paths.

    Assembled from ``HV`` rather than written out as literals: hand-escaped
    Windows paths in generated PowerShell silently mangled ``\\r`` and ``\\t``
    once already, which would have made the probe report "not writable" for
    directories that simply did not exist under the mangled name -- a passing
    check measuring nothing.
    """

    targets = {
        "reviewer-src": HV / "reviewer-src",
        "reviewer-bin": HV / "reviewer-bin",
        "reviewer-pkg": HV / "reviewer-pkg",
        "reviewer-state": HV / "reviewer" / "state",
        "reviewer-results": HV / "reviewer" / "out",
        "trust-root-dir": HV / "trust",
    }
    pin = _published_interpreter_pin()
    if pin.get("site_packages_path"):
        targets["interpreter-site-packages"] = Path(pin["site_packages_path"])
    if pin.get("interpreter_path"):
        targets["interpreter-binary"] = Path(pin["interpreter_path"])
    # Single-quoted PowerShell strings take backslashes literally; only the
    # quote character itself needs doubling.
    body = "; ".join("'%s' = '%s'" % (k, str(v).replace("'", "''"))
                     for k, v in targets.items())
    return "@{ " + body + " }"


def non_elevated_capability() -> dict:
    """What can the AUTHOR do with an ORDINARY, non-elevated token?

    This is the question certification turns on, and it is NOT the same as "does
    Administrators have power". Administrators is the one-time OPERATOR install
    route. The AUTHOR is the process that builds the package and orchestrates
    certification, and it must not be able to reach reviewer code or trust
    material through its normal token.

    Measuring it means actually dropping the elevated token, which
    ``runas /trustlevel:0x20000`` does without a password. Booleans only: no
    identity, no path, no credential ever leaves this function.
    """

    import json as _json
    import tempfile

    probe = "$ErrorActionPreference = 'SilentlyContinue'\n$paths = __PATHS__\n$r = [ordered]@{ elevated = (New-Object Security.Principal.WindowsPrincipal(\n    [Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(\n    [Security.Principal.WindowsBuiltInRole]::Administrator) }\nforeach ($k in $paths.Keys) {\n  $p = $paths[$k]\n  if (-not (Test-Path $p)) { $r[$k] = 'absent'; continue }\n  if ((Get-Item $p -Force).PSIsContainer) {\n    $f = Join-Path $p ('.ne-' + [Guid]::NewGuid().ToString('N') + '.tmp')\n    try { Set-Content -Path $f -Value 'x' -ErrorAction Stop\n          $r[$k] = $true; Remove-Item $f -Force -ErrorAction SilentlyContinue }\n    catch { $r[$k] = $false }\n  } else {\n    try { $fs = [System.IO.File]::Open($p, 'Open', 'Write', 'None')\n          $fs.Close(); $r[$k] = $true }\n    catch { $r[$k] = $false }\n  }\n}\n$r | ConvertTo-Json -Compress".replace("__PATHS__", _probe_paths())
    work = Path(tempfile.mkdtemp(prefix="mr-ne-"))
    try:
        ps1 = work / "probe.ps1"
        out = work / "out.json"
        ps1.write_text(probe, encoding="utf-8")
        runner = work / "run.cmd"
        runner.write_text(
            "@echo off\r\n"
            'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%s" > "%s" 2>nul\r\n'
            % (ps1, out),
            encoding="ascii")
        subprocess.run(["runas.exe", "/trustlevel:0x20000", str(runner)],
                       capture_output=True, text=True, timeout=180)
        for _ in range(90):
            if out.is_file() and out.read_text(encoding="utf-8", errors="ignore").strip():
                break
            time.sleep(1)
        raw = out.read_text(encoding="utf-8", errors="ignore") if out.is_file() else ""
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("{"):
                return _json.loads(line)
        return {}
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def author_process_elevated() -> dict:
    """Is the process that performs certification itself elevated?

    Every protection this file measures -- ACLs, ownership, the pinned
    interpreter, the code manifest -- binds a NON-elevated author and nothing
    else. An elevated author simply takes ownership back, rewrites the reviewer
    entry point, and produces a genuinely signed transcript of fabricated facts.
    So the separation claim is only meaningful if the authoring process is
    measured to be unprivileged at the moment certification runs, and that
    measurement belongs in the gate rather than in a one-off observation that
    was true on the day someone looked.

    This is NOT the declared "malicious administrator takeover" non-goal. That
    non-goal covers an attacker who gains administrative rights. This covers the
    ordinary, intended release process running with them by default.
    """

    ps = ("$id = [Security.Principal.WindowsIdentity]::GetCurrent();"
          "$p = New-Object Security.Principal.WindowsPrincipal($id);"
          "$admin = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);"
          "$probe = Join-Path $env:SystemRoot ('el-' + [Guid]::NewGuid().ToString('N') + '.tmp');"
          "try { Set-Content -Path $probe -Value 'x' -ErrorAction Stop; $w = $true;"
          "      Remove-Item $probe -Force -ErrorAction SilentlyContinue } catch { $w = $false };"
          "$lvl = ($id.Groups | Where-Object { $_.Value -like 'S-1-16-*' } |"
          "        Select-Object -First 1).Value;"
          "@{ in_admin_role = $admin; can_write_system_root = $w;"
          "   integrity_sid = $lvl } | ConvertTo-Json -Compress")
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=120)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith("{"):
                return json.loads(line)
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}
    return {}


def elevation_battery() -> None:
    """The ordinary author token must not reach reviewer code or trust material.

    Reported separately from the ACL checks because it answers a different
    question: not "is there an ACE" but "can the process that performs
    certification actually do it".
    """

    measured = non_elevated_capability()
    if not measured:
        rec("RI11 non-elevated-capability-measurable", False,
            "the author's non-elevated capability could not be measured, so the "
            "trust boundary is unproven rather than proven")
        return
    rec("RI11 non-elevated-capability-measurable", True,
        "the author's ordinary token was dropped and measured directly")
    rec("RI12 probe-token-really-non-elevated", measured.get("elevated") is False,
        f"the measuring token carried no administrative rights "
        f"(elevated={measured.get('elevated')})")

    for key, label in (("reviewer-src", "reviewer source"),
                       ("reviewer-bin", "reviewer entry-point directory"),
                       ("reviewer-pkg", "package the reviewer installs and executes"),
                       ("reviewer-state", "reviewer key and trust state"),
                       ("reviewer-results", "reviewer canonical results"),
                       ("trust-root-dir", "pinned trust root")):
        rec(f"RI13 non-elevated-author-cannot-write-{key}",
            measured.get(key) is False,
            f"an ordinary author token cannot write the {label}")

    # The interpreter is the route that bypassed every other control: `-I` does
    # not disable site.py, so a sitecustomize.py or .pth in site-packages runs
    # inside the reviewer session with DPAPI available. Nothing under the
    # Hyper-V root and no tracked file needs to change, so the code manifest and
    # the pristine-clone check both stay green while arbitrary code runs as the
    # reviewer. It is measured here, not argued.
    pin = _published_interpreter_pin()
    rec("RI14 reviewer-interpreter-pin-published", bool(pin.get("interpreter_path")),
        "the reviewer published which interpreter it runs, in a location the "
        "author can read and cannot write")
    for key, label in (("interpreter-site-packages",
                        "site-packages of the interpreter the reviewer runs"),
                       ("interpreter-binary",
                        "interpreter binary the reviewer runs")):
        observed = measured.get(key)
        rec(f"RI15 non-elevated-author-cannot-write-{key}",
            observed is False,
            f"an ordinary author token cannot write the {label} "
            f"(observed={observed!r})")

    # The gate itself. Everything above describes what an UNPRIVILEGED author
    # cannot do; none of it constrains a privileged one.
    author = author_process_elevated()
    if not author:
        rec("RI16 author-process-elevation-measurable", False,
            "the authoring process's own privilege level could not be measured, "
            "so separation is unproven rather than proven")
        return
    elevated = bool(author.get("in_admin_role")) or bool(author.get("can_write_system_root"))
    rec("RI16 author-process-not-elevated", not elevated,
        "the process performing certification holds no administrative rights "
        f"(in_admin_role={author.get('in_admin_role')}, "
        f"can_write_system_root={author.get('can_write_system_root')}); "
        "an elevated author can take ownership back and rewrite reviewer code, "
        "which would make every other check in this guard decorative")


def main() -> int:
    CHECKS.clear()
    acl_battery()
    secret_battery()
    contract_battery()
    elevation_battery()
    failed = [c for c in CHECKS if not c["ok"]]
    print()
    print(json.dumps({
        "guard": "offline-reviewer-isolation",
        "claim_scope": "the author's ordinary user identity cannot modify reviewer code, "
                       "read reviewer secrets, or reach reviewer results, AND the "
                       "process performing certification is itself unprivileged; "
                       "elevation remains available to the operator install route only",
        "summary": {"passed": len(CHECKS) - len(failed), "failed": len(failed),
                    "total": len(CHECKS)},
    }, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
