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
import tempfile
import time
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# FIXED, not configurable.
#
# This was env-overridable while reviewer_session.ps1, the boundary probe
# and the reviewer driver all hardcode the same path. So the guard -- and
# only the guard -- could be pointed at a decoy tree the author had built to
# pass every check, without touching a single tracked file. An anchor that
# the party it constrains can relocate is not an anchor.
HV = Path(r"C:\mr-hv")
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


def author_owns(path: Path) -> bool:
    """Does the author's ordinary identity OWN this object?

    Ownership is a write right in everything but name: the owner always holds
    READ_CONTROL and WRITE_DAC, so it can grant itself anything the DACL does
    not currently allow. Reading only the ACE list therefore reported "no write
    right" for objects the author could rewrite at will, and a decoy tree could
    be made to pass every ACL check simply by removing the explicit ACE while
    staying owner.
    """

    user = f"{os.environ.get('USERDOMAIN','')}\\{os.environ.get('USERNAME','')}"
    script = ("$ErrorActionPreference='Stop';"
              f"(Get-Acl -LiteralPath '{path}').Owner")
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return True          # unmeasurable -> assume the worst
    return (completed.stdout or "").strip().lower() == user.lower()


def acl_battery() -> None:
    """The author's user identity must not be able to change what runs."""

    # reviewer-pkg and reviewer-runtime are executed code too. Measuring only
    # bin and src left the two directories the reviewer actually launches
    # binaries out of unmeasured by the ACL battery entirely.
    for label, path in (("reviewer-bin", REVIEWER_BIN), ("reviewer-src", REVIEWER_SRC),
                        ("reviewer-pkg", HV / "reviewer-pkg"),
                        ("reviewer-runtime", HV / "reviewer-runtime")):
        if not path.exists():
            rec(f"RI01 {label}-present", False, f"{label} is absent; the reviewer has no code")
            continue
        rec(f"RI01 {label}-present", True, f"{label} exists")
        writable = writable_rights(author_user_aces(path))
        owned = author_owns(path)
        rec(f"RI02 {label}-not-author-writable", not writable and not owned,
            f"the author user identity holds {writable or 'no write right'} on {label} "
            f"and does not own it (author_is_owner={owned})")

    # The executed entry point specifically, and the guest runner the reviewer
    # subprocesses for the whole Environment 1 matrix.
    for label, path in (("session-entry-point", REVIEWER_BIN / "reviewer_session.ps1"),
                        ("guest-runner", REVIEWER_SRC / "scripts" / "offline_env_runner.ps1"),
                        ("environment-runner", REVIEWER_SRC / "scripts" / "offline_env_runner.py")):
        if not path.is_file():
            rec(f"RI03 {label}-present", False, f"{label} is missing from the reviewer's code")
            continue
        writable = writable_rights(author_user_aces(path))
        owned = author_owns(path)
        rec(f"RI03 {label}-not-author-writable", not writable and not owned,
            f"the author user identity holds {writable or 'no write right'} on {label} "
            f"and does not own it (author_is_owner={owned})")


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
        owned = author_owns(manifest)
        rec("RI04 code-manifest-not-author-writable", not writable and not owned,
            f"the author user identity holds {writable or 'no write right'} on the "
            f"code manifest and does not own it (author_is_owner={owned}), so it "
            f"cannot re-pin changed code")


def _extract_ps_function(name: str) -> str:
    """Pull one function out of the session script so it can be RUN, not read."""

    text = SESSION.read_text(encoding="utf-8")
    start = text.find(f"function {name} {{")
    if start < 0:
        return ""
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    return ""


def integrity_gate_detects_change() -> bool:
    """Adopt a fixture, verify it, move one byte, require CHANGED, restore."""

    body = _extract_ps_function("Assert-ReviewerCodeIntegrity")
    if not body:
        return False
    work = Path(tempfile.mkdtemp(prefix="mr-gate-"))
    try:
        target = work / "pinned.txt"
        harness = work / "gate.ps1"
        harness.write_text("\n".join([
            body,
            f"$mf = '{work / 'manifest.json'}'",
            f"$p = '{target}'",
            # Seeded by the SAME writer that restores it. Creating the file from
            # Python left the restore byte-different -- Set-Content -Encoding
            # utf8 emits a BOM -- so the cycle reported CHANGED after restoring
            # and the check failed for a reason with nothing to do with the gate
            # it was testing.
            "Set-Content -Path $p -Value 'original' -Encoding utf8",
            "$a = Assert-ReviewerCodeIntegrity -ManifestPath $mf -Paths @($p)",
            "$b = Assert-ReviewerCodeIntegrity -ManifestPath $mf -Paths @($p)",
            f"Set-Content -Path $p -Value 'mutated' -Encoding utf8",
            "$c = Assert-ReviewerCodeIntegrity -ManifestPath $mf -Paths @($p)",
            f"Set-Content -Path $p -Value 'original' -Encoding utf8",
            "$d = Assert-ReviewerCodeIntegrity -ManifestPath $mf -Paths @($p)",
            "\"$($a.state),$($b.state),$($c.state),$($d.state)\"",
        ]), encoding="utf-8")
        shell = (Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
                 / "WindowsPowerShell" / "v1.0" / "powershell.exe")
        proc = subprocess.run([str(shell), "-NoProfile", "-NonInteractive",
                               "-ExecutionPolicy", "Bypass", "-File", str(harness)],
                              capture_output=True, text=True, timeout=300)
        states = [ln.strip() for ln in (proc.stdout or "").splitlines() if "," in ln]
        return bool(states) and states[-1] == "ADOPTED,VERIFIED,CHANGED,VERIFIED"
    except (OSError, subprocess.SubprocessError):
        return False
    finally:
        shutil.rmtree(work, ignore_errors=True)


def credential_stage_reachability() -> tuple:
    """What the session's allowlist actually contains, in both credential states.

    The allowlist is built by two lines of the session script; they are executed
    here with the sealed-credential file present and absent, and the result is
    read rather than asserted.
    """

    text = SESSION.read_text(encoding="utf-8")
    lines = text.splitlines()
    try:
        first = next(i for i, ln in enumerate(lines) if ln.startswith("$CredentialStages"))
        last = next(i for i, ln in enumerate(lines[first:], first)
                    if ln.strip() == "}") + 1
    except StopIteration:
        return (None, None)
    snippet = "\n".join(lines[first:last])
    work = Path(tempfile.mkdtemp(prefix="mr-stages-"))
    try:
        state = work / "state"
        state.mkdir()
        results = []
        for present in (True, False):
            cred = state / "e2-guest.cred"
            if present:
                cred.write_text("fixture", encoding="utf-8")
            elif cred.exists():
                cred.unlink()
            harness = work / "stages.ps1"
            harness.write_text("\n".join([
                f"$StateRoot = '{state}'",
                snippet,
                "($AllowedStages -contains 'cred-seal').ToString()",
            ]), encoding="utf-8")
            shell = (Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
                     / "WindowsPowerShell" / "v1.0" / "powershell.exe")
            proc = subprocess.run([str(shell), "-NoProfile", "-NonInteractive",
                                   "-ExecutionPolicy", "Bypass", "-File", str(harness)],
                                  capture_output=True, text=True, timeout=300)
            out = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
            results.append(out[-1] == "True" if out else None)
        return (results[0], results[1])
    except (OSError, subprocess.SubprocessError):
        return (None, None)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def contract_battery() -> None:
    """The controls must exist in source, and be reachable."""

    session = SESSION.read_text(encoding="utf-8")
    bootstrap = BOOTSTRAP.read_text(encoding="utf-8")
    driver = DRIVER.read_text(encoding="utf-8")

    # RI05 RUNS the gate instead of grepping for its name. A function that is
    # present and does nothing satisfies a string search perfectly.
    rec("RI05 code-integrity-gate-detects-change", integrity_gate_detects_change(),
        "the reviewer's own integrity function, extracted from the session and "
        "executed, adopts a fixture, verifies it unchanged, reports CHANGED when "
        "one byte moves, and verifies again once it is put back")

    # Counting occurrences counted the function DEFINITION too, and said nothing
    # about the exits that never call it. Every `exit` in the session must be
    # preceded by a clear or by New-Status, which writes a fresh result.
    exits = [n for n, line in enumerate(session.splitlines(), 1)
             if line.strip().startswith("exit ")]
    lines = session.splitlines()
    # A fresh status is NOT a substitute for clearing.
    #
    # Accepting either token let four exits through that write a status and then
    # leave the previous run's ENVIRONMENT_1/2 transcripts in place -- the exact
    # "COMPLETE result for a run that never happened" that Clear-StaleTranscripts
    # exists to prevent. Only an exit that produces its own result may skip it,
    # and those are the ones reporting COMPLETE or OK.
    # The NEAREST preceding status decides, not "anything in a 14-line window".
    #
    # A window is proximity, not reachability: the credential branch's FAILED
    # refusal was accepted because the DIAGNOSTICS branch's COMPLETE happened to
    # sit ten lines above it, in a different block entirely. Three more exits
    # passed the same way, each with a FAILED path that clears nothing.
    unguarded = []
    for n in exits:
        nearest_status = None
        cleared = False
        # Collect BOTH facts; do not stop at the first one.
        #
        # Breaking on the status line meant the scan never reached the
        # Clear-StaleTranscripts call sitting immediately above it, which is the
        # order the code actually uses -- clear, then report, then exit. Ten
        # correctly-guarded exits were reported as unguarded.
        for k in range(n - 1, max(0, n - 30), -1):
            text = lines[k - 1]
            if "Clear-StaleTranscripts" in text:
                cleared = True
            if "-State '" in text and nearest_status is None:
                nearest_status = text
        if cleared:
            continue
        if nearest_status and ("-State 'COMPLETE'" in nearest_status
                               or "-State 'OK'" in nearest_status):
            continue
        unguarded.append(n)
    rec("RI06 refusals-clear-stale-results", not unguarded,
        f"every exit that does not produce its own result clears stale "
        f"transcripts first (unguarded exits at lines {unguarded or 'none'})")

    # RI07 is GONE. Its predicate was the ABSENCE of one exact three-token
    # literal from the bootstrap source, so reordering the arguments or
    # writing ${Account} instead of ${User} defeated it without changing a
    # single permission. The property it named -- the export leaves no author
    # ACE on reviewer-src -- is measured directly by RI02 against the live
    # filesystem, ownership included.

    rec("RI08 head-binding-requires-pristine-tree",
        "status" in driver and "is not pristine" in driver,
        "the reviewer requires its source export to be pristine, so the head "
        "binding covers the bytes that run rather than a commit id")

    # RI09 EVALUATES the allowlist the session would build, for both states of
    # the sealed-credential file. Asserting that the token "$CredentialStages"
    # appears somewhere said nothing about whether those stages are reachable.
    closed, opened = credential_stage_reachability()
    rec("RI09 credential-stages-close",
        closed is not None and not closed and bool(opened),
        f"the allowlist the session builds excludes cred-seal once a sealed "
        f"credential exists (reachable={closed}) and includes it before one does "
        f"(reachable={opened}), so the one-time stages genuinely close")

    # The residual is reported, not hidden.
    admins_write = "*S-1-5-32-544:(OI)(CI)F" in bootstrap
    # RI10 is GONE, not rewritten.
    #
    # Its replacement still reduced to `admins_write` -- a string-presence test
    # that passes when the grant exists and would pass harder if more were
    # added. It cannot establish "only", which is the word it claimed. The
    # residual it described is real and is stated in this module's docstring;
    # what BOUNDS it is RI16, which measures rather than narrates. A check that
    # rewards the defect it describes is worse than no check, twice over.


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


def author_task_rights(*, drop_token: bool = False) -> dict:
    """What the author's ordinary identity may do to the reviewer's task object.

    `schtasks /Run` is the entire author-to-reviewer control channel, so two
    opposite things must both hold: the author must be able to START the task
    without elevation, and must not be able to MODIFY it.

    Rewritten because the previous version never read the descriptor at all.
    Two defects, either of which was enough: the folder path arrived as four
    backslashes rather than one, so GetFolder threw FileNotFoundException; and
    the whoami invocation, passed through -Command, reached PowerShell with its
    quotes intact and was not a command. Neither killed the script -- it emitted
    an all-False document, `if not rights:` did not fire because that dict is
    truthy, and RI18 recorded PASS on the strength of an exception.

    So: the harness is a FILE run with -File, and it fails LOUDLY. Effective
    rights are the union of allow ACEs over the token's non-deny SIDs, minus
    deny ACEs, with generic bits mapped and ownership counted -- an ACL
    computation rather than a real AuthzAccessCheck, which is why RI16 exists.
    """

    work = Path(tempfile.mkdtemp(prefix="mr-task-"))
    try:
        script = work / "rights.ps1"
        script.write_text("\n".join([
            "$ErrorActionPreference = 'Stop'",
            "$svc = New-Object -ComObject Schedule.Service",
            "$svc.Connect()",
            "$task = $svc.GetFolder('\\').GetTask('MR-OFFLINE-REVIEWER-RUN')",
            "$sd = New-Object Security.AccessControl.RawSecurityDescriptor(",
            "    $task.GetSecurityDescriptor(7))",
            "$rows = & \"$env:SystemRoot\System32\whoami.exe\" /groups /fo csv |",
            "    ConvertFrom-Csv",
            "$me = [Security.Principal.WindowsIdentity]::GetCurrent()",
            "$sids = New-Object System.Collections.Generic.List[string]",
            "$sids.Add($me.User.Value)",
            "foreach ($r in $rows) {",
            "  if ($r.Attributes -notlike '*deny*') { $sids.Add($r.SID) } }",
            "$allow = 0; $deny = 0",
            "foreach ($a in $sd.DiscretionaryAcl) {",
            "  if (-not $sids.Contains($a.SecurityIdentifier.Value)) { continue }",
            "  $m = $a.AccessMask",
            "  if ($m -band 0x10000000) { $m = $m -bor 0x1F01FF }",
            "  if ($m -band 0x40000000) { $m = $m -bor 0x0116 }",
            "  if ($m -band 0x20000000) { $m = $m -bor 0x20 -bor 0x80 -bor 0x20000 }",
            "  if ($a.AceType -eq 'AccessAllowed') { $allow = $allow -bor $m }",
            "  else { $deny = $deny -bor $m } }",
            "$effective = $allow -band (-bnot $deny)",
            "$owns = $false",
            "if ($sd.Owner) { $owns = $sids.Contains($sd.Owner.Value) }",
            "if ($owns) { $effective = $effective -bor 0x40000 }",
            "@{ readable = $true",
            "   present = ($effective -ne 0)",
            "   may_start = [bool]($effective -band 0x20)",
            "   may_modify = [bool]($effective -band 0xD0116)",
            "   owns_task = [bool]$owns } | ConvertTo-Json -Compress",
        ]), encoding="utf-8")
        shell = (Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
                 / "WindowsPowerShell" / "v1.0" / "powershell.exe")
        # Measured through the SAME dropped token the write probes use, not
        # through whatever token the guard happens to hold.
        #
        # Measuring with an elevated token answered "can an administrator start
        # this task", which is not the question RI17 and RI18 ask -- and it
        # reported PASS for a property that is false, since the live descriptor
        # carries no author ACE at all and an ordinary token's effective mask is
        # zero.
        if drop_token:
            out = work / "rights.json"
            runner = work / "run.cmd"
            runner.write_text(
                "@echo off\r\n"
                '"%s" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%s" > "%s" 2>nul\r\n'
                % (shell, script, out), encoding="ascii")
            subprocess.run(["runas.exe", "/trustlevel:0x20000", str(runner)],
                           capture_output=True, text=True, timeout=180)
            for _ in range(60):
                if out.is_file() and out.read_text(encoding="utf-8", errors="ignore").strip():
                    break
                time.sleep(1)
            text = out.read_text(encoding="utf-8", errors="ignore") if out.is_file() else ""
        else:
            proc = subprocess.run([str(shell), "-NoProfile", "-NonInteractive",
                                   "-ExecutionPolicy", "Bypass", "-File", str(script)],
                                  capture_output=True, text=True, timeout=180)
            text = proc.stdout or ""
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{"):
                return json.loads(line)
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

    # Is this measurement authoritative, or only indicative?
    #
    # When the guard is already unprivileged it probes with its own token and
    # the answer is the real one. When it is elevated it has to drop a token
    # with `runas /trustlevel:0x20000`, and that token is NOT a faithful stand-in:
    # it removes administrative privilege but keeps a HIGH integrity label, so
    # any protection resting on the mandatory label rather than on the DACL
    # would be measured as absent when it is present. Measured directly rather
    # than assumed -- the two tokens were compared against the same paths.
    author = author_process_elevated()
    self_elevated = bool(author.get("in_admin_role")) or bool(author.get("can_write_system_root"))
    # An earlier version appended "[INDICATIVE ONLY]" to the DETAIL and still
    # recorded the check as PASS. That is worse than not measuring: the reader is
    # told the boundary held, in a check named for exactly that, on the strength
    # of a token the same paragraph calls unfaithful. When the measurement cannot
    # be trusted the result is not a pass.
    qualifier = ("" if not self_elevated else
                 " [UNPROVEN: measured through a dropped token that keeps a High "
                 "integrity label, because this guard is running elevated]")
    trustworthy = not self_elevated

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
            trustworthy and measured.get(key) is False,
            f"an ordinary author token cannot write the {label}{qualifier}")

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
            trustworthy and observed is False,
            f"an ordinary author token cannot write the {label} "
            f"(observed={observed!r}){qualifier}")

    # The gate itself. Everything above describes what an UNPRIVILEGED author
    # cannot do; none of it constrains a privileged one.
    if not author:
        rec("RI16 author-process-elevation-measurable", False,
            "the authoring process's own privilege level could not be measured, "
            "so separation is unproven rather than proven")
        return
    elevated = bool(author.get("in_admin_role")) or bool(author.get("can_write_system_root"))
    # The control channel, from both sides.
    # Elevated: use the dropped token, and label the result unproven exactly as
    # RI13/RI15 are. Already unprivileged: the guard's token IS the author's, so
    # measure directly and mean it.
    #
    # "No rights" and "could not look" also stop being the same answer here. The
    # previous version treated an all-zero mask as a failed measurement, which
    # meant the check could never state the truth in either mode: elevated it
    # over-reported, and honest it refused to report at all.
    rights = author_task_rights(drop_token=self_elevated)
    if not rights or rights.get("readable") is not True:
        rec("RI17 author-task-rights-measurable", False,
            f"the reviewer task's security descriptor could not be read by the "
            f"measuring token ({rights or 'no document'}), so the control "
            f"channel's boundary is unproven rather than proven")
    else:
        rec("RI17 author-may-start-the-reviewer-task",
            trustworthy and rights.get("may_start") is True,
            "the author's ordinary identity can start the reviewer task, so the "
            "protocol is drivable without elevation "
            f"(may_start={rights.get('may_start')}){qualifier}")
        rec("RI18 author-may-not-modify-the-reviewer-task",
            trustworthy and rights.get("may_modify") is False
            and rights.get("owns_task") is False,
            "the author's ordinary identity cannot rewrite the task action, so it "
            "cannot point the reviewer's session at code of its own choosing "
            f"(may_modify={rights.get('may_modify')}, "
            f"owns_task={rights.get('owns_task')}){qualifier}")

    rec("RI16 author-process-not-elevated", not elevated,
        "the process performing certification holds no administrative rights "
        f"(in_admin_role={author.get('in_admin_role')}, "
        f"can_write_system_root={author.get('can_write_system_root')}); "
        "an elevated author can take ownership back and rewrite reviewer code, "
        "which would make every other check in this guard decorative")


def multiline_path_literals(paths: list) -> list:
    """String literals that span more than one line and look like paths.

    Asks the PowerShell parser rather than counting quotes: prose in comments is
    full of apostrophes, and the quote-counting first attempt flagged the file
    headers of every script while finding none of the real damage.

    Selection is by EXTENT -- does the literal start and end on different lines
    -- because that needs no pattern at all. The first AST version matched the
    literal's VALUE against a newline character class, and the class did not
    survive being written through Python into PowerShell, so it silently matched
    nothing and the check reported clean against a deliberately broken fixture.
    Filtering for path shape happens here, in one language.
    """

    if not paths:
        return []
    work = Path(tempfile.mkdtemp(prefix="mr-ast-"))
    try:
        script = work / "ast.ps1"
        # No trailing comma: PowerShell rejects `@( 'x', )` outright, and the
        # parser error went to stderr while the helper read only stdout -- so a
        # syntactically dead script reported every file clean.
        lines = ["$files = @("]
        lines.append(",\n".join("  '%s'" % path for path in paths))
        lines += [
            ")",
            "foreach ($f in $files) {",
            "  $errs = $null",
            "  $ast = [System.Management.Automation.Language.Parser]::ParseFile(",
            "      $f, [ref]$null, [ref]$errs)",
            "  if (-not $ast) { continue }",
            "  $strings = $ast.FindAll({ param($n)",
            # Interpolating literals are a DIFFERENT AST type, and they are the
            # shape most path construction in these scripts actually uses --
            # "$Root\\reviewer-bin", "$HvRoot\\reviewer-src". Matching only the
            # constant type meant the detector could not see the damage most
            # likely to occur here, and its self-test passed because the fixture
            # used the one shape it could see.
            "      ($n -is [System.Management.Automation.Language.StringConstantExpressionAst])",
            "      -or ($n -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) },",
            "      $true)",
            "  foreach ($s in $strings) {",
            "    if ($s.Extent.StartLineNumber -ne $s.Extent.EndLineNumber) {",
            "      $leaf = Split-Path $f -Leaf",
            # Nothing is flattened and nothing is pattern-matched. The previous
            # version called Value.Replace([char]13, '<CR>'), which binds the
            # (char, char) overload and THROWS -- so the whole walk died, printed
            # no rows, and the check reported every file clean against a
            # deliberately broken fixture. A single boolean is emitted instead.
            # Extent text, not Value: an interpolating literal's Value does not
            # contain the $-reference, so a path built from one would not look
            # like a path.
            "      $hasSep = ($s.Extent.Text.IndexOf([char]92) -ge 0)",
            "      Write-Output ($leaf + '|' + $s.Extent.StartLineNumber + '|' + $hasSep)",
            "    } } }",
        ]
        script.write_text("\n".join(lines), encoding="utf-8")
        shell = (Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
                 / "WindowsPowerShell" / "v1.0" / "powershell.exe")
        proc = subprocess.run([str(shell), "-NoProfile", "-NonInteractive",
                               "-ExecutionPolicy", "Bypass", "-File", str(script)],
                              capture_output=True, text=True, timeout=300)
        found = []
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if line.count("|") != 2:
                continue
            name, number, has_separator = line.split("|", 2)
            # A multi-line here-string is ordinary PowerShell; a multi-line PATH
            # is the damage.
            if has_separator.strip().lower() == "true":
                found.append((name, f"line {number}: a path literal spans lines"))
        return found
    except (OSError, subprocess.SubprocessError):
        return [("<unmeasurable>", "the PowerShell parser could not be run")]
    finally:
        shutil.rmtree(work, ignore_errors=True)


def source_integrity_battery() -> None:
    """Reviewer scripts must not carry mangled paths or stray control bytes.

    This is not stylistic. Generating PowerShell from Python repeatedly wrote a
    BEL byte for a backslash-a and a CR byte for a backslash-r, so
    `backend\\app\\...` and `C:\\mr-hv\\reviewer-pkg` became unresolvable
    strings. The integrity gate hashes what it finds and skipped what it did
    not, so the manifest adopted WITHOUT the module that verifies signatures and
    WITHOUT the staged package tree -- and every run reported VERIFIED. The pin
    looked complete and covered less than it claimed.

    A stray CR is included because it is invisible in most diffs and splits a
    line in any text-mode reader, which is how the damage stayed hidden.
    """

    targets = [
        ROOT / "packaging" / "hyperv" / "reviewer_session.ps1",
        ROOT / "packaging" / "hyperv" / "reviewer_bootstrap.ps1",
        ROOT / "packaging" / "hyperv" / "reviewer_credential_migration.ps1",
        ROOT / "packaging" / "hyperv" / "reviewer_diagnostics.ps1",
        ROOT / "packaging" / "hyperv" / "verify_author_boundary.ps1",
        ROOT / "scripts" / "offline_reviewer_execute.py",
        ROOT / "scripts" / "offline_reviewer_runtime.py",
        ROOT / "scripts" / "offline_issuance_broker.py",
        ROOT / "scripts" / "offline_hyperv_matrix.py",
    ]
    damaged = []
    for path in targets:
        if not path.is_file():
            damaged.append(f"{path.name} (absent)")
            continue
        raw = path.read_bytes()
        control = sorted({b for b in raw if b < 32 and b not in (9, 10, 13)})
        stray_cr = raw.count(b"\r") - raw.count(b"\r\n")
        # A stray CR does not survive to be found. Git and every text-mode write
        # normalise it into a CRLF, after which the byte sweep sees nothing and
        # the literal is still broken -- which is what happened to the re-pin
        # action's manifest path, silently disabling the only supported remedy
        # for a refused run. The damage that survives is a string literal with a
        # line break inside it, so that is what is looked for.
        #
        # Counting quotes per line does NOT find it: prose in comments is full
        # of apostrophes, and the first attempt flagged the file header. The
        # PowerShell parser is asked instead, because it is the thing that
        # decides what a literal is.
        if control or stray_cr:
            damaged.append(f"{path.name} (control={[hex(c) for c in control]}, "
                           f"stray_cr={stray_cr})")
    multiline = multiline_path_literals(
        [t for t in targets if t.is_file() and t.suffix.lower() == ".ps1"])
    for name, value in multiline:
        damaged.append(f"{name} (path literal spans lines: {value!r})")
    # The detector proves itself on every run.
    #
    # Two earlier versions of this check reported every file clean while a
    # deliberately broken fixture sat in front of them -- once because a
    # String.Replace overload threw, once because the generated array had a
    # trailing comma PowerShell rejects, and both times the error went to stderr
    # while only stdout was read. A detector that has never been seen to fire is
    # not evidence of anything.
    probe = Path(tempfile.mkdtemp(prefix="mr-ri19-"))
    try:
        sep = bytes([92])          # a backslash, assembled rather than escaped
        cr = bytes([13])
        nl = bytes([10])
        clean = probe / "clean.ps1"
        clean.write_bytes(b"$m = Join-Path $R 'reviewer" + sep + b"state"
                          + sep + b"manifest.json'" + nl)
        broken = probe / "broken.ps1"
        broken.write_bytes(b"$m = Join-Path $R 'reviewer" + sep + b"state" + cr + nl
                           + b"eviewer-code-manifest.json'" + nl)
        fires = bool(multiline_path_literals([broken]))
        quiet = not multiline_path_literals([clean])
    finally:
        shutil.rmtree(probe, ignore_errors=True)
    rec("RI19a damage-detector-actually-fires", fires and quiet,
        f"the detector reports a deliberately mangled path literal (fired={fires}) "
        f"and stays silent on an equivalent intact one (quiet={quiet})")

    rec("RI19 reviewer-source-free-of-control-byte-damage", not damaged,
        f"no reviewer script carries a stray control byte or bare CR that would "
        f"turn a declared path into an unresolvable one ({damaged or 'clean'})")


def runtime_battery() -> None:
    """The reviewer must run a dedicated task-owned runtime, not a shared one."""

    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        from offline_reviewer_runtime import RUNTIME_ROOT, TASK_ROOT, verify
    except ImportError as exc:
        rec("RI20 runtime-contract-importable", False,
            f"the runtime contract could not be loaded ({type(exc).__name__}), so "
            f"the interpreter the reviewer runs is unverified")
        return

    pin = REVIEWER_STATE / "python-path.txt"
    if not pin.is_file():
        rec("RI20 reviewer-runtime-pinned", False,
            "the reviewer has no interpreter pin, so the operator runtime step "
            "has not run")
        return
    try:
        pinned = Path(pin.read_text(encoding="utf-8").strip())
    except OSError:
        rec("RI20 reviewer-runtime-pinned", False, "the interpreter pin is unreadable")
        return

    inside = False
    try:
        pinned.resolve().relative_to(RUNTIME_ROOT.resolve())
        inside = True
    except (ValueError, OSError):
        inside = False
    rec("RI20 reviewer-runtime-is-task-owned", inside,
        "the pinned interpreter resolves inside the task-owned runtime root "
        "rather than a shared or per-user Python installation")

    reasons = verify(pinned, task_root=TASK_ROOT, runtime_root=RUNTIME_ROOT)
    rec("RI21 reviewer-runtime-accepted", not reasons,
        f"the pinned runtime satisfies the dedicated-runtime contract "
        f"(reasons={reasons or 'none'})")


def main() -> int:
    CHECKS.clear()
    acl_battery()
    secret_battery()
    contract_battery()
    source_integrity_battery()
    runtime_battery()
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
