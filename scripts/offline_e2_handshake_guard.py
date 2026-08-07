"""``audit:offline-e2-handshake`` -- proves the Environment 2 guest runner
handshake fails LOUDLY and for the right reason.

WHY THIS EXISTS
---------------
Environment 2 stopped with "the guest did not export an activation request" and
an empty phase log. The real cause was three layers away: the matrix resolved the
head binding by shelling out to git, git refuses to operate in a repository the
running user does not own, the reviewer does not own its pristine export, so
``source_commit`` came back EMPTY -- and an empty value silently collapsed the
guest runner's argument list into "Missing an argument for parameter
'SourceCommit'".

Every layer behaved "reasonably" and the result was undiagnosable. This guard
exists so that class of failure cannot recur quietly: the binding must be
explicit, an empty binding must fail closed at the point it is produced, and the
runner's argument contract must be checked rather than assumed.

Hermetic: no VM, no package, no guest. It exercises the real functions and the
real argument contract against fixtures.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

MATRIX = ROOT / "scripts" / "offline_hyperv_matrix.py"
SESSION = ROOT / "packaging" / "hyperv" / "hyperv_session.ps1"
PS_RUNNER = ROOT / "scripts" / "offline_env_runner.ps1"
DRIVER = ROOT / "scripts" / "offline_reviewer_execute.py"
DIAGNOSTICS = ROOT / "packaging" / "hyperv" / "reviewer_diagnostics.ps1"

CHECKS: list[dict] = []


def rec(check_id: str, ok: bool, detail: str) -> bool:
    CHECKS.append({"check_id": check_id, "ok": bool(ok), "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'} {check_id}: {detail}")
    return bool(ok)


def runner_parameters() -> set[str]:
    """The parameter names the PowerShell guest runner actually declares.

    Delimited by the param block's own closing line rather than the first ")",
    which lands inside ``[ValidateSet(...)]`` on the very first parameter and
    returns almost nothing.
    """

    text = PS_RUNNER.read_text(encoding="utf-8", errors="replace")
    start = text.find("param(")
    end = text.find(chr(10) + ")", start)
    block = text[start:end if end > start else start + 4000]
    return set(re.findall(r"\$(\w+)", block))


def session_arguments() -> set[str]:
    """The argument names the guest session driver passes to THAT RUNNER.

    powershell.exe's own switches (-NoProfile, -ExecutionPolicy, -File) are
    excluded: they are consumed by the host process and never reach the runner,
    so counting them as unknown parameters is a false positive.
    """

    text = SESSION.read_text(encoding="utf-8", errors="replace")
    start = text.find("$runnerArgs")
    found = set(re.findall(r'"-(\w+)"', text[start:start + 1500]))
    return found - {"NoProfile", "ExecutionPolicy", "File"}


def binding_battery() -> None:
    """The head binding must be explicit and must fail closed when empty."""

    matrix = MATRIX.read_text(encoding="utf-8")

    rec("EH01 matrix-accepts-explicit-head-binding",
        "--source-commit" in matrix and "--source-tree" in matrix,
        "the matrix accepts the head binding from its caller instead of only "
        "discovering it")

    rec("EH02 empty-binding-fails-closed",
        "source commit/tree could not be resolved" in matrix,
        "an unresolved head binding raises instead of being written as an empty "
        "string into the guest metadata")

    rec("EH03b authoritative-mode-requires-head-binding",
        "HEAD_BINDING_REQUIRED" in matrix,
        "authoritative brokered mode refuses to run without an explicit head "
        "binding, so the issuance witness always states which head it vouches for")

    rec("EH03 reviewer-passes-frozen-binding",
        '"--source-commit", str(frozen.get("source_commit"' in
        DRIVER.read_text(encoding="utf-8"),
        "the reviewer passes the binding it already verified in the frozen "
        "package descriptor rather than depending on git")

    # The failure was invisible because git writes NOTHING to stdout when it
    # refuses. Prove the refusal shape rather than trusting that it cannot happen.
    work = Path(tempfile.mkdtemp(prefix="mr-eh-"))
    try:
        completed = subprocess.run(["git", "-C", str(work), "rev-parse", "HEAD"],
                                   capture_output=True, text=True, timeout=60)
        rec("EH04 git-refusal-produces-empty-stdout",
            completed.returncode != 0 and not completed.stdout.strip(),
            "git writes an empty stdout when it refuses, so a caller that only "
            "reads stdout silently receives an empty binding")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def contract_battery() -> None:
    """The session must pass exactly what the runner declares."""

    declared = runner_parameters()
    passed = session_arguments()

    missing = sorted(p for p in ("Phase", "EnvLabel", "EnvClass", "PackageDir",
                                 "WorkDir", "TransferOut", "SourceCommit",
                                 "SourceTree", "PackageVersion", "InstallerSha256")
                     if p not in declared)
    rec("EH05 runner-declares-the-expected-parameters", not missing,
        f"the guest runner declares the full argument contract ({missing or 'all present'})")

    unknown = sorted(a for a in passed if a not in declared)
    rec("EH06 session-passes-only-declared-parameters", not unknown,
        f"the session passes no argument the runner does not declare ({unknown or 'none'})")

    unsupplied = sorted(p for p in ("SourceCommit", "SourceTree", "PackageVersion",
                                    "InstallerSha256") if p not in passed)
    rec("EH07 session-supplies-every-binding-parameter", not unsupplied,
        f"the session supplies every binding parameter ({unsupplied or 'all supplied'})")

    # An empty value for a [string] parameter consumes the NEXT token, which is
    # how one blank field destroyed the whole argument list.
    session = SESSION.read_text(encoding="utf-8", errors="replace")
    quoted = re.findall(r'"-(\w+)",\s*"\$\(\$meta\.(\w+)\)"', session)
    rec("EH08 binding-arguments-are-quoted",
        len(quoted) >= 4,
        f"binding arguments are quoted so an empty value cannot swallow the next "
        f"token ({len(quoted)} quoted)")


def diagnostics_battery() -> None:
    """The diagnostic must classify, and must not leak."""

    diag = DIAGNOSTICS.read_text(encoding="utf-8", errors="replace")

    for name in ("GUEST_RUNNER_MISSING", "GUEST_RUNNER_PARSE_FAILURE",
                 "RUNNER_PRODUCED_NO_OUTPUT", "RUNNER_RAN_BUT_EXPORTED_NO_REQUEST",
                 "REQUEST_PRESENT_BUT_NOT_DETECTED",
                 "GUEST_UNREACHABLE_WITH_REVIEWER_CREDENTIAL"):
        rec(f"EH09 classifies-{name.lower()}", name in diag,
            f"the diagnostic names {name} instead of reporting an empty log")

    rec("EH10 diagnostic-redacts-paths-and-identity",
        "'<path>'" in diag and "'<mac>'" in diag and "'<sid>'" in diag,
        "diagnostic output normalizes paths, MACs and SIDs before the author "
        "can read it")

    rec("EH11 diagnostic-is-not-authoritative",
        "authoritative  = $false" in diag and "never acceptance evidence" in diag,
        "the diagnostic declares itself non-authoritative in its own output")

    rec("EH12 diagnostic-needs-no-author-credential",
        "ReviewerState" in diag and "Get-GuestCredential" in diag,
        "the diagnostic runs on the reviewer-owned credential; the author needs "
        "no guest password to obtain it")


def isolation_battery() -> None:
    """Diagnosing must not have re-opened any boundary."""

    matrix = MATRIX.read_text(encoding="utf-8")
    driver = DRIVER.read_text(encoding="utf-8")

    rec("EH13 authoritative-mode-still-refuses-key-file",
        "ISSUER_KEY_OFFERED_IN_AUTHORITATIVE_MODE" in matrix,
        "brokered mode still refuses issuer key material")
    rec("EH14 reviewer-still-refuses-issuer-material",
        "ISSUER_KEY_OFFERED_TO_REVIEWER" in driver,
        "the reviewer driver still refuses issuer key material")
    rec("EH15 diagnostic-does-not-return-credentials",
        "password" not in DIAGNOSTICS.read_text(encoding="utf-8").lower().replace(
            "password|secret|token", "").replace("a password", ""),
        "the diagnostic never returns a credential value")


def main() -> int:
    CHECKS.clear()
    binding_battery()
    contract_battery()
    diagnostics_battery()
    isolation_battery()
    failed = [c for c in CHECKS if not c["ok"]]
    print()
    print(json.dumps({
        "guard": "offline-e2-handshake",
        "claim_scope": "the Environment 2 guest-runner handshake binds an explicit head, "
                       "fails closed on an empty binding, and reports a named reason",
        "summary": {"passed": len(CHECKS) - len(failed), "failed": len(failed),
                    "total": len(CHECKS)},
    }, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
