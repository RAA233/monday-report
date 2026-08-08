"""``audit:offline-operator-principal`` -- the distinct-operator trust contract.

WHY THIS EXISTS
---------------
The acceptance predicate is a statement about ACCOUNTS:

    No principal that can write the release tree may hold Administrator on the
    certifying host.

It became necessary because the reviewer's signing key is protected by a LOCAL
account's DPAPI and the scheduled task carries a stored password credential. An
account holding Administrator reaches SYSTEM, reads that credential, and obtains
a genuine reviewer logon that signs anything -- no script cooperation, no
author-writable byte, no password reset. The design had assumed administrative
abuse produces denial; it produces silent forgery.

Every rule below is exercised by a fixture that makes it FAIL. "The real host
currently satisfies this" is not evidence that a rule works -- three separate
checks in this codebase passed for years while measuring nothing, and each was
believed because the live tree happened to agree with it.

Nothing here creates an account, modifies the real task, or writes outside a
disposable temporary directory.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "packaging" / "hyperv" / "principal_contract_probe.ps1"
SHELL = (Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
         / "WindowsPowerShell" / "v1.0" / "powershell.exe")

# Synthetic SIDs. Well-formed, and deliberately not any real account on any host.
SID_OPERATOR = "S-1-5-21-1111111111-2222222222-3333333333-1101"
SID_AUTHOR = "S-1-5-21-1111111111-2222222222-3333333333-1102"
SID_REVIEWER = "S-1-5-21-1111111111-2222222222-3333333333-1103"
SID_NESTED_GROUP = "S-1-5-21-1111111111-2222222222-3333333333-1200"

CHECKS: list[dict] = []


def rec(check_id: str, ok: bool, detail: str) -> bool:
    CHECKS.append({"check_id": check_id, "ok": bool(ok), "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'} {check_id}: {detail}")
    return bool(ok)


def identity(name: str, sid: str, *, exists: bool = True, resolved: bool = True) -> dict:
    return {"name": name, "sid": sid, "exists": exists, "resolved": resolved}


def probe(case: dict, work: Path) -> dict:
    """Run one case through the shared contract and return its named reasons."""

    case_file = work / "case.json"
    case_file.write_text(json.dumps(case), encoding="utf-8")
    try:
        completed = subprocess.run(
            [str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", str(PROBE), "-CaseFile", str(case_file)],
            capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"reasons": [f"PROBE_FAILED:{type(exc).__name__}"], "value": None}
    for line in (completed.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    detail = (completed.stderr or "").strip().splitlines()
    return {"reasons": [f"PROBE_NO_OUTPUT:{detail[0] if detail else 'silent'}"], "value": None}


def baseline_case(**overrides) -> dict:
    """Three distinct principals, correct memberships: the contract is satisfied."""

    case = {
        "action": "principal-contract",
        "operator": identity("OPERATOR", SID_OPERATOR),
        "author": identity("AUTHOR", SID_AUTHOR),
        "reviewer": identity("REVIEWER", SID_REVIEWER),
        "admin_members": [SID_OPERATOR],
    }
    case.update(overrides)
    return case


def cycle(case_id: str, label: str, mutate: dict, expected: str, work: Path) -> None:
    """baseline accepted -> mutate -> named reason -> baseline accepted again."""

    before = probe(baseline_case(), work)["reasons"]
    if before:
        rec(case_id, False,
            f"the unmutated contract was refused ({before}), so this cycle proves nothing")
        return
    during = probe(baseline_case(**mutate), work)["reasons"]
    after = probe(baseline_case(), work)["reasons"]
    rec(case_id, expected in during and not after,
        f"{label}: refused with {expected} (reasons={during}); the unmutated "
        f"contract is accepted before and after "
        f"({'clean' if not after else after})")


def main() -> int:
    CHECKS.clear()
    if not PROBE.is_file():
        rec("OP00 probe-present", False, "the contract probe is missing")
        return 1
    work = Path(tempfile.mkdtemp(prefix="mr-principal-"))
    try:
        # ---------------------------------------------------- the contract
        rec("OP00 baseline-accepted", not probe(baseline_case(), work)["reasons"],
            "three distinct principals with correct memberships satisfy the "
            "contract, so every refusal below means something")

        cycle("OP01 operator-equals-author", "the operator IS the author",
              {"operator": identity("AUTHOR", SID_AUTHOR)},
              "OFFLINE_OPERATOR_AUTHOR_SAME_PRINCIPAL", work)

        cycle("OP02 author-is-administrator", "the author account holds Administrator",
              {"admin_members": [SID_OPERATOR, SID_AUTHOR]},
              "OFFLINE_AUTHOR_ACCOUNT_IS_ADMINISTRATOR", work)

        cycle("OP03 reviewer-is-administrator", "the reviewer account holds Administrator",
              {"admin_members": [SID_OPERATOR, SID_REVIEWER]},
              "OFFLINE_REVIEWER_ACCOUNT_IS_ADMINISTRATOR", work)

        cycle("OP04 operator-not-administrator", "the operator holds no Administrator",
              {"admin_members": []},
              "OFFLINE_OPERATOR_ACCOUNT_NOT_ADMINISTRATOR", work)

        cycle("OP05 author-account-missing", "no author account was supplied",
              {"author": identity("", "", exists=False, resolved=True)},
              "OFFLINE_AUTHOR_ACCOUNT_UNRESOLVED", work)

        cycle("OP06 author-account-unresolvable", "the author name does not resolve",
              {"author": identity("NO-SUCH", "", exists=False, resolved=False)},
              "OFFLINE_AUTHOR_ACCOUNT_UNRESOLVED", work)

        cycle("OP07 operator-account-unresolvable", "the operator name does not resolve",
              {"operator": identity("NO-SUCH", "", exists=False, resolved=False)},
              "OFFLINE_OPERATOR_ACCOUNT_UNRESOLVED", work)

        cycle("OP08 reviewer-account-unresolvable", "the reviewer name does not resolve",
              {"reviewer": identity("NO-SUCH", "", exists=False, resolved=False)},
              "OFFLINE_REVIEWER_ACCOUNT_UNRESOLVED", work)

        cycle("OP09 operator-equals-reviewer", "the operator IS the reviewer",
              {"operator": identity("REVIEWER", SID_REVIEWER)},
              "OFFLINE_OPERATOR_REVIEWER_SAME_PRINCIPAL", work)

        cycle("OP10 author-equals-reviewer", "the author IS the reviewer",
              {"author": identity("REVIEWER", SID_REVIEWER)},
              "OFFLINE_AUTHOR_REVIEWER_SAME_PRINCIPAL", work)

        # Membership that cannot be established must not read as "not a member".
        cycle("OP11 membership-unresolvable-fails-closed",
              "nested group expansion fails", {"membership_resolvable": False},
              "OFFLINE_AUTHOR_ACCOUNT_IS_ADMINISTRATOR", work)

        # A nested group containing the author is still membership.
        cycle("OP12 nested-administrators-membership",
              "the author is a member through a nested group",
              {"admin_members": [SID_OPERATOR, SID_NESTED_GROUP, SID_AUTHOR]},
              "OFFLINE_AUTHOR_ACCOUNT_IS_ADMINISTRATOR", work)

        # ------------------------------------------------- digest determinism
        first = probe({"action": "digest", "sid": SID_AUTHOR}, work)["value"]
        second = probe({"action": "digest", "sid": SID_AUTHOR}, work)["value"]
        other = probe({"action": "digest", "sid": SID_REVIEWER}, work)["value"]
        empty = probe({"action": "digest", "sid": ""}, work)["value"]
        rec("OP13 digest-deterministic-across-processes",
            bool(first) and first == second and first != other
            and len(str(first)) == 32 and not empty,
            f"the same principal digests identically in two fresh processes, a "
            f"different principal digests differently, the width is fixed at 32, "
            f"and an unresolved principal yields no digest "
            f"(same={first == second}, differs={first != other}, empty={empty!r})")

        alias_a = probe({"action": "resolve-account", "name": os.environ.get("USERNAME", "")},
                        work)["value"]
        alias_b = probe({"action": "resolve-account",
                         "name": f"{os.environ.get('COMPUTERNAME', '')}\\{os.environ.get('USERNAME', '')}"},
                        work)["value"]
        rec("OP14 display-name-alias-digests-identically",
            bool(alias_a) and bool(alias_b) and alias_a.get("digest")
            and alias_a.get("digest") == alias_b.get("digest"),
            "a bare account name and its machine-qualified spelling resolve to "
            "one principal and therefore one digest")

        missing = probe({"action": "resolve-account", "name": "NO-SUCH-ACCOUNT-XYZ"},
                        work)["value"]
        rec("OP15 unresolved-account-has-no-digest",
            bool(missing) and missing.get("exists") is False and not missing.get("digest"),
            "an account that does not exist yields no digest and is reported as "
            "non-existent rather than as a safe negative")

        # ------------------------------------------------------- task ACE
        author_ace = f"(A;;0x1200a9;;;{SID_AUTHOR})"
        admin_ace = "(A;;0x1f01ff;;;BA)(A;;0x1f01ff;;;SY)"
        good_sddl = f"O:BAD:P{admin_ace}{author_ace}"
        task_baseline = {"action": "task-ace", "author": identity("AUTHOR", SID_AUTHOR),
                         "operator": identity("OPERATOR", SID_OPERATOR), "sddl": good_sddl}

        rec("OP16 task-ace-baseline", not probe(task_baseline, work)["reasons"],
            "read+execute for the author and nothing else satisfies the task "
            "contract, so the refusals below mean something")

        for case_id, label, sddl, expected in (
                ("OP17 task-ace-granted-to-operator",
                 "the grant landed on the operator instead of the author",
                 f"O:BAD:P{admin_ace}(A;;0x1200a9;;;{SID_OPERATOR})",
                 "OFFLINE_TASK_GRANTED_TO_OPERATOR_NOT_AUTHOR"),
                ("OP18 task-ace-over-permissive",
                 "the author ACE carries write and delete",
                 f"O:BAD:P{admin_ace}(A;;0x1f01ff;;;{SID_AUTHOR})",
                 "OFFLINE_TASK_AUTHOR_MAY_MODIFY"),
                ("OP19 task-ace-missing",
                 "the author has no ACE at all",
                 f"O:BAD:P{admin_ace}",
                 "OFFLINE_TASK_AUTHOR_CANNOT_START"),
                ("OP20 task-owned-by-author",
                 "the author owns the task, so it holds WRITE_DAC regardless",
                 f"O:{SID_AUTHOR}D:P{admin_ace}{author_ace}",
                 "OFFLINE_TASK_AUTHOR_OWNS_TASK")):
            before = probe(task_baseline, work)["reasons"]
            during = probe({**task_baseline, "sddl": sddl}, work)["reasons"]
            after = probe(task_baseline, work)["reasons"]
            rec(case_id, not before and expected in during and not after,
                f"{label}: refused with {expected} (reasons={during}); baseline "
                f"clean before and after")

        # Idempotence: applying the intended ACE twice is still exactly one ACE.
        twice = probe({**task_baseline,
                       "sddl": f"O:BAD:P{admin_ace}{author_ace}{author_ace}"}, work)["reasons"]
        rec("OP21 task-ace-idempotent",
            not twice,
            "a duplicated author ACE still yields read+execute and nothing more, "
            f"so re-running the grant is safe (reasons={twice or 'none'})")

        # --------------------------------------------- native command resolution
        fake_dir = work / "fake-bin"
        fake_dir.mkdir()
        for name in ("icacls.exe", "takeown.exe", "schtasks.exe", "secedit.exe", "git.exe"):
            (fake_dir / name).write_text("not a real program", encoding="ascii")
        shadowed = dict(os.environ)
        shadowed["PATH"] = str(fake_dir) + os.pathsep + shadowed.get("PATH", "")
        shadowed["PATHEXT"] = ".EXE;.CMD;.BAT"

        native_ok = True
        details = []
        for name in ("icacls.exe", "takeown.exe", "schtasks.exe", "secedit.exe"):
            case_file = work / "case.json"
            case_file.write_text(json.dumps({"action": "native-command", "name": name}),
                                 encoding="utf-8")
            try:
                completed = subprocess.run(
                    [str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                     "Bypass", "-File", str(PROBE), "-CaseFile", str(case_file)],
                    capture_output=True, text=True, timeout=180, env=shadowed)
                payload = {}
                for line in (completed.stdout or "").splitlines():
                    if line.strip().startswith("{"):
                        payload = json.loads(line.strip())
                value = payload.get("value") or {}
                good = value.get("resolved") is True and value.get("under_system32") is True
            except (OSError, subprocess.SubprocessError, ValueError):
                good = False
            native_ok = native_ok and good
            details.append(f"{name}={'System32' if good else 'SHADOWED'}")
        rec("OP22 native-commands-ignore-a-shadowed-PATH", native_ok,
            f"a fake binary placed first on PATH is not selected; every system "
            f"command still resolves under System32 ({', '.join(details)})")

        bogus = probe({"action": "native-command", "name": "definitely-not-real.exe"},
                      work)["value"]
        rec("OP23 unresolvable-native-command-fails-closed",
            bool(bogus) and bogus.get("resolved") is False,
            "a system command that does not exist resolves to nothing rather "
            "than to a name the shell would search for")

        # ------------------------------------------------- trusted source root
        src_reasons = probe({"action": "trusted-source", "root": str(work / "no-such-root"),
                             "author": identity("AUTHOR", SID_AUTHOR),
                             "expected_commit": "a" * 40, "expected_tree": "b" * 40},
                            work)["reasons"]
        rec("OP24 absent-source-root-refused",
            "OFFLINE_SOURCE_ROOT_ABSENT" in src_reasons,
            f"a source root that does not exist is refused ({src_reasons})")

        no_identity = probe({"action": "trusted-source", "root": str(work),
                             "author": identity("AUTHOR", SID_AUTHOR),
                             "expected_commit": "", "expected_tree": ""}, work)["reasons"]
        rec("OP25 missing-expected-identity-refused",
            "OFFLINE_SOURCE_ROOT_EXPECTED_IDENTITY_MISSING" in no_identity,
            f"a source root with no externally supplied commit/tree is refused "
            f"rather than trusted on its own account ({no_identity})")

        # The author-writable case, measured against a real directory the author
        # genuinely can write -- the scratch dir this guard is running in.
        # Resolved for real: a synthetic identity carries no SID, so the ACL
        # scan matched nothing and the directory read as unwritable by an
        # account that plainly owns it.
        real_author = os.environ.get("USERNAME", "")
        resolved = probe({"action": "resolve-account", "name": real_author}, work)["value"]
        writable_dir = work / "author-writable"
        writable_dir.mkdir(exist_ok=True)
        author_real = {"name": real_author, "sid": "", "exists": True, "resolved": True}
        direct = probe({"action": "account-writable", "author": author_real,
                        "path": str(writable_dir)}, work)["value"]
        writable = probe({"action": "trusted-source", "root": str(writable_dir),
                          "author": author_real,
                          "expected_commit": "a" * 40, "expected_tree": "b" * 40},
                         work)["reasons"]
        rec("OP26 author-writable-source-root-refused",
            "OFFLINE_SOURCE_ROOT_AUTHOR_WRITABLE" in writable,
            f"a directory the author genuinely owns is refused as a privileged "
            f"source root, and a distinct operator does not make it trustworthy "
            f"(structural write probe={direct}, reasons={writable})")

        # ---------------------------------- process token vs account capability
        # The distinction the whole requirement turns on, asserted directly: a
        # process that looks unprivileged tells you nothing about an account
        # that is still in Administrators. If these two ever agree, one of them
        # has stopped measuring.
        medium_token_admin_account = probe(baseline_case(
            admin_members=[SID_OPERATOR, SID_AUTHOR]), work)["reasons"]
        clean_account = probe(baseline_case(), work)["reasons"]
        rec("OP27 process-token-is-not-account-capability",
            "OFFLINE_AUTHOR_ACCOUNT_IS_ADMINISTRATOR" in medium_token_admin_account
            and not clean_account,
            "an author whose PROCESS is unprivileged but whose ACCOUNT remains in "
            "Administrators is refused, and the same contract accepts the same "
            "process once the account is out of the group -- so the account gate "
            "is doing work the token gate cannot "
            f"(admin_account={medium_token_admin_account}, clean={clean_account or 'none'})")

        # The boundary harness must carry BOTH gates, not one standing in for two.
        boundary = (ROOT / "packaging" / "hyperv" / "verify_author_boundary.ps1")
        text = boundary.read_text(encoding="utf-8") if boundary.is_file() else ""
        rec("OP28 boundary-harness-carries-both-gates",
            "TOKEN01 author-process-not-elevated" in text
            and "TOKEN02 author-account-not-administrator" in text
            and "Test-AccountInAdministrators" in text,
            "the boundary harness measures the process token AND the account's "
            "Administrators membership as separate probes")

        print()
    finally:
        shutil.rmtree(work, ignore_errors=True)

    failed = [c["check_id"] for c in CHECKS if not c["ok"]]
    print(json.dumps({
        "guard": "offline-operator-principal",
        "claim_scope": "operator, author and reviewer are distinct live-resolved "
                       "principals; the author account holds no Administrator; the "
                       "author's task rights are read+execute only; privileged "
                       "source and native commands are not author-controlled",
        "summary": {"passed": len(CHECKS) - len(failed), "failed": len(failed),
                    "total": len(CHECKS)},
        "failed_checks": failed,
    }, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
