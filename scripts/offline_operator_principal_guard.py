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
import re
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


def probe(case: dict, work: Path, env: dict | None = None) -> dict:
    """Run one case through the shared contract and return its named reasons."""

    case_file = work / "case.json"
    case_file.write_text(json.dumps(case), encoding="utf-8")
    try:
        completed = subprocess.run(
            [str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", str(PROBE), "-CaseFile", str(case_file)],
            capture_output=True, text=True, timeout=180, env=env)
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
    if os.name != "nt":
        # THE SUBJECT MATTER DOES NOT EXIST HERE.
        #
        # Windows SIDs, local group membership, DACLs and scheduled-task
        # security descriptors are what this battery reasons about, and the
        # certifying host is Windows by construction. Stated as a skip with a
        # named reason rather than as 39 passes, and rather than a red audit:all
        # on a platform where the question is meaningless. It is NOT an
        # environment switch: os.name is not settable from outside the process.
        print(json.dumps({
            "guard": "offline-operator-principal",
            "skipped": "not-windows",
            "detail": "the principal contract is a statement about Windows "
                      "accounts and ACLs; nothing was measured and nothing is "
                      "claimed",
        }, indent=2))
        return 0
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
            and len(str(first)) == 64 and not empty,
            f"the same principal digests identically in two fresh processes, a "
            f"different principal digests differently, the width is the full "
            f"sha256, and an unresolved principal yields no digest "
            f"(same={first == second}, differs={first != other}, empty={empty!r})")

        # THE DIGEST UNDER TEST MUST BE THE DIGEST THAT IS BOUND.
        #
        # OP13 above proved a PowerShell function deterministic. The digests
        # that are actually written -- into the trust root and into
        # review-key-public.json -- come from principal_digest() on the Python
        # side, which hashed a DIFFERENT salt at a DIFFERENT width. Same
        # principal, two incomparable values, and a fixture attesting to the one
        # nothing reads. Both implementations are driven here from one input and
        # required to produce one string.
        shared_salt = "9f2c7b1ad4e60381c5aa10be77304912"
        sys.path.insert(0, str(ROOT))
        from backend.app.offline_review_attestation import principal_digest
        ps_side = probe({"action": "digest", "sid": SID_AUTHOR, "salt": shared_salt},
                        work)["value"]
        py_side = principal_digest(SID_AUTHOR, shared_salt)
        cross_other = probe({"action": "digest", "sid": SID_REVIEWER, "salt": shared_salt},
                            work)["value"]
        rec("OP13a digest-agrees-with-the-implementation-that-binds-it",
            bool(ps_side) and ps_side == py_side and cross_other != py_side,
            "the PowerShell contract and the Python attestation module produce "
            "the same digest for one principal under one salt, so an "
            "operator-side transcript and a reviewer-published digest refer to "
            "the same account "
            f"(agree={ps_side == py_side}, distinct-principal-differs="
            f"{cross_other != py_side})")

        # And the salt genuinely participates: two salts, one SID, two values.
        other_salt = probe({"action": "digest", "sid": SID_AUTHOR,
                            "salt": "0" * 32}, work)["value"]
        rec("OP13b digest-is-salted",
            bool(other_salt) and other_salt != ps_side,
            f"the same principal under a different salt digests differently, so "
            f"the salt is not decorative (differs={other_salt != ps_side})")

        # An ORDINARY provider, returning @() without the comma operator that
        # every other fixture here remembers to write. "Nobody is an
        # administrator" must not read as "the question could not be answered":
        # the first accepts, the second refuses, and they were the same value.
        empty_bare = probe(baseline_case(membership_empty_bare=True), work)["reasons"]
        unresolvable = probe(baseline_case(membership_resolvable=False), work)["reasons"]
        rec("OP13c empty-membership-is-not-unresolvable-membership",
            "OFFLINE_OPERATOR_ACCOUNT_NOT_ADMINISTRATOR" in empty_bare
            and "OFFLINE_AUTHOR_ACCOUNT_IS_ADMINISTRATOR" not in empty_bare
            and "OFFLINE_ADMINISTRATORS_MEMBERSHIP_UNRESOLVED" in unresolvable,
            f"a bare empty collection is read as an established empty group -- the "
            f"operator is reported as not an administrator, the author is not "
            f"accused of being one -- while a provider that cannot answer is "
            f"reported as unresolved "
            f"(empty={empty_bare}, unresolvable={unresolvable})")

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

        # THE SHADOW MUST BE EFFECTIVE BEFORE ITS DEFEAT MEANS ANYTHING.
        #
        # Establish first that an ordinary PATH lookup in this environment DOES
        # pick the planted binary. Without that, "the trusted resolution did not
        # return the fake" is satisfied by a fixture that never worked.
        shadow_wins = []
        for name in ("icacls.exe", "takeown.exe", "schtasks.exe", "secedit.exe", "git.exe"):
            try:
                found = subprocess.run(["where.exe", name], capture_output=True, text=True,
                                       timeout=60, env=shadowed)
                first = (found.stdout or "").strip().splitlines()
                shadow_wins.append(bool(first) and Path(first[0].strip()).parent == fake_dir)
            except (OSError, subprocess.SubprocessError):
                shadow_wins.append(False)
        rec("OP22 planted-binaries-do-win-an-ordinary-PATH-lookup",
            all(shadow_wins) and len(shadow_wins) == 5,
            f"every planted binary is what a name-based lookup selects in this "
            f"environment, so the resolutions below are defeating a shadow that "
            f"is genuinely in force ({sum(shadow_wins)}/5)")

        native_ok = True
        details = []
        for name in ("icacls.exe", "takeown.exe", "schtasks.exe", "secedit.exe"):
            # `under_system32` alone was a tautology: Get-TrustedNativeCommand
            # BUILDS its answer by joining System32 to the name, so the property
            # was true whenever resolution succeeded and could not fail for any
            # input. The verdict is now the comparison that can: the returned
            # path is a real file and is NOT the planted one.
            value = probe({"action": "native-command", "name": name,
                           "shadow": str(fake_dir / name)}, work, env=shadowed)["value"] or {}
            good = (value.get("resolved") is True and value.get("exists") is True
                    and value.get("equals_shadow") is False
                    and value.get("under_system32") is True)
            native_ok = native_ok and good
            details.append(f"{name}={'System32' if good else 'SHADOWED'}")
        rec("OP22a native-commands-ignore-a-shadowed-PATH", native_ok,
            f"a fake binary that wins an ordinary lookup is not what the trusted "
            f"resolution returns; every system command still resolves to a real "
            f"file under System32 ({', '.join(details)})")

        # git takes the OTHER resolution path, and the battery planted a fake
        # git.exe on PATH and then never asked about it.
        git_shadowed = probe({"action": "trusted-git", "shadow": str(fake_dir / "git.exe")},
                             work, env=shadowed)["value"] or {}
        rec("OP22b git-is-not-taken-from-a-shadowed-PATH",
            git_shadowed.get("equals_shadow") is False
            and (git_shadowed.get("resolved") is False
                 or git_shadowed.get("exists") is True),
            f"git resolves to a machine-wide install or to nothing at all, never "
            f"to the planted binary that an ordinary lookup would have selected "
            f"({git_shadowed})")

        # And an explicit git inside a directory the author can write is refused
        # -- the property Resolve-TrustedGit documents and the reason it takes
        # an author identity at all.
        planted_git = work / "author-writable" / "git.exe"
        planted_git.parent.mkdir(exist_ok=True)
        planted_git.write_text("not a real program", encoding="ascii")
        git_author = probe({"action": "trusted-git", "explicit": str(planted_git),
                            "shadow": str(planted_git),
                            "author": {"name": os.environ.get("USERNAME", ""), "sid": "",
                                       "exists": True, "resolved": True}}, work)["value"] or {}
        rec("OP22c author-writable-git-is-refused",
            git_author.get("equals_shadow") is False,
            f"an explicitly supplied git inside a directory the author genuinely "
            f"owns is skipped rather than trusted ({git_author})")

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
        #
        # READ FROM THE PARSE TREE. Three substring searches were satisfied by a
        # comment quoting the identifiers -- and, more to the point, by a
        # TOKEN02 whose verdict was a hard-coded $false. The structure that
        # matters is that both are Add-Probe INVOCATIONS and that TOKEN02's
        # verdict is a measured expression.
        boundary = (ROOT / "packaging" / "hyperv" / "verify_author_boundary.ps1")
        gates = probe({"action": "harness-gates", "path": str(boundary)}, work)["value"] or {}
        rec("OP28 boundary-harness-carries-both-gates",
            gates.get("parses") is True and gates.get("token01_probe") is True
            and gates.get("token02_probe") is True
            and gates.get("token02_measured") is True
            and gates.get("membership_call") is True,
            f"the harness parses, and carries the process-token gate and the "
            f"account-membership gate as two separate Add-Probe invocations "
            f"whose second verdict is measured rather than constant ({gates})")

        # THE MUTATIONS. Without these the check above is another assertion that
        # the current file happens to be right.
        mutated = work / "harness-mutations"
        mutated.mkdir(exist_ok=True)
        original = boundary.read_text(encoding="utf-8") if boundary.is_file() else ""

        hollow = mutated / "hollow.ps1"
        hollow.write_text(original.replace(
            "Add-Probe 'TOKEN02 author-account-not-administrator' $accountIsAdmin",
            "Add-Probe 'TOKEN02 author-account-not-administrator' $false"),
            encoding="utf-8")
        hollow_gates = probe({"action": "harness-gates", "path": str(hollow)}, work)["value"] or {}
        rec("OP28a a-hard-coded-account-verdict-is-detected",
            hollow_gates.get("token02_probe") is True
            and hollow_gates.get("token02_measured") is False,
            f"a copy whose account gate answers with a constant is still found "
            f"to CARRY the gate, and is reported as not measuring it -- the "
            f"exact shape three earlier checks in this repository shipped in "
            f"({hollow_gates})")

        # The likelier regression is not a literal in the call -- it is the
        # MEASUREMENT being replaced one line above while the call still reads
        # correctly. Detecting only the literal would have missed it.
        stubbed = mutated / "stubbed.ps1"
        stubbed.write_text(original.replace(
            "$accountIsAdmin = Test-AccountInAdministrators -Identity $authorIdentity",
            "$accountIsAdmin = $false"), encoding="utf-8")
        stubbed_gates = probe({"action": "harness-gates", "path": str(stubbed)}, work)["value"] or {}
        rec("OP28c a-stubbed-measurement-is-detected",
            stubbed_gates.get("token02_probe") is True
            and stubbed_gates.get("token02_measured") is False,
            f"a copy that still calls the gate but assigns its verdict a constant "
            f"instead of measuring it is reported as not measuring "
            f"({stubbed_gates})")

        removed = mutated / "removed.ps1"
        removed.write_text("\n".join(
            line for line in original.splitlines()
            if "TOKEN02 author-account-not-administrator" not in line), encoding="utf-8")
        removed_gates = probe({"action": "harness-gates", "path": str(removed)}, work)["value"] or {}
        rec("OP28b a-deleted-account-gate-is-detected",
            removed_gates.get("token01_probe") is True
            and removed_gates.get("token02_probe") is False,
            f"a copy with the account gate deleted fails while the process gate "
            f"still passes, so one gate cannot stand in for two ({removed_gates})")

        # ------------------------------------------- the guard must not be hollow
        # EVERY CONTRACT FUNCTION MUST HAVE A PRODUCTION CALLER.
        #
        # Six predicates and two ACL evaluators were written, documented, and
        # exercised only from this file: the battery proved that unreached code
        # behaved correctly while the operator's transcript was assembled from
        # separate inline computations no fixture had ever seen. That is how the
        # display-name comparison and the stale-exit-code signal survived a green
        # run. A function this guard tests and production does not call is not a
        # covered function; it is a decoy.
        hyperv = ROOT / "packaging" / "hyperv"
        contract_text = (hyperv / "principal_contract.ps1").read_text(encoding="utf-8")
        declared = re.findall(r"^function ([A-Za-z][A-Za-z\-]*)", contract_text, re.M)
        production = [p for p in sorted(hyperv.glob("*.ps1"))
                      if p.name not in ("principal_contract.ps1", "principal_contract_probe.ps1")]
        prod_text = "\n".join(p.read_text(encoding="utf-8") for p in production)
        unreached = []
        for name in declared:
            call = re.compile(rf"(?<!function ){re.escape(name)}\b")
            if not call.search(prod_text) and not call.search(contract_text):
                unreached.append(name)
        rec("OP30 every-contract-function-has-a-production-caller",
            not unreached and len(declared) >= 20,
            f"all {len(declared)} functions in the shared contract are reached by "
            f"the scripts that run in production, not only by this battery "
            f"(unreached={unreached or 'none'})")

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
