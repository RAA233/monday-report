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


def blank_string_literals(line: str) -> str:
    """Replace literal text with filler, LENGTH FOR LENGTH.

    Length is preserved so an offset taken from the result still addresses the
    same character in the original. Interpolated variable references survive:
    "$AuthorIdentity" inside a double-quoted string IS a read, and hiding it
    would defeat the ordering check. A single-quoted string interpolates
    nothing, so it is blanked outright.
    """

    def fill(match) -> str:
        quote, body = match.group(0)[0], match.group(0)[1:-1]
        if quote == "'":
            return quote + "x" * len(body) + quote
        kept = ["x"] * len(body)
        for reference in re.finditer(r"\$\{?[A-Za-z_:][A-Za-z0-9_:]*\}?", body):
            kept[reference.start():reference.end()] = list(reference.group(0))
        return quote + "".join(kept) + quote

    # BACKTICK ESCAPES. PowerShell writes a literal quote inside a
    # double-quoted string as `" -- so "[^"]*" terminated at that quote and left
    # the rest of the literal unblanked, which is enough to make a function name
    # inside a string read as a live call again. Measured: the source-boundary
    # gate could be replaced by Write-Output "`"Assert-TrustedOperatorSource
    # ...`"" with OP30, OP30a and OP30b all still green. A single-quoted string
    # escapes a quote by doubling it, which the greedy alternation below already
    # handles as two adjacent literals.
    return re.sub(r"'(?:[^']|'')*'|\"(?:`.|[^\"])*\"", fill, line)


def strip_powershell_comments(text: str) -> str:
    """Block and line comments removed, line structure kept.

    A name that appears only in a comment is not a call. OP30 used to search raw
    text, so the sentence explaining that a gate exists satisfied the check that
    the gate is reached.
    """

    # A block comment is replaced by its own newlines, so line numbers and line
    # counts survive. Deleting it outright collapsed the file and made every
    # offset downstream refer to a different place than the reader expects.
    text = re.sub(r"<#.*?#>",
                  lambda match: chr(10) * match.group(0).count(chr(10)),
                  text, flags=re.S)
    # HERE-STRINGS, before anything is examined line by line.
    #
    # blank_string_literals works within one line, so @" ... "@ and @' ... '@
    # sailed through intact: replacing the one live invocation of the
    # source-boundary gate with a here-string containing the same text left
    # reachability reporting it as still called, and the boundary could be
    # disabled with the guard green. Braces inside one also corrupted the brace
    # counting that splits top-level code from function bodies. Blanked to
    # filler, newlines kept, so offsets and line numbers still hold.
    def blank_here_string(match):
        return re.sub(r"[^\n]", "x", match.group(0))

    text = re.sub(r"@([\"'])(?:.|\n)*?\1@", blank_here_string, text)
    out = []
    for line in text.splitlines():
        blanked = blank_string_literals(line)
        hash_at = blanked.find("#")
        # THE BLANKED LINE IS WHAT IS RETURNED, and the cut is taken from it.
        #
        # Two defects in one line. The index was computed on a line shortened by
        # collapsing quotes and then applied to the ORIGINAL, so
        # `$x = 'hello world'  # c` came back as `$x = 'hel` -- live code
        # truncated mid-statement, and three lines of reviewer_session.ps1 were
        # being mangled before reachability and position arithmetic ever ran.
        # And returning the original meant a function name inside a string
        # counted as a call to it: replacing the one live invocation of the
        # source-boundary gate with Write-Output 'Assert-TrustedOperatorSource
        # ...' disabled the second trust boundary and left OP30 green.
        out.append(blanked[:hash_at] if hash_at >= 0 else blanked)
    return "\n".join(out)


def function_bodies(text: str) -> dict:
    """Each function name mapped to its body, by brace counting."""

    # LEADING WHITESPACE IS ALLOWED. Anchoring on column 0 meant a definition
    # indented by two spaces -- valid PowerShell, and already present in
    # hyperv_control.ps1 and provision_vm.ps1 -- was not recognised as a
    # function at all, so its body was folded into "top-level code" and every
    # call inside it counted as live. Wrapping a dead gate in an indented
    # function was enough to keep the reachability checks green.
    bodies = {}
    for match in re.finditer(r"^[ \t]*function\s+([A-Za-z][A-Za-z0-9\-]*)", text, re.M):
        opening = text.find("{", match.end())
        if opening < 0:
            continue
        depth, cursor = 0, opening
        while cursor < len(text):
            if text[cursor] == "{":
                depth += 1
            elif text[cursor] == "}":
                depth -= 1
                if depth == 0:
                    break
            cursor += 1
        bodies[match.group(1)] = text[opening:cursor + 1]
    return bodies


def reachable_names(sources: list, declared: list) -> set:
    """Names reached from LIVE top-level code, transitively through live bodies.

    A call that exists only inside a function nobody invokes is not reachability.
    Assert-TrustedSourceRoot's one production occurrence was inside
    Assert-TrustedOperatorSource, which had no call site at all -- so the gate
    was dead and the check that would have said so reported it reached.
    """

    bodies, top_level = {}, []
    for text in sources:
        stripped = strip_powershell_comments(text)
        spans = function_bodies(stripped)
        bodies.update(spans)
        remainder = stripped
        for body in spans.values():
            remainder = remainder.replace(body, "", 1)
        top_level.append(
            re.sub(r"^[ \t]*function\s+[A-Za-z][A-Za-z0-9\-]*", "", remainder, flags=re.M))

    known = set(bodies) | set(declared)

    def calls_in(source: str) -> set:
        return {n for n in known if re.search(rf"(?<![\w\-]){re.escape(n)}\b", source)}

    seen: set = set()
    queue = list(calls_in("\n".join(top_level)))
    while queue:
        name = queue.pop()
        if name in seen:
            continue
        seen.add(name)
        if name in bodies:
            queue.extend(calls_in(bodies[name]) - seen)
    return seen


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
        # FAILS CLOSED. Returning 0 made a run that measured nothing about the
        # acceptance predicate byte-identical -- in exit status and in the
        # pinned step digest -- to one that measured all of it, and no consumer
        # read the marker. The certifying host is Windows by construction, so a
        # non-Windows run of this battery is a run that cannot answer the
        # question, and that is a failure rather than a pass.
        print(json.dumps({
            "guard": "offline-operator-principal",
            "error": "OFFLINE_PRINCIPAL_CONTRACT_UNMEASURABLE",
            "detail": "the principal contract is a statement about Windows "
                      "accounts, ACLs and scheduled-task descriptors; this "
                      "platform cannot answer it, and nothing is claimed",
        }, indent=2))
        return 1
    if not PROBE.is_file():
        rec("OP00 probe-present", False, "the contract probe is missing")
        return 1
    work = Path(tempfile.mkdtemp(prefix="mr-principal-"))
    # Read once. Several checks below reason about the elevated script; each
    # re-reading it invited exactly the ordering accident that this hoist
    # removes.
    # BOTH forms, read once. boot_live has comments removed and string literals
    # blanked -- which is what stops a name inside a string reading as a call --
    # so any check looking for string DATA must use the raw text instead.
    boot_text = (ROOT / "packaging" / "hyperv" / "reviewer_bootstrap.ps1").read_text(
        encoding="utf-8")
    boot_live = strip_powershell_comments(boot_text)
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
        # THE PLANTED CANDIDATE MUST BE WRITABLE BY THE PRINCIPAL UNDER TEST.
        #
        # Using the real account for this leg and the synthetic one for the
        # control meant the two legs were about different principals -- and the
        # real account is in Administrators here, so resolution produces nothing
        # for it and "equals_shadow is False" was satisfied by a resolution that
        # had failed for its own reasons. Using the synthetic account for both
        # is only meaningful if the planted directory is one IT can write, so
        # the DACL says so explicitly and that precondition is asserted.
        planted_dir = work / "synth-writable-git"
        planted_dir.mkdir(exist_ok=True)
        # The candidate is created BEFORE the DACL is applied: that DACL names
        # SYSTEM and the synthetic account only, so this process cannot write
        # into the directory afterwards.
        planted_git = planted_dir / "git.exe"
        planted_git.write_text("not a real program", encoding="ascii")
        writable_precondition = probe(
            {"action": "write-mask", "path": str(planted_dir),
             "sddl": f"O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{SID_AUTHOR})",
             "mask": 0xD0156, "author": identity("SYNTH", SID_AUTHOR)}, work)["value"]
        # A POSITIVE CONTROL FIRST. `equals_shadow is False` is satisfied by a
        # resolution that produced NOTHING, for any reason -- and that is exactly
        # what was happening: the ancestor mask was inert, every candidate scored
        # author-writable, and the check recorded a pass over a function that
        # could no longer resolve anything at all. The synthetic author is in no
        # local group, so a machine-wide git must resolve for it.
        git_control = probe({"action": "trusted-git",
                             "author": identity("SYNTH", SID_AUTHOR)}, work)["value"] or {}
        # THE SAME PRINCIPAL IN BOTH LEGS.
        #
        # The control resolved git for the SYNTHETIC author and the assertion was
        # then made about the REAL one -- which on this host is in
        # Administrators, so Test-AccountCanWritePath answers true for every git
        # candidate and resolution produces nothing at all. `equals_shadow is
        # False` is satisfied by that, so the stated property -- that the refusal
        # is a refusal and not a resolution that failed for its own reasons --
        # was exactly what the control failed to establish. Both legs now use the
        # synthetic identity, for which resolution demonstrably works.
        git_author = probe({"action": "trusted-git", "explicit": str(planted_git),
                            "shadow": str(planted_git),
                            "author": identity("SYNTH", SID_AUTHOR)}, work)["value"] or {}
        rec("OP22c author-writable-git-is-refused",
            writable_precondition is True
            and git_control.get("resolved") is True and git_control.get("exists") is True
            and git_author.get("equals_shadow") is False,
            f"resolution genuinely works for a non-administrative author, and the "
            f"explicitly supplied git inside a directory that SAME principal "
            f"provably can write is skipped rather than trusted -- so the refusal "
            f"is a refusal and not a resolution that failed for its own reasons "
            f"(writable={writable_precondition}, control={git_control}, "
            f"planted={git_author})")

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

        # The cheapest hollowing of all: leave the real measurement in place and
        # ADD a constant assignment below it. One command-derived assignment used
        # to excuse every other one, so this scored as measured.
        overridden = mutated / "overridden.ps1"
        overridden.write_text(original.replace(
            "Add-Probe 'TOKEN02 author-account-not-administrator' $accountIsAdmin",
            "$accountIsAdmin = $false\n"
            "Add-Probe 'TOKEN02 author-account-not-administrator' $accountIsAdmin"),
            encoding="utf-8")
        overridden_gates = probe({"action": "harness-gates", "path": str(overridden)},
                                 work)["value"] or {}
        rec("OP28d an-appended-overriding-constant-is-detected",
            overridden_gates.get("token02_probe") is True
            and overridden_gates.get("token02_measured") is False,
            f"a copy that keeps the genuine measurement and adds a constant "
            f"assignment beneath it is reported as not measuring ({overridden_gates})")

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

        # ------------------------------ the pre-load check, ACTUALLY EXECUTED
        # NOTHING IN THIS BATTERY HAD EVER RUN A LINE OF reviewer_bootstrap.ps1.
        #
        # Assert-SelfSourceTrusted runs above the dot-source and above every
        # gate, and it acquired an ancestor walk that judged the volume root by
        # the full write mask without skipping inherit-only ACEs. A stock C:\
        # grants Authenticated Users APPEND_DATA outright and GENERIC_WRITE
        # inherit-only, so it scored "writable" and EVERY route exited 2 --
        # while this battery stayed 56/56 green, because every check read the
        # file and none executed it.
        #
        # The shipped function is lifted verbatim out of the script and run.
        boot_bodies = function_bodies(boot_live)
        self_check = boot_bodies.get("Assert-SelfSourceTrusted", "")
        raw_boot = (ROOT / "packaging" / "hyperv" / "reviewer_bootstrap.ps1").read_text(
            encoding="utf-8")
        start = raw_boot.find("function Assert-SelfSourceTrusted")
        opening = raw_boot.find("{", start)
        depth, cursor = 0, opening
        while cursor < len(raw_boot):
            if raw_boot[cursor] == "{":
                depth += 1
            elif raw_boot[cursor] == "}":
                depth -= 1
                if depth == 0:
                    break
            cursor += 1
        function_text = raw_boot[start:cursor + 1] if start >= 0 else ""

        volume = os.environ.get("SystemDrive", "C:") + "\\"
        harness = work / "self-source-check.ps1"
        harness.write_text(
            function_text
            + "\nAssert-SelfSourceTrusted -Paths @() -AncestorPaths @('" + volume + "')\n"
            + "Write-Output 'ANCESTOR-ACCEPTED'\n", encoding="utf-8")
        try:
            ran = subprocess.run(
                [str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-File", str(harness)], capture_output=True, text=True, timeout=180)
            accepted = ran.returncode == 0 and "ANCESTOR-ACCEPTED" in (ran.stdout or "")
            detail = (ran.stdout or "").strip().replace("\n", " ")[:200]
        except (OSError, subprocess.SubprocessError) as exc:
            accepted, detail = False, type(exc).__name__
        rec("OP39 the-pre-load-check-accepts-an-ordinary-volume-root",
            bool(function_text) and accepted,
            f"the shipped Assert-SelfSourceTrusted, run verbatim against the "
            f"volume root as an ancestor, does not refuse -- so the gate that "
            f"sits above every other gate does not stop the protocol on a stock "
            f"host ({detail or 'no output'})")

        # ...and it must still refuse a genuinely replaceable ancestor.
        replaceable = work / "replaceable"
        replaceable.mkdir(exist_ok=True)
        probe({"action": "write-mask", "path": str(replaceable),
               "sddl": f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x40;;;{SID_AUTHOR})",
               "mask": 0xD0042, "author": identity("SYNTH", SID_AUTHOR)}, work)
        refuse_harness = work / "self-source-refuse.ps1"
        refuse_harness.write_text(
            function_text
            + "\nAssert-SelfSourceTrusted -Paths @() -AncestorPaths @('"
            + str(replaceable) + "')\n"
            + "Write-Output 'ANCESTOR-ACCEPTED'\n", encoding="utf-8")
        try:
            refused_run = subprocess.run(
                [str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-File", str(refuse_harness)], capture_output=True, text=True, timeout=180)
            refused = (refused_run.returncode == 2
                       and "OFFLINE_OPERATOR_SOURCE_NOT_TRUSTED" in (refused_run.stdout or ""))
            refuse_detail = (refused_run.stdout or "").strip().replace("\n", " ")[:200]
        except (OSError, subprocess.SubprocessError) as exc:
            refused, refuse_detail = False, type(exc).__name__
        # POSITION AND ARGUMENTS, PINNED.
        #
        # OP39 and OP39a run the lifted function against synthetic inputs and
        # never look at the production call site, so moving the invocation BELOW
        # the dot-source -- which discards the file's headline property, that the
        # source is checked before it is loaded -- left every check green, as did
        # reducing it to `-Paths @() -AncestorPaths @()`.
        call_at = boot_live.find("Assert-SelfSourceTrusted -Paths")
        # Searched in the BLANKED text, so the filename literal is gone --
        # blank_string_literals replaced it with filler. The dot-source is
        # located by the part that survives blanking.
        load_at = boot_live.find(". (Join-Path $PSScriptRoot ")
        empty_args = bool(re.search(
            r"Assert-SelfSourceTrusted\s+-Paths\s+@\(\s*\)", boot_live))
        rec("OP39b the-pre-load-check-runs-before-the-load-with-real-arguments",
            call_at >= 0 and load_at >= 0 and call_at < load_at and not empty_args
            and "-AncestorPaths $selfAncestors" in boot_live,
            f"the invocation precedes the dot-source it protects and is passed "
            f"the real path and ancestor lists rather than empty ones "
            f"(call@{call_at}, load@{load_at}, empty-args={empty_args})")

        rec("OP39a a-replaceable-ancestor-is-still-refused",
            refused,
            f"an ancestor granting an untrusted principal delete-child is "
            f"refused by the same function, so accepting the volume root is a "
            f"narrower question and not a disabled one ({refuse_detail or 'no output'})")

        # ------------------------- an ancestor the author OWNS, with no ACE
        # OWNERSHIP IS A WRITE RIGHT, and the ancestor branch did not read it.
        #
        # The -Paths branch of the same function checks the owner and
        # Resolve-TrustedGit judges ancestors through a predicate that counts
        # ownership; this branch accepted a directory the author owned outright
        # with no ACE at all. The author re-grants itself delete-child, renames
        # the directory away and substitutes -- the exact substitution the
        # ancestor walk was added to stop.
        owned = work / "owned-ancestor"
        owned.mkdir(exist_ok=True)
        me = subprocess.run(
            [str(SHELL), "-NoProfile", "-NonInteractive", "-Command",
             "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"],
            capture_output=True, text=True, timeout=60).stdout.strip()
        setup = work / "own-ancestor.ps1"
        setup.write_text(
            "$sd = New-Object Security.AccessControl.DirectorySecurity\n"
            "$sd.SetSecurityDescriptorSddlForm('O:" + me
            + "G:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')\n"
            "Set-Acl -LiteralPath '" + str(owned) + "' -AclObject $sd\n", encoding="utf-8")
        subprocess.run([str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                        "Bypass", "-File", str(setup)],
                       capture_output=True, text=True, timeout=180)
        owned_harness = work / "owned-ancestor-check.ps1"
        owned_harness.write_text(
            function_text
            + "\nAssert-SelfSourceTrusted -Paths @() -AncestorPaths @('" + str(owned) + "')\n"
            + "Write-Output 'ANCESTOR-ACCEPTED'\n", encoding="utf-8")
        try:
            owned_run = subprocess.run(
                [str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-File", str(owned_harness)], capture_output=True, text=True, timeout=180)
            owned_refused = (owned_run.returncode == 2
                             and "owned-ancestor" in (owned_run.stdout or ""))
            owned_detail = (owned_run.stdout or "").strip().replace("\n", " ")[:180]
        except (OSError, subprocess.SubprocessError) as exc:
            owned_refused, owned_detail = False, type(exc).__name__
        rec("OP40 an-ancestor-the-author-owns-is-refused",
            owned_refused,
            f"a directory the author owns outright, carrying no ACE for it at "
            f"all, is refused as an ancestor -- an owner holds implicit "
            f"WRITE_DAC and can grant itself the rest ({owned_detail or 'no output'})")

        # --------------------------- a failing group enumeration fails closed
        group_state = probe({"action": "group-enumeration-failure",
                             "name": os.environ.get("USERNAME", "")}, work)["value"] or {}
        rec("OP41 a-failing-group-enumeration-yields-no-answer",
            group_state.get("working_is_null") is False
            and group_state.get("broken_is_null") is True,
            f"the account's group set resolves normally, and when the "
            f"enumeration throws the function returns nothing rather than a "
            f"truncated set that every caller would read as a complete one "
            f"({group_state})")

        # --------------------- an author-writable ancestor of the interpreter
        # THE FIXTURE HAS TO REACH THE ANCESTOR WALK.
        #
        # It did not. With no DLLs and no Lib the helper returned at the
        # unlistable branch, and the single "writable hit" the check asserted
        # was `<tools>\python (unlistable)` -- not an ancestor result at all.
        # Adding DLLs and Lib was not enough either: the "hardened" tree grants
        # BUILTIN\Administrators, and the real account is in Administrators on
        # this host, so python.exe itself matched and the helper returned before
        # the walk again. Deleting the entire ancestor walk would have left the
        # check green.
        #
        # So: a SYNTHETIC author in no local group, the subdirectories present,
        # the interpreter tree granting only SYSTEM and Administrators, and the
        # PARENT granting that synthetic SID delete-child. The only path to a
        # hit is the walk, and the hit is required to say so.
        tools = work / "tools"
        interpreter_dir = tools / "python"
        (interpreter_dir / "DLLs").mkdir(parents=True, exist_ok=True)
        (interpreter_dir / "Lib").mkdir(parents=True, exist_ok=True)
        (interpreter_dir / "python.exe").write_text("stub", encoding="ascii")
        (interpreter_dir / "python313.dll").write_text("stub", encoding="ascii")
        hardened_sddl = "O:SYG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        harden = work / "harden-interpreter.ps1"
        harden.write_text(
            "$dirs = @('" + str(interpreter_dir) + "', '" + str(interpreter_dir / "DLLs")
            + "', '" + str(interpreter_dir / "Lib") + "')\n"
            "foreach ($d in $dirs) {\n"
            "  $sd = New-Object Security.AccessControl.DirectorySecurity\n"
            "  $sd.SetSecurityDescriptorSddlForm('" + hardened_sddl + "')\n"
            "  Set-Acl -LiteralPath $d -AclObject $sd\n}\n"
            "foreach ($p in @('" + str(interpreter_dir / "python.exe") + "', '"
            + str(interpreter_dir / "python313.dll") + "')) {\n"
            "  $f = New-Object Security.AccessControl.FileSecurity\n"
            "  $f.SetSecurityDescriptorSddlForm('O:SYG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')\n"
            "  Set-Acl -LiteralPath $p -AclObject $f\n}\n"
            "# The PARENT is where the author gets delete-child, and nowhere else.\n"
            "$parent = New-Object Security.AccessControl.DirectorySecurity\n"
            "$parent.SetSecurityDescriptorSddlForm("
            "'O:SYG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x40;;;" + SID_AUTHOR + ")')\n"
            "Set-Acl -LiteralPath '" + str(tools) + "' -AclObject $parent\n",
            encoding="utf-8")
        subprocess.run([str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                        "Bypass", "-File", str(harden)],
                       capture_output=True, text=True, timeout=180)
        helper_start = raw_boot.find("function Get-AuthorWritableInterpreterPaths")
        helper_open = raw_boot.find("{", helper_start)
        depth, cursor = 0, helper_open
        while cursor < len(raw_boot):
            if raw_boot[cursor] == "{":
                depth += 1
            elif raw_boot[cursor] == "}":
                depth -= 1
                if depth == 0:
                    break
            cursor += 1
        helper_text = raw_boot[helper_start:cursor + 1] if helper_start >= 0 else ""
        interp_harness = work / "interpreter-ancestor.ps1"
        interp_harness.write_text(
            ". '" + str(ROOT / "packaging" / "hyperv" / "principal_contract.ps1") + "'\n"
            # A SYNTHETIC author in no local group. The real account is in
            # Administrators here, so it matched the hardened tree's own ACE and
            # the helper never reached the walk.
            "$AuthorIdentity = [pscustomobject]@{ Name='SYNTH'; Sid='" + SID_AUTHOR + "';\n"
            "  Exists=$true; Resolved=$true; Digest=''; Requested='SYNTH'; Error='' }\n"
            "function Test-AuthorWritable { param([string]$Path)\n"
            "  return (Test-AccountCanWritePath -Identity $AuthorIdentity -Path $Path) }\n"
            + helper_text
            + "\n$hits = @(Get-AuthorWritableInterpreterPaths -Interpreter '"
            + str(interpreter_dir / "python.exe") + "')\n"
            + "Write-Output ('writable-hits=' + $hits.Count)\n"
            + "Write-Output ('hit=' + ($hits -join ';'))\n", encoding="utf-8")
        try:
            interp_run = subprocess.run(
                [str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-File", str(interp_harness)], capture_output=True, text=True, timeout=300)
            # The hit must be the ANCESTOR result. Asserting only a count let an
            # unrelated early return satisfy the check.
            interp_ok = ("writable-hits=1" in (interp_run.stdout or "")
                         and "(replaceable ancestor)" in (interp_run.stdout or ""))
            interp_detail = (interp_run.stdout or "").strip().replace("\n", " ")[:180]
        except (OSError, subprocess.SubprocessError) as exc:
            interp_ok, interp_detail = False, type(exc).__name__
        rec("OP42 an-author-writable-ancestor-of-the-interpreter-is-reported",
            bool(helper_text) and interp_ok,
            f"an interpreter whose own directory and executable are hardened, "
            f"but which sits under a directory the author can write, is still "
            f"reported -- what matters is what can replace the tree, not only "
            f"what is inside it ({interp_detail or 'no output'})")

        # ------------------------------- the SID set the predicate reasons over
        # A LOGON CARRIES MORE THAN EVERYONE AND AUTHENTICATED USERS.
        #
        # Get-AccountSidSet returned the account SID, its local groups, S-1-1-0
        # and S-1-5-11, and nothing else -- so a directory granting S-1-5-113
        # (Local account, which every local account carries) FullControl scored
        # "the author cannot write here", and the account then created a file in
        # it. Every fixture missed it by construction: they all pass
        # `-GroupProvider { return @() }` and a synthetic SID, so the well-known
        # SIDs were never in play. This one uses the REAL account and no
        # provider.
        wellknown = work / "wellknown-ace"
        wellknown.mkdir(exist_ok=True)
        wk_script = work / "wellknown.ps1"
        wk_script.write_text(
            ". '" + str(ROOT / "packaging" / "hyperv" / "principal_contract.ps1") + "'\n"
            "$id = Resolve-PrincipalIdentity -Account $env:USERNAME\n"
            "$sd = New-Object Security.AccessControl.DirectorySecurity\n"
            "$sd.SetSecurityDescriptorSddlForm("
            "'O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;S-1-5-113)')\n"
            "Set-Acl -LiteralPath '" + str(wellknown) + "' -AclObject $sd\n"
            "$says = Test-AccountCanWritePath -Identity $id -Path '" + str(wellknown) + "'\n"
            "$wrote = $false\n"
            "try { Set-Content -Path '" + str(wellknown / "probe.txt")
            + "' -Value 'x' -Encoding ascii -ErrorAction Stop; $wrote = $true } catch { }\n"
            "Write-Output ('says=' + $says + ' wrote=' + $wrote)\n", encoding="utf-8")
        try:
            wk_run = subprocess.run(
                [str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-File", str(wk_script)], capture_output=True, text=True, timeout=300)
            wk_out = (wk_run.stdout or "").strip()
            wk_agrees = "says=True wrote=True" in wk_out
        except (OSError, subprocess.SubprocessError) as exc:
            wk_out, wk_agrees = type(exc).__name__, False
        rec("OP43 the-predicate-agrees-with-what-the-account-can-actually-do",
            wk_agrees,
            f"a directory granting only a well-known SID that every local account "
            f"carries is reported writable, and the account demonstrably writes "
            f"to it -- the prediction and the outcome agree ({wk_out or 'no output'})")

        # ------------------------ the sensitive-root evaluator, finally driven
        sensitive_root = work / "sensitive-root"
        sensitive_root.mkdir(exist_ok=True)
        planted_sensitive = probe({"action": "sensitive-root", "path": str(sensitive_root),
                                   "author": identity("SYNTH", SID_AUTHOR),
                                   "plant_file_ace": True}, work)["reasons"]
        clean_sensitive_root = work / "sensitive-root-clean"
        clean_sensitive_root.mkdir(exist_ok=True)
        clean_sensitive = probe({"action": "sensitive-root", "path": str(clean_sensitive_root),
                                 "author": identity("SYNTH", SID_AUTHOR),
                                 "plant_file_ace": False}, work)["reasons"]
        rec("OP44 a-file-level-ace-inside-a-sensitive-root-is-detected",
            "OFFLINE_SENSITIVE_ROOT_AUTHOR_WRITABLE" in planted_sensitive
            and "OFFLINE_SENSITIVE_ROOT_AUTHOR_WRITABLE" not in clean_sensitive,
            f"an author ACE on the interpreter pin inside a clean, protected "
            f"sensitive root is reported, and the same tree without it is not -- "
            f"this evaluator had a probe action that no check invoked, so all "
            f"six of its named reasons were unexercised "
            f"(planted={planted_sensitive}, clean={clean_sensitive})")

        # --------------------- the boundary harness must not take its subject
        # ---------------------- from a variable the process running it controls
        # EXECUTED, NOT MATCHED. The substring form of this check passed on the
        # very regression it was written to catch: re-introducing
        # `$fromEnv = Resolve-PrincipalIdentity -Account $env:USERNAME;
        # if ($fromEnv.Exists) { $tokenSid = $fromEnv.Sid }` ABOVE the token
        # read satisfies "no env spelling present, token spelling present"
        # while one environment variable decides the gate again. It was also
        # the only check in this file with no mutation cycle.
        boundary_path = ROOT / "packaging" / "hyperv" / "verify_author_boundary.ps1"
        subject = probe({"action": "token-subject", "harness": str(boundary_path),
                         "first": "DefaultAccount", "second": "WDAGUtilityAccount"},
                        work)["value"] or {}
        rec("OP45 the-account-gate-takes-its-subject-from-the-token",
            subject.get("region_found") is True and subject.get("agree") is True
            and subject.get("both_are_the_real_token") is True,
            f"the harness's own subject-resolution region, executed twice with "
            f"$env:USERNAME set to two different built-in accounts, settles on "
            f"the same SID both times and that SID is the real token's -- so the "
            f"gate cannot be redirected by the variable whatever launches it "
            f"controls ({subject})")

        # THE MUTATION. A copy with the environment lookup restored ahead of the
        # token read must disagree with itself.
        # THE COPY LIVES BESIDE A CONTRACT IT CAN LOAD.
        #
        # Placed in a bare scratch directory the mutated harness threw
        # CommandNotFoundException on its own dot-source, and the check passed on
        # THAT rather than on the redirection -- it would have "detected" any
        # copy moved anywhere, mutation or not. The contract is copied alongside
        # so the only difference between this run and the one above is the
        # mutation itself.
        redirected_dir = work / "redirected"
        redirected_dir.mkdir(exist_ok=True)
        shutil.copyfile(ROOT / "packaging" / "hyperv" / "principal_contract.ps1",
                        redirected_dir / "principal_contract.ps1")
        redirected = redirected_dir / "redirected-boundary.ps1"
        boundary_text = boundary_path.read_text(encoding="utf-8")
        # ANCHORED ON THE TOKEN READ, not on the initialisation above it.
        # Replacing `$tokenSid = ''` left the real read on the very next line,
        # which overwrote the redirection -- so the mutation was a no-op. The
        # check failed rather than passed, which is the right direction, but a
        # mutation that cannot take effect proves nothing either way.
        anchor = ("try { $tokenSid = [Security.Principal.WindowsIdentity]"
                  "::GetCurrent().User.Value } catch { }")
        assert anchor in boundary_text, "the token read is not where the mutation expects it"
        redirected.write_text(boundary_text.replace(
            anchor,
            "$fromEnv = Resolve-PrincipalIdentity -Account $env:USERNAME; "
            "$tokenSid = if ($fromEnv.Exists) { $fromEnv.Sid } else { '' }", 1),
            encoding="utf-8")
        redirected_subject = probe({"action": "token-subject", "harness": str(redirected),
                                    "first": "DefaultAccount", "second": "WDAGUtilityAccount"},
                                   work)["value"] or {}
        # THE ARGUMENT ALONE. OP45a replaces the token READ; this replaces only
        # what the membership call is HANDED, leaving $authorIdentity assigned
        # from the token and unused. That is the cheaper edit and the one the
        # previous form of this check -- which read $authorIdentity after the
        # fact -- could not see at all.
        argument_dir = work / "argument-redirected"
        argument_dir.mkdir(exist_ok=True)
        shutil.copyfile(ROOT / "packaging" / "hyperv" / "principal_contract.ps1",
                        argument_dir / "principal_contract.ps1")
        argument_copy = argument_dir / "argument-boundary.ps1"
        argument_anchor = ("$accountIsAdmin = Test-AccountInAdministrators "
                           "-Identity $authorIdentity")
        assert argument_anchor in boundary_text, "the membership call moved"
        argument_copy.write_text(boundary_text.replace(
            argument_anchor,
            "$accountIsAdmin = Test-AccountInAdministrators -Identity "
            "(Resolve-PrincipalIdentity -Account $env:USERNAME)", 1), encoding="utf-8")
        argument_subject = probe({"action": "token-subject", "harness": str(argument_copy),
                                  "first": "DefaultAccount", "second": "WDAGUtilityAccount"},
                                 work)["value"] or {}
        rec("OP45b a-redirected-argument-is-detected",
            argument_subject.get("region_found") is True
            and argument_subject.get("both_are_the_real_token") is False,
            f"a copy that leaves the token read intact and redirects only the "
            f"identity handed to the membership call is reported -- the subject "
            f"is captured AT the call, not read from a variable beside it "
            f"({argument_subject})")

        rec("OP45a a-gate-redirected-by-the-environment-is-detected",
            redirected_subject.get("region_found") is True
            and redirected_subject.get("both_are_the_real_token") is False,
            f"a copy whose subject comes from $env:USERNAME no longer settles on "
            f"the real token, and is reported ({redirected_subject})")

        # ------------------------- the task root's ancestors, fired and quiet
        ancestor_fires = work / "anc-fires"
        ancestor_fires.mkdir(exist_ok=True)
        fired = probe({"action": "task-root-ancestor", "path": str(ancestor_fires),
                       "author": identity("SYNTH", SID_AUTHOR),
                       "grant_delete_child": True}, work)["reasons"]
        ancestor_quiet = work / "anc-quiet"
        ancestor_quiet.mkdir(exist_ok=True)
        quiet = probe({"action": "task-root-ancestor", "path": str(ancestor_quiet),
                       "author": identity("SYNTH", SID_AUTHOR),
                       "grant_delete_child": False}, work)["reasons"]
        rec("OP46 a-replaceable-task-root-ancestor-is-detected",
            "OFFLINE_TASK_ROOT_ANCESTOR_REPLACEABLE" in fired
            and "OFFLINE_TASK_ROOT_ANCESTOR_REPLACEABLE" not in quiet,
            f"a task root whose PARENT grants the author delete-child is reported "
            f"-- renaming that parent's child substitutes reviewer-bin, "
            f"reviewer-runtime and reviewer state at once -- and the same root "
            f"under a clean parent is not (fired={fired}, quiet={quiet})")

        # --------------------------------- a path is a NAME, not a pattern
        # Get-FileHash -Path, Test-Path -Path and their siblings treat [ and ]
        # as wildcards. The reviewer's code-integrity digest hashed two trees
        # whose filenames the AUTHOR chooses, so a bracketed name was hashed as
        # a different file -- the digest was provably invariant under replacing
        # that file's entire contents -- or resolved to nothing, whereupon
        # `.Hash` on nothing threw under StrictMode before any status was
        # written and before the stale-result cleanup.
        wildcard_dir = work / "wildcard"
        wildcard_dir.mkdir(exist_ok=True)
        wildcard = probe({"action": "wildcard-path", "path": str(wildcard_dir)},
                         work)["value"] or {}
        rec("OP47 a-bracketed-filename-is-a-name-not-a-pattern",
            wildcard.get("literal_sees_the_change") is True
            and wildcard.get("wildcard_sees_the_change") is False,
            f"replacing the entire contents of a file whose name contains "
            f"brackets changes its literal digest and does NOT change its "
            f"wildcard-resolved one -- so the class is real and -LiteralPath is "
            f"the property that closes it ({wildcard})")

        # ...and no trust-path script may still resolve a variable path as a
        # pattern. New-Item is excluded: it has no -LiteralPath in Windows
        # PowerShell 5.1, and it creates rather than resolves.
        # EVERY SCRIPT, and Resolve-Path with them.
        #
        # The exclusion list dropped five files with no stated reason -- and two
        # of them are named in reviewer_session's own $codeFiles, executed inside
        # the DPAPI-live reviewer session, while stage e2 runs hyperv_control and
        # hyperv_session against the author-built package. One carried a live
        # instance: a staged file named with brackets, holding bare key-shaped
        # hex, read through a wildcard path and therefore never seen by the
        # boundary check that exists to catch exactly that. Resolve-Path belongs
        # here too: its result becomes the manifest key and the relative-path
        # prefix.
        wildcard_cmdlets = ("Get-FileHash", "Test-Path", "Get-Content", "Set-Content",
                            "Add-Content", "Get-Acl", "Set-Acl", "Get-Item",
                            "Get-ChildItem", "Remove-Item", "Copy-Item", "Move-Item",
                            "Resolve-Path")
        offenders = []
        opt_outs = 0
        # The MARKERS are what a reader audits, and one marker can cover only
        # the call beneath it, so counting declarations is the honest pin.
        declared_optouts = sum(
            source.read_text(encoding='utf-8').count('WILDCARD-BY-DESIGN')
            for source in (ROOT / 'packaging' / 'hyperv').glob('*.ps1'))
        for source in sorted((ROOT / "packaging" / "hyperv").glob("*.ps1")):
            lines = source.read_text(encoding="utf-8").splitlines()
            for number, line in enumerate(lines, 1):
                if line.lstrip().startswith("#"):
                    continue
                # ONE OPT-OUT, spelled out in the source it applies to: the
                # fixture that DEMONSTRATES this defect must keep a wildcard arm,
                # or it would have nothing to compare the literal arm against.
                # It has to be declared on an immediately preceding comment line,
                # so it cannot be applied silently or in bulk.
                if any("WILDCARD-BY-DESIGN" in lines[back]
                       for back in range(max(0, number - 3), number - 1)):
                    opt_outs += 1
                    continue
                for cmdlet in wildcard_cmdlets:
                    if not re.search(rf"\b{cmdlet}\b", line):
                        continue
                    # PER CALL, NOT PER LINE. `if (Test-Path $x) { Remove-Item
                    # -LiteralPath $x }` exempted the whole line, including the
                    # Test-Path that still resolves as a pattern.
                    #
                    # And a double-quoted interpolated path is a path: matching
                    # only `$` or `(` after the cmdlet missed every `"...$x..."`
                    # argument.
                    for call in re.finditer(
                            rf"\b{cmdlet}\b\s+(?:-Path\s+|-LiteralPath\s+)?"
                            rf"(\$[^\s,)]*|\([^\n]*|\"[^\"]*\")", line):
                        if "-LiteralPath" in call.group(0):
                            continue
                        argument = call.group(1)
                        # A double-quoted CONSTANT is already a name: the source
                        # decides it, not a caller. Only an INTERPOLATED one
                        # carries a value from elsewhere, and only that can carry
                        # a bracket an author chose.
                        if argument.startswith('"') and "$" not in argument:
                            continue
                        offenders.append(f"{source.name}:{number}")
                        break
        # The opt-out count is pinned for the same reason the pending-grant
        # exemption's is: a marker that can be applied freely is not an
        # exception, it is a way out.
        rec("OP47a no-trust-path-script-resolves-a-variable-path-as-a-pattern",
            not offenders and declared_optouts == 3,
            f"every wildcard-interpreting call in the scripts on the trust path "
            f"takes -LiteralPath, so no author-chosen filename can redirect one, "
            f"and the wildcard opt-outs are exactly the declared ones "
            f"({offenders[:4] or 'none'}, declared-opt-outs={declared_optouts})")

        # ------------------------- the credential half of the no-switch route
        # THE ACCOUNT BRANCH WAS GUARDED; ITS CREDENTIAL COUNTERPART WAS NOT.
        #
        # On a host whose reviewer already exists the route printed
        # `account exists (reusing)` and then ran Set-LocalUser anyway, which
        # replaces the DPAPI master key and leaves review-key.dpapi and
        # e2-guest.cred present, correctly sized, correctly ACL'd and forever
        # unopenable. Every earlier check in this battery read that route; none
        # executed it, and reading it is exactly how the asymmetry survived --
        # the guarded branch and the unguarded one were 45 lines apart in the
        # same top-level route, with nothing between them that reads either.
        #
        # The shipped block is lifted verbatim between its own markers and run
        # against synthetic state directories. Lifting a REGION rather than a
        # function has its own failure mode: a region cut mid-statement raises a
        # ParseException that looks identical to a refusal, so the clean-host
        # case below is what proves the region is executable at all.
        chain_start = raw_boot.find("# ---- live credential chain")
        chain_end = raw_boot.find("# ---- account ---", chain_start)
        chain_text = raw_boot[chain_start:chain_end] if chain_start >= 0 < chain_end else ""

        def run_chain(state_files: list, *, recreate: bool, tag: str,
                      make_unreadable: bool = False, existing: bool = False) -> tuple:
            """Run the shipped block against a synthetic C:\\mr-hv-shaped root.

            The harness reproduces the script's own error regime. Under
            $ErrorActionPreference = 'Stop' a denied Test-Path throws instead of
            returning $false, so a harness left on the default 'Continue'
            exercises different control flow from the shipped route and would
            certify a branch production never takes.
            """
            root = work / f"chain-{tag}"
            state = root / "reviewer" / "state"
            state.mkdir(parents=True, exist_ok=True)
            for leaf in state_files:
                (state / leaf).write_bytes(b"synthetic-sealed-material")
            # Present but not enumerable is the shape a half-applied ACL leaves,
            # and the one Test-Path reports identically to absent. Whether that
            # denial can be built with a DACL depends on the token and the
            # owner, and it did not reproduce from this session -- so it is
            # injected at the call rather than asserted about the platform. The
            # branch under test is the shipped one; only the failure it reacts
            # to is synthetic. Both probes are overridden, because the leaf test
            # runs first and would throw before the enumeration is reached.
            deny = ("function Test-Path { throw 'synthetic access denial' }\n"
                    "function Get-ChildItem { throw 'synthetic access denial' }\n"
                    ) if make_unreadable else ""
            harness = work / f"chain-{tag}.ps1"
            harness.write_text(
                "Set-StrictMode -Version 2.0\n"
                "$ErrorActionPreference = 'Stop'\n"
                + deny
                + f"$HvRoot = '{root}'\n"
                f"$User = 'MR-SYNTHETIC-REVIEWER'\n"
                f"$existing = ${str(bool(existing)).lower()}\n"
                f"$RecreateReviewerCredential = ${str(bool(recreate)).lower()}\n"
                + chain_text
                + "\nWrite-Output 'CHAIN-PROCEEDED'\n", encoding="utf-8")
            try:
                out = subprocess.run(
                    [str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                     "Bypass", "-File", str(harness)],
                    capture_output=True, text=True, timeout=180)
                text = (out.stdout or "") + (out.stderr or "")
                return (out.returncode, text, text.strip().replace("\n", " ")[:180])
            except (OSError, subprocess.SubprocessError) as exc:
                return (-1, "", type(exc).__name__)

        key_rc, key_text, key_detail = run_chain(
            ["review-key.dpapi"], recreate=False, tag="key")
        rec("OP48 a-live-signing-key-stops-the-route-that-resets-the-password",
            bool(chain_text) and key_rc == 2
            and "OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE" in key_text
            and "CHAIN-PROCEEDED" not in key_text,
            f"the shipped block, run verbatim against a state directory holding "
            f"review-key.dpapi, refuses with the named reason and does not fall "
            f"through to the password prompt ({key_detail or 'no output'})")

        cred_rc, cred_text, cred_detail = run_chain(
            ["e2-guest.cred"], recreate=False, tag="cred")
        rec("OP48a the-guest-credential-alone-is-also-enough-to-stop-it",
            cred_rc == 2 and "OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE" in cred_text,
            f"the second sealed artifact is judged by the same block rather than "
            f"only the signing key, so a host that holds one but not the other is "
            f"not the unguarded counterpart ({cred_detail or 'no output'})")

        # A CLEAN HOST MUST STILL BOOTSTRAP. This is also the check that proves
        # the lifted region parses and executes -- a mis-cut region fails here.
        clean_rc, clean_text, clean_detail = run_chain([], recreate=False, tag="clean")
        rec("OP48b a-first-time-host-is-not-refused",
            clean_rc == 0 and "CHAIN-PROCEEDED" in clean_text
            and "OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE" not in clean_text,
            f"with no sealed material the block proceeds, so the refusal is bound "
            f"to the material and has not simply disabled first-time bootstrap -- "
            f"and the region is executable as lifted ({clean_detail or 'no output'})")

        byp_rc, byp_text, byp_detail = run_chain(
            ["review-key.dpapi"], recreate=True, tag="bypass")
        rec("OP48c the-deliberate-rebuild-switch-is-reachable",
            byp_rc == 0 and "CHAIN-PROCEEDED" in byp_text and "WARNING" in byp_text,
            f"-RecreateReviewerCredential proceeds and says what it is destroying, "
            f"so a genuine rebuild is possible without editing the script "
            f"({byp_detail or 'no output'})")

        # FAIL CLOSED WHEN THE ANSWER CANNOT BE ESTABLISHED. Test-Path reports
        # "absent" and "cannot look" identically, and taking that at face value
        # would license the reset on exactly the damaged host that most needs
        # protecting.
        dark_rc, dark_text, dark_detail = run_chain(
            [], recreate=False, tag="dark", make_unreadable=True)
        rec("OP48d an-unreadable-state-directory-refuses-rather-than-proceeds",
            dark_rc == 2 and "OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE" in dark_text,
            f"a state directory that exists but cannot be enumerated is treated "
            f"as possibly holding sealed material, not as holding none, and it "
            f"reaches the NAMED refusal rather than dying on the raw "
            f"access-denied that 'Stop' turns the probe into "
            f"({dark_detail or 'no output'})")

        # THE LEAST CERTAIN ARM WAS THE QUIETEST. The refusal covered three
        # conditions and the warning covered one, so an operator who bypassed
        # "I cannot establish whether material is present" was told nothing at
        # all about what the bypass was about to destroy.
        warn_rc, warn_text, warn_detail = run_chain(
            [], recreate=True, tag="darkwarn", make_unreadable=True)
        rec("OP48h the-bypass-warns-on-every-arm-it-can-bypass",
            warn_rc == 0 and "CHAIN-PROCEEDED" in warn_text and "WARNING" in warn_text,
            f"bypassing the unestablished-state arm still says what is being "
            f"destroyed, so the warning covers the same conditions the refusal "
            f"does ({warn_detail or 'no output'})")

        # POSITION, PINNED. Refusing after New-LocalUser would leave a fresh
        # principal behind on the host the operator was told was untouched, and
        # the reset itself must be downstream or the guard is decorative.
        # AN INVOCATION, NOT A SPELLING.
        #
        # These two located the account cmdlets with `find`/`re.findall` over
        # one exact spelling of one argument order. Seven ordinary alternatives
        # -- a pipeline, lowercase $user, "$User", splatting, reordered
        # parameters, positional, -InputObject -- are the same call and matched
        # none of them, so a second unguarded reset could be added and both
        # checks would still report a single site above the guard. Measuring the
        # text next to the call instead of the call is the third recurring
        # defect shape in this codebase, committed by the check written to close
        # the second one.
        #
        # The parser answers instead: every CommandAst resolving to the cmdlet,
        # whatever it looks like. Offsets are into the raw file, and so is the
        # marker search, so the two are comparable.
        ast_probe = work / "account-cmdlet-ast.ps1"
        ast_probe.write_text(
            "$e = $null\n"
            "$ast = [System.Management.Automation.Language.Parser]::ParseFile(\n"
            "    $env:MR_BOOT_PATH, [ref]$null, [ref]$e)\n"
            "if ($e.Count) { Write-Output '[]'; exit 0 }\n"
            "$found = $ast.FindAll({ param($n)\n"
            "    $n -is [System.Management.Automation.Language.CommandAst] }, $true)\n"
            "$rows = @()\n"
            "foreach ($c in $found) {\n"
            "    $name = $c.GetCommandName()\n"
            "    if (-not $name) { continue }\n"
            "    if ('set-localuser', 'new-localuser' -contains $name.ToLowerInvariant()) {\n"
            "        $rows += [ordered]@{ name = $name.ToLowerInvariant()\n"
            "                             offset = $c.Extent.StartOffset }\n"
            "    }\n"
            "}\n"
            "if (-not $rows.Count) { Write-Output '[]' }\n"
            "else { ConvertTo-Json -InputObject @($rows) -Depth 3 -Compress }\n",
            encoding="utf-8")
        boot_path = str(ROOT / "packaging" / "hyperv" / "reviewer_bootstrap.ps1")
        try:
            ast_out = subprocess.run(
                [str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                 "Bypass", "-File", str(ast_probe)],
                capture_output=True, text=True, timeout=180,
                env={**os.environ, "MR_BOOT_PATH": boot_path})
            account_cmds = json.loads((ast_out.stdout or "[]").strip() or "[]")
        except (OSError, subprocess.SubprocessError, ValueError):
            account_cmds = []
        resets = sorted(c["offset"] for c in account_cmds if c["name"] == "set-localuser")
        creates = sorted(c["offset"] for c in account_cmds if c["name"] == "new-localuser")

        guard_at = raw_boot.find("# ---- live credential chain")
        rec("OP48e the-refusal-precedes-account-creation-and-the-reset",
            guard_at >= 0 and len(creates) == 1 and len(resets) == 1
            and guard_at < creates[0] < resets[0]
            and "OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE" in raw_boot,
            f"the block sits above every parsed New-LocalUser and Set-LocalUser "
            f"invocation, so a refusal cannot leave a half-created principal and "
            f"cannot be reached after the damage (guard@{guard_at}, "
            f"creates={creates}, resets={resets})")

        rec("OP48f the-account-password-still-has-a-single-invocation",
            len(resets) == 1 and bool(account_cmds),
            f"the parser finds exactly one Set-LocalUser invocation in the "
            f"elevated script, in any spelling, so the guard above it covers "
            f"the whole credential route ({len(resets)} invocation(s), "
            f"{len(creates)} creation(s))")

        # THE ACCOUNT IS THE SUBJECT OF THE RESET.
        #
        # Gating on material found under $HvRoot let `-HvRoot <anywhere else>`
        # -- a different parameter from the $User being reset -- report no
        # material and proceed, resetting the live account whose sealed state
        # sits under the real root. Denial keyed to one operand, damage keyed to
        # the other: the closed defect, one level along.
        acct_rc, acct_text, acct_detail = run_chain(
            [], recreate=False, tag="acct", existing=True)
        rec("OP48g an-existing-account-refuses-even-when-the-root-holds-nothing",
            acct_rc == 2 and "OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE" in acct_text
            and "CHAIN-PROCEEDED" not in acct_text,
            f"an inspected root with no sealed material does not license the "
            f"reset while the account it would reset exists, so pointing the run "
            f"at another root cannot reach it ({acct_detail or 'no output'})")

        # ------------------------------ the tree the scheduled task runs from
        # THE DESTINATION TREE, NOT ONLY THE SOURCE TREE.
        #
        # Test-CanAuthorWriteReviewerCode tested the container and stopped, so a
        # file-level Allow ACE on reviewer_session.ps1 -- the entry point the
        # task executes -- inside a clean, protected reviewer-bin produced no
        # reason at all. The identical leaf-only shape had already been fixed in
        # Assert-TrustedSourceRoot, on the tree the files are copied FROM.
        code_dir = work / "reviewer-bin"
        code_dir.mkdir(exist_ok=True)
        planted_code = probe({"action": "reviewer-code-ace", "path": str(code_dir),
                              "author": identity("SYNTH", SID_AUTHOR),
                              "plant_file_ace": True}, work)["value"] or {}
        clean_code = work / "reviewer-bin-clean"
        clean_code.mkdir(exist_ok=True)
        unplanted_code = probe({"action": "reviewer-code-ace", "path": str(clean_code),
                                "author": identity("SYNTH", SID_AUTHOR),
                                "plant_file_ace": False}, work)["value"] or {}
        rec("OP37 an-author-ace-on-the-entry-point-is-detected",
            planted_code.get("gate_says_writable") is True
            and planted_code.get("container_is_writable") is False
            and unplanted_code.get("gate_says_writable") is False,
            f"an author ACE on the file the scheduled task runs is reported even "
            f"though the directory holding it grants the author nothing, and the "
            f"same tree without that ACE is not "
            f"(planted={planted_code}, clean={unplanted_code})")

        # ---------------------------- both interpreter-executing routes gated
        # -ProvisionReviewerRuntime refused an author-writable build source
        # because it COPIES from it. -HardenInterpreter EXECUTED the same
        # operator-named interpreter at High integrity, with no writability
        # check of any kind, and then trusted the JSON that execution printed to
        # decide whether to lock and pin the runtime.
        boot_body = function_bodies(boot_live)
        executing_routes = [name for name, body in boot_body.items()
                            if "$BuildPython $" in body or "& $BuildPython" in body]
        gated = re.findall(r"Assert-InterpreterSourceTrusted\s+-Interpreter", boot_live)
        top_level_exec = len(re.findall(r"&\s+\$BuildPython\s", boot_live))

        # PER ROUTE, AND BEFORE. Counting gate calls against execution sites
        # cannot see WHICH route each one is in: deleting the gate from
        # -HardenInterpreter and adding a decorative second call inside
        # -ProvisionReviewerRuntime kept the totals equal, restored an
        # ungated `& $BuildPython` at High integrity, and left a check named
        # "checks it first" green. Each top-level `if ($Switch) { ... }` block
        # is isolated by brace counting and asked the question separately.
        def route_blocks(source: str) -> list:
            blocks = []
            for opener in re.finditer(r"^if \(\$[A-Za-z]+\) \{", source, re.M):
                depth, cursor = 0, opener.end() - 1
                while cursor < len(source):
                    if source[cursor] == "{":
                        depth += 1
                    elif source[cursor] == "}":
                        depth -= 1
                        if depth == 0:
                            break
                    cursor += 1
                blocks.append(source[opener.start():cursor + 1])
            return blocks

        ungated_routes = []
        for block in route_blocks(boot_live):
            execution = re.search(r"&\s+\$BuildPython\s", block)
            if not execution:
                continue
            gate = re.search(r"Assert-InterpreterSourceTrusted\s+-Interpreter", block)
            if not gate or gate.start() > execution.start():
                header = block.splitlines()[0].strip()
                ungated_routes.append(header)
        # ONE GATE PER EXECUTION, not "all but one". `>= top_level_exec - 1`
        # passed at (1, 2) -- exactly the state the file was in -- so deleting
        # the entire writability check protecting the other route left a check
        # named "every-route-...-first" green.
        rec("OP38 every-route-that-executes-an-interpreter-checks-it-first",
            top_level_exec >= 1 and len(gated) >= top_level_exec and not ungated_routes,
            f"every route that runs an operator-named interpreter invokes the "
            f"trust gate BEFORE it, in its own block ({len(gated)} gate call(s), "
            f"{top_level_exec} execution(s), ungated routes="
            f"{ungated_routes or 'none'}, helper-scoped routes="
            f"{executing_routes or 'none'})")

        interpreter_helper = boot_body.get("Get-AuthorWritableInterpreterPaths", "")
        rec("OP38a the-interpreter-check-covers-the-application-directory",
            "$buildRoot" in interpreter_helper and "-File" in interpreter_helper,
            "the interpreter's own directory is examined, not only DLLs and Lib "
            "-- the application directory is first in the Windows DLL search "
            "order and python3xx.dll lives there, not under DLLs")

        # ------------------------------------------ the verdict channel itself
        # A REPORTER MUST NOT RETURN ITS VERDICT DOWN THE STREAM IT PRINTS TO.
        #
        # Write-Fact emits with Write-Output, so wrapping the reporter in @(...)
        # collected twelve transcript LINES as though each were a violation.
        # Measured against zero real violations, the gate refused -- so
        # -ProvisionPaths and -Verify failed on a fully compliant host, and the
        # verdict carried no signal: a compromised host and a clean one produced
        # the same refusal.
        channel = probe({"action": "reason-channel"}, work)["value"] or {}
        rec("OP34 the-verdict-channel-is-not-the-transcript-channel",
            channel.get("stream_reasons") == 2 and channel.get("ref_reasons") == 0,
            f"a reporter that returns its verdict on the success stream hands the "
            f"caller its own prose as violations, and one that writes into a "
            f"caller-supplied list hands over exactly nothing when there is "
            f"nothing to report ({channel})")

        # EVERY CALL SITE, AND THE EXEMPTION PINNED TO ONE OF THEM.
        #
        # Both counters keyed on the literal `$measured`; the bootstrap route
        # uses `$bootstrapMeasured`, so it sat outside the count and deleting
        # its verdict left the battery green -- the exact regression the route
        # was given a verdict to close. And nothing pinned the confinement of
        # -PendingAuthorTaskGrant: appending it to the other two sites was
        # invisible, so the two excused task reasons could be waived everywhere.
        reporter_calls = len(re.findall(r"Write-PrincipalCapabilityFacts\b", boot_live)) - 1
        verdict_calls = len(re.findall(r"Assert-CapabilitiesAcceptable\s+-Reasons\s+\$",
                                       boot_live))
        # CALL-SITE uses only. The parameter is DECLARED with a `$`, so a
        # dash-anchored pattern counts applications and not the declaration --
        # and the property that matters is that the exemption is APPLIED on
        # exactly one route, never that it is mentioned a certain number of
        # times.
        pending_uses = len(re.findall(r"-PendingAuthorTaskGrant\b", boot_live))
        # AND THE EXCUSED SET ITSELF. Counting applications does not stop the
        # DEFAULT branch being widened: adding the two task reasons to the
        # `else` arm waives them on -Verify and -ProvisionPaths as well, with
        # every count unchanged. The unexempted branch must excuse exactly one
        # reason, and that reason must be the absent-task one.
        # SEARCHED IN THE RAW TEXT. boot_live has every string literal blanked --
        # which is what stops a function name inside a string reading as a call
        # -- so the reason names this check is looking for were filler by the
        # time it saw them, and the inspection silently found nothing.
        default_arm = re.search(r"\}\s*else\s*\{\s*@\(([^)]*)\)\s*\}", boot_text)
        default_excused = []
        if default_arm:
            default_excused = re.findall(r"'([A-Z_]+)'", default_arm.group(1))
        rec("OP34a no-gate-is-fed-from-a-captured-stream",
            "Assert-CapabilitiesAcceptable -Reasons @(" not in boot_live
            and reporter_calls == 3 and verdict_calls == 3 and pending_uses == 1
            and default_excused == ["OFFLINE_TASK_ABSENT"],
            f"all three routes report through a caller-owned list and feed it to "
            f"the verdict, and the pending-grant exemption is APPLIED on exactly "
            f"one route, so it cannot be widened to "
            f"a route that has no grant pending "
            f"(reporters={reporter_calls}, verdicts={verdict_calls}, "
            f"pending={pending_uses}, default-excused={default_excused})")

        # ------------------------------------------- the creation route exists
        # The switch that lets the ONE route which creates the reviewer run
        # before the reviewer exists had no call site anywhere in the tree, so
        # the top-level gate refused with OFFLINE_REVIEWER_ACCOUNT_UNRESOLVED
        # and exited before New-LocalUser. The step that establishes the whole
        # protocol was unreachable in the only state that needs it.
        absent_reviewer = probe(baseline_case(
            reviewer=identity("REVIEWER", SID_REVIEWER, exists=False)), work)["reasons"]
        rec("OP35 an-absent-reviewer-blocks-the-contract-by-default",
            "OFFLINE_REVIEWER_ACCOUNT_UNRESOLVED" in absent_reviewer,
            f"a reviewer that does not exist is refused unless the caller says "
            f"it is about to create one ({absent_reviewer})")
        rec("OP35a the-creation-route-passes-the-switch",
            re.search(r"Assert-OperatorIsNotAuthor[^\n]*\n?[^\n]*-AllowAbsentReviewer",
                      boot_live) is not None,
            "the top-level principal gate relaxes the existence clause, so the "
            "route that creates the reviewer can run on a host without one")

        # ------------------------------------ the provisioning ACL is workable
        # THE OPERATOR MUST BE ABLE TO WRITE ITS OWN DECLARATIONS.
        #
        # The reviewer-owned grant used to be reviewer + SYSTEM + author-read
        # with no Administrators ACE, and the operator writes two of its own
        # files into that tree. Measured from an elevated session that OWNED the
        # directory: icacls answered "Access is denied" and Set-Content raised
        # UnauthorizedAccessException, so -ProvisionPaths, -HardenInterpreter and
        # the no-switch bootstrap all died -- the last after setting the reviewer
        # password and before registering the task. The three properties the
        # grant has to hold simultaneously are asserted here together.
        acl_dir = work / "provision-acl"
        acl_dir.mkdir(exist_ok=True)
        grant = probe({"action": "provision-acl", "path": str(acl_dir),
                       "author": identity("SYNTH", SID_AUTHOR)}, work)["value"] or {}
        rec("OP33 the-reviewer-owned-grant-admits-the-operator",
            grant.get("operator_wrote") is True
            and grant.get("author_can_write") is False
            and grant.get("author_can_read") is True,
            f"an elevated session can create the declaration in the tree it is "
            f"provisioning, a non-administrative author cannot rewrite it, and "
            f"the author can still read the declaration it is bound by ({grant})")

        # ------------------------------- a file-level ACE inside a clean root
        # THE OBJECTS THE ELEVATED SESSION EXECUTES ARE FILES.
        #
        # The recursive author-writability scan was -Directory only, so a file
        # carrying an Allow ACE inside an otherwise clean, protected root
        # produced no reason -- and the elevated session executes
        # offline_reviewer_runtime.py out of that tree and copies the reviewer's
        # own session scripts from it. `icacls /T /C` returning 0 having silently
        # skipped one open file is a documented route to exactly that state.
        root_dir = work / "source-root"
        root_dir.mkdir(exist_ok=True)
        planted = probe({"action": "source-root-file-ace", "path": str(root_dir),
                         "author": identity("SYNTH", SID_AUTHOR),
                         "plant_file_ace": True}, work)["value"] or {}
        clean_dir = work / "source-root-clean"
        clean_dir.mkdir(exist_ok=True)
        unplanted = probe({"action": "source-root-file-ace", "path": str(clean_dir),
                           "author": identity("SYNTH", SID_AUTHOR),
                           "plant_file_ace": False}, work)["value"] or {}
        rec("OP36 a-file-level-author-ace-is-visible",
            planted.get("file_is_author_writable") is True
            and planted.get("directory_is_author_writable") is False
            and unplanted.get("file_is_author_writable") is False,
            f"a file the author can write inside a directory the author cannot "
            f"is detected as writable, and the same tree without the planted ACE "
            f"is not -- so a scan that skips files skips the objects that matter "
            f"(planted={planted}, clean={unplanted})")

        hyperv_dir = ROOT / "packaging" / "hyperv"
        contract_live = strip_powershell_comments(
            (hyperv_dir / "principal_contract.ps1").read_text(encoding="utf-8"))
        rec("OP36a the-source-root-scan-enumerates-files",
            "-Recurse -Force -Directory" not in contract_live
            and "-Recurse -Force `" in contract_live,
            "the source-root scan enumerates every child, not directories only")

        # ------------------------------------------ the write predicate itself
        # THE ARITHMETIC, ON DACL SHAPES THIS HOST DOES NOT PROVIDE.
        #
        # Every author-writability gate in the protocol funnels through
        # Test-AccountCanWritePath, and nothing drove it against a DACL carrying
        # a Deny ACE. `$mask` inside its ACE loop WAS its own `[int]$Mask`
        # parameter -- PowerShell variable names are case-insensitive -- so the
        # loop overwrote the question with the last matching ACE's rights before
        # the comparison could read it. A trailing Deny made a fully
        # author-controlled tree report "cannot write", and a read-only ACE made
        # a correctly locked one report "can write". The identity is synthetic
        # and in no local group, so neither the ownership short-circuit nor
        # Administrators membership can mask the arithmetic.
        SYNTH = identity("SYNTH", SID_AUTHOR)
        mask_cases = (
            ("full-control-then-trailing-deny",
             f"O:SYG:SYD:P(A;;FA;;;{SID_AUTHOR})(A;;FA;;;SY)(D;;0x10000;;;{SID_AUTHOR})",
             0xD0116, True),
            ("read-only-ace",
             f"O:SYG:SYD:P(A;;FA;;;SY)(A;;0x120089;;;{SID_AUTHOR})", 0xD0116, False),
            ("append-only-under-the-ancestor-mask",
             f"O:SYG:SYD:P(A;;FA;;;SY)(A;;0x4;;;{SID_AUTHOR})", 0xD0042, False),
            ("append-only-under-the-default-mask",
             f"O:SYG:SYD:P(A;;FA;;;SY)(A;;0x4;;;{SID_AUTHOR})", 0xD0116, True),
            ("deny-write-over-allow-all-leaves-WRITE_DAC",
             f"O:SYG:SYD:P(A;;FA;;;{SID_AUTHOR})(D;;0x116;;;{SID_AUTHOR})(A;;FA;;;SY)",
             0xD0116, True),
        )
        wrong = []
        for index, (name, sddl, mask, want) in enumerate(mask_cases):
            target = work / f"mask-{index}"
            target.mkdir(exist_ok=True)
            got = probe({"action": "write-mask", "path": str(target), "sddl": sddl,
                         "mask": mask, "author": SYNTH}, work)["value"]
            if got is not want:
                wrong.append(f"{name}: want={want} got={got}")
        rec("OP31 the-write-predicate-answers-the-question-it-was-asked",
            not wrong,
            f"all {len(mask_cases)} DACL shapes score correctly -- a trailing Deny "
            f"does not erase a full-control grant, a read-only ACE is not a write, "
            f"and the narrowed ancestor mask actually narrows "
            f"({'; '.join(wrong) if wrong else 'no disagreement'})")

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
        declared = re.findall(r"^function ([A-Za-z][A-Za-z0-9\-]*)", contract_text, re.M)
        production = [p for p in sorted(hyperv.glob("*.ps1"))
                      if p.name not in ("principal_contract.ps1", "principal_contract_probe.ps1")]
        prod_sources = [p.read_text(encoding="utf-8") for p in production]

        # EVERY FUNCTION IN THE ELEVATED SCRIPTS, not only the shared contract.
        # Assert-CapabilitiesAcceptable and Write-PrincipalCapabilityFacts -- the
        # two the previous [void](...) and captured-stream defects lived in --
        # were outside `declared`, so nothing noticed if their call sites went
        # away.
        declared = declared + [line.split()[1] for source in prod_sources
                               for line in source.splitlines()
                               if line.startswith("function ")]

        def unreached_in(sources: list) -> list:
            live = reachable_names(sources + [contract_text], declared)
            return sorted(n for n in declared if n not in live)

        unreached = unreached_in(prod_sources)
        rec("OP30 every-contract-function-is-reached-from-live-code",
            not unreached and len(declared) >= 20,
            f"all {len(declared)} functions in the shared contract are reached "
            f"transitively from top-level code, with comments stripped and calls "
            f"inside uninvoked functions not counted "
            f"(unreached={unreached or 'none'})")

        # THE MUTATION. The previous form searched raw text for the name and
        # accepted a mention in a comment or a call inside dead code -- which is
        # how it certified Assert-TrustedSourceRoot as reached while its only
        # production occurrence sat inside Assert-TrustedOperatorSource, a
        # function nothing invoked.
        boot = hyperv / "reviewer_bootstrap.ps1"
        # LOCATED BY PATTERN, NOT BY A FIXED ARGUMENT LIST. Both mutations were
        # anchored on the exact arguments of the invocation, so adding -Reviewer
        # to it turned them into silent no-ops. They failed rather than passed,
        # which is the right direction, but a mutation that cannot be applied
        # proves nothing either way. The whole invocation is captured, backtick
        # continuations included, and both checks assert it was applied.
        gate_call = re.search(r"^Assert-TrustedOperatorSource\b(?:[^\n]*`\n)*[^\n]*",
                              boot_text, re.M)
        gate_line = gate_call.group(0) if gate_call else ""
        severed = (boot_text.replace(
            gate_line, "\n".join("# " + part for part in gate_line.splitlines()), 1)
            if gate_line else boot_text)
        severed_sources = [severed if p.name == "reviewer_bootstrap.ps1" else text
                           for p, text in zip(production, prod_sources)]
        severed_unreached = unreached_in(severed_sources)
        rec("OP30a a-gate-with-no-live-call-site-is-detected",
            severed != boot_text and "Assert-TrustedSourceRoot" in severed_unreached,
            f"commenting out the one live call to the source-boundary gate leaves "
            f"the contract function it wraps unreached, and is reported "
            f"({severed_unreached or 'none'})")

        stringified = (boot_text.replace(
            gate_line, "Write-Output '" + gate_line.replace("`\n", " ") + "'", 1)
            if gate_line else boot_text)
        stringified_sources = [stringified if p.name == "reviewer_bootstrap.ps1" else text
                               for p, text in zip(production, prod_sources)]
        stringified_unreached = unreached_in(stringified_sources)
        rec("OP30b a-call-site-replaced-by-a-string-is-detected",
            stringified != boot_text
            and "Assert-TrustedSourceRoot" in stringified_unreached,
            f"turning the one live invocation into a printed string -- which "
            f"disables the boundary while leaving the name in the file -- is "
            f"reported as unreached ({stringified_unreached or 'none'})")

        # Reachability is a static answer, so dynamic dispatch would make it a
        # guess. There is none, and there must not be.
        dynamic = [p.name for p, text in zip(production, prod_sources)
                   if re.search(r"(?<![\w-])(Invoke-Expression|iex)\s",
                                strip_powershell_comments(text))]
        rec("OP30c no-dynamic-dispatch-in-the-elevated-scripts",
            not dynamic,
            f"no production script builds a command from a string, so a static "
            f"reachability answer is the whole answer ({dynamic or 'none'})")

        # ------------------------------------- the elevated script's own ordering
        # A TOP-LEVEL READ BEFORE THE ASSIGNMENT IS A TERMINATING ERROR.
        #
        # StrictMode 2.0 arrives with the dot-source, so `$AuthorIdentity` read
        # above its assignment killed every route -- -Verify, -ProvisionPaths,
        # -ExportSource, -StagePackage, -HardenInterpreter,
        # -ProvisionReviewerRuntime, -GrantAuthorTaskRun, -RepinReviewerCode and
        # the no-switch bootstrap -- with a raw VariableIsUndefined and no named
        # reason. Nothing caught it because Assert-SelfSourceTrusted passes first
        # in the accepted configuration.
        stripped_boot = strip_powershell_comments(boot_text)
        bodies = function_bodies(stripped_boot)
        top_only = stripped_boot
        for body in bodies.values():
            top_only = top_only.replace(body, "", 1)
        early = []
        for variable in ("$AuthorIdentity", "$OperatorIdentity", "$ReviewerIdentity", "$gitExe"):
            # Aligned assignments (`$gitExe   = ...`) are still assignments;
            # matching a single space reported the variable as never assigned.
            found = re.search(rf"{re.escape(variable)}\s*=(?!=)", top_only)
            if not found:
                early.append(f"{variable}: never assigned at top level")
                continue
            assignment = found.start()
            first_use = top_only.find(variable)
            if first_use < assignment:
                early.append(f"{variable}: read at {first_use}, assigned at {assignment}")
        rec("OP32 top-level-state-is-assigned-before-it-is-read",
            not early,
            f"no top-level statement in the elevated script reads a resolved "
            f"principal or a resolved binary above its own assignment "
            f"({early or 'none'})")

        # THE MUTATION: put the git resolution back above the identity it
        # consumes, which is exactly the shape that shipped.
        git_line = "$gitExe   = Resolve-TrustedGit -Explicit $TrustedGit -Author $AuthorIdentity"
        anchor = "# THE THREE PRINCIPALS, RESOLVED ONCE AND NEVER RE-DERIVED."
        newline = chr(10)
        reordered = boot_text.replace(git_line + newline, "", 1).replace(
            anchor, git_line + newline + anchor, 1)
        stripped_bad = strip_powershell_comments(reordered)
        top_bad = stripped_bad
        for body in function_bodies(stripped_bad).values():
            top_bad = top_bad.replace(body, "", 1)
        found = re.search(r"\$gitExe\s*=(?!=)", top_bad)
        caught = (reordered != boot_text and found is not None
                  and top_bad.find("$AuthorIdentity") <
                  re.search(r"\$AuthorIdentity\s*=(?!=)", top_bad).start())
        rec("OP32a a-read-above-its-assignment-is-detected",
            caught,
            f"moving the git resolution back above the principal it consumes is "
            f"reported as a read before assignment -- the shape that made every "
            f"route die on a raw VariableIsUndefined under StrictMode "
            f"(mutation-applied={reordered != boot_text}, detected={caught})")

        print()
    finally:
        # THE FIXTURES ARE SYSTEM-OWNED AND PROTECTED, so rmtree cannot remove
        # them and ignore_errors hid that: every run left a directory behind
        # that the module docstring calls disposable and that in fact required
        # an ownership write to delete. Ownership first, then the ACL, then the
        # tree -- and only ever this run's own directory.
        if os.name == "nt" and work.exists():
            for command in (["takeown.exe", "/F", str(work), "/R", "/D", "Y"],
                            ["icacls.exe", str(work), "/reset", "/T", "/C", "/Q"]):
                try:
                    subprocess.run(command, capture_output=True, text=True, timeout=180)
                except (OSError, subprocess.SubprocessError):
                    pass
        shutil.rmtree(work, ignore_errors=True)
        if work.exists():
            print(json.dumps({"guard": "offline-operator-principal",
                              "warning": "scratch directory could not be removed",
                              "detail": work.name}, indent=2))

    # A FLOOR ASSERTED FROM THE RUN, not from a static count of the source.
    # The manifest's count is a text-shaped proxy and can be restored by adding
    # string constants; this one is the number of checks that actually
    # executed. Both are kept: the manifest catches deletion without running
    # anything, this catches hollowing at run time.
    # REPORTED DIRECTLY, NOT THROUGH rec().
    #
    # Making rec() a no-op that returns True is a one-line, syntactically valid
    # edit. It leaves every check id in the file -- so the manifest's static
    # count is unchanged -- and empties CHECKS, so this floor's own failure was
    # recorded through the same no-op and vanished, and main() returned 0 with
    # zero checks executed. The floor cannot be allowed to depend on the
    # mechanism it exists to police.
    MINIMUM_CHECKS = 69
    if len(CHECKS) < MINIMUM_CHECKS:
        print(json.dumps({
            "guard": "offline-operator-principal",
            "error": "OFFLINE_PRINCIPAL_BATTERY_HOLLOW",
            "detail": f"only {len(CHECKS)} checks executed, below the pinned "
                      f"minimum of {MINIMUM_CHECKS}",
        }, indent=2))
        return 1

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
