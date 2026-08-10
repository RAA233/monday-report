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


def _ps_literal(value: str) -> str:
    """A single-quoted PowerShell string literal for an arbitrary value."""
    return "'" + str(value).replace("'", "''") + "'"

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

        # A STRUCTURALLY CLEAN ROOT, so the missing-pin property is isolated.
        #
        # Assert-TrustedSourceRoot now returns before git the moment any
        # structural blocker (author-writable, inheriting, reparse, unenumerable)
        # is present -- correct, because running git against such a tree executes
        # author-named config programs at High integrity. The guard's own scratch
        # dir is inheriting and Authenticated-Users-writable, so it would refuse
        # for those structural reasons and never reach the missing-pin clause.
        # This fixture is made protected (no inheritance) and admin/SYSTEM only,
        # so no structural reason fires and EXPECTED_IDENTITY_MISSING is what a
        # missing pin produces.
        clean_root = work / "op25-clean"
        clean_root.mkdir(exist_ok=True)
        _icacls = str(Path(os.environ.get("SystemRoot", r"C:\Windows"))
                      / "System32" / "icacls.exe")
        for args in (["/inheritance:r"],
                     ["/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
                     ["/setowner", "*S-1-5-32-544"]):
            subprocess.run([_icacls, str(clean_root)] + args,
                           capture_output=True, text=True, timeout=60)
        no_identity = probe({"action": "trusted-source", "root": str(clean_root),
                             "author": identity("AUTHOR", SID_AUTHOR),
                             "expected_commit": "", "expected_tree": ""}, work)["reasons"]
        rec("OP25 missing-expected-identity-refused",
            "OFFLINE_SOURCE_ROOT_EXPECTED_IDENTITY_MISSING" in no_identity,
            f"a structurally clean source root with no externally supplied "
            f"commit/tree is refused rather than trusted on its own account "
            f"({no_identity})")

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

        def run_chain(state_files: list, *, recreate=False, tag: str,
                      make_unreadable: bool = False, account: str = "",
                      task: str = "", weaken: str = "",
                      task_name: str = "") -> tuple:
            """Run the shipped block against a synthetic C:\\mr-hv-shaped root.

            The harness reproduces the script's own error regime. Under
            $ErrorActionPreference = 'Stop' a denied Test-Path throws instead of
            returning $false, so a harness left on the default 'Continue'
            exercises different control flow from the shipped route and would
            certify a branch production never takes.

            $User and $TaskName are synthetic names that exist nowhere, so the
            account and task probes run for real and answer "absent" unless a
            presence is injected. Binding them to the live reviewer would make
            every case refuse and every check pass for the wrong reason.
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
            inject = ""
            if make_unreadable:
                # ADVANCED functions, so -ErrorAction is a real common parameter
                # and is honoured. A plain `function X { throw }` throws no
                # matter what the caller asks for, which made the weakening arm
                # of OP48j dead: the copy with -ErrorAction SilentlyContinue
                # still refused, for a reason unrelated to the copy. Write-Error
                # under the shipped 'Stop' is terminating and under
                # SilentlyContinue is not, which is the distinction being
                # measured.
                inject += (
                    "function Test-Path { [CmdletBinding()]\n"
                    "  param([Parameter(ValueFromRemainingArguments=$true)]$Rest)\n"
                    "  Write-Error 'synthetic access denial' }\n"
                    "function Get-ChildItem { [CmdletBinding()]\n"
                    "  param([Parameter(ValueFromRemainingArguments=$true)]$Rest)\n"
                    "  Write-Error 'synthetic access denial' }\n")
            # PRESENCE AND FAILURE. Every stub here used to SUCCEED, so each
            # probe's "I found it" direction was pinned and its "I could not
            # establish it" direction was not -- the same one-side-of-the-pair
            # shape the block itself was fixed for, committed by the checks
            # measuring the block. An advanced function is required for the
            # failure stubs so that -ErrorAction is honoured and the shipped
            # 'Stop' makes Write-Error terminating, exactly as the real cmdlet
            # would behave.
            if account == "present":
                inject += "function Get-LocalUser { [pscustomobject]@{ Name = $User } }\n"
            elif account == "unreadable":
                inject += ("function Get-LocalUser { [CmdletBinding()]\n"
                           "  param([Parameter(ValueFromRemainingArguments=$true)]$Rest)\n"
                           "  Write-Error 'synthetic SAM failure' }\n")
            if task == "present":
                inject += "function Get-ScheduledTask { [pscustomobject]@{ TaskName = $TaskName } }\n"
            elif task == "absent":
                # The cmdlet second opinion says absent. Only the schtasks
                # primary probe can still see the task, so this isolates it.
                inject += ("function Get-ScheduledTask { [CmdletBinding()]\n"
                           "  param([Parameter(ValueFromRemainingArguments=$true)]$Rest)\n"
                           "  Write-Error -Message 'not found' -Category ObjectNotFound }\n")
            elif task == "unreadable":
                inject += ("function Get-ScheduledTask { [CmdletBinding()]\n"
                           "  param([Parameter(ValueFromRemainingArguments=$true)]$Rest)\n"
                           "  Write-Error 'synthetic scheduler failure' }\n")
            body = chain_text
            if weaken:
                # A regression applied to the shipped text, to prove a check
                # notices. Kept out of the tracked file: only this copy changes.
                body = body.replace(weaken, weaken + " -ErrorAction SilentlyContinue")
            harness = work / f"chain-{tag}.ps1"
            harness.write_text(
                "Set-StrictMode -Version 2.0\n"
                "$ErrorActionPreference = 'Stop'\n"
                "$User = 'MR-SYNTHETIC-REVIEWER-NOT-ON-THIS-HOST'\n"
                + ("$TaskName = " + _ps_literal(
                    task_name or "MR-SYNTHETIC-TASK-NOT-ON-THIS-HOST") + "\n")
                # The block probes the task with the same binary the route uses
                # to overwrite it, so the harness must resolve it the way the
                # script does. Leaving it unbound made the probe throw under
                # StrictMode and every case refuse -- fail-closed, and detected
                # by the one check that asserts a clean host still proceeds.
                + ("$schtasks = '" + str(
                    Path(os.environ.get("SystemRoot", r"C:\Windows"))
                    / "System32" / "schtasks.exe") + "'\n")
                + inject
                + f"$HvRoot = '{root}'\n"
                # The bypass value is passed through verbatim so the comparison
                # itself is what gets exercised -- True means the exact phrase,
                # any other string is tested as written.
                + ("$DestroyReviewerCredentialChain = " + _ps_literal(
                    "DESTROY-THE-REVIEWER-KEY" if recreate is True
                    else (recreate or "")) + "\n")
                + body
                # utf-8-SIG. Windows PowerShell 5.1 decodes a BOM-less .ps1 with
                # the host ANSI code page, so the two invisible-suffix phrase
                # cases arrived as cp1252 mojibake -- U+FEFF as three printable
                # characters, U+00AD as two -- which every comparison rejects.
                # Measured: a soft hyphen round-trips as length 3 without a BOM
                # and 2 with one. The two cases that exist to tell an ordinal
                # comparison from a culture-sensitive one were the two that
                # could not, and what the check measured depended on the code
                # page of the host it ran on.
                + "\nWrite-Output 'CHAIN-PROCEEDED'\n", encoding="utf-8-sig")
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
            f"-DestroyReviewerCredentialChain proceeds and says what it is destroying, "
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
        # Three things the first attempt at this got wrong, all in the pass
        # direction:
        #
        # ONE FILE. It parsed reviewer_bootstrap.ps1 alone, but the elevated
        # program is that file plus everything it dot-sources, and a reset added
        # to principal_contract.ps1 would have been invisible to a check whose
        # whole claim is "there is one reset". Every script on the trust path is
        # parsed now.
        #
        # ONE SPELLING, AGAIN. GetCommandName() returns what was written, so
        # `Microsoft.PowerShell.LocalAccounts\Set-LocalUser` is not equal to
        # `set-localuser` and slipped through the equality that replaced the
        # regex. Compared on the last backslash-delimited segment.
        #
        # TWO COORDINATE SPACES. The ordering compared raw_boot.find() -- a
        # Python offset into text read with universal newlines -- against
        # Extent.StartOffset, a PowerShell offset into the file. On a CRLF
        # checkout those diverge, and they diverge by shrinking the Python side,
        # which moves the marker EARLIER and makes the ordering assertion easier
        # to satisfy. The marker offset is measured by the same parser now, so
        # there is one space.
        ast_probe = work / "account-cmdlet-ast.ps1"
        ast_probe.write_text(
            "$rows = @()\n"
            "$parseFailed = $false\n"
            "foreach ($p in ($env:MR_SCAN_PATHS -split ';')) {\n"
            "    if (-not $p) { continue }\n"
            "    $e = $null\n"
            "    $ast = [System.Management.Automation.Language.Parser]::ParseFile(\n"
            "        $p, [ref]$null, [ref]$e)\n"
            "    if ($e.Count -or -not $ast) { $parseFailed = $true; continue }\n"
            "    $leaf = Split-Path -Leaf $p\n"
            "    foreach ($c in $ast.FindAll({ param($n)\n"
            "            $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {\n"
            "        $name = $c.GetCommandName()\n"
            "        if (-not $name) { continue }\n"
            "        $short = ($name -split '\\\\')[-1].ToLowerInvariant()\n"
            "        if ('set-localuser', 'new-localuser' -contains $short) {\n"
            "            # WHOSE ACCOUNT DATABASE. Two of these run inside the\n"
            "            # Hyper-V guest and touch nothing here. Lexical\n"
            "            # ancestry does NOT establish that: an expression in\n"
            "            # -ArgumentList is evaluated by the LOCAL session before\n"
            "            # dispatch, and -ComputerName/-Session name this host as\n"
            "            # readily as another. Classifying by ancestry let two\n"
            "            # planted host-side resets above the marker be reported\n"
            "            # as guest calls -- a false statement, not just a miss.\n"
            "            #\n"
            "            # The call must sit INSIDE the scriptblock that is bound\n"
            "            # to -ScriptBlock of an Invoke-Command carrying -VMName\n"
            "            # or -VMId. That is the only construct here whose body\n"
            "            # provably executes in the guest. Anything else counts\n"
            "            # as host-side, which is the failing direction.\n"
            "            $guest = $false\n"
            "            $n = $c\n"
            "            while ($n -and -not $guest) {\n"
            "                $sb = $n\n"
            "                if ($sb -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) {\n"
            "                    $cmd = $sb.Parent\n"
            "                    if ($cmd -is [System.Management.Automation.Language.CommandAst]) {\n"
            "                        $cn = $cmd.GetCommandName()\n"
            "                        if ($cn -and ($cn -split '\\\\')[-1].ToLowerInvariant() -eq 'invoke-command') {\n"
            "                            $els = @($cmd.CommandElements)\n"
            "                            $idx = [Array]::IndexOf($els, $sb)\n"
            "                            $boundToScriptBlock = $false\n"
            "                            if ($idx -gt 0) {\n"
            "                                $prev = $els[$idx - 1]\n"
            "                                if ($prev -is [System.Management.Automation.Language.CommandParameterAst] `\n"
            "                                    -and $prev.ParameterName -match '^(sb|scr|script|scriptb|scriptbl|scriptblo|scriptbloc|scriptblock)$') {\n"
            "                                    $boundToScriptBlock = $true\n"
            "                                }\n"
            "                            }\n"
            "                            $vm = $false\n"
            "                            foreach ($el in $els) {\n"
            "                                if ($el -is [System.Management.Automation.Language.CommandParameterAst] `\n"
            "                                    -and $el.ParameterName -match '^(VMName|VMId)$') { $vm = $true }\n"
            "                            }\n"
            "                            if ($boundToScriptBlock -and $vm) { $guest = $true }\n"
            "                        }\n"
            "                    }\n"
            "                }\n"
            "                $n = $n.Parent\n"
            "            }\n"
            "            $rows += [ordered]@{ kind = $short; file = $leaf\n"
            "                                 offset = $c.Extent.StartOffset\n"
            "                                 remote = $guest }\n"
            "        }\n"
            "    }\n"
            "    # The marker offset, measured by the same parser in the same\n"
            "    # coordinate space as the invocations above.\n"
            "    foreach ($t in $ast.Extent.Text | Select-Object -First 1) {\n"
            "        $idx = $t.IndexOf('# ---- live credential chain')\n"
            "        $cnt = ([regex]::Matches($t, [regex]::Escape('# ---- live credential chain'))).Count\n"
            "        if ($idx -ge 0) {\n"
            "            $rows += [ordered]@{ kind = 'marker'; file = $leaf\n"
            "                                 offset = $idx; count = $cnt }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "$payload = [ordered]@{ parse_failed = $parseFailed; rows = @($rows) }\n"
            "ConvertTo-Json -InputObject $payload -Depth 4 -Compress\n",
            encoding="utf-8")
        scan_paths = sorted(
            str(p) for p in (ROOT / "packaging" / "hyperv").glob("*.ps1"))
        try:
            ast_out = subprocess.run(
                [str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                 "Bypass", "-File", str(ast_probe)],
                capture_output=True, text=True, timeout=300,
                env={**os.environ, "MR_SCAN_PATHS": ";".join(scan_paths)})
            payload = json.loads((ast_out.stdout or "").strip() or "{}")
        except (OSError, subprocess.SubprocessError, ValueError):
            payload = {}
        # A probe that could not answer must not read as "nothing found". An
        # empty result was previously indistinguishable from a clean file.
        ast_answered = bool(payload) and payload.get("rows") is not None \
            and not payload.get("parse_failed", True)
        ast_rows = payload.get("rows") or []
        # Guest-scoped invocations are counted and reported, never silently
        # dropped: a claim of "one reset" that quietly excluded two of three
        # would be the same kind of statement this family exists to stop.
        resets = sorted(r["offset"] for r in ast_rows
                        if r["kind"] == "set-localuser" and not r.get("remote"))
        guest_resets = sorted(
            (r["file"], r["offset"]) for r in ast_rows
            if r["kind"] == "set-localuser" and r.get("remote"))
        creates = sorted(r["offset"] for r in ast_rows
                         if r["kind"] == "new-localuser" and not r.get("remote"))
        markers = [r for r in ast_rows if r["kind"] == "marker"]
        marker_at = markers[0]["offset"] if len(markers) == 1 else -1
        marker_count = markers[0].get("count", 0) if len(markers) == 1 else 0
        reset_files = {r["file"] for r in ast_rows
                       if r["kind"] == "set-localuser" and not r.get("remote")}

        same_file = (
            len(markers) == 1 and markers[0]["file"] == "reviewer_bootstrap.ps1"
            and reset_files == {"reviewer_bootstrap.ps1"}
            and {r["file"] for r in ast_rows
                 if r["kind"] == "new-localuser" and not r.get("remote")}
            == {"reviewer_bootstrap.ps1"})
        rec("OP48e the-refusal-precedes-account-creation-and-the-reset",
            ast_answered and marker_at >= 0 and marker_count == 1 and same_file
            and len(creates) == 1 and len(resets) == 1
            and marker_at < creates[0] < resets[0]
            and "OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE" in raw_boot,
            f"the block sits above every parsed New-LocalUser and Set-LocalUser "
            f"invocation across every script on the trust path, measured in one "
            f"coordinate space, all three in the same file, and the marker it is "
            f"located by occurs once (answered={ast_answered}, "
            f"same-file={same_file}, marker@{marker_at}x{marker_count}, "
            f"creates={creates}, resets={resets})")

        rec("OP48f the-account-password-still-has-a-single-host-invocation",
            ast_answered and len(resets) == 1
            and reset_files == {"reviewer_bootstrap.ps1"},
            f"across all {len(scan_paths)} scripts on the trust path the parser "
            f"finds exactly one Set-LocalUser invocation against THIS host's "
            f"account database, in any spelling and under any module "
            f"qualification, so the guard above it covers the whole credential "
            f"route ({len(resets)} host invocation(s) in "
            f"{sorted(reset_files) or 'none'}; {len(guest_resets)} run inside "
            f"the guest via Invoke-Command and touch no host account: "
            f"{guest_resets}; answered={ast_answered})")

        # THE ACCOUNT IS THE SUBJECT OF THE RESET.
        #
        # Gating on material found under $HvRoot let `-HvRoot <anywhere else>`
        # -- a different parameter from the $User being reset -- report no
        # material and proceed, resetting the live account whose sealed state
        # sits under the real root. Denial keyed to one operand, damage keyed to
        # the other: the closed defect, one level along.
        acct_rc, acct_text, acct_detail = run_chain(
            [], recreate=False, tag="acct", account="present")
        rec("OP48g an-existing-account-refuses-even-when-the-root-holds-nothing",
            acct_rc == 2 and "OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE" in acct_text
            and "CHAIN-PROCEEDED" not in acct_text,
            f"an inspected root with no sealed material does not license the "
            f"reset while the account it would reset exists, so pointing the run "
            f"at another root cannot reach it ({acct_detail or 'no output'})")

        # THE THIRD OPERAND. The route deletes and re-registers $TaskName, and
        # the Task Scheduler's stored credential is the only retained copy of
        # the operator-typed password -- so a run that keeps the account and the
        # key can still leave the reviewer undrivable. $TaskName is independent
        # of both $User and $HvRoot; covering two of three is how this block was
        # bypassed twice.
        task_rc, task_text, task_detail = run_chain(
            [], recreate=False, tag="task", task="present")
        rec("OP48i an-existing-task-refuses-on-its-own",
            task_rc == 2 and "OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE" in task_text
            and "CHAIN-PROCEEDED" not in task_text,
            f"the registered task is judged as its own operand, so a run with a "
            f"fresh account name and a fresh root cannot delete the stored "
            f"credential that drives the existing reviewer "
            f"({task_detail or 'no output'})")

        # THE FIXTURE MUST NOTICE THE OBVIOUS REGRESSION. OP48d injects throwing
        # probes, so it passes whether or not the shipped probes are still
        # capable of throwing -- which means the single most likely "fix" for a
        # raw access-denied, adding -ErrorAction SilentlyContinue, would leave
        # every check green while restoring the fail-open the block exists to
        # remove. Applied to a copy and measured.
        # BOTH probes, not one. Weakening the enumeration and not the leaf test
        # is this codebase's second defect shape, applied by the check written
        # to close its third.
        weak_results = {}
        for label, target in (
                ("enumeration", "Get-ChildItem -LiteralPath $credChainRoot -Force"),
                ("leaf", "Test-Path -LiteralPath (Join-Path $credChainRoot $leaf)")):
            w_rc, w_text, _ = run_chain(
                [], recreate=False, tag=f"weak-{label}", make_unreadable=True,
                weaken=target)
            weak_results[label] = (w_rc, "CHAIN-PROCEEDED" in w_text)

        # AST, NOT TEXT. The regex matched only the fully written-out
        # "-ErrorAction SilentlyContinue", so -EA SilentlyContinue, -ea Ignore
        # and a quoted value all read as clean: a check claiming no probe is
        # silenced, silent about the ways to silence one. Counting it in
        # stripped text fixed which characters it looked at, not what it looked
        # for.
        region_file = work / "chain-region.ps1"
        region_file.write_text(chain_text, encoding="utf-8")
        ea_probe = work / "chain-region-ea.ps1"
        ea_probe.write_text(
            "$e = $null\n"
            "$ast = [System.Management.Automation.Language.Parser]::ParseFile(\n"
            "    $env:MR_REGION, [ref]$null, [ref]$e)\n"
            "if ($e.Count -or -not $ast) { Write-Output 'PARSE-FAILED'; exit 0 }\n"
            "$hits = @()\n"
            "foreach ($c in $ast.FindAll({ param($n)\n"
            "        $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {\n"
            "    $els = @($c.CommandElements)\n"
            "    for ($i = 0; $i -lt $els.Count; $i++) {\n"
            "        $el = $els[$i]\n"
            "        if ($el -isnot [System.Management.Automation.Language.CommandParameterAst]) { continue }\n"
            "        if ($el.ParameterName -notmatch '^(ea|er|err|erro|error|errora|erroract|erroracti|erroractio|erroraction)$') { continue }\n"
            "        $v = $el.Argument\n"
            "        if (-not $v -and ($i + 1) -lt $els.Count) { $v = $els[$i + 1] }\n"
            "        $t = ''\n"
            "        if ($v) { $t = $v.Extent.Text.Trim(([char]39), ([char]34)) }\n"
            "        if ($t -match '^(SilentlyContinue|Ignore|0|4)$') {\n"
            "            $hits += (([string]$c.GetCommandName()) + ':' + $t)\n"
            "        }\n"
            "    }\n"
            "}\n"
            "if (-not $hits.Count) { Write-Output 'NONE' } else { Write-Output ($hits -join ',') }\n",
            encoding="utf-8")
        try:
            ea_out = subprocess.run(
                [str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                 "Bypass", "-File", str(ea_probe)],
                capture_output=True, text=True, timeout=180,
                env={**os.environ, "MR_REGION": str(region_file)})
            ea_verdict = (ea_out.stdout or "").strip()
        except (OSError, subprocess.SubprocessError):
            ea_verdict = "PROBE-FAILED"

        rec("OP48j weakening-either-probe-to-a-suppressed-error-is-detected",
            ea_verdict == "NONE"
            and all(rc != 0 and not proceeded
                    for rc, proceeded in weak_results.values()),
            f"no command in the shipped block carries a suppressing ErrorAction "
            f"in any spelling, and a copy with one added to EITHER probe does "
            f"not reach the proceed path -- so the branch OP48d certifies cannot "
            f"be disarmed while OP48d still passes (ast={ea_verdict}, "
            f"{weak_results})")

        # NO ABBREVIATION ARMS THE DESTRUCTION. PowerShell binds any
        # unambiguous prefix, so a destructive SWITCH whose name is the only one
        # starting with D is armed by a bare -D -- which the rename that removed
        # the -Re collision created. As a string parameter a bare -D is a
        # binding error, and the value must be the confirmation phrase. Measured
        # by binding against the real parameter block rather than read off it.
        bind_probe = work / "bind-probe.ps1"
        bind_probe.write_text(
            "$boot = $env:MR_BOOT_PATH\n"
            "$e = $null\n"
            "$ast = [System.Management.Automation.Language.Parser]::ParseFile(\n"
            "    $boot, [ref]$null, [ref]$e)\n"
            "if ($e.Count) { Write-Output 'PARSE-FAILED'; exit 0 }\n"
            "$p = $ast.ParamBlock\n"
            "if (-not $p) { Write-Output 'NO-PARAM-BLOCK'; exit 0 }\n"
            "$rows = @()\n"
            "foreach ($v in $p.Parameters) {\n"
            "    $nm = $v.Name.VariablePath.UserPath\n"
            "    $isSwitch = $false\n"
            "    foreach ($a in $v.Attributes) {\n"
            "        if ($a -is [System.Management.Automation.Language.TypeConstraintAst] `\n"
            "            -and $a.TypeName.Name -match '^switch$') { $isSwitch = $true }\n"
            "    }\n"
            "    $rows += [ordered]@{ name = $nm; isSwitch = $isSwitch }\n"
            "}\n"
            "ConvertTo-Json -InputObject @($rows) -Depth 3 -Compress\n",
            encoding="utf-8")
        try:
            bind_out = subprocess.run(
                [str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                 "Bypass", "-File", str(bind_probe)],
                capture_output=True, text=True, timeout=180,
                env={**os.environ, "MR_BOOT_PATH": str(
                    ROOT / "packaging" / "hyperv" / "reviewer_bootstrap.ps1")})
            params = json.loads((bind_out.stdout or "[]").strip() or "[]")
        except (OSError, subprocess.SubprocessError, ValueError):
            params = []
        destructive = [p for p in params
                       if p["name"] == "DestroyReviewerCredentialChain"]
        # Every prefix of the destructive name that no other parameter shares is
        # a spelling PowerShell will bind. If the parameter is a switch, each of
        # those arms it with no value typed at all.
        others = [p["name"].lower() for p in params
                  if p["name"] != "DestroyReviewerCredentialChain"]
        arming_prefixes = []
        if destructive and destructive[0]["isSwitch"]:
            full = "DestroyReviewerCredentialChain"
            for i in range(1, len(full) + 1):
                pre = full[:i].lower()
                if not any(o.startswith(pre) for o in others):
                    arming_prefixes.append("-" + full[:i])
        rec("OP48k no-abbreviation-can-arm-the-destructive-path",
            bool(destructive) and not destructive[0]["isSwitch"]
            and not arming_prefixes,
            f"the bypass takes a value rather than being a switch, so no "
            f"unambiguous prefix arms it and the operator must type the "
            f"confirmation phrase (is-switch="
            f"{destructive[0]['isSwitch'] if destructive else 'ABSENT'}, "
            f"arming-prefixes={arming_prefixes[:3] or 'none'})")

        # THE PHRASE ITSELF, EXECUTED. OP48k reads the parameter's AST type and
        # concludes "the operator must type the confirmation phrase" -- a claim
        # about behaviour, established by looking at a type constraint. Nothing
        # ran the comparison, so replacing [string]::Equals(...) with
        # [bool]$DestroyReviewerCredentialChain left the battery green while
        # `-D yes` destroyed the chain: the one thing standing between a
        # deliberately-bindable abbreviation and unrecoverable key loss, and it
        # was the unmeasured thing.
        PHRASE = "DESTROY-THE-REVIEWER-KEY"
        phrase_cases = [
            (PHRASE, True, "the exact phrase"),
            (PHRASE.lower(), False, "lower case"),
            ("yes", False, "a truthy non-phrase"),
            (PHRASE + " ", False, "a trailing space"),
            (" " + PHRASE, False, "a leading space"),
            (PHRASE + "\ufeff", False, "a zero-width no-break space suffix"),
            (PHRASE + "\u00ad", False, "a soft-hyphen suffix"),
            (PHRASE[:-1], False, "a truncated phrase"),
        ]
        phrase_results = {}
        for value, should_pass, label in phrase_cases:
            p_rc, p_text, _ = run_chain(
                ["review-key.dpapi"], recreate=value,
                tag=f"phrase-{abs(hash(value)) % 10000}")
            proceeded = "CHAIN-PROCEEDED" in p_text and p_rc == 0
            phrase_results[label] = (proceeded == should_pass, p_rc)
        rec("OP48l only-the-exact-confirmation-phrase-permits-the-destruction",
            all(ok for ok, _ in phrase_results.values()),
            f"the comparison is executed, not read off a type: the exact phrase "
            f"proceeds and case changes, whitespace, invisible suffixes, a "
            f"truncation and a merely truthy value all refuse "
            f"({ {k: v[1] for k, v in phrase_results.items()} })")

        # THE FAILURE DIRECTION OF THE ACCOUNT PROBE. Its presence direction was
        # pinned by a succeeding stub; a lookup that CANNOT ANSWER was not
        # measured at all, so reducing the catch to `$credChainAccount = $false`
        # restored the review-1K High with nothing red.
        af_rc, af_text, af_detail = run_chain(
            [], recreate=False, tag="acct-fail", account="unreadable")
        rec("OP48m an-account-lookup-that-cannot-answer-refuses",
            af_rc == 2 and "OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE" in af_text
            and "CHAIN-PROCEEDED" not in af_text,
            f"a Get-LocalUser failure that is not 'no such user' is treated as "
            f"'cannot establish' rather than 'no account', so the operand the "
            f"block promotes to primary fails closed in both directions "
            f"({af_detail or 'no output'})")

        # THE PRIMARY TASK PROBE, ISOLATED. OP48i injects the cmdlet, which is
        # the SECOND opinion -- the arm that was in the wrong namespace. With
        # the cmdlet stubbed to report absent, only the schtasks query can see
        # the task, so this is the check that would notice if the primary probe
        # were removed.
        live_task = "MR-OFFLINE-REVIEWER-RUN"
        sch_present = subprocess.run(
            [str(Path(os.environ.get("SystemRoot", r"C:\Windows"))
                 / "System32" / "schtasks.exe"), "/Query", "/TN", live_task],
            capture_output=True, text=True, timeout=120).returncode == 0
        ti_rc, ti_text, ti_detail = run_chain(
            [], recreate=False, tag="task-primary", task="absent",
            task_name=live_task)
        rec("OP48n the-schtasks-probe-alone-is-enough-to-refuse",
            sch_present and ti_rc == 2
            and "OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE" in ti_text
            and "CHAIN-PROCEEDED" not in ti_text,
            f"with the cmdlet second opinion reporting absent, the query that "
            f"uses the same binary as the damage still sees the task and "
            f"refuses -- so the primary probe is load-bearing on its own "
            f"(schtasks-sees-it={sch_present}, {ti_detail or 'no output'})")

        # THE ENUMERATION ARM, ISOLATED, WITHOUT A STUB.
        #
        # Every make_unreadable case overrides Test-Path AND Get-ChildItem, and
        # the leaf loop runs first -- so the enumeration was never entered in
        # its failing direction by any check, and deleting it, emptying its
        # catch or silencing it left the battery green. It is the SOLE detector
        # of "the directory is there but cannot be listed", which is the state
        # the whole block was written for.
        #
        # Reproduced as a real filesystem state rather than an injection: a
        # directory junction whose target has been removed answers Test-Path
        # $true on the container, $false on every leaf with NO error, and throws
        # only on enumeration. Nothing else in the block can see it.
        junction_ok, junction_rc, junction_detail = False, -1, ""
        junction_named = False
        jroot = work / "chain-junction"
        jstate = jroot / "reviewer" / "state"
        jtarget = work / "junction-target"
        try:
            (jroot / "reviewer").mkdir(parents=True, exist_ok=True)
            jtarget.mkdir(exist_ok=True)
            made = subprocess.run(
                [str(SHELL), "-NoProfile", "-NonInteractive", "-Command",
                 "$ErrorActionPreference='Stop';"
                 "New-Item -ItemType Junction -Path $env:MR_LINK"
                 " -Target $env:MR_TARGET | Out-Null; 'ok'"],
                capture_output=True, text=True, timeout=120,
                env={**os.environ, "MR_LINK": str(jstate),
                     "MR_TARGET": str(jtarget)})
            if "ok" in (made.stdout or ""):
                shutil.rmtree(jtarget, ignore_errors=True)
                junction_ok = not jtarget.exists()
        except (OSError, subprocess.SubprocessError):
            junction_ok = False
        if junction_ok:
            jh = work / "chain-junction.ps1"
            jh.write_text(
                "Set-StrictMode -Version 2.0\n$ErrorActionPreference = 'Stop'\n"
                "$User = 'MR-SYNTHETIC-REVIEWER-NOT-ON-THIS-HOST'\n"
                "$TaskName = 'MR-SYNTHETIC-TASK-NOT-ON-THIS-HOST'\n"
                + ("$schtasks = '" + str(
                    Path(os.environ.get("SystemRoot", r"C:\Windows"))
                    / "System32" / "schtasks.exe") + "'\n")
                + f"$HvRoot = '{jroot}'\n"
                "$DestroyReviewerCredentialChain = ''\n"
                + chain_text + "\nWrite-Output 'CHAIN-PROCEEDED'\n",
                encoding="utf-8-sig")
            try:
                jout = subprocess.run(
                    [str(SHELL), "-NoProfile", "-NonInteractive",
                     "-ExecutionPolicy", "Bypass", "-File", str(jh)],
                    capture_output=True, text=True, timeout=180)
                jtext = (jout.stdout or "") + (jout.stderr or "")
                junction_rc = jout.returncode
                # The reason is the LAST line printed, so a truncated detail
                # cannot be what the assertion reads -- the first version of
                # this check failed on its own 150-character clip.
                junction_named = ("OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE" in jtext)
                junction_detail = jtext.strip().replace("\n", " ")[:150]
            except (OSError, subprocess.SubprocessError) as exc:
                junction_rc, junction_detail = -1, type(exc).__name__
        rec("OP48p a-listable-only-failure-is-caught-by-the-enumeration-arm",
            junction_ok and junction_rc == 2 and junction_named,
            f"a real state in which Test-Path answers cleanly and only "
            f"enumeration fails is refused, so the arm that alone detects it is "
            f"load-bearing rather than shadowed by the leaf probe "
            f"(built={junction_ok}, rc={junction_rc}, {junction_detail or 'no output'})")

        tf_rc, tf_text, tf_detail = run_chain(
            [], recreate=False, tag="task-fail", task="unreadable")
        rec("OP48o a-task-lookup-that-cannot-answer-refuses",
            tf_rc == 2 and "OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE" in tf_text
            and "CHAIN-PROCEEDED" not in tf_text,
            f"a Get-ScheduledTask failure that is not 'no such task' is treated "
            f"as 'cannot establish', matching the account arm rather than "
            f"diverging from it ({tf_detail or 'no output'})")

        # ---------------------- the refusal's position in the WHOLE route
        # A LIFTED REGION CANNOT ESTABLISH A PROPERTY OF THE ROUTE.
        #
        # Everything above executes the text between two comment markers with
        # $User, $TaskName, $HvRoot and the bypass supplied by the harness. That
        # measures what the region does; it cannot measure that the region is
        # REACHED on the damaging route, that its operands are the ones the
        # damage uses, that its condition has not gained a term, or that the
        # damage has not moved above it. Six edits that disarm the refusal left
        # the whole battery green, each with the region byte-identical:
        # assigning the bypass phrase above the marker; shadowing the three
        # operands around the region; adding a conjunct that reads a flag file;
        # resetting the password through ADSI, which the cmdlet scan cannot see;
        # moving the task deletion above the marker; and wrapping the region in
        # `if ($Verify)`.
        #
        # These are structural facts about the file, so they are asked of the
        # parser rather than of a harness.
        route_probe = work / "route-invariants.ps1"
        route_probe.write_text("\n".join([
            "$ErrorActionPreference = 'Stop'",
            "$out = [ordered]@{ parse_failed = $false; refusal = $null;",
            "                   reassigned = @(); damaging = @(); alt = @() }",
            "$boot = $env:MR_BOOT_PATH",
            "$e = $null",
            "$ast = [System.Management.Automation.Language.Parser]::ParseFile(",
            "    $boot, [ref]$null, [ref]$e)",
            "if ($e.Count -or -not $ast) { $out.parse_failed = $true;",
            "    ConvertTo-Json -InputObject $out -Depth 6 -Compress; exit 0 }",
            "",
            "function Enclosers([System.Management.Automation.Language.Ast]$n) {",
            "    $names = @()",
            "    $p = $n.Parent",
            "    while ($p) {",
            "        if ($p -is [System.Management.Automation.Language.IfStatementAst] -or",
            "            $p -is [System.Management.Automation.Language.FunctionDefinitionAst] -or",
            "            $p -is [System.Management.Automation.Language.TryStatementAst] -or",
            "            $p -is [System.Management.Automation.Language.LoopStatementAst] -or",
            "            $p -is [System.Management.Automation.Language.SwitchStatementAst]) {",
            "            $names += $p.GetType().Name",
            "        }",
            "        $p = $p.Parent",
            "    }",
            "    return ,$names",
            "}",
            "",
            "# The refusal: the if-statement on the liveness flag WHOSE BODY",
            "# EXITS. Two statements test that flag -- the refusal and the",
            "# bypass warning -- and taking the last match silently pinned the",
            "# warning, whose condition is the same two terms, so an extra",
            "# conjunct on the real refusal went unseen. The exit is what",
            "# distinguishes them, and there must be exactly one.",
            "$candidates = @()",
            "foreach ($i in $ast.FindAll({ param($n)",
            "        $n -is [System.Management.Automation.Language.IfStatementAst] }, $true)) {",
            "    $cond = $i.Clauses[0].Item1.Extent.Text",
            "    if ($cond -notmatch 'credChainLive') { continue }",
            "    $exits = @($i.Clauses[0].Item2.FindAll({ param($n)",
            "        $n -is [System.Management.Automation.Language.ExitStatementAst] }, $true))",
            "    if (-not $exits.Count) { continue }",
            "    $candidates += [ordered]@{",
            "        offset = $i.Extent.StartOffset",
            "        condition = ($cond -replace '\\s+', ' ')",
            "        enclosers = (Enclosers $i)",
            "    }",
            "}",
            "$out.refusal_count = $candidates.Count",
            "if ($candidates.Count -eq 1) { $out.refusal = $candidates[0] }",
            "",
            "# Top-level assignments to any operand the refusal depends on, made",
            "# anywhere outside the block itself. A shadowed operand answers",
            "# 'absent' for live state; an assigned bypass arms the destruction.",
            "$guarded = 'User','TaskName','HvRoot','DestroyReviewerCredentialChain'",
            "foreach ($a in $ast.FindAll({ param($n)",
            "        $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {",
            "    $l = $a.Left",
            "    if ($l -isnot [System.Management.Automation.Language.VariableExpressionAst]) { continue }",
            "    $nm = $l.VariablePath.UserPath",
            "    if ($guarded -notcontains $nm) { continue }",
            "    if ((Enclosers $a).Count -gt 0) { continue }",
            "    $out.reassigned += [ordered]@{ name = $nm; offset = $a.Extent.StartOffset }",
            "}",
            "",
            "# Every operation on this route that destroys retained state, at its",
            "# top-level CALL SITE (a helper's own body is not a call site).",
            "foreach ($c in $ast.FindAll({ param($n)",
            "        $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {",
            "    $nm = $c.GetCommandName()",
            "    $txt = $c.Extent.Text",
            "    $what = ''",
            "    if ($nm) {",
            "        $short = ($nm -split '\\\\')[-1].ToLowerInvariant()",
            "        if ('set-localuser','new-localuser','remove-taskifpresent' -contains $short) {",
            "            $what = $short",
            "        }",
            "    }",
            "    if (-not $what -and $txt -match '/Create|/Delete') {",
            "        if ($txt -match '\\$schtasks') { $what = 'schtasks-write' }",
            "    }",
            "    if (-not $what) { continue }",
            "    $enc = Enclosers $c",
            "    if ($enc -contains 'FunctionDefinitionAst') { continue }",
            "    $out.damaging += [ordered]@{ what = $what; offset = $c.Extent.StartOffset }",
            "}",
            "",
            "# Any OTHER way to change a password or write the task, in any of the",
            "# scripts on the trust path. The cmdlet scan sees two cmdlet names;",
            "# these are the mechanisms that bypass it entirely.",
            "$patterns = @{",
            "    'adsi-winnt'      = 'WinNT://';",
            "    'adsi-setpasswd'  = '\.SetPassword\(|\.ChangePassword\(';",
            "    'net-user'        = 'net(\\.exe)?\\s+user';",
            "    'register-task'   = 'Register-ScheduledTask|Set-ScheduledTask';",
            "    'task-com-write'  = 'RegisterTaskDefinition';",
            "    'wmi-account'     = 'Win32_UserAccount'",
            "}",
            "foreach ($p in ($env:MR_SCAN_PATHS -split ';')) {",
            "    if (-not $p) { continue }",
            "    $se = $null",
            "    $sast = [System.Management.Automation.Language.Parser]::ParseFile(",
            "        $p, [ref]$null, [ref]$se)",
            "    if ($se.Count -or -not $sast) { $out.parse_failed = $true; continue }",
            "    # Comments are not code: the AST's extent text excludes them",
            "    # only inside nodes, so scan statement extents rather than raw.",
            "    foreach ($st in $sast.FindAll({ param($n)",
            "            $n -is [System.Management.Automation.Language.CommandAst] -or",
            "            $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -or",
            "            $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)) {",
            "        foreach ($k in $patterns.Keys) {",
            "            if ($st.Extent.Text -match $patterns[$k]) {",
            "                $out.alt += [ordered]@{ file = (Split-Path -Leaf $p); what = $k;",
            "                                        offset = $st.Extent.StartOffset }",
            "            }",
            "        }",
            "    }",
            "}",
            "ConvertTo-Json -InputObject $out -Depth 6 -Compress",
        ]), encoding="utf-8-sig")
        try:
            r_out = subprocess.run(
                [str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                 "Bypass", "-File", str(route_probe)],
                capture_output=True, text=True, timeout=300,
                env={**os.environ,
                     "MR_BOOT_PATH": str(ROOT / "packaging" / "hyperv"
                                         / "reviewer_bootstrap.ps1"),
                     "MR_SCAN_PATHS": ";".join(scan_paths)})
            route = json.loads((r_out.stdout or "{}").strip() or "{}")
        except (OSError, subprocess.SubprocessError, ValueError):
            route = {}
        route_ok = bool(route) and not route.get("parse_failed", True)
        refusal = route.get("refusal") or {}
        damaging = route.get("damaging") or []
        reassigned = route.get("reassigned") or []
        alt = route.get("alt") or []

        # ---------------------------------------- the prologue, pinned whole
        # ENUMERATING ATTACKS DOES NOT TERMINATE.
        #
        # OP48q-u each name a mechanism -- an assignment, a conjunct, a cmdlet,
        # a door -- and a review found fourteen spellings that none of them see:
        # Set-Variable and New-Variable and $script: and an assignment nested in
        # `if ($true)` and a param default, all of which rebind an operand; a
        # conjunct with no $ sigil; a helper called above the refusal whose body
        # holds the task deletion; `& $sch /Delete` after aliasing the binary;
        # `& $c -Name ...` after putting the cmdlet name in a variable; ADSI
        # reached by string concatenation. Every one is a different spelling of
        # "something happened above the refusal", and pattern-matching them one
        # at a time is a race the checks keep losing.
        #
        # So the question is inverted. Instead of asking which statements above
        # the refusal are dangerous, this pins WHICH STATEMENTS ARE THERE. Any
        # insertion, deletion or edit in the prologue -- in any spelling, by any
        # mechanism, including ones nobody has thought of -- changes the digest.
        # Comments and whitespace are normalised out, so prose is free and code
        # is not. A deliberate change to this region is then an explicit act
        # that updates the pin and shows up as one line of the diff.
        prologue_probe = work / "prologue.ps1"
        prologue_probe.write_text("\n".join([
            "# DECODED ONCE, EXPLICITLY. ParseFile lets Windows PowerShell 5.1",
            "# decode a BOM-less .ps1 with the host ANSI code page, so the one",
            "# non-ASCII byte sequence in this file became three characters",
            "# under cp1252 and one under UTF-8 -- the pin was a property of the",
            "# host that computed it, and re-saving with a BOM reddened it. The",
            "# text is read as UTF-8 and PARSED FROM THAT STRING, so the offset",
            "# and the slice share one coordinate space and the digest is the",
            "# same on any host.",
            "$e = $null",
            "$text = [IO.File]::ReadAllText($env:MR_BOOT_PATH, [Text.Encoding]::UTF8)",
            "$ast = [System.Management.Automation.Language.Parser]::ParseInput(",
            "    $text, [ref]$null, [ref]$e)",
            "if ($e.Count -or -not $ast) { Write-Output 'PARSE-FAILED'; exit 0 }",
            "# The refusal, located the same way OP48q locates it.",
            "$stop = -1",
            "foreach ($i in $ast.FindAll({ param($n)",
            "        $n -is [System.Management.Automation.Language.IfStatementAst] }, $true)) {",
            "    $c = $i.Clauses[0].Item1.Extent.Text",
            "    if ($c -notmatch 'credChainLive') { continue }",
            "    $x = @($i.Clauses[0].Item2.FindAll({ param($n)",
            "        $n -is [System.Management.Automation.Language.ExitStatementAst] }, $true))",
            "    if ($x.Count) { $stop = $i.Extent.EndOffset }",
            "}",
            "if ($stop -lt 0) { Write-Output 'NO-REFUSAL'; exit 0 }",
            "# EVERY BYTE THAT RUNS FIRST, not a reconstruction of it.",
            "#",
            "# Enumerating Begin/Process/End statements missed anything that is",
            "# not one: a `dynamicparam` block executes during PARAMETER BINDING,",
            "# ahead of the first body statement and therefore ahead of every",
            "# gate, and its text appeared in no statement -- a mutant that",
            "# deleted the reviewer task from a dynamicparam produced a",
            "# byte-identical digest. `using` statements and script-level",
            "# attributes were outside it for the same reason. Reassembling from",
            "# parts also meant normalisation ran over the parts: comments were",
            "# stripped and string literals were blanked to length-preserving",
            "# filler, so a same-length change to a SID, a rights mask or a path",
            "# inside a literal did not move the digest either.",
            "#",
            "# AND THE BOUNDARY ITSELF WAS THE DEFECT.",
            "#",
            "# Pinning a prefix invites the question 'what executes before the",
            "# refusal from after it', which had three answers in three rounds:",
            "# dynamicparam binds first, #requires imports first at any offset,",
            "# and begin{} runs before end{} whatever the textual order -- after",
            "# which its body is a permanent free-edit zone. The boundary has a",
            "# second face too: the damage runs BELOW the refusal, so",
            "# substituting $HvRoot or $TaskName between the decision and the",
            "# damage defeats it without touching a byte above it.",
            "#",
            "# So there is no boundary. The whole file is digested, and",
            "# 'before' and 'after' stop being different questions. $stop is",
            "# still computed, because a file with no exiting refusal must not",
            "# pass, but it no longer bounds anything.",
            "$prefix = $text -replace \"`r`n\", \"`n\"",
            "# principal_contract.ps1 is DOT-SOURCED by it, so it runs in the",
            "# same session and belongs in the same pin, also whole.",
            "$contract = [IO.File]::ReadAllText($env:MR_CONTRACT_PATH,",
            "    [Text.Encoding]::UTF8) -replace \"`r`n\", \"`n\"",
            "# THE THIRD EXECUTED FILE. offline_reviewer_runtime.py is run by",
            "# `& $BuildPython` on -ProvisionReviewerRuntime and",
            "# -HardenInterpreter, both of which exit hundreds of lines above",
            "# the refusal, and the script says so itself: 'runs author-supplied",
            "# bytes at High integrity'. It is not a .ps1, so it fell outside a",
            "# pin that named files by extension -- a payload inserted into it",
            "# produced 93/93 with the PASS lines byte-identical to pristine.",
            "# The reference to it already lives inside the pinned bytes, so no",
            "# new reference is created and nothing else trips.",
            "$runtime = [IO.File]::ReadAllText($env:MR_RUNTIME_PATH,",
            "    [Text.Encoding]::UTF8) -replace \"`r`n\", \"`n\"",
            "$sha = [Security.Cryptography.SHA256]::Create()",
            "try {",
            "    $bytes = [Text.Encoding]::UTF8.GetBytes(",
            "        $prefix + \"`n<<CONTRACT>>`n\" + $contract +",
            "        \"`n<<RUNTIME>>`n\" + $runtime)",
            "    $digest = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''",
            "} finally { $sha.Dispose() }",
            "$dyn = [bool]$ast.DynamicParamBlock",
            "$using = @($ast.UsingStatements).Count",
            "# #requires -Modules IMPORTS AND EXECUTES during pre-flight, ahead",
            "# of the first body statement and therefore ahead of every gate --",
            "# and it is a tokenizer directive honoured wherever it appears in",
            "# the file, so a copy of it past the pinned prefix left the digest",
            "# byte-identical. It cannot be covered by extending the prefix; it",
            "# has to be asserted structurally, and on every script, not just",
            "# the two that are digested.",
            "$reqs = @()",
            "foreach ($p in ($env:MR_SCAN_PATHS -split ';')) {",
            "    if (-not $p) { continue }",
            "    $se = $null",
            "    $stext = [IO.File]::ReadAllText($p, [Text.Encoding]::UTF8)",
            "    $sast = [System.Management.Automation.Language.Parser]::ParseInput(",
            "        $stext, [ref]$null, [ref]$se)",
            "    if ($se.Count -or -not $sast) { $reqs += ('unparseable:' + (Split-Path -Leaf $p)); continue }",
            "    if ($sast.ScriptRequirements) { $reqs += ('requires:' + (Split-Path -Leaf $p)) }",
            "    if ($sast.DynamicParamBlock) { $reqs += ('dynamicparam:' + (Split-Path -Leaf $p)) }",
            "    if (@($sast.UsingStatements).Count) { $reqs += ('using:' + (Split-Path -Leaf $p)) }",
            "    # begin{} and process{} EXECUTE AHEAD OF end{} whatever the",
            "    # textual order, so a named-block conversion reorders execution",
            "    # in a way no offset comparison can show. The whole-file digest",
            "    # already covers the two pinned files; this names the shape,",
            "    # and covers the other eight.",
            "    if ($sast.BeginBlock) { $reqs += ('begin:' + (Split-Path -Leaf $p)) }",
            "    if ($sast.ProcessBlock) { $reqs += ('process:' + (Split-Path -Leaf $p)) }",
            "}",
            "# MARSHALLED, NOT PRINTED. These were labelled lines recovered with",
            "# unanchored regexes, and one line carried FILE NAMES from the tree",
            "# under review -- so a decoy file named to contain 'PREFIXCHARS=...",
            "# DIGEST=...' supplied the values the consumer read, and a real",
            "# statement inserted above the refusal passed 93/93 clean.",
            "$payload = [ordered]@{",
            "    digest = $digest",
            "    boot_chars = $prefix.Length",
            "    contract_chars = $contract.Length",
            "    runtime_chars = $runtime.Length",
            "    dynamicparam = [bool]$dyn",
            "    using_count = [int]$using",
            "    findings = @($reqs)",
            "}",
            "ConvertTo-Json -InputObject $payload -Depth 4 -Compress",
        ]), encoding="utf-8-sig")
        # Parsed as JSON, like the two sibling probes in this block. Recovering
        # labelled lines with unanchored regexes let a value the tree controls
        # -- a file name -- masquerade as the measurement.
        prologue = {}
        try:
            p_out = subprocess.run(
                [str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                 "Bypass", "-File", str(prologue_probe)],
                capture_output=True, text=True, timeout=300,
                env={**os.environ,
                     "MR_BOOT_PATH": str(ROOT / "packaging" / "hyperv"
                                         / "reviewer_bootstrap.ps1"),
                     "MR_CONTRACT_PATH": str(ROOT / "packaging" / "hyperv"
                                             / "principal_contract.ps1"),
                     "MR_RUNTIME_PATH": str(ROOT / "scripts"
                                            / "offline_reviewer_runtime.py"),
                     "MR_SCAN_PATHS": ";".join(scan_paths)})
            prologue = json.loads((p_out.stdout or "{}").strip() or "{}")
            if not isinstance(prologue, dict):
                prologue = {}
        except (OSError, subprocess.SubprocessError, ValueError):
            prologue = {}
        prologue_digest = str(prologue.get("digest") or "")
        prologue_count = prologue.get("boot_chars", -1)
        contract_count = prologue.get("contract_chars", -1)
        runtime_count = prologue.get("runtime_chars", -1)
        prologue_dyn = prologue.get("dynamicparam")
        prologue_using = prologue.get("using_count", -1)
        prologue_reqs = prologue.get("findings")
        if prologue_reqs is None:
            prologue_reqs = ["UNAVAILABLE"]
        elif isinstance(prologue_reqs, str):
            # ConvertTo-Json unrolls a one-element array to a bare value.
            prologue_reqs = [prologue_reqs]

        # Pinned. Update deliberately, in the same commit as any intended change
        # to either file, and never to make a run go green.
        PINNED_PROLOGUE = "6efe91490d1ff874"
        PINNED_BOOT_CHARS = 132137
        PINNED_CONTRACT_CHARS = 69784
        PINNED_RUNTIME_CHARS = 26139
        rec("OP48v every-file-the-elevated-session-executes-is-pinned-whole",
            bool(prologue_digest) and prologue_count == PINNED_BOOT_CHARS
            and contract_count == PINNED_CONTRACT_CHARS
            and runtime_count == PINNED_RUNTIME_CHARS
            and prologue_digest.startswith(PINNED_PROLOGUE)
            and prologue_dyn is False and prologue_using == 0
            and prologue_reqs == [],
            f"the elevated script, the contract it dot-sources and the Python "
            f"it runs at High integrity are digested "
            f"whole -- not to a boundary -- so an edit anywhere in any of them, "
            f"before or after the refusal, in any construct including one that "
            f"executes ahead of the body, moves the pin; and no script on the "
            f"trust path declares a requirement, a dynamicparam, a using "
            f"statement or a named begin/process block "
            f"({prologue_count} + {contract_count} + {runtime_count} chars, "
            f"dynamicparam={prologue_dyn}, using={prologue_using}, "
            f"structural-findings-across-all-ten={prologue_reqs or 'none'}, "
            f"digest={prologue_digest[:16] or 'UNAVAILABLE'})")

        rec("OP48q the-refusal-is-not-nested-inside-anything",
            route_ok and bool(refusal) and route.get("refusal_count") == 1
            and not (refusal.get("enclosers") or []),
            f"exactly one exiting statement turns on the liveness flag and it "
            f"is at top level, so it cannot be placed behind a condition that "
            f"never holds on the damaging route "
            f"(matches={route.get('refusal_count')}, "
            f"enclosers={(refusal.get('enclosers') or []) or 'none'})")

        # The condition is pinned to its four terms. An added conjunct -- a flag
        # file, an environment variable, a switch -- is a disarm that leaves
        # every executing check green because the region still behaves as
        # written when the harness supplies the operands.
        EXPECTED_TERMS = {"credChainLive", "credChainBypass"}
        cond = refusal.get("condition", "")
        cond_vars = set(re.findall(r"\$(\w+)", cond))
        rec("OP48r the-refusal-condition-has-not-acquired-a-term",
            route_ok and cond_vars == EXPECTED_TERMS,
            f"the refusal turns on exactly the computed liveness flag and the "
            f"validated bypass, so no extra conjunct can disarm it "
            f"(condition={cond or 'ABSENT'})")

        rec("OP48s no-operand-is-reassigned-outside-the-block",
            route_ok and not reassigned,
            f"$User, $TaskName, $HvRoot and the bypass are never assigned at "
            f"top level outside the block, so the operands the refusal reads "
            f"are the ones the damage uses ({reassigned or 'none'})")

        before = [d for d in damaging
                  if d["offset"] < (refusal.get("offset", -1))]
        rec("OP48t every-destructive-operation-follows-the-refusal",
            route_ok and bool(refusal) and bool(damaging) and not before,
            f"all {len(damaging)} top-level destructive call sites -- the "
            f"account creation and reset, the task removal and the schtasks "
            f"write -- sit after the refusal, so none can run before it "
            f"({[d['what'] for d in before] or 'none precede it'})")

        rec("OP48u no-other-mechanism-changes-a-password-or-writes-the-task",
            route_ok and not alt,
            f"no script on the trust path reaches the account database or the "
            f"scheduler through ADSI, net.exe, WMI, Register-ScheduledTask or "
            f"the COM task service, so the cmdlet-name scan is not looking at "
            f"one of several doors ({[a['what'] for a in alt] or 'none'})")

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

        # ============ PRE-TRUST ELEVATED EXECUTION SURFACE ============
        # Four defects where author-controlled code, config or input could
        # execute or be consumed at High integrity before the relevant trust
        # boundary. Each check drives the shipped code behaviourally.
        _boot = (ROOT / "packaging" / "hyperv" / "reviewer_bootstrap.ps1").read_text(encoding="utf-8")
        _git = str(Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
                   / "Git" / "cmd" / "git.exe")

        # ---- OP49a: PSModulePath is pinned before the first autoloadable cmdlet
        # A module planted on $env:PSModulePath and exporting Get-LocalUser runs
        # its body when the engine autoloads that name -- arbitrary code at High
        # integrity before any gate. The shipped hardening block is lifted and
        # run in a poisoned environment; the poison must neither resolve nor run.
        _pm_start = _boot.find("# ==== PSMODULEPATH")
        _pm_end = _boot.find("$env:PSModulePath = ($__moduleRoots -join ';')")
        _pm_block = _boot[_pm_start:_pm_end] + "$env:PSModulePath = ($__moduleRoots -join ';')\n" \
            if (_pm_start >= 0 and _pm_end > _pm_start) else ""
        pm_root = work / "op49a"
        (pm_root / "poison" / "EvilAcct").mkdir(parents=True, exist_ok=True)
        pm_marker = pm_root / "ran.txt"
        (pm_root / "poison" / "EvilAcct" / "EvilAcct.psm1").write_text(
            "Set-Content -LiteralPath '" + str(pm_marker).replace("\\", "\\\\")
            + "' -Value 'POISON BODY RAN'\n"
            "function Get-LocalUser { [pscustomobject]@{ Name='ATTACKER' } }\n"
            "Export-ModuleMember -Function Get-LocalUser\n", encoding="utf-8")
        (pm_root / "poison" / "EvilAcct" / "EvilAcct.psd1").write_text(
            "@{ ModuleVersion='9.9.9'; GUID='eeeeeeee-0000-0000-0000-0000000049a1';"
            " RootModule='EvilAcct.psm1'; FunctionsToExport=@('Get-LocalUser') }\n",
            encoding="utf-8")
        pm_harness = work / "op49a.ps1"
        pm_harness.write_text(
            "$ErrorActionPreference='Continue'\n"
            "$env:PSModulePath = '" + str(pm_root / "poison").replace("\\", "\\\\")
            + "' + ';' + $env:PSModulePath\n"
            + _pm_block +
            "$c = Get-Command Get-LocalUser -ErrorAction SilentlyContinue\n"
            "Write-Output ('SOURCE=' + $c.Source)\n"
            "Write-Output ('POISON_ON_PATH=' + ($env:PSModulePath -like '*poison*'))\n"
            "Write-Output ('MARKER=' + (Test-Path -LiteralPath '"
            + str(pm_marker).replace("\\", "\\\\") + "'))\n", encoding="utf-8")
        try:
            pm_out = subprocess.run(
                [str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                 "Bypass", "-File", str(pm_harness)],
                capture_output=True, text=True, timeout=180).stdout or ""
        except (OSError, subprocess.SubprocessError):
            pm_out = ""
        pm_source = re.search(r"SOURCE=(\S+)", pm_out)
        pm_on_path = "POISON_ON_PATH=True" not in pm_out
        pm_ran = "MARKER=True" not in pm_out
        rec("OP49a psmodulepath-is-pinned-before-the-first-autoloadable-cmdlet",
            bool(_pm_block) and pm_ran and pm_on_path
            and pm_source is not None
            and pm_source.group(1).lower() == "microsoft.powershell.localaccounts",
            f"the shipped hardening block drops the poison directory from the "
            f"module path and Get-LocalUser resolves to the real module, so a "
            f"planted module neither shadows the cmdlet nor runs its body "
            f"(source={pm_source.group(1) if pm_source else 'NONE'}, "
            f"poison-gone={pm_on_path}, body-ran={not pm_ran})")

        # ---- OP49b: privileged git does not run author-config programs pre-trust
        # git executes programs named by config (core.fsmonitor, filter drivers,
        # hooks). Assert-TrustedSourceRoot must return before git for any
        # structurally untrusted tree, refuse a tree whose repo-local config
        # carries an execution-capable directive, and run git config-hermetically
        # on a clean tree. In every case an author-named program must not run.
        _icacls_exe = str(Path(os.environ.get("SystemRoot", r"C:\Windows"))
                          / "System32" / "icacls.exe")

        def _make_repo(dest, marker, protected, with_fsmon=True):
            dest.mkdir(parents=True, exist_ok=True)
            for cmd in (["init", "-q"],
                        ["-c", "user.email=a@b.c", "-c", "user.name=a",
                         "commit", "-q", "--allow-empty", "-m", "init"]):
                subprocess.run([_git, "-C", str(dest)] + cmd,
                               capture_output=True, text=True, timeout=60)
            if with_fsmon:
                sh = dest.parent / (dest.name + "-fsmon.sh")
                sh.write_text("#!/bin/sh\necho x > '"
                              + str(marker).replace("\\", "/") + "'\nexit 1\n",
                              encoding="utf-8")
                for kv in (("core.fsmonitor", str(sh).replace("\\", "/")),
                           ("core.fsmonitorHookVersion", "2")):
                    subprocess.run([_git, "-C", str(dest), "config", kv[0], kv[1]],
                                   capture_output=True, text=True, timeout=60)
            if protected:
                for a in (["/inheritance:r"],
                          ["/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
                          ["/setowner", "*S-1-5-32-544"]):
                    subprocess.run([_icacls_exe, str(dest)] + a,
                                   capture_output=True, text=True, timeout=60)

        git_ok = os.path.exists(_git)
        # Case E -- structurally untrusted: a junction (reparse escape, detected
        # by the attribute scan, ahead of the config scan and git) with a
        # SYNTHETIC author for whom trusted git RESOLVES (the real admin author
        # never could, masking whether the early return is what stops git).
        repoE = work / "op49b-e"
        markerE = work / "op49b-e-marker.txt"
        _make_repo(repoE, markerE, protected=False)
        subprocess.run(["cmd", "/c", "mklink", "/J",
                        str(repoE / "escape"), str(work / "op49a")],
                       capture_output=True, text=True, timeout=60)
        reasonsE = probe({"action": "trusted-source", "root": str(repoE),
                          "author": identity("AUTHOR", SID_AUTHOR),
                          "expected_commit": "a" * 40, "expected_tree": "b" * 40},
                         work)["reasons"]
        _structural = {"OFFLINE_SOURCE_ROOT_REPARSE_ESCAPE",
                       "OFFLINE_SOURCE_ROOT_REPARSE_INSIDE",
                       "OFFLINE_SOURCE_ROOT_UNENUMERABLE",
                       "OFFLINE_SOURCE_ROOT_AUTHOR_WRITABLE",
                       "OFFLINE_SOURCE_ROOT_REVIEWER_WRITABLE",
                       "OFFLINE_SOURCE_ROOT_INHERITS"}
        # Case H -- protected, but .git/config carries core.fsmonitor: the config
        # scan refuses before git; the fsmonitor program never runs.
        repoH = work / "op49b-h"
        markerH = work / "op49b-h-marker.txt"
        _make_repo(repoH, markerH, protected=True, with_fsmon=True)
        reasonsH = probe({"action": "trusted-source", "root": str(repoH),
                          "author": identity("SYNTH", SID_AUTHOR),
                          "expected_commit": "a" * 40, "expected_tree": "b" * 40},
                         work)["reasons"]
        # Case C -- protected, clean config: git runs hermetically -> WRONG_COMMIT.
        repoC = work / "op49b-c"
        markerC = work / "op49b-c-marker.txt"
        _make_repo(repoC, markerC, protected=True, with_fsmon=False)
        reasonsC = probe({"action": "trusted-source", "root": str(repoC),
                          "author": identity("SYNTH", SID_AUTHOR),
                          "expected_commit": "a" * 40, "expected_tree": "b" * 40},
                         work)["reasons"]
        # Case I -- the indirection: a repo config that pulls an author FILTER
        # in via [include] -> an external config, with the attribute in an
        # external attributes file. The scan must refuse the indirection itself,
        # because it cannot read what the include points at.
        repoI = work / "op49b-i"
        markerI = work / "op49b-i-marker.txt"
        _make_repo(repoI, markerI, protected=True, with_fsmon=False)
        _evil = work / "op49b-i-evil.cfg"
        _clean = work / "op49b-i-clean.sh"
        _clean.write_text("#!/bin/sh\necho x > '" + str(markerI).replace("\\", "/")
                          + "'\ncat\n", encoding="utf-8")
        _evil.write_text('[filter "x"]\n\tclean = sh \''
                         + str(_clean).replace("\\", "/") + "'\n", encoding="utf-8")
        with (repoI / ".git" / "config").open("a", encoding="utf-8") as _fh:
            _fh.write("[include]\n\tpath = " + str(_evil).replace("\\", "/") + "\n")
        reasonsI = probe({"action": "trusted-source", "root": str(repoI),
                          "author": identity("SYNTH", SID_AUTHOR),
                          "expected_commit": "a" * 40, "expected_tree": "b" * 40},
                         work)["reasons"]
        # Case G -- a gitdir-pointer .git FILE, whose config lives outside the
        # scanned tree entirely. The shape must be refused, not followed.
        repoG = work / "op49b-g"
        repoG.mkdir(parents=True, exist_ok=True)
        gdir = work / "op49b-g-gitdir"
        gdir.mkdir(parents=True, exist_ok=True)
        subprocess.run([_git, "--git-dir", str(gdir), "--work-tree", str(repoG),
                        "init", "-q"], capture_output=True, text=True, timeout=60)
        (repoG / ".git").write_text("gitdir: " + str(gdir).replace("\\", "/") + "\n",
                                    encoding="utf-8")
        for a in (["/inheritance:r"],
                  ["/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
                  ["/setowner", "*S-1-5-32-544"]):
            subprocess.run([_icacls_exe, str(repoG)] + a,
                           capture_output=True, text=True, timeout=60)
        reasonsG = probe({"action": "trusted-source", "root": str(repoG),
                          "author": identity("SYNTH", SID_AUTHOR),
                          "expected_commit": "a" * 40, "expected_tree": "b" * 40},
                         work)["reasons"]
        # Case J -- the commondir escape: .git is an ordinary DIRECTORY and the
        # in-tree .git/config is clean, so the config scan and the gitdir-pointer
        # check both pass it. But .git/commondir redirects git's COMMON dir --
        # where it actually reads config, objects and refs -- to an external copy
        # whose config defines a filter driver. A committed .gitattributes assigns
        # that filter to a worktree file, so `git status` runs the author program
        # from config the scan never saw. The shape must be refused (a repository
        # that borrows its common dir is not self-contained), before git.
        repoJ = work / "op49b-j"
        markerJ = work / "op49b-j-marker.txt"
        _make_repo(repoJ, markerJ, protected=False, with_fsmon=False)
        (repoJ / ".gitattributes").write_text("* filter=x\n", encoding="utf-8")
        # SAME LENGTH, different bytes, below. git's ie_modified reports a
        # SIZE change as modified WITHOUT running the filter, so an orig->dirty
        # pair left the clean driver unexecuted and the no-marker clause proved
        # nothing. An equal-size edit forces the content comparison that runs it:
        # measured, the redirected filter executes under the contract's own
        # elevated git invocation when the shape is not refused.
        (repoJ / "f.txt").write_text("aaaaa\n", encoding="utf-8")
        for _cmd in (["add", "-A"],
                     ["-c", "user.email=a@b.c", "-c", "user.name=a",
                      "commit", "-q", "-m", "attrs"]):
            subprocess.run([_git, "-C", str(repoJ)] + _cmd,
                           capture_output=True, text=True, timeout=60)
        # A functioning external common dir: a copy of this .git, with a poisoned
        # filter appended to ITS config. git reads config/objects/refs from here.
        commonJ = work / "op49b-j-common"
        shutil.copytree(repoJ / ".git", commonJ)
        _cleanJ = work / "op49b-j-clean.sh"
        _cleanJ.write_text("#!/bin/sh\necho x > '" + str(markerJ).replace("\\", "/")
                           + "'\ncat\n", encoding="utf-8")
        with (commonJ / "config").open("a", encoding="utf-8") as _fh:
            _fh.write('[filter "x"]\n\tclean = sh \''
                      + str(_cleanJ).replace("\\", "/") + "'\n")
        (repoJ / ".git" / "commondir").write_text(
            str(commonJ).replace("\\", "/") + "\n", encoding="utf-8")
        # Dirty the filtered file so `git status` must run the clean filter.
        (repoJ / "f.txt").write_text("bbbbb\n", encoding="utf-8")
        for a in (["/inheritance:r"],
                  ["/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
                  ["/setowner", "*S-1-5-32-544"]):
            subprocess.run([_icacls_exe, str(repoJ)] + a,
                           capture_output=True, text=True, timeout=60)
        reasonsJ = probe({"action": "trusted-source", "root": str(repoJ),
                          "author": identity("SYNTH", SID_AUTHOR),
                          "expected_commit": "a" * 40, "expected_tree": "b" * 40},
                         work)["reasons"]

        e_early = (bool(_structural.intersection(reasonsE))
                   and "OFFLINE_SOURCE_ROOT_WRONG_COMMIT" not in reasonsE
                   and "OFFLINE_SOURCE_ROOT_NOT_A_REPOSITORY" not in reasonsE
                   and not markerE.exists())
        h_config = ("OFFLINE_SOURCE_ROOT_GIT_CONFIG_EXECUTABLE" in reasonsH
                    and "OFFLINE_SOURCE_ROOT_WRONG_COMMIT" not in reasonsH
                    and not markerH.exists())
        c_herm = (not markerC.exists()
                  and "OFFLINE_SOURCE_ROOT_WRONG_COMMIT" in reasonsC)
        i_include = ("OFFLINE_SOURCE_ROOT_GIT_CONFIG_EXECUTABLE" in reasonsI
                     and "OFFLINE_SOURCE_ROOT_WRONG_COMMIT" not in reasonsI
                     and not markerI.exists())
        g_gitdir = ("OFFLINE_SOURCE_ROOT_GITDIR_INDIRECT" in reasonsG
                    and "OFFLINE_SOURCE_ROOT_WRONG_COMMIT" not in reasonsG)
        j_commondir = ("OFFLINE_SOURCE_ROOT_GITDIR_INDIRECT" in reasonsJ
                       and "OFFLINE_SOURCE_ROOT_WRONG_COMMIT" not in reasonsJ
                       and not markerJ.exists())
        rec("OP49b privileged-git-never-runs-author-config-programs",
            git_ok and e_early and h_config and c_herm and i_include and g_gitdir
            and j_commondir,
            f"a structurally untrusted source returns before git; a repo-local "
            f"config with a direct execution-capable directive, an [include] to "
            f"an external filter, a gitdir-pointer .git file, or a .git/commondir "
            f"redirecting the common dir to an external filter config are each "
            f"refused before git and run no author program; a clean protected "
            f"source runs git hermetically "
            f"(E={reasonsE} m={markerE.exists()}, H={reasonsH} m={markerH.exists()}, "
            f"C={reasonsC} m={markerC.exists()}, I={reasonsI} m={markerI.exists()}, "
            f"G={reasonsG}, J={reasonsJ} m={markerJ.exists()})")

        # ---- OP49e: privileged git hooks come from a directory the author
        # cannot create. clone/checkout run post-checkout from core.hooksPath;
        # a value directly under C:\ (Authenticated Users can create-folder) let
        # the author populate the "nonexistent" hooks dir. The shipped value is
        # under the OS Windows directory, which a non-admin cannot write.
        _hp = re.search(r"GetFolderPath\(\[Environment\+SpecialFolder\]::Windows\),\s*"
                        r"'mr-offline-no-such-hooks'", _boot.replace("\n", " "))
        hook_marker = work / "op49e-hook.txt"
        hook_plant = work / "op49e-hooks"
        hook_plant.mkdir(parents=True, exist_ok=True)
        (hook_plant / "post-checkout").write_text(
            "#!/bin/sh\necho x > '" + str(hook_marker).replace("\\", "/") + "'\n",
            encoding="utf-8")
        hook_src = work / "op49e-src"
        _make_repo(hook_src, work / "unused", protected=False, with_fsmon=False)
        shipped_hooks = str(Path(os.environ.get("SystemRoot", r"C:\Windows"))
                            / "mr-offline-no-such-hooks")
        _env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "NUL"}

        def _clone_with_hooks(hp, dst):
            subprocess.run([_git, "-c", "core.fsmonitor=", "-c", f"core.hooksPath={hp}",
                            "clone", "--local", "--no-hardlinks", "--quiet",
                            str(hook_src), str(dst)],
                           capture_output=True, text=True, timeout=60, env=_env)
        # positive control: an author-populated hooks dir DOES fire.
        _clone_with_hooks(str(hook_plant), work / "op49e-ctl")
        ctl_fired = hook_marker.exists()
        if hook_marker.exists():
            hook_marker.unlink()
        # shipped: a hooks dir under Windows\, which the author cannot populate.
        _clone_with_hooks(shipped_hooks, work / "op49e-shipped")
        shipped_fired = hook_marker.exists()
        # the Windows dir denies a non-admin create -- proven by the ACL not
        # granting Users/Authenticated-Users an add-subdirectory right.
        win_acl = subprocess.run(
            [_icacls_exe, str(Path(os.environ.get("SystemRoot", r"C:\Windows")))],
            capture_output=True, text=True, timeout=60).stdout or ""
        win_denies_create = not re.search(
            r"(Users|Authenticated Users):\([^)]*\b(W|AD|WD)\b", win_acl)
        rec("OP49e privileged-git-hooks-come-from-a-non-author-creatable-dir",
            bool(_hp) and ctl_fired and not shipped_fired and win_denies_create,
            f"clone runs post-checkout from an author-populated hooks dir "
            f"(control fired={ctl_fired}) but not from the shipped hooks path "
            f"under the OS Windows directory, which denies a non-admin the right "
            f"to create it (shipped fired={shipped_fired}, "
            f"windows-denies-create={win_denies_create}, uses-windir={bool(_hp)})")

        # ---- OP49f: the task-root gate checks the ROOT's owner and author-
        # writability, so the build route (which passes Runtime='') cannot be
        # satisfied by an author-owned, protected root granting itself Modify.
        _atrp = ("function Assert-TaskRootProtected "
                 + _bodies_boot["Assert-TaskRootProtected"]
                 if "Assert-TaskRootProtected" in (_bodies_boot := function_bodies(_boot))
                 else "")
        # The build route must pass the runtime, not the empty string.
        _prr_block = _boot.find("if ($ProvisionReviewerRuntime)")
        _prr_gate_empty = _boot.find("Assert-TaskRootProtected -Root $HvRoot -Runtime ''",
                                     _prr_block) if _prr_block >= 0 else -1

        _real_author_name = os.environ.get("USERNAME", "")

        def _run_atrp(dst, author_writable, use_real_author):
            dst.mkdir(parents=True, exist_ok=True)
            acls = [["/inheritance:r"],
                    ["/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"]]
            if author_writable:
                # Authenticated Users Modify -- the real author (an admin here)
                # is authenticated, so Test-AccountCanWritePath matches it
                # deterministically, unlike a synthetic SID.
                acls.append(["/grant:r", "*S-1-5-11:(OI)(CI)M"])
            acls.append(["/setowner", "*S-1-5-32-544"])
            for a in acls:
                subprocess.run([_icacls_exe, str(dst)] + a,
                               capture_output=True, text=True, timeout=60)
            # Real author (an admin here) for the author-writable case; a
            # synthetic non-admin for the clean-passes control, since on this
            # single-admin host the real author is a member of Administrators and
            # would read as writable against any admin-only tree.
            if use_real_author:
                ident = ("$AuthorIdentity = Resolve-PrincipalIdentity -Account '"
                         + _real_author_name + "'\n")
            else:
                ident = ("$AuthorIdentity = [pscustomobject]@{ Name='SYNTH'; Sid='"
                         + SID_AUTHOR + "'; Exists=$true; Resolved=$true }\n")
            h = work / (dst.name + "-atrp.ps1")
            h.write_text(
                "$ErrorActionPreference='Continue'\n"
                "$icacls = (Join-Path $env:SystemRoot 'System32\\icacls.exe')\n"
                ". '" + str(ROOT / "packaging" / "hyperv" / "principal_contract.ps1")
                + "'\n" + ident
                + "function Test-AuthorWritable { param([string]$Path)\n"
                "  Test-AccountCanWritePath -Identity $AuthorIdentity -Path $Path }\n"
                + _atrp
                + "\nAssert-TaskRootProtected -Root '" + str(dst) + "' -Runtime ''\n"
                "Write-Output 'ATRP-PASSED'\n", encoding="utf-8")
            out = subprocess.run(
                [str(SHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                 "Bypass", "-File", str(h)], capture_output=True, text=True, timeout=180)
            return out.returncode, (out.stdout or "") + (out.stderr or "")
        f_rc, f_text = _run_atrp(work / "op49f-writable", author_writable=True,
                                 use_real_author=True)
        g_rc, g_text = _run_atrp(work / "op49f-clean", author_writable=False,
                                 use_real_author=False)
        rec("OP49f task-root-gate-checks-owner-and-author-writability",
            bool(_atrp) and _prr_gate_empty < 0
            and f_rc == 2 and "OFFLINE_TASK_ROOT_AUTHOR_WRITABLE" in f_text
            and g_rc == 0 and "ATRP-PASSED" in g_text,
            f"a protected root granting the author Modify is refused even with "
            f"Runtime='' (so the build route is covered), while a protected "
            f"admin-only root passes for a non-author; and the build route no "
            f"longer calls the gate with an empty Runtime (writable-rc={f_rc}, "
            f"clean-rc={g_rc}, build-empty-call={_prr_gate_empty})")

        # ---- OP49c: the reviewer runtime is not executed while it is untrusted
        # verify() spawned <runtime-root>\python.exe even after structural
        # refusal reasons; the interpreter runs only when none stand.
        rt_text = (ROOT / "scripts" / "offline_reviewer_runtime.py").read_text(encoding="utf-8")
        import importlib.util as _ilu
        _spec = _ilu.spec_from_loader("rt_op49c", loader=None)
        _rt = _ilu.module_from_spec(_spec)
        exec(compile(rt_text, "rt_op49c", "exec"), _rt.__dict__)
        _rt_calls = []
        _orig_run = _rt.subprocess.run

        def _rec_run(cmd, *a, **k):
            _rt_calls.append(list(cmd) if isinstance(cmd, (list, tuple)) else [cmd])

            class _R:
                returncode = 0
                stdout = "3.10.0\n"
                stderr = ""
            return _R()
        _rt.subprocess.run = _rec_run
        rt_work = work / "op49c"
        (rt_work / "mr-hv" / "reviewer-runtime").mkdir(parents=True, exist_ok=True)
        (rt_work / "plant").mkdir(parents=True, exist_ok=True)
        rt_exe = rt_work / "plant" / "python.exe"
        rt_exe.write_bytes(b"MZ")
        rt_reasons = _rt.verify(rt_exe, task_root=rt_work / "mr-hv",
                                runtime_root=rt_work / "mr-hv" / "reviewer-runtime",
                                run_probe=True)
        _rt.subprocess.run = _orig_run
        rt_ran = any(str(rt_exe) == c[0] for c in _rt_calls)
        rec("OP49c the-reviewer-runtime-is-not-run-while-untrusted",
            bool(rt_reasons) and not rt_ran,
            f"verify() on a runtime with structural refusal reasons does not "
            f"spawn the interpreter -- a detector must not execute the bytes it "
            f"judges (reasons={len(rt_reasons)}, interpreter-executed={rt_ran})")

        # ---- OP49c2: -HardenInterpreter checks the task root BEFORE it runs the
        # runtime verifier (structural ordering, parallel to OP38).
        # Bounded to the -HardenInterpreter route so it cannot be satisfied by
        # the identically-named gate on the -ProvisionReviewerRuntime route.
        _h_block = _boot.find("if ($HardenInterpreter)")
        _h_exec = _boot.find("& $BuildPython -I $verifier --action verify", _h_block)
        _h_gate = _boot.find("Assert-TaskRootProtected", _h_block)
        rec("OP49c2 harden-interpreter-gates-the-task-root-before-execution",
            _h_block >= 0 and _h_gate >= 0 and _h_exec >= 0
            and _h_block < _h_gate < _h_exec,
            f"within the -HardenInterpreter route Assert-TaskRootProtected "
            f"precedes the '& $BuildPython -I verifier' call, so a planted "
            f"runtime is refused before a byte of it runs "
            f"(block@{_h_block}, gate@{_h_gate}, exec@{_h_exec})")

        # ---- OP49d: privileged secedit input is not taken from $env:TEMP
        # The .inf secedit imports at High integrity must not sit in an
        # author-controllable directory where it can be swapped between write
        # and read. New-ProtectedWorkDir builds an admin-only, non-inheriting,
        # non-reparse directory off the machine Windows\Temp instead.
        _bodies = function_bodies(_boot)
        _sec_uses_temp = any("$env:TEMP" in _bodies.get(fn, "")
                             for fn in ("Get-BatchLogonHolders", "Grant-BatchLogon"))
        _npwd = ("function New-ProtectedWorkDir " + _bodies["New-ProtectedWorkDir"]
                 if "New-ProtectedWorkDir" in _bodies else "")
        sd_harness = work / "op49d.ps1"
        sd_out_file = work / "op49d-result.json"
        sd_harness.write_text(
            "$ErrorActionPreference='Stop'\n"
            "$icacls = (Join-Path $env:SystemRoot 'System32\\icacls.exe')\n"
            + _npwd +
            "\n$d = New-ProtectedWorkDir\n"
            "$sec = [System.IO.DirectoryInfo]::new($d).GetAccessControl()\n"
            "$owner = $sec.GetOwner([Security.Principal.SecurityIdentifier]).Value\n"
            "$trusted = @('S-1-5-32-544','S-1-5-18',"
            "'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')\n"
            "$untrusted = $false\n"
            "foreach ($a in $sec.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier])) {\n"
            "  if ($a.AccessControlType -ne 'Allow') { continue }\n"
            "  if ($trusted -notcontains $a.IdentityReference.Value) { $untrusted = $true }\n"
            "}\n"
            "$reparse = [bool]([System.IO.File]::GetAttributes($d) -band [System.IO.FileAttributes]::ReparsePoint)\n"
            "$underTemp = $d.StartsWith($env:TEMP, [StringComparison]::OrdinalIgnoreCase)\n"
            "[pscustomobject]@{ protected=$sec.AreAccessRulesProtected; owner=$owner;"
            " untrusted_ace=$untrusted; reparse=$reparse; under_env_temp=$underTemp;"
            " path=$d } | ConvertTo-Json -Compress |"
            " Set-Content -LiteralPath '" + str(sd_out_file).replace("\\", "\\\\")
            + "' -Encoding utf8\n"
            "$ErrorActionPreference='Continue'\n"
            "takeown /F $d /R /D Y 2>&1 | Out-Null; & $icacls $d /reset /T /C /Q 2>&1 | Out-Null\n"
            "Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue\n",
            encoding="utf-8")
        sd = {}
        try:
            subprocess.run([str(SHELL), "-NoProfile", "-NonInteractive",
                            "-ExecutionPolicy", "Bypass", "-File", str(sd_harness)],
                           capture_output=True, text=True, timeout=180)
            if sd_out_file.exists():
                sd = json.loads(sd_out_file.read_text(encoding="utf-8-sig"))
        except (OSError, subprocess.SubprocessError, ValueError):
            sd = {}
        rec("OP49d privileged-secedit-input-is-not-author-controllable",
            bool(_npwd) and not _sec_uses_temp and bool(sd)
            and sd.get("protected") is True
            and sd.get("owner") == "S-1-5-32-544"
            and sd.get("untrusted_ace") is False
            and sd.get("reparse") is False
            and sd.get("under_env_temp") is False,
            f"the secedit functions no longer read $env:TEMP and the transient "
            f"directory is admin-owned, inheritance-stripped, reparse-free and "
            f"outside the author-controllable temp (uses-temp={_sec_uses_temp}, "
            f"dir={sd})")

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
    MINIMUM_CHECKS = 82
    if len(CHECKS) < MINIMUM_CHECKS:
        print(json.dumps({
            "guard": "offline-operator-principal",
            "error": "OFFLINE_PRINCIPAL_BATTERY_HOLLOW",
            "detail": f"only {len(CHECKS)} checks executed, below the pinned "
                      f"minimum of {MINIMUM_CHECKS}",
        }, indent=2))
        return 1

    # A COUNT IS NOT A MEMBERSHIP. When this was written the floor sat far
    # enough below the executed total that the whole credential-chain family
    # could be deleted and the battery would still report a clean pass and exit
    # 0 -- the checks closing several rounds of findings were the most deletable
    # thing in the file. Families that exist because something was got wrong are
    # pinned by id and by size, not by census. Both numbers below are asserted
    # against what actually ran, so drift shows up as a failure rather than as
    # slack.
    REQUIRED_FAMILIES = {
        "OP49": ("the pre-trust elevated execution-surface checks: without these "
                 "the module-path, git-config, runtime-ordering and secedit-input "
                 "fixes are unmeasured"),
        "OP48": ("the credential-chain refusal: without these the route that "
                 "resets the reviewer password is unmeasured"),
    }
    executed_ids = {c["check_id"].split()[0] for c in CHECKS}
    missing_family = sorted(
        f"{fam} ({why})" for fam, why in REQUIRED_FAMILIES.items()
        if not any(i == fam or i.startswith(fam) for i in executed_ids))
    if missing_family:
        print(json.dumps({
            "guard": "offline-operator-principal",
            "error": "OFFLINE_PRINCIPAL_BATTERY_FAMILY_MISSING",
            "detail": "required check families did not execute: "
                      + "; ".join(missing_family),
        }, indent=2))
        return 1
    MINIMUM_CREDENTIAL_CHAIN_CHECKS = 23
    chain_checks = sorted(i for i in executed_ids if i.startswith("OP48"))
    if len(chain_checks) < MINIMUM_CREDENTIAL_CHAIN_CHECKS:
        print(json.dumps({
            "guard": "offline-operator-principal",
            "error": "OFFLINE_PRINCIPAL_BATTERY_FAMILY_THINNED",
            "detail": f"only {len(chain_checks)} credential-chain checks executed "
                      f"({chain_checks}), below the pinned "
                      f"{MINIMUM_CREDENTIAL_CHAIN_CHECKS}",
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
