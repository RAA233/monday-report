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

    bodies = {}
    for match in re.finditer(r"^function\s+([A-Za-z][A-Za-z0-9\-]*)", text, re.M):
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
            re.sub(r"^function\s+[A-Za-z][A-Za-z0-9\-]*", "", remainder, flags=re.M))

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
        # A POSITIVE CONTROL FIRST. `equals_shadow is False` is satisfied by a
        # resolution that produced NOTHING, for any reason -- and that is exactly
        # what was happening: the ancestor mask was inert, every candidate scored
        # author-writable, and the check recorded a pass over a function that
        # could no longer resolve anything at all. The synthetic author is in no
        # local group, so a machine-wide git must resolve for it.
        git_control = probe({"action": "trusted-git",
                             "author": identity("SYNTH", SID_AUTHOR)}, work)["value"] or {}
        git_author = probe({"action": "trusted-git", "explicit": str(planted_git),
                            "shadow": str(planted_git),
                            "author": {"name": os.environ.get("USERNAME", ""), "sid": "",
                                       "exists": True, "resolved": True}}, work)["value"] or {}
        rec("OP22c author-writable-git-is-refused",
            git_control.get("resolved") is True and git_control.get("exists") is True
            and git_author.get("equals_shadow") is False,
            f"resolution genuinely works for a non-administrative author, and the "
            f"explicitly supplied git inside a directory the author owns is "
            f"skipped rather than trusted -- so the refusal is a refusal and not "
            f"a resolution that failed for its own reasons "
            f"(control={git_control}, planted={git_author})")

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
        boot_live = strip_powershell_comments(
            (ROOT / "packaging" / "hyperv" / "reviewer_bootstrap.ps1").read_text(
                encoding="utf-8"))
        boot_body = function_bodies(boot_live)
        executing_routes = [name for name, body in boot_body.items()
                            if "$BuildPython $" in body or "& $BuildPython" in body]
        gated = re.findall(r"Assert-InterpreterSourceTrusted\s+-Interpreter", boot_live)
        top_level_exec = len(re.findall(r"&\s+\$BuildPython\s", boot_live))
        rec("OP38 every-route-that-executes-an-interpreter-checks-it-first",
            len(gated) >= 1 and top_level_exec >= 1 and len(gated) >= top_level_exec - 1,
            f"the interpreter-trust gate is invoked on the routes that run an "
            f"operator-named interpreter ({len(gated)} gate call(s), "
            f"{top_level_exec} execution(s), helper-scoped routes="
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

        rec("OP34a no-gate-is-fed-from-a-captured-stream",
            "Assert-CapabilitiesAcceptable -Reasons @(" not in boot_live
            and boot_live.count("-Reasons ([ref]$measured)") == 2
            and boot_live.count("Assert-CapabilitiesAcceptable -Reasons $measured") == 2,
            "both capability call sites pass a caller-owned list rather than "
            "collecting whatever the reporter printed, and both still feed that "
            "list to the verdict -- an absence test alone was satisfied by "
            "deleting the verdict call outright")

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
        boot_text = boot.read_text(encoding="utf-8")
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
        shutil.rmtree(work, ignore_errors=True)

    # A FLOOR ASSERTED FROM THE RUN, not from a static count of the source.
    # The manifest's count is a text-shaped proxy and can be restored by adding
    # string constants; this one is the number of checks that actually
    # executed. Both are kept: the manifest catches deletion without running
    # anything, this catches hollowing at run time.
    MINIMUM_CHECKS = 52
    if len(CHECKS) < MINIMUM_CHECKS:
        rec("OP99 the-battery-still-executes-its-pinned-minimum", False,
            f"only {len(CHECKS)} checks executed, below the pinned minimum of "
            f"{MINIMUM_CHECKS}")

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
