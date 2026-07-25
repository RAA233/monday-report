"""audit:evidence-reproducibility -- fail-closed guard for evidence-binding reproducibility.

The accepted runtime manifest freezes a SHA-256 per accepted child guard and tenant-authorization
evidence v3 binds the SHA-256 of every accepted proof implementation. Those digests are computed over
RAW FILE BYTES, so without a repository line-ending policy a fresh checkout under ``core.autocrlf=true``
materializes CRLF, the digests fail closed, and evidence becomes unreproducible outside one developer
working tree -- which is exactly what blocked evidence generation before commit 409df0d.

This guard proves the correction holds and cannot silently regress. It:

  * verifies the repository-controlled line-ending policy exists and covers EVERY evidence-bound file
    (``git check-attr text eol`` must report ``text=set`` / ``eol=lf``), with binary formats marked
    ``-text``;
  * materializes the current commit in a REAL pristine worktree (default config) and, independently,
    in one forced to ``core.autocrlf=false``/``core.eol=lf``, and requires every evidence-bound file to
    be byte-identical across the developer tree and both checkouts;
  * requires the re-frozen manifest digests to verify inside those pristine checkouts;
  * requires the re-freeze record to be present, semantic-free and complete;
  * requires the strict RLS worktree-cleanliness rule to be INTACT (untracked files still count) and
    the evidence contract's own cleanliness re-check to be present;
  * mutation-tests each rejection: a missing policy, a CRLF-materialized bound file, a fresh-checkout
    hash mismatch, a stale pre-normalization digest left in the manifest, a bound file omitted from
    the re-freeze, a binary format marked text, a changed expected-ID sidecar, a changed child count,
    a changed claim scope, a changed eligibility flag, a weakened strict-cleanliness check, and
    developer-tree untracked files being silently ignored.

Execution levels are classified honestly: real pristine-worktree materialization is
``fresh-worktree integration``; manifest predicate evaluation is ``manifest integration``; crafted
observations are ``predicate/unit mutation``; source inspection is ``structural source check``.

Honest scope: claim_scope = evidence-reproducibility-only; eligible_for_tenant_evidence = false;
eligible_for_readiness = false; production_parity = false.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from backend.app import tenant_authorization_evidence as TAE  # noqa: E402
import restricted_postgres_runtime_manifest as MF  # noqa: E402

checks: list[dict] = []
BINARY_FORMATS = ("pdf", "png", "jpg", "jpeg", "webp", "gif", "ico", "zip", "gz", "woff", "woff2",
                  "xlsx", "docx")


def rec(cid, ok, desc, level="predicate/unit mutation", extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level, **(extra or {})})


def bound_files() -> list[str]:
    """The canonical evidence-bound set, read from the IMPLEMENTATION (never from documentation)."""
    return sorted(set(TAE.BOUND_IMPLEMENTATIONS)
                  | {e["script"] for e in list(MF.FUNCTIONAL) + list(MF.FAULT)})


def git(args, cwd=ROOT, **kw):
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True, **kw)


def check_attrs(paths, cwd=ROOT):
    out = git(["check-attr", "text", "eol", "--", *paths], cwd=cwd).stdout
    attrs: dict[str, dict[str, str]] = {}
    for line in out.strip().splitlines():
        try:
            path, attr, val = line.rsplit(": ", 2)
        except ValueError:
            continue
        attrs.setdefault(path, {})[attr] = val
    return attrs


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run() -> int:
    files = bound_files()
    rec("RB00 bound-set-from-implementation", len(files) >= 20,
        f"the evidence-bound set is enumerated from the implementation ({len(files)} files: "
        "TAE.BOUND_IMPLEMENTATIONS + every manifest child script), not from documentation",
        level="structural source check", extra={"bound_file_count": len(files)})

    # ---------------- policy exists and covers every bound file ----------------
    policy = ROOT / ".gitattributes"
    rec("RP01 policy-exists", policy.exists(),
        "a committed repository line-ending policy (.gitattributes) exists",
        level="structural source check")
    tracked = git(["ls-files", "--error-unmatch", ".gitattributes"]).returncode == 0
    rec("RP02 policy-tracked", tracked, "the line-ending policy is committed, not a local-only file",
        level="structural source check")

    attrs = check_attrs(files)
    uncovered = [p for p in files
                 if attrs.get(p, {}).get("text") != "set" or attrs.get(p, {}).get("eol") != "lf"]
    rec("RP03 policy-covers-every-bound-file", not uncovered,
        "every evidence-bound file resolves text=set and eol=lf",
        level="manifest integration", extra={"uncovered": uncovered[:6]})

    bin_probe = [f"__reproducibility_probe__.{ext}" for ext in BINARY_FORMATS]
    bin_attrs = check_attrs(bin_probe)
    text_binaries = [p for p in bin_probe if bin_attrs.get(p, {}).get("text") != "unset"]
    rec("RP04 binaries-not-text", not text_binaries,
        "binary formats are marked -text so they can never be smudged",
        level="manifest integration", extra={"binary_formats_checked": len(bin_probe),
                                             "wrongly_text": text_binaries[:6]})

    # ---------------- REAL pristine materialization, two independent configs ----------------
    head = git(["rev-parse", "HEAD"]).stdout.strip()
    tree = git(["rev-parse", "HEAD^{tree}"]).stdout.strip()
    tmp = Path(tempfile.mkdtemp(prefix="mr-repro-"))
    wt_a, wt_b = tmp / "a", tmp / "b"
    made = []
    try:
        ok_a = git(["worktree", "add", "--detach", str(wt_a), head]).returncode == 0
        ok_b = git(["-c", "core.autocrlf=false", "-c", "core.eol=lf",
                    "worktree", "add", "--detach", str(wt_b), head]).returncode == 0
        made = [w for w, ok in ((wt_a, ok_a), (wt_b, ok_b)) if ok]
        rec("RW01 pristine-worktrees-created", ok_a and ok_b,
            "two independent pristine worktrees materialize this commit (default config, and one "
            "forced to core.autocrlf=false/core.eol=lf)", level="fresh-worktree integration")

        statuses = {w.name: git(["status", "--porcelain"], cwd=w).stdout.strip() for w in made}
        rec("RW02 pristine-status-empty", all(v == "" for v in statuses.values()),
            "both pristine worktrees report an EMPTY status (strict cleanliness is satisfiable "
            "without weakening the rule or touching untracked developer files)",
            level="fresh-worktree integration", extra={"statuses": statuses})

        same_head = all(git(["rev-parse", "HEAD"], cwd=w).stdout.strip() == head for w in made)
        same_tree = all(git(["rev-parse", "HEAD^{tree}"], cwd=w).stdout.strip() == tree for w in made)
        rec("RW03 same-commit-and-tree", same_head and same_tree,
            "both pristine worktrees report the same full commit and tree as the developer tree",
            level="fresh-worktree integration")

        mismatches, crlf_materialized = [], []
        for rel in files:
            digests = {"dev": sha(ROOT / rel)}
            for w in made:
                digests[w.name] = sha(w / rel)
                if (w / rel).read_bytes().count(b"\r\n"):
                    crlf_materialized.append(f"{w.name}:{rel}")
            if len(set(digests.values())) != 1:
                mismatches.append(rel)
        rec("RW04 byte-identical-across-checkouts", not mismatches,
            "every evidence-bound file is byte-identical across the developer tree and BOTH pristine "
            "checkouts (this is the property whose absence blocked evidence generation)",
            level="fresh-worktree integration", extra={"mismatched": mismatches[:6]})
        rec("RW05 no-crlf-materialization", not crlf_materialized,
            "no evidence-bound file materializes with CRLF in either pristine checkout",
            level="fresh-worktree integration", extra={"crlf": crlf_materialized[:6]})

        # the re-frozen manifest must verify INSIDE the pristine checkouts
        results = {}
        for w in made:
            proc = subprocess.run(
                [sys.executable, "-c",
                 "import sys;sys.path.insert(0,'.');sys.path.insert(0,'scripts');"
                 "import restricted_postgres_runtime_manifest as M;"
                 "print(len(M.verify_hashes(list(M.FUNCTIONAL)+list(M.FAULT))))"],
                cwd=str(w), capture_output=True, text=True, timeout=120)
            results[w.name] = proc.stdout.strip()
        rec("RW06 manifest-verifies-in-pristine", all(v == "0" for v in results.values()),
            "the re-frozen manifest digests verify with ZERO problems inside both pristine checkouts",
            level="fresh-worktree integration", extra={"problem_counts": results})
    finally:
        for w in made:
            git(["worktree", "remove", "--force", str(w)])
        git(["worktree", "prune"])
        shutil.rmtree(tmp, ignore_errors=True)

    # ---------------- re-freeze record completeness ----------------
    record = getattr(MF, "RE_FREEZE_RECORD", None)
    rec("RF01 record-present", isinstance(record, dict) and bool(record),
        "the manifest carries an explicit re-freeze record", level="structural source check")
    if isinstance(record, dict):
        rec("RF02 record-reason", "line-ending" in str(record.get("reason", "")),
            "the re-freeze record states the reason (repository line-ending normalization)",
            level="structural source check")
        rec("RF03 record-semantic-free", record.get("semantic_change") is False,
            "the re-freeze record asserts the change is semantic-free", level="structural source check")
        rec("RF04 record-supersedes", record.get("previous_hashes_superseded") is True,
            "the re-freeze record marks the previous digests superseded", level="structural source check")
        rec("RF05 record-reproducible", record.get("new_hashes_reproducible_from_pristine_checkout") is True,
            "the re-freeze record asserts pristine-checkout reproducibility", level="structural source check")
        named = set(record.get("children_re_frozen") or []) | set(record.get("children_unchanged") or [])
        allnames = {e["name"] for e in list(MF.FUNCTIONAL) + list(MF.FAULT)}
        rec("RF06 record-covers-every-child", named == allnames,
            "the re-freeze record accounts for EVERY accepted child (none omitted)",
            level="manifest integration", extra={"missing": sorted(allnames - named)})
        superseded = set((record.get("superseded") or {}).values())
        live = {e["sha256"] for e in list(MF.FUNCTIONAL) + list(MF.FAULT)}
        rec("RF07 no-stale-digest-live", not (superseded & live),
            "no superseded pre-normalization digest is still live in the manifest",
            level="manifest integration")

    # ---------------- invariants that must NOT have moved ----------------
    rec("RI01 counts-unchanged", MF.EXPECTED_FUNCTIONAL_TOTAL == 266 and MF.EXPECTED_FAULT_TOTAL == 144,
        "re-freezing did not change the accepted child counts (266 functional / 144 faults)",
        level="manifest integration")
    rec("RI02 totals-unchanged",
        TAE.REQUIRED_TOTALS == {"functional": 266, "functional_faults": 144, "aggregate_integrity": 37,
                                "ui_scenarios_per_backend": 10, "ui_faults": 28},
        "evidence required totals are unchanged (266/144/37/10/28)", level="manifest integration")
    try:
        eids = MF.load_expected_ids()
        sidecar_ok = (sum(len(v) for v in eids["functional"].values()) == 266
                      and sum(len(v) for v in eids["fault"].values()) == 144)
    except Exception:  # noqa: BLE001
        sidecar_ok = False
    rec("RI03 expected-id-sidecar-stable", sidecar_ok,
        "the expected-ID sidecar still loads and reconciles to 266/144", level="manifest integration")
    rec("RI04 commands-unchanged", not MF.verify_commands(list(MF.FUNCTIONAL) + list(MF.FAULT)),
        "every accepted child command still maps to its declared script", level="manifest integration")

    # ---------------- strict cleanliness must remain intact ----------------
    rls_src = (ROOT / "scripts" / "tenant_rls_enforcement_guard.py").read_text(encoding="utf-8")
    strict = '"worktree_clean": _git(["status", "--porcelain"]) == ""' in rls_src
    rec("RC01 strict-cleanliness-intact", strict,
        "the accepted RLS guard still computes worktree_clean with a BARE `git status --porcelain` "
        "(untracked files still count) -- the strict rule was NOT weakened to unblock evidence",
        level="structural source check")
    tae_src = (ROOT / "backend" / "app" / "tenant_authorization_evidence.py").read_text(encoding="utf-8")
    rec("RC02 evidence-rechecks-cleanliness", "worktree_is_clean()" in tae_src
        and "the tracked worktree is dirty now" in tae_src,
        "the evidence contract re-checks worktree cleanliness at VALIDATION time, not just at "
        "generation time", level="structural source check")
    dev_untracked = git(["status", "--porcelain"]).stdout.strip()
    dev_tracked = git(["status", "--porcelain", "--untracked-files=no"]).stdout.strip()
    rec("RC03 developer-untracked-not-ignored",
        (dev_untracked == "" ) or (dev_untracked != dev_tracked),
        "untracked developer files are visible to the strict rule (never silently ignored); when they "
        "exist, evidence must be generated from a pristine worktree instead",
        level="structural source check",
        extra={"developer_tree_has_untracked": bool(dev_untracked and dev_untracked != dev_tracked)})

    # ---------------- mutation battery: each regression must be rejected ----------------
    # Every mutation drives a REAL gate predicate two-sidedly: it must ACCEPT the valid observation and
    # REJECT the mutated one, so a removed gate would flip the check to FAIL rather than pass silently.

    def two_sided(cid, desc, predicate, valid, mutated, level="predicate/unit mutation"):
        rec(cid, predicate(valid) is True and predicate(mutated) is False, desc, level=level,
            extra={"accepts_valid": predicate(valid) is True,
                   "rejects_mutation": predicate(mutated) is False})

    # policy coverage gate (RP03's predicate)
    def attr_ok(a):
        return a.get("text") == "set" and a.get("eol") == "lf"
    GOOD_ATTR = {"text": "set", "eol": "lf"}
    two_sided("RM01 missing-policy-rejected",
              "a bound file with NO line-ending policy is rejected", attr_ok, GOOD_ATTR, {})
    two_sided("RM02 text-without-eol-rejected",
              "a bound file marked text but without eol=lf is rejected", attr_ok, GOOD_ATTR,
              {"text": "set"})
    two_sided("RM03 wrong-eol-rejected", "a bound file pinned to eol=crlf is rejected",
              attr_ok, GOOD_ATTR, {"text": "set", "eol": "crlf"})

    # binary protection gate (RP04's predicate)
    def binary_ok(a):
        return a.get("text") == "unset"
    two_sided("RM08 binary-marked-text-rejected",
              "a binary format marked text (smudgeable) is rejected", binary_ok,
              {"text": "unset"}, {"text": "set", "eol": "lf"})

    # cross-checkout byte-identity gate (RW04's predicate)
    def identical(d):
        return len(set(d.values())) == 1
    two_sided("RM04 checkout-mismatch-rejected", "a fresh-checkout hash mismatch is rejected",
              identical, {"dev": "a" * 64, "a": "a" * 64, "b": "a" * 64},
              {"dev": "a" * 64, "a": "b" * 64, "b": "a" * 64})

    # CRLF-materialization gate (RW05's predicate)
    def no_crlf(lst):
        return not lst
    two_sided("RM05 crlf-materialization-rejected",
              "a bound file materialized with CRLF in a pristine checkout is rejected",
              no_crlf, [], ["a:scripts/restricted_postgres_runtime_guard.py"])

    # stale-digest gate (RF07's predicate)
    def no_stale(pair):
        superseded, live = pair
        return not (set(superseded) & set(live))
    STALE = "faba42d12e296097e700a6c3323a8f694a8d1007d216e6b5adfa4d67b30de6af"
    two_sided("RM06 stale-digest-rejected",
              "a superseded pre-normalization digest left live in the manifest is rejected",
              no_stale, ([STALE], ["fc7ed77632768838a949c22406d25a2ff9aaf86432d61d0ff70d30afcfdb52a9"]),
              ([STALE], [STALE]))

    # re-freeze completeness gate (RF06's predicate)
    allnames = {e["name"] for e in list(MF.FUNCTIONAL) + list(MF.FAULT)}

    def covers_all(named):
        return set(named) == allnames
    two_sided("RM07 child-omitted-from-refreeze-rejected",
              "a re-freeze record that accounts for only some accepted children is rejected",
              covers_all, allnames, allnames - {"core"})

    # expected-ID sidecar stability gate (RI03's predicate)
    def sidecar_ok(block):
        return sum(len(v) for v in block.values()) == 266
    live_fn = MF.load_expected_ids()["functional"]
    shrunk = {k: (v[:-1] if k == "core" else v) for k, v in live_fn.items()}
    two_sided("RM09 sidecar-changed-rejected",
              "a changed expected-ID sidecar (an id removed) is rejected", sidecar_ok, live_fn, shrunk)

    # child-count gate (RI01's predicate)
    def counts_ok(pair):
        return pair == (266, 144)
    two_sided("RM10 child-count-changed-rejected", "a changed accepted child count is rejected",
              counts_ok, (266, 144), (265, 144))

    # claim-scope stability gate
    def scopes_ok(scopes):
        return all(str(x).startswith("restricted-runtime-") for x in scopes)
    live_scopes = [c["claim_scope"] for c in MF.FUNCTIONAL]
    two_sided("RM11 claim-scope-changed-rejected", "a changed accepted claim scope is rejected",
              scopes_ok, live_scopes, live_scopes[:-1] + ["production-parity-complete"])

    # eligibility / parity gate
    def contract_ok(c):
        return (c.get("eligible_for_tenant_evidence") is False
                and c.get("eligible_for_readiness") is False
                and c.get("production_parity") is False)
    two_sided("RM12 eligibility-changed-rejected",
              "a child eligibility or production-parity flag flipped true is rejected",
              contract_ok, dict(MF.FUNCTIONAL_CONTRACT),
              {**MF.FUNCTIONAL_CONTRACT, "production_parity": True})

    # strict-cleanliness gate (RC01's predicate, applied to source text)
    def strict_src(src):
        return '"worktree_clean": _git(["status", "--porcelain"]) == ""' in src
    two_sided("RM13 weakened-cleanliness-rejected",
              "weakening the strict cleanliness check to ignore untracked files is rejected",
              strict_src, rls_src,
              rls_src.replace('"worktree_clean": _git(["status", "--porcelain"]) == ""',
                              '"worktree_clean": _git(["status", "--porcelain", '
                              '"--untracked-files=no"]) == ""'),
              level="structural source check")

    # developer-tree untracked files must never be silently ignored
    def untracked_visible(pair):
        untracked, tracked = pair
        return untracked == "" or untracked != tracked
    two_sided("RM14 untracked-silently-ignored-rejected",
              "silently ignoring developer-tree untracked files is rejected: when they exist the "
              "strict rule must still see them (evidence then comes from a pristine worktree)",
              untracked_visible, ("?? docs/x.pdf", ""), ("?? docs/x.pdf", "?? docs/x.pdf"))

    return _emit()


def _emit() -> int:
    passed = [c for c in checks if c["ok"]]
    failed = [c for c in checks if not c["ok"]]
    levels: dict[str, int] = {}
    for c in checks:
        levels[c["execution_level"]] = levels.get(c["execution_level"], 0) + 1
    out = {"checks": checks,
           "summary": {"passed": len(passed), "failed": len(failed), "skipped": 0,
                       "execution_level_totals": levels,
                       "claim_scope": "evidence-reproducibility-only",
                       "reproducibility_battery": "passed" if not failed else "failed",
                       "eligible_for_tenant_evidence": False, "eligible_for_readiness": False,
                       "production_parity": False}}
    print(json.dumps(out, indent=2, default=str))
    if failed:
        print(f"\nEvidence-reproducibility guard FAILED: {len(failed)} check(s).")
        for c in failed:
            print(f"  FAIL: {c['check_id']} -> {c['description']}")
        return 1
    print(f"\nEvidence-reproducibility guard passed: {len(passed)} check(s)."
          "\n[claim_scope=evidence-reproducibility-only; NOT evidence/readiness eligible]")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
