---
name: monday-report-protected-files
description: >-
  The never-access rule for protected partner-status paths in Monday Report.
  INVOKE before touching, listing, hashing, or git-inspecting anything that might
  be a partner-status / protected deliverable, or whenever a task references
  partner status, protected paths, or off-limits files. Triggers: "partner
  status", "protected file", "is this off limits", "hash/stat/open this path",
  "check if X exists". The rule: do not access; only state non-access.
---

# Monday Report — protected partner-status paths

Some paths are **partner-status protected**. For those paths the ONLY permitted
interaction is to state, in a report, that they were **not accessed and not
modified**. This skill is written without accessing any such file.

## The prohibition (absolute)
For any protected partner-status path, you must NEVER:
- read, open, `cat`, or otherwise view its contents;
- list or enumerate it (`ls`, glob, directory walk that reveals it);
- **test its existence**, `stat`, or hash it (existence-probing is itself a
  prohibited access);
- copy, move, rename, or delete it;
- stage it, `git add` it, or inspect it via **Git metadata** (`git log/show/diff/
  cat-file/ls-files/status` targeting it, blob hashes, history);
- pass it to any tool, guard, or subagent as input.

A report may only assert non-access/non-modification. It may never quote,
summarize, hash, or describe the contents.

## Which paths?
- If the repository **marks** a path as partner-status (via an explicit marker the
  operator defines), treat it — and everything under it — as untouchable by
  default. When in doubt, **treat a candidate as protected and do not probe it**;
  do not run existence checks to "find out."
- **The exact protected paths must be supplied by the operator.** This skill does
  not enumerate them (enumerating would require the very access that is
  prohibited). If a task needs to act near protected paths and you do not have an
  operator-supplied list, ask the operator to supply it rather than discovering it.
- Note: the `partner_preview_*` scripts / `audit:partner-*` guards in this repo are
  the *partner-preview packaging & approval tooling* — a product feature, distinct
  from "protected partner-status data files." Do not assume they are the protected
  set; rely on the operator's marker/list.

## Related isolation (different mechanism, same caution)
- Sibling worktrees you were told are off-limits (e.g. an active
  evidence/certification PR's worktree) are out of bounds for the same practical
  reason — do not read, run, or git-inspect them. See [[monday-report-git-pr]],
  [[monday-report-ops]].

## If a required fact is unknowable without access
State plainly that the fact cannot be determined without accessing a protected
path, and that you therefore did not access it — rather than accessing it. A
missing fact is acceptable; a boundary violation is not.

## Non-goals / safety
- Never "just check whether it exists." Never hash "only the metadata." Never
  stage it "by accident" — scope every `git add` explicitly. See
  [[monday-report-git-pr]].
