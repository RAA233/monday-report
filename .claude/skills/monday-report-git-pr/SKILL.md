---
name: monday-report-git-pr
description: >-
  Git, branch, worktree, and PR discipline for Monday Report. INVOKE before any
  branching, committing, merging, rebasing, pushing, or PR action. Triggers:
  "commit this", "open/merge a PR", "rebase", "force push", "which worktree",
  "stacked PR", "should I merge". Enforces single-writer, ordinary-merge-only,
  never-rewrite-published-history rules.
---

# Monday Report — git / worktree / PR discipline

This repo is developed as many focused increments across **sibling git
worktrees** (one branch per worktree, e.g. `C:\Users\ralba\Desktop\mr-*`). Get
these rules right — history integrity is a project invariant.

## Worktree & single-writer discipline
- **Work only in the worktree you were assigned.** Never edit, stage, or
  git-inspect another worktree's tree. Each active branch has exactly ONE writer.
- Another agent may be the sole writer of a concurrent PR on the same machine.
  Treat their worktree as off-limits; do not run their guards.
- Do not touch worktrees you were told are off-limits (e.g. an active
  evidence/certification PR). See [[monday-report-protected-files]] for the
  never-access rule on protected paths.

## Commit / merge / history rules
- **Ordinary merge commits only.** Never `rebase`, `--force`/`--force-with-lease`
  push, `commit --amend` on published commits, `reset --hard` over pushed work,
  or otherwise **rewrite published history**. If asked to rebase a published
  branch, stop and surface it.
- Branch first if you're on the default branch; commit/push only when asked.
- Stage exactly what the task scopes — never blanket `git add -A` when the task
  says "stage only X". `.claude/` is NOT gitignored here, so `git add .claude/skills`
  (not `git add .claude`) to avoid staging `settings.local.json`/`worktrees`.
- `.gitattributes` pins `*.md`/`*.py`/`*.sql`/`*.json`/... to `eol=lf`. If a file
  you wrote shows as modified right after commit, it is CRLF drift — renormalize
  or rewrite the file with LF. **Never relax `.gitattributes` to fix it** (its
  byte-stability underpins migration checksums and evidence digests). See
  [[monday-report-database]], [[monday-report-evidence-certification]].
- Commit message: end with the required `Co-Authored-By` trailer when applicable.

## Stacked PRs & merge boundary
- A stacked PR is based on its parent PR's **frozen head**, not on a moving
  branch. Keep the base explicit; do not silently re-point it.
- **Merge is an explicit boundary.** Do not merge, cut over, or integrate unless
  the task explicitly authorizes that exact merge. "Author a change" ≠ "merge it."
  The parent/orchestrator opens/merges PRs unless told otherwise.
- Verification-only PRs must leave byte-identical the files they only verify.

## Independent-reviewer workflow
- The builder never certifies their own change. A **fresh-context** independent
  reviewer re-derives acceptance and executes counterexamples. RAW `0C/0H`
  (zero Critical, zero High) is the acceptance bar. See [[monday-report-security-review]].
- Re-run acceptance at the **exact head** that will merge; a review of an earlier
  head does not carry forward after new commits.

## Non-goals / safety
- Never open a PR or merge on your own initiative.
- Never rewrite or delete published refs, tags, or history.
- Never bypass hooks/signing (`--no-verify`, `--no-gpg-sign`) unless explicitly asked.
