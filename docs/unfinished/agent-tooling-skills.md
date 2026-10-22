# AI-agent skill definitions

**State:** complete and validated — **deliberately held back** from the main
line. 15 files, +1,028 lines, tooling only, no product code.
**Blocks:** nothing. This is additive developer tooling.

## What it is

Much of this codebase was built with heavy AI-agent assistance, and the project
accumulated a set of written-down operating procedures for that work: what to
check before touching the audit chain, how the evidence-certification protocol
works, which files are protected, how a release gate is supposed to fail.

Those procedures were formalised as **Claude Code skills** — small Markdown
files with YAML frontmatter that an agent discovers and loads on demand.

**14 repository-specific skills**, each mapping a task type to the relevant
rules and file paths:

```
monday-report-project          the orientation entry point
monday-report-git-pr           branch/PR conventions
monday-report-backend-api      FastAPI routes, middleware order
monday-report-database         migrations, the immutable legacy set
monday-report-queue            inline worker vs Redis Streams
monday-report-frontend         src/redesign/, Vite config quirks
monday-report-testing          the guard battery, fault batteries
monday-report-security-review  adversarial review lenses
monday-report-offline-windows  the packaged edition
monday-report-evidence-certification
monday-report-ci               the three CI jobs and the inversion
monday-report-release-ga        the blocker registry, no-waiver policy
monday-report-ops
monday-report-protected-files
```

Plus a `README.md` index mapping task → skill.

A companion set of **12 generic skills** was written at the user level
(`~/.claude/skills/`, outside the repository) covering transferable practice:
Windows security-boundary analysis, offline evidence certification, verification
environments, secure Git/PR workflow, backend API engineering, Postgres
verification, Vite frontend engineering, adversarial security review,
CI/release engineering, black-box test design, evidence integrity, and operator
runbook validation.

## Why it is worth having

Several of the repository's conventions are genuinely surprising and are the
kind of thing a fresh contributor — human or agent — gets wrong on first
contact:

- `audit:all` **exits non-zero on purpose**; a green run means CI should fail
- a guard that cannot fail is a bug, so most guards have a fault-battery twin
- `db/migrations/` is deliberately un-appliable and its checksums must not drift
- `.gitattributes eol=lf` is load-bearing for evidence reproducibility

A skill file is a reasonable place to put that, because it is loaded exactly
when the relevant work starts rather than being buried in a long document.

## Why it stopped

Two reasons, neither technical:

1. **It is tooling for one specific agent runtime.** Committing
   `.claude/skills/` to a public repository bets on that runtime's format.
   Content written as project documentation survives a format change; content
   written as frontmatter-plus-conventions may not.
2. **It was authored on a dedicated branch alongside release work** and simply
   never had a reason to merge urgently, since nothing depended on it.

The validation was real: a fresh agent session discovered all 14 project skills
plus the user-level set and successfully invoked one. Frontmatter parses,
cross-references resolve, and only `.claude/skills/` was staged — no local
settings or worktree state leaked in.

## Resuming

The interesting question is not "re-create the files" — it is **where this
content belongs**.

Option A, **ship as agent skills.** Re-create `.claude/skills/` and keep it
in sync with the code. Cheap, immediately useful if you use a compatible agent,
and worthless if you don't.

Option B, **fold the content into `docs/`** as conventional contributor
documentation, and let agent tooling be generated from it or kept locally by
whoever wants it. Slower to write, but it is readable by everyone and it cannot
rot against a vendor format.

**Option B is the recommended default for a public repository.** Quite a lot of
the content has already made that journey — the surprising conventions above now
live in [../ARCHITECTURE.md](../ARCHITECTURE.md) and
[../../CONTRIBUTING.md](../../CONTRIBUTING.md), which is exactly the migration
Option B describes.

If you do add `.claude/` (or any other agent-runtime directory) back, note that
this repository's `.gitignore` currently excludes it, so that choice is
deliberate and reversible in one line.
