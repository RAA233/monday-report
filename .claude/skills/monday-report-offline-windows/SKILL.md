---
name: monday-report-offline-windows
description: >-
  Windows/PowerShell/ACL/SID/reparse/handle rules and the Offline Edition
  bootstrap trust model for Monday Report. INVOKE for offline-package, Windows
  privilege/ACL, DPAPI/reviewer-key, or elevation work, and before reasoning
  about offline bootstrap certification. Triggers: "offline edition", "bootstrap",
  "ACL/SID/junction/reparse", "DPAPI", "elevation", "reviewer key", "PR #43".
  NOTE: the offline source material lives on separate branches, not this tree.
---

# Monday Report — offline / Windows edition

The Offline Edition packages the app for a disconnected Windows host with a
two-principal (operator vs author/reviewer) trust boundary. **This material is
NOT in this main tree** (verified: no offline scripts here) — it lives on separate
feature branches and is governed by operator-supplied procedure. Treat the facts
below as governance context, not files to edit here.

## Windows / PowerShell / native-integrity rules
- Reason about **ACLs by SID**, not display names; resolve well-known folders via
  `GetFolderPath` and **ACL-verify** privileged native binaries rather than
  trusting `%SystemRoot%`/`$env:SystemRoot`.
- **Reparse points are adversarial**: a directory **junction** or symlink makes
  every ACL read/write address the link target, not the intended tree. Detect and
  refuse reparse points on any adopted directory.
- Never derive an integrity decision from the author's `.git`: git config
  indirection is unbounded (include → attributesFile → gitdir pointer →
  commondir/alternates → submodule `.git/modules/*/config`), plus `refs/replace`,
  per-directory `.gitignore`, commit-graph, etc. Enforce **exactly one repository
  at the root**; resolve trust from the OS, not repo metadata.
- Close/track handles; a plaintext secret must never pass through an author-
  controlled process or land on disk.

## Bootstrap trust model
- **Live-elevation requirement**: a privileged property (Administrator, ACL
  ownership, task scope) must be proven by **live elevation on the real host**, not
  by a lifted code region, a string match, or a claimed prior run. A lifted region
  cannot establish route/execution-scope properties.
- The reviewer/author key must be generated **after** the operator sets the
  password, or an ordinary author logon can recover it — key custody must be
  separate from the author process.
- Hyper-V / E1 / E2 environment boundaries are distinct trust surfaces; do not
  treat a proof in one as a proof in another.

## Frozen source material — never patch
- The offline package increments **#30, #39, #40, #41, #42 are FROZEN source
  material.** Do not patch, "fix", or re-lift them; they are the studied inputs.
  Their lesson: each remediation round tended to find the previous fix incomplete
  along a new in-`.git`/Windows axis — the in-`.git` class is unbounded, so the fix
  is architectural, not another patch.
- **PR #43 is the current certification model**: a two-context (fresh-checkout +
  verified-environment) evaluation **combined with** a live-elevated proof — both
  are required; neither alone certifies. (Operator-supplied; that PR is off-limits
  and lives in its own worktree — see [[monday-report-git-pr]], [[monday-report-protected-files]].)

## Non-goals / safety
- **Never fabricate privileged/elevated evidence**, and never claim a privilege
  from anything short of live elevation on the target host. See
  [[monday-report-security-review]], [[monday-report-evidence-certification]].
- Do not modify frozen increments. Do not enter passwords/credentials or perform
  host privilege changes yourself — that is operator work. See [[monday-report-ops]].
