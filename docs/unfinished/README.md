# Unfinished work

Work that was genuinely attempted and deliberately stopped, written up so you
can resume it without re-walking the dead ends.

Each file records: what the goal was, what landed, **why it stopped**, and what
resuming would require. Where an attempt failed review, the finding is stated
plainly — these are not sanitised.

| Document | Subject | State |
|---|---|---|
| [offline-same-origin-build.md](offline-same-origin-build.md) | Packaged frontend could not reach its own backend | Fix written, reviewed, **unmerged** |
| [offline-two-environment-certification.md](offline-two-environment-certification.md) | Two independent clean-Windows acceptance runs | Env 1 passed; Env 2 **never completed** |
| [offline-trust-root-rebuilds.md](offline-trust-root-rebuilds.md) | Pre-trust bootstrap hardening (5 attempts) | v5 merged; v2/v3/v4 **abandoned** |
| [agent-tooling-skills.md](agent-tooling-skills.md) | Reusable AI-agent skill definitions | Complete, **held back** |

---

## Why this directory exists

The original repository accumulated six open pull requests representing roughly
140 commits of real engineering that never merged. Most were superseded
iterations of the same feature; a few stopped on genuine architectural walls.

Leaving that only in a private PR tracker would waste it, and would leave a new
contributor guessing why obvious-looking approaches are absent. So the reasoning
is here instead.

## How to resume one

1. Read the document end to end, especially **"why it stopped"**. Several of
   these stopped for reasons that are *still true*.
2. Check [../ROADMAP.md](../ROADMAP.md) — some have since been partly addressed.
3. Expect the relevant guard to be stricter than you think. If a guard blocks
   your fix, that is usually the guard working. Discuss it in the PR rather than
   loosening it quietly.
4. These branches do **not** exist in this public repository. The write-ups are
   self-contained by design; you are expected to re-implement, not cherry-pick.

## A pattern worth internalising

Across five attempts at the offline trust root, every single review round found
the *previous* fix incomplete along the same axis: the refusal keyed to fewer
operands than the damage, or the check measured something adjacent to the thing
it claimed to verify.

The eventual conclusion was that the failure class could not be enumerated, and
the fix had to be architectural rather than another patch.

If you find yourself on round four of fixing the same control, that is the
signal to stop and change the shape of the solution — not to write round five.
