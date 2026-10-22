# Offline pre-trust bootstrap: five attempts, one merged

**State:** v5 merged. v2, v3, and v4 abandoned.
**Value to a new contributor:** this is the most instructive failure sequence in
the project's history. Read it before hardening any trust boundary.

## The problem

Before the offline edition can be trusted on an operator's machine, something
must establish that the source it is about to run is the source the operator
intended. That "something" runs **before** trust exists, so it cannot rely on
anything in the repository it is checking.

Stated plainly: **no author-controlled executable may run before source trust is
established.** Not a repo Python helper, not a `PATH`-resolved interpreter, and
certainly not an elevated repo script that mints its own manifest hash and then
declares itself valid.

## The five attempts

| | Approach | Outcome |
|---|---|---|
| v1 | Bootstrap inside the normal repo tooling | Failed: self-certifying |
| v2 | "Terminating" trust-boundary rebuild, 22,561-line clean replacement | Abandoned |
| v3 | Trust-Root Kernel, 78 controls / 24 mutations | Failed review on a `Win32_Process.Create` observer evasion |
| v4 | Pre-trust root + release bundle, external black-box harness | Abandoned |
| **v5** | Single-file PowerShell, no repo imports, operator-supplied pin | **Merged** |

## Why v1–v4 kept failing: two recurring shapes

Every review round found the *previous* round's fix incomplete, and almost
always along one of two axes.

### Shape 1 — the refusal keyed to fewer operands than the damage

A check would refuse on one identifier while the attack moved to an adjacent
one. The progression was literally:

```
$HvRoot  →  $User  →  $TaskName-as-leaf-vs-path
```

Each fix was correct about the case it had seen and silent about the next one.

### Shape 2 — the check measured something adjacent to the call

A sequence of increasingly-close-but-still-wrong proxies for "what will actually
execute":

```
regex over the text  →  one file  →  module qualification  →  lexical ancestry
```

The last one is the subtlest: **lexical ancestry is not execution scope.** Code
can be lifted out of the region you inspected and run elsewhere. A lifted region
cannot establish route properties.

### The `.git` indirection chain

A parallel enumeration problem, five rounds deep:

```
include  →  attributesFile  →  gitdir pointer  →  commondir/alternates
         →  submodule .git/modules/<n>/config
```

Each round closed one indirection and found another. The durable rule that
emerged: **exactly one repository at the root**, verified — rather than trying
to enumerate every way Git config can redirect.

Round (e) also surfaced a second, unrelated Critical that three of four review
lenses found independently: **an adopted directory junction** makes every ACL
read and write address the link rather than the tree.

### Round (f) stopped the loop

The sixth review found three more issues in two further subsystems
(an unvalidated `$env:SystemRoot` behind every privileged native binary, which
leaked a plaintext reviewer password to an author-controlled executable;
`refs/replace`; per-directory `.gitignore`) and named commit-graph and untracked
files as still-open.

**The conclusion was that the in-`.git` failure class is unbounded, so
enumeration cannot terminate.** The fix had to be architectural: never derive
the integrity decision from the author's `.git` at all.

## What v5 does differently

`packaging/offline/Invoke-OfflineBootstrap.ps1` — 1,554 lines, single file:

- **No repo imports. No child processes. No `PATH`-derived executable
  resolution.** Privileged natives are resolved from the verified OS System
  directory, never from `PATH` or environment.
- **Operator-supplied, out-of-band pins** — the expected bundle/source root hash
  and the bootstrap's own SHA-256 come from an independent channel, *not* from
  the author's workspace. The author workspace alone can never establish
  provenance.
- **Bootstrap bytes are verified using trusted OS facilities only**, against the
  operator-supplied hash, *before* the bootstrap is allowed to execute.
- **Source export without consulting `.git`** — the byte manifest is compared
  against the operator pin. No self-consistency-only acceptance.
- **Atomic create-or-refuse** via `CreateDirectoryW`; refusal on any reparse
  point, junction, `gitdir` indirection, or Windows case-collision.
- **No compiler required** — P/Invoke only, with a canonical volume-GUID path
  chain so file identity is resolved by handle rather than by name.

Certification is **live-elevated**: it requires a live elevated token and
in-memory elevation observation. This exists because an earlier round was
defeated by a hand-edited "elevated" JSON record being accepted as evidence —
a fabrication the new design refuses structurally.

## Why the earlier branches are not worth cherry-picking

They encode the *wrong architecture*. v2–v4 all try to decide trust from
material the author controls, and the review history is a record of that
approach failing five times in five different places. v5's design premise —
operator-supplied pins from an independent channel — is the thing that made the
problem tractable.

## The transferable lesson

> Budget for each review round finding the previous fix incomplete.
>
> If you are on round four of patching the same control, the signal is not
> "write round five". It is: **the failure class is unbounded, and the shape of
> the solution has to change.**

This also changes operator procedure, which is why it was escalated as a
decision rather than silently implemented — a trusted/pristine-source handover
contract is a human process commitment, not just code.
