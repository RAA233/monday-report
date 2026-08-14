# Offline bootstrap (Phase 1) — operator instructions

`Invoke-OfflineBootstrap.ps1` creates a fresh, admin-only trust root and installs
one pinned release bundle into it. It runs **before any source in this repository
is trusted**, so it imports nothing from the repository, dot-sources nothing,
**launches no child process, no native executable and no compiler**, resolves no
executable by name, never consults `%PATH%`, and writes nothing to `%TEMP%`,
`%TMP%` or any other environment-derived directory.

Every native call it needs is declared **in this process** with
`System.Reflection.Emit`. There is no `Add-Type`, no C# source text, no `csc.exe`
and no `cvtres.exe`. That matters because the previous revision compiled its
P/Invoke declarations before it validated anything: the generated source and the
resulting DLL travelled through an environment-derived temporary directory and
the DLL was then loaded back into the elevated process. Anybody who could win the
write race owned the process before a single check had run.

## Read this first: the bootstrap does not verify itself

**A modified copy of this script can print anything it likes, including a clean
bill of health for itself.** It has no self-hash mode and no self-authorization
mode, deliberately: a check a file performs on itself is worth exactly as much as
the file, and earlier attempts at this problem failed because a verification layer
certified itself.

**You verify its SHA-256 out of band, against a value you obtained from somewhere
other than this working tree, before you run it.** Nothing the script writes to
stdout is evidence of anything. The only things you can rely on are its **exit
code** and what you can see on the filesystem yourself.

```powershell
Get-FileHash -Algorithm SHA256 .\packaging\offline\Invoke-OfflineBootstrap.ps1
```

The repository pins `*.ps1` to LF in `.gitattributes` so this hash is the same on
every platform and for any value of `core.autocrlf`. If you edit the file, the
hash changes and your pin is void — that is the point.

## Operator inputs

| Parameter | Meaning |
| --- | --- |
| `-RootName` | Leaf name of the new trust root. One path component, portable ASCII. |
| `-SourcePath` | Directory holding the release bundle. Read only, never written. |
| `-ExpectedBundleHash` | The bundle root hash **you** hold, 64 hex characters. Never read from the source tree. |
| `-ParentPath` | Optional. Defaults to the OS-derived ProgramFiles directory from `GetFolderPath` — an OS API, never an environment string. |

There is **no parameter that widens the trust set.** The previous revision
accepted a `-TrustedSid` argument, policed by a deny list of "open" groups. That
deny list omitted ALL APPLICATION PACKAGES (`S-1-15-2-1`), ALL RESTRICTED
APPLICATION PACKAGES (`S-1-15-2-2`), Backup Operators (`S-1-5-32-551`),
Pre-Windows 2000 Compatible Access (`554`) and the Server / Account / Print /
Cryptographic / Event Log / Distributed COM operator groups — so a root writable
by every AppContainer on the machine was blessed with exit 0. The fix is not a
longer deny list; the next omission is always waiting. The fix is that there is
nothing to deny: the trust test is a three-element **allow** list, and every
principal outside it is untrusted by construction.

The trusted principals are exactly:

- `S-1-5-18` — `NT AUTHORITY\SYSTEM`
- `S-1-5-32-544` — `BUILTIN\Administrators`
- `S-1-5-80-956008885-…-2271478464` — `TrustedInstaller`

## Bundle rules

Bundle path components are restricted to **portable ASCII**: `A-Z a-z 0-9 . _ -`
and nothing else. A component that is a reserved DOS device name (`CON`, `PRN`,
`AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, with or without an extension), that
ends in a dot, or that ends in a space, is refused.

This is not tidiness. The bundle root hash has to be reproducible by an
independent implementation in another language, and the manifest is
**order-sensitive**, so both sides must agree on the sort order and on the case
fold. Outside ASCII they do not, and cannot be made to:

- .NET sorts strings ordinally by **UTF-16 code unit**; Python sorts by **code
  point**. A member named with a character above U+FFFF is a surrogate pair whose
  lead unit is `0xD83D`, so it sorts *before* a member named with a character in
  U+E000–U+FFFF under .NET and *after* it under Python. Same bytes on disk, two
  different manifests, two different root hashes.
- .NET's invariant case mapping is **simple**; Python's `str.upper` is a **full**
  mapping. They disagree on `ß` and on plenty else.

Inside `A-Za-z0-9._-` the code units and the code points are the same numbers in
the same order, and the only fold is a single explicit `a`→`A` map written out
by hand on both sides. **No Unicode normalisation and no library case mapping is
relied on anywhere.** The pre-image contract is `offline-bootstrap-bundle/v2`; a
v1 pin will not verify against a v2 bundle, deliberately.

Also refused: any `.git` component in any spelling, any reparse point anywhere in
the tree, and any empty directory (an empty directory contributes nothing to the
manifest, so the pin cannot see it being added or removed).

## What "the chain" means

The parent is opened **once** and resolved with
`GetFinalPathNameByHandle(..., VOLUME_NAME_GUID)`. Every component of that
canonical path — from the real volume root down — is opened and judged: reparse
state, DACL presence, ACE interpretability, redirect-class and content-class
rights for untrusted principals, and owner. Every path used afterwards is the
canonical one.

**A drive letter is not a volume root.** The previous revision decided a chain had
ended when the path text matched the shape `X:\`. `DefineDosDeviceW` — the API
`subst.exe` calls — lets an **ordinary unelevated user** create such a drive
pointing anywhere, so a path like `X:\` was a one-component chain whose single
component sat deep inside a tree whose real ancestors were never opened, never
judged, and free to be world-writable. Exit 0, root installed. Nothing in this
revision decides where a chain ends by looking at path text.

Junctions traversed on the way in are resolved the same way, so the **target's**
ancestors are what get judged. A parent that is *itself* a reparse point is
refused outright: its identity belongs to whoever can rewrite the reparse data.

## Running it

```powershell
# 1. Verify the script's SHA-256 against your out-of-band value FIRST.
Get-FileHash -Algorithm SHA256 .\packaging\offline\Invoke-OfflineBootstrap.ps1

# 2. Then, from an ELEVATED PowerShell:
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File .\packaging\offline\Invoke-OfflineBootstrap.ps1 `
  -RootName MondayReport `
  -SourcePath D:\release\bundle `
  -ExpectedBundleHash <64 hex characters you hold out of band>

# 3. Judge the EXIT CODE, not the output.
echo $LASTEXITCODE
```

Elevation is required for the real thing, because ProgramFiles is not writable
otherwise and because the parent chain must be owned by a trusted principal. Run
unelevated and you will get `ROOT_CREATE_FAILED` (41) at best.

A root that is created and then refused (codes 42–54) is **left in place on
purpose**. Reclaiming or deleting a path that has just failed a trust check is
itself a write to an untrusted location. Remove it by hand.

## Exit codes

| Code | Reason | Code | Reason |
| --- | --- | --- | --- |
| 0 | `OK` | 38 | `PARENT_CHAIN_UNSTABLE` |
| 10 | `ARGS_INVALID` | 40 | `ROOT_EXISTS` |
| 11 | `UNEXPECTED_ERROR` | 41 | `ROOT_CREATE_FAILED` |
| 12 | `NATIVE_INIT_FAILED` | 42 | `ROOT_REPARSE` |
| 19 | `SOURCE_NOT_ANCHORED` | 43 | `ROOT_DACL_ABSENT` |
| 20 | `SOURCE_MISSING` | 44 | `ROOT_ACE_UNINTERPRETABLE` |
| 21 | `SOURCE_REPARSE` | 45 | `ROOT_OWNER_UNTRUSTED` |
| 22 | `SOURCE_GIT_PATH` | 46 | `ROOT_UNSAFE_WRITABLE_ACE` |
| 23 | `SOURCE_COLLISION` | 47 | `ROOT_MISSING` |
| 24 | `SOURCE_NAME_UNSAFE` | 48 | `ROOT_NOT_ANCHORED` |
| 25 | `BUNDLE_PIN_MISMATCH` | 49 | `ROOT_CANONICAL_UNRESOLVED` |
| 26 | `SOURCE_UNREADABLE` | 50 | `COPY_FAILED` |
| 27 | `SOURCE_EMPTY_DIRECTORY` | 51 | `DESTINATION_MISMATCH` |
| 28 | `MANIFEST_UNSORTED` | 52 | `ROOT_IDENTITY_CHANGED` |
| 29 | `SOURCE_CANONICAL_UNRESOLVED` | 53 | `COPY_DIRECTORY_OCCUPIED` |
| 30 | `PARENT_MISSING` | 54 | `ROOT_CHAIN_UNSTABLE` |
| 31 | `PARENT_REPARSE` | 60 | `DESTINATION_MISSING` |
| 32 | `PARENT_DACL_ABSENT` | 61 | `DESTINATION_REPARSE` |
| 33 | `PARENT_ACE_UNINTERPRETABLE` | 62 | `DESTINATION_GIT_PATH` |
| 34 | `PARENT_OWNER_UNTRUSTED` | 63 | `DESTINATION_COLLISION` |
| 35 | `PARENT_UNSAFE_WRITABLE_ACE` | 64 | `DESTINATION_NAME_UNSAFE` |
| 36 | `PARENT_NOT_ANCHORED` | 66 | `DESTINATION_UNREADABLE` |
| 37 | `PARENT_CANONICAL_UNRESOLVED` | 67 | `DESTINATION_EMPTY_DIRECTORY` |

A node can fail several checks at once. The refusal reported is the
**most specific** one, and the owner check is reported last. That changes which
refusal you see; it changes nothing about which nodes are accepted, because every
one of those branches is a refusal. It is ordered that way so the access-mask
logic is reachable by a test — see below.

## Verifying it: `pnpm run audit:offline:windows`

`scripts/offline_bootstrap_guard.py` is an external, black-box harness. It is a
separate gate and is **not** part of `audit:all`, because it is Windows-only.

```powershell
python scripts\offline_bootstrap_guard.py                     # the scenario table
python scripts\offline_bootstrap_guard.py --delete-mechanism  # + the self-review pass
python scripts\offline_bootstrap_guard.py --show-stdout       # + what the bootstrap printed
python scripts\offline_bootstrap_guard.py --coverage-table    # the coverage table, as markdown
python scripts\offline_bootstrap_guard.py --only SCN-15       # ONE scenario; never certifies
```

`--coverage-table` prints the table and exits without running anything.
`--only` filters the table, and a filtered run is structurally incapable of
certifying the whole: it prints `FILTERED RUN — NOT A CERTIFICATION` and exits
non-zero regardless of its rows — including when the filter matches nothing.
**Every other form, `--show-stdout` and `--delete-mechanism` included, runs the
whole table and produces a verdict.**

It treats the bootstrap as an opaque binary: it hashes the file, refuses to launch
anything whose hash does not match, and forms every verdict from the exit code
plus observations it makes itself through Win32 — file sets, digests it computes,
owner/DACL via `GetNamedSecurityInfoW`, reparse state, object identity, DOS-device
mappings via `QueryDosDeviceW`, and the live process table via
`CreateToolhelp32Snapshot`. **The bootstrap's stdout is recorded and is never an
input to any assertion.**

### Only PASS certifies

Every row in the scenario table gets one of these verdicts, and **only `PASS`
counts**:

| Verdict | Meaning | Certifies? |
| --- | --- | --- |
| `PASS` | expected refusal reason **and** every independent observation held | yes |
| `FAIL-WRONG-REASON` | refused, but for an incidental reason — not evidence for the property | no |
| `FAIL-NO-REFUSAL` | accepted what it should have refused | no |
| `FAIL-EVIDENCE` | right reason, but the harness saw the damage happen anyway | no |
| `INCONCLUSIVE` | the fixture could not be built on this machine; the run proves nothing either way | no |
| `BLOCKED_ELEVATION_REQUIRED` | the property needs the bootstrap to **accept** a chain and **install**; this process is unelevated and no principal was faked | no |

A previous revision forgave `INCONCLUSIVE` and treated the elevation-required
rows as skips, so a run in which seven rows had never been written at all still
printed "passed". They are failures now. **An unelevated run therefore cannot
certify** — that is the correct outcome, not a defect in the run.

The same hole has a second shape: a run that never constructs a row at all. A
`--only` filter selects scenarios before anything else happens, so an unselected
row is not blocked, not failed and not counted — it simply does not exist, and a
tally over what survived the filter would call a one-row table a pass. **A filtered
run therefore computes no verdict and always exits non-zero**, whatever its
selected rows did.

### Unelevated runs are honest about what they cannot show

With `-TrustedSid` gone, an unelevated process **cannot** build a fixture the
production trust set accepts: its filtered token has `BUILTIN\Administrators` as
deny-only, so every directory it creates is owned by itself. Faking a principal to
get around that is precisely the defect this revision removed.

An unelevated run proves the **16** refusal paths marked as executed in the
coverage table below *and reachable without elevation* — not the 23 the table
declares. The other seven, and outcome `OK` itself, belong to the `ELV-*` rows and
are reported `BLOCKED_ELEVATION_REQUIRED`, each of which fails the gate. Within
that boundary an unelevated run does prove the whole name and pin policy, the
process-and-temp observation, the DOS-device chain bypass and the struct-offset
half of the object-identity differential.

### Live-elevated certification: no single token certifies, and no file may claim elevation

Each scenario carries **exactly one declared certification context**, and that
declaration — not which rows happen to pass — is the only selector:

- the seven `ELV-*` rows are **`elevated`**: they need the bootstrap to *accept*
  a chain and *install*, which only a genuine elevated token can do on a fixture
  a trusted principal (`BUILTIN\Administrators`) owns;
- every `CTL-*`, `SCN-*` and `IDN-*` row is **`unelevated`**: its fixture is
  built by, and owned by, the *unelevated* current account — an **untrusted**
  owner — on purpose. Run those same fixtures under an elevated token and they
  would be owned by `BUILTIN\Administrators` (trusted), so a refusal row would
  *accept* and be mis-scored `FAIL-NO-REFUSAL` against a chain it was never
  about.

A row whose declared context is not the token running it is therefore **not
executed**. Under an unelevated token the `ELV-*` rows report
`BLOCKED_ELEVATION_REQUIRED`; under an elevated token the `CTL/SCN/IDN` rows
report `BLOCKED_WRONG_CONTEXT`. **Both** counts count as failures, so **neither a
lone unelevated run nor a lone elevated run can ever certify** — each covers only
its own half.

The unelevated half is a **head-bound evidence record**. A whole-table
unelevated run emits a machine-readable record — bound to the git head, git tree,
bootstrap SHA-256, the token it read from its own process, a whole-table flag, a
clean-worktree flag, the capturing account SID, every row's `{declared_context,
verdict, expected/observed reason}`, and the mechanism-flip results — written to
a directory **outside the git worktree** (default: a sibling `..\mr-offline-
bootstrap-evidence\`; override with `--evidence-dir`). Records are never
assembled from prose, and a malformed or partial record is a **REFUSE**, never a
lenient parse.

**The elevated half is NOT a file. A file may never claim elevated
authenticity.** A hand-edited record could set `token_context="elevated"` and
flip the seven `ELV-*` verdicts to `PASS` with no elevated token behind it — the
earlier two-file combiner accepted exactly that. So the **certify command itself
runs under a real elevated token**, verified **live** from its own process token
(`CheckTokenMembership` against `S-1-5-32-544` — read live, never from a file),
**executes `ELV-01..07` live** in that same invocation, and certifies those
**in-memory** live results against the unelevated record. **The certify path
never accepts an elevated record as an input**, now or on a future run.

**Do this in two steps, at one git head:**

```powershell
# 1. UNELEVATED PowerShell — emit the unelevated record (fails alone, by design):
cd <repo>
python scripts\offline_bootstrap_guard.py --delete-mechanism
#   -> writes ..\mr-offline-bootstrap-evidence\record-unelevated.json

# 2. ELEVATED PowerShell (Run as administrator) — the ONE certify command. It runs
#    the whole table live, executes ELV-01..07 under this real elevated token, and
#    certifies those in-memory results against the unelevated record:
cd <repo>
python scripts\offline_bootstrap_guard.py --delete-mechanism --certify ..\mr-offline-bootstrap-evidence\record-unelevated.json
#   (equivalently: pnpm run audit:offline:certify, which passes --certify default)
```

Certification is **PASS only** when all of these hold, else it **REFUSEs** with
the failing checks: this certify process holds a **real elevated token, read live
from its own process**; it was invoked with `--delete-mechanism`; its live
worktree is clean; the unelevated record is a fully-bound record that is
`token_context=unelevated` / `elevated=false`, whole-table, from a clean
worktree, `--delete-mechanism`, with a **well-formed untrusted** `account_sid`,
whose git head, git tree and bootstrap SHA-256 **equal the values the certify
process observes live**, with every declared-unelevated row at `PASS`, every
`ELV-*` row still `BLOCKED_ELEVATION_REQUIRED` (**the file claims no elevated
result**), and every unelevated-context flip flipped; `ELV-01..07` **executed
live** in this process and are all `PASS` with zero `BLOCKED/INCONCLUSIVE/FAIL`,
their flips executed live and flipped; and the unelevated record plus the live
`ELV` results **partition every scenario exactly once**. **No flag and no file
substitutes for the elevated token** — the `ELV-*` bodies run only when the
harness finds `BUILTIN\Administrators` in its own process token, and running
`--certify` unelevated **REFUSEs immediately** at the live-token gate.
`--certify` requires a whole-table run and is rejected with `--only`.

> **Threat-model honesty.** This is **not** cryptographic proof against a
> malicious local operator who controls the machine and its files. The guarantee
> is only that the certify command *itself* observes a **live** elevated token and
> runs the elevated evidence **live**, rather than trusting a file's claim of
> elevation. The unelevated record binds to *an* untrusted principal; a forger who
> substitutes a *different* valid untrusted SID is indistinguishable, and nothing
> here defends against an operator who edits the harness or the records at will.

An optional archive record (`record-elevated.json`) is emitted for audit, but the
certify path **never reads it back** as a certification input. A runnable
fail-closed adversarial battery — hand-edited fake elevated record, relabelled
record, `elevated:true`, fabricated `account_sid`, unelevated certify, stale
head/tree/SHA, dirty worktree, filtered/forged row, forged flip, and the
operator-only live PASS path — is available with `--certify-selftest` and folds
every case into its exit code.

Expected results from the **live elevated run**:

| Row | Property | Expected |
| --- | --- | --- |
| `ELV-01` | a clean bundle installs; the harness reads the created root's owner, DACL and every installed byte back for itself | `OK` (0) |
| `ELV-02` | a pre-created root is refused, not adopted | `ROOT_EXISTS` (40) |
| `ELV-03` | a junction occupying the root name is refused, not written through | `ROOT_REPARSE` (42) |
| `ELV-04` | an unsafe **inherited** ACL on the created root is refused before copying | `ROOT_UNSAFE_WRITABLE_ACE` (46) |
| `ELV-05` | a file planted in the root during the copy is caught by the destination re-hash | `DESTINATION_MISMATCH` (51) |
| `ELV-06` | the root replaced after the copy by a **byte-identical** twin is caught by object identity | `ROOT_IDENTITY_CHANGED` (52) |
| `ELV-07` | a subdirectory name occupied mid-copy is refused, not written through | `COPY_DIRECTORY_OCCUPIED` (53) |

`ELV-05`, `ELV-06` and `ELV-07` act inside a window during the bootstrap's run,
and a harness that misses its window must not blame the bootstrap for it.

`ELV-06` is the hard one: it swaps a byte-identical twin onto the root's name
between the bootstrap capturing the root's identity and re-reading it. Miss that
window **early** — in the gap between the two renames a directory swap needs — and
a member opened there refuses as `DESTINATION_UNREADABLE`. Miss it **late** and the
bootstrap has already re-read the identity and exits `OK`. The harness **cannot
see** the instant of that re-read: it is an in-process comparison with no
filesystem effect. So it may not claim the bootstrap accepted a swap it had the
chance to catch, and **every exit-0 outcome here is reported `INCONCLUSIVE`** —
"the harness could not win this race" — never `FAIL-NO-REFUSAL`. An earlier
revision did print `FAIL-NO-REFUSAL`, whose stated meaning is "accepted what it
should have refused"; measured over five runs it said that on three of them, about
a bootstrap that had done nothing wrong.

The row retries from a clean fixture up to **5 times**. If all five miss, it stays
`INCONCLUSIVE`, which **fails the gate** — the operator is told the experiment
could not be run, not that the bootstrap is broken. `ELV-06` can therefore prove
the property (exit 52) but can never accuse on an exit 0; that asymmetry is
deliberate. `ELV-05` and `ELV-07` report `INCONCLUSIVE` if their plant never lands
in the copy window.

Missing the window is now rare rather than normal, because the row's bundle is
*shaped* for it instead of relying on luck: one large member the manifest orders
first, so the destination re-hash spends hundreds of milliseconds inside a single
read, and several small members at the end so the harness knows precisely when the
copy finished. The interval the two renames must fit inside went from about a
millisecond to a few hundred. Measured after the fix: **10 of 10 observations
`PASS`** (one needed a second attempt), **0 `FAIL-NO-REFUSAL`**, **0
`INCONCLUSIVE`**. Before it: 5 observations gave `PASS, FAIL-NO-REFUSAL, PASS,
FAIL-NO-REFUSAL, FAIL-NO-REFUSAL`.

There is also `--elv-selftest`, which runs the seven bodies unelevated against a
bootstrap **deliberately weakened to trust the current account**. That exists so
whoever edits the harness can execute the scenario code; it is printed under its
own banner, it never reaches the verdict, and **it is not evidence about the
production bootstrap.**

### Object identity

The bootstrap records a node's identity as `volumeSerial:fileIndex`, read out of
`BY_HANDLE_FILE_INFORMATION` at explicit offsets. The harness reads the same
structure through its own `ctypes` declaration — two implementations of one
concept, and until this revision no row compared them. It mattered: the bootstrap
read `nNumberOfLinks` and `nFileIndexHigh` (offsets 40 and 44) instead of
`nFileIndexHigh` and `nFileIndexLow` (44 and 48), discarding the only per-file
unique field in the common case. Over 128 concurrently-existing directories the
correct identity separates all **128**, while the old offsets separate strictly
fewer. How far the old formula collapses depends on the volume and on how its MFT
records happen to be laid out, so **no fixed count is quoted here** — the guard
measures it at runtime and prints what it observed on the machine in front of you.
What does not vary is the direction.

`IDN-01` compares the offsets in the pinned bytes against the harness's structure
and fails on any disagreement. `IDN-02` measures the collapse above on live
objects and **prints what it measured on the machine in front of you**, rather
than asking you to trust a figure from somewhere else. `IDN-03` is the
negative-control pair: a rename-swap must change the
identity, and delete-and-recreate under the same name did change it on all 200
trials — an observation about that volume, **not** a guarantee that NTFS never
reuses a record number and sequence pair. `ELV-06` is the behavioural version and
needs elevation.

### Coverage: every refusal reason, executed or disclosed

The taxonomy has 46 outcomes. **23 are executed by named scenarios** — seven of
those only when the harness runs elevated — and **23 are `UNTESTED` and say why**.
There is no categorical coverage claim anywhere in this document, because the
previous revision made one — "an unelevated run proves every refusal path" — and
it was false: 10 outcomes were exercised and 36 were neither tested nor disclosed.

This table is **generated** by `python scripts\offline_bootstrap_guard.py
--coverage-table`, and `CTL-COVERAGE` fails the gate if what is pasted here is not
byte-identical to what the code generates, so it cannot drift. `CTL-COVERAGE` also
checks the harness's copy of the taxonomy against the taxonomy in the pinned
bootstrap bytes.

The `ELV-*` rows execute their outcome **only when the harness runs elevated**.
`CTL-PROGFILES` is declared **unelevated**: it runs only under the unelevated
token, where it reaches `ROOT_CREATE_FAILED` (the OS-derived ProgramFiles chain
is accepted all the way to the privilege-gated create). Outcome `OK` is reached
only by `ELV-01` executed live; a single-context run never demonstrates it, and
the live-elevated certification draws it from the live `ELV` run. Each run prints this same
table with the verdict each scenario actually got, so a claimed outcome whose
scenario was blocked reads as blocked.

<!-- COVERAGE-TABLE:BEGIN -->
| Code | Reason | Exercised by | If UNTESTED, why not |
| --- | --- | --- | --- |
| 0 | `OK` | CTL-PROGFILES, ELV-01 | - |
| 10 | `ARGS_INVALID` | SCN-21 | - |
| 11 | `UNEXPECTED_ERROR` | UNTESTED | the catch-all for a fault the bootstrap does not model; reaching it means the bootstrap has a bug, so there is no fixture for it by construction |
| 12 | `NATIVE_INIT_FAILED` | UNTESTED | requires the CLR to refuse System.Reflection.Emit; no fixture can produce that without modifying the pinned file |
| 19 | `SOURCE_NOT_ANCHORED` | UNTESTED | requires the source to canonicalise to something that is not a local volume-GUID path, i.e. an SMB/UNC path; publishing a share needs elevation and the harness will not fake one |
| 20 | `SOURCE_MISSING` | SCN-22 | - |
| 21 | `SOURCE_REPARSE` | SCN-16, SCN-23 | - |
| 22 | `SOURCE_GIT_PATH` | SCN-17 | - |
| 23 | `SOURCE_COLLISION` | SCN-15 | - |
| 24 | `SOURCE_NAME_UNSAFE` | SCN-11, SCN-12, SCN-13, SCN-14 | - |
| 25 | `BUNDLE_PIN_MISMATCH` | SCN-09 | - |
| 26 | `SOURCE_UNREADABLE` | SCN-24 | - |
| 27 | `SOURCE_EMPTY_DIRECTORY` | SCN-18 | - |
| 28 | `MANIFEST_UNSORTED` | UNTESTED | an internal invariant, unreachable while the sort works; the SCN-10 deletion experiment reaches it by removing the sort |
| 29 | `SOURCE_CANONICAL_UNRESOLVED` | UNTESTED | requires GetFinalPathNameByHandle to FAIL on a directory that opened successfully; no unelevated fixture for that was found |
| 30 | `PARENT_MISSING` | SCN-25 | - |
| 31 | `PARENT_REPARSE` | SCN-07 | - |
| 32 | `PARENT_DACL_ABSENT` | SCN-26 | - |
| 33 | `PARENT_ACE_UNINTERPRETABLE` | SCN-27 | - |
| 34 | `PARENT_OWNER_UNTRUSTED` | CTL-OWNER, SCN-01, SCN-02, SCN-10, SCN-19 | - |
| 35 | `PARENT_UNSAFE_WRITABLE_ACE` | SCN-03, SCN-04, SCN-05, SCN-06, SCN-20 | - |
| 36 | `PARENT_NOT_ANCHORED` | UNTESTED | requires a canonical component carrying a trailing dot, trailing space or control character.  Measured on this platform: NTFS rejects control characters outright and GetFinalPathNameByHandle strips a trailing space from the name it returns, so no such component reaches the check |
| 37 | `PARENT_CANONICAL_UNRESOLVED` | UNTESTED | same as SOURCE_CANONICAL_UNRESOLVED |
| 38 | `PARENT_CHAIN_UNSTABLE` | UNTESTED | requires an ancestor to be replaced BETWEEN the leaf's resolution and the walk; the window is a few microseconds and the harness has no way to schedule inside it deterministically |
| 40 | `ROOT_EXISTS` | ELV-02 | - |
| 41 | `ROOT_CREATE_FAILED` | CTL-PROGFILES | - |
| 42 | `ROOT_REPARSE` | ELV-03 | - |
| 43 | `ROOT_DACL_ABSENT` | UNTESTED | the root inherits the parent's DACL, and a parent with a NULL DACL is refused at PARENT_DACL_ABSENT first (SCN-26), so the root branch is unreachable from outside |
| 44 | `ROOT_ACE_UNINTERPRETABLE` | UNTESTED | same shape: the parent carrying the undecodable ACE is refused at PARENT_ACE_UNINTERPRETABLE first (SCN-27) |
| 45 | `ROOT_OWNER_UNTRUSTED` | UNTESTED | the created root's owner comes from the creating token's default owner; making it untrusted while the parent stays trusted needs a token this harness will not fabricate |
| 46 | `ROOT_UNSAFE_WRITABLE_ACE` | ELV-04 | - |
| 47 | `ROOT_MISSING` | UNTESTED | requires the root to disappear between its creation and its verification - a race with no deterministic fixture |
| 48 | `ROOT_NOT_ANCHORED` | UNTESTED | same as PARENT_NOT_ANCHORED |
| 49 | `ROOT_CANONICAL_UNRESOLVED` | UNTESTED | same as SOURCE_CANONICAL_UNRESOLVED |
| 50 | `COPY_FAILED` | UNTESTED | requires a source or destination open to fail mid-copy for a reason other than an occupied name; ELV-07 covers the occupied-name branch beside it |
| 51 | `DESTINATION_MISMATCH` | ELV-05 | - |
| 52 | `ROOT_IDENTITY_CHANGED` | ELV-06 | - |
| 53 | `COPY_DIRECTORY_OCCUPIED` | ELV-07 | - |
| 54 | `ROOT_CHAIN_UNSTABLE` | UNTESTED | requires the created root's canonical name to differ from the path it was created at - a race with no deterministic fixture |
| 60 | `DESTINATION_MISSING` | UNTESTED | the destination family is reached only when the INSTALLED tree is hostile at re-hash time; this one needs the root to vanish inside that window |
| 61 | `DESTINATION_REPARSE` | UNTESTED | needs a reparse point planted inside the root between the copy and the re-hash; ELV-05 plants a plain file in that window, ELV-07 plants a junction in the copy window, and neither lands in this one |
| 62 | `DESTINATION_GIT_PATH` | UNTESTED | needs a '.git' component to appear inside the root between the copy and the re-hash |
| 63 | `DESTINATION_COLLISION` | UNTESTED | needs two members differing only in ASCII case to appear inside the root between the copy and the re-hash, on a case-sensitive directory |
| 64 | `DESTINATION_NAME_UNSAFE` | UNTESTED | needs a member with a name outside the portable alphabet to appear inside the root between the copy and the re-hash |
| 66 | `DESTINATION_UNREADABLE` | UNTESTED | needs a member inside the root to become unreadable between the copy and the re-hash |
| 67 | `DESTINATION_EMPTY_DIRECTORY` | UNTESTED | needs an empty directory to appear inside the root between the copy and the re-hash |
<!-- COVERAGE-TABLE:END -->
