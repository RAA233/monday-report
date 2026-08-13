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
```

It treats the bootstrap as an opaque binary: it hashes the file, refuses to launch
anything whose hash does not match, and forms every verdict from the exit code
plus observations it makes itself through Win32 — file sets, digests it computes,
owner/DACL via `GetNamedSecurityInfoW`, reparse state, object identity, DOS-device
mappings via `QueryDosDeviceW`, and the live process table via
`CreateToolhelp32Snapshot`. **The bootstrap's stdout is recorded and is never an
input to any assertion.**

### Unelevated runs are honest about what they cannot show

With `-TrustedSid` gone, an unelevated process **cannot** build a fixture the
production trust set accepts: its filtered token has `BUILTIN\Administrators` as
deny-only, so every directory it creates is owned by itself. Faking a principal to
get around that is precisely the defect this revision removed.

So an unelevated run proves every refusal path, the whole name and pin policy, the
process-and-temp observation and the DOS-device chain bypass — and reports the
seven properties that need the bootstrap to **accept** a chain and **install** as
`NOT-RUN — ELEVATION REQUIRED`, with the command to complete them. Those rows are
not quietly turned green.

To complete them:

```powershell
# In an ELEVATED PowerShell (Run as administrator):
cd <repo>
python scripts\offline_bootstrap_guard.py --delete-mechanism
```

The harness detects the elevated token itself (`CheckTokenMembership` against
`S-1-5-32-544`); it does not take anybody's word for it. Elevated, the fixtures it
creates are owned by `BUILTIN\Administrators`, which is in the production trust
set — so no principal has to be invented for them to pass.
