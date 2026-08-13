# Offline bootstrap (Phase 1) — operator instructions

`Invoke-OfflineBootstrap.ps1` creates a fresh, admin-only trust root and installs
one pinned release bundle into it. It runs **before any source in this repository
is trusted**, so it imports nothing from the repository, dot-sources nothing,
launches no child process and no native executable, resolves no executable by
name, and never consults `%PATH%` or `%SystemRoot%`. It is PowerShell language,
.NET, and the P/Invoke declarations compiled by its single `Add-Type` call.

## Read this first: the bootstrap does not verify itself

**A modified copy of this script can print anything it likes, including a clean
bill of health for itself.** It has no self-hash mode and no self-authorization
mode, deliberately: a check a file performs on itself is worth exactly as much as
the file, and three previous attempts at this problem failed because a
verification layer certified itself.

**You verify its SHA-256 out of band, against a value you obtained from somewhere
other than this working tree, before you run it.** Nothing the script writes to
stdout is evidence of anything. The only thing you can rely on is its **exit
code** and what you can see on the filesystem yourself.

```powershell
Get-FileHash -Algorithm SHA256 .\packaging\offline\Invoke-OfflineBootstrap.ps1
```

The repository pins `*.ps1` to LF in `.gitattributes` so this hash is the same on
every platform and for any value of `core.autocrlf`. If you edit the file, the
hash changes and your pin is void — that is the point.

One disclosure so you are not surprised: under Windows PowerShell 5.1,
`Add-Type -TypeDefinition` compiles the declaration fragment through the .NET
Framework C# compiler, which is a process the CLR starts. The compiler is
resolved by the runtime, never from `%PATH%`. That single call is the only thing
in the script that is not pure PowerShell and .NET, and it is there because .NET
exposes no atomic create-or-refuse directory primitive: `CreateDirectoryW` plus
`ERROR_ALREADY_EXISTS` is the only way to create a root without first asking
"does it exist?", a question whose answer is stale the instant it is given.

## Operator inputs

| Input | Meaning |
| --- | --- |
| `-RootName` | Leaf name of the new trust root. One path component. Refused if it is already occupied by anything, including a junction. |
| `-SourcePath` | Directory holding the release bundle. Read only; never modified. |
| `-ExpectedBundleHash` | **Your** independently held release-bundle root hash, 64 hex characters. Never read from the source tree — if you take this value from the tree you are pinning the tree to itself. |
| `-ParentPath` | Optional. Defaults to `[Environment]::GetFolderPath('ProgramFiles')` — an OS API, never an environment string. Supplying it relaxes nothing: the same code judges the chain either way. |
| `-TrustedSid` | Optional, semicolon-delimited. **Widens the trust set.** Production invocations do not pass it. See below. |

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\packaging\offline\Invoke-OfflineBootstrap.ps1 `
  -RootName  'MondayReportOffline' `
  -SourcePath 'D:\release\bundle' `
  -ExpectedBundleHash '<64 hex characters you hold independently>'
```

Run it **elevated**: the default parent is admin-only-writable, which is the
whole point, so an unelevated run cannot create the root there and will refuse
with `ROOT_CREATE_FAILED`.

### What `-TrustedSid` does, and why it is dangerous

By default the trusted principals are `NT AUTHORITY\SYSTEM`,
`BUILTIN\Administrators` and `TrustedInstaller`. Every other principal holding a
right that could redirect, replace, or rewrite a node in the chain is a refusal.
`-TrustedSid` adds principals to that set — so it can make an unsafe root look
safe. Pass it only when the root legitimately belongs to a service principal that
is not one of the three built-ins, and only when you can say why.

Well-known open groups (Everyone, Authenticated Users, `BUILTIN\Users`,
INTERACTIVE, Guests, Anonymous, …) are refused outright, so the parameter cannot
be used to bless a world-writable root.

## What it does, in order

1. Validate arguments.
2. Enumerate the bundle as raw bytes — never asking git anything — and compute
   the root hash. Compare it to your pin. **A mismatch here leaves no root
   behind at all**, because nothing has been created yet.
3. Judge every path component from the volume root down to the parent: owner,
   DACL including *inherited* unsafe-writable ACEs, and reparse state. A parent
   anyone can rename defeats a leaf nobody can write, so the refusal names the
   whole path and the failing component, never just the leaf.
4. Create the root atomically. An occupied name is refused, never adopted.
5. Judge the created root the same way. Its DACL is the one it *inherited*; the
   script does not mint a friendlier DACL for it, because that would be the
   bootstrap writing down the answer it wanted.
6. Copy member by member. Every destination directory is created with
   create-or-refuse semantics, so a junction dropped into the root mid-copy is
   refused rather than written through.
7. Re-hash the installed tree from scratch and require exact equality with the
   source manifest — member set, relative paths, digests and sizes — and with
   your pin.
8. Re-check that the root is still the same filesystem object it verified.

### Refusals leave the root in place

A root that is created and then refused at steps 5–8 is **left on disk on
purpose**. Reclaiming or deleting a path that has just failed a trust check is
itself a write to a location you have just decided you do not trust. Remove it by
hand, after you have looked at it.

### What the pin covers

The pre-image is UTF-8 without BOM, LF line endings, NUL field separators:

```
offline-bootstrap-bundle/v1<LF>
members=<count><LF>
<relative path><NUL><sha256><NUL><size><LF>     once per member,
...                                             sorted by folded relative path,
                                                ordinal
```

The member count and every relative path are inside the pre-image, so adding,
removing or renaming a file changes the root hash even when no file's content
changes. There is no subset that could be pinned while a larger set is installed.
Members are sorted by their *folded* path — trailing dots and spaces trimmed per
component, then upper-cased — so the order depends only on the names, never on
the order the filesystem handed them out.

Bundles carrying any of the following are refused rather than pinned, because
their meaning depends on which API opens them, or because the pin could not see
them:

- anything named `.git` in any spelling, file or directory;
- any reparse point anywhere under the source root;
- two members whose folded paths collide (`sub/x` and `Sub /x` name one
  destination file);
- a component with a trailing dot or space, a reserved device name, or a
  character the filesystem forbids;
- an empty directory — it contributes no member, so the pin cannot see it.

The **source path's own ACLs are not judged**. The bundle's integrity comes from
your pin, not from where it happens to sit; the ACL judgement exists to protect
the *destination*.

## Refusal taxonomy

Every refusal has its own exit code, so you can tell *why* it refused without
reading, parsing, or believing its stdout.

| Code | Reason |
| --- | --- |
| 0 | `OK` |
| 10 | `ARGS_INVALID` |
| 11 | `UNEXPECTED_ERROR` |
| 20–27 | `SOURCE_MISSING`, `SOURCE_REPARSE`, `SOURCE_GIT_PATH`, `SOURCE_COLLISION`, `SOURCE_NAME_UNSAFE`, `BUNDLE_PIN_MISMATCH`, `SOURCE_UNREADABLE`, `SOURCE_EMPTY_DIRECTORY` |
| 28 | `MANIFEST_UNSORTED` |
| 30–36 | `PARENT_MISSING`, `PARENT_REPARSE`, `PARENT_DACL_ABSENT`, `PARENT_ACE_UNINTERPRETABLE`, `PARENT_OWNER_UNTRUSTED`, `PARENT_UNSAFE_WRITABLE_ACE`, `PARENT_NOT_ANCHORED` |
| 40–48 | `ROOT_EXISTS`, `ROOT_CREATE_FAILED`, `ROOT_REPARSE`, `ROOT_DACL_ABSENT`, `ROOT_ACE_UNINTERPRETABLE`, `ROOT_OWNER_UNTRUSTED`, `ROOT_UNSAFE_WRITABLE_ACE`, `ROOT_MISSING`, `ROOT_NOT_ANCHORED` |
| 50–53 | `COPY_FAILED`, `DESTINATION_MISMATCH`, `ROOT_IDENTITY_CHANGED`, `COPY_DIRECTORY_OCCUPIED` |
| 60–67 | `DESTINATION_MISSING`, `DESTINATION_REPARSE`, `DESTINATION_GIT_PATH`, `DESTINATION_COLLISION`, `DESTINATION_NAME_UNSAFE`, `DESTINATION_UNREADABLE`, `DESTINATION_EMPTY_DIRECTORY` |

## Verifying the bootstrap

`scripts/offline_bootstrap_guard.py` is a black-box harness. It records the
script's SHA-256, refuses to launch anything whose hash differs, launches that
exact file through an absolute `powershell.exe`, and forms every verdict from the
**exit code plus observations it makes itself** through `ctypes` — directory
listings, `hashlib` digests, owner/DACL via `GetNamedSecurityInfoW` and SDDL,
reparse state via `GetFileAttributesW`, object identity via
`GetFileInformationByHandle`. The bootstrap's stdout is recorded and never read
by an assertion.

```
pnpm run audit:offline:windows                                  # the gate
python scripts/offline_bootstrap_guard.py --delete-mechanism    # self-review
python scripts/offline_bootstrap_guard.py --only SCN-10 --keep  # one scenario
```

`audit:offline:windows` is a **separate** gate. It is deliberately not part of
`audit:all`, which must stay portable.

The harness runs unelevated, so it cannot build a fixture owned by
`BUILTIN\Administrators` and substitutes its own SID via `-TrustedSid`. Three
controls keep that honest: `CTL-OWNER` runs the same fixture without the
parameter and requires `PARENT_OWNER_UNTRUSTED`; `SCN-15` shows the parameter
cannot be handed Everyone; `CTL-PROGFILES` shows the real `ProgramFiles` parent
refuses an unelevated create.

`--delete-mechanism` disables each scenario's mechanism in a temporary copy and
requires the outcome to flip. It is self-review evidence, not the acceptance
oracle; the acceptance oracle is the scenario table.

## Not in scope for Phase 1

Hyper-V, licensing, package building, E1/E2, and the port of the older Offline
edition. This is the pre-trust root and the release-bundle pin, and nothing else.
