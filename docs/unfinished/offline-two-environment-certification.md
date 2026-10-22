# Two-environment offline acceptance

**State:** Environment 1 passed repeatedly (33/33 on the final attempt).
Environment 2 **never completed a full matrix**.
**Blocks:** `OFFLINE_WINDOWS_PACKAGE_ACCEPTED`, and therefore
`OFFLINE_COMMERCIAL_PACKAGE_ACCEPTED`.

## The requirement

Acceptance demands that **the same package bytes** pass a complete matrix in
**two genuinely independent clean Windows environments**, proving among other
things:

- fresh per-user install, no elevation needed after install
- unlicensed first launch; activation request export carries **no raw hardware
  identifiers**
- the host signs the licence **outside** the tested environment; only the signed
  licence returns (air-gapped issuance)
- localhost-only binding; no Internet, Node, Python, Docker, PostgreSQL, or
  Redis present or required
- real-time expiry → read-only, with data still readable and backup still available
- a licence issued for Environment 1 is **rejected** in Environment 2, and
  vice versa
- upgrade preserves data and licence; uninstall preserves data by default

The two-environment rule exists to catch anything that accidentally depends on
one machine's state. One environment proving everything is not the same claim.

## What was achieved

**Environment 1 (host, isolated install root): 33/33 passing**, via the genuine
air-gapped protocol — environment exports an activation request, the host signs
it in a separate process that is the sole key holder, only the signed licence
returns.

The air-gap boundary was made structural rather than procedural, and is covered
by 27 process-isolation checks plus a mutation cycle:

- the environment-side runner declares **no** key parameter at all
- key-shaped argv is refused **before** argument parsing, so a key option aborts
  as an explicit boundary violation rather than an ambiguous usage error
- key-shaped environment variables are refused
- key material smuggled into the transfer directory is refused
- the orchestrator scrubs key variables from the child environment

## Why it stopped

Entirely environmental. Two substrates were attempted; neither yielded a
complete second run.

### Attempt A — Windows Sandbox

Worked for the first one or two launches after a reboot, then stopped executing
its `LogonCommand` entirely: the VM booted and allocated memory, but the logon
session never ran, leaving the mapped output directory empty.

Two **genuine, reproducible** defects were found and fixed along the way, and
both are worth knowing because they are silent:

1. **Long mapped host paths break it.** A ~180-character `HostFolder` causes the
   logon session to never start. No error — it just boots and sits there. Keep
   mapped paths short (`C:\mr-sbx\...`).
2. **Mapping a large directory breaks it.** Mapping the expanded 1,437-file
   package directory reliably stalled the logon session. Mapping a **single
   installer archive** and expanding it inside the guest boots cleanly — and is
   a stronger check anyway, because the guest then hash-verifies the archive
   against the host value before expanding.

A third issue was self-inflicted and is a good cautionary tale: repeated
host-side **force-teardown** (`taskkill /F`) of sandbox processes appears to
degrade the Sandbox logon service until reboot. The corrected lifecycle is for
the **guest to shut itself down** after writing its result, with the host only
waiting for the VM to release.

> **Also worth knowing:** a later review of the committed in-sandbox session
> driver found two paths corrupted by escape-sequence handling when the file was
> generated — `"C:\tool\..."` became `C:<TAB>ool\...` and `"C:\out\03-..."`
> became `C:\out-...` (the `\t` and `\0` were interpreted). That is very likely
> a contributing cause of the repeated failures, which means **Sandbox may be
> more viable than the abandonment suggests.** Fix the paths before concluding
> Sandbox is unusable.

### Attempt B — Hyper-V clean VM

Never started. Every attempt was blocked at the elevation gate: the automation
process ran at Medium integrity with the Administrators group marked
**deny-only** (a UAC-filtered token), so `Get-VM`,
`Get-WindowsOptionalFeature`, and all VM creation were denied.

The root cause is worth recording precisely, because it wasted several
attempts: the process ancestry was
`powershell.exe ← claude.exe ← claude.exe ← explorer.exe`. The automation host
had been launched **from the Windows shell**, so launching a *separate* elevated
terminal did nothing — elevation is inherited at process creation from the
actual parent.

## Resuming

**Easiest viable path — Hyper-V, done properly:**

1. Launch the automation host **itself** elevated (right-click → Run as
   administrator), or start it *from* an already-elevated shell so it inherits
   the token. Verify before starting:
   ```powershell
   [Security.Principal.WindowsPrincipal]::new(
     [Security.Principal.WindowsIdentity]::GetCurrent()
   ).IsInRole('Administrators')   # must be True
   ```
2. Obtain official Windows 11 media. Microsoft publishes an Enterprise
   **Evaluation** image suitable for a temporary test VM — review and accept
   its terms yourself; automation must not accept licence terms on your behalf.
3. Create a Generation 2 VM, Secure Boot on, vTPM on, **no network adapter**,
   automatic checkpoints off. Short paths (`C:\mr-hv\...`).
4. Transfer the frozen package via `Copy-VMFile` / PowerShell Direct — **not**
   over a network. The signing key must never enter the guest.
5. Run the PowerShell environment runner (a Python runner cannot be used: the
   guest must prove Python is absent).
6. Combine both environment results and require: identical package hashes,
   distinct machine fingerprints, and cross-environment licence rejection in
   **both** directions.

**Or:** fix the escape-sequence path corruption noted above and retry Windows
Sandbox, one attempt per boot, with the short-path and single-archive
mitigations already in place.

## Design notes worth keeping

- **PowerShell is acceptable test tooling inside the guest.** It ships with
  Windows, so using it does not undermine the "no development runtimes" claim —
  the *packaged product* never invokes it.
- **Dependency absence must be measured against the application's PATH**, not
  the test runner's. Environment 1 is a developer host that legitimately has
  Node, Python, and Docker installed; the load-bearing claim is that the
  packaged app cannot *resolve* them. Measuring the runner's own PATH conflates
  "installed on the box" with "required by the product".
- **An Ed25519 public key is also 32 bytes**, so a "bare 64-hex blob = private
  key" heuristic flags the one artifact that is *supposed* to ship. Exclude the
  expected public key by value.
- **Expiry tests must derive their wait from the licence's own timestamps.** A
  packaged cold start takes tens of seconds and varies by machine, so a fixed
  sleep either expires the licence before the app is up or stops short of
  expiry. And the expiry instance must reuse the *requesting* installation
  identity — a fresh data root mints a new installation id and is correctly
  refused as `WRONG_INSTALLATION`.
