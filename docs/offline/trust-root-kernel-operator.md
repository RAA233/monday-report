# Trust-Root Kernel (Phase 1) — operator procedure

Scope: establishing the offline trust boundary's root of trust. Nothing else.
Provisioning, licensing, packaging and the offline application itself are **not**
covered here and are not implemented by this kernel.

Every operator-facing claim below carries a witness id. The acceptance suite
(`pnpm run audit:trust-root-kernel`) fails if a claim names a witness that did
not pass, so no statement in this document can outlive the mechanism it
describes.

---

## 1. Choose the trust root location

The kernel verifies **every** path component from the volume root down to the
trust root — owner, protected DACL, unsafe writable ACEs including inherited
ones, and reparse status.

- A refusal names the offending component and the full path, so a failure one
  level up is never reported as a leaf-level failure. <!-- witness: TRK-P1-02 -->
- `C:\Program Files` passes component verification on a stock Windows install. <!-- witness: TRK-P1-13 -->
- The user profile does **not** pass: it grants a non-administrative principal
  modify-class rights, so it is rejected as a trust-root parent. <!-- witness: TRK-P1-12 -->

Pick a parent that passes. Do **not** place the trust root directly under `C:\`:
on a stock install `C:\` grants Authenticated Users `(AD)` — permission to create
subdirectories — and propagates delete and generic-write to new children by
inheritance. The kernel breaks inheritance on the root it creates and re-verifies
the result, but the parent choice is still yours.

## 2. Create the root — the kernel refuses to adopt

Run the kernel's `New-TrustRoot`. It attempts creation first, atomically; it
never asks whether the path exists and then creates it.

- A pre-created directory at the target name is refused, not adopted. <!-- witness: TRK-P1-08 -->
- A pre-created **junction** at the target name is refused, not adopted. <!-- witness: TRK-P1-09 -->
- A reparse point anywhere on the chain — including an attacker-planted parent
  above a pristine leaf — is refused. <!-- witness: TRK-P1-05, TRK-P1-10 -->
- A writable intermediate parent is refused before the root is created. <!-- witness: TRK-P1-11 -->
- A NULL DACL on any component is refused. Windows reports such an object as
  "protected, zero access rules"; the kernel reads the descriptor bytes and sees
  it for what it is. <!-- witness: TRK-P1-03 -->
- An ACE the kernel cannot interpret exactly — a callback ACE, an object ACE, an
  unknown type — is refused rather than approximated. <!-- witness: TRK-P1-04 -->
- A component owned by a principal outside the trusted set is refused, however
  clean its DACL looks. <!-- witness: TRK-P1-17 -->
- Rights granted as generic bits (`GENERIC_WRITE`, `GENERIC_ALL`) are folded to
  their file-specific meanings before being judged, so write access spelled
  generically is not missed. <!-- witness: TRK-P1-18 -->
- Write access to the trust root's contents is refused on the root itself, while
  the same ACE on an ancestor — where it confers no power to replace or redirect
  that ancestor — is accepted. The distinction is a decision, not an accident. <!-- witness: TRK-P1-19, TRK-P1-20 -->

If creation succeeds, the kernel returns the root's file identity. Keep it.

## 3. Supply ONE out-of-band pin for the complete executed bundle

You supply a single SHA-256 pin covering the whole bundle. There is no per-file
hash list to keep in step with what actually runs.

- Membership is inside the pin: adding a file changes it. <!-- witness: TRK-P2-03 -->
- Removing a file changes it. <!-- witness: TRK-P2-04 -->
- Changing any member's contents changes it. <!-- witness: TRK-P2-02 -->
- Anything the engine actually loaded that is not a bundle member is refused,
  so the set that is hashed cannot be smaller than the set that runs. <!-- witness: TRK-P2-05 -->
- The implementation that computes the pin is itself a pinned member. <!-- witness: TRK-P2-07 -->
- Re-verifying after the pin check catches a member rewritten in between. <!-- witness: TRK-P2-06 -->
- Renaming a member with identical contents changes the pin: names are pinned,
  not just bytes. <!-- witness: TRK-P2-09 -->
- Two members whose paths differ only in case are refused as ambiguous. <!-- witness: TRK-P2-08 -->
- A reparse point inside the bundle is refused: part of what is pinned would
  live elsewhere, under someone else's control, redirectable after the pin. <!-- witness: TRK-P2-10 -->

Transfer the pin by a channel that is not the bundle.

## 4. Confirm the root has not been swapped

Between verification and use, re-check the recorded identity. A path that now
resolves to a different object — for example because the directory was replaced
with a junction — is refused. <!-- witness: TRK-P1-14 -->

## 5. Privileged natives

The kernel resolves privileged natives only from the OS-derived System directory
and records every native launch that actually happens.

- The System directory comes from the shell folder API, not `%PATH%` and not
  `%SystemRoot%`; poisoning those does not move it. <!-- witness: TRK-P5-02 -->
- A bare native name resolved from a poisoned `%PATH%` is observed and refused. <!-- witness: TRK-P5-04 -->
- An invocation through a variable (`& $path`) is observed and refused. <!-- witness: TRK-P5-05 -->
- A path that merely shares a prefix with the System directory is refused. <!-- witness: TRK-P5-08 -->
- A differently-cased spelling of the same real file is accepted, so the
  allowlist does not generate false refusals. <!-- witness: TRK-P5-09 -->
- Every native's exit code is checked; a non-zero exit is a refusal. <!-- witness: TRK-P5-06 -->
- A clean run's process creations are fully accounted for by instrumented
  launches, so an un-instrumented launch shows up as a discrepancy. <!-- witness: TRK-P5-03 -->

## 6. Operator identity

Principals are named by SID. `%USERNAME%` is never an authorization operand: it
is an ordinary environment variable.

- The caller's SID is read from the process token, so setting `%USERNAME%` to the
  expected operator's name does not satisfy the check. <!-- witness: TRK-P5-11 -->
- The kernel's own principal resolution agrees with the token. <!-- witness: TRK-P5-10 -->

## 7. Manifests

Manifests are canonicalised identically by both twins before any value is read.

- Duplicate keys are refused. <!-- witness: TRK-P4-02 -->
- Keys differing only in case are refused. <!-- witness: TRK-P4-03 -->
- Values the two runtimes would not carry identically — non-finite numbers,
  integers outside int64, a UTF-8 BOM — are refused. <!-- witness: TRK-P4-04, TRK-P4-05, TRK-P4-07 -->
- The PowerShell and Python twins return the same verdict and the same reason on
  every hostile fixture. <!-- witness: TRK-P4-DIFF-P4_MANIFEST_CASE_COLLISION -->
- The differential fixtures are genuine traps: the two runtimes' stock JSON
  parsers disagree on them, and it is the kernel's canonicaliser that makes the
  twins agree. <!-- witness: TRK-P4-DIFF-GUARD -->

---

## What this kernel does not do

No Hyper-V provisioning, no VM lifecycle, no licensing or entitlement, no package
matrix, no E1/E2 environment handshake, no commercial evidence generation, and no
port of the offline application. Those remain out of scope for Phase 1 and are
not implied by any witness above.

## Running the acceptance suite

```
pnpm run audit:trust-root-kernel
python scripts/trust_root_kernel_guard.py --mutation-audit
```

The first runs every control. The second additionally removes each mechanism
from a temporary copy of the kernel and requires the controls that cover it to
flip; a mechanism whose removal leaves its control passing is reported as a
failure. Both require Windows and PowerShell 5.1; neither requires Docker, a VM,
or administrative rights.
