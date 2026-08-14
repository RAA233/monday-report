# Release Policy — Monday Report Offline Edition

This is an **Offline** product: it is packaged and handed to a customer, not
deployed to servers we operate. There is intentionally **no CD / deploy-to-
servers** stage. This policy governs how a customer package may be produced.

## Hard gate

> **No Offline customer package may be built or released except from a source
> commit on which CI (`.github/workflows/ci.yml`) is GREEN.**

CI runs on every `pull_request` and every `push` to `main`, keyed to the exact
commit. "Green on the exact source head" is a precondition for entering the
package chain below — it is not optional and is not waivable per-release.

## Release chain (in order)

1. **CI GREEN on the exact source head.** All three CI jobs pass on the precise
   commit that will be built:
   - **Fast / hermetic** — frozen `pnpm install` + `pnpm run build` (`tsc`
     typecheck + `vite build`).
   - **Strict audit (disposable pgvector Postgres + live stack)** — the full
     `pnpm run audit:all` (73 steps) against a disposable pgvector Postgres and a
     live isolated app stack, then the honest expected-baseline gate (see below),
     plus the standalone DB-strict coverage (migration runner + the
     restricted-postgres-runtime matrix).
   - **Windows deterministic** — Python byte-compile of `scripts/` + `backend/`,
     a parse-only tokenize of the offline bootstrap PowerShell, and the offline
     bootstrap guard's deterministic certify self-test.
2. **Package build** — build the Offline package from that same green commit.
3. **Same-byte E1** — first evidence context reproduces the package
   byte-for-byte from the same source commit.
4. **Same-byte E2** — second, independent evidence context reproduces the same
   bytes.
5. **Final seal / signing** — seal and sign the reproduced artifact.
6. **Release approval** — human approval to hand the sealed package to the
   customer.

Each step's input is the *identical source commit* proven green in step 1. A
package built from an un-green or drifted commit must not proceed.

## The honest GA_BLOCKED baseline (why CI is green while the product is GA_BLOCKED)

`pnpm run audit:all` currently exits **non-zero** by design: the inherited GA
gap-assessment check **`GA50 commit-binding-is-ancestor`** fails because the
tracked acceptance artifact is not an ancestor of the exact head, so the suite's
`release_recommendation` is **`GA_BLOCKED`**.

CI does **not** mask this. The strict-audit job asserts, via
`.github/scripts/assert_audit_baseline.py`, that this is the **only** deviation:

- the run reached the terminal `audit:ga-gap-assessment` verdict (so every
  earlier step, including the DB-strict guards, passed),
- `summary.failed == 1` and the single failing check is exactly
  `GA50 commit-binding-is-ancestor`,
- `release_recommendation == GA_BLOCKED`,
- and `audit:all` exited non-zero.

Any other outcome — a different or additional failure, an earlier-step failure,
unparseable output, **or `audit:all` exiting 0** — turns the job RED. A green
`audit:all` (GA50 resolved) is treated as a deliberate, reviewable event: the
baseline assertion must then be updated on purpose, never silently.

Consequence for releases: **CI green here means "no regression beyond the known
GA_BLOCKED baseline", not "generally available".** The product remaining
`GA_BLOCKED` is an orthogonal, honest fact tracked by the GA gap-assessment; it
does not by itself authorize a GA release. This policy governs the *Offline
package* chain.

## Not CI evidence: live-elevated offline certification

The offline package's **live-elevated certification** (the real elevated
`ELV-01..07` run, requiring Admin / Hyper-V on a trusted operator machine) is an
**operator gate**. CI runs only the *deterministic* offline self-test
(`offline_bootstrap_guard.py --certify-selftest`, an adversarial battery that
runs unelevated). CI never claims Admin, Hyper-V, or E1/E2 elevated evidence.
The operator's live-elevated certification remains a required, separate,
human-run step and is out of scope for this automated CI.
