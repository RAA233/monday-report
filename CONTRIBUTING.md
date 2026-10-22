# Contributing to Monday Report

Thanks for your interest. This document covers what you need to know before
your first pull request — including a few things about this codebase that
will surprise you if nobody warns you first.

---

## 1. Before you write code: sign the CLA

All contributions require agreement to the [Contributor Licence
Agreement](CLA.md). It lets us keep the project AGPL-3.0 **and** sell
commercial licences, which is how the work gets funded.

To agree, add this line to your pull-request description (one time, with your
real name):

```
I have read and agree to the Contributor Licence Agreement (CLA.md).
Signed-off-by: Your Name <your.email@example.com>
```

Also sign off your commits (`git commit -s`). A PR without CLA agreement
cannot be merged, no matter how good the patch is.

## 2. Licensing rules for new code

The project is **AGPL-3.0-or-later**. Two hard rules:

- **Do not add dependencies whose licence is incompatible with AGPL-3.0.**
  Permissive (MIT / BSD / Apache-2.0 / ISC) is fine. Proprietary is not.
  If you add a dependency, add it to the third-party section of `NOTICE`.
- **New source files should carry an SPDX header.** Existing files predate
  this convention and are covered by `LICENSE` + `NOTICE`; please don't
  bulk-add headers in unrelated PRs.

  ```python
  # SPDX-License-Identifier: AGPL-3.0-or-later
  # Copyright (C) 2026 Rashed Albalawi and Emeil Nassrallah
  ```

> **Note on PyMuPDF.** The PDF backend (`PyMuPDF`) is itself AGPL-3.0-or-commercial,
> which is a material reason this project is AGPL. Swapping it for `pypdf` or
> `pdfplumber` is a welcome contribution and a prerequisite for any future
> permissive relicensing — see [docs/ROADMAP.md](docs/ROADMAP.md).

## 3. Environment setup

**Requirements**

| Tool | Version | Why it matters |
|---|---|---|
| Node.js | 22.x | CI pins 22.17.1 |
| **pnpm** | **10+** | **Required.** `pnpm-workspace.yaml` uses pnpm-10 `allowBuilds` / `onlyBuiltDependencies` keys with no `packages:` field. **pnpm 9 rejects it outright.** |
| Python | 3.12 | CI pins 3.12; 3.10+ generally works |

```bash
corepack enable
pnpm install --frozen-lockfile
python -m pip install -r backend/requirements.txt
```

**Run it** (two terminals — no database, no Docker, no Redis needed):

```bash
pnpm run dev:api     # FastAPI on 127.0.0.1:8000
pnpm run dev         # Vite on 127.0.0.1:5173
```

The backend defaults to a durable local JSON store under `.local_data/`
(git-ignored). PostgreSQL and Redis are optional and only activate in
approved client mode.

**On Windows**, set `$env:CI='true'` before build commands in non-interactive
automation. `.gitattributes` pins `eol=lf` on all text — do not change this;
migration checksums and evidence hashes are computed over raw bytes, so CRLF
smudging breaks migrations and makes evidence unreproducible.

## 4. Things that will surprise you

Read this section. It is the difference between a productive first day and a
confusing one.

### There is no unit-test framework

No pytest, no vitest, no jest, no test files. **The `scripts/` directory *is*
the test suite**: 117 of its 160 files are `*_guard.py` effect-level black-box
checkers with named check ids.

13 guards have a paired `*_faults_guard.py` **fault battery** that seeds a
deliberate defect and requires the guard to refuse — mutation testing of the
oracle itself. If you change a guard that has one, run its faults twin; if it
does not have one, writing it is a welcome contribution.

```bash
pnpm run audit:route-rbac          # one guard
pnpm run audit:all                 # the 77-step chain (needs a live stack + Postgres)
```

### `audit:all` exits non-zero *on purpose*

The expected result is **exactly one failure**: `GA50 commit-binding-is-ancestor`.
CI asserts this precisely and **goes red if `audit:all` ever turns green**,
because a silently-resolved GA gate must be a deliberate, reviewed event.
See [STATUS.md](STATUS.md).

So: `audit:all` failing with that one failure means *healthy*. Any other
failure is a real regression.

### `backend/app/store.py` is 8,591 lines

It is ~45% of all backend code and holds the snapshot store, every parser
(ZIP/CSV/XLSX/DOCX/EML/PDF), export rendering, and the HMAC audit chain.
This is the single largest piece of technical debt in the project and
decomposing it is a tracked roadmap item. Expect to spend time orienting.
Prefer adding new modules over growing this file.

### There are no `TODO` comments

Deliberately. Incomplete work is tracked as 28 machine-checked entries in
`evals/ga/blocker_registry.v1.json`, not as code comments. If you find
something unfinished, it is probably a registry entry — check there first,
and see [docs/ROADMAP.md](docs/ROADMAP.md).

## 5. Before you open a pull request

```bash
pnpm run build                 # tsc && vite build — must pass
pnpm run audit:<relevant>      # the guard(s) covering your change
pnpm run test:ui-redesign      # if you touched the frontend (needs a live stack)
```

Then:

- **Keep commits conventional**: `feat:`, `fix:`, `test:`, `docs:`, `chore:`,
  `refactor:`. Breaking changes get `!`.
- **Never rewrite published history.** No `--amend`, `rebase`, `reset`, or
  `push --force` on a pushed branch. Ordinary merge commits only.
- **Add or extend a guard** for behavioural changes. A change whose only
  evidence is "I tested it manually" will be asked for a guard.
- **Do not weaken a guard to make it pass.** If a guard blocks you and you
  believe it is wrong, say so in the PR and explain why — that is a
  legitimate discussion. Quietly loosening an assertion is not.

### What not to commit

`.gitignore` covers it, but to be explicit: no `node_modules/`, `dist/`,
`.local_data/`, `output/`, `__pycache__/`, `.env`, signing keys (`*.hex`,
`*.pem`, `*.key`), real customer reports, or the `*_Daily_Reports/` corpus.

## 6. Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## 7. Where to start

Good first contributions, roughly easiest first:

1. **Documentation** — the `docs/` deep-dives are solid but there is no API
   reference and no troubleshooting guide.
2. **Replace PyMuPDF** with a permissively licensed PDF backend (see §2).
3. **Wire the orphaned guards.** 45 `audit:*` scripts are not in `audit:all`,
   including the offline and behavioural-tier guards.
4. **Observability** — structured logging, metrics, worker heartbeat are all
   unimplemented GA controls (MEDIUM effort each).
5. **Decompose `store.py`.** High value, high care required.

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full prioritised list and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the pieces fit together.
