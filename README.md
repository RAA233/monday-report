<div align="center">

# Monday Report

**Turn a pile of daily drilling reports into an audited, source-cited morning report.**

[![Licence: AGPL v3](https://img.shields.io/badge/Licence-AGPL%20v3-blue.svg)](LICENSE)
[![Status: pre-GA](https://img.shields.io/badge/status-pre--GA%20(GA__BLOCKED)-orange.svg)](STATUS.md)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](backend/requirements.txt)
[![React 19](https://img.shields.io/badge/react-19-61dafb.svg)](package.json)

*Runs entirely on your machine. No cloud, no database, no Docker required.*

</div>

---

## What it does

Drilling operations generate a daily report per rig per day — PDFs, spreadsheets,
emails, scanned paper. Somebody has to read them all and write the morning
summary that management actually reads. That person spends hours copying numbers
between documents, and any number they mistype is invisible downstream.

Monday Report ingests those documents and drafts the morning report for them,
with **every extracted value carrying a citation back to the page it came from**.

The design rule throughout: *the software never pretends to know something it
cannot show you the source for.*

- **Ingests** ZIP archives, PDFs, XLSX, DOCX, CSV, email — with hashing,
  duplicate detection, and malware screening
- **Extracts** casing schematics, 24-hour activity timelines, directional survey
  stations, and hydraulics observations — each with page-level citation and a
  confidence value
- **Calculates** well trajectory via documented minimum-curvature, rendered as
  plan-view and vertical-profile diagrams. Calculated values sit **beside**
  source values, never on top of them, and gaps are left as gaps
- **Drafts** the Monday Report in five variants, blocks official export while
  validation tasks are unresolved, and exports to JSON / CSV / HTML / PDF / XLSX
- **Audits** everything into an HMAC-sealed, hash-chained log
- **Ships offline** as a signed, machine-bound Windows package for air-gapped
  sites

### What makes it unusual

Not the drilling domain — the **verification engineering**. The project treats
"is this actually proven?" as a first-class, machine-checked question:

- **117 effect-level guard scripts** act as the test suite. 13 of them are
  *fault batteries* that seed a deliberate defect in the subsystem and fail if
  the paired guard does not catch it — mutation testing applied to the oracles
  themselves. Extending that coverage is a tracked roadmap item
- **No `TODO` comments anywhere.** Unfinished work lives in a registry of 28
  machine-checked controls, so an incomplete feature cannot hide as a code comment
- **The release gate cannot be bribed.** No environment variable, no config, no
  unsigned file can turn a blocker green. `SKIPPED` never counts as a pass
- **CI goes red if the audit chain ever turns green**, because a silently
  resolved gate must be a reviewed decision rather than drift

If you have ever inherited a project where "all tests pass" meant nothing, this
repo is an argument about how to fix that.

---

## Status: pre-GA, and honest about it

> **This is a working prototype, not a product you should deploy.**
> Its own gate reports `GA_BLOCKED`: 20 of 28 controls are open, production
> database/queue infrastructure is explicitly `NOT_ACCEPTED`, and real customer
> data is gated off.

**Please read [STATUS.md](STATUS.md) before forming an opinion** — it lists what
genuinely works, what does not, and why the project refuses to credit itself.

---

## Quickstart

**Requirements:** Node 22+, **pnpm 10+** (pnpm 9 will fail — see
[CONTRIBUTING.md](CONTRIBUTING.md#3-environment-setup)), Python 3.12.

```bash
git clone https://github.com/RAA233/monday-report.git
cd monday-report

corepack enable
pnpm install --frozen-lockfile
python -m pip install -r backend/requirements.txt
```

Then start the two processes in separate terminals:

```bash
pnpm run dev:api     # FastAPI  -> http://127.0.0.1:8000
pnpm run dev         # Vite     -> http://127.0.0.1:5173
```

Open **http://127.0.0.1:5173**. That is it — state persists to a local JSON
store under `.local_data/`. PostgreSQL and Redis are optional and only engage in
approved client mode.

```bash
pnpm run build                # tsc && vite build
pnpm run audit:route-rbac     # run a single verification guard
pnpm run audit:all            # the full 77-step chain (see note below)
```

> **`audit:all` exits non-zero by design.** The expected result is exactly one
> failure — `GA50 commit-binding-is-ancestor`, a deliberate staleness gate.
> Any *other* failure is a real regression. [Why.](STATUS.md#3-how-to-read-the-honesty-machinery)

---

## Architecture at a glance

```
            Browser (React 19 + TS, Vite)
                      │  src/redesign/ — 20 routes, one canonical UI
                      ▼
            FastAPI  (backend/app/main.py — 48 routes)
                      │  default-deny RBAC → tenant authz → handler
                      ▼
          ┌───────────┴────────────┐
          ▼                        ▼
   LocalStateStore          PostgreSQL + Redis
   (.local_data JSON,        (optional, approved
    the default)              client mode, RLS)
                      │
                      ▼
          HMAC-SHA256 hash-chained audit log
```

Deeper: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**. Design notes per
subsystem live in `docs/` — trajectory maths, hydraulics extraction, audit
integrity, RBAC, tenant authorisation, migrations.

---

## Want to contribute?

There is a lot of well-marked unfinished work, and the roadmap is explicit about
effort and value: **[docs/ROADMAP.md](docs/ROADMAP.md)**.

Good first issues: replacing the AGPL PDF backend, wiring the 45 orphaned guard
scripts into the audit chain, observability (logging / metrics / heartbeat), and
decomposing the 8,591-line `store.py`.

Start with **[CONTRIBUTING.md](CONTRIBUTING.md)** — it documents the real
surprises (no unit-test framework, the guard battery, pnpm 10) and the
[CLA](CLA.md) you will need to sign.

Work that was started and deliberately stopped is written up in
**[docs/unfinished/](docs/unfinished/)**, including why each attempt stopped —
so you can pick one up without repeating the dead ends.

---

## Licence

**GNU Affero General Public License v3.0 or later** — see [LICENSE](LICENSE).

AGPL means: use it, modify it, run it. But if you distribute it **or offer it as
a network service**, you must release your modified source under the same terms
and keep the attribution in [NOTICE](NOTICE) intact.

> A **commercial licence** is available for organisations that cannot accept the
> copyleft and network-source obligations. To enquire, open an issue titled
> *Commercial licence enquiry*.

Copyright © 2026 **Rashed Albalawi** (Developer) and **Emeil Nassrallah** (Founder).

Evaluation ground truth derives from Utah FORGE Well 16A(78)-32 drilling data,
used under CC BY 4.0 — full citation in [NOTICE](NOTICE). The raw report corpus
is not redistributed here.
