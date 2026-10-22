---
name: monday-report-frontend
description: >-
  Canonical Vite/React frontend for Monday Report — routing, provider/state,
  mutation rules, build/test commands, and UI evidence expectations. INVOKE for
  any UI/component/routing/state change or UI verification. Triggers: "add a
  page/route", "workspace state", "UI test", "screenshots", "styling/tokens",
  "does v1 still exist". Enforces the single-canonical-entry rule (no v1/dual entry).
---

# Monday Report — frontend

Vite + React 19 + TypeScript. **Exactly one frontend, one origin.**

## Canonical entry (do NOT resurrect v1)
- Root `index.html` loads **`src/redesign/main.tsx`** on **port 5173**
  (`vite.config.ts`, `host 127.0.0.1`, `strictPort`, dev AND preview).
- The retired v1 entry (`src/main.tsx`, `src/App.tsx`, `src/components/`,
  `src/styles.css`, `src/data/domain.ts`) and the separate `redesign.html`/`5174`
  document are **deleted**. Never recreate a second entry, port, or dual-Vite setup.
- `redesignHistoryFallback` (in `vite.config.ts`) rewrites non-asset GETs to the
  SPA doc so deep-route refresh works — including `/app/*` ids containing a dot
  (e.g. `MR-1.2`). Anything under `/app` is always a route.

## Layout
- `src/redesign/router.tsx` — routes. `shell/` — `AppShell.tsx`, `Sidebar.tsx`,
  `Topbar.tsx`, `navigation.ts`. `pages/` — Landing, SignIn, Ask (chat-first home),
  Upload, Reports, Studio, Validation, Failures, Benchmarking, Roadmap, Tracker,
  Audit, Exports, Well, Settings, NotFound.
- `src/redesign/lib/workspace.tsx` — **shared client state provider** (the single
  workspace context); `lib/useRouteAnnounce.ts` a11y route announce.
- `src/redesign/components/` — `primitives.tsx`, `CasingSchematic.tsx`,
  `trajectory.tsx`. `src/lib/` — `api.ts` (typed API client), `citationFormat.ts`,
  `trajectoryGeometry.ts`. `src/data/` — committed program data
  (`projectTracker.ts`, `productRoadmap.ts`, `reportVariantSchemas.ts`).
- Styling: `src/styles/tokens.css` + `src/styles/redesign.css`.

## Routing / provider / state / mutation rules
- Public landing + `/app` chat-first shell. Keep route tables consistent with
  `shell/navigation.ts` — `roadmap_guard`/`audit_harness_guard` validate the
  canonical suite's route tables in lockstep.
- Consume shared state through the `workspace.tsx` provider; don't spin up parallel
  ad-hoc global stores. Use the typed shapes from `src/lib/api.ts`.
- Mutations go through the API client; the UI never fabricates data at runtime
  (guard: `audit:runtime-mock-data`). Citations/source actions must preserve
  source lineage and provenance (guard: `audit:source-citations`,
  `audit:citation-format`). Report-draft GET is treated as a WRITE on the backend.

## Build / test commands (verified)
- `pnpm run dev` — dev server. `pnpm run build` — `tsc && vite build`.
  `pnpm run preview` — serve the build. Set `$env:CI='true'` in PowerShell for
  non-interactive builds.
- `pnpm run test:ui` (= `test:ui-redesign`, `scripts/ui_redesign_e2e.mjs`) — the UI
  gate. It **requires an explicitly isolated stack** (state/storage/export roots
  outside the repo, API port ≠ 8000, web ≠ 5173) and **refuses to run against the
  live servers**. Coding style: PascalCase components, camelCase helpers, 2-space
  indent, double quotes, semicolons. See [[monday-report-testing]].

## UI evidence + source-citation requirements
- UI-facing acceptance must be re-reviewed against the **canonical** frontend;
  evidence rows that cited retired v1 paths are history only. Cite the exact
  source file/line for any UI claim; do not certify a screenshot as proof of a
  property the test did not observe. See [[monday-report-security-review]],
  [[monday-report-evidence-certification]].

## Non-goals / safety
- No second entry/port/dual-Vite. No runtime mock data. No presenting reference
  geometry as client-confirmed. Never run `test:ui` against the live stack.
