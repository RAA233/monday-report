# Repository Guidelines

## Project Structure & Module Organization

Monday Report is a Vite React/TypeScript app. Runtime source lives in `src/`: the canonical entry is `src/redesign/main.tsx` (loaded by the root `index.html` on port 5173), with the router in `src/redesign/router.tsx`, the shell in `src/redesign/shell/`, views in `src/redesign/pages/`, shared client state in `src/redesign/lib/workspace.tsx`, and styling in `src/styles/tokens.css` + `src/styles/redesign.css`. Committed program data lives in `src/data/`, and the API client plus shared display helpers in `src/lib/`. Database design artifacts live in `db/schema.sql`. `dist/` is generated output and should not be edited by hand.

## Build, Test, and Development Commands

- `pnpm install`: install dependencies from `pnpm-lock.yaml`.
- `pnpm run dev`: start the Vite dev server on `127.0.0.1`.
- `pnpm run build`: run TypeScript checks with `tsc`, then create a production build in `dist/`.
- `pnpm run preview`: serve the production build locally for a final smoke test.

Set `$env:CI='true'` in PowerShell before build commands when running in non-interactive automation.

## Coding Style & Naming Conventions

Use TypeScript and React function components. Keep component files in PascalCase, such as `Tracker.tsx`, and helper modules in camelCase, such as `trajectoryGeometry.ts`. Prefer explicit prop interfaces and the typed API shapes from `src/lib/api.ts`. Use two-space indentation, double quotes, semicolons, and JSX that keeps UI labels close to the component that renders them.

## Testing Guidelines

The UI gate is `pnpm run test:ui` (`scripts/ui_redesign_e2e.mjs`), which requires an explicitly isolated stack (state/storage/export roots outside the repo, API port != 8000, web port != 5173) and refuses to run against the live servers. Before submitting changes, run `pnpm run build` and the relevant `audit:*` guards; `pnpm run audit:all` is the full chain.

## Commit & Pull Request Guidelines

Use Conventional Commit-style messages, for example `feat: add validation queue filter` or `fix: correct upload duplicate warning` — that is the convention the existing history follows. Pull requests should include a short summary, verification steps, a linked issue or task, and screenshots for visible UI changes. Every commit must be covered by the CLA in [CLA.md](CLA.md); see [CONTRIBUTING.md](CONTRIBUTING.md) for the sign-off line, licence headers, and the full contributor workflow.

## Security & Configuration Tips

Do not commit uploaded customer reports, generated secrets, or tenant-specific credentials. Keep schema changes in `db/schema.sql` aligned with tenant isolation and row-level security assumptions described in the architecture view.
