# Repository Guidelines

## Project Structure & Module Organization

Monday Report is a Vite React/TypeScript app. Runtime source lives in `src/`, with app composition in `src/App.tsx`, entry setup in `src/main.tsx`, shared styling in `src/styles.css`, reusable views in `src/components/`, seeded domain data in `src/data/`, and deterministic analytics helpers in `src/lib/`. Database design artifacts live in `db/schema.sql`. `dist/` is generated output and should not be edited by hand.

## Build, Test, and Development Commands

- `pnpm install`: install dependencies from `pnpm-lock.yaml`.
- `pnpm run dev`: start the Vite dev server on `127.0.0.1`.
- `pnpm run build`: run TypeScript checks with `tsc`, then create a production build in `dist/`.
- `pnpm run preview`: serve the production build locally for a final smoke test.

Set `$env:CI='true'` in PowerShell before build commands when running in non-interactive automation.

## Coding Style & Naming Conventions

Use TypeScript and React function components. Keep component files in PascalCase, such as `Dashboard.tsx`, and helper modules in camelCase, such as `analytics.ts`. Prefer explicit prop interfaces and typed domain objects from `src/data/domain.ts`. Use two-space indentation, double quotes, semicolons, and JSX that keeps UI labels close to the component that renders them.

## Testing Guidelines

No automated test framework is configured yet. Before submitting changes, run `pnpm run build` and manually smoke-test the dashboard, upload flow, chat, explorer filters, validation queue, and architecture view. If tests are added, place component tests near the component or under `src/__tests__/`, and name them `*.test.ts` or `*.test.tsx`.

## Commit & Pull Request Guidelines

This checkout has no Git history, so no existing commit convention is available. Use concise Conventional Commit-style messages, for example `feat: add validation queue filter` or `fix: correct upload duplicate warning`. Pull requests should include a short summary, verification steps, linked issue or task, and screenshots for visible UI changes.

## Security & Configuration Tips

Do not commit uploaded customer reports, generated secrets, or tenant-specific credentials. Keep schema changes in `db/schema.sql` aligned with tenant isolation and row-level security assumptions described in the architecture view.
