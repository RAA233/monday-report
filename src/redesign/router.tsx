import { Navigate, Outlet, Route, Routes } from "react-router-dom";
import { WorkspaceProvider } from "./lib/workspace";
import { AppShell } from "./shell/AppShell";
import { Landing } from "./pages/Landing";
import { SignIn } from "./pages/SignIn";
import { Ask } from "./pages/Ask";
import { Reports } from "./pages/Reports";
import { Studio } from "./pages/Studio";
import { Validation } from "./pages/Validation";
import { Exports } from "./pages/Exports";
import { Well } from "./pages/Well";
import { Upload } from "./pages/Upload";
import { Benchmarking } from "./pages/Benchmarking";
import { Failures } from "./pages/Failures";
import { Audit } from "./pages/Audit";
import { Settings } from "./pages/Settings";
import { Tracker } from "./pages/Tracker";
import { Roadmap } from "./pages/Roadmap";
import { NotFound } from "./pages/NotFound";
import { useRouteAnnounce } from "./lib/useRouteAnnounce";

/**
 * Route contract for the redesigned entry.
 *
 *   /                          public landing
 *   /app/signin                sign-in surface (outside the shell)
 *   /app                       Ask — the chat-first home
 *   /app/reports               Monday reports
 *   /app/reports/:id/draft     Report Studio for one report
 *   /app/studio                Report Studio without a selected report
 *   /app/validation            validation queue
 *   /app/exports               exports and signed references
 *   /app/chat                  → /app  (the chat-first home IS Ask)
 *   /app/well                  well schematics from the workspace's evidence
 *   /app/upload                audited upload intake + processing queue
 *   /app/benchmarking          benchmark status, anomalies and configuration
 *   /app/failures              failure explorer over extracted events
 *   /app/audit                 audit-chain integrity and entries
 *   /app/settings              read-only session and runtime disclosure
 *   /app/tracker               committed project-tracker record + live status
 *   /app/roadmap               committed product-roadmap record
 *   /app/*                     in-shell not found
 *
 * Deep-route refresh works because `vite.redesign.config.ts` rewrites non-asset
 * GETs to `/redesign.html` rather than letting Vite fall back to the v1 root
 * document.
 *
 * `WorkspaceProvider` wraps the /app subtree ONLY. Mounted above the whole router it
 * ran its authenticated probe on the public landing page, so visiting `/` sent five
 * keyed reads to the tenant API for a page that displays none of them.
 */
function WorkspaceRoutes() {
  return (
    <WorkspaceProvider>
      <Outlet />
    </WorkspaceProvider>
  );
}

export function AppRoutes() {
  // Route changes set the document title and move focus to the new view's h1.
  useRouteAnnounce();

  return (
    <Routes>
      <Route path="/" element={<Landing />} />

      <Route element={<WorkspaceRoutes />}>
        <Route path="/app/signin" element={<SignIn />} />

        <Route path="/app" element={<AppShell />}>
          <Route index element={<Ask />} />
          <Route path="reports" element={<Reports />} />
          <Route path="reports/:reportId/draft" element={<Studio />} />
          <Route path="studio" element={<Studio />} />
          <Route path="validation" element={<Validation />} />
          <Route path="exports" element={<Exports />} />

          {/* Chat is not a separate destination — Ask is the chat-first home. */}
          <Route path="chat" element={<Navigate to="/app" replace />} />

          <Route path="well" element={<Well />} />
          <Route path="upload" element={<Upload />} />
          <Route path="benchmarking" element={<Benchmarking />} />
          <Route path="failures" element={<Failures />} />
          <Route path="audit" element={<Audit />} />
          <Route path="settings" element={<Settings />} />

          {/* Ported program surfaces: the committed tracker/roadmap records. */}
          <Route path="tracker" element={<Tracker />} />
          <Route path="roadmap" element={<Roadmap />} />

          <Route path="*" element={<NotFound />} />
        </Route>
      </Route>

      {/* Anything outside /app returns to the public landing page. */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
