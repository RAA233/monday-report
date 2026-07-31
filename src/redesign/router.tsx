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
import { PendingStage } from "./pages/PendingStage";
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
 *   /app/{well,upload,benchmarking,failures,audit,settings}
 *                              reserved, explicitly labelled as not implemented
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

          {/* Reserved for the next increment; each renders a labelled pending state. */}
          <Route path="well" element={<PendingStage />} />
          <Route path="upload" element={<PendingStage />} />
          <Route path="benchmarking" element={<PendingStage />} />
          <Route path="failures" element={<PendingStage />} />
          <Route path="audit" element={<PendingStage />} />
          <Route path="settings" element={<PendingStage />} />

          <Route path="*" element={<NotFound />} />
        </Route>
      </Route>

      {/* Anything outside /app returns to the public landing page. */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
