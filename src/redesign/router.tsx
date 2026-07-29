import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./shell/AppShell";
import { Landing } from "./pages/Landing";
import { PendingStage } from "./pages/PendingStage";
import { NotFound } from "./pages/NotFound";

/**
 * Route contract for the redesigned entry.
 *
 * `/` is the public product page. The Stage 1 workflow views land in the next
 * commit; until then every reserved destination renders the labelled
 * implementation-pending state rather than a surface that pretends to work.
 *
 * Deep-route refresh works because `vite.redesign.config.ts` rewrites non-asset
 * GETs to `/redesign.html` rather than letting Vite fall back to the v1 root
 * document.
 */
export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />

      <Route path="/app" element={<AppShell />}>
        <Route index element={<PendingStage />} />

        {/* Chat is not a separate destination — Ask is the chat-first home. */}
        <Route path="chat" element={<Navigate to="/app" replace />} />

        <Route path="reports" element={<PendingStage />} />
        <Route path="studio" element={<PendingStage />} />
        <Route path="validation" element={<PendingStage />} />
        <Route path="exports" element={<PendingStage />} />
        <Route path="well" element={<PendingStage />} />
        <Route path="upload" element={<PendingStage />} />
        <Route path="benchmarking" element={<PendingStage />} />
        <Route path="failures" element={<PendingStage />} />
        <Route path="audit" element={<PendingStage />} />
        <Route path="settings" element={<PendingStage />} />

        <Route path="*" element={<NotFound />} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
