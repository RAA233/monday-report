import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import "../styles/tokens.css";
import "../styles/redesign.css";
import { AppRoutes } from "./router";
import { WorkspaceProvider } from "./lib/workspace";

/**
 * Entry point for the redesigned frontend (redesign.html, port 5174).
 *
 * Deliberately separate from `src/main.tsx`: the v1 application keeps mounting at
 * `/` on 5173 so the committed UI suite keeps asserting against it unchanged.
 */
const container = document.getElementById("root");
if (!container) {
  throw new Error("redesign entry: #root is missing from redesign.html");
}

createRoot(container).render(
  <StrictMode>
    <BrowserRouter>
      <WorkspaceProvider>
        <AppRoutes />
      </WorkspaceProvider>
    </BrowserRouter>
  </StrictMode>
);
