import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import "../styles/tokens.css";
import "../styles/redesign.css";
import { AppRoutes } from "./router";

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

// `WorkspaceProvider` lives inside the router, around the /app subtree only, so the
// public landing page issues no authenticated read. See `router.tsx`.
createRoot(container).render(
  <StrictMode>
    <BrowserRouter>
      <AppRoutes />
    </BrowserRouter>
  </StrictMode>
);
