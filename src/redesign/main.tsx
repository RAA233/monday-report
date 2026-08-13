import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import "../styles/tokens.css";
import "../styles/redesign.css";
import { AppRoutes } from "./router";

/**
 * Entry point for the canonical frontend (root index.html, port 5173).
 *
 * The redesign IS the application: the retired v1 entry is gone and the root
 * document loads this module directly.
 */
const container = document.getElementById("root");
if (!container) {
  throw new Error("frontend entry: #root is missing from index.html");
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
