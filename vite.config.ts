import { defineConfig, type Connect, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

/**
 * Canonical Vite entry: the redesigned frontend on port 5173.
 *
 * The root `index.html` loads `src/redesign/main.tsx`. The retired v1 entry and
 * its separate `redesign.html`/5174 document are gone; there is exactly one
 * frontend and one dev/preview origin.
 *
 * `redesignHistoryFallback` is what makes deep-route refresh work. Vite's own SPA
 * fallback covers most cases, but this middleware keeps the explicit contract the
 * redesign router documents: every non-asset GET — including `/app/*` paths whose
 * last segment contains a dot (a report id like `MR-1.2`) — re-enters the SPA
 * document with the URL intact, in dev AND in preview.
 */
const SPA_ENTRY = "/index.html";

/**
 * Decide whether a request is for an asset (leave it alone) or a route (rewrite it
 * to the SPA document).
 *
 * The classification runs on the PATHNAME only. Testing the raw URL meant any
 * request carrying a query string — `/?utm_source=x`, `/app/reports?tab=all` —
 * matched the `?` test, was treated as an asset, and fell through untouched. For
 * the same reason the extension test must not see the query: a route whose last
 * segment contains a dot (a report id like `MR-1.2`) would otherwise be misread
 * as a file request.
 *
 * Anything under `/app` is always a route, whatever it looks like.
 */
function isAssetRequest(url: string): boolean {
  const pathname = url.split("?")[0].split("#")[0];
  if (pathname === "/app" || pathname.startsWith("/app/")) return false;
  return (
    pathname.startsWith("/@") || // vite client, react-refresh, fs
    pathname.startsWith("/__") || // vite internals (e.g. /__inspect)
    pathname.startsWith("/src/") ||
    pathname.startsWith("/node_modules/") ||
    pathname.startsWith("/assets/") ||
    /\.[a-zA-Z0-9]+$/.test(pathname) // a real file extension on the path
  );
}

function redesignHistoryFallback(): Plugin {
  const rewrite: Connect.NextHandleFunction = (req, _res, next) => {
    if (req.method === "GET" && req.url && !isAssetRequest(req.url)) {
      req.url = SPA_ENTRY;
    }
    next();
  };

  return {
    name: "redesign-history-fallback",
    configureServer(server) {
      server.middlewares.use(rewrite);
    },
    configurePreviewServer(server) {
      server.middlewares.use(rewrite);
    }
  };
}

export default defineConfig({
  plugins: [react(), redesignHistoryFallback()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true
  },
  preview: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true
  }
});
