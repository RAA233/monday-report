import { defineConfig, type Connect, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

/**
 * Second, independent Vite entry for the redesigned frontend.
 *
 * The v1 application keeps `index.html` + `src/main.tsx` on port 5173 so the
 * committed `scripts/ui_quality_e2e.mjs` suite continues to assert against it
 * unchanged. The redesign is a real separate entry — its own HTML document, its
 * own React root, its own router — served here on 5174.
 *
 * `redesignHistoryFallback` is what makes deep-route refresh work. Vite's own SPA
 * fallback rewrites unknown paths to the ROOT `index.html`, which would hand
 * `/app/reports` to the v1 app. This middleware rewrites non-asset GETs to
 * `/redesign.html` instead, so refreshing any `/app/*` route re-enters the
 * redesign router with the URL intact.
 */
const REDESIGN_ENTRY = "/redesign.html";

/**
 * Decide whether a request is for an asset (leave it alone) or a route (rewrite it
 * to the redesign document).
 *
 * The classification runs on the PATHNAME only. Testing the raw URL meant any
 * request carrying a query string — `/?utm_source=x`, `/app/reports?tab=all` —
 * matched the `?` test, was treated as an asset, and fell through to the ROOT
 * index.html, i.e. the v1 application. For the same reason the extension test must
 * not see the query: a route whose last segment contains a dot (a report id like
 * `MR-1.2`) would otherwise be misread as a file request.
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
      req.url = REDESIGN_ENTRY;
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
  build: {
    // Keeps the v1 build output untouched; `pnpm run build` still emits dist/.
    outDir: "dist-redesign",
    rollupOptions: {
      input: { redesign: "redesign.html" }
    }
  },
  server: {
    host: "127.0.0.1",
    port: 5174,
    strictPort: true
  },
  preview: {
    host: "127.0.0.1",
    port: 5174,
    strictPort: true
  }
});
