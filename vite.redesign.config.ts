import { defineConfig, type Plugin } from "vite";
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

function redesignHistoryFallback(): Plugin {
  const isAssetRequest = (url: string): boolean =>
    url.startsWith("/@") || // vite client, react-refresh, fs
    url.startsWith("/src/") ||
    url.startsWith("/node_modules/") ||
    url.includes("?") || // ?import, ?t=, ?direct
    /\.[a-zA-Z0-9]+$/.test(url); // any file extension

  return {
    name: "redesign-history-fallback",
    configureServer(server) {
      server.middlewares.use((req, _res, next) => {
        if (req.method === "GET" && req.url && !isAssetRequest(req.url)) {
          req.url = REDESIGN_ENTRY;
        }
        next();
      });
    },
    configurePreviewServer(server) {
      server.middlewares.use((req, _res, next) => {
        if (req.method === "GET" && req.url && !isAssetRequest(req.url)) {
          req.url = REDESIGN_ENTRY;
        }
        next();
      });
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
