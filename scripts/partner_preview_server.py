"""Tiny stdlib static server with SPA fallback, for the partner preview package.

The canonical frontend is a single-page application with real deep routes
(`/app/reports`, `/app/upload`, ...). `python -m http.server` answers 404 for
any path that is not a file on disk, so refreshing or directly opening a deep
route broke. This server serves the built `dist/` directory and rewrites every
non-asset GET to `index.html`, mirroring the `redesignHistoryFallback`
middleware in `vite.config.ts`.

Stdlib only — the partner machine needs nothing beyond the Python runtime the
launcher already installs.

Usage:
    python scripts/partner_preview_server.py --port 5173 --root dist
"""
from __future__ import annotations

import argparse
import posixpath
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class SpaFallbackHandler(SimpleHTTPRequestHandler):
    """Serve files as usual; rewrite non-asset route paths to /index.html.

    The classification runs on the PATHNAME only (query and fragment stripped),
    and anything under /app is ALWAYS a route — a report id such as `MR-1.2`
    contains a dot and must not be misread as a file request.
    """

    def send_head(self):  # noqa: N802 (stdlib naming)
        pathname = self.path.split("?", 1)[0].split("#", 1)[0]
        if not self._is_asset_request(pathname):
            self.path = "/index.html"
        return super().send_head()

    def _is_asset_request(self, pathname: str) -> bool:
        if pathname == "/app" or pathname.startswith("/app/"):
            return False
        if pathname.startswith("/assets/"):
            return True
        # A real file extension on the final segment (outside /app) is a file request.
        return "." in posixpath.basename(pathname)


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve the built SPA with deep-route fallback.")
    parser.add_argument("--port", type=int, default=5173)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--root", default="dist", help="Directory holding the built index.html.")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    if not (root / "index.html").exists():
        raise SystemExit(f"{root} does not contain index.html — build the frontend first.")

    handler = partial(SpaFallbackHandler, directory=str(root))
    server = ThreadingHTTPServer((args.bind, args.port), handler)
    print(f"Serving {root} at http://{args.bind}:{args.port}/ (SPA deep-route fallback active)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
