"""Same-origin frontend build invariants for the Offline package.

Kept deliberately DEPENDENCY-FREE (stdlib only): the release build script imports
these, and so does ``scripts/offline_frontend_same_origin_guard.py`` in the hermetic
audit chain -- which must not drag in the app's crypto dependencies. Do not import
anything from ``backend.app`` (or any third-party package) here.
"""
from __future__ import annotations

import os
from pathlib import Path


FORBIDDEN_FRONTEND_API_BASES = ("127.0.0.1:8000", "localhost:8000")


def production_frontend_env() -> dict:
    """Environment for the production offline frontend build. Forced here so an
    operator's ambient shell variables cannot leak into the shipped bundle:

    * ``VITE_API_BASE_URL=""`` -- SAME-ORIGIN. The offline backend serves UI + API
      from one localhost origin, so the SPA must issue relative requests. A baked dev
      host (``http://127.0.0.1:8000``) yields a UI that cannot reach its own backend
      -- the P4/E1 release blocker this fix closes.
    * ``VITE_MONDAY_REPORT_INTERNAL`` unset -- CUSTOMER build: the internal
      Tracker / Roadmap / SignIn surfaces stay hidden (they redirect to /app).
    """
    env = dict(os.environ)
    env["CI"] = "true"
    env["VITE_API_BASE_URL"] = ""
    env.pop("VITE_MONDAY_REPORT_INTERNAL", None)
    return env


def reject_reuse_frontend_for_production(key_label: str, reuse_frontend: bool) -> None:
    """A production package MUST bundle a freshly-built same-origin CUSTOMER frontend.
    Reusing an existing ``dist/`` risks shipping a dev-configured bundle (wrong API
    base, or an internal build), so refuse ``--reuse-frontend`` for a production build."""
    if key_label == "production" and reuse_frontend:
        raise SystemExit(
            "--reuse-frontend is refused for a production build (--key-label production): "
            "the production frontend must be freshly built same-origin. Remove --reuse-frontend."
        )


def assert_frontend_same_origin(app_dir: Path) -> int:
    """Fail closed if the SHIPPED frontend bundle carries a hardcoded dev API base.

    Scans every packaged SPA ``dist`` asset (a Vite build has an ``index.html``) and
    returns the number of files scanned, so a caller can prove the check was not
    vacuous. The offline SPA must use relative (same-origin) requests; a baked
    ``http://127.0.0.1:8000`` means a reused dev dist and a UI that cannot reach its
    own backend. On a hit, surrounding context is printed so a human can adjudicate
    the rare "unrelated test text" case."""
    app_dir = Path(app_dir)
    scanned = 0
    spa_dists = [p for p in app_dir.rglob("dist") if p.is_dir() and (p / "index.html").is_file()]
    for dist in sorted(spa_dists):
        for asset in sorted(dist.rglob("*")):
            if asset.is_file() and asset.suffix in (".js", ".mjs", ".html", ".css"):
                scanned += 1
                text = asset.read_text(encoding="utf-8", errors="replace")
                for marker in FORBIDDEN_FRONTEND_API_BASES:
                    hit = text.find(marker)
                    if hit >= 0:
                        ctx = text[max(0, hit - 80):hit + 40].replace("\n", " ")
                        raise SystemExit(
                            f"packaged frontend carries a hardcoded API base {marker!r} in "
                            f"{asset}: the offline SPA must use same-origin requests. "
                            f"Context: ...{ctx}..."
                        )
    if scanned == 0:
        raise SystemExit(
            "assert_frontend_same_origin found no packaged frontend assets to scan under "
            f"{app_dir} -- refusing to certify a package with no verifiable UI."
        )
    return scanned
