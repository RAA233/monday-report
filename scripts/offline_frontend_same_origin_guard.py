"""Guard: the packaged Offline customer frontend must reach its backend SAME-ORIGIN.

Regression cover for the P4/E1 release blocker where the frozen package (SHA
``8ebe298b``) shipped a dev-configured SPA that hardcoded ``http://127.0.0.1:8000``
while the Offline runtime serves UI + API on ``127.0.0.1:47613`` -- so the customer
UI could not reach its own backend. Root cause: ``--reuse-frontend`` copied a
dev-built ``dist/`` instead of building same-origin (``VITE_API_BASE_URL=""``).

The behavioral proof (a real packaged browser session) lives in E1/E2 -- it needs the
built Windows exe and cannot run in hermetic CI. This guard is the part that CAN run
everywhere: the release-pipeline invariants and a self-contained non-vacuity proof of
the shipped-bundle assertion, plus a loud (never silent) scan of a real dist when one
is present.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _load_build_module():
    path = ROOT / "packaging" / "build_offline_package.py"
    spec = importlib.util.spec_from_file_location("mr_build_offline_package", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assert_check(name: str, ok: bool, detail: object) -> dict:
    return {"name": name, "ok": bool(ok), "detail": detail}


def _make_dist(root: Path, js_body: str) -> Path:
    app = root / "MondayReportOffline"
    (app / "_internal" / "dist" / "assets").mkdir(parents=True, exist_ok=True)
    (app / "_internal" / "dist" / "index.html").write_text("<!doctype html><div id=root>", encoding="utf-8")
    (app / "_internal" / "dist" / "assets" / "index-test.js").write_text(js_body, encoding="utf-8")
    return app


def main() -> int:
    checks: list[dict] = []
    bm = _load_build_module()

    # ---- 1. Release-pipeline source invariants ----
    env = bm.production_frontend_env()
    checks.append(assert_check(
        "production build forces same-origin API base",
        env.get("VITE_API_BASE_URL") == "",
        f"VITE_API_BASE_URL={env.get('VITE_API_BASE_URL')!r}",
    ))
    checks.append(assert_check(
        "production build forces a CUSTOMER build (internal surfaces hidden)",
        "VITE_MONDAY_REPORT_INTERNAL" not in env,
        f"VITE_MONDAY_REPORT_INTERNAL present={('VITE_MONDAY_REPORT_INTERNAL' in env)}",
    ))

    # production build refuses --reuse-frontend; non-production keeps it usable
    def _rejects(label: str, reuse: bool) -> bool:
        try:
            bm.reject_reuse_frontend_for_production(label, reuse)
            return False
        except SystemExit:
            return True
    checks.append(assert_check(
        "production + --reuse-frontend is refused",
        _rejects("production", True), "production/reuse must raise SystemExit"))
    checks.append(assert_check(
        "production without reuse is allowed",
        not _rejects("production", False), "production/no-reuse must not raise"))
    checks.append(assert_check(
        "non-production may reuse (dev convenience preserved)",
        not _rejects("TEST", True), "TEST/reuse must not raise"))

    # api.ts base is env-driven (so the same-origin build env actually controls it)
    api_src = (ROOT / "src" / "lib" / "api.ts").read_text(encoding="utf-8")
    checks.append(assert_check(
        "frontend API base is driven by VITE_API_BASE_URL",
        "import.meta.env.VITE_API_BASE_URL" in api_src,
        "src/lib/api.ts must read import.meta.env.VITE_API_BASE_URL",
    ))

    # ---- 2. Built-in NON-VACUITY of the shipped-bundle assertion ----
    with tempfile.TemporaryDirectory(prefix="mr-same-origin-") as tmp:
        tmp = Path(tmp)
        # (a) a dev-configured dist MUST fail, for the stated reason
        bad = _make_dist(tmp / "bad", 'const Fx="http://127.0.0.1:8000";fetch(Fx+"/workspaces");')
        try:
            bm.assert_frontend_same_origin(bad)
            mutated_fails = False; detail_bad = "assertion PASSED a :8000 bundle (vacuous!)"
        except SystemExit as exc:
            mutated_fails = "127.0.0.1:8000" in str(exc)
            detail_bad = str(exc)[:120]
        checks.append(assert_check(
            "assertion FAILS a dev-configured (:8000) bundle", mutated_fails, detail_bad))

        # (b) a same-origin dist MUST pass and report a non-zero scan
        good = _make_dist(tmp / "good", 'const Fx="";fetch(Fx+"/workspaces");')
        try:
            n = bm.assert_frontend_same_origin(good)
            good_ok = n > 0; detail_good = f"scanned={n}"
        except SystemExit as exc:
            good_ok = False; detail_good = f"unexpected reject: {exc}"[:120]
        checks.append(assert_check(
            "assertion PASSES a same-origin bundle", good_ok, detail_good))

        # (c) localhost:8000 form is also caught
        badl = _make_dist(tmp / "badl", 'const Fx="http://localhost:8000";')
        try:
            bm.assert_frontend_same_origin(badl); loc_fails = False
        except SystemExit:
            loc_fails = True
        checks.append(assert_check(
            "assertion FAILS a localhost:8000 bundle", loc_fails, "localhost:8000 must be caught"))

        # (d) an EMPTY package (no assets) must NOT pass vacuously
        empty = (tmp / "empty" / "MondayReportOffline"); empty.mkdir(parents=True)
        try:
            bm.assert_frontend_same_origin(empty); empty_ok = False
        except SystemExit:
            empty_ok = True
        checks.append(assert_check(
            "assertion refuses a package with no frontend assets (no vacuous pass)",
            empty_ok, "empty app_dir must raise"))

    # ---- 3. Real dist scan (INFORMATIONAL -- never fails the guard) ----
    # A plain `pnpm run build` (dev/CI) legitimately bakes the :8000 dev API base --
    # CI even serves that dist against a :8000 API for e2e. Same-origin is a
    # PRODUCTION-PACKAGE property, enforced non-vacuously at build time by
    # assemble() -> assert_frontend_same_origin (proven by check group 2 above). So
    # here we only REPORT what the present dist/ looks like; we never fail on it.
    dist = ROOT / "dist"
    if (dist / "index.html").exists():
        hits = []
        scanned = 0
        for asset in sorted(dist.rglob("*")):
            if asset.is_file() and asset.suffix in (".js", ".mjs", ".html", ".css"):
                scanned += 1
                text = asset.read_text(encoding="utf-8", errors="replace")
                for marker in bm.FORBIDDEN_FRONTEND_API_BASES:
                    if marker in text:
                        hits.append(marker)
        kind = "SAME-ORIGIN" if not hits else f"dev-configured ({sorted(set(hits))})"
        print(f"NOTE: present dist/ is {kind} ({scanned} assets scanned) -- "
              "informational only; the production package is gated at build time.")
    else:
        print("NOTE: no built dist/ present -- nothing to report "
              "(the production dist is built and asserted at package time).")

    failed = [c for c in checks if not c["ok"]]
    for c in checks:
        print(f"{'PASS' if c['ok'] else 'FAIL'}: {c['name']} - {c['detail']}")
    print(f"offline-frontend-same-origin: {len(checks) - len(failed)}/{len(checks)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
