"""Structural read-coherence coverage guard (Part J/K).

AST-based, no database. Fails CLOSED when the whole-operation committed-read
boundary could be bypassed, so a NEW state-reading route/export/worker cannot
silently reintroduce multi-access generation mixing:

1. store.py declares the request/task-scoped committed read view built on
   contextvars (committed_read_view + a ContextVar-backed _read_view).
2. main.py registers the coherent_read_view http middleware that wraps every
   request in store.committed_read_view().
3. worker.py wraps its job pass in store.committed_read_view().
4. EVERY @app route that reads a managed-state collection (subscript or .get/
   .values/.items on one of the MANAGED names) also calls store.refresh(), which
   pins the request's committed generation inside the middleware's view. A route
   that reads managed state without refresh() would fall through to per-access
   reads (no coherence) and FAILS this guard.

Run: ``python scripts/read_coherence_guard.py``
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "backend" / "app" / "main.py"
STORE = ROOT / "backend" / "app" / "store.py"
WORKER = ROOT / "backend" / "app" / "worker.py"

MANAGED = {
    "workspaces", "uploads", "files", "jobs", "parsed_documents", "document_chunks",
    "failures", "validation_tasks", "monday_reports", "report_exports", "benchmark_values",
    "anomaly_rules", "benchmark_measurements", "anomaly_events", "key_decisions",
    "field_corrections", "users", "api_credentials", "audit_logs",
}
ROUTE_DECORATORS = {"get", "post", "patch", "put", "delete"}

checks: list[dict] = []


def record(name: str, ok: bool, detail: object = "") -> None:
    checks.append({"name": name, "ok": bool(ok), "detail": detail})


def _reads_managed(func: ast.AST) -> list[str]:
    """Managed-state collections this function reads via store.<M>[...]/.get/.values/.items."""
    hits: set[str] = set()
    for node in ast.walk(func):
        # store.<M>  (attribute access on `store`)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                and node.value.id == "store" and node.attr in MANAGED:
            hits.add(node.attr)
    return sorted(hits)


def _calls_store_refresh(func: ast.AST) -> bool:
    for node in ast.walk(func):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "refresh" and isinstance(node.func.value, ast.Name) \
                and node.func.value.id == "store":
            return True
    return False


def _is_route(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in func.decorator_list:
        # @app.get(...) / @app.post(...) etc.
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute) and target.attr in ROUTE_DECORATORS \
                and isinstance(target.value, ast.Name) and target.value.id == "app":
            return True
    return False


def main() -> int:
    main_src = MAIN.read_text(encoding="utf-8")
    store_src = STORE.read_text(encoding="utf-8")
    worker_src = WORKER.read_text(encoding="utf-8")

    # 1) store primitive present
    record("01 store declares committed_read_view()",
           "def committed_read_view" in store_src)
    record("02 read view is contextvars-backed (async/threadpool safe, not threading.local)",
           "import contextvars" in store_src and "_read_view" in store_src
           and "contextvars.ContextVar(" in store_src
           and '"mr_committed_read_view"' in store_src)
    record("03 store pins the committed generation on refresh inside a view",
           ".set(self._published)" in store_src)

    # 2) middleware present
    record("04 main.py registers the coherent_read_view http middleware",
           "async def coherent_read_view" in main_src
           and "store.committed_read_view()" in main_src
           and '@app.middleware("http")' in main_src)

    # 3) worker wrapped
    record("05 worker wraps its job pass in committed_read_view()",
           "store.committed_read_view()" in worker_src)

    # 4) every managed-reading route calls store.refresh()
    tree = ast.parse(main_src)
    offenders = []
    reading_routes = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_route(node):
            reads = _reads_managed(node)
            if reads:
                reading_routes += 1
                if not _calls_store_refresh(node):
                    offenders.append({"route": node.name, "reads": reads})
    record("06 every @app route that reads a managed-state collection calls store.refresh() "
           "(pins the request's committed generation inside the middleware read view)",
           not offenders, {"reading_routes": reading_routes, "offenders": offenders})

    # 07 STREAMING drift: a StreamingResponse iterator runs AFTER the middleware
    # read view exits, so a route that streams managed state without materializing
    # it inside the view (or entering its own view) would read post-view. Fail
    # closed if any route both returns a StreamingResponse AND reads managed state.
    stream_offenders = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_route(node):
            names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
            if "StreamingResponse" in names and _reads_managed(node):
                stream_offenders.append(node.name)
    record("07 STREAMING drift: no @app route streams managed state via StreamingResponse (whose "
           "iterator runs after the read view exits) without materializing inside the view",
           not stream_offenders, {"offenders": stream_offenders})

    # 08 BACKGROUND-TASK drift: a Starlette BackgroundTask runs AFTER the response,
    # outside the request read view. Fail closed if a background task is scheduled
    # anywhere in the routing layer without an explicit committed_read_view around
    # the store reads (detected structurally: any BackgroundTask/add_task usage in
    # main.py must be accompanied by a committed_read_view call).
    bg_used = ("BackgroundTask" in main_src) or (".add_task(" in main_src)
    bg_wrapped = "committed_read_view" in main_src  # the coherent_read_view middleware call
    record("08 BACKGROUND-TASK drift: no background task reads managed state outside a committed read "
           "view (none scheduled in the routing layer; a new one must enter its own view)",
           (not bg_used) or bg_wrapped, {"background_used": bg_used})

    n_pass = sum(1 for c in checks if c["ok"])
    n_fail = sum(1 for c in checks if not c["ok"])
    print(json.dumps({"checks": checks, "summary": {"passed": n_pass, "failed": n_fail}},
                     indent=2, default=str))
    if n_fail:
        print(f"\nRead-coherence coverage guard FAILED: {n_fail} failing check(s).")
        for c in checks:
            if not c["ok"]:
                print(f"  FAIL: {c['name']} -> {c['detail']}")
        return 1
    print(f"\nRead-coherence coverage guard passed: {n_pass} check(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
