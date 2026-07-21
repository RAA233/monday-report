"""Guard for the GA client-mode environment generator.

``scripts/generate_ga_client_env.py`` produces the environment an operator uses
to run Monday Report in client mode. It previously had no test coverage at all,
and it omitted ``MONDAY_REPORT_AUDIT_HMAC_KEY``.

That omission was not cosmetic. In client mode the application fails CLOSED
without a valid active audit key:

  * ``main.py`` refuses every non-public request while
    ``store._active_audit_key_available()`` is false, and
  * ``store.audit()`` raises rather than append an unkeyed event.

So the official GA env file described an environment in which no protected route
could be served and no mutation could be recorded. This guard proves the
generated environment actually yields a usable, fail-closed-correct audit key,
and that the surrounding secrets are freshly generated rather than fixed.

Run: ``python scripts/ga_client_env_guard.py``  (wired as ``audit:ga-client-env``)
"""
from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "scripts"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

import generate_ga_client_env as gen  # noqa: E402
from backend.app import audit_keys  # noqa: E402

checks: list[dict] = []

# Variables the generated client-mode environment must define for the app to run
# at all. Each is load-bearing: omitting any one produces a silently unusable env.
REQUIRED_VARS = (
    "MONDAY_REPORT_CLIENT_DATA_MODE",
    "MONDAY_REPORT_API_KEY",
    "MONDAY_REPORT_SIGNING_SECRET",
    "MONDAY_REPORT_AUDIT_HMAC_KEY",
    "MONDAY_REPORT_AUDIT_HMAC_KEY_ID",
    "MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION",
    "MONDAY_REPORT_STATE_PATH",
    "MONDAY_REPORT_STORAGE_ROOT",
    "MONDAY_REPORT_EXPORT_ROOT",
    "MONDAY_REPORT_REPOSITORY_BACKEND",
    "MONDAY_REPORT_QUEUE_BACKEND",
    "MONDAY_REPORT_MALWARE_SCANNER",
)

KEY_VARS = (
    "MONDAY_REPORT_AUDIT_HMAC_KEY",
    "MONDAY_REPORT_AUDIT_HMAC_KEY_ID",
    "MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION",
)


def record(name: str, ok: bool, detail: object = "") -> None:
    checks.append({"name": name, "ok": bool(ok), "detail": detail})


def parse_env(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip()
    return out


def with_env(pairs: dict[str, str | None]):
    """Temporarily apply environment variables and reload the key provider."""
    saved = {k: os.environ.get(k) for k in pairs}

    class _Ctx:
        def __enter__(self):
            for k, v in pairs.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            importlib.reload(audit_keys)
            return audit_keys.audit_key_provider()

        def __exit__(self, *exc):
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            importlib.reload(audit_keys)
            return False

    return _Ctx()


def main() -> int:
    base = Path(tempfile.gettempdir()) / "mr-ga-env-guard"
    env_text = gen.build_env(base)
    env = parse_env(env_text)

    # --- 01-02: completeness ------------------------------------------------ #
    missing = [v for v in REQUIRED_VARS if v not in env]
    record("01 generated env defines every required client-mode variable", not missing, {"missing": missing})
    record("02 client data mode is client", env.get("MONDAY_REPORT_CLIENT_DATA_MODE") == "client",
           env.get("MONDAY_REPORT_CLIENT_DATA_MODE"))

    # --- 03-06: the audit key is real and usable ---------------------------- #
    key = env.get("MONDAY_REPORT_AUDIT_HMAC_KEY", "")
    record("03 audit HMAC key is present and non-empty", bool(key), {"length": len(key)})
    record("04 audit HMAC key meets the minimum key size",
           len(key.encode("utf-8")) >= audit_keys.MIN_KEY_BYTES,
           {"bytes": len(key.encode("utf-8")), "minimum": audit_keys.MIN_KEY_BYTES})
    record("05 audit key id is set", bool(env.get("MONDAY_REPORT_AUDIT_HMAC_KEY_ID")),
           env.get("MONDAY_REPORT_AUDIT_HMAC_KEY_ID"))
    version_raw = env.get("MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION", "")
    record("06 audit key version is a positive integer",
           version_raw.isdigit() and int(version_raw) >= 1, version_raw)

    # --- 07: the provider actually accepts the generated key ---------------- #
    with with_env({k: env.get(k) for k in KEY_VARS}) as provider:
        available = provider.is_available()
        metadata = provider.active_metadata()
    record("07 key provider accepts the generated key (client mode can serve requests)",
           available, {"available": available})
    record("08 active key metadata reports the generated id and version",
           bool(metadata) and metadata.get("key_id") == env["MONDAY_REPORT_AUDIT_HMAC_KEY_ID"]
           and str(metadata.get("key_version")) == version_raw,
           {k: metadata.get(k) for k in ("key_id", "key_version", "provider_type")} if metadata else None)
    record("09 active key metadata never carries the secret",
           bool(metadata) and key not in json.dumps(metadata, default=str), True)

    # --- 10: regression -- the previously shipped env was unusable ---------- #
    with with_env({k: None for k in KEY_VARS}) as provider:
        unavailable = not provider.is_available()
    record("10 REGRESSION: with no audit key the provider is unavailable "
           "(the shipped GA env failed closed on every protected route)", unavailable, True)

    # --- 11-13: secrets are generated, not fixed ---------------------------- #
    second = parse_env(gen.build_env(base))
    rotating = ("MONDAY_REPORT_API_KEY", "MONDAY_REPORT_SIGNING_SECRET", "MONDAY_REPORT_AUDIT_HMAC_KEY")
    repeated = [v for v in rotating if env.get(v) == second.get(v)]
    record("11 every generated secret differs between invocations (nothing hard-coded)",
           not repeated, {"repeated": repeated})
    placeholders = [v for v in rotating
                    if "replace-with" in env.get(v, "") or "changeme" in env.get(v, "").lower()]
    record("12 no placeholder secret is emitted", not placeholders, {"placeholders": placeholders})
    record("13 api key and audit key are distinct values",
           env.get("MONDAY_REPORT_API_KEY") != env.get("MONDAY_REPORT_AUDIT_HMAC_KEY"), True)

    # --- 14-15: the documented example stays in step ------------------------ #
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    record("14 .env.example documents the audit HMAC key",
           "MONDAY_REPORT_AUDIT_HMAC_KEY=" in example, True)
    record("15 .env.example documents key id and version",
           "MONDAY_REPORT_AUDIT_HMAC_KEY_ID=" in example
           and "MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION=" in example, True)
    # Split defensively: when the variable is absent entirely this check must report
    # a clean failure rather than raise IndexError.
    example_parts = example.split("MONDAY_REPORT_AUDIT_HMAC_KEY=", 1)
    example_value = example_parts[1].splitlines()[0] if len(example_parts) > 1 else None
    record("16 .env.example ships a placeholder, never a usable secret",
           example_value is not None and "replace-with" in example_value,
           {"value": example_value if example_value is not None else "<variable absent>"})

    # --- 17-18: behavioural -- run the generator and inspect what it emits --- #
    # A source-text scan would flag the prose line "This file contains generated
    # secrets", so actually execute the generator and compare its stdout against
    # the secret values it just wrote.
    import contextlib
    import io

    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ga.env"
        argv = sys.argv[:]
        sys.argv = ["generate_ga_client_env.py", "--output", str(out_path),
                    "--base-dir", str(Path(tmp) / "base")]
        buffer = io.StringIO()
        try:
            with contextlib.redirect_stdout(buffer):
                gen.main()
        finally:
            sys.argv = argv
        stdout = buffer.getvalue()
        written = parse_env(out_path.read_text(encoding="utf-8"))

    leaked = [name for name in rotating
              if written.get(name) and written[name] in stdout]
    record("17 generator stdout never contains a generated secret", not leaked, {"leaked_vars": leaked})
    record("18 generator writes a complete env file to the requested path",
           all(v in written for v in REQUIRED_VARS),
           {"missing": [v for v in REQUIRED_VARS if v not in written]})

    failed = [c for c in checks if not c["ok"]]
    print(json.dumps({"checks": checks,
                      "summary": {"passed": len(checks) - len(failed), "failed": len(failed)}},
                     indent=2, default=str))
    if failed:
        print(f"\nGA client env guard FAILED: {len(failed)} failing check(s).")
        for c in failed:
            print(f"  FAIL: {c['name']} -> {c['detail']}")
        return 1
    print(f"\nGA client env guard passed: {len(checks)} check(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
