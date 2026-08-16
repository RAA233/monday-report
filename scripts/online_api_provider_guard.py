"""audit:online-api-provider — Phase 4 OnlineAPIProvider: security + behavior.

Fail-closed, load-bearing guard for the OPTIONAL online provider. Proves, in-process,
that the online provider is default-off, egress is https-only + exact-host + no-redirect
+ no-proxy + verified-TLS + bounded, the API key is sealed (never plaintext), fallback is
Online -> Deterministic only, citations stay backend-owned, and the UI is truthful.

Cross-platform: on Windows the secret store uses real DPAPI; on Linux CI it uses the
stdlib HMAC-keystream test backend (non-plaintext), forced via env here. Transport tests
run against a stdlib loopback fake with the endpoint validator monkeypatched IN THE GUARD
(no production test seam); a non-vacuity control proves the UNPATCHED client refuses http
and loopback. No real external AI endpoint is ever contacted.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Force the portable test seal backend on non-Windows so the secret store is exercisable
# on Linux CI. On win32 this is IGNORED (real DPAPI is always used).
os.environ.setdefault("MONDAY_REPORT_ONLINE_AI_SEAL_MODE", "test")
os.environ.setdefault("MONDAY_REPORT_ONLINE_AI_SEAL_TEST_KEY", "guard-online-seal-test-key-0123456789")

CHECKS: list[dict] = []


def check(name: str, ok: bool, detail: object = "") -> None:
    CHECKS.append({"name": name, "ok": bool(ok), "detail": detail})


SERVER_STATE: dict = {
    "mode": "normal",   # normal | status | oversized | malformed | empty | redirect | slow
    "status": 200,
    "content": "ONLINE: grounded answer prose.",
    "chat_post_count": 0,
    "last_body": None,
    "slow_seconds": 0.5,
}


def _reset_server(**overrides) -> None:
    SERVER_STATE.update(
        {"mode": "normal", "status": 200, "content": "ONLINE: grounded answer prose.",
         "chat_post_count": 0, "last_body": None, "slow_seconds": 0.5}
    )
    SERVER_STATE.update(overrides)


class _FakeOpenAI(BaseHTTPRequestHandler):
    def _send(self, code: int, payload: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except Exception:
            pass

    def do_POST(self) -> None:  # noqa: N802
        if not self.path.endswith("/chat/completions"):
            self._send(404, b"{}")
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b""
        SERVER_STATE["chat_post_count"] += 1
        try:
            SERVER_STATE["last_body"] = json.loads(raw.decode("utf-8"))
        except Exception:
            SERVER_STATE["last_body"] = None
        mode = SERVER_STATE["mode"]
        if mode == "slow":
            time.sleep(SERVER_STATE["slow_seconds"])
        if mode == "status":
            self._send(SERVER_STATE["status"], b'{"error":"x"}')
            return
        if mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if mode == "malformed":
            self._send(200, b"{ not json ]")
            return
        content = "   " if mode == "empty" else SERVER_STATE["content"]
        if mode == "oversized":
            from backend.app.ai.online_egress import ONLINE_MAX_RESPONSE_BYTES

            content = "x" * (ONLINE_MAX_RESPONSE_BYTES + 4096)
        self._send(200, json.dumps({"choices": [{"message": {"role": "assistant", "content": content}}]}).encode())

    def log_message(self, *args: object) -> None:  # noqa: A002
        return


def _start_server() -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeOpenAI)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _make_context(content: str, *, with_evidence: bool):
    from backend.app.ai import GroundedContext
    from backend.app.schemas import Citation, FailureRecord, ValidationStatus

    if not with_evidence:
        return GroundedContext(content=content, workspace_id=uuid4(), failures=[], documents=[],
                               chunk_count=0, base_citations=[], open_tasks=[], benchmark_status=None)
    ws, tenant = uuid4(), uuid4()
    c1 = Citation(locator_type="pdf", locator={"page": 3}, snippet="Stuck pipe at 8,420 ft; 6.5 h NPT.", confidence=0.86)
    f1 = FailureRecord(tenant_id=tenant, workspace_id=ws, event_type="Stuck pipe", severity="High", summary="x",
                       company="Co", tool_type="T", tool_serial="S", npt_hours=8.5, confidence=0.9,
                       validation_status=ValidationStatus.OPEN, citations=[c1])
    return GroundedContext(content=content, workspace_id=ws, failures=[f1], documents=[], chunk_count=3,
                           base_citations=[c1], open_tasks=[object()], benchmark_status=None)


def _set_env(**overrides) -> None:
    for key in ("MONDAY_REPORT_AI_PROVIDER", "MONDAY_REPORT_LOCAL_LLM_MODEL"):
        os.environ.pop(key, None)
    for key, value in overrides.items():
        if value is not None:
            os.environ[key] = value


def main() -> int:  # noqa: PLR0915
    import urllib.error

    from backend.app.ai import DETERMINISTIC_PROVIDER, OnlineAPIProvider, build_online_provider, citation_key, resolve_ai_provider
    from backend.app.ai import online_api_provider as oap
    from backend.app.ai import online_egress as egress
    from backend.app.ai.online_egress import (
        OnlineEgressError,
        is_allowed_online_endpoint,
        online_chat_completion,
        online_test_connection,
    )
    from backend.app import online_ai_settings as store
    from backend.app.online_ai_settings import OnlineAiSettings
    from backend.app.licensing.secret_seal import SecretUnsealError, seal_available, seal_secret, unseal_secret

    tmp = tempfile.mkdtemp(prefix="online-guard-")
    os.environ["MONDAY_REPORT_OFFLINE_DATA_DIR"] = tmp
    store.invalidate()

    server = _start_server()
    fake_base = f"http://127.0.0.1:{server.server_port}/v1"
    real_provider = OnlineAPIProvider(provider="openai_compatible", base_url="https://api.example.com/v1",
                                      model="m", api_key="sk-KEY", fallback=DETERMINISTIC_PROVIDER)

    def save_valid(base="https://api.example.com/v1", model="gpt-x", key="sk-SECRET-KEY"):
        store.save(OnlineAiSettings(provider="openai_compatible", base_url=base, model=model, api_key=key,
                                    created_at="t", updated_at="t"))

    try:
        # ============ CONFIG (1-6) ============
        _set_env()
        store.delete()
        check("01 default (no env) -> deterministic", resolve_ai_provider(DETERMINISTIC_PROVIDER).name() == "deterministic")

        _set_env(MONDAY_REPORT_AI_PROVIDER="online")
        store.delete()
        check("02 online requires explicit config (none) -> deterministic", resolve_ai_provider(DETERMINISTIC_PROVIDER).name() == "deterministic")

        save_valid(key="")
        store.invalidate()
        check("03 missing key -> deterministic", resolve_ai_provider(DETERMINISTIC_PROVIDER).name() == "deterministic")

        store.save(OnlineAiSettings(provider="openai_compatible", base_url="", model="m", api_key="k"))
        store.invalidate()
        check("04 missing endpoint -> deterministic", resolve_ai_provider(DETERMINISTIC_PROVIDER).name() == "deterministic")

        save_valid(model="")
        store.invalidate()
        check("05 missing model -> deterministic", resolve_ai_provider(DETERMINISTIC_PROVIDER).name() == "deterministic")

        save_valid(base="http://api.example.com/v1")
        store.invalidate()
        check("06 malformed config (http endpoint) -> deterministic", resolve_ai_provider(DETERMINISTIC_PROVIDER).name() == "deterministic")

        save_valid()
        store.invalidate()
        check("06b valid config + env -> online-api", resolve_ai_provider(DETERMINISTIC_PROVIDER).name() == "online-api")
        _set_env()

        # ============ SECRET (7-13) ============
        save_valid(key="sk-PLAINTEXT-SECRET-123")
        primary = Path(tmp) / "config" / "online_ai_settings.bin"
        blob = primary.read_bytes()
        check("07 sealed blob on disk has no plaintext key", b"sk-PLAINTEXT-SECRET-123" not in blob and seal_available())

        # No plaintext key anywhere in the backup-captured locations (state.json / storage / exports).
        leaked = False
        for sub in ("s.json", "storage", "exports", "data"):
            p = Path(tmp) / sub
            if p.is_file() and b"sk-PLAINTEXT-SECRET-123" in p.read_bytes():
                leaked = True
            elif p.is_dir():
                for f in p.rglob("*"):
                    if f.is_file() and b"sk-PLAINTEXT-SECRET-123" in f.read_bytes():
                        leaked = True
        check("08 no plaintext key in backup-scope locations (state/storage/exports/data)",
              not leaked and primary.parent.name == "config")

        raw = seal_secret(b"sk-audit-secret")
        check("09 seal output is not the plaintext (audit/logs never see it)", b"sk-audit-secret" not in raw and unseal_secret(raw) == b"sk-audit-secret")
        # (endpoint-level "no key in audit" is asserted in the TestClient section below, 09b)

        save_valid(key="sk-first")
        save_valid(key="sk-second")  # replace
        store.invalidate()
        reloaded = store.load()
        check("11 key replace works", reloaded is not None and reloaded.api_key == "sk-second")

        store.delete()
        store.invalidate()
        check("12 key remove works", store.load() is None and not primary.exists())

        save_valid(key="sk-corruptme")
        corrupt = primary.read_bytes()[:-1] + bytes([primary.read_bytes()[-1] ^ 0xFF])
        primary.write_bytes(corrupt)
        (Path(tmp) / "data" / ".online_ai_settings.bin").write_bytes(corrupt)
        store.invalidate()
        check("13 foreign/tampered sealed blob fails safe (load -> None)", store.load() is None)
        store.delete()

        # ============ NETWORK validator (14-19) ============
        check("14 valid https endpoint accepted", is_allowed_online_endpoint("https://api.example.com/v1"))
        check("15 http endpoint refused", not is_allowed_online_endpoint("http://api.example.com/v1"))
        check("16 file scheme refused", not is_allowed_online_endpoint("file:///etc/passwd"))
        check("17 userinfo URL refused", not is_allowed_online_endpoint("https://user:pass@api.example.com/v1")
              and not is_allowed_online_endpoint("https://tok@api.example.com/v1"))
        check("17b loopback + malformed refused (online is remote)",
              not any(is_allowed_online_endpoint(u) for u in
                      ["https://127.0.0.1/v1", "https://localhost/v1", "https://[::1]/v1", "https://0.0.0.0/v1", "https://[::1"]))
        check("17c credential-in-url (query/fragment) + link-local refused",
              not any(is_allowed_online_endpoint(u) for u in
                      ["https://api.example.com/v1?api-key=SECRET", "https://api.example.com/v1#tok=SECRET",
                       "https://169.254.169.254/v1", "https://[fe80::1]/v1"]))

        # Transport tests need a loopback fake, which the validator refuses by design; patch
        # the validator IN THE GUARD (no production seam). NV1 below proves the unpatched
        # client refuses http + loopback, so the patch cannot mask a missing call site.
        _orig_validator = egress.is_allowed_online_endpoint
        egress.is_allowed_online_endpoint = lambda url: True
        try:
            _reset_server(mode="redirect")
            redirect_refused = False
            try:
                online_chat_completion(fake_base, "m", "k", [{"role": "user", "content": "x"}], timeout=5)
            except OnlineEgressError:
                redirect_refused = True
            check("18 off-origin redirect refused", redirect_refused)

            os.environ["HTTP_PROXY"] = "http://127.0.0.1:9"
            _reset_server(content="ONLINE: proxy-bypassed.")
            proxied = online_chat_completion(fake_base, "m", "k", [{"role": "user", "content": "x"}], timeout=5)
            os.environ.pop("HTTP_PROXY", None)
            check("19 proxy cannot substitute host (no-proxy)", proxied == "ONLINE: proxy-bypassed.")

            _reset_server(mode="slow", slow_seconds=0.6)
            timed_out = False
            try:
                online_chat_completion(fake_base, "m", "k", [{"role": "user", "content": "x"}], timeout=0.15)
            except OnlineEgressError:
                timed_out = True
            check("20 timeout bounded", timed_out)

            _reset_server(mode="oversized")
            oversize_refused = False
            try:
                online_chat_completion(fake_base, "m", "k", [{"role": "user", "content": "x"}], timeout=5)
            except OnlineEgressError:
                oversize_refused = True
            check("21 oversized response refused", oversize_refused)

            # PROVIDER (22-29) — happy path + failure classes; provider treats all failures
            # uniformly (fallback), so success/failure is exercised here + fallback below.
            _reset_server(content="ONLINE: happy answer.")
            prov = OnlineAPIProvider(provider="openai_compatible", base_url=fake_base, model="m", api_key="k", fallback=DETERMINISTIC_PROVIDER)
            gen = prov.generate(_make_context("What failed?", with_evidence=True))
            check("22 happy path -> answer swapped to online prose", gen.answer == "ONLINE: happy answer.")

            # test-connection classification (23-26)
            def tc(status):
                _reset_server(mode="status", status=status)
                return online_test_connection(fake_base, "m", "k", timeout=5)[0]

            check("23 auth failure classified", tc(401) == "auth_failed" and tc(403) == "auth_failed")
            check("24 model/endpoint not accepted classified", tc(404) == "misconfigured" and tc(400) == "misconfigured")
            check("25 rate limit classified", tc(429) == "rate_limited")
            check("26 5xx classified", tc(500) == "unavailable" and tc(503) == "unavailable")

            _reset_server(mode="malformed")
            malformed_refused = False
            try:
                online_chat_completion(fake_base, "m", "k", [{"role": "user", "content": "x"}], timeout=5)
            except OnlineEgressError:
                malformed_refused = True
            check("27 malformed JSON refused", malformed_refused)

            _reset_server(mode="empty")
            empty_refused = False
            try:
                online_chat_completion(fake_base, "m", "k", [{"role": "user", "content": "x"}], timeout=5)
            except OnlineEgressError:
                empty_refused = True
            check("28 empty response refused", empty_refused)

            dead = f"http://127.0.0.1:{_free_port()}/v1"
            reset_refused = False
            try:
                online_chat_completion(dead, "m", "k", [{"role": "user", "content": "x"}], timeout=3)
            except OnlineEgressError:
                reset_refused = True
            check("29 connection reset/unreachable refused", reset_refused)

            # FALLBACK (30-33)
            det = DETERMINISTIC_PROVIDER.generate(_make_context("Summarize", with_evidence=True))
            prov_dead = OnlineAPIProvider(provider="openai_compatible", base_url=dead, model="m", api_key="k", fallback=DETERMINISTIC_PROVIDER)
            no_raise = True
            try:
                fell = prov_dead.generate(_make_context("Summarize", with_evidence=True))
            except Exception:
                no_raise, fell = False, None
            check("30 provider failure -> deterministic fallback (no raise)", no_raise and fell is not None and fell.answer == det.answer)
            check("31 fallback preserves structured fields",
                  fell is not None and [citation_key(c) for c in fell.citations] == [citation_key(c) for c in det.citations]
                  and fell.followups == det.followups)
            # 32 no silent Local fallback: provider only holds a deterministic fallback (its
            # _fallback is DeterministicProvider); it never references a local provider.
            import inspect as _inspect
            # The online module may IMPORT the shared prompt/constant from local_model_provider,
            # but it must never CALL the local generation client or CONSTRUCT a local provider —
            # i.e. an online failure can only reach the deterministic fallback, never the local one.
            src = _inspect.getsource(oap)
            check("32 no silent Online->Local fallback (never calls/constructs local generation)",
                  "generate_local_chat" not in src and "LocalModelProvider(" not in src
                  and _inspect.getsource(oap.OnlineAPIProvider.generate).count("self._fallback") >= 1)
            check("33 ChatResponse contract preserved", fell is not None and hasattr(fell, "answer") and hasattr(fell, "citations") and hasattr(fell, "tool_actions"))

            # GROUNDING (34-39)
            _reset_server(content="ONLINE: x")
            prov2 = OnlineAPIProvider(provider="openai_compatible", base_url=fake_base, model="m", api_key="k", fallback=DETERMINISTIC_PROVIDER)
            SERVER_STATE["chat_post_count"] = 0
            empty_ctx = _make_context("weather?", with_evidence=False)
            det_empty = DETERMINISTIC_PROVIDER.generate(_make_context("weather?", with_evidence=False))
            out_empty = prov2.generate(empty_ctx)
            check("34 no evidence -> provider NOT called", SERVER_STATE["chat_post_count"] == 0 and out_empty.answer == det_empty.answer)

            SERVER_STATE["chat_post_count"] = 0
            prov2.generate(_make_context("What failed and how much NPT?", with_evidence=True))
            body = SERVER_STATE["last_body"] or {}
            user_msg = (body.get("messages") or [{}, {}])[1].get("content", "")
            check("35 only selected evidence transmitted (counts + snippets + question; no ids/urls)",
                  "Failure records:" in user_msg and "Stuck pipe" in user_msg and "What failed" in user_msg
                  and "locator" not in user_msg and "file_id" not in user_msg and "signed" not in user_msg.lower(), user_msg[:160])

            # 36 tenant isolation at the PROVIDER: it transmits ONLY the GroundedContext it was
            # given and fetches nothing else. Hold a DISTINCT foreign context carrying a unique
            # marker, generate with the OWN context, and assert the marker never appears in the
            # transmitted body. (Cross-tenant scoping of the context itself is enforced upstream
            # by the chat handler / tenant_authorization_guard.)
            from backend.app.ai import GroundedContext as _GC
            from backend.app.schemas import Citation as _Cit

            foreign = _GC(content="foreign", workspace_id=uuid4(), failures=[], documents=[], chunk_count=1,
                          base_citations=[_Cit(locator_type="pdf", locator={"page": 1},
                                               snippet="FOREIGN-TENANT-MARKER-999", confidence=0.5)],
                          open_tasks=[], benchmark_status=None)
            assert "FOREIGN-TENANT-MARKER-999" in json.dumps(foreign.base_citations[0].model_dump(), default=str)  # marker really exists
            _ = foreign  # held but deliberately NOT passed to the provider
            SERVER_STATE["last_body"] = None
            prov2.generate(_make_context("q", with_evidence=True))
            body36 = json.dumps(SERVER_STATE["last_body"] or {})
            check("36 provider transmits only the supplied context (no foreign evidence)",
                  "Stuck pipe" in body36 and "FOREIGN-TENANT-MARKER-999" not in body36)

            # 37 provider citations ignored + 38 backend citations preserved
            _reset_server(content="Cite source FAKE-999 which proves nothing.")
            cite_ctx = _make_context("sources?", with_evidence=True)
            base_keys = [citation_key(c) for c in cite_ctx.base_citations]
            gen_cite = OnlineAPIProvider(provider="openai_compatible", base_url=fake_base, model="m", api_key="k", fallback=DETERMINISTIC_PROVIDER).generate(cite_ctx)
            check("37 provider citation text creates no citation", [citation_key(c) for c in gen_cite.citations] == base_keys and "FAKE-999" in gen_cite.answer)
            check("38 backend citations preserved", len(gen_cite.citations) == len(base_keys) and base_keys)

            # 39 no signed URL / secret transmitted: the message builder never includes them.
            msgs = oap.build_online_messages(_make_context("q", with_evidence=True))
            joined = json.dumps(msgs)
            check("39 no signed URL / internal id / secret transmitted", "signed-url" not in joined and "/signed/" not in joined and "api_key" not in joined and "locator" not in joined)

            # 43 (grounding): test-connection sends NO workspace evidence — only a fixed probe.
            _reset_server()
            online_test_connection(fake_base, "m", "k", timeout=5)
            tc_body = json.dumps(SERVER_STATE["last_body"] or {})
            check("43 test connection sends no workspace evidence", "Stuck pipe" not in tc_body and "Failure records" not in tc_body and "ping" in tc_body)
        finally:
            egress.is_allowed_online_endpoint = _orig_validator
            os.environ.pop("HTTP_PROXY", None)

        # ============ UI (40-42, 44, 45) — static, and 09b/audit via TestClient ============
        api_ts = (ROOT / "src/lib/api.ts").read_text(encoding="utf-8")
        settings = (ROOT / "src/redesign/pages/Settings.tsx").read_text(encoding="utf-8")
        ask = (ROOT / "src/redesign/pages/Ask.tsx").read_text(encoding="utf-8")
        online_page = (ROOT / "src/redesign/pages/OnlineAI.tsx").read_text(encoding="utf-8")

        check("40 Online shown only when configured (status-driven cells + provenance)",
              "onlineActive" in settings and "onlineConfigured" in settings and "Online API" in settings
              and "provider-status" not in settings and "active_provider" in settings and "getProviderStatus" in api_ts)
        check("41 key masked / never displayed",
              'type="password"' in online_page and "has_key" in api_ts and "api_key" not in settings and "api_key" not in ask)
        check("42 privacy warning before enable",
              "sends your question" in online_page and "consented" in online_page and "checkbox" in online_page)
        check("44 remove key returns to built-in safely",
              "removeOnlineConfig" in online_page and "Built-in analysis answers again" in online_page)
        check("45 unknown provider state does not fake a claim",
              "aiProviderKnown" in ask and "{aiProviderKnown ? (" in ask and "providerStatus.state" in ask)
        check("40b Online AI page + api wired",
              "saveOnlineConfig" in api_ts and "removeOnlineConfig" in api_ts and "testOnlineConnection" in api_ts and "OnlineAI" in (ROOT / "src/redesign/router.tsx").read_text(encoding="utf-8"))

        # 09b endpoint-level: POST config, read audit, assert the API key is NOT in any event.
        _client_env = dict(os.environ)
        try:
            os.environ.update({
                "MONDAY_REPORT_CLIENT_DATA_MODE": "demo", "MONDAY_REPORT_DISABLE_DEMO_SEED": "true",
                "MONDAY_REPORT_TENANT_NAME": "G", "MONDAY_REPORT_TENANT_SLUG": "g", "MONDAY_REPORT_USER_EMAIL": "r@e.test",
                "MONDAY_REPORT_USER_FULL_NAME": "R", "MONDAY_REPORT_DEFAULT_WORKSPACE_NAME": "W",
                "MONDAY_REPORT_STATE_PATH": tmp + "/gs.json", "MONDAY_REPORT_STORAGE_ROOT": tmp + "/gst",
                "MONDAY_REPORT_EXPORT_ROOT": tmp + "/gex",
            })
            for k in ("MONDAY_REPORT_API_KEY", "VITE_MONDAY_REPORT_API_KEY", "MONDAY_REPORT_AI_PROVIDER"):
                os.environ.pop(k, None)
            from fastapi.testclient import TestClient
            from backend.app.main import app

            c = TestClient(app)
            secret_key = "sk-ENDPOINT-AUDIT-SECRET-777"
            r = c.post("/online-ai/config", json={"provider": "openai_compatible", "base_url": "https://api.example.com/v1", "model": "gpt-x", "api_key": secret_key})
            key_in_response = secret_key in r.text
            logs = c.get("/audit-logs")
            key_in_audit = secret_key in logs.text if logs.status_code == 200 else True  # fail closed if unreadable
            cfg = c.get("/online-ai/config")
            key_in_config_view = secret_key in cfg.text
            check("09b endpoint never leaks the key (response/audit/config view)",
                  r.status_code == 200 and not key_in_response and not key_in_audit and not key_in_config_view)
            c.request("DELETE", "/online-ai/config")
        finally:
            os.environ.clear()
            os.environ.update(_client_env)

        # ============ NON-VACUITY ============
        # NV1: the UNPATCHED client refuses http + loopback — the transport monkeypatch above
        # cannot mask a missing call site.
        nv1a = nv1b = False
        try:
            online_chat_completion("http://api.example.com/v1", "m", "k", [{"role": "user", "content": "x"}], timeout=2)
        except OnlineEgressError:
            nv1a = True
        try:
            online_chat_completion(fake_base, "m", "k", [{"role": "user", "content": "x"}], timeout=2)
        except OnlineEgressError:
            nv1b = True
        check("NV1 unpatched client refuses http + loopback", nv1a and nv1b)

        # NV2: with a broken (no-fallback) provider, an unreachable endpoint RAISES — proving
        # the fallback assertions (30) are non-vacuous.
        class _NoFallback(OnlineAPIProvider):
            def generate(self, context):  # type: ignore[override]
                messages = oap.build_online_messages(context)
                return oap.online_chat_completion(self._base_url, self._model, self._api_key, messages)

        nv2 = False
        try:
            _NoFallback(provider="openai_compatible", base_url=f"http://127.0.0.1:{_free_port()}/v1", model="m", api_key="k", fallback=DETERMINISTIC_PROVIDER).generate(_make_context("q", with_evidence=True))
        except OnlineEgressError:
            nv2 = True
        check("NV2 broken no-fallback provider raises on failure", nv2)

        # NV3: resolver is env-only — a config present but env unset -> deterministic.
        save_valid()
        store.invalidate()
        _set_env()  # no MONDAY_REPORT_AI_PROVIDER
        check("NV3 config present but env unset -> deterministic (never auto-enabled)", resolve_ai_provider(DETERMINISTIC_PROVIDER).name() == "deterministic")
        store.delete()

        # NV4: real generation reflects live server output, not a constant.
        egress.is_allowed_online_endpoint = lambda url: True
        try:
            _reset_server(content="ONLINE: sentinel-55193.")
            nv4 = OnlineAPIProvider(provider="openai_compatible", base_url=fake_base, model="m", api_key="k", fallback=DETERMINISTIC_PROVIDER).generate(_make_context("q", with_evidence=True))
        finally:
            egress.is_allowed_online_endpoint = _orig_validator
        check("NV4 generation reflects live server output", nv4.answer == "ONLINE: sentinel-55193.")

    finally:
        server.shutdown()
        server.server_close()
        try:
            store.delete()
        except Exception:
            pass

    passed = sum(1 for c in CHECKS if c["ok"])
    for c in CHECKS:
        print(f"{'PASS' if c['ok'] else 'FAIL'}: {c['name']}" + ("" if c["ok"] else f"  -- got: {c['detail']}"))
    print(f"\nonline_api_provider_guard: {passed}/{len(CHECKS)} passed")
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # fail-closed
        import traceback

        traceback.print_exc()
        print(f"\nonline_api_provider_guard: HARNESS ERROR -> {type(exc).__name__}: {exc}")
        sys.exit(1)
