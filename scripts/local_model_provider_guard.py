"""audit:local-model-provider — Phase 3 LocalModelProvider: security + behavior.

Fail-closed, load-bearing guard for the local-model answer path. Proves, in-process
against a stdlib fake loopback Ollama (no model download, no real runtime, no external
network), that:

  * SELECTION is server/operator-controlled: only an explicit process-environment value
    plus a valid loopback endpoint plus an explicitly-named model activates the local
    model; nothing from a request/payload participates; anything else -> deterministic.
  * The endpoint is LOOPBACK-ONLY and the transport is NO-PROXY.
  * GENERATION replaces only the answer prose; every structured field (and every
    citation) stays exactly as the deterministic provider produced it.
  * FALLBACK is total: insufficient evidence -> model never called; any runtime / endpoint
    / timeout / transport / oversized / malformed / empty failure -> deterministic answer,
    never a raise (only a deterministic-provider failure surfaces).
  * CITATIONS are never model-produced and out-of-set ids cannot escape validation.
  * The Settings / Ask surfaces reflect the resolver's decision truthfully.

Ends with mutation / non-vacuity checks: a deliberately-broken variant must FAIL the same
assertions the real provider passes, proving the battery is not vacuous.
"""
from __future__ import annotations

import inspect
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CHECKS: list[dict] = []


def check(name: str, ok: bool, detail: object = "") -> None:
    CHECKS.append({"name": name, "ok": bool(ok), "detail": detail})


# --- stdlib fake loopback Ollama -------------------------------------------------

SERVER_STATE: dict = {
    "mode": "normal",  # normal | oversized | malformed | empty | error500 | slow | citations_field
    "content": "MODEL: grounded answer prose derived from the supplied evidence.",
    "models": ["qwen2.5:3b"],
    "last_chat_body": None,
    "chat_post_count": 0,
    "slow_seconds": 0.4,
}


def _reset_server(**overrides) -> None:
    SERVER_STATE.update(
        {
            "mode": "normal",
            "content": "MODEL: grounded answer prose derived from the supplied evidence.",
            "models": ["qwen2.5:3b"],
            "last_chat_body": None,
            "chat_post_count": 0,
            "slow_seconds": 0.4,
        }
    )
    SERVER_STATE.update(overrides)


class _FakeOllama(BaseHTTPRequestHandler):
    def _send(self, code: int, payload: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except Exception:
            pass

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/api/tags":
            self._send(200, json.dumps({"models": [{"name": n} for n in SERVER_STATE["models"]]}).encode())
        elif self.path == "/v1/models":  # lm_studio / openai-compatible
            self._send(200, json.dumps({"data": [{"id": n} for n in SERVER_STATE["models"]]}).encode())
        else:
            self._send(404, b"{}")

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in ("/api/chat", "/v1/chat/completions"):
            self._send(404, b"{}")
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b""
        SERVER_STATE["chat_post_count"] += 1
        try:
            SERVER_STATE["last_chat_body"] = json.loads(raw.decode("utf-8"))
        except Exception:
            SERVER_STATE["last_chat_body"] = None

        mode = SERVER_STATE["mode"]
        if mode == "slow":
            time.sleep(SERVER_STATE["slow_seconds"])
        if mode == "redirect":
            # Bounce to a different (off-endpoint) host to prove redirects are not followed.
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/redirected")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if mode == "error500":
            self._send(500, b'{"error":"boom"}')
            return
        if mode == "malformed":
            self._send(200, b"{ this is : not json ]")
            return
        if mode == "oversized":
            from backend.app.local_ai import LOCAL_GEN_MAX_RESPONSE_BYTES

            big = "x" * (LOCAL_GEN_MAX_RESPONSE_BYTES + 4096)
            self._send(200, json.dumps({"message": {"role": "assistant", "content": big}}).encode())
            return
        # Shape the successful body for the runtime that posted (ollama vs openai-compatible).
        content = "   " if mode == "empty" else SERVER_STATE["content"]
        if self.path == "/v1/chat/completions":
            body: dict = {"choices": [{"message": {"role": "assistant", "content": content}}]}
        else:
            body = {"message": {"role": "assistant", "content": content}, "done": True}
        if mode == "citations_field":
            body["citations"] = [{"id": "FABRICATED-999", "snippet": "not grounded"}]
        self._send(200, json.dumps(body).encode())

    def log_message(self, *args: object) -> None:  # noqa: A002
        return


def _start_server() -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeOllama)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


# --- grounded-context fixtures ---------------------------------------------------

def _make_context(content: str, *, with_evidence: bool):
    from backend.app.ai import GroundedContext
    from backend.app.schemas import Citation, FailureRecord, ValidationStatus

    if not with_evidence:
        return GroundedContext(
            content=content,
            workspace_id=uuid4(),
            failures=[],
            documents=[],
            chunk_count=0,
            base_citations=[],
            open_tasks=[],
            benchmark_status=None,
        )
    ws = uuid4()
    tenant = uuid4()
    c1 = Citation(
        locator_type="pdf",
        locator={"page": 3, "section": "daily drilling report"},
        snippet="Stuck pipe at 8,420 ft created 6.5 h of NPT while drilling ahead.",
        confidence=0.86,
    )
    f1 = FailureRecord(
        tenant_id=tenant, workspace_id=ws, event_type="Stuck pipe", severity="High",
        summary="Stuck pipe event.", company="Anonymized Directional Services",
        tool_type="Drill string", tool_serial="DS-01", npt_hours=8.5, confidence=0.9,
        validation_status=ValidationStatus.OPEN, citations=[c1],
    )
    f2 = FailureRecord(
        tenant_id=tenant, workspace_id=ws, event_type="Surface equipment", severity="Low",
        summary="Minor surface equipment event.", company="Rig Operations",
        tool_type="Surface", tool_serial="SE-01", npt_hours=1.0, confidence=0.8,
        validation_status=ValidationStatus.OPEN, citations=[],
    )
    return GroundedContext(
        content=content,
        workspace_id=ws,
        failures=[f1, f2],
        documents=[],
        chunk_count=3,
        base_citations=[c1],
        open_tasks=[object()],  # only len() is read by the deterministic provider
        benchmark_status=None,
    )


def _set_local_env(**overrides) -> None:
    for key in ("MONDAY_REPORT_AI_PROVIDER", "MONDAY_REPORT_LOCAL_LLM_RUNTIME", "OLLAMA_HOST",
                "LM_STUDIO_BASE_URL", "MONDAY_REPORT_LOCAL_LLM_MODEL"):
        os.environ.pop(key, None)
    for key, value in overrides.items():
        if value is not None:
            os.environ[key] = value


def main() -> int:  # noqa: PLR0915 - one linear battery
    import urllib.request

    from backend.app.ai import (
        DETERMINISTIC_PROVIDER,
        GroundedContext,
        LocalModelProvider,
        build_grounded_messages,
        citation_key,
        resolve_ai_provider,
        validate_citations,
    )
    from backend.app.ai.local_model_provider import SYSTEM_PROMPT
    from backend.app.local_ai import (
        LOCAL_GEN_NUM_PREDICT,
        LocalGenerationError,
        _no_proxy_opener,
        generate_local_chat,
        is_loopback_endpoint,
        probe_local_generation,
    )
    from backend.app.schemas import ChatRequest, Citation

    server = _start_server()
    endpoint = f"http://127.0.0.1:{server.server_port}"

    def make_provider(ep: str = endpoint, model: str = "qwen2.5:3b") -> LocalModelProvider:
        return LocalModelProvider(runtime="ollama", endpoint=ep, model=model, fallback=DETERMINISTIC_PROVIDER)

    try:
        # ============ CONFIG / SECURITY (1-10) ============
        _set_local_env()
        check("01 default resolver is deterministic", resolve_ai_provider(DETERMINISTIC_PROVIDER).name() == "deterministic")

        _set_local_env(MONDAY_REPORT_AI_PROVIDER="local", MONDAY_REPORT_LOCAL_LLM_RUNTIME="ollama",
                       OLLAMA_HOST="http://127.0.0.1:11434")
        check("02 local mode without a model stays deterministic",
              resolve_ai_provider(DETERMINISTIC_PROVIDER).name() == "deterministic")

        _set_local_env(MONDAY_REPORT_AI_PROVIDER="local", MONDAY_REPORT_LOCAL_LLM_RUNTIME="ollama",
                       OLLAMA_HOST="http://127.0.0.1:11434", MONDAY_REPORT_LOCAL_LLM_MODEL="qwen2.5:3b")
        p = resolve_ai_provider(DETERMINISTIC_PROVIDER)
        check("03 valid local config selects local-model", p.name() == "local-model" and isinstance(p, LocalModelProvider))

        _set_local_env(MONDAY_REPORT_AI_PROVIDER="local", MONDAY_REPORT_LOCAL_LLM_RUNTIME="ollama",
                       OLLAMA_HOST="http://192.168.1.50:11434", MONDAY_REPORT_LOCAL_LLM_MODEL="qwen2.5:3b")
        check("04 LAN endpoint is refused -> deterministic", resolve_ai_provider(DETERMINISTIC_PROVIDER).name() == "deterministic")

        _set_local_env(MONDAY_REPORT_AI_PROVIDER="local", MONDAY_REPORT_LOCAL_LLM_RUNTIME="ollama",
                       OLLAMA_HOST="http://172.17.0.1:11434", MONDAY_REPORT_LOCAL_LLM_MODEL="qwen2.5:3b")
        check("05 docker-bridge endpoint is refused -> deterministic", resolve_ai_provider(DETERMINISTIC_PROVIDER).name() == "deterministic")

        _set_local_env(MONDAY_REPORT_AI_PROVIDER="local", MONDAY_REPORT_LOCAL_LLM_RUNTIME="ollama",
                       OLLAMA_HOST="ftp://127.0.0.1:11434", MONDAY_REPORT_LOCAL_LLM_MODEL="qwen2.5:3b")
        check("06 non-http scheme is refused -> deterministic", resolve_ai_provider(DETERMINISTIC_PROVIDER).name() == "deterministic")

        # Malformed authority (unclosed IPv6 bracket) must fail closed to deterministic, not
        # raise out of the resolver into the chat handler.
        _set_local_env(MONDAY_REPORT_AI_PROVIDER="local", MONDAY_REPORT_LOCAL_LLM_RUNTIME="ollama",
                       OLLAMA_HOST="http://[::1:11434", MONDAY_REPORT_LOCAL_LLM_MODEL="qwen2.5:3b")
        malformed_raised = False
        malformed_provider = None
        try:
            malformed_provider = resolve_ai_provider(DETERMINISTIC_PROVIDER)
        except Exception:
            malformed_raised = True
        check("06b malformed endpoint env -> deterministic (resolver never raises)",
              not malformed_raised and malformed_provider is not None and malformed_provider.name() == "deterministic")
        _set_local_env()

        check("07 is_loopback accepts loopback forms",
              all(is_loopback_endpoint(u) for u in [
                  "http://127.0.0.1:11434", "http://localhost:11434", "http://[::1]:11434",
                  "http://127.0.0.2:11434", "http://user@127.0.0.1:11434"]))
        check("08 is_loopback rejects non-loopback + malformed forms (no raise)",
              not any(is_loopback_endpoint(u) for u in [
                  "http://192.168.1.5:11434", "http://10.0.0.9", "http://172.17.0.1:11434",
                  "http://evil.com", "http://127.0.0.1.evil.com", "file:///etc/passwd",
                  "ftp://127.0.0.1", "", "not-a-url",
                  "http://[::1:11434", "http://[::1", "http://[gggg::1]:11434"]))

        sig = inspect.signature(resolve_ai_provider)
        no_request_field = "provider" not in ChatRequest.model_fields and "endpoint" not in ChatRequest.model_fields
        check("09 provider selection is env-only (no request/payload lever)",
              list(sig.parameters) == ["default"] and no_request_field,
              {"params": list(sig.parameters), "request_clean": no_request_field})

        # With a proxy configured in the environment, the DEFAULT opener carries a live
        # ProxyHandler (it would dispatch through the proxy); our no-proxy opener passes an
        # empty ProxyHandler, which build_opener drops (no <proto>_open methods), so it
        # performs NO proxy dispatch. Setting the env here makes the discrimination real.
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:1"
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:1"
        no_proxy_has_none = not any(isinstance(h, urllib.request.ProxyHandler) for h in _no_proxy_opener().handlers)
        default_has_proxy = any(isinstance(h, urllib.request.ProxyHandler) for h in urllib.request.build_opener().handlers)
        for key in ("HTTP_PROXY", "HTTPS_PROXY"):
            os.environ.pop(key, None)
        check("10 transport is no-proxy (opener performs no proxy dispatch)",
              no_proxy_has_none and default_has_proxy,
              {"no_proxy_clean": no_proxy_has_none, "default_has_proxy": default_has_proxy})

        # ============ HEALTH (11-17) ============
        _reset_server(models=["qwen2.5:3b"])
        check("11 health available when model present", make_provider().health().available is True)

        _reset_server(models=["other-model:latest"])
        check("12 health unavailable when model absent", make_provider().health().available is False)

        dead = f"http://127.0.0.1:{_free_port()}"
        st = make_provider(ep=dead).health()
        check("13 health unavailable when unreachable (no raise)", st.available is False and isinstance(st.detail, str))

        st_lan = make_provider(ep="http://192.168.1.5:11434").health()
        check("14 health rejects non-loopback endpoint", st_lan.available is False and "loopback" in st_lan.detail)

        raised = False
        try:
            make_provider(ep="http://127.0.0.1.evil.com").health()
        except Exception:
            raised = True
        check("15 health never raises", raised is False)

        os.environ["HTTP_PROXY"] = "http://127.0.0.1:1"
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:1"
        os.environ["ALL_PROXY"] = "http://127.0.0.1:1"
        _reset_server(models=["qwen2.5:3b"])
        check("16 health works with a dead proxy configured (no-proxy)", make_provider().health().available is True)
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            os.environ.pop(key, None)

        caps = make_provider().capabilities()
        check("17 capabilities: no streaming, no multi-turn", caps.streaming is False and caps.multi_turn is False)

        # ============ GENERATION (18-24) ============
        _reset_server(content="MODEL: the grounded answer prose.")
        ctx = _make_context("Summarize the NPT hours and failures.", with_evidence=True)
        gen = make_provider().generate(ctx)
        check("18 generation swaps answer to model prose", gen.answer == "MODEL: the grounded answer prose.")

        baseline = DETERMINISTIC_PROVIDER.generate(_make_context("Summarize the NPT hours and failures.", with_evidence=True))
        same_structured = (
            gen.followups == baseline.followups
            and gen.export_actions == baseline.export_actions
            and [s.model_dump() for s in gen.workflow_steps] == [s.model_dump() for s in baseline.workflow_steps]
            and [c.model_dump() for c in gen.insight_cards] == [c.model_dump() for c in baseline.insight_cards]
            and [r.model_dump() for r in gen.risk_register] == [r.model_dump() for r in baseline.risk_register]
            and [a.label for a in gen.tool_actions] == [a.label for a in baseline.tool_actions]
        )
        check("19 generation preserves every structured field", same_structured and gen.answer != baseline.answer)

        os.environ["HTTP_PROXY"] = "http://127.0.0.1:1"
        _reset_server(content="MODEL: proxy-bypassed answer.")
        gen_np = make_provider().generate(_make_context("What failed?", with_evidence=True))
        check("20 generation works with a dead proxy configured (no-proxy)", gen_np.answer == "MODEL: proxy-bypassed answer.")
        os.environ.pop("HTTP_PROXY", None)

        _reset_server()
        make_provider().generate(_make_context("What is the NPT total?", with_evidence=True))
        body = SERVER_STATE["last_chat_body"] or {}
        opts = body.get("options", {})
        check("21 request is bounded + non-streaming",
              body.get("stream") is False and opts.get("num_predict") == LOCAL_GEN_NUM_PREDICT
              and "temperature" in opts and body.get("model") == "qwen2.5:3b", body)

        _reset_server(mode="oversized")
        over = make_provider().generate(_make_context("Draft the Monday report", with_evidence=True))
        check("22 oversized response -> deterministic fallback", over.answer == DETERMINISTIC_PROVIDER.generate(_make_context("Draft the Monday report", with_evidence=True)).answer)

        _reset_server(mode="malformed")
        mal = make_provider().generate(_make_context("Summarize the NPT", with_evidence=True))
        check("23 malformed JSON -> deterministic fallback", mal.answer == DETERMINISTIC_PROVIDER.generate(_make_context("Summarize the NPT", with_evidence=True)).answer)

        _reset_server(mode="empty")
        emp = make_provider().generate(_make_context("Summarize the NPT", with_evidence=True))
        check("24 empty content -> deterministic fallback", emp.answer == DETERMINISTIC_PROVIDER.generate(_make_context("Summarize the NPT", with_evidence=True)).answer)

        # lm_studio / OpenAI-compatible shape: generation extractor + health.
        def make_lm_provider(model: str = "qwen2.5:3b") -> LocalModelProvider:
            return LocalModelProvider(runtime="lm_studio", endpoint=endpoint, model=model, fallback=DETERMINISTIC_PROVIDER)

        _reset_server(content="LM: openai-compatible grounded prose.")
        lm_gen = make_lm_provider().generate(_make_context("Summarize the failures", with_evidence=True))
        check("24b lm_studio (openai-compatible) generation extractor works",
              lm_gen.answer == "LM: openai-compatible grounded prose.")
        check("24c lm_studio health via /v1/models", make_lm_provider().health().available is True)

        # ============ FALLBACK (25-27) ============
        _reset_server()
        unreachable = make_provider(ep=f"http://127.0.0.1:{_free_port()}")
        det = DETERMINISTIC_PROVIDER.generate(_make_context("Summarize the NPT", with_evidence=True))
        no_raise = True
        try:
            fell = unreachable.generate(_make_context("Summarize the NPT", with_evidence=True))
        except Exception:
            no_raise = False
            fell = None
        check("25 unreachable runtime -> deterministic (no raise)", no_raise and fell is not None and fell.answer == det.answer)

        lan = make_provider(ep="http://192.168.1.5:11434")
        fell_lan = lan.generate(_make_context("Summarize the NPT", with_evidence=True))
        check("26 non-loopback endpoint -> deterministic fallback", fell_lan.answer == det.answer)

        _reset_server(mode="error500")
        fell_500 = make_provider().generate(_make_context("Summarize the NPT", with_evidence=True))
        check("27 runtime 500 error -> deterministic fallback", fell_500.answer == det.answer)

        # An off-endpoint redirect must NOT be followed (no off-box egress) -> fallback.
        _reset_server(mode="redirect")
        fell_redirect = make_provider().generate(_make_context("Summarize the NPT", with_evidence=True))
        check("27b off-loopback redirect is refused -> deterministic fallback", fell_redirect.answer == det.answer)

        # A failure while PREPARING the prompt (context cannot be safely prepared) -> fallback.
        import backend.app.ai.local_model_provider as _lmp

        _reset_server()
        _original_build = _lmp.build_grounded_messages

        def _raising_build(_context):
            raise RuntimeError("prompt build failed")

        _lmp.build_grounded_messages = _raising_build
        try:
            fell_build = make_provider().generate(_make_context("Summarize the NPT", with_evidence=True))
        finally:
            _lmp.build_grounded_messages = _original_build
        check("27c prompt-build failure -> deterministic fallback (no raise)", fell_build.answer == det.answer)

        # ============ GROUNDING (28-31) ============
        _reset_server()
        empty_ctx = _make_context("What is the weather tomorrow?", with_evidence=False)
        det_empty = DETERMINISTIC_PROVIDER.generate(_make_context("What is the weather tomorrow?", with_evidence=False))
        out_empty = make_provider().generate(empty_ctx)
        check("28 insufficient evidence -> model NOT called + deterministic answer",
              SERVER_STATE["chat_post_count"] == 0 and out_empty.answer == det_empty.answer)

        _reset_server()
        make_provider().generate(_make_context("Summarize the failures", with_evidence=True))
        check("29 sufficient evidence -> model IS called", SERVER_STATE["chat_post_count"] >= 1)

        user_msg = (SERVER_STATE["last_chat_body"] or {}).get("messages", [{}, {}])[1].get("content", "")
        check("30 prompt carries the grounded structured facts",
              "Failure records: 2" in user_msg and "Validation gate:" in user_msg
              and "NPT hours" in user_msg and "Summarize the failures" in user_msg, user_msg[:200])

        sys_msg = (SERVER_STATE["last_chat_body"] or {}).get("messages", [{}])[0].get("content", "")
        check("31 system prompt forbids invention + allows refusal",
              "Do not invent" in SYSTEM_PROMPT and "insufficient" in SYSTEM_PROMPT
              and "Do not invent" in sys_msg, sys_msg[:120])

        # ============ CITATIONS (32-36) ============
        c1 = Citation(locator_type="pdf", locator={"page": 3, "section": "ddr"},
                      snippet="Stuck pipe at 8,420 ft created 6.5 h of NPT while drilling ahead.", confidence=0.86)
        fabricated = Citation(locator_type="pdf", locator={"page": 999}, snippet="FABRICATED - not grounded.", confidence=1.0)

        _reset_server(content="You should read source FAKE-999; it proves the well was abandoned.")
        cite_ctx = _make_context("What do the sources say?", with_evidence=True)
        base_keys = [citation_key(c) for c in cite_ctx.base_citations]
        gen_cite = make_provider().generate(cite_ctx)
        check("32 model text mentioning a fake source adds no citation",
              [citation_key(c) for c in gen_cite.citations] == base_keys
              and "FAKE-999" in gen_cite.answer, [citation_key(c) for c in gen_cite.citations])

        kept = validate_citations([c1, fabricated], allowed=[c1])
        check("33 validate_citations drops an out-of-set citation",
              len(kept) == 1 and citation_key(kept[0]) == citation_key(c1))

        c_extra = Citation(locator_type="csv", locator={"row": 5}, snippet="Second grounded snippet.", confidence=0.7)
        ordered = validate_citations([c_extra, c1], allowed=[c1, c_extra])
        check("34 validate_citations preserves valid citations (order + count)",
              [citation_key(x) for x in ordered] == [citation_key(c_extra), citation_key(c1)])

        check("35 provider cannot create a citation when the allowed set is empty",
              validate_citations([fabricated], allowed=[]) == [] and out_empty.citations == [])

        _reset_server(mode="citations_field", content="Grounded prose only.")
        gen_cf = make_provider().generate(_make_context("Anything?", with_evidence=True))
        leaked = any("FABRICATED-999" in json.dumps(c.model_dump(), default=str) for c in gen_cf.citations)
        check("36 a model-returned citations field is ignored", not leaked and gen_cf.answer == "Grounded prose only.")

        # ============ SETTINGS / UI (37-40) ============
        api_ts = (ROOT / "src/lib/api.ts").read_text(encoding="utf-8")
        check("37 api.ts exposes active_provider on ApiLocalAiStatus",
              "active_provider" in api_ts and "interface ApiLocalAiStatus" in api_ts)

        settings = (ROOT / "src/redesign/pages/Settings.tsx").read_text(encoding="utf-8")
        check("38 Settings AI section is data-driven + honest about availability + provenance",
              "active_provider" in settings and "localModelActive" in settings
              and "localModelServing" in settings and "model_available" in settings
              and "aiModelCells" in settings and "Local model" in settings
              and "Built-in analysis" in settings and "Not configured" in settings
              and "not currently used" in settings
              and "fall back to built-in analysis" in settings
              # provenance honesty: the positive built-in claim is gated on providerKnown, so
              # a chat-capable role without runtime-status access is not told a false engine.
              and "providerKnown" in settings
              and "Which on-computer engine writes them is shown with runtime access" in settings)
        check("39 Settings keeps the customer-surface pins",
              'aria-label="AI and model"' in settings and "{SHOW_INTERNAL ? (" in settings
              and 'aria-label="Runtime status"' in settings)

        ask = (ROOT / "src/redesign/pages/Ask.tsx").read_text(encoding="utf-8")
        check("40 Ask shows a truthful provider indicator (gated on availability + readability)",
              "aiProviderLabel" in ask and "active_provider" in ask
              and "aiProviderServing" in ask and "model_available" in ask
              and "Built-in analysis" in ask and "Local model" in ask
              # the chip renders only when the provider state is readable, so it never makes a
              # positive built-in claim to a role that cannot actually read the provider.
              and "aiProviderKnown" in ask and "{aiProviderKnown ? (" in ask)

        # ============ MUTATION / NON-VACUITY ============
        # NV1: a variant that does NOT fall back must RAISE on an unreachable runtime,
        # proving the fallback assertions in 22-27 are non-vacuous.
        class _NoFallbackProvider(LocalModelProvider):
            def generate(self, context):  # type: ignore[override]
                messages = build_grounded_messages(context)
                return generate_local_chat(self._runtime, self._endpoint, self._model, messages)

        nv_raised = False
        try:
            _NoFallbackProvider(runtime="ollama", endpoint=f"http://127.0.0.1:{_free_port()}",
                                model="qwen2.5:3b", fallback=DETERMINISTIC_PROVIDER).generate(
                _make_context("Summarize the NPT", with_evidence=True))
        except LocalGenerationError:
            nv_raised = True
        check("NV1 broken (no-fallback) provider raises on an unreachable runtime", nv_raised)

        # NV2: the validator is discriminating, not an unconditional dropper — a citation
        # that IS in the allowed set is kept, proving check 33 is non-vacuous.
        check("NV2 validator keeps an in-set citation (discriminating, not vacuous)",
              validate_citations([fabricated], allowed=[fabricated]) == [fabricated])

        # NV3: generation truly reflects the server output, not a hard-coded string.
        _reset_server(content="MODEL: distinctive-sentinel-8823.")
        nv3 = make_provider().generate(_make_context("What failed?", with_evidence=True))
        check("NV3 generation reflects live server output", nv3.answer == "MODEL: distinctive-sentinel-8823.")

    finally:
        server.shutdown()
        server.server_close()
        _set_local_env()

    passed = sum(1 for c in CHECKS if c["ok"])
    for c in CHECKS:
        print(f"{'PASS' if c['ok'] else 'FAIL'}: {c['name']}" + ("" if c["ok"] else f"  -- got: {c['detail']}"))
    print(f"\nlocal_model_provider_guard: {passed}/{len(CHECKS)} passed")
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # fail-closed: any harness error is a guard failure
        import traceback

        traceback.print_exc()
        print(f"\nlocal_model_provider_guard: HARNESS ERROR -> {type(exc).__name__}: {exc}")
        sys.exit(1)
