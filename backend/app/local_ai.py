from __future__ import annotations

import ipaddress
import json
import os
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

from .schemas import LocalAIStatus


LOCAL_AI_RUNTIME_ENV = "MONDAY_REPORT_LOCAL_LLM_RUNTIME"
LOCAL_AI_MODEL_ENV = "MONDAY_REPORT_LOCAL_LLM_MODEL"
OLLAMA_HOST_ENV = "OLLAMA_HOST"
LM_STUDIO_BASE_URL_ENV = "LM_STUDIO_BASE_URL"
DEFAULT_LOCAL_AI_RUNTIME = "ollama"
DEFAULT_LOCAL_AI_MODEL = "gemma4:e2b"
DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"
DISABLED_RUNTIME_VALUES = {"0", "false", "no", "none", "off", "disabled", "unconfigured"}


def evaluate_local_ai_status(policy: dict[str, Any] | None = None) -> LocalAIStatus:
    runtime, endpoint = _runtime_and_endpoint()
    model = _configured_model(runtime)
    hosted_fallback_enabled = bool((policy or {}).get("hosted_fallback_enabled", False))
    configured = runtime != "unconfigured" and endpoint is not None
    reachable = False
    model_available = False
    detail = "No local AI endpoint configured."

    if configured and endpoint:
        reachable, model_available, detail = _probe_runtime(runtime, endpoint, model)

    return LocalAIStatus(
        runtime=runtime,
        configured=configured,
        reachable=reachable,
        model_available=model_available,
        endpoint=endpoint,
        model=model,
        hosted_fallback_enabled=hosted_fallback_enabled,
        detail=detail,
    )


def _runtime_and_endpoint() -> tuple[str, str | None]:
    requested_runtime = os.getenv(LOCAL_AI_RUNTIME_ENV, "").strip().lower()
    ollama_host = os.getenv(OLLAMA_HOST_ENV, "").strip().rstrip("/")
    lm_studio_url = os.getenv(LM_STUDIO_BASE_URL_ENV, "").strip().rstrip("/")

    if requested_runtime in DISABLED_RUNTIME_VALUES:
        return "unconfigured", None
    if requested_runtime in {"ollama", "llama"}:
        return "ollama", ollama_host or DEFAULT_OLLAMA_HOST
    if requested_runtime in {"lm_studio", "lm-studio", "lmstudio"}:
        return "lm_studio", lm_studio_url or None
    if ollama_host:
        return "ollama", ollama_host
    if lm_studio_url:
        return "lm_studio", lm_studio_url
    return DEFAULT_LOCAL_AI_RUNTIME, DEFAULT_OLLAMA_HOST


def _configured_model(runtime: str) -> str | None:
    configured = os.getenv(LOCAL_AI_MODEL_ENV, "").strip()
    if configured:
        return configured
    if runtime == "ollama":
        return DEFAULT_LOCAL_AI_MODEL
    return None


def _probe_runtime(runtime: str, endpoint: str, model: str | None) -> tuple[bool, bool, str]:
    if runtime == "ollama":
        probe_url = f"{endpoint}/api/tags"
    elif runtime == "lm_studio":
        probe_url = f"{endpoint}/v1/models"
    else:
        return False, False, f"Unsupported local AI runtime: {runtime}."

    request = urllib.request.Request(probe_url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=1.5) as response:
            payload = json.loads(response.read().decode("utf-8") or "{}")
    except urllib.error.URLError as exc:
        return False, False, f"{runtime} endpoint is not reachable: {exc.reason}."
    except (TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return False, False, f"{runtime} endpoint did not return valid model metadata: {exc}."

    model_count = _model_count(runtime, payload)
    if not model:
        return True, True, f"{runtime} endpoint reachable; {model_count} model(s) reported."

    model_names = _model_names(runtime, payload)
    if model in model_names:
        return True, True, f"{runtime} endpoint reachable; model {model!r} is available."

    available_preview = ", ".join(model_names[:5]) if model_names else "none reported"
    return (
        True,
        False,
        f"{runtime} endpoint reachable, but model {model!r} is not installed; available models: {available_preview}.",
    )


def _model_count(runtime: str, payload: Any) -> int:
    return len(_model_names(runtime, payload))


def _model_names(runtime: str, payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return []
    if runtime == "ollama":
        models = payload.get("models")
    else:
        models = payload.get("data")
    if not isinstance(models, list):
        return []
    names: list[str] = []
    for model in models:
        if not isinstance(model, dict):
            continue
        name = model.get("name") or model.get("model") or model.get("id")
        if name:
            names.append(str(name))
    return names


# ---------------------------------------------------------------------------
# Local model GENERATION client (Phase 3)
#
# Everything ABOVE this line is the diagnostic reachability probe and is kept
# byte-for-byte as shipped. What follows is a SEPARATE generation path used only
# by ``LocalModelProvider``. Hard invariants, all enforced here (not by the caller):
#   * loopback-only: the endpoint host must be 127.0.0.0/8, ::1, or ``localhost``;
#     any public / LAN / docker-bridge IP, remote hostname, ``file://`` or other
#     scheme is refused. No DNS resolution of arbitrary hostnames.
#   * no-proxy: requests go through an opener with every proxy explicitly disabled,
#     so a system HTTP(S)_PROXY / ALL_PROXY cannot redirect a local request off-box.
#   * strictly bounded: connect/read timeout, response-size cap, generated-token cap.
#   * never streams, never retries, and carries only the grounded prompt the caller
#     built — this module logs nothing about the prompt, evidence, or output.
# ---------------------------------------------------------------------------

# Selection: only an explicit, trusted process-environment value activates the local
# model. Nothing from a request/header/user payload participates. The generation model
# is read from the EXISTING model env DIRECTLY (never the ``gemma4:e2b`` probe default),
# so an unverified default can never be used to generate.
AI_PROVIDER_ENV = "MONDAY_REPORT_AI_PROVIDER"
LOCAL_GEN_ENABLED_VALUES = {"local", "local-model", "local_model"}

# Bounds (named so the provider guard can pin them and the mutation pass can flip them).
LOCAL_GEN_TIMEOUT_SECONDS = 90.0          # socket timeout for the (non-streaming) call
LOCAL_GEN_HEALTH_TIMEOUT_SECONDS = 2.0    # reachability probe timeout
LOCAL_GEN_NUM_PREDICT = 512               # hard cap on generated tokens
LOCAL_GEN_MAX_RESPONSE_BYTES = 512 * 1024  # hard cap on the model HTTP response body
LOCAL_GEN_TEMPERATURE = 0.2               # low temperature: grounded, non-creative prose


class LocalGenerationError(RuntimeError):
    """Raised by the generation client on any refusal / transport / decode failure.

    ``LocalModelProvider`` catches this (and every other exception) and falls back to
    the deterministic answer, so this type never reaches the request handler."""


def is_loopback_endpoint(endpoint: str | None) -> bool:
    """True only if ``endpoint`` is an http(s) URL whose host is a loopback address
    (``127.0.0.0/8`` / ``::1``) or the literal ``localhost``. Everything else — public
    or LAN IPs, the docker bridge, any non-``localhost`` hostname, ``file://`` and other
    schemes — is rejected. Arbitrary hostnames are NOT DNS-resolved."""
    if not endpoint or not isinstance(endpoint, str):
        return False
    try:
        parts = urlsplit(endpoint.strip())
        if parts.scheme not in {"http", "https"}:
            return False
        host = parts.hostname  # strips [..] brackets and any user:pass@ prefix; may raise
    except ValueError:
        # A malformed authority (e.g. an unclosed IPv6 bracket) is not loopback and must
        # never propagate — the resolver relies on this to fail closed to deterministic.
        return False
    if not host:
        return False
    host = host.lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse ALL HTTP redirects. A loopback model endpoint never legitimately redirects,
    and following one would send the request to an un-revalidated (possibly off-box) host.
    Returning ``None`` makes urllib not follow; the 3xx then surfaces as an ``HTTPError``,
    which the caller treats as a failure and falls back to deterministic."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: A002
        return None


def _no_proxy_opener() -> urllib.request.OpenerDirector:
    # ProxyHandler({}) installs NO proxy for any scheme and suppresses environment proxy
    # discovery, so a configured system proxy cannot intercept a loopback call. The
    # no-redirect handler prevents a loopback listener from bouncing the request off-box.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirectHandler())


def selected_generation_model() -> str | None:
    """The explicitly configured generation model, or ``None``. Never the probe's
    ``gemma4:e2b`` default — a generation model must be named on purpose."""
    model = os.getenv(LOCAL_AI_MODEL_ENV, "").strip()
    return model or None


def _extract_generated_text(runtime: str, payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    if runtime == "ollama":
        message = payload.get("message")
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            return message["content"]
        response = payload.get("response")  # /api/generate-style fallback shape
        return response if isinstance(response, str) else None
    choices = payload.get("choices")  # lm_studio / openai-compatible
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            return message["content"]
    return None


def generate_local_chat(
    runtime: str,
    endpoint: str,
    model: str,
    messages: list[dict[str, str]],
    *,
    timeout: float = LOCAL_GEN_TIMEOUT_SECONDS,
    num_predict: int = LOCAL_GEN_NUM_PREDICT,
    max_response_bytes: int = LOCAL_GEN_MAX_RESPONSE_BYTES,
) -> str:
    """POST a bounded, loopback-only, no-proxy, non-streaming chat completion and return
    the assistant text. Raises ``LocalGenerationError`` on a non-loopback endpoint, any
    transport error, an oversized or malformed response, or empty content."""
    endpoint = (endpoint or "").rstrip("/")
    if not is_loopback_endpoint(endpoint):
        raise LocalGenerationError("refusing a non-loopback generation endpoint")
    if runtime == "ollama":
        url = f"{endpoint}/api/chat"
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {"num_predict": int(num_predict), "temperature": LOCAL_GEN_TEMPERATURE},
        }
    elif runtime == "lm_studio":
        url = f"{endpoint}/v1/chat/completions"
        body = {
            "model": model,
            "messages": messages,
            "stream": False,
            "max_tokens": int(num_predict),
            "temperature": LOCAL_GEN_TEMPERATURE,
        }
    else:
        raise LocalGenerationError(f"unsupported local runtime {runtime!r}")

    # Re-validate the fully-formed request URL is still loopback before opening it.
    if not is_loopback_endpoint(url):
        raise LocalGenerationError("refusing a non-loopback request url")

    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    opener = _no_proxy_opener()
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(max_response_bytes + 1)
    except LocalGenerationError:
        raise
    except Exception as exc:  # URLError, socket timeout, connection reset, etc.
        raise LocalGenerationError(f"local generation transport failure: {type(exc).__name__}") from exc

    if len(raw) > max_response_bytes:
        raise LocalGenerationError("local generation response exceeded the size cap")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise LocalGenerationError("local generation response was not valid JSON") from exc

    text = _extract_generated_text(runtime, payload)
    if not text or not text.strip():
        raise LocalGenerationError("local generation returned empty content")
    return text.strip()


def probe_local_generation(
    runtime: str,
    endpoint: str,
    model: str,
    *,
    timeout: float = LOCAL_GEN_HEALTH_TIMEOUT_SECONDS,
) -> tuple[bool, str]:
    """No-proxy, loopback-only reachability + model-presence check for the generation
    provider's ``health()``. Returns ``(available, detail)`` and never raises."""
    if not is_loopback_endpoint(endpoint):
        return False, "endpoint is not loopback"
    endpoint = endpoint.rstrip("/")
    if runtime == "ollama":
        probe_url = f"{endpoint}/api/tags"
    elif runtime == "lm_studio":
        probe_url = f"{endpoint}/v1/models"
    else:
        return False, f"unsupported local runtime {runtime!r}"
    request = urllib.request.Request(probe_url, headers={"Accept": "application/json"}, method="GET")
    opener = _no_proxy_opener()
    try:
        with opener.open(request, timeout=timeout) as response:
            payload = json.loads(response.read(LOCAL_GEN_MAX_RESPONSE_BYTES).decode("utf-8") or "{}")
    except Exception as exc:  # never raise out of a health check
        return False, f"local runtime not reachable ({type(exc).__name__})"
    if model in _model_names(runtime, payload):
        return True, f"local model {model!r} is available"
    return False, f"local model {model!r} is not installed"
