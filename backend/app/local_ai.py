from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

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
