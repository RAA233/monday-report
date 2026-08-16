"""Outbound HTTPS client for the Online AI provider — the ONLY code path in the product
allowed to reach a non-loopback endpoint, and a strictly separate module from the
loopback-only ``local_ai`` client (whose loopback gate must never be relaxed).

Hard invariants, all enforced here:
  * HTTPS ONLY — http/ftp/file/other schemes are refused.
  * EXACT-HOST allowlist — the only reachable host is the one in the operator-configured
    ``base_url``; the fully-formed request URL is re-validated against it.
  * Loopback is REJECTED (online is remote; a loopback endpoint mislabeled as Online is
    refused), as are credential-in-URL (userinfo) and malformed authorities.
  * NO redirects (a 3xx cannot bounce the request off the allowlisted origin).
  * NO ambient system proxy (a proxy cannot silently substitute the destination host).
  * TLS certificate + hostname verification is ON (default SSL context); there is no
    unverified-context path.
  * Bounded connect/read timeout, response-size cap, and generated-token cap.

The client carries only the caller-built grounded prompt and the Bearer key; it logs
nothing about the prompt, evidence, key, or response body. Errors are raised as
``OnlineEgressError`` carrying only an error class / HTTP status, never a response body.
"""
from __future__ import annotations

import ipaddress
import json
import ssl
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

ONLINE_TIMEOUT_SECONDS = 60.0
ONLINE_TEST_TIMEOUT_SECONDS = 15.0
ONLINE_MAX_RESPONSE_BYTES = 512 * 1024
ONLINE_MAX_TOKENS = 512
ONLINE_TEMPERATURE = 0.2


class OnlineEgressError(RuntimeError):
    """Raised on a refused endpoint, transport/TLS failure, non-2xx status, or an
    oversized/malformed/empty response. The provider catches this and falls back."""


def is_allowed_online_endpoint(base_url: str | None) -> bool:
    """True only for an ``https`` URL with a real REMOTE host and no embedded credential.
    Rejects non-https schemes, loopback/unspecified addresses and ``localhost``, userinfo
    URLs, and malformed authorities. Hostnames (resolved later under cert verification)
    are allowed; the exact host becomes the allowlist."""
    if not base_url or not isinstance(base_url, str):
        return False
    try:
        parts = urlsplit(base_url.strip())
        host = parts.hostname
        if parts.username or parts.password:  # credential in URL
            return False
    except ValueError:
        return False
    if parts.scheme != "https":
        return False
    if not host:
        return False
    host = host.lower()
    if host == "localhost":
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return True  # a hostname (not an IP literal) — allowed as the allowlist host
    return not (address.is_loopback or address.is_unspecified)


def _host(url: str) -> str | None:
    try:
        return (urlsplit(url).hostname or "").lower() or None
    except ValueError:
        return None


def _validated_host(base_url: str) -> str:
    if not is_allowed_online_endpoint(base_url):
        raise OnlineEgressError("endpoint is not an allowed https remote endpoint")
    host = _host(base_url)
    if not host:
        raise OnlineEgressError("endpoint has no resolvable host")
    return host


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse ALL redirects: the request must stay on the allowlisted origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: A002
        return None


def _opener() -> urllib.request.OpenerDirector:
    # HTTPSHandler with the default (verifying) context; ProxyHandler({}) suppresses
    # ambient system proxies; _NoRedirect refuses 3xx. No unverified-context path exists.
    context = ssl.create_default_context()
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=context),
    )


def _completions_url(base_url: str) -> str:
    allowed_host = _validated_host(base_url)
    url = base_url.rstrip("/") + "/chat/completions"
    if _host(url) != allowed_host or not is_allowed_online_endpoint(url):
        raise OnlineEgressError("request url is not the configured allowlisted https endpoint")
    return url


def _extract_answer(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    choices = payload.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            return message["content"]
    return None


def _post(url: str, api_key: str, body: dict, *, timeout: float, max_response_bytes: int) -> bytes:
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with _opener().open(request, timeout=timeout) as response:
        raw = response.read(max_response_bytes + 1)
    if len(raw) > max_response_bytes:
        raise OnlineEgressError("online response exceeded the size cap")
    return raw


def online_chat_completion(
    base_url: str,
    model: str,
    api_key: str,
    messages: list[dict[str, str]],
    *,
    timeout: float = ONLINE_TIMEOUT_SECONDS,
    max_tokens: int = ONLINE_MAX_TOKENS,
    max_response_bytes: int = ONLINE_MAX_RESPONSE_BYTES,
) -> str:
    """POST a bounded, non-streaming OpenAI-compatible completion to the allowlisted
    https endpoint and return the assistant text. Raises ``OnlineEgressError`` on any
    refusal / transport / TLS / status / decode / empty failure."""
    url = _completions_url(base_url)
    body = {
        "model": model,
        "messages": messages,
        "stream": False,
        "max_tokens": int(max_tokens),
        "temperature": ONLINE_TEMPERATURE,
    }
    try:
        raw = _post(url, api_key, body, timeout=timeout, max_response_bytes=max_response_bytes)
    except OnlineEgressError:
        raise
    except urllib.error.HTTPError as exc:
        raise OnlineEgressError(f"online provider http status {exc.code}") from exc
    except ssl.SSLError as exc:
        raise OnlineEgressError("online TLS/certificate verification failed") from exc
    except Exception as exc:  # URLError, socket timeout, connection reset, etc.
        raise OnlineEgressError(f"online transport failure: {type(exc).__name__}") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise OnlineEgressError("online response was not valid JSON") from exc
    text = _extract_answer(payload)
    if not text or not text.strip():
        raise OnlineEgressError("online provider returned empty content")
    return text.strip()


def online_test_connection(
    base_url: str,
    model: str,
    api_key: str,
    *,
    timeout: float = ONLINE_TEST_TIMEOUT_SECONDS,
) -> tuple[str, str]:
    """A minimal, evidence-free reachability + auth + model probe. Sends a fixed one-token
    request with NO workspace evidence and returns ``(status_class, friendly_detail)`` —
    never a raw provider body/exception. status_class ∈ {connected, auth_failed,
    rate_limited, unavailable, misconfigured}."""
    if not is_allowed_online_endpoint(base_url):
        return ("misconfigured", "The endpoint is not a valid https address.")
    if not model:
        return ("misconfigured", "No model is configured.")
    if not api_key:
        return ("misconfigured", "No API key is configured.")
    try:
        url = _completions_url(base_url)
    except OnlineEgressError:
        return ("misconfigured", "The endpoint is not a valid https address.")
    body = {
        "model": model,
        "messages": [{"role": "user", "content": "ping"}],  # fixed probe — NO evidence
        "stream": False,
        "max_tokens": 1,
        "temperature": 0,
    }
    try:
        _post(url, api_key, body, timeout=timeout, max_response_bytes=ONLINE_MAX_RESPONSE_BYTES)
        return ("connected", "Connected to the configured provider.")
    except urllib.error.HTTPError as exc:
        code = exc.code
        if code in (401, 403):
            return ("auth_failed", "Authentication failed — check the API key.")
        if code in (400, 404):
            return ("misconfigured", "The endpoint or model was not accepted.")
        if code == 429:
            return ("rate_limited", "The provider is rate limiting requests.")
        if 500 <= code < 600:
            return ("unavailable", "The provider returned a server error.")
        return ("unavailable", f"The provider returned status {code}.")
    except ssl.SSLError:
        return ("unavailable", "TLS/certificate verification failed.")
    except Exception:
        return ("unavailable", "The provider could not be reached.")
