"""OnlineAPIProvider — an OPTIONAL, default-off answer generator that reaches a configured
remote OpenAI-compatible Chat Completions endpoint over HTTPS.

Same seam and same discipline as LocalModelProvider: the deterministic baseline is built
first and only ``answer`` prose is replaced on success; the model returns a string and can
never own a citation; ANY failure (or insufficient evidence) returns the deterministic
baseline. It differs from Local ONLY in that it egresses to a remote https host — via the
strictly separate ``online_egress`` client (https-only, exact-host allowlist, no-redirect,
no-proxy, verified TLS, bounded). It NEVER falls back to the local model (that would hide
whether evidence left the machine); fallback is Online → Deterministic only.

Selection is env + sealed-config only (see ``resolve_ai_provider``); nothing from a request
participates. Grounding is MINIMIZED for egress: only counts, a few evidence snippet texts,
and the question are sent — never signed URLs, internal ids, tenant/actor ids, or secrets.
"""
from __future__ import annotations

from ..schemas import ChatResponse
from .contract import AIProvider, GroundedContext, ProviderCapabilities, ProviderStatus
from .local_model_provider import ONLINE_ENABLED_VALUES, SYSTEM_PROMPT
from .online_egress import ONLINE_MAX_TOKENS, is_allowed_online_endpoint, online_chat_completion

__all__ = [
    "ONLINE_ENABLED_VALUES",
    "OnlineAPIProvider",
    "build_online_messages",
    "build_online_provider",
]

# Minimized grounding bounds for egress — TIGHTER than the local model's.
ONLINE_MAX_PROMPT_CHARS = 8_000
ONLINE_MAX_EVIDENCE_SNIPPETS = 5
ONLINE_MAX_SNIPPET_CHARS = 500


def build_online_messages(context: GroundedContext) -> list[dict[str, str]]:
    """Assemble the minimized [system, user] pair sent off-box. The user message carries
    ONLY: counts (evidence scope, validation gate, failure/NPT totals), a bounded set of
    evidence snippet TEXTS, and the question. No file ids, locators, signed URLs, tenant or
    actor identifiers, or secrets are ever included. Bounded to ``ONLINE_MAX_PROMPT_CHARS``."""
    documents = context.documents or []
    open_tasks = context.open_tasks or []
    failures = context.failures or []
    high = len([f for f in failures if getattr(f, "severity", None) in {"High", "Critical"}])
    total_npt = sum(getattr(f, "npt_hours", 0) or 0 for f in failures)

    facts = [
        f"Evidence scope: {len(documents)} document(s), {context.chunk_count} source chunk(s).",
        f"Validation gate: {len(open_tasks)} open task(s).",
        f"Failure records: {len(failures)} (high/critical: {high}; total NPT hours: {total_npt:.1f}).",
    ]
    status = context.benchmark_status
    if status is not None:
        current = getattr(status, "current_ft_per_day", None)
        facts.append(f"Benchmark: current ft/day={current if current is not None else 'missing'}.")

    snippets: list[str] = []
    for citation in (context.base_citations or [])[:ONLINE_MAX_EVIDENCE_SNIPPETS]:
        snippet = (getattr(citation, "snippet", "") or "").strip()
        if snippet:
            snippets.append(f"- {snippet[:ONLINE_MAX_SNIPPET_CHARS]}")

    sections = ["EVIDENCE:", *facts]
    if snippets:
        sections.append("SOURCE SNIPPETS:")
        sections.extend(snippets)
    sections.append("QUESTION:")
    sections.append((context.content or "").strip())

    user = "\n".join(sections)
    if len(user) > ONLINE_MAX_PROMPT_CHARS:
        user = user[:ONLINE_MAX_PROMPT_CHARS]
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


class OnlineAPIProvider(AIProvider):
    """Remote OpenAI-compatible generator with a mandatory deterministic fallback."""

    def __init__(
        self,
        *,
        provider: str,
        base_url: str,
        model: str,
        api_key: str,
        fallback: AIProvider,
    ) -> None:
        self._provider = provider
        self._base_url = base_url
        self._model = model
        self._api_key = api_key  # in-memory only
        self._fallback = fallback

    def name(self) -> str:
        return "online-api"

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(streaming=False, multi_turn=False, max_context_tokens=ONLINE_MAX_PROMPT_CHARS)

    def health(self) -> ProviderStatus:
        # Config-level ONLY — no network here, so a status read never triggers egress. A
        # real reachability/auth probe is the on-demand Test-connection action.
        configured = bool(self._model) and bool(self._api_key) and is_allowed_online_endpoint(self._base_url)
        detail = "online provider configured" if configured else "online provider misconfigured"
        return ProviderStatus(provider="online-api", available=configured, detail=detail)

    @staticmethod
    def _insufficient_evidence(context: GroundedContext) -> bool:
        return (
            not (context.failures or [])
            and not (context.documents or [])
            and (context.chunk_count or 0) == 0
            and not (context.base_citations or [])
        )

    def generate(self, context: GroundedContext) -> ChatResponse:
        baseline = self._fallback.generate(context)  # deterministic baseline first; its failure surfaces
        try:
            if self._insufficient_evidence(context):
                return baseline  # no evidence -> do NOT send anything off-box
            messages = build_online_messages(context)
            text = online_chat_completion(
                self._base_url, self._model, self._api_key, messages, max_tokens=ONLINE_MAX_TOKENS
            )
        except Exception:
            return baseline  # ANY online failure -> deterministic; never Online -> Local; never raise
        baseline.answer = text  # only the prose changes; citations stay backend-owned
        return baseline


def build_online_provider(settings: object, fallback: AIProvider) -> OnlineAPIProvider | None:
    """Return an ``OnlineAPIProvider`` iff ``settings`` is a complete, valid online config
    (known provider, allowed https remote endpoint, model, and key); otherwise ``None`` so
    the resolver falls back to the deterministic default."""
    from ..online_ai_settings import KNOWN_PROVIDERS, OnlineAiSettings

    if not isinstance(settings, OnlineAiSettings):
        return None
    if settings.provider not in KNOWN_PROVIDERS:
        return None
    if not is_allowed_online_endpoint(settings.base_url):
        return None
    if not settings.model or not settings.api_key:
        return None
    return OnlineAPIProvider(
        provider=settings.provider,
        base_url=settings.base_url,
        model=settings.model,
        api_key=settings.api_key,
        fallback=fallback,
    )
