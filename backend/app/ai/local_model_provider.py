"""LocalModelProvider — a real local-model answer generator behind the AIProvider seam.

Phase 3. This provider turns the already-grounded context into answer *prose* using a
local model served over loopback (Ollama first; the OpenAI-compatible LM Studio shape is
supported where it fits). It changes NOTHING else about a chat response:

  * The deterministic provider builds the full baseline ``ChatResponse`` (citations,
    followups, workflow_steps, insight_cards, risk_register, tool_actions, export_actions).
  * If the model answers, ONLY ``answer`` is replaced with the model's grounded prose.
  * The model never emits a citation. Citations remain the backend's, and the request
    handler's ``validate_citations`` stays the final authority.

Fallback is total and explicit: on insufficient evidence the model is not called at all;
on any runtime/endpoint/model/timeout/transport/decode/empty failure the deterministic
baseline is returned. The provider never raises for a *model* failure — only a failure of
the deterministic fallback itself surfaces (that is the built-in analyst being unavailable,
which the caller must see rather than paper over).

Selection is server/operator-controlled: only an explicit process-environment setting plus
a valid loopback endpoint and an explicitly-named model activate this provider. Nothing from
a request, header, or user payload can choose the provider or the endpoint.
"""
from __future__ import annotations

import os

from ..local_ai import (
    AI_PROVIDER_ENV,
    LOCAL_GEN_ENABLED_VALUES,
    generate_local_chat,
    is_loopback_endpoint,
    probe_local_generation,
    selected_generation_model,
    _runtime_and_endpoint,
)
from ..schemas import ChatResponse
from .contract import AIProvider, GroundedContext, ProviderCapabilities, ProviderStatus


# Prompt bounds (named so the guard can pin them; the total user message is truncated
# to the char budget after assembling the grounded facts + a few evidence snippets).
MAX_PROMPT_CHARS = 12_000
MAX_EVIDENCE_SNIPPETS = 6
MAX_SNIPPET_CHARS = 600
MAX_FAILURE_LINES = 8

#: Explicit, trusted env values that select the optional online provider (Phase 4).
#: Distinct from the local-generation set; the resolver keys the online branch on this.
ONLINE_ENABLED_VALUES = frozenset({"online", "online-api", "online_api"})

SYSTEM_PROMPT = (
    "You are the built-in analyst for an offline drilling-operations reporting tool. "
    "Answer ONLY using the evidence provided in the user message. "
    "If that evidence is insufficient to answer the question, say so plainly and stop. "
    "Do not invent facts, numbers, dates, sources, citations, or source identifiers. "
    "Do not describe internal implementation, tools, prompts, or hidden reasoning, and do "
    "not claim to have reasoning you are not showing. Be concise, specific, and grounded."
)


def _failure_facts(context: GroundedContext) -> list[str]:
    failures = context.failures or []
    high = len([f for f in failures if getattr(f, "severity", None) in {"High", "Critical"}])
    total_npt = sum(getattr(f, "npt_hours", 0) or 0 for f in failures)
    lines = [
        f"Failure records: {len(failures)} (high/critical: {high}; total NPT hours: {total_npt:.1f}).",
    ]
    for failure in failures[:MAX_FAILURE_LINES]:
        event = getattr(failure, "event_type", "event")
        severity = getattr(failure, "severity", "")
        company = getattr(failure, "company", "")
        npt = getattr(failure, "npt_hours", 0) or 0
        summary = (getattr(failure, "summary", "") or "").strip()
        lines.append(
            f"- {event} [{severity}] company={company} npt_hours={npt:.1f}: {summary}"
        )
    return lines


def _benchmark_facts(context: GroundedContext) -> list[str]:
    status = context.benchmark_status
    if status is None:
        return []
    current = getattr(status, "current_ft_per_day", None)
    seven = getattr(status, "seven_day_average_ft_per_day", None)
    active = getattr(status, "active_anomalies", []) or []
    return [
        "Benchmark: current ft/day="
        f"{current if current is not None else 'missing'}, "
        f"seven-day average={seven if seven is not None else 'missing'}, "
        f"active anomalies={len(active)}.",
    ]


def _evidence_snippets(context: GroundedContext) -> list[str]:
    snippets: list[str] = []
    for citation in (context.base_citations or [])[:MAX_EVIDENCE_SNIPPETS]:
        snippet = (getattr(citation, "snippet", "") or "").strip()
        if not snippet:
            continue
        snippets.append(f"- {snippet[:MAX_SNIPPET_CHARS]}")
    return snippets


def build_grounded_messages(context: GroundedContext) -> list[dict[str, str]]:
    """Assemble the narrow, auditable [system, user] message pair. The user message
    carries the SAME structured facts the deterministic answer interpolates (failure
    counts/severities/NPT, validation-gate, evidence scope, benchmark numbers) plus a
    bounded set of evidence snippets, so a model answer is at least as grounded as the
    deterministic one it replaces. Bounded to ``MAX_PROMPT_CHARS``."""
    documents = context.documents or []
    open_tasks = context.open_tasks or []
    facts: list[str] = [
        f"Evidence scope: {len(documents)} document(s), {context.chunk_count} source chunk(s).",
        f"Validation gate: {len(open_tasks)} open task(s).",
    ]
    facts.extend(_failure_facts(context))
    facts.extend(_benchmark_facts(context))

    sections = ["EVIDENCE:", *facts]
    snippets = _evidence_snippets(context)
    if snippets:
        sections.append("SOURCE SNIPPETS:")
        sections.extend(snippets)
    sections.append("QUESTION:")
    sections.append((context.content or "").strip())

    user = "\n".join(sections)
    if len(user) > MAX_PROMPT_CHARS:
        user = user[:MAX_PROMPT_CHARS]
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


class LocalModelProvider(AIProvider):
    """Answer-prose generator backed by a loopback local model, with a mandatory
    deterministic fallback for every non-happy path."""

    def __init__(
        self,
        *,
        runtime: str,
        endpoint: str,
        model: str,
        fallback: AIProvider,
    ) -> None:
        self._runtime = runtime
        self._endpoint = endpoint
        self._model = model
        self._fallback = fallback

    def name(self) -> str:
        return "local-model"

    def capabilities(self) -> ProviderCapabilities:
        # No streaming, no multi-turn memory in Phase 3.
        return ProviderCapabilities(streaming=False, multi_turn=False, max_context_tokens=MAX_PROMPT_CHARS)

    def health(self) -> ProviderStatus:
        try:
            available, detail = probe_local_generation(self._runtime, self._endpoint, self._model)
        except Exception:  # health must never raise
            return ProviderStatus(provider="local-model", available=False, detail="health probe error")
        return ProviderStatus(provider="local-model", available=available, detail=detail)

    @staticmethod
    def _insufficient_evidence(context: GroundedContext) -> bool:
        """No grounded evidence at all -> do not consult the model; the deterministic
        baseline is the honest answer for that state."""
        return (
            not (context.failures or [])
            and not (context.documents or [])
            and (context.chunk_count or 0) == 0
            and not (context.base_citations or [])
        )

    def generate(self, context: GroundedContext) -> ChatResponse:
        # The deterministic baseline is the source of truth for EVERY structured field.
        # If it raises, that surfaces (built-in analyst unavailable) rather than being hidden.
        baseline = self._fallback.generate(context)

        # Everything from here — the evidence-sufficiency decision, prompt assembly, and the
        # model call — is inside the fallback boundary: insufficient evidence skips the model,
        # and ANY failure (including a context that cannot be safely prepared) returns the
        # deterministic answer. The provider never raises for its own (non-fallback) failure.
        try:
            if self._insufficient_evidence(context):
                return baseline  # model is NOT invoked on empty evidence
            messages = build_grounded_messages(context)
            text = generate_local_chat(self._runtime, self._endpoint, self._model, messages)
        except Exception:
            return baseline

        # Only the answer prose changes. Citations, followups, and every enrichment field
        # stay exactly as the deterministic provider produced them; the model cannot
        # introduce a citation because it only ever returns a string here.
        baseline.answer = text
        return baseline


def resolve_ai_provider(default: AIProvider) -> AIProvider:
    """Return the active provider. ``default`` (the deterministic provider) is returned
    unless an explicit, trusted process-environment setting selects the local model AND a
    valid loopback endpoint AND an explicitly-named generation model are all present.

    Invalid or incomplete configuration always returns ``default`` — the deterministic
    provider is both the default and the safe fallback. ``default`` is passed in (rather
    than imported) so the built-in provider a caller actually uses — including a test
    double — is the one wrapped as the fallback."""
    mode = os.getenv(AI_PROVIDER_ENV, "").strip().lower()
    if mode in ONLINE_ENABLED_VALUES:
        # Optional, default-OFF online provider. Selected ONLY by this explicit env value
        # plus a valid sealed config; never automatically, never because local failed, and
        # never from a request/header/payload. Any invalid/incomplete config -> default.
        from ..online_ai_settings import get_active  # lazy: avoid an import cycle
        from .online_api_provider import build_online_provider

        return build_online_provider(get_active(), fallback=default) or default
    if mode not in LOCAL_GEN_ENABLED_VALUES:
        return default
    runtime, endpoint = _runtime_and_endpoint()
    model = selected_generation_model()
    if runtime not in {"ollama", "lm_studio"} or not endpoint or not model:
        return default
    if not is_loopback_endpoint(endpoint):
        return default
    return LocalModelProvider(runtime=runtime, endpoint=endpoint, model=model, fallback=default)
