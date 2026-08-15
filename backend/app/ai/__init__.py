"""AI provider layer for the Ask chat.

Phase 1 (architecture extraction only): the current deterministic chat generation
is lifted behind ``AIProvider``; retrieval/grounding and citation ownership stay in
the request handler. No model, no network, no behavior change.
"""
from .citations import citation_key, dedupe_citations, validate_citations
from .contract import AIProvider, GroundedContext, ProviderCapabilities, ProviderStatus
from .deterministic_provider import DETERMINISTIC_PROVIDER, DeterministicProvider
from .local_model_provider import (
    LocalModelProvider,
    build_grounded_messages,
    resolve_ai_provider,
)

__all__ = [
    "AIProvider",
    "GroundedContext",
    "ProviderStatus",
    "ProviderCapabilities",
    "DeterministicProvider",
    "DETERMINISTIC_PROVIDER",
    "LocalModelProvider",
    "resolve_ai_provider",
    "build_grounded_messages",
    "citation_key",
    "dedupe_citations",
    "validate_citations",
]
