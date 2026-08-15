"""AI provider boundary for the Ask chat.

Phase 1 is an **architecture extraction only**: the current deterministic chat
generation is lifted, unchanged, behind this contract. The retrieval / grounding /
citation layer stays in the request handler and is passed in as ``GroundedContext``
so the *answer generator* is swappable later (local model, online API) without
touching how evidence is gathered or how citations are owned/validated.

No behavior change, no model, no network in this phase.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..schemas import ChatResponse


@dataclass
class GroundedContext:
    """Evidence assembled by the backend's deterministic retrieval layer, handed to
    a provider to turn into an answer. A provider may reference only what is here;
    citations are selected/validated by the backend, never invented by a provider.
    """

    content: str
    workspace_id: Any
    failures: list = field(default_factory=list)
    documents: list = field(default_factory=list)
    chunk_count: int = 0
    base_citations: list = field(default_factory=list)
    open_tasks: list = field(default_factory=list)
    benchmark_status: Any | None = None


@dataclass(frozen=True)
class ProviderStatus:
    """What a provider reports about its own availability. Never raises."""

    provider: str
    available: bool
    detail: str = ""


@dataclass(frozen=True)
class ProviderCapabilities:
    """Static description of what a provider can do. The deterministic provider is
    single-shot and stateless; model providers may set these true later."""

    streaming: bool = False
    multi_turn: bool = False
    max_context_tokens: int | None = None


class AIProvider(ABC):
    """A pluggable answer generator. Implementations receive already-grounded
    evidence and return a ``ChatResponse``; they do not fetch data themselves."""

    @abstractmethod
    def name(self) -> str:
        """Stable identifier, e.g. ``"deterministic"``."""

    @abstractmethod
    def generate(self, context: GroundedContext) -> ChatResponse:
        """Produce the chat answer from the grounded context."""

    @abstractmethod
    def health(self) -> ProviderStatus:
        """Report availability without raising."""

    @abstractmethod
    def capabilities(self) -> ProviderCapabilities:
        """Report static capabilities."""
