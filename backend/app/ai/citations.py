"""Backend-owned citation utilities.

``dedupe_citations`` is moved here unchanged (it was defined in ``main.py`` and is
shared by the chat path and the report-draft route). ``citation_key`` is the exact
identity used by the dedupe, extracted so validation keys the same way.

``validate_citations`` is the anti-invention control: a citation is only allowed
through if its identity is present in the grounded set the backend actually
retrieved. A provider therefore cannot introduce a source that was never grounded.
For the deterministic provider — which only ever emits citations drawn from that
same grounded set — this is a proven no-op (see ``scripts/ai_provider_guard.py``).
"""
from __future__ import annotations

import json


def citation_key(citation) -> str:
    """Stable identity of a citation, excluding the volatile per-object ``id``.

    Identical to the key ``dedupe_citations`` has always used, so dedupe behavior
    is byte-for-byte unchanged.
    """
    return json.dumps(
        {
            "file_id": str(citation.file_id) if citation.file_id else None,
            "locator_type": citation.locator_type,
            "locator": citation.locator,
            "snippet": citation.snippet,
        },
        sort_keys=True,
    )


def dedupe_citations(citations: list) -> list:
    seen: set[str] = set()
    unique = []
    for citation in citations:
        key = citation_key(citation)
        if key in seen:
            continue
        seen.add(key)
        unique.append(citation)
    return unique[:8]


def validate_citations(citations: list, allowed: list) -> list:
    """Return only the citations whose identity is present in ``allowed`` (the
    grounded evidence the backend retrieved), preserving order. Drops any
    fabricated / out-of-set citation. No-op when every citation is already grounded.
    """
    allowed_keys = {citation_key(candidate) for candidate in allowed}
    return [citation for citation in citations if citation_key(citation) in allowed_keys]
