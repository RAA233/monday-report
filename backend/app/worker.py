from __future__ import annotations

from .store import store


def run_once() -> dict[str, int]:
    """Process queued ingestion jobs once.

    The store pipeline performs ZIP extraction, parser/OCR routing, chunking,
    failure extraction, citation mapping, and validation routing.
    """

    return {"processed": store.process_queued_jobs()}


if __name__ == "__main__":
    result = run_once()
    print(f"Processed {result['processed']} Monday Report job(s).")
