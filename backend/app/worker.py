from __future__ import annotations

from .store import store


def run_once() -> dict[str, int]:
    """Process queued demo jobs once.

    This placeholder marks jobs complete and gives the real worker pipeline a
    stable entrypoint for ZIP extraction, parser, OCR, chunking, local AI
    classification, extraction, citation mapping, and validation routing.
    """

    return {"processed": store.process_queued_jobs()}


if __name__ == "__main__":
    result = run_once()
    print(f"Processed {result['processed']} Monday Report job(s).")
