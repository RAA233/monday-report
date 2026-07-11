from __future__ import annotations

import os
import time
from datetime import datetime, timezone

from backend.app.store import store


def main() -> int:
    poll_seconds = poll_interval()
    print(f"Monday Report worker loop started; polling every {poll_seconds:.1f}s.", flush=True)
    while True:
        try:
            processed = store.process_queued_jobs()
            if processed:
                timestamp = datetime.now(timezone.utc).isoformat()
                print(f"{timestamp} processed {processed} job(s).", flush=True)
        except KeyboardInterrupt:
            print("Monday Report worker loop stopped.", flush=True)
            return 0
        except Exception as exc:  # noqa: BLE001 - partner preview loop should stay alive and visible.
            timestamp = datetime.now(timezone.utc).isoformat()
            print(f"{timestamp} worker error: {exc!r}", flush=True)
        time.sleep(poll_seconds)


def poll_interval() -> float:
    raw_value = os.getenv("MONDAY_REPORT_WORKER_POLL_SECONDS", "3").strip()
    try:
        return max(1.0, min(float(raw_value), 30.0))
    except ValueError:
        return 3.0


if __name__ == "__main__":
    raise SystemExit(main())
