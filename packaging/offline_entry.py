"""PyInstaller entry point for the Monday Report Offline Edition executable."""
from __future__ import annotations

import multiprocessing
import sys


def run() -> int:
    multiprocessing.freeze_support()
    from backend.app.offline_runtime import main

    return main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(run())
