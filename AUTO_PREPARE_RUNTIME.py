"""Prepare the local Web runtime automatically from an existing NetworkAutomation data set.

This is intentionally non-interactive and does not start/stop services.  It is used by
START_WEB.bat as a recovery path when a freshly extracted code-only release does not
have runtime_data yet.  The source database is only read; ONECLICK_SETUP.ensure_runtime
creates and validates a snapshot before committing it locally.
"""
from __future__ import annotations

from ONECLICK_SETUP import ensure_runtime


def main() -> int:
    try:
        path = ensure_runtime()
        print(f"[DATA] Runtime ready: {path}")
        return 0
    except Exception as exc:
        print(f"[DATA] AUTO PREPARE FAILED: {type(exc).__name__}: {exc}")
        print("[DATA] Existing databases/credential keys were not reset.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
