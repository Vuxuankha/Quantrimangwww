# QA Fix Report — 6.9.0 Hotfix16d Render DB Bootstrap

## Issue
Render startup failed with:

`RuntimeError: Missing seed database: .../database/network_automation.db`

The repository correctly ignores `*.db`, so the runtime launcher must not depend
on a committed SQLite database file.

## Fix
- `render_start.py` no longer copies a seed database from the repository.
- It creates the writable Render data directories first.
- It sets `NETWORK_AUTOMATION_DATA_DIR` before importing database modules.
- It calls the existing `database.db.init_database()` to create/migrate the
  SQLite schema in the runtime data directory.
- `.gitignore` continues to ignore `*.db`, keys, lock files, and environment
  files, so no real database or credential material needs to be pushed to Git.

## Render settings
- Build: `pip install --upgrade pip && pip install -r requirements-render.txt`
- Start: `python render_start.py`
- Health check: `/api/health`

## Storage note
Render Free filesystem is ephemeral. Use a persistent disk and set
`NETWORK_AUTOMATION_DATA_DIR=/var/data` for persistent production data.
