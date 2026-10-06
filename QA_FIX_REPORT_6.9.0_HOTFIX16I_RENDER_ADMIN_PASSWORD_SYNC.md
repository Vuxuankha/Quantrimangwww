# QA Hotfix 16i - Render Admin Password Sync

## Problem
A Render database can already contain the `Admin` user from an earlier deployment. Hotfix16h only created the bootstrap user when the database had zero users, so changing `NA_BOOTSTRAP_ADMIN_PASSWORD` did not update the existing credential and login continued to return `INVALID_CREDENTIALS`.

## Fix
`render_start.py` now treats the Render environment variables as the bootstrap Admin source of truth on each startup:

- `NA_BOOTSTRAP_ADMIN_USER` selects the Admin username (default `Admin`).
- `NA_BOOTSTRAP_ADMIN_PASSWORD` is validated and hashed on startup.
- If the username already exists (case-insensitive), its password is synchronized, role is set to `Admin`, and the account is enabled.
- If it does not exist, the Admin account is created.
- No database deletion is required.

Changing the password secret in Render therefore takes effect after the next redeploy/restart.
