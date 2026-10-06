# QA Fix Report 6.9.0 Hotfix16h - Render Admin Bootstrap

## Problem
A Render AutoDB deployment starts with an empty `app_users` table. Credentials from the Windows/local SQLite database therefore cannot authenticate and the web UI reports `INVALID_CREDENTIALS`.

## Fix
- Added one-time first-admin bootstrap to `render_start.py`.
- `NA_BOOTSTRAP_ADMIN_USER` optionally sets the first username (default `Admin`).
- `NA_BOOTSTRAP_ADMIN_PASSWORD` is required only while the database has zero users.
- No default password is embedded in source or logs.
- Once any account exists, bootstrap variables are ignored and cannot overwrite credentials on restart.

## Render settings
Set environment variables before deploy:
- `NA_BOOTSTRAP_ADMIN_USER=Admin` (optional)
- `NA_BOOTSTRAP_ADMIN_PASSWORD=<your strong password>`

On Render Free, the filesystem is ephemeral. If the service receives a fresh filesystem, the account will be recreated from these environment variables.
