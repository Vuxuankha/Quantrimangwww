# UI 6.9.0 Hotfix15 Scheduler/API Stability Fix

This build is based on Hotfix14 and fixes the remaining QA findings from full functional testing.

## Fixed
- Scheduler run-now now returns 404 for a missing schedule and 403 for a role that is not allowed to execute the scheduled operation.
- Scheduler list returns `can_run`; the UI does not show an actionable Run now button for disallowed operations.
- Scheduled rows now mirror the real worker job status through completion/failure/cancellation.
- `/api/scan-results/{id}/import` creates the scan-results table before lookup, eliminating first-use 500 responses.
- `/api/v45/security/events/{id}/close` ensures enterprise-security tables exist before lookup.
- MFA reset returns 404 for a non-existent user.
- Removed the duplicate RequestValidationError handler and retained the sanitized handler.
- Visible build marker/cache-buster updated to Hotfix15 / 6915.
