# QA Fix Report — UI 6.9.0 Hotfix15 Scheduler/API Stability Fix

## Scope
This hotfix addresses the remaining findings from the independent full-function QA pass on Hotfix14.

## Fixes
1. **Scheduler HTTP semantics**
   - Missing schedule: `404 Schedule not found` instead of an unhandled 500.
   - Disallowed role: `403 TASK_PERMISSION_DENIED` instead of an unhandled 500.
2. **Role-aware Scheduler UI**
   - `/api/v4/schedules` returns `can_run` for the current user.
   - UI replaces Run now with a non-actionable permission message when execution is not allowed.
3. **Accurate Scheduler status**
   - `web_schedules40.last_status` mirrors the worker job state through Running and final states.
4. **First-use API stability**
   - Scan-result import creates `web_scan_results` before lookup.
   - Security-event close initializes enterprise security tables before lookup.
5. **MFA admin API contract**
   - Reset for a missing user returns 404.
6. **Validation handling cleanup**
   - A single sanitized `RequestValidationError` handler remains registered.

## Regression coverage
`tests/test_hotfix15_scheduler_api_stability.py` adds focused regression tests for the above behavior.

## Visible release marker
`UI 6.9.0 · QA Hotfix15 Scheduler/API Stability Fix` with cache-buster `6915`.

## Independent validation after patch
- `pytest`: **84 passed**.
- Regression smoke: **PASS**.
- Release integrity: **256/256 tracked files PASS** before packaging.
- Runtime Admin/MFA flow: **PASS**.
- Missing schedule run: **404**.
- Operator running Admin-only DB backup schedule: **403** and `can_run=false`.
- Admin DB backup schedule: worker and schedule both finished **Completed**.
- Scan-result first-use import with table removed: **404**, no 500.
- Security-event first-use close with table removed: **404**, no 500.
- MFA reset for missing user: **404**.
- Full authenticated GET sweep: **145 routes, 0 HTTP 500 / 0 exceptions**.
- Central write authorization: **202 write routes, 0 unmatched rules**.
