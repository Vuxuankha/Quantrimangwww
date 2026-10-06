# QA Fix Report 6.9.0 Hotfix13 - Auth Guard

## Field symptom
A user can enter White Hat pages successfully, then a later HTTP 401 from a child/feature API causes the global frontend wrapper to call `showLogin()` immediately. This makes a valid browser session appear to be logged out.

## Root cause
Both `app.js` and `operations47.js` treated every 401 from every protected endpoint as definitive proof that the login session had expired. `operations47.js` also overrides the global `api()` function, so fixing only `app.js` is insufficient.

## Fix
- A non-login 401 now triggers a direct `/api/auth/me` confirmation request.
- The UI returns to the login screen only when `/api/auth/me` itself confirms HTTP 401.
- Transient/feature-specific 401 responses no longer destroy valid client auth state.
- A successful auth probe refreshes `state.user` and the CSRF token.
- Both the base API wrapper and the Operations 4.7 override use the same auth-loss confirmation logic.
- Static cache revision bumped to `6913`.

## Data safety
No passwords, MFA secrets, sessions, devices, IP/MAC data, SIEM records, credentials, backups, or runtime database content are deleted by this patch.
