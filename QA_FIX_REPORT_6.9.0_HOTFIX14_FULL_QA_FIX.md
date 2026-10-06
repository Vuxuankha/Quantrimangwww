# QA Fix Report — UI 6.9.0 Hotfix14 Full QA Fix

Core/API remains `5.9.2-cybersecurity`.

## Fixed defects

1. **Kali authentication mismatch**
   - `webapi/kali63.py` now uses the primary `webapi.security37` cookie session/RBAC path.
   - Removed the second `webapi.core.security` dependency from Kali routes.
2. **Missing central write authorization**
   - Added rules for `POST /api/v1/kali/config`, `/test`, `/run`.
   - Added rule for `POST /api/v59/network/optimize`.
3. **Case-insensitive username collision**
   - Account create/update rejects `Alice` vs `alice` collisions.
   - Login keeps exact-case access for legacy databases that already contain such duplicates so an Admin can repair them.
   - Login rate-limit username matching is also case-insensitive.
4. **Duplicate session cookie logout**
   - Logout revokes every `na_session` candidate instead of only one parsed cookie value.
5. **Remote HTTP session downgrade**
   - Plain HTTP is permitted only for the local loopback desktop path.
   - Non-loopback sessions require HTTPS and therefore receive a Secure cookie.
6. **Kali target boundary / DNS rebinding**
   - Single-host profiles resolve once and execute against the approved private IP.
   - HTTP(S) profiles use `curl --resolve` to preserve Host/SNI while pinning the approved private IP.
   - Redirects stay disabled.
   - Capacity probe remains bounded to 10 sequential requests with 200 ms delay.
7. **White-Hat navigation consistency**
   - Fixed `bluesecret62` → `bluesecrets62`.
   - Restored `blueids62` to the final authoritative menu.
8. **Role-aware Kali UI**
   - Admin-only configuration controls are hidden from non-Admins.
   - Remote Kali execution controls are shown only to Admin/Operator.
9. **Release backup marker hygiene**
   - Removed stale packaged `.release_backup_*` markers/lock files so a preserved user database cannot incorrectly skip its first pre-upgrade snapshot for the release.
10. **Release branding/cache**
   - Visible UI marker is now `UI 6.9.0 · QA Hotfix14 Full QA Fix`.
   - Final sidebar brand is `Cybersecurity Platform / UI 6.9.0 · HF14`.
   - Changed assets use cache-buster `6914`.

## Verification evidence

- Python compile: **144 files, 0 failures**.
- JavaScript syntax: **15 files, 0 failures**.
- Pytest: **74 passed**.
- Regression smoke: **PASS**.
- Loaded application routes: **202 private write route-method combinations, 0 unmatched central authorization rules**.
- Runtime Admin GET sweep: **128×200, 15×404 (missing test IDs), 1×409 (Kali not configured), 1×422 (missing required query), 0×401, 0×500**.
- Runtime CSRF sweep: **199/199 authenticated private writes rejected with `CSRF_REJECTED` when the token is omitted**.
- Runtime Kali auth: Admin `GET /api/v1/kali/config` returns **200** (previously 401).
- Runtime Network Optimize authorization: Admin with a valid CSRF reaches handler and receives expected **400 SYSTEM_CHANGE_CONFIRMATION_REQUIRED** when confirmation is false (previously central 403).
- Username collision: first `Alice` create **200**, second `alice` create **400**.
- Legacy duplicate recovery: exact `Alice` and `alice` logins both work with their own passwords; ambiguous `ALICE` remains rejected.
- Remote HTTP login from non-loopback: **403 HTTPS_REQUIRED_FOR_REMOTE_SESSION**.
- Remote HTTPS login: **200** with `Secure` session cookie.

## External integration note

No claim is made that a real Kali SSH host, Windows network optimizer, SNMP device, router/switch, or Internet endpoint was exercised end-to-end in this Linux QA container. Authentication, authorization, validation, target pinning, routing, local workflows, and failure paths were exercised locally; real infrastructure integration still requires the intended Windows/LAN lab.
