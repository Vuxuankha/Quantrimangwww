# QA Fix Report 6.9.0 Hotfix12 - Auth Session

## Field symptom
Correct local Admin credentials were accepted but the browser immediately returned to the login view.

## Fix
- Session cookie `Secure` now follows the actual request scheme. Loopback HTTP therefore always receives a usable cookie.
- Session lookup tolerates stale duplicate `na_session` cookies left by older local builds and accepts the first valid session.
- Successful login revokes all old candidate session cookies server-side before issuing a new session.
- Login/static assets use a new cache-busting revision (`6912`).
- Login screen build marker updated to Hotfix12.

## Data safety
No password, MFA secret, device, IP/MAC, SIEM, credential-vault, backup, or operator data is deleted by this patch.
