# QA Fix Report 6.9.0 Hotfix16j - Public Registration

## Scope
Adds self-service username/password registration to the Web login screen.

## Security behavior
- New self-registered accounts are always `Viewer`; the public endpoint cannot grant Admin, Analyst, or Operator privileges.
- Passwords must be at least 12 characters and are stored with the existing Argon2id/PBKDF2 password hashing path.
- Case-insensitive duplicate usernames are rejected.
- Five registration attempts per source address per hour are allowed.
- Total application accounts are capped at 100 through the public registration path.
- `NA_PUBLIC_REGISTRATION` can disable self-registration.
- `NA_REGISTRATION_AUTO_ENABLE` can require Admin approval before first login.

## UI
The login screen now exposes **Đăng ký tài khoản**, opening a username/password/confirmation form. Successful registrations return to the login form with the username prefilled.

## QA
- Registration smoke test: PASS.
- Duplicate username rejection: PASS.
- Viewer-only role assertion: PASS.
- Full project test suite: 88 passed.
