NetworkAutomation UI 6.6.0

QA P1/P2 corrections after three tester rounds.

Fixed:
- Analyst is accepted by POST/PUT /api/accounts.
- Analyst can change its own password via POST /api/auth/password.
- Device delete + current Presence cleanup are one SQLite transaction.
- Delete API no longer converts a non-empty failure dict into success=True.
- Presence history is retained with DEVICE_DELETE audit event.
- Full-inventory Presence batching from 6.5.0 remains enabled; no [:128] truncation.
- Dashboard Presence continues to use web_presence_state64 as the canonical source.

Versioning:
- UI: 6.6.0
- Core/API: 5.9.2-cybersecurity
