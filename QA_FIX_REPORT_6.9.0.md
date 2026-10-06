# QA / Function Update 6.9.0

Focus: "Việc cần làm hôm nay" automatic completion.

Implemented:
- Admin-only persistent safe-auto switch.
- Background cycle every 300 seconds.
- Immediate Run Now action.
- Safe steps: Presence, LAN Discovery, Alert Rules, Incident/RCA, Line Quality, DB Backup.
- Underlying risk remains visible until it is actually clear.
- No automatic alert/case closure, vulnerability remediation, MFA enrollment, endpoint protection changes, credential/config writes, delete or restore.
- Per-category automation evidence and history.
QA hotfix validation (2026-10-05):
- Fixed misleading `auto_completed_today=true` when the safe-auto execution succeeded but one or more checklist categories still require human attention.
- Added regression coverage for PASS + remaining attention => not completed.
- Added test bootstrap so both `pytest -q tests` and `python -m pytest -q tests` resolve the release package consistently.
- Verified with a fresh isolated runtime, mandatory MFA login, live HTTP API calls, Run Now execution, DB backup creation, and post-run checklist state.

