# QA / Function Update 6.8.0

## Fixed
- Vulnerability Center no longer calls missing `/api/ipmac`; it uses `/api/v45/ipmac`.

## Added
- Master Automation one-switch control in the main Operations Center.
- Persistent coordinator state and per-task history.
- Bounded background task pool with no overlapping run of the same task.
- Safe scheduled tasks: Presence, LAN Discovery, Alert Rules, Incident/RCA, Server Monitor, Line Quality and DB Backup.
- Destructive/intrusive actions remain manual-only.

## QA
- Python compile PASS.
- JavaScript syntax PASS.
- Unit tests include Master Automation enable/disable and safety registry.
