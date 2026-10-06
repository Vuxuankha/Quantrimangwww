# QA Fix Report — UI 6.6.0 / Core 5.9.2-cybersecurity

## Fixed from tester round 3

- P1: device deletion and `web_presence_state64` cleanup now execute in one SQLite transaction.
- P1: false `success: true` from `bool(non-empty dict)` is removed from the Web delete endpoint.
- P1: `Analyst` is accepted by the account create/edit Pydantic schema.
- P2: `Analyst` is included in the self-password-change authorization rule.
- P2: no hard `[:128]` truncation; Presence keeps bounded batching across the full target set.
- P2: Dashboard Presence remains sourced from `web_presence_state64` summary.
- P3: regression suite is shipped and release checks execute it before PASS.

## Runtime verification performed

- Analyst schema validation: PASS.
- Analyst `/api/auth/password` authorization lookup: PASS.
- Device delete: device row 1 -> 0 and current Presence row 1 -> 0: PASS.
- `DEVICE_DELETE` historical event retained: PASS.
- Simulated Presence delete failure can roll back the device deletion: PASS.
- 8 unit/regression tests: PASS.
- Release integrity: 204+ tracked files after final manifest regeneration.

## Note

A deleted asset that is still physically connected to the LAN may be discovered again later as an **unmanaged/discovered** host. That is intentional network-presence behavior and is distinct from the deleted managed asset record.
