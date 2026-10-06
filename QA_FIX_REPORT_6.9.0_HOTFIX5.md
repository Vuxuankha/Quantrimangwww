# QA Fix Report 6.9.0 Hotfix5 - Manual Terminal + Select All Ping

Date: 2026-10-05

## Requested changes

1. Terminal SSH/Telnet can connect to a manually entered literal IP, not only a saved managed device.
2. Terminal has an explicit command input and Send button while preserving direct xterm typing.
3. Device inventory has Select All.
4. Bulk Ping supports the full selected inventory up to 2048 devices; SNMP/SSH remain limited to 20 and backup to 5.

## Safety / behavior

- Manual terminal target accepts a validated literal IP only. No hostname/DNS expansion is introduced.
- A manual SSH target cannot reuse a saved device credential implicitly; temporary password or temporary private-key authentication is required.
- SSH host-key trust remains enforced by the existing transport.
- Telnet plaintext acknowledgement remains required.
- Terminal command text is sent only to the active WebSocket session and is not added to the server audit log.
- Select All only selects inventory rows already returned by the existing /devices API. It does not discover or create devices.

## Verification performed

- `python -m py_compile webapi/terminal46.py webapi/operations47.py`: PASS
- `node --check webapi/static/terminal46.js`: PASS
- `node --check webapi/static/operations47.js`: PASS
- `python -m pytest -q`: 37 passed
- `python tools/run_release_checks.py`: PASS
  - 24 unittest regression tests: PASS
  - `regression_test.py`: PASS
- Dedicated Hotfix5 tests verify:
  - manual IP target accepted without inventory id;
  - invalid/ambiguous manual target rejected;
  - manual terminal schema supports optional device id;
  - 100 selected inventory devices produce a valid PING plan;
  - non-PING bulk operations retain the 20-device limit;
  - UI assets contain manual target, command input, and Select All controls.

## Environment limitation

Actual SSH/Telnet connection to the user's physical network devices cannot be executed from the QA sandbox because those private LAN targets are not reachable from this environment. The connection path and validation logic were tested locally; final device-specific authentication/host-key behavior must be confirmed on the user's Windows LAN.
