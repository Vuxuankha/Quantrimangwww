NetworkAutomation UI 6.5.0
Core/API: 5.9.2-cybersecurity

Functional reliability upgrade based on QA findings:
- Device delete cleans current Presence state and writes a Deleted audit event.
- Presence no longer truncates managed inventory at 128 devices.
- Presence targets = managed devices + live LAN discovery + recently discovered devices.
- Probing runs in bounded configurable batches (NA_PRESENCE_BATCH_SIZE, NA_PRESENCE_WORKERS).
- Dashboard Online/Offline/Unknown/Total all come from the same Presence source of truth.
- Actual tests/ and regression_test.py are shipped and executed by tools/run_release_checks.py.
- Optional SSH/SNMP dependency absence is WARN; core regression tests still run.
- UI and Core versions are explicitly separate: UI 6.5.0 / Core 5.9.2-cybersecurity.
