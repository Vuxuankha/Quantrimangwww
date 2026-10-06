# QA Fix Report 6.7.0

## Fixed
- `/api/devices` and `/api/dashboard` now prefer `web_presence_state64` for current Online/Offline/Unknown status.
- Legacy ping/health data remains diagnostic evidence and fallback only when Presence has no row.
- Startup LAN discovery now publishes passive ARP/DHCP/mDNS/SSDP evidence before the active sweep finishes.
- Discovery status now exposes `progress_done`, `progress_total`, `preliminary_active`, and preliminary device rows.
- `/api/v50/connected-devices` returns preliminary passive LAN results while discovery is still RUNNING/QUEUED.
- UI chip now shows found IP count and scan progress instead of only `dang quet`.

## Regression
- 9 unit tests PASS, including a runtime-style database test proving Presence Offline overrides legacy Device Unknown.
- Regression smoke PASS.
- Release checks PASS before manifest regeneration.
