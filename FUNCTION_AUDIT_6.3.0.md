# NetworkAutomation UI 6.3.0 - Function Audit

Audit date: 2026-10-05

## Scope checked

- 63 Web UI pages detected.
- 333 application routes loaded; 330 are `/api` routes.
- 329 unique route/method pairs; 0 duplicates.
- 192 write routes checked against central RBAC/CSRF allow rules; 0 missing rules.
- 136 authenticated GET endpoints smoke-tested against a disposable database; 121 returned 200 and 15 returned expected 404 for nonexistent object IDs; 0 returned 5xx.
- Python source compiled successfully.
- Main JavaScript assets passed syntax checking.
- Login with MFA policy disabled for the disposable audit runtime succeeded.
- CSV IP/MAC file import succeeded.
- ActiveLAN result import succeeded and produced an `Active` IP/MAC record.
- Presence refresh was simulated with ICMP blocked + ARP evidence and correctly classified the device as online via ARP.

## Functional fixes in 6.3.0

1. **IP/MAC scan import**: `ActiveLAN` records produced by rich discovery (ARP/DHCP/mDNS/SSDP) are now imported. 6.2.5 only imported `Online` and legacy `ActiveARP` rows.
2. **Presence accuracy**: dashboard status refresh now combines bounded ICMP checks with current ARP/neighbor-table evidence. Devices that are active on Layer 2 but block ping are no longer automatically shown as offline.
3. **Unknown vs Offline**: dashboard no longer counts every non-online result as offline. `Unknown` is shown separately in the device list to reduce false alarms.
4. **ActiveLAN badge**: UI styling now treats `ActiveLAN` as an active state.
5. **Function Audit**: `Quản trị > Kiểm tra chức năng` now includes Web runtime, Login/MFA, file-import dependency readiness, rich LAN discovery evidence, endpoint monitoring, SIEM/vulnerability, and network-quality coverage.

## Important runtime checks still requiring the real Windows host/network

These cannot be truthfully certified in an isolated build container and must be validated on the target PC/device environment: real ICMP/ARP visibility across VLANs, SSH authentication/host-key trust, SNMPv2/v3 responses, Windows Service recovery, router/DHCP visibility, endpoint-agent check-in, camera/Wi-Fi diagnostics, and real backup/restore against managed devices.

The built-in **Quản trị > Kiểm tra chức năng** page is intended to show setup/readiness gaps on that machine without changing network devices.
