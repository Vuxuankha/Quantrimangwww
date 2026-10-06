# QA Fix Report 6.9.0 Hotfix8 — Kali Linux Integration

- Added a dedicated Kali Linux worker over pinned SSH.
- Password is encrypted with the existing application credential vault; it is never returned by the API.
- Added host-key fingerprint probe and strict fingerprint pinning before authentication.
- Added safe defensive Kali profiles: private-LAN discovery, private-host TCP/service assessment (top 100 ports), TLS audit, private-Web header audit, and Kali worker network-state diagnostics.
- Active targets are restricted to private/loopback/link-local address space; CIDR ranges are capped at 4096 addresses.
- Red Team pages remain simulation-only and are not remotely executed on Kali.
- Added UI page under Hacker Mu Trang for configuration, tool status, connection test and task execution.
- Existing defensive pages Network Discovery, Vulnerability/Service Scan, TLS Auditor and Web Header Auditor now include a Kali execution panel, so the user does not need to leave the feature page.
