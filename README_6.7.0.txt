NetworkAutomation UI 6.7.0 - Presence Sync + Live Discovery Progress

- /api/devices and /api/dashboard now use web_presence_state64 as canonical current status.
- Legacy ping/health remain diagnostic fallback only when no Presence row exists.
- Startup LAN discovery reports preliminary ARP/DHCP/mDNS/SSDP evidence immediately.
- Active sweep exposes progress_done/progress_total/icmp_online while RUNNING.
- UI no longer shows only "dang quet" with zero observable progress.
- UI 6.7.0; Core/API remains 5.9.2-cybersecurity.
