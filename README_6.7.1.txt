NetworkAutomation UI 6.7.1 - Live Discovery Source Fix + External Data Self-Check

- Fix preliminary Live Discovery sources when data is already a Python list/tuple/set.
- Correct source_counts for ARP/DHCP/mDNS/SSDP during RUNNING/QUEUED scans.
- Preserve completed scan DB source strings such as ARP,MDNS.
- SELF_CHECK now supports --data-dir, NETWORK_AUTOMATION_DATA_DIR, and --external-data/data_location.json.
- SELF_CHECK is read-only for data resolution and does not seed/copy a database.
- SELF_CHECK.bat forwards command-line options to SELF_CHECK.py.
- Regression label updated to 6.7.1.
- UI 6.7.1; Core/API remains 5.9.2-cybersecurity.
