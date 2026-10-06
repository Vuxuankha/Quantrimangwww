# QA Fix Report 6.7.1

## Tester findings addressed

### P2 - Live Discovery preliminary `sources` parsing
The 6.7.0 endpoint converted a preliminary list such as `['ARP','MDNS']` to a string and split it, producing malformed badges and zero source counters. 6.7.1 normalizes both in-memory lists and completed DB comma strings before counting.

Expected running-scan result now remains:

```json
{
  "sources": ["ARP", "MDNS"],
  "source_counts": {"ICMP": 0, "ARP": 1, "DHCP": 1, "MDNS": 1, "SSDP": 0}
}
```

### P3 - SELF_CHECK custom/external data directory
`SELF_CHECK.py` now resolves data in this order:

1. `--data-dir <path>`
2. `NETWORK_AUTOMATION_DATA_DIR`
3. `--external-data` using the shared `data_location.json` resolver
4. normal isolated `runtime_data`

The check only reads the selected database and does not seed or copy operator data.

## Regression
- Added direct runtime-style endpoint test for `/api/v50/connected-devices` while discovery is RUNNING.
- Added tests for preliminary list sources, completed DB source strings, and source counts.
- Added tests for SELF_CHECK environment, explicit data-dir, and external resolver.
- Existing Presence, device lifecycle, Analyst role and source-of-truth regression tests retained.
