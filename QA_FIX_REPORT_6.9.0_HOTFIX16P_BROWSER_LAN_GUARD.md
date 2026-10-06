# QA Fix Report - 6.9.0 Hotfix16P Browser LAN Guard

## Problem
On Render, legacy Network Scan paths could still execute from the server process. The discovered subnet/devices therefore belonged to the Render host environment, not to the PC/phone opening the website.

## Fix
- Hard-block `_run_scan()` whenever `NA_WEB_ONLY_BROWSER=1`.
- Hard-block queued `SCAN` jobs before submission in browser-only mode.
- Hard-block `autodiscovery5010.ensure()` so automatic engines cannot discover the Render host LAN.
- Replace the Web scan page with a browser-only limitation panel instead of a CIDR scan form.
- Remove misleading LAN scan actions/toasts when browser-only mode is active.
- Bump static asset version to `6921` to prevent stale cached JS after deploy.

## Important architectural boundary
A website hosted on Render cannot enumerate the private LAN of the visiting browser (ARP/MAC/gateway/all 192.168.x.x hosts). Modern browsers intentionally do not expose a general API for this. Hotfix16P therefore prevents false host-side results. Real client-LAN discovery requires an execution point inside that LAN (local agent/native helper, managed router/controller API, or collector appliance).

## Expected result on Render
- Public IP / HTTPS quality checks: available.
- Render-host LAN discovery: disabled.
- Client private-LAN enumeration: explicitly unavailable in pure Web-only mode.

## QA result
- Regression smoke: PASS
- Production gate: 41/41 PASS
- Release integrity: 277 files PASS
- Pytest regression: 107/107 PASS
- Initial payload remains within Hotfix16O budget: 146255 raw bytes / 42481 gzip bytes.
