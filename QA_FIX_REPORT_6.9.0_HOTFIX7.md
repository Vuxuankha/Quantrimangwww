# QA Hotfix 7 - 35-function Cybersecurity Catalog

## Scope
Expanded the UI architecture to the full requested 35-function catalog while preserving the two explicit zones:
- 17 White-Hat / Blue-Team / GRC functions.
- 18 Red-Team functions implemented as isolated, non-networked simulation/defense labs.

## Defensive additions
TLS configuration audit, internal NTA flow analysis, API metadata audit, source-code secret pattern scan, local SHA-256 file hashing, firewall blocklist planning, IAM privilege review, IR playbook builder, Dockerfile review, browser-local FIM hash compare, process-tree behavior review, and phishing-awareness campaign planning.

## Red-Team safety boundary
Advanced offensive categories are represented as offline simulators and defensive-control evaluators. They do not transmit exploit payloads, brute-force credentials, sniff interfaces, create tunnels/persistence, alter privileges, or erase logs.

## QA
See `tests/test_hotfix7_security_catalog35.py` for architecture, safety-boundary, local hashing, and asset-loading regression coverage.
