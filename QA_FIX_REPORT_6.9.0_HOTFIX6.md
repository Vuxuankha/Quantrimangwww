# QA Hotfix6 - Security Modes

## Scope
- Split the UI into a dedicated White-Hat defensive group and a separate isolated Red-Team Lab group.
- Reuse the existing authorized/private-LAN discovery and defensive vulnerability/SIEM/endpoint features.
- Add local-only Web header, log and password-strength analyzers.
- Add six Red-Team training simulators for injection, XSS/CSRF, authentication resilience, packet inspection, IDOR/access control and capacity/load modeling.

## Safety boundary
Red-Team Lab is simulation-only: it does not send attack payloads, perform credential attempts, sniff a live network interface, bypass access controls, or generate request floods/DDoS traffic.

## Verification
- `python -m pytest -q`: 42 passed.
- `node --check webapi/static/security_modes61.js`: passed.
- `python VERIFY_RELEASE.py`: RELEASE OK, 227 code/assets checked.
