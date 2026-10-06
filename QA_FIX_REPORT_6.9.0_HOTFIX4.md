# QA Hotfix 4 - 6.9.0

## Requested behavior
- Add a visible animated line-quality check instead of an apparently frozen UI.
- When the measured line is FAIR/POOR, offer an Admin-only local Windows optimization and show measured before/after results.

## Implementation
- Added staged Gateway -> Internet -> Latency -> Jitter/Loss progress UI.
- Added lag banner and result action for FAIR/POOR results.
- Added POST `/api/v59/network/optimize` (Admin only, explicit confirmation required).
- The optimization is intentionally conservative: flush Windows DNS cache and restore TCP Receive Auto-Tuning to NORMAL, then re-run the line test.
- The UI explicitly states that local optimization cannot exceed the physical/router/ISP bandwidth limit and never claims a fake Mbps increase.
- Added cache-busting version for the changed network-quality JS/CSS assets.

## Verification
- Python regression suite: 31/31 PASS.
- JavaScript syntax: `node --check webapi/static/cybersecurity51.js` PASS.
- Release integrity: PASS after manifest regeneration.
- Added regression tests for improvement calculation, non-Windows safety, GOOD-line no-op, and POOR -> after-test behavior.

## Environment limitation
The release was verified in Linux CI/sandbox. The actual Windows commands (`ipconfig` and `netsh`) are fixed, bounded, and covered by code-path tests, but their OS-level effect must be validated on the target Windows host because this environment cannot execute Windows networking commands.
