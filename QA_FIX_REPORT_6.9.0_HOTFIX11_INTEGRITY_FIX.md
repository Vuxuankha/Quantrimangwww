# QA Fix - 6.9.0 Hotfix11 Integrity/OneClick

Fixed the OneClick release verification failure caused by mutable runtime database data being included in the immutable release manifest.

Changes:
- Removed `database/network_automation.db` from `RELEASE_MANIFEST.json`.
- Added an explicit mutable-file allowlist in `VERIFY_RELEASE.py` for database/key/known_hosts so legacy manifests cannot block an update because operator data changed.
- Updated the OneClick success banner from HOTFIX3 to HOTFIX11.
- Recomputed manifest hashes for all 239 immutable code/assets.

Validation:
- `VERIFY_RELEASE.py --json`: PASS, 239 immutable files checked.
- Verification still PASS after intentionally mutating `database/network_automation.db`.
- Python compileall: PASS.
- `regression_test.py`: PASS.

Runtime/operator database and credential material remain preserved and are not reset by this fix.
