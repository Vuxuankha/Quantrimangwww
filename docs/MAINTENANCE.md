# Maintenance

## Normal update
Use `ONECLICK_UPDATE.bat`. Do not manually copy an old database over a running installation.

## Integrity
Run `VERIFY_RELEASE.bat` after extraction or whenever code corruption is suspected.

## Runtime directories
`runtime_data`, logs, reports and backups are operational data and are intentionally not part of release-integrity hashes.

## Development artifacts
Automated tests and historical QA evidence are kept outside this production package. Their removal does not change runtime behavior.
