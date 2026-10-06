# QA Fix Report 6.9.0 Hotfix2

## Windows OneClick bootstrap defect

Observed on a real Windows run: `ONECLICK FAILED: No module named 'cryptography'`.

Root cause: `ensure_runtime()` could import `IMPORT_APP_DATA` before `ensure_venv_and_dependencies()` had installed `cryptography>=42` into the release `.venv`.

Fix: OneClick now creates/verifies the isolated environment and installs requirements before runtime discovery/import. Existing runtime/database/key preservation semantics are unchanged.

Regression coverage: `tests/test_oneclick_bootstrap690.py` prevents the dependency/runtime order from being reversed again.
