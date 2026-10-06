# QA Hotfix 3 - 6.9.0

## Reproduced Windows failure
Hotfix2 could install `cryptography` successfully into `.venv` and pass `pip check`, then still fail at runtime import with `No module named 'cryptography'`.

## Root cause
The first `ONECLICK_SETUP.py` process continued running under the system Python that launched it. Creating/installing packages into `.venv` does not change `sys.executable` or `sys.path` of that already-running process. `ensure_runtime()` then imported `IMPORT_APP_DATA` in the old interpreter, which could not see `.venv`'s `cryptography` package.

## Fix
After dependency bootstrap, OneClick now detects whether the current interpreter is `.venv\\Scripts\\python.exe`. If not, it restarts itself under that interpreter with a guarded bootstrap marker before any runtime-data import. The child validates that it is really running under the expected venv.

## Regression coverage
Added checks that dependency installation occurs first, venv relaunch occurs before `ensure_runtime()`, and the relaunch command uses the venv Python plus a guard marker.
