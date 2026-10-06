# QA Fix Report - 6.9.0 Hotfix16e Render Dependencies

## Problem
Render successfully executed `python render_start.py` but exited with:

`ModuleNotFoundError: No module named 'uvicorn'`

The service had installed only the root `requirements.txt`, while the web stack
had previously been split into `requirements-web.txt`.

## Fix
- Merged the required web/Render packages into root `requirements.txt`.
- Kept `requirements-render.txt` as a thin include of the complete root file.
- This supports both of these Render build commands:
  - `pip install -r requirements.txt`
  - `pip install -r requirements-render.txt`
- No runtime database, key, lock or credential file is added to Git.

## Required Render start command
`python render_start.py`

## Expected result
`uvicorn` is available when `render_start.py` starts and the service proceeds to
FastAPI/Uvicorn startup instead of exiting with `ModuleNotFoundError`.
