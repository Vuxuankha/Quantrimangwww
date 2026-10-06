# QA Hotfix16g - Render startup headless Tk fix

## Symptom
Render reached Uvicorn startup but failed in FastAPI lifespan with:
`ModuleNotFoundError: No module named '_tkinter'`.
The failing import path was `webapi.migrate37 -> modules.extra_pages`; the next schema path also imported `modules.nms_v3 -> modules.nms_v4`, both desktop/Tk modules.

## Fix
- Made Tkinter imports optional in `modules/extra_pages.py`.
- Made Tkinter imports optional in `modules/nms_v3.py` and `modules/nms_v4.py`.
- Database/schema helpers remain available on headless Linux/Render.
- Desktop Tk UI behavior is unchanged when Tkinter is present.

## Verification
- Simulated a Python environment where `_tkinter` raises ImportError.
- Imported `webapi.main` successfully.
- Ran `ensure_support_tables()` successfully.
- Started `render_start.py` under the same headless simulation and verified `/api/health` returns HTTP 200.
