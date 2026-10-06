from __future__ import annotations
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNTIME_DATA = ROOT / 'runtime_data'
SEED_DATA = ROOT / 'seed_data'
CONFIG = ROOT / 'data_location.json'


def _copy_seed_file(rel: str) -> None:
    src = SEED_DATA / rel
    dst = RUNTIME_DATA / rel
    if src.is_file() and not dst.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def ensure_runtime_seed() -> Path:
    """Create isolated Web runtime data once from the packaged healthy seed.

    Existing runtime DB/key/known_hosts are never overwritten by normal start.
    The legacy ROOT/database tree is intentionally ignored.
    """
    db = RUNTIME_DATA / 'database' / 'network_automation.db'
    if db.exists():
        # Never pair an existing DB with a different seed key.
        return RUNTIME_DATA.resolve()
    if (RUNTIME_DATA / 'database' / '.credential.key').exists():
        raise RuntimeError('Runtime key exists but database is missing. Restore the matching DB; do not seed over existing data.')
    if not (SEED_DATA/'database'/'network_automation.db').is_file():
        raise RuntimeError('Code-only release: run IMPORT_APP_DATA.bat to keep your current data, or CREATE_EMPTY_RUNTIME.bat for a new installation. Nothing was reset.')
    from IMPORT_APP_DATA import prepare_snapshot
    prepare_snapshot(SEED_DATA, RUNTIME_DATA, RUNTIME_DATA.resolve())
    return RUNTIME_DATA.resolve()


def resolve_web_data(*, use_external: bool = False) -> tuple[Path, str]:
    """Resolve Web data without ever consulting inherited Windows env vars.

    Default: isolated runtime_data next to the Web package.
    External data: only when the caller explicitly requests it AND
    CONFIGURE_WEB.bat has created data_location.json.
    """
    if not use_external:
        return ensure_runtime_seed(), 'isolated runtime_data'
    if not CONFIG.exists():
        raise RuntimeError('Chua cau hinh external data. Chay CONFIGURE_WEB.bat truoc.')
    try:
        obj = json.loads(CONFIG.read_text(encoding='utf-8-sig'))
        value = obj.get('data_dir')
        if not value:
            raise ValueError('missing data_dir')
        selected = Path(value).expanduser().resolve()
    except Exception as exc:
        raise RuntimeError(f'data_location.json khong hop le: {exc}') from exc
    return selected, 'data_location.json (explicit external mode)'
