"""Local deployment safety. Does not alter desktop configuration or choose a DB by size."""
from __future__ import annotations
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import uuid

VERSION='5.9.2-cybersecurity'
UI_VERSION='6.9.0'
RELEASE='Hotfix16R Router Auto Sync'
SERVICE = 'networkautomation-operational-web'

def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

@contextmanager
def connection():
    from database.db import get_connection
    c = get_connection()
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()

def sqlite_snapshot(source: Path, destination: Path):
    """Online SQLite backup, including WAL state; refuses to overwrite an existing file."""
    if not source.is_file():
        raise FileNotFoundError('Existing database is required')
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    try:
        with sqlite3.connect(source.resolve().as_uri() + '?mode=ro', uri=True) as src:
            with sqlite3.connect(destination) as dst:
                src.backup(dst, pages=256)
                if dst.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                    raise RuntimeError('Backup quick_check failed')
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return destination

class DataLock:
    """Held for the whole server lifetime; OS releases it on process termination."""
    def __init__(self, path):
        self.path, self.file = Path(path), None
    def acquire(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = open(self.path, 'a+b')
        self.file.seek(0)
        if not self.file.read(1):
            self.file.write(b'0'); self.file.flush()
        self.file.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close(); self.file = None
            raise RuntimeError('Another Web instance uses this data folder. Close it first; no process was killed.')
    def release(self):
        if self.file:
            self.file.close(); self.file = None

def preflight():
    from app_runtime import DATABASE_DIR
    from database.db import DB_PATH
    path = Path(DB_PATH)
    if not path.exists() and os.environ.get('NA_ALLOW_EMPTY_DB') != '1':
        raise RuntimeError('Database not found. Run CONFIGURE_WEB.bat and select the existing desktop folder. No new DB was created.')
    if not path.exists():
        return None
    with sqlite3.connect(path.resolve().as_uri()+'?mode=ro', uri=True) as c:
        if c.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise RuntimeError('Database quick_check failed. Run VERIFY_WEB_DATA.bat. Do not overwrite or migrate this database.')
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'devices','network_devices'} & tables:
            raise RuntimeError('This is not the expected NetworkAutomation database.')
        encrypted = False
        for table in tables:
            qt='"'+table.replace('"','""')+'"'
            cols=[r[1] for r in c.execute('PRAGMA table_info('+qt+')')]
            for col in cols:
                qc='"'+col.replace('"','""')+'"'
                if col.endswith('_enc') and c.execute('SELECT 1 FROM '+qt+' WHERE '+qc+" IS NOT NULL AND "+qc+"<>'' LIMIT 1").fetchone(): encrypted=True
        if 'settings' in tables:
            for key,value in c.execute('SELECT key,value FROM settings'):
                if str(key).endswith('_enc') and value:encrypted=True
        if encrypted and not (Path(DATABASE_DIR)/'.credential.key').is_file():
            raise RuntimeError('Encrypted credentials exist but .credential.key is missing. Restore the original key; do not generate a replacement.')
    marker = Path(DATABASE_DIR)/'.web_migration_37.json'
    if not marker.exists():
        backup = Path(DATABASE_DIR)/'web_preupgrade_backups'/('before_37_'+datetime.now().strftime('%Y%m%d_%H%M%S')+'_'+uuid.uuid4().hex[:8]+'.db')
        sqlite_snapshot(path, backup)
        return backup
    return None
