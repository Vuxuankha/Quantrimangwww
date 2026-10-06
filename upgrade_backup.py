"""Consistent local snapshots before each application release's first migration."""
import json
import os
import shutil
import sqlite3
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

_LOCK = threading.Lock()


@contextmanager
def _release_lock(base):
    from agent_runtime import AgentLock
    lock = AgentLock(base / '.release_backup.lock')
    deadline = time.monotonic() + 30
    while True:
        try:
            lock.__enter__()
            break
        except RuntimeError:
            if time.monotonic() >= deadline:
                raise RuntimeError('Đang sao lưu trước nâng cấp; hãy đợi rồi mở lại ứng dụng.') from None
            time.sleep(.02)
    try:
        yield
    finally:
        lock.__exit__(None, None, None)


def backup_before_release(database_path, resource_dir, version=None):
    database_path = Path(database_path)
    base = database_path.parent
    version = version or (Path(resource_dir) / 'VERSION.txt').read_text(encoding='utf-8').strip()
    if not version or any(c not in '0123456789.' for c in version):
        raise ValueError('Invalid application version')
    marker = base / f'.release_backup_{version}.json'
    base.mkdir(parents=True, exist_ok=True)
    with _LOCK, _release_lock(base):
        if marker.exists() or not database_path.exists() or database_path.stat().st_size == 0:
            return None
        backups = base / 'db_backups'
        backups.mkdir(parents=True, exist_ok=True)
        pending = Path(tempfile.mkdtemp(prefix='.pending_', dir=backups))
        try:
            source = sqlite3.connect(database_path, timeout=15)
            destination = sqlite3.connect(pending / database_path.name)
            try:
                source.backup(destination)
                if destination.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                    raise RuntimeError('Backup database integrity check failed')
            finally:
                destination.close()
                source.close()
            for name in ('.credential.key', 'known_hosts'):
                if (base / name).is_file():
                    shutil.copy2(base / name, pending / name)
            metadata = {'version': version, 'created_at': datetime.now().isoformat(),
                        'database': database_path.name,
                        'files': sorted(p.name for p in pending.iterdir())}
            (pending / 'manifest.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
            final = backups / f"pre_app_v{version}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
            pending.rename(final)
            temporary_marker = base / f'.release_backup_{version}.tmp'
            temporary_marker.write_text(json.dumps({'backup': str(final)}), encoding='utf-8')
            os.replace(temporary_marker, marker)
            return final
        except Exception:
            shutil.rmtree(pending, ignore_errors=True)
            raise
