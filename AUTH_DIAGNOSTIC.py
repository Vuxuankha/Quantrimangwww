"""Read-only authentication compatibility check used by OneClick.

This never changes passwords, users, MFA secrets, sessions, or application data.
It verifies that the preserved runtime has at least one enabled Admin account and
that the active Python environment can read every enabled account password hash.
"""
from __future__ import annotations
import os
import sqlite3
import sys
from collections import Counter
from run_web import resolve_data


def main() -> int:
    root = resolve_data()
    os.environ['NETWORK_AUTOMATION_DATA_DIR'] = str(root)
    db = root / 'database' / 'network_automation.db'
    if not db.is_file():
        print('[AUTH] FAIL: runtime database is missing')
        return 2
    with sqlite3.connect(db) as c:
        c.row_factory = sqlite3.Row
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'app_users' not in tables:
            print('[AUTH] FAIL: app_users table is missing. Do not reset data automatically.')
            return 3
        rows = c.execute('SELECT id,username,role,enabled,password_hash FROM app_users ORDER BY id').fetchall()
    enabled = [r for r in rows if int(r['enabled'] or 0) == 1]
    admins = [r for r in enabled if str(r['role'] or '').casefold() == 'admin']
    if not admins:
        print('[AUTH] FAIL: no enabled Admin account exists. Use RESET_WEB_PASSWORD.bat locally after confirming the correct runtime.')
        return 4
    collisions = [name for name,count in Counter(str(r['username']).casefold() for r in enabled).items() if count > 1]
    if collisions:
        print('[AUTH] FAIL: duplicate enabled usernames differ only by letter case. Resolve locally before login.')
        return 5
    unsupported=[]
    needs_argon=False
    for r in enabled:
        h=str(r['password_hash'] or '')
        if h.startswith('$argon2'):
            needs_argon=True
        elif h.startswith('pbkdf2_sha256$'):
            pass
        else:
            unsupported.append(str(r['username']))
    if unsupported:
        print('[AUTH] FAIL: unsupported legacy password hash exists for enabled account(s).')
        print('[AUTH] Use RESET_WEB_PASSWORD.bat for the affected local account; OneClick will not rewrite passwords automatically.')
        return 6
    if needs_argon:
        try:
            import argon2  # noqa: F401
        except Exception as exc:
            print('[AUTH] FAIL: Argon2 password backend is unavailable:', type(exc).__name__)
            return 7
    print(f'[AUTH] OK: enabled_users={len(enabled)}, enabled_admins={len(admins)}, password_hash_backend=ready')
    print('[AUTH] Username matching is case-insensitive; password matching remains exact and is never reset by OneClick.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
