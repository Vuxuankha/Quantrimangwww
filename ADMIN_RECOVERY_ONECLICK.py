from __future__ import annotations
import getpass, os, sqlite3, sys, time
from pathlib import Path
from run_web import resolve_data


def _tables(c):
    return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _cols(c, table):
    return {r['name'] for r in c.execute(f'PRAGMA table_info({table})').fetchall()}


def _disable_mandatory_mfa(c):
    """Keep MFA available, but do not force it after a local owner recovery.

    The previous recovery reset the Admin MFA secret while leaving the global
    mfa_required policy enabled. That immediately forced a brand-new enrollment
    on the next login and could strand the owner at INVALID_MFA_CODE. For a local
    127.0.0.1 recovery we clear the recovered Admin's MFA and make MFA optional.
    It can be enabled again later from Security / Administration.
    """
    tables = _tables(c)
    if 'web_security_policy51' in tables:
        c.execute("UPDATE web_security_policy51 SET mfa_required=0,updated_at=datetime('now') WHERE id=1")
        if c.total_changes == 0:
            c.execute("INSERT OR REPLACE INTO web_security_policy51(id,mfa_required,updated_at) VALUES(1,0,datetime('now'))")


def main() -> int:
    root = resolve_data()
    os.environ['NETWORK_AUTOMATION_DATA_DIR'] = str(root)
    db = root / 'database' / 'network_automation.db'
    if not db.is_file():
        print('[RECOVERY] FAIL: database missing')
        return 2

    from modules.nms_v5 import _hash_password, _verify_password, _now, ensure_v5_tables
    ensure_v5_tables()

    backup_dir = root / 'database' / 'web_preupgrade_backups'
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup = backup_dir / f'admin_recovery_{time.strftime("%Y%m%d_%H%M%S")}.db'
    with sqlite3.connect(db) as src, sqlite3.connect(backup) as dst:
        src.backup(dst)

    with sqlite3.connect(db) as c:
        c.row_factory = sqlite3.Row
        cols = _cols(c, 'app_users')
        rows = c.execute('SELECT * FROM app_users ORDER BY id').fetchall()

        admins = [r for r in rows if str(r['role'] or '').casefold() == 'admin']
        enabled_admins = [r for r in admins if int(r['enabled'] or 0) == 1]
        row = enabled_admins[0] if enabled_admins else (admins[0] if admins else None)
        action = 'preserve-enabled-admin' if enabled_admins else ('reenable-admin' if row else '')
        needs_password_reset = not bool(enabled_admins)

        if row is None:
            username_admin = [r for r in rows if str(r['username'] or '').casefold() == 'admin']
            if username_admin:
                row = username_admin[0]
                action = 'promote-existing-admin-username'
                needs_password_reset = True
            else:
                now = _now()
                placeholder = _hash_password('__temporary_local_recovery_password_not_for_login__')
                c.execute(
                    'INSERT INTO app_users(username,password_hash,role,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)',
                    ('Admin', placeholder, 'Admin', 1, now, now),
                )
                row = c.execute('SELECT * FROM app_users WHERE id=last_insert_rowid()').fetchone()
                action = 'create-local-admin'
                needs_password_reset = True
                c.commit()

        print('[RECOVERY] Backup created:', backup)
        print('[RECOVERY] Account action:', action)
        print('[RECOVERY] Admin account:', row['username'])
        print('[RECOVERY] Devices, IP/MAC, SIEM, alerts, cases, vault, backups and credentials are preserved.')

        params = []
        assignments = ["role='Admin'", 'enabled=1', 'updated_at=?']
        params.append(_now())

        new_password = None
        if needs_password_reset:
            print('[RECOVERY] This Admin account needs a password repair.')
            p1 = getpass.getpass('New Admin password (8-256 characters): ')
            p2 = getpass.getpass('Confirm new Admin password: ')
            if p1 != p2:
                print('[RECOVERY] FAIL: passwords do not match')
                return 4
            if not 8 <= len(p1) <= 256:
                print('[RECOVERY] FAIL: password length must be 8-256 characters')
                return 5
            new_hash = _hash_password(p1)
            if not _verify_password(p1, new_hash):
                print('[RECOVERY] FAIL: generated password hash could not be verified')
                return 6
            assignments.insert(0, 'password_hash=?')
            params.insert(0, new_hash)
            new_password = p1
        else:
            print('[RECOVERY] Existing Admin password is preserved; no password prompt is needed.')

        if 'mfa_enabled' in cols:
            assignments.append('mfa_enabled=0')
        if 'mfa_secret_enc' in cols:
            assignments.append('mfa_secret_enc=NULL')
        if 'mfa_updated_at' in cols:
            assignments.append('mfa_updated_at=?')
            params.append(_now())
        params.append(row['id'])
        c.execute(f"UPDATE app_users SET {','.join(assignments)} WHERE id=?", params)

        tables = _tables(c)
        if 'web_sessions37' in tables:
            c.execute('DELETE FROM web_sessions37 WHERE user_id=?', (row['id'],))
        if 'web_mfa_challenges51' in tables:
            c.execute('DELETE FROM web_mfa_challenges51 WHERE user_id=?', (row['id'],))
        _disable_mandatory_mfa(c)
        c.commit()

        check = c.execute('SELECT username,password_hash,role,enabled FROM app_users WHERE id=?', (row['id'],)).fetchone()
        ok = bool(check and check['enabled'] and str(check['role']).casefold() == 'admin' and check['password_hash'])
        if new_password is not None:
            ok = ok and _verify_password(new_password, check['password_hash'])
        if not ok:
            print('[RECOVERY] FAIL: post-write verification failed; restore backup:', backup)
            return 7

    print('[RECOVERY] OK: Admin access is unlocked.')
    print('[RECOVERY] MFA is now optional for the recovered local Admin, so the next login uses username + existing password only.')
    print('[RECOVERY] You can enable MFA again later from the Security / Administration area.')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print('\n[RECOVERY] Cancelled. Database backup was kept. No further changes were made.')
        raise SystemExit(130)
