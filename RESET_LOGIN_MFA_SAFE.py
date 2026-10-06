from __future__ import annotations
import os, sqlite3, sys, time
from pathlib import Path
from run_web import resolve_data


def tables(c):
    return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def cols(c, table):
    return {r[1] for r in c.execute(f"PRAGMA table_info({table})").fetchall()}


def backup_db(db: Path, root: Path) -> Path:
    stamp=time.strftime('%Y%m%d_%H%M%S')
    candidates=[
        root/'database'/'web_preupgrade_backups'/f'login_mfa_repair_{stamp}.db',
        Path(os.environ.get('PROGRAMDATA', str(Path.home())))/'NetworkAutomation'/'recovery_backups'/f'login_mfa_repair_{stamp}.db',
        Path(os.environ.get('TEMP', str(Path.home())))/'NetworkAutomationRecovery'/f'login_mfa_repair_{stamp}.db',
    ]
    last=None
    for dest in candidates:
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(db) as src, sqlite3.connect(dest) as dst:
                src.backup(dst)
                if dst.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                    raise RuntimeError('backup quick_check failed')
            return dest
        except Exception as exc:
            last=exc
            try: dest.unlink(missing_ok=True)
            except Exception: pass
    raise PermissionError(f'Không tạo được bản sao lưu DB: {last}')


def main() -> int:
    root=resolve_data()
    os.environ['NETWORK_AUTOMATION_DATA_DIR']=str(root)
    db=root/'database'/'network_automation.db'
    if not db.is_file():
        print('[LOGIN/MFA] FAIL: không tìm thấy database:', db)
        return 2
    backup=backup_db(db,root)
    print('[LOGIN/MFA] Backup:', backup)
    try:
        with sqlite3.connect(db, timeout=15) as c:
            c.row_factory=sqlite3.Row
            t=tables(c)
            if 'app_users' not in t:
                raise RuntimeError('Thiếu bảng app_users')
            user_cols=cols(c,'app_users')
            rows=c.execute("SELECT * FROM app_users ORDER BY CASE WHEN lower(role)='admin' THEN 0 ELSE 1 END,id").fetchall()
            admin=next((r for r in rows if str(r['role'] or '').casefold()=='admin' and int(r['enabled'] or 0)==1),None)
            if admin is None:
                admin=next((r for r in rows if str(r['role'] or '').casefold()=='admin'),None)
            if admin is None:
                raise RuntimeError('Không tìm thấy tài khoản Admin. Hãy dùng RESET_WEB_PASSWORD.bat để tạo/khôi phục Admin.')
            sets=["enabled=1","role='Admin'"]
            if 'mfa_enabled' in user_cols: sets.append('mfa_enabled=0')
            if 'mfa_secret_enc' in user_cols: sets.append('mfa_secret_enc=NULL')
            if 'mfa_updated_at' in user_cols: sets.append("mfa_updated_at=datetime('now')")
            if 'updated_at' in user_cols: sets.append("updated_at=datetime('now')")
            c.execute(f"UPDATE app_users SET {','.join(sets)} WHERE id=?",(admin['id'],))
            if 'web_security_policy51' in t:
                pc=cols(c,'web_security_policy51')
                if 'mfa_required' in pc:
                    row=c.execute('SELECT 1 FROM web_security_policy51 WHERE id=1').fetchone()
                    if row:
                        if 'updated_at' in pc:
                            c.execute("UPDATE web_security_policy51 SET mfa_required=0,updated_at=datetime('now') WHERE id=1")
                        else:
                            c.execute("UPDATE web_security_policy51 SET mfa_required=0 WHERE id=1")
            if 'web_sessions37' in t: c.execute('DELETE FROM web_sessions37 WHERE user_id=?',(admin['id'],))
            if 'web_mfa_challenges51' in t: c.execute('DELETE FROM web_mfa_challenges51 WHERE user_id=?',(admin['id'],))
            c.commit()
            chk=c.execute('SELECT username,role,enabled'+(',mfa_enabled' if 'mfa_enabled' in user_cols else '')+' FROM app_users WHERE id=?',(admin['id'],)).fetchone()
            print('[LOGIN/MFA] Admin:', chk['username'])
            print('[LOGIN/MFA] MFA đã được tắt cho Admin và chính sách MFA bắt buộc đã được chuyển sang tùy chọn.')
            print('[LOGIN/MFA] Mật khẩu hiện tại được GIỮ NGUYÊN. Dữ liệu thiết bị/IP-MAC/SIEM/credential không thay đổi.')
        return 0
    except sqlite3.OperationalError as exc:
        msg=str(exc).lower()
        if 'locked' in msg:
            print('[LOGIN/MFA] FAIL: database đang bị tiến trình Web giữ. Đóng Web hoặc chạy RESET_LOGIN_MFA_SAFE.bat bằng Run as administrator.')
        else:
            print('[LOGIN/MFA] FAIL:', exc)
        return 3
    except PermissionError as exc:
        print('[LOGIN/MFA] FAIL Permission denied:', exc)
        print('Hãy chuột phải RESET_LOGIN_MFA_SAFE.bat -> Run as administrator.')
        return 4
    except Exception as exc:
        print('[LOGIN/MFA] FAIL:', exc)
        return 5

if __name__=='__main__':
    raise SystemExit(main())
