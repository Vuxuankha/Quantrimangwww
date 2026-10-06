"""Local account operations, checked against the current database role."""
from contextlib import contextmanager
import sqlite3

from modules.nms_v5 import ensure_v5_tables, _connect, _hash_password, _verify_password, _now
from modules.nms_v6 import ensure_v6_tables

ROLES = ('Admin', 'Analyst', 'Operator', 'Viewer')
PUBLIC_FIELDS = ('id', 'username', 'role', 'enabled', 'created_at', 'updated_at')


def public_user(row):
    return {key: row[key] for key in PUBLIC_FIELDS}


@contextmanager
def transaction():
    ensure_v5_tables()
    ensure_v6_tables()
    c = _connect()
    try:
        c.execute('BEGIN IMMEDIATE')
        yield c
        c.commit()
    except sqlite3.IntegrityError as exc:
        c.rollback()
        raise ValueError('Tên đăng nhập đã tồn tại.') from exc
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def _actor(c, session, admin=False):
    if session.get('bootstrap'):
        if c.execute('SELECT COUNT(*) FROM app_users').fetchone()[0]:
            raise ValueError('Phiên thiết lập đã kết thúc. Hãy đăng nhập bằng tài khoản Admin.')
        return {'username': 'local-admin', 'role': 'Admin', 'bootstrap': True}
    row = c.execute('SELECT * FROM app_users WHERE id=? AND enabled=1', (session.get('id'),)).fetchone()
    if not row or (admin and row['role'] != 'Admin'):
        raise ValueError('Tài khoản không còn quyền thực hiện thao tác này. Hãy đăng nhập lại.')
    return public_user(row)


def _target(c, user_id):
    row = c.execute('SELECT * FROM app_users WHERE id=?', (user_id,)).fetchone()
    if not row:
        raise ValueError('Tài khoản không còn tồn tại. Hãy làm mới danh sách.')
    return row


def _validate(username, role, password=None):
    username = username.strip()
    if not username or len(username) > 64 or any(ch.isspace() or ord(ch) < 32 for ch in username):
        raise ValueError('Tên đăng nhập phải có 1–64 ký tự và không chứa khoảng trắng.')
    if role not in ROLES:
        raise ValueError('Vai trò phải là Admin, Analyst, Operator hoặc Viewer.')
    if password is not None and not 8 <= len(password) <= 256:
        raise ValueError('Mật khẩu phải có từ 8 đến 256 ký tự.')
    return username


def _ensure_username_available(c, username, exclude_id=None):
    if exclude_id is None:
        row=c.execute('SELECT id FROM app_users WHERE username=? COLLATE NOCASE LIMIT 1',(username,)).fetchone()
    else:
        row=c.execute('SELECT id FROM app_users WHERE username=? COLLATE NOCASE AND id<>? LIMIT 1',(username,int(exclude_id))).fetchone()
    if row:
        raise ValueError('Tên đăng nhập đã tồn tại (không phân biệt chữ hoa/chữ thường).')


def _event(c, actor, action, target, detail=''):
    c.execute('INSERT INTO audit_log(username,role,action,target,detail,created_at) VALUES(?,?,?,?,?,?)',
              (actor['username'], actor['role'], action, target, detail, _now()))


def get_profile(session):
    with transaction() as c:
        return _actor(c, session)


def list_users(session):
    with transaction() as c:
        _actor(c, session, admin=True)
        return [public_user(r) for r in c.execute('SELECT * FROM app_users ORDER BY username COLLATE NOCASE')]


def create_user(session, username, password, role='Viewer', enabled=True):
    username = _validate(username, role, password)
    with transaction() as c:
        actor = _actor(c, session, admin=True)
        if actor.get('bootstrap') and (role != 'Admin' or not enabled):
            raise ValueError('Tài khoản đầu tiên phải là Admin đang hoạt động.')
        _ensure_username_available(c, username)
        now = _now()
        cur = c.execute('INSERT INTO app_users(username,password_hash,role,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)',
                        (username, _hash_password(password), role, int(bool(enabled)), now, now))
        result = public_user(_target(c, cur.lastrowid))
        _event(c, actor, 'Thêm tài khoản', username, f'Vai trò: {role}; hoạt động: {bool(enabled)}')
        return result


def update_user(session, user_id, username, role, enabled):
    username = _validate(username, role)
    with transaction() as c:
        actor = _actor(c, session, admin=True)
        row = _target(c, user_id)
        if actor.get('id') == user_id and (role != 'Admin' or not enabled):
            raise ValueError('Không thể khóa hoặc hạ quyền tài khoản đang đăng nhập.')
        if row['role'] == 'Admin' and row['enabled'] and (role != 'Admin' or not enabled):
            _keep_admin(c, user_id)
        _ensure_username_available(c, username, user_id)
        c.execute('UPDATE app_users SET username=?,role=?,enabled=?,updated_at=? WHERE id=?',
                  (username, role, int(bool(enabled)), _now(), user_id))
        _event(c, actor, 'Sửa tài khoản', username,
               f'Tên cũ: {row["username"]}; vai trò: {row["role"]} → {role}; hoạt động: {bool(enabled)}')
        return public_user(_target(c, user_id))


def _keep_admin(c, user_id):
    if not c.execute("SELECT COUNT(*) FROM app_users WHERE role='Admin' AND enabled=1 AND id<>?", (user_id,)).fetchone()[0]:
        raise ValueError('Phải giữ ít nhất một tài khoản Admin đang hoạt động.')


def delete_user(session, user_id):
    with transaction() as c:
        actor = _actor(c, session, admin=True)
        row = _target(c, user_id)
        if actor.get('id') == user_id:
            raise ValueError('Không thể xóa tài khoản đang đăng nhập.')
        if row['role'] == 'Admin' and row['enabled']:
            _keep_admin(c, user_id)
        c.execute('DELETE FROM app_users WHERE id=?', (user_id,))
        _event(c, actor, 'Xóa tài khoản', row['username'])


def reset_password(session, user_id, new_password):
    _validate('password-check', 'Viewer', new_password)
    with transaction() as c:
        actor = _actor(c, session, admin=True)
        row = _target(c, user_id)
        if actor.get('id') == user_id:
            raise ValueError('Hãy dùng Đổi mật khẩu trong menu cá nhân để xác thực mật khẩu hiện tại.')
        c.execute('UPDATE app_users SET password_hash=?,updated_at=? WHERE id=?', (_hash_password(new_password), _now(), user_id))
        _event(c, actor, 'Đặt lại mật khẩu', row['username'])


def change_password(session, old_password, new_password, confirmation):
    if new_password != confirmation:
        raise ValueError('Mật khẩu xác nhận không khớp.')
    _validate('password-check', 'Viewer', new_password)
    with transaction() as c:
        actor = _actor(c, session)
        if actor.get('bootstrap'):
            raise ValueError('Hãy tạo tài khoản Admin trước khi đổi mật khẩu.')
        row = _target(c, actor['id'])
        if not _verify_password(old_password, row['password_hash']):
            raise ValueError('Mật khẩu hiện tại không đúng.')
        c.execute('UPDATE app_users SET password_hash=?,updated_at=? WHERE id=?', (_hash_password(new_password), _now(), actor['id']))
        _event(c, actor, 'Đổi mật khẩu', actor['username'])


def activity_rows(session, query=''):
    """Admin sees all actions; other roles only see their own account's actions."""
    with transaction() as c:
        actor = _actor(c, session)
        q = '%' + query.strip() + '%'
        sql = 'SELECT * FROM audit_log WHERE (username LIKE ? OR action LIKE ? OR target LIKE ? OR detail LIKE ?)'
        params = [q, q, q, q]
        if actor['role'] != 'Admin':
            sql += ' AND username=?'
            params.append(actor['username'])
        return [dict(r) for r in c.execute(sql + ' ORDER BY id DESC LIMIT 1000', params)]
