from modules.ui_ux_config import PALETTE as UI_COLORS
import base64
import hashlib
import hmac
import os
import tempfile
import queue
import logging
from contextlib import contextmanager
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
try:
    import tkinter as tk
except (ImportError, ModuleNotFoundError):
    tk = None
try:
    from tkinter import ttk, messagebox, simpledialog, filedialog
except (ImportError, ModuleNotFoundError):
    ttk = messagebox = simpledialog = filedialog = None

from database.db import DB_PATH, init_database, get_connection
from app_runtime import BACKUP_DIR as APP_BACKUP_DIR, DATABASE_DIR
from modules.ssh_security import build_strict_ssh_client

BACKUP_DIR = APP_BACKUP_DIR
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
KEY_FILE = DATABASE_DIR / '.credential.key'


def _now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _connect():
    init_database()
    c = get_connection()
    return c


def ensure_v5_tables():
    c = _connect()
    try:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS credentials(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            kind TEXT NOT NULL DEFAULT 'SSH',
            username TEXT DEFAULT '',
            secret_enc TEXT NOT NULL,
            port INTEGER,
            note TEXT DEFAULT '',
            created_at TEXT,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS device_credentials(
            device_id INTEGER NOT NULL,
            credential_id INTEGER NOT NULL,
            purpose TEXT NOT NULL DEFAULT 'SSH',
            created_at TEXT,
            UNIQUE(device_id,purpose)
        );
        CREATE TABLE IF NOT EXISTS secure_backup_jobs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            device_id INTEGER NOT NULL,
            credential_id INTEGER NOT NULL,
            command TEXT DEFAULT 'show running-config',
            interval_min INTEGER DEFAULT 1440,
            enabled INTEGER DEFAULT 1,
            last_run TEXT,
            last_status TEXT,
            next_run REAL,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS app_users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'Viewer',
            enabled INTEGER DEFAULT 1,
            created_at TEXT,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS auth_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            success INTEGER,
            detail TEXT,
            created_at TEXT
        );
        ''')
        c.commit()
    finally:
        c.close()


def _encrypted_data_present(c):
    tables = {r['name'] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table in tables:
        quoted_table = '"' + table.replace('"', '""') + '"'
        for row in c.execute(f'PRAGMA table_info({quoted_table})').fetchall():
            col = row['name']
            quoted_col = '"' + col.replace('"', '""') + '"'
            if col.endswith('_enc') and c.execute(f'SELECT 1 FROM {quoted_table} WHERE {quoted_col} IS NOT NULL AND {quoted_col}<>\'\' LIMIT 1').fetchone():
                return True
    return 'settings' in tables and bool(c.execute("SELECT 1 FROM settings WHERE key LIKE '%\\_enc' ESCAPE '\\' AND value IS NOT NULL AND value<>'' LIMIT 1").fetchone())


@contextmanager
def _key_lock():
    from agent_runtime import AgentLock
    lock = AgentLock(KEY_FILE.with_suffix('.lock'))
    deadline = time.monotonic()+5
    while True:
        try:
            lock.__enter__()
            break
        except RuntimeError:
            if time.monotonic() >= deadline:
                raise RuntimeError('Đang tạo khóa credential. Hãy thử lại sau.') from None
            time.sleep(.02)
    try:
        yield
    finally:
        lock.__exit__(None, None, None)


def _fernet(allow_create=True):
    try:
        from cryptography.fernet import Fernet
    except Exception as e:
        raise RuntimeError('Thiếu thư viện cryptography. Hãy chạy: pip install cryptography') from e
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if KEY_FILE.exists():
        return Fernet(KEY_FILE.read_bytes().strip())
    if not allow_create:
        raise RuntimeError('Mất khóa credential. Khôi phục đúng khóa từ bản sao lưu.')
    with _key_lock():
        if not KEY_FILE.exists():
            c = _connect()
            try:
                # Do not silently replace a lost key and make existing secrets unusable.
                if _encrypted_data_present(c):
                    raise RuntimeError('Mất khóa .credential.key nhưng database còn dữ liệu mã hóa. Khôi phục đúng khóa từ bản sao lưu.')
            finally:
                c.close()
            fd, temporary = tempfile.mkstemp(prefix='.vault_', dir=KEY_FILE.parent)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(Fernet.generate_key())
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, KEY_FILE)
            finally:
                Path(temporary).unlink(missing_ok=True)
        return Fernet(KEY_FILE.read_bytes().strip())


def encrypt_secret(text):
    return _fernet().encrypt((text or '').encode('utf-8')).decode('ascii')


def decrypt_secret(token):
    return _fernet(allow_create=False).decrypt((token or '').encode('ascii')).decode('utf-8')


def _hash_password(password, salt=None):
    """Hash application passwords with Argon2id when available.

    Existing PBKDF2 hashes remain readable so upgrades do not lock users out.
    New passwords and passwords changed after the upgrade use Argon2id.
    """
    try:
        from argon2 import PasswordHasher
        return PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16).hash(password)
    except Exception:
        salt = salt or os.urandom(16)
        rounds = 310000
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, rounds)
        return f'pbkdf2_sha256${rounds}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}'


def _verify_password(password, stored):
    if not stored:
        return False
    if str(stored).startswith('$argon2'):
        try:
            from argon2 import PasswordHasher
            from argon2.exceptions import VerifyMismatchError, InvalidHashError
            try:
                return bool(PasswordHasher().verify(stored, password))
            except (VerifyMismatchError, InvalidHashError):
                return False
        except Exception:
            return False
    try:
        algo, rounds, s, expected = stored.split('$', 3)
        if algo != 'pbkdf2_sha256':
            return False
        salt = base64.b64decode(s)
        got = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, int(rounds))
        return hmac.compare_digest(base64.b64encode(got).decode(), expected)
    except Exception:
        return False


def authenticate(username, password):
    ensure_v5_tables(); c = _connect()
    try:
        rows = c.execute('SELECT * FROM app_users WHERE username=? COLLATE NOCASE AND enabled=1 ORDER BY id', (username,)).fetchall()
        r = rows[0] if len(rows) == 1 else None
        ok = bool(r and _verify_password(password, r['password_hash']))
        c.execute('INSERT INTO auth_log(username,success,detail,created_at) VALUES(?,?,?,?)',
                  (username, 1 if ok else 0, 'Đăng nhập thành công' if ok else 'Sai tài khoản hoặc mật khẩu', _now()))
        c.commit()
        return {key: r[key] for key in ('id', 'username', 'role', 'enabled', 'created_at', 'updated_at')} if ok else None
    finally:
        c.close()


def has_local_users():
    ensure_v5_tables(); c = _connect()
    try:
        return c.execute('SELECT COUNT(*) FROM app_users').fetchone()[0] > 0
    finally:
        c.close()


def ssh_backup(device, credential, command, destination=None):
    import paramiko
    secret = decrypt_secret(credential['secret_enc'])
    host = device['ip']; port = int(credential['port'] or 22)
    cli = build_strict_ssh_client(paramiko)
    try:
        cli.connect(host, port=port, username=credential['username'], password=secret,
                    timeout=10, banner_timeout=15, auth_timeout=15, look_for_keys=False, allow_agent=False)
        from modules.ssh_runner import read_exec_output
        data, err = read_exec_output(cli,command or 'show running-config',30)
        if not data.strip():
            raise RuntimeError(err.strip() or 'Thiết bị không trả dữ liệu cấu hình; không tạo bản sao rỗng.')
    finally:
        cli.close()
    if destination is None:
        safe = ''.join(ch if ch.isalnum() or ch in '-_.' else '_' for ch in (device['name'] or host))
        fd, filename = tempfile.mkstemp(prefix=f"{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_",
                                        suffix='.cfg',dir=BACKUP_DIR)
        destination = Path(filename)
        temporary = destination
    else:
        destination = Path(destination)
        fd, filename = tempfile.mkstemp(prefix='.backup_',dir=destination.parent)
        temporary = Path(filename)
    try:
        with os.fdopen(fd,'w',encoding='utf-8',newline='') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        if temporary != destination:
            os.replace(temporary,destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    c = _connect()
    try:
        c.execute('INSERT INTO config_backups(device_name,source,file_path,size_bytes,note,created_at) VALUES(?,?,?,?,?,?)',
                  (device['name'] or host, 'SSH mã hóa', str(destination), destination.stat().st_size,
                   f"Credential: {credential['name']}", _now()))
        c.commit()
    finally:
        c.close()
    return destination


class CredentialManagerPage:
    def __init__(self, parent, activity_callback=None):
        ensure_v5_tables(); self.parent=parent; self.activity=activity_callback or (lambda m:None)
        self._build(); self.refresh()

    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['background']); ctl.pack(fill='x',padx=25,pady=(0,8))
        tk.Button(ctl,text='Thêm Credential',command=self.add,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left')
        tk.Button(ctl,text='Sửa',command=self.edit).pack(side='left',padx=5)
        tk.Button(ctl,text='Gán cho thiết bị',command=self.assign).pack(side='left',padx=5)
        tk.Button(ctl,text='Kiểm tra SSH',command=self.test).pack(side='left',padx=5)
        tk.Button(ctl,text='Xóa',command=self.delete).pack(side='left',padx=5)
        tk.Button(ctl,text='Làm mới',command=self.refresh).pack(side='left',padx=5)
        box=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid'); box.pack(fill='both',expand=True,padx=25,pady=(0,10))
        cols=('name','kind','username','port','assigned','note','updated')
        self.t=ttk.Treeview(box,columns=cols,show='headings',selectmode='browse')
        for c,h,w in [('name','Tên',180),('kind','Loại',90),('username','Tài khoản',150),('port','Cổng',70),('assigned','Đã gán',90),('note','Ghi chú',260),('updated','Cập nhật',150)]:
            self.t.heading(c,text=h); self.t.column(c,width=w,anchor='w')
        self.t.pack(fill='both',expand=True,padx=8,pady=8)
        tk.Label(self.parent,text='Mật khẩu/community được mã hóa bằng Fernet và không hiển thị lại trên giao diện.',bg=UI_COLORS['background'],fg=UI_COLORS['muted']).pack(anchor='w',padx=25,pady=(0,8))

    def refresh(self):
        for x in self.t.get_children(): self.t.delete(x)
        c=_connect(); rows=c.execute('''SELECT cr.*,COUNT(dc.device_id) assigned FROM credentials cr LEFT JOIN device_credentials dc ON dc.credential_id=cr.id GROUP BY cr.id ORDER BY cr.name''').fetchall(); c.close()
        for r in rows:self.t.insert('','end',iid=str(r['id']),values=(r['name'],r['kind'],r['username'],r['port'] or '-',r['assigned'],r['note'],r['updated_at'] or r['created_at']))

    def _selected(self):
        s=self.t.selection(); return int(s[0]) if s else None

    def _dialog(self,title,row=None):
        w=tk.Toplevel(self.parent); w.title(title); w.geometry('430x330'); w.transient(self.parent.winfo_toplevel()); w.grab_set()
        vals={'name':tk.StringVar(value=(row or {}).get('name','')),'kind':tk.StringVar(value=(row or {}).get('kind','SSH')),
              'username':tk.StringVar(value=(row or {}).get('username','')),'port':tk.StringVar(value=str((row or {}).get('port') or 22)),
              'secret':tk.StringVar(),'note':tk.StringVar(value=(row or {}).get('note',''))}
        labels=[('Tên credential','name'),('Loại','kind'),('Username','username'),('Port','port'),('Mật khẩu / Community','secret'),('Ghi chú','note')]
        for i,(lab,k) in enumerate(labels):
            tk.Label(w,text=lab).grid(row=i,column=0,sticky='w',padx=15,pady=8)
            if k=='kind': z=ttk.Combobox(w,textvariable=vals[k],values=['SSH','SNMPv2c'],state='readonly',width=28)
            else: z=tk.Entry(w,textvariable=vals[k],width=31,show='*' if k=='secret' else '')
            z.grid(row=i,column=1,padx=10,pady=8)
        result={}
        def save():
            if not vals['name'].get().strip(): messagebox.showwarning(title,'Vui lòng nhập tên.',parent=w); return
            if not row and not vals['secret'].get(): messagebox.showwarning(title,'Vui lòng nhập mật khẩu/community.',parent=w); return
            result.update({k:v.get() if k=='secret' else v.get().strip() for k,v in vals.items()}); w.destroy()
        tk.Button(w,text='Lưu',command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],width=12).grid(row=7,column=1,sticky='e',padx=10,pady=15)
        w.wait_window(); return result or None

    def add(self):
        d=self._dialog('Thêm Credential')
        if not d:return
        try: port=int(d['port'] or (161 if d['kind']=='SNMPv2c' else 22))
        except: port=161 if d['kind']=='SNMPv2c' else 22
        c=_connect()
        try:c.execute('INSERT INTO credentials(name,kind,username,secret_enc,port,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',(d['name'],d['kind'],d['username'],encrypt_secret(d['secret']),port,d['note'],_now(),_now()));c.commit()
        except sqlite3.IntegrityError: messagebox.showerror('Credential','Tên credential đã tồn tại.')
        finally:c.close()
        self.activity('Đã thêm credential: '+d['name']); self.refresh()

    def edit(self):
        i=self._selected()
        if not i:return
        c=_connect(); r=c.execute('SELECT * FROM credentials WHERE id=?',(i,)).fetchone(); c.close(); d=self._dialog('Sửa Credential',dict(r))
        if not d:return
        try: port=int(d['port'] or 22)
        except: port=22
        c=_connect()
        try:
            if d['secret']: c.execute('UPDATE credentials SET name=?,kind=?,username=?,secret_enc=?,port=?,note=?,updated_at=? WHERE id=?',(d['name'],d['kind'],d['username'],encrypt_secret(d['secret']),port,d['note'],_now(),i))
            else:c.execute('UPDATE credentials SET name=?,kind=?,username=?,port=?,note=?,updated_at=? WHERE id=?',(d['name'],d['kind'],d['username'],port,d['note'],_now(),i))
            c.commit()
        finally:c.close()
        self.refresh()

    def assign(self):
        cid=self._selected()
        if not cid: messagebox.showinfo('Credential','Chọn một credential trước.'); return
        c=_connect(); devices=[dict(r) for r in c.execute('SELECT id,name,ip FROM network_devices ORDER BY name,ip')]; cred=c.execute('SELECT * FROM credentials WHERE id=?',(cid,)).fetchone(); c.close()
        if not devices: messagebox.showinfo('Credential','Chưa có thiết bị mạng.'); return
        w=tk.Toplevel(self.parent);w.title('Gán Credential');w.geometry('430x180');w.transient(self.parent.winfo_toplevel());w.grab_set()
        labels=[f"{x['name']} ({x['ip']})" for x in devices]; dv=tk.StringVar(value=labels[0]); purpose=tk.StringVar(value='SNMP' if cred['kind']=='SNMPv2c' else 'SSH')
        tk.Label(w,text='Thiết bị').pack(anchor='w',padx=15,pady=(15,3));ttk.Combobox(w,textvariable=dv,values=labels,state='readonly',width=48).pack(padx=15)
        tk.Label(w,text='Mục đích').pack(anchor='w',padx=15,pady=(10,3));ttk.Combobox(w,textvariable=purpose,values=['SSH','SNMP','Backup'],state='readonly',width=20).pack(anchor='w',padx=15)
        def save():
            did=devices[labels.index(dv.get())]['id']; c=_connect();c.execute('INSERT INTO device_credentials(device_id,credential_id,purpose,created_at) VALUES(?,?,?,?) ON CONFLICT(device_id,purpose) DO UPDATE SET credential_id=excluded.credential_id,created_at=excluded.created_at',(did,cid,purpose.get(),_now()));c.commit();c.close();w.destroy();self.refresh()
        tk.Button(w,text='Gán',command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text']).pack(anchor='e',padx=15,pady=12)

    def test(self):
        i=self._selected()
        if not i:return
        c=_connect(); cr=c.execute('SELECT * FROM credentials WHERE id=?',(i,)).fetchone(); c.close()
        if cr['kind']!='SSH': messagebox.showinfo('Kiểm tra','Chức năng này dùng cho credential SSH.'); return
        host=simpledialog.askstring('Kiểm tra SSH','IP / Host:',parent=self.parent)
        if not host:return
        def work():
            try:
                import paramiko; cli=build_strict_ssh_client(paramiko);cli.connect(host,port=int(cr['port'] or 22),username=cr['username'],password=decrypt_secret(cr['secret_enc']),timeout=8,look_for_keys=False,allow_agent=False);cli.close();msg='Kết nối SSH thành công.'
            except Exception as e:msg='Không kết nối được SSH:\n'+str(e)
            self.parent.after(0,lambda:messagebox.showinfo('Kiểm tra SSH',msg))
        threading.Thread(target=work,daemon=True).start()

    def delete(self):
        i=self._selected()
        if not i:return
        if not messagebox.askyesno('Xóa Credential','Xóa credential đã chọn? Các gán liên quan cũng sẽ bị xóa.'):return
        c=_connect();c.execute('DELETE FROM device_credentials WHERE credential_id=?',(i,));c.execute('DELETE FROM secure_backup_jobs WHERE credential_id=?',(i,));c.execute('DELETE FROM credentials WHERE id=?',(i,));c.commit();c.close();self.refresh()


class SecureBackupSchedulerPage:
    def __init__(self,parent,activity_callback=None,worker_threads=None):
        ensure_v5_tables()
        self.parent=parent;self.activity=activity_callback or (lambda m:None)
        self.worker_threads=worker_threads if worker_threads is not None else []
        self.stop_event=threading.Event();self.results=queue.Queue()
        self._build();self.refresh()
        self.t.bind('<Destroy>',self.on_destroy,add='+')
        self.parent.after(5000,self._tick)
        self.parent.after(100,self.poll_results)
    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['background']);ctl.pack(fill='x',padx=25,pady=(0,8))
        tk.Button(ctl,text='Thêm lịch sao lưu',command=self.add,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left')
        tk.Button(ctl,text='Chạy ngay',command=self.run_now).pack(side='left',padx=5);tk.Button(ctl,text='Bật/Tắt',command=self.toggle).pack(side='left',padx=5);tk.Button(ctl,text='Xóa',command=self.delete).pack(side='left',padx=5);tk.Button(ctl,text='Làm mới',command=self.refresh).pack(side='left',padx=5)
        box=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid');box.pack(fill='both',expand=True,padx=25,pady=(0,10));cols=('name','device','credential','interval','last','status','enabled');self.t=ttk.Treeview(box,columns=cols,show='headings')
        for c,h,w in [('name','Tên lịch',170),('device','Thiết bị',180),('credential','Credential',160),('interval','Chu kỳ',100),('last','Lần chạy cuối',150),('status','Kết quả',220),('enabled','Bật',60)]:self.t.heading(c,text=h);self.t.column(c,width=w,anchor='w')
        self.t.pack(fill='both',expand=True,padx=8,pady=8)
    def refresh(self):
        for x in self.t.get_children():self.t.delete(x)
        c=_connect();rows=c.execute('''SELECT j.*,d.name device_name,d.ip,cr.name cred_name FROM secure_backup_jobs j JOIN network_devices d ON d.id=j.device_id JOIN credentials cr ON cr.id=j.credential_id ORDER BY j.name''').fetchall();c.close()
        for r in rows:self.t.insert('','end',iid=str(r['id']),values=(r['name'],f"{r['device_name']} ({r['ip']})",r['cred_name'],f"{r['interval_min']} phút",r['last_run'] or '-',r['last_status'] or '-', 'Có' if r['enabled'] else 'Không'))
    def _selected(self):s=self.t.selection();return int(s[0]) if s else None
    def add(self):
        c=_connect();dev=[dict(r) for r in c.execute('SELECT id,name,ip FROM network_devices ORDER BY name')];creds=[dict(r) for r in c.execute("SELECT * FROM credentials WHERE kind='SSH' ORDER BY name")];c.close()
        if not dev or not creds:messagebox.showinfo('Lịch sao lưu','Cần có ít nhất 1 thiết bị và 1 credential SSH.');return
        w=tk.Toplevel(self.parent);w.title('Thêm lịch sao lưu');w.geometry('470x330');w.transient(self.parent.winfo_toplevel());w.grab_set()
        name=tk.StringVar();dl=[f"{x['name']} ({x['ip']})" for x in dev];cl=[x['name'] for x in creds];dv=tk.StringVar(value=dl[0]);cv=tk.StringVar(value=cl[0]);cmd=tk.StringVar(value='show running-config');mins=tk.StringVar(value='1440')
        def apply_profile_command(event=None):
            try:
                from modules.nms_v7 import get_profile_for_device
                did=dev[dl.index(dv.get())]['id'];p=get_profile_for_device(device_id=did)
                if p and p.get('backup_command'):cmd.set(p['backup_command'])
            except Exception:pass
        apply_profile_command()
        for i,(lab,var,vals) in enumerate([('Tên lịch',name,None),('Thiết bị',dv,dl),('Credential SSH',cv,cl),('Lệnh backup',cmd,None),('Chu kỳ (phút)',mins,None)]):
            tk.Label(w,text=lab).grid(row=i,column=0,sticky='w',padx=15,pady=10);z=ttk.Combobox(w,textvariable=var,values=vals,state='readonly',width=35) if vals else tk.Entry(w,textvariable=var,width=38);z.grid(row=i,column=1,padx=10,pady=10)
            if lab=='Thiết bị': z.bind('<<ComboboxSelected>>',apply_profile_command)
        def save():
            if not name.get().strip():messagebox.showwarning('Lịch sao lưu','Nhập tên lịch.',parent=w);return
            try:m=max(1,int(mins.get()))
            except:messagebox.showwarning('Lịch sao lưu','Chu kỳ phải là số phút.',parent=w);return
            did=dev[dl.index(dv.get())]['id'];cid=creds[cl.index(cv.get())]['id'];c=_connect();c.execute('INSERT INTO secure_backup_jobs(name,device_id,credential_id,command,interval_min,enabled,next_run,created_at) VALUES(?,?,?,?,?,1,?,?)',(name.get().strip(),did,cid,cmd.get().strip() or 'show running-config',m,time.time(),_now()));c.commit();c.close();w.destroy();self.refresh()
        tk.Button(w,text='Lưu',command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text']).grid(row=6,column=1,sticky='e',padx=10,pady=15)
    def run_now(self):
        i=self._selected()
        if i:self._run(i)
    def toggle(self):
        i=self._selected()
        if not i:return
        c=_connect();c.execute('UPDATE secure_backup_jobs SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?',(i,));c.commit();c.close();self.refresh()
    def delete(self):
        i=self._selected()
        if not i:return
        c=_connect();c.execute('DELETE FROM secure_backup_jobs WHERE id=?',(i,));c.commit();c.close();self.refresh()
    def _tick(self):
        if self.stop_event.is_set():
            return
        try:
            c=_connect()
            try:
                rows=c.execute('SELECT id FROM secure_backup_jobs WHERE enabled=1 AND next_run<=?',(time.time(),)).fetchall()
            finally:
                c.close()
            for r in rows:
                self._run(r['id'],scheduled=True)
        except Exception:
            logging.getLogger(__name__).exception('Secure backup scheduler tick failed')
        finally:
            if not self.stop_event.is_set():
                self.parent.after(5000,self._tick)

    def _run(self,i,scheduled=False):
        if self.stop_event.is_set():
            return False
        from agent_runtime import AgentLock
        # Shared across page instances and application processes using the same data directory.
        lock=AgentLock(DATABASE_DIR/'backup_job_locks'/f'{int(i)}.lock')
        try:
            lock.__enter__()
        except RuntimeError:
            return False
        launched=False
        try:
            c=_connect()
            try:
                r=c.execute('''SELECT j.*,d.name device_name,d.ip,cr.name cred_name,cr.kind,
                    cr.username,cr.secret_enc,cr.port,cr.note FROM secure_backup_jobs j
                    JOIN network_devices d ON d.id=j.device_id
                    JOIN credentials cr ON cr.id=j.credential_id WHERE j.id=?''',(i,)).fetchone()
            finally:
                c.close()
            if not r:
                return False
            rr=dict(r)
            if scheduled and (not rr['enabled'] or rr['next_run'] is None or float(rr['next_run'])>time.time()):
                return False
            def work():
                try:
                    interval=60
                    try:
                        interval=max(1,int(rr['interval_min']))*60
                        device={'name':rr['device_name'],'ip':rr['ip']}
                        cred={'name':rr['cred_name'],'username':rr['username'],
                              'secret_enc':rr['secret_enc'],'port':rr['port']}
                        dst=ssh_backup(device,cred,rr['command'])
                        status='OK: '+dst.name
                        message='Sao lưu tự động thành công: '+str(dst)
                    except Exception as e:
                        status='Lỗi: '+str(e)
                        message='Sao lưu tự động lỗi: '+str(e)
                    c=_connect()
                    try:
                        c.execute('UPDATE secure_backup_jobs SET last_run=?,last_status=?,next_run=? WHERE id=?',
                                  (_now(),status,time.time()+interval,i))
                        c.commit()
                    finally:
                        c.close()
                    self.results.put(message)
                except Exception as e:
                    logging.getLogger(__name__).exception('Cannot record secure backup result')
                    self.results.put('Không lưu được kết quả sao lưu: '+str(e))
                finally:
                    lock.__exit__(None,None,None)
            thread=threading.Thread(target=work,daemon=True,name=f'SecureBackup-{i}')
            self.worker_threads[:]=[t for t in self.worker_threads if t.is_alive()]
            self.worker_threads.append(thread)
            thread.start()
            launched=True
            return True
        finally:
            if not launched:
                lock.__exit__(None,None,None)

    def poll_results(self):
        if self.stop_event.is_set():
            return
        changed=False
        while True:
            try:
                message=self.results.get_nowait()
            except queue.Empty:
                break
            self.activity(message)
            changed=True
        if changed:
            self.refresh()
        self.parent.after(100,self.poll_results)

    def on_destroy(self,event):
        if event.widget is self.t:
            self.stop_event.set()


class ConfigComparePage:
    def __init__(self,parent,activity_callback=None):
        self.parent=parent;self.activity=activity_callback or (lambda m:None);self._build();self.refresh()
    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['background']);ctl.pack(fill='x',padx=25,pady=(0,8));tk.Label(ctl,text='Bản A:',bg=UI_COLORS['background']).pack(side='left');self.a=tk.StringVar();self.ac=ttk.Combobox(ctl,textvariable=self.a,state='readonly',width=38);self.ac.pack(side='left',padx=5);tk.Label(ctl,text='Bản B:',bg=UI_COLORS['background']).pack(side='left');self.b=tk.StringVar();self.bc=ttk.Combobox(ctl,textvariable=self.b,state='readonly',width=38);self.bc.pack(side='left',padx=5);tk.Button(ctl,text='So sánh',command=self.compare,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left',padx=5);tk.Button(ctl,text='Làm mới',command=self.refresh).pack(side='left')
        box=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid');box.pack(fill='both',expand=True,padx=25,pady=(0,10));self.text=tk.Text(box,wrap='none',font=('Consolas',10));ys=ttk.Scrollbar(box,orient='vertical',command=self.text.yview);xs=ttk.Scrollbar(box,orient='horizontal',command=self.text.xview);self.text.configure(yscrollcommand=ys.set,xscrollcommand=xs.set);self.text.grid(row=0,column=0,sticky='nsew');ys.grid(row=0,column=1,sticky='ns');xs.grid(row=1,column=0,sticky='ew');box.grid_rowconfigure(0,weight=1);box.grid_columnconfigure(0,weight=1)
    def refresh(self):
        c=_connect();rows=[dict(r) for r in c.execute('SELECT id,device_name,file_path,created_at FROM config_backups WHERE file_path IS NOT NULL ORDER BY id DESC LIMIT 300')];c.close();self.rows=rows;labels=[f"#{r['id']} | {r['device_name']} | {r['created_at']}" for r in rows];self.ac['values']=labels;self.bc['values']=labels
        if labels and not self.a.get():self.a.set(labels[min(1,len(labels)-1)]);self.b.set(labels[0])
    def compare(self):
        import difflib
        vals=list(self.ac['values'])
        if self.a.get() not in vals or self.b.get() not in vals:return
        ra=self.rows[vals.index(self.a.get())];rb=self.rows[vals.index(self.b.get())]
        try:A=Path(ra['file_path']).read_text(encoding='utf-8',errors='replace').splitlines();B=Path(rb['file_path']).read_text(encoding='utf-8',errors='replace').splitlines()
        except Exception as e:messagebox.showerror('So sánh config',str(e));return
        diff=list(difflib.unified_diff(A,B,fromfile=self.a.get(),tofile=self.b.get(),lineterm=''))
        self.text.delete('1.0','end');self.text.insert('1.0','\n'.join(diff) if diff else 'Hai bản cấu hình không có khác biệt.');self.activity('Đã so sánh hai bản cấu hình.')


class UserRolePage:
    def __init__(self, parent, activity_callback=None, session_user=None, on_session_update=None):
        from modules.account_ui import AccountManagementPage
        self.page = AccountManagementPage(parent, activity_callback, session_user, on_session_update)


class LoginDialog:
    def __init__(self,root,allow_bootstrap=True):
        self.root=root;self.user=None;self.allow_bootstrap=allow_bootstrap
    def run(self):
        if self.allow_bootstrap and not has_local_users():
            return {'username':'local-admin','role':'Admin','bootstrap':True}
        w=tk.Toplevel(self.root);w.title('Đăng nhập Network Automation');w.geometry('420x290');w.resizable(False,False);w.grab_set();w.protocol('WM_DELETE_WINDOW',lambda:(setattr(self,'user',None),w.destroy()))
        tk.Label(w,text='NETWORK AUTOMATION',font=('Segoe UI',16,'bold')).pack(pady=(18,12));tk.Label(w,text='Đăng nhập để tiếp tục phiên làm việc.' if has_local_users() else 'Chưa có tài khoản. Đóng và mở lại ứng dụng để thiết lập Admin.',wraplength=360,fg=UI_COLORS['muted']).pack(pady=(0,8));frm=tk.Frame(w);frm.pack(fill='x',padx=35);u=tk.StringVar();p=tk.StringVar();tk.Label(frm,text='Tài khoản').grid(row=0,column=0,sticky='w',pady=7);tk.Entry(frm,textvariable=u,width=27).grid(row=0,column=1,pady=7);tk.Label(frm,text='Mật khẩu').grid(row=1,column=0,sticky='w',pady=7);pe=tk.Entry(frm,textvariable=p,show='*',width=27);pe.grid(row=1,column=1,pady=7)
        msg=tk.StringVar();tk.Label(w,textvariable=msg,fg=UI_COLORS['danger']).pack()
        def go(event=None):
            r=authenticate(u.get().strip(),p.get())
            if r:self.user=r;w.destroy()
            else:msg.set('Sai tài khoản hoặc mật khẩu.')
        tk.Button(w,text='Đăng nhập',command=go,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],width=14).pack(pady=8);pe.bind('<Return>',go);w.wait_window();return self.user


__all__=['ensure_v5_tables','CredentialManagerPage','SecureBackupSchedulerPage','ConfigComparePage','UserRolePage','LoginDialog','has_local_users']
