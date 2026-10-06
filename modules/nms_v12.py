from modules.ui_ux_config import PALETTE as UI_COLORS
import asyncio
import re
import sqlite3
import threading
try:
    import tkinter as tk
except (ImportError, ModuleNotFoundError):
    tk = None
from datetime import datetime
try:
    from tkinter import ttk, messagebox
except (ImportError, ModuleNotFoundError):
    ttk = messagebox = None

from modules.advanced_pages import _connect, snmp_get
from modules.nms_v5 import encrypt_secret, decrypt_secret


def _now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


DRIVERS = [
    {
        'name': 'Cisco IOS / IOS-XE', 'vendor': 'Cisco', 'priority': 100,
        'sysobject_prefix': '1.3.6.1.4.1.9', 'descr_regex': r'cisco|ios[- ]?xe|ios software',
        'cpu_oid': '1.3.6.1.4.1.9.2.1.58.0', 'mem_used_oid': '', 'mem_total_oid': '',
        'backup_command': 'show running-config', 'save_command': 'write memory', 'lldp_mode': 'LLDP/CDP',
        'note': 'Driver mặc định Cisco. CPU OID có thể khác trên một số nền tảng IOS-XE mới.'
    },
    {
        'name': 'MikroTik RouterOS', 'vendor': 'MikroTik', 'priority': 100,
        'sysobject_prefix': '1.3.6.1.4.1.14988', 'descr_regex': r'mikrotik|routeros',
        'cpu_oid': '1.3.6.1.4.1.14988.1.1.3.14.0', 'mem_used_oid': '', 'mem_total_oid': '',
        'backup_command': '/export terse', 'save_command': '', 'lldp_mode': 'LLDP',
        'note': 'Driver RouterOS. RAM phụ thuộc model/phiên bản nên để trống mặc định.'
    },
    {
        'name': 'Ruijie / Reyee', 'vendor': 'Ruijie', 'priority': 90,
        'sysobject_prefix': '1.3.6.1.4.1.4881', 'descr_regex': r'ruijie|reyee',
        'cpu_oid': '', 'mem_used_oid': '', 'mem_total_oid': '',
        'backup_command': 'show running-config', 'save_command': 'write', 'lldp_mode': 'LLDP',
        'note': 'Driver nhận diện Ruijie/Reyee. OID tài nguyên cần tùy model/firmware.'
    },
    {
        'name': 'Aruba / HPE', 'vendor': 'Aruba/HPE', 'priority': 80,
        'sysobject_prefix': '', 'descr_regex': r'aruba|hewlett[- ]packard|procurve|arubaos|aoscx|hpe',
        'cpu_oid': '', 'mem_used_oid': '', 'mem_total_oid': '',
        'backup_command': 'show running-config', 'save_command': 'write memory', 'lldp_mode': 'LLDP',
        'note': 'ArubaOS, AOS-CX và ProCurve khác nhau; dùng driver tùy chỉnh khi cần.'
    },
    {
        'name': 'Generic HOST-RESOURCES', 'vendor': 'Generic', 'priority': 10,
        'sysobject_prefix': '', 'descr_regex': r'linux|windows|microsoft|unix',
        'cpu_oid': '1.3.6.1.2.1.25.3.3.1.2.1', 'mem_used_oid': '', 'mem_total_oid': '',
        'backup_command': '', 'save_command': '', 'lldp_mode': 'LLDP',
        'note': 'Fallback cho host hỗ trợ HOST-RESOURCES-MIB.'
    },
]


def _table_cols(c, table):
    return {r['name'] for r in c.execute(f'PRAGMA table_info({table})').fetchall()}


def ensure_v12_tables():
    c = _connect()
    try:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS vendor_drivers(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT UNIQUE NOT NULL,
          vendor TEXT DEFAULT '',
          priority INTEGER DEFAULT 50,
          sysobject_prefix TEXT DEFAULT '',
          descr_regex TEXT DEFAULT '',
          cpu_oid TEXT DEFAULT '',
          mem_used_oid TEXT DEFAULT '',
          mem_total_oid TEXT DEFAULT '',
          backup_command TEXT DEFAULT '',
          save_command TEXT DEFAULT '',
          lldp_mode TEXT DEFAULT 'LLDP',
          note TEXT DEFAULT '',
          builtin INTEGER DEFAULT 0,
          enabled INTEGER DEFAULT 1,
          created_at TEXT,
          updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS device_driver_assignments(
          device_id INTEGER PRIMARY KEY,
          driver_id INTEGER NOT NULL,
          source TEXT DEFAULT 'manual',
          detected_descr TEXT DEFAULT '',
          detected_object_id TEXT DEFAULT '',
          updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS snmpv3_credentials(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT UNIQUE NOT NULL,
          username TEXT NOT NULL,
          security_level TEXT NOT NULL DEFAULT 'authPriv',
          auth_protocol TEXT DEFAULT 'SHA',
          auth_secret_enc TEXT DEFAULT '',
          priv_protocol TEXT DEFAULT 'AES128',
          priv_secret_enc TEXT DEFAULT '',
          context_name TEXT DEFAULT '',
          port INTEGER DEFAULT 161,
          note TEXT DEFAULT '',
          created_at TEXT,
          updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS device_snmpv3_assignments(
          device_id INTEGER PRIMARY KEY,
          credential_id INTEGER NOT NULL,
          updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS snmp_diagnostics_history(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          host TEXT,
          version TEXT,
          credential_name TEXT,
          success INTEGER,
          sys_name TEXT,
          sys_descr TEXT,
          sys_object_id TEXT,
          detail TEXT,
          created_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_snmpdiag_host_time ON snmp_diagnostics_history(host,created_at);
        ''')
        for d in DRIVERS:
            row = c.execute('SELECT id FROM vendor_drivers WHERE name=?', (d['name'],)).fetchone()
            vals = (d['vendor'], d['priority'], d['sysobject_prefix'], d['descr_regex'], d['cpu_oid'],
                    d['mem_used_oid'], d['mem_total_oid'], d['backup_command'], d['save_command'],
                    d['lldp_mode'], d['note'], _now())
            if row:
                c.execute('''UPDATE vendor_drivers SET vendor=?,priority=?,sysobject_prefix=?,descr_regex=?,cpu_oid=?,
                  mem_used_oid=?,mem_total_oid=?,backup_command=?,save_command=?,lldp_mode=?,note=?,builtin=1,updated_at=? WHERE id=?''', vals + (row['id'],))
            else:
                c.execute('''INSERT INTO vendor_drivers(name,vendor,priority,sysobject_prefix,descr_regex,cpu_oid,
                  mem_used_oid,mem_total_oid,backup_command,save_command,lldp_mode,note,builtin,enabled,created_at,updated_at)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,1,?,?)''',
                  (d['name'], d['vendor'], d['priority'], d['sysobject_prefix'], d['descr_regex'], d['cpu_oid'],
                   d['mem_used_oid'], d['mem_total_oid'], d['backup_command'], d['save_command'], d['lldp_mode'],
                   d['note'], _now(), _now()))
        c.commit()
    finally:
        c.close()


def list_drivers(enabled_only=False):
    ensure_v12_tables(); c = _connect()
    try:
        q = 'SELECT * FROM vendor_drivers' + (' WHERE enabled=1' if enabled_only else '') + ' ORDER BY priority DESC,vendor,name'
        return [dict(r) for r in c.execute(q).fetchall()]
    finally: c.close()


def detect_driver(sys_descr='', sys_object_id=''):
    text = str(sys_descr or '')
    oid = str(sys_object_id or '').lstrip('.')
    for d in list_drivers(True):
        prefix = str(d.get('sysobject_prefix') or '').lstrip('.')
        if prefix and oid.startswith(prefix):
            return d
        regex = str(d.get('descr_regex') or '').strip()
        if regex:
            try:
                if re.search(regex, text, re.I):
                    return d
            except re.error:
                if regex.lower() in text.lower():
                    return d
    return None


def assign_driver(device_id, driver_id, source='manual', descr='', object_id=''):
    ensure_v12_tables(); c = _connect()
    try:
        c.execute('''INSERT INTO device_driver_assignments(device_id,driver_id,source,detected_descr,detected_object_id,updated_at)
          VALUES(?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET driver_id=excluded.driver_id,source=excluded.source,
          detected_descr=excluded.detected_descr,detected_object_id=excluded.detected_object_id,updated_at=excluded.updated_at''',
          (device_id, driver_id, source, descr, object_id, _now()))
        c.commit()
    finally: c.close()


def get_driver_for_device(device_id=None, host=None):
    ensure_v12_tables(); c = _connect()
    try:
        if device_id is None and host:
            r = c.execute('SELECT id FROM network_devices WHERE ip=? ORDER BY id LIMIT 1', (host,)).fetchone()
            device_id = r['id'] if r else None
        if device_id is None: return None
        r = c.execute('''SELECT d.* FROM device_driver_assignments a JOIN vendor_drivers d ON d.id=a.driver_id WHERE a.device_id=?''', (device_id,)).fetchone()
        return dict(r) if r else None
    finally: c.close()


def _credential_dict(credential_id):
    c = _connect()
    try:
        r = c.execute('SELECT * FROM snmpv3_credentials WHERE id=?', (credential_id,)).fetchone()
        return dict(r) if r else None
    finally: c.close()


def _proto_constants(mod, auth_name, priv_name):
    auth_map = {
        'MD5': 'usmHMACMD5AuthProtocol', 'SHA': 'usmHMACSHAAuthProtocol',
        'SHA224': 'usmHMAC128SHA224AuthProtocol', 'SHA256': 'usmHMAC192SHA256AuthProtocol',
        'SHA384': 'usmHMAC256SHA384AuthProtocol', 'SHA512': 'usmHMAC384SHA512AuthProtocol',
    }
    priv_map = {
        'DES': 'usmDESPrivProtocol', 'AES128': 'usmAesCfb128Protocol',
        'AES192': 'usmAesCfb192Protocol', 'AES256': 'usmAesCfb256Protocol',
    }
    auth = getattr(mod, auth_map.get(str(auth_name).upper(), 'usmHMACSHAAuthProtocol'), None)
    priv = getattr(mod, priv_map.get(str(priv_name).upper(), 'usmAesCfb128Protocol'), None)
    return auth, priv


def _run_async(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # Hàm này thường chạy ở worker thread; fallback này tránh xung đột nếu được gọi từ loop khác.
    result = []; error = []
    def runner():
        try: result.append(asyncio.run(coro))
        except Exception as e: error.append(e)
    t = threading.Thread(target=runner); t.start(); t.join()
    if error: raise error[0]
    return result[0]


def snmpv3_get(host, credential, oids, timeout=2.0, retries=1):
    """SNMPv3 GET qua pysnmp. Hỗ trợ API pysnmp 7.x và fallback API cũ."""
    if not credential:
        raise ValueError('Chưa chọn credential SNMPv3.')
    username = credential.get('username') or ''
    level = credential.get('security_level') or 'authPriv'
    auth_key = decrypt_secret(credential.get('auth_secret_enc') or '') if credential.get('auth_secret_enc') else None
    priv_key = decrypt_secret(credential.get('priv_secret_enc') or '') if credential.get('priv_secret_enc') else None
    context_name = credential.get('context_name') or ''
    port = int(credential.get('port') or 161)
    if not username: raise ValueError('SNMPv3 thiếu username.')
    if level in ('authNoPriv','authPriv') and not auth_key: raise ValueError('SNMPv3 cần Auth password.')
    if level == 'authPriv' and not priv_key: raise ValueError('SNMPv3 authPriv cần Privacy password.')

    # pysnmp 7.x asyncio API
    try:
        import pysnmp.hlapi.v3arch.asyncio as hl
        auth_proto, priv_proto = _proto_constants(hl, credential.get('auth_protocol'), credential.get('priv_protocol'))
        kwargs = {}
        if level in ('authNoPriv','authPriv'):
            kwargs.update(authKey=auth_key, authProtocol=auth_proto)
        if level == 'authPriv':
            kwargs.update(privKey=priv_key, privProtocol=priv_proto)
        user_data = hl.UsmUserData(username, **kwargs)
        async def query():
            target = await hl.UdpTransportTarget.create((host, port), timeout=float(timeout), retries=int(retries))
            objs = [hl.ObjectType(hl.ObjectIdentity(str(oid).lstrip('.'))) for oid in oids]
            return await hl.get_cmd(hl.SnmpEngine(), user_data, target, hl.ContextData(contextName=context_name), *objs)
        error_indication, error_status, error_index, var_binds = _run_async(query())
        if error_indication:
            raise TimeoutError(f'SNMPv3 không phản hồi hoặc xác thực thất bại: {error_indication}')
        if error_status:
            raise RuntimeError(f'SNMPv3 lỗi {error_status.prettyPrint()} tại {error_index}')
        return {str(n.prettyPrint()).lstrip('.'): _pretty_value(v) for n,v in var_binds}
    except ImportError:
        pass

    # pysnmp 4.x/5.x synchronous API fallback
    try:
        import pysnmp.hlapi as hl
        auth_proto, priv_proto = _proto_constants(hl, credential.get('auth_protocol'), credential.get('priv_protocol'))
        kwargs = {}
        if level in ('authNoPriv','authPriv'):
            kwargs.update(authKey=auth_key, authProtocol=auth_proto)
        if level == 'authPriv': kwargs.update(privKey=priv_key, privProtocol=priv_proto)
        user_data = hl.UsmUserData(username, **kwargs)
        iterator = hl.getCmd(hl.SnmpEngine(), user_data, hl.UdpTransportTarget((host,port), timeout=float(timeout), retries=int(retries)),
                             hl.ContextData(contextName=context_name), *[hl.ObjectType(hl.ObjectIdentity(str(o).lstrip('.'))) for o in oids])
        error_indication, error_status, error_index, var_binds = next(iterator)
        if error_indication: raise TimeoutError(f'SNMPv3 không phản hồi hoặc xác thực thất bại: {error_indication}')
        if error_status: raise RuntimeError(f'SNMPv3 lỗi {error_status.prettyPrint()} tại {error_index}')
        return {str(n.prettyPrint()).lstrip('.'): _pretty_value(v) for n,v in var_binds}
    except ImportError as e:
        raise RuntimeError('Thiếu thư viện pysnmp. Chạy: pip install pysnmp>=7.1') from e


def _pretty_value(v):
    try:
        # Numeric SNMP types
        if hasattr(v, '__int__') and v.__class__.__name__ not in ('OctetString','ObjectIdentifier'):
            return int(v)
    except Exception: pass
    try: return v.prettyPrint()
    except Exception: return str(v)


def secure_snmp_get(host, oids, version='v2c', community='public', credential_id=None, port=161, timeout=2.0):
    if str(version).lower() in ('v3','snmpv3'):
        cred = _credential_dict(credential_id)
        return snmpv3_get(host, cred, oids, timeout=timeout)
    return snmp_get(host, community, oids, port=int(port), timeout=float(timeout))


SYS_DESCR='1.3.6.1.2.1.1.1.0'; SYS_OBJECT='1.3.6.1.2.1.1.2.0'; SYS_UPTIME='1.3.6.1.2.1.1.3.0'; SYS_NAME='1.3.6.1.2.1.1.5.0'


class SNMPv3CredentialsPage:
    def __init__(self, parent, activity_callback=None):
        ensure_v12_tables(); self.parent=parent; self.activity=activity_callback or (lambda m:None); self._build(); self.refresh()
    def _build(self):
        top=tk.Frame(self.parent,bg=UI_COLORS['background']); top.pack(fill='x',padx=25,pady=(0,8))
        tk.Button(top,text='Thêm SNMPv3',command=self.add,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left')
        tk.Button(top,text='Sửa',command=self.edit).pack(side='left',padx=5); tk.Button(top,text='Gán cho thiết bị',command=self.assign).pack(side='left',padx=5)
        tk.Button(top,text='Xóa',command=self.delete).pack(side='left',padx=5); tk.Button(top,text='Làm mới',command=self.refresh).pack(side='left',padx=5)
        box=tk.Frame(self.parent,bg=UI_COLORS['surface']);box.pack(fill='both',expand=True,padx=25,pady=(0,10)); cols=('name','user','level','auth','priv','port','assigned','note')
        self.t=ttk.Treeview(box,columns=cols,show='headings')
        for c,h,w in [('name','Tên',160),('user','Username',130),('level','Security',100),('auth','Auth',80),('priv','Privacy',90),('port','Port',60),('assigned','Đã gán',70),('note','Ghi chú',260)]: self.t.heading(c,text=h);self.t.column(c,width=w,anchor='w')
        self.t.pack(fill='both',expand=True,padx=8,pady=8)
        tk.Label(self.parent,text='Auth/Privacy password được mã hóa Fernet. Không hiển thị lại sau khi lưu.',bg=UI_COLORS['background'],fg=UI_COLORS['muted']).pack(anchor='w',padx=25,pady=(0,8))
    def refresh(self):
        for x in self.t.get_children():self.t.delete(x)
        c=_connect(); rows=c.execute('''SELECT s.*,COUNT(a.device_id) assigned FROM snmpv3_credentials s LEFT JOIN device_snmpv3_assignments a ON a.credential_id=s.id GROUP BY s.id ORDER BY s.name''').fetchall(); c.close()
        for r in rows:self.t.insert('','end',iid=str(r['id']),values=(r['name'],r['username'],r['security_level'],r['auth_protocol'],r['priv_protocol'],r['port'],r['assigned'],r['note']))
    def _selected(self):
        s=self.t.selection(); return int(s[0]) if s else None
    def _dialog(self,title,row=None):
        w=tk.Toplevel(self.parent);w.title(title);w.geometry('520x500');w.transient(self.parent.winfo_toplevel());w.grab_set(); row=row or {}
        v={
          'name':tk.StringVar(value=row.get('name','')), 'username':tk.StringVar(value=row.get('username','')),
          'level':tk.StringVar(value=row.get('security_level','authPriv')), 'auth':tk.StringVar(value=row.get('auth_protocol','SHA')),
          'authpass':tk.StringVar(), 'priv':tk.StringVar(value=row.get('priv_protocol','AES128')), 'privpass':tk.StringVar(),
          'context':tk.StringVar(value=row.get('context_name','')), 'port':tk.StringVar(value=str(row.get('port') or 161)), 'note':tk.StringVar(value=row.get('note',''))}
        specs=[('Tên credential','name'),('Username','username'),('Security level','level'),('Auth protocol','auth'),('Auth password','authpass'),('Privacy protocol','priv'),('Privacy password','privpass'),('Context name','context'),('Port','port'),('Ghi chú','note')]
        for i,(lab,key) in enumerate(specs):
            tk.Label(w,text=lab).grid(row=i,column=0,sticky='w',padx=15,pady=7)
            if key=='level': z=ttk.Combobox(w,textvariable=v[key],values=['noAuthNoPriv','authNoPriv','authPriv'],state='readonly',width=29)
            elif key=='auth': z=ttk.Combobox(w,textvariable=v[key],values=['MD5','SHA','SHA224','SHA256','SHA384','SHA512'],state='readonly',width=29)
            elif key=='priv': z=ttk.Combobox(w,textvariable=v[key],values=['DES','AES128','AES192','AES256'],state='readonly',width=29)
            else: z=tk.Entry(w,textvariable=v[key],width=32,show='*' if 'pass' in key else '')
            z.grid(row=i,column=1,padx=10,pady=7)
        result={}
        def save():
            if not v['name'].get().strip() or not v['username'].get().strip(): messagebox.showwarning(title,'Nhập tên và username.',parent=w);return
            level=v['level'].get();
            if not row and level in ('authNoPriv','authPriv') and not v['authpass'].get(): messagebox.showwarning(title,'Security level này cần Auth password.',parent=w);return
            if not row and level=='authPriv' and not v['privpass'].get(): messagebox.showwarning(title,'authPriv cần Privacy password.',parent=w);return
            result.update({k:x.get().strip() for k,x in v.items()});w.destroy()
        tk.Button(w,text='Lưu',command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],width=12).grid(row=11,column=1,sticky='e',padx=10,pady=15);w.wait_window();return result or None
    def add(self):
        d=self._dialog('Thêm Credential SNMPv3');
        if not d:return
        try: port=int(d['port'] or 161)
        except: port=161
        c=_connect()
        try:
            c.execute('''INSERT INTO snmpv3_credentials(name,username,security_level,auth_protocol,auth_secret_enc,priv_protocol,priv_secret_enc,context_name,port,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
              (d['name'],d['username'],d['level'],d['auth'],encrypt_secret(d['authpass']) if d['authpass'] else '',d['priv'],encrypt_secret(d['privpass']) if d['privpass'] else '',d['context'],port,d['note'],_now(),_now()));c.commit()
        except sqlite3.IntegrityError:messagebox.showerror('SNMPv3','Tên credential đã tồn tại.')
        finally:c.close()
        self.activity('Đã thêm credential SNMPv3: '+d['name']);self.refresh()
    def edit(self):
        i=self._selected();
        if not i:return
        c=_connect();r=c.execute('SELECT * FROM snmpv3_credentials WHERE id=?',(i,)).fetchone();c.close();d=self._dialog('Sửa Credential SNMPv3',dict(r));
        if not d:return
        try:port=int(d['port'] or 161)
        except:port=161
        c=_connect();sets=['name=?','username=?','security_level=?','auth_protocol=?','priv_protocol=?','context_name=?','port=?','note=?','updated_at=?'];vals=[d['name'],d['username'],d['level'],d['auth'],d['priv'],d['context'],port,d['note'],_now()]
        if d['authpass']:sets.append('auth_secret_enc=?');vals.append(encrypt_secret(d['authpass']))
        if d['privpass']:sets.append('priv_secret_enc=?');vals.append(encrypt_secret(d['privpass']))
        vals.append(i);c.execute('UPDATE snmpv3_credentials SET '+','.join(sets)+' WHERE id=?',vals);c.commit();c.close();self.refresh()
    def assign(self):
        cid=self._selected();
        if not cid:messagebox.showinfo('SNMPv3','Chọn credential trước.');return
        c=_connect();dev=[dict(r) for r in c.execute('SELECT id,name,ip FROM network_devices ORDER BY name,ip')];c.close()
        if not dev:messagebox.showinfo('SNMPv3','Chưa có thiết bị.');return
        labels=[f"{d['name']} ({d['ip']})" for d in dev];w=tk.Toplevel(self.parent);w.title('Gán SNMPv3');w.geometry('460x170');w.transient(self.parent.winfo_toplevel());w.grab_set();v=tk.StringVar(value=labels[0]);ttk.Combobox(w,textvariable=v,values=labels,state='readonly',width=50).pack(padx=15,pady=(25,10))
        def save():
            d=dev[labels.index(v.get())];c=_connect();c.execute('''INSERT INTO device_snmpv3_assignments(device_id,credential_id,updated_at) VALUES(?,?,?) ON CONFLICT(device_id) DO UPDATE SET credential_id=excluded.credential_id,updated_at=excluded.updated_at''',(d['id'],cid,_now()));c.commit();c.close();w.destroy();self.refresh()
        tk.Button(w,text='Gán',command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text']).pack(pady=8)
    def delete(self):
        i=self._selected();
        if not i or not messagebox.askyesno('SNMPv3','Xóa credential đã chọn?'):return
        c=_connect();c.execute('DELETE FROM device_snmpv3_assignments WHERE credential_id=?',(i,));c.execute('DELETE FROM snmpv3_credentials WHERE id=?',(i,));c.commit();c.close();self.refresh()


class VendorDriverPage:
    def __init__(self,parent,activity_callback=None):
        ensure_v12_tables();self.parent=parent;self.activity=activity_callback or (lambda m:None);self._build();self.refresh()
    def _build(self):
        top=tk.Frame(self.parent,bg=UI_COLORS['background']);top.pack(fill='x',padx=25,pady=(0,8));tk.Button(top,text='Thêm driver tùy chỉnh',command=self.add,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left');tk.Button(top,text='Sửa',command=self.edit).pack(side='left',padx=5);tk.Button(top,text='Gán cho thiết bị',command=self.assign).pack(side='left',padx=5);tk.Button(top,text='Làm mới',command=self.refresh).pack(side='left',padx=5)
        pan=ttk.Panedwindow(self.parent,orient='horizontal');pan.pack(fill='both',expand=True,padx=25,pady=(0,10));l=tk.Frame(pan,bg=UI_COLORS['surface']);r=tk.Frame(pan,bg=UI_COLORS['surface']);pan.add(l,weight=3);pan.add(r,weight=2)
        cols=('name','vendor','priority','match','enabled');self.t=ttk.Treeview(l,columns=cols,show='headings')
        for c,h,w in [('name','Driver',210),('vendor','Hãng',110),('priority','Ưu tiên',70),('match','SysObject prefix',170),('enabled','Bật',50)]:self.t.heading(c,text=h);self.t.column(c,width=w,anchor='w')
        self.t.pack(fill='both',expand=True,padx=8,pady=8);self.t.bind('<<TreeviewSelect>>',lambda e:self.detail())
        self.txt=tk.Text(r,wrap='word',font=('Consolas',10));self.txt.pack(fill='both',expand=True,padx=8,pady=8)
    def refresh(self):
        for x in self.t.get_children():self.t.delete(x)
        for d in list_drivers():self.t.insert('','end',iid=str(d['id']),values=(d['name'],d['vendor'],d['priority'],d['sysobject_prefix'] or '-', 'Có' if d['enabled'] else 'Không'))
    def selected(self):
        s=self.t.selection();return int(s[0]) if s else None
    def detail(self):
        i=self.selected();self.txt.delete('1.0','end');
        if not i:return
        d=next((x for x in list_drivers() if x['id']==i),None)
        if d:self.txt.insert('1.0',f"Driver: {d['name']}\nHãng: {d['vendor']}\nRegex: {d['descr_regex'] or '-'}\nSysObject prefix: {d['sysobject_prefix'] or '-'}\nCPU OID: {d['cpu_oid'] or '-'}\nRAM used: {d['mem_used_oid'] or '-'}\nRAM total: {d['mem_total_oid'] or '-'}\nBackup: {d['backup_command'] or '-'}\nSave: {d['save_command'] or '-'}\nDiscovery: {d['lldp_mode']}\n\n{d['note'] or ''}")
    def _dialog(self,title,row=None):
        row=row or {};w=tk.Toplevel(self.parent);w.title(title);w.geometry('650x610');w.transient(self.parent.winfo_toplevel());w.grab_set();keys=['name','vendor','priority','sysobject_prefix','descr_regex','cpu_oid','mem_used_oid','mem_total_oid','backup_command','save_command','lldp_mode','note'];v={k:tk.StringVar(value=str(row.get(k,'') if row.get(k) is not None else '')) for k in keys};v['priority'].set(v['priority'].get() or '50');v['lldp_mode'].set(v['lldp_mode'].get() or 'LLDP')
        labels=['Tên driver','Hãng','Ưu tiên','SysObjectID prefix','Regex sysDescr','CPU OID','RAM used OID','RAM total OID','Lệnh backup','Lệnh lưu config','LLDP/CDP','Ghi chú']
        for i,(lab,k) in enumerate(zip(labels,keys)):tk.Label(w,text=lab).grid(row=i,column=0,sticky='w',padx=12,pady=6);tk.Entry(w,textvariable=v[k],width=60).grid(row=i,column=1,padx=12,pady=6,sticky='ew')
        w.grid_columnconfigure(1,weight=1);res={}
        def save():
            if not v['name'].get().strip():messagebox.showwarning(title,'Nhập tên driver.',parent=w);return
            res.update({k:x.get().strip() for k,x in v.items()});w.destroy()
        tk.Button(w,text='Lưu driver',command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text']).grid(row=13,column=1,sticky='e',padx=12,pady=15);w.wait_window();return res or None
    def add(self):
        d=self._dialog('Thêm driver');
        if not d:return
        c=_connect();
        try:c.execute('''INSERT INTO vendor_drivers(name,vendor,priority,sysobject_prefix,descr_regex,cpu_oid,mem_used_oid,mem_total_oid,backup_command,save_command,lldp_mode,note,builtin,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0,1,?,?)''',(d['name'],d['vendor'],int(d['priority'] or 50),d['sysobject_prefix'],d['descr_regex'],d['cpu_oid'],d['mem_used_oid'],d['mem_total_oid'],d['backup_command'],d['save_command'],d['lldp_mode'],d['note'],_now(),_now()));c.commit()
        except sqlite3.IntegrityError:messagebox.showerror('Driver','Tên driver đã tồn tại.')
        finally:c.close()
        self.refresh()
    def edit(self):
        i=self.selected();
        if not i:return
        c=_connect();r=c.execute('SELECT * FROM vendor_drivers WHERE id=?',(i,)).fetchone();c.close();d=self._dialog('Sửa driver',dict(r));
        if not d:return
        c=_connect();c.execute('''UPDATE vendor_drivers SET name=?,vendor=?,priority=?,sysobject_prefix=?,descr_regex=?,cpu_oid=?,mem_used_oid=?,mem_total_oid=?,backup_command=?,save_command=?,lldp_mode=?,note=?,updated_at=? WHERE id=?''',(d['name'],d['vendor'],int(d['priority'] or 50),d['sysobject_prefix'],d['descr_regex'],d['cpu_oid'],d['mem_used_oid'],d['mem_total_oid'],d['backup_command'],d['save_command'],d['lldp_mode'],d['note'],_now(),i));c.commit();c.close();self.refresh();self.detail()
    def assign(self):
        dr=self.selected();
        if not dr:messagebox.showinfo('Driver','Chọn driver.');return
        c=_connect();dev=[dict(r) for r in c.execute('SELECT id,name,ip FROM network_devices ORDER BY name,ip')];c.close();
        if not dev:return
        labels=[f"{d['name']} ({d['ip']})" for d in dev];w=tk.Toplevel(self.parent);w.title('Gán Driver');w.geometry('460x170');w.transient(self.parent.winfo_toplevel());w.grab_set();v=tk.StringVar(value=labels[0]);ttk.Combobox(w,textvariable=v,values=labels,state='readonly',width=50).pack(padx=15,pady=(25,10))
        def save():assign_driver(dev[labels.index(v.get())]['id'],dr,'manual');w.destroy()
        tk.Button(w,text='Gán',command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text']).pack(pady=8)


class SecureSNMPDiagnosticsPage:
    def __init__(self,parent,activity_callback=None):
        ensure_v12_tables();self.parent=parent;self.activity=activity_callback or (lambda m:None);self.host=tk.StringVar();self.version=tk.StringVar(value='v2c');self.community=tk.StringVar(value='public');self.cred=tk.StringVar();self.status=tk.StringVar(value='Sẵn sàng');self._build();self.reload_credentials()
    def _build(self):
        f=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid');f.pack(fill='x',padx=25,pady=(0,10));
        tk.Label(f,text='IP / Host',bg=UI_COLORS['surface']).grid(row=0,column=0,padx=(10,3),pady=10);tk.Entry(f,textvariable=self.host,width=20).grid(row=0,column=1)
        tk.Label(f,text='Phiên bản',bg=UI_COLORS['surface']).grid(row=0,column=2,padx=(10,3));cb=ttk.Combobox(f,textvariable=self.version,values=['v2c','v3'],state='readonly',width=8);cb.grid(row=0,column=3);cb.bind('<<ComboboxSelected>>',lambda e:self._mode())
        tk.Label(f,text='Community',bg=UI_COLORS['surface']).grid(row=0,column=4,padx=(10,3));self.comm_entry=tk.Entry(f,textvariable=self.community,width=14);self.comm_entry.grid(row=0,column=5)
        tk.Label(f,text='SNMPv3 Credential',bg=UI_COLORS['surface']).grid(row=1,column=0,padx=(10,3),pady=(0,10));self.cred_cb=ttk.Combobox(f,textvariable=self.cred,state='readonly',width=28);self.cred_cb.grid(row=1,column=1,columnspan=2,sticky='w',pady=(0,10));tk.Button(f,text='Kiểm tra & nhận diện',command=self.test,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').grid(row=1,column=3,columnspan=2,padx=8,pady=(0,10));tk.Label(f,textvariable=self.status,bg=UI_COLORS['surface'],fg=UI_COLORS['muted']).grid(row=1,column=5,sticky='w')
        body=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid');body.pack(fill='both',expand=True,padx=25,pady=(0,10));self.out=tk.Text(body,wrap='word',font=('Consolas',10));self.out.pack(fill='both',expand=True,padx=10,pady=10);self._mode()
    def reload_credentials(self):
        c=_connect();self.creds=[dict(r) for r in c.execute('SELECT * FROM snmpv3_credentials ORDER BY name')];c.close();vals=[x['name'] for x in self.creds];self.cred_cb['values']=vals
        if vals and not self.cred.get():self.cred.set(vals[0])
    def _mode(self):
        state='normal' if self.version.get()=='v2c' else 'disabled';self.comm_entry.configure(state=state);self.cred_cb.configure(state='readonly' if self.version.get()=='v3' else 'disabled')
    def _cred_id(self):
        for c in self.creds:
            if c['name']==self.cred.get():return c['id']
        return None
    def test(self):
        host=self.host.get().strip();
        if not host:messagebox.showinfo('SNMP','Nhập IP/Host.');return
        ver=self.version.get();cid=self._cred_id();self.status.set('Đang kiểm tra...');self.out.delete('1.0','end')
        def work():
            try:
                vals=secure_snmp_get(host,[SYS_DESCR,SYS_OBJECT,SYS_UPTIME,SYS_NAME],ver,self.community.get().strip(),cid,timeout=2.0);descr=str(vals.get(SYS_DESCR,'') or '');obj=str(vals.get(SYS_OBJECT,'') or '');name=str(vals.get(SYS_NAME,'') or '');driver=detect_driver(descr,obj)
                c=_connect();d=c.execute('SELECT id FROM network_devices WHERE ip=? ORDER BY id LIMIT 1',(host,)).fetchone();
                if d and driver:assign_driver(d['id'],driver['id'],'auto',descr,obj)
                credname=self.cred.get() if ver=='v3' else self.community.get().strip();c.execute('''INSERT INTO snmp_diagnostics_history(host,version,credential_name,success,sys_name,sys_descr,sys_object_id,detail,created_at) VALUES(?,?,?,?,?,?,?,?,?)''',(host,ver,credname,1,name,descr,obj,'OK',_now()));c.commit();c.close()
                text=f"KẾT QUẢ SNMP {ver}\n\nHost: {host}\nsysName: {name or '-'}\nsysDescr: {descr or '-'}\nsysObjectID: {obj or '-'}\nUptime ticks: {vals.get(SYS_UPTIME,'-')}\n\nDriver: {driver['name'] if driver else 'Chưa nhận diện'}"
                if driver:
                    oids=[x for x in [driver.get('cpu_oid'),driver.get('mem_used_oid'),driver.get('mem_total_oid')] if x]
                    if oids:
                        try:
                            res=secure_snmp_get(host,oids,ver,self.community.get().strip(),cid,timeout=2.0);text+='\n\nTài nguyên theo driver:\n'+ '\n'.join(f"{k}: {v}" for k,v in res.items())
                        except Exception as e:text+='\n\nKhông đọc được OID tài nguyên: '+str(e)
                self.parent.after(0,lambda t=text:(self.status.set('SNMP hoạt động'),self.out.insert('1.0',t)))
            except Exception as e:
                msg=str(e);c=_connect();c.execute('''INSERT INTO snmp_diagnostics_history(host,version,credential_name,success,detail,created_at) VALUES(?,?,?,?,?,?)''',(host,ver,self.cred.get() if ver=='v3' else self.community.get().strip(),0,msg,_now()));c.commit();c.close();self.parent.after(0,lambda m=msg:(self.status.set('Lỗi'),self.out.insert('1.0','Không thể kết nối SNMP.\n\n'+m+'\n\nGợi ý: kiểm tra UDP/161, username/community, Auth/Privacy protocol và mật khẩu.')))
        threading.Thread(target=work,daemon=True).start()


__all__=['ensure_v12_tables','detect_driver','assign_driver','get_driver_for_device','secure_snmp_get','snmpv3_get','SNMPv3CredentialsPage','VendorDriverPage','SecureSNMPDiagnosticsPage']
