from modules.ui_theme import PALETTE as UI_COLORS
import sqlite3
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

from modules.advanced_pages import _connect, snmp_get


def _now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


BUILTIN_PROFILES = [
    {
        'name': 'Cisco IOS / IOS-XE', 'vendor': 'Cisco',
        'match_text': 'cisco|1.3.6.1.4.1.9',
        'cpu_oid': '1.3.6.1.4.1.9.2.1.58.0',
        'mem_used_oid': '', 'mem_total_oid': '',
        'backup_command': 'show running-config',
        'lldp_mode': 'LLDP/CDP',
        'note': 'CPU OID kiểu Cisco cũ. Một số IOS-XE/model mới cần OID khác; hãy tùy chỉnh nếu không có dữ liệu.'
    },
    {
        'name': 'MikroTik RouterOS', 'vendor': 'MikroTik',
        'match_text': 'mikrotik|routeros|1.3.6.1.4.1.14988',
        'cpu_oid': '1.3.6.1.4.1.14988.1.1.3.14.0',
        'mem_used_oid': '', 'mem_total_oid': '',
        'backup_command': '/export terse',
        'lldp_mode': 'LLDP',
        'note': 'CPU load dùng MIKROTIK-MIB. RAM khác nhau theo RouterOS/model nên để trống để tránh số liệu sai.'
    },
    {
        'name': 'Ruijie / Reyee', 'vendor': 'Ruijie',
        'match_text': 'ruijie|reyee|1.3.6.1.4.1.4881',
        'cpu_oid': '', 'mem_used_oid': '', 'mem_total_oid': '',
        'backup_command': 'show running-config',
        'lldp_mode': 'LLDP',
        'note': 'OID CPU/RAM phụ thuộc dòng thiết bị và firmware. Dùng OID do hãng cung cấp cho model cụ thể.'
    },
    {
        'name': 'Aruba / HPE', 'vendor': 'Aruba/HPE',
        'match_text': 'aruba|hewlett packard enterprise|procurve|hpe',
        'cpu_oid': '', 'mem_used_oid': '', 'mem_total_oid': '',
        'backup_command': 'show running-config',
        'lldp_mode': 'LLDP',
        'note': 'ArubaOS, Aruba CX và ProCurve có MIB/CLI khác nhau. Hồ sơ này chỉ chọn lệnh backup phổ biến.'
    },
    {
        'name': 'Generic HOST-RESOURCES', 'vendor': 'Generic',
        'match_text': 'linux|windows|microsoft',
        'cpu_oid': '1.3.6.1.2.1.25.3.3.1.2.1',
        'mem_used_oid': '', 'mem_total_oid': '',
        'backup_command': '',
        'lldp_mode': 'LLDP',
        'note': 'CPU lấy instance đầu của HOST-RESOURCES-MIB; không phù hợp mọi hệ điều hành/thiết bị.'
    },
]


def ensure_v7_tables():
    c = _connect()
    try:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS device_profiles(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            vendor TEXT DEFAULT '',
            match_text TEXT DEFAULT '',
            cpu_oid TEXT DEFAULT '',
            mem_used_oid TEXT DEFAULT '',
            mem_total_oid TEXT DEFAULT '',
            backup_command TEXT DEFAULT '',
            lldp_mode TEXT DEFAULT 'LLDP',
            note TEXT DEFAULT '',
            builtin INTEGER DEFAULT 0,
            created_at TEXT,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS device_profile_assignments(
            device_id INTEGER PRIMARY KEY,
            profile_id INTEGER NOT NULL,
            source TEXT DEFAULT 'manual',
            detected_descr TEXT DEFAULT '',
            detected_object_id TEXT DEFAULT '',
            updated_at TEXT
        );
        ''')
        cols = {r['name'] for r in c.execute('PRAGMA table_info(network_devices)').fetchall()}
        if 'profile_id' not in cols:
            c.execute('ALTER TABLE network_devices ADD COLUMN profile_id INTEGER')
        for p in BUILTIN_PROFILES:
            row = c.execute('SELECT id FROM device_profiles WHERE name=?', (p['name'],)).fetchone()
            if row:
                c.execute('''UPDATE device_profiles SET vendor=?,match_text=?,cpu_oid=?,mem_used_oid=?,mem_total_oid=?,backup_command=?,lldp_mode=?,note=?,builtin=1,updated_at=? WHERE id=?''',
                          (p['vendor'],p['match_text'],p['cpu_oid'],p['mem_used_oid'],p['mem_total_oid'],p['backup_command'],p['lldp_mode'],p['note'],_now(),row['id']))
            else:
                c.execute('''INSERT INTO device_profiles(name,vendor,match_text,cpu_oid,mem_used_oid,mem_total_oid,backup_command,lldp_mode,note,builtin,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,1,?,?)''',
                          (p['name'],p['vendor'],p['match_text'],p['cpu_oid'],p['mem_used_oid'],p['mem_total_oid'],p['backup_command'],p['lldp_mode'],p['note'],_now(),_now()))
        c.commit()
    finally:
        c.close()


def detect_profile(descr='', object_id=''):
    ensure_v7_tables()
    text = (str(descr) + ' ' + str(object_id)).lower()
    c = _connect()
    try:
        rows = c.execute('SELECT * FROM device_profiles ORDER BY builtin DESC,id').fetchall()
        for r in rows:
            keys = [x.strip().lower() for x in (r['match_text'] or '').split('|') if x.strip()]
            if keys and any(k in text for k in keys):
                return dict(r)
    finally:
        c.close()
    return None


def get_profile_for_device(device_id=None, host=None):
    ensure_v7_tables(); c = _connect()
    try:
        if device_id is None and host:
            r = c.execute('SELECT id,profile_id FROM network_devices WHERE ip=? ORDER BY id LIMIT 1',(host,)).fetchone()
            if r: device_id = r['id']
        if device_id is None: return None
        r = c.execute('''SELECT p.* FROM device_profile_assignments a JOIN device_profiles p ON p.id=a.profile_id WHERE a.device_id=?''',(device_id,)).fetchone()
        if not r:
            r = c.execute('''SELECT p.* FROM network_devices d JOIN device_profiles p ON p.id=d.profile_id WHERE d.id=?''',(device_id,)).fetchone()
        return dict(r) if r else None
    finally:c.close()


def assign_profile(device_id, profile_id, source='manual', descr='', object_id=''):
    ensure_v7_tables(); c=_connect()
    try:
        c.execute('''INSERT INTO device_profile_assignments(device_id,profile_id,source,detected_descr,detected_object_id,updated_at)
                     VALUES(?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET profile_id=excluded.profile_id,source=excluded.source,detected_descr=excluded.detected_descr,detected_object_id=excluded.detected_object_id,updated_at=excluded.updated_at''',
                  (device_id,profile_id,source,descr,object_id,_now()))
        c.execute('UPDATE network_devices SET profile_id=?,updated_at=? WHERE id=?',(profile_id,_now(),device_id)); c.commit()
    finally:c.close()


class DeviceProfilesPage:
    SYS_DESCR='1.3.6.1.2.1.1.1.0'; SYS_OBJECT='1.3.6.1.2.1.1.2.0'; SYS_NAME='1.3.6.1.2.1.1.5.0'
    def __init__(self,parent,activity_callback=None):
        ensure_v7_tables(); self.parent=parent; self.activity=activity_callback or (lambda m:None); self.status=tk.StringVar(value='Sẵn sàng'); self.community=tk.StringVar(value='public'); self._build(); self.refresh()
    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['background']);ctl.pack(fill='x',padx=25,pady=(0,8))
        tk.Button(ctl,text='Gán hồ sơ',command=self.assign,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left')
        tk.Button(ctl,text='Thêm hồ sơ tùy chỉnh',command=self.add_custom).pack(side='left',padx=5)
        tk.Button(ctl,text='Tự nhận diện SNMP',command=self.auto_detect,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left',padx=5)
        tk.Label(ctl,text='Community:',bg=UI_COLORS['background']).pack(side='left',padx=(12,3));tk.Entry(ctl,textvariable=self.community,width=14).pack(side='left')
        tk.Button(ctl,text='Làm mới',command=self.refresh).pack(side='left',padx=5);tk.Label(ctl,textvariable=self.status,bg=UI_COLORS['background'],fg=UI_COLORS['muted']).pack(side='left',padx=10)
        pan=ttk.Panedwindow(self.parent,orient='horizontal');pan.pack(fill='both',expand=True,padx=25,pady=(0,10))
        l=tk.Frame(pan,bg=UI_COLORS['surface']);r=tk.Frame(pan,bg=UI_COLORS['surface']);pan.add(l,weight=3);pan.add(r,weight=2)
        cols=('name','ip','vendor','profile','source');self.t=ttk.Treeview(l,columns=cols,show='headings')
        for c,h,w in [('name','Thiết bị',180),('ip','IP',130),('vendor','Vendor',110),('profile','Hồ sơ',210),('source','Nguồn',90)]: self.t.heading(c,text=h);self.t.column(c,width=w,anchor='w')
        self.t.pack(fill='both',expand=True,padx=8,pady=8);self.t.bind('<<TreeviewSelect>>',lambda e:self.show_profile())
        self.detail=tk.Text(r,wrap='word',font=('Consolas',10));self.detail.pack(fill='both',expand=True,padx=8,pady=8)
    def refresh(self):
        for x in self.t.get_children(): self.t.delete(x)
        c=_connect(); rows=c.execute('''SELECT d.id,d.name,d.ip,d.vendor,a.source,p.name profile_name FROM network_devices d LEFT JOIN device_profile_assignments a ON a.device_id=d.id LEFT JOIN device_profiles p ON p.id=COALESCE(a.profile_id,d.profile_id) ORDER BY d.name,d.ip''').fetchall(); c.close()
        for r in rows:self.t.insert('','end',iid=str(r['id']),values=(r['name'],r['ip'],r['vendor'] or '-',r['profile_name'] or 'Chưa gán',r['source'] or '-'))
    def _device_id(self):
        s=self.t.selection();return int(s[0]) if s else None
    def show_profile(self):
        did=self._device_id();p=get_profile_for_device(device_id=did) if did else None;self.detail.delete('1.0','end')
        if not p:self.detail.insert('1.0','Thiết bị chưa được gán hồ sơ.\nDùng “Tự nhận diện SNMP” hoặc “Gán hồ sơ”.');return
        self.detail.insert('1.0',f"Tên: {p['name']}\nHãng: {p['vendor']}\nCPU OID: {p['cpu_oid'] or '-'}\nRAM used OID: {p['mem_used_oid'] or '-'}\nRAM total OID: {p['mem_total_oid'] or '-'}\nBackup command: {p['backup_command'] or '-'}\nDiscovery: {p['lldp_mode'] or '-'}\n\nGhi chú:\n{p['note'] or '-'}")
    def add_custom(self):
        w=tk.Toplevel(self.parent);w.title('Thêm hồ sơ tùy chỉnh');w.geometry('620x520');w.transient(self.parent.winfo_toplevel());w.grab_set()
        vars={k:tk.StringVar() for k in ('name','vendor','match','cpu','used','total','backup','lldp','note')};vars['lldp'].set('LLDP')
        fields=[('Tên hồ sơ','name'),('Hãng','vendor'),('Chuỗi nhận diện (ngăn cách |)','match'),('CPU OID','cpu'),('RAM used OID','used'),('RAM total OID','total'),('Lệnh backup','backup'),('Discovery (LLDP/CDP)','lldp'),('Ghi chú','note')]
        for i,(lab,key) in enumerate(fields):
            tk.Label(w,text=lab).grid(row=i,column=0,sticky='nw',padx=12,pady=7)
            tk.Entry(w,textvariable=vars[key],width=55).grid(row=i,column=1,sticky='ew',padx=12,pady=7)
        w.grid_columnconfigure(1,weight=1)
        def save():
            if not vars['name'].get().strip():messagebox.showwarning('Hồ sơ','Nhập tên hồ sơ.',parent=w);return
            c=_connect()
            try:
                c.execute('''INSERT INTO device_profiles(name,vendor,match_text,cpu_oid,mem_used_oid,mem_total_oid,backup_command,lldp_mode,note,builtin,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,0,?,?)''',
                          (vars['name'].get().strip(),vars['vendor'].get().strip(),vars['match'].get().strip(),vars['cpu'].get().strip(),vars['used'].get().strip(),vars['total'].get().strip(),vars['backup'].get().strip(),vars['lldp'].get().strip(),vars['note'].get().strip(),_now(),_now()));c.commit()
            except sqlite3.IntegrityError:messagebox.showerror('Hồ sơ','Tên hồ sơ đã tồn tại.',parent=w);c.close();return
            c.close();self.activity('Đã thêm hồ sơ thiết bị tùy chỉnh: '+vars['name'].get().strip());w.destroy();self.refresh()
        tk.Button(w,text='Lưu hồ sơ',command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text']).grid(row=len(fields),column=1,sticky='e',padx=12,pady=15)

    def assign(self):
        did=self._device_id()
        if not did:messagebox.showinfo('Hồ sơ thiết bị','Chọn một thiết bị.');return
        c=_connect();profiles=[dict(r) for r in c.execute('SELECT * FROM device_profiles ORDER BY vendor,name')];c.close()
        w=tk.Toplevel(self.parent);w.title('Gán hồ sơ thiết bị');w.geometry('430x180');w.transient(self.parent.winfo_toplevel());w.grab_set(); labels=[f"{p['vendor']} - {p['name']}" for p in profiles];v=tk.StringVar(value=labels[0] if labels else '')
        tk.Label(w,text='Chọn hồ sơ').pack(anchor='w',padx=15,pady=(18,5));ttk.Combobox(w,textvariable=v,values=labels,state='readonly',width=48).pack(padx=15)
        def save():
            if v.get() not in labels:return
            p=profiles[labels.index(v.get())];assign_profile(did,p['id'],'manual');self.activity('Đã gán hồ sơ thiết bị: '+p['name']);w.destroy();self.refresh();self.show_profile()
        tk.Button(w,text='Gán',command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text']).pack(pady=18)
    def auto_detect(self):
        did=self._device_id()
        if not did:messagebox.showinfo('Tự nhận diện','Chọn một thiết bị.');return
        c=_connect();d=c.execute('SELECT * FROM network_devices WHERE id=?',(did,)).fetchone();c.close()
        if not d or not d['ip']:messagebox.showwarning('Tự nhận diện','Thiết bị chưa có IP.');return
        self.status.set('Đang nhận diện '+d['ip']+'...')
        def work():
            try:
                vals=snmp_get(d['ip'],self.community.get().strip(),[self.SYS_DESCR,self.SYS_OBJECT,self.SYS_NAME]);descr=str(vals.get(self.SYS_DESCR) or '');obj=str(vals.get(self.SYS_OBJECT) or '');p=detect_profile(descr,obj)
                if not p:raise RuntimeError('SNMP phản hồi nhưng chưa khớp hồ sơ hãng. Hãy gán thủ công.')
                assign_profile(did,p['id'],'auto',descr,obj);msg=f"Đã nhận diện: {p['name']}"
                self.parent.after(0,lambda m=msg:(self.status.set(m),self.refresh(),self.show_profile()))
            except Exception as e:self.parent.after(0,lambda m=str(e):self.status.set('Lỗi: '+m))
        threading.Thread(target=work,daemon=True).start()


__all__=['ensure_v7_tables','DeviceProfilesPage','detect_profile','get_profile_for_device','assign_profile','BUILTIN_PROFILES']
