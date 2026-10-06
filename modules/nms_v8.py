from modules.ui_ux_config import PALETTE as UI_COLORS
import sqlite3
try:
    import tkinter as tk
except (ImportError, ModuleNotFoundError):
    tk = None
try:
    from tkinter import ttk, messagebox, simpledialog
except (ImportError, ModuleNotFoundError):
    ttk = messagebox = simpledialog = None
from datetime import datetime

from modules.advanced_pages import _connect


def _now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def ensure_v8_tables():
    c = _connect()
    try:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS sites(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE,
          location TEXT,
          note TEXT,
          created_at TEXT,
          updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS device_groups(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE,
          note TEXT,
          created_at TEXT,
          updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS device_organization(
          device_id INTEGER PRIMARY KEY,
          site_id INTEGER,
          group_id INTEGER,
          vlan TEXT,
          tags TEXT,
          updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS maintenance_windows(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          scope_type TEXT NOT NULL DEFAULT 'Device',
          scope_id INTEGER,
          host TEXT,
          start_at TEXT NOT NULL,
          end_at TEXT NOT NULL,
          suppress_alerts INTEGER DEFAULT 1,
          enabled INTEGER DEFAULT 1,
          note TEXT,
          created_at TEXT,
          updated_at TEXT
        );
        ''')
        c.commit()
    finally:
        c.close()


def _parse_dt(value):
    try:
        return datetime.strptime(str(value), '%Y-%m-%d %H:%M:%S')
    except Exception:
        return None


def active_maintenance_for_host(host, when=None):
    """Return the active maintenance row for host, if any."""
    ensure_v8_tables()
    when = when or datetime.now()
    c = _connect()
    try:
        rows = c.execute('''
          SELECT m.*, d.id AS device_id, o.site_id, o.group_id
          FROM maintenance_windows m
          LEFT JOIN network_devices d ON d.ip=?
          LEFT JOIN device_organization o ON o.device_id=d.id
          WHERE m.enabled=1 AND m.suppress_alerts=1
        ''', (host,)).fetchall()
        for r in rows:
            start = _parse_dt(r['start_at']); end = _parse_dt(r['end_at'])
            if not start or not end or not (start <= when <= end):
                continue
            scope = r['scope_type']
            if scope == 'All':
                return dict(r)
            if scope == 'Device' and ((r['host'] or '').strip() == host or (r['scope_id'] and r['device_id'] == r['scope_id'])):
                return dict(r)
            if scope == 'Site' and r['scope_id'] and r['site_id'] == r['scope_id']:
                return dict(r)
            if scope == 'Group' and r['scope_id'] and r['group_id'] == r['scope_id']:
                return dict(r)
        return None
    finally:
        c.close()


class OrganizationPage:
    def __init__(self, parent, activity_callback=None):
        ensure_v8_tables()
        self.parent = parent
        self.activity = activity_callback or (lambda m: None)
        self.status = tk.StringVar(value='Sẵn sàng')
        self._build(); self.refresh()

    def _build(self):
        ctl = tk.Frame(self.parent, bg=UI_COLORS['background']); ctl.pack(fill='x', padx=25, pady=(0,8))
        tk.Button(ctl, text='Thêm Site', command=self.add_site, bg=UI_COLORS['primary'], fg=UI_COLORS['text'], relief='flat').pack(side='left')
        tk.Button(ctl, text='Thêm nhóm', command=self.add_group).pack(side='left', padx=5)
        tk.Button(ctl, text='Gán Site / Nhóm', command=self.assign).pack(side='left', padx=5)
        tk.Button(ctl, text='Sửa VLAN / Tags', command=self.edit_meta).pack(side='left', padx=5)
        tk.Button(ctl, text='Làm mới', command=self.refresh).pack(side='left', padx=5)
        tk.Label(ctl, textvariable=self.status, bg=UI_COLORS['background'], fg=UI_COLORS['muted']).pack(side='left', padx=12)

        box = tk.Frame(self.parent, bg=UI_COLORS['surface'], bd=1, relief='solid'); box.pack(fill='both', expand=True, padx=25, pady=(0,10))
        cols = ('name','ip','vendor','site','group','vlan','tags')
        self.table = ttk.Treeview(box, columns=cols, show='headings')
        defs = [('name','Thiết bị',180),('ip','IP',130),('vendor','Hãng',120),('site','Site',150),('group','Nhóm',150),('vlan','VLAN',90),('tags','Tags',220)]
        for c,h,w in defs:
            self.table.heading(c,text=h); self.table.column(c,width=w,anchor='w')
        self.table.pack(fill='both', expand=True, padx=8, pady=8)

    def _selected(self):
        s=self.table.selection(); return int(s[0]) if s else None

    def refresh(self):
        for x in self.table.get_children(): self.table.delete(x)
        c=_connect()
        try:
            rows=c.execute('''SELECT d.id,d.name,d.ip,d.vendor,s.name site_name,g.name group_name,o.vlan,o.tags
              FROM network_devices d
              LEFT JOIN device_organization o ON o.device_id=d.id
              LEFT JOIN sites s ON s.id=o.site_id
              LEFT JOIN device_groups g ON g.id=o.group_id
              ORDER BY COALESCE(s.name,''),COALESCE(g.name,''),d.name,d.ip''').fetchall()
        finally:c.close()
        for r in rows:
            self.table.insert('', 'end', iid=str(r['id']), values=(r['name'],r['ip'],r['vendor'] or '-',r['site_name'] or 'Chưa gán',r['group_name'] or 'Chưa gán',r['vlan'] or '-',r['tags'] or '-'))
        self.status.set(f'{len(rows)} thiết bị')

    def add_site(self):
        name=simpledialog.askstring('Site','Tên Site:',parent=self.parent)
        if not name:return
        location=simpledialog.askstring('Site','Địa điểm / mô tả vị trí:',parent=self.parent) or ''
        c=_connect()
        try:
            c.execute('INSERT INTO sites(name,location,created_at,updated_at) VALUES(?,?,?,?)',(name.strip(),location.strip(),_now(),_now()));c.commit()
        except sqlite3.IntegrityError:
            messagebox.showerror('Site','Tên Site đã tồn tại.');return
        finally:c.close()
        self.activity('Đã thêm Site: '+name.strip());self.refresh()

    def add_group(self):
        name=simpledialog.askstring('Nhóm thiết bị','Tên nhóm:',parent=self.parent)
        if not name:return
        note=simpledialog.askstring('Nhóm thiết bị','Ghi chú:',parent=self.parent) or ''
        c=_connect()
        try:
            c.execute('INSERT INTO device_groups(name,note,created_at,updated_at) VALUES(?,?,?,?)',(name.strip(),note.strip(),_now(),_now()));c.commit()
        except sqlite3.IntegrityError:
            messagebox.showerror('Nhóm thiết bị','Tên nhóm đã tồn tại.');return
        finally:c.close()
        self.activity('Đã thêm nhóm thiết bị: '+name.strip());self.refresh()

    def assign(self):
        did=self._selected()
        if not did:messagebox.showinfo('Tổ chức thiết bị','Chọn một thiết bị.');return
        c=_connect();sites=[dict(r) for r in c.execute('SELECT id,name FROM sites ORDER BY name')];groups=[dict(r) for r in c.execute('SELECT id,name FROM device_groups ORDER BY name')];c.close()
        w=tk.Toplevel(self.parent);w.title('Gán Site / Nhóm');w.geometry('460x240');w.transient(self.parent.winfo_toplevel());w.grab_set()
        site_names=['(Không gán)']+[x['name'] for x in sites]; group_names=['(Không gán)']+[x['name'] for x in groups]
        sv=tk.StringVar(value=site_names[0]);gv=tk.StringVar(value=group_names[0])
        tk.Label(w,text='Site').pack(anchor='w',padx=16,pady=(18,4));ttk.Combobox(w,textvariable=sv,values=site_names,state='readonly',width=48).pack(padx=16)
        tk.Label(w,text='Nhóm').pack(anchor='w',padx=16,pady=(12,4));ttk.Combobox(w,textvariable=gv,values=group_names,state='readonly',width=48).pack(padx=16)
        def save():
            sid=None if sv.get()==site_names[0] else sites[site_names.index(sv.get())-1]['id']
            gid=None if gv.get()==group_names[0] else groups[group_names.index(gv.get())-1]['id']
            c=_connect();c.execute('''INSERT INTO device_organization(device_id,site_id,group_id,updated_at) VALUES(?,?,?,?)
              ON CONFLICT(device_id) DO UPDATE SET site_id=excluded.site_id,group_id=excluded.group_id,updated_at=excluded.updated_at''',(did,sid,gid,_now()));c.commit();c.close()
            self.activity('Đã cập nhật Site/Nhóm cho thiết bị');w.destroy();self.refresh()
        tk.Button(w,text='Lưu',command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(pady=18)

    def edit_meta(self):
        did=self._selected()
        if not did:messagebox.showinfo('VLAN / Tags','Chọn một thiết bị.');return
        c=_connect();row=c.execute('SELECT vlan,tags FROM device_organization WHERE device_id=?',(did,)).fetchone();c.close()
        vlan=simpledialog.askstring('VLAN','VLAN (ví dụ 10, 20, MGMT):',initialvalue=(row['vlan'] if row else '') or '',parent=self.parent)
        if vlan is None:return
        tags=simpledialog.askstring('Tags','Tags, phân cách bằng dấu phẩy:',initialvalue=(row['tags'] if row else '') or '',parent=self.parent)
        if tags is None:return
        c=_connect();c.execute('''INSERT INTO device_organization(device_id,vlan,tags,updated_at) VALUES(?,?,?,?)
          ON CONFLICT(device_id) DO UPDATE SET vlan=excluded.vlan,tags=excluded.tags,updated_at=excluded.updated_at''',(did,vlan.strip(),tags.strip(),_now()));c.commit();c.close();self.refresh()


class MaintenanceWindowsPage:
    def __init__(self,parent,activity_callback=None):
        ensure_v8_tables(); self.parent=parent; self.activity=activity_callback or (lambda m:None); self.status=tk.StringVar(value='Sẵn sàng'); self._build(); self.refresh()
    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['background']);ctl.pack(fill='x',padx=25,pady=(0,8))
        tk.Button(ctl,text='Thêm lịch bảo trì',command=self.add,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left')
        tk.Button(ctl,text='Bật / Tắt',command=self.toggle).pack(side='left',padx=5)
        tk.Button(ctl,text='Xóa',command=self.delete).pack(side='left',padx=5)
        tk.Button(ctl,text='Làm mới',command=self.refresh).pack(side='left',padx=5)
        tk.Label(ctl,textvariable=self.status,bg=UI_COLORS['background'],fg=UI_COLORS['muted']).pack(side='left',padx=12)
        box=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid');box.pack(fill='both',expand=True,padx=25,pady=(0,10))
        cols=('name','scope','target','start','end','alerts','enabled')
        self.t=ttk.Treeview(box,columns=cols,show='headings')
        for c,h,w in [('name','Tên',180),('scope','Phạm vi',90),('target','Đối tượng',180),('start','Bắt đầu',160),('end','Kết thúc',160),('alerts','Tắt cảnh báo',100),('enabled','Bật',70)]:self.t.heading(c,text=h);self.t.column(c,width=w,anchor='w')
        self.t.pack(fill='both',expand=True,padx=8,pady=8)
        tk.Label(self.parent,text='Trong thời gian bảo trì, Alert Rules sẽ không tạo cảnh báo mới cho thiết bị nằm trong phạm vi đã chọn.',bg=UI_COLORS['background'],fg=UI_COLORS['muted']).pack(anchor='w',padx=25,pady=(0,8))
    def _selected(self):
        s=self.t.selection();return int(s[0]) if s else None
    def refresh(self):
        for x in self.t.get_children():self.t.delete(x)
        c=_connect();rows=c.execute('SELECT * FROM maintenance_windows ORDER BY start_at DESC,id DESC').fetchall()
        sites={r['id']:r['name'] for r in c.execute('SELECT id,name FROM sites')};groups={r['id']:r['name'] for r in c.execute('SELECT id,name FROM device_groups')};devices={r['id']:(r['name'] or r['ip']) for r in c.execute('SELECT id,name,ip FROM network_devices')};c.close()
        now=datetime.now();active=0
        for r in rows:
            scope=r['scope_type'];target='Tất cả'
            if scope=='Device':target=r['host'] or devices.get(r['scope_id'],'Thiết bị')
            elif scope=='Site':target=sites.get(r['scope_id'],'Site')
            elif scope=='Group':target=groups.get(r['scope_id'],'Nhóm')
            st=_parse_dt(r['start_at']);en=_parse_dt(r['end_at'])
            if r['enabled'] and st and en and st<=now<=en:active+=1
            self.t.insert('','end',iid=str(r['id']),values=(r['name'],scope,target,r['start_at'],r['end_at'],'Có' if r['suppress_alerts'] else 'Không','Có' if r['enabled'] else 'Không'))
        self.status.set(f'{len(rows)} lịch • {active} đang hiệu lực')
    def add(self):
        c=_connect();devices=[dict(r) for r in c.execute('SELECT id,name,ip FROM network_devices ORDER BY name,ip')];sites=[dict(r) for r in c.execute('SELECT id,name FROM sites ORDER BY name')];groups=[dict(r) for r in c.execute('SELECT id,name FROM device_groups ORDER BY name')];c.close()
        w=tk.Toplevel(self.parent);w.title('Thêm lịch bảo trì');w.geometry('620x500');w.transient(self.parent.winfo_toplevel());w.grab_set()
        name=tk.StringVar();scope=tk.StringVar(value='Device');target=tk.StringVar();start=tk.StringVar(value=datetime.now().strftime('%Y-%m-%d %H:%M:%S'));end=tk.StringVar(value=datetime.now().replace(hour=23,minute=59,second=59).strftime('%Y-%m-%d %H:%M:%S'));sup=tk.BooleanVar(value=True);note=tk.StringVar()
        tk.Label(w,text='Tên lịch').pack(anchor='w',padx=16,pady=(16,4));tk.Entry(w,textvariable=name,width=60).pack(padx=16)
        tk.Label(w,text='Phạm vi').pack(anchor='w',padx=16,pady=(12,4));cb=ttk.Combobox(w,textvariable=scope,values=['Device','Site','Group','All'],state='readonly',width=56);cb.pack(padx=16)
        tk.Label(w,text='Đối tượng').pack(anchor='w',padx=16,pady=(12,4));target_cb=ttk.Combobox(w,textvariable=target,state='readonly',width=56);target_cb.pack(padx=16)
        mapping={}
        def update_targets(*_):
            mapping.clear(); vals=[]
            if scope.get()=='Device':
                for d in devices:
                    label=f"{d['name'] or '-'} | {d['ip'] or '-'}";vals.append(label);mapping[label]=(d['id'],d['ip'])
            elif scope.get()=='Site':
                for d in sites:vals.append(d['name']);mapping[d['name']]=(d['id'],None)
            elif scope.get()=='Group':
                for d in groups:vals.append(d['name']);mapping[d['name']]=(d['id'],None)
            else:vals=['Tất cả'];mapping['Tất cả']=(None,None)
            target_cb['values']=vals;target.set(vals[0] if vals else '')
        cb.bind('<<ComboboxSelected>>',update_targets);update_targets()
        for lab,var in [('Bắt đầu (YYYY-MM-DD HH:MM:SS)',start),('Kết thúc (YYYY-MM-DD HH:MM:SS)',end),('Ghi chú',note)]:
            tk.Label(w,text=lab).pack(anchor='w',padx=16,pady=(12,4));tk.Entry(w,textvariable=var,width=60).pack(padx=16)
        tk.Checkbutton(w,text='Tắt cảnh báo Alert Rules trong thời gian bảo trì',variable=sup).pack(anchor='w',padx=16,pady=14)
        def save():
            if not name.get().strip():messagebox.showwarning('Bảo trì','Nhập tên lịch.',parent=w);return
            sdt=_parse_dt(start.get().strip());edt=_parse_dt(end.get().strip())
            if not sdt or not edt or edt<=sdt:messagebox.showwarning('Bảo trì','Thời gian không hợp lệ hoặc kết thúc phải sau bắt đầu.',parent=w);return
            sid,host=mapping.get(target.get(),(None,None))
            if scope.get()!='All' and not target.get():messagebox.showwarning('Bảo trì','Chọn đối tượng.',parent=w);return
            c=_connect();c.execute('''INSERT INTO maintenance_windows(name,scope_type,scope_id,host,start_at,end_at,suppress_alerts,enabled,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)''',(name.get().strip(),scope.get(),sid,host,start.get().strip(),end.get().strip(),1 if sup.get() else 0,1,note.get().strip(),_now(),_now()));c.commit();c.close();self.activity('Đã thêm lịch bảo trì: '+name.get().strip());w.destroy();self.refresh()
        tk.Button(w,text='Lưu lịch',command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(pady=8)
    def toggle(self):
        i=self._selected()
        if not i:return
        c=_connect();r=c.execute('SELECT enabled FROM maintenance_windows WHERE id=?',(i,)).fetchone();c.execute('UPDATE maintenance_windows SET enabled=?,updated_at=? WHERE id=?',(0 if r and r['enabled'] else 1,_now(),i));c.commit();c.close();self.refresh()
    def delete(self):
        i=self._selected()
        if not i:return
        if not messagebox.askyesno('Xóa lịch','Xóa lịch bảo trì đã chọn?'):return
        c=_connect();c.execute('DELETE FROM maintenance_windows WHERE id=?',(i,));c.commit();c.close();self.refresh()


__all__=['ensure_v8_tables','active_maintenance_for_host','OrganizationPage','MaintenanceWindowsPage']
