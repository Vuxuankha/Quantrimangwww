from __future__ import annotations
from modules.ui_ux_config import PALETTE as UI_COLORS

from datetime import datetime
try:
    import tkinter as tk
except (ImportError, ModuleNotFoundError):
    tk = None
try:
    from tkinter import ttk, messagebox
except (ImportError, ModuleNotFoundError):
    ttk = messagebox = None

from modules.advanced_pages import _connect, _now
from modules.nms_v9 import ensure_v9_tables


def ensure_v10_tables():
    ensure_v9_tables()
    c = _connect()
    try:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS device_dependencies(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          parent_device_id INTEGER NOT NULL,
          child_device_id INTEGER NOT NULL,
          relation_type TEXT NOT NULL DEFAULT 'Network',
          criticality TEXT NOT NULL DEFAULT 'Normal',
          enabled INTEGER NOT NULL DEFAULT 1,
          note TEXT,
          created_at TEXT,
          updated_at TEXT,
          UNIQUE(parent_device_id, child_device_id)
        );
        CREATE TABLE IF NOT EXISTS alert_suppressions(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          alert_id INTEGER NOT NULL,
          child_host TEXT,
          root_host TEXT,
          reason TEXT,
          active INTEGER NOT NULL DEFAULT 1,
          first_seen TEXT,
          last_seen TEXT,
          UNIQUE(alert_id, root_host)
        );
        CREATE TABLE IF NOT EXISTS root_cause_events(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          root_host TEXT NOT NULL,
          title TEXT,
          severity TEXT DEFAULT 'Warning',
          status TEXT DEFAULT 'Open',
          impacted_count INTEGER DEFAULT 0,
          first_seen TEXT,
          last_seen TEXT,
          resolved_at TEXT,
          note TEXT
        );
        CREATE TABLE IF NOT EXISTS managed_services(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE,
          description TEXT,
          owner TEXT,
          target_status TEXT DEFAULT 'Operational',
          enabled INTEGER NOT NULL DEFAULT 1,
          created_at TEXT,
          updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS service_members(
          service_id INTEGER NOT NULL,
          device_id INTEGER NOT NULL,
          required INTEGER NOT NULL DEFAULT 1,
          note TEXT,
          PRIMARY KEY(service_id, device_id)
        );
        ''')
        c.commit()
    finally:
        c.close()


def _device_label_expr(alias=''):
    p = (alias + '.') if alias else ''
    return f"COALESCE(NULLIF({p}name,''),NULLIF({p}device_name,''),'Thiết bị #'||{p}id)"


def _device_ip_expr(alias=''):
    p = (alias + '.') if alias else ''
    return f"COALESCE(NULLIF({p}ip,''),NULLIF({p}ip_address,''),'')"


def _devices():
    c = _connect()
    try:
        return [dict(r) for r in c.execute(
            f"SELECT id,{_device_label_expr()} AS label,{_device_ip_expr()} AS host,COALESCE(status,'Unknown') AS status FROM network_devices ORDER BY label"
        ).fetchall()]
    finally:
        c.close()


def _open_alert_rows():
    c = _connect()
    try:
        return [dict(r) for r in c.execute('''
            SELECT id,COALESCE(NULLIF(ip,''),NULLIF(ip_address,''),'') AS host,
                   COALESCE(alert_type,'Alert') AS alert_type,COALESCE(message,'') AS message,
                   COALESCE(severity,'Warning') AS severity,COALESCE(status,'Open') AS status,
                   COALESCE(resolved,0) AS resolved,created_at
            FROM alerts
            WHERE COALESCE(resolved,0)=0 AND COALESCE(status,'Open') NOT IN ('Closed','Resolved')
        ''').fetchall() if r['host']]
    finally:
        c.close()


def _is_connectivity_alert(row):
    s = (' '.join(str(row.get(k, '')) for k in ('alert_type', 'message'))).lower()
    return any(x in s for x in ('offline', 'down', 'ping', 'mất kết nối', 'không phản hồi', 'unreachable'))


def _dependency_graph():
    c = _connect()
    try:
        rows = c.execute(f'''
            SELECT dd.*, {_device_ip_expr('p')} AS parent_host,{_device_label_expr('p')} AS parent_name,
                   {_device_ip_expr('ch')} AS child_host,{_device_label_expr('ch')} AS child_name
            FROM device_dependencies dd
            JOIN network_devices p ON p.id=dd.parent_device_id
            JOIN network_devices ch ON ch.id=dd.child_device_id
            WHERE dd.enabled=1
        ''').fetchall()
        return [dict(r) for r in rows]
    finally:
        c.close()


def _descendants(root_host, links):
    by_parent = {}
    for r in links:
        if r['parent_host'] and r['child_host']:
            by_parent.setdefault(r['parent_host'], set()).add(r['child_host'])
    out, stack = set(), list(by_parent.get(root_host, set()))
    while stack:
        h = stack.pop()
        if h in out or h == root_host:
            continue
        out.add(h)
        stack.extend(by_parent.get(h, set()))
    return out


def analyze_root_causes():
    """Correlate connectivity alerts using dependency graph.

    Returns dict with roots/suppressed/resolved. Child alerts remain visible but are
    tagged in alert_suppressions so operators can distinguish symptoms from likely root cause.
    """
    ensure_v10_tables()
    alerts = [a for a in _open_alert_rows() if _is_connectivity_alert(a)]
    links = _dependency_graph()
    alert_hosts = {a['host'] for a in alerts}
    parents_of = {}
    for l in links:
        parents_of.setdefault(l['child_host'], set()).add(l['parent_host'])

    def alerted_ancestor(host):
        seen, stack = set(), list(parents_of.get(host, set()))
        while stack:
            p = stack.pop()
            if p in seen:
                continue
            seen.add(p)
            if p in alert_hosts:
                return p
            stack.extend(parents_of.get(p, set()))
        return None

    suppressions = []
    roots = set()
    for a in alerts:
        root = alerted_ancestor(a['host'])
        if root:
            suppressions.append((a, root))
            roots.add(root)
        else:
            roots.add(a['host'])

    c = _connect()
    try:
        now = _now()
        # Mark all active suppressions stale first; active ones are reactivated below.
        c.execute("UPDATE alert_suppressions SET active=0")
        for a, root in suppressions:
            c.execute('''INSERT INTO alert_suppressions(alert_id,child_host,root_host,reason,active,first_seen,last_seen)
                         VALUES(?,?,?,?,1,?,?)
                         ON CONFLICT(alert_id,root_host) DO UPDATE SET active=1,last_seen=excluded.last_seen,reason=excluded.reason''',
                      (a['id'], a['host'], root, f'Phụ thuộc thiết bị {root} đang có cảnh báo mất kết nối', now, now))

        # Close root-cause events whose root no longer has an open connectivity alert.
        open_events = c.execute("SELECT id,root_host FROM root_cause_events WHERE status='Open'").fetchall()
        for e in open_events:
            if e['root_host'] not in roots:
                c.execute("UPDATE root_cause_events SET status='Resolved',resolved_at=?,last_seen=? WHERE id=?", (now, now, e['id']))

        for root in roots:
            impacted = len([1 for a, r in suppressions if r == root])
            severities = [a['severity'] for a in alerts if a['host'] == root]
            rank = {'Info': 1, 'Warning': 2, 'Critical': 3}
            severity = max(severities or ['Warning'], key=lambda x: rank.get(str(x), 2))
            current = c.execute("SELECT id FROM root_cause_events WHERE root_host=? AND status='Open' ORDER BY id DESC LIMIT 1", (root,)).fetchone()
            if current:
                c.execute("UPDATE root_cause_events SET impacted_count=?,severity=?,last_seen=? WHERE id=?", (impacted, severity, now, current['id']))
            else:
                c.execute('''INSERT INTO root_cause_events(root_host,title,severity,status,impacted_count,first_seen,last_seen)
                             VALUES(?,?,'Warning','Open',?,?,?)''',
                          (root, f'Khả năng sự cố gốc tại {root}', impacted, now, now))
                # overwrite default warning with detected severity
                c.execute("UPDATE root_cause_events SET severity=? WHERE id=last_insert_rowid()", (severity,))
        c.commit()
    finally:
        c.close()
    return {'roots': len(roots), 'suppressed': len(suppressions), 'open_alerts': len(alerts)}


class RootCauseEngine:
    def __init__(self, root, activity_callback=None, interval_ms=60000):
        self.root = root
        self.activity = activity_callback or (lambda m: None)
        self.interval_ms = max(15000, int(interval_ms))
        self.job = None
        self.running = True
        self._schedule(8000)

    def _schedule(self, delay=None):
        if self.running:
            self.job = self.root.after(delay if delay is not None else self.interval_ms, self._tick)

    def _tick(self):
        if not self.running:
            return
        try:
            result = analyze_root_causes()
            if result['suppressed']:
                self.activity(f"Tương quan cảnh báo: {result['roots']} nguyên nhân gốc, {result['suppressed']} cảnh báo phụ thuộc")
        except Exception as e:
            self.activity(f"Lỗi tương quan cảnh báo: {e}")
        self._schedule()

    def stop(self):
        self.running = False
        if self.job:
            try:
                self.root.after_cancel(self.job)
            except Exception:
                pass
            self.job = None


class DeviceDependenciesPage:
    def __init__(self, parent, activity_callback=None, role='Viewer'):
        ensure_v10_tables(); self.parent=parent; self.activity=activity_callback or (lambda m:None); self.role=role
        self._build(); self.refresh()

    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['background']);ctl.pack(fill='x',padx=25,pady=(0,8))
        self.add_btn=tk.Button(ctl,text='Thêm phụ thuộc',command=self.add,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat');self.add_btn.pack(side='left')
        self.del_btn=tk.Button(ctl,text='Xóa',command=self.delete);self.del_btn.pack(side='left',padx=5)
        self.import_btn=tk.Button(ctl,text='Nhập từ Sơ đồ mạng',command=self.import_links);self.import_btn.pack(side='left',padx=5)
        tk.Button(ctl,text='Làm mới',command=self.refresh).pack(side='left',padx=5)
        if self.role=='Viewer':
            for b in (self.add_btn,self.del_btn,self.import_btn): b.configure(state='disabled')
        cols=('id','parent','p_ip','child','c_ip','type','critical','enabled','note')
        self.t=ttk.Treeview(self.parent,columns=cols,show='headings')
        specs=[('id','ID',50),('parent','Thiết bị cha',170),('p_ip','IP cha',120),('child','Thiết bị con',170),('c_ip','IP con',120),('type','Loại',90),('critical','Mức quan trọng',105),('enabled','Bật',55),('note','Ghi chú',220)]
        for c,h,w in specs:self.t.heading(c,text=h);self.t.column(c,width=w,anchor='w')
        self.t.pack(fill='both',expand=True,padx=25,pady=(0,12))
        tk.Label(self.parent,text='Thiết bị cha là thiết bị mà thiết bị con phụ thuộc để kết nối/dịch vụ hoạt động. Dữ liệu này được dùng để chống “bão cảnh báo” và phân tích nguyên nhân gốc.',bg=UI_COLORS['background'],fg=UI_COLORS['muted'],wraplength=1000,justify='left').pack(anchor='w',padx=25,pady=(0,12))

    def refresh(self):
        for x in self.t.get_children():self.t.delete(x)
        c=_connect()
        try:
            rows=c.execute(f'''SELECT dd.id,{_device_label_expr('p')} parent,{_device_ip_expr('p')} p_ip,
                {_device_label_expr('ch')} child,{_device_ip_expr('ch')} c_ip,dd.relation_type,dd.criticality,dd.enabled,dd.note
                FROM device_dependencies dd JOIN network_devices p ON p.id=dd.parent_device_id JOIN network_devices ch ON ch.id=dd.child_device_id ORDER BY dd.id DESC''').fetchall()
        finally:c.close()
        for r in rows:self.t.insert('','end',iid=str(r['id']),values=(r['id'],r['parent'],r['p_ip'],r['child'],r['c_ip'],r['relation_type'],r['criticality'],'Có' if r['enabled'] else 'Không',r['note'] or ''))

    def add(self):
        ds=_devices()
        if len(ds)<2:messagebox.showinfo('Phụ thuộc thiết bị','Cần ít nhất 2 thiết bị trong danh sách.');return
        w=tk.Toplevel(self.parent);w.title('Thêm phụ thuộc thiết bị');w.geometry('520x360');w.transient(self.parent.winfo_toplevel());w.grab_set()
        labels=[f"#{d['id']} | {d['label']} | {d['host']}" for d in ds]; by_label={x:d for x,d in zip(labels,ds)}
        p=tk.StringVar(value=labels[0]);ch=tk.StringVar(value=labels[1]);typ=tk.StringVar(value='Network');crit=tk.StringVar(value='Normal');note=tk.StringVar()
        fields=[('Thiết bị cha',p,labels),('Thiết bị con',ch,labels),('Loại phụ thuộc',typ,['Network','Power','Service','WAN','Other']),('Mức quan trọng',crit,['Low','Normal','High','Critical']),('Ghi chú',note,None)]
        for i,(lab,var,vals) in enumerate(fields):
            tk.Label(w,text=lab).grid(row=i,column=0,sticky='w',padx=12,pady=9)
            wd=ttk.Combobox(w,textvariable=var,values=vals,state='readonly',width=38) if vals else tk.Entry(w,textvariable=var,width=41)
            wd.grid(row=i,column=1,sticky='ew',padx=8,pady=9)
        w.grid_columnconfigure(1,weight=1)
        def save():
            pd,cd=by_label[p.get()],by_label[ch.get()]
            if pd['id']==cd['id']:messagebox.showwarning('Phụ thuộc thiết bị','Thiết bị cha và con không được giống nhau.',parent=w);return
            c=_connect()
            try:
                c.execute('''INSERT INTO device_dependencies(parent_device_id,child_device_id,relation_type,criticality,enabled,note,created_at,updated_at)
                    VALUES(?,?,?,?,1,?,?,?) ON CONFLICT(parent_device_id,child_device_id) DO UPDATE SET relation_type=excluded.relation_type,criticality=excluded.criticality,enabled=1,note=excluded.note,updated_at=excluded.updated_at''',(pd['id'],cd['id'],typ.get(),crit.get(),note.get().strip(),_now(),_now()));c.commit()
            finally:c.close()
            self.activity(f"Đã thêm phụ thuộc {pd['label']} -> {cd['label']}");w.destroy();self.refresh()
        tk.Button(w,text='Lưu',command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text']).grid(row=len(fields),column=1,sticky='e',padx=8,pady=16)

    def delete(self):
        s=self.t.selection()
        if not s:return
        if not messagebox.askyesno('Phụ thuộc thiết bị','Xóa quan hệ phụ thuộc đã chọn?'):return
        c=_connect();c.execute('DELETE FROM device_dependencies WHERE id=?',(int(s[0]),));c.commit();c.close();self.refresh();self.activity('Đã xóa quan hệ phụ thuộc')

    def import_links(self):
        c=_connect();count=0
        try:
            rows=c.execute('SELECT source_device_id,target_device_id,label FROM device_links').fetchall()
            for r in rows:
                if not r['source_device_id'] or not r['target_device_id'] or r['source_device_id']==r['target_device_id']:continue
                cur=c.execute('''INSERT OR IGNORE INTO device_dependencies(parent_device_id,child_device_id,relation_type,criticality,enabled,note,created_at,updated_at)
                    VALUES(?,?, 'Network','Normal',1,?,?,?)''',(r['source_device_id'],r['target_device_id'],'Nhập từ Sơ đồ mạng: '+(r['label'] or ''),_now(),_now()))
                count += max(0,cur.rowcount)
            c.commit()
        finally:c.close()
        self.refresh();self.activity(f'Đã nhập {count} quan hệ phụ thuộc từ Sơ đồ mạng');messagebox.showinfo('Phụ thuộc thiết bị',f'Đã thêm {count} quan hệ mới.')


class RootCauseAnalysisPage:
    def __init__(self,parent,activity_callback=None):
        ensure_v10_tables();self.parent=parent;self.activity=activity_callback or (lambda m:None);self._build();self.refresh()
    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['background']);ctl.pack(fill='x',padx=25,pady=(0,8))
        tk.Button(ctl,text='Phân tích ngay',command=self.analyze,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left')
        tk.Button(ctl,text='Làm mới',command=self.refresh).pack(side='left',padx=5)
        self.summary=tk.StringVar(value='Chưa phân tích');tk.Label(ctl,textvariable=self.summary,bg=UI_COLORS['background'],fg=UI_COLORS['text']).pack(side='left',padx=14)
        pan=ttk.Panedwindow(self.parent,orient='vertical');pan.pack(fill='both',expand=True,padx=25,pady=(0,12))
        top=tk.Frame(pan,bg=UI_COLORS['surface']);bot=tk.Frame(pan,bg=UI_COLORS['surface']);pan.add(top,weight=1);pan.add(bot,weight=1)
        cols=('id','root','severity','impact','status','first','last')
        self.events=ttk.Treeview(top,columns=cols,show='headings',height=8)
        for c,h,w in [('id','ID',50),('root','Nguyên nhân gốc',170),('severity','Mức độ',90),('impact','Thiết bị ảnh hưởng',120),('status','Trạng thái',100),('first','Bắt đầu',150),('last','Gần nhất',150)]:self.events.heading(c,text=h);self.events.column(c,width=w,anchor='w')
        self.events.pack(fill='both',expand=True,padx=8,pady=8);self.events.bind('<<TreeviewSelect>>',lambda e:self.show_detail())
        cols2=('alert','child','root','reason','last')
        self.supp=ttk.Treeview(bot,columns=cols2,show='headings')
        for c,h,w in [('alert','Alert ID',70),('child','Cảnh báo phụ thuộc',150),('root','Nguyên nhân gốc',150),('reason','Lý do',360),('last','Cập nhật',150)]:self.supp.heading(c,text=h);self.supp.column(c,width=w,anchor='w')
        self.supp.pack(fill='both',expand=True,padx=8,pady=8)
    def analyze(self):
        r=analyze_root_causes();self.summary.set(f"{r['roots']} nguyên nhân gốc • {r['suppressed']} cảnh báo phụ thuộc • {r['open_alerts']} cảnh báo kết nối mở");self.activity('Đã phân tích nguyên nhân gốc');self.refresh(keep_summary=True)
    def refresh(self,keep_summary=False):
        for t in (self.events,self.supp):
            for x in t.get_children():t.delete(x)
        c=_connect()
        try:
            events=c.execute("SELECT * FROM root_cause_events ORDER BY CASE status WHEN 'Open' THEN 0 ELSE 1 END,id DESC LIMIT 300").fetchall()
            sups=c.execute("SELECT * FROM alert_suppressions WHERE active=1 ORDER BY id DESC LIMIT 500").fetchall()
        finally:c.close()
        for r in events:self.events.insert('','end',iid=str(r['id']),values=(r['id'],r['root_host'],r['severity'],r['impacted_count'],r['status'],r['first_seen'],r['last_seen']))
        for r in sups:self.supp.insert('','end',values=(r['alert_id'],r['child_host'],r['root_host'],r['reason'],r['last_seen']))
        if not keep_summary:self.summary.set(f"{sum(1 for r in events if r['status']=='Open')} sự cố gốc đang mở • {len(sups)} cảnh báo phụ thuộc đang được tương quan")
    def show_detail(self):
        pass


def service_status(service_id):
    c=_connect()
    try:
        rows=c.execute(f'''SELECT sm.required,{_device_ip_expr('d')} host,COALESCE(d.status,'Unknown') device_status
            FROM service_members sm JOIN network_devices d ON d.id=sm.device_id WHERE sm.service_id=?''',(service_id,)).fetchall()
        if not rows:return {'status':'Chưa cấu hình','total':0,'down':0,'required_down':0}
        open_roots={r['root_host'] for r in c.execute("SELECT root_host FROM root_cause_events WHERE status='Open'").fetchall()}
        down=required_down=0
        for r in rows:
            bad=(str(r['device_status']).lower()=='offline') or (r['host'] in open_roots)
            if bad:
                down+=1
                if r['required']:required_down+=1
        if required_down:status='Gián đoạn'
        elif down:status='Suy giảm'
        else:status='Hoạt động'
        return {'status':status,'total':len(rows),'down':down,'required_down':required_down}
    finally:c.close()


class ServiceImpactPage:
    def __init__(self,parent,activity_callback=None,role='Viewer'):
        ensure_v10_tables();self.parent=parent;self.activity=activity_callback or (lambda m:None);self.role=role;self._build();self.refresh()
    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['background']);ctl.pack(fill='x',padx=25,pady=(0,8))
        self.add_btn=tk.Button(ctl,text='Thêm dịch vụ',command=self.add_service,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat');self.add_btn.pack(side='left')
        self.member_btn=tk.Button(ctl,text='Quản lý thành viên',command=self.manage_members);self.member_btn.pack(side='left',padx=5)
        self.del_btn=tk.Button(ctl,text='Xóa',command=self.delete);self.del_btn.pack(side='left',padx=5)
        tk.Button(ctl,text='Đánh giá trạng thái',command=self.refresh).pack(side='left',padx=5)
        if self.role=='Viewer':
            for b in (self.add_btn,self.member_btn,self.del_btn):b.configure(state='disabled')
        cols=('id','name','owner','status','members','down','description')
        self.t=ttk.Treeview(self.parent,columns=cols,show='headings')
        for c,h,w in [('id','ID',50),('name','Dịch vụ',180),('owner','Phụ trách',130),('status','Trạng thái',110),('members','Thiết bị',80),('down','Ảnh hưởng',80),('description','Mô tả',300)]:self.t.heading(c,text=h);self.t.column(c,width=w,anchor='w')
        self.t.pack(fill='both',expand=True,padx=25,pady=(0,12))
        tk.Label(self.parent,text='Thiết bị “Bắt buộc” bị Offline hoặc là nguyên nhân gốc sẽ làm dịch vụ chuyển sang Gián đoạn. Thiết bị không bắt buộc bị lỗi sẽ làm dịch vụ Suy giảm.',bg=UI_COLORS['background'],fg=UI_COLORS['muted'],wraplength=1000,justify='left').pack(anchor='w',padx=25,pady=(0,12))
    def refresh(self):
        for x in self.t.get_children():self.t.delete(x)
        c=_connect();rows=c.execute('SELECT * FROM managed_services ORDER BY name').fetchall();c.close()
        for r in rows:
            s=service_status(r['id']);self.t.insert('','end',iid=str(r['id']),values=(r['id'],r['name'],r['owner'] or '-',s['status'],s['total'],s['down'],r['description'] or ''))
    def _id(self):
        s=self.t.selection();return int(s[0]) if s else None
    def add_service(self):
        w=tk.Toplevel(self.parent);w.title('Thêm dịch vụ');w.geometry('470x300');w.transient(self.parent.winfo_toplevel());w.grab_set();name=tk.StringVar();owner=tk.StringVar();desc=tk.StringVar()
        for i,(lab,var) in enumerate([('Tên dịch vụ',name),('Người/nhóm phụ trách',owner),('Mô tả',desc)]):tk.Label(w,text=lab).grid(row=i,column=0,sticky='w',padx=12,pady=10);tk.Entry(w,textvariable=var,width=34).grid(row=i,column=1,sticky='ew',padx=8,pady=10)
        w.grid_columnconfigure(1,weight=1)
        def save():
            if not name.get().strip():messagebox.showwarning('Dịch vụ','Nhập tên dịch vụ.',parent=w);return
            c=_connect()
            try:c.execute('INSERT INTO managed_services(name,description,owner,enabled,created_at,updated_at) VALUES(?,?,?,1,?,?)',(name.get().strip(),desc.get().strip(),owner.get().strip(),_now(),_now()));c.commit()
            except Exception as e:messagebox.showerror('Dịch vụ',str(e),parent=w);return
            finally:c.close()
            self.activity('Đã thêm dịch vụ: '+name.get().strip());w.destroy();self.refresh()
        tk.Button(w,text='Lưu',command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text']).grid(row=3,column=1,sticky='e',padx=8,pady=18)
    def delete(self):
        i=self._id()
        if not i:return
        if not messagebox.askyesno('Dịch vụ','Xóa dịch vụ đã chọn?'):return
        c=_connect();c.execute('DELETE FROM service_members WHERE service_id=?',(i,));c.execute('DELETE FROM managed_services WHERE id=?',(i,));c.commit();c.close();self.refresh()
    def manage_members(self):
        sid=self._id()
        if not sid:messagebox.showinfo('Dịch vụ','Chọn một dịch vụ trước.');return
        ds=_devices();c=_connect();existing={r['device_id']:r['required'] for r in c.execute('SELECT device_id,required FROM service_members WHERE service_id=?',(sid,)).fetchall()};c.close()
        w=tk.Toplevel(self.parent);w.title('Thành viên dịch vụ');w.geometry('650x520');w.transient(self.parent.winfo_toplevel());w.grab_set()
        tree=ttk.Treeview(w,columns=('id','name','ip','required'),show='headings',selectmode='extended')
        for c,h,ww in [('id','ID',55),('name','Thiết bị',220),('ip','IP',140),('required','Bắt buộc',90)]:tree.heading(c,text=h);tree.column(c,width=ww,anchor='w')
        tree.pack(fill='both',expand=True,padx=12,pady=12)
        for d in ds:
            iid=str(d['id']);tree.insert('','end',iid=iid,values=(d['id'],d['label'],d['host'],'Có' if existing.get(d['id']) else 'Không'))
            if d['id'] in existing:tree.selection_add(iid)
        req=tk.BooleanVar(value=True);tk.Checkbutton(w,text='Các thiết bị đang chọn là thành viên bắt buộc',variable=req).pack(anchor='w',padx=12)
        def save():
            selected={int(x) for x in tree.selection()};c=_connect();c.execute('DELETE FROM service_members WHERE service_id=?',(sid,))
            for did in selected:c.execute('INSERT INTO service_members(service_id,device_id,required) VALUES(?,?,?)',(sid,did,1 if req.get() else 0))
            c.commit();c.close();self.activity(f'Đã cập nhật {len(selected)} thành viên dịch vụ');w.destroy();self.refresh()
        tk.Button(w,text='Lưu thành viên',command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text']).pack(anchor='e',padx=12,pady=12)
