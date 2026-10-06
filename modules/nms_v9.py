from modules.ui_ux_config import PALETTE as UI_COLORS
import csv
from datetime import datetime, timedelta
try:
    import tkinter as tk
except (ImportError, ModuleNotFoundError):
    tk = None
try:
    from tkinter import ttk, messagebox, filedialog
except (ImportError, ModuleNotFoundError):
    ttk = messagebox = filedialog = None

from modules.advanced_pages import _connect, _now
from modules.nms_v8 import ensure_v8_tables


def ensure_v9_tables():
    ensure_v8_tables()
    c = _connect()
    try:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS sla_policies(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          scope_type TEXT NOT NULL DEFAULT 'Device',
          scope_id INTEGER,
          host TEXT,
          target_percent REAL NOT NULL DEFAULT 99.0,
          period_days INTEGER NOT NULL DEFAULT 30,
          enabled INTEGER NOT NULL DEFAULT 1,
          note TEXT,
          created_at TEXT,
          updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS incidents(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          host TEXT,
          title TEXT,
          severity TEXT DEFAULT 'Warning',
          status TEXT DEFAULT 'Open',
          first_seen TEXT,
          last_seen TEXT,
          alert_count INTEGER DEFAULT 0,
          ack_by TEXT,
          resolved_at TEXT,
          note TEXT
        );
        CREATE TABLE IF NOT EXISTS incident_alerts(
          incident_id INTEGER NOT NULL,
          alert_id INTEGER NOT NULL UNIQUE,
          linked_at TEXT,
          PRIMARY KEY(incident_id, alert_id)
        );
        ''')
        c.commit()
    finally:
        c.close()


def _parse_dt(value):
    if isinstance(value, datetime):
        return value
    try:
        return datetime.strptime(str(value), '%Y-%m-%d %H:%M:%S')
    except Exception:
        return None


def _scope_hosts(scope_type, scope_id=None, host=''):
    c = _connect()
    try:
        if scope_type == 'All':
            rows = c.execute("SELECT DISTINCT ip FROM network_devices WHERE ip IS NOT NULL AND TRIM(ip)<>''").fetchall()
        elif scope_type == 'Device':
            if host:
                return [host]
            rows = c.execute("SELECT ip FROM network_devices WHERE id=? AND ip IS NOT NULL", (scope_id,)).fetchall()
        elif scope_type == 'Site':
            rows = c.execute("SELECT d.ip FROM network_devices d JOIN device_organization o ON o.device_id=d.id WHERE o.site_id=? AND d.ip IS NOT NULL AND TRIM(d.ip)<>''", (scope_id,)).fetchall()
        elif scope_type == 'Group':
            rows = c.execute("SELECT d.ip FROM network_devices d JOIN device_organization o ON o.device_id=d.id WHERE o.group_id=? AND d.ip IS NOT NULL AND TRIM(d.ip)<>''", (scope_id,)).fetchall()
        else:
            rows = []
        return [r['ip'] for r in rows if r['ip']]
    finally:
        c.close()


def _maintenance_match(host, at_time):
    """Historical maintenance check used by SLA calculation."""
    at_time = _parse_dt(at_time)
    if not at_time:
        return False
    c = _connect()
    try:
        dev = c.execute('''SELECT d.id,o.site_id,o.group_id FROM network_devices d
                           LEFT JOIN device_organization o ON o.device_id=d.id WHERE d.ip=? LIMIT 1''', (host,)).fetchone()
        rows = c.execute('SELECT * FROM maintenance_windows WHERE enabled=1 AND suppress_alerts=1').fetchall()
        for r in rows:
            st, en = _parse_dt(r['start_at']), _parse_dt(r['end_at'])
            if not st or not en or not (st <= at_time <= en):
                continue
            scope = r['scope_type']
            if scope == 'All':
                return True
            if scope == 'Device' and ((r['host'] or '').strip() == host or (dev and r['scope_id'] == dev['id'])):
                return True
            if scope == 'Site' and dev and r['scope_id'] == dev['site_id']:
                return True
            if scope == 'Group' and dev and r['scope_id'] == dev['group_id']:
                return True
        return False
    finally:
        c.close()


def calculate_availability(host, days=30, exclude_maintenance=True):
    cutoff = (datetime.now() - timedelta(days=max(1, int(days)))).strftime('%Y-%m-%d %H:%M:%S')
    c = _connect()
    try:
        rows = c.execute('''SELECT packet_loss,created_at FROM health_samples
                            WHERE host=? AND created_at>=? AND packet_loss IS NOT NULL ORDER BY id''', (host, cutoff)).fetchall()
    finally:
        c.close()
    usable = []
    excluded = 0
    for r in rows:
        if exclude_maintenance and _maintenance_match(host, r['created_at']):
            excluded += 1
            continue
        usable.append(r)
    total = len(usable)
    if not total:
        return {'host': host, 'availability': None, 'samples': 0, 'good': 0, 'excluded': excluded}
    good = sum(1 for r in usable if float(r['packet_loss'] or 0) < 100.0)
    return {'host': host, 'availability': good * 100.0 / total, 'samples': total, 'good': good, 'excluded': excluded}


def sync_incidents(window_minutes=15):
    """Group unmapped alerts into host incidents and auto-resolve when all linked alerts close."""
    ensure_v9_tables()
    c = _connect()
    created = linked = resolved = 0
    try:
        alerts = c.execute('''SELECT a.* FROM alerts a LEFT JOIN incident_alerts ia ON ia.alert_id=a.id
                              WHERE ia.alert_id IS NULL ORDER BY a.id''').fetchall()
        window = timedelta(minutes=max(1, int(window_minutes)))
        for a in alerts:
            host = (a['ip'] or 'Không xác định').strip() or 'Không xác định'
            at = _parse_dt(a['created_at']) or datetime.now()
            row = c.execute('''SELECT * FROM incidents WHERE host=? AND status IN ('Open','Acknowledged')
                               ORDER BY id DESC LIMIT 1''', (host,)).fetchone()
            incident_id = None
            if row:
                last = _parse_dt(row['last_seen']) or at
                if abs(at - last) <= window:
                    incident_id = row['id']
            if incident_id is None:
                title = f'Sự cố trên {host}'
                sev = a['severity'] if 'severity' in a.keys() and a['severity'] else 'Warning'
                cur = c.execute('''INSERT INTO incidents(host,title,severity,status,first_seen,last_seen,alert_count)
                                   VALUES(?,?,?,'Open',?,?,0)''', (host, title, sev, a['created_at'] or _now(), a['created_at'] or _now()))
                incident_id = cur.lastrowid
                created += 1
            c.execute('INSERT OR IGNORE INTO incident_alerts(incident_id,alert_id,linked_at) VALUES(?,?,?)', (incident_id, a['id'], _now()))
            if c.execute('SELECT changes()').fetchone()[0]:
                linked += 1
                sev = a['severity'] if 'severity' in a.keys() and a['severity'] else 'Warning'
                # Critical > Warning > Info
                rank = {'Info': 1, 'Warning': 2, 'Critical': 3}
                cursev = c.execute('SELECT severity FROM incidents WHERE id=?', (incident_id,)).fetchone()['severity']
                newsev = sev if rank.get(sev, 2) > rank.get(cursev, 2) else cursev
                c.execute('''UPDATE incidents SET last_seen=?, alert_count=alert_count+1, severity=? WHERE id=?''',
                          (a['created_at'] or _now(), newsev, incident_id))
        active = c.execute("SELECT id FROM incidents WHERE status IN ('Open','Acknowledged')").fetchall()
        for inc in active:
            open_count = c.execute('''SELECT COUNT(*) n FROM incident_alerts ia JOIN alerts a ON a.id=ia.alert_id
                                      WHERE ia.incident_id=? AND COALESCE(a.status,'Open') NOT IN ('Closed','Resolved')''', (inc['id'],)).fetchone()['n']
            if open_count == 0:
                c.execute("UPDATE incidents SET status='Resolved',resolved_at=? WHERE id=?", (_now(), inc['id']))
                resolved += 1
        c.commit()
    finally:
        c.close()
    return created, linked, resolved


def capacity_summary(host, days=7):
    cutoff = (datetime.now() - timedelta(days=max(1, int(days)))).strftime('%Y-%m-%d %H:%M:%S')
    c = _connect()
    try:
        rows = c.execute('''SELECT cpu,memory,latency_ms,packet_loss,created_at FROM health_samples
                            WHERE host=? AND created_at>=? ORDER BY id''', (host, cutoff)).fetchall()
        errors = c.execute('''SELECT SUM(COALESCE(in_errors,0)+COALESCE(out_errors,0)) e,
                                     SUM(COALESCE(in_discards,0)+COALESCE(out_discards,0)) d,
                                     COUNT(*) n FROM interface_samples WHERE host=? AND created_at>=?''', (host, cutoff)).fetchone()
    finally:
        c.close()
    def stats(key):
        vals = [float(r[key]) for r in rows if r[key] is not None]
        if not vals:
            return None, None, 'Chưa đủ dữ liệu'
        avg = sum(vals) / len(vals); mx = max(vals)
        mid = max(1, len(vals)//2)
        first = vals[:mid]; second = vals[mid:]
        if not second:
            trend = 'Ổn định'
        else:
            a1 = sum(first)/len(first); a2 = sum(second)/len(second)
            delta = a2-a1
            threshold = max(1.0, abs(a1)*0.1)
            trend = 'Tăng' if delta > threshold else 'Giảm' if delta < -threshold else 'Ổn định'
        return avg, mx, trend
    return {
        'CPU %': stats('cpu'), 'RAM %': stats('memory'), 'Độ trễ ms': stats('latency_ms'),
        'Mất gói %': stats('packet_loss'), 'Lỗi cổng': (float(errors['e'] or 0), None, f"{int(errors['n'] or 0)} mẫu"),
        'Discard cổng': (float(errors['d'] or 0), None, f"{int(errors['n'] or 0)} mẫu"),
    }


class SLAAvailabilityPage:
    def __init__(self, parent, activity_callback=None, role='Viewer'):
        ensure_v9_tables(); self.parent=parent; self.activity=activity_callback or (lambda m:None); self.role=role
        self._build(); self.refresh_policies()
    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['background']);ctl.pack(fill='x',padx=25,pady=(0,8))
        self.add_btn=tk.Button(ctl,text='Thêm SLA',command=self.add_policy,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat');self.add_btn.pack(side='left')
        self.del_btn=tk.Button(ctl,text='Xóa',command=self.delete_policy);self.del_btn.pack(side='left',padx=5)
        tk.Button(ctl,text='Tính SLA',command=self.calculate).pack(side='left',padx=5)
        tk.Button(ctl,text='Xuất CSV',command=self.export_csv).pack(side='left',padx=5)
        if self.role=='Viewer': self.add_btn.configure(state='disabled'); self.del_btn.configure(state='disabled')
        pan=ttk.Panedwindow(self.parent,orient='vertical');pan.pack(fill='both',expand=True,padx=25,pady=(0,12))
        top=tk.Frame(pan,bg=UI_COLORS['surface']);bot=tk.Frame(pan,bg=UI_COLORS['surface']);pan.add(top,weight=1);pan.add(bot,weight=2)
        cols=('id','name','scope','target','days','enabled');self.policies=ttk.Treeview(top,columns=cols,show='headings',height=6)
        for c,h,w in [('id','ID',45),('name','Tên SLA',220),('scope','Phạm vi',220),('target','Mục tiêu',100),('days','Chu kỳ',80),('enabled','Bật',60)]:self.policies.heading(c,text=h);self.policies.column(c,width=w,anchor='w')
        self.policies.pack(fill='both',expand=True,padx=8,pady=8)
        cols2=('host','availability','target','samples','excluded','state');self.results=ttk.Treeview(bot,columns=cols2,show='headings')
        for c,h,w in [('host','Host',160),('availability','Sẵn sàng',110),('target','Mục tiêu',90),('samples','Mẫu',80),('excluded','Loại do bảo trì',110),('state','Trạng thái',140)]:self.results.heading(c,text=h);self.results.column(c,width=w,anchor='w')
        self.results.pack(fill='both',expand=True,padx=8,pady=8);self.last_rows=[]
    def refresh_policies(self):
        for x in self.policies.get_children(): self.policies.delete(x)
        c=_connect();rows=c.execute('SELECT * FROM sla_policies ORDER BY id DESC').fetchall();c.close()
        for r in rows:
            scope=r['scope_type']+(f" #{r['scope_id']}" if r['scope_id'] else '')+(f" {r['host']}" if r['host'] else '')
            self.policies.insert('','end',iid=str(r['id']),values=(r['id'],r['name'],scope,f"{r['target_percent']:.2f}%",r['period_days'],'Có' if r['enabled'] else 'Không'))
    def _selected_policy(self):
        s=self.policies.selection()
        if not s:return None
        c=_connect();r=c.execute('SELECT * FROM sla_policies WHERE id=?',(int(s[0]),)).fetchone();c.close();return dict(r) if r else None
    def add_policy(self):
        w=tk.Toplevel(self.parent);w.title('Thêm chính sách SLA');w.geometry('460x390');w.transient(self.parent.winfo_toplevel());w.grab_set()
        name=tk.StringVar();scope=tk.StringVar(value='All');scope_id=tk.StringVar();host=tk.StringVar();target=tk.StringVar(value='99.0');days=tk.StringVar(value='30');note=tk.StringVar()
        fields=[('Tên SLA',name,None),('Phạm vi',scope,['All','Device','Site','Group']),('Scope ID',scope_id,None),('Host (nếu Device)',host,None),('Mục tiêu %',target,None),('Chu kỳ ngày',days,None),('Ghi chú',note,None)]
        for i,(lab,var,vals) in enumerate(fields):
            tk.Label(w,text=lab).grid(row=i,column=0,sticky='w',padx=12,pady=8)
            widget=ttk.Combobox(w,textvariable=var,values=vals,state='readonly',width=28) if vals else tk.Entry(w,textvariable=var,width=31)
            widget.grid(row=i,column=1,padx=8,pady=8,sticky='ew')
        w.grid_columnconfigure(1,weight=1)
        def save():
            try:tar=float(target.get());period=int(days.get());sid=int(scope_id.get()) if scope_id.get().strip() else None
            except ValueError:messagebox.showerror('SLA','Mục tiêu/chu kỳ/Scope ID không hợp lệ.',parent=w);return
            if not name.get().strip():messagebox.showwarning('SLA','Nhập tên SLA.',parent=w);return
            c=_connect();c.execute('''INSERT INTO sla_policies(name,scope_type,scope_id,host,target_percent,period_days,enabled,note,created_at,updated_at)
                                     VALUES(?,?,?,?,?,?,1,?,?,?)''',(name.get().strip(),scope.get(),sid,host.get().strip(),tar,period,note.get().strip(),_now(),_now()));c.commit();c.close();self.activity('Đã thêm chính sách SLA: '+name.get().strip());w.destroy();self.refresh_policies()
        tk.Button(w,text='Lưu',command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text']).grid(row=len(fields),column=1,sticky='e',padx=8,pady=14)
    def delete_policy(self):
        p=self._selected_policy()
        if not p:return
        if not messagebox.askyesno('SLA',f"Xóa SLA {p['name']}?"):return
        c=_connect();c.execute('DELETE FROM sla_policies WHERE id=?',(p['id'],));c.commit();c.close();self.refresh_policies()
    def calculate(self):
        p=self._selected_policy()
        if not p:messagebox.showinfo('SLA','Chọn một SLA trước.');return
        hosts=_scope_hosts(p['scope_type'],p['scope_id'],p['host'] or '')
        self.last_rows=[]
        for x in self.results.get_children():self.results.delete(x)
        for h in hosts:
            r=calculate_availability(h,p['period_days'],True);av=r['availability'];state='Chưa đủ dữ liệu' if av is None else ('Đạt SLA' if av>=float(p['target_percent']) else 'Không đạt SLA')
            vals=(h,'--' if av is None else f'{av:.3f}%',f"{p['target_percent']:.3f}%",r['samples'],r['excluded'],state);self.results.insert('','end',values=vals);self.last_rows.append(vals)
        self.activity(f"Đã tính SLA {p['name']} cho {len(hosts)} thiết bị")
    def export_csv(self):
        if not self.last_rows:messagebox.showinfo('SLA','Chưa có kết quả để xuất.');return
        path=filedialog.asksaveasfilename(defaultextension='.csv',filetypes=[('CSV','*.csv')],title='Xuất báo cáo SLA')
        if not path:return
        with open(path,'w',newline='',encoding='utf-8-sig') as f:
            w=csv.writer(f);w.writerow(['Host','Sẵn sàng','Mục tiêu','Mẫu','Loại do bảo trì','Trạng thái']);w.writerows(self.last_rows)
        messagebox.showinfo('SLA','Đã xuất CSV.')


class IncidentCenterPage:
    def __init__(self,parent,activity_callback=None,role='Viewer',username=''):
        ensure_v9_tables();self.parent=parent;self.activity=activity_callback or (lambda m:None);self.role=role;self.username=username or 'local-admin';self._build();self.refresh()
    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['background']);ctl.pack(fill='x',padx=25,pady=(0,8))
        tk.Button(ctl,text='Đồng bộ cảnh báo',command=self.sync,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left')
        self.ack_btn=tk.Button(ctl,text='Xác nhận',command=self.ack);self.ack_btn.pack(side='left',padx=5)
        self.resolve_btn=tk.Button(ctl,text='Đóng sự cố',command=self.resolve);self.resolve_btn.pack(side='left',padx=5)
        tk.Button(ctl,text='Làm mới',command=self.refresh).pack(side='left',padx=5)
        if self.role=='Viewer':self.ack_btn.configure(state='disabled');self.resolve_btn.configure(state='disabled')
        cols=('id','host','severity','status','alerts','first','last','ack');self.t=ttk.Treeview(self.parent,columns=cols,show='headings')
        for c,h,w in [('id','ID',55),('host','Host',150),('severity','Mức độ',90),('status','Trạng thái',110),('alerts','Cảnh báo',80),('first','Bắt đầu',150),('last','Gần nhất',150),('ack','Xác nhận bởi',110)]:self.t.heading(c,text=h);self.t.column(c,width=w,anchor='w')
        self.t.pack(fill='both',expand=True,padx=25,pady=(0,12));self.t.bind('<<TreeviewSelect>>',lambda e:self.show_detail())
        self.detail=tk.Text(self.parent,height=8,wrap='word',font=('Consolas',9));self.detail.pack(fill='x',padx=25,pady=(0,12))
    def refresh(self):
        for x in self.t.get_children():self.t.delete(x)
        c=_connect();rows=c.execute("SELECT * FROM incidents ORDER BY CASE status WHEN 'Open' THEN 0 WHEN 'Acknowledged' THEN 1 ELSE 2 END, id DESC").fetchall();c.close()
        for r in rows:self.t.insert('','end',iid=str(r['id']),values=(r['id'],r['host'],r['severity'],r['status'],r['alert_count'],r['first_seen'],r['last_seen'],r['ack_by'] or '-'))
    def _id(self):
        s=self.t.selection();return int(s[0]) if s else None
    def sync(self):
        a,b,c=sync_incidents();self.refresh();self.activity(f'Đồng bộ sự cố: {a} mới, {b} cảnh báo liên kết, {c} tự đóng');messagebox.showinfo('Trung tâm sự cố',f'Tạo {a} sự cố mới\nLiên kết {b} cảnh báo\nTự đóng {c} sự cố')
    def ack(self):
        i=self._id()
        if not i:return
        c=_connect();c.execute("UPDATE incidents SET status='Acknowledged',ack_by=? WHERE id=? AND status='Open'",(self.username,i));c.commit();c.close();self.activity(f'Xác nhận sự cố #{i}');self.refresh()
    def resolve(self):
        i=self._id()
        if not i:return
        if not messagebox.askyesno('Trung tâm sự cố',f'Đóng sự cố #{i}?'):return
        c=_connect();c.execute("UPDATE incidents SET status='Resolved',resolved_at=? WHERE id=?",(_now(),i));c.execute("UPDATE alerts SET status='Closed' WHERE id IN (SELECT alert_id FROM incident_alerts WHERE incident_id=?)",(i,));c.commit();c.close();self.activity(f'Đóng sự cố #{i}');self.refresh()
    def show_detail(self):
        i=self._id();self.detail.delete('1.0','end')
        if not i:return
        c=_connect();rows=c.execute('''SELECT a.* FROM alerts a JOIN incident_alerts ia ON ia.alert_id=a.id WHERE ia.incident_id=? ORDER BY a.id''',(i,)).fetchall();c.close()
        lines=[]
        for a in rows:lines.append(f"[{a['created_at']}] {a['severity'] if 'severity' in a.keys() else 'Warning'} | {a['alert_type']} | {a['message']} | {a['status']}")
        self.detail.insert('1.0','\n'.join(lines) if lines else 'Chưa có cảnh báo liên kết.')


class CapacityPlanningPage:
    def __init__(self,parent,activity_callback=None):
        ensure_v9_tables();self.parent=parent;self.activity=activity_callback or (lambda m:None);self.host=tk.StringVar();self.period=tk.StringVar(value='7 ngày');self._build()
    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid');ctl.pack(fill='x',padx=25,pady=(0,10))
        tk.Label(ctl,text='Host',bg=UI_COLORS['surface']).pack(side='left',padx=(10,3),pady=10);tk.Entry(ctl,textvariable=self.host,width=20).pack(side='left')
        tk.Label(ctl,text='Khoảng thời gian',bg=UI_COLORS['surface']).pack(side='left',padx=(12,3));ttk.Combobox(ctl,textvariable=self.period,values=['24 giờ','7 ngày','30 ngày','90 ngày'],state='readonly',width=12).pack(side='left')
        tk.Button(ctl,text='Phân tích',command=self.analyze,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left',padx=8)
        cols=('metric','avg','max','trend','advice');self.t=ttk.Treeview(self.parent,columns=cols,show='headings')
        for c,h,w in [('metric','Chỉ số',150),('avg','Trung bình/Tổng',140),('max','Cao nhất',120),('trend','Xu hướng',110),('advice','Gợi ý vận hành',430)]:self.t.heading(c,text=h);self.t.column(c,width=w,anchor='w')
        self.t.pack(fill='both',expand=True,padx=25,pady=(0,12))
    def analyze(self):
        host=self.host.get().strip()
        if not host:messagebox.showinfo('Phân tích dung lượng','Nhập Host/IP.');return
        days={'24 giờ':1,'7 ngày':7,'30 ngày':30,'90 ngày':90}[self.period.get()];data=capacity_summary(host,days)
        for x in self.t.get_children():self.t.delete(x)
        for metric,(avg,mx,trend) in data.items():
            if avg is None:avgtxt='--';maxtxt='--';advice='Cần thêm dữ liệu giám sát.'
            else:
                avgtxt=f'{avg:.2f}';maxtxt='--' if mx is None else f'{mx:.2f}'
                if metric in ('CPU %','RAM %') and mx is not None and mx>=85:advice='Mức cao; kiểm tra tải và cân nhắc tăng tài nguyên.'
                elif metric=='Độ trễ ms' and mx is not None and mx>=100:advice='Độ trễ cao; kiểm tra đường truyền, QoS và nghẽn.'
                elif metric=='Mất gói %' and mx is not None and mx>=5:advice='Có mất gói đáng kể; kiểm tra link/interface.'
                elif metric in ('Lỗi cổng','Discard cổng') and avg>0:advice='Có lỗi/discard; kiểm tra cáp, duplex, congestion và interface.'
                else:advice='Chưa thấy dấu hiệu vượt ngưỡng phổ biến.'
            self.t.insert('','end',values=(metric,avgtxt,maxtxt,trend,advice))
        self.activity(f'Phân tích dung lượng {host} trong {self.period.get()}')


__all__=['ensure_v9_tables','calculate_availability','sync_incidents','capacity_summary','SLAAvailabilityPage','IncidentCenterPage','CapacityPlanningPage']
