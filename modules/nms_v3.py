from modules.ui_theme import PALETTE as UI_COLORS
import threading, time, socket, subprocess, platform
from datetime import datetime, timedelta
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog
except (ImportError, ModuleNotFoundError):
    tk = ttk = messagebox = simpledialog = None
from modules.advanced_pages import _connect, _now, snmp_get
from modules.nms_v4 import evaluate_alert_rules


def ensure_v3_tables():
    c=_connect()
    try:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS health_samples(
          id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT, cpu REAL, memory REAL,
          latency_ms REAL, packet_loss REAL, created_at TEXT);
        CREATE TABLE IF NOT EXISTS interface_samples(
          id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT, ifindex INTEGER, ifname TEXT,
          oper_status INTEGER, speed_bps INTEGER, in_octets INTEGER, out_octets INTEGER,
          in_errors INTEGER, out_errors INTEGER, in_discards INTEGER, out_discards INTEGER,
          created_at TEXT);
        CREATE TABLE IF NOT EXISTS alert_rules(
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, metric TEXT, operator TEXT,
          threshold REAL, severity TEXT DEFAULT 'Warning', host TEXT DEFAULT '', enabled INTEGER DEFAULT 1,
          created_at TEXT);
        ''')
        c.commit()
    finally:c.close()


def _num(v):
    try:return float(v)
    except:return None

class ResourceMonitorPage:
    SYS_DESCR='1.3.6.1.2.1.1.1.0'
    SYS_OBJECT='1.3.6.1.2.1.1.2.0'
    SYS_UPTIME='1.3.6.1.2.1.1.3.0'
    SYS_NAME='1.3.6.1.2.1.1.5.0'
    PRESETS={
      'Cisco IOS (CPU 5 phút)':('1.3.6.1.4.1.9.2.1.58.0','',''),
      'HOST-RESOURCES MIB (CPU)':('1.3.6.1.2.1.25.3.3.1.2.1','',''),
      'Theo hồ sơ thiết bị':('','',''),
      'Tùy chỉnh OID':('','','')}
    def __init__(self,parent,activity_callback=None):
        ensure_v3_tables();self.parent=parent;self.activity=activity_callback or (lambda m:None)
        self.host=tk.StringVar();self.community=tk.StringVar(value='public');self.preset=tk.StringVar(value=list(self.PRESETS)[0]);self.cpu_oid=tk.StringVar(value=self.PRESETS[self.preset.get()][0]);self.mem_used_oid=tk.StringVar();self.mem_total_oid=tk.StringVar();self.status=tk.StringVar(value='Sẵn sàng');self.device_info=tk.StringVar(value='Chưa kiểm tra SNMP.');self._build()
    def _build(self):
        f=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid');f.pack(fill='x',padx=25,pady=(0,10))
        fields=[('IP / Host',self.host,18),('Community',self.community,13)]
        for lab,var,w in fields:tk.Label(f,text=lab,bg=UI_COLORS['surface']).pack(side='left',padx=(10,3),pady=10);tk.Entry(f,textvariable=var,width=w).pack(side='left')
        cb=ttk.Combobox(f,textvariable=self.preset,values=list(self.PRESETS),state='readonly',width=25);cb.pack(side='left',padx=8);cb.bind('<<ComboboxSelected>>',self._preset)
        tk.Button(f,text='Kiểm tra SNMP',command=self.test_snmp,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left',padx=4)
        tk.Button(f,text='Đọc CPU/RAM',command=self.poll,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left',padx=4);tk.Label(f,textvariable=self.status,bg=UI_COLORS['surface']).pack(side='left',padx=6)
        info=tk.LabelFrame(self.parent,text='Chẩn đoán SNMP',bg=UI_COLORS['background']);info.pack(fill='x',padx=25,pady=(0,10));tk.Label(info,textvariable=self.device_info,bg=UI_COLORS['background'],fg=UI_COLORS['text'],justify='left',anchor='w',wraplength=900).pack(fill='x',padx=8,pady=7)
        o=tk.LabelFrame(self.parent,text='OID tài nguyên (có thể thay đổi theo hãng/model)',bg=UI_COLORS['background']);o.pack(fill='x',padx=25,pady=(0,10))
        for i,(lab,var) in enumerate([('CPU %',self.cpu_oid),('RAM đã dùng',self.mem_used_oid),('RAM tổng',self.mem_total_oid)]):tk.Label(o,text=lab,bg=UI_COLORS['background']).grid(row=i,column=0,sticky='w',padx=8,pady=4);tk.Entry(o,textvariable=var,width=58).grid(row=i,column=1,sticky='ew',padx=8,pady=4)
        o.columnconfigure(1,weight=1)
        b=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid');b.pack(fill='both',expand=True,padx=25,pady=(0,10));self.cpu=tk.StringVar(value='-- %');self.mem=tk.StringVar(value='-- %')
        for title,var in [('CPU',self.cpu),('RAM',self.mem)]:x=tk.Frame(b,bg=UI_COLORS['surface']);x.pack(side='left',fill='both',expand=True,padx=30,pady=30);tk.Label(x,text=title,bg=UI_COLORS['surface'],font=('Segoe UI',14,'bold')).pack();tk.Label(x,textvariable=var,bg=UI_COLORS['surface'],font=('Segoe UI',34,'bold')).pack(pady=15)
    def _preset(self,e=None):
        if self.preset.get()=='Theo hồ sơ thiết bị':
            try:
                from modules.nms_v7 import get_profile_for_device
                p=get_profile_for_device(host=self.host.get().strip())
                if not p:
                    self.status.set('Thiết bị chưa được gán hồ sơ');return
                self.cpu_oid.set(p.get('cpu_oid') or '');self.mem_used_oid.set(p.get('mem_used_oid') or '');self.mem_total_oid.set(p.get('mem_total_oid') or '');self.status.set('Đã nạp hồ sơ: '+p.get('name',''))
                return
            except Exception as exc:
                self.status.set('Lỗi hồ sơ: '+str(exc));return
        self.cpu_oid.set(self.PRESETS[self.preset.get()][0]);self.mem_used_oid.set('');self.mem_total_oid.set('')
    @staticmethod
    def _vendor(descr,obj=''):
        t=(str(descr)+' '+str(obj)).lower()
        if 'cisco' in t or '.1.3.6.1.4.1.9' in t:return 'Cisco'
        if 'mikrotik' in t or 'routeros' in t or '.1.3.6.1.4.1.14988' in t:return 'MikroTik'
        if 'ruijie' in t or '.1.3.6.1.4.1.4881' in t:return 'Ruijie'
        if 'aruba' in t or 'hewlett packard enterprise' in t or 'procurve' in t:return 'Aruba/HPE'
        if 'linux' in t:return 'Linux'
        if 'windows' in t or 'microsoft' in t:return 'Windows'
        return 'Không xác định'
    def _apply_detected_profile(self,vendor):
        # Chỉ tự chọn khi có preset đáng tin cậy. Không tự đoán OID RAM theo hãng/model.
        try:
            from modules.nms_v7 import detect_profile, assign_profile
            p=detect_profile(self.device_info.get(), '')
        except Exception:
            p=None
        if vendor=='Cisco':
            self.preset.set('Cisco IOS (CPU 5 phút)');self._preset()
        elif vendor=='MikroTik':
            self.cpu_oid.set('1.3.6.1.4.1.14988.1.1.3.14.0');self.mem_used_oid.set('');self.mem_total_oid.set('');self.preset.set('Tùy chỉnh OID')
        elif vendor in ('Linux','Windows'):
            self.preset.set('HOST-RESOURCES MIB (CPU)');self._preset()
    def test_snmp(self):
        host=self.host.get().strip();community=self.community.get().strip()
        if not host:messagebox.showwarning('Kiểm tra SNMP','Nhập IP / Host.');return
        self.status.set('Đang kiểm tra SNMP...');self.device_info.set('Đang gửi yêu cầu SNMP v2c tới UDP/161...')
        def work():
            try:
                vals=snmp_get(host,community,[self.SYS_DESCR,self.SYS_OBJECT,self.SYS_UPTIME,self.SYS_NAME])
                descr=vals.get(self.SYS_DESCR) or '-';obj=vals.get(self.SYS_OBJECT) or '-';name=vals.get(self.SYS_NAME) or '-';uptime=vals.get(self.SYS_UPTIME)
                vendor=self._vendor(descr,obj);self.parent.after(0,lambda:self._snmp_ok(name,descr,obj,uptime,vendor))
            except Exception as exc:
                msg=str(exc);self.parent.after(0,lambda m=msg:self._snmp_fail(m))
        threading.Thread(target=work,daemon=True).start()
    def _snmp_ok(self,name,descr,obj,uptime,vendor):
        # Ưu tiên Device Profile v3.7; nếu chưa có thì vẫn dùng preset cũ.
        profile_name=''
        try:
            from modules.nms_v7 import detect_profile, assign_profile
            p=detect_profile(descr,obj)
            if p:
                profile_name=p.get('name','')
                if p.get('cpu_oid'): self.cpu_oid.set(p['cpu_oid'])
                self.mem_used_oid.set(p.get('mem_used_oid') or '')
                self.mem_total_oid.set(p.get('mem_total_oid') or '')
                c=_connect();d=c.execute('SELECT id FROM network_devices WHERE ip=? ORDER BY id LIMIT 1',(self.host.get().strip(),)).fetchone();c.close()
                if d: assign_profile(d['id'],p['id'],'auto',str(descr),str(obj))
            else:self._apply_detected_profile(vendor)
        except Exception:
            self._apply_detected_profile(vendor)
        up='-' if uptime is None else f'{float(uptime)/100/86400:.1f} ngày'
        extra=f' | Hồ sơ: {profile_name}' if profile_name else ''
        self.status.set('SNMP OK');self.device_info.set(f'✓ SNMP v2c phản hồi | sysName: {name} | Hãng: {vendor}{extra} | Uptime: {up}\nsysDescr: {descr}\nsysObjectID: {obj}')
        self.activity('Kiểm tra SNMP thành công: '+self.host.get())
    def _snmp_fail(self,msg):
        self.status.set('SNMP không phản hồi')
        if 'không phản hồi SNMP' in msg:
            self.device_info.set('✓ IP có thể vẫn Ping được nhưng ✗ SNMP UDP/161 không phản hồi.\n'+msg)
        else:self.device_info.set('✗ Kiểm tra SNMP thất bại: '+msg)
    def poll(self):
        host=self.host.get().strip();oids=[x.get().strip() for x in (self.cpu_oid,self.mem_used_oid,self.mem_total_oid) if x.get().strip()]
        if not host or not oids:messagebox.showwarning('CPU/RAM','Nhập IP và ít nhất một OID.');return
        self.status.set('Đang đọc SNMP...')
        def work():
            try:
                v=snmp_get(host,self.community.get(),oids);cpu=_num(v.get(self.cpu_oid.get().strip())) if self.cpu_oid.get().strip() else None
                used=_num(v.get(self.mem_used_oid.get().strip())) if self.mem_used_oid.get().strip() else None;total=_num(v.get(self.mem_total_oid.get().strip())) if self.mem_total_oid.get().strip() else None;mem=(used*100/total) if used is not None and total else None
                c=_connect();c.execute('INSERT INTO health_samples(host,cpu,memory,created_at) VALUES(?,?,?,?)',(host,cpu,mem,_now()));c.commit();c.close();self.parent.after(0,lambda:self._done(cpu,mem))
            except Exception as exc:
                msg=str(exc);self.parent.after(0,lambda m=msg:self._poll_fail(m))
        threading.Thread(target=work,daemon=True).start()
    def _poll_fail(self,msg):
        self.cpu.set('-- %');self.mem.set('-- %');self.status.set('Lỗi SNMP');self.device_info.set('Không đọc được CPU/RAM: '+msg)
    def _done(self,cpu,mem):
        self.cpu.set('-- %' if cpu is None else f'{cpu:.1f} %');self.mem.set('-- %' if mem is None else f'{mem:.1f} %')
        if cpu is None and mem is None:self.status.set('SNMP OK nhưng OID không trả về số liệu');self.device_info.set('Thiết bị phản hồi SNMP nhưng OID CPU/RAM hiện tại không có dữ liệu. Hãy chọn đúng preset hoặc OID theo hãng/model.')
        else:self.status.set('Hoàn tất')
        self.activity('Đã đọc CPU/RAM SNMP: '+self.host.get())

class AdvancedPortMonitorPage:
    def __init__(self,parent,activity_callback=None):
        ensure_v3_tables();self.parent=parent;self.activity=activity_callback or (lambda m:None);self.host=tk.StringVar();self.community=tk.StringVar(value='public');self.indices=tk.StringVar(value='1,2,3,4');self.status=tk.StringVar(value='Sẵn sàng');self._build()
    def _build(self):
        f=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid');f.pack(fill='x',padx=25,pady=(0,10))
        for lab,var,w in [('IP / Host',self.host,18),('Community',self.community,13),('IfIndex',self.indices,24)]:tk.Label(f,text=lab,bg=UI_COLORS['surface']).pack(side='left',padx=(10,3),pady=10);tk.Entry(f,textvariable=var,width=w).pack(side='left')
        tk.Button(f,text='Đọc chi tiết cổng',command=self.poll,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left',padx=8);tk.Label(f,textvariable=self.status,bg=UI_COLORS['surface']).pack(side='left')
        b=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid');b.pack(fill='both',expand=True,padx=25,pady=(0,10));cols=('idx','name','state','speed','inerr','outerr','indisc','outdisc');self.t=ttk.Treeview(b,columns=cols,show='headings')
        heads=['IfIndex','Tên cổng','Trạng thái','Tốc độ','Lỗi IN','Lỗi OUT','Discard IN','Discard OUT']
        for c,h in zip(cols,heads):self.t.heading(c,text=h);self.t.column(c,width=110,anchor='w')
        self.t.pack(fill='both',expand=True,padx=8,pady=8)
    def poll(self):
        try:idxs=[int(x.strip()) for x in self.indices.get().split(',') if x.strip()]
        except:messagebox.showerror('Cổng','IfIndex phải là số nguyên.');return
        host=self.host.get().strip();self.status.set('Đang đọc...')
        def work():
            rows=[]
            for i in idxs:
                bases=['1.3.6.1.2.1.2.2.1.2','1.3.6.1.2.1.2.2.1.8','1.3.6.1.2.1.2.2.1.5','1.3.6.1.2.1.2.2.1.10','1.3.6.1.2.1.2.2.1.16','1.3.6.1.2.1.2.2.1.14','1.3.6.1.2.1.2.2.1.20','1.3.6.1.2.1.2.2.1.13','1.3.6.1.2.1.2.2.1.19'];oids=[f'{b}.{i}' for b in bases]
                try:
                    v=snmp_get(host,self.community.get(),oids);vals=[v.get(x,0) for x in oids];state=int(vals[1] or 0);row=(i,vals[0],'UP' if state==1 else 'DOWN' if state==2 else state,f'{int(vals[2] or 0)/1e6:.0f} Mbps',vals[5],vals[6],vals[7],vals[8]);rows.append(row)
                    c=_connect();c.execute('INSERT INTO interface_samples(host,ifindex,ifname,oper_status,speed_bps,in_octets,out_octets,in_errors,out_errors,in_discards,out_discards,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(host,i,str(vals[0]),state,int(vals[2] or 0),int(vals[3] or 0),int(vals[4] or 0),int(vals[5] or 0),int(vals[6] or 0),int(vals[7] or 0),int(vals[8] or 0),_now()));c.commit();c.close()
                except Exception as e:rows.append((i,'','LỖI','','','','',str(e)[:80]))
            self.parent.after(0,lambda:self._done(rows))
        threading.Thread(target=work,daemon=True).start()
    def _done(self,rows):
        for x in self.t.get_children():self.t.delete(x)
        for r in rows:self.t.insert('','end',values=r)
        self.status.set(f'Đã đọc {len(rows)} cổng');self.activity('Đã giám sát chi tiết cổng: '+self.host.get())

class AlertRulesPage:
    METRICS=['CPU %','RAM %','Mất gói %','Độ trễ ms','Lỗi cổng IN','Lỗi cổng OUT']
    def __init__(self,parent,activity_callback=None):ensure_v3_tables();self.parent=parent;self.activity=activity_callback or (lambda m:None);self._build();self.refresh()
    def _build(self):
        f=tk.Frame(self.parent,bg=UI_COLORS['background']);f.pack(fill='x',padx=25,pady=(0,8));tk.Button(f,text='Thêm quy tắc',command=self.add,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left');tk.Button(f,text='Bật / Tắt',command=self.toggle).pack(side='left',padx=5);tk.Button(f,text='Xóa',command=self.delete).pack(side='left',padx=5);tk.Button(f,text='Đánh giá ngay',command=self.evaluate).pack(side='left',padx=5)
        b=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid');b.pack(fill='both',expand=True,padx=25,pady=(0,10));cols=('id','name','host','metric','op','threshold','severity','enabled');self.t=ttk.Treeview(b,columns=cols,show='headings')
        for c in cols:self.t.heading(c,text=c.upper());self.t.column(c,width=120,anchor='w')
        self.t.pack(fill='both',expand=True,padx=8,pady=8)
    def refresh(self):
        c=_connect();self.rows=[dict(r) for r in c.execute('SELECT * FROM alert_rules ORDER BY id DESC')];c.close()
        for x in self.t.get_children():self.t.delete(x)
        for r in self.rows:self.t.insert('','end',values=(r['id'],r['name'],r['host'] or '*',r['metric'],r['operator'],r['threshold'],r['severity'],'Có' if r['enabled'] else 'Không'))
    def add(self):
        w=tk.Toplevel(self.parent);w.title('Thêm quy tắc cảnh báo');w.geometry('430x350');vars=[tk.StringVar() for _ in range(6)];vars[2].set(self.METRICS[0]);vars[3].set('>');vars[5].set('Warning');labs=['Tên','Host (trống = tất cả)','Chỉ số','Toán tử','Ngưỡng','Mức độ']
        for i,(lab,var) in enumerate(zip(labs,vars)):tk.Label(w,text=lab).grid(row=i,column=0,padx=12,pady=9,sticky='w');(ttk.Combobox(w,textvariable=var,values=self.METRICS if i==2 else (['>','>=','<','<='] if i==3 else ['Info','Warning','Critical']),state='readonly',width=25) if i in (2,3,5) else tk.Entry(w,textvariable=var,width=28)).grid(row=i,column=1,padx=8,pady=9)
        def save():
            try:th=float(vars[4].get())
            except:messagebox.showerror('Quy tắc','Ngưỡng phải là số.',parent=w);return
            c=_connect();c.execute('INSERT INTO alert_rules(name,host,metric,operator,threshold,severity,enabled,created_at) VALUES(?,?,?,?,?,?,1,?)',(vars[0].get() or vars[2].get(),vars[1].get().strip(),vars[2].get(),vars[3].get(),th,vars[5].get(),_now()));c.commit();c.close();w.destroy();self.refresh()
        tk.Button(w,text='Lưu',command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text']).grid(row=6,column=1,pady=14,sticky='e')
    def _id(self):
        s=self.t.selection();return int(self.t.item(s[0])['values'][0]) if s else None
    def toggle(self):
        i=self._id();
        if i is None:return
        c=_connect();c.execute('UPDATE alert_rules SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?',(i,));c.commit();c.close();self.refresh()
    def delete(self):
        i=self._id();
        if i is None:return
        c=_connect();c.execute('DELETE FROM alert_rules WHERE id=?',(i,));c.commit();c.close();self.refresh()
    def evaluate(self):
        try:
            created,recovered=evaluate_alert_rules()
            messagebox.showinfo('Quy tắc cảnh báo',f'Đã tạo {created} cảnh báo mới; {recovered} cảnh báo đã phục hồi.')
            self.activity(f'Đánh giá quy tắc cảnh báo: {created} mới, {recovered} phục hồi')
        except Exception as e:
            messagebox.showerror('Quy tắc cảnh báo',str(e))

class HistoryChartsPage:
    def __init__(self,parent,activity_callback=None):ensure_v3_tables();self.parent=parent;self.host=tk.StringVar();self.period=tk.StringVar(value='24 giờ');self.metric=tk.StringVar(value='Traffic IN');self.status=tk.StringVar(value='Sẵn sàng');self._build()
    def _build(self):
        f=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid');f.pack(fill='x',padx=25,pady=(0,10))
        for lab,var,vals,w in [('Host',self.host,None,20),('Khoảng thời gian',self.period,['24 giờ','7 ngày','30 ngày'],12),('Chỉ số',self.metric,['Traffic IN','Traffic OUT','CPU','RAM'],14)]:tk.Label(f,text=lab,bg=UI_COLORS['surface']).pack(side='left',padx=(10,3),pady=10);(ttk.Combobox(f,textvariable=var,values=vals,state='readonly',width=w) if vals else tk.Entry(f,textvariable=var,width=w)).pack(side='left')
        tk.Button(f,text='Xem biểu đồ',command=self.refresh,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left',padx=8);tk.Label(f,textvariable=self.status,bg=UI_COLORS['surface']).pack(side='left')
        self.c=tk.Canvas(self.parent,bg=UI_COLORS['surface'],highlightthickness=1,highlightbackground=UI_COLORS['border']);self.c.pack(fill='both',expand=True,padx=25,pady=(0,15));self.c.bind('<Configure>',lambda e:self.draw())
        self.data=[]
    def refresh(self):
        host=self.host.get().strip();days={'24 giờ':1,'7 ngày':7,'30 ngày':30}[self.period.get()];cut=(datetime.now()-timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S');m=self.metric.get();c=_connect()
        if m in ('Traffic IN','Traffic OUT'):
            col='in_bps' if m=='Traffic IN' else 'out_bps';rows=c.execute(f'SELECT created_at,{col} v FROM snmp_samples WHERE host=? AND created_at>=? ORDER BY id',(host,cut)).fetchall()
        else:
            col='cpu' if m=='CPU' else 'memory';rows=c.execute(f'SELECT created_at,{col} v FROM health_samples WHERE host=? AND created_at>=? AND {col} IS NOT NULL ORDER BY id',(host,cut)).fetchall()
        c.close();self.data=[(r['created_at'],float(r['v'] or 0)) for r in rows];self.status.set(f'{len(self.data)} mẫu');self.draw()
    def draw(self):
        c=self.c;c.delete('all');w=max(500,c.winfo_width());h=max(300,c.winfo_height());p=55;c.create_line(p,20,p,h-p,fill=UI_COLORS['muted']);c.create_line(p,h-p,w-20,h-p,fill=UI_COLORS['muted'])
        if len(self.data)<2:c.create_text(w/2,h/2,text='Chưa đủ dữ liệu lịch sử. Hãy chạy giám sát để thu thập mẫu.',fill=UI_COLORS['muted']);return
        vals=[v for _,v in self.data];mx=max(1,max(vals));pts=[]
        for i,v in enumerate(vals):x=p+(w-p-25)*i/(len(vals)-1);y=h-p-(h-p-30)*v/mx;pts.extend([x,y])
        c.create_line(*pts,width=2,smooth=True, fill=UI_COLORS['muted']);unit='%' if self.metric.get() in ('CPU','RAM') else 'bps';c.create_text(8,22,text=f'{mx:,.1f} {unit}',anchor='w', fill=UI_COLORS['text']);c.create_text(8,h-p,text='0',anchor='w', fill=UI_COLORS['text']);c.create_text(w/2,h-18,text=f'{self.period.get()} • {len(vals)} mẫu', fill=UI_COLORS['text'])
