from modules.ui_theme import PALETTE as UI_COLORS
import os, re, socket, sqlite3, subprocess, threading, time
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from database.db import DB_PATH, init_database
from modules.advanced_pages import snmp_get, _connect, _now, log_activity, BACKUP_DIR, ensure_advanced_tables
from app_runtime import hidden_subprocess_kwargs
from modules.ssh_security import build_strict_ssh_client

BACKUP_JOB_SECRETS = {}


def _ping(ip):
    from modules.icmp_probe import icmp_ping
    return icmp_ping(ip)['status'] == 'Online'

class NOCDashboardPage:
    def __init__(self,parent,activity_callback=None):
        ensure_advanced_tables();self.parent=parent;self.activity_callback=activity_callback or (lambda m:None);self._build();self.refresh()
    def _build(self):
        top=tk.Frame(self.parent,bg=UI_COLORS['background']);top.pack(fill='x',padx=25,pady=(0,10))
        tk.Button(top,text='Làm mới NOC',command=self.refresh,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left')
        self.cards=tk.Frame(self.parent,bg=UI_COLORS['background']);self.cards.pack(fill='x',padx=25)
        self.vars=[]
        for title in ('Đang quản lý','Online','Offline','Cảnh báo đang mở','Hồ sơ SNMP'):
            box=tk.Frame(self.cards,bg=UI_COLORS['surface'],bd=1,relief='solid');box.pack(side='left',fill='x',expand=True,padx=4,pady=4)
            v=tk.StringVar(value='0');self.vars.append(v);tk.Label(box,text=title,bg=UI_COLORS['surface'],fg=UI_COLORS['muted']).pack(pady=(12,2));tk.Label(box,textvariable=v,bg=UI_COLORS['surface'],font=('Segoe UI',22,'bold')).pack(pady=(0,12))
        body=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid');body.pack(fill='both',expand=True,padx=25,pady=10)
        tk.Label(body,text='Cảnh báo nghiêm trọng / cảnh báo gần đây',bg=UI_COLORS['surface'],font=('Segoe UI',12,'bold')).pack(anchor='w',padx=12,pady=10)
        self.table=ttk.Treeview(body,columns=('time','severity','ip','type','message'),show='headings')
        for c,w in zip(('time','severity','ip','type','message'),(150,90,130,150,520)):self.table.heading(c,text=c.title());self.table.column(c,width=w,anchor='w')
        self.table.pack(fill='both',expand=True,padx=10,pady=(0,10))
    def refresh(self):
        c=_connect()
        try:
            managed=c.execute('SELECT COUNT(*) FROM network_devices').fetchone()[0]
            online=c.execute("SELECT COUNT(*) FROM network_devices WHERE status='Online'").fetchone()[0]
            offline=c.execute("SELECT COUNT(*) FROM network_devices WHERE status='Offline'").fetchone()[0]
            alerts=c.execute("SELECT COUNT(*) FROM alerts WHERE status<>'Closed'").fetchone()[0]
            profiles=c.execute('SELECT COUNT(*) FROM snmp_profiles').fetchone()[0]
            rows=c.execute("SELECT * FROM alerts WHERE status<>'Closed' ORDER BY id DESC LIMIT 100").fetchall()
        finally:c.close()
        for v,x in zip(self.vars,(managed,online,offline,alerts,profiles)):v.set(str(x))
        for i in self.table.get_children():self.table.delete(i)
        for r in rows:self.table.insert('', 'end', values=(r['created_at'],r['severity'],r['ip'],r['alert_type'],r['message']))

class AutoDiscoveryPage:
    def __init__(self,parent,activity_callback=None):
        self.parent=parent;self.activity_callback=activity_callback or (lambda m:None);self.subnet=tk.StringVar(value='192.168.1.0/24');self.status=tk.StringVar(value='Sẵn sàng');self._build()
    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid');ctl.pack(fill='x',padx=25,pady=(0,10))
        tk.Label(ctl,text='Mạng con',bg=UI_COLORS['surface']).pack(side='left',padx=(12,5),pady=12);tk.Entry(ctl,textvariable=self.subnet,width=22).pack(side='left')
        tk.Button(ctl,text='Phát hiện',command=self.discover,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left',padx=8);tk.Label(ctl,textvariable=self.status,bg=UI_COLORS['surface']).pack(side='left',padx=10)
        box=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid');box.pack(fill='both',expand=True,padx=25,pady=(0,10))
        self.table=ttk.Treeview(box,columns=('ip','hostname','status','source'),show='headings');
        for c,w in zip(('ip','hostname','status','source'),(160,280,120,250)):self.table.heading(c,text=c.title());self.table.column(c,width=w,anchor='w')
        self.table.pack(fill='both',expand=True,padx=10,pady=10)
    def discover(self):
        import ipaddress
        try:hosts=list(ipaddress.ip_network(self.subnet.get().strip(),strict=False).hosts())
        except Exception as e:messagebox.showerror('Discovery',str(e));return
        if len(hosts)>1024:messagebox.showwarning('Discovery','For safety, scan a subnet with 1024 hosts or fewer.');return
        self.status.set(f'Scanning {len(hosts)} hosts...')
        def worker():
            from concurrent.futures import ThreadPoolExecutor, as_completed
            found=[]
            def one(ip):
                s=str(ip)
                if not _ping(s):return None
                try:h=socket.gethostbyaddr(s)[0]
                except Exception:h=''
                return (s,h,'Online','ICMP + DNS')
            with ThreadPoolExecutor(max_workers=64) as ex:
                for f in as_completed([ex.submit(one,x) for x in hosts]):
                    r=f.result()
                    if r:found.append(r)
            self.parent.after(0,lambda:self._done(found))
        threading.Thread(target=worker,daemon=True).start()
    def _done(self,rows):
        for i in self.table.get_children():self.table.delete(i)
        c=_connect()
        try:
            for ip,host,status,source in sorted(rows):
                self.table.insert('', 'end',values=(ip,host,status,source))
                exists=c.execute('SELECT id FROM network_devices WHERE ip=?',(ip,)).fetchone()
                if not exists:c.execute('INSERT INTO network_devices(name,ip,device_type,vendor,location,status,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)',(host or ip,ip,'Discovered','','',status,'Tự động phát hiện',_now(),_now()))
            c.commit()
        finally:c.close()
        self.status.set(f'Found {len(rows)} online device(s); new devices added to Network Devices.')
        self.activity_callback(f'Auto discovery completed: {len(rows)} online device(s)')

class MultiPortMonitorPage:
    def __init__(self,parent,activity_callback=None):
        self.parent=parent;self.activity_callback=activity_callback or (lambda m:None);self.host=tk.StringVar();self.community=tk.StringVar(value='public');self.indices=tk.StringVar(value='1,2,3,4');self.status=tk.StringVar(value='Sẵn sàng');self._build()
    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid');ctl.pack(fill='x',padx=25,pady=(0,10))
        for lab,var,w in [('Máy chủ/IP',self.host,18),('Community',self.community,14),('Danh sách IfIndex',self.indices,25)]:tk.Label(ctl,text=lab,bg=UI_COLORS['surface']).pack(side='left',padx=(10,3),pady=12);tk.Entry(ctl,textvariable=var,width=w).pack(side='left')
        tk.Button(ctl,text='Kiểm tra cổng',command=self.poll,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left',padx=10);tk.Label(ctl,textvariable=self.status,bg=UI_COLORS['surface']).pack(side='left')
        box=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid');box.pack(fill='both',expand=True,padx=25,pady=(0,10))
        self.table=ttk.Treeview(box,columns=('ifindex','status','in_octets','out_octets'),show='headings');
        for c,w in zip(('ifindex','status','in_octets','out_octets'),(120,140,220,220)):self.table.heading(c,text=c.replace('_',' ').title());self.table.column(c,width=w,anchor='w')
        self.table.pack(fill='both',expand=True,padx=10,pady=10)
    def poll(self):
        host=self.host.get().strip()
        try:idxs=[int(x.strip()) for x in self.indices.get().split(',') if x.strip()]
        except ValueError:messagebox.showerror('Multi-Port','IfIndex list must contain integers.');return
        if not host:return
        self.status.set('Đang kiểm tra...')
        def worker():
            out=[]
            for idx in idxs:
                try:
                    o=[f'1.3.6.1.2.1.2.2.1.8.{idx}',f'1.3.6.1.2.1.2.2.1.10.{idx}',f'1.3.6.1.2.1.2.2.1.16.{idx}'];v=snmp_get(host,self.community.get(),o)
                    st=int(v.get(o[0],0) or 0);out.append((idx,'UP' if st==1 else 'DOWN' if st==2 else str(st),v.get(o[1],0),v.get(o[2],0)))
                except Exception as e:out.append((idx,'ERROR',str(e),''))
            self.parent.after(0,lambda:self._done(out))
        threading.Thread(target=worker,daemon=True).start()
    def _done(self,rows):
        for i in self.table.get_children():self.table.delete(i)
        for r in rows:self.table.insert('', 'end',values=r)
        self.status.set(f'Polled {len(rows)} interface(s)')

class BackupSchedulerPage:
    def __init__(self,parent,activity_callback=None):
        self.parent=parent;self.activity_callback=activity_callback or (lambda m:None);self._ensure();self._build();self.refresh();self.parent.after(5000,self._tick)
    def _ensure(self):
        c=_connect();c.execute('''CREATE TABLE IF NOT EXISTS ssh_backup_jobs(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,host TEXT,port INTEGER DEFAULT 22,username TEXT,password TEXT,command TEXT,interval_min INTEGER DEFAULT 1440,last_run TEXT,next_run REAL,enabled INTEGER DEFAULT 1)''');c.commit();c.close()
    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['background']);ctl.pack(fill='x',padx=25,pady=(0,8));tk.Button(ctl,text='Thêm lịch sao lưu SSH',command=self.add,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left');tk.Button(ctl,text='Chạy ngay',command=self.run_now).pack(side='left',padx=5);tk.Button(ctl,text='Đặt mật khẩu',command=self.set_password).pack(side='left',padx=5);tk.Button(ctl,text='Xóa',command=self.delete).pack(side='left',padx=5);tk.Button(ctl,text='Làm mới',command=self.refresh).pack(side='left',padx=5)
        box=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid');box.pack(fill='both',expand=True,padx=25,pady=(0,10));self.table=ttk.Treeview(box,columns=('name','host','user','interval','last','enabled'),show='headings')
        for c,w in zip(('name','host','user','interval','last','enabled'),(180,150,150,120,180,90)):self.table.heading(c,text=c.title());self.table.column(c,width=w,anchor='w')
        self.table.pack(fill='both',expand=True,padx=10,pady=10)
    def add(self):
        name=simpledialog.askstring('Backup Job','Job name:',parent=self.parent);host=simpledialog.askstring('Backup Job','Host / IP:',parent=self.parent) if name else None;user=simpledialog.askstring('Backup Job','SSH username:',parent=self.parent) if host else None;pwd=simpledialog.askstring('Backup Job','SSH password:',show='*',parent=self.parent) if user else None
        if not all((name,host,user,pwd)):return
        cmd=simpledialog.askstring('Backup Job','Command:',initialvalue='show running-config',parent=self.parent) or 'show running-config';mins=simpledialog.askinteger('Backup Job','Interval in minutes:',initialvalue=1440,minvalue=1,parent=self.parent)
        if not mins:return
        c=_connect();cur=c.execute('INSERT INTO ssh_backup_jobs(name,host,username,password,command,interval_min,next_run,enabled) VALUES(?,?,?,?,?,?,?,1)',(name,host,user,'',cmd,mins,time.time()));jid=cur.lastrowid;c.commit();c.close();BACKUP_JOB_SECRETS[jid]=pwd;self.refresh()
    def _selected(self):
        s=self.table.selection();return int(s[0]) if s else None
    def set_password(self):
        i=self._selected()
        if not i:return
        pwd=simpledialog.askstring('Backup Job','SSH password for this session:',show='*',parent=self.parent)
        if pwd is not None:BACKUP_JOB_SECRETS[i]=pwd
    def run_now(self):
        i=self._selected()
        if i:self._run_id(i)
    def delete(self):
        i=self._selected()
        if not i:return
        c=_connect();c.execute('DELETE FROM ssh_backup_jobs WHERE id=?',(i,));c.commit();c.close();self.refresh()
    def refresh(self):
        for i in self.table.get_children():self.table.delete(i)
        c=_connect();rows=c.execute('SELECT * FROM ssh_backup_jobs ORDER BY name').fetchall();c.close()
        for r in rows:self.table.insert('', 'end',iid=str(r['id']),values=(r['name'],r['host'],r['username'],f"{r['interval_min']} min",r['last_run'] or '-', 'Yes' if r['enabled'] else 'No'))
    def _tick(self):
        try:
            c=_connect();rows=c.execute('SELECT id FROM ssh_backup_jobs WHERE enabled=1 AND next_run<=?',(time.time(),)).fetchall();c.close()
            for r in rows:self._run_id(r['id'])
            self.parent.after(5000,self._tick)
        except tk.TclError:pass
    def _run_id(self,i):
        c=_connect();r=c.execute('SELECT * FROM ssh_backup_jobs WHERE id=?',(i,)).fetchone();c.close()
        if not r:return
        def worker():
            try:
                import paramiko
                cli=build_strict_ssh_client(paramiko);pwd=BACKUP_JOB_SECRETS.get(i)
                if not pwd:raise RuntimeError('SSH password is not loaded for this session. Select the job and click Set Password.')
                cli.connect(r['host'],port=r['port'],username=r['username'],password=pwd,timeout=8,look_for_keys=False,allow_agent=False);stdin,stdout,stderr=cli.exec_command(r['command'],timeout=20);data=stdout.read().decode(errors='replace');err=stderr.read().decode(errors='replace');cli.close()
                if err and not data:raise RuntimeError(err)
                dst=BACKUP_DIR/f"{r['host'].replace(':','_')}_scheduled_{datetime.now().strftime('%Y%m%d_%H%M%S')}.cfg";dst.write_text(data,encoding='utf-8')
                c=_connect();c.execute('UPDATE ssh_backup_jobs SET last_run=?,next_run=? WHERE id=?',(_now(),time.time()+r['interval_min']*60,i));c.execute('INSERT INTO config_backups(device_name,source,file_path,size_bytes,note,created_at) VALUES(?,?,?,?,?,?)',(r['host'],'Scheduled SSH',str(dst),dst.stat().st_size,r['name'],_now()));c.commit();c.close();self.parent.after(0,self.refresh);self.activity_callback(f"Scheduled backup saved: {dst}")
            except Exception as e:
                c=_connect();c.execute('UPDATE ssh_backup_jobs SET last_run=?,next_run=? WHERE id=?',(_now(),time.time()+r['interval_min']*60,i));c.commit();c.close();self.activity_callback(f"Backup job {r['name']} failed: {e}")
        threading.Thread(target=worker,daemon=True).start()

__all__=['NOCDashboardPage','AutoDiscoveryPage','MultiPortMonitorPage','BackupSchedulerPage']

class NetworkHealthPage:
    """Giám sát độ trễ, mất gói và thông tin hệ thống SNMP cơ bản."""
    def __init__(self,parent,activity_callback=None):
        self.parent=parent; self.activity_callback=activity_callback or (lambda m:None)
        self.host=tk.StringVar(); self.community=tk.StringVar(value='public'); self.status=tk.StringVar(value='Sẵn sàng')
        self._build()
    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid'); ctl.pack(fill='x',padx=25,pady=(0,10))
        tk.Label(ctl,text='IP / Tên máy',bg=UI_COLORS['surface']).pack(side='left',padx=(12,4),pady=12); tk.Entry(ctl,textvariable=self.host,width=22).pack(side='left')
        tk.Label(ctl,text='SNMP Community',bg=UI_COLORS['surface']).pack(side='left',padx=(12,4)); tk.Entry(ctl,textvariable=self.community,width=15).pack(side='left')
        tk.Button(ctl,text='Kiểm tra sức khỏe',command=self.check,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left',padx=10)
        tk.Label(ctl,textvariable=self.status,bg=UI_COLORS['surface']).pack(side='left',padx=8)
        box=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief='solid'); box.pack(fill='both',expand=True,padx=25,pady=(0,10))
        self.table=ttk.Treeview(box,columns=('metric','value','note'),show='headings')
        for c,t,w in [('metric','Chỉ số',240),('value','Giá trị',220),('note','Ghi chú',520)]: self.table.heading(c,text=t); self.table.column(c,width=w,anchor='w')
        self.table.pack(fill='both',expand=True,padx=10,pady=10)
    def check(self):
        host=self.host.get().strip()
        if not host: messagebox.showwarning('Giám sát sức khỏe','Vui lòng nhập IP hoặc tên máy.'); return
        self.status.set('Đang kiểm tra...')
        def worker():
            rows=[]
            # 4 ICMP probes; parse platform output conservatively.
            flag='-n' if os.name=='nt' else '-c'; cmd=['ping',flag,'4',host]
            try:
                p=subprocess.run(cmd,capture_output=True,text=True,timeout=8,errors='replace',**hidden_subprocess_kwargs()); out=p.stdout
                sent=4
                if os.name=='nt':
                    m=re.search(r'Lost = (\d+)',out,re.I); lost=int(m.group(1)) if m else (0 if p.returncode==0 else 4)
                    m=re.search(r'Average = (\d+)ms',out,re.I); avg=(m.group(1)+' ms') if m else '-'
                else:
                    m=re.search(r'(\d+(?:\.\d+)?)% packet loss',out); lost=round(sent*float(m.group(1))/100) if m else (0 if p.returncode==0 else 4)
                    m=re.search(r'= [\d.]+/([\d.]+)/',out); avg=(m.group(1)+' ms') if m else '-'
                rows += [('Độ trễ trung bình',avg,'ICMP Ping'),('Mất gói',f'{lost}/{sent} ({lost*25:.0f}%)','4 gói ICMP')]
            except Exception as e: rows.append(('Ping','Lỗi',str(e)))
            # Standard SNMP system OIDs are vendor-neutral.
            try:
                oids=['1.3.6.1.2.1.1.5.0','1.3.6.1.2.1.1.3.0','1.3.6.1.2.1.1.1.0']
                v=snmp_get(host,self.community.get(),oids)
                ticks=int(v.get(oids[1],0) or 0); days=ticks/100/86400
                rows += [('Tên hệ thống',v.get(oids[0],'-'),'SNMP sysName'),('Uptime',f'{days:.2f} ngày','SNMP sysUpTime'),('Mô tả thiết bị',str(v.get(oids[2],'-'))[:180],'SNMP sysDescr')]
            except Exception as e: rows.append(('SNMP','Không phản hồi',str(e)))
            self.parent.after(0,lambda:self._done(rows))
        threading.Thread(target=worker,daemon=True).start()
    def _done(self,rows):
        for i in self.table.get_children(): self.table.delete(i)
        for r in rows:self.table.insert('', 'end',values=r)
        self.status.set('Hoàn tất'); self.activity_callback('Đã kiểm tra sức khỏe mạng: '+self.host.get().strip())

__all__.append('NetworkHealthPage')
