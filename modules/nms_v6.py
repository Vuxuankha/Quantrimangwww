from modules.ui_ux_config import PALETTE as UI_COLORS
import os, re, sqlite3, subprocess, threading, time
from datetime import datetime, timedelta
from pathlib import Path
try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except (ImportError, ModuleNotFoundError):
    tk = ttk = messagebox = None
from database.db import DB_PATH
from modules.advanced_pages import _connect, _now
from app_runtime import hidden_subprocess_kwargs
from modules.ssh_security import build_strict_ssh_client


def ensure_v6_tables():
    c=_connect()
    try:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS audit_log(
          id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, role TEXT,
          action TEXT NOT NULL, target TEXT DEFAULT '', detail TEXT DEFAULT '', created_at TEXT);
        CREATE TABLE IF NOT EXISTS monitoring_settings(
          id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER DEFAULT 1,
          interval_sec INTEGER DEFAULT 60, retention_days INTEGER DEFAULT 90,
          last_run TEXT, last_status TEXT);
        INSERT OR IGNORE INTO monitoring_settings(id,enabled,interval_sec,retention_days,last_status)
          VALUES(1,1,60,90,'Chưa chạy');
        CREATE TABLE IF NOT EXISTS restore_history(
          id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, device_id INTEGER,
          backup_id INTEGER, status TEXT, detail TEXT, created_at TEXT);
        ''')
        c.commit()
    finally:c.close()


def audit(username, role, action, target='', detail=''):
    ensure_v6_tables(); c=_connect()
    try:
        c.execute('INSERT INTO audit_log(username,role,action,target,detail,created_at) VALUES(?,?,?,?,?,?)',
                  (username or 'local-admin',role or 'Admin',action,target,detail,_now())); c.commit()
    finally:c.close()


def _ping_windows(host, count=2, timeout_ms=1000):
    from modules.icmp_probe import icmp_ping
    r = icmp_ping(host, timeout_ms, count)
    if r['status'] == 'Error':
        raise RuntimeError(r['error'])
    return r['response'], r['packet_loss'], r['status'] == 'Online'


class MonitoringService:
    """Collector nền nhẹ: ping các network_devices, lưu health_samples, đánh giá rule, dọn lịch sử."""
    def __init__(self, root, activity=None):
        ensure_v6_tables(); self.root=root; self.activity=activity or (lambda m:None); self.stop_event=threading.Event(); self.thread=None
        self.start_if_enabled()
    def settings(self):
        c=_connect(); r=c.execute('SELECT * FROM monitoring_settings WHERE id=1').fetchone(); c.close(); return dict(r)
    def start_if_enabled(self):
        if self.settings()['enabled']: self.start()
    def start(self):
        if self.thread and self.thread.is_alive(): return
        self.stop_event.clear(); self.thread=threading.Thread(target=self._loop,daemon=True,name='NMS-Monitoring'); self.thread.start()
    def stop(self): self.stop_event.set()
    def _loop(self):
        while not self.stop_event.is_set():
            s=self.settings(); interval=max(15,int(s['interval_sec'] or 60))
            if not s['enabled']: return
            try:self.collect_once(int(s['retention_days'] or 90))
            except Exception as e:self._set_status('Lỗi: '+str(e))
            self.stop_event.wait(interval)
    def _set_status(self,status):
        c=_connect(); c.execute('UPDATE monitoring_settings SET last_run=?,last_status=? WHERE id=1',(_now(),status)); c.commit(); c.close()
    def collect_once(self,retention=90):
        c=_connect(); rows=c.execute("SELECT id,name,ip FROM network_devices WHERE ip IS NOT NULL AND TRIM(ip)<>''").fetchall(); c.close()
        ok=0
        for r in rows:
            if self.stop_event.is_set(): break
            try:
                lat,loss,alive=_ping_windows(r['ip']); c=_connect();
                c.execute('INSERT INTO health_samples(host,latency_ms,packet_loss,created_at) VALUES(?,?,?,?)',(r['ip'],lat,loss,_now()))
                c.commit(); c.close()
                try:
                    from modules.nms_v11 import record_ping_result
                    record_ping_result(r['id'], alive)
                except Exception:
                    c=_connect(); c.execute('UPDATE network_devices SET status=? WHERE id=?',('Online' if alive else 'Offline',r['id'])); c.commit(); c.close()
                ok+=1
            except Exception: pass
        # Alert rules use the newly collected ping metrics.
        try:
            from modules.nms_v4 import evaluate_alert_rules
            evaluate_alert_rules()
        except Exception: pass
        cutoff=(datetime.now()-timedelta(days=max(1,retention))).strftime('%Y-%m-%d %H:%M:%S'); c=_connect()
        for table in ('health_samples','interface_samples','snmp_samples'):
            try:c.execute(f'DELETE FROM {table} WHERE created_at < ?',(cutoff,))
            except sqlite3.Error:pass
        c.commit(); c.close(); self._set_status(f'OK - {ok}/{len(rows)} thiết bị');


class MonitoringServicePage:
    def __init__(self,parent,service,session_user):
        ensure_v6_tables(); self.parent=parent; self.service=service; self.user=session_user
        s=service.settings(); self.enabled=tk.BooleanVar(value=bool(s['enabled'])); self.interval=tk.IntVar(value=s['interval_sec'] or 60); self.retention=tk.IntVar(value=s['retention_days'] or 90); self.status=tk.StringVar(); self._build(); self.refresh()
    def _build(self):
        f=tk.LabelFrame(self.parent,text='Dịch vụ giám sát nền',bg=UI_COLORS['background']); f.pack(fill='x',padx=25,pady=(0,10))
        tk.Checkbutton(f,text='Bật giám sát nền',variable=self.enabled,bg=UI_COLORS['background']).grid(row=0,column=0,padx=10,pady=10,sticky='w')
        tk.Label(f,text='Chu kỳ (giây)',bg=UI_COLORS['background']).grid(row=0,column=1); tk.Spinbox(f,from_=15,to=3600,textvariable=self.interval,width=8).grid(row=0,column=2,padx=5)
        tk.Label(f,text='Giữ lịch sử (ngày)',bg=UI_COLORS['background']).grid(row=0,column=3); tk.Spinbox(f,from_=1,to=3650,textvariable=self.retention,width=8).grid(row=0,column=4,padx=5)
        tk.Button(f,text='Lưu cấu hình',command=self.save,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').grid(row=0,column=5,padx=8)
        tk.Button(f,text='Chạy một lần',command=self.run_once,relief='flat').grid(row=0,column=6,padx=4)
        tk.Label(self.parent,textvariable=self.status,bg=UI_COLORS['background'],justify='left',anchor='w').pack(fill='x',padx=25,pady=8)
    def refresh(self):
        s=self.service.settings(); alive=bool(self.service.thread and self.service.thread.is_alive()); self.status.set(f"Trạng thái worker: {'ĐANG CHẠY' if alive else 'DỪNG'}\nLần chạy gần nhất: {s['last_run'] or '-'}\nKết quả: {s['last_status'] or '-'}")
        self.parent.after(3000,self.refresh)
    def save(self):
        iv=max(15,int(self.interval.get())); rt=max(1,int(self.retention.get())); c=_connect(); c.execute('UPDATE monitoring_settings SET enabled=?,interval_sec=?,retention_days=? WHERE id=1',(1 if self.enabled.get() else 0,iv,rt)); c.commit(); c.close()
        if self.enabled.get(): self.service.start()
        else:self.service.stop()
        audit(self.user.get('username'),self.user.get('role'),'Cập nhật monitoring','Monitoring Service',f'enabled={self.enabled.get()}, interval={iv}, retention={rt}')
        messagebox.showinfo('Giám sát nền','Đã lưu cấu hình.')
    def run_once(self):
        def w():
            try:self.service.collect_once(max(1,int(self.retention.get())))
            except Exception as e:self.parent.after(0,lambda m=str(e):messagebox.showerror('Giám sát nền',m))
        threading.Thread(target=w,daemon=True).start()


class AuditLogPage:
    def __init__(self,parent,session_user=None): ensure_v6_tables(); self.parent=parent; self.session=session_user or {}; self.q=tk.StringVar(); self._build(); self.refresh()
    def _build(self):
        f=tk.Frame(self.parent,bg=UI_COLORS['background']); f.pack(fill='x',padx=25,pady=(0,8)); tk.Entry(f,textvariable=self.q,width=35).pack(side='left'); tk.Button(f,text='Tìm',command=self.refresh).pack(side='left',padx=5); tk.Button(f,text='Làm mới',command=self.refresh).pack(side='left')
        b=tk.Frame(self.parent,bg=UI_COLORS['surface']); b.pack(fill='both',expand=True,padx=25,pady=(0,10)); cols=('time','user','role','action','target','detail'); self.t=ttk.Treeview(b,columns=cols,show='headings')
        for c,h,w in [('time','Thời gian',150),('user','Người dùng',120),('role','Quyền',80),('action','Hành động',180),('target','Đối tượng',160),('detail','Chi tiết',420)]:self.t.heading(c,text=h);self.t.column(c,width=w,anchor='w')
        b.columnconfigure(0,weight=1); b.rowconfigure(0,weight=1); self.t.grid(row=0,column=0,sticky='nsew')
        ys=ttk.Scrollbar(b,orient='vertical',command=self.t.yview); ys.grid(row=0,column=1,sticky='ns')
        xs=ttk.Scrollbar(b,orient='horizontal',command=self.t.xview); xs.grid(row=1,column=0,sticky='ew'); self.t.configure(yscrollcommand=ys.set,xscrollcommand=xs.set)
    def refresh(self):
        for x in self.t.get_children():self.t.delete(x)
        from modules.accounts import activity_rows
        try: rows=activity_rows(self.session,self.q.get())
        except ValueError as exc:
            messagebox.showwarning('Nhật ký hoạt động',str(exc),parent=self.parent); return
        for r in rows:self.t.insert('','end',values=(r['created_at'],r['username'],r['role'],r['action'],r['target'],r['detail']))


class RestoreConfigPage:
    """Khôi phục có kiểm soát: xem backup, tạo safety backup, rồi gửi config qua SSH shell."""
    def __init__(self,parent,session_user): self.parent=parent; self.user=session_user; ensure_v6_tables(); self._build(); self.refresh()
    def _build(self):
        b=tk.Frame(self.parent,bg=UI_COLORS['surface']);b.pack(fill='both',expand=True,padx=25,pady=(0,10)); cols=('id','device','source','file','time');self.t=ttk.Treeview(b,columns=cols,show='headings',height=12)
        for c,h,w in [('id','ID',50),('device','Thiết bị',170),('source','Nguồn',120),('file','File',500),('time','Thời gian',150)]:self.t.heading(c,text=h);self.t.column(c,width=w,anchor='w')
        self.t.pack(fill='both',expand=True); f=tk.Frame(self.parent,bg=UI_COLORS['background']);f.pack(fill='x',padx=25,pady=(0,10));tk.Button(f,text='Xem nội dung',command=self.preview).pack(side='left');tk.Button(f,text='Khôi phục qua SSH',command=self.restore,bg=UI_COLORS['danger_bg'],fg=UI_COLORS['text'],relief='flat').pack(side='left',padx=8)
        tk.Label(f,text='Chỉ Admin. Hệ thống sẽ sao lưu cấu hình hiện tại trước khi gửi bản khôi phục.',bg=UI_COLORS['background']).pack(side='left',padx=8)
    def refresh(self):
        for x in self.t.get_children():self.t.delete(x)
        c=_connect();rows=c.execute('SELECT * FROM config_backups ORDER BY id DESC LIMIT 500').fetchall();c.close()
        for r in rows:self.t.insert('','end',values=(r['id'],r['device_name'],r['source'],r['file_path'],r['created_at']))
    def _row(self):
        s=self.t.selection();
        if not s:return None
        return self.t.item(s[0])['values']
    def preview(self):
        r=self._row();
        if not r:return
        p=Path(str(r[3]));
        if not p.exists():messagebox.showerror('Backup','Không tìm thấy file backup.');return
        w=tk.Toplevel(self.parent);w.title('Xem backup');tx=tk.Text(w,wrap='none');tx.pack(fill='both',expand=True);tx.insert('1.0',p.read_text(encoding='utf-8',errors='replace'));w.geometry('900x600')
    def restore(self):
        if self.user.get('role')!='Admin':messagebox.showerror('Phân quyền','Chỉ Admin được khôi phục cấu hình.');return
        r=self._row();
        if not r:return
        if not messagebox.askyesno('XÁC NHẬN KHÔI PHỤC','Thao tác này có thể làm thay đổi kết nối thiết bị.\n\nHệ thống sẽ tạo backup an toàn trước. Bạn chắc chắn tiếp tục?'):return
        backup_id=int(r[0]); path=Path(str(r[3])); devname=str(r[1])
        if not path.exists():messagebox.showerror('Backup','Không tìm thấy file backup.');return
        c=_connect(); d=c.execute('SELECT * FROM network_devices WHERE name=? ORDER BY id LIMIT 1',(devname,)).fetchone()
        if not d: c.close();messagebox.showerror('Khôi phục','Không tìm thấy thiết bị tương ứng trong Thiết bị mạng.');return
        cred=c.execute("SELECT cr.* FROM device_credentials dc JOIN credentials cr ON cr.id=dc.credential_id WHERE dc.device_id=? AND dc.purpose IN ('SSH','Backup') ORDER BY CASE dc.purpose WHEN 'Backup' THEN 0 ELSE 1 END LIMIT 1",(d['id'],)).fetchone(); c.close()
        if not cred:messagebox.showerror('Khôi phục','Thiết bị chưa được gán Credential SSH/Backup.');return
        def work():
            status='Failed';detail=''
            try:
                from modules.nms_v5 import ssh_backup, decrypt_secret
                safety=ssh_backup(dict(d),dict(cred),'show running-config')
                import paramiko
                cli=build_strict_ssh_client(paramiko);cli.connect(d['ip'],port=int(cred['port'] or 22),username=cred['username'],password=decrypt_secret(cred['secret_enc']),timeout=10,look_for_keys=False,allow_agent=False)
                sh=cli.invoke_shell();time.sleep(.7);sh.send('configure terminal\n');time.sleep(.4)
                for line in path.read_text(encoding='utf-8',errors='replace').splitlines():
                    line=line.strip('\r');
                    if line and not line.startswith(('!','Building configuration','Current configuration')):sh.send(line+'\n');time.sleep(.03)
                sh.send('end\nwrite memory\n');time.sleep(1);cli.close();status='Success';detail=f'Safety backup: {safety}'
            except Exception as e:detail=str(e)
            c=_connect();c.execute('INSERT INTO restore_history(username,device_id,backup_id,status,detail,created_at) VALUES(?,?,?,?,?,?)',(self.user.get('username'),d['id'],backup_id,status,detail,_now()));c.commit();c.close();audit(self.user.get('username'),self.user.get('role'),'Khôi phục cấu hình',devname,status+' - '+detail)
            self.parent.after(0,lambda:messagebox.showinfo('Khôi phục',('Hoàn tất. ' if status=='Success' else 'Thất bại. ')+detail))
        threading.Thread(target=work,daemon=True).start()

__all__=['ensure_v6_tables','audit','MonitoringService','MonitoringServicePage','AuditLogPage','RestoreConfigPage']
