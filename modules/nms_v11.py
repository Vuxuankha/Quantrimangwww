from __future__ import annotations
from modules.ui_ux_config import PALETTE as UI_COLORS
import os, queue, shutil, sqlite3, threading, time
from datetime import datetime, timedelta
from pathlib import Path
try:
    import tkinter as tk
except (ImportError, ModuleNotFoundError):
    tk = None
try:
    from tkinter import ttk, messagebox, filedialog
except (ImportError, ModuleNotFoundError):
    ttk = messagebox = filedialog = None

from database.db import DB_PATH, database_health as db_database_health, optimize_database
from modules.advanced_pages import _connect, _now
from modules.nms_v10 import ensure_v10_tables


def ensure_v11_tables():
    ensure_v10_tables(); c=_connect()
    try:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS core_settings(
          id INTEGER PRIMARY KEY CHECK(id=1), worker_count INTEGER DEFAULT 4,
          retry_count INTEGER DEFAULT 3, retry_delay_sec REAL DEFAULT 1,
          offline_failures INTEGER DEFAULT 3, online_successes INTEGER DEFAULT 2,
          db_backup_enabled INTEGER DEFAULT 1, db_backup_keep INTEGER DEFAULT 10,
          updated_at TEXT);
        INSERT OR IGNORE INTO core_settings(id,updated_at) VALUES(1,datetime('now','localtime'));
        CREATE TABLE IF NOT EXISTS device_health_state(
          device_id INTEGER PRIMARY KEY, consecutive_failures INTEGER DEFAULT 0,
          consecutive_successes INTEGER DEFAULT 0, effective_status TEXT DEFAULT 'Unknown',
          last_error TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS worker_jobs(
          id INTEGER PRIMARY KEY AUTOINCREMENT, job_type TEXT, target TEXT, status TEXT,
          attempts INTEGER DEFAULT 0, detail TEXT, created_at TEXT, started_at TEXT, finished_at TEXT);
        CREATE TABLE IF NOT EXISTS system_health_history(
          id INTEGER PRIMARY KEY AUTOINCREMENT, component TEXT, status TEXT, detail TEXT, created_at TEXT);
        CREATE INDEX IF NOT EXISTS idx_worker_jobs_status ON worker_jobs(status,created_at);
        CREATE INDEX IF NOT EXISTS idx_health_history_time ON system_health_history(created_at);
        '''); c.commit()
    finally: c.close()


def core_settings():
    ensure_v11_tables(); c=_connect(); r=c.execute('SELECT * FROM core_settings WHERE id=1').fetchone(); c.close(); return dict(r)


def record_ping_result(device_id:int, alive:bool, error=''):
    """Debounce trạng thái: chỉ Offline/Online sau N kết quả liên tiếp."""
    s=core_settings(); c=_connect()
    try:
        r=c.execute('SELECT * FROM device_health_state WHERE device_id=?',(device_id,)).fetchone()
        fail=(r['consecutive_failures'] if r else 0); ok=(r['consecutive_successes'] if r else 0)
        eff=(r['effective_status'] if r else 'Unknown')
        if alive:
            ok+=1; fail=0
            if ok>=max(1,int(s['online_successes'])): eff='Online'
        else:
            fail+=1; ok=0
            if fail>=max(1,int(s['offline_failures'])): eff='Offline'
        c.execute('''INSERT INTO device_health_state(device_id,consecutive_failures,consecutive_successes,effective_status,last_error,last_check)
                     VALUES(?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET consecutive_failures=excluded.consecutive_failures,
                     consecutive_successes=excluded.consecutive_successes,effective_status=excluded.effective_status,last_error=excluded.last_error,last_check=excluded.last_check''',
                  (device_id,fail,ok,eff,error,_now()))
        if eff in ('Online','Offline'): c.execute('UPDATE network_devices SET status=? WHERE id=?',(eff,device_id))
        c.commit(); return eff,fail,ok
    finally: c.close()


class JobQueueEngine:
    """Worker pool dùng chung cho tác vụ mạng; retry/backoff và lịch sử job."""
    def __init__(self, workers=None):
        ensure_v11_tables(); self.q=queue.Queue(); self.stop_event=threading.Event(); self.threads=[]
        self.workers=max(1,int(workers or core_settings()['worker_count'] or 4)); self.start()
    def start(self):
        if self.threads: return
        for i in range(self.workers):
            t=threading.Thread(target=self._worker,daemon=True,name=f'NMS-Worker-{i+1}'); t.start(); self.threads.append(t)
    def submit(self, job_type, target, fn, *args, retries=None, **kwargs):
        c=_connect(); cur=c.execute("INSERT INTO worker_jobs(job_type,target,status,created_at) VALUES(?,?,'Queued',?)",(job_type,target,_now())); jid=cur.lastrowid; c.commit(); c.close()
        self.q.put((jid,job_type,target,fn,args,kwargs,retries)); return jid
    def _worker(self):
        while not self.stop_event.is_set():
            try: item=self.q.get(timeout=.5)
            except queue.Empty: continue
            jid,jtype,target,fn,args,kwargs,retries=item; s=core_settings(); max_try=max(1,int(retries if retries is not None else s['retry_count']))
            c=_connect(); c.execute("UPDATE worker_jobs SET status='Running',started_at=? WHERE id=?",(_now(),jid)); c.commit(); c.close(); err=''
            for attempt in range(1,max_try+1):
                try:
                    result=fn(*args,**kwargs); c=_connect(); c.execute("UPDATE worker_jobs SET status='Success',attempts=?,detail=?,finished_at=? WHERE id=?",(attempt,str(result)[:1000],_now(),jid)); c.commit(); c.close(); break
                except Exception as e:
                    err=str(e)
                    if attempt<max_try: time.sleep(min(30,float(s['retry_delay_sec'] or 1)*(2**(attempt-1))))
            else:
                c=_connect(); c.execute("UPDATE worker_jobs SET status='Failed',attempts=?,detail=?,finished_at=? WHERE id=?",(max_try,err[:1000],_now(),jid)); c.commit(); c.close()
            self.q.task_done()
    def stop(self): self.stop_event.set()
    def stats(self):
        c=_connect(); rows=c.execute("SELECT status,COUNT(*) n FROM worker_jobs GROUP BY status").fetchall(); c.close(); d={r['status']:r['n'] for r in rows}; d['queue']=self.q.qsize(); d['workers_alive']=sum(t.is_alive() for t in self.threads); return d


def database_health():
    try:
        h=db_database_health()
        status='OK' if h['quick_check']=='ok' else 'Lỗi'
        detail=(f"quick_check={h['quick_check']}; WAL={h['journal_mode']}; "
                f"schema=v{h['schema_version']}; indexes={h['indexes']}; "
                f"size={h['db_size_bytes']/1024/1024:.1f} MB")
        return status,detail
    except Exception as e: return 'Lỗi',str(e)


def backup_database(dest_dir=None):
    ensure_v11_tables(); base=Path(dest_dir or (Path(DB_PATH).parent/'db_backups')); base.mkdir(parents=True,exist_ok=True)
    out=base/f"network_automation_{datetime.now():%Y%m%d_%H%M%S}.db"; src=sqlite3.connect(DB_PATH); dst=sqlite3.connect(out)
    try: src.backup(dst)
    finally: dst.close(); src.close()
    keep=max(1,int(core_settings()['db_backup_keep'] or 10)); files=sorted(base.glob('network_automation_*.db'),key=lambda p:p.stat().st_mtime,reverse=True)
    for p in files[keep:]: p.unlink(missing_ok=True)
    return str(out)


def vacuum_database():
    optimize_database(vacuum=True); return True


def system_health(worker=None):
    ensure_v11_tables(); checks=[]
    dbs,dbd=database_health(); checks.append(('Database',dbs,dbd))
    if worker:
        st=worker.stats(); checks.append(('Worker','OK' if st['workers_alive'] else 'Lỗi',f"{st['workers_alive']} worker; queue={st['queue']}"))
    c=_connect()
    try:
        dev=c.execute('SELECT COUNT(*) n FROM network_devices').fetchone()['n']; off=c.execute("SELECT COUNT(*) n FROM network_devices WHERE status='Offline'").fetchone()['n']
        checks.append(('Thiết bị','OK',f'{dev} thiết bị; {off} Offline'))
        for comp,status,detail in checks: c.execute('INSERT INTO system_health_history(component,status,detail,created_at) VALUES(?,?,?,?)',(comp,status,detail,_now()))
        c.commit()
    finally:c.close()
    return checks


class StableCorePage:
    def __init__(self,parent,worker,session_user):
        ensure_v11_tables(); self.parent=parent; self.worker=worker; self.user=session_user; self._build(); self.refresh()
    def _build(self):
        top=tk.Frame(self.parent,bg=UI_COLORS['background']); top.pack(fill='x',padx=25,pady=(0,8))
        tk.Button(top,text='Kiểm tra hệ thống',command=self.refresh,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat').pack(side='left')
        tk.Button(top,text='Backup Database',command=self.backup).pack(side='left',padx=6); tk.Button(top,text='Tối ưu Database',command=self.vacuum).pack(side='left')
        self.summary=tk.StringVar(); tk.Label(top,textvariable=self.summary,bg=UI_COLORS['background']).pack(side='right')
        box=tk.Frame(self.parent,bg=UI_COLORS['surface']); box.pack(fill='both',expand=True,padx=25,pady=(0,10)); cols=('component','status','detail'); self.t=ttk.Treeview(box,columns=cols,show='headings')
        for c,h,w in [('component','Thành phần',200),('status','Trạng thái',120),('detail','Chi tiết',650)]: self.t.heading(c,text=h); self.t.column(c,width=w,anchor='w')
        self.t.pack(fill='both',expand=True)
        s=core_settings(); cfg=tk.LabelFrame(self.parent,text='Độ ổn định trạng thái',bg=UI_COLORS['background']); cfg.pack(fill='x',padx=25,pady=(0,10)); self.fail=tk.IntVar(value=s['offline_failures']); self.ok=tk.IntVar(value=s['online_successes']); self.retry=tk.IntVar(value=s['retry_count'])
        for i,(label,var) in enumerate([('Số lần lỗi để Offline',self.fail),('Số lần OK để Online',self.ok),('Retry job',self.retry)]): tk.Label(cfg,text=label,bg=UI_COLORS['background']).grid(row=0,column=i*2,padx=5,pady=8); tk.Spinbox(cfg,from_=1,to=10,textvariable=var,width=5).grid(row=0,column=i*2+1)
        tk.Button(cfg,text='Lưu',command=self.save).grid(row=0,column=6,padx=10)
    def refresh(self):
        for x in self.t.get_children(): self.t.delete(x)
        checks=system_health(self.worker)
        for r in checks:self.t.insert('','end',values=r)
        st=self.worker.stats(); self.summary.set(f"Worker: {st['workers_alive']} | Queue: {st['queue']} | Job lỗi: {st.get('Failed',0)}")
    def save(self):
        c=_connect(); c.execute('UPDATE core_settings SET offline_failures=?,online_successes=?,retry_count=?,updated_at=? WHERE id=1',(max(1,self.fail.get()),max(1,self.ok.get()),max(1,self.retry.get()),_now())); c.commit(); c.close(); messagebox.showinfo('Stable Core','Đã lưu cấu hình.')
    def backup(self):
        try: messagebox.showinfo('Backup Database','Đã tạo:\n'+backup_database())
        except Exception as e: messagebox.showerror('Backup Database',str(e))
    def vacuum(self):
        try: vacuum_database(); messagebox.showinfo('Database','Đã PRAGMA optimize + VACUUM.'); self.refresh()
        except Exception as e: messagebox.showerror('Database',str(e))


__all__=['ensure_v11_tables','core_settings','record_ping_result','JobQueueEngine','database_health','backup_database','vacuum_database','system_health','StableCorePage']
