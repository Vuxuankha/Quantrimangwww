import sqlite3, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from database.db import DB_PATH, init_database, get_connection
from modules.auto_config_audit import list_ssh_audit_devices, audit_device


def _conn():
    init_database(); c=get_connection()
    c.execute('''CREATE TABLE IF NOT EXISTS auto_audit_settings(
      id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER DEFAULT 0,
      run_time TEXT DEFAULT '02:00', max_workers INTEGER DEFAULT 3,
      command TEXT DEFAULT 'show running-config', last_run TEXT, next_run TEXT,
      last_status TEXT, updated_at TEXT)''')
    c.execute("INSERT OR IGNORE INTO auto_audit_settings(id,enabled,run_time,max_workers,command,updated_at) VALUES(1,0,'02:00',3,'show running-config',?)",(_now(),))
    c.execute('''CREATE TABLE IF NOT EXISTS auto_audit_runs(
      id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT, finished_at TEXT,
      total INTEGER, passed INTEGER, warned INTEGER, failed INTEGER, detail TEXT)''')
    c.commit(); return c

def _now(): return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def get_settings():
    c=_conn(); r=dict(c.execute('SELECT * FROM auto_audit_settings WHERE id=1').fetchone()); c.close(); return r

def save_settings(enabled, run_time, max_workers=3, command='show running-config'):
    datetime.strptime(run_time,'%H:%M'); max_workers=max(1,min(8,int(max_workers)))
    c=_conn(); c.execute('UPDATE auto_audit_settings SET enabled=?,run_time=?,max_workers=?,command=?,updated_at=? WHERE id=1',(1 if enabled else 0,run_time,max_workers,command.strip() or 'show running-config',_now())); c.commit(); c.close()

def _next_due(run_time, now=None):
    now=now or datetime.now(); h,m=map(int,run_time.split(':')); due=now.replace(hour=h,minute=m,second=0,microsecond=0)
    if due<=now: due+=timedelta(days=1)
    return due

def run_all(activity=None):
    activity=activity or (lambda x:None); s=get_settings(); devices=[d for d in list_ssh_audit_devices() if d.get('credential_id')]
    started=_now(); ok=warn=fail=0; details=[]
    def one(d): return d,audit_device(d['id'],s.get('command') or 'show running-config',True)
    with ThreadPoolExecutor(max_workers=max(1,min(8,int(s.get('max_workers') or 3)))) as ex:
        futs=[ex.submit(one,d) for d in devices]
        for f in as_completed(futs):
            try:
                d,r=f.result(); st=r['status']; details.append(f"{d.get('name') or d['ip']}: {st} - {r['detail']}")
                if st=='PASS': ok+=1
                else: warn+=1
            except Exception as e: fail+=1; details.append('ERROR: '+str(e))
    finished=_now(); status=f'Hoàn tất: {len(devices)} thiết bị, PASS {ok}, cần chú ý {warn}, lỗi {fail}'
    c=_conn(); c.execute('INSERT INTO auto_audit_runs(started_at,finished_at,total,passed,warned,failed,detail) VALUES(?,?,?,?,?,?,?)',(started,finished,len(devices),ok,warn,fail,'\n'.join(details)[:12000])); c.execute('UPDATE auto_audit_settings SET last_run=?,last_status=? WHERE id=1',(finished,status)); c.commit(); c.close(); activity('Auto Audit Scheduler: '+status); return status

class AutoAuditSchedulerEngine:
    def __init__(self, root, activity=None):
        self.root=root; self.activity=activity or (lambda x:None); self.running=True; self.busy=False; self.thread=None; self.job=None; self._tick()
    def stop(self):
        self.running=False
        if self.job:
            try:self.root.after_cancel(self.job)
            except Exception:pass
            self.job=None
    def _tick(self):
        if not self.running:return
        try:
            s=get_settings(); now=datetime.now(); due=_next_due(s['run_time'],now)
            c=_conn(); c.execute('UPDATE auto_audit_settings SET next_run=? WHERE id=1',(due.strftime('%Y-%m-%d %H:%M:%S'),)); c.commit(); c.close()
            if s['enabled'] and not self.busy:
                last=s.get('last_run'); h,m=map(int,s['run_time'].split(':')); today=now.replace(hour=h,minute=m,second=0,microsecond=0)
                last_dt=datetime.strptime(last,'%Y-%m-%d %H:%M:%S') if last else None
                if now>=today and (not last_dt or last_dt<today):
                    self.busy=True
                    def work():
                        try: run_all(self.activity)
                        finally: self.busy=False
                    self.thread=threading.Thread(target=work,daemon=True);self.thread.start()
        except Exception as e: self.activity('Auto Audit Scheduler lỗi: '+str(e))
        if self.running:self.job=self.root.after(60000,self._tick)
