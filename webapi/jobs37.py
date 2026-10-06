"""Bounded in-process worker with durable status. No arbitrary shell/command jobs."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import json
import logging
import threading
from fastapi import HTTPException
from webapi.runtime37 import connection, utcnow

LOGGER=logging.getLogger(__name__)

ROLES={'PING':('Admin','Operator'),'PING_ALL':('Admin','Operator'),'SERVER_CHECK':('Admin','Operator'),
       'SNMP':('Admin','Operator'),'SSH_TEST':('Admin','Operator'),'SCAN':('Admin',),'AUDIT':('Admin',),
       'CONFIG_BACKUP':('Admin',),'DB_BACKUP':('Admin',),'REPORT':('Admin','Operator'),
       'TOPOLOGY_DISCOVER':('Admin','Operator'),'WIFI_DIAG':('Admin','Operator'),'CAMERA_CHECK':('Admin','Operator'),
       'INCIDENT_SYNC':('Admin','Operator'),'RCA_ANALYZE':('Admin','Operator'),'LAN_PROBE':('Admin','Operator'),'RESTORE_CONFIG':('Admin',),'DAILY_AUDIT':('Admin','Operator')}

from webapi.workbench45 import EXTENDED_ROLES
ROLES.update(EXTENDED_ROLES)

def ensure_tables():
    with connection() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS web_jobs37(id INTEGER PRIMARY KEY,operation TEXT,actor_id INTEGER,actor TEXT,payload TEXT,status TEXT,done INTEGER DEFAULT 0,total INTEGER DEFAULT 0,result TEXT,error TEXT,cancel INTEGER DEFAULT 0,created_at TEXT,finished_at TEXT)''')

def _sync_schedule_status(jid:int,status:str)->None:
    """Best-effort mirror of a scheduled job state into the scheduler row.

    Direct/manual jobs do not have a matching schedule and are ignored.  A
    scheduler status must never be allowed to turn a successfully completed job
    into a failure, so auxiliary sync errors are logged instead of re-raised.
    """
    try:
        with connection() as c:
            exists=c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='web_schedules40'").fetchone()
            if exists:
                c.execute('UPDATE web_schedules40 SET last_status=?,updated_at=? WHERE last_job_id=?',(str(status)[:80],utcnow(),int(jid)))
    except Exception as exc:
        LOGGER.warning('Unable to sync scheduler status for job %s: %s',jid,type(exc).__name__)

class Engine:
    def __init__(self):
        self.pool=None; self.lock=threading.Lock(); self.stopping=threading.Event()
    def start(self):
        ensure_tables(); self.stopping.clear()
        with connection() as c:
            c.execute("UPDATE web_jobs37 SET status='Interrupted',error='Server stopped; not automatically retried',finished_at=? WHERE status IN ('Queued','Running')",(utcnow(),))
        self.pool=ThreadPoolExecutor(max_workers=2,thread_name_prefix='Web-Job')
    def stop(self):
        self.stopping.set()
        if self.pool: self.pool.shutdown(wait=True,cancel_futures=True);self.pool=None
        with connection() as c:
            c.execute("UPDATE web_jobs37 SET status='Interrupted',finished_at=? WHERE status IN ('Queued','Running')",(utcnow(),))
    def submit(self,operation,payload,user):
        if operation not in ROLES or user['role'] not in ROLES[operation]: raise HTTPException(403,'TASK_PERMISSION_DENIED')
        if self.pool is None: raise HTTPException(503,'Worker not ready')
        safe=json.dumps(payload,sort_keys=True)
        with self.lock, connection() as c:
            c.execute('BEGIN IMMEDIATE')
            if c.execute("SELECT COUNT(*) FROM web_jobs37 WHERE status IN ('Queued','Running')").fetchone()[0]>=16: raise HTTPException(429,'JOB_QUEUE_FULL')
            old=c.execute("SELECT id FROM web_jobs37 WHERE operation=? AND payload=? AND status IN ('Queued','Running')",(operation,safe)).fetchone()
            if old: raise HTTPException(409,'Equivalent task is already running')
            cur=c.execute("INSERT INTO web_jobs37(operation,actor_id,actor,payload,status,created_at) VALUES(?,?,?,?,?,?)",(operation,user['id'],user['username'],safe,'Queued',utcnow())); jid=cur.lastrowid
        self.pool.submit(self.run,jid)
        return {'id':jid,'status':'Queued'}
    def cancelled(self,jid):
        with connection() as c:
            r=c.execute('SELECT cancel FROM web_jobs37 WHERE id=?',(jid,)).fetchone()
        return self.stopping.is_set() or not r or bool(r['cancel'])
    def update(self,jid,**fields):
        with connection() as c:
            c.execute('UPDATE web_jobs37 SET '+','.join(k+'=?' for k in fields)+' WHERE id=?',list(fields.values())+[jid])
        if 'status' in fields:
            _sync_schedule_status(jid,fields['status'])
    def run(self,jid):
        try:
            with connection() as c:
                job=dict(c.execute('SELECT * FROM web_jobs37 WHERE id=?',(jid,)).fetchone())
                user=c.execute('SELECT role,enabled FROM app_users WHERE id=?',(job['actor_id'],)).fetchone()
                if not user or not user['enabled'] or user['role'] not in ROLES[job['operation']]: raise RuntimeError('Permission revoked before execution')
            if self.cancelled(jid): self.update(jid,status='Cancelled',finished_at=utcnow());return
            self.update(jid,status='Running')
            from webapi import main as m
            from webapi.reports37 import export_report,backup_db
            op=job['operation']; p=json.loads(job['payload']); result=[]
            if op=='PING_ALL':
                ids=[d['id'] for d in m.manager.get_devices()]
                if len(ids)>2048:
                    raise HTTPException(400,'More than 2048 devices: use the Ping monitor to select a bounded target list')
            else: ids=p.get('device_ids',[])
            if op in ('PING','PING_ALL','SNMP','SSH_TEST','AUDIT','CONFIG_BACKUP'):
                self.update(jid,total=len(ids))
                for did in ids:
                    if self.cancelled(jid): break
                    try:
                        if op.startswith('PING'): r=m.ping_device(did)
                        elif op=='SNMP': r=m.api_snmp_refresh(did)
                        elif op=='SSH_TEST': r=m._ssh_test_one(did)
                        elif op=='AUDIT': r=m.api_run_ssh_audit(did,m.AuditIn())
                        else: r=m.api_config_backup(did,m.BackupIn())
                        result.append({'device_id':did,'result':r,'success':r.get('success',r.get('status') not in ('Unknown','Error'))})
                    except HTTPException as e: result.append({'device_id':did,'success':False,'detail':str(e.detail)[:300]})
                    except Exception as e: result.append({'device_id':did,'success':False,'detail':type(e).__name__})
                    self.update(jid,done=len(result))
            elif op in EXTENDED_ROLES:
                from webapi.workbench45 import execute_extended
                actor={'id':job['actor_id'],'username':job['actor'],'role':user['role']}
                result=execute_extended(op,p,actor,lambda **fields:self.update(jid,**fields),lambda:self.cancelled(jid))
            elif op=='SCAN':
                class _CancelProxy:
                    def is_set(_self):
                        return self.cancelled(jid)
                progress={'done':0,'total':0}
                def on_scan(event):
                    if event.get('event')=='total':
                        progress['total']=int(event.get('total') or 0); self.update(jid,total=progress['total'])
                    elif event.get('event')=='completed':
                        progress['done']+=1; self.update(jid,done=progress['done'])
                r=m._run_scan(p['network'],16,800,callback=on_scan,stop_event=_CancelProxy())
                result=r
            elif op=='SERVER_CHECK':
                result=m.run_server_monitor()
            elif op=='DB_BACKUP': result=backup_db(job['actor_id'])
            elif op=='REPORT': result=export_report(job['actor_id'])
            elif op=='TOPOLOGY_DISCOVER':
                from webapi.ops40 import discover_topology
                result=discover_topology(p.get('device_ids') or None)
            elif op=='WIFI_DIAG':
                from webapi.ops40 import run_wifi_diag
                prm=p.get('parameters') or {}; result=run_wifi_diag(str(prm.get('gateway') or ''),str(prm.get('internet') or '1.1.1.1'))
            elif op=='CAMERA_CHECK':
                from webapi.ops40 import run_camera_check
                prm=p.get('parameters') or {}; result=run_camera_check(int(prm.get('camera_id') or 0))
            elif op=='INCIDENT_SYNC':
                from webapi.ops40 import sync_incidents_and_rca
                result=sync_incidents_and_rca()
            elif op=='RCA_ANALYZE':
                from modules.nms_v10 import analyze_root_causes
                result=analyze_root_causes()
            elif op=='LAN_PROBE':
                from webapi.lan42 import run_registered_probe
                result=run_registered_probe()
            elif op=='DAILY_AUDIT':
                from webapi.parity44 import run_daily_audit
                result=run_daily_audit()
            elif op=='RESTORE_CONFIG':
                from webapi.ops40 import execute_restore_job
                prm=p.get('parameters') or {}
                if len(p.get('device_ids') or [])!=1: raise RuntimeError('Restore requires exactly one managed device')
                actor={'id':job['actor_id'],'username':job['actor'],'role':user['role']}
                result=execute_restore_job(int(p['device_ids'][0]),int(prm.get('backup_id') or 0),str(prm.get('token') or ''),str(prm.get('confirmation') or ''),actor)
            failed=False
            if isinstance(result,list):
                failed=any(isinstance(x,dict) and x.get('success') is False for x in result)
            elif isinstance(result,dict):
                failed=result.get('success') is False or str(result.get('status') or '').lower() in {'failed','error','unreachable','invalid'}
            status='Cancelled' if self.cancelled(jid) else 'CompletedWithErrors' if failed else 'Completed'
            self.update(jid,status=status,result=json.dumps(result,ensure_ascii=True,default=str),finished_at=utcnow())
        except Exception as e:
            self.update(jid,status='Failed',error=str(e.detail)[:300] if isinstance(e,HTTPException) else type(e).__name__,finished_at=utcnow())

engine=Engine()
