from __future__ import annotations
import json, threading, time
from fastapi import HTTPException
from webapi.runtime37 import connection, utcnow

class Scheduler40:
    def __init__(self):
        self.stop_event=threading.Event();self.thread=None
    def start(self):
        if self.thread and self.thread.is_alive(): return
        self.stop_event.clear();self.thread=threading.Thread(target=self.loop,name='Web-Scheduler40',daemon=True);self.thread.start()
    def stop(self):
        self.stop_event.set()
        if self.thread:self.thread.join(timeout=5)
        self.thread=None
    def loop(self):
        while not self.stop_event.wait(10):
            try:self.tick()
            except Exception:pass
    def tick(self):
        now=time.time()
        with connection() as c:
            due=[dict(r) for r in c.execute('SELECT * FROM web_schedules40 WHERE enabled=1 AND COALESCE(next_epoch,0)<=? ORDER BY id LIMIT 8',(now,))]
            for r in due:
                # Claim next run before submission so another tick cannot double submit.
                c.execute('UPDATE web_schedules40 SET next_epoch=?,updated_at=? WHERE id=?',(now+max(1,int(r['interval_minutes']))*60,utcnow(),r['id']))
        for r in due:
            try:
                with connection() as c:u=c.execute('SELECT id,username,role,enabled FROM app_users WHERE id=?',(r['actor_id'],)).fetchone()
                if not u or not u['enabled']:raise RuntimeError('Schedule owner disabled')
                submit_schedule(r['id'],dict(u),manual=False)
            except Exception as exc:
                status=(str(exc.detail) if isinstance(exc,HTTPException) else type(exc).__name__)[:80]
                with connection() as c:c.execute('UPDATE web_schedules40 SET last_run=?,last_status=? WHERE id=?',(utcnow(),status,r['id']))


def submit_schedule(sid,user,manual=False):
    from webapi.jobs37 import engine,ROLES
    with connection() as c:r=c.execute('SELECT * FROM web_schedules40 WHERE id=?',(sid,)).fetchone()
    if not r: raise HTTPException(404,'Schedule not found')
    r=dict(r);op=r['operation']
    if user['role'] not in ROLES.get(op,()): raise HTTPException(403,'TASK_PERMISSION_DENIED')
    payload={'device_ids':json.loads(r['device_ids_json'] or '[]'),'network':r['network'] or '','parameters':json.loads(r['parameters_json'] or '{}')}
    out=engine.submit(op,payload,user)
    # Link the schedule to the durable job immediately.  The worker can finish
    # very quickly (for example DB_BACKUP), so link first and then re-read the
    # job status to close the submit-vs-worker race.
    with connection() as c:
        if manual:
            c.execute('UPDATE web_schedules40 SET last_run=?,last_status=?,last_job_id=?,next_epoch=?,updated_at=? WHERE id=?',
                      (utcnow(),'Queued',out['id'],time.time()+max(1,int(r['interval_minutes']))*60,utcnow(),sid))
        else:
            c.execute('UPDATE web_schedules40 SET last_run=?,last_status=?,last_job_id=?,updated_at=? WHERE id=?',
                      (utcnow(),'Queued',out['id'],utcnow(),sid))
    with connection() as c:
        current=c.execute('SELECT status FROM web_jobs37 WHERE id=?',(out['id'],)).fetchone()
        if current:
            c.execute('UPDATE web_schedules40 SET last_status=?,updated_at=? WHERE id=?',(current['status'],utcnow(),sid))
    return out

scheduler=Scheduler40()
