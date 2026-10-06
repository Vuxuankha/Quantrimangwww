"""Operations 4.7: explicit observations, device workspace and guarded workflows.

No discovery, device writes or external notifications are initiated by reading a
page. New ping events are a local inbox; they do not change legacy alert rules.
"""
from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
import hashlib
import importlib.metadata
import importlib.util
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import threading
import time

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from webapi.runtime37 import VERSION, connection, utcnow
from webapi import security37
from webapi.data37 import columns, ip_value, merged_devices, stamp

router = APIRouter(prefix='/api/v47')
BOOT_ID = secrets.token_hex(8)
BOOT_AT = utcnow()
BOOT_CLOCK = time.monotonic()
METRIC_LOCK = threading.Lock()
REQUESTS = deque(maxlen=200)
REQUEST_COUNTS = Counter()
PLAN_LOCK = threading.Lock()
security37.WRITE_RULES.extend([
    ('PUT', r'/api/v47/ping-policy', ('Admin',)),
    ('POST', r'/api/v47/inbox/\d+/ack', ('Admin', 'Operator')),
    ('POST', r'/api/v47/silences', ('Admin', 'Operator')),
    ('DELETE', r'/api/v47/silences/\d+', ('Admin', 'Operator')),
    ('POST', r'/api/v47/plans/(preview|execute)', ('Admin', 'Operator')),
])


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid')


class PingPolicy(Strict):
    enabled: bool = True
    failures: int = Field(default=3, ge=1, le=30)
    recoveries: int = Field(default=2, ge=1, le=30)
    cooldown_seconds: int = Field(default=300, ge=0, le=86400)


class SilenceIn(Strict):
    scope: Literal['ip', 'all'] = 'ip'
    ip: str = Field(default='', max_length=45)
    minutes: int = Field(default=60, ge=1, le=10080)
    reason: str = Field(min_length=3, max_length=240)

    @field_validator('ip')
    @classmethod
    def parse_ip(cls, value):
        return str(ipaddress.ip_address(value)) if value else ''


class PlanIn(Strict):
    operation: Literal['PING', 'SNMP', 'SSH_TEST', 'CONFIG_BACKUP']
    inventory_ids: list[int] = Field(min_length=1, max_length=2048)


class ExecuteIn(Strict):
    token: str = Field(min_length=30, max_length=120)
    authorized: bool = False


def ensure_tables():
    with connection() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS web_ops_settings47(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS web_ping_runs47(
          id TEXT PRIMARY KEY,actor_id INTEGER,state TEXT NOT NULL,started_at TEXT,finished_at TEXT,updated_at TEXT);
        CREATE TABLE IF NOT EXISTS web_ping_latest47(
          ip TEXT PRIMARY KEY,run_id TEXT NOT NULL,cycle INTEGER NOT NULL,status TEXT NOT NULL,observed_at TEXT);
        CREATE TABLE IF NOT EXISTS web_ping_signal47(
          ip TEXT PRIMARY KEY,bad INTEGER NOT NULL DEFAULT 0,good INTEGER NOT NULL DEFAULT 0,
          event_id INTEGER,last_open REAL NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS web_ping_events47(
          id INTEGER PRIMARY KEY,ip TEXT NOT NULL,kind TEXT NOT NULL DEFAULT 'NO_ICMP_REPLY',
          status TEXT NOT NULL DEFAULT 'open',first_at TEXT NOT NULL,last_at TEXT NOT NULL,
          recovered_at TEXT,occurrences INTEGER NOT NULL DEFAULT 1,
          acknowledged_at TEXT,acknowledged_by INTEGER,suppressed INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS ix_ping_events47_status ON web_ping_events47(status,id);
        CREATE INDEX IF NOT EXISTS ix_ping_events47_ip ON web_ping_events47(ip,id);
        CREATE TABLE IF NOT EXISTS web_silences47(
          id INTEGER PRIMARY KEY,scope TEXT NOT NULL,ip TEXT NOT NULL,reason TEXT NOT NULL,
          actor_id INTEGER NOT NULL,created_at TEXT NOT NULL,until_epoch REAL NOT NULL,cancelled INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS web_plans47(
          token_hash TEXT PRIMARY KEY,actor_id INTEGER NOT NULL,session_hash TEXT NOT NULL,
          operation TEXT NOT NULL,payload TEXT NOT NULL,expires REAL NOT NULL,consumed INTEGER NOT NULL DEFAULT 0);
        ''')
        c.execute('INSERT OR IGNORE INTO web_ops_settings47 VALUES(?,?)',
                  ('ping_policy', PingPolicy().model_dump_json()))
        c.execute('DELETE FROM web_plans47 WHERE expires<?', (time.time(),))


def policy(c):
    row = c.execute("SELECT value FROM web_ops_settings47 WHERE key='ping_policy'").fetchone()
    return PingPolicy.model_validate_json(row['value']) if row else PingPolicy()


def persist_ping(state, actor_id=None):
    if not state.get('run_id'):
        return
    with connection() as c:
        c.execute('''INSERT INTO web_ping_runs47(id,actor_id,state,started_at,finished_at,updated_at)
                     VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,
                     finished_at=excluded.finished_at,updated_at=excluded.updated_at''',
                  (state['run_id'], actor_id, json.dumps(state), state.get('started_at'),
                   state.get('finished_at'), utcnow()))


def recover_ping(coordinator):
    """A restart is Interrupted, never a successful run or an implicit restart."""
    with connection() as c:
        c.execute('UPDATE web_ping_signal47 SET bad=0,good=0')
        active = c.execute('SELECT * FROM web_ping_runs47 ORDER BY started_at DESC').fetchall()
        last = None
        for row in active:
            state = json.loads(row['state'])
            if state.get('running') or state.get('status') in ('Starting','Running','Waiting','Stopping'):
                state.update(status='Interrupted', running=False, next_run_at=None,
                             finished_at=utcnow(), message='SERVER_RESTARTED: run was not automatically replayed')
                c.execute('UPDATE web_ping_runs47 SET state=?,finished_at=?,updated_at=? WHERE id=?',
                          (json.dumps(state), state['finished_at'], utcnow(), row['id']))
                if last is None:
                    last = state
        if last:
            coordinator.state = last


def is_silenced(c, ip, now=None):
    now = time.time() if now is None else now
    return bool(c.execute('''SELECT 1 FROM web_silences47 WHERE cancelled=0 AND until_epoch>?
                          AND (scope='all' OR ip=?) LIMIT 1''', (now, ip)).fetchone())


def record_ping(result, run_id, cycle):
    """Record current-generation evidence and coalesce local ICMP alerts.

    Error/Unknown break consecutive-failure streaks. A failed local executable is
    never counted as a device-down observation. Suppression affects the local
    inbox only, not measurements or other collectors' notification policies.
    """
    ip, status = result['ip'], result.get('status', 'Unknown')
    at = result.get('observed_at') or utcnow()
    with connection() as c:
        c.execute('''INSERT INTO web_ping_latest47 VALUES(?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET
                     run_id=excluded.run_id,cycle=excluded.cycle,status=excluded.status,observed_at=excluded.observed_at''',
                  (ip, run_id, cycle, status, at))
        p = policy(c)
        if not p.enabled:
            return
        c.execute('INSERT OR IGNORE INTO web_ping_signal47(ip) VALUES(?)', (ip,))
        signal = dict(c.execute('SELECT * FROM web_ping_signal47 WHERE ip=?', (ip,)).fetchone())
        event = c.execute('SELECT * FROM web_ping_events47 WHERE id=? AND status=\'open\'', (signal['event_id'],)).fetchone()
        bad = signal['bad'] + 1 if status == 'Offline' else 0
        good = signal['good'] + 1 if status == 'Online' else 0
        event_id, last_open = signal['event_id'], signal['last_open']
        if event:
            if good >= p.recoveries:
                c.execute("UPDATE web_ping_events47 SET status='recovered',last_at=?,recovered_at=? WHERE id=?",
                          (at, at, event['id']))
                event_id = None
            elif status == 'Offline':
                c.execute('UPDATE web_ping_events47 SET occurrences=occurrences+1,last_at=?,suppressed=? WHERE id=?',
                          (at, int(is_silenced(c, ip)), event['id']))
        elif bad >= p.failures and time.time() - last_open >= p.cooldown_seconds:
            cur = c.execute('INSERT INTO web_ping_events47(ip,first_at,last_at,suppressed) VALUES(?,?,?,?)',
                            (ip, at, at, int(is_silenced(c, ip))))
            event_id, last_open = cur.lastrowid, time.time()
        c.execute('UPDATE web_ping_signal47 SET bad=?,good=?,event_id=?,last_open=? WHERE ip=?',
                  (bad, good, event_id, last_open, ip))


def enrich_ping(targets, state):
    with connection() as c:
        latest = {r['ip']: dict(r) for r in c.execute('SELECT * FROM web_ping_latest47')}
    counts = Counter()
    for target in targets:
        obs = latest.get(target['ip'], {})
        current = bool(state.get('run_id') and obs.get('run_id') == state['run_id'] and
                       obs.get('cycle') == state.get('cycle'))
        target['measurement_cycle'] = 'CURRENT' if current else 'PREVIOUS' if target.get('observed_at') else 'UNMEASURED'
        if current:
            counts[obs.get('status', 'Unknown')] += 1
    return {**{s: counts[s] for s in ('Online','Offline','Unknown','Error')},
            'Pending': max(0, int(state.get('total') or len(targets)) - sum(counts.values())),
            'measured': sum(counts.values()), 'scope': 'current_cycle',
            'run_id': state.get('run_id'), 'cycle': state.get('cycle', 0)}


@router.get('/ping-runs')
def ping_runs(request: Request):
    security37.require_role(request, 'Admin', 'Operator')
    with connection() as c:
        rows = c.execute('SELECT * FROM web_ping_runs47 ORDER BY started_at DESC LIMIT 50').fetchall()
    return [json.loads(r['state']) for r in rows]


@router.get('/ping-policy')
def get_policy(request: Request):
    security37.require_role(request)
    with connection() as c:
        return {**policy(c).model_dump(), 'scope': 'Web Ping monitor only; local inbox; no external messages'}


@router.put('/ping-policy')
def set_policy(x: PingPolicy, request: Request):
    security37.require_role(request, 'Admin')
    with connection() as c:
        c.execute("UPDATE web_ops_settings47 SET value=? WHERE key='ping_policy'", (x.model_dump_json(),))
        # Changing thresholds must not reinterpret old consecutive streaks.
        c.execute('UPDATE web_ping_signal47 SET bad=0,good=0')
    return {'success': True}


@router.get('/inbox')
def inbox(request: Request, view: Literal['active','all','open','recovered','unacknowledged','silenced']='open', limit: int=Query(200,ge=1,le=500)):
    security37.require_role(request)
    clauses = {'all': '1', 'open': "status='open'", 'recovered': "status='recovered'",
               'unacknowledged': "status='open' AND acknowledged_at IS NULL"}
    suppressed_sql = "EXISTS(SELECT 1 FROM web_silences47 s WHERE s.cancelled=0 AND s.until_epoch>? AND (s.scope='all' OR s.ip=web_ping_events47.ip))"
    clauses['active'] = "status='open' AND NOT " + suppressed_sql
    clauses['silenced'] = "status='open' AND " + suppressed_sql
    now=time.time()
    with connection() as c:
        args=(now,limit) if view in ('active','silenced') else (limit,)
        events = [dict(r) for r in c.execute('SELECT * FROM web_ping_events47 WHERE '+clauses[view]+' ORDER BY id DESC LIMIT ?', args)]
        for event in events:
            event['silenced_now'] = is_silenced(c, event['ip']) if event['status']=='open' else False
        summary = {r['status']:r['n'] for r in c.execute('SELECT status,COUNT(*) n FROM web_ping_events47 GROUP BY status')}
        unack = c.execute("SELECT COUNT(*) FROM web_ping_events47 WHERE status='open' AND acknowledged_at IS NULL AND NOT "+suppressed_sql,(now,)).fetchone()[0]
        silenced_open=c.execute("SELECT COUNT(*) FROM web_ping_events47 WHERE status='open' AND "+suppressed_sql,(now,)).fetchone()[0]
        silences = [dict(r) for r in c.execute('SELECT * FROM web_silences47 WHERE cancelled=0 AND until_epoch>? ORDER BY id DESC LIMIT 100', (time.time(),))]
    return {'events':events,'summary':summary,'unacknowledged':unack,'silences':silences,'silenced_open':silenced_open,
            'limit':limit,'scope':'WEB_PING_LOCAL_ONLY','observed_at':utcnow()}


@router.post('/inbox/{event_id}/ack')
def acknowledge(event_id:int, request:Request):
    user=security37.require_role(request,'Admin','Operator')
    with connection() as c:
        if not c.execute('SELECT 1 FROM web_ping_events47 WHERE id=?',(event_id,)).fetchone():
            raise HTTPException(404,'EVENT_NOT_FOUND')
        c.execute('UPDATE web_ping_events47 SET acknowledged_at=COALESCE(acknowledged_at,?),acknowledged_by=COALESCE(acknowledged_by,?) WHERE id=?', (utcnow(),user['id'],event_id))
    return {'success':True}


@router.post('/silences', status_code=201)
def silence(x:SilenceIn, request:Request):
    user=security37.require_role(request,'Admin','Operator')
    if x.scope=='all' and user['role']!='Admin':
        raise HTTPException(403,'ADMIN_REQUIRED_FOR_GLOBAL_SILENCE')
    if x.scope=='ip' and not x.ip:
        raise HTTPException(400,'IP_REQUIRED')
    if x.scope=='all' and x.ip:
        raise HTTPException(400,'GLOBAL_SILENCE_HAS_NO_IP')
    with connection() as c:
        if x.scope=='ip' and not c.execute('SELECT 1 FROM web_ping_targets45 WHERE ip=?',(x.ip,)).fetchone():
            raise HTTPException(404,'PING_TARGET_NOT_REGISTERED')
        cur=c.execute('INSERT INTO web_silences47(scope,ip,reason,actor_id,created_at,until_epoch) VALUES(?,?,?,?,?,?)',
                      (x.scope,x.ip,x.reason,user['id'],utcnow(),time.time()+60*x.minutes))
    return {'success':True,'id':cur.lastrowid,'scope':'WEB_PING_LOCAL_ONLY'}


@router.delete('/silences/{sid}')
def unsilence(sid:int, request:Request):
    user=security37.require_role(request,'Admin','Operator')
    with connection() as c:
        row=c.execute('SELECT * FROM web_silences47 WHERE id=?',(sid,)).fetchone()
        if not row: raise HTTPException(404,'SILENCE_NOT_FOUND')
        if user['role']!='Admin' and row['actor_id']!=user['id']:
            raise HTTPException(403,'CANNOT_CANCEL_ANOTHER_USERS_SILENCE')
        c.execute('UPDATE web_silences47 SET cancelled=1 WHERE id=?',(sid,))
    return {'success':True}


def safe_projection(c, table, fields, where='', args=(), limit=100):
    cols=columns(c,table)
    if not cols:return []
    selected=[f for f in fields if f in cols]
    if not selected:return []
    return [dict(r) for r in c.execute('SELECT '+','.join('"'+f+'"' for f in selected)+' FROM "'+table+'"'+
            (' WHERE '+where if where else '')+(' ORDER BY id DESC' if 'id' in cols else '')+' LIMIT ?', (*args,limit))]


def prerequisite(c, managed_id, host):
    if not managed_id:
        return {'managed':False,'ssh_assigned':False,'snmp_assigned':False,'host_key_trusted':False,'ssh_port':22}
    ssh=c.execute("SELECT cr.port FROM credentials cr JOIN device_credentials dc ON cr.id=dc.credential_id WHERE dc.device_id=? AND upper(dc.purpose)='SSH' LIMIT 1",(managed_id,)).fetchone()
    snmp=False
    for table in ('device_snmpv3_assignments','web_device_snmpv2_assignments42'):
        if columns(c,table) and c.execute('SELECT 1 FROM '+table+' WHERE device_id=?',(managed_id,)).fetchone():snmp=True
    if columns(c,'snmp_profiles') and c.execute('SELECT 1 FROM snmp_profiles WHERE host=? AND enabled=1',(host,)).fetchone():snmp=True
    port=int(ssh['port'] or 22) if ssh else 22
    trusted=False
    try:
        from app_runtime import DATABASE_DIR
        known=DATABASE_DIR/'known_hosts'
        if known.is_file():
            # Match a literal host token only; hashed keys remain unverified here.
            target=host if port==22 else f'[{host}]:{port}'
            trusted=any(target in line.split()[0].split(',') for line in known.read_text(encoding='utf-8').splitlines() if line.strip() and not line.startswith('#'))
    except (OSError,IndexError):pass
    return {'managed':True,'ssh_assigned':bool(ssh),'snmp_assigned':snmp,'host_key_trusted':trusted,'ssh_port':port}


@router.get('/devices/{inventory_id}')
def device_workspace(inventory_id:int, request:Request):
    user=security37.require_role(request)
    d=next((x for x in merged_devices() if x['id']==inventory_id),None)
    if d is None:raise HTTPException(404,'INVENTORY_DEVICE_NOT_FOUND')
    host=d['ip']; mid=d.get('managed_id')
    allowed={'id','ip','hostname','mac','status','observed_at','data_state','managed_id','identity_conflict',
             'observation_source','ping_ms','cpu','ram','health_fresh','last_ping_at','last_health_at','packet_loss','status_reason'}
    with connection() as c:
        prereq=prerequisite(c,mid,host)
        ping_cols=columns(c,'ping_results'); ip_col='ip' if 'ip' in ping_cols else 'ip_address'
        ping_rows=safe_projection(c,'ping_results',['id','status','response','response_ms','ping_time','created_at'],f'"{ip_col}"=?',(host,),120)
        health=safe_projection(c,'health_samples',['id','host','cpu','memory','ram','packet_loss','latency_ms','created_at'],'host=?',(host,),120)
        ports=safe_projection(c,'interface_samples',['id','ifindex','ifname','oper_status','speed_bps','in_errors','out_errors','created_at'],'host=?',(host,),100)
        ac=columns(c,'alerts'); aip='ip' if 'ip' in ac else 'ip_address'
        alerts=safe_projection(c,'alerts',['id','severity','message','status','created_at'],f'"{aip}"=?',(host,),50) if aip in ac else []
        events=safe_projection(c,'web_ping_events47',['id','kind','status','first_at','last_at','acknowledged_at'],'ip=?',(host,),50)
        backups=[]
        if user['role'] in ('Admin','Operator'):
            names=[host]
            if mid:
                m=c.execute('SELECT * FROM network_devices WHERE id=?',(mid,)).fetchone()
                m=dict(m) if m else {}
                name=m.get('name') or m.get('device_name')
                # Only a unique exact device label can associate older unkeyed backups.
                if name and 'name' in columns(c,'network_devices') and c.execute('SELECT COUNT(*) FROM network_devices WHERE name=?',(name,)).fetchone()[0]==1:names.append(name)
            backups=safe_projection(c,'config_backups',['id','device_name','source','size_bytes','created_at'],
                                    'device_name IN ('+','.join('?' for _ in names)+')',tuple(names),50)
    return {'device':{k:v for k,v in d.items() if k in allowed},'prerequisites':prereq,
            'ping':ping_rows,'health':health,'ports':ports,'alerts':alerts,'ping_events':events,'backups':backups,
            'history_limit':120,'observed_at':utcnow(),'backup_association':'exact IP or unique device label; verify before restore'}


def build_plan(x:PlanIn, user):
    if x.operation=='CONFIG_BACKUP' and user['role']!='Admin':raise HTTPException(403,'ADMIN_REQUIRED_FOR_BACKUP')
    ids=list(dict.fromkeys(x.inventory_ids))
    limit=5 if x.operation=='CONFIG_BACKUP' else 2048 if x.operation=='PING' else 20
    if not ids or min(ids)<1 or len(ids)>limit:raise HTTPException(400,f'SELECT_1_TO_{limit}_DEVICES')
    devices={d['id']:d for d in merged_devices()}
    if any(i not in devices for i in ids):raise HTTPException(404,'INVENTORY_DEVICE_NOT_FOUND')
    targets=[]; blockers=[]
    with connection() as c:
        for i in ids:
            d=devices[i];host=d['ip'];mid=d.get('managed_id')
            try:
                addr=ipaddress.ip_address(host)
                if addr.is_unspecified or addr.is_multicast:raise ValueError()
            except ValueError:raise HTTPException(400,'INVALID_REGISTERED_IP') from None
            checks=[];pre=prerequisite(c,mid,host)
            if x.operation=='PING':
                if not shutil.which('ping'):checks.append('PING_EXECUTABLE_MISSING')
            else:
                if d.get('identity_conflict'):checks.append('MANAGED_IDENTITY_CONFLICT')
                elif not mid:checks.append('REGISTER_MANAGED_DEVICE_FIRST')
                if x.operation in ('SSH_TEST','CONFIG_BACKUP'):
                    if not importlib.util.find_spec('paramiko'):checks.append('PARAMIKO_MISSING')
                    if not pre['ssh_assigned']:checks.append('SSH_CREDENTIAL_MISSING')
                    if not pre['host_key_trusted']:checks.append('SSH_HOST_KEY_NOT_VERIFIED')
                elif x.operation=='SNMP':
                    if not importlib.util.find_spec('pysnmp'):checks.append('PYSNMP_MISSING')
                    if not pre['snmp_assigned']:checks.append('SNMP_CREDENTIAL_MISSING')
            target={'inventory_id':i,'managed_id':mid,'ip':host,'name':d.get('hostname') or host,'blockers':checks}
            targets.append(target);blockers.extend(checks)
    return {'operation':x.operation,'inventory_ids':ids,'targets':targets,'can_run':not blockers,
            'blockers':sorted(set(blockers)),'device_ids':[t['inventory_id'] if x.operation=='PING' else t['managed_id'] for t in targets],
            'effect':'Read remote configuration and create a private backup file' if x.operation=='CONFIG_BACKUP' else 'Read-only diagnostic; stores observations',
            'limit':limit}


@router.post('/plans/preview')
def plan_preview(x:PlanIn, request:Request):
    user=security37.require_role(request,'Admin','Operator')
    plan=build_plan(x,user);token=None
    if plan['can_run']:
        token=secrets.token_urlsafe(32)
        with connection() as c:
            c.execute('DELETE FROM web_plans47 WHERE expires<?',(time.time(),))
            if c.execute('SELECT COUNT(*) FROM web_plans47 WHERE actor_id=? AND consumed=0',(user['id'],)).fetchone()[0]>=20:
                raise HTTPException(429,'TOO_MANY_PENDING_PLANS')
            c.execute('INSERT INTO web_plans47 VALUES(?,?,?,?,?,?,0)',
                      (security37.digest(token),user['id'],security37.digest(request.cookies.get(security37.COOKIE,'')),
                       x.operation,json.dumps(plan),time.time()+300))
    return {**plan,'token':token,'expires_seconds':300 if token else 0}


@router.post('/plans/execute',status_code=202)
def execute_plan(x:ExecuteIn, request:Request):
    user=security37.require_role(request,'Admin','Operator')
    if not x.authorized:raise HTTPException(400,'AUTHORIZATION_REQUIRED')
    key=security37.digest(x.token)
    with PLAN_LOCK:
        with connection() as c:
            r=c.execute('SELECT * FROM web_plans47 WHERE token_hash=?',(key,)).fetchone()
        if not r or r['actor_id']!=user['id'] or r['session_hash']!=security37.digest(request.cookies.get(security37.COOKIE,'')):
            raise HTTPException(403,'PLAN_NOT_OWNED_BY_THIS_SESSION')
        if r['consumed'] or r['expires']<=time.time():raise HTTPException(409,'PLAN_EXPIRED_OR_USED: preview again')
        old=json.loads(r['payload'])
        current=build_plan(PlanIn(operation=r['operation'],inventory_ids=old['inventory_ids']),user)
        if not current['can_run'] or current['targets']!=old['targets']:
            raise HTTPException(409,'DEVICE_OR_PREREQUISITES_CHANGED: preview again')
        with connection() as c:
            if not c.execute('UPDATE web_plans47 SET consumed=1 WHERE token_hash=? AND consumed=0 AND expires>?',(key,time.time())).rowcount:
                raise HTTPException(409,'PLAN_EXPIRED_OR_USED')
        from webapi.jobs37 import engine
        # A failed queue submission consumes the plan; no automatic write retry.
        result=engine.submit(current['operation'],{'device_ids':current['device_ids'],'network':'','parameters':{}},user)
    return {**result,'source':'guarded_plan','operation':current['operation']}


def record_request(request, response, elapsed):
    route=request.scope.get('route')
    path=getattr(route,'path','/unmatched')
    # Templates only. Never record query/body/cookies, raw host or user-supplied text.
    if not path.startswith('/api/'):return
    item={'at':utcnow(),'method':request.method,'route':path,'status':response.status_code,
          'request_id':getattr(request.state,'request_id',''),'duration_ms':round(elapsed*1000,1)}
    with METRIC_LOCK:
        REQUEST_COUNTS['total']+=1
        if response.status_code>=400:REQUEST_COUNTS['errors']+=1
        if response.status_code>=500:REQUEST_COUNTS['server_errors']+=1
        if response.status_code>=400 or elapsed>2:REQUESTS.append(item)


def asset_report():
    from webapi.routes37 import STATIC_ROOT, STATIC_ASSETS
    result=[];root=STATIC_ROOT.resolve()
    for name in STATIC_ASSETS:
        p=(root/name).resolve();ok=p.is_relative_to(root) and p.is_file()
        result.append({'name':name,'present':ok,'sha256':hashlib.sha256(p.read_bytes()).hexdigest() if ok else None})
    return result


def runtime_report():
    from app_runtime import DATABASE_DIR
    from database.db import DB_PATH
    from webapi.jobs37 import engine
    from webapi.scheduler40 import scheduler
    from webapi.workbench45 import ping
    with connection() as c:
        jobs={r['status']:r['n'] for r in c.execute('SELECT status,COUNT(*) n FROM web_jobs37 GROUP BY status')}
        schedules=c.execute('SELECT COUNT(*) FROM web_schedules40 WHERE enabled=1').fetchone()[0]
        journal=c.execute('PRAGMA journal_mode').fetchone()[0]
        latest=c.execute('SELECT updated_at FROM web_ping_runs47 ORDER BY updated_at DESC LIMIT 1').fetchone()
        recent=safe_projection(c,'web_jobs37',['id','operation','status','done','total','error','created_at','finished_at'],limit=20)
        size_rows=[]
        for table in ('devices','network_devices','ping_results','health_samples','web_jobs37','web_ping_runs47','web_ping_events47','web_security_log37'):
            size_rows.append({'table':table,'rows':c.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]})
    disk=shutil.disk_usage(DATABASE_DIR)
    with METRIC_LOCK:metrics=dict(REQUEST_COUNTS);errors=list(REQUESTS)[-30:][::-1]
    libraries={}
    for name in ('fastapi','uvicorn','paramiko','pysnmp','cryptography'):
        try:libraries[name]=importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:libraries[name]=None
    snap=ping.snapshot(); snap.pop('owner',None)
    return {'version':VERSION,'boot_id':BOOT_ID,'started_at':BOOT_AT,'uptime_seconds':int(time.monotonic()-BOOT_CLOCK),
            'observed_at':utcnow(),'platform':platform.system(),'python':platform.python_version(),
            'worker_ready':engine.pool is not None and not engine.stopping.is_set(),
            'scheduler_alive':bool(scheduler.thread and scheduler.thread.is_alive()),'enabled_schedules':schedules,
            'jobs':jobs,'recent_jobs':recent,'ping':snap,'last_ping_update':latest['updated_at'] if latest else None,
            'database':{'bytes':Path(DB_PATH).stat().st_size,'journal_mode':journal,'reachable':True},
            'storage':{'free_bytes':disk.free,'total_bytes':disk.total,'low_space':disk.free<512*1024*1024},
            'tables':size_rows,'libraries':libraries,'ping_executable':bool(shutil.which('ping')),
            'assets':asset_report(),'request_counts':metrics,'recent_errors':errors,
            'limits':{'job_workers':2,'max_queued_running':16,'ping_targets':2048},
            'automatic_replay':False,'external_exposure':'loopback by default'}


@router.get('/runtime')
def runtime(request:Request):
    security37.require_role(request,'Admin')
    return runtime_report()


@router.get('/diagnostics/export')
def diagnostics_export(request:Request):
    security37.require_role(request,'Admin')
    report=runtime_report()
    # Deliberately remove job error strings and run state, which may include IPs.
    report.pop('recent_jobs',None);report.pop('ping',None)
    report['privacy']='No IP, account, credential, terminal payload, file path or job output included.'
    return Response(json.dumps(report,ensure_ascii=False,indent=2),media_type='application/json',
                    headers={'Content-Disposition':'attachment; filename="NetworkAutomation-5.0-diagnostics.json"'})


@router.get('/session')
def session_info(request:Request):
    user=security37.require_role(request)
    key=security37.digest(request.cookies.get(security37.COOKIE,''))
    with connection() as c:r=c.execute('SELECT issued FROM web_sessions37 WHERE token_hash=?',(key,)).fetchone()
    return {'role':user['role'],'absolute_remaining_seconds':max(0,int(security37.ABSOLUTE_TTL-(time.time()-r['issued']))) if r else 0,
            'terminal_allowed':user['role']=='Admin','mutation_allowed':user['role'] in ('Admin','Operator'),
            'auto_reconnect_terminal':False}
