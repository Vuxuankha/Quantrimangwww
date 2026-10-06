from __future__ import annotations
import ipaddress, sqlite3, logging
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from database.db import DB_PATH, get_connection, init_database, get_device_by_ip
from modules.device_manager import DeviceManager
from webapi.data37 import icmp_probe as ping_host
from modules.network_scan import scan_network

from contextlib import asynccontextmanager
from webapi.runtime37 import VERSION, UI_VERSION, RELEASE, SERVICE, connection as get_connection, DataLock, preflight, utcnow
from webapi import security37, data37
from app_runtime import DATABASE_DIR
import os

logger=logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app):
    global AUTO_ENGINE
    lock=DataLock(DATABASE_DIR/'.web37.lock'); lock.acquire()
    worker_started=False
    try:
        backup=preflight()
        from upgrade_backup import backup_before_release
        backup_before_release(DB_PATH, Path(__file__).resolve().parent.parent)
        init_database()
        from webapi.migrate37 import ensure_support_tables
        ensure_support_tables()
        ensure_v5_tables(); ensure_v12_tables(); ensure_server_monitor_tables()
        from modules.nms_v6 import ensure_v6_tables
        ensure_v6_tables(); _ensure_web_ops_tables(); security37.ensure_tables()
        from webapi.cybersecurity51 import ensure_tables as ensure_cybersecurity51_tables
        ensure_cybersecurity51_tables()
        from webapi.cybersecurity54 import ensure_tables54 as ensure_cybersecurity54_tables
        ensure_cybersecurity54_tables()
        from webapi.cybersecurity57 import ensure_tables57 as ensure_cybersecurity57_tables, daily_auto_engine
        ensure_cybersecurity57_tables(); daily_auto_engine.start()
        from webapi.cybersecurity58 import ensure_tables58 as ensure_cybersecurity58_tables, start_local_endpoint_monitor
        ensure_cybersecurity58_tables(); start_local_endpoint_monitor()
        from webapi.cybersecurity59 import ensure_tables59 as ensure_cybersecurity59_tables
        ensure_cybersecurity59_tables()
        if backup:
            (DATABASE_DIR/'.web_migration_37.json').write_text(json.dumps({'backup':str(backup),'version':VERSION}),encoding='utf-8')
        from webapi.ops40 import ensure_tables as ensure_v40_tables
        ensure_v40_tables()
        from webapi.ops41 import ensure_tables as ensure_v41_tables
        ensure_v41_tables()
        from webapi.lan42 import ensure_tables as ensure_v42_tables
        ensure_v42_tables()
        from webapi.workbench45 import ensure_tables as ensure_v45
        ensure_v45()
        from webapi.terminal46 import ensure_tables as ensure_v46
        ensure_v46()
        from webapi.operations47 import ensure_tables as ensure_v47, recover_ping
        ensure_v47()
        from webapi.workbench45 import ping as recovery_ping
        recover_ping(recovery_ping)
        from webapi.jobs37 import engine
        from webapi.scheduler40 import scheduler
        from webapi.automation68 import engine as master_automation68
        engine.start(); worker_started=True
        scheduler.start()
        master_automation68.start()
        # 5.0.11: record the Web host IPv4 identity at process start.
        # The existing browser-open workflow starts the bounded LAN discovery, so
        # simply starting the Windows Service does not unexpectedly scan the LAN.
        try:
            from webapi.platform50 import record_network_identity
            record_network_identity(reason='server-start', force=True)
        except Exception:
            pass
        yield
    finally:
        try:
            from webapi.cybersecurity58 import stop_local_endpoint_monitor
            stop_local_endpoint_monitor(wait=True)
        except Exception:
            pass
        try:
            from webapi.cybersecurity57 import daily_auto_engine
            daily_auto_engine.stop()
        except Exception:
            logger.exception('daily auto-completion shutdown failed')
        from webapi.autodiscovery5010 import shutdown as shutdown_startup_discovery
        shutdown_startup_discovery(wait=False)
        from webapi.terminal46 import shutdown as shutdown_terminals
        await shutdown_terminals()
        from webapi.workbench45 import ping as ping_coordinator
        ping_coordinator.stop(wait=True)
        if AUTO_ENGINE is not None:
            AUTO_ENGINE.stop()
            if AUTO_ENGINE.thread: AUTO_ENGINE.thread.join(timeout=15)
        if worker_started:
            try:
                from webapi.automation68 import engine as master_automation68
                master_automation68.stop()
            except Exception:
                logger.exception('master automation shutdown failed')
            from webapi.scheduler40 import scheduler
            scheduler.stop()
            from webapi.jobs37 import engine
            engine.stop()
        lock.release()

app=FastAPI(title='NetworkAutomation Operations',version=VERSION,lifespan=lifespan,docs_url=None,redoc_url=None)
from webapi import ops41
security37.install(app)
from starlette.middleware.trustedhost import TrustedHostMiddleware
app.add_middleware(TrustedHostMiddleware,allowed_hosts=[h.strip() for h in os.environ.get('NA_ALLOWED_HOSTS','127.0.0.1,localhost,testserver').split(',') if h.strip()])
manager=DeviceManager()

class RegisterIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)
    confirmation: str = Field(min_length=8, max_length=256)

class MfaVerify51In(BaseModel):
    challenge: str = Field(min_length=16, max_length=256)
    code: str = Field(min_length=6, max_length=12)

class ServerTargetIn(BaseModel):
    name:str; host:str; app_type:str='Custom'; port:int=80; protocol:str='TCP'; service_name:str=''; enabled:bool=True


class DeviceIn(BaseModel):
    ip:str=Field(max_length=45); hostname:str=Field(default='',max_length=255); mac:str=Field(default='',max_length=64); status:str='Unknown'; duration:float|None=None
class ScanIn(BaseModel):
    network:str; max_workers:int=32; timeout:int=800

def rows(sql,args=()):
    with get_connection() as c: return [dict(r) for r in c.execute(sql,args).fetchall()]

def _cols(c, table):
    return {r['name'] for r in c.execute(f'PRAGMA table_info({table})').fetchall()}


def _stable_table_rows(table: str, fields: list[str], order_by: str='id DESC', limit: int=500):
    """Read a compatibility projection without assuming every legacy column exists.

    Older desktop databases can contain an earlier version of operational/security
    tables.  Web visibility must degrade to NULL fields rather than returning HTTP
    500 merely because an additive column has not existed in that database yet.
    Table/field names are internal constants only.
    """
    with get_connection() as c:
        exists=c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()
        if not exists:
            return []
        cols=_cols(c,table)
        projection=[]
        for f in fields:
            if f in cols:
                projection.append(f'"{f}"')
            else:
                projection.append(f'NULL AS "{f}"')
        order=''
        # Keep ordering deterministic but only on columns that actually exist.
        ob=(order_by or '').strip()
        if ob:
            first=ob.split()[0].strip('`"[]')
            if first in cols:
                order=' ORDER BY '+ob
        return [dict(r) for r in c.execute('SELECT '+','.join(projection)+f' FROM "{table}"'+order+' LIMIT ?', (max(1,int(limit)),)).fetchall()]

def write_ping(r):
    return data37.write_ping(r)

@app.get('/api/health')
def health():
    return {'ok':True,'version':VERSION,'core_version':VERSION,'ui_version':UI_VERSION,'release':RELEASE,'service':SERVICE,'instance':os.environ.get('NA_INSTANCE_TOKEN','manual'),'boot_id':__import__('webapi.operations47',fromlist=['BOOT_ID']).BOOT_ID}
def _latest_health_map(c):
    out={}
    try:
        for r in c.execute("SELECT h.* FROM health_samples h JOIN (SELECT host,MAX(id) mid FROM health_samples GROUP BY host) x ON x.mid=h.id").fetchall():
            d=dict(r); out[str(d.get('host') or '')]=d
    except Exception: pass
    return out

def _latest_ping_map(c):
    out={}
    try:
        pc=_cols(c,'ping_results'); ip='ip' if 'ip' in pc else 'ip_address'
        for r in c.execute(f"SELECT p.* FROM ping_results p JOIN (SELECT {ip} ipx,MAX(id) mid FROM ping_results GROUP BY {ip}) x ON x.mid=p.id").fetchall():
            d=dict(r); out[str(d.get(ip) or '')]=d
    except Exception: pass
    return out

def _merged_devices():
    return data37.merged_devices()

@app.get('/api/dashboard')
def dashboard():
    devs=_merged_devices()
    with get_connection() as c:
        def n(t): return c.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
        ac=_cols(c,'alerts')
        filt="lower(COALESCE(status,'open')) NOT IN ('closed','resolved')" if 'status' in ac else '1'
        if 'resolved' in ac: filt+=' AND COALESCE(resolved,0)=0'
        return {'devices':len(devs),'online':sum(d['status']=='Online' for d in devs),'offline':sum(d['status']=='Offline' for d in devs),
            'unknown':sum(d['status']=='Unknown' for d in devs),'stale':sum(d['data_state']=='STALE' for d in devs),
            'path_issue':sum(d.get('data_state')=='PATH_ISSUE' for d in devs),'no_reply':sum(d.get('data_state')=='NO_REPLY' for d in devs),
            'ip_mac':n('ip_mac_inventory'),'alerts':c.execute('SELECT COUNT(*) FROM alerts WHERE '+filt).fetchone()[0],
            'health_samples':n('health_samples'),'autoip_targets':n('autoip_targets'),'observed_at':utcnow()}
@app.get('/api/devices')
def devices(): return _merged_devices()

@app.get('/api/devices/{device_id}/detail')
def device_detail(device_id:int):
    dev=manager.get_device(device_id)
    if not dev: raise HTTPException(404,'Không tìm thấy thiết bị')
    ip=str(dev.get('ip') or dev.get('ip_address') or '')
    with get_connection() as c:
        pc=_cols(c,'ping_results'); pip='ip' if 'ip' in pc else 'ip_address'; presp='response' if 'response' in pc else ('response_ms' if 'response_ms' in pc else 'NULL'); pt='ping_time' if 'ping_time' in pc else ('created_at' if 'created_at' in pc else 'NULL')
        ping=[dict(r) for r in c.execute(f'SELECT id,{pip} AS ip,status,{presp} AS response,{pt} AS created_at FROM ping_results WHERE {pip}=? ORDER BY id DESC LIMIT 50',(ip,)).fetchall()]
        health=[dict(r) for r in c.execute('SELECT * FROM health_samples WHERE host=? ORDER BY id DESC LIMIT 100',(ip,)).fetchall()]
        ac=_cols(c,'alerts'); aip='ip' if 'ip' in ac else 'ip_address'
        if 'ip_address' in ac and aip!='ip_address': al=[dict(r) for r in c.execute(f'SELECT * FROM alerts WHERE {aip}=? OR ip_address=? ORDER BY id DESC LIMIT 50',(ip,ip)).fetchall()]
        else: al=[dict(r) for r in c.execute(f'SELECT * FROM alerts WHERE {aip}=? ORDER BY id DESC LIMIT 50',(ip,)).fetchall()]
    return {'device':dev,'ping':ping,'health':health,'alerts':al}
@app.post('/api/devices')
def add_device(x:DeviceIn):
    ip=x.ip.strip()
    try: ipaddress.ip_address(ip)
    except: raise HTTPException(400,'IP không hợp lệ')
    now=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with get_connection() as c:
        dc=_cols(c,'devices'); dip='ip' if 'ip' in dc else 'ip_address'
        if c.execute(f'SELECT 1 FROM devices WHERE {dip}=? OR '+('ip_address=?' if 'ip_address' in dc and dip!='ip_address' else '0'), (ip,ip) if 'ip_address' in dc and dip!='ip_address' else (ip,)).fetchone():
            raise HTTPException(400,f'IP {ip} đã tồn tại')
        fields=[]; vals=[]
        def put(k,v):
            if k in dc: fields.append(k); vals.append(v)
        put('ip_address',ip); put('ip',ip); put('hostname',x.hostname.strip()); put('mac_address',x.mac.strip()); put('mac',x.mac.strip()); put('status','Unknown'); put('first_seen',now)
        q=','.join('?' for _ in fields); cur=c.execute(f"INSERT INTO devices({','.join(fields)}) VALUES({q})",tuple(vals)); c.commit()
        return {'success':True,'message':'Thêm thiết bị thành công.','device_id':cur.lastrowid}

@app.put('/api/devices/{device_id}')
def edit_device(device_id:int,x:DeviceIn):
    ip=x.ip.strip()
    try: ipaddress.ip_address(ip)
    except: raise HTTPException(400,'IP không hợp lệ')
    now=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with get_connection() as c:
        dc=_cols(c,'devices'); sets=[]; vals=[]
        old=c.execute('SELECT * FROM devices WHERE id=?',(device_id,)).fetchone()
        if not old: raise HTTPException(404,'Device not found')
        old_ip=data37.ip_value(dict(old))
        if old_ip!=ip:
            raise HTTPException(409,'IP_CHANGE_REQUIRES_REENROLLMENT: add the new IP explicitly and re-verify SSH identity')
        for k,v in [('ip_address',ip),('ip',ip),('hostname',x.hostname.strip()),('mac_address',x.mac.strip()),('mac',x.mac.strip())]:
            if k in dc: sets.append(f'{k}=?'); vals.append(v)
        vals.append(device_id)
        try: cur=c.execute(f"UPDATE devices SET {','.join(sets)} WHERE id=?",tuple(vals)); c.commit()
        except sqlite3.IntegrityError: raise HTTPException(400,'IP đã tồn tại')
        if not cur.rowcount: raise HTTPException(404,'Không tìm thấy thiết bị')
        return {'success':True}

@app.delete('/api/devices/{device_id}')
def delete_device(device_id:int):
    # 6.6.0: inventory delete and current Presence cleanup share one DB transaction.
    from webapi.presence65 import delete_managed_device_atomic
    try:
        with get_connection() as c:
            result=delete_managed_device_atomic(c,device_id,utcnow())
            if result.get('not_found'):
                raise HTTPException(404,'Device not found')
            return result
    except HTTPException:
        raise
    except Exception:
        logger.exception('atomic device delete failed device_id=%s',device_id)
        raise HTTPException(500,'Xóa thiết bị thất bại; giao dịch đã được hoàn tác.')
@app.post('/api/devices/{device_id}/ping')
def ping_device(device_id:int):
    d=manager.get_device(device_id)
    if not d: raise HTTPException(404,'Không tìm thấy thiết bị')
    r=ping_host(d['ip'],1000); write_ping(r); return r

def _ensure_presence64_tables(c):
    c.executescript('''
    CREATE TABLE IF NOT EXISTS web_presence_state64(
      ip TEXT PRIMARY KEY, hostname TEXT, mac TEXT, status TEXT NOT NULL DEFAULT 'Unknown',
      source TEXT, last_seen_at TEXT, offline_since TEXT, consecutive_misses INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL, origin TEXT NOT NULL DEFAULT 'managed', device_id INTEGER
    );
    CREATE TABLE IF NOT EXISTS web_presence_events64(
      id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, hostname TEXT, mac TEXT,
      old_status TEXT, new_status TEXT NOT NULL, source TEXT, observed_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_presence_events64_ip_id ON web_presence_events64(ip,id DESC);
    ''')
    cols={r[1] for r in c.execute('PRAGMA table_info(web_presence_state64)').fetchall()}
    if 'origin' not in cols: c.execute("ALTER TABLE web_presence_state64 ADD COLUMN origin TEXT NOT NULL DEFAULT 'managed'")
    if 'device_id' not in cols: c.execute("ALTER TABLE web_presence_state64 ADD COLUMN device_id INTEGER")

def _presence64_apply(results):
    now=utcnow()
    with get_connection() as c:
        _ensure_presence64_tables(c)
        for r in results:
            ip=str(r.get('ip') or '').strip()
            if not ip: continue
            prev=c.execute('SELECT * FROM web_presence_state64 WHERE ip=?',(ip,)).fetchone()
            prev=dict(prev) if prev else {}
            raw=str(r.get('status') or 'Unknown').title()
            online=(raw=='Online')
            misses=0 if online else int(prev.get('consecutive_misses') or 0)+1
            effective='Online' if online else ('Unknown' if misses==1 and prev.get('status')=='Online' else ('Offline' if raw=='Offline' or misses>=2 else 'Unknown'))
            last_seen=now if online else prev.get('last_seen_at')
            offline_since=None if online else (prev.get('offline_since') or (now if effective=='Offline' else None))
            source=str(r.get('presence_source') or '')
            old_status=str(prev.get('status') or '')
            if old_status and old_status!=effective:
                c.execute('INSERT INTO web_presence_events64(ip,hostname,mac,old_status,new_status,source,observed_at) VALUES(?,?,?,?,?,?,?)',
                          (ip,r.get('hostname') or '',r.get('mac') or '',old_status,effective,source,now))
            elif not old_status:
                c.execute('INSERT INTO web_presence_events64(ip,hostname,mac,old_status,new_status,source,observed_at) VALUES(?,?,?,?,?,?,?)',
                          (ip,r.get('hostname') or '',r.get('mac') or '','',effective,source,now))
            origin=str(r.get('_origin') or prev.get('origin') or 'managed')
            device_id=r.get('id') if origin=='managed' else None
            c.execute('''INSERT INTO web_presence_state64(ip,hostname,mac,status,source,last_seen_at,offline_since,consecutive_misses,updated_at,origin,device_id)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET hostname=excluded.hostname,mac=excluded.mac,status=excluded.status,source=excluded.source,last_seen_at=excluded.last_seen_at,offline_since=excluded.offline_since,consecutive_misses=excluded.consecutive_misses,updated_at=excluded.updated_at,origin=excluded.origin,device_id=excluded.device_id''',
                      (ip,r.get('hostname') or '',r.get('mac') or '',effective,source,last_seen,offline_since,misses,now,origin,device_id))
            r['raw_status']=raw;r['status']=effective;r['last_seen_at']=last_seen;r['offline_since']=offline_since;r['consecutive_misses']=misses
        c.execute('DELETE FROM web_presence_events64 WHERE id NOT IN (SELECT id FROM web_presence_events64 ORDER BY id DESC LIMIT 5000)')
        c.commit()
    return results

@app.get('/api/devices/presence-history')
def presence_history(limit:int=200):
    with get_connection() as c:
        _ensure_presence64_tables(c)
        rows=[dict(r) for r in c.execute('SELECT * FROM web_presence_events64 ORDER BY id DESC LIMIT ?',(min(max(limit,1),1000),)).fetchall()]
    return {'count':len(rows),'events':rows}

@app.get('/api/devices/presence-state')
def presence_state():
    from webapi.presence65 import summary
    with get_connection() as c:
        _ensure_presence64_tables(c)
        rows=[dict(r) for r in c.execute('SELECT * FROM web_presence_state64 ORDER BY ip').fetchall()]
    return {**summary(rows),'results':rows,'source_of_truth':'web_presence_state64'}

@app.get('/api/devices/identity-conflicts')
def identity_conflicts():
    conflicts=[]
    with get_connection() as c:
        names={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        rows=[dict(r) for r in c.execute('SELECT id,ip,mac,hostname,status,last_seen FROM ip_mac_inventory').fetchall()] if 'ip_mac_inventory' in names else []
    by_mac={}
    for r in rows:
        mac=str(r.get('mac') or '').replace('-',':').upper().strip()
        if mac: by_mac.setdefault(mac,[]).append(r)
    for mac,items in by_mac.items():
        ips=sorted({str(x.get('ip') or '') for x in items if x.get('ip')})
        if len(ips)>1:
            conflicts.append({'type':'MAC_MULTI_IP','severity':'warning','mac':mac,'ips':ips,'records':items})
    return {'count':len(conflicts),'conflicts':conflicts}

@app.post('/api/devices/refresh-status')
def refresh_device_status():
    # 6.6.0 canonical Presence Engine:
    #   managed inventory + current LAN discovery + recently discovered hosts.
    # There is no 128-device truncation; probing is processed in bounded batches.
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from datetime import datetime, timedelta, timezone
    from webapi.presence65 import batches, merge_targets, summary

    managed=list(manager.get_devices() or [])
    live_rows=[]; neighbors={}; discovery_network=''; scan_key=''
    try:
        from webapi.autodiscovery5010 import status as discovery_status, _arp_neighbors, _netsh_neighbors
        st=discovery_status(); discovery_network=str(st.get('network') or ''); scan_key=str(st.get('scan_key') or '')
        if discovery_network:
            neighbors.update(_arp_neighbors(discovery_network)); neighbors.update(_netsh_neighbors(discovery_network))
        if scan_key:
            with get_connection() as c:
                live_rows=[dict(r) for r in c.execute("""SELECT r.ip,r.mac,r.hostname,r.status,r.created_at,
                       COALESCE(e.sources,CASE WHEN lower(r.status)='online' THEN 'ICMP' ELSE 'LAN' END) sources
                    FROM web_scan_results r LEFT JOIN web_connected_device_evidence e
                      ON e.scan_key=r.scan_key AND e.ip=r.ip
                    WHERE r.scan_key=? AND lower(r.status) IN ('online','activearp','activelan')""",(scan_key,)).fetchall()]
    except Exception:
        logger.exception('LAN discovery evidence unavailable during presence refresh')

    # Keep previously discovered hosts long enough to show that a machine has left
    # the LAN or powered off. Explicit device deletion still removes state at once.
    recent=[]
    cutoff=(datetime.now(timezone.utc)-timedelta(hours=float(os.getenv('NA_PRESENCE_DISCOVERED_RETENTION_HOURS','24')))).strftime('%Y-%m-%dT%H:%M:%SZ')
    with get_connection() as c:
        _ensure_presence64_tables(c)
        try:
            recent=[dict(r) for r in c.execute("SELECT * FROM web_presence_state64 WHERE origin='discovered' AND COALESCE(last_seen_at,updated_at)>=?",(cutoff,)).fetchall()]
            c.execute("DELETE FROM web_presence_state64 WHERE origin='discovered' AND status<>'Online' AND COALESCE(last_seen_at,updated_at)<?",(cutoff,))
            c.commit()
        except Exception:
            logger.exception('presence retention cleanup failed')

    targets=merge_targets(managed,recent,live_rows)
    live_by_ip={str(r.get('ip') or ''):r for r in live_rows}
    max_workers=max(1,min(int(os.getenv('NA_PRESENCE_WORKERS','32')),64))
    batch_size=max(16,min(int(os.getenv('NA_PRESENCE_BATCH_SIZE','128')),512))
    results=[]

    def probe(d):
        ip=str(d.get('ip') or d.get('ip_address') or '')
        live=live_by_ip.get(ip)
        if live:
            return {'ip':ip,'status':'Online','response':None,
                    'hostname':d.get('hostname') or d.get('name') or live.get('hostname') or '',
                    'mac':d.get('mac') or d.get('mac_address') or live.get('mac') or '',
                    'presence_source':str(live.get('sources') or 'LAN'),'_origin':d.get('_origin') or 'discovered','id':d.get('id')}
        try:
            r=ping_host(ip,900); write_ping(r)
        except Exception:
            logger.exception('ICMP presence probe failed ip=%s',ip)
            r={'ip':ip,'status':'Unknown','response':None}
        out={**r,'hostname':d.get('hostname') or d.get('name') or '', 'mac':d.get('mac') or d.get('mac_address') or '',
             'presence_source':'ICMP' if r.get('status')=='Online' else '', '_origin':d.get('_origin') or 'managed','id':d.get('id')}
        if ip in neighbors and out.get('status')!='Online':
            out['status']='Online'; out['response']=None; out['presence_source']='ARP'
            if not out.get('mac'): out['mac']=neighbors.get(ip) or ''
        return out

    for batch in batches(targets,batch_size):
        with ThreadPoolExecutor(max_workers=min(max_workers,max(1,len(batch)))) as ex:
            futs=[ex.submit(probe,d) for d in batch]
            for f in as_completed(futs):
                try: results.append(f.result())
                except Exception: logger.exception('presence worker failed')

    results=_presence64_apply(results)
    results.sort(key=lambda x:tuple(int(p) if p.isdigit() else 999 for p in str(x.get('ip') or '').split('.')))
    sm=summary(results)
    return {**sm,'results':results,'observed_at':utcnow(),'neighbor_evidence':len(neighbors),
            'managed_count':len(managed),'live_discovery_count':len(live_rows),'target_count':len(targets),
            'batch_size':batch_size,'workers':max_workers,'source_of_truth':'web_presence_state64'}
@app.get('/api/ping-history')
def ping_history(limit:int=100):
    with get_connection() as c:
        pc=_cols(c,'ping_results')
        ip='ip' if 'ip' in pc else 'ip_address'
        resp='response' if 'response' in pc else ('response_ms' if 'response_ms' in pc else 'NULL')
        tm='ping_time' if 'ping_time' in pc else ('created_at' if 'created_at' in pc else 'NULL')
        return [dict(r) for r in c.execute(f'SELECT id,{ip} AS ip,status,{resp} AS response,{tm} AS ping_time FROM ping_results ORDER BY id DESC LIMIT ?', (min(max(limit,1),500),)).fetchall()]
@app.get('/api/ip-mac')
def ipmac(limit:int=1000): return rows('SELECT * FROM ip_mac_inventory ORDER BY id DESC LIMIT ?', (min(max(limit,1),3000),))
@app.get('/api/alerts')
def alerts(limit:int=300):
    data=rows('SELECT * FROM alerts ORDER BY id DESC LIMIT ?',(max(1,min(limit,1000)),))
    for d in data: d['ip']=d.get('ip') or d.get('ip_address') or ''
    return data
@app.get('/api/health-samples')
def health_samples(limit:int=300):
    data=rows('SELECT * FROM health_samples ORDER BY id DESC LIMIT ?',(max(1,min(limit,1000)),))
    for d in data:
        d['ip']=d.get('ip') or d.get('host');d['ram']=d.get('ram',d.get('memory'))
        d['data_state']=data37.freshness(d.get('created_at'));d['status']='Unknown'
        if d['data_state']=='FRESH' and d.get('packet_loss') is not None: d['status']='Offline' if d['packet_loss']>=100 else 'Online'
    return data
def _validate_scan_scope(network: str):
    try:
        net=ipaddress.ip_network(network,strict=False)
    except Exception:
        raise HTTPException(400,'Network không hợp lệ, ví dụ 192.168.1.0/24')
    if net.num_addresses>1024:
        raise HTTPException(400,'Web giới hạn tối đa 1024 địa chỉ mỗi lần quét')
    if net.version!=4 or not net.is_private or net.is_link_local or net.is_multicast or net.is_unspecified:
        raise HTTPException(400,'Chỉ cho phép quét IPv4 private trong phạm vi được quản trị')
    return net


def _run_scan(network:str,max_workers:int=32,timeout:int=800,callback=None,stop_event=None):
    """Run an authorized scan and record observations without silently changing inventory."""
    net=_validate_scan_scope(network)
    found=scan_network(
        str(net),max_workers=min(max(int(max_workers),1),64),timeout=min(max(int(timeout),100),5000),
        callback=callback,stop_event=stop_event,resolve_hostnames=True,dns_timeout=0.8,
    )
    now=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    online=sum(str(r.get('status','')).lower()=='online' for r in found)
    errors=sum(str(r.get('status','')).lower()=='error' for r in found)
    cancelled=bool(stop_event is not None and stop_event.is_set())
    scan_status='Cancelled' if cancelled else ('CompletedWithErrors' if errors else 'Completed')
    scan_key=secrets.token_hex(16)
    with get_connection() as c:
        sc=_cols(c,'network_scans')
        if {'network','start_time','end_time','total_hosts','online_hosts','offline_hosts','status'} <= sc:
            c.execute(
                'INSERT INTO network_scans(network,start_time,end_time,total_hosts,online_hosts,offline_hosts,status) VALUES(?,?,?,?,?,?,?)',
                (str(net),now,now,len(found),online,max(0,len(found)-online-errors),scan_status),
            )
        c.execute('CREATE TABLE IF NOT EXISTS web_scan_results(id INTEGER PRIMARY KEY AUTOINCREMENT,scan_key TEXT,network TEXT,ip TEXT,hostname TEXT,mac TEXT,status TEXT,latency_ms REAL,created_at TEXT)')
        for r in found:
            latency=r.get('latency_ms') if r.get('latency_ms') is not None else r.get('response')
            try: latency=float(latency) if latency is not None else None
            except (TypeError,ValueError): latency=None
            c.execute(
                'INSERT INTO web_scan_results(scan_key,network,ip,hostname,mac,status,latency_ms,created_at) VALUES(?,?,?,?,?,?,?,?)',
                (scan_key,str(net),r.get('ip'),r.get('hostname',''),r.get('mac',''),r.get('status','Unknown'),latency,now),
            )
        c.commit()
    return {'success':not errors and not cancelled,'count':len(found),'online':online,'errors':errors,'status':scan_status,'results':found,'scan_key':scan_key}


@app.post('/api/scan')
def scan(x:ScanIn):
    return _run_scan(x.network,x.max_workers,x.timeout)


@app.get('/api/scan-history')
def scan_history(limit:int=300):
    return rows('SELECT * FROM network_scans ORDER BY id DESC LIMIT ?', (min(max(limit,1),1000),))


@app.get('/api/scan-results')
def web_scan_results(limit:int=500):
    limit=max(1,min(limit,3000))
    with get_connection() as c:
        c.execute('CREATE TABLE IF NOT EXISTS web_scan_results(id INTEGER PRIMARY KEY AUTOINCREMENT,scan_key TEXT,network TEXT,ip TEXT,hostname TEXT,mac TEXT,status TEXT,latency_ms REAL,created_at TEXT)')
        dcols=_cols(c,'devices')
        address_cols=[x for x in ('ip','ip_address') if x in dcols]
        inventory={}
        if address_cols:
            for d in c.execute('SELECT * FROM devices').fetchall():
                dd=dict(d); address=str(dd.get('ip') or dd.get('ip_address') or '').strip()
                if address: inventory[address]=dd.get('id')
        data=[]
        for r in c.execute('SELECT * FROM web_scan_results ORDER BY id DESC LIMIT ?',(limit,)).fetchall():
            d=dict(r); d['inventory_id']=inventory.get(str(d.get('ip') or '').strip()); data.append(d)
        return data


@app.post('/api/scan-results/{result_id}/import')
def import_scan_result(result_id:int):
    """Explicitly add one discovered host to inventory. Scanning itself never mutates inventory."""
    with get_connection() as c:
        c.execute('CREATE TABLE IF NOT EXISTS web_scan_results(id INTEGER PRIMARY KEY AUTOINCREMENT,scan_key TEXT,network TEXT,ip TEXT,hostname TEXT,mac TEXT,status TEXT,latency_ms REAL,created_at TEXT)')
        r=c.execute('SELECT * FROM web_scan_results WHERE id=?',(result_id,)).fetchone()
    if not r: raise HTTPException(404,'Không tìm thấy kết quả quét')
    d=dict(r)
    if str(d.get('status') or '').lower()!='online':
        raise HTTPException(400,'Chỉ nhập thiết bị đang Online từ kết quả quét')
    try: address=str(ipaddress.ip_address(str(d.get('ip') or '').strip()))
    except ValueError: raise HTTPException(400,'Kết quả quét không có IP hợp lệ')
    result=manager.add_device(address,d.get('hostname') or '',d.get('mac') or '','Online',d.get('latency_ms'))
    if not result.get('success'):
        existing=get_device_by_ip(address)
        if existing: return {'success':True,'existing':True,'device_id':existing.get('id')}
        raise HTTPException(409,result.get('message') or 'Không thể nhập thiết bị')
    return {'success':True,'existing':False,'device_id':result.get('device_id')}


@app.post('/api/alerts/{alert_id}/reopen')
def reopen_alert(alert_id:int):
    with get_connection() as c:
        cols=_cols(c,'alerts'); sets=[]; vals=[]
        if 'status' in cols: sets.append('status=?'); vals.append('Open')
        if 'resolved' in cols: sets.append('resolved=?'); vals.append(0)
        if not sets: raise HTTPException(400,'Bảng alerts không hỗ trợ trạng thái.')
        vals.append(alert_id); cur=c.execute(f"UPDATE alerts SET {','.join(sets)} WHERE id=?",tuple(vals)); c.commit()
        if not cur.rowcount: raise HTTPException(404,'Không tìm thấy cảnh báo')
    return {'success':True}

@app.get('/api/server-targets/{target_id}/history')
def server_target_history(target_id:int,limit:int=100):
    ensure_server_monitor_tables()
    return rows('SELECT * FROM server_monitor_results WHERE target_id=? ORDER BY id DESC LIMIT ?',(target_id,max(1,min(limit,500))))

@app.put('/api/server-targets/{target_id}')
def edit_server_target(target_id:int,x:ServerTargetIn):
    try: host,port,proto=validate_target(x.host,x.port,x.protocol)
    except ValueError as e: raise HTTPException(400,str(e))
    if any(ch.isdigit() for ch in host) and '.' in host:
        try: ipaddress.ip_address(host)
        except ValueError:
            if all(ch.isdigit() or ch=='.' for ch in host): raise HTTPException(400,'Địa chỉ IPv4 không hợp lệ.')
    ensure_server_monitor_tables()
    with get_connection() as c:
        cur=c.execute('UPDATE server_monitor_targets SET name=?,host=?,app_type=?,port=?,protocol=?,service_name=?,enabled=? WHERE id=?',(x.name.strip() or host,host,x.app_type,port,proto,x.service_name,1 if x.enabled else 0,target_id)); c.commit()
        if not cur.rowcount: raise HTTPException(404,'Không tìm thấy target')
    return {'success':True}

@app.get('/api/health/latest')
def latest_health(limit:int=500):
    with get_connection() as c:
        data=[{**r,'data_state':data37.freshness(t)} for r,t in data37.latest_by_host(c,'health_samples',('created_at',)).values()]
    return data[:max(1,min(limit,2000))]

@app.get('/')
def root(): return FileResponse(Path(__file__).parent/'static'/'index.html')

# --- v3.1 operational bridge ---
from modules.server_monitor import ensure_server_monitor_tables, run_all_targets, validate_target
from modules.nms_v11 import backup_database, database_health, system_health


@app.get('/api/server-targets')
def server_targets():
    ensure_server_monitor_tables()
    data=rows("""SELECT t.*,r.status,r.latency_ms,r.cpu,r.ram,r.disk,r.service_status,r.detail,r.checked_at
    FROM server_monitor_targets t LEFT JOIN server_monitor_results r ON r.id=(SELECT id FROM server_monitor_results WHERE target_id=t.id ORDER BY checked_at DESC,id DESC LIMIT 1) ORDER BY t.name""")
    for d in data:
        d['data_state']=data37.freshness(d.get('checked_at'));d['reported_status']=d.get('status')
        d['validation_error']=''
        try:
            host,_,_=validate_target(str(d.get('host') or ''),d.get('port') or 0,d.get('protocol') or 'TCP')
            if any(ch.isdigit() for ch in host) and '.' in host:
                try: ipaddress.ip_address(host)
                except ValueError:
                    if all(ch.isdigit() or ch=='.' for ch in host):
                        d['validation_error']='Địa chỉ IPv4 không hợp lệ'
        except ValueError as exc:
            d['validation_error']=str(exc)
        if d['validation_error']:
            d['status']='Invalid'; d['data_state']='INVALID'
        elif d['data_state']!='FRESH': d['status']='Unknown'
    return data

@app.post('/api/server-targets')
def add_server_target(x:ServerTargetIn):
    try: host,port,proto=validate_target(x.host,x.port,x.protocol)
    except ValueError as e: raise HTTPException(400,str(e))
    if any(ch.isdigit() for ch in host) and '.' in host:
        try: ipaddress.ip_address(host)
        except ValueError:
            if all(ch.isdigit() or ch=='.' for ch in host):
                raise HTTPException(400,'Địa chỉ IPv4 không hợp lệ.')
    ensure_server_monitor_tables()
    with get_connection() as c:
        cur=c.execute('INSERT INTO server_monitor_targets(name,host,app_type,port,protocol,service_name,enabled,created_at) VALUES(?,?,?,?,?,?,?,?)',(x.name.strip() or host,host,x.app_type,port,proto,x.service_name,1 if x.enabled else 0,datetime.now().strftime('%Y-%m-%d %H:%M:%S')));c.commit()
        return {'success':True,'id':cur.lastrowid}

@app.delete('/api/server-targets/{target_id}')
def delete_server_target(target_id:int):
    ensure_server_monitor_tables()
    with get_connection() as c:
        c.execute('DELETE FROM server_monitor_results WHERE target_id=?',(target_id,)); cur=c.execute('DELETE FROM server_monitor_targets WHERE id=?',(target_id,)); c.commit()
        return {'success':cur.rowcount>0}

@app.post('/api/server-monitor/run')
def run_server_monitor():
    out=run_all_targets()
    return {'count':len(out),'results':[{'target':t,'result':r} for t,r in out]}

@app.post('/api/alerts/{alert_id}/close')
def close_alert(alert_id:int):
    with get_connection() as c:
        cols=_cols(c,'alerts'); sets=[];values=[]
        if 'status' in cols: sets.append("status='Closed'")
        if 'resolved' in cols: sets.append('resolved=1')
        if not sets: raise HTTPException(409,'Alert state columns missing')
        cur=c.execute('UPDATE alerts SET '+','.join(sets)+' WHERE id=?',(alert_id,))
        if not cur.rowcount: raise HTTPException(404,'Alert not found')
    return {'success':True}

@app.get('/api/system-health')
def api_system_health():
    status,detail=database_health()
    return {'database':{'status':status,'detail':detail},'checks':[{'component':a,'status':b,'detail':c} for a,b,c in system_health()]}

@app.post('/api/database/backup')
def api_database_backup(request:Request):
    from webapi.reports37 import backup_db
    return backup_db(_require_role(request,'Admin')['id'])

@app.get('/api/autoip/history')
def autoip_history(limit:int=100):
    return [{**r,'run_id':r['id']} for r in run_history()[:max(1,min(limit,500))]]

@app.get('/api/autoip/targets')
def autoip_targets(limit:int=500):
    return rows('SELECT ip,name,profile FROM autoip_targets ORDER BY ip LIMIT ?',(max(1,min(limit,2048)),))

# --- v3.2 network operations bridge ---
import threading, json
from dataclasses import asdict, replace
from modules.auto_ip import (AutomationEngine, load_targets, load_options, profiles as autoip_profiles,
                             run_steps, run_history, Options as AutoIPOptions)
from modules.auto_config_audit import list_ssh_audit_devices, audit_device
from modules.nms_v5 import ensure_v5_tables, ssh_backup
from modules.nms_v12 import ensure_v12_tables, secure_snmp_get, SYS_DESCR, SYS_OBJECT, SYS_UPTIME, SYS_NAME, detect_driver
from app_runtime import REPORT_DIR

AUTO_ENGINE = None

class AutoIPRunIn(BaseModel):
    authorized: bool = False
    repeat: bool | None = None
    workers: int | None = None
    timeout: float | None = None
    backup: bool | None = None
    notifications: bool | None = None

class AuditIn(BaseModel):
    command: str = 'show running-config'
    create_alerts: bool = True

class BackupIn(BaseModel):
    command: str = ''


def _safe_profile_rows():
    out=[]
    for p in autoip_profiles():
        q=dict(p)
        q.pop('community_enc',None)
        q['has_community']=bool(p.get('community_enc'))
        out.append(q)
    return out

@app.get('/api/autoip/options')
def api_autoip_options():
    o=load_options(); return asdict(o)

@app.get('/api/autoip/profiles')
def api_autoip_profiles():
    return _safe_profile_rows()

@app.get('/api/autoip/status')
def api_autoip_status():
    enabled=os.environ.get('NA_ENABLE_AUTOIP')=='1'
    state=AUTO_ENGINE.snapshot() if AUTO_ENGINE else {'running':False,'status':'Ready' if enabled else 'Disabled','done':0,'total':0}
    return {**state,'enabled':enabled}

@app.get('/api/autoip/steps/{run_id}')
def api_autoip_steps(run_id:str, after_id:int=0, limit:int=500):
    return [{**r,'step':r.get('task'),'detail':r.get('message')} for r in run_steps(run_id,after_id,max(1,min(limit,2000)))]

@app.post('/api/autoip/start')
def api_autoip_start(x:AutoIPRunIn,request:Request):
    global AUTO_ENGINE
    user=_require_role(request,'Admin')
    if not x.authorized: raise HTTPException(400,'Authorization confirmation is required')
    # Keep this coordinator opt-in: it cannot share a desktop coordinator safely yet.
    if os.environ.get('NA_ENABLE_AUTOIP')!='1': raise HTTPException(409,'AUTOIP_DISABLED: stop the desktop Auto IP coordinator, then explicitly enable NA_ENABLE_AUTOIP=1')
    targets=load_targets()
    if not targets: raise HTTPException(400,'No Auto IP targets')
    if len(targets)>128: raise HTTPException(400,'Maximum 128 targets for the pilot')
    for t in targets: ipaddress.ip_address(t.ip)
    if x.repeat or x.notifications: raise HTTPException(400,'Repeat and email notifications are disabled in Web pilot')
    base=load_options()
    overrides={
        'repeat':False,
        'notifications':False,
        'email_report_after_run':False,
        'report_email_to':'',
    }
    for k in ('workers','timeout','backup'):
        v=getattr(x,k)
        if v is not None:
            overrides[k]=v
    # Options is a frozen dataclass. Use replace() instead of mutating fields;
    # mutating here raised FrozenInstanceError as soon as Auto IP was enabled.
    o=replace(base,**overrides).validate()
    if AUTO_ENGINE is None: AUTO_ENGINE=AutomationEngine()
    try: AUTO_ENGINE.start(targets,o,user,authorized=True)
    except Exception as e: raise HTTPException(400,str(e))
    return {'success':True,'targets':len(targets),'options':asdict(o)}

@app.post('/api/autoip/stop')
def api_autoip_stop():
    if AUTO_ENGINE: AUTO_ENGINE.stop()
    return {'success':True,'status':api_autoip_status()}

@app.get('/api/snmp/diagnostics')
def api_snmp_diagnostics(limit:int=200):
    ensure_v12_tables()
    return rows('SELECT id,host,version,credential_name,success,sys_name,sys_descr,sys_object_id,detail,created_at FROM snmp_diagnostics_history ORDER BY id DESC LIMIT ?', (max(1,min(limit,1000)),))

@app.post('/api/snmp/device/{device_id}/refresh')
def api_snmp_refresh(device_id:int):
    ensure_v12_tables()
    with get_connection() as c:
        d=c.execute('SELECT * FROM network_devices WHERE id=?',(device_id,)).fetchone()
        if not d: raise HTTPException(404,'Không tìm thấy thiết bị quản lý.')
        d=dict(d); host=(d.get('ip') or d.get('ip_address') or '').strip()
        if not host: raise HTTPException(400,'Thiết bị chưa có IP.')
        # Prefer assigned SNMPv3, else existing legacy SNMP profile. Never expose secrets.
        a=c.execute('SELECT credential_id FROM device_snmpv3_assignments WHERE device_id=?',(device_id,)).fetchone()
        secure_v2=c.execute('SELECT s.* FROM web_device_snmpv2_assignments42 a JOIN web_snmpv2_credentials42 s ON s.id=a.credential_id WHERE a.device_id=? LIMIT 1',(device_id,)).fetchone()
        legacy=c.execute('SELECT * FROM snmp_profiles WHERE host=? AND enabled=1 ORDER BY id LIMIT 1',(host,)).fetchone()
    try:
        if a:
            vals=secure_snmp_get(host,[SYS_DESCR,SYS_OBJECT,SYS_UPTIME,SYS_NAME],version='v3',credential_id=a['credential_id'],timeout=2.0)
            version='v3'; cred_name='assigned-v3'
        elif secure_v2:
            vals=secure_snmp_get(host,[SYS_DESCR,SYS_OBJECT,SYS_UPTIME,SYS_NAME],version='v2c',community=decrypt_secret(secure_v2['community_enc']),port=secure_v2['port'] or 161,timeout=2.0)
            version='v2c'; cred_name=str(secure_v2['name'] or 'web-v2c')
        elif legacy:
            vals=secure_snmp_get(host,[SYS_DESCR,SYS_OBJECT,SYS_UPTIME,SYS_NAME],version='v2c',community=legacy['community'],port=legacy['port'] or 161,timeout=2.0)
            version='v2c'; cred_name='legacy-profile'
        else:
            raise HTTPException(400,'Thiết bị chưa có SNMP profile/credential được gán.')
        descr=str(vals.get(SYS_DESCR,'') or ''); obj=str(vals.get(SYS_OBJECT,'') or ''); name=str(vals.get(SYS_NAME,'') or '')
        driver=detect_driver(descr,obj)
        with get_connection() as c:
            c.execute('INSERT INTO snmp_diagnostics_history(host,version,credential_name,success,sys_name,sys_descr,sys_object_id,detail,created_at) VALUES(?,?,?,?,?,?,?,?,?)',
                      (host,version,cred_name,1,name,descr,obj,'Web manual refresh',datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            if name:
                c.execute("UPDATE network_devices SET name=CASE WHEN COALESCE(name,'')='' OR name=ip THEN ? ELSE name END,updated_at=? WHERE id=?",(name,datetime.now().strftime('%Y-%m-%d %H:%M:%S'),device_id))
            if driver and driver.get('vendor'):
                c.execute("UPDATE network_devices SET vendor=CASE WHEN COALESCE(vendor,'')='' THEN ? ELSE vendor END,updated_at=? WHERE id=?",(driver['vendor'],datetime.now().strftime('%Y-%m-%d %H:%M:%S'),device_id))
            c.commit()
        return {'success':True,'host':host,'version':version,'sys_name':name,'sys_descr':descr,'sys_object_id':obj,'uptime':vals.get(SYS_UPTIME),'driver':(driver or {}).get('name'),'vendor':(driver or {}).get('vendor')}
    except HTTPException: raise
    except Exception as e:
        with get_connection() as c:
            c.execute('INSERT INTO snmp_diagnostics_history(host,version,credential_name,success,sys_name,sys_descr,sys_object_id,detail,created_at) VALUES(?,?,?,?,?,?,?,?,?)',
                      (host,'unknown','',0,'','','',str(e)[:800],datetime.now().strftime('%Y-%m-%d %H:%M:%S'))); c.commit()
        raise HTTPException(400,str(e))

@app.get('/api/ssh-audit/devices')
def api_ssh_audit_devices():
    return [{k:v for k,v in d.items() if k not in ('secret_enc',)} for d in list_ssh_audit_devices()]

@app.get('/api/ssh-audit/history')
def api_ssh_audit_history(limit:int=200):
    try:return rows('SELECT * FROM config_audit_history ORDER BY id DESC LIMIT ?',(max(1,min(limit,1000)),))
    except Exception:return []

@app.post('/api/ssh-audit/{device_id}')
def api_run_ssh_audit(device_id:int,x:AuditIn):
    # Read-only commands only. This endpoint intentionally does not accept arbitrary CLI changes.
    allowed={'show running-config','display current-configuration','show configuration','/export terse'}
    if x.command not in allowed: raise HTTPException(400,'Lệnh audit không nằm trong danh sách read-only cho phép.')
    try:
        r=audit_device(device_id,x.command,x.create_alerts)
        return {'success':True,'status':r['status'],'detail':r['detail'],'counts':r['counts'],'rows':r['rows'],'diff_count':len(r['diff'])}
    except Exception as e: raise HTTPException(400,str(e))


def _backup_device_credential(device_id:int):
    ensure_v5_tables()
    with get_connection() as c:
        d=c.execute('SELECT * FROM network_devices WHERE id=?',(device_id,)).fetchone()
        if not d: raise ValueError('Không tìm thấy thiết bị.')
        cr=c.execute("""SELECT cr.* FROM device_credentials dc JOIN credentials cr ON cr.id=dc.credential_id
                        WHERE dc.device_id=? AND UPPER(cr.kind)='SSH' AND UPPER(dc.purpose) IN ('SSH','BACKUP')
                        ORDER BY CASE UPPER(dc.purpose) WHEN 'BACKUP' THEN 0 ELSE 1 END LIMIT 1""",(device_id,)).fetchone()
        if not cr: raise ValueError('Thiết bị chưa được gán credential SSH/Backup.')
        return dict(d),dict(cr)

@app.get('/api/config-backups')
def api_config_backups(limit:int=300):
    data=rows('SELECT * FROM config_backups ORDER BY id DESC LIMIT ?',(max(1,min(limit,1000)),))
    for d in data:
        d['filename']=Path(str(d.get('file_path') or d.get('path') or '')).name
        for key in ('config','content','secret','password'): d.pop(key,None)
    return data

@app.post('/api/config-backup/{device_id}')
def api_config_backup(device_id:int,x:BackupIn):
    try:
        d,cr=_backup_device_credential(device_id)
        # Select command from detected driver if the caller leaves it blank; caller may only choose read-only known commands.
        cmd=(x.command or '').strip()
        allowed={'show running-config','display current-configuration','show configuration','/export terse'}
        if not cmd:
            with get_connection() as c:
                r=c.execute('''SELECT vd.backup_command FROM vendor_drivers vd JOIN device_driver_assignments a ON a.driver_id=vd.id WHERE a.device_id=?''',(device_id,)).fetchone()
                cmd=(r['backup_command'] if r else '') or 'show running-config'
        if cmd not in allowed: raise ValueError('Lệnh backup không nằm trong danh sách read-only cho phép.')
        path=Path(ssh_backup(d,cr,cmd))
        return {'success':True,'filename':path.name,'size_bytes':path.stat().st_size if path.exists() else None,'command':cmd}
    except Exception as e: raise HTTPException(400,str(e))

@app.get('/api/reports/summary')
def api_report_summary():
    devs=_merged_devices()
    with get_connection() as c:
        def count(sql,*args):
            try:return c.execute(sql,args).fetchone()[0]
            except Exception:return 0
        ac=_cols(c,'alerts') if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='alerts'").fetchone() else set()
        open_filter="lower(COALESCE(status,'open')) NOT IN ('closed','resolved')" if 'status' in ac else '1'
        if 'resolved' in ac: open_filter += ' AND COALESCE(resolved,0)=0'
        return {'generated_at':datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'devices':len(devs),'online':sum(d.get('status')=='Online' for d in devs),
                'offline':sum(d.get('status')=='Offline' for d in devs),'unknown':sum(d.get('status')=='Unknown' for d in devs),
                'stale':sum(d.get('data_state')=='STALE' for d in devs),'path_issue':sum(d.get('data_state')=='PATH_ISSUE' for d in devs),
                'no_reply':sum(d.get('data_state')=='NO_REPLY' for d in devs),
                'network_devices':count('SELECT COUNT(*) FROM network_devices'),'open_alerts':count('SELECT COUNT(*) FROM alerts WHERE '+open_filter),
                'config_backups':count('SELECT COUNT(*) FROM config_backups'),'scan_records':count('SELECT COUNT(*) FROM network_scans'),
                'ping_records':count('SELECT COUNT(*) FROM ping_results'),'health_samples':count('SELECT COUNT(*) FROM health_samples'),
                'status_source':'freshness-aware merged observations'}

@app.post('/api/reports/export')
def api_export_report(request:Request):
    from webapi.reports37 import export_report
    return export_report(_require_role(request,'Admin','Operator')['id'])

@app.get('/api/managed-devices')
def api_managed_devices():
    return rows("SELECT id,COALESCE(NULLIF(name,''),NULLIF(device_name,''),ip,ip_address) name,COALESCE(NULLIF(ip,''),ip_address) ip,vendor,device_type,status,location,updated_at FROM network_devices ORDER BY name,ip")

# --- v3.3 credential & SSH trust management ---
import base64, hashlib, secrets, socket
from modules.nms_v5 import encrypt_secret, decrypt_secret, authenticate, ensure_v5_tables, _now
from modules.nms_v12 import ensure_v12_tables
from modules.ssh_security import APP_KNOWN_HOSTS, build_strict_ssh_client
from modules.auto_ip import save_profile as save_autoip_profile

_WEB_SESSIONS = {}

class LoginIn(BaseModel):
    username: str
    password: str

class CredentialIn(BaseModel):
    name: str
    kind: str = 'SSH'
    username: str = ''
    secret: str = ''
    port: int | None = 22
    note: str = ''

class CredentialAssignIn(BaseModel):
    credential_id: int
    purpose: str = 'SSH'

class SSHTestIn(BaseModel):
    credential_id: int | None = None

class HostTrustIn(BaseModel):
    expected_fingerprint: str
    confirm_replace: bool = False
    port: int = 22

class SNMPv3In(BaseModel):
    name: str
    username: str
    security_level: str = 'authPriv'
    auth_protocol: str = 'SHA'
    auth_secret: str = ''
    priv_protocol: str = 'AES128'
    priv_secret: str = ''
    context_name: str = ''
    port: int = 161
    note: str = ''

class SNMPv3AssignIn(BaseModel):
    credential_id: int

class AutoIPProfileIn(BaseModel):
    name: str
    mode: str = 'assigned'
    community: str = ''
    snmpv3_id: int | None = None
    ssh_id: int | None = None
    port: int = 161

class AutoIPTargetProfileIn(BaseModel):
    profile: str


def _current_user(request:Request):
    return security37.session(request)


def _require_role(request:Request,*roles):
    return security37.require_role(request,*roles)

@app.post('/api/auth/login')
def web_login(x:LoginIn,request:Request,response:Response):
    return security37.login(x.username,x.password,request,response)

@app.post('/api/auth/register')
def web_register(x:RegisterIn,request:Request):
    return security37.register(x.username,x.password,x.confirmation,request)

@app.post('/api/auth/mfa/verify')
def web_mfa_verify(x:MfaVerify51In,request:Request,response:Response):
    return security37.verify_mfa_login(x.challenge,x.code,request,response)

@app.post('/api/auth/logout')
def web_logout(request:Request,response:Response):
    return security37.logout(request,response)

@app.get('/api/auth/me')
def web_me(request:Request):
    return _require_role(request)


def _clean_credential(row):
    d=dict(row); d.pop('secret_enc',None); d['has_secret']=bool(row['secret_enc']); return d

@app.get('/api/credentials')
def api_credentials(request:Request):
    _require_role(request,'Admin'); ensure_v5_tables()
    with get_connection() as c:
        rs=c.execute("SELECT cr.*,COUNT(dc.device_id) assigned FROM credentials cr LEFT JOIN device_credentials dc ON dc.credential_id=cr.id GROUP BY cr.id ORDER BY cr.name").fetchall()
        return [_clean_credential(r) for r in rs]

@app.post('/api/credentials')
def api_create_credential(x:CredentialIn,request:Request):
    _require_role(request,'Admin'); ensure_v5_tables()
    name=x.name.strip(); kind='SSH' if x.kind.strip().upper()=='BACKUP' else x.kind.strip().upper()
    if not name or len(name)>120: raise HTTPException(400,'Tên credential không hợp lệ.')
    if kind not in ('SSH','BACKUP'): raise HTTPException(400,'Web chỉ cho tạo credential SSH/Backup ở mục này.')
    if not x.secret: raise HTTPException(400,'Mật khẩu/secret không được để trống.')
    port=int(x.port or 22)
    if not 1<=port<=65535: raise HTTPException(400,'Port không hợp lệ.')
    try:
        with get_connection() as c:
            cur=c.execute('INSERT INTO credentials(name,kind,username,secret_enc,port,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',(name,kind,x.username.strip(),encrypt_secret(x.secret),port,x.note.strip(),_now(),_now())); c.commit()
            return {'success':True,'id':cur.lastrowid}
    except sqlite3.IntegrityError: raise HTTPException(409,'Tên credential đã tồn tại.')
    except Exception as e: raise HTTPException(400,str(e))

@app.put('/api/credentials/{credential_id}')
def api_update_credential(credential_id:int,x:CredentialIn,request:Request):
    _require_role(request,'Admin'); ensure_v5_tables()
    kind='SSH' if x.kind.strip().upper()=='BACKUP' else x.kind.strip().upper(); port=int(x.port or 22)
    if kind not in ('SSH','BACKUP') or not 1<=port<=65535: raise HTTPException(400,'Loại/port không hợp lệ.')
    with get_connection() as c:
        old=c.execute('SELECT * FROM credentials WHERE id=?',(credential_id,)).fetchone()
        if not old: raise HTTPException(404,'Credential không tồn tại.')
        enc=encrypt_secret(x.secret) if x.secret else old['secret_enc']
        try:
            c.execute('UPDATE credentials SET name=?,kind=?,username=?,secret_enc=?,port=?,note=?,updated_at=? WHERE id=?',(x.name.strip(),kind,x.username.strip(),enc,port,x.note.strip(),_now(),credential_id)); c.commit()
        except sqlite3.IntegrityError: raise HTTPException(409,'Tên credential đã tồn tại.')
    return {'success':True}

@app.delete('/api/credentials/{credential_id}')
def api_delete_credential(credential_id:int,request:Request):
    _require_role(request,'Admin'); ensure_v5_tables()
    with get_connection() as c:
        n=c.execute('SELECT COUNT(*) FROM device_credentials WHERE credential_id=?',(credential_id,)).fetchone()[0]
        if n: raise HTTPException(409,f'Credential đang được gán cho {n} thiết bị. Hãy bỏ gán trước.')
        c.execute('DELETE FROM secure_backup_jobs WHERE credential_id=?',(credential_id,)); cur=c.execute('DELETE FROM credentials WHERE id=?',(credential_id,)); c.commit()
        return {'success':cur.rowcount>0}

@app.post('/api/devices/{device_id}/credential')
def api_assign_credential(device_id:int,x:CredentialAssignIn,request:Request):
    _require_role(request,'Admin'); ensure_v5_tables()
    purpose=x.purpose.strip().upper()
    if purpose not in ('SSH','BACKUP'): raise HTTPException(400,'Purpose chỉ được SSH hoặc BACKUP.')
    with get_connection() as c:
        if not c.execute('SELECT id FROM network_devices WHERE id=?',(device_id,)).fetchone(): raise HTTPException(404,'Không tìm thấy thiết bị.')
        if not c.execute("SELECT id FROM credentials WHERE id=? AND UPPER(kind) IN ('SSH','BACKUP')",(x.credential_id,)).fetchone(): raise HTTPException(404,'Credential không tồn tại.')
        c.execute('INSERT INTO device_credentials(device_id,credential_id,purpose,created_at) VALUES(?,?,?,?) ON CONFLICT(device_id,purpose) DO UPDATE SET credential_id=excluded.credential_id,created_at=excluded.created_at',(device_id,x.credential_id,purpose,_now())); c.commit()
    return {'success':True}

@app.delete('/api/devices/{device_id}/credential/{purpose}')
def api_unassign_credential(device_id:int,purpose:str,request:Request):
    _require_role(request,'Admin'); purpose=purpose.upper().strip()
    if purpose not in ('SSH','BACKUP'):
        raise HTTPException(400,'Purpose chỉ được SSH hoặc BACKUP.')
    with get_connection() as c:
        if not c.execute('SELECT id FROM network_devices WHERE id=?',(device_id,)).fetchone():
            raise HTTPException(404,'Không tìm thấy thiết bị.')
        cur=c.execute('DELETE FROM device_credentials WHERE device_id=? AND UPPER(purpose)=?',(device_id,purpose)); c.commit()
        return {'success':cur.rowcount>0}

@app.get('/api/device-credentials')
def api_device_credentials(request:Request):
    _require_role(request,'Admin'); ensure_v5_tables()
    return rows("""SELECT dc.device_id,COALESCE(NULLIF(d.name,''),NULLIF(d.device_name,''),d.ip,d.ip_address) device,
      COALESCE(NULLIF(d.ip,''),d.ip_address) ip,dc.purpose,cr.id credential_id,cr.name credential_name,cr.kind,cr.username,cr.port
      FROM device_credentials dc JOIN network_devices d ON d.id=dc.device_id JOIN credentials cr ON cr.id=dc.credential_id ORDER BY device,dc.purpose""")


def _registered_device(device_id:int):
    with get_connection() as c:
        r=c.execute('SELECT * FROM network_devices WHERE id=?',(device_id,)).fetchone()
    if not r: raise HTTPException(404,'Không tìm thấy thiết bị.')
    d=dict(r); host=(d.get('ip') or d.get('ip_address') or '').strip()
    if not host: raise HTTPException(400,'Thiết bị chưa có IP.')
    return d,host


def _ssh_key_probe(device_id:int,port:int=22):
    d,host=_registered_device(device_id)
    if not 1<=int(port)<=65535: raise HTTPException(400,'Port không hợp lệ.')
    try:
        import paramiko
        sock=socket.create_connection((host,int(port)),timeout=5)
        tr=None
        try:
            tr=paramiko.Transport(sock); tr.start_client(timeout=7); key=tr.get_remote_server_key()
            raw=key.asbytes(); fp='SHA256:'+base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')
            entry_host=host if int(port)==22 else f'[{host}]:{int(port)}'
            return {'device_id':device_id,'host':host,'port':int(port),'key_type':key.get_name(),'fingerprint':fp,'known_hosts_line':f'{entry_host} {key.get_name()} {key.get_base64()}'}
        finally:
            if tr:
                try: tr.close()
                except Exception: pass
            try: sock.close()
            except Exception: pass
    except Exception as e: raise HTTPException(400,f'Không đọc được SSH host key: {e}')

@app.get('/api/ssh/hostkey/{device_id}')
def api_probe_hostkey(device_id:int,request:Request,port:int=22):
    _require_role(request,'Admin','Operator'); return _ssh_key_probe(device_id,port)

@app.post('/api/ssh/hostkey/{device_id}/trust')
def api_trust_hostkey(device_id:int,x:HostTrustIn,request:Request):
    _require_role(request,'Admin'); probe=_ssh_key_probe(device_id,x.port)
    if not secrets.compare_digest(probe['fingerprint'],x.expected_fingerprint.strip()):
        raise HTTPException(409,'Fingerprint hiện tại không khớp fingerprint đã xác minh.')
    path=Path(APP_KNOWN_HOSTS); path.parent.mkdir(parents=True,exist_ok=True)
    host_field=probe['known_hosts_line'].split(' ',1)[0]
    existing=path.read_text(encoding='utf-8').splitlines() if path.exists() else []
    matching=[line for line in existing if line.strip() and not line.lstrip().startswith('#') and line.split(' ',1)[0]==host_field]
    if matching and probe['known_hosts_line'] not in matching and not x.confirm_replace:
        raise HTTPException(409,'Host đã có key khác trong known_hosts. Chỉ thay sau khi xác minh và bật confirm_replace.')
    kept=[line for line in existing if not (line.strip() and not line.lstrip().startswith('#') and line.split(' ',1)[0]==host_field)]
    kept.append(probe['known_hosts_line'])
    tmp=path.with_suffix('.tmp'); tmp.write_text('\n'.join(kept).rstrip()+'\n',encoding='utf-8'); tmp.replace(path)
    return {'success':True,'fingerprint':probe['fingerprint']}

@app.get('/api/ssh/known-hosts')
def api_known_hosts(request:Request):
    _require_role(request,'Admin'); path=Path(APP_KNOWN_HOSTS)
    out=[]
    if path.exists():
        for line in path.read_text(encoding='utf-8').splitlines():
            p=line.strip().split()
            if len(p)>=3 and not line.lstrip().startswith('#'):
                try:
                    raw=base64.b64decode(p[2]); fp='SHA256:'+base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')
                except Exception: fp='invalid'
                out.append({'host':p[0],'key_type':p[1],'fingerprint':fp})
    return out

@app.post('/api/devices/{device_id}/ssh-test')
def api_ssh_test(device_id:int,x:SSHTestIn,request:Request):
    _require_role(request,'Admin','Operator'); d,host=_registered_device(device_id); ensure_v5_tables()
    with get_connection() as c:
        # Never test an arbitrary vault entry against an unrelated host. The
        # credential must already be assigned to this managed device.
        if x.credential_id:
            cr=c.execute("""SELECT cr.* FROM device_credentials dc JOIN credentials cr ON cr.id=dc.credential_id
                            WHERE dc.device_id=? AND cr.id=? AND UPPER(cr.kind) IN ('SSH','BACKUP')
                              AND UPPER(dc.purpose) IN ('SSH','BACKUP')
                            ORDER BY CASE UPPER(dc.purpose) WHEN 'SSH' THEN 0 ELSE 1 END,dc.created_at DESC LIMIT 1""",
                         (device_id,x.credential_id)).fetchone()
        else:
            cr=c.execute("""SELECT cr.* FROM device_credentials dc JOIN credentials cr ON cr.id=dc.credential_id
                            WHERE dc.device_id=? AND UPPER(cr.kind) IN ('SSH','BACKUP')
                              AND UPPER(dc.purpose) IN ('SSH','BACKUP')
                            ORDER BY CASE UPPER(dc.purpose) WHEN 'SSH' THEN 0 ELSE 1 END,dc.created_at DESC LIMIT 1""",
                         (device_id,)).fetchone()
    if not cr: raise HTTPException(400,'Thiết bị chưa được gán credential SSH/Backup phù hợp để kiểm tra.')
    try:
        import paramiko
        cli=build_strict_ssh_client(paramiko); cli.connect(host,port=int(cr['port'] or 22),username=cr['username'] or '',password=decrypt_secret(cr['secret_enc']),timeout=8,banner_timeout=10,auth_timeout=10,look_for_keys=False,allow_agent=False); cli.close()
        return {'success':True,'host':host,'credential':cr['name']}
    except Exception as e: raise HTTPException(400,str(e))


def _clean_snmpv3(row):
    d=dict(row); d.pop('auth_secret_enc',None); d.pop('priv_secret_enc',None); d['has_auth_secret']=bool(row['auth_secret_enc']); d['has_priv_secret']=bool(row['priv_secret_enc']); return d


def _validate_snmpv3_input(x:SNMPv3In, old=None):
    level=x.security_level
    if level not in ('noAuthNoPriv','authNoPriv','authPriv'):
        raise HTTPException(400,'security_level không hợp lệ.')
    auth_protocol=x.auth_protocol.upper().strip()
    priv_protocol=x.priv_protocol.upper().strip()
    if auth_protocol not in ('MD5','SHA','SHA224','SHA256','SHA384','SHA512'):
        raise HTTPException(400,'auth_protocol không được hỗ trợ.')
    if priv_protocol not in ('DES','AES128','AES192','AES256'):
        raise HTTPException(400,'priv_protocol không được hỗ trợ.')
    if not 1 <= int(x.port) <= 65535:
        raise HTTPException(400,'Port SNMP không hợp lệ.')
    old_auth=(old['auth_secret_enc'] if old else '') or ''
    old_priv=(old['priv_secret_enc'] if old else '') or ''
    if level!='noAuthNoPriv' and not (x.auth_secret or old_auth):
        raise HTTPException(400,'Thiếu auth secret cho security level đã chọn.')
    if level=='authPriv' and not (x.priv_secret or old_priv):
        raise HTTPException(400,'Thiếu privacy secret cho authPriv.')
    return level,auth_protocol,priv_protocol

@app.get('/api/snmpv3/credentials')
def api_snmpv3_credentials(request:Request):
    _require_role(request,'Admin'); ensure_v12_tables()
    with get_connection() as c:
        rs=c.execute("SELECT s.*,COUNT(a.device_id) assigned FROM snmpv3_credentials s LEFT JOIN device_snmpv3_assignments a ON a.credential_id=s.id GROUP BY s.id ORDER BY s.name").fetchall()
        return [_clean_snmpv3(r) for r in rs]

@app.post('/api/snmpv3/credentials')
def api_create_snmpv3(x:SNMPv3In,request:Request):
    _require_role(request,'Admin'); ensure_v12_tables()
    level,auth_protocol,priv_protocol=_validate_snmpv3_input(x)
    if not x.name.strip() or not x.username.strip():
        raise HTTPException(400,'Tên credential và SNMPv3 username không được để trống.')
    try:
        with get_connection() as c:
            cur=c.execute('INSERT INTO snmpv3_credentials(name,username,security_level,auth_protocol,auth_secret_enc,priv_protocol,priv_secret_enc,context_name,port,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(x.name.strip(),x.username.strip(),level,auth_protocol,encrypt_secret(x.auth_secret) if x.auth_secret else '',priv_protocol,encrypt_secret(x.priv_secret) if x.priv_secret else '',x.context_name.strip(),int(x.port),x.note.strip(),_now(),_now())); c.commit(); return {'success':True,'id':cur.lastrowid}
    except sqlite3.IntegrityError: raise HTTPException(409,'Tên credential SNMPv3 đã tồn tại.')
    except Exception as e: raise HTTPException(400,str(e))

@app.put('/api/snmpv3/credentials/{credential_id}')
def api_update_snmpv3(credential_id:int,x:SNMPv3In,request:Request):
    _require_role(request,'Admin'); ensure_v12_tables()
    with get_connection() as c:
        old=c.execute('SELECT * FROM snmpv3_credentials WHERE id=?',(credential_id,)).fetchone()
        if not old: raise HTTPException(404,'Credential SNMPv3 không tồn tại.')
        level,auth_protocol,priv_protocol=_validate_snmpv3_input(x,old)
        if not x.name.strip() or not x.username.strip():
            raise HTTPException(400,'Tên credential và SNMPv3 username không được để trống.')
        auth=encrypt_secret(x.auth_secret) if x.auth_secret else old['auth_secret_enc']; priv=encrypt_secret(x.priv_secret) if x.priv_secret else old['priv_secret_enc']
        if level=='noAuthNoPriv': auth=''; priv=''
        elif level=='authNoPriv': priv=''
        try:
            c.execute('UPDATE snmpv3_credentials SET name=?,username=?,security_level=?,auth_protocol=?,auth_secret_enc=?,priv_protocol=?,priv_secret_enc=?,context_name=?,port=?,note=?,updated_at=? WHERE id=?',(x.name.strip(),x.username.strip(),level,auth_protocol,auth,priv_protocol,priv,x.context_name.strip(),int(x.port),x.note.strip(),_now(),credential_id)); c.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(409,'Tên credential SNMPv3 đã tồn tại.')
    return {'success':True}

@app.delete('/api/snmpv3/credentials/{credential_id}')
def api_delete_snmpv3(credential_id:int,request:Request):
    _require_role(request,'Admin'); ensure_v12_tables()
    with get_connection() as c:
        n=c.execute('SELECT COUNT(*) FROM device_snmpv3_assignments WHERE credential_id=?',(credential_id,)).fetchone()[0]
        if n: raise HTTPException(409,f'Credential đang được gán cho {n} thiết bị.')
        cur=c.execute('DELETE FROM snmpv3_credentials WHERE id=?',(credential_id,)); c.commit(); return {'success':cur.rowcount>0}

@app.post('/api/devices/{device_id}/snmpv3')
def api_assign_snmpv3(device_id:int,x:SNMPv3AssignIn,request:Request):
    _require_role(request,'Admin'); ensure_v12_tables(); _registered_device(device_id)
    with get_connection() as c:
        if not c.execute('SELECT id FROM snmpv3_credentials WHERE id=?',(x.credential_id,)).fetchone(): raise HTTPException(404,'Credential SNMPv3 không tồn tại.')
        c.execute('INSERT INTO device_snmpv3_assignments(device_id,credential_id,updated_at) VALUES(?,?,?) ON CONFLICT(device_id) DO UPDATE SET credential_id=excluded.credential_id,updated_at=excluded.updated_at',(device_id,x.credential_id,_now())); c.commit()
    return {'success':True}

@app.delete('/api/devices/{device_id}/snmpv3')
def api_unassign_snmpv3(device_id:int,request:Request):
    _require_role(request,'Admin'); ensure_v12_tables()
    with get_connection() as c:
        if not c.execute('SELECT id FROM network_devices WHERE id=?',(device_id,)).fetchone():
            raise HTTPException(404,'Không tìm thấy thiết bị.')
        cur=c.execute('DELETE FROM device_snmpv3_assignments WHERE device_id=?',(device_id,)); c.commit()
    return {'success':cur.rowcount>0}


@app.get('/api/snmpv3/assignments')
def api_snmpv3_assignments(request:Request):
    _require_role(request,'Admin'); ensure_v12_tables()
    return rows("SELECT a.device_id,COALESCE(NULLIF(d.name,''),NULLIF(d.device_name,''),d.ip,d.ip_address) device,COALESCE(NULLIF(d.ip,''),d.ip_address) ip,s.id credential_id,s.name credential_name,s.username,s.security_level,s.port FROM device_snmpv3_assignments a JOIN network_devices d ON d.id=a.device_id JOIN snmpv3_credentials s ON s.id=a.credential_id ORDER BY device")

@app.get('/api/connection-profiles')
def api_connection_profiles(request:Request):
    _require_role(request,'Admin'); out=[]
    for p in autoip_profiles():
        d=dict(p); d.pop('community_enc',None); d['has_community']=bool(p.get('community_enc')); out.append(d)
    return out

@app.post('/api/connection-profiles')
def api_save_connection_profile(x:AutoIPProfileIn,request:Request):
    _require_role(request,'Admin')
    try: save_autoip_profile(x.name,x.mode,x.community,x.snmpv3_id,x.ssh_id,x.port,role='Admin'); return {'success':True}
    except Exception as e: raise HTTPException(400,str(e))

@app.delete('/api/connection-profiles/{name}')
def api_delete_connection_profile(name:str,request:Request):
    _require_role(request,'Admin')
    if name=='Mặc định an toàn': raise HTTPException(400,'Không xóa profile mặc định.')
    with get_connection() as c:
        n=c.execute('SELECT COUNT(*) FROM autoip_targets WHERE profile=?',(name,)).fetchone()[0]
        if n: raise HTTPException(409,f'Profile đang được {n} target sử dụng.')
        cur=c.execute('DELETE FROM autoip_profiles WHERE name=?',(name,)); c.commit(); return {'success':cur.rowcount>0}

@app.post('/api/autoip/targets/{ip}/profile')
def api_assign_target_profile(ip:str,x:AutoIPTargetProfileIn,request:Request):
    _require_role(request,'Admin')
    with get_connection() as c:
        if not c.execute('SELECT name FROM autoip_profiles WHERE name=?',(x.profile,)).fetchone(): raise HTTPException(404,'Profile không tồn tại.')
        cur=c.execute('UPDATE autoip_targets SET profile=? WHERE ip=?',(x.profile,ip)); c.commit()
        if not cur.rowcount: raise HTTPException(404,'Auto IP target không tồn tại.')
    return {'success':True}


# --- v3.4 operational readiness & controlled batch operations ---
from concurrent.futures import ThreadPoolExecutor, as_completed

class BatchOpsIn(BaseModel):
    device_ids: list[int]
    authorized: bool = False
    create_alerts: bool = True


def _ensure_web_ops_tables():
    with get_connection() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS web_operation_runs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            operation TEXT NOT NULL,
            requested_by TEXT,
            total INTEGER DEFAULT 0,
            success_count INTEGER DEFAULT 0,
            failure_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'Running',
            created_at TEXT,
            finished_at TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS web_operation_results(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            device_id INTEGER,
            ip TEXT,
            success INTEGER DEFAULT 0,
            detail TEXT,
            created_at TEXT
        )''')
        c.commit()


def _known_host_fields():
    path=Path(APP_KNOWN_HOSTS); out=set()
    if not path.exists(): return out
    for line in path.read_text(encoding='utf-8',errors='replace').splitlines():
        line=line.strip()
        if not line or line.startswith('#'): continue
        parts=line.split()
        if parts: out.add(parts[0])
    return out


def _device_readiness_rows():
    ensure_v5_tables(); ensure_v12_tables()
    known=_known_host_fields()
    with get_connection() as c:
        dev=[dict(r) for r in c.execute("SELECT id,COALESCE(NULLIF(name,''),NULLIF(device_name,''),ip,ip_address) name,COALESCE(NULLIF(ip,''),ip_address) ip,vendor,device_type,status,updated_at FROM network_devices ORDER BY name,ip").fetchall()]
        ssh={r['device_id']:dict(r) for r in c.execute("SELECT dc.device_id,cr.id credential_id,cr.name credential_name,cr.username,cr.port FROM device_credentials dc JOIN credentials cr ON cr.id=dc.credential_id WHERE UPPER(dc.purpose)='SSH'").fetchall()}
        bak={r['device_id']:dict(r) for r in c.execute("SELECT dc.device_id,cr.id credential_id,cr.name credential_name,cr.username,cr.port FROM device_credentials dc JOIN credentials cr ON cr.id=dc.credential_id WHERE UPPER(dc.purpose)='BACKUP'").fetchall()}
        v3={r['device_id']:dict(r) for r in c.execute("SELECT a.device_id,s.id credential_id,s.name credential_name,s.security_level,s.port FROM device_snmpv3_assignments a JOIN snmpv3_credentials s ON s.id=a.credential_id").fetchall()}
        v2secure={r['device_id']:dict(r) for r in c.execute("SELECT a.device_id,s.id credential_id,s.name credential_name,s.port FROM web_device_snmpv2_assignments42 a JOIN web_snmpv2_credentials42 s ON s.id=a.credential_id").fetchall()}
        legacy={str(r['host']).strip():dict(r) for r in c.execute("SELECT id,host,port,enabled FROM snmp_profiles WHERE enabled=1").fetchall() if r['host']}
        last_audit={r['device_id']:dict(r) for r in c.execute("SELECT h.* FROM config_audit_history h JOIN (SELECT device_id,MAX(id) mid FROM config_audit_history GROUP BY device_id) x ON x.mid=h.id").fetchall()}
        latest_backup={}
        for r in c.execute("SELECT * FROM config_backups ORDER BY id DESC").fetchall():
            d=dict(r); key=str(d.get('device_name') or d.get('source') or '').strip()
            if key and key not in latest_backup: latest_backup[key]=d
    out=[]
    for d in dev:
        did=d['id']; host=str(d.get('ip') or '').strip(); sshr=ssh.get(did); bakr=bak.get(did) or sshr; v3r=v3.get(did); v2r=v2secure.get(did)
        port=int((sshr or bakr or {}).get('port') or 22)
        hostfield=host if port==22 else f'[{host}]:{port}'
        trusted=hostfield in known
        legacy_snmp=legacy.get(host)
        audit=last_audit.get(did)
        b=latest_backup.get(host) or latest_backup.get(str(d.get('name') or '').strip())
        reasons=[]
        if not sshr: reasons.append('Chưa gán SSH credential')
        elif not trusted: reasons.append('SSH host key chưa trust')
        if not (v3r or v2r or legacy_snmp): reasons.append('Chưa có SNMP profile/credential')
        out.append({**d,
            'ssh_credential':(sshr or {}).get('credential_name',''),
            'backup_credential':(bakr or {}).get('credential_name',''),
            'ssh_trusted':trusted,
            'snmp_mode':'v3' if v3r else ('v2c-secure' if v2r else ('v2c-legacy' if legacy_snmp else '')),
            'snmp_credential':(v3r or v2r or {}).get('credential_name',''),
            'audit_status':(audit or {}).get('status',''),
            'audit_at':(audit or {}).get('created_at',''),
            'backup_at':(b or {}).get('created_at',''),
            'ready_ssh':bool(sshr and trusted),
            'ready_snmp':bool(v3r or v2r or legacy_snmp),
            'issues':'; '.join(reasons)
        })
    return out

@app.get('/api/operations/readiness')
def api_operations_readiness(request:Request):
    _require_role(request,'Admin','Operator')
    data=_device_readiness_rows()
    return {'summary':{
        'devices':len(data),
        'ssh_credentialed':sum(bool(x['ssh_credential']) for x in data),
        'ssh_trusted':sum(bool(x['ssh_trusted']) for x in data),
        'ssh_ready':sum(bool(x['ready_ssh']) for x in data),
        'snmp_ready':sum(bool(x['ready_snmp']) for x in data),
        'fully_ready':sum(bool(x['ready_ssh'] and x['ready_snmp']) for x in data),
    },'devices':data}


def _start_op_run(operation,user,total):
    _ensure_web_ops_tables()
    with get_connection() as c:
        cur=c.execute('INSERT INTO web_operation_runs(operation,requested_by,total,status,created_at) VALUES(?,?,?,?,?)',(operation,user.get('username',''),total,'Running',_now())); c.commit(); return cur.lastrowid


def _finish_op_run(run_id,results):
    ok=sum(bool(r.get('success')) for r in results); fail=len(results)-ok
    with get_connection() as c:
        for r in results:
            c.execute('INSERT INTO web_operation_results(run_id,device_id,ip,success,detail,created_at) VALUES(?,?,?,?,?,?)',(run_id,r.get('device_id'),r.get('ip',''),1 if r.get('success') else 0,str(r.get('detail',''))[:1200],_now()))
        c.execute("UPDATE web_operation_runs SET success_count=?,failure_count=?,status='Completed',finished_at=? WHERE id=?",(ok,fail,_now(),run_id)); c.commit()
    return {'run_id':run_id,'total':len(results),'success':ok,'failure':fail,'results':results}


def _validated_batch_ids(ids,limit):
    uniq=[]
    for x in ids:
        try:i=int(x)
        except:continue
        if i>0 and i not in uniq: uniq.append(i)
    if not uniq: raise HTTPException(400,'Chưa chọn thiết bị.')
    if len(uniq)>limit: raise HTTPException(400,f'Mỗi lần tối đa {limit} thiết bị.')
    with get_connection() as c:
        found={r['id'] for r in c.execute('SELECT id FROM network_devices WHERE id IN (%s)'%(','.join('?'*len(uniq))),uniq).fetchall()}
    missing=[i for i in uniq if i not in found]
    if missing: raise HTTPException(404,'Không tìm thấy device ID: '+','.join(map(str,missing[:10])))
    return uniq


def _ssh_test_one(device_id):
    try:
        d,host=_registered_device(device_id); ensure_v5_tables()
        with get_connection() as c:
            cr=c.execute("SELECT cr.* FROM device_credentials dc JOIN credentials cr ON cr.id=dc.credential_id WHERE dc.device_id=? AND UPPER(dc.purpose)='SSH' ORDER BY dc.created_at DESC LIMIT 1",(device_id,)).fetchone()
        if not cr: raise ValueError('Chưa gán SSH credential.')
        import paramiko
        cli=build_strict_ssh_client(paramiko); cli.connect(host,port=int(cr['port'] or 22),username=cr['username'] or '',password=decrypt_secret(cr['secret_enc']),timeout=6,banner_timeout=8,auth_timeout=8,look_for_keys=False,allow_agent=False); cli.close()
        return {'device_id':device_id,'ip':host,'success':True,'detail':'SSH OK / '+str(cr['name'])}
    except Exception as e:
        try: host=_registered_device(device_id)[1]
        except Exception: host=''
        return {'device_id':device_id,'ip':host,'success':False,'detail':str(e)}


def _snmp_test_one(device_id):
    try:
        r=api_snmp_refresh(device_id)
        return {'device_id':device_id,'ip':r.get('host',''),'success':True,'detail':f"SNMP {r.get('version','')} / {r.get('sys_name','')}"}
    except HTTPException as e:
        try: host=_registered_device(device_id)[1]
        except Exception: host=''
        return {'device_id':device_id,'ip':host,'success':False,'detail':str(e.detail)}
    except Exception as e:
        return {'device_id':device_id,'ip':'','success':False,'detail':str(e)}


def _parallel_map(ids,fn,workers=4):
    out=[]
    with ThreadPoolExecutor(max_workers=min(workers,len(ids))) as ex:
        fut={ex.submit(fn,i):i for i in ids}
        for f in as_completed(fut):
            try: out.append(f.result())
            except Exception as e: out.append({'device_id':fut[f],'ip':'','success':False,'detail':str(e)})
    return sorted(out,key=lambda r:r.get('device_id') or 0)

@app.post('/api/operations/ssh-test')
def api_batch_ssh_test(x:BatchOpsIn,request:Request):
    user=_require_role(request,'Admin','Operator')
    if not x.authorized: raise HTTPException(400,'Phải xác nhận quyền quản trị các thiết bị trước khi kiểm tra.')
    ids=_validated_batch_ids(x.device_ids,20); run=_start_op_run('SSH_TEST',user,len(ids)); return _finish_op_run(run,_parallel_map(ids,_ssh_test_one,4))

@app.post('/api/operations/snmp-test')
def api_batch_snmp_test(x:BatchOpsIn,request:Request):
    user=_require_role(request,'Admin','Operator')
    if not x.authorized: raise HTTPException(400,'Phải xác nhận quyền quản trị các thiết bị trước khi kiểm tra.')
    ids=_validated_batch_ids(x.device_ids,20); run=_start_op_run('SNMP_TEST',user,len(ids)); return _finish_op_run(run,_parallel_map(ids,_snmp_test_one,4))


def _audit_one(device_id,create_alerts=True):
    try:
        r=audit_device(device_id,'show running-config',create_alerts)
        d,host=_registered_device(device_id)
        return {'device_id':device_id,'ip':host,'success':True,'detail':str(r.get('status',''))+' - '+str(r.get('detail',''))}
    except Exception as e:
        try: host=_registered_device(device_id)[1]
        except Exception: host=''
        return {'device_id':device_id,'ip':host,'success':False,'detail':str(e)}


def _backup_one(device_id):
    try:
        d,cr=_backup_device_credential(device_id)
        with get_connection() as c:
            r=c.execute('''SELECT vd.backup_command FROM vendor_drivers vd JOIN device_driver_assignments a ON a.driver_id=vd.id WHERE a.device_id=?''',(device_id,)).fetchone()
        cmd=(r['backup_command'] if r else '') or 'show running-config'
        if cmd not in {'show running-config','display current-configuration','show configuration','/export terse'}: raise ValueError('Backup command không nằm trong allowlist read-only.')
        path=ssh_backup(d,cr,cmd)
        host=(d.get('ip') or d.get('ip_address') or '')
        return {'device_id':device_id,'ip':host,'success':True,'detail':'Backup: '+str(path)}
    except Exception as e:
        try: host=_registered_device(device_id)[1]
        except Exception: host=''
        return {'device_id':device_id,'ip':host,'success':False,'detail':str(e)}

@app.post('/api/operations/audit')
def api_batch_audit(x:BatchOpsIn,request:Request):
    user=_require_role(request,'Admin')
    if not x.authorized: raise HTTPException(400,'Phải xác nhận quyền quản trị trước khi chạy audit.')
    ids=_validated_batch_ids(x.device_ids,5); run=_start_op_run('SSH_AUDIT',user,len(ids)); return _finish_op_run(run,_parallel_map(ids,lambda i:_audit_one(i,x.create_alerts),2))

@app.post('/api/operations/backup')
def api_batch_backup(x:BatchOpsIn,request:Request):
    user=_require_role(request,'Admin')
    if not x.authorized: raise HTTPException(400,'Phải xác nhận quyền quản trị trước khi backup cấu hình.')
    ids=_validated_batch_ids(x.device_ids,5); run=_start_op_run('CONFIG_BACKUP',user,len(ids)); return _finish_op_run(run,_parallel_map(ids,_backup_one,2))

@app.get('/api/operations/history')
def api_operation_history(request:Request,limit:int=100):
    _require_role(request,'Admin','Operator'); _ensure_web_ops_tables()
    return rows('SELECT * FROM web_operation_runs ORDER BY id DESC LIMIT ?',(max(1,min(limit,500)),))

@app.get('/api/operations/history/{run_id}')
def api_operation_result(run_id:int,request:Request):
    _require_role(request,'Admin','Operator'); _ensure_web_ops_tables()
    with get_connection() as c:
        run=c.execute('SELECT * FROM web_operation_runs WHERE id=?',(run_id,)).fetchone()
        if not run: raise HTTPException(404,'Không tìm thấy operation run.')
        result=[dict(r) for r in c.execute('SELECT * FROM web_operation_results WHERE run_id=? ORDER BY id',(run_id,)).fetchall()]
    return {'run':dict(run),'results':result}


# --- v3.8 operational visibility: incidents, security posture, logs ---
@app.get('/api/incidents')
def api_incidents(limit:int=500):
    """Read-only incident view from the desktop incident tables."""
    limit=max(1,min(limit,2000))
    return rows("SELECT * FROM incidents ORDER BY id DESC LIMIT ?",(limit,))

@app.get('/api/root-causes')
def api_root_causes(limit:int=500):
    """Read-only RCA history. Historical rows are not presented as current state."""
    limit=max(1,min(limit,2000))
    data=rows("SELECT * FROM root_cause_events ORDER BY id DESC LIMIT ?",(limit,))
    for d in data:
        d['data_state']=data37.freshness(d.get('last_seen') or d.get('first_seen'))
    return data

@app.get('/api/security/assets')
def api_security_assets(limit:int=1000):
    limit=max(1,min(limit,3000))
    return _stable_table_rows('security_assets',['id','device_id','ip','expected_mac','expected_hostname','criticality','owner','environment','last_verified','identity_status','created_at','updated_at'],'id DESC',limit)

@app.get('/api/security/checks')
def api_security_checks(limit:int=500):
    """Return security check metadata only; raw detail_json can contain sensitive configuration."""
    limit=max(1,min(limit,2000))
    return _stable_table_rows('security_checks',['id','asset_ip','check_type','result','severity','created_at'],'id DESC',limit)

@app.get('/api/security/events')
def api_security_events(limit:int=500):
    limit=max(1,min(limit,2000))
    return _stable_table_rows('security_events',['id','asset_ip','source','event_type','severity','title','status','created_at','updated_at'],'id DESC',limit)

@app.get('/api/system-logs')
def api_system_logs(limit:int=200):
    """Operational logs available to every authenticated role, matching desktop system-log visibility."""
    limit=max(1,min(limit,1000))
    return {
        'activity':_stable_table_rows('activity_logs',['id','action','description','created_at'],'id DESC',limit),
        'notifications':_stable_table_rows('notification_log',['id','event_key','channel','status','detail','created_at'],'id DESC',limit),
        'health':_stable_table_rows('system_health_history',['id','component','status','detail','created_at'],'id DESC',limit),
    }

@app.get('/api/audit-log')
def api_audit_log(request:Request,limit:int=300):
    security37.require_role(request,'Admin')
    limit=max(1,min(limit,1000))
    return rows("SELECT id,username,role,action,target,detail,created_at FROM audit_log ORDER BY id DESC LIMIT ?",(limit,))

# RC additions: tasks, account self-service, diagnostics, download registry.
from webapi.routes37 import router as deployment_router
app.include_router(deployment_router)
from webapi.ops40 import router as ops40_router
app.include_router(ops40_router)
app.include_router(ops41.router)
from webapi.lan42 import router as lan42_router
app.include_router(lan42_router)
from webapi.audit43 import router as audit43_router
app.include_router(audit43_router)
from webapi.parity44 import router as parity44_router
app.include_router(parity44_router)
from webapi.workbench45 import router as workbench45_router
app.include_router(workbench45_router)
from webapi.terminal46 import router as terminal46_router
app.include_router(terminal46_router)

from webapi.operations47 import router as operations47_router
app.include_router(operations47_router)
from webapi.platform50 import router as platform50_router
app.include_router(platform50_router)
from webapi.cybersecurity51 import router as cybersecurity51_router
app.include_router(cybersecurity51_router)
from webapi.cybersecurity54 import router as cybersecurity54_router
app.include_router(cybersecurity54_router)
from webapi.cybersecurity55 import router as cybersecurity55_router
app.include_router(cybersecurity55_router)
from webapi.cybersecurity56 import router as cybersecurity56_router
app.include_router(cybersecurity56_router)
from webapi.cybersecurity57 import router as cybersecurity57_router
app.include_router(cybersecurity57_router)
from webapi.cybersecurity58 import router as cybersecurity58_router
app.include_router(cybersecurity58_router)
from webapi.cybersecurity59 import router as cybersecurity59_router
app.include_router(cybersecurity59_router)
from webapi.automation68 import router as automation68_router
app.include_router(automation68_router)
from webapi.kali63 import router as kali63_router
app.include_router(kali63_router)

# Do not echo secret input values in Pydantic validation failures.
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
@app.exception_handler(RequestValidationError)
async def sanitized_validation(request, exc):
    errors=[{'loc':list(e.get('loc',())), 'msg':e.get('msg','Invalid value'), 'type':e.get('type','validation_error')} for e in exc.errors()]
    return JSONResponse({'detail':errors},status_code=422)
