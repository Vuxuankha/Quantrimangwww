from __future__ import annotations

from pathlib import Path
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app_runtime import DATA_DIR, DATABASE_DIR
from database.db import DB_PATH, get_connection, get_device_statistics, create_device, update_device, delete_device, get_device_by_ip
from modules import accounts as account_ops
from modules.ping_check import ping_host
from webapi.core.security import current_user, require_roles

router = APIRouter(tags=['Desktop Parity'])


def _table_exists(c, name):
    return c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _cols(c, table):
    if not _table_exists(c, table):
        return []
    return [r['name'] for r in c.execute(f'PRAGMA table_info("{table}")').fetchall()]


def _safe_rows(table, limit=1000, order_candidates=()):
    c = get_connection()
    try:
        if not _table_exists(c, table):
            return []
        cols = _cols(c, table)
        order = next((x for x in order_candidates if x in cols), None)
        sql = f'SELECT * FROM "{table}"'
        if order:
            sql += f' ORDER BY "{order}" DESC'
        sql += ' LIMIT ?'
        return [dict(r) for r in c.execute(sql, (max(1, min(int(limit), 10000)),)).fetchall()]
    finally:
        c.close()


def _count(c, table, where=None):
    if not _table_exists(c, table):
        return 0
    sql = f'SELECT COUNT(*) n FROM "{table}"'
    if where:
        sql += ' WHERE ' + where
    try:
        return int(c.execute(sql).fetchone()['n'])
    except Exception:
        return 0


def _latest(c, table, order_candidates=()):
    if not _table_exists(c, table):
        return None
    cols = _cols(c, table)
    order = next((x for x in order_candidates if x in cols), None)
    sql = f'SELECT * FROM "{table}"'
    if order:
        sql += f' ORDER BY "{order}" DESC'
    sql += ' LIMIT 1'
    row = c.execute(sql).fetchone()
    return dict(row) if row else None


def _norm_status(value):
    text = str(value or '').strip()
    low = text.lower()
    if low in ('online','up','alive','ok','success','reachable','1','true'):
        return 'Online'
    if low in ('offline','down','dead','failed','unreachable','0','false'):
        return 'Offline'
    return text or 'Unknown'


def _unified_devices():
    """Merge every legacy source that can identify a managed endpoint.

    Status freshness matters more than table age: recent ping/health state wins
    over stale inventory status. Missing fields are filled without fabricating
    values.
    """
    c = get_connection()
    try:
        merged = {}
        def add(ip, source, status_priority=0, **fields):
            ip = str(ip or '').strip()
            if not ip:
                return
            row = merged.setdefault(ip, {'ip': ip, 'source': '', '_status_priority': -1})
            sources = {x for x in str(row.get('source') or '').split(',') if x}
            sources.add(source); row['source'] = ','.join(sorted(sources))
            status = fields.pop('status', None)
            if status not in (None, '') and status_priority >= row.get('_status_priority', -1):
                row['status'] = _norm_status(status); row['_status_priority'] = status_priority
            for k, v in fields.items():
                if v in (None, ''):
                    continue
                if k == 'last_seen':
                    current = str(row.get(k) or '')
                    candidate = str(v)
                    if not current or candidate > current:
                        row[k] = v
                    continue
                if row.get(k) in (None, '', 'Unknown'):
                    row[k] = v

        if _table_exists(c, 'network_devices'):
            health = {}
            if _table_exists(c, 'device_health_state'):
                health = {r['device_id']: dict(r) for r in c.execute('SELECT * FROM device_health_state').fetchall()}
            drivers = {}
            if _table_exists(c, 'device_driver_assignments') and _table_exists(c, 'vendor_drivers'):
                for r in c.execute("SELECT a.device_id,d.vendor,d.name driver_name FROM device_driver_assignments a JOIN vendor_drivers d ON d.id=a.driver_id").fetchall():
                    drivers[r['device_id']] = dict(r)
            for r in c.execute('SELECT * FROM network_devices').fetchall():
                d=dict(r); h=health.get(d.get('id'),{}); dr=drivers.get(d.get('id'),{})
                add(d.get('ip') or d.get('ip_address'),'network_devices',82,
                    hostname=d.get('name') or d.get('device_name') or d.get('hostname'),
                    mac=d.get('mac') or d.get('mac_address'),
                    status=h.get('effective_status') or d.get('status'), vendor=d.get('vendor') or dr.get('vendor'),
                    device_type=d.get('device_type'), location=d.get('location'), note=d.get('note'),
                    last_seen=h.get('last_check') or d.get('updated_at') or d.get('last_seen'))

        if _table_exists(c, 'devices'):
            for r in c.execute('SELECT * FROM devices').fetchall():
                d=dict(r); add(d.get('ip') or d.get('ip_address'),'devices',88, hostname=d.get('hostname'),
                    mac=d.get('mac') or d.get('mac_address'), status=d.get('status'), duration=d.get('duration'),
                    first_seen=d.get('first_seen'), last_seen=d.get('last_seen'))

        if _table_exists(c, 'ip_mac_inventory'):
            for r in c.execute('SELECT * FROM ip_mac_inventory').fetchall():
                d=dict(r); add(d.get('ip'),'ip_mac_inventory',75, hostname=d.get('hostname'),mac=d.get('mac'),status=d.get('status'),note=d.get('note'),first_seen=d.get('first_seen'),last_seen=d.get('last_seen'))

        if _table_exists(c, 'autoip_targets'):
            for r in c.execute('SELECT * FROM autoip_targets').fetchall():
                d=dict(r); add(d.get('ip'),'autoip_targets',30,hostname=d.get('name'),profile=d.get('profile'))

        if _table_exists(c, 'snmp_profiles'):
            for r in c.execute('SELECT * FROM snmp_profiles').fetchall():
                d=dict(r); add(d.get('host'),'snmp_profiles',40,hostname=d.get('name'),profile=d.get('name'),last_seen=d.get('created_at'))
        if _table_exists(c, 'snmp_samples'):
            for r in c.execute('SELECT * FROM snmp_samples ORDER BY id DESC LIMIT 5000').fetchall():
                d=dict(r); add(d.get('host'),'snmp_samples',65,hostname=d.get('sys_name'),status='Online',last_seen=d.get('created_at'))
        if _table_exists(c, 'snmp_diagnostics_history'):
            for r in c.execute('SELECT * FROM snmp_diagnostics_history ORDER BY id DESC LIMIT 5000').fetchall():
                d=dict(r); add(d.get('host'),'snmp_diagnostics',70,hostname=d.get('sys_name'),status='Online' if d.get('success') else None,last_seen=d.get('created_at'),snmp_version=d.get('version'))

        if _table_exists(c, 'server_monitor_targets'):
            for r in c.execute('SELECT * FROM server_monitor_targets').fetchall():
                d=dict(r); add(d.get('host'),'server_monitor_targets',35,hostname=d.get('name'),device_type='Server/Application')

        if _table_exists(c, 'sla_policies'):
            for r in c.execute("SELECT * FROM sla_policies WHERE host IS NOT NULL AND TRIM(host)<>''").fetchall():
                d=dict(r); add(d.get('host'),'sla_policies',20)

        if _table_exists(c, 'health_samples'):
            for r in c.execute('SELECT * FROM health_samples ORDER BY id DESC LIMIT 5000').fetchall():
                d=dict(r); add(d.get('host'),'health_samples',76,status='Online' if (d.get('packet_loss') is None or float(d.get('packet_loss') or 0)<100) else 'Offline',last_seen=d.get('created_at'))

        if _table_exists(c, 'ping_results'):
            for r in c.execute('SELECT * FROM ping_results ORDER BY id DESC LIMIT 10000').fetchall():
                d=dict(r); add(d.get('ip'),'ping_results',100,status=d.get('status'),last_seen=d.get('ping_time') or d.get('created_at'),response_time=d.get('response'))

        if _table_exists(c, 'security_assets'):
            for r in c.execute('SELECT * FROM security_assets').fetchall():
                d=dict(r); add(d.get('ip'),'security_assets',50,hostname=d.get('expected_hostname'),mac=d.get('expected_mac'),status=d.get('operational_status'),vendor=d.get('vendor'),device_type=d.get('device_type'),last_seen=d.get('last_seen'))

        if _table_exists(c, 'network_scans'):
            for r in c.execute('SELECT * FROM network_scans ORDER BY id DESC LIMIT 10000').fetchall():
                d=dict(r); add(d.get('ip') or d.get('ip_address'),'network_scans',60,hostname=d.get('hostname'),mac=d.get('mac'),status=d.get('status'),last_seen=d.get('scan_time') or d.get('created_at'))

        out=[]
        for row in merged.values():
            row.pop('_status_priority',None); row.setdefault('status','Unknown'); out.append(row)
        return sorted(out,key=lambda x:x.get('ip') or '')
    finally:
        c.close()


@router.get('/legacy/overview')
def overview(user=Depends(current_user)):
    c = get_connection()
    try:
        stats = get_device_statistics()
        unified = _unified_devices()
        online = sum(str(x.get('status') or '').lower() == 'online' for x in unified)
        offline = sum(str(x.get('status') or '').lower() == 'offline' for x in unified)
        return {
            'devices': {'total': len(unified) or stats.get('total', 0), 'online': online or stats.get('online', 0), 'offline': offline or stats.get('offline', 0)},
            'network_devices': _count(c, 'network_devices'),
            'ip_mac': _count(c, 'ip_mac_inventory'),
            'alerts_open': _count(c, 'alerts', "LOWER(COALESCE(status,'')) NOT IN ('closed','resolved')"),
            'scheduled_tasks': _count(c, 'scheduled_tasks', 'COALESCE(enabled,0)=1'),
            'backups': _count(c, 'config_backups'),
            'scan_history': _count(c, 'network_scans'),
            'ping_samples': _count(c, 'ping_results'),
            'health_samples': _count(c, 'health_samples'),
            'security_events': _count(c, 'security_events'),
            'incidents': _count(c, 'security_incidents') + _count(c, 'incidents'),
            'database_path': str(DB_PATH),
        }
    finally:
        c.close()


@router.get('/legacy/noc')
def noc(user=Depends(current_user)):
    c = get_connection()
    try:
        devices = _unified_devices()
        online = sum(str(x.get('status') or '').lower() == 'online' for x in devices)
        offline = sum(str(x.get('status') or '').lower() == 'offline' for x in devices)
        unknown = max(0, len(devices) - online - offline)
        return {
            'inventory': {'total': len(devices), 'online': online, 'offline': offline, 'unknown': unknown},
            'open_alerts': _count(c, 'alerts', "LOWER(COALESCE(status,'')) NOT IN ('closed','resolved')"),
            'health_samples': _count(c, 'health_samples'),
            'interface_samples': _count(c, 'interface_samples'),
            'server_targets': _count(c, 'server_monitor_targets', 'COALESCE(enabled,1)=1'),
            'camera_registry': _count(c, 'camera_registry'),
            'active_sla': _count(c, 'sla_policies', 'COALESCE(enabled,1)=1'),
            'latest_health': _latest(c, 'health_samples', ('created_at','id')),
            'latest_ping': _latest(c, 'ping_results', ('created_at','timestamp','id')),
            'latest_alert': _latest(c, 'alerts', ('created_at','updated_at','id')),
        }
    finally:
        c.close()


@router.get('/legacy/devices')
def devices(user=Depends(current_user)):
    return _unified_devices()


@router.get('/legacy/network-devices')
def network_devices(user=Depends(current_user)):
    return _safe_rows('network_devices', 5000, ('updated_at','id'))


@router.get('/legacy/ip-mac')
def ip_mac(user=Depends(current_user)):
    return _safe_rows('ip_mac_inventory', 5000, ('last_seen','id'))


@router.get('/legacy/scans')
def scans(user=Depends(current_user)):
    return _safe_rows('network_scans', 3000, ('scan_time','created_at','id'))


@router.get('/legacy/ping-results')
def ping_results(user=Depends(current_user)):
    rows=_safe_rows('ping_results',3000,('ping_time','id'))
    for d in rows:
        d['response_time']=d.get('response_time',d.get('response'))
        d['timestamp']=d.get('timestamp') or d.get('ping_time') or d.get('created_at')
        d['created_at']=d.get('created_at') or d.get('ping_time')
    return rows


@router.get('/legacy/health-samples')
def health_samples(user=Depends(current_user)):
    return _safe_rows('health_samples', 3000, ('created_at','sample_time','id'))


@router.get('/legacy/interface-samples')
def interface_samples(user=Depends(current_user)):
    return _safe_rows('interface_samples', 5000, ('created_at','id'))


@router.get('/legacy/server-targets')
def server_targets(user=Depends(current_user)):
    return _safe_rows('server_monitor_targets', 2000, ('created_at','id'))


@router.get('/legacy/server-results')
def server_results(user=Depends(current_user)):
    c = get_connection()
    try:
        if not _table_exists(c, 'server_monitor_results'):
            return []
        if _table_exists(c, 'server_monitor_targets'):
            return [dict(r) for r in c.execute('''SELECT r.*,t.name,t.host,t.app_type,t.protocol,t.port
                FROM server_monitor_results r LEFT JOIN server_monitor_targets t ON t.id=r.target_id
                ORDER BY r.id DESC LIMIT 3000''').fetchall()]
        return _safe_rows('server_monitor_results', 3000, ('checked_at','id'))
    finally:
        c.close()


@router.get('/legacy/extensions')
def extensions(user=Depends(current_user)):
    return _safe_rows('extension_history', 3000, ('created_at','id'))


@router.get('/legacy/cameras')
def cameras(user=Depends(current_user)):
    c = get_connection()
    try:
        if not _table_exists(c, 'camera_registry'):
            return []
        cols = _cols(c, 'camera_registry')
        safe = [x for x in ('id','name','host','port') if x in cols]
        return [dict(r) for r in c.execute('SELECT '+','.join(safe)+' FROM camera_registry ORDER BY id').fetchall()] if safe else []
    finally:
        c.close()


@router.get('/legacy/sla-policies')
def sla_policies(user=Depends(current_user)):
    return _safe_rows('sla_policies', 2000, ('updated_at','created_at','id'))


@router.get('/legacy/operational-incidents')
def operational_incidents(user=Depends(current_user)):
    return _safe_rows('incidents', 3000, ('last_seen','id'))


@router.get('/legacy/alerts')
def alerts(user=Depends(current_user)):
    rows=_safe_rows('alerts',3000,('created_at','updated_at','id'))
    for d in rows:
        d['title']=d.get('title') or d.get('message') or d.get('alert_type') or 'Cảnh báo'
        d['ip']=d.get('ip') or d.get('ip_address')
        d['device']=d.get('device') or d.get('ip') or d.get('ip_address')
        if d.get('resolved') and str(d.get('status') or '').lower() not in ('closed','resolved'):
            d['status']='Resolved'
    return rows


@router.get('/legacy/backups')
def backups(user=Depends(current_user)):
    return _safe_rows('config_backups', 2000, ('created_at','id'))


@router.get('/legacy/baselines')
def baselines(user=Depends(current_user)):
    c = get_connection()
    try:
        if not _table_exists(c, 'config_baselines'):
            return []
        cols = _cols(c, 'config_baselines')
        # Do not return full device configurations to the overview table.
        safe = [x for x in ('id','device','source','updated_at') if x in cols]
        return [dict(r) for r in c.execute('SELECT '+','.join(safe)+' FROM config_baselines ORDER BY id DESC').fetchall()] if safe else []
    finally:
        c.close()


@router.get('/legacy/scheduled-tasks')
def scheduled_tasks(user=Depends(current_user)):
    return _safe_rows('scheduled_tasks', 2000, ('created_at','id'))


@router.get('/legacy/autoip-runs')
def autoip_runs(user=Depends(current_user)):
    return _safe_rows('autoip_runs', 2000, ('started_at','id'))


@router.get('/legacy/auto-audit-runs')
def auto_audit_runs(user=Depends(current_user)):
    rows=_safe_rows('auto_audit_runs',2000,('started_at','created_at','id'))
    for d in rows:
        if not d.get('status'):
            d['status']='FAILED' if int(d.get('failed') or 0)>0 else ('WARN' if int(d.get('warned') or 0)>0 else 'PASS')
    return rows


@router.get('/legacy/notifications')
def notifications(user=Depends(current_user)):
    rows = _safe_rows('notification_log', 3000, ('created_at','id'))
    return rows or _safe_rows('alerts', 3000, ('created_at','id'))


@router.get('/legacy/activity')
def activity(user=Depends(require_roles('Admin'))):
    rows = _safe_rows('audit_log', 3000, ('created_at','id'))
    return rows or _safe_rows('app_activity', 3000, ('created_at','id')) or _safe_rows('activity_logs', 3000, ('created_at','id'))


@router.get('/legacy/accounts')
def accounts(user=Depends(require_roles('Admin'))):
    c = get_connection()
    try:
        if not _table_exists(c, 'app_users'):
            return []
        cols = _cols(c, 'app_users')
        allowed = [x for x in ('id','username','role','enabled','created_at','updated_at','last_login_at','mfa_enabled') if x in cols]
        if not allowed:
            return []
        sql = 'SELECT ' + ','.join(f'"{x}"' for x in allowed) + ' FROM app_users ORDER BY id'
        return [dict(r) for r in c.execute(sql).fetchall()]
    finally:
        c.close()


class AccountCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)
    role: str = 'Viewer'
    enabled: bool = True


class AccountUpdate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    role: str
    enabled: bool = True


class PasswordReset(BaseModel):
    password: str = Field(min_length=8, max_length=256)


def _session(user):
    return {'id': int(user['id']), 'username': user['username'], 'role': user['role']}


@router.post('/legacy/accounts')
def create_account(body: AccountCreate, user=Depends(require_roles('Admin'))):
    try:
        return account_ops.create_user(_session(user), body.username, body.password, body.role, body.enabled)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.patch('/legacy/accounts/{user_id}')
def update_account(user_id: int, body: AccountUpdate, user=Depends(require_roles('Admin'))):
    try:
        return account_ops.update_user(_session(user), user_id, body.username, body.role, body.enabled)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post('/legacy/accounts/{user_id}/reset-password')
def reset_account_password(user_id: int, body: PasswordReset, user=Depends(require_roles('Admin'))):
    try:
        account_ops.reset_password(_session(user), user_id, body.password)
        return {'ok': True}
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc



class DeviceBody(BaseModel):
    ip: str = Field(min_length=1,max_length=128)
    hostname: str = ''
    mac: str = ''
    status: str = 'Unknown'
    duration: float | None = None

@router.post('/legacy/devices')
def create_legacy_device(body:DeviceBody,user=Depends(require_roles('Admin','Operator'))):
    if get_device_by_ip(body.ip.strip()): raise HTTPException(409,'IP đã tồn tại')
    did=create_device(body.ip.strip(),body.hostname.strip(),body.mac.strip(),body.status.strip() or 'Unknown',body.duration)
    if not did: raise HTTPException(400,'Không thể thêm thiết bị')
    return {'id':did,'ok':True}

@router.patch('/legacy/devices/{device_id}')
def update_legacy_device(device_id:int,body:DeviceBody,user=Depends(require_roles('Admin','Operator'))):
    if not update_device(device_id,body.ip.strip(),body.hostname.strip(),body.mac.strip(),body.status.strip() or 'Unknown',body.duration):
        raise HTTPException(404,'Không tìm thấy thiết bị')
    return {'ok':True}

@router.delete('/legacy/devices/{device_id}')
def delete_legacy_device(device_id:int,user=Depends(require_roles('Admin'))):
    if not delete_device(device_id): raise HTTPException(404,'Không tìm thấy thiết bị')
    return {'ok':True}

def _registered_ip_set():
    return {str(x.get('ip') or '').strip() for x in _unified_devices() if str(x.get('ip') or '').strip()}


def _update_operational_status(ip, status, response=None, hostname=None, record_ping=True):
    """Keep desktop and web inventory aligned with the latest read-only check."""
    c = get_connection()
    try:
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if record_ping and _table_exists(c, 'ping_results'):
            c.execute('INSERT INTO ping_results(ip,status,response,ping_time) VALUES(?,?,?,?)', (ip, status, response, now))
        for table, ip_names in (
            ('devices', ('ip','ip_address')),
            ('network_devices', ('ip','ip_address')),
            ('ip_mac_inventory', ('ip','ip_address')),
        ):
            cols = _cols(c, table)
            if not cols:
                continue
            ip_col = next((x for x in ip_names if x in cols), None)
            if not ip_col:
                continue
            sets=[]; params=[]
            if 'status' in cols:
                sets.append('status=?'); params.append(status)
            if table == 'devices' and 'duration' in cols and response is not None:
                sets.append('duration=?'); params.append(response)
            for candidate in ('last_seen','updated_at'):
                if candidate in cols:
                    sets.append(f'{candidate}=?'); params.append(now)
                    break
            if hostname:
                name_col = next((x for x in ('hostname','device_name','name') if x in cols), None)
                if name_col:
                    sets.append(f'{name_col}=CASE WHEN {name_col} IS NULL OR TRIM({name_col})=\'\' THEN ? ELSE {name_col} END')
                    params.append(hostname)
            if sets:
                params.append(ip)
                c.execute(f'UPDATE "{table}" SET '+','.join(sets)+f' WHERE "{ip_col}"=?', tuple(params))
        c.commit()
    finally:
        c.close()


@router.post('/legacy/devices/{ip}/ping')
def ping_registered_device(ip:str,user=Depends(require_roles('Admin','Operator'))):
    ip=ip.strip()
    if ip not in _registered_ip_set():
        raise HTTPException(403,'Chỉ được ping IP đã đăng ký trong hệ thống')
    result=ping_host(ip,timeout=1200)
    _update_operational_status(ip,result.get('status') or 'Unknown',result.get('response'))
    return result


@router.post('/legacy/devices/refresh-all')
def refresh_all_registered_devices(user=Depends(require_roles('Admin','Operator'))):
    """Ping registered devices only; capped to avoid accidental broad scanning."""
    ips=sorted(_registered_ip_set())[:128]
    results=[]
    for ip in ips:
        r=ping_host(ip,timeout=900)
        _update_operational_status(ip,r.get('status') or 'Unknown',r.get('response'))
        results.append(r)
    return {
        'total':len(results),
        'online':sum(r.get('status')=='Online' for r in results),
        'offline':sum(r.get('status')=='Offline' for r in results),
        'error':sum(r.get('status')=='Error' for r in results),
        'results':results,
    }


def _recent_for_ip(c, table, ip, ip_candidates, order_candidates, limit=50):
    if not _table_exists(c,table): return []
    cols=_cols(c,table)
    ip_col=next((x for x in ip_candidates if x in cols),None)
    if not ip_col: return []
    order=next((x for x in order_candidates if x in cols),None)
    sql=f'SELECT * FROM "{table}" WHERE "{ip_col}"=?'
    if order: sql+=f' ORDER BY "{order}" DESC'
    sql+=' LIMIT ?'
    return [dict(r) for r in c.execute(sql,(ip,max(1,min(int(limit),200)))).fetchall()]


@router.get('/legacy/devices/{ip}/history')
def registered_device_history(ip:str,user=Depends(current_user)):
    ip=ip.strip()
    if ip not in _registered_ip_set(): raise HTTPException(404,'Thiết bị chưa đăng ký')
    c=get_connection()
    try:
        ping=_recent_for_ip(c,'ping_results',ip,('ip','ip_address'),('ping_time','created_at','id'),50)
        health=_recent_for_ip(c,'health_samples',ip,('host','ip','ip_address'),('created_at','id'),50)
        snmp=_recent_for_ip(c,'snmp_samples',ip,('host','ip','ip_address'),('created_at','id'),50)
        diag=_recent_for_ip(c,'snmp_diagnostics_history',ip,('host','ip','ip_address'),('created_at','id'),20)
        alerts=_recent_for_ip(c,'alerts',ip,('ip','ip_address','host'),('created_at','id'),50)
        for d in diag: d.pop('credential_name',None)
        return {'ip':ip,'ping':ping,'health':health,'snmp':snmp,'snmp_diagnostics':diag,'alerts':alerts}
    finally:c.close()


@router.post('/legacy/devices/{ip}/snmp-refresh')
def snmp_refresh_registered_device(ip:str,user=Depends(require_roles('Admin','Operator'))):
    """Read-only SNMP v2c GET using an existing profile for a registered asset."""
    ip=ip.strip()
    if ip not in _registered_ip_set(): raise HTTPException(403,'Chỉ được kiểm tra SNMP thiết bị đã đăng ký')
    c=get_connection()
    try:
        if not _table_exists(c,'snmp_profiles'): raise HTTPException(404,'Chưa có SNMP profile')
        cols=_cols(c,'snmp_profiles')
        host_col=next((x for x in ('host','ip','ip_address') if x in cols),None)
        if not host_col: raise HTTPException(500,'SNMP profile không có cột host/IP')
        row=c.execute(f'SELECT * FROM snmp_profiles WHERE "{host_col}"=? ORDER BY id DESC LIMIT 1',(ip,)).fetchone()
        if not row: raise HTTPException(404,'Thiết bị chưa có SNMP profile')
        profile=dict(row)
    finally:c.close()
    community=str(profile.get('community') or '').strip()
    if not community: raise HTTPException(400,'SNMP profile chưa có community')
    try:
        from modules.advanced_pages import snmp_get
        oids=['1.3.6.1.2.1.1.5.0','1.3.6.1.2.1.1.1.0','1.3.6.1.2.1.1.3.0']
        data=snmp_get(ip,community,oids,port=int(profile.get('port') or 161),timeout=1.5)
        hostname=data.get('1.3.6.1.2.1.1.5.0')
        _update_operational_status(ip,'Online',hostname=hostname,record_ping=False)
        return {
            'ip':ip,'success':True,'sys_name':hostname,
            'sys_descr':data.get('1.3.6.1.2.1.1.1.0'),
            'uptime_ticks':data.get('1.3.6.1.2.1.1.3.0'),
            'profile':profile.get('name') or '',
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502,f'SNMP không phản hồi: {str(exc)[:300]}') from exc


@router.get('/legacy/snmp-profiles')
def snmp_profiles(user=Depends(current_user)):
    rows=_safe_rows('snmp_profiles',2000,('created_at','id'))
    for d in rows: d.pop('community',None)
    return rows

@router.get('/legacy/snmp-samples')
def snmp_samples(user=Depends(current_user)):
    return _safe_rows('snmp_samples',3000,('created_at','id'))

@router.get('/legacy/snmp-diagnostics')
def snmp_diagnostics(user=Depends(current_user)):
    rows=_safe_rows('snmp_diagnostics_history',3000,('created_at','id'))
    for d in rows: d.pop('credential_name',None)
    return rows

@router.get('/legacy/system-health')
def system_health(user=Depends(current_user)):
    return _safe_rows('system_health_history',2000,('created_at','id'))

@router.get('/legacy/data-quality')
def data_quality(user=Depends(require_roles('Admin'))):
    c=get_connection()
    try:
        important=['devices','network_devices','ip_mac_inventory','network_scans','ping_results','snmp_profiles','snmp_samples','snmp_diagnostics_history','health_samples','interface_samples','server_monitor_targets','server_monitor_results','alerts','incidents','security_assets','security_events']
        tables=[]
        for name in important:
            cols=_cols(c,name); tables.append({'table':name,'exists':bool(cols),'rows':_count(c,name),'columns':cols})
        unified=_unified_devices()
        total=len(unified)
        coverage={}
        for field in ('hostname','mac','status','vendor','device_type','last_seen','source'):
            present=sum(1 for x in unified if str(x.get(field) or '').strip() not in ('','Unknown'))
            coverage[field]={'present':present,'missing':max(0,total-present),'percent':round((present*100/total),1) if total else 0}
        source_counts={}
        for x in unified:
            for source in str(x.get('source') or '').split(','):
                source=source.strip()
                if source: source_counts[source]=source_counts.get(source,0)+1
        return {
            'database_path':str(DB_PATH),'unified_devices':total,
            'online':sum(x.get('status')=='Online' for x in unified),
            'offline':sum(x.get('status')=='Offline' for x in unified),
            'unknown':sum(x.get('status') not in ('Online','Offline') for x in unified),
            'coverage':coverage,'source_counts':source_counts,'tables':tables
        }
    finally:c.close()

@router.get('/legacy/database-info')
def database_info(user=Depends(require_roles('Admin'))):
    p = Path(DB_PATH)
    c = get_connection()
    try:
        tables = [r['name'] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()]
        populated = []
        for name in tables:
            n = _count(c, name)
            if n:
                populated.append({'table': name, 'rows': n})
        return {
            'db_path': str(p),
            'exists': p.exists(),
            'size_bytes': p.stat().st_size if p.exists() else 0,
            'data_dir': str(DATA_DIR),
            'database_dir': str(DATABASE_DIR),
            'tables': len(tables),
            'populated_tables': populated,
        }
    finally:
        c.close()


@router.get('/legacy/table-status')
def table_status(user=Depends(require_roles('Admin'))):
    names = [
        'devices','network_devices','ip_mac_inventory','network_scans','ping_results','health_samples','interface_samples',
        'alerts','config_backups','scheduled_tasks','server_monitor_targets','server_monitor_results','camera_registry','extension_history',
        'sla_policies','incidents','config_baselines','notification_log','autoip_runs','auto_audit_runs','app_users',
        'security_assets','security_events','security_incidents','vulnerabilities','patch_records','compliance_controls'
    ]
    c = get_connection()
    try:
        return [{'table': n, 'exists': _table_exists(c,n), 'rows': _count(c,n)} for n in names]
    finally:
        c.close()
