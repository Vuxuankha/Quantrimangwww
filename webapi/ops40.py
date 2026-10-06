from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import secrets
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app_runtime import BACKUP_DIR
from webapi.runtime37 import connection, utcnow
from webapi.security37 import require_role

router = APIRouter(prefix='/api/v4', tags=['v4-operations'])


def now_local() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def ensure_tables() -> None:
    # Reuse the additive desktop migrations. These functions create schema only;
    # they do not start Tk or network collectors.
    from modules.advanced_pages import ensure_advanced_tables
    from modules.nms_v4 import ensure_v4_tables
    from modules.nms_v6 import ensure_v6_tables
    from modules.nms_v8 import ensure_v8_tables
    from modules.nms_v9 import ensure_v9_tables
    from modules.nms_v10 import ensure_v10_tables
    from modules.monitor_extensions import ensure_tables as ensure_extension_tables

    ensure_advanced_tables()
    ensure_v4_tables()
    ensure_v6_tables()
    ensure_v8_tables()
    ensure_v9_tables()
    ensure_v10_tables()
    ensure_extension_tables()
    with connection() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS web_schedules40(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          operation TEXT NOT NULL,
          device_ids_json TEXT NOT NULL DEFAULT '[]',
          network TEXT NOT NULL DEFAULT '',
          parameters_json TEXT NOT NULL DEFAULT '{}',
          interval_minutes INTEGER NOT NULL DEFAULT 60,
          enabled INTEGER NOT NULL DEFAULT 1,
          actor_id INTEGER NOT NULL,
          actor TEXT NOT NULL,
          next_epoch REAL,
          last_run TEXT,
          last_status TEXT,
          last_job_id INTEGER,
          created_at TEXT,
          updated_at TEXT
        );
        CREATE INDEX IF NOT EXISTS ix_web_schedules40_due ON web_schedules40(enabled,next_epoch);
        ''')


# ---------------- Topology / dependencies ----------------

class DependencyIn(BaseModel):
    parent_device_id: int = Field(gt=0)
    child_device_id: int = Field(gt=0)
    relation_type: str = Field(default='Network', max_length=64)
    criticality: Literal['Low','Normal','High','Critical'] = 'Normal'
    note: str = Field(default='', max_length=500)


def _managed_row(c, did: int):
    return c.execute("SELECT id,COALESCE(NULLIF(name,''),NULLIF(device_name,''),ip,ip_address) name,COALESCE(NULLIF(ip,''),ip_address) ip,COALESCE(status,'Unknown') status,COALESCE(vendor,'') vendor,COALESCE(device_type,'') device_type FROM network_devices WHERE id=?", (did,)).fetchone()


@router.get('/topology')
def topology(request: Request):
    require_role(request)
    ensure_tables()
    with connection() as c:
        nodes = [dict(r) for r in c.execute('''
          SELECT d.id,COALESCE(NULLIF(d.name,''),NULLIF(d.device_name,''),d.ip,d.ip_address) name,
                 COALESCE(NULLIF(d.ip,''),d.ip_address) ip,COALESCE(d.status,'Unknown') status,
                 COALESCE(d.vendor,'') vendor,COALESCE(d.device_type,'') device_type,
                 COALESCE(s.name,'') site,COALESCE(g.name,'') device_group
          FROM network_devices d
          LEFT JOIN device_organization o ON o.device_id=d.id
          LEFT JOIN sites s ON s.id=o.site_id
          LEFT JOIN device_groups g ON g.id=o.group_id
          ORDER BY name,ip
        ''')]
        links = [dict(r) for r in c.execute('''
          SELECT l.id,l.source_device_id source_id,l.target_device_id target_id,l.label,'Discovered/Manual' source,l.created_at
          FROM device_links l ORDER BY l.id
        ''')]
        deps = [dict(r) for r in c.execute('''
          SELECT dd.id,dd.parent_device_id source_id,dd.child_device_id target_id,
                 dd.relation_type||' / '||dd.criticality label,'Dependency' source,dd.updated_at created_at,
                 dd.relation_type,dd.criticality,dd.note,dd.enabled
          FROM device_dependencies dd ORDER BY dd.id
        ''')]
        discovery = [dict(r) for r in c.execute('SELECT * FROM discovery_links ORDER BY discovered_at DESC LIMIT 1000')]
    return {'nodes': nodes, 'links': links + deps, 'discovery': discovery}


@router.post('/topology/dependencies')
def add_dependency(x: DependencyIn, request: Request):
    require_role(request, 'Admin')
    if x.parent_device_id == x.child_device_id:
        raise HTTPException(400, 'Thiết bị cha và con phải khác nhau.')
    with connection() as c:
        if not _managed_row(c, x.parent_device_id) or not _managed_row(c, x.child_device_id):
            raise HTTPException(404, 'Managed device không tồn tại.')
        try:
            cur = c.execute('''INSERT INTO device_dependencies(parent_device_id,child_device_id,relation_type,criticality,enabled,note,created_at,updated_at)
                               VALUES(?,?,?,?,1,?,?,?)''',
                            (x.parent_device_id, x.child_device_id, x.relation_type.strip() or 'Network', x.criticality, x.note.strip(), now_local(), now_local()))
        except Exception as exc:
            if 'UNIQUE' in str(exc).upper():
                raise HTTPException(409, 'Quan hệ phụ thuộc đã tồn tại.')
            raise
        return {'success': True, 'id': cur.lastrowid}


@router.delete('/topology/dependencies/{dep_id}')
def delete_dependency(dep_id: int, request: Request):
    require_role(request, 'Admin')
    with connection() as c:
        cur = c.execute('DELETE FROM device_dependencies WHERE id=?', (dep_id,))
        if not cur.rowcount:
            raise HTTPException(404, 'Dependency not found')
    return {'success': True}


def discover_topology(device_ids: list[int] | None = None) -> dict:
    """Run the desktop LLDP/CDP v2c walk for registered devices with a configured v2c profile.

    SNMPv3 WALK is not implemented in the desktop module, so v3-only devices are
    reported as skipped instead of silently downgrading security.
    """
    from modules.nms_v4 import snmp_walk, AutoTopologyPage
    ensure_tables()
    with connection() as c:
        sql = "SELECT id,COALESCE(NULLIF(name,''),NULLIF(device_name,''),ip,ip_address) name,COALESCE(NULLIF(ip,''),ip_address) ip FROM network_devices"
        args: list[object] = []
        if device_ids:
            sql += ' WHERE id IN (' + ','.join('?' for _ in device_ids) + ')'
            args.extend(device_ids)
        devices = [dict(r) for r in c.execute(sql, args).fetchall()]
        profiles = {str(r['host']): dict(r) for r in c.execute('SELECT * FROM snmp_profiles WHERE enabled=1').fetchall() if r['host']}
        secure_v2 = {r['device_id']: dict(r) for r in c.execute('SELECT a.device_id,s.community_enc,s.port,s.name FROM web_device_snmpv2_assignments42 a JOIN web_snmpv2_credentials42 s ON s.id=a.credential_id').fetchall()}
        v3_ids = {r['device_id'] for r in c.execute('SELECT device_id FROM device_snmpv3_assignments').fetchall()}
    found: list[tuple[str,str,str,str,str]] = []
    skipped = []
    failures = []
    for d in devices:
        host = str(d.get('ip') or '').strip()
        p = profiles.get(host); sp = secure_v2.get(d['id'])
        if not host:
            skipped.append({'device_id': d['id'], 'reason': 'missing IP'}); continue
        if not (sp or p):
            skipped.append({'device_id': d['id'], 'ip': host, 'reason': 'SNMPv3-only walk not supported by desktop module' if d['id'] in v3_ids else 'no enabled SNMP v2c credential/profile'})
            continue
        if sp:
            from modules.nms_v5 import decrypt_secret
            community=decrypt_secret(sp['community_enc']); port=int(sp['port'] or 161)
        else:
            community=p['community']; port=int(p['port'] or 161)
        for proto, bn, bp in [('LLDP', AutoTopologyPage.LLDP_NAME, AutoTopologyPage.LLDP_RPORT), ('CDP', AutoTopologyPage.CDP_NAME, AutoTopologyPage.CDP_RPORT)]:
            try:
                names = snmp_walk(host, community, bn, port=port)
                ports = {AutoTopologyPage._suffix(o, bp): v for o, v in snmp_walk(host, community, bp, port=port)}
                for oid, name in names:
                    suf = AutoTopologyPage._suffix(oid, bn)
                    local_port = suf.split('.')[-2] if '.' in suf else suf
                    found.append((proto, host, local_port, str(name), str(ports.get(suf, ''))))
            except Exception as exc:
                failures.append({'device_id': d['id'], 'ip': host, 'protocol': proto, 'error': type(exc).__name__})
    with connection() as c:
        for row in found:
            c.execute('INSERT INTO discovery_links(protocol,local_host,local_port,remote_name,remote_port,discovered_at) VALUES(?,?,?,?,?,?)', row + (now_local(),))
        all_devices = [dict(r) for r in c.execute("SELECT id,COALESCE(NULLIF(name,''),NULLIF(device_name,''),'') name,COALESCE(NULLIF(ip,''),ip_address) ip FROM network_devices")]
        by_ip = {str(x.get('ip') or '').strip(): x for x in all_devices if x.get('ip')}
        def match(text: str):
            t=(text or '').strip().lower()
            for x in all_devices:
                if t and (t==str(x.get('name') or '').strip().lower() or t==str(x.get('ip') or '').strip().lower()): return x
            return None
        mapped=0
        for proto, lh, lp, rn, rp in found:
            a=by_ip.get(lh); b=match(rn)
            if a and b and a['id'] != b['id']:
                x,y=sorted((a['id'],b['id']))
                before=c.total_changes
                c.execute('INSERT OR IGNORE INTO device_links(source_device_id,target_device_id,label,created_at) VALUES(?,?,?,?)',(x,y,f'{proto}: {lp} ↔ {rp}',now_local()))
                if c.total_changes>before: mapped += 1
    return {'success': True, 'observations': len(found), 'mapped_links': mapped, 'skipped': skipped, 'failures': failures}


# ---------------- SLA / maintenance / capacity ----------------

class SlaIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scope_type: Literal['Device','Site','Group','All'] = 'Device'
    scope_id: int | None = None
    host: str = Field(default='', max_length=255)
    target_percent: float = Field(default=99.0, ge=0, le=100)
    period_days: int = Field(default=30, ge=1, le=365)
    enabled: bool = True
    note: str = Field(default='', max_length=500)

class MaintenanceIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scope_type: Literal['Device','Site','Group','All'] = 'Device'
    scope_id: int | None = None
    host: str = Field(default='', max_length=255)
    start_at: str
    end_at: str
    suppress_alerts: bool = True
    enabled: bool = True
    note: str = Field(default='', max_length=500)


def _validate_dt_range(start: str, end: str):
    try:
        s=datetime.strptime(start,'%Y-%m-%d %H:%M:%S'); e=datetime.strptime(end,'%Y-%m-%d %H:%M:%S')
    except ValueError:
        raise HTTPException(400,'Thời gian phải theo YYYY-MM-DD HH:MM:SS')
    if e <= s: raise HTTPException(400,'Thời gian kết thúc phải sau thời gian bắt đầu.')


def _validated_scope_values(c, scope_type: str, scope_id: int | None, host: str):
    host=(host or '').strip()
    if scope_type == 'All':
        return None, ''
    if scope_type == 'Device':
        if scope_id:
            d=_managed_row(c,int(scope_id))
            if not d: raise HTTPException(404,'Managed device not found')
            actual=str(d['ip'] or '').strip()
            if host and actual and host != actual:
                raise HTTPException(400,'Host does not match the selected managed device')
            return int(scope_id), actual
        if not host: raise HTTPException(400,'Device scope requires scope_id or host')
        try: ipaddress.ip_address(host)
        except ValueError: raise HTTPException(400,'Device host must be a valid IP address')
        row=c.execute("SELECT id FROM network_devices WHERE COALESCE(NULLIF(ip,''),ip_address)=? LIMIT 1",(host,)).fetchone()
        return (int(row['id']) if row else None), host
    if not scope_id: raise HTTPException(400,f'{scope_type} scope requires scope_id')
    table='sites' if scope_type=='Site' else 'device_groups'
    if not c.execute(f'SELECT 1 FROM {table} WHERE id=?',(int(scope_id),)).fetchone():
        raise HTTPException(404,f'{scope_type} not found')
    return int(scope_id), ''


@router.get('/sla')
def sla_overview(request: Request):
    require_role(request)
    ensure_tables()
    from modules.nms_v9 import _scope_hosts, calculate_availability
    with connection() as c:
        policies=[dict(r) for r in c.execute('SELECT * FROM sla_policies ORDER BY id DESC')]
    for p in policies:
        hosts=_scope_hosts(p['scope_type'],p.get('scope_id'),p.get('host') or '')
        results=[calculate_availability(h,p['period_days'],True) for h in hosts]
        vals=[x['availability'] for x in results if x['availability'] is not None]
        p['host_count']=len(hosts);p['availability']=round(sum(vals)/len(vals),3) if vals else None
        p['met']=None if p['availability'] is None else p['availability']>=float(p['target_percent'])
        p['sample_count']=sum(x['samples'] for x in results)
    return policies


@router.post('/sla')
def create_sla(x:SlaIn, request:Request):
    require_role(request,'Admin')
    with connection() as c:
        scope_id,host=_validated_scope_values(c,x.scope_type,x.scope_id,x.host)
        cur=c.execute('''INSERT INTO sla_policies(name,scope_type,scope_id,host,target_percent,period_days,enabled,note,created_at,updated_at)
                         VALUES(?,?,?,?,?,?,?,?,?,?)''',(x.name.strip(),x.scope_type,scope_id,host,x.target_percent,x.period_days,int(x.enabled),x.note.strip(),now_local(),now_local()))
    return {'success':True,'id':cur.lastrowid}


@router.put('/sla/{policy_id}')
def update_sla(policy_id:int,x:SlaIn,request:Request):
    require_role(request,'Admin')
    with connection() as c:
        if not c.execute('SELECT 1 FROM sla_policies WHERE id=?',(policy_id,)).fetchone(): raise HTTPException(404,'SLA policy not found')
        scope_id,host=_validated_scope_values(c,x.scope_type,x.scope_id,x.host)
        c.execute('''UPDATE sla_policies SET name=?,scope_type=?,scope_id=?,host=?,target_percent=?,period_days=?,enabled=?,note=?,updated_at=? WHERE id=?''',(x.name.strip(),x.scope_type,scope_id,host,x.target_percent,x.period_days,int(x.enabled),x.note.strip(),now_local(),policy_id))
    return {'success':True}


@router.delete('/sla/{policy_id}')
def delete_sla(policy_id:int,request:Request):
    require_role(request,'Admin')
    with connection() as c:
        cur=c.execute('DELETE FROM sla_policies WHERE id=?',(policy_id,))
        if not cur.rowcount: raise HTTPException(404,'SLA policy not found')
    return {'success':True}


@router.get('/availability')
def availability(request:Request, days:int=30):
    require_role(request); days=max(1,min(days,365))
    from modules.nms_v9 import calculate_availability
    with connection() as c:
        ds=[dict(r) for r in c.execute("SELECT id,COALESCE(NULLIF(name,''),NULLIF(device_name,''),ip,ip_address) name,COALESCE(NULLIF(ip,''),ip_address) ip FROM network_devices ORDER BY name")]
    out=[]
    for d in ds:
        if not d.get('ip'): continue
        r=calculate_availability(d['ip'],days,True);out.append({**d,**r})
    return out


@router.get('/capacity/{device_id}')
def capacity(device_id:int,request:Request,days:int=7):
    require_role(request); days=max(1,min(days,90))
    from modules.nms_v9 import capacity_summary
    with connection() as c: d=_managed_row(c,device_id)
    if not d: raise HTTPException(404,'Managed device not found')
    return {'device':dict(d),'days':days,'summary':capacity_summary(d['ip'],days)}


@router.get('/maintenance')
def maintenance(request:Request):
    require_role(request)
    return [dict(r) for r in _query('SELECT * FROM maintenance_windows ORDER BY start_at DESC')]


def _query(sql,args=()):
    with connection() as c: return c.execute(sql,args).fetchall()


@router.post('/maintenance')
def create_maintenance(x:MaintenanceIn,request:Request):
    require_role(request,'Admin');_validate_dt_range(x.start_at,x.end_at)
    with connection() as c:
        scope_id,host=_validated_scope_values(c,x.scope_type,x.scope_id,x.host)
        cur=c.execute('''INSERT INTO maintenance_windows(name,scope_type,scope_id,host,start_at,end_at,suppress_alerts,enabled,note,created_at,updated_at)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?)''',(x.name.strip(),x.scope_type,scope_id,host,x.start_at,x.end_at,int(x.suppress_alerts),int(x.enabled),x.note.strip(),now_local(),now_local()))
    return {'success':True,'id':cur.lastrowid}


@router.put('/maintenance/{mid}')
def update_maintenance(mid:int,x:MaintenanceIn,request:Request):
    require_role(request,'Admin');_validate_dt_range(x.start_at,x.end_at)
    with connection() as c:
        if not c.execute('SELECT 1 FROM maintenance_windows WHERE id=?',(mid,)).fetchone(): raise HTTPException(404,'Maintenance window not found')
        scope_id,host=_validated_scope_values(c,x.scope_type,x.scope_id,x.host)
        c.execute('''UPDATE maintenance_windows SET name=?,scope_type=?,scope_id=?,host=?,start_at=?,end_at=?,suppress_alerts=?,enabled=?,note=?,updated_at=? WHERE id=?''',(x.name.strip(),x.scope_type,scope_id,host,x.start_at,x.end_at,int(x.suppress_alerts),int(x.enabled),x.note.strip(),now_local(),mid))
    return {'success':True}


@router.delete('/maintenance/{mid}')
def delete_maintenance(mid:int,request:Request):
    require_role(request,'Admin')
    with connection() as c:
        cur=c.execute('DELETE FROM maintenance_windows WHERE id=?',(mid,))
        if not cur.rowcount: raise HTTPException(404,'Maintenance window not found')
    return {'success':True}


# ---------------- Organization ----------------

class NameIn(BaseModel):
    name:str=Field(min_length=1,max_length=120)
    note:str=Field(default='',max_length=500)
    location:str=Field(default='',max_length=255)

class OrgAssignIn(BaseModel):
    site_id:int|None=None
    group_id:int|None=None
    vlan:str=Field(default='',max_length=64)
    tags:str=Field(default='',max_length=500)


@router.get('/organization')
def organization(request:Request):
    require_role(request)
    with connection() as c:
        sites=[dict(r) for r in c.execute('SELECT * FROM sites ORDER BY name')]
        groups=[dict(r) for r in c.execute('SELECT * FROM device_groups ORDER BY name')]
        devices=[dict(r) for r in c.execute('''SELECT d.id,COALESCE(NULLIF(d.name,''),NULLIF(d.device_name,''),d.ip,d.ip_address) name,COALESCE(NULLIF(d.ip,''),d.ip_address) ip,d.vendor,s.name site,g.name device_group,o.site_id,o.group_id,o.vlan,o.tags
          FROM network_devices d LEFT JOIN device_organization o ON o.device_id=d.id LEFT JOIN sites s ON s.id=o.site_id LEFT JOIN device_groups g ON g.id=o.group_id ORDER BY name''')]
    return {'sites':sites,'groups':groups,'devices':devices}


@router.post('/organization/sites')
def create_site(x:NameIn,request:Request):
    require_role(request,'Admin')
    try:
        with connection() as c: cur=c.execute('INSERT INTO sites(name,location,note,created_at,updated_at) VALUES(?,?,?,?,?)',(x.name.strip(),x.location.strip(),x.note.strip(),now_local(),now_local()))
    except Exception as e:
        if 'UNIQUE' in str(e).upper(): raise HTTPException(409,'Site đã tồn tại')
        raise
    return {'success':True,'id':cur.lastrowid}


@router.post('/organization/groups')
def create_group(x:NameIn,request:Request):
    require_role(request,'Admin')
    try:
        with connection() as c: cur=c.execute('INSERT INTO device_groups(name,note,created_at,updated_at) VALUES(?,?,?,?)',(x.name.strip(),x.note.strip(),now_local(),now_local()))
    except Exception as e:
        if 'UNIQUE' in str(e).upper(): raise HTTPException(409,'Nhóm đã tồn tại')
        raise
    return {'success':True,'id':cur.lastrowid}


@router.put('/organization/sites/{site_id}')
def update_site(site_id:int,x:NameIn,request:Request):
    require_role(request,'Admin')
    try:
        with connection() as c:
            cur=c.execute('UPDATE sites SET name=?,location=?,note=?,updated_at=? WHERE id=?',(x.name.strip(),x.location.strip(),x.note.strip(),now_local(),site_id))
            if not cur.rowcount: raise HTTPException(404,'Site not found')
    except HTTPException: raise
    except Exception as e:
        if 'UNIQUE' in str(e).upper(): raise HTTPException(409,'Site đã tồn tại')
        raise
    return {'success':True}

@router.delete('/organization/sites/{site_id}')
def delete_site(site_id:int,request:Request):
    require_role(request,'Admin')
    with connection() as c:
        if c.execute('SELECT 1 FROM device_organization WHERE site_id=? LIMIT 1',(site_id,)).fetchone():
            raise HTTPException(409,'Site đang được gán cho thiết bị; hãy bỏ gán trước.')
        cur=c.execute('DELETE FROM sites WHERE id=?',(site_id,))
        if not cur.rowcount: raise HTTPException(404,'Site not found')
    return {'success':True}

@router.put('/organization/groups/{group_id}')
def update_group(group_id:int,x:NameIn,request:Request):
    require_role(request,'Admin')
    try:
        with connection() as c:
            cur=c.execute('UPDATE device_groups SET name=?,note=?,updated_at=? WHERE id=?',(x.name.strip(),x.note.strip(),now_local(),group_id))
            if not cur.rowcount: raise HTTPException(404,'Group not found')
    except HTTPException: raise
    except Exception as e:
        if 'UNIQUE' in str(e).upper(): raise HTTPException(409,'Nhóm đã tồn tại')
        raise
    return {'success':True}

@router.delete('/organization/groups/{group_id}')
def delete_group(group_id:int,request:Request):
    require_role(request,'Admin')
    with connection() as c:
        if c.execute('SELECT 1 FROM device_organization WHERE group_id=? LIMIT 1',(group_id,)).fetchone():
            raise HTTPException(409,'Nhóm đang được gán cho thiết bị; hãy bỏ gán trước.')
        cur=c.execute('DELETE FROM device_groups WHERE id=?',(group_id,))
        if not cur.rowcount: raise HTTPException(404,'Group not found')
    return {'success':True}


@router.put('/organization/devices/{device_id}')
def assign_org(device_id:int,x:OrgAssignIn,request:Request):
    require_role(request,'Admin')
    with connection() as c:
        if not _managed_row(c,device_id): raise HTTPException(404,'Managed device not found')
        if x.site_id is not None and not c.execute('SELECT 1 FROM sites WHERE id=?',(x.site_id,)).fetchone(): raise HTTPException(404,'Site not found')
        if x.group_id is not None and not c.execute('SELECT 1 FROM device_groups WHERE id=?',(x.group_id,)).fetchone(): raise HTTPException(404,'Group not found')
        c.execute('''INSERT INTO device_organization(device_id,site_id,group_id,vlan,tags,updated_at) VALUES(?,?,?,?,?,?)
          ON CONFLICT(device_id) DO UPDATE SET site_id=excluded.site_id,group_id=excluded.group_id,vlan=excluded.vlan,tags=excluded.tags,updated_at=excluded.updated_at''',(device_id,x.site_id,x.group_id,x.vlan.strip(),x.tags.strip(),now_local()))
    return {'success':True}


# ---------------- Incidents / RCA ----------------

class IncidentStateIn(BaseModel):
    status: Literal['Open','Acknowledged','Resolved']
    note: str = Field(default='', max_length=1000)


def sync_incidents_and_rca() -> dict:
    from modules.nms_v9 import sync_incidents
    from modules.nms_v10 import analyze_root_causes
    a=sync_incidents(); r=analyze_root_causes()
    return {'incidents':{'created':a[0],'linked':a[1],'resolved':a[2]},'rca':r}


@router.post('/incidents/sync')
def api_sync_incidents(request:Request):
    require_role(request,'Admin','Operator');return sync_incidents_and_rca()


@router.put('/incidents/{incident_id}')
def incident_state(incident_id:int,x:IncidentStateIn,request:Request):
    u=require_role(request,'Admin','Operator')
    with connection() as c:
        row=c.execute('SELECT * FROM incidents WHERE id=?',(incident_id,)).fetchone()
        if not row: raise HTTPException(404,'Incident not found')
        ack=u['username'] if x.status=='Acknowledged' else row['ack_by']
        resolved=now_local() if x.status=='Resolved' else None
        c.execute('UPDATE incidents SET status=?,ack_by=?,resolved_at=?,note=?,last_seen=? WHERE id=?',(x.status,ack,resolved,x.note.strip(),now_local(),incident_id))
    return {'success':True}


# ---------------- Wi-Fi / Camera ----------------

class CameraIn(BaseModel):
    name:str=Field(min_length=1,max_length=120)
    host:str=Field(min_length=1,max_length=255)
    port:int=Field(default=554,ge=1,le=65535)
    stream:str=Field(default='',max_length=2000)
    snapshot:str=Field(default='',max_length=2000)

class WifiIn(BaseModel):
    gateway:str=Field(default='',max_length=255)
    internet:str=Field(default='1.1.1.1',max_length=255)


@router.get('/extensions')
def extensions(request:Request):
    require_role(request)
    from modules.monitor_extensions import cameras, wifi_adapter_status
    cams=[]
    for r in cameras():
        cams.append({'id':r['id'],'name':r['name'],'host':r['host'],'port':r['port'],'has_stream':bool(r.get('stream_enc')),'has_snapshot':bool(r.get('snapshot_enc'))})
    with connection() as c:
        hist=[dict(r) for r in c.execute('SELECT id,kind,target,status,detail,created_at FROM extension_history ORDER BY id DESC LIMIT 200')]
    wifi=wifi_adapter_status()
    return {'cameras':cams,'history':hist,'platform':os.name,'wifi_supported':wifi.get('supported',False),'wifi_status':wifi}


@router.post('/cameras')
def add_camera(x:CameraIn,request:Request):
    require_role(request,'Admin')
    from modules.monitor_extensions import save_camera
    try: save_camera(x.name,x.host,x.port,x.stream,x.snapshot)
    except ValueError as e: raise HTTPException(400,str(e))
    return {'success':True}


@router.put('/cameras/{camera_id}')
def update_camera(camera_id:int,x:CameraIn,request:Request):
    require_role(request,'Admin')
    try: ipaddress.ip_address(x.host.strip())
    except ValueError:
        if not x.host.strip() or any(ch.isspace() for ch in x.host): raise HTTPException(400,'Camera host không hợp lệ')
    from modules.nms_v5 import encrypt_secret
    if x.stream and not x.stream.lower().startswith(('rtsp://','rtsps://')): raise HTTPException(400,'Stream URL phải dùng rtsp/rtsps')
    if x.snapshot and not x.snapshot.lower().startswith(('http://','https://')): raise HTTPException(400,'Snapshot URL phải dùng http/https')
    with connection() as c:
        row=c.execute('SELECT * FROM camera_registry WHERE id=?',(camera_id,)).fetchone()
        if not row: raise HTTPException(404,'Camera not found')
        stream_enc=encrypt_secret(x.stream) if x.stream else row['stream_enc']
        snapshot_enc=encrypt_secret(x.snapshot) if x.snapshot else row['snapshot_enc']
        c.execute('UPDATE camera_registry SET name=?,host=?,port=?,stream_enc=?,snapshot_enc=? WHERE id=?',(x.name.strip(),x.host.strip(),x.port,stream_enc,snapshot_enc,camera_id))
    return {'success':True}

@router.delete('/cameras/{camera_id}')
def delete_camera(camera_id:int,request:Request):
    require_role(request,'Admin')
    with connection() as c:
        cur=c.execute('DELETE FROM camera_registry WHERE id=?',(camera_id,))
        if not cur.rowcount: raise HTTPException(404,'Camera not found')
    return {'success':True}


def run_camera_check(camera_id:int) -> dict:
    from modules.monitor_extensions import check_camera, history
    with connection() as c: r=c.execute('SELECT * FROM camera_registry WHERE id=?',(camera_id,)).fetchone()
    if not r: raise ValueError('Camera not found')
    cam=dict(r); status,detail=check_camera(cam); history('Camera',cam['host'],status,detail)
    return {'camera_id':camera_id,'name':cam['name'],'host':cam['host'],'status':status,'detail':detail}


def run_wifi_diag(gateway='',internet='1.1.1.1') -> dict:
    from modules.monitor_extensions import wifi_diagnostics, history, redact
    result=wifi_diagnostics(gateway,internet)
    safe=redact(json.dumps(result,ensure_ascii=False,indent=2))
    history('WiFi','Windows',str(result.get('status') or 'Checked'),safe)
    return result


# ---------------- Restore configuration ----------------

_RESTORE_LOCK=threading.Lock()
_RESTORE_TOKENS: dict[str,dict] = {}
_RESTORE_TTL=300


def _backup_file(backup_id:int) -> tuple[dict,Path]:
    with connection() as c:r=c.execute('SELECT * FROM config_backups WHERE id=?',(backup_id,)).fetchone()
    if not r: raise HTTPException(404,'Backup not found')
    d=dict(r); p=Path(str(d.get('file_path') or '')).expanduser().resolve()
    root=Path(BACKUP_DIR).resolve()
    # Web never reads arbitrary file paths from old imported backup records.
    if not p.is_file() or not p.is_relative_to(root):
        raise HTTPException(409,'Backup này không nằm trong thư mục backup được Web quản lý hoặc file không còn tồn tại.')
    if p.stat().st_size > 4*1024*1024: raise HTTPException(413,'Backup quá lớn để restore qua Web.')
    return d,p


def _redact_config(text:str) -> str:
    import re
    patterns=[
        (r'(?im)^(\s*(?:enable\s+secret|username\s+\S+\s+(?:password|secret)|snmp-server\s+community)\s+).+$',r'\1[REDACTED]'),
        (r'(?im)((?:password|passwd|community|secret|token)\s*[=:]\s*)\S+',r'\1[REDACTED]'),
    ]
    for pat,repl in patterns:text=re.sub(pat,repl,text)
    return text


@router.get('/restore')
def restore_overview(request:Request):
    require_role(request,'Admin')
    root=Path(BACKUP_DIR).resolve()
    with connection() as c:
        backups=[dict(r) for r in c.execute('SELECT * FROM config_backups ORDER BY id DESC LIMIT 500')]
        hist=[dict(r) for r in c.execute('''SELECT rh.*,COALESCE(NULLIF(d.name,''),NULLIF(d.device_name,''),d.ip,d.ip_address) device_name,COALESCE(NULLIF(d.ip,''),d.ip_address) ip FROM restore_history rh LEFT JOIN network_devices d ON d.id=rh.device_id ORDER BY rh.id DESC LIMIT 200''')]
    for b in backups:
        p=Path(str(b.get('file_path') or '')).expanduser()
        try: rp=p.resolve();managed=rp.is_relative_to(root) and rp.is_file()
        except Exception: managed=False
        b['filename']=p.name;b['restorable']=managed;b.pop('file_path',None)
    return {'backups':backups,'history':hist}


@router.post('/restore/prepare')
def restore_prepare(x:dict,request:Request):
    u=require_role(request,'Admin')
    try:device_id=int(x.get('device_id'));backup_id=int(x.get('backup_id'))
    except Exception:raise HTTPException(400,'device_id/backup_id không hợp lệ')
    b,p=_backup_file(backup_id)
    with connection() as c:
        d=_managed_row(c,device_id)
        if not d:raise HTTPException(404,'Managed device not found')
        cr=c.execute("""SELECT cr.id,cr.name,cr.username,cr.port FROM device_credentials dc JOIN credentials cr ON cr.id=dc.credential_id WHERE dc.device_id=? AND UPPER(cr.kind)='SSH' AND UPPER(dc.purpose) IN ('BACKUP','SSH') ORDER BY CASE UPPER(dc.purpose) WHEN 'BACKUP' THEN 0 ELSE 1 END LIMIT 1""",(device_id,)).fetchone()
        if not cr:raise HTTPException(409,'Thiết bị chưa có SSH/Backup credential.')
    raw=p.read_text(encoding='utf-8',errors='replace')
    sha=hashlib.sha256(p.read_bytes()).hexdigest()
    token=secrets.token_urlsafe(32);phrase=f'RESTORE {device_id} {backup_id}'
    with _RESTORE_LOCK:
        now=time.time();
        for k,v in list(_RESTORE_TOKENS.items()):
            if v['expires']<now:_RESTORE_TOKENS.pop(k,None)
        _RESTORE_TOKENS[token]={'user_id':u['id'],'device_id':device_id,'backup_id':backup_id,'sha256':sha,'expires':now+_RESTORE_TTL}
    return {'token':token,'expires_seconds':_RESTORE_TTL,'confirmation_phrase':phrase,'device':dict(d),'backup':{'id':backup_id,'filename':p.name,'size_bytes':p.stat().st_size,'sha256':sha},'preview':_redact_config('\n'.join(raw.splitlines()[:220]))}


def validate_restore_authorization(token:str,confirmation:str,user_id:int,device_id:int,backup_id:int) -> dict:
    phrase=f'RESTORE {device_id} {backup_id}'
    if confirmation.strip()!=phrase: raise ValueError('Confirmation phrase does not match')
    with _RESTORE_LOCK:
        data=_RESTORE_TOKENS.pop(token,None)
    if not data or data['expires']<time.time(): raise ValueError('Restore authorization expired; prepare again')
    if (data['user_id'],data['device_id'],data['backup_id'])!=(user_id,device_id,backup_id): raise ValueError('Restore authorization mismatch')
    b,p=_backup_file(backup_id)
    if hashlib.sha256(p.read_bytes()).hexdigest()!=data['sha256']: raise ValueError('Backup changed after preview')
    return {'backup':b,'path':p}


def execute_restore_job(device_id:int,backup_id:int,token:str,confirmation:str,actor:dict) -> dict:
    """Controlled Cisco-IOS style restore. No generic arbitrary-command restore."""
    auth=validate_restore_authorization(token,confirmation,actor['id'],device_id,backup_id)
    from modules.nms_v5 import ssh_backup,decrypt_secret
    from modules.nms_v6 import audit
    from modules.ssh_security import build_strict_ssh_client
    with connection() as c:
        d=_managed_row(c,device_id)
        if not d: raise ValueError('Managed device not found')
        full=dict(c.execute('SELECT * FROM network_devices WHERE id=?',(device_id,)).fetchone())
        cr=c.execute("""SELECT cr.* FROM device_credentials dc JOIN credentials cr ON cr.id=dc.credential_id WHERE dc.device_id=? AND UPPER(cr.kind)='SSH' AND UPPER(dc.purpose) IN ('BACKUP','SSH') ORDER BY CASE UPPER(dc.purpose) WHEN 'BACKUP' THEN 0 ELSE 1 END LIMIT 1""",(device_id,)).fetchone()
        if not cr: raise ValueError('Missing SSH/Backup credential')
        cr=dict(cr)
    vendor=(dict(d).get('vendor') or '').lower()
    if 'cisco' not in vendor:
        raise ValueError('Web restore is intentionally limited to Cisco-like managed devices; other vendors require a verified vendor-specific restore driver')
    path=auth['path']; text=path.read_text(encoding='utf-8',errors='replace')
    lines=text.splitlines()
    if len(lines)>20000:raise ValueError('Backup has too many lines for guarded Web restore')
    safety=ssh_backup(full,cr,'show running-config')
    status='Failed';detail=''
    try:
        import paramiko
        cli=build_strict_ssh_client(paramiko)
        cli.connect(full.get('ip') or full.get('ip_address'),port=int(cr.get('port') or 22),username=cr['username'],password=decrypt_secret(cr['secret_enc']),timeout=10,banner_timeout=15,auth_timeout=15,look_for_keys=False,allow_agent=False)
        sh=cli.invoke_shell(width=200,height=1000);time.sleep(.7);sh.send('configure terminal\n');time.sleep(.4)
        sent=0
        for line in lines:
            line=line.strip('\r')
            if line and not line.startswith(('!','Building configuration','Current configuration')):
                sh.send(line+'\n');sent+=1
                if sent%100==0:time.sleep(.15)
                else:time.sleep(.015)
        sh.send('end\nwrite memory\n');time.sleep(1);cli.close()
        status='Success';detail=f'Safety backup: {Path(safety).name}; sent lines: {sent}'
        return {'success':True,'status':status,'safety_backup':Path(safety).name,'sent_lines':sent}
    finally:
        if status!='Success' and not detail: detail='Restore failed before completion; inspect device console and safety backup.'
        with connection() as c:c.execute('INSERT INTO restore_history(username,device_id,backup_id,status,detail,created_at) VALUES(?,?,?,?,?,?)',(actor['username'],device_id,backup_id,status,detail[:2000],now_local()))
        audit(actor['username'],actor.get('role','Admin'),'Web restore config',str(dict(d).get('name') or dict(d).get('ip')),status+' - '+detail)


# ---------------- Scheduler models/endpoints ----------------

SCHEDULE_OPS={'PING','PING_ALL','SERVER_CHECK','SNMP','SSH_TEST','AUDIT','CONFIG_BACKUP','DB_BACKUP','REPORT','TOPOLOGY_DISCOVER','WIFI_DIAG','CAMERA_CHECK','INCIDENT_SYNC','RCA_ANALYZE','LAN_PROBE','DAILY_AUDIT'}

class ScheduleIn(BaseModel):
    name:str=Field(min_length=1,max_length=120)
    operation:str
    device_ids:list[int]=Field(default_factory=list,max_length=128)
    network:str=Field(default='',max_length=48)
    parameters:dict=Field(default_factory=dict)
    interval_minutes:int=Field(default=60,ge=1,le=10080)
    enabled:bool=True


def _validate_schedule(x:ScheduleIn):
    if x.operation not in SCHEDULE_OPS: raise HTTPException(400,'Operation không được phép lập lịch')
    if len(set(x.device_ids)) != len(x.device_ids) or any(int(i) < 1 for i in x.device_ids): raise HTTPException(400,'Danh sách thiết bị không hợp lệ hoặc bị trùng')
    if x.operation in {'PING','SNMP','SSH_TEST'} and not (1<=len(x.device_ids)<=20): raise HTTPException(400,'Chọn 1-20 thiết bị')
    if x.operation in {'AUDIT','CONFIG_BACKUP'} and not (1<=len(x.device_ids)<=5): raise HTTPException(400,'Chọn 1-5 thiết bị')
    if x.device_ids:
        with connection() as c:
            marks=','.join('?' for _ in x.device_ids)
            found={int(r['id']) for r in c.execute(f'SELECT id FROM network_devices WHERE id IN ({marks})',tuple(x.device_ids))}
        missing=sorted(set(x.device_ids)-found)
        if missing: raise HTTPException(404,f'Managed device IDs not found: {missing[:10]}')
    if x.operation=='CAMERA_CHECK':
        try: cid=int(x.parameters.get('camera_id'))
        except Exception: raise HTTPException(400,'camera_id required')
        if cid<1:raise HTTPException(400,'camera_id invalid')
        with connection() as c:
            if not c.execute('SELECT 1 FROM camera_registry WHERE id=?',(cid,)).fetchone(): raise HTTPException(404,'Camera not found')


@router.get('/schedules')
def schedules(request:Request):
    u=require_role(request,'Admin','Operator')
    from webapi.jobs37 import ROLES
    with connection() as c:
        data=[dict(r) for r in c.execute('SELECT * FROM web_schedules40 ORDER BY id DESC')]
    for row in data:
        row['can_run']=u['role'] in ROLES.get(row.get('operation'),())
    return data


@router.post('/schedules')
def create_schedule(x:ScheduleIn,request:Request):
    u=require_role(request,'Admin');_validate_schedule(x)
    epoch=time.time()+x.interval_minutes*60
    with connection() as c:
        cur=c.execute('''INSERT INTO web_schedules40(name,operation,device_ids_json,network,parameters_json,interval_minutes,enabled,actor_id,actor,next_epoch,created_at,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',(x.name.strip(),x.operation,json.dumps(x.device_ids),x.network,json.dumps(x.parameters),x.interval_minutes,int(x.enabled),u['id'],u['username'],epoch,utcnow(),utcnow()))
    return {'success':True,'id':cur.lastrowid}


@router.put('/schedules/{sid}')
def update_schedule(sid:int,x:ScheduleIn,request:Request):
    u=require_role(request,'Admin');_validate_schedule(x)
    with connection() as c:
        cur=c.execute('''UPDATE web_schedules40 SET name=?,operation=?,device_ids_json=?,network=?,parameters_json=?,interval_minutes=?,enabled=?,actor_id=?,actor=?,next_epoch=?,updated_at=? WHERE id=?''',(x.name.strip(),x.operation,json.dumps(x.device_ids),x.network,json.dumps(x.parameters),x.interval_minutes,int(x.enabled),u['id'],u['username'],time.time()+x.interval_minutes*60,utcnow(),sid))
        if not cur.rowcount:raise HTTPException(404,'Schedule not found')
    return {'success':True}


@router.delete('/schedules/{sid}')
def delete_schedule(sid:int,request:Request):
    require_role(request,'Admin')
    with connection() as c:
        cur=c.execute('DELETE FROM web_schedules40 WHERE id=?',(sid,))
        if not cur.rowcount:raise HTTPException(404,'Schedule not found')
    return {'success':True}


@router.post('/schedules/{sid}/run')
def run_schedule_now(sid:int,request:Request):
    u=require_role(request,'Admin','Operator')
    from webapi.scheduler40 import submit_schedule
    return submit_schedule(sid,u,manual=True)
