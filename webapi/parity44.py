from __future__ import annotations

import difflib
import hashlib
import ipaddress
import json
import math
import os
import platform
import re
import socket
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app_runtime import BACKUP_DIR, DATA_DIR, resource_path, hidden_subprocess_kwargs
from webapi.runtime37 import connection, utcnow
from webapi.security37 import require_role

router = APIRouter(prefix='/api/v44', tags=['v44-desktop-parity'])

READ_ONLY_BACKUP_COMMANDS = {
    '', 'show running-config', 'display current-configuration',
    'show configuration', '/export terse'
}
OID_RE = re.compile(r'^\d+(?:\.\d+)*$')


def _now() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _table(c, name: str) -> bool:
    return c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _cols(c, table: str) -> set[str]:
    return {r['name'] for r in c.execute(f'PRAGMA table_info("{table}")').fetchall()}


def ensure_tables() -> None:
    from modules.extra_pages import ensure_extra_tables
    from modules.advanced_pages import ensure_advanced_tables
    from modules.nms_v3 import ensure_v3_tables
    from modules.nms_v7 import ensure_v7_tables
    from modules.nms_v10 import ensure_v10_tables
    from modules.nms_v12 import ensure_v12_tables
    ensure_extra_tables(); ensure_advanced_tables(); ensure_v3_tables(); ensure_v7_tables(); ensure_v10_tables(); ensure_v12_tables()
    with connection() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS config_baselines(id INTEGER PRIMARY KEY AUTOINCREMENT,device TEXT NOT NULL UNIQUE,config TEXT NOT NULL,source TEXT,updated_at TEXT NOT NULL)''')


def _managed(c, device_id: int):
    r = c.execute('SELECT * FROM network_devices WHERE id=?', (device_id,)).fetchone()
    if not r:
        raise HTTPException(404, 'Không tìm thấy thiết bị quản lý.')
    return dict(r)


def _host(d: dict) -> str:
    return str(d.get('ip') or d.get('ip_address') or '').strip()


def _valid_oid(value: str) -> str:
    value = str(value or '').strip().lstrip('.')
    if value and not OID_RE.fullmatch(value):
        raise HTTPException(400, f'OID không hợp lệ: {value[:80]}')
    return value


def _num(value):
    try:
        n = float(value)
        return n if math.isfinite(n) else None
    except (TypeError, ValueError):
        return None


# ---------------- Device profiles / vendor drivers ----------------
class ProfileIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    vendor: str = Field(default='', max_length=120)
    match_text: str = Field(default='', max_length=500)
    cpu_oid: str = Field(default='', max_length=160)
    mem_used_oid: str = Field(default='', max_length=160)
    mem_total_oid: str = Field(default='', max_length=160)
    backup_command: str = Field(default='', max_length=160)
    lldp_mode: Literal['LLDP','LLDP/CDP','CDP','None'] = 'LLDP'
    note: str = Field(default='', max_length=1200)

class AssignIn(BaseModel):
    device_id: int = Field(gt=0)
    target_id: int = Field(gt=0)

class DriverIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    vendor: str = Field(default='', max_length=120)
    priority: int = Field(default=50, ge=0, le=1000)
    sysobject_prefix: str = Field(default='', max_length=160)
    descr_regex: str = Field(default='', max_length=500)
    cpu_oid: str = Field(default='', max_length=160)
    mem_used_oid: str = Field(default='', max_length=160)
    mem_total_oid: str = Field(default='', max_length=160)
    backup_command: str = Field(default='', max_length=160)
    save_command: str = Field(default='', max_length=160)
    lldp_mode: Literal['LLDP','LLDP/CDP','CDP','None'] = 'LLDP'
    note: str = Field(default='', max_length=1200)
    enabled: bool = True


def _profile_payload(x: ProfileIn):
    if x.backup_command.strip() not in READ_ONLY_BACKUP_COMMANDS:
        raise HTTPException(400, 'Lệnh backup profile không nằm trong allowlist read-only.')
    return (x.name.strip(), x.vendor.strip(), x.match_text.strip(), _valid_oid(x.cpu_oid),
            _valid_oid(x.mem_used_oid), _valid_oid(x.mem_total_oid), x.backup_command.strip(),
            x.lldp_mode, x.note.strip())

@router.get('/profiles')
def profiles(request: Request):
    require_role(request); ensure_tables()
    with connection() as c:
        prof=[dict(r) for r in c.execute('SELECT * FROM device_profiles ORDER BY builtin DESC,vendor,name')]
        dev=[dict(r) for r in c.execute('''SELECT d.id,COALESCE(NULLIF(d.name,''),NULLIF(d.device_name,''),d.ip,d.ip_address) name,
          COALESCE(NULLIF(d.ip,''),d.ip_address) ip,d.vendor,a.profile_id,a.source,p.name profile_name
          FROM network_devices d LEFT JOIN device_profile_assignments a ON a.device_id=d.id
          LEFT JOIN device_profiles p ON p.id=COALESCE(a.profile_id,d.profile_id) ORDER BY name,ip''')]
    return {'profiles':prof,'devices':dev}

@router.post('/profiles')
def create_profile(x: ProfileIn, request: Request):
    require_role(request,'Admin'); ensure_tables(); vals=_profile_payload(x); now=_now()
    with connection() as c:
        try:
            cur=c.execute('''INSERT INTO device_profiles(name,vendor,match_text,cpu_oid,mem_used_oid,mem_total_oid,backup_command,lldp_mode,note,builtin,created_at,updated_at)
              VALUES(?,?,?,?,?,?,?,?,?,0,?,?)''', vals+(now,now))
        except Exception as exc:
            raise HTTPException(409,'Tên hồ sơ đã tồn tại hoặc dữ liệu không hợp lệ.') from exc
    return {'success':True,'id':cur.lastrowid}

@router.put('/profiles/{profile_id}')
def update_profile(profile_id:int,x:ProfileIn,request:Request):
    require_role(request,'Admin'); ensure_tables(); vals=_profile_payload(x)
    with connection() as c:
        r=c.execute('SELECT builtin FROM device_profiles WHERE id=?',(profile_id,)).fetchone()
        if not r: raise HTTPException(404,'Không tìm thấy hồ sơ.')
        if r['builtin']: raise HTTPException(409,'Hồ sơ built-in được quản lý bởi ứng dụng; hãy tạo hồ sơ tùy chỉnh.')
        c.execute('''UPDATE device_profiles SET name=?,vendor=?,match_text=?,cpu_oid=?,mem_used_oid=?,mem_total_oid=?,backup_command=?,lldp_mode=?,note=?,updated_at=? WHERE id=?''', vals+(_now(),profile_id))
    return {'success':True}

@router.delete('/profiles/{profile_id}')
def delete_profile(profile_id:int,request:Request):
    require_role(request,'Admin'); ensure_tables()
    with connection() as c:
        r=c.execute('SELECT builtin FROM device_profiles WHERE id=?',(profile_id,)).fetchone()
        if not r: raise HTTPException(404,'Không tìm thấy hồ sơ.')
        if r['builtin']: raise HTTPException(409,'Không xóa hồ sơ built-in.')
        if c.execute('SELECT 1 FROM device_profile_assignments WHERE profile_id=? LIMIT 1',(profile_id,)).fetchone():
            raise HTTPException(409,'Hồ sơ đang được gán cho thiết bị.')
        c.execute('DELETE FROM device_profiles WHERE id=?',(profile_id,))
    return {'success':True}

@router.post('/profiles/assign')
def assign_profile_api(x:AssignIn,request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    from modules.nms_v7 import assign_profile
    with connection() as c:
        _managed(c,x.device_id)
        if not c.execute('SELECT 1 FROM device_profiles WHERE id=?',(x.target_id,)).fetchone(): raise HTTPException(404,'Không tìm thấy hồ sơ.')
    assign_profile(x.device_id,x.target_id,'web-manual')
    return {'success':True}

@router.delete('/profiles/assign/{device_id}')
def unassign_profile_api(device_id:int,request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    with connection() as c:
        _managed(c,device_id)
        c.execute('DELETE FROM device_profile_assignments WHERE device_id=?',(device_id,))
        cols=_cols(c,'network_devices')
        if 'profile_id' in cols: c.execute('UPDATE network_devices SET profile_id=NULL WHERE id=?',(device_id,))
    return {'success':True}

@router.post('/profiles/auto-detect/{device_id}')
def auto_profile(device_id:int,request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    from modules.nms_v7 import detect_profile, assign_profile
    with connection() as c:
        d=_managed(c,device_id); host=_host(d)
        r=c.execute('SELECT sys_descr,sys_object_id FROM snmp_diagnostics_history WHERE host=? AND success=1 ORDER BY id DESC LIMIT 1',(host,)).fetchone()
    if not r: raise HTTPException(409,'Chưa có SNMP diagnostics thành công. Hãy chạy SNMP Refresh trước.')
    p=detect_profile(r['sys_descr'] or '',r['sys_object_id'] or '')
    if not p: raise HTTPException(409,'SNMP phản hồi nhưng chưa khớp hồ sơ. Hãy gán thủ công.')
    assign_profile(device_id,p['id'],'web-auto',r['sys_descr'] or '',r['sys_object_id'] or '')
    return {'success':True,'profile_id':p['id'],'profile_name':p['name']}


def _driver_values(x:DriverIn):
    for oid in (x.sysobject_prefix,x.cpu_oid,x.mem_used_oid,x.mem_total_oid): _valid_oid(oid)
    if x.backup_command.strip() not in READ_ONLY_BACKUP_COMMANDS:
        raise HTTPException(400,'Lệnh backup driver không nằm trong allowlist read-only.')
    if x.descr_regex:
        try: re.compile(x.descr_regex,re.I)
        except re.error as exc: raise HTTPException(400,'Regex nhận diện driver không hợp lệ.') from exc
    return (x.name.strip(),x.vendor.strip(),x.priority,x.sysobject_prefix.strip().lstrip('.'),x.descr_regex.strip(),
            x.cpu_oid.strip().lstrip('.'),x.mem_used_oid.strip().lstrip('.'),x.mem_total_oid.strip().lstrip('.'),
            x.backup_command.strip(),x.save_command.strip(),x.lldp_mode,x.note.strip(),1 if x.enabled else 0)

@router.get('/drivers')
def drivers(request:Request):
    require_role(request); ensure_tables()
    with connection() as c:
        ds=[dict(r) for r in c.execute('SELECT * FROM vendor_drivers ORDER BY priority DESC,vendor,name')]
        ass=[dict(r) for r in c.execute('''SELECT a.device_id,a.driver_id,a.source,a.updated_at,d.name driver_name,COALESCE(NULLIF(n.name,''),NULLIF(n.device_name,''),n.ip,n.ip_address) device_name,COALESCE(NULLIF(n.ip,''),n.ip_address) ip
          FROM device_driver_assignments a JOIN vendor_drivers d ON d.id=a.driver_id JOIN network_devices n ON n.id=a.device_id ORDER BY device_name''')]
    return {'drivers':ds,'assignments':ass}

@router.post('/drivers')
def create_driver(x:DriverIn,request:Request):
    require_role(request,'Admin'); ensure_tables(); vals=_driver_values(x); now=_now()
    with connection() as c:
        try:
            cur=c.execute('''INSERT INTO vendor_drivers(name,vendor,priority,sysobject_prefix,descr_regex,cpu_oid,mem_used_oid,mem_total_oid,backup_command,save_command,lldp_mode,note,builtin,enabled,created_at,updated_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?)''',vals[:-1]+(vals[-1],now,now))
        except Exception as exc: raise HTTPException(409,'Tên driver đã tồn tại hoặc dữ liệu không hợp lệ.') from exc
    return {'success':True,'id':cur.lastrowid}

@router.put('/drivers/{driver_id}')
def update_driver(driver_id:int,x:DriverIn,request:Request):
    require_role(request,'Admin'); ensure_tables(); vals=_driver_values(x)
    with connection() as c:
        r=c.execute('SELECT builtin FROM vendor_drivers WHERE id=?',(driver_id,)).fetchone()
        if not r: raise HTTPException(404,'Không tìm thấy driver.')
        if r['builtin']: raise HTTPException(409,'Driver built-in được quản lý bởi ứng dụng; hãy tạo driver tùy chỉnh.')
        c.execute('''UPDATE vendor_drivers SET name=?,vendor=?,priority=?,sysobject_prefix=?,descr_regex=?,cpu_oid=?,mem_used_oid=?,mem_total_oid=?,backup_command=?,save_command=?,lldp_mode=?,note=?,enabled=?,updated_at=? WHERE id=?''',vals+(_now(),driver_id))
    return {'success':True}

@router.delete('/drivers/{driver_id}')
def delete_driver(driver_id:int,request:Request):
    require_role(request,'Admin'); ensure_tables()
    with connection() as c:
        r=c.execute('SELECT builtin FROM vendor_drivers WHERE id=?',(driver_id,)).fetchone()
        if not r: raise HTTPException(404,'Không tìm thấy driver.')
        if r['builtin']: raise HTTPException(409,'Không xóa driver built-in.')
        if c.execute('SELECT 1 FROM device_driver_assignments WHERE driver_id=? LIMIT 1',(driver_id,)).fetchone(): raise HTTPException(409,'Driver đang được gán cho thiết bị.')
        c.execute('DELETE FROM vendor_drivers WHERE id=?',(driver_id,))
    return {'success':True}

@router.post('/drivers/assign')
def assign_driver_api(x:AssignIn,request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    from modules.nms_v12 import assign_driver
    with connection() as c:
        _managed(c,x.device_id)
        if not c.execute('SELECT 1 FROM vendor_drivers WHERE id=? AND enabled=1',(x.target_id,)).fetchone(): raise HTTPException(404,'Không tìm thấy driver đang bật.')
    assign_driver(x.device_id,x.target_id,'web-manual')
    return {'success':True}

@router.delete('/drivers/assign/{device_id}')
def unassign_driver_api(device_id:int,request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    with connection() as c:
        _managed(c,device_id); c.execute('DELETE FROM device_driver_assignments WHERE device_id=?',(device_id,))
    return {'success':True}

@router.post('/drivers/auto-detect/{device_id}')
def auto_driver(device_id:int,request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    from modules.nms_v12 import detect_driver, assign_driver
    with connection() as c:
        d=_managed(c,device_id); host=_host(d)
        r=c.execute('SELECT sys_descr,sys_object_id FROM snmp_diagnostics_history WHERE host=? AND success=1 ORDER BY id DESC LIMIT 1',(host,)).fetchone()
    if not r: raise HTTPException(409,'Chưa có SNMP diagnostics thành công. Hãy chạy SNMP Refresh trước.')
    dr=detect_driver(r['sys_descr'] or '',r['sys_object_id'] or '')
    if not dr: raise HTTPException(409,'Chưa nhận diện được vendor driver. Hãy gán thủ công.')
    assign_driver(device_id,dr['id'],'web-auto',r['sys_descr'] or '',r['sys_object_id'] or '')
    return {'success':True,'driver_id':dr['id'],'driver_name':dr['name']}


# ---------------- Secure SNMP resource / port monitoring ----------------
class ResourcePollIn(BaseModel):
    authorized: bool = False

class InterfacePollIn(BaseModel):
    ifindices: list[int] = Field(min_length=1,max_length=32)
    authorized: bool = False


def _snmp_context(c, device_id:int):
    from modules.nms_v5 import decrypt_secret
    d=_managed(c,device_id); host=_host(d)
    if not host: raise HTTPException(400,'Thiết bị chưa có IP.')
    a=c.execute('SELECT credential_id FROM device_snmpv3_assignments WHERE device_id=?',(device_id,)).fetchone()
    v2=c.execute('''SELECT s.* FROM web_device_snmpv2_assignments42 a JOIN web_snmpv2_credentials42 s ON s.id=a.credential_id WHERE a.device_id=? LIMIT 1''',(device_id,)).fetchone() if _table(c,'web_device_snmpv2_assignments42') else None
    legacy=c.execute('SELECT * FROM snmp_profiles WHERE host=? AND enabled=1 ORDER BY id LIMIT 1',(host,)).fetchone() if _table(c,'snmp_profiles') else None
    if a: return d,host,{'version':'v3','credential_id':a['credential_id']}
    if v2: return d,host,{'version':'v2c','community':decrypt_secret(v2['community_enc']),'port':int(v2['port'] or 161)}
    if legacy: return d,host,{'version':'v2c','community':legacy['community'],'port':int(legacy['port'] or 161)}
    raise HTTPException(409,'Thiết bị chưa được gán SNMP credential/profile.')


def _snmp_read(device_id:int,oids:list[str]):
    from modules.nms_v12 import secure_snmp_get
    with connection() as c:
        d,host,ctx=_snmp_context(c,device_id)
    if ctx['version']=='v3': vals=secure_snmp_get(host,oids,version='v3',credential_id=ctx['credential_id'],timeout=2.0)
    else: vals=secure_snmp_get(host,oids,version='v2c',community=ctx['community'],port=ctx['port'],timeout=2.0)
    return d,host,ctx['version'],vals

@router.get('/monitoring')
def monitoring(request:Request,device_id:int|None=None,limit:int=200):
    require_role(request); ensure_tables(); limit=max(1,min(limit,1000))
    with connection() as c:
        devices=[dict(r) for r in c.execute('''SELECT id,COALESCE(NULLIF(name,''),NULLIF(device_name,''),ip,ip_address) name,COALESCE(NULLIF(ip,''),ip_address) ip,vendor,status FROM network_devices ORDER BY name,ip''')]
        health=[]; interfaces=[]
        if device_id:
            d=_managed(c,device_id); h=_host(d)
            health=[dict(r) for r in c.execute('SELECT * FROM health_samples WHERE host=? ORDER BY id DESC LIMIT ?',(h,limit))]
            interfaces=[dict(r) for r in c.execute('SELECT * FROM interface_samples WHERE host=? ORDER BY id DESC LIMIT ?',(h,limit))]
        rules=[dict(r) for r in c.execute('SELECT * FROM alert_rules ORDER BY id DESC')]
    return {'devices':devices,'health':health,'interfaces':interfaces,'alert_rules':rules}

@router.post('/monitoring/resource/{device_id}')
def poll_resource(device_id:int,x:ResourcePollIn,request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    if not x.authorized: raise HTTPException(400,'Phải xác nhận quyền giám sát thiết bị.')
    from modules.nms_v7 import get_profile_for_device
    from modules.nms_v12 import get_driver_for_device
    p=get_profile_for_device(device_id=device_id) or get_driver_for_device(device_id=device_id)
    if not p: raise HTTPException(409,'Thiết bị chưa có Device Profile/Vendor Driver.')
    cpu_oid=_valid_oid(p.get('cpu_oid') or ''); used_oid=_valid_oid(p.get('mem_used_oid') or ''); total_oid=_valid_oid(p.get('mem_total_oid') or '')
    oids=[x for x in (cpu_oid,used_oid,total_oid) if x]
    if not oids: raise HTTPException(409,'Profile/driver chưa có OID CPU/RAM phù hợp.')
    try: d,host,version,vals=_snmp_read(device_id,oids)
    except HTTPException: raise
    except Exception as exc: raise HTTPException(400,str(exc)) from exc
    cpu=_num(vals.get(cpu_oid)) if cpu_oid else None
    used=_num(vals.get(used_oid)) if used_oid else None; total=_num(vals.get(total_oid)) if total_oid else None
    memory=(used*100.0/total) if used is not None and total not in (None,0) else None
    if cpu is not None and not 0<=cpu<=100: cpu=None
    if memory is not None and not 0<=memory<=100: memory=None
    if cpu is None and memory is None:
        raise HTTPException(409,'NO_RESOURCE_MEASUREMENT: SNMP returned no usable CPU/RAM values; verify profile OIDs on this device')
    with connection() as c:
        c.execute('INSERT INTO health_samples(host,cpu,memory,created_at) VALUES(?,?,?,?)',(host,cpu,memory,_now()))
    return {'success':True,'device_id':device_id,'host':host,'version':version,'profile':p.get('name'),'cpu':cpu,'memory':memory,'raw':{'cpu':vals.get(cpu_oid) if cpu_oid else None,'mem_used':vals.get(used_oid) if used_oid else None,'mem_total':vals.get(total_oid) if total_oid else None}}

@router.post('/monitoring/interfaces/{device_id}')
def poll_interfaces(device_id:int,x:InterfacePollIn,request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    if not x.authorized: raise HTTPException(400,'Phải xác nhận quyền giám sát thiết bị.')
    indices=list(dict.fromkeys(x.ifindices))
    if any(i<1 or i>2147483647 for i in indices): raise HTTPException(400,'IfIndex không hợp lệ.')
    bases={'ifname':'1.3.6.1.2.1.2.2.1.2','oper_status':'1.3.6.1.2.1.2.2.1.8','speed_bps':'1.3.6.1.2.1.2.2.1.5','in_octets':'1.3.6.1.2.1.2.2.1.10','out_octets':'1.3.6.1.2.1.2.2.1.16','in_errors':'1.3.6.1.2.1.2.2.1.14','out_errors':'1.3.6.1.2.1.2.2.1.20','in_discards':'1.3.6.1.2.1.2.2.1.13','out_discards':'1.3.6.1.2.1.2.2.1.19'}
    rows=[]
    for idx in indices:
        oids={k:f'{v}.{idx}' for k,v in bases.items()}
        try:
            d,host,version,vals=_snmp_read(device_id,list(oids.values()))
            row={'ifindex':idx}
            for k,oid in oids.items(): row[k]=vals.get(oid)
            for k in ('oper_status','speed_bps','in_octets','out_octets','in_errors','out_errors','in_discards','out_discards'):
                try: row[k]=int(row[k] or 0)
                except Exception: row[k]=0
            row['ifname']=str(row.get('ifname') or '')
            row['status']='UP' if row['oper_status']==1 else 'DOWN' if row['oper_status']==2 else str(row['oper_status'])
            with connection() as c:
                c.execute('''INSERT INTO interface_samples(host,ifindex,ifname,oper_status,speed_bps,in_octets,out_octets,in_errors,out_errors,in_discards,out_discards,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',(host,idx,row['ifname'],row['oper_status'],row['speed_bps'],row['in_octets'],row['out_octets'],row['in_errors'],row['out_errors'],row['in_discards'],row['out_discards'],_now()))
            row['success']=True; rows.append(row)
        except Exception as exc:
            rows.append({'ifindex':idx,'success':False,'detail':str(getattr(exc,'detail',exc))[:300]})
    return {'device_id':device_id,'success':all(r.get('success') for r in rows),'results':rows}


# ---------------- Alert rules ----------------
class AlertRuleIn(BaseModel):
    name:str=Field(min_length=1,max_length=160)
    host:str=Field(default='',max_length=255)
    metric:Literal['CPU %','RAM %','Mất gói %','Độ trễ ms','Lỗi cổng IN','Lỗi cổng OUT']
    operator:Literal['>','>=','<','<=']
    threshold:float
    severity:Literal['Info','Warning','Critical']='Warning'
    enabled:bool=True

@router.get('/alert-rules')
def alert_rules(request:Request):
    require_role(request); ensure_tables()
    with connection() as c: return [dict(r) for r in c.execute('SELECT * FROM alert_rules ORDER BY id DESC')]

@router.post('/alert-rules')
def create_alert_rule(x:AlertRuleIn,request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    with connection() as c:
        cur=c.execute('INSERT INTO alert_rules(name,host,metric,operator,threshold,severity,enabled,created_at) VALUES(?,?,?,?,?,?,?,?)',(x.name.strip(),x.host.strip(),x.metric,x.operator,x.threshold,x.severity,1 if x.enabled else 0,_now()))
    return {'success':True,'id':cur.lastrowid}

@router.put('/alert-rules/{rule_id}')
def update_alert_rule(rule_id:int,x:AlertRuleIn,request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    with connection() as c:
        cur=c.execute('UPDATE alert_rules SET name=?,host=?,metric=?,operator=?,threshold=?,severity=?,enabled=? WHERE id=?',(x.name.strip(),x.host.strip(),x.metric,x.operator,x.threshold,x.severity,1 if x.enabled else 0,rule_id))
        if not cur.rowcount: raise HTTPException(404,'Không tìm thấy quy tắc.')
    return {'success':True}

@router.delete('/alert-rules/{rule_id}')
def delete_alert_rule(rule_id:int,request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    with connection() as c:
        cur=c.execute('DELETE FROM alert_rules WHERE id=?',(rule_id,))
        if not cur.rowcount: raise HTTPException(404,'Không tìm thấy quy tắc.')
    return {'success':True}

@router.post('/alert-rules/evaluate')
def evaluate_rules(request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    from modules.nms_v4 import evaluate_alert_rules
    created,recovered=evaluate_alert_rules()
    return {'success':True,'created':created,'recovered':recovered}


# ---------------- Notifications ----------------
class NotificationSettingsIn(BaseModel):
    notify_enabled:bool=False; notify_telegram:bool=True; notify_email:bool=False
    notify_offline:bool=True; notify_drift:bool=True; notify_security:bool=True; notify_daily_audit:bool=True
    notify_cooldown_min:int=Field(default=60,ge=0,le=10080)
    telegram_chat_id:str=Field(default='',max_length=255)
    telegram_token:str=Field(default='',max_length=1000)
    smtp_host:str=Field(default='',max_length=255)
    smtp_port:int=Field(default=587,ge=1,le=65535)
    smtp_user:str=Field(default='',max_length=255)
    smtp_password:str=Field(default='',max_length=1000)
    smtp_to:str=Field(default='',max_length=512)

class NotificationTestIn(BaseModel):
    channel:Literal['Telegram','Email']
    authorized:bool=False

@router.get('/notifications')
def notifications(request:Request,limit:int=100):
    require_role(request); ensure_tables()
    from modules.advanced_pages import get_setting,_load_secret
    keys=['notify_enabled','notify_telegram','notify_email','notify_offline','notify_drift','notify_security','notify_daily_audit','notify_cooldown_min','telegram_chat_id','smtp_host','smtp_port','smtp_user','smtp_to']
    settings={k:get_setting(k,'') for k in keys}
    settings['has_telegram_token']=bool(_load_secret('telegram_token_enc'))
    settings['has_smtp_password']=bool(_load_secret('smtp_password_enc'))
    with connection() as c:
        logs=[dict(r) for r in c.execute('SELECT id,event_key,channel,status,detail,created_at FROM notification_log ORDER BY id DESC LIMIT ?',(max(1,min(limit,500)),))] if _table(c,'notification_log') else []
    return {'settings':settings,'logs':logs}

@router.put('/notifications')
def update_notifications(x:NotificationSettingsIn,request:Request):
    require_role(request,'Admin'); ensure_tables()
    from modules.advanced_pages import set_setting,_save_secret
    vals=x.model_dump()
    token=vals.pop('telegram_token'); password=vals.pop('smtp_password')
    for k,v in vals.items(): set_setting(k, '1' if isinstance(v,bool) and v else '0' if isinstance(v,bool) else str(v).strip())
    if token: _save_secret('telegram_token_enc',token)
    if password: _save_secret('smtp_password_enc',password)
    return {'success':True,'secrets_preserved_if_blank':True}

@router.post('/notifications/test')
def test_notification(x:NotificationTestIn,request:Request):
    require_role(request,'Admin'); ensure_tables()
    if not x.authorized: raise HTTPException(400,'Phải xác nhận gửi thử tới kênh đã cấu hình.')
    from modules.advanced_pages import get_setting,_load_secret,send_telegram,send_email
    msg='NetworkAutomation Web v4.4: notification test successful.'
    try:
        if x.channel=='Telegram':
            token=_load_secret('telegram_token_enc'); chat=get_setting('telegram_chat_id','')
            if not token or not chat: raise HTTPException(409,'Telegram token/chat ID chưa được cấu hình.')
            send_telegram(token,chat,msg)
        else:
            host=get_setting('smtp_host',''); port=int(get_setting('smtp_port','587') or 587); user=get_setting('smtp_user',''); pwd=_load_secret('smtp_password_enc'); to=get_setting('smtp_to','')
            if not host or not to: raise HTTPException(409,'SMTP host/to chưa được cấu hình.')
            send_email(host,port,user,pwd,to,'NetworkAutomation notification test',msg)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502,f'Không gửi được {x.channel}: {type(exc).__name__}') from exc
    return {'success':True,'channel':x.channel}


# ---------------- Service impact ----------------
class ServiceIn(BaseModel):
    name:str=Field(min_length=1,max_length=160)
    description:str=Field(default='',max_length=1000)
    owner:str=Field(default='',max_length=160)
    enabled:bool=True

class MembersIn(BaseModel):
    required_ids:list[int]=Field(default_factory=list,max_length=256)
    optional_ids:list[int]=Field(default_factory=list,max_length=256)

@router.get('/services')
def services(request:Request):
    require_role(request); ensure_tables()
    from modules.nms_v10 import service_status
    with connection() as c:
        ss=[dict(r) for r in c.execute('SELECT * FROM managed_services ORDER BY name')]
        members=[dict(r) for r in c.execute('''SELECT sm.service_id,sm.device_id,sm.required,COALESCE(NULLIF(d.name,''),NULLIF(d.device_name,''),d.ip,d.ip_address) device_name,COALESCE(NULLIF(d.ip,''),d.ip_address) ip FROM service_members sm JOIN network_devices d ON d.id=sm.device_id ORDER BY sm.service_id,device_name''')]
        devices=[dict(r) for r in c.execute('''SELECT id,COALESCE(NULLIF(name,''),NULLIF(device_name,''),ip,ip_address) name,COALESCE(NULLIF(ip,''),ip_address) ip FROM network_devices ORDER BY name,ip''')]
    for s in ss: s['impact']=service_status(s['id'])
    return {'services':ss,'members':members,'devices':devices}

@router.post('/services')
def create_service(x:ServiceIn,request:Request):
    require_role(request,'Admin','Operator'); ensure_tables(); now=_now()
    with connection() as c:
        try: cur=c.execute('INSERT INTO managed_services(name,description,owner,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)',(x.name.strip(),x.description.strip(),x.owner.strip(),1 if x.enabled else 0,now,now))
        except Exception as exc: raise HTTPException(409,'Tên dịch vụ đã tồn tại hoặc dữ liệu không hợp lệ.') from exc
    return {'success':True,'id':cur.lastrowid}

@router.put('/services/{service_id}')
def update_service(service_id:int,x:ServiceIn,request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    with connection() as c:
        cur=c.execute('UPDATE managed_services SET name=?,description=?,owner=?,enabled=?,updated_at=? WHERE id=?',(x.name.strip(),x.description.strip(),x.owner.strip(),1 if x.enabled else 0,_now(),service_id))
        if not cur.rowcount: raise HTTPException(404,'Không tìm thấy dịch vụ.')
    return {'success':True}

@router.delete('/services/{service_id}')
def delete_service(service_id:int,request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    with connection() as c:
        if not c.execute('SELECT 1 FROM managed_services WHERE id=?',(service_id,)).fetchone(): raise HTTPException(404,'Không tìm thấy dịch vụ.')
        c.execute('DELETE FROM service_members WHERE service_id=?',(service_id,)); c.execute('DELETE FROM managed_services WHERE id=?',(service_id,))
    return {'success':True}

@router.put('/services/{service_id}/members')
def update_members(service_id:int,x:MembersIn,request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    req=set(x.required_ids); opt=set(x.optional_ids)-req; ids=req|opt
    with connection() as c:
        if not c.execute('SELECT 1 FROM managed_services WHERE id=?',(service_id,)).fetchone(): raise HTTPException(404,'Không tìm thấy dịch vụ.')
        if ids:
            found={int(r['id']) for r in c.execute('SELECT id FROM network_devices WHERE id IN ('+','.join('?' for _ in ids)+')',tuple(ids))}
            if found!=ids: raise HTTPException(404,'Có Managed Device ID không tồn tại.')
        c.execute('DELETE FROM service_members WHERE service_id=?',(service_id,))
        for did in sorted(req): c.execute('INSERT INTO service_members(service_id,device_id,required) VALUES(?,?,1)',(service_id,did))
        for did in sorted(opt): c.execute('INSERT INTO service_members(service_id,device_id,required) VALUES(?,?,0)',(service_id,did))
    return {'success':True,'required':len(req),'optional':len(opt)}


# ---------------- Manual text backup (desktop BackupConfig parity) ----------------
class ManualBackupIn(BaseModel):
    device_name:str=Field(min_length=1,max_length=120)
    note:str=Field(default='',max_length=500)
    content:str=Field(min_length=1,max_length=48000)
    authorized:bool=False

@router.post('/manual-backups')
def manual_backup(x:ManualBackupIn,request:Request):
    require_role(request,'Admin'); ensure_tables()
    if not x.authorized: raise HTTPException(400,'Phải xác nhận nội dung cấu hình thuộc phạm vi quản trị.')
    safe=re.sub(r'[^A-Za-z0-9._-]+','_',x.device_name.strip()).strip('._-')[:80] or 'device'
    stamp=datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    path=(BACKUP_DIR/f'{safe}_manual_{stamp}.cfg').resolve()
    root=BACKUP_DIR.resolve()
    if root not in path.parents: raise HTTPException(400,'Tên thiết bị không hợp lệ.')
    path.write_text(x.content,encoding='utf-8')
    with connection() as c:
        cur=c.execute('INSERT INTO config_backups(device_name,source,file_path,size_bytes,note,created_at) VALUES(?,?,?,?,?,?)',(x.device_name.strip(),'Web pasted configuration',str(path),path.stat().st_size,x.note.strip(),_now()))
    return {'success':True,'id':cur.lastrowid,'filename':path.name,'size_bytes':path.stat().st_size}

class PostureIn(BaseModel):
    backup_id:int=Field(gt=0)

# ---------------- Config compare / baselines ----------------
class CompareIn(BaseModel):
    backup_a:int=Field(gt=0); backup_b:int=Field(gt=0)

class BaselineFromBackupIn(BaseModel):
    backup_id:int=Field(gt=0)
    device:str=Field(min_length=1,max_length=255)


def _safe_backup_file(row:dict) -> Path:
    raw=str(row.get('file_path') or '').strip()
    candidates=[]
    if raw:
        candidates.append(Path(raw))
        candidates.append(BACKUP_DIR/Path(raw).name)
        candidates.append(Path(__file__).resolve().parents[1]/'backups'/Path(raw).name)
    roots=[BACKUP_DIR.resolve(),(Path(__file__).resolve().parents[1]/'backups').resolve()]
    for p in candidates:
        try:
            rp=p.expanduser().resolve()
            if rp.is_file() and any(rp==root or root in rp.parents for root in roots):
                if rp.stat().st_size>2*1024*1024: raise HTTPException(413,'Backup quá lớn để so sánh trên Web (>2 MB).')
                if rp.suffix.lower() not in {'.txt','.cfg','.conf','.config','.log','.rsc'}: raise HTTPException(415,'Backup này không phải cấu hình text có thể so sánh.')
                return rp
        except OSError: pass
    raise HTTPException(404,'File backup không còn tồn tại trong thư mục backup được Web quản lý.')

@router.get('/config-compare')
def config_compare_list(request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    with connection() as c:
        rows=[dict(r) for r in c.execute('SELECT id,device_name,source,file_path,size_bytes,note,created_at FROM config_backups ORDER BY id DESC LIMIT 500')]
    out=[]
    for r in rows:
        available=True
        try: _safe_backup_file(r)
        except HTTPException: available=False
        out.append({'id':r['id'],'device_name':r.get('device_name'),'source':r.get('source'),'size_bytes':r.get('size_bytes'),'note':r.get('note'),'created_at':r.get('created_at'),'text_available':available})
    return out

@router.post('/config-compare')
def compare_configs(x:CompareIn,request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    with connection() as c:
        a=c.execute('SELECT * FROM config_backups WHERE id=?',(x.backup_a,)).fetchone(); b=c.execute('SELECT * FROM config_backups WHERE id=?',(x.backup_b,)).fetchone()
    if not a or not b: raise HTTPException(404,'Không tìm thấy một trong hai backup.')
    pa=_safe_backup_file(dict(a)); pb=_safe_backup_file(dict(b))
    A=pa.read_text(encoding='utf-8',errors='replace').splitlines(); B=pb.read_text(encoding='utf-8',errors='replace').splitlines()
    diff=list(difflib.unified_diff(A,B,fromfile=f'backup#{x.backup_a}',tofile=f'backup#{x.backup_b}',lineterm=''))
    adds=sum(1 for line in diff if line.startswith('+') and not line.startswith('+++')); rems=sum(1 for line in diff if line.startswith('-') and not line.startswith('---'))
    return {'same':not diff,'added':adds,'removed':rems,'truncated':len(diff)>4000,'diff':'\n'.join(diff[:4000]) if diff else 'Hai bản cấu hình không có khác biệt.'}

@router.post('/config-posture')
def config_posture(x:PostureIn,request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    with connection() as c: r=c.execute('SELECT * FROM config_backups WHERE id=?',(x.backup_id,)).fetchone()
    if not r: raise HTTPException(404,'Không tìm thấy backup.')
    p=_safe_backup_file(dict(r)); config=p.read_text(encoding='utf-8',errors='replace')
    from modules.security_audit import posture
    rows=posture(config)
    return {'backup_id':x.backup_id,'device_name':r['device_name'],'checks':rows,'summary':{'PASS':sum(y.get('status')=='PASS' for y in rows),'WARN':sum(y.get('status')=='WARN' for y in rows),'HIGH':sum(y.get('status')=='HIGH' for y in rows),'REVIEW':sum(y.get('status')=='REVIEW' for y in rows)}}

@router.get('/baselines')
def baselines(request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    with connection() as c:
        rows=[dict(r) for r in c.execute('SELECT device,config,source,updated_at FROM config_baselines ORDER BY updated_at DESC')]
    return [{'device':r['device'],'source':r['source'],'updated_at':r['updated_at'],'bytes':len((r['config'] or '').encode('utf-8')),'sha256':hashlib.sha256((r['config'] or '').encode()).hexdigest()} for r in rows]

@router.post('/baselines/from-backup')
def baseline_from_backup(x:BaselineFromBackupIn,request:Request):
    require_role(request,'Admin'); ensure_tables()
    with connection() as c: r=c.execute('SELECT * FROM config_backups WHERE id=?',(x.backup_id,)).fetchone()
    if not r: raise HTTPException(404,'Không tìm thấy backup.')
    p=_safe_backup_file(dict(r)); config=p.read_text(encoding='utf-8',errors='replace')
    from modules.security_audit import save_baseline
    save_baseline(x.device.strip(),config,'web-backup')
    return {'success':True,'device':x.device.strip(),'bytes':len(config.encode('utf-8')),'sha256':hashlib.sha256(config.encode()).hexdigest()}

@router.delete('/baselines/{device}')
def delete_baseline(device:str,request:Request):
    require_role(request,'Admin'); ensure_tables()
    with connection() as c: c.execute('DELETE FROM config_baselines WHERE device=?',(device,))
    return {'success':True}


# ---------------- Settings / remote tools ----------------
class SettingsIn(BaseModel):
    default_network:str='192.168.1.0/24'
    ping_timeout_ms:int=Field(default=1000,ge=100,le=60000)
    ping_interval_sec:int=Field(default=5,ge=1,le=3600)
    scan_workers:int=Field(default=50,ge=1,le=128)
    export_directory:str=Field(default='',max_length=1000)
    confirm_delete:bool=True

@router.get('/settings')
def settings_get(request:Request):
    require_role(request,'Admin'); ensure_tables()
    from modules.extra_pages import get_setting
    defaults={'default_network':'192.168.1.0/24','ping_timeout_ms':'1000','ping_interval_sec':'5','scan_workers':'50','export_directory':'','confirm_delete':'1'}
    return {k:get_setting(k,v) for k,v in defaults.items()}

@router.put('/settings')
def settings_put(x:SettingsIn,request:Request):
    require_role(request,'Admin'); ensure_tables()
    try:
        net=ipaddress.ip_network(x.default_network.strip(),strict=False)
        if net.version!=4 or not net.is_private: raise ValueError
    except ValueError: raise HTTPException(400,'Mạng mặc định phải là private IPv4 CIDR.')
    from modules.extra_pages import set_setting
    for k,v in x.model_dump().items(): set_setting(k,'1' if isinstance(v,bool) and v else '0' if isinstance(v,bool) else str(v).strip())
    return {'success':True}

class RemoteCheckIn(BaseModel):
    service:Literal['SSH','TELNET','RDP','HTTP','HTTPS']
    authorized:bool=False

@router.get('/remote/history')
def remote_history(request:Request,limit:int=200):
    require_role(request); ensure_tables(); limit=max(1,min(limit,500))
    with connection() as c:
        if not _table(c,'remote_history'): return []
        return [dict(r) for r in c.execute('SELECT id,protocol,host,port,username,status,detail,created_at FROM remote_history ORDER BY id DESC LIMIT ?',(limit,))]

@router.post('/remote/{device_id}/check')
def remote_check(device_id:int,x:RemoteCheckIn,request:Request):
    require_role(request,'Admin','Operator'); ensure_tables()
    if not x.authorized: raise HTTPException(400,'Phải xác nhận thiết bị thuộc phạm vi quản trị.')
    ports={'SSH':22,'TELNET':23,'RDP':3389,'HTTP':80,'HTTPS':443}; port=ports[x.service]
    with connection() as c: d=_managed(c,device_id)
    host=_host(d)
    try:
        with socket.create_connection((host,port),timeout=3): pass
        ok=True; detail=f'TCP/{port} open'
    except Exception as exc: ok=False; detail=type(exc).__name__
    with connection() as c:
        c.execute('INSERT INTO remote_history(protocol,host,port,username,status,detail,created_at) VALUES(?,?,?,?,?,?,?)',(x.service,host,port,'','Open' if ok else 'Failed',detail,_now()))
    result={'device_id':device_id,'host':host,'service':x.service,'port':port,'success':ok,'detail':detail}
    if x.service in ('HTTP','HTTPS'): result['url']=('https' if x.service=='HTTPS' else 'http')+'://'+host+('/' if port in (80,443) else f':{port}/')
    return result


# ---------------- Daily Audit Windows ----------------
def _daily_paths():
    root=resource_path('tools','daily_audit'); return root,root/'config.json',root/'Daily-Audit.ps1',root/'Install-ScheduledTask.ps1'

def _daily_report_dir() -> Path|None:
    _,cfg,_,_=_daily_paths()
    try:
        data=json.loads(cfg.read_text(encoding='utf-8-sig')); raw=str(data.get('ReportDirectory',r'C:\DailyAudit\Reports'))
        return Path(os.path.expandvars(raw))
    except Exception:return None

@router.get('/daily-audit')
def daily_audit_status(request:Request):
    require_role(request); root,cfg,script,scheduler=_daily_paths(); report_dir=_daily_report_dir()
    latest=None
    if report_dir and report_dir.is_dir():
        files=sorted(report_dir.glob('daily_audit_*.json'),key=lambda p:p.stat().st_mtime,reverse=True)
        if files:
            try:
                d=json.loads(files[0].read_text(encoding='utf-8-sig')); findings=d.get('Findings') or []
                latest={'generated_at':d.get('GeneratedAt'),'high':d.get('High',sum(str(x.get('Severity','')).upper()=='HIGH' for x in findings)),'warn':d.get('Warn',sum(str(x.get('Severity','')).upper()=='WARN' for x in findings)),'review':d.get('Review',sum(str(x.get('Severity','')).upper()=='REVIEW' for x in findings)),'findings':findings[:200]}
            except Exception as exc: latest={'error':str(exc)[:300]}
    return {'windows':platform.system()=='Windows','script_ready':script.is_file(),'config_ready':cfg.is_file(),'scheduler_ready':scheduler.is_file(),'latest':latest}


def run_daily_audit():
    root,cfg,script,_=_daily_paths()
    if platform.system()!='Windows': return {'success':False,'status':'NOT_WINDOWS','detail':'Daily Audit chỉ chạy trên Windows/Windows Server.'}
    if not script.is_file() or not cfg.is_file(): return {'success':False,'status':'NOT_READY','detail':'Thiếu Daily-Audit.ps1 hoặc config.json.'}
    try:
        r=subprocess.run(['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(script),'-ConfigPath',str(cfg)],capture_output=True,text=True,timeout=900,**hidden_subprocess_kwargs())
        code=int(r.returncode); status='OK' if code==0 else 'WARN' if code==1 else 'HIGH' if code==2 else 'ERROR'
        return {'success':code in (0,1,2),'status':status,'exit_code':code,'detail':((r.stdout or '')+'\n'+(r.stderr or ''))[-3000:]}
    except subprocess.TimeoutExpired:return {'success':False,'status':'TIMEOUT','detail':'Daily Audit vượt quá 900 giây.'}
    except Exception as exc:return {'success':False,'status':'ERROR','detail':str(exc)[:500]}

@router.post('/daily-audit/run',status_code=202)
def daily_audit_run(request:Request):
    user=require_role(request,'Admin','Operator')
    from webapi.jobs37 import engine
    return engine.submit('DAILY_AUDIT',{'device_ids':[],'network':'','parameters':{}},user)


# ---------------- Desktop/Web parity summary ----------------
@router.get('/parity')
def parity(request:Request):
    require_role(request); ensure_tables()
    features=[
      ('Dashboard / NOC','native'),('Device Manager','native'),('IP/MAC','native'),('Network Scan / Discovery','native'),
      ('Ping Monitor','consolidated'),('SNMP Diagnostics','native'),('CPU/RAM SNMP','v4.4'),('Advanced/Multi Port','v4.4'),
      ('History Charts','consolidated'),('Alert Rules','v4.4'),('Device Profiles','v4.4'),('Vendor Drivers','v4.4'),
      ('Topology / Dependencies','native'),('Service Impact','v4.4'),('SLA / Capacity / Maintenance','native'),
      ('Auto IP','native'),('SSH Audit / Backup / Restore','native'),('Secure Backup Scheduler','consolidated'),('Config Compare','v4.4'),
      ('Daily Audit Windows','v4.4'),('Notification Center','v4.4'),('Remote Service Check','v4.4'),('Settings','v4.4'),
      ('Monitoring Service / Stable Core','consolidated'),('Accounts / RBAC','native'),('Enterprise Security','native'),('Reports / Logs / DR','native')]
    return {'version':'4.4.0-rc1','features':[{'desktop':n,'web':s} for n,s in features], 'note':'consolidated = desktop workflow is represented in a combined Web operations page rather than a 1:1 Tk screen.'}
