from __future__ import annotations
import ipaddress
import json
import os
from pathlib import Path
from typing import Literal
from fastapi import APIRouter,Request,HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel,Field
from modules import accounts
from webapi.runtime37 import connection
from webapi.security37 import require_role
from webapi.data37 import diagnostics
from webapi.jobs37 import engine,ROLES

router=APIRouter()

class JobIn(BaseModel):
    operation:Literal['PING','PING_ALL','SERVER_CHECK','SCAN','SNMP','SSH_TEST','AUDIT','CONFIG_BACKUP','DB_BACKUP','REPORT','TOPOLOGY_DISCOVER','WIFI_DIAG','CAMERA_CHECK','INCIDENT_SYNC','RCA_ANALYZE','LAN_PROBE','RESTORE_CONFIG','DAILY_AUDIT']
    device_ids:list[int]=Field(default_factory=list,max_length=128)
    network:str=Field(default='',max_length=48)
    parameters:dict=Field(default_factory=dict)
    authorized:bool=False

@router.post('/api/jobs',status_code=202)
def submit_job(x:JobIn,request:Request):
    u=require_role(request,*ROLES[x.operation])
    if not x.authorized: raise HTTPException(400,'Confirm authority over the selected targets')
    ids=list(dict.fromkeys(x.device_ids))
    if x.operation in ('PING','SNMP','SSH_TEST','AUDIT','CONFIG_BACKUP'):
        limit=5 if x.operation in ('AUDIT','CONFIG_BACKUP') else 20
        if not ids or len(ids)>limit or min(ids)<1: raise HTTPException(400,f'Select 1 to {limit} devices')
        table='devices' if x.operation=='PING' else 'network_devices'
        with connection() as c:
            found={r['id'] for r in c.execute(f'SELECT id FROM {table} WHERE id IN ('+','.join('?' for _ in ids)+')',ids)}
        if found!=set(ids): raise HTTPException(404,'Unregistered device ID')
    if x.operation=='SCAN':
        if str(os.environ.get('NA_WEB_ONLY_BROWSER','')).strip().lower() in ('1','true','yes','on'):
            raise HTTPException(409,'BROWSER_ONLY_LAN_SCAN_UNAVAILABLE: server-side LAN scan is disabled on Render')
        try: net=ipaddress.ip_network(x.network,strict=False)
        except ValueError: raise HTTPException(400,'Invalid CIDR')
        if net.version!=4 or net.num_addresses>1024 or not net.is_private or net.is_link_local or net.is_multicast or net.is_unspecified: raise HTTPException(400,'Pilot scanning: private IPv4 CIDR, maximum 1024 addresses')
    if x.operation=='TOPOLOGY_DISCOVER' and len(ids)>20:
        raise HTTPException(400,'Topology discovery is limited to 20 managed devices per job')
    if x.operation=='CAMERA_CHECK':
        try: camera_id=int(x.parameters.get('camera_id'))
        except Exception: raise HTTPException(400,'camera_id required')
        if camera_id<1: raise HTTPException(400,'camera_id invalid')
    if x.operation=='WIFI_DIAG':
        for key in ('gateway','internet'):
            if len(str(x.parameters.get(key,'') or ''))>255: raise HTTPException(400,'Wi-Fi target too long')
    if x.operation=='RESTORE_CONFIG':
        if len(ids)!=1: raise HTTPException(400,'Restore requires exactly one managed device')
        try: backup_id=int(x.parameters.get('backup_id'))
        except Exception: raise HTTPException(400,'backup_id required')
        if backup_id<1 or not x.parameters.get('token') or not x.parameters.get('confirmation'): raise HTTPException(400,'Prepare restore and provide confirmation first')
    safe_params={k:v for k,v in x.parameters.items() if k in {'gateway','internet','camera_id','backup_id','token','confirmation'}}
    return engine.submit(x.operation,{'device_ids':ids,'network':x.network,'parameters':safe_params},u)

@router.get('/api/jobs')
def jobs(request:Request):
    require_role(request,'Admin','Operator')
    with connection() as c:
        return [dict(r) for r in c.execute('SELECT id,operation,actor,status,done,total,error,created_at,finished_at FROM web_jobs37 ORDER BY id DESC LIMIT 100')]

@router.get('/api/jobs/{jid}')
def job_detail(jid:int,request:Request):
    require_role(request,'Admin','Operator')
    with connection() as c: r=c.execute('SELECT * FROM web_jobs37 WHERE id=?',(jid,)).fetchone()
    if not r: raise HTTPException(404,'Job not found')
    d=dict(r);d['result']=json.loads(d['result']) if d['result'] else None;d.pop('payload',None);return d

@router.post('/api/jobs/{jid}/cancel')
def cancel_job(jid:int,request:Request):
    u=require_role(request,'Admin','Operator')
    with connection() as c:
        r=c.execute('SELECT actor_id,status FROM web_jobs37 WHERE id=?',(jid,)).fetchone()
        if not r: raise HTTPException(404,'Job not found')
        if u['role']!='Admin' and r['actor_id']!=u['id']: raise HTTPException(403,'Cannot cancel another user task')
        if r['status'] not in ('Queued','Running'): raise HTTPException(409,'Job already finished')
        c.execute('UPDATE web_jobs37 SET cancel=1 WHERE id=?',(jid,))
    return {'success':True,'message':'Cancellation requested; current bounded network call may finish first'}

@router.get('/api/diagnostics')
def diagnostic(request:Request):
    require_role(request,'Admin'); return diagnostics()

class UserIn(BaseModel):
    username:str=Field(min_length=1,max_length=64)
    password:str=Field(default='',max_length=256)
    role:Literal['Admin','Analyst','Operator','Viewer']='Viewer'
    enabled:bool=True
class PasswordIn(BaseModel):
    old_password:str=Field(default='',max_length=256)
    new_password:str=Field(min_length=12,max_length=256)
    confirmation:str=Field(default='',max_length=256)

def account_call(fn,*args):
    try:return fn(*args)
    except ValueError as e: raise HTTPException(400,str(e))

@router.get('/api/accounts')
def list_users(request:Request):
    return account_call(accounts.list_users,require_role(request,'Admin'))
@router.post('/api/accounts')
def create_user(x:UserIn,request:Request):
    u=require_role(request,'Admin')
    if len(x.password)<12: raise HTTPException(400,'Use at least 12 characters')
    return account_call(accounts.create_user,u,x.username,x.password,x.role,x.enabled)
@router.put('/api/accounts/{uid}')
def edit_user(uid:int,x:UserIn,request:Request):
    return account_call(accounts.update_user,require_role(request,'Admin'),uid,x.username,x.role,x.enabled)
@router.delete('/api/accounts/{uid}')
def delete_user(uid:int,request:Request):
    account_call(accounts.delete_user,require_role(request,'Admin'),uid);return {'success':True}
@router.post('/api/accounts/{uid}/reset-password')
def reset_user(uid:int,x:PasswordIn,request:Request):
    account_call(accounts.reset_password,require_role(request,'Admin'),uid,x.new_password);return {'success':True}
@router.post('/api/auth/password')
def change_password(x:PasswordIn,request:Request):
    u=require_role(request)
    account_call(accounts.change_password,u,x.old_password,x.new_password,x.confirmation)
    with connection() as c: c.execute('DELETE FROM web_sessions37 WHERE user_id=?',(u['id'],))
    return {'success':True,'login_required':True}
@router.get('/api/security-log')
def security_log(request:Request):
    require_role(request,'Admin')
    with connection() as c:return [dict(r) for r in c.execute('SELECT * FROM web_security_log37 ORDER BY id DESC LIMIT 200')]

@router.get('/api/downloads/{token}')
def download(token:str,request:Request):
    u=require_role(request)
    from webapi.reports37 import ensure_registry
    from app_runtime import REPORT_DIR,BACKUP_DIR
    ensure_registry()
    with connection() as c:r=c.execute('SELECT * FROM web_downloads37 WHERE token=?',(token,)).fetchone()
    if not r: raise HTTPException(404,'Download not found')
    if (r['kind']=='database' and u['role']!='Admin') or (r['owner_id']!=u['id'] and u['role']!='Admin'): raise HTTPException(403,'Download not authorized')
    p=Path(r['path']).resolve();root=Path(BACKUP_DIR if r['kind']=='database' else REPORT_DIR).resolve()
    if not p.is_relative_to(root) or not p.is_file(): raise HTTPException(404,'File unavailable')
    return FileResponse(p,filename=r['name'],media_type='application/octet-stream')

# Explicit public UI assets only. The 4.6 UI includes nested vendor assets;
# keeping the older four-file route made live46.js/terminal46.js return 404.
# Do not mount the project or data directory as a public static root.
STATIC_ROOT = Path(__file__).parent / 'static'
STATIC_ASSETS = {
    'operations47.js': 'text/javascript',
    'operations47.css': 'text/css',
    'operations50.js': 'text/javascript',
    'routerapi69.js': 'text/javascript',
    'operations50.css': 'text/css',
    'cybersecurity51.js': 'text/javascript',
    'cybersecurity51.css': 'text/css',
    'enterprise592.js': 'text/javascript',
    'enterprise592.css': 'text/css',
    'enterprise600.js': 'text/javascript',
    'enterprise600.css': 'text/css',
    'security_modes61.js': 'text/javascript',
    'security_modes61.css': 'text/css',
    'security_catalog62.js': 'text/javascript',
    'kali63.js': 'text/javascript',
    'hotfix9_kali_red.js': 'text/javascript',
    'hotfix10_nav_core.js': 'text/javascript',
    'app.js': 'text/javascript',
    'style.css': 'text/css',
    'workbench45.js': 'text/javascript',
    'workbench45.css': 'text/css',
    'live46.js': 'text/javascript',
    'terminal46.js': 'text/javascript',
    'terminal46.css': 'text/css',
    'vendor/xterm.js': 'text/javascript',
    'vendor/xterm.css': 'text/css',
}

@router.api_route('/static/{name:path}', methods=['GET', 'HEAD'], include_in_schema=False)
def static(name: str):
    media_type = STATIC_ASSETS.get(name)
    if media_type is None:
        raise HTTPException(404, 'Static asset not found')
    root = STATIC_ROOT.resolve()
    target = (root / name).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        raise HTTPException(404, 'Static asset not found')
    return FileResponse(target, media_type=media_type)

@router.post('/api/devices/{device_id}/manage')
def register_managed_device(device_id:int,request:Request):
    """Explicitly link an inventory item to the managed inventory by IP, not row ID."""
    require_role(request,'Admin')
    from webapi.data37 import columns,ip_value
    from webapi.runtime37 import utcnow
    with connection() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT * FROM devices WHERE id=?',(device_id,)).fetchone()
        if not row:raise HTTPException(404,'Device not found')
        d=dict(row);host=str(ipaddress.ip_address(ip_value(d)));cols=columns(c,'network_devices')
        ips=[k for k in ('ip','ip_address') if k in cols]
        matches=c.execute('SELECT id FROM network_devices WHERE '+' OR '.join(k+'=?' for k in ips),[host]*len(ips)).fetchall()
        if len(matches)>1:raise HTTPException(409,'Duplicate managed IP; resolve identity conflict first')
        if matches:return {'success':True,'managed_id':matches[0]['id'],'existing':True}
        name=d.get('hostname') or host
        values={k:v for k,v in {'name':name,'device_name':name,'ip':host,'ip_address':host,'mac_address':d.get('mac') or d.get('mac_address') or '',
            'status':'Unknown','vendor':d.get('manufacturer') or '', 'device_type':d.get('device_type') or '', 'created_at':utcnow(),'updated_at':utcnow()}.items() if k in cols}
        cur=c.execute('INSERT INTO network_devices('+','.join(values)+') VALUES('+','.join('?' for _ in values)+')',list(values.values()))
        return {'success':True,'managed_id':cur.lastrowid,'existing':False}
