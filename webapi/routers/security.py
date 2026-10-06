from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from database.db import get_connection
from modules.enterprise_security import ensure_enterprise_security_tables,sync_registered_assets,asset_sync_diagnostics,record_event,close_event,calculate_risk,verify_asset_identity,tcp_probe,tls_certificate_check
from modules.enterprise_response import create_incident,create_incident_from_event,request_playbook,approve_playbook,upsert_vulnerability,security_score,audit
from webapi.core.security import current_user,require_roles
from webapi.schemas import EventIn,IncidentIn,PlaybookIn,VulnerabilityIn,IdentityIn,TcpProbeIn,PatchIn,PatchStatusIn,ComplianceUpdateIn
from webapi.realtime import hub
from webapi.workers import enqueue
from webapi.db import production_database_status
router=APIRouter(tags=['Enterprise Security'])
def rows(sql,args=()):
    c=get_connection()
    try:return [dict(r) for r in c.execute(sql,args).fetchall()]
    finally:c.close()
def now(): return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
@router.get('/dashboard')
def dashboard(user=Depends(current_user)):
    sync_registered_assets()
    return {'score':security_score(),'events':rows("SELECT * FROM security_events ORDER BY id DESC LIMIT 20"),'incidents':rows("SELECT * FROM security_incidents ORDER BY id DESC LIMIT 20"),'stats':{
      'assets': rows("SELECT COUNT(*) n FROM security_assets")[0]['n'],
      'open_events': rows("SELECT COUNT(*) n FROM security_events WHERE status='OPEN'")[0]['n'],
      'open_incidents': rows("SELECT COUNT(*) n FROM security_incidents WHERE status='OPEN'")[0]['n'],
      'open_vulnerabilities': rows("SELECT COUNT(*) n FROM vulnerabilities WHERE status='OPEN'")[0]['n']}}
@router.get('/assets')
def assets(user=Depends(current_user)):
    sync_registered_assets()
    return rows('SELECT * FROM security_assets ORDER BY ip')

@router.get('/assets/diagnostics')
def assets_diagnostics(user=Depends(require_roles('Admin'))):
    return asset_sync_diagnostics()
@router.post('/assets/sync')
def sync(user=Depends(require_roles('Admin','Operator'))): return {'synced':sync_registered_assets()}
@router.get('/assets/{ip}/risk')
def risk(ip:str,user=Depends(current_user)): return calculate_risk(ip)
@router.post('/assets/{ip}/identity')
def identity(ip:str,body:IdentityIn,user=Depends(require_roles('Admin','Operator'))): return verify_asset_identity(ip,body.observed_mac,body.observed_hostname)
@router.post('/assets/{ip}/tcp-check')
def tcp(ip:str,body:TcpProbeIn,user=Depends(require_roles('Admin','Operator'))): return tcp_probe(ip,body.ports)
@router.post('/assets/{ip}/tls-check')
def tls(ip:str,port:int=443,user=Depends(require_roles('Admin','Operator'))): return tls_certificate_check(ip,port)
@router.get('/events')
def events(status:str|None=None,user=Depends(current_user)):
    return rows('SELECT * FROM security_events WHERE status=? ORDER BY id DESC',(status.upper(),)) if status else rows('SELECT * FROM security_events ORDER BY id DESC LIMIT 1000')
@router.post('/events')
async def add_event(body:EventIn,user=Depends(require_roles('Admin','Operator'))):
    eid=record_event(body.asset_ip,body.source,body.event_type,body.severity,body.title,body.detail)
    await hub.broadcast({'type':'security_event','id':eid,'asset_ip':body.asset_ip,'source':body.source,'event_type':body.event_type,'severity':body.severity.upper(),'title':body.title})
    return {'id':eid}
@router.post('/events/{event_id}/close')
def close(event_id:int,user=Depends(require_roles('Admin','Operator'))): close_event(event_id); return {'ok':True}
@router.get('/incidents')
def incidents(user=Depends(current_user)): return rows('SELECT * FROM security_incidents ORDER BY id DESC LIMIT 1000')
@router.post('/incidents')
def incident(body:IncidentIn,user=Depends(require_roles('Admin','Operator'))): return {'id':create_incident(body.title,body.severity,body.summary,body.owner,user['username'])}
@router.post('/incidents/from-event/{event_id}')
def incident_event(event_id:int,user=Depends(require_roles('Admin','Operator'))): return {'id':create_incident_from_event(event_id,user['username'])}
@router.get('/playbooks')
def playbooks(user=Depends(current_user)): return rows('SELECT * FROM response_playbooks ORDER BY id DESC LIMIT 1000')
@router.post('/playbooks')
def playbook(body:PlaybookIn,user=Depends(require_roles('Admin','Operator'))): return {'id':request_playbook(body.incident_id,body.name,body.action_type,body.target,user['username'],body.notes)}
@router.post('/playbooks/{playbook_id}/approve')
def approve(playbook_id:int,user=Depends(require_roles('Admin'))): approve_playbook(playbook_id,user['username'],user['role']); return {'ok':True,'note':'Approval recorded; no remote action executed'}
@router.get('/vulnerabilities')
def vulnerabilities(user=Depends(current_user)): return rows('SELECT * FROM vulnerabilities ORDER BY kev DESC,cvss DESC,id DESC LIMIT 2000')
@router.post('/vulnerabilities')
def vulnerability(body:VulnerabilityIn,user=Depends(require_roles('Admin','Operator'))): upsert_vulnerability(**body.model_dump(),actor=user['username']); return {'ok':True}
@router.get('/patches')
def patches(user=Depends(current_user)): return rows('SELECT * FROM patch_records ORDER BY id DESC LIMIT 2000')
@router.post('/patches')
def add_patch(body:PatchIn,user=Depends(require_roles('Admin','Operator'))):
    allowed={'PENDING','SCHEDULED','INSTALLED','FAILED','OVERDUE'}
    if body.status.upper() not in allowed: raise HTTPException(400,'Invalid patch status')
    c=get_connection()
    try:
        cur=c.execute('INSERT INTO patch_records(asset_ip,cve_id,patch_name,status,due_date,owner,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)',(body.asset_ip,body.cve_id.upper(),body.patch_name,body.status.upper(),body.due_date,body.owner,body.notes,now(),now())); c.commit(); pid=cur.lastrowid
    finally:c.close()
    audit(user['username'],'CREATE','PATCH',pid,body.patch_name); return {'id':pid}
@router.patch('/patches/{patch_id}')
def patch_status(patch_id:int,body:PatchStatusIn,user=Depends(require_roles('Admin','Operator'))):
    allowed={'PENDING','SCHEDULED','INSTALLED','FAILED','OVERDUE'}; st=body.status.upper()
    if st not in allowed: raise HTTPException(400,'Invalid patch status')
    c=get_connection()
    try:
        cur=c.execute("UPDATE patch_records SET status=?, notes=?, installed_at=CASE WHEN ?='INSTALLED' THEN ? ELSE installed_at END, updated_at=? WHERE id=?",(st,body.notes,st,now(),now(),patch_id)); c.commit()
        if cur.rowcount==0: raise HTTPException(404,'Patch not found')
    finally:c.close()
    audit(user['username'],'UPDATE_STATUS','PATCH',patch_id,st); return {'ok':True}
@router.get('/compliance')
def compliance(user=Depends(current_user)): return rows('SELECT * FROM compliance_controls ORDER BY framework,control_id')
@router.patch('/compliance/{control_id}')
def compliance_update(control_id:int,body:ComplianceUpdateIn,user=Depends(require_roles('Admin','Operator'))):
    allowed={'NOT_ASSESSED','PASS','PARTIAL','FAIL','COMPLIANT','NON_COMPLIANT'}; st=body.status.upper()
    if st not in allowed: raise HTTPException(400,'Invalid compliance status')
    c=get_connection()
    try:
        cur=c.execute('UPDATE compliance_controls SET status=?,evidence=?,owner=?,updated_at=? WHERE id=?',(st,body.evidence,body.owner,now(),control_id)); c.commit()
        if cur.rowcount==0: raise HTTPException(404,'Control not found')
    finally:c.close()
    audit(user['username'],'ASSESS','COMPLIANCE',control_id,st); return {'ok':True}
@router.get('/audit')
def audit_log(user=Depends(require_roles('Admin'))): return rows('SELECT * FROM security_audit_trail ORDER BY id DESC LIMIT 2000')


@router.get('/system/architecture')
def architecture(user=Depends(require_roles('Admin'))):
    return {'database':production_database_status(),'redis_queue':'optional','syslog':'disabled-by-default','websocket':'/api/v1/ws/events'}

@router.post('/jobs/sync-assets')
def queue_sync(user=Depends(require_roles('Admin','Operator'))):
    return enqueue('SYNC_ASSETS',{})

@router.post('/jobs/recalc-risk/{ip}')
def queue_risk(ip:str,user=Depends(require_roles('Admin','Operator'))):
    return enqueue('RECALC_RISK',{'asset_ip':ip})
