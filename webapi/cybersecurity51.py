"""NetworkAutomation Cybersecurity 5.2 defensive security center.

The module intentionally limits active network checks to assets already known to the
local NetworkAutomation inventory and private/link-local addresses. It does not
perform exploitation, credential attacks, persistence, or remote destructive actions.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from webapi.runtime37 import connection, utcnow
from webapi.security37 import require_role, reset_mfa
from webapi import security37

router = APIRouter(prefix='/api/v51', tags=['Cybersecurity 5.1'])

COMMON_PORTS = [22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]
INSECURE_PORTS = {23: 'Telnet plaintext management', 21: 'FTP plaintext transfer', 69: 'TFTP unauthenticated/plaintext transfer', 80: 'HTTP plaintext web service'}
SERVICE_NAMES = {22:'ssh',23:'telnet',25:'smtp',53:'dns',80:'http',110:'pop3',135:'msrpc',139:'netbios',143:'imap',161:'snmp',389:'ldap',443:'https',445:'smb',465:'smtps',587:'smtp-submission',636:'ldaps',993:'imaps',995:'pop3s',1433:'mssql',1521:'oracle',3306:'mysql',3389:'rdp',5432:'postgresql',5900:'vnc',8080:'http-alt',8443:'https-alt'}
SEV_WEIGHT = {'INFO':0,'LOW':5,'MEDIUM':15,'HIGH':30,'CRITICAL':50}


class SiemEventIn(BaseModel):
    source: str = Field(min_length=1, max_length=80)
    event_type: str = Field(min_length=1, max_length=100)
    severity: str = Field(default='INFO', max_length=16)
    message: str = Field(min_length=1, max_length=4000)
    asset_ip: str = Field(default='', max_length=45)
    subject_user: str = Field(default='', max_length=120)
    peer_ip: str = Field(default='', max_length=45)
    metadata: dict[str, Any] = Field(default_factory=dict)


class VulnScanIn(BaseModel):
    asset_ip: str = Field(max_length=45)
    ports: list[int] = Field(default_factory=list)
    timeout_ms: int = Field(default=500, ge=100, le=2500)


class CveLookupIn(BaseModel):
    cve_id: str = Field(min_length=9, max_length=32)


class HashLookupIn(BaseModel):
    sha256: str = Field(min_length=64, max_length=64)


class PasswordStrengthIn(BaseModel):
    password: str = Field(min_length=1, max_length=512)


class CryptoEncryptIn(BaseModel):
    plaintext: str = Field(max_length=200000)
    passphrase: str = Field(min_length=12, max_length=512)


class CryptoDecryptIn(BaseModel):
    package: str = Field(max_length=400000)
    passphrase: str = Field(min_length=12, max_length=512)


class TlsCheckIn(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)


class AlertWorkflowIn(BaseModel):
    note: str = Field(default='', max_length=2000)
    owner: str = Field(default='', max_length=120)


class VaultCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    category: str = Field(default='General', max_length=80)
    username: str = Field(default='', max_length=160)
    secret: str = Field(min_length=1, max_length=4096)
    url: str = Field(default='', max_length=500)
    note: str = Field(default='', max_length=2000)


class VaultRevealIn(BaseModel):
    code: str = Field(min_length=6, max_length=12)


def _json(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def ensure_tables():
    with connection() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS siem_events51(
          id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL,event_type TEXT NOT NULL,
          severity TEXT NOT NULL,message TEXT NOT NULL,asset_ip TEXT DEFAULT '',subject_user TEXT DEFAULT '',
          peer_ip TEXT DEFAULT '',metadata_json TEXT DEFAULT '{}',actor TEXT DEFAULT '',created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_siem51_time ON siem_events51(created_at DESC);
        CREATE INDEX IF NOT EXISTS ix_siem51_type ON siem_events51(event_type,severity);
        CREATE TABLE IF NOT EXISTS security_alerts51(
          id INTEGER PRIMARY KEY AUTOINCREMENT,rule_key TEXT NOT NULL,title TEXT NOT NULL,severity TEXT NOT NULL,
          asset_ip TEXT DEFAULT '',subject_user TEXT DEFAULT '',status TEXT NOT NULL DEFAULT 'OPEN',
          evidence_json TEXT DEFAULT '{}',first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,count INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS ix_alert51_status ON security_alerts51(status,severity,last_seen DESC);
        CREATE TABLE IF NOT EXISTS vulnerability_scans51(
          id INTEGER PRIMARY KEY AUTOINCREMENT,asset_ip TEXT NOT NULL,ports_json TEXT NOT NULL,
          open_ports INTEGER NOT NULL DEFAULT 0,high_findings INTEGER NOT NULL DEFAULT 0,
          actor TEXT DEFAULT '',created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS vulnerability_findings51(
          id INTEGER PRIMARY KEY AUTOINCREMENT,scan_id INTEGER NOT NULL,asset_ip TEXT NOT NULL,port INTEGER NOT NULL,
          service TEXT DEFAULT '',severity TEXT NOT NULL,finding TEXT NOT NULL,evidence_json TEXT DEFAULT '{}',created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_vfind51_asset ON vulnerability_findings51(asset_ip,severity,created_at DESC);
        CREATE TABLE IF NOT EXISTS threat_lookup_cache51(
          lookup_key TEXT PRIMARY KEY,kind TEXT NOT NULL,result_json TEXT NOT NULL,source TEXT NOT NULL,updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS security_settings51(
          id INTEGER PRIMARY KEY CHECK(id=1),remote_https_required INTEGER NOT NULL DEFAULT 1,
          vt_enabled INTEGER NOT NULL DEFAULT 0,nvd_enabled INTEGER NOT NULL DEFAULT 1,updated_at TEXT NOT NULL
        );
        INSERT OR IGNORE INTO security_settings51(id,remote_https_required,vt_enabled,nvd_enabled,updated_at)
          VALUES(1,1,0,1,datetime('now'));
        CREATE TABLE IF NOT EXISTS secret_vault52(
          id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,category TEXT NOT NULL DEFAULT 'General',
          username TEXT DEFAULT '',secret_enc TEXT NOT NULL,url TEXT DEFAULT '',note TEXT DEFAULT '',
          owner TEXT DEFAULT '',created_at TEXT NOT NULL,updated_at TEXT NOT NULL,last_accessed_at TEXT DEFAULT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_secret_vault52_name ON secret_vault52(category,name);
        ''')
        cols={r['name'] for r in c.execute('PRAGMA table_info(security_alerts51)').fetchall()}
        for name,ddl in {
            'owner':'TEXT DEFAULT \'\'',
            'ack_by':'TEXT DEFAULT \'\'',
            'ack_at':'TEXT DEFAULT NULL',
            'resolution_note':'TEXT DEFAULT \'\'',
            'resolved_by':'TEXT DEFAULT \'\'',
            'resolved_at':'TEXT DEFAULT NULL'}.items():
            if name not in cols:
                c.execute(f'ALTER TABLE security_alerts51 ADD COLUMN {name} {ddl}')
        c.commit()


def _rows(sql, args=()):
    with connection() as c:
        return [dict(r) for r in c.execute(sql,args).fetchall()]


def _one(sql, args=()):
    with connection() as c:
        r=c.execute(sql,args).fetchone()
        return dict(r) if r else None


def _known_private_asset(ip: str):
    try:
        addr=ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400,'INVALID_IP')
    if addr.version != 4 or not (addr.is_private or addr.is_link_local):
        raise HTTPException(400,'DEFENSIVE_SCAN_PRIVATE_ASSETS_ONLY')
    ensure_tables()
    with connection() as c:
        checks=[
            ("SELECT 1 FROM security_assets WHERE ip=? LIMIT 1",(ip,)),
            ("SELECT 1 FROM ip_mac_inventory WHERE ip=? LIMIT 1",(ip,)),
        ]
        # devices schemas differ across legacy versions.
        try:
            cols={r['name'] for r in c.execute('PRAGMA table_info(devices)').fetchall()}
            if 'ip' in cols: checks.append(("SELECT 1 FROM devices WHERE ip=? LIMIT 1",(ip,)))
            if 'ip_address' in cols: checks.append(("SELECT 1 FROM devices WHERE ip_address=? LIMIT 1",(ip,)))
        except Exception:
            pass
        for sql,args in checks:
            try:
                if c.execute(sql,args).fetchone(): return True
            except Exception:
                continue
    raise HTTPException(404,'ASSET_NOT_REGISTERED')


def _notify_security_async(title,severity,asset_ip,evidence):
    if severity not in ('HIGH','CRITICAL'):
        return
    def worker():
        try:
            from modules.advanced_pages import notify_alert
            notify_alert(asset_ip or 'application', 'Cybersecurity', title, severity=severity,
                         event_key='cyber51:'+hashlib.sha256((title+'|'+(asset_ip or '')).encode()).hexdigest()[:20])
        except Exception:
            pass
    threading.Thread(target=worker,name='cyber51-notify',daemon=True).start()


def _upsert_alert(rule_key,title,severity,asset_ip='',subject_user='',evidence=None):
    ensure_tables(); now=utcnow(); evidence=evidence or {}
    with connection() as c:
        row=c.execute("SELECT id,count FROM security_alerts51 WHERE rule_key=? AND asset_ip=? AND subject_user=? AND status='OPEN' ORDER BY id DESC LIMIT 1",
                      (rule_key,asset_ip,subject_user)).fetchone()
        if row:
            c.execute('UPDATE security_alerts51 SET count=?,last_seen=?,evidence_json=? WHERE id=?',(int(row['count'])+1,now,_json(evidence),row['id']))
            aid=row['id']
        else:
            cur=c.execute('INSERT INTO security_alerts51(rule_key,title,severity,asset_ip,subject_user,evidence_json,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?)',
                          (rule_key,title,severity,asset_ip,subject_user,_json(evidence),now,now)); aid=cur.lastrowid
        c.commit()
    _notify_security_async(title,severity,asset_ip,evidence)
    return aid


def _correlate_event(event_id:int, event:dict):
    et=event['event_type'].upper(); sev=event['severity']; now=time.time()
    if et in {'LOGIN_FAILED','AUTH_FAILURE','FAILED_LOGIN'}:
        # Five failures for same user or peer in ten minutes.
        with connection() as c:
            since=datetime.fromtimestamp(now-600).strftime('%Y-%m-%d %H:%M:%S')
            row=c.execute("SELECT COUNT(*) n FROM siem_events51 WHERE event_type IN ('LOGIN_FAILED','AUTH_FAILURE','FAILED_LOGIN') AND created_at>=? AND (subject_user=? OR peer_ip=?)",
                          (since,event.get('subject_user',''),event.get('peer_ip',''))).fetchone()
        if row and int(row['n'])>=5:
            _upsert_alert('BRUTE_FORCE','Repeated authentication failures','HIGH',event.get('asset_ip',''),event.get('subject_user',''),{'event_id':event_id,'failures_10m':int(row['n']),'peer_ip':event.get('peer_ip','')})
    if et in {'LOGIN_SUCCESS','AUTH_SUCCESS','SUCCESSFUL_LOGIN'} and event.get('subject_user') and event.get('peer_ip'):
        # Alert only when this user has prior successful-login history and this peer is new within 30 days.
        with connection() as c:
            since=datetime.fromtimestamp(now-30*86400).strftime('%Y-%m-%d %H:%M:%S')
            prior=c.execute("SELECT COUNT(*) n FROM siem_events51 WHERE id<>? AND event_type IN ('LOGIN_SUCCESS','AUTH_SUCCESS','SUCCESSFUL_LOGIN') AND subject_user=? AND created_at>=?",
                            (event_id,event.get('subject_user',''),since)).fetchone()
            known=c.execute("SELECT COUNT(*) n FROM siem_events51 WHERE id<>? AND event_type IN ('LOGIN_SUCCESS','AUTH_SUCCESS','SUCCESSFUL_LOGIN') AND subject_user=? AND peer_ip=? AND created_at>=?",
                            (event_id,event.get('subject_user',''),event.get('peer_ip',''),since)).fetchone()
        if prior and int(prior['n'])>0 and known and int(known['n'])==0:
            _upsert_alert('NEW_LOGIN_SOURCE','New login source for existing account','MEDIUM',event.get('asset_ip',''),event.get('subject_user',''),{'event_id':event_id,'peer_ip':event.get('peer_ip','')})
    if et in {'ADMIN_CREATED','PRIVILEGE_ESCALATION','ROLE_CHANGED_TO_ADMIN'}:
        _upsert_alert('PRIVILEGED_CHANGE','Privileged account/role change','HIGH',event.get('asset_ip',''),event.get('subject_user',''),{'event_id':event_id})
    if sev in {'CRITICAL','HIGH'}:
        _upsert_alert('HIGH_SEVERITY_EVENT',event['message'][:180],sev,event.get('asset_ip',''),event.get('subject_user',''),{'event_id':event_id,'source':event['source']})
    try:
        from webapi.cybersecurity54 import correlate_event54
        correlate_event54(event_id,event)
    except Exception:
        # 5.4 enrichment is fail-open for SIEM ingestion; built-in correlation remains authoritative.
        pass


@router.get('/dashboard')
def dashboard(request:Request):
    require_role(request)
    ensure_tables()
    with connection() as c:
        def count(sql,args=()): return int(c.execute(sql,args).fetchone()[0])
        assets=0
        for table in ('security_assets','ip_mac_inventory'):
            try: assets=max(assets,count(f'SELECT COUNT(*) FROM {table}'))
            except Exception: pass
        open_alerts=count("SELECT COUNT(*) FROM security_alerts51 WHERE status='OPEN'")
        critical=count("SELECT COUNT(*) FROM security_alerts51 WHERE status='OPEN' AND severity='CRITICAL'")
        high=count("SELECT COUNT(*) FROM security_alerts51 WHERE status='OPEN' AND severity='HIGH'")
        findings=count("SELECT COUNT(*) FROM vulnerability_findings51")
        failed_24h=count("SELECT COUNT(*) FROM web_login_attempts37 WHERE success=0 AND at>?",(time.time()-86400,))
        incidents=0
        try: incidents=count("SELECT COUNT(*) FROM security_incidents WHERE status NOT IN ('CLOSED','RESOLVED')")
        except Exception: pass
        score=max(0,100-min(100,critical*35+high*15+min(25,findings)+min(20,failed_24h//2)))
    return {'security_score':score,'assets':assets,'open_alerts':open_alerts,'critical_alerts':critical,'high_alerts':high,
            'vulnerability_findings':findings,'failed_logins_24h':failed_24h,'open_incidents':incidents,
            'alerts':_rows("SELECT * FROM security_alerts51 ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,last_seen DESC LIMIT 15"),
            'events':_rows('SELECT id,source,event_type,severity,message,asset_ip,subject_user,peer_ip,actor,created_at FROM siem_events51 ORDER BY id DESC LIMIT 20')}


@router.get('/siem/events')
def list_siem(request:Request, limit:int=500):
    require_role(request); ensure_tables(); limit=max(1,min(limit,2000))
    return _rows('SELECT id,source,event_type,severity,message,asset_ip,subject_user,peer_ip,actor,created_at FROM siem_events51 ORDER BY id DESC LIMIT ?',(limit,))


@router.post('/siem/events')
def ingest_siem(body:SiemEventIn, request:Request):
    user=require_role(request,'Admin','Analyst','Operator'); ensure_tables()
    sev=body.severity.upper()
    if sev not in SEV_WEIGHT: raise HTTPException(400,'INVALID_SEVERITY')
    if body.asset_ip:
        try: ipaddress.ip_address(body.asset_ip)
        except ValueError: raise HTTPException(400,'INVALID_ASSET_IP')
    if body.peer_ip:
        try: ipaddress.ip_address(body.peer_ip)
        except ValueError: raise HTTPException(400,'INVALID_PEER_IP')
    safe_meta={k:v for k,v in body.metadata.items() if str(k).lower() not in {'password','secret','token','private_key','authorization'}}
    with connection() as c:
        cur=c.execute('INSERT INTO siem_events51(source,event_type,severity,message,asset_ip,subject_user,peer_ip,metadata_json,actor,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',
                      (body.source,body.event_type.upper(),sev,body.message,body.asset_ip,body.subject_user,body.peer_ip,_json(safe_meta),user['username'],utcnow())); eid=cur.lastrowid; c.commit()
    _correlate_event(eid,{'source':body.source,'event_type':body.event_type.upper(),'severity':sev,'message':body.message,'asset_ip':body.asset_ip,'subject_user':body.subject_user,'peer_ip':body.peer_ip,'metadata':safe_meta})
    return {'id':eid,'correlated':True}


@router.get('/alerts')
def alerts(request:Request, status:str='OPEN', limit:int=500):
    require_role(request); ensure_tables(); limit=max(1,min(limit,2000))
    if status.upper()=='ALL': return _rows('SELECT * FROM security_alerts51 ORDER BY id DESC LIMIT ?',(limit,))
    return _rows('SELECT * FROM security_alerts51 WHERE status=? ORDER BY id DESC LIMIT ?',(status.upper(),limit))


@router.post('/alerts/{alert_id}/ack')
def alert_ack(alert_id:int, body:AlertWorkflowIn, request:Request):
    user=require_role(request,'Admin','Analyst','Operator'); ensure_tables(); now=utcnow()
    with connection() as c:
        row=c.execute('SELECT id,status FROM security_alerts51 WHERE id=?',(alert_id,)).fetchone()
        if not row: raise HTTPException(404,'ALERT_NOT_FOUND')
        if row['status']=='RESOLVED': raise HTTPException(409,'ALERT_ALREADY_RESOLVED')
        owner=(body.owner or user['username']).strip()
        c.execute("UPDATE security_alerts51 SET status='ACKNOWLEDGED',owner=?,ack_by=?,ack_at=?,last_seen=last_seen WHERE id=?",(owner,user['username'],now,alert_id)); c.commit()
    return {'ok':True,'id':alert_id,'status':'ACKNOWLEDGED','owner':owner,'actor':user['username']}


@router.post('/alerts/{alert_id}/resolve')
def alert_resolve(alert_id:int, body:AlertWorkflowIn, request:Request):
    user=require_role(request,'Admin','Analyst'); ensure_tables(); now=utcnow()
    with connection() as c:
        row=c.execute('SELECT id FROM security_alerts51 WHERE id=?',(alert_id,)).fetchone()
        if not row: raise HTTPException(404,'ALERT_NOT_FOUND')
        owner=(body.owner or user['username']).strip()
        c.execute("UPDATE security_alerts51 SET status='RESOLVED',owner=?,resolution_note=?,resolved_by=?,resolved_at=? WHERE id=?",(owner,body.note.strip(),user['username'],now,alert_id)); c.commit()
    return {'ok':True,'id':alert_id,'status':'RESOLVED','owner':owner,'actor':user['username']}


@router.post('/alerts/{alert_id}/reopen')
def alert_reopen(alert_id:int, request:Request):
    user=require_role(request,'Admin','Analyst'); ensure_tables()
    with connection() as c:
        row=c.execute('SELECT id FROM security_alerts51 WHERE id=?',(alert_id,)).fetchone()
        if not row: raise HTTPException(404,'ALERT_NOT_FOUND')
        c.execute("UPDATE security_alerts51 SET status='OPEN',resolution_note='',resolved_by='',resolved_at=NULL WHERE id=?",(alert_id,)); c.commit()
    return {'ok':True,'id':alert_id,'status':'OPEN','actor':user['username']}


def _vault_mfa_ok(user:dict, code:str):
    from modules.nms_v5 import decrypt_secret
    security37.ensure_tables()
    with connection() as c:
        row=c.execute('SELECT COALESCE(mfa_enabled,0) mfa_enabled,mfa_secret_enc FROM app_users WHERE id=?',(user['id'],)).fetchone()
    if not row or not row['mfa_enabled'] or not row['mfa_secret_enc']:
        raise HTTPException(403,'MFA_STEP_UP_REQUIRED')
    try: secret=decrypt_secret(row['mfa_secret_enc'])
    except Exception as exc: raise HTTPException(500,'MFA_SECRET_UNAVAILABLE') from exc
    if not security37._verify_totp(secret,code): raise HTTPException(401,'INVALID_MFA_CODE')


@router.get('/vault')
def vault_list(request:Request):
    require_role(request,'Admin','Analyst'); ensure_tables()
    return _rows('SELECT id,name,category,username,url,note,owner,created_at,updated_at,last_accessed_at FROM secret_vault52 ORDER BY category COLLATE NOCASE,name COLLATE NOCASE')


@router.post('/vault')
def vault_create(body:VaultCreateIn, request:Request):
    user=require_role(request,'Admin'); ensure_tables()
    from modules.nms_v5 import encrypt_secret
    now=utcnow()
    with connection() as c:
        cur=c.execute('INSERT INTO secret_vault52(name,category,username,secret_enc,url,note,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)',
                      (body.name.strip(),body.category.strip() or 'General',body.username.strip(),encrypt_secret(body.secret),body.url.strip(),body.note.strip(),user['username'],now,now)); vid=cur.lastrowid; c.commit()
    return {'ok':True,'id':vid,'stored_encrypted':True,'secret_returned':False}


@router.post('/vault/{vault_id}/reveal')
def vault_reveal(vault_id:int, body:VaultRevealIn, request:Request):
    user=require_role(request,'Admin'); ensure_tables(); _vault_mfa_ok(user,body.code)
    from modules.nms_v5 import decrypt_secret
    with connection() as c:
        row=c.execute('SELECT id,name,username,secret_enc FROM secret_vault52 WHERE id=?',(vault_id,)).fetchone()
        if not row: raise HTTPException(404,'VAULT_ENTRY_NOT_FOUND')
        c.execute('UPDATE secret_vault52 SET last_accessed_at=? WHERE id=?',(utcnow(),vault_id)); c.commit()
    return {'id':vault_id,'name':row['name'],'username':row['username'],'secret':decrypt_secret(row['secret_enc']),'step_up_mfa':True}


@router.delete('/vault/{vault_id}')
def vault_delete(vault_id:int, request:Request):
    user=require_role(request,'Admin'); ensure_tables()
    with connection() as c:
        row=c.execute('SELECT id FROM secret_vault52 WHERE id=?',(vault_id,)).fetchone()
        if not row: raise HTTPException(404,'VAULT_ENTRY_NOT_FOUND')
        c.execute('DELETE FROM secret_vault52 WHERE id=?',(vault_id,)); c.commit()
    return {'ok':True,'id':vault_id,'actor':user['username']}


@router.post('/vulnerability/scan')
def vulnerability_scan(body:VulnScanIn, request:Request):
    user=require_role(request,'Admin','Analyst','Operator'); _known_private_asset(body.asset_ip); ensure_tables()
    ports=body.ports or COMMON_PORTS
    clean=[]
    for p in ports:
        p=int(p)
        if not 1<=p<=65535: raise HTTPException(400,'INVALID_PORT')
        if p not in clean: clean.append(p)
    if len(clean)>32: raise HTTPException(400,'MAX_32_PORTS')
    timeout=max(.1,min(2.5,body.timeout_ms/1000.0)); findings=[]; open_ports=[]
    for port in clean:
        started=time.monotonic(); ok=False; err=''
        try:
            with socket.create_connection((body.asset_ip,port),timeout=timeout): ok=True
        except OSError as exc: err=type(exc).__name__
        elapsed=round((time.monotonic()-started)*1000,1)
        if not ok: continue
        open_ports.append(port); service=SERVICE_NAMES.get(port,'tcp')
        severity='LOW'; finding=f'Open TCP service: {service}/{port}'
        if port in INSECURE_PORTS:
            severity='HIGH' if port==23 else 'MEDIUM'; finding=INSECURE_PORTS[port]
        elif port in {3389,445,5900}:
            severity='MEDIUM'; finding=f'Remote/administrative service exposed on LAN: {service}/{port}'
        evidence={'tcp_connect':True,'elapsed_ms':elapsed}
        if port in (443,8443):
            try:
                ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
                with socket.create_connection((body.asset_ip,port),timeout=timeout) as raw:
                    with ctx.wrap_socket(raw,server_hostname=body.asset_ip) as tls:
                        evidence['tls_version']=tls.version(); evidence['cipher']=tls.cipher()[0] if tls.cipher() else ''
            except Exception as exc: evidence['tls_probe_error']=type(exc).__name__
        findings.append({'port':port,'service':service,'severity':severity,'finding':finding,'evidence':evidence})
    high=sum(1 for f in findings if f['severity'] in ('HIGH','CRITICAL'))
    with connection() as c:
        cur=c.execute('INSERT INTO vulnerability_scans51(asset_ip,ports_json,open_ports,high_findings,actor,created_at) VALUES(?,?,?,?,?,?)',
                      (body.asset_ip,_json(clean),len(open_ports),high,user['username'],utcnow())); sid=cur.lastrowid
        for f in findings:
            c.execute('INSERT INTO vulnerability_findings51(scan_id,asset_ip,port,service,severity,finding,evidence_json,created_at) VALUES(?,?,?,?,?,?,?,?)',
                      (sid,body.asset_ip,f['port'],f['service'],f['severity'],f['finding'],_json(f['evidence']),utcnow()))
        c.commit()
    if high:
        _upsert_alert('VULNERABILITY_SCAN','High-risk service exposure detected','HIGH',body.asset_ip,'',{'scan_id':sid,'high_findings':high,'open_ports':open_ports})
    return {'scan_id':sid,'asset_ip':body.asset_ip,'ports_checked':len(clean),'open_ports':open_ports,'findings':findings,'note':'TCP connect assessment only; no exploit or credential attempt was performed.'}


@router.get('/vulnerability/findings')
def vulnerability_findings(request:Request, limit:int=1000):
    require_role(request); ensure_tables(); limit=max(1,min(limit,3000))
    return _rows('SELECT id,scan_id,asset_ip,port,service,severity,finding,created_at FROM vulnerability_findings51 ORDER BY id DESC LIMIT ?',(limit,))


def _http_json(url:str, headers:dict[str,str]|None=None, timeout=8):
    req=urllib.request.Request(url,headers={'User-Agent':'NetworkAutomation-Cybersecurity/5.2',**(headers or {})})
    with urllib.request.urlopen(req,timeout=timeout) as resp:
        data=resp.read(2_000_000)
        return json.loads(data.decode('utf-8','replace'))


@router.post('/vulnerability/cve/lookup')
def cve_lookup(body:CveLookupIn, request:Request):
    require_role(request,'Admin','Analyst'); ensure_tables(); cve=body.cve_id.upper().strip()
    if not re.fullmatch(r'CVE-\d{4}-\d{4,8}',cve): raise HTTPException(400,'INVALID_CVE_ID')
    key='CVE:'+cve; cached=_one('SELECT * FROM threat_lookup_cache51 WHERE lookup_key=?',(key,))
    if cached:
        try:
            age=(datetime.now(timezone.utc)-datetime.fromisoformat(cached['updated_at'].replace('Z','+00:00'))).total_seconds()
            if age<86400: return {'cached':True,**json.loads(cached['result_json'])}
        except Exception: pass
    url='https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='+urllib.parse.quote(cve)
    headers={}; api_key=os.environ.get('NA_NVD_API_KEY','').strip()
    if api_key: headers['apiKey']=api_key
    try: data=_http_json(url,headers,10)
    except Exception as exc: raise HTTPException(502,f'NVD_LOOKUP_FAILED:{type(exc).__name__}')
    vulns=data.get('vulnerabilities') or []
    if not vulns: result={'cve_id':cve,'found':False,'source':'NVD'}
    else:
        obj=vulns[0].get('cve') or {}; desc=''
        for d in obj.get('descriptions') or []:
            if d.get('lang')=='en': desc=d.get('value',''); break
        metrics=obj.get('metrics') or {}; score=None; severity='UNKNOWN'
        for keym in ('cvssMetricV31','cvssMetricV30','cvssMetricV2'):
            if metrics.get(keym):
                cv=metrics[keym][0].get('cvssData') or {}; score=cv.get('baseScore'); severity=cv.get('baseSeverity') or metrics[keym][0].get('baseSeverity') or 'UNKNOWN'; break
        result={'cve_id':cve,'found':True,'published':obj.get('published'),'last_modified':obj.get('lastModified'),'description':desc[:4000],'cvss':score,'severity':severity,'source':'NVD'}
    with connection() as c:
        c.execute('INSERT INTO threat_lookup_cache51(lookup_key,kind,result_json,source,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(lookup_key) DO UPDATE SET result_json=excluded.result_json,source=excluded.source,updated_at=excluded.updated_at',
                  (key,'CVE',_json(result),'NVD',datetime.now(timezone.utc).isoformat())); c.commit()
    return {'cached':False,**result}


@router.post('/threat/hash-lookup')
def hash_lookup(body:HashLookupIn, request:Request):
    require_role(request,'Admin','Analyst'); ensure_tables(); h=body.sha256.lower().strip()
    if not re.fullmatch(r'[0-9a-f]{64}',h): raise HTTPException(400,'INVALID_SHA256')
    api_key=os.environ.get('NA_VT_API_KEY','').strip()
    if not api_key: return {'configured':False,'sha256':h,'source':'VirusTotal','note':'Set NA_VT_API_KEY to enable hash reputation lookup. File upload is intentionally not automatic.'}
    try:
        data=_http_json('https://www.virustotal.com/api/v3/files/'+h,{'x-apikey':api_key},10)
        attrs=(data.get('data') or {}).get('attributes') or {}; stats=attrs.get('last_analysis_stats') or {}
        result={'configured':True,'sha256':h,'source':'VirusTotal','malicious':int(stats.get('malicious') or 0),'suspicious':int(stats.get('suspicious') or 0),'harmless':int(stats.get('harmless') or 0),'undetected':int(stats.get('undetected') or 0),'reputation':attrs.get('reputation'),'last_analysis_date':attrs.get('last_analysis_date')}
    except urllib.error.HTTPError as exc:
        if exc.code==404: result={'configured':True,'sha256':h,'source':'VirusTotal','found':False,'malicious':0,'suspicious':0}
        else: raise HTTPException(502,f'VT_LOOKUP_FAILED:{exc.code}')
    except Exception as exc: raise HTTPException(502,f'VT_LOOKUP_FAILED:{type(exc).__name__}')
    return result


@router.post('/password-strength')
def password_strength(body:PasswordStrengthIn, request:Request):
    require_role(request)
    p=body.password; score=0; reasons=[]
    if len(p)>=12: score+=1
    else: reasons.append('Use at least 12 characters')
    if len(p)>=16: score+=1
    classes=sum(bool(re.search(rx,p)) for rx in (r'[a-z]',r'[A-Z]',r'\d',r'[^A-Za-z0-9]'))
    if classes>=3: score+=1
    else: reasons.append('Mix upper/lowercase, numbers and symbols')
    lowered=p.lower()
    weak=('password','123456','qwerty','admin','letmein','welcome','networkautomation')
    if not any(w in lowered for w in weak): score+=1
    else: reasons.append('Avoid common/password-like words')
    if len(set(p))>=max(6,len(p)//3): score+=1
    else: reasons.append('Avoid excessive repeated characters')
    labels=['Very weak','Weak','Fair','Good','Strong','Very strong']
    # Never log or return the supplied password.
    return {'score':score,'max_score':5,'label':labels[score],'recommendations':reasons}


@router.post('/crypto/encrypt')
def crypto_encrypt(body:CryptoEncryptIn, request:Request):
    user=require_role(request)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        import base64, os as _os
        salt=_os.urandom(16); nonce=_os.urandom(12)
        key=Scrypt(salt=salt,length=32,n=2**15,r=8,p=1).derive(body.passphrase.encode())
        ct=AESGCM(key).encrypt(nonce,body.plaintext.encode('utf-8'),b'NetworkAutomation-5.1')
        pkg={'v':1,'alg':'AES-256-GCM+scrypt','salt':base64.b64encode(salt).decode(),'nonce':base64.b64encode(nonce).decode(),'ciphertext':base64.b64encode(ct).decode()}
        return {'package':base64.urlsafe_b64encode(_json(pkg).encode()).decode(),'algorithm':pkg['alg'],'stored':False}
    except Exception as exc: raise HTTPException(500,f'CRYPTO_UNAVAILABLE:{type(exc).__name__}')


@router.post('/crypto/decrypt')
def crypto_decrypt(body:CryptoDecryptIn, request:Request):
    require_role(request)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        import base64
        raw=base64.urlsafe_b64decode(body.package.encode()); pkg=json.loads(raw.decode())
        if pkg.get('alg')!='AES-256-GCM+scrypt': raise ValueError('algorithm')
        salt=base64.b64decode(pkg['salt']); nonce=base64.b64decode(pkg['nonce']); ct=base64.b64decode(pkg['ciphertext'])
        key=Scrypt(salt=salt,length=32,n=2**15,r=8,p=1).derive(body.passphrase.encode())
        pt=AESGCM(key).decrypt(nonce,ct,b'NetworkAutomation-5.1').decode('utf-8')
        return {'plaintext':pt,'stored':False}
    except Exception: raise HTTPException(400,'DECRYPT_FAILED')


def _allowed_tls_target(host:str):
    # IP targets must be known private assets. Hostnames are allowed only when configured as server targets.
    try:
        ipaddress.ip_address(host); _known_private_asset(host); return
    except ValueError:
        pass
    except HTTPException:
        raise
    with connection() as c:
        try:
            row=c.execute('SELECT 1 FROM server_targets WHERE lower(host)=lower(?) LIMIT 1',(host,)).fetchone()
        except Exception: row=None
    if not row: raise HTTPException(404,'TLS_TARGET_NOT_REGISTERED')


@router.post('/tls/check')
def tls_check(body:TlsCheckIn, request:Request):
    require_role(request,'Admin','Analyst','Operator'); host=body.host.strip(); _allowed_tls_target(host)
    started=time.monotonic(); verified=False; verify_error=''; cert={}; version=''; cipher=''
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,body.port),timeout=4) as raw:
            with ctx.wrap_socket(raw,server_hostname=host) as tls:
                verified=True; version=tls.version() or ''; cipher=(tls.cipher() or ('',))[0]; cert=tls.getpeercert() or {}
    except Exception as exc:
        verify_error=f'{type(exc).__name__}: {exc}'[:600]
        try:
            ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            with socket.create_connection((host,body.port),timeout=4) as raw:
                with ctx.wrap_socket(raw,server_hostname=host) as tls:
                    version=tls.version() or ''; cipher=(tls.cipher() or ('',))[0]
        except Exception as exc2: raise HTTPException(502,f'TLS_CONNECT_FAILED:{type(exc2).__name__}')
    return {'host':host,'port':body.port,'verified':verified,'verify_error':verify_error,'tls_version':version,'cipher':cipher,
            'subject':cert.get('subject'),'issuer':cert.get('issuer'),'not_before':cert.get('notBefore'),'not_after':cert.get('notAfter'),
            'elapsed_ms':round((time.monotonic()-started)*1000,1)}


@router.get('/network/posture')
def network_posture(request:Request):
    require_role(request)
    from webapi.platform50 import network_connectivity, network_identity_status
    conn=network_connectivity(force=False); ident=network_identity_status(force=False)
    adapters=conn.get('adapters') or []
    vpn_hints=[]
    for a in adapters:
        text=(str(a.get('name',''))+' '+str(a.get('description',''))).lower()
        if any(k in text for k in ('vpn','wireguard','openvpn','tap','tun','fortinet','anyconnect','globalprotect')):
            vpn_hints.append(a.get('name') or a.get('description'))
    return {'mode':conn.get('mode'),'lan':conn.get('lan'),'wan':conn.get('wan'),'ipv4':ident.get('ipv4'),'network':ident.get('network'),'gateway':ident.get('gateway'),'adapter':ident.get('adapter'),
            'vpn_detected':bool(vpn_hints),'vpn_adapters':vpn_hints,'note':'VPN detection is adapter-name based and is an indicator, not cryptographic proof of tunnel use.'}


@router.get('/network/traffic')
def network_traffic(request:Request):
    require_role(request)
    # Read-only counters only. No packet capture and no payload inspection.
    try:
        import psutil
        total=psutil.net_io_counters()
        per=psutil.net_io_counters(pernic=True)
        adapters=[]
        for name,v in per.items():
            adapters.append({'adapter':name,'bytes_sent':int(v.bytes_sent),'bytes_recv':int(v.bytes_recv),'packets_sent':int(v.packets_sent),'packets_recv':int(v.packets_recv),'errin':int(v.errin),'errout':int(v.errout),'dropin':int(v.dropin),'dropout':int(v.dropout)})
        return {'source':'psutil','bytes_sent':int(total.bytes_sent),'bytes_recv':int(total.bytes_recv),'packets_sent':int(total.packets_sent),'packets_recv':int(total.packets_recv),'adapters':adapters,'captured_payloads':False}
    except Exception:
        if os.name=='nt':
            try:
                r=subprocess.run(['netstat','-e'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,errors='replace',timeout=5)
                text=(r.stdout or '')[:8000]
                nums=[]
                for line in text.splitlines():
                    if 'Bytes' in line:
                        nums=[int(x) for x in re.findall(r'\d+',line)]
                        break
                if len(nums)>=2:
                    return {'source':'netstat -e','bytes_recv':nums[0],'bytes_sent':nums[1],'captured_payloads':False,'raw_included':False}
            except Exception:
                pass
        return {'source':'unavailable','captured_payloads':False,'note':'Install psutil for cross-platform interface counters. Packet payload capture is intentionally not enabled.'}


@router.get('/audit')
def audit(request:Request, limit:int=1000):
    require_role(request,'Admin','Analyst'); ensure_tables(); limit=max(1,min(limit,3000))
    web=_rows('SELECT id,actor,method,path,status,request_id,created_at FROM web_security_log37 ORDER BY id DESC LIMIT ?',(limit,))
    return {'web_security':web,'siem_count':len(_rows('SELECT id FROM siem_events51 LIMIT 5000')),'alerts_open':len(_rows("SELECT id FROM security_alerts51 WHERE status='OPEN' LIMIT 5000"))}


@router.get('/auth/mfa/status')
def mfa_status(request:Request):
    user=require_role(request); security37.ensure_tables()
    with connection() as c:
        row=c.execute('SELECT COALESCE(mfa_enabled,0) mfa_enabled,mfa_updated_at FROM app_users WHERE id=?',(user['id'],)).fetchone()
        policy=c.execute('SELECT mfa_required FROM web_security_policy51 WHERE id=1').fetchone()
    return {'enabled':bool(row['mfa_enabled']) if row else False,'updated_at':row['mfa_updated_at'] if row else None,'required':bool(policy['mfa_required']) if policy else True}


@router.get('/users/security')
def users_security(request:Request):
    require_role(request,'Admin'); security37.ensure_tables()
    return _rows('SELECT id,username,role,enabled,COALESCE(mfa_enabled,0) mfa_enabled,mfa_updated_at FROM app_users ORDER BY username COLLATE NOCASE')


@router.post('/auth/mfa/reset/{user_id}')
def admin_reset_mfa(user_id:int, request:Request):
    actor=require_role(request,'Admin')
    if not security37.reset_mfa(user_id):
        raise HTTPException(404,'User not found')
    return {'ok':True,'user_id':user_id,'note':'MFA reset. The user must enroll again at next login. Existing Web sessions were revoked.','actor':actor['username']}


@router.get('/security-posture')
def security_posture(request:Request):
    require_role(request); ensure_tables()
    https=os.environ.get('NA_COOKIE_SECURE','1')!='0'
    api_secret=bool(os.environ.get('NA_API_SECRET',''))
    vt=bool(os.environ.get('NA_VT_API_KEY',''))
    nvd=bool(os.environ.get('NA_NVD_API_KEY',''))
    with connection() as c:
        users=c.execute('SELECT COUNT(*) FROM app_users WHERE enabled=1').fetchone()[0]
        mfa=c.execute('SELECT COUNT(*) FROM app_users WHERE enabled=1 AND COALESCE(mfa_enabled,0)=1').fetchone()[0]
        argon=c.execute("SELECT COUNT(*) FROM app_users WHERE enabled=1 AND password_hash LIKE '$argon2%'").fetchone()[0]
    checks=[
        {'control':'MFA','status':'PASS' if users and mfa==users else 'WARN','evidence':f'{mfa}/{users} active accounts enrolled'},
        {'control':'Argon2id password hashing','status':'PASS' if users and argon==users else 'WARN','evidence':f'{argon}/{users} active accounts migrated; remaining accounts migrate on successful login/password change'},
        {'control':'Secure cookies / HTTPS mode','status':'PASS' if https else 'WARN','evidence':'NA_COOKIE_SECURE='+('1' if https else '0')},
        {'control':'API request signing secret','status':'PASS' if api_secret else 'WARN','evidence':'NA_API_SECRET '+('configured' if api_secret else 'not configured for optional v1 token API')},
        {'control':'VirusTotal integration','status':'PASS' if vt else 'OPTIONAL','evidence':'API key '+('configured' if vt else 'not configured')},
        {'control':'NVD API key','status':'PASS' if nvd else 'OPTIONAL','evidence':'Lookup works without key at public rate limits; API key is optional'},
        {'control':'Encrypted Secret Vault','status':'PASS','evidence':'Secrets use the existing credential encryption key; reveal requires Admin + current TOTP'},
        {'control':'SOC alert workflow','status':'PASS','evidence':'Open / acknowledged / resolved lifecycle with owner and resolution note'}]
    return {'checks':checks,'principles':['deny-by-default writes','CSRF protection','same-origin enforcement','request size limits','API rate limiting','MFA step-up for secret reveal','no secret values in audit logs']}


# ---- Cybersecurity 5.3: compliance + defensive response orchestration ----
class ComplianceUpdate53(BaseModel):
    status: str = Field(max_length=24)
    evidence: str = Field(default='', max_length=4000)
    owner: str = Field(default='', max_length=120)

class PlaybookCreate53(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    action_type: str = Field(min_length=1, max_length=60)
    target: str = Field(default='', max_length=255)
    note: str = Field(default='', max_length=2000)


def ensure_tables53():
    ensure_tables()
    with connection() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS compliance_controls53(
          id INTEGER PRIMARY KEY AUTOINCREMENT, framework TEXT NOT NULL, control_id TEXT NOT NULL,
          title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'NOT_ASSESSED', evidence TEXT DEFAULT '',
          owner TEXT DEFAULT '', updated_at TEXT NOT NULL, UNIQUE(framework,control_id)
        );
        CREATE TABLE IF NOT EXISTS response_playbooks53(
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, action_type TEXT NOT NULL,
          target TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'PENDING_APPROVAL',
          requested_by TEXT DEFAULT '', approved_by TEXT DEFAULT '', note TEXT DEFAULT '',
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        ''')
        defaults=[
          ('ISO 27001','A.5.15','Access control'),
          ('ISO 27001','A.5.17','Authentication information'),
          ('ISO 27001','A.5.24','Information security incident management planning and preparation'),
          ('ISO 27001','A.8.8','Management of technical vulnerabilities'),
          ('ISO 27001','A.8.15','Logging'),
          ('ISO 27001','A.8.16','Monitoring activities'),
          ('OWASP','A01','Broken Access Control'),
          ('OWASP','A02','Cryptographic Failures'),
          ('OWASP','A05','Security Misconfiguration'),
          ('OWASP','A07','Identification and Authentication Failures'),
          ('OWASP','A09','Security Logging and Monitoring Failures'),
          ('PCI DSS','6.3','Security vulnerabilities are identified and addressed'),
          ('PCI DSS','8.4','Multi-factor authentication is implemented'),
          ('PCI DSS','10.2','Audit logs are implemented to support anomaly detection')]
        now=utcnow()
        for fw,cid,title in defaults:
            c.execute('INSERT OR IGNORE INTO compliance_controls53(framework,control_id,title,updated_at) VALUES(?,?,?,?)',(fw,cid,title,now))
        c.commit()

@router.get('/compliance')
def compliance53(request:Request):
    require_role(request); ensure_tables53()
    rows=_rows('SELECT * FROM compliance_controls53 ORDER BY framework,control_id')
    total=len(rows) or 1
    passed=sum(1 for r in rows if r['status'] in ('PASS','COMPLIANT'))
    failed=sum(1 for r in rows if r['status'] in ('FAIL','NON_COMPLIANT'))
    assessed=sum(1 for r in rows if r['status']!='NOT_ASSESSED')
    return {'summary':{'total':len(rows),'assessed':assessed,'passed':passed,'failed':failed,'coverage_pct':round(assessed*100/total,1)},'controls':rows}

@router.patch('/compliance/{control_id}')
def compliance53_update(control_id:int, body:ComplianceUpdate53, request:Request):
    user=require_role(request,'Admin','Analyst'); ensure_tables53()
    status=body.status.upper()
    allowed={'NOT_ASSESSED','PASS','PARTIAL','FAIL','COMPLIANT','NON_COMPLIANT'}
    if status not in allowed: raise HTTPException(400,'INVALID_COMPLIANCE_STATUS')
    with connection() as c:
        cur=c.execute('UPDATE compliance_controls53 SET status=?,evidence=?,owner=?,updated_at=? WHERE id=?',
                      (status,body.evidence.strip(),(body.owner or user['username']).strip(),utcnow(),control_id))
        c.commit()
        if cur.rowcount==0: raise HTTPException(404,'CONTROL_NOT_FOUND')
    return {'ok':True,'id':control_id,'status':status,'actor':user['username']}

@router.get('/playbooks')
def playbooks53(request:Request, limit:int=500):
    require_role(request); ensure_tables53(); limit=max(1,min(limit,2000))
    return _rows('SELECT * FROM response_playbooks53 ORDER BY id DESC LIMIT ?',(limit,))

@router.post('/playbooks')
def playbook53_create(body:PlaybookCreate53, request:Request):
    user=require_role(request,'Admin','Analyst','Operator'); ensure_tables53()
    action=body.action_type.upper()
    allowed={'COLLECT_EVIDENCE','NOTIFY_OWNER','ISOLATE_DEVICE','DISABLE_ACCOUNT','BLOCK_IOC'}
    if action not in allowed: raise HTTPException(400,'UNSUPPORTED_DEFENSIVE_PLAYBOOK')
    now=utcnow()
    with connection() as c:
        cur=c.execute('INSERT INTO response_playbooks53(name,action_type,target,status,requested_by,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',
                      (body.name.strip(),action,body.target.strip(),'PENDING_APPROVAL',user['username'],body.note.strip(),now,now))
        pid=cur.lastrowid; c.commit()
    return {'ok':True,'id':pid,'status':'PENDING_APPROVAL','executed':False,'note':'Approval workflow only; no remote action is executed automatically.'}

@router.post('/playbooks/{playbook_id}/approve')
def playbook53_approve(playbook_id:int, request:Request):
    user=require_role(request,'Admin'); ensure_tables53()
    with connection() as c:
        row=c.execute('SELECT id,status FROM response_playbooks53 WHERE id=?',(playbook_id,)).fetchone()
        if not row: raise HTTPException(404,'PLAYBOOK_NOT_FOUND')
        if row['status']!='PENDING_APPROVAL': raise HTTPException(409,'PLAYBOOK_NOT_PENDING')
        c.execute("UPDATE response_playbooks53 SET status='APPROVED',approved_by=?,updated_at=? WHERE id=?",(user['username'],utcnow(),playbook_id)); c.commit()
    return {'ok':True,'id':playbook_id,'status':'APPROVED','executed':False,'note':'Approval recorded only; remote action execution remains disabled.'}

@router.post('/playbooks/{playbook_id}/cancel')
def playbook53_cancel(playbook_id:int, request:Request):
    user=require_role(request,'Admin','Analyst'); ensure_tables53()
    with connection() as c:
        row=c.execute('SELECT id,status FROM response_playbooks53 WHERE id=?',(playbook_id,)).fetchone()
        if not row: raise HTTPException(404,'PLAYBOOK_NOT_FOUND')
        c.execute("UPDATE response_playbooks53 SET status='CANCELLED',updated_at=? WHERE id=?",(utcnow(),playbook_id)); c.commit()
    return {'ok':True,'id':playbook_id,'status':'CANCELLED','actor':user['username']}

@router.get('/reports/executive')
def executive_report53(request:Request):
    require_role(request,'Admin','Analyst'); ensure_tables53()
    dash=dashboard(request)
    comp=compliance53(request)
    with connection() as c:
        vault_count=int(c.execute('SELECT COUNT(*) FROM secret_vault52').fetchone()[0])
        playbooks=int(c.execute("SELECT COUNT(*) FROM response_playbooks53 WHERE status='PENDING_APPROVAL'").fetchone()[0])
        resolved=int(c.execute("SELECT COUNT(*) FROM security_alerts51 WHERE status='RESOLVED'").fetchone()[0])
    return {'generated_at':utcnow(),'version':'5.9.2-cybersecurity','security_score':dash['security_score'],
            'assets':dash['assets'],'open_alerts':dash['open_alerts'],'critical_alerts':dash['critical_alerts'],
            'high_alerts':dash['high_alerts'],'vulnerability_findings':dash['vulnerability_findings'],
            'failed_logins_24h':dash['failed_logins_24h'],'open_incidents':dash['open_incidents'],
            'resolved_alerts':resolved,'vault_entries':vault_count,'pending_playbooks':playbooks,
            'compliance':comp['summary'],'top_alerts':dash['alerts'][:10]}
