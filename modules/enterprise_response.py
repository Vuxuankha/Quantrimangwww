"""Enterprise incident, vulnerability, patch and compliance management.

Defensive-only module. It records findings and approval-gated response playbooks;
it does not exploit targets or execute isolation/account-lock actions remotely.
"""
from __future__ import annotations
import hashlib, json
from datetime import datetime
from database.db import get_connection, init_database

SEV_POINTS={"INFO":0,"LOW":5,"MEDIUM":15,"HIGH":30,"CRITICAL":50}

def _now(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def _connect(): init_database(); return get_connection()

def ensure_response_tables():
    c=_connect()
    try:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS security_incidents(
          id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, severity TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'OPEN', owner TEXT DEFAULT '', summary TEXT DEFAULT '',
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL, closed_at TEXT);
        CREATE TABLE IF NOT EXISTS incident_events(
          incident_id INTEGER NOT NULL, event_id INTEGER NOT NULL, added_at TEXT NOT NULL,
          UNIQUE(incident_id,event_id));
        CREATE TABLE IF NOT EXISTS response_playbooks(
          id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER, name TEXT NOT NULL,
          action_type TEXT NOT NULL, target TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'PENDING_APPROVAL',
          requested_by TEXT DEFAULT '', approved_by TEXT DEFAULT '', notes TEXT DEFAULT '',
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS vulnerabilities(
          id INTEGER PRIMARY KEY AUTOINCREMENT, asset_ip TEXT NOT NULL, cve_id TEXT NOT NULL,
          product TEXT DEFAULT '', installed_version TEXT DEFAULT '', fixed_version TEXT DEFAULT '',
          cvss REAL DEFAULT 0, kev INTEGER NOT NULL DEFAULT 0, severity TEXT NOT NULL DEFAULT 'MEDIUM',
          status TEXT NOT NULL DEFAULT 'OPEN', source TEXT DEFAULT 'MANUAL', notes TEXT DEFAULT '',
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(asset_ip,cve_id,product));
        CREATE TABLE IF NOT EXISTS patch_records(
          id INTEGER PRIMARY KEY AUTOINCREMENT, asset_ip TEXT NOT NULL, cve_id TEXT DEFAULT '',
          patch_name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING', due_date TEXT DEFAULT '',
          installed_at TEXT, owner TEXT DEFAULT '', notes TEXT DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS compliance_controls(
          id INTEGER PRIMARY KEY AUTOINCREMENT, framework TEXT NOT NULL, control_id TEXT NOT NULL,
          title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'NOT_ASSESSED', evidence TEXT DEFAULT '',
          owner TEXT DEFAULT '', updated_at TEXT NOT NULL, UNIQUE(framework,control_id));
        CREATE TABLE IF NOT EXISTS security_audit_trail(
          id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT DEFAULT '', action TEXT NOT NULL,
          object_type TEXT NOT NULL, object_id TEXT DEFAULT '', detail TEXT DEFAULT '', created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_vuln_asset ON vulnerabilities(asset_ip,status,severity);
        CREATE INDEX IF NOT EXISTS idx_incident_status ON security_incidents(status,severity);
        ''')
        defaults=[
          ('ISO 27001','A.5.24','Information security incident management planning and preparation'),
          ('ISO 27001','A.8.8','Management of technical vulnerabilities'),
          ('ISO 27001','A.8.15','Logging'),('ISO 27001','A.8.16','Monitoring activities'),
          ('OWASP','A01','Broken Access Control'),('OWASP','A02','Cryptographic Failures'),
          ('OWASP','A05','Security Misconfiguration'),('OWASP','A09','Security Logging and Monitoring Failures'),
          ('PCI DSS','6.3','Security vulnerabilities are identified and addressed'),
          ('PCI DSS','10.2','Audit logs are implemented to support anomaly detection')]
        for fw,cid,title in defaults:
            c.execute("INSERT OR IGNORE INTO compliance_controls(framework,control_id,title,updated_at) VALUES(?,?,?,?)",(fw,cid,title,_now()))
        c.commit()
    finally: c.close()

def audit(actor,action,obj_type,obj_id='',detail=''):
    ensure_response_tables(); c=_connect()
    try:
        c.execute("INSERT INTO security_audit_trail(actor,action,object_type,object_id,detail,created_at) VALUES(?,?,?,?,?,?)",(actor,action,obj_type,str(obj_id),detail[:4000],_now())); c.commit()
    finally:c.close()

def create_incident(title,severity='MEDIUM',summary='',owner='',actor='system'):
    severity=severity.upper()
    if severity not in SEV_POINTS: raise ValueError('Invalid severity')
    ensure_response_tables(); c=_connect()
    try:
        cur=c.execute("INSERT INTO security_incidents(title,severity,owner,summary,created_at,updated_at) VALUES(?,?,?,?,?,?)",(title[:180],severity,owner[:100],summary[:4000],_now(),_now())); iid=cur.lastrowid;c.commit()
    finally:c.close()
    audit(actor,'CREATE','INCIDENT',iid,title); return iid

def create_incident_from_event(event_id,actor='system'):
    ensure_response_tables(); c=_connect()
    try:
        e=c.execute("SELECT * FROM security_events WHERE id=?",(int(event_id),)).fetchone()
        if not e: raise ValueError('Security event not found')
        cur=c.execute("INSERT INTO security_incidents(title,severity,summary,created_at,updated_at) VALUES(?,?,?,?,?)",(e['title'],e['severity'],e['detail'] or '',_now(),_now())); iid=cur.lastrowid
        c.execute("INSERT OR IGNORE INTO incident_events(incident_id,event_id,added_at) VALUES(?,?,?)",(iid,int(event_id),_now())); c.commit()
    finally:c.close()
    audit(actor,'CREATE_FROM_EVENT','INCIDENT',iid,f'event={event_id}'); return iid

def request_playbook(incident_id,name,action_type,target='',actor='system',notes=''):
    allowed={'ISOLATE_DEVICE','DISABLE_ACCOUNT','BLOCK_IOC','COLLECT_EVIDENCE','NOTIFY_OWNER'}
    if action_type not in allowed: raise ValueError('Unsupported defensive playbook action')
    ensure_response_tables(); c=_connect()
    try:
        cur=c.execute("INSERT INTO response_playbooks(incident_id,name,action_type,target,status,requested_by,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",(int(incident_id),name[:120],action_type,target[:255],'PENDING_APPROVAL',actor,notes[:2000],_now(),_now())); pid=cur.lastrowid;c.commit()
    finally:c.close()
    audit(actor,'REQUEST','PLAYBOOK',pid,action_type); return pid

def approve_playbook(playbook_id,actor,role):
    if role not in ('Admin','Administrator'): raise PermissionError('Only Admin may approve response playbooks')
    c=_connect()
    try:
        c.execute("UPDATE response_playbooks SET status='APPROVED',approved_by=?,updated_at=? WHERE id=? AND status='PENDING_APPROVAL'",(actor,_now(),int(playbook_id))); c.commit()
    finally:c.close()
    audit(actor,'APPROVE','PLAYBOOK',playbook_id,'Approval only; no remote action executed')

def upsert_vulnerability(asset_ip,cve_id,product='',installed_version='',fixed_version='',cvss=0,kev=False,severity='MEDIUM',source='MANUAL',notes='',actor='system'):
    ensure_response_tables(); c=_connect()
    try:
        if not c.execute("SELECT 1 FROM security_assets WHERE ip=?",(asset_ip,)).fetchone(): raise ValueError('Asset must be registered first')
        c.execute('''INSERT INTO vulnerabilities(asset_ip,cve_id,product,installed_version,fixed_version,cvss,kev,severity,status,source,notes,created_at,updated_at)
        VALUES(?,?,?,?,?,?,?,?, 'OPEN',?,?,?,?) ON CONFLICT(asset_ip,cve_id,product) DO UPDATE SET installed_version=excluded.installed_version,fixed_version=excluded.fixed_version,cvss=excluded.cvss,kev=excluded.kev,severity=excluded.severity,source=excluded.source,notes=excluded.notes,updated_at=excluded.updated_at''',(asset_ip,cve_id.upper()[:32],product[:180],installed_version[:80],fixed_version[:80],float(cvss),1 if kev else 0,severity.upper(),source[:80],notes[:2000],_now(),_now()));c.commit()
    finally:c.close()
    audit(actor,'UPSERT','VULNERABILITY',f'{asset_ip}:{cve_id}',source)

def security_score():
    ensure_response_tables(); c=_connect()
    try:
        open_events=c.execute("SELECT severity,COUNT(*) n FROM security_events WHERE status='OPEN' GROUP BY severity").fetchall()
        vulns=c.execute("SELECT severity,kev,COUNT(*) n FROM vulnerabilities WHERE status='OPEN' GROUP BY severity,kev").fetchall()
        controls=c.execute("SELECT status,COUNT(*) n FROM compliance_controls GROUP BY status").fetchall()
    finally:c.close()
    penalty=sum(SEV_POINTS.get(r['severity'],0)*r['n'] for r in open_events)
    penalty+=sum((SEV_POINTS.get(r['severity'],0)+(20 if r['kev'] else 0))*r['n'] for r in vulns)
    score=max(0,100-min(100,penalty))
    cs={r['status']:r['n'] for r in controls}; total=sum(cs.values()) or 1
    assessed=sum(v for k,v in cs.items() if k in ('PASS','COMPLIANT','PARTIAL','FAIL','NON_COMPLIANT'))
    return {'security_score':score,'open_event_penalty':sum(SEV_POINTS.get(r['severity'],0)*r['n'] for r in open_events),'open_vulnerabilities':sum(r['n'] for r in vulns),'kev_open':sum(r['n'] for r in vulns if r['kev']),'compliance_assessed_pct':round(assessed*100/total,1)}

__all__=['ensure_response_tables','audit','create_incident','create_incident_from_event','request_playbook','approve_playbook','upsert_vulnerability','security_score']
