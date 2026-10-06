import difflib
import sqlite3
from datetime import datetime

from database.db import DB_PATH, init_database, get_connection
from modules.nms_v5 import decrypt_secret
from modules.security_core import get_baseline, posture


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _conn():
    init_database()
    c = get_connection()
    c.execute("""CREATE TABLE IF NOT EXISTS config_audit_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER, device_name TEXT, ip TEXT,
        drift_add INTEGER DEFAULT 0, drift_remove INTEGER DEFAULT 0, high_count INTEGER DEFAULT 0,
        warn_count INTEGER DEFAULT 0, review_count INTEGER DEFAULT 0, pass_count INTEGER DEFAULT 0,
        status TEXT, detail TEXT, created_at TEXT)""")
    c.commit()
    return c


def list_ssh_audit_devices():
    c = _conn()
    try:
        rows = c.execute("""SELECT d.id,d.name,d.ip,d.vendor,d.device_type,cr.id credential_id,
               cr.name credential_name,cr.username,cr.secret_enc,cr.port
            FROM network_devices d
            LEFT JOIN device_credentials dc ON dc.device_id=d.id AND dc.purpose IN ('SSH','Backup')
            LEFT JOIN credentials cr ON cr.id=dc.credential_id AND cr.kind='SSH'
            GROUP BY d.id ORDER BY d.name,d.ip""").fetchall()
        return [dict(r) for r in rows]
    finally:
        c.close()


def _device_and_credential(device_id):
    c = _conn()
    try:
        r = c.execute("""SELECT d.*,cr.id credential_id,cr.name credential_name,cr.username,cr.secret_enc,cr.port credential_port
            FROM network_devices d
            LEFT JOIN device_credentials dc ON dc.device_id=d.id AND dc.purpose IN ('SSH','Backup')
            LEFT JOIN credentials cr ON cr.id=dc.credential_id AND cr.kind='SSH'
            WHERE d.id=? ORDER BY CASE dc.purpose WHEN 'SSH' THEN 0 ELSE 1 END LIMIT 1""",(device_id,)).fetchone()
        if not r: raise ValueError('Không tìm thấy thiết bị.')
        d=dict(r)
        if not d.get('credential_id'): raise ValueError('Thiết bị chưa được gán credential SSH/Backup.')
        return d
    finally:
        c.close()


def fetch_running_config(device_id, command='show running-config'):
    import paramiko
    d=_device_and_credential(device_id)
    from modules.ssh_security import build_strict_ssh_client
    cli=build_strict_ssh_client(paramiko)
    try:
        cli.connect(d['ip'],port=int(d.get('credential_port') or 22),username=d.get('username') or '',
                    password=decrypt_secret(d['secret_enc']),timeout=10,look_for_keys=False,allow_agent=False)
        _stdin,stdout,stderr=cli.exec_command(command or 'show running-config',timeout=35)
        data=stdout.read().decode(errors='replace'); err=stderr.read().decode(errors='replace')
        if not data.strip(): raise RuntimeError(err.strip() or 'Thiết bị không trả về running-config.')
        return d,data
    finally:
        cli.close()


def _open_alert(ip, alert_type, message, severity):
    c=_conn()
    try:
        old=c.execute("SELECT id FROM alerts WHERE ip=? AND alert_type=? AND message=? AND LOWER(COALESCE(status,''))<>'closed' LIMIT 1",(ip,alert_type,message)).fetchone()
        if not old:
            c.execute("INSERT INTO alerts(ip,alert_type,message,created_at,status,severity) VALUES(?,?,?,?,?,?)",(ip,alert_type,message,_now(),'Open',severity))
            c.commit()
            return True
        return False
    finally:c.close()


def audit_device(device_id, command='show running-config', create_alerts=True):
    d,cfg=fetch_running_config(device_id,command)
    name=(d.get('name') or d.get('ip') or str(device_id)).strip()
    b=get_baseline(name)
    adds=removes=0; diff=[]
    if b:
        diff=list(difflib.unified_diff(b['config'].splitlines(),cfg.splitlines(),fromfile='BASELINE',tofile='CURRENT',lineterm=''))
        adds=sum(1 for x in diff if x.startswith('+') and not x.startswith('+++'))
        removes=sum(1 for x in diff if x.startswith('-') and not x.startswith('---'))
    rows=posture(cfg); counts={k:sum(r['status']==k for r in rows) for k in ('HIGH','WARN','REVIEW','PASS')}
    status='HIGH' if counts['HIGH'] else ('WARN' if (adds or removes or counts['WARN']) else ('REVIEW' if counts['REVIEW'] else 'PASS'))
    detail=f"Drift +{adds}/-{removes}; HIGH {counts['HIGH']} WARN {counts['WARN']} REVIEW {counts['REVIEW']} PASS {counts['PASS']}"
    c=_conn()
    try:
        c.execute("""INSERT INTO config_audit_history(device_id,device_name,ip,drift_add,drift_remove,high_count,warn_count,review_count,pass_count,status,detail,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (device_id,name,d['ip'],adds,removes,counts['HIGH'],counts['WARN'],counts['REVIEW'],counts['PASS'],status,detail,_now()))
        c.commit()
    finally:c.close()
    if create_alerts:
        if adds or removes:
            msg=f'{name}: configuration drift +{adds}/-{removes}'
            if _open_alert(d['ip'],'Configuration Drift',msg,'Warning'):
                try:
                    from modules.advanced_pages import notify_alert
                    notify_alert(d['ip'],'Configuration Drift',msg,'Warning',event_key=f'drift|{d["ip"]}|{adds}|{removes}')
                except Exception: pass
        if counts['HIGH']:
            failed=', '.join(r['control'] for r in rows if r['status']=='HIGH')
            msg=f'{name}: {counts["HIGH"]} HIGH - {failed}'
            if _open_alert(d['ip'],'Security Posture',msg,'Critical'):
                try:
                    from modules.advanced_pages import notify_alert
                    notify_alert(d['ip'],'Security Posture',msg,'Critical',event_key=f'security|{d["ip"]}|{failed}')
                except Exception: pass
    return {'device':d,'config':cfg,'baseline':b,'diff':diff,'counts':counts,'rows':rows,'status':status,'detail':detail}
