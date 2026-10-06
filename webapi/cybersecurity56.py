"""Cybersecurity 5.8 notification delivery visibility and security reporting.

This module reuses the application's existing encrypted notification settings.
It never returns notification secrets to the browser. External notification tests
and alert dispatches are explicit operator actions; normal HIGH/CRITICAL SOC alerts
continue to use the existing background notifier from v5.1.
"""
from __future__ import annotations

import csv
import io
import json
import time
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from webapi.runtime37 import connection, utcnow
from webapi.security37 import require_role
from webapi.cybersecurity55 import ensure_tables55

router = APIRouter(prefix='/api/v56', tags=['Cybersecurity 5.7'])


class NotifyTestIn(BaseModel):
    channel: str = Field(pattern='^(EMAIL|TELEGRAM)$')
    confirm_external: bool = False


class AlertDispatchIn(BaseModel):
    confirm_external: bool = False


def ensure_tables56() -> None:
    ensure_tables55()
    with connection() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS security_report_snapshots56(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          created_by TEXT NOT NULL,
          created_at TEXT NOT NULL,
          payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_security_report56_time
          ON security_report_snapshots56(created_at DESC);
        """)
        c.commit()


def _count(c, sql: str, args=()) -> int:
    try:
        row = c.execute(sql, args).fetchone()
        return int(row[0] if row is not None else 0)
    except Exception:
        return 0


def _notification_status() -> dict:
    # Existing notification config is stored by the desktop/shared engine. Importing
    # get_setting is safe; secret values are deliberately never exposed here.
    try:
        from modules.advanced_pages import get_setting
        enabled = get_setting('notify_enabled', '0') == '1'
        email_enabled = get_setting('notify_email', '0') == '1'
        telegram_enabled = get_setting('notify_telegram', '1') == '1'
        host = bool(get_setting('smtp_host', '').strip())
        recipient = bool(get_setting('smtp_to', '').strip())
        chat = bool(get_setting('telegram_chat_id', '').strip())
        # Encrypted secret presence only; never decrypt for a status read.
        smtp_secret = bool(get_setting('smtp_password_enc', '').strip())
        tg_secret = bool(get_setting('telegram_token_enc', '').strip())
        cooldown = int(get_setting('notify_cooldown_min', '60') or 60)
        return {
            'enabled': enabled,
            'email_enabled': email_enabled,
            'email_ready': bool(email_enabled and host and recipient),
            'smtp_secret_present': smtp_secret,
            'telegram_enabled': telegram_enabled,
            'telegram_ready': bool(telegram_enabled and chat and tg_secret),
            'telegram_secret_present': tg_secret,
            'cooldown_min': max(0, cooldown),
            'security_events_enabled': get_setting('notify_security', '1') == '1',
        }
    except Exception as exc:
        return {'enabled': False, 'email_enabled': False, 'email_ready': False,
                'smtp_secret_present': False, 'telegram_enabled': False,
                'telegram_ready': False, 'telegram_secret_present': False,
                'cooldown_min': 60, 'security_events_enabled': False,
                'error': type(exc).__name__}


def _report_payload() -> dict:
    ensure_tables56()
    now = utcnow()
    with connection() as c:
        critical = _count(c, "SELECT COUNT(*) FROM security_alerts51 WHERE status!='RESOLVED' AND severity='CRITICAL'")
        high = _count(c, "SELECT COUNT(*) FROM security_alerts51 WHERE status!='RESOLVED' AND severity='HIGH'")
        medium = _count(c, "SELECT COUNT(*) FROM security_alerts51 WHERE status!='RESOLVED' AND severity='MEDIUM'")
        findings = _count(c, "SELECT COUNT(*) FROM vulnerability_findings51")
        open_cases = _count(c, "SELECT COUNT(*) FROM soc_cases55 WHERE status NOT IN ('RESOLVED','CLOSED')")
        breached = 0
        try:
            rows = c.execute("SELECT due_at,status FROM soc_cases55 WHERE status NOT IN ('RESOLVED','CLOSED') AND due_at IS NOT NULL").fetchall()
            now_dt = datetime.now(timezone.utc)
            for r in rows:
                try:
                    d = datetime.fromisoformat(r['due_at'])
                    if d.tzinfo is None:
                        d = d.replace(tzinfo=timezone.utc)
                    if now_dt > d:
                        breached += 1
                except Exception:
                    pass
        except Exception:
            pass
        assets = max(_count(c, 'SELECT COUNT(*) FROM ip_mac_inventory'), _count(c, 'SELECT COUNT(*) FROM security_assets'))
        iocs = _count(c, 'SELECT COUNT(*) FROM threat_iocs54 WHERE enabled=1')
        rules = _count(c, 'SELECT COUNT(*) FROM detection_rules54 WHERE enabled=1')
        score = max(0, 100 - min(100, critical*35 + high*15 + medium*5 + min(25, findings) + min(20, breached*5)))
        top = []
        try:
            top = [dict(r) for r in c.execute("""
                SELECT id,severity,title,asset_ip,status,owner,count,last_seen
                FROM security_alerts51
                WHERE status!='RESOLVED'
                ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
                         last_seen DESC LIMIT 20
            """).fetchall()]
        except Exception:
            pass
    return {
        'version': '5.9.2-cybersecurity', 'generated_at': now,
        'security_score': score, 'assets': assets,
        'critical_alerts': critical, 'high_alerts': high, 'medium_alerts': medium,
        'vulnerability_findings': findings, 'open_cases': open_cases,
        'sla_breached_cases': breached, 'active_iocs': iocs,
        'active_detection_rules': rules, 'notification': _notification_status(),
        'top_alerts': top,
    }


@router.get('/notifications/status')
def notifications_status(request: Request):
    require_role(request)
    ensure_tables56()
    status = _notification_status()
    with connection() as c:
        try:
            status['sent_24h'] = _count(c, "SELECT COUNT(*) FROM notification_log WHERE status='SENT' AND created_at>=datetime('now','-1 day')")
            status['failed_24h'] = _count(c, "SELECT COUNT(*) FROM notification_log WHERE status='FAILED' AND created_at>=datetime('now','-1 day')")
        except Exception:
            status['sent_24h'] = 0
            status['failed_24h'] = 0
    return status


@router.get('/notifications/logs')
def notification_logs(request: Request, limit: int = 300):
    require_role(request)
    ensure_tables56()
    limit = max(1, min(int(limit), 2000))
    with connection() as c:
        try:
            return [dict(r) for r in c.execute(
                'SELECT id,event_key,channel,status,detail,created_at FROM notification_log ORDER BY id DESC LIMIT ?',
                (limit,)).fetchall()]
        except Exception:
            return []


@router.post('/notifications/test')
def notification_test(body: NotifyTestIn, request: Request):
    user = require_role(request, 'Admin')
    ensure_tables56()
    if not body.confirm_external:
        raise HTTPException(400, 'EXTERNAL_SEND_CONFIRMATION_REQUIRED')
    try:
        from modules.advanced_pages import (
            get_setting, _load_secret, send_email, send_telegram, _log_notification
        )
        key = f'cyber56:test:{body.channel}:{int(time.time())}'
        if body.channel == 'EMAIL':
            host = get_setting('smtp_host', '').strip(); to = get_setting('smtp_to', '').strip()
            if not host or not to:
                raise HTTPException(409, 'EMAIL_NOT_CONFIGURED')
            password = _load_secret('smtp_password_enc')
            send_email(host, get_setting('smtp_port', '587'), get_setting('smtp_user', ''), password,
                       to, 'NetworkAutomation Cybersecurity test',
                       f'Cybersecurity 5.8 notification test by {user["username"]}.')
            _log_notification(key, 'Email', 'SENT', 'Manual Cybersecurity 5.8 test')
        else:
            token = _load_secret('telegram_token_enc'); chat = get_setting('telegram_chat_id', '').strip()
            if not token or not chat:
                raise HTTPException(409, 'TELEGRAM_NOT_CONFIGURED')
            send_telegram(token, chat, f'NetworkAutomation Cybersecurity 5.8 test by {user["username"]}.')
            _log_notification(key, 'Telegram', 'SENT', 'Manual Cybersecurity 5.8 test')
        return {'ok': True, 'channel': body.channel, 'actor': user['username']}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f'NOTIFICATION_SEND_FAILED:{type(exc).__name__}') from exc


@router.post('/alerts/{alert_id}/notify')
def alert_notify(alert_id: int, body: AlertDispatchIn, request: Request):
    user = require_role(request, 'Admin', 'Analyst')
    ensure_tables56()
    if not body.confirm_external:
        raise HTTPException(400, 'EXTERNAL_SEND_CONFIRMATION_REQUIRED')
    with connection() as c:
        row = c.execute('SELECT * FROM security_alerts51 WHERE id=?', (alert_id,)).fetchone()
    if not row:
        raise HTTPException(404, 'ALERT_NOT_FOUND')
    alert = dict(row)
    try:
        from modules.advanced_pages import notify_alert
        results = notify_alert(alert.get('asset_ip') or 'application', 'Cybersecurity',
                               alert.get('title') or 'Security alert', severity=alert.get('severity') or 'Warning',
                               event_key=f'cyber56:alert:{alert_id}:{alert.get("last_seen") or ""}')
        return {'ok': True, 'alert_id': alert_id, 'actor': user['username'], 'results': results}
    except Exception as exc:
        raise HTTPException(502, f'NOTIFICATION_SEND_FAILED:{type(exc).__name__}') from exc


@router.post('/reports/snapshots')
def create_report_snapshot(request: Request):
    user = require_role(request, 'Admin', 'Analyst')
    ensure_tables56()
    payload = _report_payload()
    name = 'Security snapshot ' + datetime.now().strftime('%Y-%m-%d %H:%M')
    with connection() as c:
        cur = c.execute('INSERT INTO security_report_snapshots56(name,created_by,created_at,payload_json) VALUES(?,?,?,?)',
                        (name, user['username'], utcnow(), json.dumps(payload, ensure_ascii=False, separators=(',', ':'))))
        c.commit()
        rid = int(cur.lastrowid)
    return {'ok': True, 'id': rid, 'name': name, 'payload': payload}


@router.get('/reports/snapshots')
def list_report_snapshots(request: Request, limit: int = 100):
    require_role(request)
    ensure_tables56()
    limit = max(1, min(int(limit), 1000))
    with connection() as c:
        rows = c.execute('SELECT id,name,created_by,created_at,payload_json FROM security_report_snapshots56 ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
    out = []
    for row in rows:
        d = dict(row)
        try:
            p = json.loads(d.pop('payload_json'))
        except Exception:
            p = {}
            d.pop('payload_json', None)
        d.update({k: p.get(k) for k in ('security_score','critical_alerts','high_alerts','vulnerability_findings','open_cases','sla_breached_cases')})
        out.append(d)
    return out


@router.get('/reports/snapshots/{report_id}')
def get_report_snapshot(report_id: int, request: Request):
    require_role(request)
    ensure_tables56()
    with connection() as c:
        row = c.execute('SELECT * FROM security_report_snapshots56 WHERE id=?', (report_id,)).fetchone()
    if not row:
        raise HTTPException(404, 'REPORT_NOT_FOUND')
    d = dict(row)
    d['payload'] = json.loads(d.pop('payload_json'))
    return d


@router.get('/reports/snapshots/{report_id}/csv')
def export_report_snapshot_csv(report_id: int, request: Request):
    require_role(request)
    ensure_tables56()
    with connection() as c:
        row = c.execute('SELECT * FROM security_report_snapshots56 WHERE id=?', (report_id,)).fetchone()
    if not row:
        raise HTTPException(404, 'REPORT_NOT_FOUND')
    payload = json.loads(row['payload_json'])
    buf = io.StringIO(newline='')
    w = csv.writer(buf)
    w.writerow(['metric', 'value'])
    for key in ('version','generated_at','security_score','assets','critical_alerts','high_alerts','medium_alerts',
                'vulnerability_findings','open_cases','sla_breached_cases','active_iocs','active_detection_rules'):
        w.writerow([key, payload.get(key, '')])
    w.writerow([]); w.writerow(['top_alert_id','severity','title','asset_ip','status','owner','count','last_seen'])
    for a in payload.get('top_alerts') or []:
        w.writerow([a.get('id',''),a.get('severity',''),a.get('title',''),a.get('asset_ip',''),a.get('status',''),a.get('owner',''),a.get('count',''),a.get('last_seen','')])
    return PlainTextResponse(buf.getvalue(), media_type='text/csv; charset=utf-8',
                             headers={'Content-Disposition': f'attachment; filename="security_snapshot_{report_id}.csv"'})


@router.get('/summary')
def summary(request: Request):
    require_role(request)
    ensure_tables56()
    return _report_payload()
