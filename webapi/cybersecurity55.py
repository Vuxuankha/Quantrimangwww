"""Cybersecurity 5.5 enterprise case management and asset risk.

Defensive-only features: local SOC cases, evidence notes, alert linking, and
read-only risk scoring from data already collected by NetworkAutomation.
No exploitation, credential testing, or automatic remote containment is done here.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from webapi.runtime37 import connection, utcnow
from webapi.security37 import require_role
from webapi.cybersecurity54 import ensure_tables54

router = APIRouter(prefix='/api/v55', tags=['Cybersecurity 5.5'])

PRIORITIES = {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}
STATUSES = {'OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED'}
DEFAULT_DUE_HOURS = {'CRITICAL': 4, 'HIGH': 24, 'MEDIUM': 72, 'LOW': 168}


class CaseCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    priority: str = Field(default='MEDIUM', max_length=16)
    owner: str = Field(default='', max_length=120)
    asset_ip: str = Field(default='', max_length=64)
    summary: str = Field(default='', max_length=4000)
    due_hours: int | None = Field(default=None, ge=1, le=24 * 90)
    alert_id: int | None = Field(default=None, ge=1)


class CaseUpdate(BaseModel):
    status: str | None = Field(default=None, max_length=24)
    priority: str | None = Field(default=None, max_length=16)
    owner: str | None = Field(default=None, max_length=120)
    summary: str | None = Field(default=None, max_length=4000)
    due_hours: int | None = Field(default=None, ge=1, le=24 * 90)


class CaseNote(BaseModel):
    note: str = Field(min_length=1, max_length=8000)
    evidence_ref: str = Field(default='', max_length=500)


class AlertLink(BaseModel):
    alert_id: int = Field(ge=1)


def ensure_tables55() -> None:
    ensure_tables54()
    with connection() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS soc_cases55(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL,
          priority TEXT NOT NULL DEFAULT 'MEDIUM',
          status TEXT NOT NULL DEFAULT 'OPEN',
          owner TEXT DEFAULT '',
          asset_ip TEXT DEFAULT '',
          summary TEXT DEFAULT '',
          opened_by TEXT DEFAULT '',
          opened_at TEXT NOT NULL,
          due_at TEXT DEFAULT NULL,
          resolved_at TEXT DEFAULT NULL,
          closed_at TEXT DEFAULT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_cases55_status
          ON soc_cases55(status, priority, updated_at DESC);
        CREATE INDEX IF NOT EXISTS ix_cases55_asset
          ON soc_cases55(asset_ip, status);

        CREATE TABLE IF NOT EXISTS soc_case_notes55(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          case_id INTEGER NOT NULL,
          actor TEXT NOT NULL,
          note TEXT NOT NULL,
          evidence_ref TEXT DEFAULT '',
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_case_notes55_case
          ON soc_case_notes55(case_id, id DESC);

        CREATE TABLE IF NOT EXISTS soc_case_alerts55(
          case_id INTEGER NOT NULL,
          alert_id INTEGER NOT NULL,
          linked_by TEXT DEFAULT '',
          linked_at TEXT NOT NULL,
          PRIMARY KEY(case_id, alert_id)
        );
        """)
        c.commit()


def _row(sql: str, args=()):
    with connection() as c:
        r = c.execute(sql, args).fetchone()
        return dict(r) if r else None


def _rows(sql: str, args=()):
    with connection() as c:
        return [dict(r) for r in c.execute(sql, args).fetchall()]


def _priority(value: str) -> str:
    v = str(value or '').upper().strip()
    if v not in PRIORITIES:
        raise HTTPException(400, 'INVALID_PRIORITY')
    return v


def _status(value: str) -> str:
    v = str(value or '').upper().strip()
    if v not in STATUSES:
        raise HTTPException(400, 'INVALID_CASE_STATUS')
    return v


def _due_at(priority: str, due_hours: int | None) -> str:
    hours = int(due_hours or DEFAULT_DUE_HOURS[priority])
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat(timespec='seconds')


def _case_or_404(case_id: int) -> dict:
    row = _row('SELECT * FROM soc_cases55 WHERE id=?', (case_id,))
    if not row:
        raise HTTPException(404, 'CASE_NOT_FOUND')
    return row


def _alert_exists(alert_id: int) -> bool:
    return bool(_row('SELECT id FROM security_alerts51 WHERE id=?', (alert_id,)))


@router.get('/cases')
def cases(request: Request, status: str='ALL', limit: int=500):
    require_role(request)
    ensure_tables55()
    limit = max(1, min(int(limit), 2000))
    if status.upper() == 'ALL':
        rows = _rows('SELECT * FROM soc_cases55 ORDER BY id DESC LIMIT ?', (limit,))
    else:
        rows = _rows('SELECT * FROM soc_cases55 WHERE status=? ORDER BY id DESC LIMIT ?', (_status(status), limit))
    now = datetime.now(timezone.utc)
    for row in rows:
        due = None
        try:
            due = datetime.fromisoformat(row['due_at']) if row.get('due_at') else None
            if due and due.tzinfo is None:
                due = due.replace(tzinfo=timezone.utc)
        except Exception:
            due = None
        row['sla_breached'] = bool(due and row['status'] not in {'RESOLVED','CLOSED'} and now > due)
        row['linked_alerts'] = int(_row('SELECT COUNT(*) n FROM soc_case_alerts55 WHERE case_id=?', (row['id'],))['n'])
    return rows


@router.get('/cases/{case_id}')
def case_detail(case_id: int, request: Request):
    require_role(request)
    ensure_tables55()
    case = _case_or_404(case_id)
    case['notes'] = _rows('SELECT * FROM soc_case_notes55 WHERE case_id=? ORDER BY id DESC LIMIT 500', (case_id,))
    case['alerts'] = _rows('''SELECT a.id,a.rule_key,a.title,a.severity,a.asset_ip,a.subject_user,a.status,a.owner,a.count,a.first_seen,a.last_seen,
                                     l.linked_by,l.linked_at
                              FROM soc_case_alerts55 l JOIN security_alerts51 a ON a.id=l.alert_id
                              WHERE l.case_id=? ORDER BY a.id DESC''', (case_id,))
    return case


@router.post('/cases')
def case_create(body: CaseCreate, request: Request):
    user = require_role(request, 'Admin', 'Analyst')
    ensure_tables55()
    priority = _priority(body.priority)
    now = utcnow()
    owner = (body.owner or user['username']).strip()
    with connection() as c:
        cur = c.execute('''INSERT INTO soc_cases55(title,priority,status,owner,asset_ip,summary,opened_by,opened_at,due_at,updated_at)
                           VALUES(?,?,?,?,?,?,?,?,?,?)''',
                        (body.title.strip(), priority, 'OPEN', owner, body.asset_ip.strip(), body.summary.strip(),
                         user['username'], now, _due_at(priority, body.due_hours), now))
        case_id = int(cur.lastrowid)
        if body.alert_id is not None:
            if not c.execute('SELECT 1 FROM security_alerts51 WHERE id=?', (body.alert_id,)).fetchone():
                raise HTTPException(404, 'ALERT_NOT_FOUND')
            c.execute('INSERT OR IGNORE INTO soc_case_alerts55(case_id,alert_id,linked_by,linked_at) VALUES(?,?,?,?)',
                      (case_id, body.alert_id, user['username'], now))
        c.commit()
    return {'ok': True, 'id': case_id, 'status': 'OPEN', 'priority': priority, 'owner': owner}


@router.patch('/cases/{case_id}')
def case_update(case_id: int, body: CaseUpdate, request: Request):
    user = require_role(request, 'Admin', 'Analyst')
    ensure_tables55()
    current = _case_or_404(case_id)
    status = _status(body.status) if body.status is not None else current['status']
    priority = _priority(body.priority) if body.priority is not None else current['priority']
    owner = body.owner.strip() if body.owner is not None else current['owner']
    summary = body.summary.strip() if body.summary is not None else current['summary']
    due_at = _due_at(priority, body.due_hours) if body.due_hours is not None else current['due_at']
    now = utcnow()
    resolved_at = current['resolved_at']
    closed_at = current['closed_at']
    if status == 'RESOLVED' and current['status'] != 'RESOLVED':
        resolved_at = now
    if status == 'CLOSED' and current['status'] != 'CLOSED':
        closed_at = now
    if status not in {'RESOLVED','CLOSED'}:
        closed_at = None
    with connection() as c:
        c.execute('''UPDATE soc_cases55 SET status=?,priority=?,owner=?,summary=?,due_at=?,resolved_at=?,closed_at=?,updated_at=? WHERE id=?''',
                  (status, priority, owner, summary, due_at, resolved_at, closed_at, now, case_id))
        c.execute('INSERT INTO soc_case_notes55(case_id,actor,note,evidence_ref,created_at) VALUES(?,?,?,?,?)',
                  (case_id, user['username'], f'Case updated: status={status}, priority={priority}, owner={owner}', '', now))
        c.commit()
    return {'ok': True, 'id': case_id, 'status': status, 'priority': priority, 'owner': owner}


@router.post('/cases/{case_id}/notes')
def case_note(case_id: int, body: CaseNote, request: Request):
    user = require_role(request, 'Admin', 'Analyst', 'Operator')
    ensure_tables55()
    _case_or_404(case_id)
    with connection() as c:
        c.execute('INSERT INTO soc_case_notes55(case_id,actor,note,evidence_ref,created_at) VALUES(?,?,?,?,?)',
                  (case_id, user['username'], body.note.strip(), body.evidence_ref.strip(), utcnow()))
        c.execute('UPDATE soc_cases55 SET updated_at=? WHERE id=?', (utcnow(), case_id))
        c.commit()
    return {'ok': True, 'case_id': case_id}


@router.post('/cases/{case_id}/alerts')
def case_link_alert(case_id: int, body: AlertLink, request: Request):
    user = require_role(request, 'Admin', 'Analyst', 'Operator')
    ensure_tables55()
    _case_or_404(case_id)
    if not _alert_exists(body.alert_id):
        raise HTTPException(404, 'ALERT_NOT_FOUND')
    now = utcnow()
    with connection() as c:
        c.execute('INSERT OR IGNORE INTO soc_case_alerts55(case_id,alert_id,linked_by,linked_at) VALUES(?,?,?,?)',
                  (case_id, body.alert_id, user['username'], now))
        c.execute('UPDATE soc_cases55 SET updated_at=? WHERE id=?', (now, case_id))
        c.commit()
    return {'ok': True, 'case_id': case_id, 'alert_id': body.alert_id}


@router.get('/risk/assets')
def asset_risk(request: Request, limit: int=1000):
    require_role(request)
    ensure_tables55()
    limit = max(1, min(int(limit), 3000))
    ips = set()
    with connection() as c:
        for table in ('ip_mac_inventory', 'security_assets'):
            try:
                for r in c.execute(f'SELECT ip FROM {table} WHERE ip IS NOT NULL AND ip<>\'\' LIMIT ?', (limit,)).fetchall():
                    ips.add(str(r['ip']))
            except Exception:
                pass
        for r in c.execute("SELECT DISTINCT asset_ip FROM security_alerts51 WHERE asset_ip<>'' LIMIT ?", (limit,)).fetchall():
            ips.add(str(r['asset_ip']))
        for r in c.execute("SELECT DISTINCT asset_ip FROM vulnerability_findings51 WHERE asset_ip<>'' LIMIT ?", (limit,)).fetchall():
            ips.add(str(r['asset_ip']))

        out=[]
        for ip in sorted(ips)[:limit]:
            alerts = c.execute("""SELECT severity,COUNT(*) n FROM security_alerts51
                                  WHERE asset_ip=? AND status<>'RESOLVED' GROUP BY severity""", (ip,)).fetchall()
            findings = c.execute("SELECT severity,COUNT(*) n FROM vulnerability_findings51 WHERE asset_ip=? GROUP BY severity", (ip,)).fetchall()
            a = {str(r['severity']).upper(): int(r['n']) for r in alerts}
            v = {str(r['severity']).upper(): int(r['n']) for r in findings}
            score = min(100,
                        a.get('CRITICAL',0)*35 + a.get('HIGH',0)*18 + a.get('MEDIUM',0)*8 + a.get('LOW',0)*2 +
                        v.get('CRITICAL',0)*25 + v.get('HIGH',0)*12 + v.get('MEDIUM',0)*5 + v.get('LOW',0))
            level = 'CRITICAL' if score >= 80 else 'HIGH' if score >= 55 else 'MEDIUM' if score >= 25 else 'LOW'
            out.append({'asset_ip':ip,'risk_score':score,'risk_level':level,'open_alerts':sum(a.values()),
                        'vulnerability_findings':sum(v.values()),'alert_breakdown':a,'finding_breakdown':v})
    out.sort(key=lambda x:(-x['risk_score'], x['asset_ip']))
    return out


@router.get('/summary')
def summary(request: Request):
    require_role(request)
    ensure_tables55()
    with connection() as c:
        def n(sql, args=()): return int(c.execute(sql,args).fetchone()[0])
        return {
            'version':'5.9.2-cybersecurity',
            'open_cases': n("SELECT COUNT(*) FROM soc_cases55 WHERE status NOT IN ('RESOLVED','CLOSED')"),
            'critical_cases': n("SELECT COUNT(*) FROM soc_cases55 WHERE status NOT IN ('RESOLVED','CLOSED') AND priority='CRITICAL'"),
            'unassigned_cases': n("SELECT COUNT(*) FROM soc_cases55 WHERE status NOT IN ('RESOLVED','CLOSED') AND trim(owner)=''"),
            'open_alerts': n("SELECT COUNT(*) FROM security_alerts51 WHERE status<>'RESOLVED'"),
            'vulnerability_findings': n('SELECT COUNT(*) FROM vulnerability_findings51'),
            'ioc_matches': n('SELECT COUNT(*) FROM ioc_matches54'),
            'generated_at': utcnow(),
            'mode':'defensive-case-management'
        }
