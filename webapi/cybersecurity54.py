"""Cybersecurity 5.4 defensive threat intelligence and detection rules.

This module adds a local IOC watchlist and bounded SIEM correlation rules. It is
intentionally defensive: it does not exploit targets, brute-force credentials,
or automatically block remote systems.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from webapi.runtime37 import connection, utcnow
from webapi.security37 import require_role
from webapi.cybersecurity51 import ensure_tables53, _rows, _upsert_alert, SEV_WEIGHT

router = APIRouter(prefix='/api/v54', tags=['Cybersecurity 5.4'])


class IOCIn(BaseModel):
    indicator_type: str = Field(min_length=2, max_length=16)
    indicator: str = Field(min_length=2, max_length=512)
    severity: str = Field(default='HIGH', max_length=16)
    label: str = Field(default='', max_length=160)
    source: str = Field(default='manual', max_length=160)
    note: str = Field(default='', max_length=2000)


class DetectionRuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    source: str = Field(default='', max_length=80)
    event_type: str = Field(default='', max_length=100)
    min_severity: str = Field(default='INFO', max_length=16)
    contains_text: str = Field(default='', max_length=240)
    threshold: int = Field(default=1, ge=1, le=100)
    window_sec: int = Field(default=300, ge=60, le=86400)
    alert_severity: str = Field(default='HIGH', max_length=16)
    enabled: bool = True


def ensure_tables54() -> None:
    ensure_tables53()
    with connection() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS ioc_watchlist54(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          indicator_type TEXT NOT NULL,
          indicator TEXT NOT NULL,
          severity TEXT NOT NULL DEFAULT 'HIGH',
          label TEXT DEFAULT '',
          source TEXT DEFAULT 'manual',
          note TEXT DEFAULT '',
          enabled INTEGER NOT NULL DEFAULT 1,
          created_by TEXT DEFAULT '',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          UNIQUE(indicator_type, indicator)
        );
        CREATE INDEX IF NOT EXISTS ix_ioc54_enabled
          ON ioc_watchlist54(enabled, indicator_type);

        CREATE TABLE IF NOT EXISTS ioc_matches54(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ioc_id INTEGER NOT NULL,
          event_id INTEGER NOT NULL,
          matched_field TEXT NOT NULL,
          matched_value TEXT NOT NULL,
          created_at TEXT NOT NULL,
          UNIQUE(ioc_id, event_id, matched_field)
        );
        CREATE INDEX IF NOT EXISTS ix_ioc_matches54_time
          ON ioc_matches54(created_at DESC);

        CREATE TABLE IF NOT EXISTS detection_rules54(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          source TEXT DEFAULT '',
          event_type TEXT DEFAULT '',
          min_severity TEXT NOT NULL DEFAULT 'INFO',
          contains_text TEXT DEFAULT '',
          threshold INTEGER NOT NULL DEFAULT 1,
          window_sec INTEGER NOT NULL DEFAULT 300,
          alert_severity TEXT NOT NULL DEFAULT 'HIGH',
          enabled INTEGER NOT NULL DEFAULT 1,
          created_by TEXT DEFAULT '',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_detection54_enabled
          ON detection_rules54(enabled, event_type, source);
        """)
        c.commit()


def _normalize_ioc(kind: str, value: str) -> tuple[str, str]:
    kind = (kind or '').strip().upper()
    value = (value or '').strip()
    if kind == 'IP':
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError:
            raise HTTPException(400, 'INVALID_IOC_IP')
    elif kind == 'DOMAIN':
        value = value.lower().rstrip('.')
        pattern = r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
        if len(value) > 253 or not re.fullmatch(pattern, value):
            raise HTTPException(400, 'INVALID_IOC_DOMAIN')
    elif kind == 'SHA256':
        value = value.lower()
        if not re.fullmatch(r'[0-9a-f]{64}', value):
            raise HTTPException(400, 'INVALID_IOC_SHA256')
    else:
        raise HTTPException(400, 'UNSUPPORTED_IOC_TYPE')
    return kind, value


def _severity_rank(value: str) -> int:
    return {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}.get(
        str(value or '').upper(), 0
    )


def _event_candidates(event: dict) -> list[tuple[str, str, str]]:
    """Return tuples of (kind, field, normalized value)."""
    out: list[tuple[str, str, str]] = []
    for field in ('asset_ip', 'peer_ip'):
        value = str(event.get(field) or '').strip()
        if value:
            try:
                out.append(('IP', field, str(ipaddress.ip_address(value))))
            except ValueError:
                pass
    text = ' '.join([
        str(event.get('message') or ''),
        json.dumps(event.get('metadata') or {}, ensure_ascii=False),
    ])
    for value in set(re.findall(r'(?i)\b[0-9a-f]{64}\b', text)):
        out.append(('SHA256', 'text_sha256', value.lower()))
    domain_pattern = r'(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b'
    for value in set(re.findall(domain_pattern, text)):
        out.append(('DOMAIN', 'text_domain', value.lower().rstrip('.')))
    return out


def correlate_event54(event_id: int, event: dict) -> dict:
    """Enrich one already-stored SIEM event with IOC/rule correlation.

    This function never performs network traffic or remote actions. It only compares
    the local event against local watchlist/rules and creates SOC alerts.
    """
    ensure_tables54()
    now = utcnow()
    ioc_hits = 0
    rule_hits = 0
    candidates = _event_candidates(event)
    alerts_to_create: list[tuple] = []

    with connection() as c:
        iocs = [dict(r) for r in c.execute(
            'SELECT * FROM ioc_watchlist54 WHERE enabled=1'
        ).fetchall()]
        for ioc in iocs:
            wanted = ioc['indicator']
            for kind, field, value in candidates:
                if kind != ioc['indicator_type']:
                    continue
                matched = value == wanted
                if kind == 'DOMAIN':
                    matched = value == wanted or value.endswith('.' + wanted)
                if not matched:
                    continue
                cur = c.execute(
                    'INSERT OR IGNORE INTO ioc_matches54(ioc_id,event_id,matched_field,matched_value,created_at) VALUES(?,?,?,?,?)',
                    (ioc['id'], event_id, field, value, now),
                )
                if cur.rowcount:
                    ioc_hits += 1
                alerts_to_create.append((
                    'IOC_MATCH:' + str(ioc['id']),
                    'IOC match: ' + (ioc['label'] or wanted),
                    ioc['severity'],
                    event.get('asset_ip', ''),
                    event.get('subject_user', ''),
                    {
                        'event_id': event_id,
                        'ioc_id': ioc['id'],
                        'indicator_type': ioc['indicator_type'],
                        'indicator': wanted,
                        'matched_field': field,
                    },
                ))

        rules = [dict(r) for r in c.execute(
            'SELECT * FROM detection_rules54 WHERE enabled=1'
        ).fetchall()]
        for rule in rules:
            if rule['source'] and rule['source'].lower() != str(event.get('source') or '').lower():
                continue
            if rule['event_type'] and rule['event_type'].upper() != str(event.get('event_type') or '').upper():
                continue
            if _severity_rank(event.get('severity', 'INFO')) < _severity_rank(rule['min_severity']):
                continue
            needle = (rule['contains_text'] or '').strip().lower()
            if needle and needle not in str(event.get('message') or '').lower():
                continue

            since = (datetime.now(timezone.utc) - timedelta(seconds=int(rule['window_sec']))).isoformat(timespec='seconds')
            clauses = ['created_at>=?']
            args: list = [since]
            if rule['source']:
                clauses.append('lower(source)=?')
                args.append(rule['source'].lower())
            if rule['event_type']:
                clauses.append('event_type=?')
                args.append(rule['event_type'].upper())
            if rule['min_severity'] != 'INFO':
                allowed = [
                    value for value in ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
                    if _severity_rank(value) >= _severity_rank(rule['min_severity'])
                ]
                clauses.append('severity IN (' + ','.join('?' for _ in allowed) + ')')
                args.extend(allowed)
            if needle:
                clauses.append('lower(message) LIKE ?')
                args.append('%' + needle + '%')
            count = int(c.execute(
                'SELECT COUNT(*) FROM siem_events51 WHERE ' + ' AND '.join(clauses), args
            ).fetchone()[0])
            if count >= int(rule['threshold']):
                rule_hits += 1
                alerts_to_create.append((
                    'CUSTOM_RULE:' + str(rule['id']),
                    rule['name'],
                    rule['alert_severity'],
                    event.get('asset_ip', ''),
                    event.get('subject_user', ''),
                    {
                        'event_id': event_id,
                        'rule_id': rule['id'],
                        'matches_in_window': count,
                        'window_sec': rule['window_sec'],
                    },
                ))
        c.commit()

    # Create/update SOC alerts only after closing the correlation transaction.
    # _upsert_alert opens its own SQLite connection and can also trigger async notifications.
    for args in alerts_to_create:
        _upsert_alert(*args)
    return {'ioc_hits': ioc_hits, 'rule_hits': rule_hits}


@router.get('/threat/summary')
def threat_summary(request: Request):
    require_role(request)
    ensure_tables54()
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec='seconds')
    with connection() as c:
        return {
            'active_iocs': int(c.execute('SELECT COUNT(*) FROM ioc_watchlist54 WHERE enabled=1').fetchone()[0]),
            'active_rules': int(c.execute('SELECT COUNT(*) FROM detection_rules54 WHERE enabled=1').fetchone()[0]),
            'ioc_matches_24h': int(c.execute('SELECT COUNT(*) FROM ioc_matches54 WHERE created_at>=?', (since,)).fetchone()[0]),
            'mode': 'defensive-detection-only',
        }


@router.get('/threat/iocs')
def ioc_list(request: Request):
    require_role(request)
    ensure_tables54()
    return _rows('SELECT * FROM ioc_watchlist54 ORDER BY enabled DESC,id DESC')


@router.post('/threat/iocs')
def ioc_create(body: IOCIn, request: Request):
    user = require_role(request, 'Admin', 'Analyst')
    ensure_tables54()
    kind, value = _normalize_ioc(body.indicator_type, body.indicator)
    severity = body.severity.upper()
    if severity not in {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
        raise HTTPException(400, 'INVALID_SEVERITY')
    now = utcnow()
    try:
        with connection() as c:
            cur = c.execute(
                'INSERT INTO ioc_watchlist54(indicator_type,indicator,severity,label,source,note,enabled,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)',
                (kind, value, severity, body.label.strip(), body.source.strip() or 'manual', body.note.strip(), 1, user['username'], now, now),
            )
            ioc_id = cur.lastrowid
            c.commit()
    except Exception as exc:
        if 'UNIQUE' in str(exc).upper():
            raise HTTPException(409, 'IOC_ALREADY_EXISTS')
        raise
    return {'ok': True, 'id': ioc_id, 'indicator_type': kind, 'indicator': value, 'enabled': True}


@router.post('/threat/iocs/{ioc_id}/toggle')
def ioc_toggle(ioc_id: int, request: Request):
    user = require_role(request, 'Admin', 'Analyst')
    ensure_tables54()
    with connection() as c:
        row = c.execute('SELECT enabled FROM ioc_watchlist54 WHERE id=?', (ioc_id,)).fetchone()
        if not row:
            raise HTTPException(404, 'IOC_NOT_FOUND')
        enabled = 0 if int(row['enabled']) else 1
        c.execute('UPDATE ioc_watchlist54 SET enabled=?,updated_at=? WHERE id=?', (enabled, utcnow(), ioc_id))
        c.commit()
    return {'ok': True, 'id': ioc_id, 'enabled': bool(enabled), 'actor': user['username']}


@router.delete('/threat/iocs/{ioc_id}')
def ioc_delete(ioc_id: int, request: Request):
    user = require_role(request, 'Admin')
    ensure_tables54()
    with connection() as c:
        if not c.execute('SELECT 1 FROM ioc_watchlist54 WHERE id=?', (ioc_id,)).fetchone():
            raise HTTPException(404, 'IOC_NOT_FOUND')
        c.execute('DELETE FROM ioc_matches54 WHERE ioc_id=?', (ioc_id,))
        c.execute('DELETE FROM ioc_watchlist54 WHERE id=?', (ioc_id,))
        c.commit()
    return {'ok': True, 'id': ioc_id, 'actor': user['username']}


@router.get('/threat/matches')
def ioc_matches(request: Request, limit: int = 500):
    require_role(request)
    ensure_tables54()
    limit = max(1, min(limit, 2000))
    return _rows(
        'SELECT m.id,m.event_id,m.matched_field,m.matched_value,m.created_at,w.indicator_type,w.indicator,w.severity,w.label,w.source FROM ioc_matches54 m JOIN ioc_watchlist54 w ON w.id=m.ioc_id ORDER BY m.id DESC LIMIT ?',
        (limit,),
    )


@router.get('/detection-rules')
def detection_rules(request: Request):
    require_role(request)
    ensure_tables54()
    return _rows('SELECT * FROM detection_rules54 ORDER BY enabled DESC,id DESC')


@router.post('/detection-rules')
def detection_rule_create(body: DetectionRuleIn, request: Request):
    user = require_role(request, 'Admin', 'Analyst')
    ensure_tables54()
    min_severity = body.min_severity.upper()
    alert_severity = body.alert_severity.upper()
    if min_severity not in SEV_WEIGHT or alert_severity not in {'MEDIUM', 'HIGH', 'CRITICAL'}:
        raise HTTPException(400, 'INVALID_RULE_SEVERITY')
    now = utcnow()
    with connection() as c:
        cur = c.execute(
            'INSERT INTO detection_rules54(name,source,event_type,min_severity,contains_text,threshold,window_sec,alert_severity,enabled,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
            (
                body.name.strip(), body.source.strip(), body.event_type.strip().upper(), min_severity,
                body.contains_text.strip(), body.threshold, body.window_sec, alert_severity,
                1 if body.enabled else 0, user['username'], now, now,
            ),
        )
        rule_id = cur.lastrowid
        c.commit()
    return {'ok': True, 'id': rule_id, 'enabled': body.enabled}


@router.post('/detection-rules/{rule_id}/toggle')
def detection_rule_toggle(rule_id: int, request: Request):
    user = require_role(request, 'Admin', 'Analyst')
    ensure_tables54()
    with connection() as c:
        row = c.execute('SELECT enabled FROM detection_rules54 WHERE id=?', (rule_id,)).fetchone()
        if not row:
            raise HTTPException(404, 'RULE_NOT_FOUND')
        enabled = 0 if int(row['enabled']) else 1
        c.execute('UPDATE detection_rules54 SET enabled=?,updated_at=? WHERE id=?', (enabled, utcnow(), rule_id))
        c.commit()
    return {'ok': True, 'id': rule_id, 'enabled': bool(enabled), 'actor': user['username']}


@router.delete('/detection-rules/{rule_id}')
def detection_rule_delete(rule_id: int, request: Request):
    user = require_role(request, 'Admin')
    ensure_tables54()
    with connection() as c:
        if not c.execute('SELECT 1 FROM detection_rules54 WHERE id=?', (rule_id,)).fetchone():
            raise HTTPException(404, 'RULE_NOT_FOUND')
        c.execute('DELETE FROM detection_rules54 WHERE id=?', (rule_id,))
        c.commit()
    return {'ok': True, 'id': rule_id, 'actor': user['username']}
