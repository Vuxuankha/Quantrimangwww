from __future__ import annotations

import importlib.util
import json
import os
import platform
import secrets
import shutil
import sqlite3
import time
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from webapi.runtime37 import connection, sqlite_snapshot, utcnow
from webapi.security37 import require_role

router = APIRouter(prefix='/api/v41')

RETENTION_TABLES = {
    'ping_results': ('ping_time', 'created_at', 'timestamp'),
    'health_samples': ('created_at', 'timestamp', 'sampled_at'),
    'activity_logs': ('created_at', 'timestamp'),
    'notification_log': ('created_at', 'timestamp'),
    'web_security_log37': ('created_at',),
    'web_operation_runs': ('created_at', 'started_at'),
    'web_operation_results': ('created_at',),
}
DEFAULT_RETENTION = {
    'ping_results': 90,
    'health_samples': 180,
    'activity_logs': 180,
    'notification_log': 180,
    'web_security_log37': 365,
    'web_operation_runs': 180,
    'web_operation_results': 180,
}


def ensure_tables():
    with connection() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS web_retention41(
            table_name TEXT PRIMARY KEY,
            keep_days INTEGER NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS web_dr_exports41(
            id INTEGER PRIMARY KEY,
            filename TEXT NOT NULL,
            created_by TEXT,
            created_at TEXT,
            db_sha256 TEXT,
            notes TEXT
        );
        ''')
        for table, days in DEFAULT_RETENTION.items():
            c.execute('INSERT OR IGNORE INTO web_retention41(table_name,keep_days,enabled,updated_at) VALUES(?,?,0,?)', (table, days, utcnow()))


def _tables(c):
    return {r['name'] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _columns(c, table):
    if table not in _tables(c):
        return set()
    return {r['name'] for r in c.execute(f'PRAGMA table_info("{table}")')}


def _timestamp_column(c, table):
    cols = _columns(c, table)
    for candidate in RETENTION_TABLES.get(table, ()):
        if candidate in cols:
            return candidate
    return None


def _quick_check(db_path: Path):
    try:
        with sqlite3.connect(db_path.resolve().as_uri() + '?mode=ro', uri=True, timeout=5) as c:
            result = c.execute('PRAGMA quick_check').fetchone()[0]
        return result
    except Exception as exc:
        return 'ERROR:' + type(exc).__name__


def _latest_file_age(paths):
    existing = [p for p in paths if p.exists() and p.is_file()]
    if not existing:
        return None, None
    p = max(existing, key=lambda x: x.stat().st_mtime)
    return p.name, max(0, int(time.time() - p.stat().st_mtime))


def _dir_size(path: Path):
    total = 0
    try:
        for p in path.rglob('*'):
            if p.is_file():
                total += p.stat().st_size
    except Exception:
        pass
    return total


@router.get('/production')
def production_status(request: Request):
    require_role(request, 'Admin')
    from database.db import DB_PATH
    from app_runtime import DATABASE_DIR, BACKUP_DIR, LOG_DIR
    from webapi.scheduler40 import scheduler
    from webapi.jobs37 import engine

    db_path = Path(DB_PATH)
    data_root = Path(DATABASE_DIR)
    backup_root = Path(BACKUP_DIR)
    log_root = Path(LOG_DIR)
    disk = shutil.disk_usage(data_root)

    with connection() as c:
        tables = _tables(c)
        jobs = {'Queued': 0, 'Running': 0, 'Failed': 0, 'Interrupted': 0}
        if 'web_jobs37' in tables:
            for r in c.execute("SELECT status,COUNT(*) n FROM web_jobs37 GROUP BY status"):
                if r['status'] in jobs:
                    jobs[r['status']] = r['n']
        schedules = {'enabled': 0, 'overdue': 0}
        if 'web_schedules40' in tables:
            schedules['enabled'] = c.execute('SELECT COUNT(*) FROM web_schedules40 WHERE enabled=1').fetchone()[0]
            schedules['overdue'] = c.execute('SELECT COUNT(*) FROM web_schedules40 WHERE enabled=1 AND COALESCE(next_epoch,0)<?', (time.time() - 120,)).fetchone()[0]
        creds = {}
        for table in ('credentials', 'snmpv3_credentials', 'device_credentials'):
            creds[table] = c.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0] if table in tables else 0
        notif = {'sent': 0, 'failed': 0}
        if 'notification_log' in tables:
            for r in c.execute("SELECT upper(COALESCE(status,'')) s,COUNT(*) n FROM notification_log GROUP BY upper(COALESCE(status,''))"):
                if r['s'] == 'SENT': notif['sent'] += r['n']
                if r['s'] == 'FAILED': notif['failed'] += r['n']
        lan = {'REACHABLE':0,'NO_ROUTE':0,'PATH_UNVERIFIED':0,'NO_ICMP_REPLY':0,'total':0}
        if 'web_lan_probe42' in tables:
            for r in c.execute("SELECT p.path_state,COUNT(*) n FROM web_lan_probe42 p JOIN (SELECT ip,MAX(id) mid FROM web_lan_probe42 GROUP BY ip) x ON x.mid=p.id GROUP BY p.path_state"):
                key=str(r['path_state'] or ''); lan[key]=int(r['n']); lan['total']+=int(r['n'])
        invalid_server_targets = 0
        if 'server_monitor_targets' in tables:
            from modules.server_monitor import validate_target
            import ipaddress as _ipaddress
            for row in c.execute('SELECT host,port,protocol FROM server_monitor_targets'):
                try:
                    host,_,_=validate_target(str(row['host'] or ''),row['port'] or 0,row['protocol'] or 'TCP')
                    if any(ch.isdigit() for ch in host) and '.' in host and all(ch.isdigit() or ch=='.' for ch in host):
                        _ipaddress.ip_address(host)
                except (ValueError,TypeError):
                    invalid_server_targets += 1

    backup_candidates = list(backup_root.glob('*.db')) if backup_root.exists() else []
    pre = data_root / 'web_preupgrade_backups'
    if pre.exists():
        backup_candidates += list(pre.glob('*.db'))
    latest_backup, latest_backup_age = _latest_file_age(backup_candidates)

    known_hosts = data_root / 'known_hosts'
    if not known_hosts.exists():
        known_hosts = Path.cwd() / 'database' / 'known_hosts'
    known_lines = 0
    if known_hosts.exists():
        try:
            known_lines = sum(1 for line in known_hosts.read_text(encoding='utf-8', errors='ignore').splitlines() if line.strip() and not line.lstrip().startswith('#'))
        except Exception:
            pass

    libraries = {name: bool(importlib.util.find_spec(name)) for name in ('paramiko', 'pysnmp', 'openpyxl', 'fastapi', 'uvicorn')}
    checks = [
        {'name': 'Database quick_check', 'status': 'PASS' if _quick_check(db_path) == 'ok' else 'FAIL', 'detail': _quick_check(db_path)},
        {'name': 'Disk free', 'status': 'PASS' if disk.free >= 2 * 1024**3 else 'WARN', 'detail': f'{disk.free/1024**3:.1f} GB'},
        {'name': 'Recent DB backup', 'status': 'PASS' if latest_backup_age is not None and latest_backup_age <= 7*86400 else 'WARN', 'detail': latest_backup or 'No backup found'},
        {'name': 'Job queue', 'status': 'PASS' if jobs['Running'] <= 2 and jobs['Queued'] <= 16 else 'WARN', 'detail': json.dumps(jobs)},
        {'name': 'Scheduler thread', 'status': 'PASS' if scheduler.thread and scheduler.thread.is_alive() else 'FAIL', 'detail': f"enabled={schedules['enabled']} overdue={schedules['overdue']}"},
        {'name': 'SSH library', 'status': 'PASS' if libraries['paramiko'] else 'WARN', 'detail': 'paramiko'},
        {'name': 'SNMP library', 'status': 'PASS' if libraries['pysnmp'] else 'WARN', 'detail': 'pysnmp'},
        {'name': 'LAN path evidence', 'status': 'PASS' if lan['total'] and not (lan.get('NO_ROUTE',0) or lan.get('PATH_UNVERIFIED',0)) else 'WARN', 'detail': json.dumps(lan)},
        {'name': 'Server target validation', 'status': 'PASS' if invalid_server_targets==0 else 'WARN', 'detail': f'invalid={invalid_server_targets}'},
    ]
    overall = 'PASS' if all(x['status'] == 'PASS' for x in checks) else ('FAIL' if any(x['status'] == 'FAIL' for x in checks) else 'WARN')
    return {
        'overall': overall,
        'platform': platform.platform(),
        'python': platform.python_version(),
        'database': {'path': str(db_path), 'bytes': db_path.stat().st_size if db_path.exists() else 0, 'quick_check': _quick_check(db_path)},
        'disk': {'free_bytes': disk.free, 'total_bytes': disk.total, 'free_percent': round(disk.free/disk.total*100, 1)},
        'backups': {'latest': latest_backup, 'age_seconds': latest_backup_age, 'root_bytes': _dir_size(backup_root)},
        'jobs': jobs,
        'scheduler': schedules,
        'worker_ready': engine.pool is not None,
        'credential_key_present': (data_root / '.credential.key').is_file(),
        'known_hosts_entries': known_lines,
        'credentials': creds,
        'notifications': notif,
        'lan': lan,
        'invalid_server_targets': invalid_server_targets,
        'libraries': libraries,
        'checks': checks,
        'observed_at': utcnow(),
    }


class RetentionItem(BaseModel):
    table_name: str = Field(max_length=64)
    keep_days: int = Field(ge=7, le=3650)
    enabled: bool = False

class RetentionUpdate(BaseModel):
    policies: list[RetentionItem] = Field(max_length=20)

class RetentionApply(BaseModel):
    confirmation: str = Field(max_length=64)
    authorized: bool = False


def _retention_preview(c):
    rows = []
    tables = _tables(c)
    for p in c.execute('SELECT table_name,keep_days,enabled,updated_at FROM web_retention41 ORDER BY table_name'):
        d = dict(p); table = d['table_name']; col = _timestamp_column(c, table) if table in tables else None
        cutoff = (datetime.now(timezone.utc) - timedelta(days=int(d['keep_days']))).isoformat(timespec='seconds')
        count = 0
        if col and d['enabled']:
            try:
                count = c.execute(f'SELECT COUNT(*) FROM "{table}" WHERE "{col}" IS NOT NULL AND "{col}"<?', (cutoff,)).fetchone()[0]
            except Exception:
                count = 0
        d.update({'timestamp_column': col, 'cutoff': cutoff, 'would_delete': count})
        rows.append(d)
    return rows


@router.get('/retention')
def retention(request: Request):
    require_role(request, 'Admin')
    with connection() as c:
        return _retention_preview(c)

@router.put('/retention')
def retention_update(x: RetentionUpdate, request: Request):
    require_role(request, 'Admin')
    allowed = set(DEFAULT_RETENTION)
    with connection() as c:
        for p in x.policies:
            if p.table_name not in allowed:
                raise HTTPException(400, 'Unsupported retention table')
            c.execute('INSERT INTO web_retention41(table_name,keep_days,enabled,updated_at) VALUES(?,?,?,?) ON CONFLICT(table_name) DO UPDATE SET keep_days=excluded.keep_days,enabled=excluded.enabled,updated_at=excluded.updated_at', (p.table_name, p.keep_days, int(p.enabled), utcnow()))
        return _retention_preview(c)

@router.post('/retention/apply')
def retention_apply(x: RetentionApply, request: Request):
    u = require_role(request, 'Admin')
    if not x.authorized or x.confirmation != 'APPLY RETENTION':
        raise HTTPException(400, 'Type APPLY RETENTION and confirm authorization')
    from database.db import DB_PATH
    from app_runtime import BACKUP_DIR
    snap = Path(BACKUP_DIR) / ('pre_retention_' + datetime.now().strftime('%Y%m%d_%H%M%S') + '_' + secrets.token_hex(4) + '.db')
    sqlite_snapshot(Path(DB_PATH), snap)
    deleted = {}
    with connection() as c:
        preview = _retention_preview(c)
        c.execute('BEGIN IMMEDIATE')
        for p in preview:
            if not p['enabled'] or not p['timestamp_column'] or not p['would_delete']:
                continue
            cur = c.execute(f'DELETE FROM "{p["table_name"]}" WHERE "{p["timestamp_column"]}" IS NOT NULL AND "{p["timestamp_column"]}"<?', (p['cutoff'],))
            deleted[p['table_name']] = cur.rowcount
        if 'web_security_log37' in _tables(c):
            c.execute('INSERT INTO web_security_log37(actor,method,path,status,request_id,created_at) VALUES(?,?,?,?,?,?)', (u['username'], 'RETENTION', '/api/v41/retention/apply', 200, 'manual', utcnow()))
    return {'success': True, 'deleted': deleted, 'safety_backup': snap.name}


class DrExportIn(BaseModel):
    confirmation: str = Field(max_length=64)

@router.post('/disaster-recovery/export')
def dr_export(x: DrExportIn, request: Request):
    u = require_role(request, 'Admin')
    if x.confirmation != 'EXPORT PRIVATE DR':
        raise HTTPException(400, 'Type EXPORT PRIVATE DR')
    from database.db import DB_PATH
    from app_runtime import DATABASE_DIR, BACKUP_DIR
    from webapi.reports37 import register
    root = Path(BACKUP_DIR); root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    tmp_db = root / f'dr_snapshot_{stamp}_{secrets.token_hex(4)}.db'
    sqlite_snapshot(Path(DB_PATH), tmp_db)
    out = root / f'NetworkAutomation_DR_PRIVATE_{stamp}_{secrets.token_hex(4)}.zip'
    manifest = {'created_at': utcnow(), 'created_by': u['username'], 'warning': 'PRIVATE: contains database and may contain credential key/known_hosts', 'files': []}
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        z.write(tmp_db, 'database/network_automation.db'); manifest['files'].append('database/network_automation.db')
        for name in ('.credential.key', 'known_hosts'):
            p = Path(DATABASE_DIR) / name
            if p.is_file():
                z.write(p, 'database/' + name); manifest['files'].append('database/' + name)
        z.writestr('DR_MANIFEST.json', json.dumps(manifest, ensure_ascii=False, indent=2))
    tmp_db.unlink(missing_ok=True)
    import hashlib
    h = hashlib.sha256(out.read_bytes()).hexdigest()
    with connection() as c:
        c.execute('INSERT INTO web_dr_exports41(filename,created_by,created_at,db_sha256,notes) VALUES(?,?,?,?,?)', (out.name, u['username'], utcnow(), h, 'Private disaster recovery export'))
    result = register(out, u['id'], 'database')
    result['sha256'] = h
    result['private'] = True
    return result
