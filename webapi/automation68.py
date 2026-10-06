"""6.8.0 master automation coordinator for safe, non-destructive Web operations.

The master switch intentionally automates only bounded monitoring/maintenance jobs.
Destructive actions, credential changes, restores, Auto-IP changes, vulnerability
scans, bandwidth tests and remote configuration writes remain explicit/manual.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable

from fastapi import APIRouter, Request

from webapi.runtime37 import connection, utcnow
from webapi.security37 import require_role, WRITE_RULES

logger = logging.getLogger(__name__)
router = APIRouter(prefix='/api/v68')

WRITE_RULES.extend([
    ('POST', r'/api/v68/automation/(enable|disable|run-now)', ('Admin',)),
])


@dataclass(frozen=True)
class TaskSpec:
    key: str
    label: str
    interval_seconds: int
    runner: Callable[[int, str], dict]


def ensure_tables() -> None:
    with connection() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS web_autoops68_state(
          id INTEGER PRIMARY KEY CHECK(id=1),
          enabled INTEGER NOT NULL DEFAULT 0,
          actor_id INTEGER,
          actor_username TEXT,
          enabled_at TEXT,
          disabled_at TEXT,
          updated_at TEXT,
          last_cycle_at TEXT,
          last_cycle_status TEXT,
          last_cycle_detail TEXT
        );
        INSERT OR IGNORE INTO web_autoops68_state(id,enabled,updated_at)
          VALUES(1,0,datetime('now'));
        CREATE TABLE IF NOT EXISTS web_autoops68_tasks(
          task_key TEXT PRIMARY KEY,
          label TEXT NOT NULL,
          interval_seconds INTEGER NOT NULL,
          last_started_at TEXT,
          last_finished_at TEXT,
          last_status TEXT,
          last_detail TEXT,
          last_duration_ms INTEGER,
          next_epoch REAL NOT NULL DEFAULT 0,
          run_count INTEGER NOT NULL DEFAULT 0,
          fail_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS web_autoops68_runs(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          task_key TEXT NOT NULL,
          status TEXT NOT NULL,
          detail TEXT,
          duration_ms INTEGER,
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_web_autoops68_runs_time
          ON web_autoops68_runs(created_at DESC);
        ''')


def _run_presence(actor_id: int, username: str) -> dict:
    from webapi.main import refresh_device_status
    r = refresh_device_status()
    return {
        'count': int(r.get('count') or 0),
        'online': int(r.get('online') or 0),
        'offline': int(r.get('offline') or 0),
        'unknown': int(r.get('unknown') or 0),
    }


def _run_discovery(actor_id: int, username: str) -> dict:
    from webapi.autodiscovery5010 import ensure
    r = ensure(source='master-auto-6.8', force=False)
    return {
        'state': r.get('state'),
        'network': r.get('network'),
        'active': int(r.get('active') or r.get('preliminary_active') or 0),
        'detail': str(r.get('detail') or '')[:300],
    }


def _run_alert_rules(actor_id: int, username: str) -> dict:
    from modules.nms_v4 import evaluate_alert_rules
    created, recovered = evaluate_alert_rules()
    return {'created': int(created or 0), 'recovered': int(recovered or 0)}


def _run_incidents(actor_id: int, username: str) -> dict:
    from webapi.ops40 import sync_incidents_and_rca
    return sync_incidents_and_rca()


def _run_server_monitor(actor_id: int, username: str) -> dict:
    from modules.server_monitor import run_all_targets
    out = run_all_targets()
    ok = 0
    for _, result in out:
        if isinstance(result, dict) and str(result.get('status') or '').lower() in {'online','ok','up','healthy'}:
            ok += 1
    return {'checked': len(out), 'healthy': ok}


def _run_line_quality(actor_id: int, username: str) -> dict:
    from webapi.cybersecurity59 import run_line_test_internal
    r = run_line_test_internal(username or 'master-auto')
    return {
        'grade': r.get('grade'),
        'latency_ms': r.get('latency_ms'),
        'jitter_ms': r.get('jitter_ms'),
        'packet_loss': r.get('packet_loss'),
    }


def _run_database_backup(actor_id: int, username: str) -> dict:
    from webapi.reports37 import backup_db
    r = backup_db(int(actor_id or 0))
    return {'success': bool(r.get('success')), 'name': r.get('name')}


TASKS = [
    TaskSpec('PRESENCE', 'Trạng thái Online / Offline', 60, _run_presence),
    TaskSpec('LIVE_DISCOVERY', 'Quét IP đang dùng trong LAN', 300, _run_discovery),
    TaskSpec('ALERT_RULES', 'Đánh giá Alert Rules', 120, _run_alert_rules),
    TaskSpec('INCIDENT_RCA', 'Đồng bộ Sự cố / RCA', 180, _run_incidents),
    TaskSpec('SERVER_MONITOR', 'Kiểm tra Server / Service', 180, _run_server_monitor),
    TaskSpec('LINE_QUALITY', 'Đo chất lượng đường truyền', 300, _run_line_quality),
    TaskSpec('DATABASE_BACKUP', 'Sao lưu Database an toàn', 86400, _run_database_backup),
]
TASK_BY_KEY = {x.key: x for x in TASKS}


class MasterAutomation68:
    def __init__(self):
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.pool: ThreadPoolExecutor | None = ThreadPoolExecutor(max_workers=3, thread_name_prefix='NA-Auto68')
        self.lock = threading.RLock()
        self.running: set[str] = set()

    def start(self) -> None:
        ensure_tables()
        self._seed_tasks()
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        if self.pool is None or getattr(self.pool, '_shutdown', False):
            self.pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix='NA-Auto68')
        self.thread = threading.Thread(target=self._loop, name='NA-MasterAutomation68', daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=8)
        self.thread = None
        if self.pool is not None:
            self.pool.shutdown(wait=False, cancel_futures=False)
            self.pool = None

    def _seed_tasks(self) -> None:
        with connection() as c:
            for t in TASKS:
                c.execute('''INSERT INTO web_autoops68_tasks(task_key,label,interval_seconds,next_epoch)
                             VALUES(?,?,?,0)
                             ON CONFLICT(task_key) DO UPDATE SET label=excluded.label,interval_seconds=excluded.interval_seconds''',
                          (t.key, t.label, t.interval_seconds))

    def _state(self) -> dict:
        ensure_tables()
        with connection() as c:
            row = c.execute('SELECT * FROM web_autoops68_state WHERE id=1').fetchone()
        return dict(row) if row else {'enabled': 0}

    def _loop(self) -> None:
        while not self.stop_event.wait(5):
            try:
                self.tick()
            except Exception:
                logger.exception('master automation tick failed')

    def tick(self, force: bool=False) -> None:
        state = self._state()
        if not state.get('enabled') and not force:
            return
        actor_id = int(state.get('actor_id') or 0)
        username = str(state.get('actor_username') or 'master-auto')
        now = time.time()
        due: list[TaskSpec] = []
        with connection() as c:
            rows = {r['task_key']: dict(r) for r in c.execute('SELECT * FROM web_autoops68_tasks').fetchall()}
            for spec in TASKS:
                row = rows.get(spec.key, {})
                if force or float(row.get('next_epoch') or 0) <= now:
                    due.append(spec)
            c.execute('UPDATE web_autoops68_state SET last_cycle_at=?,last_cycle_status=?,last_cycle_detail=?,updated_at=? WHERE id=1',
                      (utcnow(), 'RUNNING' if due else 'IDLE', f'{len(due)} task(s) due', utcnow()))
        for spec in due:
            with self.lock:
                if spec.key in self.running:
                    continue
                self.running.add(spec.key)
            with connection() as c:
                c.execute('UPDATE web_autoops68_tasks SET next_epoch=? WHERE task_key=?',
                          (now + max(10, spec.interval_seconds), spec.key))
            pool = self.pool
            if pool is None:
                with self.lock:
                    self.running.discard(spec.key)
                continue
            pool.submit(self._execute, spec, actor_id, username)

    def _execute(self, spec: TaskSpec, actor_id: int, username: str) -> None:
        started = time.monotonic()
        status = 'PASS'
        detail = ''
        try:
            with connection() as c:
                c.execute('UPDATE web_autoops68_tasks SET last_started_at=?,last_status=? WHERE task_key=?',
                          (utcnow(), 'RUNNING', spec.key))
            result = spec.runner(actor_id, username)
            detail = json.dumps(result, ensure_ascii=False, default=str)[:1800]
        except Exception as exc:
            status = 'FAIL'
            detail = f'{type(exc).__name__}: {exc}'[:1800]
            logger.exception('master automation task failed task=%s', spec.key)
        finally:
            duration_ms = int((time.monotonic() - started) * 1000)
            with connection() as c:
                c.execute('''UPDATE web_autoops68_tasks
                             SET last_finished_at=?,last_status=?,last_detail=?,last_duration_ms=?,
                                 run_count=run_count+1,fail_count=fail_count+?
                             WHERE task_key=?''',
                          (utcnow(), status, detail, duration_ms, 1 if status == 'FAIL' else 0, spec.key))
                c.execute('INSERT INTO web_autoops68_runs(task_key,status,detail,duration_ms,created_at) VALUES(?,?,?,?,?)',
                          (spec.key, status, detail, duration_ms, utcnow()))
                c.execute('''UPDATE web_autoops68_state SET last_cycle_status=?,last_cycle_detail=?,updated_at=? WHERE id=1''',
                          (status if status == 'FAIL' else 'ACTIVE', f'{spec.label}: {status}', utcnow()))
            with self.lock:
                self.running.discard(spec.key)

    def enable(self, user: dict) -> dict:
        ensure_tables(); self._seed_tasks()
        now = time.time()
        with connection() as c:
            c.execute('''UPDATE web_autoops68_state SET enabled=1,actor_id=?,actor_username=?,enabled_at=?,disabled_at=NULL,updated_at=?,last_cycle_status='STARTING',last_cycle_detail='Master automation enabled' WHERE id=1''',
                      (int(user['id']), str(user['username']), utcnow(), utcnow()))
            c.execute('UPDATE web_autoops68_tasks SET next_epoch=?', (now,))
        self.tick(force=True)
        return status_payload()

    def disable(self, user: dict) -> dict:
        with connection() as c:
            c.execute('''UPDATE web_autoops68_state SET enabled=0,disabled_at=?,updated_at=?,last_cycle_status='STOPPED',last_cycle_detail=? WHERE id=1''',
                      (utcnow(), utcnow(), f"Disabled by {user['username']}"))
        return status_payload()

    def run_now(self) -> dict:
        self.tick(force=True)
        return status_payload()


engine = MasterAutomation68()


def status_payload() -> dict:
    ensure_tables()
    with connection() as c:
        state = c.execute('SELECT * FROM web_autoops68_state WHERE id=1').fetchone()
        tasks = [dict(r) for r in c.execute('SELECT * FROM web_autoops68_tasks ORDER BY rowid').fetchall()]
        recent = [dict(r) for r in c.execute('SELECT * FROM web_autoops68_runs ORDER BY id DESC LIMIT 30').fetchall()]
    state = dict(state) if state else {'enabled': 0}
    for t in tasks:
        t['running'] = t['task_key'] in engine.running
        t['next_in_seconds'] = max(0, int(float(t.get('next_epoch') or 0) - time.time()))
    return {
        'enabled': bool(state.get('enabled')),
        'state': state,
        'tasks': tasks,
        'recent_runs': recent,
        'running_count': len(engine.running),
        'safety': {
            'automatic': ['Presence', 'LAN discovery', 'Alert Rules', 'Incident/RCA sync', 'Server monitor', 'Line quality', 'Database backup'],
            'manual_only': ['Delete/restore', 'Credential changes', 'Auto IP writes', 'Config restore', 'Vulnerability scan', 'WAN speed test', 'Remote configuration writes'],
        },
    }


@router.get('/automation')
def automation_status(request: Request):
    require_role(request)
    return status_payload()


@router.post('/automation/enable')
def automation_enable(request: Request):
    user = require_role(request, 'Admin')
    return engine.enable(user)


@router.post('/automation/disable')
def automation_disable(request: Request):
    user = require_role(request, 'Admin')
    return engine.disable(user)


@router.post('/automation/run-now')
def automation_run_now(request: Request):
    require_role(request, 'Admin')
    return engine.run_now()
