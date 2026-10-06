"""Cybersecurity 5.7 daily operations checklist with 6.9 safe auto-completion.

The checklist aggregates operational/security work. 6.9 adds an optional background
"safe auto-complete" mode. It runs bounded read/refresh/maintenance actions, records
what was checked, and only marks an item AUTO DONE when the underlying condition is
actually clear. It never closes alerts/cases, changes credentials/MFA, remediates
vulnerabilities, restores configs, deletes assets, or writes remote configuration.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import json
import logging
import threading
import time

from fastapi import APIRouter, Request

from webapi.runtime37 import connection, utcnow
from webapi.security37 import require_role, WRITE_RULES
from webapi.cybersecurity56 import ensure_tables56

logger = logging.getLogger(__name__)
router = APIRouter(prefix='/api/v57', tags=['Cybersecurity 5.7'])

WRITE_RULES.extend([
    ('POST', r'/api/v57/daily/reviewed', ('Admin','Analyst','Operator')),
    ('POST', r'/api/v57/daily/auto/(enable|disable|run-now)', ('Admin',)),
])

AUTO_INTERVAL_SECONDS = 300


def ensure_tables57() -> None:
    ensure_tables56()
    with connection() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS daily_security_reviews57(
          review_date TEXT NOT NULL,
          username TEXT NOT NULL,
          reviewed_at TEXT NOT NULL,
          summary_json TEXT NOT NULL DEFAULT '{}',
          PRIMARY KEY(review_date, username)
        );
        CREATE INDEX IF NOT EXISTS ix_daily_review57_time
          ON daily_security_reviews57(reviewed_at DESC);

        CREATE TABLE IF NOT EXISTS daily_auto57_state(
          id INTEGER PRIMARY KEY CHECK(id=1),
          enabled INTEGER NOT NULL DEFAULT 0,
          actor_id INTEGER,
          actor_username TEXT,
          enabled_at TEXT,
          disabled_at TEXT,
          updated_at TEXT,
          last_run_at TEXT,
          last_status TEXT,
          last_detail TEXT,
          next_epoch REAL NOT NULL DEFAULT 0,
          run_count INTEGER NOT NULL DEFAULT 0,
          fail_count INTEGER NOT NULL DEFAULT 0
        );
        INSERT OR IGNORE INTO daily_auto57_state(id,enabled,updated_at,next_epoch)
          VALUES(1,0,datetime('now'),0);

        CREATE TABLE IF NOT EXISTS daily_auto57_runs(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          run_date TEXT NOT NULL,
          actor_username TEXT,
          status TEXT NOT NULL,
          before_items INTEGER NOT NULL DEFAULT 0,
          after_items INTEGER NOT NULL DEFAULT 0,
          completed_keys_json TEXT NOT NULL DEFAULT '[]',
          pending_keys_json TEXT NOT NULL DEFAULT '[]',
          checked_keys_json TEXT NOT NULL DEFAULT '[]',
          detail_json TEXT NOT NULL DEFAULT '{}',
          started_at TEXT NOT NULL,
          finished_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_daily_auto57_runs_time
          ON daily_auto57_runs(id DESC);
        """)
        c.commit()


def _table_exists(c, name: str) -> bool:
    row = c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
    return bool(row)


def _count(c, sql: str, args=()) -> int:
    try:
        row = c.execute(sql, args).fetchone()
        return int(row[0] if row else 0)
    except Exception:
        logger.exception('daily checklist count failed sql=%s', sql[:120])
        return 0


def _parse_dt(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _today_key() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _task(key: str, title: str, count: int, severity: str, page: str, detail: str) -> dict:
    return {
        'key': key, 'title': title, 'count': int(count), 'severity': severity,
        'page': page, 'detail': detail, 'needs_attention': int(count) > 0,
    }


def _json_list(raw) -> list[str]:
    try:
        v = json.loads(raw or '[]')
        return [str(x) for x in v] if isinstance(v, list) else []
    except Exception:
        return []


def _auto_payload() -> dict:
    ensure_tables57()
    with connection() as c:
        state = c.execute('SELECT * FROM daily_auto57_state WHERE id=1').fetchone()
        latest = c.execute('SELECT * FROM daily_auto57_runs ORDER BY id DESC LIMIT 1').fetchone()
    s = dict(state) if state else {'enabled': 0, 'next_epoch': 0}
    latest_d = dict(latest) if latest else None
    now = time.time()
    return {
        'enabled': bool(s.get('enabled')),
        'running': bool(daily_auto_engine.running),
        'interval_seconds': AUTO_INTERVAL_SECONDS,
        'next_in_seconds': max(0, int(float(s.get('next_epoch') or 0) - now)) if s.get('enabled') else None,
        'last_run_at': s.get('last_run_at'),
        'last_status': s.get('last_status'),
        'last_detail': s.get('last_detail'),
        'run_count': int(s.get('run_count') or 0),
        'fail_count': int(s.get('fail_count') or 0),
        'latest': latest_d,
        'safety': {
            'automatic_checks': ['Presence', 'LAN discovery', 'Alert Rules', 'Incident/RCA sync', 'Line quality', 'Database backup'],
            'manual_only': ['Resolve/close alert', 'Close SOC case', 'Vulnerability remediation/scan', 'MFA enrollment', 'Endpoint firewall/antivirus changes', 'Credential/config/restore/delete actions'],
        },
    }


def build_daily_summary(username: str = '') -> dict:
    ensure_tables57()
    now = datetime.now(timezone.utc)
    cutoff24 = (now - timedelta(hours=24)).isoformat(timespec='seconds')
    tasks: list[dict] = []
    with connection() as c:
        critical = _count(c, "SELECT COUNT(*) FROM security_alerts51 WHERE status!='RESOLVED' AND severity='CRITICAL'")
        high = _count(c, "SELECT COUNT(*) FROM security_alerts51 WHERE status!='RESOLVED' AND severity='HIGH'")
        tasks.append(_task('critical_alerts', 'Cảnh báo Critical đang mở', critical, 'CRITICAL', 'siem51', 'Ưu tiên điều tra ngay; tự động chỉ kiểm tra/đồng bộ, không tự resolve cảnh báo.'))
        tasks.append(_task('high_alerts', 'Cảnh báo High đang mở', high, 'HIGH', 'siem51', 'Xác nhận, gán owner hoặc đưa vào SOC Case.'))

        new_assets = _count(c, "SELECT COUNT(*) FROM ip_mac_inventory WHERE COALESCE(first_seen,'')>=?", (cutoff24,))
        tasks.append(_task('new_assets', 'IP / thiết bị mới phát hiện trong 24h', new_assets, 'MEDIUM', 'ipmac', 'Tự động làm mới discovery/presence; thiết bị mới vẫn cần xác nhận hợp lệ.'))

        vuln = _count(c, "SELECT COUNT(*) FROM vulnerability_findings51 WHERE severity IN ('CRITICAL','HIGH')")
        tasks.append(_task('priority_vulns', 'Lỗ hổng Critical/High cần xem', vuln, 'HIGH', 'vuln51', 'Không tự quét/remediate; ưu tiên asset Risk Score cao.'))

        breached = 0
        due_soon = 0
        if _table_exists(c, 'soc_cases55'):
            rows = c.execute("SELECT due_at,status FROM soc_cases55 WHERE status NOT IN ('RESOLVED','CLOSED') AND due_at IS NOT NULL").fetchall()
            for row in rows:
                due = _parse_dt(row['due_at'])
                if not due:
                    continue
                if due < now:
                    breached += 1
                elif due <= now + timedelta(hours=24):
                    due_soon += 1
        tasks.append(_task('sla_breached', 'SOC Case đã quá SLA', breached, 'CRITICAL', 'cases55', 'Tự động đồng bộ RCA/Incident; case quá hạn vẫn cần người xử lý.'))
        tasks.append(_task('sla_due', 'SOC Case sắp tới SLA trong 24h', due_soon, 'HIGH', 'cases55', 'Kiểm tra owner, evidence và bước xử lý tiếp theo.'))

        notif_fail = 0
        if _table_exists(c, 'notification_log'):
            notif_fail = _count(c, "SELECT COUNT(*) FROM notification_log WHERE status='FAILED' AND created_at>=?", (cutoff24,))
        tasks.append(_task('notification_failures', 'Thông báo thất bại trong 24h', notif_fail, 'MEDIUM', 'notify56', 'Không tự gửi lại để tránh spam; cần kiểm tra Email/Telegram.'))

        backup_fail = 0
        if _table_exists(c, 'secure_backup_jobs'):
            backup_fail += _count(c, "SELECT COUNT(*) FROM secure_backup_jobs WHERE enabled=1 AND COALESCE(last_status,'')!='' AND UPPER(COALESCE(last_status,'')) NOT IN ('OK','PASS','SUCCESS','COMPLETED')")
        if _table_exists(c, 'scheduled_tasks'):
            backup_fail += _count(c, "SELECT COUNT(*) FROM scheduled_tasks WHERE enabled=1 AND LOWER(COALESCE(task_type,'')) LIKE '%backup%' AND COALESCE(last_status,'')!='' AND UPPER(COALESCE(last_status,'')) NOT IN ('OK','PASS','SUCCESS','COMPLETED','WAITING','QUEUED')")
        tasks.append(_task('backup_failures', 'Backup task cần kiểm tra', backup_fail, 'HIGH', 'backup', 'Tự động tạo DB backup an toàn; backup cấu hình lỗi vẫn cần kiểm tra.'))

        mfa_missing = 0
        if _table_exists(c, 'app_users'):
            mfa_missing = _count(c, "SELECT COUNT(*) FROM app_users WHERE COALESCE(enabled,1)=1 AND COALESCE(mfa_enabled,0)=0")
        tasks.append(_task('mfa_missing', 'Tài khoản đang hoạt động chưa bật MFA', mfa_missing, 'HIGH', 'secpost51', 'MFA không thể bật thay người dùng; cần enroll thủ công.'))

        endpoint_offline = 0
        endpoint_risk = 0
        if _table_exists(c, 'endpoint_agents58'):
            cutoff5 = (now - timedelta(minutes=5)).isoformat(timespec='seconds')
            endpoint_offline = _count(c, "SELECT COUNT(*) FROM endpoint_agents58 WHERE last_seen<?", (cutoff5,))
            endpoint_risk = _count(c, "SELECT COUNT(*) FROM endpoint_agents58 WHERE UPPER(COALESCE(firewall_status,''))='OFF' OR UPPER(COALESCE(antivirus_status,''))='OFF'")
        tasks.append(_task('endpoint_offline', 'Endpoint không check-in > 5 phút', endpoint_offline, 'HIGH', 'endpoint58', 'Tự động theo dõi; mất kết nối vẫn cần kiểm tra máy/agent.'))
        tasks.append(_task('endpoint_risk', 'Endpoint tắt Firewall/Antivirus', endpoint_risk, 'CRITICAL', 'endpoint58', 'Không tự bật bảo vệ từ xa; cần xác minh.'))

        line_poor = 0
        if _table_exists(c, 'network_quality59'):
            latest_line = c.execute("SELECT grade,created_at FROM network_quality59 WHERE test_type='LINE' ORDER BY id DESC LIMIT 1").fetchone()
            if latest_line and str(latest_line['grade'] or '').upper() == 'POOR':
                line_poor = 1
        tasks.append(_task('line_quality', 'Chất lượng đường truyền gần nhất kém', line_poor, 'HIGH', 'netspeed59', 'Tự động đo lại latency, jitter và packet loss.'))

        review = c.execute("SELECT reviewed_at FROM daily_security_reviews57 WHERE review_date=? AND username=?", (_today_key(), username)).fetchone() if username else None
        latest_auto = c.execute("SELECT * FROM daily_auto57_runs WHERE run_date=? ORDER BY id DESC LIMIT 1", (_today_key(),)).fetchone()

    latest_auto_d = dict(latest_auto) if latest_auto else None
    completed = set(_json_list(latest_auto_d.get('completed_keys_json')) if latest_auto_d else [])
    pending = set(_json_list(latest_auto_d.get('pending_keys_json')) if latest_auto_d else [])
    checked = set(_json_list(latest_auto_d.get('checked_keys_json')) if latest_auto_d else [])
    for t in tasks:
        key = t['key']
        t['auto_checked'] = key in checked
        t['auto_completed'] = key in completed and not t['needs_attention']
        t['auto_pending'] = key in pending and t['needs_attention']
        if t['auto_completed']:
            t['auto_status'] = 'AUTO_DONE'
        elif t['auto_pending']:
            t['auto_status'] = 'NEEDS_HUMAN'
        elif t['auto_checked']:
            t['auto_status'] = 'CHECKED'
        else:
            t['auto_status'] = 'NOT_RUN'

    priority = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    tasks.sort(key=lambda x: (0 if x['needs_attention'] else 1, priority.get(x['severity'], 9), x['title']))
    attention = sum(1 for x in tasks if x['needs_attention'])
    total_items = sum(x['count'] for x in tasks)
    auto = _auto_payload()
    return {
        'version': '5.9.2-cybersecurity', 'ui_feature': '6.9.0-safe-daily-auto', 'generated_at': utcnow(),
        'attention_categories': attention, 'attention_items': total_items,
        'all_clear': attention == 0, 'tasks': tasks,
        'reviewed_today': bool(review), 'reviewed_at': review['reviewed_at'] if review else None,
        'review_date': _today_key(), 'daily_auto': auto,
        'auto_completed_today': _auto_run_completed_today(latest_auto_d, attention),
        'note': 'Tự động hoàn thiện chỉ chạy kiểm tra/đồng bộ/bảo trì an toàn. Mục rủi ro còn tồn tại vẫn giữ trạng thái CẦN NGƯỜI XỬ LÝ; hệ thống không tự đóng cảnh báo/case hoặc thay đổi bảo mật.'
    }


def _auto_run_completed_today(latest_auto_d: dict | None, attention_categories: int) -> bool:
    """True only when the last safe-auto run succeeded AND the checklist is actually clear now.

    A successful execution (PASS) means the automation itself did not fail.  It must
    not be presented as "completed today" while any risk category still requires
    human attention.
    """
    return bool(latest_auto_d and latest_auto_d.get('status') == 'PASS' and int(attention_categories or 0) == 0)


def _safe_step(name: str, fn, details: dict) -> None:
    try:
        result = fn()
        details[name] = {'status': 'PASS', 'result': result}
    except Exception as exc:
        logger.exception('daily auto safe step failed step=%s', name)
        details[name] = {'status': 'FAIL', 'error': f'{type(exc).__name__}: {exc}'[:500]}


def _run_safe_daily_actions(actor_id: int, username: str) -> dict:
    """Run only bounded/non-destructive actions and return step evidence."""
    details: dict = {}

    def presence():
        from webapi.main import refresh_device_status
        r = refresh_device_status()
        return {k: r.get(k) for k in ('count','online','offline','unknown','managed_count','target_count')}

    def discovery():
        from webapi.autodiscovery5010 import ensure
        r = ensure(source='daily-auto-6.9', force=False)
        return {'state': r.get('state'), 'network': r.get('network'), 'active': r.get('active') or r.get('preliminary_active') or 0}

    def alerts():
        from modules.nms_v4 import evaluate_alert_rules
        created, recovered = evaluate_alert_rules()
        return {'created': int(created or 0), 'recovered': int(recovered or 0)}

    def incidents():
        from webapi.ops40 import sync_incidents_and_rca
        return sync_incidents_and_rca()

    def line_quality():
        from webapi.cybersecurity59 import run_line_test_internal
        r = run_line_test_internal(username or 'daily-auto')
        return {k: r.get(k) for k in ('grade','latency_ms','jitter_ms','packet_loss')}

    def db_backup():
        from webapi.reports37 import backup_db
        r = backup_db(int(actor_id or 0))
        return {'success': bool(r.get('success')), 'name': r.get('name')}

    for name, fn in (
        ('presence', presence), ('live_discovery', discovery), ('alert_rules', alerts),
        ('incident_rca', incidents), ('line_quality', line_quality), ('database_backup', db_backup),
    ):
        _safe_step(name, fn, details)
    return details


def run_daily_auto_once(actor_id: int, username: str) -> dict:
    ensure_tables57()
    started = utcnow()
    before = build_daily_summary(username)
    details = _run_safe_daily_actions(actor_id, username)
    # Discovery can continue asynchronously; current summary reflects all data available now.
    after = build_daily_summary(username)
    checked_keys = [str(t['key']) for t in after['tasks']]
    completed_keys = [str(t['key']) for t in after['tasks'] if not t['needs_attention']]
    pending_keys = [str(t['key']) for t in after['tasks'] if t['needs_attention']]
    failed_steps = [k for k, v in details.items() if v.get('status') == 'FAIL']
    status = 'PARTIAL' if failed_steps else 'PASS'
    finished = utcnow()
    summary_detail = {
        'safe_steps': details,
        'failed_steps': failed_steps,
        'completed_categories': len(completed_keys),
        'pending_categories': len(pending_keys),
        'safety': 'No alert/case closure, no vulnerability remediation, no MFA/credential/config/delete/restore action.',
    }
    with connection() as c:
        c.execute('''INSERT INTO daily_auto57_runs(
                     run_date,actor_username,status,before_items,after_items,
                     completed_keys_json,pending_keys_json,checked_keys_json,detail_json,started_at,finished_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
                  (_today_key(), username, status, int(before['attention_items']), int(after['attention_items']),
                   json.dumps(completed_keys), json.dumps(pending_keys), json.dumps(checked_keys),
                   json.dumps(summary_detail, ensure_ascii=False, default=str)[:12000], started, finished))
        c.execute('''UPDATE daily_auto57_state
                     SET last_run_at=?,last_status=?,last_detail=?,updated_at=?,run_count=run_count+1,
                         fail_count=fail_count+?,next_epoch=? WHERE id=1''',
                  (finished, status, f"{len(completed_keys)} nhóm sạch; {len(pending_keys)} nhóm còn cần xử lý", finished,
                   1 if failed_steps else 0, time.time() + AUTO_INTERVAL_SECONDS))
        c.commit()
    return {
        'ok': not failed_steps, 'status': status, 'started_at': started, 'finished_at': finished,
        'before_items': before['attention_items'], 'after_items': after['attention_items'],
        'completed_keys': completed_keys, 'pending_keys': pending_keys, 'details': summary_detail,
    }


class DailyAuto57:
    def __init__(self):
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.lock = threading.RLock()
        self.running = False

    def start(self) -> None:
        ensure_tables57()
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._loop, name='NA-DailyAuto57', daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=8)
        self.thread = None

    def _loop(self) -> None:
        while not self.stop_event.wait(10):
            try:
                with connection() as c:
                    s = c.execute('SELECT * FROM daily_auto57_state WHERE id=1').fetchone()
                if not s or not s['enabled']:
                    continue
                if float(s['next_epoch'] or 0) <= time.time():
                    self.run_async(int(s['actor_id'] or 0), str(s['actor_username'] or 'daily-auto'))
            except Exception:
                logger.exception('daily auto loop failed')

    def run_async(self, actor_id: int, username: str) -> bool:
        with self.lock:
            if self.running:
                return False
            self.running = True
        def worker():
            try:
                run_daily_auto_once(actor_id, username)
            finally:
                with self.lock:
                    self.running = False
        threading.Thread(target=worker, name='NA-DailyAuto57-Run', daemon=True).start()
        return True

    def enable(self, user: dict) -> dict:
        ensure_tables57()
        with connection() as c:
            c.execute('''UPDATE daily_auto57_state SET enabled=1,actor_id=?,actor_username=?,enabled_at=?,disabled_at=NULL,
                         updated_at=?,next_epoch=0,last_status='STARTING',last_detail='Safe daily auto-completion enabled' WHERE id=1''',
                      (int(user['id']), str(user['username']), utcnow(), utcnow()))
            c.commit()
        self.run_async(int(user['id']), str(user['username']))
        return _auto_payload()

    def disable(self, user: dict) -> dict:
        with connection() as c:
            c.execute('''UPDATE daily_auto57_state SET enabled=0,disabled_at=?,updated_at=?,last_status='STOPPED',last_detail=? WHERE id=1''',
                      (utcnow(), utcnow(), f"Disabled by {user['username']}"))
            c.commit()
        return _auto_payload()


daily_auto_engine = DailyAuto57()


@router.get('/daily')
def daily(request: Request):
    user = require_role(request)
    return build_daily_summary(user['username'])


@router.post('/daily/reviewed')
def mark_reviewed(request: Request):
    user = require_role(request, 'Admin', 'Analyst', 'Operator')
    summary = build_daily_summary(user['username'])
    compact = {'attention_categories': summary['attention_categories'], 'attention_items': summary['attention_items']}
    with connection() as c:
        c.execute("""INSERT INTO daily_security_reviews57(review_date,username,reviewed_at,summary_json)
                     VALUES(?,?,?,?)
                     ON CONFLICT(review_date,username) DO UPDATE SET reviewed_at=excluded.reviewed_at,summary_json=excluded.summary_json""",
                  (_today_key(), user['username'], utcnow(), json.dumps(compact, separators=(',', ':'))))
        c.commit()
    return {'ok': True, 'review_date': _today_key(), 'reviewed_at': utcnow(), **compact}


@router.get('/daily/auto/status')
def daily_auto_status(request: Request):
    require_role(request)
    return _auto_payload()


@router.post('/daily/auto/enable')
def daily_auto_enable(request: Request):
    user = require_role(request, 'Admin')
    return daily_auto_engine.enable(user)


@router.post('/daily/auto/disable')
def daily_auto_disable(request: Request):
    user = require_role(request, 'Admin')
    return daily_auto_engine.disable(user)


@router.post('/daily/auto/run-now')
def daily_auto_run_now(request: Request):
    user = require_role(request, 'Admin')
    started = daily_auto_engine.run_async(int(user['id']), str(user['username']))
    return {'ok': True, 'started': started, **_auto_payload()}
