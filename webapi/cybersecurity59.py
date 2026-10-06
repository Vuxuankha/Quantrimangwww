"""Cybersecurity 5.9 network speed and line-quality diagnostics.

Read-only diagnostics. Lightweight quality tests measure ICMP latency/loss/jitter to the
current gateway and a public probe. Bandwidth tests are explicit user actions because
they consume traffic and contact a third-party speed-test endpoint.
"""
from __future__ import annotations

import math
import os
import socket
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from modules.icmp_probe import icmp_ping
from webapi.platform50 import network_connectivity, network_identity_status
from webapi.runtime37 import connection, utcnow
from webapi.security37 import require_role

router = APIRouter(prefix='/api/v59', tags=['Cybersecurity 5.9'])

DEFAULT_DOWNLOAD_URL = os.environ.get('NA_SPEEDTEST_DOWNLOAD_URL', 'https://speed.cloudflare.com/__down')
DEFAULT_UPLOAD_URL = os.environ.get('NA_SPEEDTEST_UPLOAD_URL', 'https://speed.cloudflare.com/__up')
PUBLIC_PROBE = os.environ.get('NA_LINE_PUBLIC_PROBE', '1.1.1.1')


class SpeedTestIn(BaseModel):
    download_mb: int = Field(default=5, ge=1, le=25)
    upload_mb: int = Field(default=2, ge=1, le=10)
    run_upload: bool = True
    confirm_bandwidth_use: bool = False


class OptimizeLineIn(BaseModel):
    confirm_system_change: bool = False


class BrowserReportIn(BaseModel):
    latency_ms: float | None = Field(default=None, ge=0, le=60000)
    jitter_ms: float | None = Field(default=None, ge=0, le=60000)
    packet_loss: float | None = Field(default=None, ge=0, le=100)
    download_mbps: float | None = Field(default=None, ge=0, le=100000)
    upload_mbps: float | None = Field(default=None, ge=0, le=100000)
    effective_type: str = Field(default='', max_length=40)
    downlink_hint: float | None = Field(default=None, ge=0, le=100000)
    rtt_hint: float | None = Field(default=None, ge=0, le=60000)
    save_data: bool = False
    test_type: str = Field(default='BROWSER_LINE', max_length=32)


def _client_public_ip(request: Request) -> str:
    """Return the end-user public IP as observed by Render/proxy headers.

    This is intentionally *not* presented as a private LAN address. Browsers do
    not expose a reliable 192.168.x.x address, gateway, ARP table or raw ICMP
    sockets, especially on mobile.
    """
    xff = str(request.headers.get('x-forwarded-for') or '').strip()
    if xff:
        return xff.split(',', 1)[0].strip()[:80]
    real = str(request.headers.get('x-real-ip') or '').strip()
    if real:
        return real[:80]
    return str(getattr(request.client, 'host', '') or '')[:80]


def _browser_identity(request: Request) -> dict[str, Any]:
    return {
        'local_ip': _client_public_ip(request),
        'gateway': '',
        'adapter': 'Browser / HTTPS',
        'mode': 'BROWSER',
        'source': 'BROWSER',
        'hostname': '',
        'endpoint_id': '',
        'checked_at': utcnow(),
    }


def ensure_tables59() -> None:
    with connection() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS network_quality59(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          test_type TEXT NOT NULL,
          target TEXT,
          gateway TEXT,
          local_ip TEXT,
          network_mode TEXT,
          latency_ms REAL,
          jitter_ms REAL,
          packet_loss REAL,
          download_mbps REAL,
          upload_mbps REAL,
          grade TEXT NOT NULL,
          detail TEXT,
          created_by TEXT,
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_network_quality59_time ON network_quality59(created_at DESC);
        ''')
        c.commit()


def _primary_network() -> dict[str, Any]:
    ident = network_identity_status(force=True)
    return {'local_ip': str(ident.get('ipv4') or ''), 'gateway': str(ident.get('gateway') or ''),
            'adapter': str(ident.get('adapter') or ''), 'mode': ident.get('mode') or 'OFFLINE',
            'source': str(ident.get('source') or 'WEB_HOST'), 'hostname': str(ident.get('hostname') or ''),
            'endpoint_id': '', 'checked_at': ident.get('checked_at')}

def _web_only_browser_mode() -> bool:
    return str(os.environ.get('NA_WEB_ONLY_BROWSER','')).strip().lower() in ('1','true','yes','on')


def _icmp_series(target: str, samples: int = 4, timeout_ms: int = 1000) -> dict[str, Any]:
    values: list[float] = []
    replies = 0
    errors: list[str] = []
    for _ in range(samples):
        r = icmp_ping(target, timeout_ms=timeout_ms, count=1)
        if r.get('status') == 'Online':
            replies += 1
            if r.get('response') is not None:
                values.append(float(r['response']))
        elif r.get('error'):
            errors.append(str(r['error']))
        time.sleep(0.05)
    loss = round((samples - replies) * 100.0 / samples, 1)
    latency = round(sum(values) / len(values), 2) if values else None
    jitter = round(statistics.pstdev(values), 2) if len(values) > 1 else (0.0 if values else None)
    return {'target': target, 'samples': samples, 'replies': replies, 'packet_loss': loss, 'latency_ms': latency, 'jitter_ms': jitter, 'errors': errors[:4]}


def _grade(latency: float | None, jitter: float | None, loss: float | None) -> str:
    if latency is None or loss is None or loss >= 25:
        return 'POOR'
    j = 999.0 if jitter is None else jitter
    if loss == 0 and latency < 30 and j < 10:
        return 'EXCELLENT'
    if loss <= 1 and latency < 60 and j < 20:
        return 'GOOD'
    if loss <= 3 and latency < 120 and j < 40:
        return 'FAIR'
    return 'POOR'



def _run_windows_command(args: list[str], timeout: int = 15) -> dict[str, Any]:
    """Run one bounded Windows networking command and return auditable output.

    Commands are fixed by the application, never user supplied.  A failed command is
    reported instead of aborting the whole optimization so the after-test still runs.
    """
    try:
        cp = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        out = (cp.stdout or cp.stderr or '').strip().replace('\r', '')
        return {'command': ' '.join(args[:3]), 'ok': cp.returncode == 0,
                'returncode': int(cp.returncode), 'detail': out[-800:] or ('OK' if cp.returncode == 0 else 'FAILED')}
    except Exception as exc:
        return {'command': ' '.join(args[:3]), 'ok': False, 'returncode': None,
                'detail': f'{type(exc).__name__}: {str(exc)[:300]}'}


def _safe_windows_line_optimization() -> list[dict[str, Any]]:
    """Apply only conservative Windows network repairs that do not invent bandwidth.

    - DNS cache flush can clear stale resolution state.
    - TCP receive auto-tuning NORMAL restores Windows dynamic receive-window behavior
      if it had previously been disabled/restricted.
    These changes cannot exceed the ISP/router/link capacity and that limitation is
    intentionally surfaced to the UI.
    """
    if sys.platform != 'win32':
        return [{'command': 'windows-network-optimization', 'ok': False, 'returncode': None,
                 'detail': 'UNSUPPORTED_PLATFORM'}]
    return [
        _run_windows_command(['ipconfig', '/flushdns']),
        _run_windows_command(['netsh', 'interface', 'tcp', 'set', 'global', 'autotuninglevel=normal']),
    ]


def _improvement(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    def n(v):
        try:
            return float(v)
        except (TypeError, ValueError):
            return None
    bl, al = n(before.get('latency_ms')), n(after.get('latency_ms'))
    bj, aj = n(before.get('jitter_ms')), n(after.get('jitter_ms'))
    bp, ap = n(before.get('packet_loss')), n(after.get('packet_loss'))
    latency_delta = round(bl - al, 2) if bl is not None and al is not None else None
    jitter_delta = round(bj - aj, 2) if bj is not None and aj is not None else None
    loss_delta = round(bp - ap, 2) if bp is not None and ap is not None else None
    improved = any(x is not None and x > 0 for x in (latency_delta, jitter_delta, loss_delta))
    return {'improved': improved, 'latency_reduction_ms': latency_delta,
            'jitter_reduction_ms': jitter_delta, 'packet_loss_reduction_pct': loss_delta}

def _https_probe(timeout: float = 3.0) -> dict[str, Any]:
    started = time.monotonic()
    try:
        req = urllib.request.Request('https://1.1.1.1/', method='HEAD', headers={'User-Agent': 'NetworkAutomation/5.9'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {'ok': True, 'status': int(getattr(r, 'status', 200)), 'elapsed_ms': round((time.monotonic()-started)*1000, 1)}
    except Exception as exc:
        return {'ok': False, 'error': type(exc).__name__, 'elapsed_ms': round((time.monotonic()-started)*1000, 1)}


def _store(test_type: str, user: str, ident: dict[str, Any], result: dict[str, Any]) -> int:
    ensure_tables59()
    with connection() as c:
        cur = c.execute('''INSERT INTO network_quality59(test_type,target,gateway,local_ip,network_mode,latency_ms,jitter_ms,packet_loss,download_mbps,upload_mbps,grade,detail,created_by,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
            test_type, str(result.get('target') or ''), ident.get('gateway') or '', ident.get('local_ip') or '', ident.get('mode') or '',
            result.get('latency_ms'), result.get('jitter_ms'), result.get('packet_loss'), result.get('download_mbps'), result.get('upload_mbps'),
            result.get('grade') or 'UNKNOWN', str(result.get('detail') or '')[:2000], user, utcnow()))
        c.commit()
        return int(cur.lastrowid)


def _download_test(megabytes: int) -> float:
    byte_count = int(megabytes) * 1024 * 1024
    url = DEFAULT_DOWNLOAD_URL + ('&' if '?' in DEFAULT_DOWNLOAD_URL else '?') + urllib.parse.urlencode({'bytes': byte_count})
    req = urllib.request.Request(url, headers={'User-Agent': 'NetworkAutomation/5.9', 'Cache-Control': 'no-cache'})
    started = time.monotonic(); received = 0
    with urllib.request.urlopen(req, timeout=30) as r:
        while received < byte_count:
            chunk = r.read(min(256 * 1024, byte_count - received))
            if not chunk:
                break
            received += len(chunk)
    elapsed = max(time.monotonic() - started, 0.001)
    if received < 256 * 1024:
        raise RuntimeError('SPEEDTEST_DOWNLOAD_TOO_SMALL')
    return round((received * 8.0 / 1_000_000.0) / elapsed, 2)


def _upload_test(megabytes: int) -> float:
    byte_count = int(megabytes) * 1024 * 1024
    body = b'0' * byte_count
    req = urllib.request.Request(DEFAULT_UPLOAD_URL, data=body, method='POST', headers={
        'User-Agent': 'NetworkAutomation/5.9', 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-cache'})
    started = time.monotonic()
    with urllib.request.urlopen(req, timeout=30) as r:
        r.read(1024)
    elapsed = max(time.monotonic() - started, 0.001)
    return round((byte_count * 8.0 / 1_000_000.0) / elapsed, 2)


@router.get('/network/summary')
def summary(request: Request):
    user = require_role(request)
    ensure_tables59()
    if _web_only_browser_mode():
        ident = _browser_identity(request)
        with connection() as c:
            latest = c.execute("SELECT * FROM network_quality59 WHERE test_type LIKE 'BROWSER_%' AND created_by=? ORDER BY id DESC LIMIT 1", (user['username'],)).fetchone()
            speed = c.execute("SELECT * FROM network_quality59 WHERE test_type='BROWSER_SPEED' AND created_by=? ORDER BY id DESC LIMIT 1", (user['username'],)).fetchone()
            line = c.execute("SELECT * FROM network_quality59 WHERE test_type='BROWSER_LINE' AND created_by=? ORDER BY id DESC LIMIT 1", (user['username'],)).fetchone()
        return {'identity': ident, 'latest': dict(latest) if latest else None, 'latest_speed': dict(speed) if speed else None,
                'latest_line': dict(line) if line else None, 'speed_provider': 'Thiết bị đang mở Web ↔ Render',
                'note': 'Web tự nhận IP Internet công khai và đo chất lượng kết nối từ chính trình duyệt. Không cần tiến trình cục bộ.'}
    ident = _primary_network()
    with connection() as c:
        latest = c.execute("SELECT * FROM network_quality59 ORDER BY id DESC LIMIT 1").fetchone()
        speed = c.execute("SELECT * FROM network_quality59 WHERE test_type='SPEED' ORDER BY id DESC LIMIT 1").fetchone()
        line = c.execute("SELECT * FROM network_quality59 WHERE test_type='LINE' ORDER BY id DESC LIMIT 1").fetchone()
    return {'identity':ident,'latest':dict(latest) if latest else None,'latest_speed':dict(speed) if speed else None,
            'latest_line':dict(line) if line else None,'speed_provider':'Web host','note':'Local server diagnostics.'}


@router.get('/browser/probe')
def browser_probe(request: Request):
    user = require_role(request)
    return {
        'mode': 'BROWSER',
        'public_ip': _client_public_ip(request),
        'server_time': utcnow(),
        'username': user.get('username'),
        'note': 'Public IP is observed by the Web server. Private LAN IP/gateway are not exposed reliably by modern browsers.'
    }


@router.get('/browser/ping')
def browser_ping(request: Request):
    require_role(request)
    return Response(content=b'ok', media_type='text/plain', headers={'Cache-Control': 'no-store'})


@router.get('/browser/download')
def browser_download(request: Request, bytes: int = 2 * 1024 * 1024):
    require_role(request, 'Admin', 'Analyst', 'Operator')
    size = max(64 * 1024, min(int(bytes), 8 * 1024 * 1024))
    return Response(content=os.urandom(size), media_type='application/octet-stream', headers={
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Content-Length': str(size),
        'X-NA-Browser-Test': 'download',
    })


@router.post('/browser/upload')
async def browser_upload(request: Request):
    require_role(request, 'Admin', 'Analyst', 'Operator')
    body = await request.body()
    if len(body) > 4 * 1024 * 1024:
        raise HTTPException(413, 'BROWSER_UPLOAD_TOO_LARGE')
    return {'received_bytes': len(body), 'server_time': utcnow()}


@router.post('/browser/report')
def browser_report(payload: BrowserReportIn, request: Request):
    user = require_role(request, 'Admin', 'Analyst', 'Operator')
    test_type = str(payload.test_type or 'BROWSER_LINE').upper()
    if test_type not in {'BROWSER_LINE', 'BROWSER_SPEED'}:
        raise HTTPException(400, 'INVALID_BROWSER_TEST_TYPE')
    ident = _browser_identity(request)
    grade = _grade(payload.latency_ms, payload.jitter_ms, payload.packet_loss)
    hints = f"effective_type={payload.effective_type or '-'}; downlink_hint={payload.downlink_hint}; rtt_hint={payload.rtt_hint}; save_data={payload.save_data}"
    result = {
        'target': 'THIS_WEB_SERVICE',
        'latency_ms': payload.latency_ms, 'jitter_ms': payload.jitter_ms,
        'packet_loss': payload.packet_loss, 'download_mbps': payload.download_mbps,
        'upload_mbps': payload.upload_mbps, 'grade': grade,
        'detail': 'Measured in the end-user browser over HTTPS to Render; ' + hints,
    }
    result['id'] = _store(test_type, user['username'], ident, result)
    result['identity'] = ident
    result['source'] = 'BROWSER'
    return result

def run_line_test_internal(username: str = 'system'):
    ident = _primary_network(); gateway = str(ident.get('gateway') or '')
    gw = _icmp_series(gateway, 4, 1000) if gateway else None
    public = _icmp_series(PUBLIC_PROBE, 4, 1200)
    chosen = public if public.get('replies', 0) else (gw or public)
    grade = _grade(chosen.get('latency_ms'), chosen.get('jitter_ms'), chosen.get('packet_loss'))
    https = _https_probe()
    result = {**chosen, 'grade': grade, 'gateway_probe': gw, 'public_probe': public, 'https_probe': https,
              'target': chosen.get('target') or PUBLIC_PROBE,
              'detail': f"gateway={gateway or '-'}; https={'OK' if https.get('ok') else 'FAIL'}"}
    result['id'] = _store('LINE', username or 'system', ident, result)
    result['identity'] = ident
    return result


@router.post('/network/line-test')
def line_test(request: Request):
    user = require_role(request, 'Admin', 'Analyst', 'Operator')
    if _web_only_browser_mode():
        raise HTTPException(409, 'BROWSER_MEASUREMENT_REQUIRED')
    return run_line_test_internal(user['username'])


@router.post('/network/speed-test')
def speed_test(payload: SpeedTestIn, request: Request):
    user = require_role(request, 'Admin', 'Analyst', 'Operator')
    if not payload.confirm_bandwidth_use:
        raise HTTPException(400, 'BANDWIDTH_CONFIRMATION_REQUIRED')
    if _web_only_browser_mode():
        raise HTTPException(409, 'BROWSER_MEASUREMENT_REQUIRED')
    ident = _primary_network()
    if ident.get('mode') not in {'LAN+WAN', 'WAN'}:
        raise HTTPException(409, 'WAN_NOT_AVAILABLE')
    before = _icmp_series(PUBLIC_PROBE, 4, 1200)
    try:
        down = _download_test(payload.download_mb)
        up = _upload_test(payload.upload_mb) if payload.run_upload else None
    except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as exc:
        raise HTTPException(502, 'SPEEDTEST_FAILED: ' + str(exc)[:180])
    after = _icmp_series(PUBLIC_PROBE, 4, 1200)
    latency = after.get('latency_ms') if after.get('latency_ms') is not None else before.get('latency_ms')
    jitter = after.get('jitter_ms') if after.get('jitter_ms') is not None else before.get('jitter_ms')
    loss = max(float(before.get('packet_loss') or 0), float(after.get('packet_loss') or 0))
    grade = _grade(latency, jitter, loss)
    result = {'target': DEFAULT_DOWNLOAD_URL, 'download_mbps': down, 'upload_mbps': up, 'latency_ms': latency,
              'jitter_ms': jitter, 'packet_loss': loss, 'grade': grade,
              'download_mb': payload.download_mb, 'upload_mb': payload.upload_mb if payload.run_upload else 0,
              'detail': 'Manual WAN bandwidth test; third-party endpoint contacted explicitly by user.'}
    result['id'] = _store('SPEED', user['username'], ident, result)
    result['identity'] = ident
    return result


@router.post('/network/optimize')
def optimize_line(payload: OptimizeLineIn, request: Request):
    user = require_role(request, 'Admin')
    if not payload.confirm_system_change:
        raise HTTPException(400, 'SYSTEM_CHANGE_CONFIRMATION_REQUIRED')
    if _web_only_browser_mode():
        raise HTTPException(409, 'BROWSER_ONLY_NO_SYSTEM_CHANGES')
    ident=_primary_network()
    before = run_line_test_internal(user['username'])
    if str(before.get('grade') or '').upper() in {'EXCELLENT', 'GOOD'}:
        return {
            'status': 'NOT_NEEDED', 'before': before, 'after': before, 'actions': [],
            'improvement': _improvement(before, before),
            'message': 'Đường truyền hiện không ở mức lag cần tối ưu. Không thay đổi cấu hình Windows.',
            'capacity_note': 'Ứng dụng không thể tăng vượt giới hạn gói cước, Wi-Fi/router hoặc đường truyền ISP.'
        }

    actions = _safe_windows_line_optimization()
    time.sleep(0.6)
    after = run_line_test_internal(user['username'])
    ok_actions = sum(1 for a in actions if a.get('ok'))
    return {
        'status': 'APPLIED' if ok_actions else 'NO_CHANGE',
        'before': before, 'after': after, 'actions': actions,
        'improvement': _improvement(before, after),
        'message': f'Đã áp dụng {ok_actions}/{len(actions)} tối ưu an toàn và đo lại đường truyền.',
        'capacity_note': 'Tối ưu chỉ xử lý cấu hình cục bộ có thể gây trễ; không thể tự tăng băng thông vượt tốc độ do Wi-Fi/router/ISP cung cấp.'
    }


@router.get('/network/history')
def history(request: Request, limit: int = 100):
    user = require_role(request)
    ensure_tables59(); limit = max(1, min(int(limit), 500))
    if _web_only_browser_mode():
        with connection() as c:
            return [dict(r) for r in c.execute("SELECT * FROM network_quality59 WHERE test_type LIKE 'BROWSER_%' AND created_by=? ORDER BY id DESC LIMIT ?", (user['username'], limit)).fetchall()]
    with connection() as c:
        return [dict(r) for r in c.execute("SELECT * FROM network_quality59 ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]
