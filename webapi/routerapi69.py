"""Hotfix16Q router/controller API integration for hosted Web mode.

The Render host never scans its own LAN. Device discovery comes from either:
- a read-only HTTPS router/controller API reachable from the hosted service, or
- a browser-direct HTTPS API that the user's browser is allowed to call via CORS.

Secrets for server-side providers are encrypted with the application's existing
Fernet credential key. Browser-direct secrets are intentionally not returned by
this API and are supplied only in the browser session.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from modules.nms_v5 import decrypt_secret, encrypt_secret
from webapi.runtime37 import connection, utcnow
from webapi.security37 import require_role

router = APIRouter(prefix='/api/v69', tags=['Router API 6.9'])

PROVIDERS = {
    'mikrotik_rest': 'MikroTik RouterOS REST (server HTTPS)',
    'unifi_cloud': 'UniFi Cloud Connector (server HTTPS)',
    'generic_server': 'Generic JSON API (server HTTPS)',
    'generic_browser': 'Generic JSON API (browser direct HTTPS/CORS)',
}
SERVER_PROVIDERS = {'mikrotik_rest', 'unifi_cloud', 'generic_server'}
BROWSER_PROVIDERS = {'generic_browser'}
MAC_RE = re.compile(r'^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$')


def _web_only() -> bool:
    return str(os.environ.get('NA_WEB_ONLY_BROWSER', '')).strip().lower() in ('1', 'true', 'yes', 'on')


def ensure_tables69() -> None:
    with connection() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS web_router_api_config69(
          id INTEGER PRIMARY KEY CHECK(id=1),
          enabled INTEGER NOT NULL DEFAULT 0,
          provider TEXT NOT NULL DEFAULT 'generic_browser',
          base_url TEXT NOT NULL DEFAULT '',
          username TEXT NOT NULL DEFAULT '',
          secret_enc TEXT NOT NULL DEFAULT '',
          token_enc TEXT NOT NULL DEFAULT '',
          verify_tls INTEGER NOT NULL DEFAULT 1,
          options_json TEXT NOT NULL DEFAULT '{}',
          updated_at TEXT NOT NULL DEFAULT ''
        );
        INSERT OR IGNORE INTO web_router_api_config69(id,updated_at) VALUES(1,datetime('now'));
        CREATE TABLE IF NOT EXISTS web_router_api_observations69(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          provider TEXT NOT NULL,
          ip TEXT NOT NULL,
          mac TEXT NOT NULL DEFAULT '',
          hostname TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'Observed',
          interface TEXT NOT NULL DEFAULT '',
          detail TEXT NOT NULL DEFAULT '',
          observed_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_router_obs69_ip_time ON web_router_api_observations69(ip,observed_at DESC);
        ''')
        c.commit()


def _json_options(raw: str | None) -> dict[str, Any]:
    try:
        d = json.loads(raw or '{}')
    except Exception:
        d = {}
    return d if isinstance(d, dict) else {}


def _read_config(include_secret: bool = False) -> dict[str, Any]:
    ensure_tables69()
    with connection() as c:
        r = c.execute('SELECT * FROM web_router_api_config69 WHERE id=1').fetchone()
    d = dict(r) if r else {}
    out = {
        'enabled': bool(d.get('enabled')),
        'provider': str(d.get('provider') or 'generic_browser'),
        'base_url': str(d.get('base_url') or ''),
        'username': str(d.get('username') or ''),
        'verify_tls': bool(d.get('verify_tls', 1)),
        'options': _json_options(d.get('options_json')),
        'has_secret': bool(d.get('secret_enc')),
        'has_token': bool(d.get('token_enc')),
        'updated_at': str(d.get('updated_at') or ''),
    }
    if include_secret:
        try:
            out['secret'] = decrypt_secret(d.get('secret_enc') or '') if d.get('secret_enc') else ''
        except Exception as exc:
            raise HTTPException(500, 'ROUTER_SECRET_UNAVAILABLE: ' + type(exc).__name__) from None
        try:
            out['token'] = decrypt_secret(d.get('token_enc') or '') if d.get('token_enc') else ''
        except Exception as exc:
            raise HTTPException(500, 'ROUTER_TOKEN_UNAVAILABLE: ' + type(exc).__name__) from None
    return out


class RouterConfigIn(BaseModel):
    enabled: bool = False
    provider: str = Field(default='generic_browser', max_length=40)
    base_url: str = Field(default='', max_length=600)
    username: str = Field(default='', max_length=160)
    secret: str = Field(default='', max_length=4096)
    token: str = Field(default='', max_length=8192)
    clear_secret: bool = False
    clear_token: bool = False
    verify_tls: bool = True
    options: dict[str, Any] = Field(default_factory=dict)


class RouterObservationIn(BaseModel):
    provider: str = Field(default='generic_browser', max_length=40)
    clients: list[dict[str, Any]] = Field(default_factory=list, max_length=2048)


class RouterImportIn(BaseModel):
    clients: list[dict[str, Any]] = Field(default_factory=list, max_length=1024)


def _validate_base_url(base_url: str, provider: str) -> str:
    base = str(base_url or '').strip().rstrip('/')
    if provider == 'unifi_cloud' and not base:
        base = 'https://api.ui.com'
    if not base:
        raise HTTPException(400, 'ROUTER_API_BASE_URL_REQUIRED')
    try:
        u = urllib.parse.urlsplit(base)
    except Exception:
        raise HTTPException(400, 'ROUTER_API_URL_INVALID') from None
    if u.scheme.lower() != 'https':
        raise HTTPException(400, 'ROUTER_API_HTTPS_REQUIRED')
    if not u.hostname or u.username or u.password:
        raise HTTPException(400, 'ROUTER_API_URL_INVALID')
    if u.fragment:
        raise HTTPException(400, 'ROUTER_API_URL_FRAGMENT_NOT_ALLOWED')
    return base


def _resolved_addresses(host: str, port: int) -> list[str]:
    try:
        rows = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise HTTPException(502, 'ROUTER_API_DNS_FAILED') from None
    out: list[str] = []
    for row in rows:
        addr = str(row[4][0]).split('%', 1)[0]
        if addr not in out:
            out.append(addr)
    return out


def _assert_server_destination(base_url: str) -> None:
    """Prevent a hosted API from becoming an SSRF bridge into Render/private networks."""
    u = urllib.parse.urlsplit(base_url)
    host = str(u.hostname or '')
    if host.lower() in {'localhost', 'localhost.localdomain'} or host.lower().endswith('.local'):
        raise HTTPException(400, 'ROUTER_API_PRIVATE_DESTINATION_BLOCKED')
    port = int(u.port or 443)
    if not _web_only():
        return
    for raw in _resolved_addresses(host, port):
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            raise HTTPException(400, 'ROUTER_API_DESTINATION_INVALID') from None
        if not addr.is_global:
            raise HTTPException(400, 'ROUTER_API_PRIVATE_DESTINATION_BLOCKED: hosted mode only calls public HTTPS/cloud endpoints')


def _join_url(base: str, endpoint: str) -> str:
    ep = str(endpoint or '').strip()
    if not ep.startswith('/'):
        ep = '/' + ep
    url = base.rstrip('/') + ep
    bu = urllib.parse.urlsplit(base)
    uu = urllib.parse.urlsplit(url)
    if (bu.scheme.lower(), bu.hostname, bu.port or 443) != (uu.scheme.lower(), uu.hostname, uu.port or 443):
        raise HTTPException(400, 'ROUTER_API_ENDPOINT_MUST_STAY_ON_BASE_ORIGIN')
    return url


class _NoRedirect69(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPException(502, 'ROUTER_API_REDIRECT_BLOCKED')


def _http_json(url: str, *, username: str = '', secret: str = '', token: str = '', auth_mode: str = 'none', token_header: str = 'Authorization', timeout: float = 12.0, verify_tls: bool = True) -> Any:
    if not verify_tls and _web_only():
        raise HTTPException(400, 'ROUTER_API_TLS_VERIFY_REQUIRED_ON_HOSTED_WEB')
    headers = {'Accept': 'application/json', 'User-Agent': 'NetworkAutomation/6.9 RouterAPI'}
    mode = str(auth_mode or 'none').lower()
    if mode == 'basic':
        if not username or not secret:
            raise HTTPException(400, 'ROUTER_API_BASIC_CREDENTIAL_REQUIRED')
        blob = base64.b64encode((username + ':' + secret).encode('utf-8')).decode('ascii')
        headers['Authorization'] = 'Basic ' + blob
    elif mode == 'bearer':
        if not token:
            raise HTTPException(400, 'ROUTER_API_TOKEN_REQUIRED')
        headers['Authorization'] = 'Bearer ' + token
    elif mode == 'x-api-key':
        if not token:
            raise HTTPException(400, 'ROUTER_API_TOKEN_REQUIRED')
        h = str(token_header or 'X-API-Key').strip()
        if not re.fullmatch(r'[A-Za-z0-9-]{1,64}', h):
            raise HTTPException(400, 'ROUTER_API_TOKEN_HEADER_INVALID')
        headers[h] = token
    elif mode != 'none':
        raise HTTPException(400, 'ROUTER_API_AUTH_MODE_UNSUPPORTED')
    req = urllib.request.Request(url, headers=headers, method='GET')
    ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()  # noqa: SLF001
    try:
        opener=urllib.request.build_opener(_NoRedirect69, urllib.request.HTTPSHandler(context=ctx))
        with opener.open(req, timeout=max(2.0, min(float(timeout), 25.0))) as response:
            raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise HTTPException(502, 'ROUTER_API_RESPONSE_TOO_LARGE')
            ctype = str(response.headers.get('content-type') or '').lower()
            if 'json' not in ctype and raw[:1] not in (b'{', b'['):
                raise HTTPException(502, 'ROUTER_API_RESPONSE_NOT_JSON')
    except HTTPException:
        raise
    except urllib.error.HTTPError as exc:
        code = int(getattr(exc, 'code', 502) or 502)
        if code in (401, 403):
            raise HTTPException(502, 'ROUTER_API_AUTH_FAILED') from None
        raise HTTPException(502, f'ROUTER_API_HTTP_{code}') from None
    except urllib.error.URLError as exc:
        reason = type(getattr(exc, 'reason', exc)).__name__
        raise HTTPException(502, 'ROUTER_API_UNREACHABLE: ' + reason) from None
    except TimeoutError:
        raise HTTPException(504, 'ROUTER_API_TIMEOUT') from None
    try:
        return json.loads(raw.decode('utf-8'))
    except Exception:
        raise HTTPException(502, 'ROUTER_API_INVALID_JSON') from None


def _dot_get(data: Any, path: str, default: Any = None) -> Any:
    if not path:
        return data
    cur = data
    for part in str(path).split('.'):
        if isinstance(cur, dict):
            cur = cur.get(part, default)
        elif isinstance(cur, list) and part.isdigit():
            idx = int(part)
            cur = cur[idx] if 0 <= idx < len(cur) else default
        else:
            return default
    return cur


def _clean_mac(value: Any) -> str:
    s = str(value or '').strip()
    if not s:
        return ''
    s = s.replace('-', ':').upper()
    return s if MAC_RE.fullmatch(s) else ''


def _clean_ip(value: Any) -> str:
    try:
        addr = ipaddress.ip_address(str(value or '').strip())
        return str(addr) if addr.version == 4 else ''
    except ValueError:
        return ''


def _normalize_client(row: dict[str, Any], *, ip_field='ip', mac_field='mac', hostname_field='hostname', status_field='status', interface_field='interface', online_values: set[str] | None = None) -> dict[str, Any] | None:
    ip = _clean_ip(_dot_get(row, ip_field, ''))
    mac = _clean_mac(_dot_get(row, mac_field, ''))
    if not ip and not mac:
        return None
    raw_status = str(_dot_get(row, status_field, '') or '').strip()
    online = {x.lower() for x in (online_values or {'online', 'active', 'bound', 'connected', 'true', '1'})}
    status = 'Online' if raw_status.lower() in online else ('Observed' if not raw_status else raw_status[:80])
    return {
        'ip': ip,
        'mac': mac,
        'hostname': str(_dot_get(row, hostname_field, '') or '')[:255],
        'status': status,
        'interface': str(_dot_get(row, interface_field, '') or '')[:255],
    }


def _normalize_generic(payload: Any, options: dict[str, Any]) -> list[dict[str, Any]]:
    rows = _dot_get(payload, str(options.get('list_path') or ''), payload)
    if isinstance(rows, dict):
        rows = list(rows.values())
    if not isinstance(rows, list):
        raise HTTPException(502, 'ROUTER_API_CLIENT_LIST_NOT_FOUND')
    online_values = {x.strip().lower() for x in str(options.get('online_values') or 'online,active,bound,connected,true,1').split(',') if x.strip()}
    out = []
    for row in rows[:2048]:
        if not isinstance(row, dict):
            continue
        d = _normalize_client(
            row,
            ip_field=str(options.get('ip_field') or 'ip'),
            mac_field=str(options.get('mac_field') or 'mac'),
            hostname_field=str(options.get('hostname_field') or 'hostname'),
            status_field=str(options.get('status_field') or 'status'),
            interface_field=str(options.get('interface_field') or 'interface'),
            online_values=online_values,
        )
        if d:
            out.append(d)
    return _dedupe(out)


def _dedupe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = str(row.get('mac') or row.get('ip') or '').upper()
        if not key:
            continue
        if key not in merged:
            merged[key] = dict(row)
            continue
        cur = merged[key]
        for field in ('ip', 'mac', 'hostname', 'interface'):
            if not cur.get(field) and row.get(field):
                cur[field] = row[field]
        if row.get('status') == 'Online':
            cur['status'] = 'Online'
    return list(merged.values())


def _fetch_mikrotik(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    base = _validate_base_url(cfg['base_url'], 'mikrotik_rest')
    _assert_server_destination(base)
    root = base.rstrip('/')
    if not root.lower().endswith('/rest'):
        root += '/rest'
    username, secret = cfg.get('username', ''), cfg.get('secret', '')
    leases = _http_json(_join_url(root, '/ip/dhcp-server/lease'), username=username, secret=secret, auth_mode='basic', verify_tls=cfg.get('verify_tls', True))
    arp = _http_json(_join_url(root, '/ip/arp'), username=username, secret=secret, auth_mode='basic', verify_tls=cfg.get('verify_tls', True))
    rows: list[dict[str, Any]] = []
    for item in leases if isinstance(leases, list) else []:
        if not isinstance(item, dict):
            continue
        address = item.get('active-address') or item.get('address')
        mac = item.get('active-mac-address') or item.get('mac-address')
        d = _normalize_client({
            'ip': address,
            'mac': mac,
            'hostname': item.get('host-name') or item.get('comment') or '',
            'status': item.get('status') or '',
            'interface': item.get('server') or '',
        }, online_values={'bound', 'online', 'active'})
        if d:
            rows.append(d)
    for item in arp if isinstance(arp, list) else []:
        if not isinstance(item, dict):
            continue
        complete = str(item.get('complete') or '').lower() in ('true', 'yes', '1')
        d = _normalize_client({
            'ip': item.get('address'),
            'mac': item.get('mac-address'),
            'hostname': item.get('comment') or '',
            'status': 'online' if complete else 'observed',
            'interface': item.get('interface') or '',
        }, online_values={'online'})
        if d:
            rows.append(d)
    return _dedupe(rows)


def _fetch_generic_server(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    base = _validate_base_url(cfg['base_url'], cfg['provider'])
    _assert_server_destination(base)
    o = cfg.get('options') or {}
    endpoint = str(o.get('endpoint') or '/api/clients')
    url = _join_url(base, endpoint)
    payload = _http_json(
        url,
        username=cfg.get('username', ''),
        secret=cfg.get('secret', ''),
        token=cfg.get('token', ''),
        auth_mode=str(o.get('auth_mode') or 'none'),
        token_header=str(o.get('token_header') or 'X-API-Key'),
        verify_tls=cfg.get('verify_tls', True),
    )
    return _normalize_generic(payload, o)


def _fetch_unifi_cloud(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    o = cfg.get('options') or {}
    console_id = str(o.get('console_id') or '').strip()
    endpoint = str(o.get('endpoint') or '').strip()
    if not re.fullmatch(r'[A-Za-z0-9-]{6,128}', console_id):
        raise HTTPException(400, 'UNIFI_CONSOLE_ID_REQUIRED')
    if not endpoint.startswith('/') or '..' in endpoint:
        raise HTTPException(400, 'UNIFI_NETWORK_ENDPOINT_REQUIRED')
    # UniFi Cloud Connector proxies a Network integration API call to the console.
    base = 'https://api.ui.com'
    url = _join_url(base, f'/v1/connector/consoles/{console_id}/proxy/network/integration{endpoint}')
    payload = _http_json(url, token=cfg.get('token', ''), auth_mode='x-api-key', token_header='X-API-Key', verify_tls=True)
    return _normalize_generic(payload, o)


def fetch_clients(cfg: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    cfg = cfg or _read_config(include_secret=True)
    if not cfg.get('enabled'):
        raise HTTPException(409, 'ROUTER_API_DISABLED')
    provider = str(cfg.get('provider') or '')
    if provider in BROWSER_PROVIDERS:
        raise HTTPException(409, 'ROUTER_API_BROWSER_DIRECT_REQUIRED')
    if provider == 'mikrotik_rest':
        return _fetch_mikrotik(cfg)
    if provider == 'unifi_cloud':
        return _fetch_unifi_cloud(cfg)
    if provider == 'generic_server':
        return _fetch_generic_server(cfg)
    raise HTTPException(400, 'ROUTER_API_PROVIDER_UNSUPPORTED')


def _validate_reported_clients(clients: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out=[]
    for row in clients[:2048]:
        if not isinstance(row, dict):
            continue
        ip=_clean_ip(row.get('ip'))
        mac=_clean_mac(row.get('mac'))
        if not ip and not mac:
            continue
        # Local router inventory is expected to contain private LAN IPv4 addresses.
        if ip:
            addr=ipaddress.ip_address(ip)
            if not addr.is_private or addr.is_link_local or addr.is_loopback or addr.is_multicast:
                continue
        out.append({'ip':ip,'mac':mac,'hostname':str(row.get('hostname') or '')[:255],
                    'status':str(row.get('status') or 'Observed')[:80],
                    'interface':str(row.get('interface') or '')[:255]})
    return _dedupe(out)


def _save_observations(provider: str, clients: list[dict[str, Any]]) -> None:
    ensure_tables69(); now=utcnow()
    clean=_validate_reported_clients(clients)
    with connection() as c:
        for row in clean:
            c.execute('INSERT INTO web_router_api_observations69(provider,ip,mac,hostname,status,interface,detail,observed_at) VALUES(?,?,?,?,?,?,?,?)',
                      (provider,row.get('ip',''),row.get('mac',''),row.get('hostname',''),row.get('status','Observed'),row.get('interface',''),'Router/API observation',now))
        # Bound history growth without modifying inventory.
        c.execute('DELETE FROM web_router_api_observations69 WHERE id NOT IN (SELECT id FROM web_router_api_observations69 ORDER BY id DESC LIMIT 10000)')
        c.commit()


def browser_connect_origin() -> str:
    """Exact CSP connect-src origin for the configured browser-direct router."""
    try:
        cfg=_read_config(False)
        if not cfg.get('enabled') or cfg.get('provider') not in BROWSER_PROVIDERS:
            return ''
        base=_validate_base_url(cfg.get('base_url',''), cfg.get('provider','generic_browser'))
        u=urllib.parse.urlsplit(base)
        port=f':{u.port}' if u.port and u.port != 443 else ''
        return f'https://{u.hostname}{port}'
    except Exception:
        return ''


@router.get('/router-api/providers')
def providers(request: Request):
    require_role(request, 'Admin', 'Operator')
    return {
        'providers': [{'id': k, 'name': v, 'execution': 'BROWSER' if k in BROWSER_PROVIDERS else 'SERVER'} for k, v in PROVIDERS.items()],
        'notes': {
            'mikrotik_rest': 'REST read-only; hosted Render requires a securely reachable public/cloud HTTPS endpoint. Do not expose router management directly to the Internet.',
            'unifi_cloud': 'Uses api.ui.com Cloud Connector with X-API-Key and a Network integration endpoint.',
            'generic_server': 'HTTPS JSON endpoint reachable from Render; private/link-local destinations are blocked in hosted mode.',
            'generic_browser': 'Browser calls the router directly. Router must use trusted HTTPS and allow CORS/Private Network Access from this web origin.',
        }
    }


@router.get('/router-api/config')
def config_get(request: Request):
    require_role(request, 'Admin', 'Operator')
    return _read_config(False)


@router.put('/router-api/config')
def config_put(body: RouterConfigIn, request: Request):
    require_role(request, 'Admin')
    provider=str(body.provider or '').strip().lower()
    if provider not in PROVIDERS:
        raise HTTPException(400, 'ROUTER_API_PROVIDER_UNSUPPORTED')
    base=_validate_base_url(body.base_url, provider) if body.enabled else str(body.base_url or '').strip().rstrip('/')
    options=dict(body.options or {})
    # Keep options small and JSON-only. Secrets belong in encrypted columns.
    try:
        options_json=json.dumps(options, ensure_ascii=False, separators=(',', ':'))
    except (TypeError, ValueError):
        raise HTTPException(400, 'ROUTER_API_OPTIONS_INVALID') from None
    if len(options_json) > 12000:
        raise HTTPException(400, 'ROUTER_API_OPTIONS_TOO_LARGE')
    if provider in SERVER_PROVIDERS and body.enabled:
        if not body.verify_tls and _web_only():
            raise HTTPException(400, 'ROUTER_API_TLS_VERIFY_REQUIRED_ON_HOSTED_WEB')
        if provider != 'unifi_cloud':
            _assert_server_destination(base)
    ensure_tables69()
    with connection() as c:
        old=c.execute('SELECT secret_enc,token_enc FROM web_router_api_config69 WHERE id=1').fetchone()
        secret_enc='' if body.clear_secret else str((old or {}).get('secret_enc') if isinstance(old,dict) else (old['secret_enc'] if old else '') or '')
        token_enc='' if body.clear_token else str((old or {}).get('token_enc') if isinstance(old,dict) else (old['token_enc'] if old else '') or '')
        if provider in BROWSER_PROVIDERS:
            # Browser-direct credentials stay in browser sessionStorage only.
            # Clear any legacy server-side copy so Render never stores LAN router secrets.
            secret_enc=''; token_enc=''
        else:
            if body.secret:
                secret_enc=encrypt_secret(body.secret)
            if body.token:
                token_enc=encrypt_secret(body.token)
        c.execute('''UPDATE web_router_api_config69 SET enabled=?,provider=?,base_url=?,username=?,secret_enc=?,token_enc=?,verify_tls=?,options_json=?,updated_at=? WHERE id=1''',
                  (1 if body.enabled else 0,provider,base,str(body.username or '').strip(),secret_enc,token_enc,1 if body.verify_tls else 0,options_json,utcnow()))
        c.commit()
    return _read_config(False)


@router.post('/router-api/test')
def router_test(request: Request):
    require_role(request, 'Admin', 'Operator')
    cfg=_read_config(True)
    if cfg.get('provider') in BROWSER_PROVIDERS:
        return {'ok':True,'execution':'BROWSER','requires_browser_fetch':True,'provider':cfg.get('provider'),
                'detail':'Cấu hình hợp lệ ở backend. Trình duyệt phải gọi trực tiếp router; HTTPS/CORS/PNA được kiểm tra khi bấm Đọc thiết bị.'}
    rows=_validate_reported_clients(fetch_clients(cfg))
    _save_observations(str(cfg.get('provider') or ''), rows)
    return {'ok':True,'execution':'SERVER','provider':cfg.get('provider'),'count':len(rows),'sample':rows[:10]}


@router.get('/router-api/clients')
def clients(request: Request):
    require_role(request, 'Admin', 'Operator')
    cfg=_read_config(True)
    rows=_validate_reported_clients(fetch_clients(cfg))
    _save_observations(str(cfg.get('provider') or ''), rows)
    return {'provider':cfg.get('provider'),'execution':'SERVER','count':len(rows),'clients':rows,'observed_at':utcnow()}


@router.post('/router-api/browser-observations')
def browser_observations(body: RouterObservationIn, request: Request):
    require_role(request, 'Admin', 'Operator')
    cfg=_read_config(False)
    if cfg.get('provider') not in BROWSER_PROVIDERS:
        raise HTTPException(409, 'ROUTER_API_NOT_BROWSER_DIRECT')
    if str(body.provider or '') != str(cfg.get('provider') or ''):
        raise HTTPException(400, 'ROUTER_API_PROVIDER_MISMATCH')
    clean=_validate_reported_clients(body.clients)
    _save_observations(str(body.provider), clean)
    return {'ok':True,'count':len(clean),'clients':clean,'observed_at':utcnow()}


@router.get('/router-api/observations')
def observations(request: Request, limit: int = 500):
    require_role(request, 'Admin', 'Operator')
    ensure_tables69(); limit=max(1,min(int(limit),2000))
    with connection() as c:
        rows=[dict(r) for r in c.execute('SELECT * FROM web_router_api_observations69 ORDER BY id DESC LIMIT ?',(limit,)).fetchall()]
    return rows


@router.post('/router-api/import')
def import_clients(body: RouterImportIn, request: Request):
    require_role(request, 'Admin')
    clean=_validate_reported_clients(body.clients)
    from database.db import get_device_by_ip
    from modules.device_manager import DeviceManager
    manager=DeviceManager()
    added=0; existing=0; skipped=0
    for row in clean:
        ip=row.get('ip') or ''
        if not ip:
            skipped+=1; continue
        if get_device_by_ip(ip):
            existing+=1; continue
        result=manager.add_device(ip,row.get('hostname') or '',row.get('mac') or '','Online' if row.get('status')=='Online' else 'Unknown',None)
        if result.get('success'):
            added+=1
        else:
            skipped+=1
    return {'ok':True,'added':added,'existing':existing,'skipped':skipped,'total':len(clean)}
