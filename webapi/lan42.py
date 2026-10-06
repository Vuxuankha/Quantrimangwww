from __future__ import annotations

import ipaddress
import json
import os
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app_runtime import hidden_subprocess_kwargs
from webapi.runtime37 import connection, utcnow
from webapi.security37 import require_role

router = APIRouter(prefix='/api/v42', tags=['v42-lan'])

PATH_TTL_SECONDS = 900


def ensure_tables() -> None:
    with connection() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS web_lan_probe42(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ip TEXT NOT NULL,
          subnet TEXT,
          route_class TEXT,
          path_state TEXT,
          ping_state TEXT,
          detail TEXT,
          observed_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_web_lan_probe42_ip_time ON web_lan_probe42(ip,id DESC);
        CREATE INDEX IF NOT EXISTS ix_web_lan_probe42_subnet_time ON web_lan_probe42(subnet,id DESC);
        CREATE TABLE IF NOT EXISTS web_snmpv2_credentials42(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT UNIQUE NOT NULL,
          community_enc TEXT NOT NULL,
          port INTEGER NOT NULL DEFAULT 161,
          note TEXT NOT NULL DEFAULT '',
          created_at TEXT,
          updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS web_device_snmpv2_assignments42(
          device_id INTEGER PRIMARY KEY,
          credential_id INTEGER NOT NULL,
          updated_at TEXT
        );
        CREATE INDEX IF NOT EXISTS ix_web_device_snmpv2_credential42 ON web_device_snmpv2_assignments42(credential_id);
        ''')


def _run(args: list[str], timeout: int = 12) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors='replace',
        timeout=timeout,
        **hidden_subprocess_kwargs(),
    )


def _powershell_json(script: str) -> list[dict[str, Any]]:
    if os.name != 'nt':
        return []
    p = _run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script])
    if p.returncode != 0 or not p.stdout.strip():
        return []
    try:
        data = json.loads(p.stdout.strip())
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    return [x for x in data if isinstance(x, dict)]


def network_snapshot() -> dict[str, Any]:
    interfaces: list[dict[str, Any]] = []
    routes: list[dict[str, Any]] = []
    if os.name == 'nt':
        interfaces = _powershell_json(r'''
$items = Get-NetIPConfiguration | Where-Object {$_.IPv4Address -and $_.NetAdapter.Status -eq 'Up'} | ForEach-Object {
  [PSCustomObject]@{
    alias=$_.InterfaceAlias
    ip=$_.IPv4Address.IPAddress
    prefix=[int]$_.IPv4Address.PrefixLength
    gateway=if($_.IPv4DefaultGateway){$_.IPv4DefaultGateway.NextHop}else{''}
  }
}
$items | ConvertTo-Json -Compress
''')
        routes = _powershell_json(r'''
$items = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.State -eq 'Alive'} | ForEach-Object {
  [PSCustomObject]@{
    destination=$_.DestinationPrefix
    next_hop=$_.NextHop
    alias=$_.InterfaceAlias
    metric=[int]$_.RouteMetric
  }
}
$items | ConvertTo-Json -Compress
''')
    if not interfaces:
        # Cross-platform fallback for QA; this is not used to infer a subnet mask.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('1.1.1.1', 53))
            ip = s.getsockname()[0]
            s.close()
            interfaces = [{'alias': 'default', 'ip': ip, 'prefix': None, 'gateway': ''}]
        except OSError:
            pass
    return {'interfaces': interfaces, 'routes': routes, 'platform': platform.system()}


def _net(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def classify_route(ip: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    addr = ipaddress.ip_address(ip)
    local_match = None
    for it in snapshot.get('interfaces') or []:
        try:
            prefix = it.get('prefix')
            if prefix is None:
                continue
            n = ipaddress.ip_network(f"{it.get('ip')}/{int(prefix)}", strict=False)
            if addr in n:
                local_match = (n, it)
                break
        except (ValueError, TypeError):
            continue
    if local_match:
        n, it = local_match
        return {'route_class': 'LOCAL_SUBNET', 'network': str(n), 'next_hop': '', 'interface': it.get('alias') or ''}

    candidates = []
    default = None
    for r in snapshot.get('routes') or []:
        n = _net(str(r.get('destination') or ''))
        if n is None or addr not in n:
            continue
        if n.prefixlen == 0:
            if default is None or int(r.get('metric') or 999999) < int(default.get('metric') or 999999):
                default = r
            continue
        candidates.append((n.prefixlen, int(r.get('metric') or 999999), n, r))
    if candidates:
        candidates.sort(key=lambda x: (-x[0], x[1]))
        _, _, n, r = candidates[0]
        nh = str(r.get('next_hop') or '')
        return {
            'route_class': 'ON_LINK' if nh in ('', '0.0.0.0') else 'EXPLICIT_ROUTE',
            'network': str(n),
            'next_hop': nh,
            'interface': r.get('alias') or '',
        }
    if default:
        return {'route_class': 'DEFAULT_ROUTE_ONLY', 'network': '0.0.0.0/0', 'next_hop': default.get('next_hop') or '', 'interface': default.get('alias') or ''}
    return {'route_class': 'NO_ROUTE', 'network': '', 'next_hop': '', 'interface': ''}


def _registered_devices() -> list[dict[str, Any]]:
    with connection() as c:
        cols = {r['name'] for r in c.execute('PRAGMA table_info(devices)')}
        ipcol = 'ip' if 'ip' in cols else 'ip_address'
        name_expr = "COALESCE(NULLIF(hostname,'')," + ipcol + ")" if 'hostname' in cols else ipcol
        rows = c.execute(f'SELECT id,{ipcol} AS ip,{name_expr} AS name FROM devices WHERE {ipcol} IS NOT NULL AND trim({ipcol})<>\'\' ORDER BY id').fetchall()
        managed={}
        try:
            for m in c.execute("SELECT id,COALESCE(NULLIF(ip,''),ip_address) ip FROM network_devices").fetchall():
                if m['ip'] and str(m['ip']).strip() not in managed:
                    managed[str(m['ip']).strip()]=m['id']
        except Exception:
            pass
    out = []
    for r in rows:
        try:
            ip = str(ipaddress.ip_address(str(r['ip']).strip()))
        except ValueError:
            continue
        out.append({'id': r['id'], 'ip': ip, 'name': r['name'] or ip, 'managed_id': managed.get(ip)})
    return out


def _group_network(ip: str, route: dict[str, Any]) -> str:
    if route.get('route_class') in ('LOCAL_SUBNET', 'ON_LINK', 'EXPLICIT_ROUTE') and route.get('network') not in ('', '0.0.0.0/0'):
        return str(route['network'])
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv4Address) and addr.is_private:
        return str(ipaddress.ip_network(f'{ip}/24', strict=False))
    return str(ipaddress.ip_network(f'{ip}/32', strict=False))


def _latest_probe_map() -> dict[str, dict[str, Any]]:
    ensure_tables()
    with connection() as c:
        rows = c.execute('''SELECT p.* FROM web_lan_probe42 p
          JOIN (SELECT ip,MAX(id) mid FROM web_lan_probe42 GROUP BY ip) x ON x.mid=p.id''').fetchall()
    return {r['ip']: dict(r) for r in rows}


def _age_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        d = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - d.astimezone(timezone.utc)).total_seconds()
    except ValueError:
        return None


def readiness_payload() -> dict[str, Any]:
    snap = network_snapshot()
    latest = _latest_probe_map()
    devices = []
    for d in _registered_devices():
        route = classify_route(d['ip'], snap)
        p = latest.get(d['ip'])
        age = _age_seconds((p or {}).get('observed_at'))
        cached = p if age is not None and age <= PATH_TTL_SECONDS else None
        devices.append({**d, **route, 'probe': cached, 'probe_age_seconds': round(age, 1) if age is not None else None})
    by_class: dict[str, int] = {}
    for d in devices:
        by_class[d['route_class']] = by_class.get(d['route_class'], 0) + 1
    return {
        'platform': snap.get('platform'),
        'interfaces': snap.get('interfaces') or [],
        'routes': snap.get('routes') or [],
        'devices': devices,
        'route_summary': by_class,
        'observed_at': utcnow(),
        'note': 'DEFAULT_ROUTE_ONLY means Windows has only the default gateway for that target; it does not prove the remote VLAN is unreachable.',
    }


class ProbeIn(BaseModel):
    authorized: bool = False


def _probe_one(d: dict[str, Any], snap: dict[str, Any]) -> dict[str, Any]:
    from webapi.data37 import icmp_probe
    route = classify_route(d['ip'], snap)
    subnet = _group_network(d['ip'], route)
    try:
        ping = icmp_probe(d['ip'])
        ping_state = str(ping.get('status') or 'Unknown')
    except Exception as exc:
        ping_state = 'Error'
        ping = {'detail': str(exc)[:300]}
    return {**d, **route, 'subnet': subnet, 'ping_state': ping_state, 'raw_detail': str(ping.get('detail') or '')[:300]}


@router.get('/lan/readiness')
def lan_readiness(request: Request):
    require_role(request)
    return readiness_payload()


def run_registered_probe() -> dict[str, Any]:
    snap = network_snapshot()
    devices = _registered_devices()
    if len(devices) > 128:
        raise HTTPException(409, 'LAN probe giới hạn tối đa 128 thiết bị đã đăng ký mỗi lần.')
    results = []
    with ThreadPoolExecutor(max_workers=min(12, max(1, len(devices)))) as pool:
        fut = {pool.submit(_probe_one, d, snap): d for d in devices}
        for f in as_completed(fut):
            results.append(f.result())

    groups: dict[str, list[dict[str, Any]]] = {}
    for r in results:
        groups.setdefault(r['subnet'], []).append(r)
    subnet_state = {}
    for subnet, items in groups.items():
        if any(i['ping_state'] == 'Online' for i in items):
            state = 'REACHABLE'
        elif all(i['route_class'] == 'NO_ROUTE' for i in items):
            state = 'NO_ROUTE'
        elif all(i['route_class'] == 'DEFAULT_ROUTE_ONLY' for i in items):
            state = 'PATH_UNVERIFIED'
        else:
            state = 'NO_ICMP_REPLY'
        subnet_state[subnet] = state

    now = utcnow()
    with connection() as c:
        for r in results:
            if r['ping_state'] == 'Online':
                path_state = 'REACHABLE'
                detail = 'Registered target replied to ICMP.'
            else:
                path_state = subnet_state[r['subnet']]
                if path_state == 'PATH_UNVERIFIED':
                    detail = 'No registered target in this remote private subnet replied; Windows only exposes a default route. Do not classify devices as Offline until VLAN/routing is verified.'
                elif path_state == 'NO_ROUTE':
                    detail = 'Windows has no IPv4 route for this target.'
                elif path_state == 'NO_ICMP_REPLY':
                    detail = 'A path exists, but registered targets did not reply to ICMP; ICMP may be blocked or devices may be unavailable.'
                else:
                    detail = r.get('raw_detail') or ''
            r['path_state'] = path_state
            r['detail'] = detail
            c.execute('INSERT INTO web_lan_probe42(ip,subnet,route_class,path_state,ping_state,detail,observed_at) VALUES(?,?,?,?,?,?,?)',
                      (r['ip'], r['subnet'], r['route_class'], path_state, r['ping_state'], detail, now))
        # Bound LAN probe history.
        c.execute('DELETE FROM web_lan_probe42 WHERE id < COALESCE((SELECT id FROM web_lan_probe42 ORDER BY id DESC LIMIT 1 OFFSET 4999),0)')
    results.sort(key=lambda r: tuple(int(x) for x in r['ip'].split('.')) if '.' in r['ip'] else (999,))
    return {
        'count': len(results),
        'summary': {k: sum(1 for r in results if r['path_state'] == k) for k in ('REACHABLE','NO_ROUTE','PATH_UNVERIFIED','NO_ICMP_REPLY')},
        'subnets': [{'subnet': k, 'state': subnet_state[k], 'targets': len(v), 'online': sum(i['ping_state']=='Online' for i in v)} for k, v in sorted(groups.items())],
        'results': results,
        'observed_at': now,
    }


@router.post('/lan/probe')
def lan_probe(x: ProbeIn, request: Request):
    require_role(request, 'Admin', 'Operator')
    if not x.authorized:
        raise HTTPException(400, 'Phải xác nhận bạn có quyền kiểm tra các thiết bị đã đăng ký.')
    return run_registered_probe()


class SnmpV2CredentialIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    community: str = Field(min_length=1, max_length=512)
    port: int = Field(default=161, ge=1, le=65535)
    note: str = Field(default='', max_length=500)

class SnmpV2CredentialUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    community: str = Field(default='', max_length=512)
    port: int = Field(default=161, ge=1, le=65535)
    note: str = Field(default='', max_length=500)

class BulkAssignIn(BaseModel):
    credential_id: int = Field(gt=0)
    device_ids: list[int] = Field(min_length=1, max_length=128)

class BulkSshAssignIn(BulkAssignIn):
    purpose: Literal['SSH','BACKUP'] = 'SSH'


def _validated_managed_ids(c, ids: list[int]) -> list[int]:
    uniq=[]
    for x in ids:
        i=int(x)
        if i>0 and i not in uniq: uniq.append(i)
    if not uniq or len(uniq)>128:
        raise HTTPException(400,'Chọn từ 1 đến 128 managed device IDs.')
    q=','.join('?' for _ in uniq)
    found={r['id'] for r in c.execute(f'SELECT id FROM network_devices WHERE id IN ({q})',uniq)}
    missing=[i for i in uniq if i not in found]
    if missing: raise HTTPException(404,'Không tìm thấy managed device ID: '+','.join(map(str,missing[:20])))
    return uniq


@router.get('/snmpv2/credentials')
def snmpv2_credentials(request: Request):
    require_role(request,'Admin')
    ensure_tables()
    with connection() as c:
        rows=[dict(r) for r in c.execute('''SELECT s.id,s.name,s.port,s.note,s.created_at,s.updated_at,
          (SELECT COUNT(*) FROM web_device_snmpv2_assignments42 a WHERE a.credential_id=s.id) assigned
          FROM web_snmpv2_credentials42 s ORDER BY s.name''')]
    return rows


@router.post('/snmpv2/credentials')
def create_snmpv2(x: SnmpV2CredentialIn, request: Request):
    require_role(request,'Admin'); ensure_tables()
    from modules.nms_v5 import encrypt_secret
    try:
        with connection() as c:
            cur=c.execute('INSERT INTO web_snmpv2_credentials42(name,community_enc,port,note,created_at,updated_at) VALUES(?,?,?,?,?,?)',
                          (x.name.strip(),encrypt_secret(x.community),x.port,x.note.strip(),utcnow(),utcnow()))
        return {'success':True,'id':cur.lastrowid}
    except Exception as exc:
        if 'UNIQUE' in str(exc).upper(): raise HTTPException(409,'Tên SNMPv2c credential đã tồn tại.')
        raise


@router.put('/snmpv2/credentials/{credential_id}')
def update_snmpv2(credential_id:int,x:SnmpV2CredentialUpdate,request:Request):
    require_role(request,'Admin'); ensure_tables()
    from modules.nms_v5 import encrypt_secret
    with connection() as c:
        old=c.execute('SELECT * FROM web_snmpv2_credentials42 WHERE id=?',(credential_id,)).fetchone()
        if not old: raise HTTPException(404,'SNMPv2c credential không tồn tại.')
        enc=encrypt_secret(x.community) if x.community else old['community_enc']
        try:
            c.execute('UPDATE web_snmpv2_credentials42 SET name=?,community_enc=?,port=?,note=?,updated_at=? WHERE id=?',
                      (x.name.strip(),enc,x.port,x.note.strip(),utcnow(),credential_id))
        except Exception as exc:
            if 'UNIQUE' in str(exc).upper(): raise HTTPException(409,'Tên SNMPv2c credential đã tồn tại.')
            raise
    return {'success':True}


@router.delete('/snmpv2/credentials/{credential_id}')
def delete_snmpv2(credential_id:int,request:Request):
    require_role(request,'Admin'); ensure_tables()
    with connection() as c:
        n=c.execute('SELECT COUNT(*) FROM web_device_snmpv2_assignments42 WHERE credential_id=?',(credential_id,)).fetchone()[0]
        if n: raise HTTPException(409,f'Credential đang được gán cho {n} thiết bị.')
        cur=c.execute('DELETE FROM web_snmpv2_credentials42 WHERE id=?',(credential_id,))
    return {'success':cur.rowcount>0}


@router.get('/snmpv2/assignments')
def snmpv2_assignments(request:Request):
    require_role(request,'Admin'); ensure_tables()
    with connection() as c:
        return [dict(r) for r in c.execute('''SELECT a.device_id,COALESCE(NULLIF(d.name,''),NULLIF(d.device_name,''),d.ip,d.ip_address) device,
          COALESCE(NULLIF(d.ip,''),d.ip_address) ip,s.id credential_id,s.name credential_name,s.port
          FROM web_device_snmpv2_assignments42 a JOIN network_devices d ON d.id=a.device_id
          JOIN web_snmpv2_credentials42 s ON s.id=a.credential_id ORDER BY device''')]


@router.post('/snmpv2/assign')
def assign_snmpv2(x:BulkAssignIn,request:Request):
    require_role(request,'Admin'); ensure_tables()
    with connection() as c:
        if not c.execute('SELECT id FROM web_snmpv2_credentials42 WHERE id=?',(x.credential_id,)).fetchone():
            raise HTTPException(404,'SNMPv2c credential không tồn tại.')
        ids=_validated_managed_ids(c,x.device_ids)
        for did in ids:
            c.execute('INSERT INTO web_device_snmpv2_assignments42(device_id,credential_id,updated_at) VALUES(?,?,?) '
                      'ON CONFLICT(device_id) DO UPDATE SET credential_id=excluded.credential_id,updated_at=excluded.updated_at',
                      (did,x.credential_id,utcnow()))
    return {'success':True,'assigned':len(ids)}


@router.delete('/snmpv2/assign/{device_id}')
def unassign_snmpv2(device_id:int,request:Request):
    require_role(request,'Admin'); ensure_tables()
    with connection() as c:
        cur=c.execute('DELETE FROM web_device_snmpv2_assignments42 WHERE device_id=?',(device_id,))
    return {'success':cur.rowcount>0}


@router.post('/ssh/assign')
def assign_ssh_bulk(x:BulkSshAssignIn,request:Request):
    require_role(request,'Admin')
    with connection() as c:
        if not c.execute('SELECT id FROM credentials WHERE id=?',(x.credential_id,)).fetchone():
            raise HTTPException(404,'SSH credential không tồn tại.')
        ids=_validated_managed_ids(c,x.device_ids)
        for did in ids:
            c.execute('INSERT INTO device_credentials(device_id,credential_id,purpose,created_at) VALUES(?,?,?,?) '
                      'ON CONFLICT(device_id,purpose) DO UPDATE SET credential_id=excluded.credential_id,created_at=excluded.created_at',
                      (did,x.credential_id,x.purpose,utcnow()))
    return {'success':True,'assigned':len(ids),'purpose':x.purpose}


@router.get('/device-setup/{device_id}')
def device_setup(device_id: int, request: Request):
    require_role(request, 'Admin', 'Operator')
    from modules.ssh_security import APP_KNOWN_HOSTS
    with connection() as c:
        d = c.execute("SELECT id,COALESCE(NULLIF(name,''),NULLIF(device_name,''),ip,ip_address) name,COALESCE(NULLIF(ip,''),ip_address) ip,vendor,device_type FROM network_devices WHERE id=?", (device_id,)).fetchone()
        if not d:
            raise HTTPException(404, 'Không tìm thấy managed device.')
        d = dict(d)
        ssh = c.execute("SELECT cr.id,cr.name,cr.username,cr.port FROM device_credentials dc JOIN credentials cr ON cr.id=dc.credential_id WHERE dc.device_id=? AND UPPER(dc.purpose)='SSH' ORDER BY dc.created_at DESC LIMIT 1", (device_id,)).fetchone()
        v3 = c.execute("SELECT s.id,s.name,s.security_level,s.port FROM device_snmpv3_assignments a JOIN snmpv3_credentials s ON s.id=a.credential_id WHERE a.device_id=? LIMIT 1", (device_id,)).fetchone()
        v2secure = c.execute("SELECT s.id,s.name,s.port FROM web_device_snmpv2_assignments42 a JOIN web_snmpv2_credentials42 s ON s.id=a.credential_id WHERE a.device_id=? LIMIT 1", (device_id,)).fetchone()
        v2 = c.execute("SELECT id,host,port,enabled FROM snmp_profiles WHERE host=? AND enabled=1 LIMIT 1", (d['ip'],)).fetchone()
    trusted = False
    port = int((ssh['port'] if ssh else 22) or 22)
    trust_key = d['ip'] if port == 22 else f"[{d['ip']}]:{port}"
    path = Path(APP_KNOWN_HOSTS)
    if path.exists():
        for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
            if line.strip() and not line.lstrip().startswith('#') and line.split()[0] == trust_key:
                trusted = True; break
    latest = _latest_probe_map().get(d['ip'])
    return {
        'device': d,
        'lan': latest,
        'ssh': {'configured': bool(ssh), 'credential': dict(ssh) if ssh else None, 'trusted': trusted, 'trust_key': trust_key},
        'snmp': {'configured': bool(v3 or v2secure or v2), 'mode': 'v3' if v3 else ('v2c-secure' if v2secure else ('v2c-legacy' if v2 else '')), 'credential': ({'id': v3['id'], 'name': v3['name'], 'security_level': v3['security_level'], 'port': v3['port']} if v3 else ({'id': v2secure['id'], 'name': v2secure['name'], 'port': v2secure['port']} if v2secure else None)), 'profile_id': v2['id'] if v2 else None},
        'steps': [
            {'key': 'lan', 'ok': bool(latest and latest.get('path_state') == 'REACHABLE'), 'label': 'LAN path verified'},
            {'key': 'ssh_credential', 'ok': bool(ssh), 'label': 'SSH credential assigned'},
            {'key': 'ssh_trust', 'ok': bool(ssh and trusted), 'label': 'SSH host key trusted'},
            {'key': 'snmp', 'ok': bool(v3 or v2secure or v2), 'label': 'SNMP profile/credential assigned'},
        ],
    }
