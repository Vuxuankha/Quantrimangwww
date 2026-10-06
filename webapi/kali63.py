from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import shlex
import socket
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app_runtime import data_path
from modules.nms_v5 import encrypt_secret, decrypt_secret
from webapi.security37 import require_role

router = APIRouter(prefix='/api/v1/kali', tags=['Kali Integration'])
CONFIG_PATH = data_path('kali_integration.json')


class KaliConfigIn(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=128)
    password: str | None = Field(default=None, max_length=1024)
    hostkey_sha256: str = Field(min_length=10, max_length=256)
    enabled: bool = True


class KaliRunIn(BaseModel):
    profile: str
    target: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)


def _load() -> dict:
    if not CONFIG_PATH.is_file():
        return {'enabled': False}
    try:
        obj = json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
        if not isinstance(obj, dict):
            return {'enabled': False}
        return obj
    except Exception:
        return {'enabled': False}


def _public_config(obj: dict | None = None) -> dict:
    obj = obj or _load()
    return {
        'enabled': bool(obj.get('enabled')),
        'host': obj.get('host', ''),
        'port': int(obj.get('port') or 22),
        'username': obj.get('username', ''),
        'hostkey_sha256': obj.get('hostkey_sha256', ''),
        'password_saved': bool(obj.get('password_enc')),
        'mode': 'defensive-authorized-only',
    }


def _fingerprint(key) -> str:
    raw = key.asbytes()
    return 'SHA256:' + base64.b64encode(hashlib.sha256(raw).digest()).decode('ascii').rstrip('=')


def _probe_hostkey(host: str, port: int) -> dict:
    try:
        import paramiko
    except Exception as exc:
        raise HTTPException(503, 'PARAMIKO_MISSING') from exc
    sock = None
    tr = None
    try:
        sock = socket.create_connection((host, int(port)), timeout=7)
        tr = paramiko.Transport(sock)
        tr.start_client(timeout=7)
        key = tr.get_remote_server_key()
        return {'algorithm': key.get_name(), 'sha256': _fingerprint(key)}
    except Exception as exc:
        raise HTTPException(502, f'KALI_SSH_HOSTKEY_FAILED: {type(exc).__name__}') from exc
    finally:
        try:
            if tr: tr.close()
        except Exception:
            pass
        try:
            if sock: sock.close()
        except Exception:
            pass


def _connect():
    cfg = _load()
    if not cfg.get('enabled'):
        raise HTTPException(409, 'KALI_NOT_CONFIGURED')
    try:
        import paramiko
    except Exception as exc:
        raise HTTPException(503, 'PARAMIKO_MISSING') from exc
    host = str(cfg.get('host') or '').strip()
    port = int(cfg.get('port') or 22)
    expected = str(cfg.get('hostkey_sha256') or '').strip()
    observed = _probe_hostkey(host, port)['sha256']
    if observed != expected:
        raise HTTPException(409, 'KALI_HOSTKEY_CHANGED')
    password_enc = cfg.get('password_enc')
    if not password_enc:
        raise HTTPException(409, 'KALI_PASSWORD_NOT_SAVED')
    password = decrypt_secret(password_enc)
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.RejectPolicy())
    # We pin the host key ourselves above, then load it into the in-memory host key store.
    sock = socket.create_connection((host, port), timeout=8)
    tr = paramiko.Transport(sock)
    try:
        tr.start_client(timeout=8)
        key = tr.get_remote_server_key()
        if _fingerprint(key) != expected:
            raise HTTPException(409, 'KALI_HOSTKEY_CHANGED')
        tr.auth_password(username=str(cfg.get('username') or ''), password=password)
        if not tr.is_authenticated():
            raise HTTPException(401, 'KALI_AUTH_FAILED')
        return tr, sock
    except Exception:
        tr.close(); sock.close(); raise


def _exec(command: str, timeout: int = 35) -> dict:
    tr, sock = _connect()
    try:
        chan = tr.open_session(timeout=8)
        chan.settimeout(timeout)
        chan.exec_command(command)
        out = chan.makefile('r', -1).read(256000)
        err = chan.makefile_stderr('r', -1).read(64000)
        code = chan.recv_exit_status()
        return {'ok': code == 0, 'exit_code': int(code), 'stdout': out, 'stderr': err}
    except socket.timeout as exc:
        raise HTTPException(504, 'KALI_COMMAND_TIMEOUT') from exc
    finally:
        try: tr.close()
        finally: sock.close()


def _private_ip_or_cidr(value: str) -> str:
    value = (value or '').strip()
    try:
        if '/' in value:
            net = ipaddress.ip_network(value, strict=False)
            if not (net.is_private or net.is_loopback or net.is_link_local):
                raise ValueError
            if net.num_addresses > 4096:
                raise HTTPException(400, 'TARGET_RANGE_TOO_LARGE')
            return str(net)
        ip = ipaddress.ip_address(value)
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            raise ValueError
        return str(ip)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, 'TARGET_MUST_BE_PRIVATE_IP_OR_CIDR') from exc


def _private_host(value: str) -> str:
    """Resolve one host once and return the approved private IP.

    Returning the pinned IP (rather than the original hostname) prevents a
    second DNS lookup on the Kali worker from changing the destination after
    validation. CIDRs are intentionally rejected here; only the dedicated
    network_discovery profile accepts a bounded private CIDR.
    """
    value = (value or '').strip()
    if not value or '/' in value:
        raise HTTPException(400, 'TARGET_HOST_MUST_BE_SINGLE_PRIVATE_HOST')
    try:
        ip = ipaddress.ip_address(value)
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            raise ValueError
        return str(ip)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)
        addrs = {ipaddress.ip_address(x[4][0]) for x in infos}
        if not addrs or any(not (ip.is_private or ip.is_loopback or ip.is_link_local) for ip in addrs):
            raise ValueError
        approved = sorted(addrs, key=lambda ip: (ip.version, int(ip)))[0]
        return str(approved)
    except Exception as exc:
        raise HTTPException(400, 'TARGET_HOST_MUST_RESOLVE_PRIVATE') from exc


def _private_url_target(value: str) -> tuple[str, str, str]:
    """Validate a private HTTP(S) URL and pin it to one approved IP.

    Returns (original_url, curl_resolve_value, approved_ip). curl --resolve
    preserves the original Host header/SNI while preventing another DNS lookup.
    """
    try:
        p = urlsplit((value or '').strip())
        if p.scheme not in {'http', 'https'} or not p.hostname or p.username or p.password:
            raise ValueError
        approved_ip = _private_host(p.hostname)
        port = p.port or (443 if p.scheme == 'https' else 80)
        curl_ip = f'[{approved_ip}]' if ':' in approved_ip else approved_ip
        resolve_value = f'{p.hostname}:{port}:{curl_ip}'
        return p.geturl(), resolve_value, approved_ip
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, 'URL_MUST_BE_HTTP_S_AND_PRIVATE') from exc


@router.get('/config')
def get_config(request: Request):
    require_role(request,'Admin')
    return _public_config()


@router.get('/probe-hostkey')
def probe_hostkey(host: str, request: Request, port: int = 22):
    require_role(request,'Admin')
    if not host.strip():
        raise HTTPException(400, 'HOST_REQUIRED')
    return _probe_hostkey(host.strip(), port)


@router.post('/config')
def save_config(body: KaliConfigIn, request: Request):
    require_role(request,'Admin')
    fp = body.hostkey_sha256.strip()
    if not fp.startswith('SHA256:'):
        raise HTTPException(400, 'HOSTKEY_SHA256_REQUIRED')
    obj = _load()
    obj.update({'host': body.host.strip(), 'port': body.port, 'username': body.username.strip(), 'hostkey_sha256': fp, 'enabled': body.enabled})
    if body.password:
        obj['password_enc'] = encrypt_secret(body.password)
    elif not obj.get('password_enc'):
        raise HTTPException(400, 'PASSWORD_REQUIRED_ON_FIRST_SETUP')
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_PATH.with_suffix('.tmp')
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding='utf-8')
    tmp.replace(CONFIG_PATH)
    return _public_config(obj)


@router.post('/test')
def test_connection(request: Request):
    require_role(request,'Admin','Operator')
    result = _exec("printf 'KALI_OK\\n'; uname -srmo; command -v nmap || true; command -v curl || true; command -v openssl || true; command -v tshark || true", timeout=15)
    return {'connection': 'ok' if result['ok'] else 'failed', **result}


@router.get('/tools')
def tools(request: Request):
    require_role(request)
    cmd = "for x in nmap curl openssl tshark tcpdump python3 ss; do if command -v $x >/dev/null 2>&1; then printf '%s=READY\\n' $x; else printf '%s=MISSING\\n' $x; fi; done"
    return _exec(cmd, timeout=15)


@router.post('/run')
def run_profile(body: KaliRunIn, request: Request):
    require_role(request,'Admin','Operator')
    profile = body.profile.strip().lower()
    target = (body.target or '').strip()
    if profile == 'network_discovery':
        t = _private_ip_or_cidr(target)
        cmd = f"nmap -sn -n --max-retries 1 --host-timeout 5s {shlex.quote(t)}"
    elif profile == 'port_service_scan':
        t = _private_host(target)
        cmd = f"nmap -sT -sV --version-light -Pn -n --top-ports 100 --max-retries 1 --host-timeout 45s {shlex.quote(t)}"
    elif profile == 'tls_audit':
        t = _private_host(target); p = int(body.port or 443)
        cmd = "timeout 15 openssl s_client -brief -showcerts -verify_return_error -connect %s:%d </dev/null 2>&1" % (shlex.quote(t), p)
    elif profile == 'web_headers':
        u, resolve_value, _approved_ip = _private_url_target(target)
        cmd = f"curl -k -sS -D - -o /dev/null --max-time 15 --max-redirs 0 --resolve {shlex.quote(resolve_value)} {shlex.quote(u)}"
    elif profile == 'worker_network_state':
        cmd = "ip -brief addr 2>/dev/null; printf '\\n--- routes ---\\n'; ip route 2>/dev/null; printf '\\n--- sockets ---\\n'; ss -tunap 2>/dev/null | head -200"
    elif profile == 'session_cookie_audit':
        # Defensive check only: fetch response headers from an authorized private URL.
        u, resolve_value, _approved_ip = _private_url_target(target)
        cmd = f"curl -k -sS -D - -o /dev/null --max-time 15 --max-redirs 0 --resolve {shlex.quote(resolve_value)} {shlex.quote(u)}"
    elif profile == 'tls_transport_audit':
        # Defensive transport inspection; no interception/MitM is performed.
        t = _private_host(target); p = int(body.port or 443)
        cmd = "timeout 15 openssl s_client -brief -verify_return_error -connect %s:%d </dev/null 2>&1" % (shlex.quote(t), p)
    elif profile == 'component_versions':
        # Inventory the Kali worker's own security-tool versions for patch review.
        cmd = "printf '%s\\n' '--- nmap ---'; nmap --version 2>/dev/null | head -3; printf '%s\\n' '--- openssl ---'; openssl version 2>/dev/null; printf '%s\\n' '--- curl ---'; curl --version 2>/dev/null | head -2; printf '%s\\n' '--- python ---'; python3 --version 2>/dev/null"
    elif profile == 'http_capacity_probe':
        # Intentionally tiny bounded probe: 10 sequential requests, private URL only.
        # DNS is pinned with curl --resolve and redirects are disabled.
        u, resolve_value, _approved_ip = _private_url_target(target)
        q_url = shlex.quote(u)
        q_resolve = shlex.quote(resolve_value)
        cmd = (
            "tmp=$(mktemp); trap 'rm -f \"$tmp\"' EXIT; ok=0; i=0; "
            "while [ $i -lt 10 ]; do "
            f"t=$(curl -k -sS -o /dev/null --max-time 5 --max-redirs 0 --resolve {q_resolve} -w '%{{time_total}}' {q_url} 2>/dev/null); "
            "rc=$?; [ $rc -eq 0 ] && ok=$((ok+1)); printf '%s\n' \"${t:-0}\" >> \"$tmp\"; "
            "i=$((i+1)); sleep 0.2; done; "
            "awk -v ok=\"$ok\" 'BEGIN{sum=0;max=0;n=0} {v=$1+0;sum+=v;if(v>max)max=v;n++} "
            "END{printf \"requests=10\\nsuccess=%d\\navg_ms=%.2f\\nmax_ms=%.2f\\n\",ok,(n?sum/n*1000:0),max*1000}' \"$tmp\""
        )
    else:
        raise HTTPException(400, 'UNSUPPORTED_KALI_PROFILE')
    result = _exec(cmd, timeout=60)
    return {'profile': profile, 'target': target, 'backend': 'kali-ssh', **result}
