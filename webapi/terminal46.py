"""Authenticated, bounded SSH/Telnet terminals for registered devices (Admin only).

HTTP middleware does not protect WebSockets: origin, cookie, CSRF-derived ticket,
role, session revocation and per-message validation are enforced explicitly here.
No command, password, raw session token or terminal output is written to logs.
"""
from __future__ import annotations
import asyncio
import anyio
import importlib.metadata
import importlib.util
import ipaddress
import json
import os
import platform
import secrets
import shutil
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit
from typing import Literal
from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from webapi import security37
from webapi.runtime37 import connection, utcnow, VERSION
from modules.terminal_transport import SSHTransport, TelnetTransport

router = APIRouter(prefix='/api/v46')
security37.WRITE_RULES.extend([
    ('POST', r'/api/v46/terminal/tickets', ('Admin',)),
    ('DELETE', r'/api/v46/terminal/sessions/[^/]+', ('Admin',)),
])
MAX_SESSIONS = 16
MAX_PER_USER = 4
TICKET_TTL = 30
IDLE_SECONDS = 15*60
SESSION_SECONDS = 8*3600
AUTH_CHECK_SECONDS = 2


class ConnectIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    device_id: int | None = Field(default=None, gt=0)
    target_ip: str = Field(default='', max_length=45)
    protocol: Literal['ssh','telnet'] = 'ssh'
    port: int | None = Field(default=None, ge=1, le=65535)
    use_saved: bool = True
    username: str = Field(default='', max_length=128)
    password: str = Field(default='', max_length=4096, repr=False)
    auth_type: Literal['password','private_key'] = 'password'
    private_key: str = Field(default='', max_length=48000, repr=False)
    passphrase: str = Field(default='', max_length=4096, repr=False)
    authorized: bool = False
    acknowledge_plaintext: bool = False
    cols: int = Field(default=100, ge=20, le=400)
    rows: int = Field(default=30, ge=5, le=150)


@dataclass(repr=False)
class Ticket:
    user_id: int
    session_hash: str
    actor: str
    device_id: int | None
    host: str
    port: int
    protocol: str
    username: str
    password: str
    cols: int
    rows: int
    private_key: str = ''
    passphrase: str = ''
    created: float = field(default_factory=time.monotonic)


@dataclass
class Active:
    sid: str
    user_id: int
    device_id: int | None
    protocol: str
    host: str
    port: int
    started_at: str
    stop: asyncio.Event = field(repr=False)
    last_input: float = field(default_factory=time.monotonic)
    created: float = field(default_factory=time.monotonic)
    sent_seq: int = 0
    ack: asyncio.Event = field(default_factory=asyncio.Event, repr=False)


class Registry:
    def __init__(self):
        self.lock = threading.RLock()
        self.tickets: dict[str, Ticket] = {}
        self.active: dict[str, Active] = {}

    def prune(self):
        for key, ticket in list(self.tickets.items()):
            if time.monotonic()-ticket.created > TICKET_TTL:
                ticket.password = ticket.private_key = ticket.passphrase = ''; del self.tickets[key]

    def issue(self, ticket):
        with self.lock:
            self.prune()
            if len(self.active)+len(self.tickets) >= MAX_SESSIONS:
                raise HTTPException(429, 'TERMINAL_SERVER_LIMIT')
            count = sum(x.user_id==ticket.user_id for x in self.tickets.values()) + sum(x.user_id==ticket.user_id for x in self.active.values())
            if count >= MAX_PER_USER: raise HTTPException(429, 'TERMINAL_USER_LIMIT: maximum 4 pending/active terminals')
            token = secrets.token_urlsafe(32)
            self.tickets[security37.digest(token)] = ticket
            def expire():
                with self.lock: self.prune()
            timer=threading.Timer(TICKET_TTL+1,expire);timer.daemon=True;timer.start()
            return token

    def consume(self, token, user, cookie):
        with self.lock:
            self.prune()
            ticket = self.tickets.get(security37.digest(token))
            if not ticket or ticket.user_id!=user['id'] or not secrets.compare_digest(ticket.session_hash, security37.digest(cookie)):
                raise HTTPException(403, 'TERMINAL_TICKET_INVALID_OR_EXPIRED')
            del self.tickets[security37.digest(token)]
            sid = secrets.token_hex(16)
            active = Active(sid, user['id'], ticket.device_id, ticket.protocol, ticket.host, ticket.port, utcnow(), asyncio.Event())
            self.active[sid] = active
            return ticket, active

    def remove(self, sid):
        with self.lock: self.active.pop(sid, None)


registry = Registry()


def ensure_tables():
    with connection() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS web_terminal_audit46(
          id INTEGER PRIMARY KEY, actor TEXT, device_id INTEGER, protocol TEXT,
          event TEXT, code TEXT, created_at TEXT)''')


def audit(ticket, event, code=''):
    try:
        with connection() as c:
            c.execute('INSERT INTO web_terminal_audit46(actor,device_id,protocol,event,code,created_at) VALUES(?,?,?,?,?,?)',
                      (ticket.actor,ticket.device_id,ticket.protocol,event,code,utcnow()))
    except Exception:
        pass  # No raw payloads are logged on an audit DB error.


def _validated_target_ip(value: str, code: str) -> str:
    host = str(value or '').strip()
    try:
        address = ipaddress.ip_address(host)
        if address.is_unspecified or address.is_multicast or '%' in host or host == '255.255.255.255':
            raise ValueError()
    except ValueError:
        raise HTTPException(400, code) from None
    return str(address)


def resolve_device(device_id):
    with connection() as c:
        row = c.execute('SELECT * FROM network_devices WHERE id=?', (device_id,)).fetchone()
    if not row: raise HTTPException(404, 'MANAGED_DEVICE_NOT_FOUND')
    device = dict(row)
    host = _validated_target_ip(device.get('ip') or device.get('ip_address') or '', 'INVALID_REGISTERED_IP')
    return device, host


def resolve_target(device_id, target_ip):
    manual = str(target_ip or '').strip()
    if manual and device_id:
        raise HTTPException(400, 'CHOOSE_REGISTERED_DEVICE_OR_MANUAL_IP')
    if manual:
        host = _validated_target_ip(manual, 'INVALID_MANUAL_TARGET_IP')
        return {'id': None, 'name': 'Manual '+host, 'ip': host}, host, None
    if not device_id:
        raise HTTPException(400, 'DEVICE_OR_MANUAL_IP_REQUIRED')
    device, host = resolve_device(device_id)
    return device, host, int(device_id)


def saved_ssh(device_id):
    with connection() as c:
        r=c.execute('''SELECT cr.* FROM credentials cr JOIN device_credentials dc ON cr.id=dc.credential_id
          WHERE dc.device_id=? AND UPPER(dc.purpose)='SSH' AND UPPER(cr.kind) IN ('SSH','BACKUP') LIMIT 1''',(device_id,)).fetchone()
    return dict(r) if r else None


@router.get('/terminal/capabilities')
def capabilities(request: Request):
    security37.require_role(request,'Admin')
    return {'ssh_available':bool(importlib.util.find_spec('paramiko')),'telnet_available':True,
            'ssh_trust':'known_hosts required; no automatic trust','allowed_roles':['Admin'],
            'ssh_auth':['saved_password','temporary_password','temporary_private_key'],'max_per_user':MAX_PER_USER,'idle_seconds':IDLE_SECONDS,
            'ticket_seconds':TICKET_TTL,'session_seconds':SESSION_SECONDS,
            'reconnect':'manual; never replay input','telnet_warning':'Plaintext device connection; login manually in remote prompt'}


@router.post('/terminal/tickets', status_code=201)
def create_ticket(x: ConnectIn, request: Request):
    user = security37.require_role(request,'Admin')
    if not x.authorized: raise HTTPException(400, 'CONFIRM_AUTHORIZED_DEVICE_ACCESS')
    device, host, device_id = resolve_target(x.device_id, x.target_ip)
    username, password, port = x.username.strip(), x.password, x.port
    if x.protocol=='telnet':
        if not x.acknowledge_plaintext: raise HTTPException(400, 'TELNET_PLAINTEXT_CONFIRMATION_REQUIRED')
        if username or password or x.private_key or x.passphrase or x.auth_type!='password': raise HTTPException(400,'TELNET_LOGIN_IN_REMOTE_PROMPT_ONLY')
        port = port or 23
    else:
        if not importlib.util.find_spec('paramiko'): raise HTTPException(503,'SSH_DEPENDENCY_MISSING: run INSTALL_WEB.bat')
        if x.auth_type=='private_key' and x.use_saved:
            raise HTTPException(400,'PRIVATE_KEY_REQUIRES_TEMPORARY_AUTH')
        if x.auth_type=='password' and (x.private_key or x.passphrase):
            raise HTTPException(400,'UNEXPECTED_KEY_FIELDS')
        if x.use_saved:
            if device_id is None: raise HTTPException(409,'MANUAL_IP_REQUIRES_TEMPORARY_SSH_AUTH')
            cred = saved_ssh(device_id)
            if not cred: raise HTTPException(409,'SSH_CREDENTIAL_MISSING: assign an SSH credential or choose temporary login')
            from modules.nms_v5 import decrypt_secret
            try: password=decrypt_secret(cred['secret_enc'])
            except Exception: raise HTTPException(409,'CREDENTIAL_KEY_MISMATCH: restore the matching key; do not reset the database') from None
            username = str(cred.get('username') or '').strip()
            port = port or int(cred.get('port') or 22)
        port = port or 22
        if x.auth_type=='private_key':
            if not username or not x.private_key or password:
                raise HTTPException(400,'SSH_USERNAME_PRIVATE_KEY_REQUIRED')
            if not x.private_key.strip().startswith(('-----BEGIN OPENSSH PRIVATE KEY-----','-----BEGIN RSA PRIVATE KEY-----','-----BEGIN EC PRIVATE KEY-----','-----BEGIN PRIVATE KEY-----','-----BEGIN ENCRYPTED PRIVATE KEY-----')):
                raise HTTPException(400,'SSH_PRIVATE_KEY_FORMAT_INVALID')
        elif not username or not password: raise HTTPException(400,'SSH_USERNAME_PASSWORD_REQUIRED')
    ticket = Ticket(user['id'],security37.digest(request.cookies.get(security37.COOKIE,'')),user['username'],device_id,host,port,x.protocol,username,password,x.cols,x.rows)
    if x.protocol=='ssh' and x.auth_type=='private_key':
        ticket.private_key=x.private_key;ticket.passphrase=x.passphrase
    token = registry.issue(ticket)
    audit(ticket, 'ticket_created')
    return {'ticket':token,'expires_in':TICKET_TTL,'ws_path':'/api/v46/terminal/ws',
            'host':host,'port':port,'protocol':x.protocol,'device_name':device.get('name') or host}


@router.get('/terminal/sessions')
def sessions(request: Request):
    security37.require_role(request,'Admin')
    with registry.lock:
        registry.prune()
        return [{'id':v.sid,'user_id':v.user_id,'device_id':v.device_id,'host':v.host,'port':v.port,
                 'protocol':v.protocol,'started_at':v.started_at} for v in registry.active.values()]


@router.delete('/terminal/sessions/{sid}')
async def terminate(sid: str, request: Request):
    security37.require_role(request,'Admin')
    with registry.lock: active=registry.active.get(sid)
    if not active: raise HTTPException(404,'TERMINAL_NOT_FOUND')
    active.stop.set()
    return {'status':'closing'}


@router.get('/terminal/audit')
def terminal_audit(request: Request):
    security37.require_role(request,'Admin')
    with connection() as c:
        return [dict(r) for r in c.execute('SELECT * FROM web_terminal_audit46 ORDER BY id DESC LIMIT 100')]


def websocket_origin_ok(ws):
    origin = ws.headers.get('origin','')
    parsed = urlsplit(origin)
    expected_scheme = 'https' if ws.url.scheme=='wss' else 'http'
    if parsed.scheme != expected_scheme or parsed.netloc != ws.url.netloc or parsed.path not in ('','/') or parsed.query or parsed.fragment:
        return False
    if ws.headers.get('sec-fetch-site')=='cross-site': return False
    if os.environ.get('NA_COOKIE_SECURE','1')=='0':
        if not ws.client or ws.client.host not in ('127.0.0.1','::1','testclient'): return False
    elif ws.url.scheme!='wss':
        return False
    return True


def error_code(exc):
    name=type(exc).__name__
    if isinstance(exc,ValueError) and str(exc)=='SSH_PRIVATE_KEY_INVALID_OR_PASSPHRASE':return 'SSH_PRIVATE_KEY_INVALID_OR_PASSPHRASE'
    if isinstance(exc,HTTPException): return str(exc.detail)
    if isinstance(exc,(asyncio.TimeoutError,TimeoutError,socket.timeout)): return 'CONNECTION_OR_OUTPUT_TIMEOUT'
    if name=='AuthenticationException': return 'SSH_AUTHENTICATION_FAILED'
    if name=='BadHostKeyException': return 'SSH_HOST_KEY_CHANGED: verify fingerprint independently'
    if name=='SSHException': return 'SSH_HANDSHAKE_OR_HOST_TRUST_FAILED: check known_hosts and device SSH support'
    if isinstance(exc,ConnectionRefusedError): return 'CONNECTION_REFUSED: check service and port'
    if isinstance(exc,ModuleNotFoundError): return 'SSH_DEPENDENCY_MISSING: run INSTALL_WEB.bat'
    return 'TERMINAL_CONNECTION_ERROR: check target, permission and network'


# socket used only for timeout classification, not shell execution.
import socket


@router.websocket('/terminal/ws')
async def terminal_socket(ws: WebSocket):
    if not websocket_origin_ok(ws):
        await ws.close(code=1008); return
    user=await asyncio.to_thread(security37.session,ws)
    if not user or user['role']!='Admin':
        await ws.close(code=1008); return
    await ws.accept()
    ticket=active=transport=None
    tasks=[]
    async def send(obj):
        await asyncio.wait_for(ws.send_json(obj),5)
    try:
        raw=await asyncio.wait_for(ws.receive_text(),5)
        if len(raw)>1024: raise HTTPException(400,'AUTH_FRAME_TOO_LARGE')
        auth=json.loads(raw)
        if not isinstance(auth,dict) or auth.get('type')!='auth' or not isinstance(auth.get('ticket'),str) or len(auth['ticket'])>128:
            raise HTTPException(403,'TERMINAL_AUTH_REQUIRED')
        ticket,active=registry.consume(auth['ticket'],user,ws.cookies.get(security37.COOKIE,''))
        # A registered-device edit after the ticket was issued must not silently redirect access.
        # Manual IP tickets are already bound to the validated literal IP stored in the ticket.
        if ticket.device_id is not None:
            _device,current_host=await asyncio.to_thread(resolve_device,ticket.device_id)
            if current_host!=ticket.host: raise HTTPException(409,'DEVICE_CHANGED_RECONNECT_REQUIRED')
        else:
            current_host=_validated_target_ip(ticket.host,'INVALID_MANUAL_TARGET_IP')
        transport=SSHTransport() if ticket.protocol=='ssh' else TelnetTransport()
        await send({'type':'status','status':'connecting','session_id':active.sid})
        extra={'private_key':ticket.private_key,'passphrase':ticket.passphrase} if ticket.private_key else {}
        try:
            await transport.open(ticket.host,ticket.port,ticket.username,ticket.password,ticket.cols,ticket.rows,**extra)
        finally:
            extra.clear();ticket.password=ticket.private_key=ticket.passphrase=''
        current=await asyncio.to_thread(security37.session,ws)
        if not current or current['role']!='Admin' or current['id']!=ticket.user_id:
            raise HTTPException(401,'SESSION_EXPIRED')
        await asyncio.to_thread(audit,ticket,'connected')
        await send({'type':'status','status':'connected','session_id':active.sid,'host':ticket.host,'protocol':ticket.protocol})

        async def output_loop():
            while not active.stop.is_set():
                text=await transport.read()
                if text=='': return
                if text is None: continue
                active.sent_seq+=1; active.ack.clear()
                await send({'type':'output','data':text,'seq':active.sent_seq})
                # Browser acknowledges after xterm has rendered, not merely received.
                await asyncio.wait_for(active.ack.wait(),30)

        async def input_loop():
            window=time.monotonic(); frames=byte_count=0
            while not active.stop.is_set():
                message=await ws.receive_text()
                now=time.monotonic()
                if now-window>=1: window=now; frames=byte_count=0
                frames+=1; byte_count+=len(message.encode('utf-8'))
                if len(message)>16384 or byte_count>131072 or frames>180:
                    raise HTTPException(429,'TERMINAL_INPUT_RATE_LIMIT')
                msg=json.loads(message)
                if not isinstance(msg,dict): raise HTTPException(400,'INVALID_TERMINAL_FRAME')
                kind=msg.get('type')
                if kind=='input':
                    data=msg.get('data')
                    if not isinstance(data,str) or len(data.encode('utf-8'))>8192:
                        raise HTTPException(400,'TERMINAL_INPUT_TOO_LARGE')
                    # Recheck revocation before every user input; heartbeats are not activity.
                    now_user=await asyncio.to_thread(security37.session,ws)
                    if not now_user or now_user['role']!='Admin' or now_user['id']!=ticket.user_id:
                        raise HTTPException(401,'SESSION_EXPIRED')
                    active.last_input=time.monotonic()
                    await asyncio.wait_for(transport.write(data),5)
                elif kind=='resize':
                    cols,rows=msg.get('cols'),msg.get('rows')
                    if type(cols)!=int or type(rows)!=int or not 20<=cols<=400 or not 5<=rows<=150:
                        raise HTTPException(400,'INVALID_TERMINAL_SIZE')
                    await asyncio.wait_for(transport.resize(cols,rows),5)
                elif kind=='ack':
                    if type(msg.get('seq'))==int and msg['seq']==active.sent_seq: active.ack.set()
                elif kind=='ping': await send({'type':'pong'})
                elif kind=='close': return
                else: raise HTTPException(400,'UNKNOWN_TERMINAL_FRAME')

        async def watchdog():
            while True:
                try:
                    await asyncio.wait_for(active.stop.wait(),AUTH_CHECK_SECONDS)
                    return
                except asyncio.TimeoutError: pass
                now_user=await asyncio.to_thread(security37.session,ws)
                if not now_user or now_user['role']!='Admin' or now_user['id']!=ticket.user_id:
                    raise HTTPException(401,'SESSION_EXPIRED: sign in again')
                if time.monotonic()-active.last_input>IDLE_SECONDS:
                    raise HTTPException(408,'TERMINAL_IDLE_TIMEOUT')
                if time.monotonic()-active.created>SESSION_SECONDS:
                    raise HTTPException(408,'TERMINAL_MAX_DURATION')

        tasks=[asyncio.create_task(fn()) for fn in (input_loop,output_loop,watchdog)]
        done,_=await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
        for task in done: task.result()
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        code=error_code(exc)
        if ticket: await asyncio.to_thread(audit,ticket,'error',code.split(':')[0])
        try: await send({'type':'error','code':code})
        except Exception: pass
    finally:
        # Release capacity and erase credentials even if ASGI cancels during cleanup.
        if active:
            active.stop.set()
            registry.remove(active.sid)
        if ticket: ticket.password=ticket.private_key=ticket.passphrase=''
        with anyio.CancelScope(shield=True):
            for task in tasks: task.cancel()
            if tasks: await asyncio.gather(*tasks,return_exceptions=True)
            if transport:
                try: await transport.close()
                except Exception: pass
            if ticket: await asyncio.to_thread(audit,ticket,'closed')
            try: await ws.close(code=1000)
            except Exception: pass



async def shutdown():
    with registry.lock:
        for active in registry.active.values(): active.stop.set()
        for ticket in registry.tickets.values(): ticket.password=ticket.private_key=ticket.passphrase=''
        registry.tickets.clear()


def readiness_data():
    from app_runtime import DATABASE_DIR,DATA_DIR
    libs={}
    for name in ('fastapi','uvicorn','paramiko','cryptography','pysnmp','websockets'):
        try: libs[name]=importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError: libs[name]=None
    with connection() as c:
        check=c.execute('PRAGMA quick_check').fetchone()[0]
        count=c.execute('SELECT COUNT(*) FROM network_devices').fetchone()[0]
        accounts=c.execute('SELECT COUNT(*) FROM app_users WHERE enabled=1').fetchone()[0]
    return {'version':VERSION,'platform':platform.system(),'python':platform.python_version(),
            'database_check':check,'managed_devices':count,'enabled_accounts':accounts,
            'ping_available':bool(shutil.which('ping')),'libraries':libs,
            'known_hosts_present':(DATABASE_DIR/'known_hosts').is_file(),
            'credential_key_present':(DATABASE_DIR/'.credential.key').is_file(),
            'free_disk_bytes':shutil.disk_usage(DATA_DIR).free,
            'terminal':{'ssh':bool(libs['paramiko']),'telnet':True,'admin_only':True},
            'auto_refresh':'in-place; paused while editing; no page reload',
            'windows_autostart':'optional scheduled task at user logon; not a Windows service',
            'verified_device_connectivity':False,'observed_at':utcnow()}


@router.get('/readiness')
def readiness(request:Request):
    security37.require_role(request,'Admin')
    d=readiness_data()
    from app_runtime import DATA_DIR
    d['data_directory']=str(DATA_DIR)
    return d


@router.get('/diagnostics/export')
def export_diagnostics(request:Request):
    security37.require_role(request,'Admin')
    # Intentionally no IP list, usernames, config, secrets, raw errors or absolute paths.
    return Response(json.dumps(readiness_data(),ensure_ascii=False,indent=2),media_type='application/json',
                    headers={'Content-Disposition':'attachment; filename="NetworkAutomation_diagnostics.json"'})
