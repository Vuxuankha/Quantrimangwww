"""Isolated IP/Excel automation engine. No Tk calls and no device configuration writes.

All jobs are opt-in. Credentials stay in the existing encrypted credential store.
New workflow data uses autoip_* tables. Shared metrics feed the existing NMS views.
"""
from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import json
import math
import os
import re
import socket
import sqlite3
import subprocess
import threading
import time
import unicodedata
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from database import db
from modules.nms_v5 import encrypt_secret, decrypt_secret
from app_runtime import BACKUP_DIR, REPORT_DIR, DATABASE_DIR

MAX_TARGETS = 2048
DEFAULT_PROFILE = 'Default'
SYS = {'descr': '1.3.6.1.2.1.1.1.0', 'object': '1.3.6.1.2.1.1.2.0',
       'uptime': '1.3.6.1.2.1.1.3.0', 'name': '1.3.6.1.2.1.1.5.0'}
IF_INDEX = '1.3.6.1.2.1.2.2.1.1'
IF_OIDS = {'name': '1.3.6.1.2.1.2.2.1.2', 'oper': '1.3.6.1.2.1.2.2.1.8',
           'speed': '1.3.6.1.2.1.2.2.1.5', 'in32': '1.3.6.1.2.1.2.2.1.10',
           'out32': '1.3.6.1.2.1.2.2.1.16', 'in_errors': '1.3.6.1.2.1.2.2.1.14',
           'out_errors': '1.3.6.1.2.1.2.2.1.20', 'in_discards': '1.3.6.1.2.1.2.2.1.13',
           'out_discards': '1.3.6.1.2.1.2.2.1.19', 'in64': '1.3.6.1.2.1.31.1.1.1.6',
           'out64': '1.3.6.1.2.1.31.1.1.1.10', 'highspeed': '1.3.6.1.2.1.31.1.1.1.15'}
TASK_NAMES = {'inventory': 'Thi\u1ebft b\u1ecb', 'ping': 'Ping', 'tcp': 'C\u1ed5ng TCP',
              'snmp': 'SNMP / Driver', 'resources': 'CPU / RAM',
              'interfaces': 'C\u1ed5ng / L\u01b0u l\u01b0\u1ee3ng', 'topology': 'LLDP / CDP',
              'backup': 'Sao l\u01b0u SSH', 'alerts': 'C\u1ea3nh b\u00e1o / S\u1ef1 c\u1ed1',
              'notifications': 'Th\u00f4ng b\u00e1o', 'report': 'B\u00e1o c\u00e1o Excel',
              'email_report': 'G\u1eedi Gmail b\u00e1o c\u00e1o', 'engine': 'B\u1ed9 \u0111i\u1ec1u ph\u1ed1i'}


def now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


@contextmanager
def connect():
    c = sqlite3.connect(db.DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    try:
        c.execute('PRAGMA busy_timeout=30000')
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def ensure_tables():
    # Main application performs its original migrations; do not overwrite drivers here.
    with connect() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS autoip_profiles(
          name TEXT PRIMARY KEY, mode TEXT NOT NULL DEFAULT 'assigned',
          community_enc TEXT DEFAULT '', snmpv3_id INTEGER, ssh_id INTEGER,
          port INTEGER NOT NULL DEFAULT 161, updated_at TEXT);
        CREATE TABLE IF NOT EXISTS autoip_settings(id INTEGER PRIMARY KEY CHECK(id=1), data TEXT);
        CREATE TABLE IF NOT EXISTS autoip_targets(ip TEXT PRIMARY KEY, name TEXT, profile TEXT);
        CREATE TABLE IF NOT EXISTS autoip_runs(
          id TEXT PRIMARY KEY, started_at TEXT, finished_at TEXT, status TEXT,
          username TEXT, total INTEGER, cycle INTEGER, options TEXT, report_path TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS autoip_steps(
          id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, ip TEXT, task TEXT,
          status TEXT, message TEXT, data TEXT, created_at TEXT);
        CREATE INDEX IF NOT EXISTS autoip_steps_run ON autoip_steps(run_id,id);
        CREATE TABLE IF NOT EXISTS autoip_counters(
          ip TEXT, ifindex INTEGER, in_octets INTEGER, out_octets INTEGER,
          bits INTEGER, uptime REAL, sampled_at REAL, PRIMARY KEY(ip,ifindex));
        ''')
        # The old RCA queries also use legacy aliases. Fresh databases lack them.
        # Add only absent columns; never replace existing user data.
        for table, columns in {
            'network_devices': {'device_name': 'TEXT', 'ip_address': 'TEXT'},
            'alerts': {'ip_address': 'TEXT', 'resolved': 'INTEGER DEFAULT 0'},
        }.items():
            present = {r['name'] for r in c.execute(f'PRAGMA table_info({table})')}
            for column, definition in columns.items():
                if column not in present:
                    c.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')
        c.execute('INSERT OR IGNORE INTO autoip_profiles(name,mode,updated_at) VALUES(?,?,?)',
                  (DEFAULT_PROFILE, 'assigned', now()))


def normalize_header(value):
    text = unicodedata.normalize('NFKD', str(value or '').strip().lower().replace('\u0111', 'd'))
    return re.sub(r'[^a-z0-9]', '', ''.join(x for x in text if not unicodedata.combining(x)))


def validate_ip(value):
    text = str(value or '').strip()
    if '%' in text:
        raise ValueError('IPv6 scope ID ch\u01b0a \u0111\u01b0\u1ee3c h\u1ed7 tr\u1ee3.')
    try:
        addr = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValueError(f'IP kh\u00f4ng h\u1ee3p l\u1ec7: {text[:80]}') from exc
    if addr.is_multicast or addr.is_unspecified or str(addr) == '255.255.255.255':
        raise ValueError(f'Kh\u00f4ng nh\u1eadn IP multicast/broadcast/unspecified: {addr}')
    return str(addr)


@dataclass(frozen=True)
class Target:
    ip: str
    name: str = ''
    profile: str = ''


def parse_rows(rows):
    result, seen, duplicates = [], set(), 0
    for number, row in enumerate(rows, 2):
        ip = str(row.get('ip') or '').strip()
        name = str(row.get('name') or '').strip()
        profile = str(row.get('profile') or '').strip()
        if not ip and not name and not profile:
            continue
        if len(result) >= MAX_TARGETS:
            raise ValueError(f'T\u1ed1i \u0111a {MAX_TARGETS} IP m\u1ed7i \u0111\u1ee3t.')
        if len(name) > 200 or len(profile) > 120:
            raise ValueError(f'D\u00f2ng {number}: t\u00ean qu\u00e1 d\u00e0i.')
        addr = validate_ip(ip)
        if addr in seen:
            duplicates += 1
            continue
        seen.add(addr)
        result.append(Target(addr, name, profile))
    if not result:
        raise ValueError('Danh s\u00e1ch kh\u00f4ng c\u00f3 IP.')
    return result, duplicates


def parse_text(text):
    tokens = re.split(r'[\s,;]+', str(text).strip())
    if len(tokens) > MAX_TARGETS * 2:
        raise ValueError('Danh s\u00e1ch qu\u00e1 l\u1edbn.')
    return parse_rows({'ip': x} for x in tokens if x)


def parse_excel(path):
    from openpyxl import load_workbook
    path = Path(path)
    if path.suffix.lower() != '.xlsx':
        raise ValueError('Ch\u1ec9 nh\u1eadn .xlsx. H\u00e3y l\u01b0u file .xls th\u00e0nh .xlsx.')
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('File v\u01b0\u1ee3t 8 MB.')
    with zipfile.ZipFile(path) as z:
        entries = z.infolist()
        if len(entries) > 2000 or sum(x.file_size for x in entries) > 40 * 1024 * 1024:
            raise ValueError('N\u1ed9i dung Excel v\u01b0\u1ee3t gi\u1edbi h\u1ea1n an to\u00e0n.')
    wb = load_workbook(path, read_only=True, data_only=False, keep_links=False)
    try:
        ws = wb['IP_List'] if 'IP_List' in wb.sheetnames else wb.worksheets[0]
        if ws.max_row and ws.max_row > MAX_TARGETS * 2 + 1:
            raise ValueError('Sheet qu\u00e1 nhi\u1ec1u d\u00f2ng; t\u00e1ch th\u00e0nh file nh\u1ecf.')
        rows = ws.iter_rows()
        header = next(rows, None)
        if not header:
            raise ValueError('Sheet r\u1ed7ng.')
        aliases = {'ip': 'ip', 'ipaddress': 'ip', 'diachiip': 'ip',
                   'name': 'name', 'tenthietbi': 'name', 'hostname': 'name',
                   'profile': 'profile', 'hoso': 'profile'}
        mapping = {}
        for i, cell in enumerate(header):
            key = aliases.get(normalize_header(cell.value))
            if key:
                if key in mapping.values():
                    raise ValueError('C\u1ed9t b\u1ecb tr\u00f9ng: ' + key)
                mapping[i] = key
        if 'ip' not in mapping.values():
            raise ValueError('D\u00f2ng \u0111\u1ea7u c\u1ea7n c\u1ed9t IP (ho\u1eb7c IP Address).')
        data = []
        for count, cells in enumerate(rows, 2):
            if count > MAX_TARGETS * 2 + 1:
                raise ValueError('Qu\u00e1 nhi\u1ec1u d\u00f2ng.')
            row = {}
            for i, key in mapping.items():
                cell = cells[i] if i < len(cells) else None
                if cell is not None and cell.data_type == 'f':
                    raise ValueError(f'D\u00f2ng {count}: nh\u1eadp gi\u00e1 tr\u1ecb, kh\u00f4ng d\u00f9ng c\u00f4ng th\u1ee9c.')
                row[key] = cell.value if cell else None
            data.append(row)
        return parse_rows(data)
    finally:
        wb.close()


def profiles():
    with connect() as c:
        return [dict(r) for r in c.execute('SELECT * FROM autoip_profiles ORDER BY name')]


def credentials(kind):
    with connect() as c:
        if kind == 'v3':
            return [dict(r) for r in c.execute('SELECT id,name FROM snmpv3_credentials ORDER BY name')]
        return [dict(r) for r in c.execute("SELECT id,name FROM credentials WHERE UPPER(kind)='SSH' ORDER BY name")]


def save_profile(name, mode, community='', snmpv3_id=None, ssh_id=None, port=161, role='Viewer'):
    if role != 'Admin':
        raise PermissionError('Ch\u1ec9 Admin \u0111\u01b0\u1ee3c s\u1eeda h\u1ed3 s\u01a1 k\u1ebft n\u1ed1i.')
    name = name.strip()
    if not name or len(name) > 120 or mode not in ('assigned', 'off', 'v2c', 'v3'):
        raise ValueError('T\u00ean ho\u1eb7c ch\u1ebf \u0111\u1ed9 h\u1ed3 s\u01a1 kh\u00f4ng h\u1ee3p l\u1ec7.')
    if not 1 <= int(port) <= 65535:
        raise ValueError('Port ph\u1ea3i t\u1eeb 1 \u0111\u1ebfn 65535.')
    with connect() as c:
        old = c.execute('SELECT * FROM autoip_profiles WHERE name=?', (name,)).fetchone()
        enc = encrypt_secret(community) if community else (old['community_enc'] if old else '')
        if mode == 'v2c' and not enc:
            raise ValueError('Nh\u1eadp SNMP community.')
        if mode == 'v3' and not c.execute('SELECT id FROM snmpv3_credentials WHERE id=?', (snmpv3_id,)).fetchone():
            raise ValueError('Ch\u1ecdn Credential SNMPv3 \u0111\u00e3 l\u01b0u.')
        if ssh_id and not c.execute("SELECT id FROM credentials WHERE id=? AND UPPER(kind)='SSH'", (ssh_id,)).fetchone():
            raise ValueError('Credential SSH kh\u00f4ng t\u1ed3n t\u1ea1i.')
        c.execute('''INSERT INTO autoip_profiles VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(name) DO UPDATE SET mode=excluded.mode,community_enc=excluded.community_enc,
            snmpv3_id=excluded.snmpv3_id,ssh_id=excluded.ssh_id,port=excluded.port,updated_at=excluded.updated_at''',
                  (name, mode, enc, snmpv3_id, ssh_id, int(port), now()))


@dataclass(frozen=True)
class Options:
    default_profile: str = DEFAULT_PROFILE
    ping: bool = True
    tcp: bool = True
    snmp: bool = True
    resources: bool = True
    interfaces: bool = True
    topology: bool = True
    backup: bool = False
    alerts: bool = True
    notifications: bool = False
    report: bool = True
    repeat: bool = False
    interval: int = 300
    workers: int = 4
    timeout: float = 2.0
    retries: int = 1
    max_interfaces: int = 128
    device_budget: int = 120
    ports: str = '22,80,443'
    auto_start: bool = True
    email_report_after_run: bool = False
    report_email_to: str = ''

    def validate(self):
        if not (1 <= int(self.workers) <= 16 and 0.5 <= float(self.timeout) <= 10):
            raise ValueError('Worker: 1-16; timeout: 0.5-10 gi\u00e2y.')
        if not 0 <= int(self.retries) <= 2:
            raise ValueError('Retry: 0-2.')
        if not 30 <= int(self.interval) <= 86400:
            raise ValueError('Chu k\u1ef3: 30-86400 gi\u00e2y, t\u00ednh sau khi xong m\u1ed9t l\u01b0\u1ee3t.')
        if not 1 <= int(self.max_interfaces) <= 512 or not 30 <= int(self.device_budget) <= 600:
            raise ValueError('Gi\u1edbi h\u1ea1n c\u1ed5ng/th\u1eddi gian kh\u00f4ng h\u1ee3p l\u1ec7.')
        if self.tcp:
            self.port_list()
        return self

    def port_list(self):
        try:
            ports = sorted(set(int(x.strip()) for x in self.ports.split(',') if x.strip()))
        except ValueError as exc:
            raise ValueError('TCP: nh\u1eadp s\u1ed1 c\u1ed5ng c\u00e1ch nhau b\u1eb1ng d\u1ea5u ph\u1ea9y.') from exc
        if not ports or len(ports) > 32 or any(p < 1 or p > 65535 for p in ports):
            raise ValueError('Ch\u1ecdn 1-32 c\u1ed5ng TCP, m\u1ed7i c\u1ed5ng 1-65535.')
        return ports


def load_options():
    with connect() as c:
        row = c.execute('SELECT data FROM autoip_settings WHERE id=1').fetchone()
    try:
        data = json.loads(row['data']) if row else {}
        return Options(**{k: v for k, v in data.items() if k in Options.__dataclass_fields__}).validate()
    except (ValueError, TypeError):
        return Options()


def save_options(options):
    options.validate()
    with connect() as c:
        c.execute('INSERT OR REPLACE INTO autoip_settings(id,data) VALUES(1,?)', (json.dumps(asdict(options)),))


def save_targets(targets):
    with connect() as c:
        c.execute('DELETE FROM autoip_targets')
        c.executemany('INSERT INTO autoip_targets(ip,name,profile) VALUES(?,?,?)',
                      [(x.ip, x.name, x.profile) for x in targets])


def load_targets():
    with connect() as c:
        return [Target(**dict(r)) for r in c.execute('SELECT ip,name,profile FROM autoip_targets ORDER BY rowid')]


class SkipTask(Exception):
    pass


class Cancelled(Exception):
    pass


def numeric(value):
    try:
        result = float(value)
        return result if math.isfinite(result) else None
    except (TypeError, ValueError):
        return None


def excel_safe(value):
    # Device names / SNMP strings are untrusted, never Excel formulas.
    if isinstance(value, str):
        value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', value)[:32000]
        if value.lstrip().startswith(('=', '+', '-', '@')):
            return "'" + value
    return value


def redact(error, secrets=()):
    text = str(error) or type(error).__name__
    for secret in sorted((str(s) for s in secrets if s), key=len, reverse=True):
        text = text.replace(secret, '***')
    return text[:1800]


def upsert_device(target):
    # Both inventories are supported, including the legacy NOT NULL ip_address schema.
    with connect() as c:
        r = c.execute('SELECT id,name FROM network_devices WHERE ip=? ORDER BY id LIMIT 1', (target.ip,)).fetchone()
        if r:
            did = r['id']
            # Do not overwrite user labels automatically.
        else:
            cols = {r['name'] for r in c.execute('PRAGMA table_info(network_devices)')}
            data = {'name': target.name or target.ip, 'ip': target.ip, 'status': 'Unknown',
                    'created_at': now(), 'updated_at': now()}
            for alias, val in [('device_name', data['name']), ('ip_address', target.ip)]:
                if alias in cols:
                    data[alias] = val
            did = c.execute('INSERT INTO network_devices(' + ','.join(data) + ') VALUES(' +
                            ','.join('?' for _ in data) + ')', tuple(data.values())).lastrowid
        if not c.execute('SELECT id FROM devices WHERE ip=?', (target.ip,)).fetchone():
            cols = {r['name'] for r in c.execute('PRAGMA table_info(devices)')}
            data = {'ip': target.ip, 'hostname': target.name or '', 'status': 'Unknown',
                    'first_seen': now(), 'last_seen': now()}
            if 'ip_address' in cols:
                data['ip_address'] = target.ip
            c.execute('INSERT INTO devices(' + ','.join(data) + ') VALUES(' + ','.join('?' for _ in data) + ')', tuple(data.values()))
    return did


def resolve_credentials(target, did, options):
    with connect() as c:
        profile = c.execute('SELECT * FROM autoip_profiles WHERE name=?', (target.profile or options.default_profile,)).fetchone()
        if not profile:
            raise ValueError('Kh\u00f4ng t\u00ecm th\u1ea5y h\u1ed3 s\u01a1: ' + (target.profile or options.default_profile))
        p = dict(profile)
        mode, v3_id, community, port = p['mode'], p['snmpv3_id'], '', p['port']
        snmp_error = ''
        if mode == 'assigned':
            assignment = c.execute('SELECT credential_id FROM device_snmpv3_assignments WHERE device_id=?', (did,)).fetchone()
            if assignment:
                mode, v3_id = 'v3', assignment['credential_id']
            else:
                # Web and Desktop share assignments: prefer the encrypted v2 vault,
                # with the legacy desktop profile as a backwards-compatible fallback.
                secure = None
                if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='web_device_snmpv2_assignments42'").fetchone():
                    secure = c.execute('''SELECT s.* FROM web_device_snmpv2_assignments42 a
                        JOIN web_snmpv2_credentials42 s ON s.id=a.credential_id WHERE a.device_id=?''', (did,)).fetchone()
                legacy = c.execute('SELECT * FROM snmp_profiles WHERE host=? AND enabled=1 ORDER BY id LIMIT 1', (target.ip,)).fetchone()
                if secure:
                    try:
                        mode, community, port = 'v2c', decrypt_secret(secure['community_enc']), secure['port']
                    except Exception:
                        mode = 'off'
                        snmp_error = 'Cannot decrypt SNMPv2 credential; check the matching credential key.'
                elif legacy:
                    mode, community, port = 'v2c', legacy['community'], legacy['port']
                else:
                    mode = 'off'
        elif mode == 'v2c':
            try:
                community = decrypt_secret(p['community_enc'])
            except Exception:
                mode = 'off'
                snmp_error = 'Kh\u00f4ng gi\u1ea3i m\u00e3 \u0111\u01b0\u1ee3c Community; ki\u1ec3m tra .credential.key.'
        v3 = None
        if mode == 'v3':
            row = c.execute('SELECT * FROM snmpv3_credentials WHERE id=?', (v3_id,)).fetchone()
            if not row:
                mode = 'off'
                snmp_error = 'Credential SNMPv3 \u0111\u00e3 b\u1ecb x\u00f3a ho\u1eb7c ch\u01b0a g\u00e1n.'
            else:
                v3 = dict(row)
                port = int(v3['port'] or 161)
        ssh_id = p['ssh_id']
        if not ssh_id:
            row = c.execute("SELECT credential_id FROM device_credentials WHERE device_id=? AND UPPER(purpose)='SSH'", (did,)).fetchone()
            ssh_id = row['credential_id'] if row else None
        row = c.execute("SELECT * FROM credentials WHERE id=? AND UPPER(kind)='SSH'", (ssh_id,)).fetchone()
        ssh = dict(row) if row else None
    return {'mode': mode, 'community': community, 'port': int(port), 'v3': v3, 'ssh': ssh, 'snmp_error': snmp_error}


class NetworkAdapter:
    """One adapter per target, one asyncio engine per worker; GET/GETNEXT only."""
    def __init__(self, host, credential, options, stop):
        self.host, self.credential, self.options, self.stop = host, credential, options, stop
        self.deadline = time.monotonic() + options.device_budget
        self.loop = None
        self.engine = None
        self.secret_values = [credential.get('community', '')]

    def check(self):
        if self.stop.is_set():
            raise Cancelled('D\u1eebng theo y\u00eau c\u1ea7u.')
        if time.monotonic() >= self.deadline:
            raise TimeoutError('H\u1ebft ng\u00e2n s\u00e1ch th\u1eddi gian cho IP n\u00e0y.')

    def ping(self):
        self.check()
        from modules.icmp_probe import icmp_ping
        result = icmp_ping(self.host, int(self.options.timeout * 1000), count=2)
        if result['status'] == 'Error':
            raise RuntimeError(result['error'])
        return {'alive': result['status'] == 'Online', 'latency_ms': result['response'],
                'packet_loss': result['packet_loss']}

    def tcp(self):
        result = {}
        for port in self.options.port_list():
            self.check()
            try:
                with socket.create_connection((self.host, port), timeout=self.options.timeout):
                    result[str(port)] = 'OPEN'
            except OSError:
                result[str(port)] = 'CLOSED_OR_FILTERED'
        return result

    async def _init_snmp(self):
        if self.engine is not None:
            return
        if self.credential.get('snmp_error'):
            raise SkipTask(self.credential['snmp_error'])
        if self.credential['mode'] == 'off':
            raise SkipTask('Ch\u01b0a c\u00f3 h\u1ed3 s\u01a1 SNMP, ho\u1eb7c SNMP \u0111ang t\u1eaft trong h\u1ed3 s\u01a1.')
        try:
            from pysnmp.hlapi.v3arch import asyncio as hl
        except ImportError as exc:
            raise SkipTask('Thi\u1ebfu pysnmp 7.x: ch\u1ea1y pip install -r requirements.txt.') from exc
        self.hl = hl
        self.engine = hl.SnmpEngine()
        if self.credential['mode'] == 'v3':
            from modules.nms_v12 import _proto_constants
            cred = self.credential['v3']
            if cred['security_level'] not in ('noAuthNoPriv', 'authNoPriv', 'authPriv'):
                raise ValueError('Invalid SNMPv3 security level; refusing to downgrade.')
            if cred['security_level'] != 'noAuthNoPriv' and str(cred['auth_protocol']).upper() not in ('MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512'):
                raise ValueError('Unsupported SNMPv3 authentication protocol.')
            if cred['security_level'] == 'authPriv' and str(cred['priv_protocol']).upper() not in ('DES', 'AES128', 'AES192', 'AES256'):
                raise ValueError('Unsupported SNMPv3 privacy protocol.')
            kwargs = {}
            auth, priv = _proto_constants(hl, cred['auth_protocol'], cred['priv_protocol'])
            if cred['security_level'] in ('authNoPriv', 'authPriv'):
                if auth is None:
                    raise ValueError('Thu\u1eadt to\u00e1n SNMP Auth kh\u00f4ng \u0111\u01b0\u1ee3c h\u1ed7 tr\u1ee3.')
                key = decrypt_secret(cred['auth_secret_enc'])
                self.secret_values.append(key)
                kwargs.update(authKey=key, authProtocol=auth)
            if cred['security_level'] == 'authPriv':
                if priv is None:
                    raise ValueError('Thu\u1eadt to\u00e1n SNMP Privacy kh\u00f4ng \u0111\u01b0\u1ee3c h\u1ed7 tr\u1ee3.')
                key = decrypt_secret(cred['priv_secret_enc'])
                self.secret_values.append(key)
                kwargs.update(privKey=key, privProtocol=priv)
            self.auth = hl.UsmUserData(cred['username'], **kwargs)
            self.context = hl.ContextData(contextName=cred.get('context_name', ''))
        else:
            self.auth = hl.CommunityData(self.credential['community'], mpModel=1)
            self.context = hl.ContextData()
        transport = hl.Udp6TransportTarget if ipaddress.ip_address(self.host).version == 6 else hl.UdpTransportTarget
        self.transport = await transport.create((self.host, self.credential['port']),
                                                timeout=self.options.timeout, retries=self.options.retries)

    async def _request(self, oids, next_request=False):
        await self._init_snmp()
        hl = self.hl
        fun = hl.next_cmd if next_request else hl.get_cmd
        err, status, index, bindings = await fun(self.engine, self.auth, self.transport, self.context,
                                                *[hl.ObjectType(hl.ObjectIdentity(o)) for o in oids], lookupMib=False)
        if err:
            raise TimeoutError(str(err))
        if status:
            raise RuntimeError(status.prettyPrint())
        from pysnmp.proto.rfc1905 import NoSuchObject, NoSuchInstance, EndOfMibView
        out = {}
        for oid, value in bindings:
            key = str(oid)
            if isinstance(value, (NoSuchObject, NoSuchInstance, EndOfMibView)):
                out[key] = None
            elif value.__class__.__name__ in ('Integer', 'Integer32', 'Counter32', 'Counter64', 'Gauge32', 'Unsigned32', 'TimeTicks'):
                out[key] = int(value)
            else:
                out[key] = value.prettyPrint()
        return out

    def _call(self, oids, next_request=False):
        self.check()
        if self.loop is None:
            self.loop = asyncio.new_event_loop()
        budget = min(self.options.timeout * (self.options.retries + 2) + 3, self.deadline - time.monotonic())
        return self.loop.run_until_complete(asyncio.wait_for(self._request(oids, next_request), timeout=max(0.1, budget)))

    def get(self, oids):
        return self._call(oids)

    def walk(self, base, limit=None):
        limit = limit or self.options.max_interfaces
        current, result, truncated = base, {}, False
        for _ in range(limit + 1):
            values = self._call([current], True)
            if not values:
                break
            oid, value = next(iter(values.items()))
            if value is None or not oid.startswith(base + '.') or tuple(map(int, oid.split('.'))) <= tuple(map(int, current.split('.'))):
                break
            if len(result) == limit:
                truncated = True
                break
            result[oid] = value
            current = oid
        return result, truncated

    def backup(self, driver):
        self.check()
        cred = self.credential.get('ssh')
        if not cred:
            raise SkipTask('Ch\u01b0a g\u00e1n Credential SSH.')
        command = (driver or {}).get('backup_command', '').strip()
        # Never execute arbitrary custom-driver commands in this automatic workflow.
        if command not in ('show running-config', '/export terse', 'display current-configuration', 'show configuration'):
            raise SkipTask('Driver ch\u01b0a c\u00f3 l\u1ec7nh backup ch\u1ec9 \u0111\u1ecdc trong danh s\u00e1ch cho ph\u00e9p.')
        try:
            import paramiko
        except ImportError as exc:
            raise SkipTask('Thi\u1ebfu paramiko: ch\u1ea1y pip install -r requirements.txt.') from exc
        secret = decrypt_secret(cred['secret_enc'])
        self.secret_values.append(secret)
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        known = DATABASE_DIR / 'known_hosts'
        if known.exists():
            client.load_host_keys(str(known))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(self.host, port=int(cred['port'] or 22), username=cred['username'], password=secret,
                           timeout=self.options.timeout, auth_timeout=10, banner_timeout=10,
                           look_for_keys=False, allow_agent=False)
            transport = client.get_transport()
            chan = transport.open_session(timeout=self.options.timeout)
            chan.settimeout(self.options.timeout)
            chan.exec_command(command)
            data, error = bytearray(), bytearray()
            until = min(self.deadline, time.monotonic() + 30)
            while True:
                self.check()
                if time.monotonic() >= until:
                    raise TimeoutError('Backup qu\u00e1 30 gi\u00e2y; ch\u01b0a l\u01b0u file.')
                if chan.recv_ready():
                    data.extend(chan.recv(65536))
                if chan.recv_stderr_ready():
                    error.extend(chan.recv_stderr(65536))
                if len(data) + len(error) > 8 * 1024 * 1024:
                    raise ValueError('Backup v\u01b0\u1ee3t 8 MB.')
                if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                    break
                self.stop.wait(0.05)
            code = chan.recv_exit_status()
            text = data.decode('utf-8', errors='replace')
            if code not in (0, -1) or not text.strip() or error or re.search(r'(?im)^\s*(%\s*(?:invalid|error|incomplete|ambiguous)|syntax error)', text):
                raise RuntimeError('Thi\u1ebft b\u1ecb kh\u00f4ng tr\u1ea3 c\u1ea5u h\u00ecnh h\u1ee3p l\u1ec7; kh\u00f4ng l\u01b0u backup.')
        finally:
            client.close()
        path = BACKUP_DIR / 'auto_ip' / (self.host.replace(':', '_') + '_' + datetime.now().strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:8] + '.cfg')
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'x', encoding='utf-8') as f:
            f.write(text)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        with connect() as c:
            c.execute('INSERT INTO config_backups(device_name,source,file_path,size_bytes,note,created_at) VALUES(?,?,?,?,?,?)',
                      (self.host, 'Auto IP / SSH', str(path), path.stat().st_size, 'Read-only, verified host key', now()))
        return {'path': str(path)}

    def close(self):
        if self.engine is not None:
            self.engine.close_dispatcher()
        if self.loop is not None:
            self.loop.run_until_complete(self.loop.shutdown_asyncgens())
            self.loop.close()


def select_driver(did, descr, object_id):
    # Preserve manual assignments and never call ensure_v12_tables from concurrent workers.
    with connect() as c:
        row = c.execute('''SELECT d.* FROM vendor_drivers d JOIN device_driver_assignments a ON d.id=a.driver_id
                          WHERE a.device_id=? AND d.enabled=1''', (did,)).fetchone()
        if row:
            return dict(row)
        drivers = [dict(r) for r in c.execute('SELECT * FROM vendor_drivers WHERE enabled=1 ORDER BY priority DESC,id')]
        for driver in drivers:
            prefix = (driver.get('sysobject_prefix') or '').strip('.')
            oid = str(object_id or '').strip('.')
            regex = driver.get('descr_regex') or ''
            try:
                matched = bool(regex and re.search(regex, str(descr or ''), re.I))
            except re.error:
                matched = False
            if (prefix and (oid == prefix or oid.startswith(prefix + '.'))) or matched:
                c.execute('''INSERT OR IGNORE INTO device_driver_assignments
                (device_id,driver_id,source,detected_descr,detected_object_id,updated_at) VALUES(?,?,?,?,?,?)''',
                          (did, driver['id'], 'auto_ip', str(descr), str(object_id), now()))
                return driver
    return None


def get_existing_driver(did):
    with connect() as c:
        r = c.execute('''SELECT d.* FROM vendor_drivers d JOIN device_driver_assignments a ON d.id=a.driver_id
                        WHERE a.device_id=? AND d.enabled=1''', (did,)).fetchone()
        return dict(r) if r else None


def collect_resources(adapter, driver):
    if not driver:
        raise SkipTask('Ch\u01b0a nh\u1eadn di\u1ec7n/g\u00e1n driver; kh\u00f4ng \u0111o\u00e1n OID.')
    keys = ['cpu_oid', 'mem_used_oid', 'mem_total_oid']
    oids = [driver[k] for k in keys if driver.get(k)]
    if not oids:
        raise SkipTask('Driver ch\u01b0a khai b\u00e1o OID CPU/RAM cho model n\u00e0y.')
    vals = adapter.get(oids)
    cpu, used, total = (numeric(vals.get(driver.get(k))) for k in keys)
    memory = used * 100.0 / total if used is not None and total and total > 0 else None
    cpu = cpu if cpu is not None and 0 <= cpu <= 100 else None
    memory = memory if memory is not None and 0 <= memory <= 100 else None
    if cpu is None and memory is None:
        raise SkipTask('OID kh\u00f4ng tr\u1ea3 CPU/RAM h\u1ee3p l\u1ec7; ki\u1ec3m tra driver.')
    with connect() as c:
        c.execute('INSERT INTO health_samples(host,cpu,memory,created_at) VALUES(?,?,?,?)', (adapter.host, cpu, memory, now()))
    return {'cpu': cpu, 'memory': memory}


def rate_from_counter(previous, current, elapsed, bits, speed=None, reset=False):
    if reset or previous is None or current is None or elapsed <= 0 or current < previous:
        return None  # Never turn a counter reset/wrap into an artificial traffic spike.
    if bits == 32 and (not speed or elapsed * speed / 8 >= 2 ** 32):
        return None  # Ambiguous multiple wraps at fast interfaces.
    rate = (current - previous) * 8 / elapsed
    if speed and rate > speed * 1.1:
        return None
    return rate


def collect_interfaces(adapter, uptime):
    indexes, truncated = adapter.walk(IF_INDEX)
    if not indexes:
        raise SkipTask('Thi\u1ebft b\u1ecb kh\u00f4ng cung c\u1ea5p IF-MIB.')
    result, errors = [], []
    for oid, value in indexes.items():
        adapter.check()
        index = int(value)
        try:
            vals = adapter.get([base + '.' + str(index) for base in IF_OIDS.values()])
            row = {key: vals.get(base + '.' + str(index)) for key, base in IF_OIDS.items()}
            count_in, count_out, bits = row['in64'], row['out64'], 64
            if not isinstance(count_in, int) or not isinstance(count_out, int):
                count_in, count_out, bits = row['in32'], row['out32'], 32
            speed = int(row['highspeed']) * 1000000 if numeric(row['highspeed']) else row['speed']
            stamp = time.time()
            with connect() as c:
                prev = c.execute('SELECT * FROM autoip_counters WHERE ip=? AND ifindex=?', (adapter.host, index)).fetchone()
                elapsed = stamp - prev['sampled_at'] if prev else 0
                reset = bool(prev and (prev['bits'] != bits or (uptime is not None and prev['uptime'] is not None and uptime < prev['uptime'])))
                in_bps = rate_from_counter(prev['in_octets'] if prev else None, count_in, elapsed, bits, numeric(speed), reset)
                out_bps = rate_from_counter(prev['out_octets'] if prev else None, count_out, elapsed, bits, numeric(speed), reset)
                c.execute('''INSERT INTO interface_samples(host,ifindex,ifname,oper_status,speed_bps,in_octets,out_octets,
                             in_errors,out_errors,in_discards,out_discards,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
                          (adapter.host, index, str(row['name'] or index), row['oper'], speed, count_in, count_out,
                           row['in_errors'], row['out_errors'], row['in_discards'], row['out_discards'], now()))
                c.execute('''INSERT INTO snmp_samples(host,interface_index,oper_status,in_octets,out_octets,
                             in_bps,out_bps,uptime_ticks,created_at) VALUES(?,?,?,?,?,?,?,?,?)''',
                          (adapter.host, index, row['oper'], count_in, count_out, in_bps, out_bps, uptime, now()))
                c.execute('INSERT OR REPLACE INTO autoip_counters VALUES(?,?,?,?,?,?,?)',
                          (adapter.host, index, count_in, count_out, bits, uptime, stamp))
            result.append({'ifindex': index, 'name': row['name'], 'oper_status': row['oper'],
                           'in_bps': in_bps, 'out_bps': out_bps, 'counter_bits': bits})
        except (Cancelled, TimeoutError):
            raise
        except Exception as exc:
            errors.append({'ifindex': index, 'error': redact(exc, adapter.secret_values)})
    if not result:
        raise RuntimeError('Kh\u00f4ng \u0111\u1ecdc \u0111\u01b0\u1ee3c c\u1ed5ng; xem IF-MIB/driver.')
    return {'interfaces': result, 'truncated': truncated, 'errors': errors,
            'rate_note': 'L\u01b0u l\u01b0\u1ee3ng c\u1ea7n t\u1ed1i thi\u1ec3u hai l\u1ea7n l\u1ea5y m\u1eabu h\u1ee3p l\u1ec7.'}


def collect_topology(adapter, driver):
    protocols = [('LLDP', '1.0.8802.1.1.2.1.4.1.1.9', '1.0.8802.1.1.2.1.4.1.1.7')]
    if 'CDP' in (driver or {}).get('lldp_mode', ''):
        protocols.append(('CDP', '1.3.6.1.4.1.9.9.23.1.2.1.1.6', '1.3.6.1.4.1.9.9.23.1.2.1.1.7'))
    found, errors, truncated = [], [], False
    for protocol, base_name, base_port in protocols:
        try:
            names, tn = adapter.walk(base_name)
            ports, tp = adapter.walk(base_port) if names else ({}, False)
            truncated = truncated or tn or tp
            for oid, name in names.items():
                suffix = oid[len(base_name) + 1:]
                local = suffix.split('.')[-2] if '.' in suffix else suffix
                found.append((protocol, adapter.host, local, str(name), str(ports.get(base_port + '.' + suffix, ''))))
        except (Cancelled, TimeoutError):
            raise
        except Exception as exc:
            errors.append(redact(exc, adapter.secret_values))
    with connect() as c:
        for row in found:
            c.execute('''INSERT INTO discovery_links(protocol,local_host,local_port,remote_name,remote_port,discovered_at)
                         VALUES(?,?,?,?,?,?) ON CONFLICT(protocol,local_host,local_port,remote_name,remote_port)
                         DO UPDATE SET discovered_at=excluded.discovered_at''', row + (now(),))
        devices = [dict(r) for r in c.execute('SELECT id,ip,name FROM network_devices')]
        for protocol, host, lp, neighbor, rp in found:
            sources = [r for r in devices if r['ip'] == host]
            matches = [r for r in devices if neighbor.strip().lower() in ((r['name'] or '').strip().lower(), (r['ip'] or '').strip().lower())]
            if len(sources) == 1 and len(matches) == 1 and sources[0]['id'] != matches[0]['id']:
                a, b = sorted((sources[0]['id'], matches[0]['id']))
                c.execute('INSERT OR IGNORE INTO device_links(source_device_id,target_device_id,label,created_at) VALUES(?,?,?,?)',
                          (a, b, f'{protocol}: {lp} <-> {rp}', now()))
    return {'neighbors': len(found), 'truncated': truncated, 'errors': errors}


def export_report(run_id, destination):
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment
    with connect() as c:
        run = c.execute('SELECT * FROM autoip_runs WHERE id=?', (run_id,)).fetchone()
        rows = [dict(r) for r in c.execute('SELECT ip,task,status,message,created_at,data FROM autoip_steps WHERE run_id=? ORDER BY id', (run_id,))]
    if not run:
        raise ValueError('Kh\u00f4ng t\u00ecm th\u1ea5y l\u01b0\u1ee3t ch\u1ea1y.')
    wb = Workbook()
    info = wb.active
    info.title = 'Summary'
    info.append(['AUTO IP / EXCEL', 'NetworkAutomation v3.13'])
    for key in ('id', 'started_at', 'finished_at', 'status', 'total', 'cycle'):
        info.append([key, excel_safe(run[key])])
    counts = {}
    for row in rows:
        counts[row['status']] = counts.get(row['status'], 0) + 1
    for status, count in counts.items():
        info.append([status, count])
    info.append(['Note', 'Completed means workflow finished; review SKIP/WARN/ERROR. No credentials included.'])
    sheet = wb.create_sheet('Results')
    sheet.append(['IP', 'Task', 'Status', 'Detail', 'Time', 'Data (JSON)'])
    for row in rows:
        sheet.append([excel_safe(row[k]) for k in ('ip', 'task', 'status', 'message', 'created_at', 'data')])
    for ws in wb:
        ws.sheet_view.showGridLines = False
        ws.freeze_panes = 'A2'
        ws.auto_filter.ref = ws.dimensions
        for cell in ws[1]:
            cell.font = Font(bold=True, color='FFFFFF')
            cell.fill = PatternFill('solid', fgColor='183153')
        ws.row_dimensions[1].height = 26
        for row in ws.iter_rows(min_row=2):
            for cell in row:
                cell.alignment = Alignment(vertical='top', wrap_text=True)
                cell.font = Font(color='008000' if ws.title == 'Results' else '666666')
        for col, width in (('A', 26), ('B', 26), ('C', 14), ('D', 80), ('E', 24), ('F', 90)):
            ws.column_dimensions[col].width = width
    info.column_dimensions['B'].width = 95
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp = destination.with_name(destination.stem + '.' + uuid.uuid4().hex[:6] + '.tmp.xlsx')
    try:
        wb.save(tmp)
        tmp.replace(destination)
    finally:
        wb.close()
        tmp.unlink(missing_ok=True)
    return destination


def send_run_report_email(run_id, report_path, recipient_override=''):
    """Send the finished Auto IP/Excel XLSX using Notification Center SMTP settings."""
    from modules.advanced_pages import get_setting, _load_secret, SESSION_SECRETS, send_email
    host = get_setting('smtp_host', '').strip()
    port = get_setting('smtp_port', '587').strip() or '587'
    user = get_setting('smtp_user', '').strip()
    recipient = (recipient_override or get_setting('smtp_to', '')).strip()
    password = _load_secret('smtp_password_enc') or SESSION_SECRETS.get('smtp_password', '')
    if not host or not recipient:
        raise SkipTask('Chưa cấu hình SMTP/Email nhận trong Notification Center.')
    with connect() as c:
        run = c.execute('SELECT * FROM autoip_runs WHERE id=?', (run_id,)).fetchone()
        counts = {r['status']: r['n'] for r in c.execute(
            "SELECT status,COUNT(*) AS n FROM autoip_steps WHERE run_id=? AND task NOT IN ('email_report') GROUP BY status", (run_id,))}
    if not run:
        raise ValueError('Không tìm thấy lượt chạy để gửi báo cáo.')
    subject = f"NetworkAutomation - Auto IP/Excel - {run['status']} - {str(run_id)[:8]}"
    body = (
        'Báo cáo Auto IP/Excel đã hoàn tất.\n\n'
        f"Lượt chạy: {run_id}\n"
        f"Bắt đầu: {run['started_at'] or ''}\n"
        f"Kết thúc: {run['finished_at'] or ''}\n"
        f"Trạng thái: {run['status'] or ''}\n"
        f"Số IP: {run['total'] or 0}\n"
        f"OK: {counts.get('OK', 0)} | WARN: {counts.get('WARN', 0)} | ERROR: {counts.get('ERROR', 0)} | SKIP: {counts.get('SKIP', 0)}\n\n"
        'File Excel chi tiết được đính kèm theo email này.'
    )
    send_email(host, port, user, password, recipient, subject, body, attachment_path=report_path)
    return {'recipient': recipient, 'report_path': str(report_path), 'subject': subject}


class AutomationEngine:
    def __init__(self, adapter_factory=NetworkAdapter):
        ensure_tables()
        self.adapter_factory = adapter_factory
        self.stop_event = threading.Event()
        self.lock = threading.RLock()
        self.thread = None
        self.state = {'running': False, 'run_id': '', 'cycle': 0, 'done': 0, 'total': 0,
                      'status': 'Ready', 'message': '', 'report_path': ''}
        self._lease = None

    @property
    def running(self):
        return bool(self.thread and self.thread.is_alive())

    def snapshot(self):
        with self.lock:
            return dict(self.state, running=self.running)

    def _state(self, **kwargs):
        with self.lock:
            self.state.update(kwargs)

    def start(self, targets, options, user, authorized=False):
        if user.get('role') not in ('Admin', 'Operator'):
            raise PermissionError('Ch\u1ec9 Admin/Operator \u0111\u01b0\u1ee3c ch\u1ea1y.')
        if not authorized:
            raise PermissionError('X\u00e1c nh\u1eadn b\u1ea1n c\u00f3 quy\u1ec1n qu\u1ea3n tr\u1ecb c\u00e1c IP n\u00e0y.')
        options.validate()
        targets, _ = parse_rows(asdict(t) for t in targets)
        known = {p['name'] for p in profiles()}
        missing = {t.profile or options.default_profile for t in targets} - known
        if missing:
            raise ValueError('H\u1ed3 s\u01a1 ch\u01b0a t\u1ed3n t\u1ea1i: ' + ', '.join(sorted(missing)))
        with self.lock:
            if self.running:
                raise RuntimeError('\u0110\u1ee3t tr\u01b0\u1edbc ch\u01b0a d\u1eebng xong.')
            from modules.operation_lock import OperationLease
            self._lease = OperationLease(DATABASE_DIR / '.autoip-coordinator.lock').acquire()
            try:
                with connect() as c:
                    c.execute("UPDATE autoip_runs SET status='Interrupted',finished_at=? WHERE status='Running'", (now(),))
                self.stop_event.clear()
                save_options(options)
                save_targets(targets)
                self._state(status='Starting', done=0, total=len(targets), cycle=0, report_path='', message='')
                self.thread = threading.Thread(target=self._loop, args=(tuple(targets), options, dict(user)),
                                               daemon=True, name='Auto-IP-Coordinator')
                self.thread.start()
            except Exception:
                self._lease.release()
                self._lease = None
                raise

    def stop(self):
        self.stop_event.set()
        if self.running:
            self._state(status='Stopping', message='\u0110ang d\u1eebng; ch\u1edd y\u00eau c\u1ea7u hi\u1ec7n t\u1ea1i k\u1ebft th\u00fac/timeout.')

    def _record(self, run, ip, task, status, message, data=None):
        with connect() as c:
            c.execute('INSERT INTO autoip_steps(run_id,ip,task,status,message,data,created_at) VALUES(?,?,?,?,?,?,?)',
                      (run, ip, task, status, str(message)[:2000], json.dumps(data or {}, ensure_ascii=False, default=str), now()))

    def _task(self, run, ip, task, function, adapter=None):
        if self.stop_event.is_set():
            self._record(run, ip, task, 'CANCEL', 'D\u1eebng theo y\u00eau c\u1ea7u.')
            return None
        try:
            if adapter:
                adapter.check()
            data = function() or {}
            status, message = 'OK', 'Ho\u00e0n t\u1ea5t'
            if data.get('truncated') or data.get('errors'):
                status, message = 'WARN', 'K\u1ebft qu\u1ea3 m\u1ed9t ph\u1ea7n; xem chi ti\u1ebft.'
            if task == 'ping':
                status = 'OK' if data['alive'] else 'WARN'
                message = 'C\u00f3 ph\u1ea3n h\u1ed3i ICMP' if data['alive'] else 'Kh\u00f4ng ph\u1ea3n h\u1ed3i ICMP; v\u1eabn th\u1eed TCP/SNMP.'
            elif task == 'tcp':
                message = ', '.join(f'{p}: {v}' for p, v in data.items())
                status = 'OK' if all(v == 'OPEN' for v in data.values()) else 'WARN'
            elif task == 'resources':
                message = f"CPU: {data.get('cpu')}%; RAM: {data.get('memory')}% (None = ch\u01b0a c\u00f3)"
                if data.get('cpu') is None or data.get('memory') is None:
                    status = 'WARN'
            elif task == 'interfaces':
                message = f"{len(data['interfaces'])} c\u1ed5ng. L\u01b0u l\u01b0\u1ee3ng c\u1ea7n 2 m\u1eabu; xem chi ti\u1ebft."
            elif task == 'topology':
                message = f"{data['neighbors']} l\u00e1ng gi\u1ec1ng; kh\u00f4ng suy \u0111o\u00e1n li\u00ean k\u1ebft."
                if not data['neighbors']:
                    status = 'WARN'
            elif task == 'snmp':
                message = f"{data.get('version')} | {data.get('name') or '-'} | {data.get('driver') or 'Ch\u01b0a c\u00f3 driver'}"
            self._record(run, ip, task, status, message, data)
            return data
        except Cancelled as exc:
            self._record(run, ip, task, 'CANCEL', str(exc))
        except SkipTask as exc:
            self._record(run, ip, task, 'SKIP', str(exc))
        except Exception as exc:
            self._record(run, ip, task, 'ERROR', redact(exc, getattr(adapter, 'secret_values', ())))
        return None

    def _device(self, run, target, options):
        adapter = None
        try:
            if self.stop_event.is_set():
                self._record(run, target.ip, 'engine', 'CANCEL', 'Ch\u01b0a ch\u1ea1y; \u0111\u00e3 d\u1eebng.')
                return
            did = upsert_device(target)
            self._record(run, target.ip, 'inventory', 'OK', '\u0110\u00e3 c\u00f3 trong danh s\u00e1ch thi\u1ebft b\u1ecb.', {'device_id': did})
            creds = resolve_credentials(target, did, options)
            adapter = self.adapter_factory(target.ip, creds, options, self.stop_event)
            if options.ping:
                def ping():
                    data = adapter.ping()
                    with connect() as c:
                        c.execute('INSERT INTO health_samples(host,latency_ms,packet_loss,created_at) VALUES(?,?,?,?)',
                                  (target.ip, data['latency_ms'], data['packet_loss'], now()))
                        c.execute('UPDATE devices SET status=?,last_seen=? WHERE ip=?',
                                  ('Online' if data['alive'] else 'Offline', now(), target.ip))
                    from modules.nms_v11 import record_ping_result
                    record_ping_result(did, data['alive'])
                    return data
                self._task(run, target.ip, 'ping', ping, adapter)
            if options.tcp:
                self._task(run, target.ip, 'tcp', adapter.tcp, adapter)
            driver, uptime, snmp_ok = get_existing_driver(did), None, False
            needs_snmp = options.snmp or options.resources or options.interfaces or options.topology
            if needs_snmp:
                def identify():
                    nonlocal driver, uptime
                    vals = adapter.get(list(SYS.values()))
                    if not any(vals.get(o) is not None for o in SYS.values()):
                        raise SkipTask('SNMP ph\u1ea3n h\u1ed3i nh\u01b0ng kh\u00f4ng c\u00f3 system OID.')
                    driver = select_driver(did, vals.get(SYS['descr']), vals.get(SYS['object']))
                    uptime = numeric(vals.get(SYS['uptime']))
                    with connect() as c:
                        if driver:
                            c.execute("UPDATE network_devices SET vendor=CASE WHEN COALESCE(vendor,'')='' THEN ? ELSE vendor END,updated_at=? WHERE id=?",
                                      (driver['vendor'], now(), did))
                        c.execute("UPDATE network_devices SET name=? WHERE id=? AND (name IS NULL OR name='' OR name=ip)",
                                  (str(vals.get(SYS['name']) or target.name or target.ip), did))
                        c.execute('''INSERT INTO snmp_diagnostics_history(host,version,credential_name,success,sys_name,sys_descr,sys_object_id,detail,created_at)
                                     VALUES(?,?,?,?,?,?,?,?,?)''', (target.ip, creds['mode'], (creds['v3'] or {}).get('name', ''), 1,
                                     str(vals.get(SYS['name']) or ''), str(vals.get(SYS['descr']) or ''), str(vals.get(SYS['object']) or ''), 'Auto IP', now()))
                    return {'name': vals.get(SYS['name']), 'descr': vals.get(SYS['descr']), 'object_id': vals.get(SYS['object']),
                            'uptime_ticks': uptime, 'version': creds['mode'], 'driver': (driver or {}).get('name')}
                snmp_ok = self._task(run, target.ip, 'snmp', identify, adapter) is not None
            for task, enabled, fun in [('resources', options.resources, lambda: collect_resources(adapter, driver)),
                                       ('interfaces', options.interfaces, lambda: collect_interfaces(adapter, uptime)),
                                       ('topology', options.topology, lambda: collect_topology(adapter, driver))]:
                if enabled:
                    if not snmp_ok:
                        self._record(run, target.ip, task, 'SKIP', 'Ch\u01b0a k\u1ebft n\u1ed1i SNMP; c\u00e1c t\u00e1c v\u1ee5 kh\u00e1c v\u1eabn ti\u1ebfp t\u1ee5c.')
                    else:
                        self._task(run, target.ip, task, fun, adapter)
            if options.backup:
                self._task(run, target.ip, 'backup', lambda: adapter.backup(driver), adapter)
        except Exception as exc:
            self._record(run, target.ip, 'engine', 'ERROR', redact(exc, getattr(adapter, 'secret_values', ())))
        finally:
            if adapter:
                try:
                    adapter.close()
                except Exception as exc:
                    self._record(run, target.ip, 'engine', 'ERROR', 'Close: ' + redact(exc, getattr(adapter, 'secret_values', ())))
            with self.lock:
                self.state['done'] += 1

    def _postprocess(self, run, targets, options):
        # Existing rule/incident engines operate on shared data, as they do in the old UI.
        with connect() as c:
            old_alert = c.execute('SELECT COALESCE(MAX(id),0) FROM alerts').fetchone()[0]
        if options.alerts:
            def alerts():
                from modules.nms_v4 import evaluate_alert_rules
                from modules.nms_v9 import sync_incidents
                from modules.nms_v10 import analyze_root_causes
                created, recovered = evaluate_alert_rules()
                incidents = sync_incidents()
                rca = analyze_root_causes()
                return {'created': created, 'recovered': recovered, 'incidents': incidents, 'rca': rca,
                        'scope': 'Existing global alert rules / incident / RCA engine'}
            self._task(run, '', 'alerts', alerts)
        if options.notifications:
            def notify():
                from modules.advanced_pages import notify_alert, get_setting
                if not options.alerts:
                    raise SkipTask('B\u1eadt t\u00e1c v\u1ee5 C\u1ea3nh b\u00e1o \u0111\u1ec3 g\u1eedi c\u1ea3nh b\u00e1o m\u1edbi.')
                if get_setting('notify_enabled', '0') != '1':
                    raise SkipTask('Ch\u01b0a b\u1eadt/c\u1ea5u h\u00ecnh m\u1ee5c Th\u00f4ng b\u00e1o.')
                hosts = {t.ip for t in targets}
                with connect() as c:
                    alerts = [dict(r) for r in c.execute("SELECT * FROM alerts WHERE id>? AND status='Open'", (old_alert,)) if r['ip'] in hosts]
                sent, failed = 0, []
                for alert in alerts[:50]:
                    if self.stop_event.is_set():
                        raise Cancelled('D\u1eebng th\u00f4ng b\u00e1o.')
                    result = notify_alert(alert['ip'], alert['alert_type'], alert['message'], alert['severity'])
                    sent += sum('sent' in x.lower() for x in result)
                    # Do not persist raw provider errors; they can contain a token in a URL.
                    if not result or any('failed' in x.lower() for x in result):
                        failed.append({'alert_id': alert['id'], 'error': 'Kh\u00f4ng g\u1eedi \u0111\u01b0\u1ee3c; ki\u1ec3m tra c\u1ea5u h\u00ecnh Th\u00f4ng b\u00e1o.'})
                return {'sent': sent, 'new_alerts': len(alerts), 'errors': failed, 'truncated': len(alerts) > 50}
            self._task(run, '', 'notifications', notify)

    def _loop(self, targets, options, user):
        run = ''
        try:
            cycle = 0
            while not self.stop_event.is_set():
                cycle += 1
                run = uuid.uuid4().hex
                self._state(run_id=run, cycle=cycle, status='Running', done=0, total=len(targets), message='', report_path='')
                with connect() as c:
                    c.execute('INSERT INTO autoip_runs(id,started_at,status,username,total,cycle,options) VALUES(?,?,?,?,?,?,?)',
                              (run, now(), 'Running', user.get('username', ''), len(targets), cycle, json.dumps(asdict(options))))
                # Pre-register names for topology matching, before parallel probes begin.
                for target in targets:
                    if self.stop_event.is_set():
                        break
                    upsert_device(target)
                with ThreadPoolExecutor(max_workers=options.workers, thread_name_prefix='Auto-IP') as pool:
                    futures = [pool.submit(self._device, run, target, options) for target in targets]
                    for future in as_completed(futures):
                        future.result()
                if not self.stop_event.is_set():
                    self._postprocess(run, targets, options)
                with connect() as c:
                    failures = c.execute("SELECT COUNT(*) FROM autoip_steps WHERE run_id=? AND status IN ('ERROR','FAILED')", (run,)).fetchone()[0]
                status = 'Stopped' if self.stop_event.is_set() else 'CompletedWithErrors' if failures else 'Completed'
                with connect() as c:
                    c.execute('UPDATE autoip_runs SET status=?,finished_at=? WHERE id=?', (status, now(), run))
                report_path = ''
                if options.report or options.email_report_after_run:
                    # Export partial results even after Stop; this performs no network activity.
                    try:
                        path = REPORT_DIR / 'auto_ip' / (datetime.now().strftime('%Y%m%d_%H%M%S') + '_' + run[:8] + '.xlsx')
                        export_report(run, path)
                        report_path = str(path)
                        self._record(run, '', 'report', 'OK', report_path)
                        with connect() as c:
                            c.execute('UPDATE autoip_runs SET report_path=? WHERE id=?', (report_path, run))
                        self._state(report_path=report_path)
                    except Exception as exc:
                        self._record(run, '', 'report', 'ERROR', redact(exc))
                if options.email_report_after_run and report_path:
                    try:
                        result = send_run_report_email(run, report_path, options.report_email_to)
                        self._record(run, '', 'email_report', 'OK', 'Đã gửi: ' + result['recipient'])
                    except SkipTask as exc:
                        self._record(run, '', 'email_report', 'SKIP', str(exc))
                    except Exception as exc:
                        self._record(run, '', 'email_report', 'ERROR', 'Không gửi được email báo cáo: ' + redact(exc))
                # Report / notification errors are part of the run, too.
                with connect() as c:
                    failures = c.execute("SELECT COUNT(*) FROM autoip_steps WHERE run_id=? AND status IN ('ERROR','FAILED')", (run,)).fetchone()[0]
                    if failures and status == 'Completed':
                        status = 'CompletedWithErrors'
                        c.execute('UPDATE autoip_runs SET status=? WHERE id=?', (status, run))
                self._state(status=status)
                if not options.repeat or self.stop_event.is_set():
                    break
                self._state(status='Waiting', message=f'Ch\u1edd {options.interval} gi\u00e2y r\u1ed3i ch\u1ea1y l\u01b0\u1ee3t ti\u1ebfp; kh\u00f4ng ch\u1ed3ng l\u1ecbch.')
                self.stop_event.wait(options.interval)
        except Exception as exc:
            self._state(status='Failed', message=redact(exc))
            if run:
                with connect() as c:
                    c.execute("UPDATE autoip_runs SET status='Failed',finished_at=? WHERE id=?", (now(), run))
                self._record(run, '', 'engine', 'ERROR', redact(exc))
        finally:
            if self.stop_event.is_set() and self.state['status'] != 'Failed':
                self._state(status='Stopped')
            if self._lease is not None:
                self._lease.release()
                self._lease = None


def run_history():
    with connect() as c:
        return [dict(r) for r in c.execute('SELECT * FROM autoip_runs ORDER BY started_at DESC,rowid DESC LIMIT 50')]


def run_steps(run_id, after_id=0, limit=1000):
    with connect() as c:
        return [dict(r) for r in c.execute('SELECT * FROM autoip_steps WHERE run_id=? AND id>? ORDER BY id LIMIT ?',
                                         (run_id, after_id, limit))]
