"""Cybersecurity 5.8 endpoint monitoring.

Defensive telemetry only: CPU/RAM/disk, process/service/software counts, host firewall
and antivirus state. No remote command execution is exposed by this module.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from webapi.runtime37 import connection, utcnow
from webapi.security37 import require_role

router = APIRouter(prefix='/api/v58', tags=['Cybersecurity 5.8'])
_STOP = threading.Event()
_THREAD: threading.Thread | None = None
_SOFTWARE_CACHE: tuple[float, list[str]] = (0.0, [])




def ensure_tables58() -> None:
    with connection() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS endpoint_agents58(
          endpoint_id TEXT PRIMARY KEY, hostname TEXT NOT NULL, os_name TEXT, os_version TEXT, platform TEXT, local_ip TEXT,
          agent_version TEXT, firewall_status TEXT, antivirus_status TEXT, logged_user TEXT, first_seen TEXT NOT NULL,
          last_seen TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'LOCAL_WEB_HOST'
        );
        CREATE TABLE IF NOT EXISTS endpoint_samples58(
          id INTEGER PRIMARY KEY AUTOINCREMENT, endpoint_id TEXT NOT NULL, cpu_percent REAL, memory_percent REAL, disk_percent REAL,
          process_count INTEGER NOT NULL DEFAULT 0, service_count INTEGER NOT NULL DEFAULT 0, software_count INTEGER NOT NULL DEFAULT 0,
          firewall_status TEXT, antivirus_status TEXT, top_processes_json TEXT NOT NULL DEFAULT '[]', software_sample_json TEXT NOT NULL DEFAULT '[]',
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_endpoint_samples58_endpoint_time ON endpoint_samples58(endpoint_id,created_at DESC);
        CREATE INDEX IF NOT EXISTS ix_endpoint_agents58_seen ON endpoint_agents58(last_seen DESC);
        """)
        c.commit()



def _normalize_state(value: str) -> str:
    v = str(value or 'UNKNOWN').upper().strip()
    return v if v in {'ON','OFF','UNKNOWN','UNAVAILABLE'} else 'UNKNOWN'


def _record(payload: dict[str, Any], source: str='LOCAL_WEB_HOST') -> None:
    ensure_tables58(); now = utcnow(); eid = str(payload['endpoint_id'])[:128]
    fw = _normalize_state(payload.get('firewall_status','UNKNOWN'))
    av = _normalize_state(payload.get('antivirus_status','UNKNOWN'))
    top = [str(x)[:180] for x in (payload.get('top_processes') or [])[:80]]
    software = [str(x)[:220] for x in (payload.get('software_sample') or [])[:100]]
    with connection() as c:
        c.execute("""INSERT INTO endpoint_agents58(endpoint_id,hostname,os_name,os_version,platform,local_ip,agent_version,firewall_status,antivirus_status,logged_user,first_seen,last_seen,source)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                     ON CONFLICT(endpoint_id) DO UPDATE SET hostname=excluded.hostname,os_name=excluded.os_name,os_version=excluded.os_version,
                     platform=excluded.platform,local_ip=excluded.local_ip,agent_version=excluded.agent_version,firewall_status=excluded.firewall_status,
                     antivirus_status=excluded.antivirus_status,logged_user=excluded.logged_user,last_seen=excluded.last_seen,source=excluded.source""",
                  (eid, str(payload.get('hostname') or 'unknown')[:255], str(payload.get('os_name') or '')[:80], str(payload.get('os_version') or '')[:255],
                   str(payload.get('platform') or '')[:80], str(payload.get('local_ip') or '')[:64], str(payload.get('agent_version') or '5.8.0')[:40],
                   fw, av, str(payload.get('logged_user') or '')[:255], now, now, source))
        c.execute("""INSERT INTO endpoint_samples58(endpoint_id,cpu_percent,memory_percent,disk_percent,process_count,service_count,software_count,
                     firewall_status,antivirus_status,top_processes_json,software_sample_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (eid, payload.get('cpu_percent'), payload.get('memory_percent'), payload.get('disk_percent'), int(payload.get('process_count') or 0),
                   int(payload.get('service_count') or 0), int(payload.get('software_count') or 0), fw, av,
                   json.dumps(top, ensure_ascii=False, separators=(',',':')), json.dumps(software, ensure_ascii=False, separators=(',',':')), now))
        # Keep bounded history: roughly the newest 5000 samples per endpoint.
        c.execute("""DELETE FROM endpoint_samples58 WHERE endpoint_id=? AND id NOT IN
                     (SELECT id FROM endpoint_samples58 WHERE endpoint_id=? ORDER BY id DESC LIMIT 5000)""", (eid, eid))
        c.commit()


def _local_ip() -> str:
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(('8.8.8.8',53)); ip=s.getsockname()[0]; s.close(); return ip
    except Exception:
        try: return socket.gethostbyname(socket.gethostname())
        except Exception: return ''


def _firewall_state() -> str:
    try:
        if os.name == 'nt':
            p=subprocess.run(['netsh','advfirewall','show','allprofiles','state'],capture_output=True,text=True,timeout=5,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            t=(p.stdout+' '+p.stderr).upper()
            if 'STATE' in t and 'ON' in t: return 'ON'
            if 'STATE' in t and 'OFF' in t: return 'OFF'
        else:
            for cmd in (['ufw','status'],['firewall-cmd','--state']):
                try:
                    p=subprocess.run(cmd,capture_output=True,text=True,timeout=3)
                    t=(p.stdout+' '+p.stderr).lower()
                    if 'active' in t or 'running' in t: return 'ON'
                    if 'inactive' in t or 'not running' in t: return 'OFF'
                except Exception: pass
    except Exception: pass
    return 'UNKNOWN'


def _antivirus_state() -> str:
    if os.name != 'nt': return 'UNKNOWN'
    try:
        cmd=['powershell','-NoProfile','-NonInteractive','-Command',"$x=Get-MpComputerStatus -ErrorAction Stop; if($x.AntivirusEnabled -and $x.RealTimeProtectionEnabled){'ON'}elseif($x.AntivirusEnabled){'ON'}else{'OFF'}"]
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=8,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        t=p.stdout.strip().upper()
        if t in {'ON','OFF'}: return t
    except Exception: pass
    return 'UNKNOWN'


def _software_sample() -> list[str]:
    global _SOFTWARE_CACHE
    now=time.time()
    if now-_SOFTWARE_CACHE[0] < 1800: return list(_SOFTWARE_CACHE[1])
    names: list[str]=[]
    try:
        if os.name == 'nt':
            import winreg
            roots=[(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'),
                   (winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall')]
            for hive,path in roots:
                try:
                    with winreg.OpenKey(hive,path) as k:
                        for i in range(winreg.QueryInfoKey(k)[0]):
                            try:
                                with winreg.OpenKey(k,winreg.EnumKey(k,i)) as sk:
                                    name=winreg.QueryValueEx(sk,'DisplayName')[0]
                                    if name and str(name) not in names: names.append(str(name)[:220])
                            except Exception: pass
                except Exception: pass
        else:
            try:
                p=subprocess.run(['dpkg-query','-W','-f=${binary:Package}\\n'],capture_output=True,text=True,timeout=12)
                if p.returncode == 0: names=[x.strip()[:220] for x in p.stdout.splitlines() if x.strip()]
            except Exception: pass
    except Exception: pass
    names=sorted(set(names), key=str.lower)[:2000]
    _SOFTWARE_CACHE=(now,names)
    return list(names)


def collect_local_snapshot() -> dict[str, Any]:
    import getpass
    try:
        import psutil
        cpu=float(psutil.cpu_percent(interval=0.15)); mem=float(psutil.virtual_memory().percent)
        root=os.environ.get('SystemDrive','C:')+'\\' if os.name=='nt' else '/'
        disk=float(psutil.disk_usage(root).percent)
        procs=[]
        for p in psutil.process_iter(['name','memory_percent']):
            try:
                n=str(p.info.get('name') or '')
                if n: procs.append((float(p.info.get('memory_percent') or 0),n))
            except Exception: pass
        procs=[x[1] for x in sorted(procs, reverse=True)[:30]]
        pcount=len(psutil.pids())
        scount=0
        if os.name=='nt':
            try: scount=sum(1 for _ in psutil.win_service_iter())
            except Exception: pass
    except Exception:
        cpu=mem=disk=None; procs=[]; pcount=scount=0
    software=_software_sample()
    host=socket.gethostname() or 'localhost'
    stable=hashlib.sha256((host+'|'+platform.node()).encode()).hexdigest()[:24]
    return {
      'endpoint_id':'local-'+stable,'hostname':host,'os_name':platform.system(),'os_version':platform.version(),
      'platform':platform.machine(),'local_ip':_local_ip(),'agent_version':'5.8.0-local','cpu_percent':cpu,'memory_percent':mem,
      'disk_percent':disk,'process_count':pcount,'service_count':scount,'software_count':len(software),
      'firewall_status':_firewall_state(),'antivirus_status':_antivirus_state(),'logged_user':getpass.getuser(),
      'top_processes':procs,'software_sample':software[:100]
    }


def _local_loop(interval: int=60) -> None:
    while not _STOP.is_set():
        try: _record(collect_local_snapshot(), source='LOCAL_WEB_HOST')
        except Exception: pass
        _STOP.wait(max(30, interval))


def start_local_endpoint_monitor() -> None:
    global _THREAD
    ensure_tables58(); _STOP.clear()
    if _THREAD and _THREAD.is_alive(): return
    _THREAD=threading.Thread(target=_local_loop,name='endpoint58-local',daemon=True); _THREAD.start()


def stop_local_endpoint_monitor(wait: bool=False) -> None:
    _STOP.set()
    if wait and _THREAD and _THREAD.is_alive(): _THREAD.join(timeout=5)


def _risk(row: dict[str, Any]) -> tuple[int,str,list[str]]:
    score=0; reasons=[]
    try:
        last=datetime.fromisoformat(str(row.get('last_seen') or '').replace('Z','+00:00'))
        if last.tzinfo is None: last=last.replace(tzinfo=timezone.utc)
        age=(datetime.now(timezone.utc)-last.astimezone(timezone.utc)).total_seconds()
    except Exception: age=10**9
    if age>300: score+=35; reasons.append('Endpoint không check-in > 5 phút')
    if str(row.get('firewall_status')).upper()=='OFF': score+=35; reasons.append('Host firewall OFF')
    if str(row.get('antivirus_status')).upper()=='OFF': score+=35; reasons.append('Antivirus OFF')
    if float(row.get('disk_percent') or 0)>=90: score+=15; reasons.append('Disk >= 90%')
    if float(row.get('memory_percent') or 0)>=95: score+=10; reasons.append('RAM >= 95%')
    score=min(100,score); level='CRITICAL' if score>=75 else 'HIGH' if score>=50 else 'MEDIUM' if score>=25 else 'LOW'
    return score,level,reasons


@router.get('/endpoints')
def endpoints(request: Request):
    require_role(request)
    ensure_tables58()
    with connection() as c:
        rows=c.execute("""SELECT a.*,s.cpu_percent,s.memory_percent,s.disk_percent,s.process_count,s.service_count,s.software_count
                          FROM endpoint_agents58 a LEFT JOIN endpoint_samples58 s ON s.id=(SELECT id FROM endpoint_samples58 z WHERE z.endpoint_id=a.endpoint_id ORDER BY id DESC LIMIT 1)
                          WHERE a.source='LOCAL_WEB_HOST' ORDER BY a.last_seen DESC""").fetchall()
    out=[]
    for r in rows:
        d=dict(r); score,level,reasons=_risk(d); d.update(risk_score=score,risk_level=level,risk_reasons=reasons)
        out.append(d)
    return out


@router.get('/endpoints/{endpoint_id}')
def endpoint_detail(endpoint_id: str, request: Request):
    require_role(request); ensure_tables58()
    with connection() as c:
        a=c.execute('SELECT * FROM endpoint_agents58 WHERE endpoint_id=?',(endpoint_id,)).fetchone()
        if not a: raise HTTPException(404,'ENDPOINT_NOT_FOUND')
        samples=[dict(x) for x in c.execute('SELECT * FROM endpoint_samples58 WHERE endpoint_id=? ORDER BY id DESC LIMIT 200',(endpoint_id,)).fetchall()]
    d=dict(a); score,level,reasons=_risk({**d, **(samples[0] if samples else {})}); d.update(risk_score=score,risk_level=level,risk_reasons=reasons)
    if samples:
        for s in samples:
            for k in ('top_processes_json','software_sample_json'):
                try: s[k[:-5]]=json.loads(s.get(k) or '[]')
                except Exception: s[k[:-5]]=[]
    return {'endpoint':d,'samples':samples}


