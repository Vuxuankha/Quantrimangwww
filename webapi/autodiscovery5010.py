"""Automatic, bounded LAN discovery for NetworkAutomation Web 5.0.10.

The coordinator only scans one active private IPv4 subnet at a time. It never
scans public/WAN address space and caps automatic discovery to a /24-sized
segment (<= 256 addresses). Results are written to the existing scan history;
only hosts actually observed Online are synchronized into IP/MAC inventory.
Managed devices/credentials are never auto-enrolled.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import threading
import time
import socket
import struct
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from webapi.runtime37 import connection, utcnow
from app_runtime import hidden_subprocess_kwargs

_LOCK = threading.RLock()
_THREAD: threading.Thread | None = None
_STOP = threading.Event()
_STATE = {
    'state': 'IDLE',
    'network': '',
    'source': '',
    'started_at': None,
    'completed_at': None,
    'online': 0,
    'active': 0,
    'icmp_online': 0,
    'arp_only': 0,
    'total': 0,
    'imported': 0,
    'scan_key': '',
    'progress_done': 0, 'progress_total': 0, 'preliminary_active': 0, 'preliminary_devices': [],
    'detail': 'Chưa chạy tự động quét LAN.',
}
_COOLDOWN_SECONDS = 300


def ensure_tables():
    with connection() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS web_startup_discovery_runs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network TEXT NOT NULL,
            source TEXT NOT NULL,
            state TEXT NOT NULL,
            scan_key TEXT,
            online INTEGER DEFAULT 0,
            total INTEGER DEFAULT 0,
            imported INTEGER DEFAULT 0,
            detail TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT
        )''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_web_startup_discovery_network ON web_startup_discovery_runs(network,id DESC)')
        c.execute('''CREATE TABLE IF NOT EXISTS web_connected_device_evidence(
            scan_key TEXT NOT NULL, ip TEXT NOT NULL, mac TEXT, hostname TEXT, sources TEXT,
            last_seen TEXT NOT NULL, PRIMARY KEY(scan_key,ip))''')


def _safe_network_from_adapter(adapter):
    networks=[]
    for raw in adapter.get('networks') or []:
        try:
            iface=ipaddress.ip_interface(str(raw))
            if iface.version!=4 or not iface.ip.is_private or iface.ip.is_link_local:
                continue
            net=iface.network
            # Automatic discovery deliberately never scans more than a /24.
            if net.prefixlen < 24:
                net=ipaddress.ip_network(f'{iface.ip}/24', strict=False)
            networks.append((int(adapter.get('metric') or 999999), bool(adapter.get('gateway')), iface.ip, net, False))
        except Exception:
            continue
    if not networks:
        # Safe fallback when Windows cannot provide a prefix: scan only the local /24.
        for raw in adapter.get('ipv4') or []:
            try:
                addr=ipaddress.ip_address(str(raw))
                if addr.version==4 and addr.is_private and not addr.is_link_local:
                    net=ipaddress.ip_network(f'{addr}/24', strict=False)
                    networks.append((int(adapter.get('metric') or 999999), bool(adapter.get('gateway')), addr, net, True))
            except Exception:
                continue
    return networks


def select_network(connectivity):
    candidates=[]
    for adapter in connectivity.get('adapters') or []:
        candidates.extend(_safe_network_from_adapter(adapter))
    if not candidates:
        return None
    # Prefer an adapter with a default gateway, then lower interface metric.
    candidates.sort(key=lambda x: (not x[1], x[0], int(x[2])))
    metric,has_gateway,address,network,inferred=candidates[0]
    return {
        'network': str(network),
        'local_ip': str(address),
        'metric': metric,
        'has_gateway': has_gateway,
        'prefix_inferred': inferred,
    }


_IPV4_RE = re.compile(r"(?<!\d)(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?!\d)")
_MAC_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")


def _normalise_mac(value: str) -> str:
    value=(value or '').strip().replace(':','-').upper()
    if value in ('00-00-00-00-00-00','FF-FF-FF-FF-FF-FF'):
        return ''
    return value if re.fullmatch(r'(?:[0-9A-F]{2}-){5}[0-9A-F]{2}', value) else ''


def _arp_neighbors(network: str) -> dict[str,str]:
    """Return active L2 neighbors from Windows/Linux neighbor tables.

    Windows 6.2.3 reads both Get-NetNeighbor and arp -a because some adapters
    expose useful entries in only one source. Dynamic/Reachable/Stale/Delay/
    Probe entries are accepted; permanent broadcast/zero MAC entries are ignored.
    """
    try:
        net=ipaddress.ip_network(network, strict=False)
    except ValueError:
        return {}
    found={}
    def keep(raw_ip, raw_mac):
        try:
            addr=ipaddress.ip_address(str(raw_ip).strip())
        except ValueError:
            return
        mac=_normalise_mac(str(raw_mac or ''))
        if (not mac or addr.version!=4 or addr not in net or
            addr in (net.network_address,net.broadcast_address)):
            return
        found[str(addr)]=mac

    if os.name=='nt':
        # PowerShell exposes entries that arp.exe can omit on some Windows builds.
        ps=("Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            "Where-Object {$_.State -in @('Reachable','Stale','Delay','Probe','Permanent')} | "
            "Select-Object IPAddress,LinkLayerAddress,State | ConvertTo-Json -Compress")
        try:
            cp=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',ps],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,errors='ignore',timeout=8,
                **hidden_subprocess_kwargs())
            raw=(cp.stdout or '').strip()
            if raw:
                data=json.loads(raw)
                if isinstance(data,dict): data=[data]
                for row in data if isinstance(data,list) else []:
                    keep(row.get('IPAddress'),row.get('LinkLayerAddress'))
        except Exception:
            pass
        commands=[['arp','-a']]
    else:
        commands=[['ip','neigh','show'],['arp','-an']]
    for cmd in commands:
        try:
            cp=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,errors='ignore',timeout=5,**hidden_subprocess_kwargs())
            for line in (cp.stdout or '').splitlines():
                ips=_IPV4_RE.findall(line); macs=_MAC_RE.findall(line)
                if ips and macs:
                    for raw_ip in ips: keep(raw_ip,macs[0])
        except Exception:
            continue
    return found


def _netsh_neighbors(network: str) -> dict[str,str]:
    """Best-effort Windows neighbor view from netsh, complementary to ARP/NetNeighbor."""
    if os.name!='nt':
        return {}
    try:
        net=ipaddress.ip_network(network, strict=False)
    except ValueError:
        return {}
    found={}
    try:
        cp=subprocess.run(['netsh','interface','ipv4','show','neighbors'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          text=True,errors='ignore',timeout=6,**hidden_subprocess_kwargs())
        for line in (cp.stdout or '').splitlines():
            ips=_IPV4_RE.findall(line); macs=_MAC_RE.findall(line)
            if not ips or not macs: continue
            for raw_ip in ips:
                try: addr=ipaddress.ip_address(raw_ip)
                except ValueError: continue
                mac=_normalise_mac(macs[0])
                if mac and addr in net and addr not in (net.network_address,net.broadcast_address):
                    found[str(addr)]=mac
    except Exception:
        pass
    return found


def _windows_dhcp_server_leases(network: str) -> dict[str,dict]:
    """Read leases only when this host is itself a Windows DHCP server.

    This does not guess router passwords or scrape a router UI. On ordinary clients
    it simply returns an empty mapping.
    """
    if os.name!='nt':
        return {}
    try:
        net=ipaddress.ip_network(network, strict=False)
    except ValueError:
        return {}
    ps=("$ErrorActionPreference='SilentlyContinue'; "
        "if (Get-Command Get-DhcpServerv4Lease -ErrorAction SilentlyContinue) { "
        "$o=@(); Get-DhcpServerv4Scope -ComputerName localhost | ForEach-Object { "
        "$sid=$_.ScopeId; Get-DhcpServerv4Lease -ComputerName localhost -ScopeId $sid | ForEach-Object { "
        "$o += [pscustomobject]@{IPAddress=$_.IPAddress.IPAddressToString; ClientId=$_.ClientId; HostName=$_.HostName; AddressState=$_.AddressState.ToString()} } }; "
        "$o | ConvertTo-Json -Compress }")
    out={}
    try:
        cp=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',ps],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          text=True,errors='ignore',timeout=10,**hidden_subprocess_kwargs())
        raw=(cp.stdout or '').strip()
        if not raw: return out
        data=json.loads(raw)
        if isinstance(data,dict): data=[data]
        for row in data if isinstance(data,list) else []:
            try: addr=ipaddress.ip_address(str(row.get('IPAddress') or '').strip())
            except ValueError: continue
            if addr not in net: continue
            mac=_normalise_mac(str(row.get('ClientId') or '').replace('-',':'))
            out[str(addr)]={'mac':mac,'hostname':str(row.get('HostName') or '').strip()}
    except Exception:
        pass
    return out


def _linux_dhcp_leases(network: str) -> dict[str,dict]:
    if os.name=='nt': return {}
    try: net=ipaddress.ip_network(network, strict=False)
    except ValueError: return {}
    out={}
    paths=['/var/lib/misc/dnsmasq.leases','/var/lib/dhcp/dhcpd.leases','/var/lib/dhcp/dhclient.leases']
    for name in paths:
        try:
            text=open(name,'r',encoding='utf-8',errors='ignore').read()
        except Exception:
            continue
        # dnsmasq: expiry mac ip hostname clientid
        for line in text.splitlines():
            parts=line.split()
            if len(parts)>=4 and _IPV4_RE.fullmatch(parts[2] or ''):
                try: addr=ipaddress.ip_address(parts[2])
                except ValueError: continue
                if addr in net: out[str(addr)]={'mac':_normalise_mac(parts[1]),'hostname':'' if parts[3]=='*' else parts[3]}
        # ISC lease blocks
        for m in re.finditer(r'lease\s+(\d+\.\d+\.\d+\.\d+)\s*\{(.*?)\}',text,re.S|re.I):
            try: addr=ipaddress.ip_address(m.group(1))
            except ValueError: continue
            if addr not in net: continue
            body=m.group(2)
            mm=re.search(r'hardware ethernet\s+([0-9a-f:.-]+)',body,re.I)
            hm=re.search(r'client-hostname\s+"([^"]+)"',body,re.I)
            out[str(addr)]={'mac':_normalise_mac(mm.group(1) if mm else ''),'hostname':hm.group(1) if hm else ''}
    return out


def _dhcp_leases(network: str) -> dict[str,dict]:
    out=_windows_dhcp_server_leases(network)
    if not out: out=_linux_dhcp_leases(network)
    return out


def _dns_read_name(data: bytes, offset: int, depth: int=0):
    if depth>12: return '', offset
    labels=[]; jumped=False; end=offset
    while offset < len(data):
        ln=data[offset]
        if ln==0:
            offset+=1
            if not jumped: end=offset
            break
        if ln & 0xC0 == 0xC0:
            if offset+1>=len(data): break
            ptr=((ln & 0x3F)<<8)|data[offset+1]
            if not jumped: end=offset+2
            name,_=_dns_read_name(data,ptr,depth+1)
            if name: labels.append(name)
            jumped=True
            break
        offset+=1
        if offset+ln>len(data): break
        labels.append(data[offset:offset+ln].decode('utf-8','ignore'))
        offset+=ln
        if not jumped: end=offset
    return '.'.join(x for x in labels if x), end


def _mdns_query_packet(name: str, qtype: int=12) -> bytes:
    body=b''
    for label in name.strip('.').split('.'):
        raw=label.encode('utf-8','ignore')[:63]; body+=bytes([len(raw)])+raw
    return struct.pack('!HHHHHH',0,0,1,0,0,0)+body+b'\x00'+struct.pack('!HH',qtype,1)


def _parse_mdns(data: bytes, network: str) -> dict[str,dict]:
    out={}
    try:
        net=ipaddress.ip_network(network, strict=False)
        if len(data)<12: return out
        _id,_flags,qd,an,ns,ar=struct.unpack('!HHHHHH',data[:12]); off=12
        for _ in range(qd):
            _,off=_dns_read_name(data,off)
            off+=4
        names_by_ip={}
        for _ in range(an+ns+ar):
            owner,off=_dns_read_name(data,off)
            if off+10>len(data): break
            rtype,rclass,ttl,rdlen=struct.unpack('!HHIH',data[off:off+10]); off+=10
            rstart=off; rend=min(len(data),off+rdlen)
            if rtype==1 and rdlen==4 and rend<=len(data):
                ip=socket.inet_ntoa(data[rstart:rend])
                try: addr=ipaddress.ip_address(ip)
                except ValueError: addr=None
                if addr and addr in net:
                    host=owner[:-6] if owner.lower().endswith('.local') else owner
                    out[ip]={'hostname':host,'mac':''}
            elif rtype==12:
                target,_=_dns_read_name(data,rstart)
                # PTR alone has no IP; kept for parser completeness.
            off=rend
    except Exception:
        return {}
    return out


def _mdns_devices(network: str, timeout: float=0.9) -> dict[str,dict]:
    out={}
    queries=['_services._dns-sd._udp.local','_workstation._tcp.local','_googlecast._tcp.local','_airplay._tcp.local','_ipp._tcp.local','_http._tcp.local']
    sock=None
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_TTL,2)
        sock.settimeout(0.12)
        for q in queries:
            try: sock.sendto(_mdns_query_packet(q,12),('224.0.0.251',5353))
            except OSError: pass
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            try: data,_=sock.recvfrom(65535)
            except socket.timeout: continue
            except OSError: break
            for ip,row in _parse_mdns(data,network).items(): out[ip]=row
    except Exception:
        pass
    finally:
        try:
            if sock: sock.close()
        except Exception: pass
    return out


def _ssdp_devices(network: str, timeout: float=0.7) -> dict[str,dict]:
    out={}
    try: net=ipaddress.ip_network(network, strict=False)
    except ValueError: return out
    msg=('M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:"ssdp:discover"\r\nMX:1\r\nST:ssdp:all\r\n\r\n').encode('ascii')
    sock=None
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP); sock.settimeout(0.1)
        sock.sendto(msg,('239.255.255.250',1900)); deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            try: data,peer=sock.recvfrom(65535)
            except socket.timeout: continue
            except OSError: break
            ip=peer[0]
            try: addr=ipaddress.ip_address(ip)
            except ValueError: continue
            if addr not in net: continue
            text=data.decode('latin1','ignore')
            server=''; usn=''
            for line in text.splitlines():
                if ':' not in line: continue
                k,v=line.split(':',1); k=k.strip().lower(); v=v.strip()
                if k=='server': server=v
                elif k=='usn': usn=v
            out[ip]={'hostname':server[:120] or usn[:120],'mac':''}
    except Exception:
        pass
    finally:
        try:
            if sock: sock.close()
        except Exception: pass
    return out


def _reverse_dns_bounded(ip: str, timeout: float=0.25) -> str:
    """Bound reverse-DNS wait so one broken resolver cannot stall LAN discovery."""
    box=[]
    def run():
        try:
            name=socket.gethostbyaddr(ip)[0].strip().rstrip('.')
            if name and name != ip:
                box.append(name)
        except Exception:
            pass
    t=threading.Thread(target=run,daemon=True)
    t.start(); t.join(max(0.05,float(timeout)))
    return box[0] if box else ''


def _resolve_name(ip: str, dns_timeout: float=0.25, netbios_timeout: float=0.45) -> tuple[str,str]:
    """Return (hostname, source) with strict per-device time bounds."""
    name=_reverse_dns_bounded(ip,dns_timeout)
    if name:
        return name,'DNS'
    if os.name=='nt':
        try:
            cp=subprocess.run(['nbtstat','-A',ip],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,errors='ignore',timeout=netbios_timeout,
                              **hidden_subprocess_kwargs())
            for line in (cp.stdout or '').splitlines():
                m=re.match(r'\s*([^<\s][^<]{0,14})\s+<00>\s+UNIQUE',line,re.I)
                if m:
                    name=m.group(1).strip()
                    if name: return name,'NETBIOS'
        except Exception:
            pass
    return '',''


def _enrich_names_parallel(evidence: dict[str,dict], max_workers: int=12):
    targets=[ip for ip,row in evidence.items() if not row.get('hostname')]
    if not targets:
        return
    with ThreadPoolExecutor(max_workers=min(max_workers,len(targets))) as pool:
        jobs={pool.submit(_resolve_name,ip):ip for ip in targets}
        for fut in as_completed(jobs):
            ip=jobs[fut]
            try: name,src=fut.result()
            except Exception: continue
            if name:
                evidence[ip]['hostname']=name
                evidence[ip]['sources'].add(src)


def _collect_lan_evidence(network: str, scan_rows: list[dict], enrich_names: bool=True, fast_only: bool=False) -> dict[str,dict]:
    evidence={}
    def add(ip, source, mac='', hostname=''):
        try:
            net=ipaddress.ip_network(network,strict=False); addr=ipaddress.ip_address(str(ip).strip())
        except ValueError: return
        if addr not in net or addr in (net.network_address,net.broadcast_address): return
        key=str(addr); row=evidence.setdefault(key,{'mac':'','hostname':'','sources':set()})
        row['sources'].add(source)
        if mac and not row['mac']: row['mac']=_normalise_mac(mac)
        if hostname and not row['hostname']: row['hostname']=str(hostname).strip()[:255]
    for r in scan_rows:
        if str(r.get('status') or '').lower()=='online': add(r.get('ip'),'ICMP',r.get('mac') or '',r.get('hostname') or '')

    # ARP/neighbor is the fastest and most reliable local-L2 source. Read both
    # views in parallel so UI gets useful data almost immediately.
    with ThreadPoolExecutor(max_workers=2) as pool:
        arp_job=pool.submit(_arp_neighbors,network)
        netsh_job=pool.submit(_netsh_neighbors,network)
        for source in (arp_job,netsh_job):
            try: rows=source.result()
            except Exception: rows={}
            for ip,mac in rows.items(): add(ip,'ARP',mac)

    if not fast_only:
        # Slower multicast/DHCP sources run concurrently instead of serially.
        with ThreadPoolExecutor(max_workers=3) as pool:
            jobs=[('DHCP',pool.submit(_dhcp_leases,network)),('MDNS',pool.submit(_mdns_devices,network)),('SSDP',pool.submit(_ssdp_devices,network))]
            for source,fut in jobs:
                try: rows=fut.result()
                except Exception: rows={}
                for ip,row in rows.items(): add(ip,source,row.get('mac',''),row.get('hostname',''))
    if enrich_names:
        _enrich_names_parallel(evidence)
    return evidence


def _merge_neighbor_evidence(scan_key: str, network: str) -> dict:
    """Merge ICMP + ARP + DHCP + mDNS + SSDP + DNS/NetBIOS evidence."""
    if not scan_key:
        return {'active':0,'icmp_online':0,'arp_only':0,'dhcp':0,'mdns':0,'ssdp':0}
    ensure_tables()
    with connection() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS web_connected_device_evidence(
            scan_key TEXT NOT NULL, ip TEXT NOT NULL, mac TEXT, hostname TEXT, sources TEXT,
            last_seen TEXT NOT NULL, PRIMARY KEY(scan_key,ip))""")
        rows=[dict(r) for r in c.execute('SELECT * FROM web_scan_results WHERE scan_key=?',(scan_key,)).fetchall()]
        by_ip={str(r.get('ip') or ''):r for r in rows}
        evidence=_collect_lan_evidence(network,rows)
        for ip,e in evidence.items():
            row=by_ip.get(ip); sources=sorted(e['sources']); mac=e.get('mac') or ''; hostname=e.get('hostname') or ''
            if row:
                current=str(row.get('status') or '').lower()
                new_status='Online' if current=='online' else 'ActiveLAN'
                c.execute("UPDATE web_scan_results SET status=?, mac=CASE WHEN COALESCE(mac,'')='' THEN ? ELSE mac END, hostname=CASE WHEN COALESCE(hostname,'')='' THEN ? ELSE hostname END WHERE id=?",
                          (new_status,mac,hostname,row['id']))
            else:
                c.execute("INSERT INTO web_scan_results(scan_key,network,ip,hostname,mac,status,latency_ms,created_at) VALUES(?,?,?,?,?,'ActiveLAN',NULL,?)",
                          (scan_key,network,ip,hostname,mac,utcnow()))
            c.execute("""INSERT INTO web_connected_device_evidence(scan_key,ip,mac,hostname,sources,last_seen)
                         VALUES(?,?,?,?,?,?) ON CONFLICT(scan_key,ip) DO UPDATE SET
                         mac=excluded.mac,hostname=excluded.hostname,sources=excluded.sources,last_seen=excluded.last_seen""",
                      (scan_key,ip,mac,hostname,','.join(sources),utcnow()))
        c.commit()
    icmp=sum('ICMP' in e['sources'] for e in evidence.values())
    arp=sum('ARP' in e['sources'] and 'ICMP' not in e['sources'] for e in evidence.values())
    dhcp=sum('DHCP' in e['sources'] for e in evidence.values())
    mdns=sum('MDNS' in e['sources'] for e in evidence.values())
    ssdp=sum('SSDP' in e['sources'] for e in evidence.values())
    return {'active':len(evidence),'icmp_online':icmp,'arp_only':arp,'dhcp':dhcp,'mdns':mdns,'ssdp':ssdp}

def _active_counts(scan_key: str) -> dict:
    if not scan_key:
        return {'active':0,'icmp_online':0,'arp_only':0}
    with connection() as c:
        rows=c.execute("SELECT lower(status) s, COUNT(*) n FROM web_scan_results WHERE scan_key=? GROUP BY lower(status)",(scan_key,)).fetchall()
    counts={str(r['s']):int(r['n']) for r in rows}
    icmp=counts.get('online',0); lan=counts.get('activelan',0); arp=counts.get('activearp',0)
    return {'active':icmp+lan+arp,'icmp_online':icmp,'arp_only':lan+arp}


def _recent_same_network(network: str):
    ensure_tables()
    with connection() as c:
        row=c.execute('SELECT * FROM web_startup_discovery_runs WHERE network=? ORDER BY id DESC LIMIT 1',(network,)).fetchone()
    if not row:
        return None
    data=dict(row)
    stamp=data.get('completed_at') or data.get('started_at')
    try:
        dt=datetime.fromisoformat(str(stamp).replace('Z','+00:00'))
        if dt.tzinfo is None:
            dt=dt.replace(tzinfo=timezone.utc)
        age=(datetime.now(timezone.utc)-dt).total_seconds()
    except Exception:
        age=10**9
    return data if age < _COOLDOWN_SECONDS else None


def _sync_active_to_ipmac(scan_key: str):
    if not scan_key:
        return 0
    with connection() as c:
        rows=[dict(r) for r in c.execute("SELECT * FROM web_scan_results WHERE scan_key=? AND lower(status) IN ('online','activearp','activelan')",(scan_key,)).fetchall()]
        now=utcnow()
        imported=0
        for r in rows:
            try:
                address=str(ipaddress.ip_address(str(r.get('ip') or '').strip()))
            except ValueError:
                continue
            mac=str(r.get('mac') or '').strip()
            hostname=str(r.get('hostname') or '').strip()
            observed=str(r.get('created_at') or now)
            arp_only=str(r.get('status') or '').lower() in ('activearp','activelan')
            status='Active' if arp_only else 'Online'
            source_note='Tự động phát hiện ARP trong LAN' if arp_only else 'Tự động phát hiện khi mở Web'
            existing=c.execute('SELECT id FROM ip_mac_inventory WHERE ip=?',(address,)).fetchone()
            if existing:
                c.execute("""UPDATE ip_mac_inventory SET
                    mac=CASE WHEN ?<>'' THEN ? ELSE mac END,
                    hostname=CASE WHEN ?<>'' THEN ? ELSE hostname END,
                    status=?, last_seen=? WHERE ip=?""",
                    (mac,mac,hostname,hostname,status,observed,address))
            else:
                c.execute("""INSERT INTO ip_mac_inventory(ip,mac,hostname,status,note,first_seen,last_seen)
                             VALUES(?,?,?,?,?,?,?)""",
                          (address,mac,hostname,status,source_note,observed,observed))
            imported += 1
        return imported


def _record(network, source, state, started_at, result=None, detail=''):
    result=result or {}
    with connection() as c:
        c.execute('''INSERT INTO web_startup_discovery_runs(network,source,state,scan_key,online,total,imported,detail,started_at,completed_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?)''',(
            network,source,state,result.get('scan_key') or '',int(result.get('online') or 0),int(result.get('count') or result.get('total') or 0),
            int(result.get('imported') or 0),str(detail or '')[:1000],started_at,utcnow() if state not in ('QUEUED','RUNNING') else None
        ))


def _worker(selection, source):
    global _THREAD
    network=selection['network']; started=utcnow()
    with _LOCK:
        _STATE.update({'state':'RUNNING','network':network,'source':source,'started_at':started,'completed_at':None,
                       'online':0,'active':0,'icmp_online':0,'arp_only':0,'total':0,'imported':0,'scan_key':'','detail':f'Đang tự động quét IP đang dùng trong {network}.'})
    try:
        if _STOP.is_set():
            raise RuntimeError('STOP_REQUESTED')
        # Show useful results immediately while the active ICMP sweep is still running.
        # This prevents the UI from sitting at 'đang quét' with no observable result.
        preliminary=_collect_lan_evidence(network,[],enrich_names=False,fast_only=True)
        preliminary_devices=[{'ip':ip,'mac':row.get('mac') or '','hostname':row.get('hostname') or '',
                              'status':'ActiveLAN','latency_ms':None,'created_at':started,
                              'sources':sorted(row.get('sources') or [])}
                             for ip,row in sorted(preliminary.items(),key=lambda kv:tuple(int(x) for x in kv[0].split('.')))]
        with _LOCK:
            _STATE['preliminary_active']=len(preliminary)
            _STATE['preliminary_devices']=preliminary_devices
            _STATE['active']=len(preliminary)
            _STATE['detail']=f'Đang quét {network}; đã thấy sơ bộ {len(preliminary)} IP từ ARP/DHCP/mDNS/SSDP.'
        preliminary_ips=set(preliminary)
        progress={'done':0,'total':0,'online':0,'icmp_ips':set()}
        def on_scan(event):
            kind=str(event.get('event') or '')
            if kind=='total': progress['total']=int(event.get('total') or 0)
            elif kind=='completed':
                progress['done']+=1
                rr=event.get('result') or {}
                if str(rr.get('status') or '').lower()=='online':
                    progress['online']+=1
                    if rr.get('ip'): progress['icmp_ips'].add(str(rr.get('ip')))
            with _LOCK:
                _STATE['progress_done']=progress['done']; _STATE['progress_total']=progress['total']
                _STATE['icmp_online']=progress['online']
                _STATE['active']=len(preliminary_ips | progress['icmp_ips'])
                if progress['total']:
                    _STATE['detail']=f"Đang quét {network}: {progress['done']}/{progress['total']} IP; đang thấy {len(preliminary_ips | progress['icmp_ips'])} IP hoạt động (ICMP {progress['online']}, LAN thụ động {len(preliminary_ips)})."
        # Late import avoids an import cycle while webapi.main is booting.
        from webapi.main import _run_scan
        result=_run_scan(network,max_workers=48,timeout=650,callback=on_scan,stop_event=_STOP)
        with _LOCK:
            _STATE['detail']=f'Đã quét ICMP xong {network}; đang hợp nhất ARP/DHCP/mDNS/SSDP.'
        evidence=_merge_neighbor_evidence(result.get('scan_key') or '',network)
        imported=_sync_active_to_ipmac(result.get('scan_key') or '')
        state='CANCELLED' if _STOP.is_set() or result.get('status')=='Cancelled' else ('COMPLETED_WITH_ERRORS' if result.get('errors') else 'COMPLETED')
        detail=(f"Đã quét {network}: {evidence['active']} IP đang dùng "
                f"({evidence['icmp_online']} ICMP, {evidence['arp_only']} LAN thụ động, DHCP {evidence.get('dhcp',0)}, mDNS {evidence.get('mdns',0)}, SSDP {evidence.get('ssdp',0)}); "
                f"đồng bộ {imported} bản ghi IP/MAC.")
        result={**result,**evidence,'imported':imported}
        _record(network,source,state,started,result,detail)
        with _LOCK:
            _STATE.update({'state':state,'network':network,'source':source,'started_at':started,'completed_at':utcnow(),
                           'online':int(result.get('online') or 0),'active':int(result.get('active') or 0),
                           'icmp_online':int(result.get('icmp_online') or 0),'arp_only':int(result.get('arp_only') or 0),
                           'total':int(result.get('count') or 0),'imported':imported,
                           'scan_key':result.get('scan_key') or '','progress_done':int(result.get('count') or 0),'progress_total':int(result.get('count') or 0),'preliminary_active':int(_STATE.get('preliminary_active') or 0),'detail':detail})
    except Exception as exc:
        state='CANCELLED' if str(exc)=='STOP_REQUESTED' or _STOP.is_set() else 'FAILED'
        detail='Đã dừng tự động quét LAN.' if state=='CANCELLED' else f'Tự động quét LAN lỗi: {type(exc).__name__}: {exc}'[:1000]
        _record(network,source,state,started,{},detail)
        with _LOCK:
            _STATE.update({'state':state,'network':network,'source':source,'started_at':started,'completed_at':utcnow(),
                           'detail':detail})
    finally:
        with _LOCK:
            _THREAD=None


def ensure(source='web-open', force=False):
    """Ensure one bounded discovery run for the currently active LAN.

    Calls are deduplicated across browser refreshes. A scan on the same subnet less
    than five minutes ago is returned as RECENT instead of starting another scan.
    """
    global _THREAD
    if str(os.environ.get('NA_WEB_ONLY_BROWSER','')).strip().lower() in ('1','true','yes','on'):
        with _LOCK:
            _STATE.update({
                'state':'BROWSER_ONLY','network':'','source':source,
                'started_at':None,'completed_at':utcnow(),'online':0,'active':0,
                'icmp_online':0,'arp_only':0,'total':0,'imported':0,'scan_key':'',
                'progress_done':0,'progress_total':0,'preliminary_active':0,'preliminary_devices':[],
                'detail':'Browser-only mode: LAN discovery on the Render host is disabled. A website cannot enumerate the private LAN of the visiting device.'
            })
        return status()
    ensure_tables()
    with _LOCK:
        if _THREAD and _THREAD.is_alive():
            return status()
    from webapi.platform50 import network_connectivity
    connectivity=network_connectivity(force=True)
    if not connectivity.get('lan'):
        with _LOCK:
            _STATE.update({'state':'SKIPPED','network':'','source':source,'started_at':None,'completed_at':utcnow(),
                           'online':0,'active':0,'icmp_online':0,'arp_only':0,'total':0,'imported':0,'scan_key':'','detail':'Không phát hiện LAN private đang hoạt động; không tự quét WAN/Internet.'})
        return status()
    selection=select_network(connectivity)
    if not selection:
        with _LOCK:
            _STATE.update({'state':'SKIPPED','network':'','source':source,'started_at':None,'completed_at':utcnow(),
                           'detail':'Có LAN nhưng không xác định được subnet IPv4 an toàn để tự quét.'})
        return status()
    if not force:
        recent=_recent_same_network(selection['network'])
        if recent:
            with _LOCK:
                counts=_active_counts(recent.get('scan_key') or '')
                _STATE.update({'state':'RECENT','network':selection['network'],'source':source,'started_at':recent.get('started_at'),
                               'completed_at':recent.get('completed_at'),'online':int(recent.get('online') or 0),
                               'active':counts['active'],'icmp_online':counts['icmp_online'],'arp_only':counts['arp_only'],
                               'total':int(recent.get('total') or 0),'imported':int(recent.get('imported') or 0),'scan_key':recent.get('scan_key') or '',
                               'detail':f"Mạng này vừa được quét trong 5 phút gần đây: {counts['active']} IP đang dùng; không chạy trùng."})
            return status()
    _STOP.clear()
    with _LOCK:
        _STATE.update({'state':'QUEUED','network':selection['network'],'source':source,'started_at':utcnow(),'completed_at':None,
                       'online':0,'active':0,'icmp_online':0,'arp_only':0,'total':0,'imported':0,'scan_key':'','progress_done':0,'progress_total':0,'preliminary_active':0,'preliminary_devices':[],'detail':f"Chuẩn bị quét IP đang dùng trong {selection['network']}."})
        _THREAD=threading.Thread(target=_worker,args=(selection,source),name='na-startup-lan-discovery',daemon=True)
        _THREAD.start()
    return status()


def status():
    with _LOCK:
        return dict(_STATE)


def shutdown(wait=False):
    _STOP.set()
    thread=None
    with _LOCK:
        thread=_THREAD
    if wait and thread and thread.is_alive():
        thread.join(timeout=10)
