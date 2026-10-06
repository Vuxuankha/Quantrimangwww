"""NetworkAutomation Web 5.0 platform endpoints.

Adds explicit device-extension diagnostics and deployment readiness without
changing operator credentials or performing hidden network writes.
"""
from __future__ import annotations
import json, os, platform, shutil, socket, subprocess, sys, time, ipaddress, threading
from pathlib import Path
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from webapi.runtime37 import connection, utcnow
from webapi.security37 import require_role
from webapi import security37

router=APIRouter(prefix='/api/v50')

def _web_only_browser_mode() -> bool:
    return str(os.environ.get('NA_WEB_ONLY_BROWSER','')).strip().lower() in ('1','true','yes','on')

def _request_public_ip(request: Request) -> str:
    if request is None:
        return ''
    xff=str(request.headers.get('x-forwarded-for') or '').strip()
    if xff:
        return xff.split(',',1)[0].strip()[:80]
    real=str(request.headers.get('x-real-ip') or '').strip()
    if real:
        return real[:80]
    return str(getattr(request.client,'host','') or '')[:80]

def _browser_request_identity(request: Request) -> dict:
    ip=_request_public_ip(request)
    return {'ipv4':ip,'network':'','adapter':'Browser / HTTPS','gateway':'','description':'IP Internet công khai của thiết bị đang mở Web',
            'mode':'WEB','checked_at':utcnow(),'changed_since_start':False,'startup_ipv4':ip,'startup_network':'',
            'startup_adapter':'Browser / HTTPS','startup_observed_at':utcnow(),'source':'BROWSER'}

SERVICE_NAME='NetworkAutomationWeb'
security37.WRITE_RULES.extend([
    ('POST', r'/api/v50/cameras/\d+/diagnose', ('Admin','Operator')),
    ('POST', r'/api/v50/wifi/diagnose', ('Admin','Operator')),
    ('POST', r'/api/v50/startup-discovery/ensure', ('Admin','Operator')),
])

class CameraDiagIn(BaseModel):
    timeout_seconds: float = Field(default=5.0, ge=0.5, le=15.0)

class WifiDiagIn(BaseModel):
    gateway: str = Field(default='', max_length=255)
    internet: str = Field(default='1.1.1.1', max_length=255)


def normalize_discovery_sources(raw):
    """Normalize DB comma strings and preliminary in-memory source lists."""
    if isinstance(raw,(list,tuple,set)):
        src=[str(x).strip().upper() for x in raw if str(x).strip()]
    else:
        src=[x.strip().upper() for x in str(raw or '').split(',') if x.strip()]
    return list(dict.fromkeys(src))


def normalize_discovery_rows(rows):
    counts={'ICMP':0,'ARP':0,'DHCP':0,'MDNS':0,'SSDP':0,'DNS':0,'NETBIOS':0}
    for row in rows:
        src=normalize_discovery_sources(row.get('sources'))
        row['sources']=src
        for source in src:
            if source in counts:
                counts[source]+=1
    return counts


def _run_sc(*args):
    if os.name!='nt':
        return {'supported':False,'ok':False,'code':'WINDOWS_ONLY','detail':'Windows Service chỉ có trên Windows.'}
    try:
        r=subprocess.run(['sc.exe',*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,errors='replace',timeout=10)
        text=(r.stdout or r.stderr or '').strip()
        return {'supported':True,'ok':r.returncode==0,'code':'OK' if r.returncode==0 else 'SC_ERROR','detail':text[:5000]}
    except Exception as exc:
        return {'supported':True,'ok':False,'code':'SC_EXEC_ERROR','detail':f'{type(exc).__name__}: {exc}'[:1000]}



_NETWORK_CACHE_LOCK=threading.Lock()
_NETWORK_CACHE={'checked_at':0.0,'result':None}


def _powershell_adapters():
    """Return active Windows IPv4 adapters. Read-only and best-effort."""
    if os.name!='nt':
        return []
    script=(
        "$ErrorActionPreference='Stop';"
        "Get-NetIPConfiguration | Where-Object { $_.IPv4Address -and $_.NetAdapter.Status -eq 'Up' } | "
        "ForEach-Object { [PSCustomObject]@{ alias=$_.InterfaceAlias; description=$_.InterfaceDescription; "
        "ipv4=@($_.IPv4Address | ForEach-Object {$_.IPAddress}); "
        "networks=@($_.IPv4Address | ForEach-Object {\"$($_.IPAddress)/$($_.PrefixLength)\"}); "
        "metric=if($_.NetIPInterface){$_.NetIPInterface.InterfaceMetric}else{999999}; "
        "gateway=if($_.IPv4DefaultGateway){$_.IPv4DefaultGateway.NextHop}else{$null} } } | ConvertTo-Json -Compress"
    )
    try:
        r=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,errors='replace',timeout=6)
        if r.returncode or not (r.stdout or '').strip():
            return []
        data=json.loads(r.stdout)
        rows=data if isinstance(data,list) else [data]
        out=[]
        for row in rows:
            ips=row.get('ipv4') or []
            if isinstance(ips,str): ips=[ips]
            clean=[]
            for value in ips:
                try:
                    addr=ipaddress.ip_address(str(value))
                    if addr.version==4 and not addr.is_loopback: clean.append(str(addr))
                except ValueError: pass
            if clean:
                nets=[]
                for value in row.get('networks') or []:
                    try:
                        iface=ipaddress.ip_interface(str(value))
                        if iface.version==4 and not iface.ip.is_loopback: nets.append(str(iface))
                    except ValueError: pass
                try: metric=int(row.get('metric') or 999999)
                except Exception: metric=999999
                out.append({'name':str(row.get('alias') or ''),'description':str(row.get('description') or ''),'ipv4':clean,
                            'networks':nets,'metric':metric,'gateway':str(row.get('gateway') or '')})
        return out
    except Exception:
        return []


def _fallback_ipv4():
    ips=set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(),None,socket.AF_INET,socket.SOCK_DGRAM):
            ip=info[4][0]
            if ip and not ip.startswith('127.'): ips.add(ip)
    except Exception:
        pass
    for target in ('1.1.1.1','8.8.8.8','192.168.1.1'):
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try:
            s.connect((target,53));ip=s.getsockname()[0]
            if ip and not ip.startswith('127.'): ips.add(ip)
        except OSError:
            pass
        finally:
            s.close()
    return [{'name':'system','description':'fallback route detection','ipv4':sorted(ips),'gateway':''}] if ips else []


def _wan_probe(timeout=1.5):
    targets=[('1.1.1.1',443),('8.8.8.8',53),('9.9.9.9',443)]
    attempts=[]
    for host,port in targets:
        started=time.monotonic()
        try:
            with socket.create_connection((host,port),timeout=timeout):
                elapsed=round((time.monotonic()-started)*1000,1)
                attempts.append({'target':f'{host}:{port}','ok':True,'elapsed_ms':elapsed})
                return True,attempts
        except OSError as exc:
            attempts.append({'target':f'{host}:{port}','ok':False,'error':type(exc).__name__,
                             'elapsed_ms':round((time.monotonic()-started)*1000,1)})
    return False,attempts


def network_connectivity(force=False):
    now=time.time()
    with _NETWORK_CACHE_LOCK:
        cached=_NETWORK_CACHE.get('result')
        if cached and not force and now-float(_NETWORK_CACHE.get('checked_at') or 0)<30:
            return {**cached,'cached':True}
    adapters=_powershell_adapters() or _fallback_ipv4()
    addresses=[];private=[];link_local=[];gateways=[]
    for row in adapters:
        if row.get('gateway'): gateways.append(row['gateway'])
        for value in row.get('ipv4',[]):
            if value in addresses: continue
            addresses.append(value)
            try:
                addr=ipaddress.ip_address(value)
                if addr.is_link_local: link_local.append(value)
                elif addr.is_private: private.append(value)
            except ValueError: pass
    lan=bool(private)
    wan,attempts=_wan_probe()
    if wan and lan: mode='LAN+WAN'
    elif wan: mode='WAN'
    elif lan: mode='LAN_ONLY'
    elif link_local: mode='LINK_LOCAL'
    else: mode='OFFLINE'
    result={'mode':mode,'lan':lan,'wan':wan,'connected':bool(lan or wan),'checked_at':utcnow(),
            'adapters':adapters,'ipv4':addresses,'private_ipv4':private,'gateways':gateways,
            'wan_checks':attempts,'meaning':{
                'LAN+WAN':'Đã kết nối mạng nội bộ và có đường ra Internet.',
                'WAN':'Có đường ra Internet; không phát hiện IPv4 LAN riêng trên adapter đang hoạt động.',
                'LAN_ONLY':'Đã kết nối LAN nhưng chưa xác minh được đường ra Internet.',
                'LINK_LOCAL':'Chỉ phát hiện địa chỉ link-local; có thể chưa nhận được IP/gateway hợp lệ.',
                'OFFLINE':'Chưa phát hiện LAN hoạt động và chưa xác minh được kết nối Internet.'
            }[mode], 'cached':False}
    with _NETWORK_CACHE_LOCK:
        _NETWORK_CACHE['checked_at']=now;_NETWORK_CACHE['result']=result
    return result


@router.get('/network/connectivity')
def network_status(request:Request, force:bool=False):
    require_role(request)
    if _web_only_browser_mode():
        ip=_request_public_ip(request)
        return {'mode':'WEB','lan':False,'wan':True,'connected':True,'checked_at':utcnow(),'adapters':[],
                'ipv4':[ip] if ip else [],'private_ipv4':[],'gateways':[],'wan_checks':[],
                'meaning':'Web đang kết nối qua HTTPS. IP hiển thị là IP Internet công khai của thiết bị đang mở trang.',
                'cached':False,'source':'BROWSER'}
    return network_connectivity(force=force)


def _primary_identity_from_connectivity(result: dict) -> dict:
    candidates=[]
    for row in result.get('adapters') or []:
        try: metric=int(row.get('metric') or 999999)
        except Exception: metric=999999
        gateway=str(row.get('gateway') or '')
        net_by_ip={}
        for raw in row.get('networks') or []:
            try:
                iface=ipaddress.ip_interface(str(raw))
                if iface.version==4: net_by_ip[str(iface.ip)]=str(iface.network)
            except ValueError: pass
        for raw_ip in row.get('ipv4') or []:
            try: addr=ipaddress.ip_address(str(raw_ip))
            except ValueError: continue
            if addr.version!=4 or addr.is_loopback or addr.is_link_local: continue
            candidates.append((0 if gateway else 1, metric, 0 if addr.is_private else 1, str(addr), row, net_by_ip.get(str(addr),'')))
    if not candidates:
        return {'ipv4':'','network':'','adapter':'','gateway':'','description':''}
    candidates.sort(key=lambda x:(x[0],x[1],x[2],x[3]))
    _,_,_,ip,row,network=candidates[0]
    return {'ipv4':ip,'network':network,'adapter':str(row.get('name') or ''),
            'gateway':str(row.get('gateway') or ''),'description':str(row.get('description') or '')}


def ensure_network_identity_table():
    sql="""CREATE TABLE IF NOT EXISTS web_network_identity_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ipv4 TEXT NOT NULL DEFAULT '', network TEXT NOT NULL DEFAULT '',
        adapter TEXT NOT NULL DEFAULT '', gateway TEXT NOT NULL DEFAULT '',
        mode TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL DEFAULT '', observed_at TEXT NOT NULL
    )"""
    with connection() as c:
        c.execute(sql)
        c.execute('CREATE INDEX IF NOT EXISTS idx_web_network_identity_history_id ON web_network_identity_history(id DESC)')
        c.commit()


def record_network_identity(reason='runtime', force=False) -> dict:
    ensure_network_identity_table()
    current=network_connectivity(force=force)
    ident=_primary_identity_from_connectivity(current)
    with connection() as c:
        prev=c.execute('SELECT * FROM web_network_identity_history ORDER BY id DESC LIMIT 1').fetchone()
        previous=dict(prev) if prev else {}
        changed=bool(previous and (previous.get('ipv4')!=ident['ipv4'] or previous.get('network')!=ident['network'] or previous.get('adapter')!=ident['adapter']))
        c.execute('INSERT INTO web_network_identity_history(ipv4,network,adapter,gateway,mode,reason,observed_at) VALUES(?,?,?,?,?,?,?)',
                  (ident['ipv4'],ident['network'],ident['adapter'],ident['gateway'],current.get('mode') or '',reason,utcnow()))
        c.commit()
    return {**ident,'mode':current.get('mode') or 'OFFLINE','checked_at':current.get('checked_at'),
            'reason':reason,'changed':changed,'previous_ipv4':previous.get('ipv4',''),
            'previous_network':previous.get('network',''),'previous_adapter':previous.get('adapter','')}



def network_identity_status(force=False) -> dict:
    current=network_connectivity(force=force)
    ident=_primary_identity_from_connectivity(current)
    ensure_network_identity_table()
    with connection() as c:
        row=c.execute('SELECT * FROM web_network_identity_history ORDER BY id DESC LIMIT 1').fetchone()
    last=dict(row) if row else {}
    changed=bool(last and (last.get('ipv4')!=ident['ipv4'] or last.get('network')!=ident['network'] or last.get('adapter')!=ident['adapter']))
    return {**ident,'mode':current.get('mode') or 'OFFLINE','checked_at':current.get('checked_at'),
            'changed_since_start':changed,'startup_ipv4':last.get('ipv4',''),'startup_network':last.get('network',''),
            'startup_adapter':last.get('adapter',''),'startup_observed_at':last.get('observed_at',''),'source':'WEB_HOST'}

@router.get('/network/identity')
def network_identity(request:Request, force:bool=False):
    require_role(request)
    if _web_only_browser_mode():
        return _browser_request_identity(request)
    return network_identity_status(force=force)

def service_status():
    q=_run_sc('query',SERVICE_NAME)
    state='NOT_INSTALLED'
    if q['supported']:
        if q['ok']:
            upper=q['detail'].upper()
            state='RUNNING' if 'RUNNING' in upper else 'STOPPED' if 'STOPPED' in upper else 'INSTALLED'
        elif '1060' not in q['detail'] and 'does not exist' not in q['detail'].lower():
            state='UNKNOWN'
    return {**q,'name':SERVICE_NAME,'state':state,'run_mode':os.environ.get('NA_RUN_MODE','interactive'),
            'recommended':'Windows Service' if os.name=='nt' else 'Local process'}

@router.get('/about')
def about(request:Request):
    require_role(request)
    return {'version':'5.9.2','api':'5.9.2-cybersecurity','edition':'Production Web',
            'principle':'one shared engine; Web actions show explicit execution evidence',
            'run_mode':os.environ.get('NA_RUN_MODE','interactive'),'python':platform.python_version(),'platform':platform.platform()}

@router.get('/service')
def service(request:Request):
    require_role(request,'Admin')
    s=service_status()
    s['install_script']='INSTALL_WEB_SERVICE.bat'
    s['remove_script']='REMOVE_WEB_SERVICE.bat'
    s['note']='Service management is performed locally with the supplied scripts; the Web does not stop its own process.'
    return s

@router.post('/cameras/{camera_id}/diagnose')
def camera_diagnose(camera_id:int,x:CameraDiagIn,request:Request):
    u=require_role(request,'Admin','Operator')
    from modules.monitor_extensions import diagnose_camera, history
    with connection() as c:
        row=c.execute('SELECT id,name,host,port,stream_enc,snapshot_enc FROM camera_registry WHERE id=?',(camera_id,)).fetchone()
    if not row: raise HTTPException(404,'Không tìm thấy camera/NVR.')
    camera=dict(row)
    result=diagnose_camera(camera,x.timeout_seconds)
    result.update({'camera_id':camera_id,'name':camera['name'],'has_stream':bool(camera.get('stream_enc')),'has_snapshot':bool(camera.get('snapshot_enc')),
                   'checked_at':utcnow(),'actor':u['username']})
    safe={'code':result.get('code'),'elapsed_ms':result.get('elapsed_ms'),'steps':result.get('steps',[]),'meaning':result.get('meaning')}
    history('Camera',camera['host'],result['status'],json.dumps(safe,ensure_ascii=False))
    return result

@router.post('/wifi/diagnose')
def wifi_diagnose(x:WifiDiagIn,request:Request):
    u=require_role(request,'Admin','Operator')
    from modules.monitor_extensions import wifi_diagnostics, history, redact
    result=wifi_diagnostics(x.gateway,x.internet)
    safe={k:v for k,v in result.items() if k not in ('interfaces','nearby_networks')}
    history('WiFi','Windows',result.get('status','Unknown'),redact(json.dumps(safe,ensure_ascii=False)))
    result['checked_at']=utcnow();result['actor']=u['username']
    return result


@router.get('/startup-discovery')
def startup_discovery_status(request:Request):
    require_role(request)
    if _web_only_browser_mode():
        return {'state':'BROWSER_ONLY','network':'','online':0,'active':0,'icmp_online':0,'arp_only':0,'total':0,'imported':0,
                'scan_key':'','progress_done':0,'progress_total':0,'preliminary_active':0,'preliminary_devices':[],
                'detail':'Web host không quét mạng LAN của thiết bị người dùng. Trình duyệt chỉ tự xác định IP Internet công khai và chất lượng kết nối HTTPS.','source':'BROWSER'}
    from webapi.autodiscovery5010 import status
    return status()


@router.get('/connected-devices')
def connected_devices(request:Request):
    """Return devices observed by active and passive LAN discovery sources."""
    require_role(request,'Admin','Operator','Viewer')
    if _web_only_browser_mode():
        return {'state':'BROWSER_ONLY','network':'','scan_key':'','count':0,'devices':[],'source_counts':{},
                'detail':'Trình duyệt Web không có quyền đọc ARP/MAC hoặc quét các IP private trong LAN.','completed_at':None,'source':'BROWSER'}
    from webapi.autodiscovery5010 import status as discovery_status, ensure_tables
    ensure_tables()
    st=discovery_status()
    scan_key=st.get('scan_key') or ''
    result=[]
    if not scan_key and st.get('state') in ('RUNNING','QUEUED'):
        # 6.7.1: expose passive preliminary LAN evidence immediately instead of
        # returning an empty list for the entire active sweep duration.
        result=[dict(x) for x in (st.get('preliminary_devices') or [])]
    if scan_key:
        with connection() as c:
            try:
                rows=c.execute("""SELECT r.ip,r.mac,r.hostname,r.status,r.latency_ms,r.created_at,
                               COALESCE(e.sources,CASE WHEN lower(r.status)='online' THEN 'ICMP' ELSE 'ARP' END) sources
                        FROM web_scan_results r LEFT JOIN web_connected_device_evidence e
                          ON e.scan_key=r.scan_key AND e.ip=r.ip
                        WHERE r.scan_key=? AND lower(r.status) IN ('online','activearp','activelan')
                        ORDER BY r.ip""",(scan_key,)).fetchall()
            except Exception:
                rows=c.execute("SELECT ip,mac,hostname,status,latency_ms,created_at FROM web_scan_results WHERE scan_key=? AND lower(status) IN ('online','activearp','activelan') ORDER BY ip",(scan_key,)).fetchall()
            result=[dict(r) for r in rows]
    counts=normalize_discovery_rows(result)
    return {'state':st.get('state'),'network':st.get('network'),'scan_key':scan_key,
            'count':len(result),'devices':result,'source_counts':counts,'detail':st.get('detail'),'completed_at':st.get('completed_at')}

@router.post('/startup-discovery/ensure')
def startup_discovery_ensure(request:Request, force:bool=False):
    require_role(request,'Admin','Operator')
    if _web_only_browser_mode():
        return {'state':'BROWSER_ONLY','network':'','online':0,'active':0,'icmp_online':0,'arp_only':0,'total':0,'imported':0,
                'scan_key':'','progress_done':0,'progress_total':0,
                'detail':'Không thể quét LAN từ Web host. IP Internet công khai và kiểm tra đường truyền được thực hiện tự động từ trình duyệt.','source':'BROWSER'}
    from webapi.autodiscovery5010 import ensure
    return ensure(source='web-open', force=force)

@router.get('/readiness')
def readiness(request:Request):
    require_role(request,'Admin')
    root=Path(__file__).resolve().parent.parent
    deps={name:bool(shutil.which(name)) for name in ('ping','ssh','telnet')}
    pydeps={}
    for name in ('paramiko','pysnmp','uvicorn','fastapi','cryptography'):
        try: __import__(name);pydeps[name]=True
        except Exception: pydeps[name]=False
    svc=service_status()
    return {'version':'5.9.2','service':svc,'executables':deps,'python_dependencies':pydeps,'network':network_connectivity(),
            'release_verify':(root/'VERIFY_RELEASE.py').is_file(),'data_policy':'runtime_data is preserved across code updates',
            'warnings':[m for m,ok in [('Paramiko chưa sẵn sàng',pydeps['paramiko']),('PySNMP chưa sẵn sàng',pydeps['pysnmp'])] if not ok]}
