"""Windows Wi-Fi diagnostics, encrypted camera registry and monitoring history."""
import os
import re
import socket
import subprocess
import errno
import time
from urllib.parse import urlsplit
from database.db import get_connection
from app_runtime import hidden_subprocess_kwargs
from modules.nms_v5 import encrypt_secret, decrypt_secret
from modules.ping_check import ping_host


def ensure_tables():
    c=get_connection()
    try:
        c.executescript('''CREATE TABLE IF NOT EXISTS camera_registry(
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL,
          port INTEGER NOT NULL DEFAULT 554, stream_enc TEXT NOT NULL DEFAULT '',
          snapshot_enc TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS extension_history(
          id INTEGER PRIMARY KEY, kind TEXT NOT NULL, target TEXT NOT NULL,
          status TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE INDEX IF NOT EXISTS idx_extension_history_time ON extension_history(created_at);
        ''');c.commit()
    finally:c.close()


def history(kind,target,status,detail):
    c=get_connection()
    try:
        c.execute('INSERT INTO extension_history(kind,target,status,detail) VALUES(?,?,?,?)',
                  (kind,target,status,detail));c.commit()
        # Bound history storage (latest 10,000 samples).
        c.execute('DELETE FROM extension_history WHERE id < COALESCE((SELECT id FROM extension_history ORDER BY id DESC LIMIT 1 OFFSET 9999),0)');c.commit()
    finally:c.close()


def validate_host(host):
    host=host.strip()
    if not host or host.startswith('-') or any(c.isspace() for c in host) or '/' in host or '\\' in host:
        raise ValueError('Nhập IP hoặc hostname hợp lệ.')
    return host


def save_camera(name,host,port,stream='',snapshot=''):
    host=validate_host(host);port=int(port)
    if not name.strip() or not 1<=port<=65535:raise ValueError('Tên hoặc cổng camera không hợp lệ.')
    if stream and urlsplit(stream).scheme not in ('rtsp','rtsps'):raise ValueError('Luồng phải dùng rtsp:// hoặc rtsps://')
    if snapshot and urlsplit(snapshot).scheme not in ('http','https'):raise ValueError('Snapshot phải dùng http:// hoặc https://')
    c=get_connection()
    try:
        c.execute('INSERT INTO camera_registry(name,host,port,stream_enc,snapshot_enc) VALUES(?,?,?,?,?)',
                  (name.strip(),host,port,encrypt_secret(stream) if stream else '',encrypt_secret(snapshot) if snapshot else ''));c.commit()
    finally:c.close()


def cameras():
    c=get_connection()
    try:return [dict(x) for x in c.execute('SELECT * FROM camera_registry ORDER BY id')]
    finally:c.close()


def _socket_failure(exc):
    # Keep the transport failure class; do not collapse every failure to Offline.
    if isinstance(exc, socket.timeout) or getattr(exc, 'errno', None) in {getattr(errno,'ETIMEDOUT',110), 10060}:
        return 'TIMEOUT', 'Hết thời gian chờ kết nối TCP.'
    code=getattr(exc,'errno',None)
    if isinstance(exc, ConnectionRefusedError) or code in {getattr(errno,'ECONNREFUSED',111),10061}:
        return 'CONNECTION_REFUSED', 'Máy đích từ chối kết nối; kiểm tra đúng cổng và dịch vụ.'
    if code in {getattr(errno,'ENETUNREACH',101),10051}:
        return 'NETWORK_UNREACHABLE', 'Không có đường tới mạng đích từ máy chạy Web.'
    if code in {getattr(errno,'EHOSTUNREACH',113),10065}:
        return 'HOST_UNREACHABLE', 'Không có đường tới host đích từ máy chạy Web.'
    if isinstance(exc, PermissionError) or code in {getattr(errno,'EACCES',13),10013}:
        return 'PERMISSION_DENIED', 'Hệ điều hành từ chối phép kết nối.'
    if isinstance(exc, socket.gaierror):
        return 'NAME_RESOLUTION_FAILED', 'Không phân giải được hostname.'
    return 'TCP_ERROR', f'Lỗi TCP: {type(exc).__name__}.'


def diagnose_camera(camera, timeout=5.0):
    host=validate_host(str(camera['host'])); port=int(camera['port'])
    started=time.monotonic(); steps=[]
    try:
        resolved=socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)
        addresses=sorted({x[4][0] for x in resolved})[:8]
        steps.append({'step':'resolve','status':'PASS','detail':'Phân giải địa chỉ thành công.','addresses':addresses})
    except OSError as exc:
        code,detail=_socket_failure(exc)
        steps.append({'step':'resolve','status':'FAIL','code':code,'detail':detail})
        return {'status':'FAIL','code':code,'host':host,'port':port,'elapsed_ms':round((time.monotonic()-started)*1000,1),'steps':steps,
                'meaning':'Không thể bắt đầu kiểm tra TCP; chưa kết luận camera tắt.'}
    probe=ping_host(host, min(2000, max(300,int(float(timeout)*1000))))
    steps.append({'step':'icmp','status':probe.get('status','Unknown'),'rtt_ms':probe.get('response'),'detail':probe.get('error') or 'ICMP chỉ là tín hiệu phụ; không phản hồi vẫn tiếp tục thử TCP.'})
    t0=time.monotonic()
    try:
        with socket.create_connection((host,port),timeout=max(0.5,min(float(timeout),15.0))):
            pass
        steps.append({'step':'tcp','status':'PASS','code':'TCP_OPEN','elapsed_ms':round((time.monotonic()-t0)*1000,1),
                      'detail':'Mở được kết nối TCP. Chưa xác nhận đăng nhập, RTSP hoặc hình ảnh.'})
        status='PASS'; code='TCP_OPEN'
    except OSError as exc:
        code,detail=_socket_failure(exc)
        steps.append({'step':'tcp','status':'FAIL','code':code,'elapsed_ms':round((time.monotonic()-t0)*1000,1),'detail':detail})
        status='FAIL'
    return {'status':status,'code':code,'host':host,'port':port,'elapsed_ms':round((time.monotonic()-started)*1000,1),'steps':steps,
            'meaning':'TCP_OPEN chỉ xác nhận cổng có thể kết nối; không đồng nghĩa xem được hình hoặc xác thực thành công.'}


def check_camera(camera):
    result=diagnose_camera(camera,3.0)
    if result['status']=='PASS':
        return 'Reachable','Cổng TCP truy cập được; chưa xác nhận hình ảnh hoặc đăng nhập.'
    return result.get('code','Unreachable'), result['steps'][-1].get('detail','Không kết nối được cổng TCP camera/đầu ghi.')


def command_output_detail(args, timeout=15):
    try:
        result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              text=True,errors='replace',timeout=timeout,**hidden_subprocess_kwargs())
    except subprocess.TimeoutExpired:
        return {'ok':False,'code':'COMMAND_TIMEOUT','stdout':'','stderr':'','detail':'Lệnh Windows quá thời gian chờ.'}
    out=(result.stdout or '').strip(); err=(result.stderr or '').strip()
    if result.returncode:
        raw=(err or out or f'Exit code {result.returncode}')[:4000]
        low=raw.lower()
        if 'location' in low or 'vị trí' in low:
            code='LOCATION_PERMISSION'
        elif 'access is denied' in low or 'access denied' in low or 'từ chối truy cập' in low:
            code='ACCESS_DENIED'
        elif 'wireless' in low and ('not running' in low or 'not started' in low):
            code='WLAN_SERVICE_STOPPED'
        else:
            code='COMMAND_FAILED'
        return {'ok':False,'code':code,'stdout':out[:30000],'stderr':err[:4000],'detail':raw}
    return {'ok':True,'code':'OK','stdout':out[:30000],'stderr':err[:4000],'detail':''}


def command_output(args):
    result=command_output_detail(args)
    if not result['ok']:
        raise RuntimeError(result['detail'] or result['code'])
    return result['stdout']




def wifi_adapter_status():
    if os.name!='nt':
        return {'supported':False,'status':'N/A','detail':'Wi-Fi diagnostics requires Windows.','adapters':[]}
    ps=("Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {"
        "$_.InterfaceDescription -match 'Wireless|Wi-Fi|802\\.11|WLAN' -or $_.Name -match 'Wi-Fi|WLAN'"
        "} | Select-Object Name,InterfaceDescription,Status | ConvertTo-Json -Compress")
    try:
        r=subprocess.run(['powershell','-NoProfile','-ExecutionPolicy','Bypass','-Command',ps],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,errors='replace',timeout=12,**hidden_subprocess_kwargs())
        if r.returncode!=0:
            return {'supported':True,'status':'WARN','detail':'Không đọc được trạng thái Wi-Fi adapter.','adapters':[]}
        raw=r.stdout.strip()
        if not raw:
            return {'supported':False,'status':'N/A','detail':'Không phát hiện Wi-Fi/WLAN adapter trên máy chạy Web.','adapters':[]}
        import json
        data=json.loads(raw); data=[data] if isinstance(data,dict) else data
        adapters=[{'name':str(x.get('Name') or ''),'description':str(x.get('InterfaceDescription') or ''),'status':str(x.get('Status') or '')} for x in (data or []) if isinstance(x,dict)]
        return {'supported':bool(adapters),'status':'PASS' if adapters else 'N/A','detail':'Phát hiện Wi-Fi adapter.' if adapters else 'Không phát hiện Wi-Fi/WLAN adapter.','adapters':adapters}
    except Exception as exc:
        return {'supported':True,'status':'WARN','detail':f'Không xác định được Wi-Fi adapter: {exc}','adapters':[]}

def wifi_diagnostics(gateway='',internet='1.1.1.1',stop=None):
    adapter=wifi_adapter_status()
    if adapter['status']=='N/A':
        return {'status':'N/A','detail':adapter['detail'],'adapters':adapter['adapters'],'interfaces':'','nearby_networks':'','probes':{},'steps':[]}
    if os.name!='nt':
        return {'status':'N/A','detail':'Chức năng Wi-Fi yêu cầu Windows.','adapters':[],'interfaces':'','nearby_networks':'','probes':{},'steps':[]}
    steps=[]
    iface=command_output_detail(['netsh','wlan','show','interfaces'])
    steps.append({'step':'interfaces','status':'PASS' if iface['ok'] else 'FAIL','code':iface['code'],'detail':iface['detail']})
    scan=command_output_detail(['netsh','wlan','show','networks','mode=bssid'])
    steps.append({'step':'nearby_networks','status':'PASS' if scan['ok'] else 'FAIL','code':scan['code'],'detail':scan['detail']})
    interfaces=iface['stdout'] if iface['ok'] else 'Không đọc được Wi-Fi: '+iface['detail']
    surrounding=scan['stdout'] if scan['ok'] else 'Không quét được mạng xung quanh: '+scan['detail']
    if not gateway:
        gw=command_output_detail(['powershell','-NoProfile','-Command',"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop"])
        gateway=gw['stdout'].strip() if gw['ok'] else ''
        steps.append({'step':'default_gateway','status':'PASS' if gateway else 'WARN','code':gw['code'],'detail':gw['detail'] or ('Gateway: '+gateway if gateway else 'Không xác định được gateway.')})
    probes={}
    for target in (gateway,internet):
        if not target:continue
        try: validate_host(target)
        except ValueError as exc:
            probes[str(target)]={'samples':0,'loss_percent':None,'latency_ms':None,'errors':1,'detail':str(exc)};continue
        samples=[]
        for _ in range(4):
            if stop is not None and stop.is_set():break
            samples.append(ping_host(target,1000))
        if not samples:continue
        online=[x['response'] for x in samples if x['status']=='Online' and x.get('response') is not None]
        probes[target]={'samples':len(samples),'loss_percent':round(100*(len(samples)-len(online))/len(samples),1),
                        'latency_ms':round(sum(online)/len(online),2) if online else None,
                        'errors':sum(x['status']=='Error' for x in samples),
                        'statuses':[x.get('status','Unknown') for x in samples]}
    failures=[x for x in steps if x['status']=='FAIL']
    detail='Wi-Fi diagnostics hoàn tất.' if not failures else 'Một hoặc nhiều bước Windows WLAN thất bại; xem mã lỗi từng bước.'
    return {'status':'PASS' if not failures else 'WARN','detail':detail,'adapters':adapter.get('adapters',[]),
            'interfaces':interfaces,'nearby_networks':surrounding,'probes':probes,'steps':steps}


def redact(text):
    text=re.sub(r'(rtsp[s]?://|https?://)[^\s/@]+:[^\s/@]+@',r'\1[REDACTED]@',text,flags=re.I)
    text=re.sub(r'(?im)((?:password|passwd|api[_ -]?key|token|secret|community)\s*[:=]\s*)[^\s,;]+',r'\1[REDACTED]',text)
    return text[:30000]

