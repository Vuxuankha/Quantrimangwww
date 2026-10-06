from __future__ import annotations
import ipaddress, os, re, socketserver, threading, time
from collections import defaultdict, deque
from modules.enterprise_security import record_event
from webapi.realtime import hub

PRI_RE=re.compile(r'^<(\d{1,3})>')
SEV={0:'CRITICAL',1:'CRITICAL',2:'CRITICAL',3:'HIGH',4:'MEDIUM',5:'LOW',6:'INFO',7:'INFO'}

def _allowed(ip:str)->bool:
    spec=os.getenv('NA_SYSLOG_ALLOW_CIDRS','127.0.0.0/8,::1/128')
    try: addr=ipaddress.ip_address(ip)
    except ValueError:return False
    for item in (x.strip() for x in spec.split(',') if x.strip()):
        try:
            if addr in ipaddress.ip_network(item,strict=False): return True
        except ValueError: continue
    return False

class _Rate:
    def __init__(self): self.hits=defaultdict(deque); self.lock=threading.Lock()
    def ok(self,ip):
        limit=int(os.getenv('NA_SYSLOG_RATE_PER_MIN','600')); now=time.monotonic()
        with self.lock:
            q=self.hits[ip]
            while q and q[0]<now-60:q.popleft()
            if len(q)>=limit:return False
            q.append(now);return True
_rate=_Rate()

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data=self.request[0][:8192]; ip=self.client_address[0]
        if not _allowed(ip) or not _rate.ok(ip): return
        text=data.decode('utf-8','replace').replace('\x00','').strip()
        if not text:return
        m=PRI_RE.match(text); sev='INFO'
        if m: sev=SEV.get(int(m.group(1)) & 7,'INFO')
        try:
            eid=record_event('', 'SYSLOG', 'SYSLOG_MESSAGE', sev, f'Syslog from {ip}', text)
            hub.broadcast_threadsafe({'type':'security_event','id':eid,'source':'SYSLOG','severity':sev,'title':f'Syslog from {ip}'})
        except Exception:
            return

class ThreadedUDP(socketserver.ThreadingMixIn,socketserver.UDPServer):
    daemon_threads=True; allow_reuse_address=True

class SyslogCollector:
    def __init__(self): self.server=None; self.thread=None
    def start(self):
        if os.getenv('NA_SYSLOG_ENABLED','0')!='1': return False
        host=os.getenv('NA_SYSLOG_HOST','127.0.0.1'); port=int(os.getenv('NA_SYSLOG_PORT','5514'))
        self.server=ThreadedUDP((host,port),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,name='na-syslog',daemon=True); self.thread.start(); return True
    def stop(self):
        if self.server:
            self.server.shutdown(); self.server.server_close(); self.server=None
collector=SyslogCollector()
