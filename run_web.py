"""Single-command local launcher. Reserves its socket; never kills another process."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import threading
import time
import urllib.request
import webbrowser

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))

def resolve_data():
    from web_data_root import resolve_web_data
    data, _source = resolve_web_data(use_external=('--external-data' in sys.argv))
    db=data/'database'/'network_automation.db'
    if not db.is_file():
        raise RuntimeError('Selected data root has no database/network_automation.db. Run RESET_TO_LOCAL_DATA.bat or CONFIGURE_WEB.bat.')
    return data

def fetch_json(url):
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url,timeout=1) as r:return json.load(r)

def main():
    from VERIFY_RELEASE import require_release
    report = require_release(ROOT)
    print("RELEASE OK:", report["version"], "-", report["checked"], "code/asset files")
    os.chdir(ROOT);data=resolve_data()
    os.environ['NETWORK_AUTOMATION_DATA_DIR']=str(data)
    os.environ['NA_COOKIE_SECURE']='0' # loopback HTTP only; not a global Windows setting
    os.environ.setdefault('NA_TIMEZONE','Asia/Ho_Chi_Minh')
    os.environ['NA_ALLOWED_HOSTS']='127.0.0.1,localhost'
    # The local Web launcher owns the loopback-only coordinator. Enable Auto IP/Ping
    # by default here; operators can still explicitly disable it with NA_ENABLE_AUTOIP=0.
    os.environ.setdefault('NA_ENABLE_AUTOIP','1')
    from webapi.runtime37 import VERSION,SERVICE
    fingerprint=hashlib.sha256(str(ROOT).encode()).hexdigest()
    state=data/'database'/'.web37-instance.json'
    if state.exists():
        try:
            previous=json.loads(state.read_text())
            port=int(previous['port'])
            if not 8765<=port<=8785: raise ValueError('invalid port')
            old=fetch_json(f'http://127.0.0.1:{port}/api/health')
            if old.get('instance')==previous['nonce'] and old.get('service')==SERVICE:
                if old.get('version')!=VERSION or previous.get('source')!=fingerprint:
                    raise RuntimeError('Another Web version/source is using this data. Stop its Web terminal before upgrading. Nothing was overwritten or killed.')
                print('Web is already running. Opening its existing instance.')
                if '--no-browser' not in sys.argv: webbrowser.open(f'http://127.0.0.1:{port}/')
                return
        except RuntimeError: raise
        except Exception: pass
    sock=None
    for port in range(8765,8786):
        candidate=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            candidate.bind(('127.0.0.1',port));candidate.listen(128);sock=candidate;break
        except OSError: candidate.close()
    if sock is None: raise RuntimeError('No free port 8765-8785. Nothing was stopped.')
    nonce=secrets.token_hex(24);os.environ['NA_INSTANCE_TOKEN']=nonce
    url=f'http://127.0.0.1:{port}/'
    import uvicorn
    record={'nonce':nonce,'port':port,'source':fingerprint,'version':VERSION,'pid':os.getpid(),'started_at':time.time()}
    def open_ready():
        for _ in range(120):
            try:
                r=fetch_json(url+'api/health')
                if r.get('instance')==nonce and r.get('version')==VERSION and r.get('service')==SERVICE:
                    state.write_text(json.dumps(record),encoding='utf-8')
                    print('READY:',url,'\nData:',data)
                    if '--no-browser' not in sys.argv: webbrowser.open(url)
                    return
            except Exception: pass
            time.sleep(.5)
    threading.Thread(target=open_ready,daemon=True).start()
    try:
        config=uvicorn.Config('webapi.main:app',host='127.0.0.1',port=port,workers=1,reload=False,ws_max_size=16384,ws_max_queue=16,ws_per_message_deflate=False,proxy_headers=False,use_colors=False,log_level='info')
        uvicorn.Server(config).run(sockets=[sock])
    finally:
        sock.close()
        try:
            if json.loads(state.read_text()).get('nonce')==nonce:state.unlink()
        except Exception:pass

if __name__=='__main__':
    try:main()
    except Exception as exc:
        print('START FAILED:',exc);sys.exit(1)
