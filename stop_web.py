"""Stop only the NetworkAutomation Web process whose live instance nonce matches local state."""
from __future__ import annotations
import json, os, signal, subprocess, sys, time, urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parent

def resolve_data():
    from web_data_root import resolve_web_data
    return resolve_web_data(use_external=('--external-data' in __import__('sys').argv))[0]

def get_json(url):
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url,timeout=2) as r:return json.load(r)

def main():
    data=resolve_data();state=data/'database'/'.web37-instance.json'
    if not state.exists():
        print('Khong tim thay Web instance dang chay cho data folder nay.');return 0
    rec=json.loads(state.read_text(encoding='utf-8'))
    try: port=int(rec['port']);pid=int(rec['pid']);nonce=str(rec['nonce'])
    except Exception:
        print('State cu khong co PID hop le. Dong cua so START_WEB bang Ctrl+C, sau do khoi dong lai ban v4.0.');return 2
    if not (8765<=port<=8785) or pid<=0:
        print('State khong hop le; KHONG kill process.');return 2
    try:
        live=get_json(f'http://127.0.0.1:{port}/api/health')
    except Exception:
        print('Khong xac minh duoc live instance; KHONG kill PID de tranh dung nham process.');return 2
    if live.get('instance')!=nonce or live.get('service')!='networkautomation-operational-web':
        print('Nonce/service khong khop; KHONG kill process.');return 2
    (data/'database'/'.web46-intentional-stop').write_text(nonce,encoding='utf-8')
    print(f'Dang dung NetworkAutomation Web PID={pid}, port={port} ...')
    if os.name=='nt':
        r=subprocess.run(['taskkill','/PID',str(pid),'/T'],capture_output=True,text=True)
        if r.returncode!=0:
            print((r.stdout or '')+(r.stderr or ''));return r.returncode
    else:
        os.kill(pid,signal.SIGTERM)
    # Wait for that exact instance to disappear. Only then remove its stale state file.
    stopped=False
    for _ in range(50):
        try:
            live=get_json(f'http://127.0.0.1:{port}/api/health')
            if live.get('instance')!=nonce:
                stopped=True;break
        except Exception:
            stopped=True;break
        time.sleep(.1)
    if stopped:
        try:
            current=json.loads(state.read_text(encoding='utf-8'))
            if current.get('nonce')==nonce: state.unlink(missing_ok=True)
        except Exception: pass
        print('Da dung dung instance da xac minh.')
        return 0
    print('Da gui yeu cau dung nhung server chua thoat sau 5 giay; state duoc giu lai de chan doan.')
    return 3

if __name__=='__main__':
    raise SystemExit(main())
