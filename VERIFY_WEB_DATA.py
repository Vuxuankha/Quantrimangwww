from __future__ import annotations
import json, os, sqlite3, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def resolve_data():
    from web_data_root import resolve_web_data
    return resolve_web_data(use_external=('--external-data' in sys.argv))

def count(c,t):
    try:return c.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
    except Exception:return 'N/A'

def main():
    data,source=resolve_data(); db=data/'database'/'network_automation.db'; key=data/'database'/'.credential.key'
    print('NETWORKAUTOMATION WEB - KIEM TRA DU LIEU')
    print('Nguon chon:',source); print('Data root:',data); print('Database:',db)
    if not db.is_file():
        print('FAIL: Khong tim thay database.'); return 2
    try:
        uri=db.resolve().as_uri()+'?mode=ro'
        with sqlite3.connect(uri,uri=True,timeout=5) as c:
            quick=[r[0] for r in c.execute('PRAGMA quick_check').fetchall()]
            print('quick_check:', ' | '.join(map(str,quick[:10])))
            print('database bytes:',db.stat().st_size)
            print('credential key:', 'CO' if key.is_file() else 'KHONG')
            for t in ('devices','network_devices','ip_mac_inventory','alerts','health_samples','app_users','web_scan_results','autoip_targets'):
                print(f'{t}:',count(c,t))
            if quick != ['ok']:
                print('FAIL: Database khong dat quick_check. KHONG khoi dong Web bang DB nay.'); return 3
    except Exception as e:
        print('FAIL:',type(e).__name__,str(e)); return 4
    print('OK: Database co the doc va quick_check = ok.')
    return 0
if __name__=='__main__':
    raise SystemExit(main())
