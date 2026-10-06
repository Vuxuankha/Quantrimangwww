from __future__ import annotations
import argparse
import json
import os
import sqlite3
import urllib.request
from pathlib import Path

from VERIFY_RELEASE import verify_release
from web_data_root import RUNTIME_DATA, resolve_web_data

ROOT=Path(__file__).resolve().parent


def resolve_self_check_data(argv=None, env=None) -> tuple[Path,str]:
    """Resolve the same data location operators can select for the Web runtime.

    Priority is explicit --data-dir, NETWORK_AUTOMATION_DATA_DIR, explicit
    --external-data/data_location.json, then the normal isolated runtime_data.
    This resolver is read-only: SELF_CHECK never seeds/copies a database.
    """
    parser=argparse.ArgumentParser(add_help=False)
    parser.add_argument('--data-dir')
    parser.add_argument('--external-data',action='store_true')
    args,_=parser.parse_known_args(argv)
    env=os.environ if env is None else env

    if args.data_dir:
        return Path(args.data_dir).expanduser().resolve(),'--data-dir'

    override=str(env.get('NETWORK_AUTOMATION_DATA_DIR','') or '').strip()
    if override:
        return Path(override).expanduser().resolve(),'NETWORK_AUTOMATION_DATA_DIR'

    if args.external_data:
        selected,source=resolve_web_data(use_external=True)
        return Path(selected).resolve(),source

    return RUNTIME_DATA.resolve(),'isolated runtime_data'


def main(argv=None)->int:
    errors=[]
    release=verify_release(ROOT)
    print('[RELEASE]', 'OK' if release['ok'] else 'FAIL', release['version'], 'files=',release['checked'])
    if not release['ok']:
        errors.extend(release['errors'])

    try:
        data_root,data_source=resolve_self_check_data(argv)
        print(f'[DATA] root={data_root} source={data_source}')
        db=data_root/'database'/'network_automation.db'
    except Exception as exc:
        print('[DATA] RESOLVE FAIL',type(exc).__name__,str(exc))
        errors.append('data root resolution failed')
        db=None

    if db is None or not db.is_file():
        print('[DATA] NOT READY - runtime database missing')
        errors.append('runtime database missing')
    else:
        try:
            with sqlite3.connect(db) as c:
                qc=c.execute('pragma quick_check').fetchone()[0]
                tabs={r[0] for r in c.execute("select name from sqlite_master where type='table'")}
                admins=0
                if 'app_users' in tabs:
                    admins=c.execute("select count(*) from app_users where enabled=1 and lower(role)='admin'").fetchone()[0]
                print(f'[DATA] quick_check={qc}; enabled_admins={admins}')
                if qc!='ok': errors.append('sqlite quick_check failed')
                if admins<1: errors.append('no enabled Admin')
        except Exception as exc:
            print('[DATA] FAIL',type(exc).__name__,str(exc))
            errors.append('database open failed')

    expected=(ROOT/'WEB_VERSION.txt').read_text(encoding='utf-8').strip()
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    found=None
    for port in range(8765,8786):
        try:
            with opener.open(f'http://127.0.0.1:{port}/api/health',timeout=.35) as r:
                obj=json.load(r)
            if isinstance(obj,dict) and obj.get('service')=='networkautomation-operational-web':
                found=(port,obj.get('version'))
                break
        except Exception:
            pass
    if found:
        print(f'[WEB] RUNNING port={found[0]} version={found[1]}')
        if found[1]!=expected: errors.append('running Web version mismatch')
    else:
        print('[WEB] NOT RUNNING on ports 8765-8785')
    if errors:
        print('[RESULT] NEEDS ATTENTION:', '; '.join(errors[:8]))
        return 1
    print('[RESULT] READY')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
