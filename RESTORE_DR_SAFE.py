from __future__ import annotations
import json, os, shutil, sqlite3, sys, tempfile, zipfile
from datetime import datetime
from pathlib import Path

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from web_data_root import resolve_web_data
_selected_data, _selected_source = resolve_web_data(use_external=('--external-data' in sys.argv))
os.environ['NETWORK_AUTOMATION_DATA_DIR']=str(_selected_data)
from app_runtime import DATABASE_DIR
from database.db import DB_PATH
from webapi.runtime37 import DataLock, sqlite_snapshot

ALLOWED={'database/network_automation.db','database/.credential.key','database/known_hosts','DR_MANIFEST.json'}

def check_db(path:Path):
    with sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=5) as c:
        q=c.execute('PRAGMA quick_check').fetchone()[0]
        i=c.execute('PRAGMA integrity_check').fetchone()[0]
        fk=c.execute('PRAGMA foreign_key_check').fetchall()
    if q!='ok' or i!='ok' or fk:
        raise RuntimeError(f'DR database invalid: quick={q} integrity={i} foreign_keys={len(fk)}')

def main():
    print('NetworkAutomation - SAFE PRIVATE DR RESTORE')
    print('BAT BUOC: dung Web, desktop, Auto IP va monitor/service truoc khi restore.')
    zpath=Path(input('Duong dan file NetworkAutomation_DR_PRIVATE_*.zip: ').strip().strip('"')).expanduser().resolve()
    if not zpath.is_file(): raise RuntimeError('Khong tim thay file DR')
    confirm=input('Go chinh xac RESTORE PRIVATE DR de tiep tuc: ').strip()
    if confirm!='RESTORE PRIVATE DR':
        print('Da huy. Khong thay doi du lieu.');return 1
    lock=DataLock(Path(DATABASE_DIR)/'.web37.lock')
    lock.acquire()
    try:
        with zipfile.ZipFile(zpath) as z:
            names=set(z.namelist())
            if 'database/network_automation.db' not in names: raise RuntimeError('DR package missing database')
            unknown=[n for n in names if n not in ALLOWED]
            if unknown: raise RuntimeError('DR package contains unexpected files')
            with tempfile.TemporaryDirectory(prefix='na-dr-') as td:
                td=Path(td)
                dbtmp=td/'network_automation.db'
                with z.open('database/network_automation.db') as src, open(dbtmp,'wb') as dst: shutil.copyfileobj(src,dst)
                check_db(dbtmp)
                # Best-effort exclusive check for the current SQLite file before replacement.
                current=Path(DB_PATH)
                if current.exists():
                    try:
                        c=sqlite3.connect(current,timeout=1);c.execute('BEGIN EXCLUSIVE');c.rollback();c.close()
                    except Exception as exc:
                        raise RuntimeError('Database dang duoc su dung. Dong desktop/service roi thu lai.') from exc
                stamp=datetime.now().strftime('%Y%m%d_%H%M%S')
                safety=Path(DATABASE_DIR)/'dr_restore_backups'/stamp
                safety.mkdir(parents=True,exist_ok=False)
                if current.exists(): sqlite_snapshot(current,safety/'network_automation.db')
                for name in ('.credential.key','known_hosts'):
                    p=Path(DATABASE_DIR)/name
                    if p.exists(): shutil.copy2(p,safety/name)
                incoming=Path(DATABASE_DIR)/('network_automation.db.incoming_'+stamp)
                shutil.copy2(dbtmp,incoming);check_db(incoming)
                os.replace(incoming,current)
                for name in ('.credential.key','known_hosts'):
                    arc='database/'+name
                    if arc in names:
                        temp=Path(DATABASE_DIR)/(name+'.incoming_'+stamp)
                        with z.open(arc) as src, open(temp,'wb') as dst: shutil.copyfileobj(src,dst)
                        os.replace(temp,Path(DATABASE_DIR)/name)
                try:check_db(current)
                except Exception:
                    if (safety/'network_automation.db').exists(): shutil.copy2(safety/'network_automation.db',current)
                    raise RuntimeError('Final verification failed; original DB restored from safety copy')
                print('RESTORE OK')
                print('Safety backup:',safety)
                print('Hay chay VERIFY_DATABASE.bat truoc khi START_WEB.bat.')
                return 0
    finally:
        lock.release()

if __name__=='__main__':
    try: raise SystemExit(main())
    except Exception as exc:
        print('RESTORE FAILED:',exc)
        input('Press Enter...')
        raise SystemExit(1)
