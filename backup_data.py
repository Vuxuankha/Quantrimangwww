"""Create a consistent private backup of the selected NetworkAutomation data."""
from __future__ import annotations
import json, os, shutil, sqlite3, uuid
from pathlib import Path
from datetime import datetime

ROOT=Path(__file__).resolve().parent

def resolve_data():
    from web_data_root import resolve_web_data
    return resolve_web_data(use_external=('--external-data' in __import__('sys').argv))[0]

def main():
    data=resolve_data();db=data/'database'/'network_automation.db'
    if not db.is_file():raise SystemExit('Khong tim thay database/network_automation.db')
    stamp=datetime.now().strftime('%Y%m%d_%H%M%S')+'_'+uuid.uuid4().hex[:8]
    out=data/'database'/'manual_backups'/stamp;out.mkdir(parents=True,exist_ok=False)
    dest=out/'network_automation.db'
    with sqlite3.connect(db.resolve().as_uri()+'?mode=ro',uri=True) as src, sqlite3.connect(dest) as dst:
        src.backup(dst,pages=256)
        qc=dst.execute('PRAGMA quick_check').fetchone()[0]
        if qc!='ok':raise RuntimeError('Backup quick_check failed: '+str(qc))
    for p in (data/'database'/'.credential.key', data/'.credential.key', data/'database'/'known_hosts', data/'known_hosts'):
        if p.is_file():
            target=out/p.name
            if not target.exists():shutil.copy2(p,target)
    meta={'created_at':datetime.now().isoformat(timespec='seconds'),'source':str(data),'database':str(dest),'quick_check':'ok'}
    (out/'BACKUP_INFO.json').write_text(json.dumps(meta,ensure_ascii=False,indent=2),encoding='utf-8')
    print('BACKUP OK:',out)
    print('Day la backup rieng tu: co the chua credential key/known_hosts. Khong chia se cong khai.')

if __name__=='__main__':main()
