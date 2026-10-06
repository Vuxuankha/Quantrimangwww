"""Offline, explicit data migration. Never reads or changes the source database in-place.

Use IMPORT_APP_DATA.bat on Windows, or pass --source DATA_ROOT. New runtime is
prepared and validated first. Existing runtime is moved to a timestamped backup.
"""
from __future__ import annotations
import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent


def source_root(value: Path) -> Path:
    p=value.expanduser().resolve()
    if p.is_file() and p.name=='network_automation.db': p=p.parent
    if p.name=='database' and (p/'network_automation.db').is_file(): p=p.parent
    if not (p/'database'/'network_automation.db').is_file():
        raise ValueError('Select the actual data folder containing database/network_automation.db (not the ZIP).')
    return p


def encrypted_values(c):
    tables={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for t in tables:
        qt='"'+t.replace('"','""')+'"'
        for col in (r[1] for r in c.execute('PRAGMA table_info('+qt+')')):
            if col.endswith('_enc'):
                qc='"'+col.replace('"','""')+'"'
                yield from (r[0] for r in c.execute('SELECT '+qc+' FROM '+qt+' WHERE '+qc+" IS NOT NULL AND "+qc+"<>''"))
    if 'settings' in tables:
        for k,v in c.execute('SELECT key,value FROM settings'):
            if str(k).endswith('_enc') and v: yield v


def inspect(db: Path, key: Path) -> dict:
    with sqlite3.connect(db.resolve().as_uri()+'?mode=ro',uri=True,timeout=10) as c:
        if c.execute('PRAGMA quick_check').fetchall()!=[('ok',)]: raise ValueError('Database quick_check failed. Source is unchanged.')
        if c.execute('PRAGMA foreign_key_check').fetchone(): raise ValueError('Database contains broken foreign keys. Source is unchanged.')
        tables={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'devices','network_devices'} & tables: raise ValueError('Not a NetworkAutomation database.')
        secrets=list(encrypted_values(c))
        if secrets:
            if not key.is_file(): raise ValueError('Encrypted data exists but the original .credential.key is missing. Do not create a replacement key.')
            from cryptography.fernet import Fernet, InvalidToken
            try:
                f=Fernet(key.read_bytes().strip())
                for secret in secrets: f.decrypt(secret.encode() if isinstance(secret,str) else secret)
            except (InvalidToken,ValueError,TypeError) as exc:
                raise ValueError('Credential key does not match encrypted data. Nothing was imported.') from exc
        return {t:c.execute('SELECT COUNT(*) FROM '+t).fetchone()[0] for t in ('devices','network_devices','autoip_targets','credentials','app_users') if t in tables}


def copy_tree_safe(source: Path, destination: Path):
    if not source.exists(): return
    for item in source.rglob('*'):
        if item.is_symlink(): raise ValueError('Symbolic links in data are not imported: '+str(item))
        if item.is_file():
            dest=destination/item.relative_to(source);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(item,dest)


def prepare_snapshot(source: Path, staging: Path, final_root: Path) -> dict:
    """Safe snapshot callable by tests and release builder; no running app imports."""
    source=source_root(source)
    report=inspect(source/'database'/'network_automation.db',source/'database'/'.credential.key')
    (staging/'database').mkdir(parents=True,exist_ok=True)
    db=staging/'database'/'network_automation.db'
    with sqlite3.connect((source/'database'/'network_automation.db').as_uri()+'?mode=ro',uri=True) as old:
        with sqlite3.connect(db) as new: old.backup(new)
    for name in ('.credential.key','known_hosts'):
        src=source/'database'/name
        if src.is_file(): shutil.copy2(src,staging/'database'/name)
    for name in ('backups','reports'): copy_tree_safe(source/name,staging/name)
    paused=[];unresolved=0
    with sqlite3.connect(db) as c:
        tables={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table in ('web_schedules40','scheduled_tasks','monitoring_settings'):
            if table in tables and 'enabled' in {r[1] for r in c.execute('PRAGMA table_info('+table+')')}:
                n=c.execute('UPDATE '+table+' SET enabled=0 WHERE enabled<>0').rowcount
                if n: paused.append({'table':table,'count':n})
        for table in ('web_sessions37','web_login_attempts37'):
            if table in tables:c.execute('DELETE FROM '+table)
        # Historical absolute Windows paths are remapped only when the exact
        # suffix exists in the copied backup/report tree. Never invent a file.
        for table,col in (('config_backups','file_path'),('autoip_runs','report_path')):
            if table not in tables:continue
            for rid,path in c.execute('SELECT id,'+col+' FROM '+table).fetchall():
                if not path:continue
                parts=str(path).replace('\\','/').split('/');rel=None
                for anchor in ('backups','reports'):
                    if anchor in parts:
                        suffix=Path(*parts[parts.index(anchor):])
                        if '..' not in suffix.parts and (staging/suffix).is_file():rel=suffix;break
                if rel:c.execute('UPDATE '+table+' SET '+col+'=? WHERE id=?',(str(final_root/rel),rid))
                else:unresolved+=1
        c.commit()
    inspect(db,staging/'database'/'.credential.key')
    result={'counts':report,'paused_automation':paused,'unresolved_historical_paths':unresolved,
            'source':str(source),'created_at':datetime.now(timezone.utc).isoformat(),
            'note':'Source untouched. Existing automation paused in this copy; explicitly enable after review.'}
    (staging/'IMPORT_REPORT.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path)
    args=parser.parse_args(argv)
    print('Stop the old Web terminal, Desktop app and monitoring service BEFORE importing.')
    if not args.source:
        try:
            import tkinter as tk
            from tkinter import filedialog
            w=tk.Tk();w.withdraw()
            selected=filedialog.askdirectory(title='Chon thu muc DU LIEU app / Web cu (co database)');w.destroy()
        except Exception: selected=input('Data folder: ').strip().strip('"')
        if not selected:return 1
        args.source=Path(selected)
    src=source_root(args.source);dest=ROOT/'runtime_data'
    if src==dest or src in dest.parents or dest in src.parents:
        raise ValueError('Source and destination must be separate data folders, not nested.')
    counts=inspect(src/'database'/'network_automation.db',src/'database'/'.credential.key')
    print('READ source:',src);print('NEW runtime:',dest);print('Record counts:',counts)
    print('Existing runtime will be preserved in a timestamped backup. Accounts/key will be retained; schedules paused.')
    if input('Type IMPORT to confirm: ').strip()!='IMPORT':print('Cancelled.');return 1
    # Test OS leases without importing app_runtime (which could initialize DB).
    from modules.operation_lock import OperationLease
    with ExitStack() as stack:
        for folder in (src,dest):
            if not folder.exists():continue
            for name in ('.web37.lock','.autoip-coordinator.lock'):
                lease=OperationLease(folder/'database'/name);lease.acquire();stack.callback(lease.release)
        staging=Path(tempfile.mkdtemp(prefix='.import45-',dir=ROOT))
        try:result=prepare_snapshot(src,staging,dest)
        except Exception:shutil.rmtree(staging,ignore_errors=True);raise
        # On Windows open lease files prevent folder rename; release only after
        # snapshot validation. Operator must keep all apps stopped during import.
    backup=None
    try:
        if dest.exists():
            backup=ROOT/('runtime_backup_'+datetime.now().strftime('%Y%m%d_%H%M%S')+'_'+uuid.uuid4().hex[:6]);dest.rename(backup)
        staging.rename(dest)
    except Exception:
        if backup and backup.exists() and not dest.exists():backup.rename(dest)
        shutil.rmtree(staging,ignore_errors=True);raise
    print('IMPORT OK. Counts:',result['counts']);print('Old runtime backup:',backup or 'not needed')
    print('Paused automation:',result['paused_automation']);print('Unresolved old report paths:',result['unresolved_historical_paths'])
    print('Run START_WEB.bat. Full details: runtime_data/IMPORT_REPORT.json')
    return 0

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as exc:print('IMPORT FAILED:',exc);raise SystemExit(2)
