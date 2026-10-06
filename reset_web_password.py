"""Offline owner recovery. No default password; backs up before changing one admin row."""
from getpass import getpass
import secrets
import sys
from run_web import resolve_data
import os

def main():
    root=resolve_data();os.environ['NETWORK_AUTOMATION_DATA_DIR']=str(root)
    from webapi.runtime37 import DataLock,sqlite_snapshot,connection
    from modules.nms_v5 import ensure_v5_tables,_hash_password,_now
    lock=DataLock(root/'database'/'.web37.lock');lock.acquire()
    try:
        backup=sqlite_snapshot(root/'database'/'network_automation.db',root/'database'/'web_preupgrade_backups'/('password_'+secrets.token_hex(8)+'.db'))
        ensure_v5_tables()
        with connection() as c:rows=c.execute('SELECT id,username,role,enabled FROM app_users ORDER BY id').fetchall()
        print('Data:',root,'\nBackup:',backup)
        for row in rows: print(row['username'],row['role'],bool(row['enabled']))
        username=input('Admin username to recover (or first admin for empty DB): ').strip()
        chosen=next((r for r in rows if r['username']==username),None)
        if rows and (not chosen or chosen['role']!='Admin'):raise ValueError('Choose an EXISTING Admin. This tool does not elevate other roles.')
        if input('Type RESET to confirm ownership and password replacement: ')!='RESET':return
        p=getpass('New password (minimum 12 characters): ');again=getpass('Confirm: ')
        if p!=again or not 12<=len(p)<=256:raise ValueError('Passwords must match and have 12-256 characters')
        from modules import accounts
        accounts._validate(username,'Admin',p)
        with connection() as c:
            if chosen:c.execute("UPDATE app_users SET password_hash=?,enabled=1,updated_at=? WHERE id=?",(_hash_password(p),_now(),chosen['id']))
            else:c.execute('INSERT INTO app_users(username,password_hash,role,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)',(username,_hash_password(p),'Admin',1,_now(),_now()))
            # Existing sessions are invalidated by password fingerprint at the next request.
        print('Password updated. No device, IP or telemetry records were changed.')
    finally:lock.release()
if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt) as e:print('Recovery stopped:',e);sys.exit(1)
