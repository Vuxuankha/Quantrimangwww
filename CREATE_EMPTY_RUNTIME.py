"""Explicit first install only. Never overwrite an existing runtime or invent a password."""
from __future__ import annotations
import asyncio
from getpass import getpass
import os
from pathlib import Path
import shutil
import tempfile

ROOT=Path(__file__).resolve().parent

def initialize(destination:Path,username:str,password:str):
    destination=destination.resolve()
    if destination.exists():
        raise ValueError('Runtime already exists. Import/recover it; do not reset existing data.')
    stage=Path(tempfile.mkdtemp(prefix='.new-runtime-',dir=destination.parent))
    try:
        os.environ['NETWORK_AUTOMATION_DATA_DIR']=str(stage)
        os.environ['NA_ALLOW_EMPTY_DB']='1'
        from modules import accounts
        accounts._validate(username,'Admin',password)
        from webapi.main import app
        from webapi.runtime37 import connection,utcnow
        from modules.nms_v5 import _hash_password,_fernet
        async def setup():
            async with app.router.lifespan_context(app):
                with connection() as c:
                    if c.execute('SELECT COUNT(*) FROM app_users').fetchone()[0]:
                        raise ValueError('Expected empty runtime.')
                    c.execute('INSERT INTO app_users(username,password_hash,role,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)',
                              (username,_hash_password(password),'Admin',1,utcnow(),utcnow()))
                _fernet()  # New random key belongs ONLY to this brand-new empty DB.
        asyncio.run(setup())
        with connection() as c:c.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        stage.rename(destination)
    finally:
        if stage.exists():shutil.rmtree(stage)


def main():
    dest=ROOT/'runtime_data'
    if dest.exists():raise ValueError('runtime_data exists. No changes made; use IMPORT_APP_DATA.bat or password recovery.')
    print('New EMPTY installation only. To keep your devices use IMPORT_APP_DATA.bat instead.')
    if input('Type CREATE EMPTY to continue: ')!='CREATE EMPTY':return
    username=input('Admin username: ').strip()
    password=getpass('Admin password (12+ characters): ')
    if getpass('Confirm password: ')!=password:raise ValueError('Passwords do not match.')
    initialize(dest,username,password)
    print('Created empty runtime with your Admin account. Run START_WEB.bat.')

if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt) as exc:
        print('NOT CREATED:',exc);raise SystemExit(1)
