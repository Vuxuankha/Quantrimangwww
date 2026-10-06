from __future__ import annotations
import os
DATABASE_URL=os.getenv('NA_DATABASE_URL','sqlite-legacy')
POSTGRES_ENABLED=DATABASE_URL.startswith('postgresql')

def production_database_status():
    return {'database_url_configured':POSTGRES_ENABLED,'mode':'postgresql' if POSTGRES_ENABLED else 'sqlite-compat','note':'Core legacy NMS remains on SQLite until its repositories are migrated.'}
