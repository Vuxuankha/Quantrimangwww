"""Bounded, credential-free exports and protected downloads; no arbitrary path download."""
from __future__ import annotations
from pathlib import Path
import re
import secrets
from webapi.runtime37 import connection,utcnow,sqlite_snapshot

def ensure_registry():
    with connection() as c:
        c.execute('CREATE TABLE IF NOT EXISTS web_downloads37(token TEXT PRIMARY KEY,name TEXT,path TEXT,owner_id INTEGER,kind TEXT,created_at TEXT)')

def register(path,owner_id,kind):
    ensure_registry(); token=secrets.token_urlsafe(24)
    with connection() as c:
        c.execute('INSERT INTO web_downloads37 VALUES(?,?,?,?,?,?)',(token,path.name,str(path.resolve()),owner_id,kind,utcnow()))
    return {'success':True,'name':path.name,'download_url':'/api/downloads/'+token}

def backup_db(owner_id):
    from database.db import DB_PATH
    from app_runtime import BACKUP_DIR
    path=Path(BACKUP_DIR)/('web_db_'+secrets.token_hex(12)+'.db')
    sqlite_snapshot(Path(DB_PATH),path)
    return register(path,owner_id,'database')

def export_report(owner_id):
    from openpyxl import Workbook
    from openpyxl.styles import Font,PatternFill,Alignment
    from openpyxl.utils import get_column_letter
    from app_runtime import REPORT_DIR
    from webapi.data37 import merged_devices
    wb=Workbook(); meta=wb.active; meta.title='Readme'
    meta.append(['NetworkAutomation operational export',utcnow()]);meta.append(['Source','Selected desktop database / Web API']);meta.append(['Scope','Maximum 5000 latest rows per sheet; no credentials/configuration content']);meta.append(['Meaning','Unknown/Stale is not Offline; status is time-bound']);
    tables={'Devices':merged_devices()}
    with connection() as c:
        for tab,table,fields in [
            ('Alerts','alerts',['id','ip','ip_address','severity','message','status','resolved','created_at']),
            ('Server targets','server_monitor_targets',['id','name','host','port','protocol','enabled']),
            ('Ping history','ping_results',['ip','ip_address','status','response','response_ms','ping_time']),
            ('Health history','health_samples',['host','cpu','memory','latency_ms','packet_loss','created_at'])]:
            cols={r['name'] for r in c.execute(f'PRAGMA table_info("{table}")')}; use=[f for f in fields if f in cols]
            if use: tables[tab]=[dict(r) for r in c.execute('SELECT '+','.join(use)+f' FROM "{table}" ORDER BY rowid DESC LIMIT 5000')]
    for name,rows in tables.items():
        ws=wb.create_sheet(name)
        if not rows: ws.append(['No data']); continue
        cols=list(rows[0]);ws.append(cols)
        for row in rows:
            values=[]
            for key in cols:
                v=row.get(key)
                if isinstance(v,str):
                    v=re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]','',v)[:32000]
                    if v.lstrip().startswith(('=','+','-','@')): v="'"+v
                values.append(v)
            ws.append(values)
        ws.freeze_panes='A2';ws.auto_filter.ref=ws.dimensions
    for ws in wb:
        ws.sheet_view.showGridLines=False
        for cell in ws[1]: cell.font=Font(bold=True,color='FFFFFF');cell.fill=PatternFill('solid',fgColor='183B56')
        ws.row_dimensions[1].height=26
        for col in range(1,ws.max_column+1): ws.column_dimensions[get_column_letter(col)].width=22
        for row in ws.iter_rows(min_row=2):
            for cell in row: cell.font=Font(color='176B45');cell.alignment=Alignment(vertical='top',wrap_text=True)
    out=Path(REPORT_DIR)/('web_report_'+secrets.token_hex(12)+'.xlsx');out.parent.mkdir(parents=True,exist_ok=True);wb.save(out)
    return register(out,owner_id,'report')
