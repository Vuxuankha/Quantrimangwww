"""Select an existing data root explicitly; do not copy, reset or replace the DB/key."""
from pathlib import Path
import json
import sqlite3
import sys
ROOT=Path(__file__).resolve().parent

def main():
    if len(sys.argv)>1: value=sys.argv[1]
    else:
        import tkinter as tk
        from tkinter import filedialog
        top=tk.Tk();top.withdraw()
        value=filedialog.askdirectory(title='Choose existing desktop folder (contains database)')
        top.destroy()
    if not value:return
    selected=Path(value).resolve()
    if selected.name=='database' and (selected/'network_automation.db').is_file():selected=selected.parent
    db=selected/'database'/'network_automation.db'
    if not db.is_file():raise ValueError('Selected folder does not contain database/network_automation.db')
    with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True) as c:
        tables={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'devices','network_devices'}&tables:raise ValueError('Unexpected database')
        if c.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise ValueError('Database integrity check failed')
        counts={t:c.execute('SELECT COUNT(*) FROM '+t).fetchone()[0] for t in ('devices','network_devices','app_users') if t in tables}
    temp=ROOT/'data_location.json.tmp';temp.write_text(json.dumps({'data_dir':str(selected)},indent=2),encoding='utf-8');temp.replace(ROOT/'data_location.json')
    print('Selected:',db,'\nCounts:',counts,'\nOriginal data/key unchanged. Start with START_WEB.bat.')
if __name__=='__main__':
    try:main()
    except Exception as e:print('CONFIGURATION FAILED:',e);sys.exit(1)
