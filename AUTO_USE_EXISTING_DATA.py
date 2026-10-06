from __future__ import annotations
import json, os, sqlite3
from pathlib import Path
ROOT=Path(__file__).resolve().parent
CONFIG=ROOT/'data_location.json'

def score(db:Path):
    if not db.exists(): return (0,0)
    try:
        c=sqlite3.connect(db)
        tables=[r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        total=0
        for t in ('devices','network_devices','ip_mac_inventory','network_scans','ping_results','snmp_profiles','health_samples','alerts','app_users'):
            if t in tables:
                try: total+=int(c.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0])
                except Exception: pass
        c.close(); return (total,db.stat().st_size)
    except Exception: return (0,db.stat().st_size if db.exists() else 0)

def main():
    if CONFIG.exists():
        print(f'[DATA] Using configured data path: {CONFIG}')
        return
    current=ROOT/'database'/'network_automation.db'
    candidates=[]
    local=os.environ.get('LOCALAPPDATA') or os.environ.get('APPDATA')
    if local:
        candidates.append(Path(local)/'NetworkAutomation'/'database'/'network_automation.db')
    cur_score=score(current)
    best=None; best_score=cur_score
    for db in candidates:
        sc=score(db)
        if sc>best_score:
            best,best_score=db,sc
    # Only auto-select another data root when it is clearly richer than the local source DB.
    if best and (best_score[0] > cur_score[0] or (cur_score[0]==0 and best_score[1] > max(cur_score[1],65536))):
        root=best.parent.parent
        CONFIG.write_text(json.dumps({'data_dir':str(root.resolve())},ensure_ascii=False,indent=2),encoding='utf-8')
        print(f'[DATA] Selected existing desktop data: {root}')
    else:
        print(f'[DATA] Current source data retained: {current} score={cur_score}')
if __name__=='__main__': main()
