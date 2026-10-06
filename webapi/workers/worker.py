from __future__ import annotations
import json, os, time
from modules.enterprise_security import sync_registered_assets, calculate_risk

def run():
    try: import redis
    except ImportError: raise SystemExit('Install redis package first')
    r=redis.Redis.from_url(os.getenv('NA_REDIS_URL','redis://127.0.0.1:6379/0'),decode_responses=True)
    while True:
        item=r.blpop('networkautomation:jobs',timeout=5)
        if not item: continue
        job=json.loads(item[1]); typ=job.get('type'); payload=job.get('payload') or {}
        try:
            if typ=='SYNC_ASSETS': result={'synced':sync_registered_assets()}
            elif typ=='RECALC_RISK': result=calculate_risk(payload['asset_ip'])
            elif typ=='GENERATE_REPORT': result={'status':'deferred','note':'Report generation worker hook ready'}
            else: result={'error':'unknown_job'}
        except Exception as exc: result={'error':str(exc)}
        r.setex(f"networkautomation:job:{job['id']}",3600,json.dumps(result,default=str))

if __name__=='__main__': run()
