from __future__ import annotations
import json, os, uuid

def _redis():
    try:
        import redis
        return redis.Redis.from_url(os.getenv('NA_REDIS_URL','redis://127.0.0.1:6379/0'),decode_responses=True,socket_connect_timeout=2)
    except Exception:
        return None

def enqueue(job_type:str,payload:dict|None=None)->dict:
    if job_type not in {'SYNC_ASSETS','RECALC_RISK','GENERATE_REPORT'}:
        raise ValueError('Unsupported background job')
    job={'id':uuid.uuid4().hex,'type':job_type,'payload':payload or {}}
    r=_redis()
    if not r: return {'queued':False,'reason':'redis_unavailable','job':job}
    r.rpush('networkautomation:jobs',json.dumps(job,separators=(',',':')))
    return {'queued':True,'job':job}
