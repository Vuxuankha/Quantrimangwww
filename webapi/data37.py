"""Display observations, not invented live state. Device IDs and managed IDs are separate."""
from __future__ import annotations
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import ipaddress
import math
import os
from webapi.runtime37 import connection

def columns(c,table):
    return {r['name'] for r in c.execute(f'PRAGMA table_info("{table}")')}

def stamp(value):
    if not value: return None
    try:
        d=datetime.fromisoformat(str(value).replace('Z','+00:00'))
        if d.tzinfo is None: d=d.replace(tzinfo=ZoneInfo(os.environ.get('NA_TIMEZONE','Asia/Ho_Chi_Minh')))
        return d.astimezone(timezone.utc)
    except (ValueError,TypeError): return None

def freshness(value,now=None):
    d=stamp(value); now=now or datetime.now(timezone.utc)
    if not d: return 'UNKNOWN'
    age=(now-d).total_seconds()
    if age < -30: return 'CLOCK_SKEW'
    return 'FRESH' if age<=int(os.environ.get('NA_TELEMETRY_TTL','180')) else 'STALE'

def ip_value(row):
    return str(row.get('ip') or row.get('ip_address') or row.get('host') or '').strip()

def normalized_status(value):
    s=str(value or '').lower()
    return 'Online' if s in ('up','online','ok') else 'Offline' if s in ('down','offline','unreachable') else 'Unknown'

def table_rows(c,table):
    if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone(): return []
    return [dict(r) for r in c.execute(f'SELECT * FROM "{table}"')]

def latest_by_host(c,table,time_fields):
    out={}
    # Tables are internal constants, never request identifiers. Choose timestamp first, not insertion ID.
    for row in table_rows(c,table):
        host=ip_value(row); ts=next((row.get(k) for k in time_fields if row.get(k)),None)
        key=(stamp(ts) or datetime.min.replace(tzinfo=timezone.utc),row.get('id',0))
        if host and (host not in out or key>out[host][0]): out[host]=(key,row,ts)
    return {h:(r,t) for h,(_,r,t) in out.items()}

def merged_devices():
    with connection() as c:
        base=table_rows(c,'devices'); managed=table_rows(c,'network_devices')
        managed_by_ip={}
        for m in managed: managed_by_ip.setdefault(ip_value(m),[]).append(m)
        hp=latest_by_host(c,'health_samples',('created_at',)); pp=latest_by_host(c,'ping_results',('ping_time','created_at'))
        lp=latest_by_host(c,'web_lan_probe42',('observed_at',)) if columns(c,'web_lan_probe42') else {}
        # 6.7.0: current Presence is the canonical live-state source. Legacy ping/health
        # remains useful as fallback/evidence only when a presence row does not exist.
        presence={}
        if columns(c,'web_presence_state64'):
            for row in table_rows(c,'web_presence_state64'):
                ip=ip_value(row)
                if ip: presence[ip]=row
    out=[]; now=datetime.now(timezone.utc)
    for d in base:
        ip=ip_value(d); h,ht=hp.get(ip,({},None)); p,pt=pp.get(ip,({},None)); matches=managed_by_ip.get(ip,[])
        observations=[]
        if pt: observations.append((stamp(pt) or datetime.min.replace(tzinfo=timezone.utc),'ICMP',pt,normalized_status(p.get('status'))))
        if ht and h.get('packet_loss') is not None:
            try:
                loss=float(h['packet_loss']); hs=('Offline' if loss>=100 else 'Online') if math.isfinite(loss) and 0<=loss<=100 else 'Unknown'
            except (TypeError,ValueError): hs='Unknown'
            observations.append((stamp(ht) or datetime.min.replace(tzinfo=timezone.utc),'HEALTH_ICMP',ht,hs))
        observed=max(observations,key=lambda r:r[0]) if observations else None
        state=freshness(observed[2],now) if observed else 'UNKNOWN'
        status=observed[3] if observed and state=='FRESH' else 'Unknown'
        path,path_at=lp.get(ip,({},None)); path_fresh=freshness(path_at,now)=='FRESH'
        path_state=str(path.get('path_state') or '') if path_fresh else ''
        status_reason=''
        # A failed ICMP observation is not enough to label a device Offline when the
        # Windows host cannot verify the network path to that private subnet.
        if path_fresh and path_state=='REACHABLE' and str(path.get('ping_state') or '')=='Online':
            status='Online'; state='FRESH'; status_reason='LAN probe verified reachability'
        elif path_fresh and path_state in ('NO_ROUTE','PATH_UNVERIFIED') and status!='Online':
            status='Unknown'; state='PATH_ISSUE'; status_reason=str(path.get('detail') or path_state)
        elif path_fresh and path_state=='NO_ICMP_REPLY' and status!='Online':
            status='Unknown'; state='NO_REPLY'; status_reason=str(path.get('detail') or 'No ICMP reply')
        original=d.get('status')
        pr=presence.get(ip)
        if pr:
            pstatus=normalized_status(pr.get('status'))
            # web_presence_state64 is current source of truth for managed device state.
            # Preserve legacy evidence in reported_status/last_ping fields for diagnostics.
            status=pstatus
            state='FRESH' if freshness(pr.get('updated_at'),now)=='FRESH' else 'STALE'
            status_reason='Presence Engine'
            observation_source=str(pr.get('source') or 'PRESENCE')
            observed_at=pr.get('updated_at') or pr.get('last_seen_at')
        else:
            observation_source=('LAN_PATH' if path_fresh and path_state else (observed[1] if observed else 'INVENTORY'))
            observed_at=(path_at if path_fresh and path_state else (observed[2] if observed else None))
        d.update(ip=ip,mac=d.get('mac') or d.get('mac_address') or '',reported_status=original,
            managed_id=matches[0]['id'] if len(matches)==1 else None,identity_conflict=len(matches)>1,
            observation_source=observation_source,observed_at=observed_at,
            data_state=state,status=status,status_reason=status_reason,path_state=path_state,path_observed_at=path_at if path_fresh else None,
            last_seen_at=(pr.get('last_seen_at') if pr else d.get('last_seen')),offline_since=(pr.get('offline_since') if pr else None),
            consecutive_misses=(int(pr.get('consecutive_misses') or 0) if pr else None),presence_source=(pr.get('source') if pr else None),
            last_ping_at=pt,ping_ms=p.get('response_ms',p.get('response')),last_health_at=ht,
            latency_ms=h.get('latency_ms'),packet_loss=h.get('packet_loss'),cpu=h.get('cpu'),ram=h.get('memory',h.get('ram')),
            health_fresh=freshness(ht,now)=='FRESH')
        out.append(d)
    return out

def write_ping(result):
    address=str(ipaddress.ip_address(result['ip']))
    now=datetime.now(ZoneInfo(os.environ.get('NA_TIMEZONE','Asia/Ho_Chi_Minh'))).strftime('%Y-%m-%d %H:%M:%S')
    status=normalized_status(result.get('status'))
    latency=result.get('response') if status=='Online' else None
    with connection() as c:
        pc=columns(c,'ping_results'); fields=[]; values=[]
        for k,v in [('ip',address),('ip_address',address),('status',status),('response_ms',latency),('response',latency),('ping_time',now),('created_at',now)]:
            if k in pc: fields.append(k); values.append(v)
        c.execute('INSERT INTO ping_results('+','.join(fields)+') VALUES('+','.join('?' for _ in fields)+')',values)
        # Match the address, NEVER assume devices.id equals network_devices.id.
        for table in ('devices','network_devices'):
            cols=columns(c,table)
            ips=[x for x in ('ip','ip_address') if x in cols]
            if not ips: continue
            sets=['status=?']; vals=[status]
            if status=='Online' and 'last_seen' in cols: sets.append('last_seen=?'); vals.append(now)
            if 'duration' in cols: sets.append('duration=?'); vals.append(latency)
            if 'updated_at' in cols: sets.append('updated_at=?'); vals.append(now)
            c.execute(f'UPDATE {table} SET '+','.join(sets)+' WHERE '+' OR '.join(f'{x}=?' for x in ips),vals+[address]*len(ips))
    return result

def icmp_probe(ip, timeout=1000):
    from modules.icmp_probe import icmp_ping
    return icmp_ping(ip, timeout)

def diagnostics():
    from database.db import DB_PATH
    from app_runtime import DATABASE_DIR
    with connection() as c:
        result={}
        for t in ['devices','network_devices','ip_mac_inventory','autoip_targets','autoip_runs','autoip_steps','ping_results','health_samples','server_monitor_targets','server_monitor_results','alerts','app_users','credentials','snmp_profiles','web_scan_results']:
            cols=columns(c,t)
            result[t]={'exists':bool(cols),'rows':c.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0] if cols else None,'columns':sorted(cols)}
        quick=c.execute('PRAGMA quick_check').fetchone()[0]
        journal=c.execute('PRAGMA journal_mode').fetchone()[0]
        user_version=c.execute('PRAGMA user_version').fetchone()[0]
        latest_health=c.execute('SELECT MAX(created_at) FROM health_samples').fetchone()[0] if columns(c,'health_samples') else None
        latest_ping=None
        if columns(c,'ping_results'):
            pc=columns(c,'ping_results'); tf='ping_time' if 'ping_time' in pc else ('created_at' if 'created_at' in pc else None)
            if tf: latest_ping=c.execute(f'SELECT MAX("{tf}") FROM ping_results').fetchone()[0]
    d=merged_devices()
    return {'database':str(DB_PATH),'database_size_bytes':DB_PATH.stat().st_size if DB_PATH.exists() else 0,
        'database_quick_check':quick,'journal_mode':journal,'schema_version':user_version,
        'credential_key_present':(DATABASE_DIR/'.credential.key').is_file(),
        'timezone':os.environ.get('NA_TIMEZONE','Asia/Ho_Chi_Minh'),'ttl_seconds':int(os.environ.get('NA_TELEMETRY_TTL','180')),
        'latest_health_at':latest_health,'latest_ping_at':latest_ping,
        'tables':result,'identity_conflicts':sum(x['identity_conflict'] for x in d),'unmapped_devices':sum(x['managed_id'] is None for x in d),
        'fresh':sum(x['data_state']=='FRESH' for x in d),'stale':sum(x['data_state']=='STALE' for x in d)}
