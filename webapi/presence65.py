"""Presence reliability helpers for UI 6.6.0.

This module intentionally uses only the Python standard library so its core
behaviour can be regression-tested even before optional SSH/SNMP dependencies
are installed.
"""
from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone


def batches(items, size=128):
    """Yield every item exactly once in bounded batches."""
    size=max(1, int(size or 1))
    seq=list(items or [])
    for start in range(0, len(seq), size):
        yield seq[start:start+size]


def summary(rows):
    rows=list(rows or [])
    online=sum(str(r.get('status') or '').lower()=='online' for r in rows)
    offline=sum(str(r.get('status') or '').lower()=='offline' for r in rows)
    unknown=sum(str(r.get('status') or '').lower()=='unknown' for r in rows)
    return {'count':len(rows),'online':online,'offline':offline,'unknown':unknown}


def normalize_ip(value):
    return str(value or '').strip()


def merge_targets(managed, recent_discovered, live_rows):
    """Create one canonical presence target set keyed by IP.

    Precedence: managed inventory > current live discovery > historical
    discovered target. Current live evidence enriches an existing managed row.
    """
    targets={}
    for d in recent_discovered or []:
        ip=normalize_ip(d.get('ip') or d.get('ip_address'))
        if not ip: continue
        targets[ip]={**d,'ip':ip,'_origin':'discovered'}
    for d in live_rows or []:
        ip=normalize_ip(d.get('ip') or d.get('ip_address'))
        if not ip: continue
        base=targets.get(ip,{})
        targets[ip]={**base,**d,'ip':ip,'_origin':base.get('_origin') or 'discovered','_live':True}
    for d in managed or []:
        ip=normalize_ip(d.get('ip') or d.get('ip_address'))
        if not ip: continue
        base=targets.get(ip,{})
        targets[ip]={**base,**d,'ip':ip,'_origin':'managed','_live':bool(base.get('_live'))}
    return list(targets.values())



def _presence_tables(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS web_presence_state64(
      ip TEXT PRIMARY KEY, hostname TEXT, mac TEXT, status TEXT NOT NULL DEFAULT 'Unknown',
      source TEXT, last_seen_at TEXT, offline_since TEXT, consecutive_misses INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL, origin TEXT NOT NULL DEFAULT 'managed', device_id INTEGER
    );
    CREATE TABLE IF NOT EXISTS web_presence_events64(
      id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, hostname TEXT, mac TEXT,
      old_status TEXT, new_status TEXT NOT NULL, source TEXT, observed_at TEXT NOT NULL
    );
    """)


def delete_managed_device_atomic(conn, device_id, observed_at=None):
    """Delete inventory row + current Presence in the SAME SQLite transaction."""
    _presence_tables(conn)
    row=conn.execute('SELECT * FROM devices WHERE id=?',(int(device_id),)).fetchone()
    if row is None:
        return {'success':False,'not_found':True,'message':'Không tìm thấy thiết bị.'}
    data=dict(row)
    ip=normalize_ip(data.get('ip') or data.get('ip_address') or data.get('ip_addr') or data.get('address'))
    hostname=str(data.get('hostname') or data.get('name') or '').strip()
    mac=str(data.get('mac') or data.get('mac_address') or data.get('mac_addr') or '').strip()
    observed_at=observed_at or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    prev=conn.execute('SELECT * FROM web_presence_state64 WHERE ip=?',(ip,)).fetchone() if ip else None
    old_status=''
    if prev is not None:
        try:
            old_status=str(prev['status'] or '')
        except Exception:
            old_status=''
    cur=conn.execute('DELETE FROM devices WHERE id=?',(int(device_id),))
    if int(cur.rowcount or 0) != 1:
        raise RuntimeError('DEVICE_DELETE_ROWCOUNT_MISMATCH')
    if ip:
        conn.execute('DELETE FROM web_presence_state64 WHERE ip=?',(ip,))
        conn.execute('INSERT INTO web_presence_events64(ip,hostname,mac,old_status,new_status,source,observed_at) VALUES(?,?,?,?,?,?,?)',
                     (ip,hostname,mac,old_status,'Deleted','DEVICE_DELETE',observed_at))
    return {'success':True,'message':'Xóa thiết bị thành công.','device_id':int(device_id),'ip':ip}

def cleanup_deleted_presence(conn, ip, hostname='', mac='', observed_at=None):
    """Remove current presence for a deleted managed device, keep an audit event."""
    ip=normalize_ip(ip)
    if not ip:
        return 0
    observed_at=observed_at or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    prev=conn.execute('SELECT * FROM web_presence_state64 WHERE ip=?',(ip,)).fetchone()
    old_status=''
    if prev is not None:
        try: old_status=str(prev['status'] or '')
        except Exception:
            try: old_status=str(prev[3] or '')
            except Exception: old_status=''
    if old_status:
        conn.execute('''INSERT INTO web_presence_events64(ip,hostname,mac,old_status,new_status,source,observed_at)
                        VALUES(?,?,?,?,?,?,?)''',(ip,hostname or '',mac or '',old_status,'Deleted','DEVICE_DELETE',observed_at))
    cur=conn.execute('DELETE FROM web_presence_state64 WHERE ip=?',(ip,))
    return int(cur.rowcount or 0)
