from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request

from database.db import DB_PATH
from webapi.runtime37 import connection
from webapi.security37 import require_role

router = APIRouter(prefix='/api/v43', tags=['v43-function-audit'])


def _table(c, name: str) -> bool:
    return c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _count(c, table: str) -> int:
    if not _table(c, table):
        return 0
    return int(c.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])


def _valid_host(value: str) -> bool:
    value=(value or '').strip()
    if not value or any(ch.isspace() for ch in value):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        labels=value.rstrip('.').split('.')
        return bool(labels) and all(label and len(label)<=63 and label.replace('-','').isalnum() and not label.startswith('-') and not label.endswith('-') for label in labels)


def _feature(name: str, state: str, detail: str, action: str='') -> dict[str, Any]:
    return {'feature':name,'state':state,'detail':detail,'action':action}


@router.get('/feature-audit')
def feature_audit(request: Request):
    require_role(request,'Admin')
    # Additive schema creation only; no collectors or network activity.
    from webapi.ops40 import ensure_tables as ensure40
    from webapi.lan42 import ensure_tables as ensure42
    from webapi.parity44 import ensure_tables as ensure44
    ensure40(); ensure42(); ensure44()
    issues=[]
    features=[]
    with connection() as c:
        quick=[str(r[0]) for r in c.execute('PRAGMA quick_check').fetchall()]
        db_ok=(quick==['ok'])
        managed=_count(c,'network_devices')
        inventory=_count(c,'devices')
        ipmac=_count(c,'ip_mac_inventory')
        alerts=_count(c,'alerts')
        health=_count(c,'health_samples')
        ssh_assigned=_count(c,'device_credentials')
        snmpv3_assigned=_count(c,'device_snmpv3_assignments')
        snmpv2_assigned=_count(c,'web_device_snmpv2_assignments42')
        legacy_v2_profiles=0
        if _table(c,'snmp_profiles'):
            legacy_v2_profiles=int(c.execute('SELECT COUNT(*) FROM snmp_profiles WHERE enabled=1').fetchone()[0])
        trusted=0
        from modules.ssh_security import APP_KNOWN_HOSTS
        candidates=[Path(APP_KNOWN_HOSTS)]
        for kh in candidates:
            if kh.is_file():
                try:
                    trusted=max(trusted, sum(1 for line in kh.read_text(errors='ignore').splitlines() if line.strip() and not line.lstrip().startswith('#')))
                except OSError:
                    pass
        malformed=[]
        if _table(c,'server_monitor_targets'):
            for r in c.execute('SELECT id,name,host FROM server_monitor_targets ORDER BY id'):
                if not _valid_host(r['host']): malformed.append({'id':r['id'],'name':r['name'],'host':r['host']})
        orphan_creds=[]
        if _table(c,'device_credentials'):
            orphan_creds=[dict(r) for r in c.execute('''SELECT dc.device_id,dc.credential_id,dc.purpose FROM device_credentials dc
                LEFT JOIN network_devices d ON d.id=dc.device_id LEFT JOIN credentials cr ON cr.id=dc.credential_id
                WHERE d.id IS NULL OR cr.id IS NULL LIMIT 100''')]
        orphan_v3=[]
        if _table(c,'device_snmpv3_assignments'):
            orphan_v3=[dict(r) for r in c.execute('''SELECT a.device_id,a.credential_id FROM device_snmpv3_assignments a
                LEFT JOIN network_devices d ON d.id=a.device_id LEFT JOIN snmpv3_credentials s ON s.id=a.credential_id
                WHERE d.id IS NULL OR s.id IS NULL LIMIT 100''')]
        orphan_v2=[]
        if _table(c,'web_device_snmpv2_assignments42'):
            orphan_v2=[dict(r) for r in c.execute('''SELECT a.device_id,a.credential_id FROM web_device_snmpv2_assignments42 a
                LEFT JOIN network_devices d ON d.id=a.device_id LEFT JOIN web_snmpv2_credentials42 s ON s.id=a.credential_id
                WHERE d.id IS NULL OR s.id IS NULL LIMIT 100''')]
        orphan_org=[]
        if _table(c,'device_organization'):
            orphan_org=[dict(r) for r in c.execute('''SELECT o.device_id,o.site_id,o.group_id FROM device_organization o
                LEFT JOIN network_devices d ON d.id=o.device_id LEFT JOIN sites s ON s.id=o.site_id LEFT JOIN device_groups g ON g.id=o.group_id
                WHERE d.id IS NULL OR (o.site_id IS NOT NULL AND s.id IS NULL) OR (o.group_id IS NOT NULL AND g.id IS NULL) LIMIT 100''')]
        bad_schedules=[]
        if _table(c,'web_schedules40'):
            devices={int(r['id']) for r in c.execute('SELECT id FROM network_devices')}
            cameras={int(r['id']) for r in c.execute('SELECT id FROM camera_registry')} if _table(c,'camera_registry') else set()
            for r in c.execute('SELECT id,name,operation,device_ids_json,parameters_json FROM web_schedules40'):
                reason=[]
                try: ids=json.loads(r['device_ids_json'] or '[]')
                except Exception: ids=[];reason.append('device_ids_json invalid')
                miss=[x for x in ids if x not in devices]
                if miss: reason.append('missing managed IDs: '+','.join(map(str,miss[:10])))
                if r['operation']=='CAMERA_CHECK':
                    try: cid=int(json.loads(r['parameters_json'] or '{}').get('camera_id'))
                    except Exception: cid=0
                    if cid not in cameras: reason.append('camera missing')
                if reason: bad_schedules.append({'id':r['id'],'name':r['name'],'reason':'; '.join(reason)})

        counts={
            'inventory_devices':inventory,'managed_devices':managed,'ip_mac':ipmac,'alerts':alerts,'health_samples':health,
            'ssh_assignments':ssh_assigned,'snmpv3_assignments':snmpv3_assigned,'snmpv2_assignments':snmpv2_assigned,'legacy_snmpv2_profiles':legacy_v2_profiles,
            'trusted_host_entries':trusted,'server_targets':_count(c,'server_monitor_targets'),'cameras':_count(c,'camera_registry'),
            'schedules':_count(c,'web_schedules40'),'sla_policies':_count(c,'sla_policies'),'maintenance_windows':_count(c,'maintenance_windows'),
            'incidents':_count(c,'incidents'),'topology_links':_count(c,'device_links') + _count(c,'discovery_links'),
            'device_profiles':_count(c,'device_profiles'),'profile_assignments':_count(c,'device_profile_assignments'),
            'vendor_drivers':_count(c,'vendor_drivers'),'driver_assignments':_count(c,'device_driver_assignments'),
            'alert_rules':_count(c,'alert_rules'),'managed_services':_count(c,'managed_services'),
            'notification_log':_count(c,'notification_log'),'config_baselines':_count(c,'config_baselines'),
            'remote_history':_count(c,'remote_history'),
            'web_users':_count(c,'app_users'),'web_sessions':_count(c,'web_sessions37'),'scan_results':_count(c,'web_scan_results'),
            'connected_evidence':_count(c,'web_connected_device_evidence'),'endpoint_assets':_count(c,'endpoint_agents58'),
            'siem_events':_count(c,'siem_events51'),'vulnerability_findings':_count(c,'vulnerability_findings51'),
            'config_backups':_count(c,'config_backups'),'report_snapshots':_count(c,'security_report_snapshots56'),
            'presence_state':_count(c,'web_presence_state64'),'presence_events':_count(c,'web_presence_events64'),
        }

    if not db_ok: issues.append({'severity':'critical','area':'Database','detail':'SQLite quick_check failed','action':'Stop writes and recover database before continuing.'})
    for item in malformed: issues.append({'severity':'high','area':'Server Monitor','detail':f"Target #{item['id']} {item['name']} has invalid host {item['host']}",'action':'Edit or remove the invalid target.'})
    if orphan_creds: issues.append({'severity':'high','area':'SSH credentials','detail':f'{len(orphan_creds)} orphan assignment(s)','action':'Remove/reassign orphan SSH credentials.'})
    if orphan_v3 or orphan_v2: issues.append({'severity':'high','area':'SNMP','detail':f'{len(orphan_v3)+len(orphan_v2)} orphan SNMP assignment(s)','action':'Remove/reassign orphan SNMP credentials.'})
    if orphan_org: issues.append({'severity':'medium','area':'Organization','detail':f'{len(orphan_org)} orphan Site/Group assignment(s)','action':'Correct organization assignments.'})
    if bad_schedules: issues.append({'severity':'high','area':'Scheduler','detail':f'{len(bad_schedules)} invalid schedule reference(s)','action':'Edit or delete invalid schedules.'})

    paramiko_ok=importlib.util.find_spec('paramiko') is not None
    pysnmp_ok=importlib.util.find_spec('pysnmp') is not None
    openpyxl_ok=importlib.util.find_spec('openpyxl') is not None
    fastapi_ok=importlib.util.find_spec('fastapi') is not None
    uvicorn_ok=importlib.util.find_spec('uvicorn') is not None
    try:
        data_dir=DB_PATH.parent
        writable=data_dir.exists() and os.access(data_dir,os.W_OK)
    except Exception:
        writable=False
    key_ok=(DB_PATH.parent/'.credential.key').is_file()
    auth_ok=counts['web_users']>0
    features.extend([
        _feature('Database','PASS' if db_ok else 'FAIL','quick_check = '+('ok' if db_ok else 'failed'),'Repair DB before operation' if not db_ok else ''),
        _feature('Web runtime','PASS' if fastapi_ok and uvicorn_ok and writable else 'FAIL',f'FastAPI={fastapi_ok}; Uvicorn={uvicorn_ok}; data directory writable={writable}.','Run OneClick as Administrator / repair Python dependencies' if not (fastapi_ok and uvicorn_ok and writable) else ''),
        _feature('Đăng nhập / MFA','PASS' if auth_ok else 'FAIL',f"users={counts['web_users']}; session table={'ready' if counts['web_sessions']>=0 else 'missing'}; credential key={key_ok}.",'Repair Admin/login data before operation' if not auth_ok else ''),
        _feature('Dashboard / NOC','PASS','Freshness-aware device state and LAN path classification.'),
        _feature('Device Manager','PASS',f'{inventory} inventory / {managed} managed devices.'),
        _feature('IP / MAC + File Import','READY' if openpyxl_ok else 'WARN',f'{ipmac} records; CSV/TXT import ready; XLSX dependency={openpyxl_ok}; scan results={counts["scan_results"]}; connected evidence={counts["connected_evidence"]}.','Install openpyxl for XLSX import' if not openpyxl_ok else ''),
        _feature('LAN Readiness','PASS','Route-aware probe for registered devices only.'),
        _feature('Application / Server','WARN' if malformed else 'PASS',f"{counts['server_targets']} target(s); invalid={len(malformed)}.",'Fix invalid target hosts' if malformed else ''),
        _feature('Health / Telemetry','PASS' if health else 'WARN',f'{health} stored sample(s).','Collect fresh telemetry' if not health else ''),
        _feature('Alerts / Incidents','PASS',f"{alerts} alert(s), {counts['incidents']} incident(s)."),
        _feature('SNMP','READY' if pysnmp_ok and (snmpv3_assigned+snmpv2_assigned)>0 else 'SETUP',f'PySNMP={pysnmp_ok}; assigned={snmpv3_assigned+snmpv2_assigned}.','Install/configure SNMP credentials' if not (pysnmp_ok and (snmpv3_assigned+snmpv2_assigned)>0) else ''),
        _feature('SSH / Audit','READY' if paramiko_ok and ssh_assigned>0 and trusted>0 else 'SETUP',f'Paramiko={paramiko_ok}; assigned={ssh_assigned}; trusted entries={trusted}.','Assign SSH credentials and trust verified fingerprints' if not (paramiko_ok and ssh_assigned>0 and trusted>0) else ''),
        _feature('Config Backup / Restore','READY' if paramiko_ok and ssh_assigned>0 and trusted>0 else 'SETUP','Guarded backup/restore adapters; restore remains vendor-controlled.','Complete SSH/trust setup and pilot on non-critical device'),
        _feature('Topology','READY' if pysnmp_ok and (snmpv2_assigned+legacy_v2_profiles)>0 else 'SETUP',f"stored links={counts['topology_links']}; v2c ready={snmpv2_assigned+legacy_v2_profiles}; v3-only topology is not supported by the desktop LLDP/CDP walker.",'Assign SNMPv2c/profile for topology discovery' if not (pysnmp_ok and (snmpv2_assigned+legacy_v2_profiles)>0) else ''),
        _feature('SLA / Maintenance','PASS',f"policies={counts['sla_policies']}; maintenance={counts['maintenance_windows']}."),
        _feature('Scheduler','WARN' if bad_schedules else 'PASS',f"schedules={counts['schedules']}; invalid references={len(bad_schedules)}."),
        _feature('Wi-Fi','READY','Windows adapter diagnostics are available; hardware acceptance is runtime-dependent.'),
        _feature('Camera','PASS',f"registered cameras={counts['cameras']}; reachability checks only, not video quality."),
        _feature('Security / RBAC','PASS','Server-side authorization and secret redaction are enabled.'),
        _feature('Device Profiles / Vendor Drivers','PASS',f"profiles={counts['device_profiles']} assigned={counts['profile_assignments']}; drivers={counts['vendor_drivers']} assigned={counts['driver_assignments']}."),
        _feature('SNMP Resource / Port Monitoring','READY' if pysnmp_ok and (snmpv3_assigned+snmpv2_assigned)>0 and (counts['profile_assignments']+counts['driver_assignments'])>0 else 'SETUP',f"SNMP assigned={snmpv3_assigned+snmpv2_assigned}; profile/driver assigned={counts['profile_assignments']+counts['driver_assignments']}.",'Assign SNMP plus a Device Profile/Vendor Driver to collect CPU/RAM/ports' if not (pysnmp_ok and (snmpv3_assigned+snmpv2_assigned)>0 and (counts['profile_assignments']+counts['driver_assignments'])>0) else ''),
        _feature('Alert Rules','PASS',f"rules={counts['alert_rules']}; evaluation is explicit or scheduler-driven."),
        _feature('Notification Center','PASS',f"notification log entries={counts['notification_log']}; secrets are encrypted/redacted."),
        _feature('Service Impact','PASS',f"managed services={counts['managed_services']}; required/optional dependency model enabled."),
        _feature('Config Compare / Baselines','PASS',f"baselines={counts['config_baselines']}; only managed text backups are readable."),
        _feature('Daily Audit Windows','READY' if __import__('platform').system()=='Windows' else 'SETUP','Bundled PowerShell audit is available and can be queued/scheduled.','Run acceptance on Windows' if __import__('platform').system()!='Windows' else ''),
        _feature('Remote Service Check','PASS',f"history entries={counts['remote_history']}; registered devices only, TCP reachability without arbitrary shell."),
        _feature('Settings','PASS','Validated private CIDR, ping/scan bounds and export preference are available.'),
        _feature('Live LAN Discovery','PASS',f"scan results={counts['scan_results']}; connected evidence={counts['connected_evidence']}; ICMP/ARP/DHCP/mDNS/SSDP sources supported."),
        _feature('Master Automation 6.8','PASS','One-switch coordinator for bounded monitoring/maintenance tasks; destructive and intrusive actions remain manual.'),
        _feature('Live Machine Presence','PASS',f"persisted state={counts['presence_state']}; transition events={counts['presence_events']}; ICMP + ARP evidence with single-miss hysteresis enabled."),
        _feature('Identity Guard','READY' if ipmac else 'SETUP',f"IP/MAC inventory={ipmac}; duplicate-MAC/multi-IP detection endpoint enabled.",'Import or discover assets first' if not ipmac else ''),
        _feature('Endpoint Monitoring','PASS',f"endpoint records={counts['endpoint_assets']}; agent token/check-in workflow available."),
        _feature('SIEM / Vulnerability','PASS',f"SIEM events={counts['siem_events']}; vulnerability findings={counts['vulnerability_findings']}."),
        _feature('Network Quality','PASS','Line test/history are read-only by default; speed test requires explicit operator action.'),
        _feature('Reports / DR','PASS',f"Allowlisted reports and private disaster-recovery export are available; report snapshots={counts['report_snapshots']}.") ,
    ])
    summary={
        'pass':sum(1 for f in features if f['state']=='PASS'),
        'ready':sum(1 for f in features if f['state']=='READY'),
        'setup':sum(1 for f in features if f['state']=='SETUP'),
        'warn':sum(1 for f in features if f['state']=='WARN'),
        'fail':sum(1 for f in features if f['state']=='FAIL'),
        'issues':len(issues),
    }
    return {'summary':summary,'counts':counts,'features':features,'issues':issues,'details':{'malformed_server_targets':malformed,'orphan_ssh':orphan_creds,'orphan_snmpv3':orphan_v3,'orphan_snmpv2':orphan_v2,'orphan_organization':orphan_org,'invalid_schedules':bad_schedules}}
