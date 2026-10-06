"""Headless monitoring; does not import main.py or create Tk widgets."""
import json
import logging
import threading
from modules.monitor_extensions import ensure_tables, cameras, check_camera, history, wifi_diagnostics
from database.db import get_connection
from modules.ping_check import ping_host
from app_runtime import data_path, setup_logging
from agent_runtime import AgentLock, Heartbeat


def record_sample(kind,target,status,detail):
    c=get_connection()
    try:
        previous=c.execute('SELECT status FROM extension_history WHERE kind=? AND target=? ORDER BY id DESC LIMIT 1',(kind,target)).fetchone()
    finally:c.close()
    history(kind,target,status,detail)
    if status in ('Offline','Unreachable','Warning','Error') and (previous is None or previous[0]!=status):
        try:
            from modules.advanced_pages import notify_alert
            notify_alert(target, kind+' Offline' if status in ('Offline','Unreachable') else kind+' Warning',
                         detail[:1500],event_key=f'agent|{kind}|{target}|{status}')
        except Exception:logging.exception('Agent notification failed')


def cycle(stop):
    c=get_connection()
    try:
        targets=[dict(r) for r in c.execute('SELECT id,ip FROM network_devices WHERE ip IS NOT NULL AND ip<>\'\'')]
        wifi=c.execute("SELECT value FROM settings WHERE key='agent_wifi_enabled'").fetchone()
    finally:c.close()
    for target in targets:
        if stop.is_set():return
        result=ping_host(target['ip'],1000)
        record_sample('Network',target['ip'],result['status'],json.dumps(result,ensure_ascii=False))
    for camera in cameras():
        if stop.is_set():return
        status,detail=check_camera(camera)
        record_sample('Camera',camera['host'],status,detail)
    if wifi and wifi[0]=='1' and not stop.is_set():
        try:
            detail=wifi_diagnostics(stop=stop)
            status='Warning' if any(x['loss_percent']>0 for x in detail['probes'].values()) else 'Checked'
            record_sample('WiFi','Windows',status,json.dumps(detail,ensure_ascii=False))
        except Exception as exc:record_sample('WiFi','Windows','Error',str(exc))



def run(stop=None,interval=60):
    stop=stop if stop is not None else threading.Event()
    if stop.is_set():
        return
    if interval <= 0:
        raise ValueError('Chu kỳ phải lớn hơn 0.')
    with AgentLock(data_path('agent.lock')):
        setup_logging()
        pulse = Heartbeat(data_path('agent_status.json'))
        pulse.start()
        try:
            from modules.advanced_pages import ensure_advanced_tables
            ensure_advanced_tables()
            ensure_tables()
            while not stop.is_set():
                pulse.write(state='running')
                try:
                    cycle(stop)
                    pulse.write(state='waiting',last_cycle=__import__('datetime').datetime.now().isoformat(),error='')
                except Exception as exc:
                    logging.exception('Monitoring cycle failed')
                    pulse.write(state='error',error=type(exc).__name__)
                stop.wait(interval)
        finally:
            pulse.close()

if __name__=='__main__':
    try:run()
    except KeyboardInterrupt:pass
