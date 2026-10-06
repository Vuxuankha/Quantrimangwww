"""Live ICMP presence for the Device Manager's devices table; no Tk calls."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import ipaddress
import logging
import os
import re
import subprocess
import threading
import time

from app_runtime import hidden_subprocess_kwargs
from database.db import get_connection


def probe_device(ip):
    from modules.icmp_probe import icmp_ping
    result = icmp_ping(ip, 1000)
    return True if result['status'] == 'Online' else False if result['status'] == 'Offline' else None


class DevicePresenceMonitor:
    """Bounded parallel checks start immediately and repeat after each cycle.

    Snapshots belong to this session and IP. Old DB statuses are never presented
    as live evidence; results also expire if collection stalls. last_seen changes
    only for an actual reply. The coordinator alone writes the database.
    """
    def __init__(self, interval=15, workers=16, probe=probe_device, autostart=True):
        self.interval = max(.05, float(interval))
        self.workers = max(1, min(32, int(workers)))
        self.probe = probe
        self.stop_event = threading.Event()
        self.wake_event = threading.Event()
        self.lock = threading.Lock()
        self.results = {}
        self.checking = False
        self.error = ''
        self.thread = None
        if autostart:
            self.thread = threading.Thread(target=self._loop, daemon=True,
                                           name='Device-Presence')
            self.thread.start()

    def request_check(self):
        self.wake_event.set()

    def stop(self):
        self.stop_event.set()
        self.wake_event.set()

    def snapshot(self):
        with self.lock:
            return dict(self.results), self.checking, self.error

    def display_result(self, device, snapshot):
        result = snapshot.get((device['id'], device['ip']))
        if result and time.monotonic() - result['monotonic'] <= max(60, self.interval * 3):
            return result['status'], result['checked_at']
        return 'Unknown', '-'

    def _loop(self):
        while not self.stop_event.is_set():
            self.wake_event.clear()
            self.collect_once()
            self.wake_event.wait(self.interval)

    def collect_once(self):
        with self.lock:
            if self.checking or self.stop_event.is_set():
                return
            self.checking = True
            self.error = ''
        try:
            connection = get_connection(timeout=2)
            try:
                rows = connection.execute('SELECT id,ip FROM devices').fetchall()
            finally:
                connection.close()
            with ThreadPoolExecutor(max_workers=self.workers,
                                    thread_name_prefix='Device-Ping') as pool:
                futures = {pool.submit(self._probe_unless_stopped, row['ip']):
                           (row['id'], row['ip']) for row in rows}
                for future in as_completed(futures):
                    if self.stop_event.is_set():
                        for pending in futures:
                            pending.cancel()
                        break
                    device_id, ip = futures[future]
                    try:
                        alive = future.result()
                    except Exception:
                        logging.getLogger(__name__).exception('Device presence probe failed')
                        alive = None
                    status = 'Online' if alive is True else 'Offline' if alive is False else 'Unknown'
                    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    connection = get_connection(timeout=2)
                    try:
                        cursor = connection.execute(
                            "UPDATE devices SET status=?, last_seen=CASE WHEN ?='Online' "
                            "THEN ? ELSE last_seen END WHERE id=? AND ip=?",
                            (status, status, now, device_id, ip))
                        connection.commit()
                        updated = cursor.rowcount
                    finally:
                        connection.close()
                    if updated:
                        # Keep the managed-device inventory consistent with the discovery table.
                        # NMS dashboards read network_devices, while discovery/presence reads devices.
                        # Use the existing debounce logic so one transient ping does not flap status.
                        try:
                            connection = get_connection(timeout=2)
                            try:
                                managed = connection.execute(
                                    "SELECT id FROM network_devices WHERE ip=? ORDER BY id LIMIT 1",
                                    (ip,),
                                ).fetchone()
                            finally:
                                connection.close()
                            if managed:
                                from modules.nms_v11 import record_ping_result
                                record_ping_result(int(managed['id']), alive is True,
                                                   '' if alive is not None else 'Presence probe unavailable')
                        except Exception:
                            logging.getLogger(__name__).exception(
                                'Managed-device status synchronization failed for %s', ip)
                        with self.lock:
                            self.results[(device_id, ip)] = dict(status=status, checked_at=now,
                                                                 monotonic=time.monotonic())
            with self.lock:
                targets = {(row['id'], row['ip']) for row in rows}
                self.results = {key: value for key, value in self.results.items() if key in targets}
        except Exception:
            logging.getLogger(__name__).exception('Device presence collection failed')
            with self.lock:
                self.error = 'Không thể kiểm tra thiết bị; kiểm tra nhật ký ứng dụng.'
                self.results.clear()
        finally:
            with self.lock:
                self.checking = False

    def _probe_unless_stopped(self, ip):
        return None if self.stop_event.is_set() else self.probe(ip)
