import sqlite3
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from webapi import data37

class Presence67SyncTests(unittest.TestCase):
    def db(self):
        c=sqlite3.connect(':memory:'); c.row_factory=sqlite3.Row
        c.executescript('''
        CREATE TABLE devices(id INTEGER PRIMARY KEY, ip TEXT, hostname TEXT, mac TEXT, status TEXT, last_seen TEXT);
        CREATE TABLE network_devices(id INTEGER PRIMARY KEY, ip_address TEXT);
        CREATE TABLE ping_results(id INTEGER PRIMARY KEY, ip TEXT, status TEXT, response_ms REAL, ping_time TEXT);
        CREATE TABLE health_samples(id INTEGER PRIMARY KEY, host TEXT, packet_loss REAL, created_at TEXT);
        CREATE TABLE web_presence_state64(ip TEXT PRIMARY KEY,hostname TEXT,mac TEXT,status TEXT,source TEXT,last_seen_at TEXT,offline_since TEXT,consecutive_misses INTEGER,updated_at TEXT,origin TEXT,device_id INTEGER);
        INSERT INTO devices VALUES(1,'10.251.0.1','PC1','AA:BB:CC:DD:EE:01','Unknown',NULL);
        INSERT INTO web_presence_state64 VALUES('10.251.0.1','PC1','AA:BB:CC:DD:EE:01','Offline','ICMP',NULL,'2026-10-05T00:00:00Z',2,'2099-10-05T00:00:00Z','managed',1);
        ''')
        return c

    def test_merged_devices_prefers_presence_over_legacy_inventory_status(self):
        c=self.db()
        @contextmanager
        def fake_connection():
            yield c
        with patch.object(data37,'connection',fake_connection):
            rows=data37.merged_devices()
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['status'],'Offline')
        self.assertEqual(rows[0]['observation_source'],'ICMP')
        self.assertEqual(rows[0]['consecutive_misses'],2)
        self.assertEqual(rows[0]['reported_status'],'Unknown')

if __name__=='__main__': unittest.main()
