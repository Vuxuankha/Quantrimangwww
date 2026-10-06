import sqlite3
import unittest
from pathlib import Path
from webapi.presence65 import delete_managed_device_atomic

class AccountRoleSourceTests(unittest.TestCase):
    def test_analyst_is_in_account_schema(self):
        self.assertIn("Literal['Admin','Analyst','Operator','Viewer']",Path('webapi/routes37.py').read_text(encoding='utf-8'))
    def test_analyst_can_change_own_password(self):
        self.assertIn("r'/api/auth/password', ('Admin','Analyst','Operator','Viewer')",Path('webapi/security37.py').read_text(encoding='utf-8'))

class AtomicDeviceLifecycleTests(unittest.TestCase):
    def connection(self):
        c=sqlite3.connect(':memory:'); c.row_factory=sqlite3.Row
        c.execute('CREATE TABLE devices(id INTEGER PRIMARY KEY, ip TEXT, hostname TEXT, mac TEXT)')
        c.execute("CREATE TABLE web_presence_state64(ip TEXT PRIMARY KEY, hostname TEXT, mac TEXT, status TEXT NOT NULL DEFAULT 'Unknown', source TEXT, last_seen_at TEXT, offline_since TEXT, consecutive_misses INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL, origin TEXT NOT NULL DEFAULT 'managed', device_id INTEGER)")
        c.execute('CREATE TABLE web_presence_events64(id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, hostname TEXT, mac TEXT, old_status TEXT, new_status TEXT NOT NULL, source TEXT, observed_at TEXT NOT NULL)')
        return c
    def seed(self,c):
        c.execute("INSERT INTO devices VALUES(1,'10.10.10.10','qa-host','AA:BB:CC:DD:EE:FF')")
        c.execute("INSERT INTO web_presence_state64(ip,hostname,mac,status,updated_at,origin,device_id) VALUES('10.10.10.10','qa-host','AA:BB:CC:DD:EE:FF','Online','now','managed',1)")
    def test_delete_removes_current_presence_but_keeps_event(self):
        c=self.connection(); self.seed(c)
        result=delete_managed_device_atomic(c,1,'2026-10-05T04:00:00Z')
        self.assertTrue(result['success']); self.assertEqual(c.execute('SELECT COUNT(*) FROM devices').fetchone()[0],0); self.assertEqual(c.execute('SELECT COUNT(*) FROM web_presence_state64').fetchone()[0],0)
        event=c.execute('SELECT * FROM web_presence_events64').fetchone(); self.assertEqual(event['new_status'],'Deleted'); self.assertEqual(event['source'],'DEVICE_DELETE')
    def test_presence_failure_can_roll_back_device_delete(self):
        c=self.connection(); self.seed(c); c.commit(); c.execute("CREATE TRIGGER block_presence_delete BEFORE DELETE ON web_presence_state64 BEGIN SELECT RAISE(ABORT,'simulated presence failure'); END;"); c.commit()
        c.execute('BEGIN')
        try: delete_managed_device_atomic(c,1,'2026-10-05T04:00:00Z')
        except sqlite3.DatabaseError: c.rollback()
        else: self.fail('expected simulated database failure')
        self.assertEqual(c.execute('SELECT COUNT(*) FROM devices').fetchone()[0],1); self.assertEqual(c.execute('SELECT COUNT(*) FROM web_presence_state64').fetchone()[0],1)

if __name__=='__main__': unittest.main()
