import sqlite3
import unittest

from webapi.presence65 import batches, cleanup_deleted_presence, merge_targets, summary


class Presence65Tests(unittest.TestCase):
    def test_batches_process_more_than_128(self):
        items=list(range(300))
        out=[x for batch in batches(items,128) for x in batch]
        self.assertEqual(out,items)
        self.assertEqual([len(x) for x in batches(items,128)],[128,128,44])

    def test_summary_is_self_consistent(self):
        rows=[{'status':'Online'}]*9+[{'status':'Offline'}]*3+[{'status':'Unknown'}]*2
        got=summary(rows)
        self.assertEqual(got['count'],14)
        self.assertEqual(got['online']+got['offline']+got['unknown'],got['count'])

    def test_merge_targets_includes_managed_and_live(self):
        managed=[{'id':1,'ip':'192.168.1.10','hostname':'PC01'}]
        recent=[{'ip':'192.168.1.20','hostname':'OldPhone'}]
        live=[{'ip':'192.168.1.30','hostname':'Printer','sources':'ARP'}]
        rows=merge_targets(managed,recent,live)
        self.assertEqual({r['ip'] for r in rows},{'192.168.1.10','192.168.1.20','192.168.1.30'})
        self.assertEqual(next(r for r in rows if r['ip']=='192.168.1.10')['_origin'],'managed')

    def test_delete_cleanup_removes_state_but_keeps_audit_event(self):
        c=sqlite3.connect(':memory:'); c.row_factory=sqlite3.Row
        c.executescript('''
        CREATE TABLE web_presence_state64(ip TEXT PRIMARY KEY,hostname TEXT,mac TEXT,status TEXT,source TEXT,last_seen_at TEXT,offline_since TEXT,consecutive_misses INTEGER,updated_at TEXT,origin TEXT,device_id INTEGER);
        CREATE TABLE web_presence_events64(id INTEGER PRIMARY KEY AUTOINCREMENT,ip TEXT,hostname TEXT,mac TEXT,old_status TEXT,new_status TEXT,source TEXT,observed_at TEXT);
        INSERT INTO web_presence_state64 VALUES('192.168.1.12','PC12','AA','Offline','','','','2','2026-10-05T00:00:00Z','managed',12);
        ''')
        n=cleanup_deleted_presence(c,'192.168.1.12','PC12','AA','2026-10-05T01:00:00Z'); c.commit()
        self.assertEqual(n,1)
        self.assertIsNone(c.execute("SELECT 1 FROM web_presence_state64 WHERE ip='192.168.1.12'").fetchone())
        ev=dict(c.execute("SELECT * FROM web_presence_events64 WHERE ip='192.168.1.12'").fetchone())
        self.assertEqual(ev['new_status'],'Deleted')
        self.assertEqual(ev['source'],'DEVICE_DELETE')


if __name__=='__main__': unittest.main()
