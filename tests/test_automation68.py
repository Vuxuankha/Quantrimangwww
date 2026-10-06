import sqlite3
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from webapi import automation68


class Automation68Tests(unittest.TestCase):
    def setUp(self):
        self.c = sqlite3.connect(':memory:', check_same_thread=False)
        self.c.row_factory = sqlite3.Row

    def tearDown(self):
        self.c.close()

    @contextmanager
    def fake_connection(self):
        try:
            yield self.c
            self.c.commit()
        except Exception:
            self.c.rollback()
            raise

    def test_master_task_registry_is_bounded_and_non_destructive(self):
        keys = {x.key for x in automation68.TASKS}
        self.assertEqual(keys, {
            'PRESENCE','LIVE_DISCOVERY','ALERT_RULES','INCIDENT_RCA',
            'SERVER_MONITOR','LINE_QUALITY','DATABASE_BACKUP'
        })
        self.assertNotIn('RESTORE', keys)
        self.assertNotIn('AUTOIP', keys)
        self.assertNotIn('VULNERABILITY_SCAN', keys)
        self.assertNotIn('SPEED_TEST', keys)

    def test_enable_disable_persists_switch(self):
        user={'id':7,'username':'qaadmin','role':'Admin'}
        with patch.object(automation68,'connection',self.fake_connection), \
             patch.object(automation68.engine,'tick',return_value=None):
            automation68.ensure_tables()
            enabled=automation68.engine.enable(user)
            self.assertTrue(enabled['enabled'])
            self.assertEqual(len(enabled['tasks']),7)
            disabled=automation68.engine.disable(user)
            self.assertFalse(disabled['enabled'])

    def test_security_write_rules_cover_master_switch(self):
        rules=[r for r in automation68.WRITE_RULES if 'v68/automation' in r[1]]
        self.assertTrue(rules)
        self.assertTrue(any('Admin' in roles for _,_,roles in rules))


if __name__=='__main__':
    unittest.main()
