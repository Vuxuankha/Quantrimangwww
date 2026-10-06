import sqlite3
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from webapi import cybersecurity57


class DailyAuto69Tests(unittest.TestCase):
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

    def test_daily_auto_switch_persists(self):
        user={'id':1,'username':'admin','role':'Admin'}
        with patch.object(cybersecurity57,'connection',self.fake_connection), \
             patch.object(cybersecurity57,'ensure_tables56',return_value=None), \
             patch.object(cybersecurity57.daily_auto_engine,'run_async',return_value=True):
            cybersecurity57.ensure_tables57()
            enabled=cybersecurity57.daily_auto_engine.enable(user)
            self.assertTrue(enabled['enabled'])
            disabled=cybersecurity57.daily_auto_engine.disable(user)
            self.assertFalse(disabled['enabled'])

    def test_write_rules_admin_only_for_auto_controls(self):
        rules=[r for r in cybersecurity57.WRITE_RULES if 'daily/auto' in r[1]]
        self.assertTrue(rules)
        self.assertTrue(all(tuple(roles)==('Admin',) for _,_,roles in rules))

    def test_auto_completion_never_claims_attention_item_done(self):
        task=cybersecurity57._task('critical_alerts','Critical',2,'CRITICAL','siem51','manual')
        self.assertTrue(task['needs_attention'])
        self.assertEqual(task['count'],2)

    def test_daily_auto_completed_requires_actual_all_clear(self):
        latest={'status':'PASS'}
        self.assertFalse(cybersecurity57._auto_run_completed_today(latest, 1))
        self.assertTrue(cybersecurity57._auto_run_completed_today(latest, 0))
        self.assertFalse(cybersecurity57._auto_run_completed_today({'status':'PARTIAL'}, 0))

    def test_manual_only_safety_contract_is_exposed(self):
        with patch.object(cybersecurity57,'connection',self.fake_connection), \
             patch.object(cybersecurity57,'ensure_tables56',return_value=None):
            cybersecurity57.ensure_tables57()
            payload=cybersecurity57._auto_payload()
            manual=' '.join(payload['safety']['manual_only'])
            self.assertIn('Resolve/close alert',manual)
            self.assertIn('Credential/config/restore/delete',manual)


if __name__=='__main__':
    unittest.main()
