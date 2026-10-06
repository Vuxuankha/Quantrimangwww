import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import SELF_CHECK


class SelfCheck671Tests(unittest.TestCase):
    def test_environment_data_dir_is_honored(self):
        with tempfile.TemporaryDirectory() as td:
            path,source=SELF_CHECK.resolve_self_check_data([],{'NETWORK_AUTOMATION_DATA_DIR':td})
            self.assertEqual(path,Path(td).resolve())
            self.assertEqual(source,'NETWORK_AUTOMATION_DATA_DIR')

    def test_explicit_data_dir_has_highest_priority(self):
        with tempfile.TemporaryDirectory() as explicit, tempfile.TemporaryDirectory() as envdir:
            path,source=SELF_CHECK.resolve_self_check_data(['--data-dir',explicit],{'NETWORK_AUTOMATION_DATA_DIR':envdir})
            self.assertEqual(path,Path(explicit).resolve())
            self.assertEqual(source,'--data-dir')

    def test_external_data_uses_shared_web_resolver(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(SELF_CHECK,'resolve_web_data',return_value=(Path(td),'data_location.json (explicit external mode)')) as resolver:
                path,source=SELF_CHECK.resolve_self_check_data(['--external-data'],{})
            resolver.assert_called_once_with(use_external=True)
            self.assertEqual(path,Path(td).resolve())
            self.assertEqual(source,'data_location.json (explicit external mode)')


if __name__=='__main__':
    unittest.main()
