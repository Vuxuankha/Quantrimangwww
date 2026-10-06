import unittest
from unittest.mock import patch

from webapi import platform50
from webapi.platform50 import normalize_discovery_rows, normalize_discovery_sources


class LiveDiscovery671Tests(unittest.TestCase):
    def test_preliminary_list_sources_are_preserved(self):
        self.assertEqual(normalize_discovery_sources(['ARP','MDNS']),['ARP','MDNS'])
        self.assertEqual(normalize_discovery_sources(['DHCP']),['DHCP'])

    def test_completed_db_string_sources_are_preserved(self):
        self.assertEqual(normalize_discovery_sources('ARP,MDNS'),['ARP','MDNS'])

    def test_source_counts_match_preliminary_rows(self):
        rows=[
            {'ip':'192.168.1.10','sources':['ARP','MDNS']},
            {'ip':'192.168.1.20','sources':['DHCP']},
        ]
        counts=normalize_discovery_rows(rows)
        self.assertEqual(rows[0]['sources'],['ARP','MDNS'])
        self.assertEqual(rows[1]['sources'],['DHCP'])
        self.assertEqual(counts['ARP'],1)
        self.assertEqual(counts['DHCP'],1)
        self.assertEqual(counts['MDNS'],1)
        self.assertEqual(counts['ICMP'],0)

    def test_connected_devices_endpoint_handles_running_preliminary_sources(self):
        state={
            'state':'RUNNING','scan_key':'','network':'192.168.1.0/24',
            'preliminary_devices':[
                {'ip':'192.168.1.10','sources':['ARP','MDNS']},
                {'ip':'192.168.1.20','sources':['DHCP']},
            ],
        }
        with patch.object(platform50,'require_role',return_value={'role':'Admin'}), \
             patch('webapi.autodiscovery5010.ensure_tables',return_value=None), \
             patch('webapi.autodiscovery5010.status',return_value=state):
            result=platform50.connected_devices(None)
        self.assertEqual(result['devices'][0]['sources'],['ARP','MDNS'])
        self.assertEqual(result['devices'][1]['sources'],['DHCP'])
        self.assertEqual(result['source_counts']['ARP'],1)
        self.assertEqual(result['source_counts']['DHCP'],1)
        self.assertEqual(result['source_counts']['MDNS'],1)


if __name__=='__main__':
    unittest.main()
