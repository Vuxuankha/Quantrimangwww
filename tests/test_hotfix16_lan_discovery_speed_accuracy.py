import time
from unittest.mock import patch

from webapi import autodiscovery5010 as ad
from modules import network_scan


def test_fast_preliminary_skips_slow_sources_and_name_resolution():
    with patch.object(ad, '_arp_neighbors', return_value={'192.168.2.10':'AA-BB-CC-DD-EE-10'}), \
         patch.object(ad, '_netsh_neighbors', return_value={}), \
         patch.object(ad, '_dhcp_leases', side_effect=AssertionError('DHCP should be skipped')), \
         patch.object(ad, '_mdns_devices', side_effect=AssertionError('mDNS should be skipped')), \
         patch.object(ad, '_ssdp_devices', side_effect=AssertionError('SSDP should be skipped')), \
         patch.object(ad, '_enrich_names_parallel', side_effect=AssertionError('name enrichment should be skipped')):
        rows=ad._collect_lan_evidence('192.168.2.0/24', [], enrich_names=False, fast_only=True)
    assert set(rows) == {'192.168.2.10'}
    assert rows['192.168.2.10']['sources'] == {'ARP'}


def test_reverse_dns_is_time_bounded():
    def slow(_ip):
        time.sleep(0.5)
        return ('slow-host', [], [])
    started=time.monotonic()
    with patch.object(ad.socket, 'gethostbyaddr', side_effect=slow):
        assert ad._reverse_dns_bounded('192.168.2.10', timeout=0.05) == ''
    assert time.monotonic()-started < 0.2


def test_arp_lookup_uses_shared_snapshot_cache(monkeypatch):
    calls={'n':0}
    class CP:
        stdout='  192.168.2.10          aa-bb-cc-dd-ee-ff     dynamic\n'
        stderr=''
    def fake_run(*args, **kwargs):
        calls['n'] += 1
        return CP()
    monkeypatch.setattr(network_scan.subprocess, 'run', fake_run)
    monkeypatch.setattr(network_scan.platform, 'system', lambda:'Windows')
    monkeypatch.setattr(network_scan, '_arp_cache', {})
    monkeypatch.setattr(network_scan, '_arp_cache_at', 0.0)
    assert network_scan.get_mac_from_arp('192.168.2.10') == 'AA-BB-CC-DD-EE-FF'
    assert network_scan.get_mac_from_arp('192.168.2.10') == 'AA-BB-CC-DD-EE-FF'
    assert calls['n'] == 1


def test_discovery_modal_auto_refreshes_source():
    src=open('webapi/static/operations50.js',encoding='utf-8').read()
    assert 'refreshDiscoveryDetail5016' in src
    assert 'setTimeout(()=>void refreshDiscoveryDetail5016(token),1000)' in src
    assert "BROWSER_ONLY" in src or "},1500);" in src
