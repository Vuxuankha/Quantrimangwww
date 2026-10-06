from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
JS=(ROOT/'webapi/static/hotfix9_kali_red.js').read_text(encoding='utf-8')
PYK=(ROOT/'webapi/kali63.py').read_text(encoding='utf-8')
IDX=(ROOT/'webapi/static/index.html').read_text(encoding='utf-8')

def test_two_security_groups_are_authoritative():
    assert '🛡 HACKER MŨ TRẮNG · PHÒNG THỦ' in JS
    assert '🥷 HACKER MŨ ĐEN · RED TEAM LAB' in JS
    assert 'installGroups' in JS
    assert 'window.addEventListener(\'load\',installGroups' in JS

def test_safe_kali_red_profiles_only():
    for p in ['session_cookie_audit','tls_transport_audit','component_versions','http_capacity_probe','worker_network_state']:
        assert p in JS and p in PYK
    banned=['hydra ','sqlmap ','metasploit ','msfconsole ','chisel ','ettercap ','hping3 ','nmap --script vuln']
    low=(JS+'\n'+PYK).lower()
    for token in banned:
        assert token not in low

def test_capacity_probe_is_bounded():
    assert ('range(10)' in PYK) or ('i -lt 10' in PYK)
    assert ('time.sleep(0.2)' in PYK) or ('sleep 0.2' in PYK)
    assert '10 request tuần tự' in JS

def test_hotfix9_loaded_after_kali():
    loader=(ROOT/'webapi/static/app.js').read_text(encoding='utf-8')
    assert loader.index("'kali63.js'") < loader.index("'hotfix9_kali_red.js'")
