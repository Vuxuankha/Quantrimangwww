from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BACK=(ROOT/'webapi/kali63.py').read_text(encoding='utf-8')
JS=(ROOT/'webapi/static/kali63.js').read_text(encoding='utf-8')
MAIN=(ROOT/'webapi/main.py').read_text(encoding='utf-8')
INDEX=(ROOT/'webapi/static/index.html').read_text(encoding='utf-8')

def test_kali_router_registered_and_asset_loaded():
    assert 'kali63_router' in MAIN
    assert "'kali63.js'" in (ROOT/'webapi/static/app.js').read_text(encoding='utf-8')

def test_kali_is_defensive_and_private_target_limited():
    assert "TARGET_MUST_BE_PRIVATE_IP_OR_CIDR" in BACK
    assert "TARGET_HOST_MUST_RESOLVE_PRIVATE" in BACK
    assert "UNSUPPORTED_KALI_PROFILE" in BACK
    assert "--top-ports 100" in BACK
    assert "nmap -sn" in BACK

def test_kali_host_key_pinning_and_encrypted_password():
    assert 'KALI_HOSTKEY_CHANGED' in BACK
    assert 'encrypt_secret' in BACK and 'decrypt_secret' in BACK
    assert 'hostkey_sha256' in BACK

def test_no_offensive_remote_profiles_exposed():
    forbidden=['brute','exploit','pivot','persistence','ddos','hydra','sqlmap','metasploit','msfconsole']
    low=BACK.lower()
    for x in forbidden:
        assert f"profile == '{x}'" not in low

def test_ui_has_kali_worker_and_safe_profiles():
    assert 'Kali Linux Integration' in JS
    assert 'network_discovery' in JS
    assert 'port_service_scan' in JS
    assert 'tls_audit' in JS
    assert 'web_headers' in JS
