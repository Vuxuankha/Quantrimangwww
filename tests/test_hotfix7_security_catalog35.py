from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
JS=(ROOT/'webapi/static/security_catalog62.js').read_text(encoding='utf-8')
HTML=(ROOT/'webapi/static/index.html').read_text(encoding='utf-8')

def test_catalog_exposes_exact_35_feature_architecture():
    assert "white_features:17" in JS
    assert "red_lab_features:18" in JS
    assert "total_features:35" in JS
    for n in range(1,18): assert f'{n}. ' in JS
    for n in range(18,36): assert f'{n}. ' in JS

def test_white_hat_new_modules_present():
    for page in ['bluetls62','blueids62','blueapi62','bluesecrets62','bluemalware62','bluefirewall62','blueiam62','blueir62','bluecontainer62','bluefim62','blueedr62','bluephish62']:
        assert page in JS

def test_red_lab_advanced_modules_present_and_simulation_only():
    for page in ['redupload62','redredirect62','redssrf62','redxxe62','redhash62','redsupply62','redsession62','redmitm62','redtunnel62','redprivesc62','redpersist62','redevasion62']:
        assert page in JS
    assert "red_team_mode:'simulation-only'" in JS
    assert 'không phát payload' in JS.lower()
    assert 'không tạo tunnel' in JS.lower()
    assert 'không tạo scheduled task' in JS.lower()
    assert 'không xóa hoặc sửa log' in JS.lower()

def test_red_catalog_extension_has_no_attack_network_apis():
    red=JS[JS.index("/* ---------- RED TEAM / SIMULATION ONLY ---------- */"):]
    assert "fetch(" not in red
    assert "WebSocket(" not in red
    assert "api('/" not in red
    assert 'subprocess' not in red

def test_file_hash_tools_are_browser_local():
    assert "crypto.subtle.digest('SHA-256'" in JS
    assert 'file.arrayBuffer()' in JS

def test_asset_is_loaded_with_cache_busting():
    loader=(ROOT/'webapi/static/app.js').read_text(encoding='utf-8')
    assert "'security_catalog62.js'" in loader
