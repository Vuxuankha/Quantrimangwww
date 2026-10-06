from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def test_hotfix16r_dashboard_router_auto_sync_loaded_last():
    app=(ROOT/'webapi/static/app.js').read_text(encoding='utf-8')
    assert 'routerapi70.js' in app
    assert app.index('routerapi70.js') > app.index('enterprise600.js')
    js=(ROOT/'webapi/static/routerapi70.js').read_text(encoding='utf-8')
    assert "pages.dashboard=async()=>{const r=await sync70()" in js
    assert "/v69/router-api/sync" in js
    assert 'Router API chưa được cấu hình' in js

def test_hotfix16r_automation_uses_router_api_not_host_scan():
    src=(ROOT/'webapi/automation68.py').read_text(encoding='utf-8')
    assert 'sync_server_provider69' in src
    assert "Đồng bộ thiết bị từ Router API" in src
    block=src[src.index('def _run_discovery'):src.index('def _run_alert_rules')]
    assert 'autodiscovery5010' not in block

def test_hotfix16r_router_sync_auto_import_and_browser_auto_import():
    src=(ROOT/'webapi/routerapi69.py').read_text(encoding='utf-8')
    assert 'def sync_server_provider69' in src
    assert "@router.post('/router-api/sync')" in src
    assert '_import_clients_internal' in src
    assert "user.get('role')=='Admin'" in src
    assert "opts.get('auto_import', True)" in src

def test_hotfix16r_public_ip_label_is_not_lan_ip():
    js=(ROOT/'webapi/static/operations50.js').read_text(encoding='utf-8')
    assert 'IP Internet:' in js
    assert "chip.textContent='IP mạng: '+(ip||'—')" not in js
