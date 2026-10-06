from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def test_render_is_browser_only():
    s=(ROOT/'render_start.py').read_text(encoding='utf-8')
    assert 'NA_WEB_ONLY_BROWSER' in s
    assert 'NA_LOCAL_AGENT_SHARED_TOKEN' not in s
    assert 'NA_LOCAL_AGENT_PREFERRED' not in s

def test_topbar_has_no_agent_ui_and_auto_public_ip():
    s=(ROOT/'webapi/static/operations50.js').read_text(encoding='utf-8')
    assert "api('/v59/browser/probe" in s
    assert "IP mạng: " in s
    assert 'ensureAgentChip16l' not in s
    assert 'checkAgent16l' not in s
    assert 'Agent: ONLINE' not in s

def test_netspeed_is_browser_only():
    s=(ROOT/'webapi/static/cybersecurity51.js').read_text(encoding='utf-8')
    assert 'Web tự kiểm tra mạng đang dùng' in s
    assert 'browserLineProbe59()' in s
    assert 'browserSpeedProbe59(5,2)' in s
    assert 'Tạo Agent Token' not in s
    assert 'NA_LOCAL_AGENT_SHARED_TOKEN' not in s

def test_agent_runtime_files_removed():
    for rel in ('endpoint_agent16l.py','SETUP_LOCAL_AGENT_16L.bat','LOCAL_AGENT_16L.bat','ONECLICK_LOCAL_AGENT_16L.bat','CONFIGURE_LOCAL_AGENT_16L.py'):
        assert not (ROOT/rel).exists(), rel

def test_browser_ip_backend_uses_proxy_request():
    s=(ROOT/'webapi/cybersecurity59.py').read_text(encoding='utf-8')
    assert 'x-forwarded-for' in s
    assert "'source': 'BROWSER'" in s
    assert 'BROWSER_MEASUREMENT_REQUIRED' in s

def test_agent_routes_not_public_or_writable():
    s=(ROOT/'webapi/security37.py').read_text(encoding='utf-8')
    assert '/api/v58/agent/checkin' not in s
    assert '/api/v58/agent-tokens' not in s
