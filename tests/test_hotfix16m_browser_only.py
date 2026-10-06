from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def test_browser_mode_backend_endpoints_present():
    s=(ROOT/'webapi/cybersecurity59.py').read_text(encoding='utf-8')
    for route in ("/browser/probe","/browser/ping","/browser/download","/browser/upload","/browser/report"):
        assert route in s
    assert "source': 'BROWSER'" in s
    assert 'x-forwarded-for' in s

def test_browser_mode_frontend_is_primary():
    s=(ROOT/'webapi/static/cybersecurity51.js').read_text(encoding='utf-8')
    assert 'browserLineProbe59' in s
    assert 'browserSpeedProbe59' in s
    assert 'Web tự kiểm tra mạng đang dùng' in s
    assert 'Tạo Agent Token' not in s

def test_topbar_uses_public_ip_without_agent():
    s=(ROOT/'webapi/static/operations50.js').read_text(encoding='utf-8')
    assert "IP mạng: " in s
    assert 'checkBrowser16n' in s
    assert 'checkAgent16l' not in s
    assert 'ensureAgentChip16l' not in s

def test_browser_write_routes_are_centrally_guarded():
    s=(ROOT/'webapi/security37.py').read_text(encoding='utf-8')
    assert "/api/v59/browser/upload" in s
    assert "/api/v59/browser/report" in s
