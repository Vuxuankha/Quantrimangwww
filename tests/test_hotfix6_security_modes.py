from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
JS=(ROOT/'webapi/static/security_modes61.js').read_text(encoding='utf-8')
HTML=(ROOT/'webapi/static/index.html').read_text(encoding='utf-8')

def test_two_separate_security_groups_are_present():
    assert 'HACKER MŨ TRẮNG · PHÒNG THỦ' in JS
    assert 'HACKER MŨ ĐEN · LAB CÔ LẬP' in JS
    assert "['🛡 HACKER MŨ TRẮNG · PHÒNG THỦ',white]" in JS
    assert "['🥷 HACKER MŨ ĐEN · LAB CÔ LẬP',red]" in JS

def test_white_hat_pages_include_requested_defensive_areas():
    for page in ['scan','ipmac','vuln51','blueweb61','bluelog61','bluepass61','siem51','threat54','endpoint58']:
        assert page in JS

def test_red_team_is_simulation_only_and_has_all_requested_categories():
    for page in ['redinject61','redxss61','redauth61','redpacket61','redidor61','redload61']:
        assert page in JS
    assert "red_team_mode:'simulation-only'" in JS
    assert 'không gửi payload tấn công' in JS.lower()
    assert 'không brute-force tài khoản' in JS.lower()
    assert 'không bắt gói từ card mạng' in JS.lower()
    assert 'không tạo flood/ddos' in JS.lower()

def test_red_lab_has_no_network_api_calls():
    red_section=JS[JS.index('pages.redhub61='):]
    assert "api('/" not in red_section
    assert 'fetch(' not in red_section
    assert 'WebSocket(' not in red_section

def test_new_assets_are_loaded():
    loader=(ROOT/'webapi/static/app.js').read_text(encoding='utf-8')
    assert "'security_modes61.css'" in loader
    assert "'security_modes61.js'" in loader
