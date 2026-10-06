from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_non_auth_401_must_confirm_session_before_login_screen():
    app = (ROOT / 'webapi/static/app.js').read_text(encoding='utf-8')
    ops = (ROOT / 'webapi/static/operations47.js').read_text(encoding='utf-8')
    assert "async function naConfirmSessionAfter401" in app
    assert "fetch('/api/auth/me'" in app
    assert "if(r.status===401){showLogin();return false;}" in app
    assert "await naConfirmSessionAfter401(path)" in app
    assert "await naConfirmSessionAfter401(path)" in ops
    assert "if(r.status===401&&path!=='/auth/login')showLogin();" not in ops


def test_hotfix13_assets_are_cache_busted_and_visible():
    html = (ROOT / 'webapi/static/index.html').read_text(encoding='utf-8')
    assert 'app.js?v=6923' in html
    assert "'operations47.js'" in (ROOT / 'webapi/static/app.js').read_text(encoding='utf-8')
    assert 'Hotfix16R Router Auto Sync' in html
