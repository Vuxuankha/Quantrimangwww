import re
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient

from webapi import security37

ROOT = Path(__file__).resolve().parents[1]
INDEX = (ROOT / 'webapi/static/index.html').read_text(encoding='utf-8')
APP = (ROOT / 'webapi/static/app.js').read_text(encoding='utf-8')
SEC = (ROOT / 'webapi/security37.py').read_text(encoding='utf-8')
MAIN = (ROOT / 'webapi/main.py').read_text(encoding='utf-8')
RUNTIME = (ROOT / 'webapi/runtime37.py').read_text(encoding='utf-8')


def test_login_shell_only_loads_minimal_initial_assets():
    refs = re.findall(r'(?:src|href)="/static/([^"?]+)', INDEX)
    assert refs == ['style.css', 'app.js']
    assert 'vendor/xterm.js' not in INDEX
    assert 'workbench45.js' not in INDEX
    assert "'vendor/xterm.js'" in APP
    assert "'workbench45.js'" in APP
    assert 'await naLoadOperationalAssets()' in APP


def test_all_operational_assets_are_versioned_and_lazy_loaded_after_auth():
    assert "NA_ASSET_VERSION='6922'" in APP
    assert "async function loggedIn(){state.user=await api('/auth/me');state.csrf=state.user.csrf_token;await naLoadOperationalAssets();" in APP
    for name in ['operations47.js','operations50.js','cybersecurity51.js','enterprise592.js','security_modes61.js','security_catalog62.js','kali63.js','hotfix9_kali_red.js','hotfix10_nav_core.js']:
        assert repr(name) in APP


def test_https_security_headers_and_cache_policy_are_present():
    assert 'Strict-Transport-Security' in SEC
    assert "max-age=31536000; includeSubDomains" in SEC
    assert 'Permissions-Policy' in SEC
    assert "camera=(), microphone=(), geolocation=()" in SEC
    assert "public, max-age=31536000, immutable" in SEC
    assert "security_headers['Cache-Control']='no-store'" in SEC


def test_security_middleware_runtime_headers():
    app = FastAPI()
    security37.install(app)

    @app.get('/static/demo.js')
    def static_demo():
        return PlainTextResponse('ok', media_type='text/javascript')

    @app.get('/page')
    def page():
        return PlainTextResponse('ok')

    client = TestClient(app, base_url='https://testserver')
    r = client.get('/static/demo.js?v=6920')
    assert r.status_code == 200
    assert r.headers['strict-transport-security'] == 'max-age=31536000; includeSubDomains'
    assert r.headers['permissions-policy'] == 'camera=(), microphone=(), geolocation=()'
    assert r.headers['cache-control'] == 'public, max-age=31536000, immutable'
    p = client.get('/page')
    assert p.headers['cache-control'] == 'no-store'


def test_health_exposes_ui_and_core_versions_explicitly():
    assert "UI_VERSION='6.9.0'" in RUNTIME
    assert "RELEASE='Hotfix16Q Router API Provider'" in RUNTIME
    assert "'core_version':VERSION" in MAIN
    assert "'ui_version':UI_VERSION" in MAIN
    assert "'release':RELEASE" in MAIN


def test_hosted_login_ui_requires_no_windows_agent_or_bat_action():
    assert 'Không cần Agent, PowerShell hay thao tác Windows' in INDEX
    assert '.bat' not in INDEX.lower()
    assert 'START_WEB.bat' not in APP
    assert 'ONECLICK_UPDATE.bat' not in APP
