from starlette.requests import Request
from pathlib import Path
from webapi.security37 import _session_tokens


def _request(cookie: str, scheme: str = 'http'):
    headers=[(b'cookie',cookie.encode('latin-1'))] if cookie else []
    return Request({'type':'http','method':'GET','scheme':scheme,'path':'/api/auth/me','raw_path':b'/api/auth/me','query_string':b'','headers':headers,'client':('127.0.0.1',12345),'server':('127.0.0.1',8765)})


def test_duplicate_session_cookie_candidates_are_preserved_in_wire_order():
    r=_request('na_session=stale; x=1; na_session=fresh')
    assert _session_tokens(r)==['stale','fresh']


def test_login_cookie_security_follows_actual_request_scheme():
    src=Path('webapi/security37.py').read_text(encoding='utf-8')
    assert 'HTTPS_REQUIRED_FOR_REMOTE_SESSION' in src
    assert 'secure=cookie_secure' in src
    assert '_is_loopback_request(request)' in src


def test_hotfix12_or_later_cache_buster_and_visible_version_marker():
    html=Path('webapi/static/index.html').read_text(encoding='utf-8')
    assert 'app.js?v=6922' in html
    assert 'Hotfix16Q Router API Provider' in html
