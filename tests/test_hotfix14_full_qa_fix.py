from contextlib import contextmanager
import sqlite3
import socket
from pathlib import Path

import pytest
from fastapi import HTTPException, Response
from starlette.requests import Request

from modules import accounts
from webapi import security37
from webapi import kali63

ROOT=Path(__file__).resolve().parents[1]


def _request(cookie='', scheme='http', peer='127.0.0.1', host='127.0.0.1'):
    headers=[]
    if cookie:
        headers.append((b'cookie', cookie.encode('latin-1')))
    return Request({'type':'http','method':'POST','scheme':scheme,'path':'/api/auth/logout','raw_path':b'/api/auth/logout','query_string':b'',
                    'headers':headers,'client':(peer,12345),'server':(host,8765)})


def test_all_previously_unmatched_writes_have_central_rules():
    assert security37.allowed_roles('POST','/api/v59/network/optimize') == ('Admin',)
    assert security37.allowed_roles('POST','/api/v1/kali/config') == ('Admin',)
    assert security37.allowed_roles('POST','/api/v1/kali/test') == ('Admin','Operator')
    assert security37.allowed_roles('POST','/api/v1/kali/run') == ('Admin','Operator')


def test_kali_uses_primary_cookie_session_auth():
    src=(ROOT/'webapi/kali63.py').read_text(encoding='utf-8')
    assert 'from webapi.security37 import require_role' in src
    assert 'webapi.core.security' not in src
    assert 'Depends(require_roles' not in src
    assert 'Depends(current_user)' not in src


def test_kali_hostname_is_pinned_to_validated_private_ip(monkeypatch):
    def fake_getaddrinfo(host, port, type=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.7', 0))]
    monkeypatch.setattr(kali63.socket,'getaddrinfo',fake_getaddrinfo)
    assert kali63._private_host('qa.internal') == '10.0.0.7'
    url, resolve_value, ip = kali63._private_url_target('https://qa.internal/a?b=1')
    assert url == 'https://qa.internal/a?b=1'
    assert resolve_value == 'qa.internal:443:10.0.0.7'
    assert ip == '10.0.0.7'


def test_kali_rejects_cidr_for_single_host_profiles():
    with pytest.raises(HTTPException) as exc:
        kali63._private_host('10.0.0.0/24')
    assert exc.value.detail == 'TARGET_HOST_MUST_BE_SINGLE_PRIVATE_HOST'


def test_account_username_duplicate_is_case_insensitive():
    c=sqlite3.connect(':memory:'); c.row_factory=sqlite3.Row
    c.execute('CREATE TABLE app_users(id INTEGER PRIMARY KEY, username TEXT)')
    c.execute("INSERT INTO app_users(username) VALUES('Alice')")
    with pytest.raises(ValueError):
        accounts._ensure_username_available(c,'alice')
    # Updating the same account with case-only change remains allowed.
    accounts._ensure_username_available(c,'ALICE',1)


def test_logout_revokes_all_duplicate_cookie_candidates(monkeypatch):
    c=sqlite3.connect(':memory:'); c.row_factory=sqlite3.Row
    c.execute('CREATE TABLE web_sessions37(token_hash TEXT PRIMARY KEY)')
    c.execute('INSERT INTO web_sessions37 VALUES(?)',(security37.digest('valid'),))
    c.execute('INSERT INTO web_sessions37 VALUES(?)',(security37.digest('stale'),))
    c.commit()
    @contextmanager
    def fake_connection():
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback(); raise
    monkeypatch.setattr(security37,'connection',fake_connection)
    r=_request('na_session=valid; na_session=stale')
    security37.logout(r,Response())
    assert c.execute('SELECT COUNT(*) FROM web_sessions37').fetchone()[0] == 0


def test_plain_http_is_only_allowed_for_loopback():
    assert security37._is_loopback_request(_request(peer='127.0.0.1',host='127.0.0.1'))
    assert not security37._is_loopback_request(_request(peer='203.0.113.10',host='example.test'))



def test_finish_login_refuses_remote_plain_http_without_leaking_session():
    c=sqlite3.connect(':memory:'); c.row_factory=sqlite3.Row
    c.execute('CREATE TABLE web_sessions37(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,password_stamp TEXT NOT NULL,csrf TEXT NOT NULL,issued REAL NOT NULL,last_used REAL NOT NULL)')
    row={'id':1,'username':'Admin','role':'Admin','enabled':1,'password_hash':'hash','mfa_enabled':0}
    req=_request(scheme='http',peer='203.0.113.10',host='127.0.0.1')
    with pytest.raises(HTTPException) as exc:
        security37._finish_login(c,row,req,Response())
    assert exc.value.status_code == 403
    assert exc.value.detail == 'HTTPS_REQUIRED_FOR_REMOTE_SESSION'
    assert c.execute('SELECT COUNT(*) FROM web_sessions37').fetchone()[0] == 0


def test_kali_run_command_uses_pinned_ip_not_hostname(monkeypatch):
    monkeypatch.setattr(kali63,'require_role',lambda request,*roles:{'role':'Admin'})
    monkeypatch.setattr(kali63,'_private_host',lambda target:'10.0.0.7')
    seen={}
    def fake_exec(command,timeout=60):
        seen['command']=command
        return {'ok':True,'exit_code':0,'stdout':'','stderr':''}
    monkeypatch.setattr(kali63,'_exec',fake_exec)
    result=kali63.run_profile(kali63.KaliRunIn(profile='port_service_scan',target='qa.internal'),None)
    assert '10.0.0.7' in seen['command']
    assert 'qa.internal' not in seen['command']
    assert result['profile']=='port_service_scan'

def test_authoritative_white_hat_navigation_has_all_real_page_ids():
    js=(ROOT/'webapi/static/hotfix10_nav_core.js').read_text(encoding='utf-8')
    assert 'bluesecret62' not in js
    assert 'bluesecrets62' in js
    assert 'blueids62' in js
    assert any(x in js for x in ('6.9.0-hf14','6.9.0-hf15'))


def test_hotfix14_visible_release_marker_and_cache_buster():
    html=(ROOT/'webapi/static/index.html').read_text(encoding='utf-8')
    assert 'Hotfix16Q Router API Provider' in html
    assert 'app.js?v=6922' in html
    assert "'kali63.js'" in (ROOT/'webapi/static/app.js').read_text(encoding='utf-8')
    assert "'hotfix10_nav_core.js'" in (ROOT/'webapi/static/app.js').read_text(encoding='utf-8')
