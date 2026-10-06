from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi import HTTPException

ROOT=Path(__file__).resolve().parents[1]


def test_server_side_scan_is_hard_blocked_in_browser_only(monkeypatch):
    monkeypatch.setenv('NA_WEB_ONLY_BROWSER','1')
    from webapi import main
    called={'scan':False}
    def forbidden(*args,**kwargs):
        called['scan']=True
        raise AssertionError('scan_network must never run in browser-only mode')
    monkeypatch.setattr(main,'scan_network',forbidden)
    with pytest.raises(HTTPException) as exc:
        main._run_scan('192.168.1.0/24')
    assert exc.value.status_code==409
    assert 'BROWSER_ONLY_LAN_SCAN_UNAVAILABLE' in str(exc.value.detail)
    assert called['scan'] is False


def test_auto_discovery_does_not_inspect_render_lan(monkeypatch):
    monkeypatch.setenv('NA_WEB_ONLY_BROWSER','1')
    from webapi import autodiscovery5010 as auto
    r=auto.ensure(source='qa-hotfix16p',force=True)
    assert r['state']=='BROWSER_ONLY'
    assert r['network']==''
    assert r['active']==0
    assert 'Render host' in r['detail']


def test_ui_has_no_host_scan_form_in_browser_mode():
    app=(ROOT/'webapi/static/app.js').read_text(encoding='utf-8')
    ops=(ROOT/'webapi/static/operations50.js').read_text(encoding='utf-8')
    routes=(ROOT/'webapi/routes37.py').read_text(encoding='utf-8')
    assert 'Đã khóa quét LAN trên Render' in app
    assert 'Bản Web-only không quét LAN trên Render' in ops
    assert 'BROWSER_ONLY_LAN_SCAN_UNAVAILABLE' in routes
