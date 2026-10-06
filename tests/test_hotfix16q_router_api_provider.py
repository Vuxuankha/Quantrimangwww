from pathlib import Path

import pytest
from fastapi import HTTPException

from webapi import routerapi69 as r69

ROOT=Path(__file__).resolve().parents[1]


def test_router_provider_catalog_supports_cloud_server_and_browser_modes():
    assert 'mikrotik_rest' in r69.PROVIDERS
    assert 'unifi_cloud' in r69.PROVIDERS
    assert 'generic_server' in r69.SERVER_PROVIDERS
    assert 'generic_browser' in r69.BROWSER_PROVIDERS


def test_hosted_server_provider_blocks_private_destination(monkeypatch):
    monkeypatch.setattr(r69, '_web_only', lambda: True)
    monkeypatch.setattr(r69, '_resolved_addresses', lambda host, port: ['192.168.1.1'])
    with pytest.raises(HTTPException) as exc:
        r69._assert_server_destination('https://router.example.test')
    assert exc.value.status_code == 400
    assert 'ROUTER_API_PRIVATE_DESTINATION_BLOCKED' in str(exc.value.detail)


def test_hosted_server_provider_allows_public_destination(monkeypatch):
    monkeypatch.setattr(r69, '_web_only', lambda: True)
    monkeypatch.setattr(r69, '_resolved_addresses', lambda host, port: ['203.0.113.10'])
    # Documentation range is not globally routable according to ipaddress, so use a public resolver IP.
    monkeypatch.setattr(r69, '_resolved_addresses', lambda host, port: ['1.1.1.1'])
    r69._assert_server_destination('https://router-api.example.test')


def test_browser_provider_never_runs_server_fetch():
    with pytest.raises(HTTPException) as exc:
        r69.fetch_clients({'enabled': True, 'provider': 'generic_browser'})
    assert exc.value.status_code == 409
    assert 'ROUTER_API_BROWSER_DIRECT_REQUIRED' in str(exc.value.detail)


def test_generic_normalization_keeps_private_clients_only_at_report_boundary():
    payload={'data':[{'addr':'192.168.1.20','hw':'aa-bb-cc-dd-ee-ff','name':'pc-01','state':'connected'},
                     {'addr':'8.8.8.8','hw':'11:22:33:44:55:66','name':'public','state':'connected'}]}
    rows=r69._normalize_generic(payload, {'list_path':'data','ip_field':'addr','mac_field':'hw','hostname_field':'name','status_field':'state'})
    assert rows[0]['ip']=='192.168.1.20'
    assert rows[0]['mac']=='AA:BB:CC:DD:EE:FF'
    clean=r69._validate_reported_clients(rows)
    assert all(x['ip'].startswith(('10.','172.','192.168.')) or not x['ip'] for x in clean)
    assert not any(x['ip']=='8.8.8.8' for x in clean)


def test_browser_csp_origin_is_exact_https_origin(monkeypatch):
    monkeypatch.setattr(r69, '_read_config', lambda include_secret=False: {
        'enabled': True, 'provider': 'generic_browser', 'base_url': 'https://192.168.1.1:8443/base'
    })
    assert r69.browser_connect_origin() == 'https://192.168.1.1:8443'


def test_redirects_are_blocked_for_server_side_router_api():
    h=r69._NoRedirect69()
    with pytest.raises(HTTPException) as exc:
        h.redirect_request(None, None, 302, 'Found', {}, 'https://192.168.1.1/private')
    assert 'ROUTER_API_REDIRECT_BLOCKED' in str(exc.value.detail)


def test_router_ui_uses_router_api_and_never_reenables_host_scan():
    js=(ROOT/'webapi/static/routerapi69.js').read_text(encoding='utf-8')
    app=(ROOT/'webapi/static/app.js').read_text(encoding='utf-8')
    routes=(ROOT/'webapi/routes37.py').read_text(encoding='utf-8')
    assert "/v69/router-api/clients" in js
    assert "/v69/router-api/browser-observations" in js
    assert "mode:'cors'" in js
    assert 'sessionStorage' in js
    assert 'Host scan van bi khoa' in js
    assert "'routerapi69.js'" in app
    assert "'routerapi69.js': 'text/javascript'" in routes
    assert "api('/scan" not in js


def test_browser_secrets_are_explicitly_cleared_from_server_storage_logic():
    src=(ROOT/'webapi/routerapi69.py').read_text(encoding='utf-8')
    assert 'Browser-direct credentials stay in browser sessionStorage only.' in src
    assert "secret_enc=''; token_enc=''" in src
