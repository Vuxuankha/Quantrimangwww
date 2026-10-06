from contextlib import contextmanager
from pathlib import Path
import pytest
from fastapi import HTTPException

from webapi import terminal46 as term
from webapi import operations47 as ops


def test_manual_terminal_target_accepts_literal_ip_without_inventory():
    device, host, device_id = term.resolve_target(None, '192.168.11.250')
    assert host == '192.168.11.250'
    assert device_id is None
    assert device['ip'] == host


def test_manual_terminal_target_rejects_ambiguous_or_invalid_target():
    with pytest.raises(HTTPException) as both:
        term.resolve_target(1, '192.168.11.250')
    assert both.value.detail == 'CHOOSE_REGISTERED_DEVICE_OR_MANUAL_IP'
    with pytest.raises(HTTPException) as invalid:
        term.resolve_target(None, 'not-an-ip')
    assert invalid.value.detail == 'INVALID_MANUAL_TARGET_IP'
    with pytest.raises(HTTPException) as missing:
        term.resolve_target(None, '')
    assert missing.value.detail == 'DEVICE_OR_MANUAL_IP_REQUIRED'


def test_connect_schema_allows_manual_ip_and_optional_device_id():
    x = term.ConnectIn(target_ip='10.0.0.5', use_saved=False, username='admin', password='secret', authorized=True)
    assert x.device_id is None
    assert x.target_ip == '10.0.0.5'


def test_ping_plan_accepts_100_selected_devices(monkeypatch):
    rows=[{'id':i,'ip':f'10.10.{i//250}.{i%250+1}','hostname':f'dev-{i}','managed_id':None,'identity_conflict':False} for i in range(1,101)]
    monkeypatch.setattr(ops, 'merged_devices', lambda: rows)
    monkeypatch.setattr(ops.shutil, 'which', lambda name: '/bin/ping' if name=='ping' else None)

    @contextmanager
    def fake_connection():
        yield object()
    monkeypatch.setattr(ops, 'connection', fake_connection)

    plan=ops.build_plan(ops.PlanIn(operation='PING', inventory_ids=list(range(1,101))), {'role':'Operator'})
    assert plan['can_run'] is True
    assert len(plan['targets']) == 100
    assert plan['limit'] == 2048
    assert plan['device_ids'] == list(range(1,101))


def test_non_ping_plan_still_limited_to_20(monkeypatch):
    rows=[{'id':i,'ip':f'10.20.{i//250}.{i%250+1}','hostname':f'dev-{i}','managed_id':None,'identity_conflict':False} for i in range(1,22)]
    monkeypatch.setattr(ops, 'merged_devices', lambda: rows)
    @contextmanager
    def fake_connection():
        yield object()
    monkeypatch.setattr(ops, 'connection', fake_connection)
    with pytest.raises(HTTPException) as exc:
        ops.build_plan(ops.PlanIn(operation='SNMP', inventory_ids=list(range(1,22))), {'role':'Operator'})
    assert exc.value.detail == 'SELECT_1_TO_20_DEVICES'


def test_ui_contains_manual_target_command_input_and_select_all():
    root=Path(__file__).resolve().parents[1]
    terminal=(root/'webapi/static/terminal46.js').read_text(encoding='utf-8')
    devices=(root/'webapi/static/operations47.js').read_text(encoding='utf-8')
    assert "'target_mode'" in terminal and "'target_ip'" in terminal
    assert 'terminal-command-form' in terminal
    assert "'select-all47'" in devices
    assert 'Ping t\\u1ed1i \\u0111a 2048 IP' in devices
