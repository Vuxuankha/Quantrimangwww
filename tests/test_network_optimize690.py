from webapi import cybersecurity59 as net


def test_improvement_detects_reduced_latency_jitter_loss():
    before={'latency_ms':80,'jitter_ms':22,'packet_loss':4}
    after={'latency_ms':35,'jitter_ms':8,'packet_loss':0}
    r=net._improvement(before, after)
    assert r['improved'] is True
    assert r['latency_reduction_ms']==45.0
    assert r['jitter_reduction_ms']==14.0
    assert r['packet_loss_reduction_pct']==4.0


def test_safe_optimization_never_runs_windows_commands_off_windows(monkeypatch):
    monkeypatch.setattr(net.sys, 'platform', 'linux')
    called=[]
    monkeypatch.setattr(net, '_run_windows_command', lambda args, timeout=15: called.append(args) or {'ok': True})
    r=net._safe_windows_line_optimization()
    assert called == []
    assert r[0]['detail'] == 'UNSUPPORTED_PLATFORM'
    assert r[0]['ok'] is False


def test_optimize_line_skips_changes_when_quality_is_good(monkeypatch):
    monkeypatch.setattr(net, 'require_role', lambda request, *roles: {'username':'qa-admin'})
    good={'grade':'GOOD','latency_ms':25,'jitter_ms':4,'packet_loss':0}
    monkeypatch.setattr(net, 'run_line_test_internal', lambda username='system': dict(good))
    called=[]
    monkeypatch.setattr(net, '_safe_windows_line_optimization', lambda: called.append(True) or [])
    r=net.optimize_line(net.OptimizeLineIn(confirm_system_change=True), None)
    assert r['status']=='NOT_NEEDED'
    assert called==[]


def test_optimize_line_measures_before_and_after(monkeypatch):
    monkeypatch.setattr(net, 'require_role', lambda request, *roles: {'username':'qa-admin'})
    samples=iter([
        {'grade':'POOR','latency_ms':180,'jitter_ms':45,'packet_loss':5},
        {'grade':'GOOD','latency_ms':45,'jitter_ms':8,'packet_loss':0},
    ])
    monkeypatch.setattr(net, 'run_line_test_internal', lambda username='system': next(samples))
    monkeypatch.setattr(net, '_safe_windows_line_optimization', lambda: [{'command':'safe-test','ok':True,'detail':'OK'}])
    monkeypatch.setattr(net.time, 'sleep', lambda _: None)
    r=net.optimize_line(net.OptimizeLineIn(confirm_system_change=True), None)
    assert r['status']=='APPLIED'
    assert r['before']['grade']=='POOR' and r['after']['grade']=='GOOD'
    assert r['improvement']['improved'] is True
