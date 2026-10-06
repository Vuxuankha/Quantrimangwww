"""Release regression smoke tests for NetworkAutomation UI 6.9.0."""
from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    main_py=(ROOT/'webapi'/'main.py').read_text(encoding='utf-8')
    js=(ROOT/'webapi'/'static'/'enterprise592.js').read_text(encoding='utf-8')
    check('manager.get_devices()[:128]' not in main_py,'Presence still truncates managed devices at 128')
    check('delete_managed_device_atomic' in main_py,'Device delete is not transactional with Presence cleanup')
    check("source_of_truth':'web_presence_state64'" in main_py,'Presence API does not declare canonical source')
    check('presenceTotal' in js,'Dashboard does not use Presence total consistently')
    check((ROOT/'tests'/'test_presence65.py').is_file(),'Presence regression tests missing')
    check((ROOT/'tests'/'test_accounts66.py').is_file(),'Account-role regression tests missing')
    check((ROOT/'tests'/'test_live_discovery671.py').is_file(),'Live Discovery 6.7.1 regression tests missing')
    check((ROOT/'tests'/'test_self_check671.py').is_file(),'SELF_CHECK 6.7.1 regression tests missing')
    check((ROOT/'tests'/'test_automation68.py').is_file(),'Master Automation 6.8 regression tests missing')
    check((ROOT/'tests'/'test_daily_auto69.py').is_file(),'Daily auto-completion 6.9 regression tests missing')
    routes=(ROOT/'webapi'/'routes37.py').read_text(encoding='utf-8')
    sec=(ROOT/'webapi'/'security37.py').read_text(encoding='utf-8')
    check("Literal['Admin','Analyst','Operator','Viewer']" in routes,'Analyst missing from account schema')
    check("r'/api/auth/password', ('Admin','Analyst','Operator','Viewer')" in sec,'Analyst cannot change own password')
    platform=(ROOT/'webapi'/'platform50.py').read_text(encoding='utf-8')
    selfcheck=(ROOT/'SELF_CHECK.py').read_text(encoding='utf-8')
    check('normalize_discovery_sources' in platform,'Live Discovery source normalization fix missing')
    check('resolve_self_check_data' in selfcheck,'SELF_CHECK custom data resolver missing')
    auto=(ROOT/'webapi'/'automation68.py').read_text(encoding='utf-8')
    check('MasterAutomation68' in auto and "/automation/enable" in auto,'Master Automation 6.8 backend missing')
    daily=(ROOT/'webapi'/'cybersecurity57.py').read_text(encoding='utf-8')
    check('DailyAuto57' in daily and "/daily/auto/run-now" in daily,'Daily safe auto-completion 6.9 backend missing')
    dailyjs=(ROOT/'webapi'/'static'/'cybersecurity51.js').read_text(encoding='utf-8')
    check('daily-auto-toggle57' in dailyjs and 'AUTO DONE' in dailyjs,'Daily safe auto-completion 6.9 UI missing')
    # Hotfix14: auth/RBAC/session/navigation hardening regressions.
    kali=(ROOT/'webapi'/'kali63.py').read_text(encoding='utf-8')
    accounts=(ROOT/'modules'/'accounts.py').read_text(encoding='utf-8')
    nav=(ROOT/'webapi'/'static'/'hotfix10_nav_core.js').read_text(encoding='utf-8')
    index=(ROOT/'webapi'/'static'/'index.html').read_text(encoding='utf-8')
    check("r'/api/v59/network/optimize', ('Admin',)" in sec,'Network optimize central WRITE_RULE missing')
    check("r'/api/v1/kali/config', ('Admin',)" in sec and "r'/api/v1/kali/run', ('Admin','Operator')" in sec,'Kali central WRITE_RULE missing')
    check('from webapi.security37 import require_role' in kali and 'webapi.core.security' not in kali,'Kali is not using the primary cookie session auth')
    check('_ensure_username_available' in accounts and 'COLLATE NOCASE' in accounts,'Case-insensitive account collision protection missing')
    check('for token in tokens:' in sec and 'HTTPS_REQUIRED_FOR_REMOTE_SESSION' in sec,'Logout/remote HTTP session hardening missing')
    check('bluesecret62' not in nav and 'bluesecrets62' in nav and 'blueids62' in nav,'White Hat final navigation is inconsistent')
    check('Hotfix16O Web Production Standards' in index and 'app.js?v=6920' in index,'Hotfix16O cache/version marker missing')
    check("'vendor/xterm.js'" in (ROOT/'webapi'/'static'/'app.js').read_text(encoding='utf-8'),'Hotfix16O lazy feature bundle missing')
    check("api('/v45/ipmac')" in (ROOT/'webapi'/'static'/'cybersecurity51.js').read_text(encoding='utf-8'),'Vulnerability Center still calls missing /api/ipmac route')
    check("HTTPException(404,'Schedule not found')" in (ROOT/'webapi'/'scheduler40.py').read_text(encoding='utf-8'),'Scheduler missing-ID 404 fix missing')
    check("HTTPException(403,'TASK_PERMISSION_DENIED')" in (ROOT/'webapi'/'scheduler40.py').read_text(encoding='utf-8'),'Scheduler role 403 fix missing')
    check("row['can_run']" in (ROOT/'webapi'/'ops40.py').read_text(encoding='utf-8'),'Scheduler role-aware can_run missing')
    check("_sync_schedule_status" in (ROOT/'webapi'/'jobs37.py').read_text(encoding='utf-8'),'Scheduler final-status synchronization missing')
    check((ROOT/'tests'/'test_hotfix15_scheduler_api_stability.py').is_file(),'Hotfix15 regression tests missing')
    print('PASS: 6.9.0 Hotfix16O Web Production Standards regression smoke checks')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
