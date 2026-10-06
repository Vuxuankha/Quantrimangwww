"""Offline release-integrity check. This checks corruption, NOT publisher identity.

Only read-only code/assets checks are performed. No DB is opened, no package is
installed, no network requests are made. The manifest excludes operator data.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

BUILD = '5.9.2-cybersecurity'
ROOT = Path(__file__).resolve().parent
FORBIDDEN_PARTS = {'runtime_data', 'seed_data', '.venv', '.git', '__pycache__', 'node_modules'}
MUTABLE_FILES = {'database/network_automation.db', 'database/.credential.key', 'database/known_hosts'}
REQUIRED = {'.gitignore','WEB_VERSION.txt','run_web.py','VERIFY_RELEASE.py','webapi/main.py','webapi/runtime37.py','webapi/routes37.py','webapi/security37.py','webapi/operations47.py','webapi/platform50.py','webapi/static/index.html','webapi/static/operations47.js','webapi/static/operations47.css','webapi/static/operations50.js','webapi/static/operations50.css','webapi/cybersecurity51.py','webapi/cybersecurity54.py','webapi/cybersecurity55.py','webapi/cybersecurity56.py','webapi/cybersecurity57.py','webapi/cybersecurity58.py','webapi/cybersecurity59.py','webapi/static/cybersecurity51.js','webapi/static/cybersecurity51.css','webapi/static/enterprise592.js','webapi/static/enterprise592.css','webapi/static/enterprise600.js','webapi/static/enterprise600.css','webapi/automation68.py','webapi/kali63.py','webapi/static/kali63.js','webapi/static/hotfix9_kali_red.js','webapi/static/hotfix10_nav_core.js','modules/accounts.py','tests/test_automation68.py','tests/test_daily_auto69.py','tests/test_hotfix14_full_qa_fix.py','QA_FIX_REPORT_6.9.0_HOTFIX14_FULL_QA_FIX.md','tests/test_hotfix15_scheduler_api_stability.py','QA_FIX_REPORT_6.9.0_HOTFIX15_SCHEDULER_API_STABILITY.md','tests/test_hotfix16_lan_discovery_speed_accuracy.py','QA_FIX_REPORT_6.9.0_HOTFIX16_LAN_DISCOVERY.md','tests/test_hotfix16m_browser_only.py','QA_FIX_REPORT_6.9.0_HOTFIX16M_WEB_ONLY_BROWSER_MODE.md','tests/test_hotfix16n_web_native_network.py','QA_FIX_REPORT_6.9.0_HOTFIX16N_WEB_NATIVE_NETWORK.md','QA_PRODUCTION_GATE.py','QA_FIX_REPORT_6.9.0_HOTFIX16O_WEB_PRODUCTION_STANDARDS.md','tests/test_hotfix16p_browser_lan_guard.py','QA_FIX_REPORT_6.9.0_HOTFIX16P_BROWSER_LAN_GUARD.md','webapi/routerapi69.py','webapi/static/routerapi69.js','tests/test_hotfix16q_router_api_provider.py','QA_FIX_REPORT_6.9.0_HOTFIX16Q_ROUTER_API_PROVIDER.md','ROUTER_API_SETUP.md','webapi/static/routerapi70.js','tests/test_hotfix16r_router_auto_sync.py','QA_FIX_REPORT_6.9.0_HOTFIX16R_ROUTER_AUTO_SYNC.md'}


def verify_release(root: Path = ROOT) -> dict:
    root = root.resolve()
    if (root / '.web47-update-in-progress').exists():
        return {'ok':False,'version':BUILD,'checked':0,'errors':['UPDATE_IN_PROGRESS: finish or recover the previous code update first.']}
    path = root / 'RELEASE_MANIFEST.json'
    if not path.is_file():
        return {'ok':False, 'version':BUILD, 'checked':0, 'errors':['RELEASE_MANIFEST_MISSING: extract the complete release or apply the full update.']}
    try:
        manifest = json.loads(path.read_text(encoding='utf-8'))
        if manifest.get('version') != BUILD or not isinstance(manifest.get('files'), dict):
            raise ValueError('INVALID_MANIFEST_VERSION_OR_SHAPE')
        errors=[]; checked=0
        for name, expected in manifest['files'].items():
            # Runtime/operator data is intentionally mutable and must never block a code update.
            # Ignore legacy manifests that accidentally listed these files.
            if name in MUTABLE_FILES:
                continue
            relative=PurePosixPath(name)
            if relative.is_absolute() or '..' in relative.parts or '\\' in name or ':' in name or any(p in FORBIDDEN_PARTS for p in relative.parts):
                errors.append('UNSAFE_MANIFEST_PATH');continue
            p=root.joinpath(*relative.parts)
            if not p.resolve().is_relative_to(root) or p.is_symlink():
                errors.append('UNSAFE_FILE: '+name);continue
            if not re.fullmatch('[0-9a-f]{64}', str(expected)):
                errors.append('INVALID_HASH: '+name);continue
            if not p.is_file():
                errors.append('MISSING: '+name);continue
            checked+=1
            if hashlib.sha256(p.read_bytes()).hexdigest()!=expected:
                errors.append('CHANGED_OR_CORRUPT: '+name)
        for name in sorted(REQUIRED-set(manifest['files'])):
            errors.append('REQUIRED_FILE_NOT_LISTED: '+name)
        index=root/'webapi/static/index.html'
        if index.is_file():
            # Every linked local JS/CSS must be in the shipped integrity manifest.
            urls=re.findall(r'(?:src|href)=[\'"](/static/[^\'"?#]+)', index.read_text(encoding='utf-8'))
            for url in urls:
                if 'webapi'+url not in manifest['files']:
                    errors.append('UNTRACKED_ASSET: '+url)
        if (root/'WEB_VERSION.txt').is_file() and (root/'WEB_VERSION.txt').read_text().strip()!=BUILD:
            errors.append('BUILD_VERSION_MISMATCH')
        return {'ok':not errors,'version':BUILD,'checked':checked,'errors':errors}
    except (ValueError,TypeError,KeyError,OSError) as exc:
        return {'ok':False,'version':BUILD,'checked':0,'errors':['MANIFEST_READ_FAILED: '+type(exc).__name__]}


def require_release(root: Path = ROOT) -> dict:
    result=verify_release(root)
    if not result['ok']:
        raise RuntimeError('RELEASE_CHECK_FAILED\n'+'\n'.join(result['errors'][:20])+ '\nKeep runtime_data and its original key. Reapply the complete code update; do not reset the database.')
    return result


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true')
    args=parser.parse_args()
    report=verify_release()
    if args.json:
        print(json.dumps(report,indent=2))
    else:
        print(('RELEASE OK' if report['ok'] else 'RELEASE CHECK FAILED')+' - '+BUILD)
        print('Code/asset files checked:',report['checked'])
        for message in report['errors']:print(message)
        if not report['ok']:print('DO NOT DELETE DATABASE/KEY. Restore intact code from the update package.')
    return 0 if report['ok'] else 1

if __name__=='__main__':raise SystemExit(main())
