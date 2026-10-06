"""Run release checks using disposable data.

6.9.0 runs core regression tests even when optional SSH/SNMP integrations are
not installed. Missing optional dependencies are reported as warnings instead
of masking the regression result.
"""
import os
import importlib
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]


def run(command, environment):
    print('+',' '.join(command))
    return subprocess.run(command,cwd=ROOT,env=environment).returncode


def main():
    required=('fastapi','uvicorn','pydantic','pytest')
    optional=('pandas','openpyxl','paramiko','cryptography','pysnmp','tkinter')
    missing_required=[]; missing_optional=[]
    for name in required:
        try: importlib.import_module(name)
        except ImportError: missing_required.append(name)
    for name in optional:
        try: importlib.import_module(name)
        except ImportError: missing_optional.append(name)
    if missing_required:
        print('FAIL: missing required Web dependencies: '+', '.join(missing_required),file=sys.stderr)
        return 1
    if missing_optional:
        print('WARN: optional/integration dependencies unavailable: '+', '.join(missing_optional),file=sys.stderr)
    if not (ROOT/'tests').is_dir() or not (ROOT/'regression_test.py').is_file():
        print('FAIL: regression suite is missing from release package.',file=sys.stderr); return 2
    with tempfile.TemporaryDirectory(prefix='na-release-check-') as temporary:
        environment=dict(os.environ,NETWORK_AUTOMATION_DATA_DIR=temporary)
        commands=(
            [sys.executable,'-m','pytest','-q'],
            [sys.executable,'regression_test.py'],
        )
        for command in commands:
            code=run(command,environment)
            if code: return code
    print('PASS: release checks; disposable data removed.')
    return 0


if __name__=='__main__': raise SystemExit(main())
