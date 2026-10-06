from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT / 'runtime_data'
DB_REL = Path('database') / 'network_automation.db'
KEY_REL = Path('database') / '.credential.key'
SERVICE_NAME = 'NetworkAutomationWeb'


def log(msg: str) -> None:
    print(msg, flush=True)


def valid_db(root: Path) -> tuple[bool, tuple[int, int], str]:
    db = root / DB_REL
    if not db.is_file():
        return False, (0, 0), 'missing db'
    try:
        uri = db.resolve().as_uri() + '?mode=ro'
        with sqlite3.connect(uri, uri=True, timeout=5) as c:
            if c.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                return False, (0, 0), 'quick_check failed'
            tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not ({'devices', 'network_devices'} & tables):
                return False, (0, 0), 'not NetworkAutomation db'
            total = 0
            for t in ('devices','network_devices','autoip_targets','credentials','app_users','ip_mac_inventory','ping_results'):
                if t in tables:
                    try:
                        total += int(c.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0])
                    except Exception:
                        pass
        return True, (total, db.stat().st_size), 'ok'
    except Exception as exc:
        return False, (0, db.stat().st_size if db.exists() else 0), f'{type(exc).__name__}: {exc}'


def discover_candidates() -> list[tuple[Path, int]]:
    """Find plausible existing NetworkAutomation data roots without trusting folder names.

    Fresh OneClick releases are often extracted into generic folders such as
    ``Documents/new/source``.  Older discovery logic only looked for folders whose
    name contained "NetworkAutomation", which could miss the real runtime and then
    select an empty/development database.  This scanner is bounded, skips the current
    code tree, and validates every candidate before it can be selected.
    """
    candidates: list[tuple[Path, int]] = []
    seen: set[str] = set()

    def inside_current_code(p: Path) -> bool:
        try:
            p.resolve().relative_to(ROOT.resolve())
            return True
        except Exception:
            return False

    def add(p: Path, priority: int) -> None:
        try:
            p = p.expanduser().resolve()
        except Exception:
            return
        if inside_current_code(p) and p != RUNTIME.resolve():
            return
        if p.name.startswith('.oneclick'):
            return
        key = str(p).casefold()
        if key in seen:
            return
        seen.add(key)
        if (p / DB_REL).is_file():
            candidates.append((p, priority))

    add(RUNTIME, 1000)

    # Known application-data locations.
    for env_name in ('LOCALAPPDATA', 'APPDATA'):
        value = os.environ.get(env_name)
        if value:
            add(Path(value) / 'NetworkAutomation' / 'runtime_data', 990)
            add(Path(value) / 'NetworkAutomation', 970)

    # Nearby releases, regardless of whether the parent folder is named "source",
    # "new", "open", or NetworkAutomation_*.
    nearby = [ROOT.parent, ROOT.parent.parent]
    for base in nearby:
        if not base.exists():
            continue
        try:
            for child in base.iterdir():
                if not child.is_dir() or child.resolve() == ROOT.resolve():
                    continue
                add(child / 'runtime_data', 950)
                add(child, 720)
                try:
                    for grand in child.iterdir():
                        if grand.is_dir() and grand.resolve() != ROOT.resolve():
                            add(grand / 'runtime_data', 930)
                            add(grand, 700)
                except OSError:
                    pass
        except OSError:
            pass

    # Bounded search of the user's normal working folders.  We search for the
    # database filename itself rather than relying on release folder names.
    user = Path(os.environ.get('USERPROFILE') or Path.home())
    prune_names = {'.venv', 'venv', '__pycache__', 'node_modules', '.git', 'windows', 'program files', 'program files (x86)'}
    for named in ('Desktop', 'Downloads', 'Documents'):
        base = user / named
        if not base.exists():
            continue
        base_depth = len(base.parts)
        try:
            for dirpath, dirnames, filenames in os.walk(base):
                here = Path(dirpath)
                depth = len(here.parts) - base_depth
                dirnames[:] = [d for d in dirnames if d.casefold() not in prune_names and not d.startswith('.oneclick')]
                if depth >= 4:
                    dirnames[:] = []
                if 'network_automation.db' not in filenames:
                    continue
                db_dir = here
                if db_dir.name.casefold() != 'database':
                    continue
                root = db_dir.parent
                if inside_current_code(root):
                    continue
                priority = 940 if root.name.casefold() == 'runtime_data' else 680
                if 'networkautomation' in str(root).casefold():
                    priority += 15
                add(root, priority)
        except OSError:
            pass

    return candidates


def choose_best_source() -> tuple[Path | None, list[dict]]:
    rows = []
    best: tuple[tuple, Path] | None = None
    for root, priority in discover_candidates():
        ok, score, reason = valid_db(root)
        mtime = 0.0
        try:
            mtime = (root / DB_REL).stat().st_mtime
        except OSError:
            pass
        rows.append({'root': str(root), 'priority': priority, 'ok': ok, 'records': score[0], 'bytes': score[1], 'reason': reason})
        if not ok:
            continue
        # Never prefer an empty high-priority runtime over a populated valid one.
        # Within the same populated/empty class, prefer trusted locations, then
        # recency and record count.
        rank = (1 if score[0] > 0 else 0, priority, mtime, score[0], score[1])
        if best is None or rank > best[0]:
            best = (rank, root)
    return (best[1] if best else None), rows


def run_quiet(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(cmd, cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    except Exception:
        return None


def _health(port: int) -> dict | None:
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f'http://127.0.0.1:{port}/api/health', timeout=1.5) as response:
            value = json.load(response)
            return value if isinstance(value, dict) else None
    except Exception:
        return None


def _listening_ports_and_pids() -> dict[int, set[int]]:
    """Return LISTENING TCP ports/PIDs in the NetworkAutomation Web range.

    Query netstat once so OneClick never waits 1.5 seconds on every unused port.
    """
    found: dict[int, set[int]] = {}
    q = run_quiet(['netstat', '-ano', '-p', 'tcp'], timeout=8)
    if not q:
        return found
    for line in (q.stdout or '').splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != 'TCP' or parts[3].upper() != 'LISTENING':
            continue
        try:
            port = int(parts[1].rsplit(':', 1)[1])
            pid = int(parts[-1])
        except Exception:
            continue
        if 8765 <= port <= 8785 and pid > 0:
            found.setdefault(port, set()).add(pid)
    return found


def _service_state_pid() -> tuple[str, int]:
    q = run_quiet(['sc', 'queryex', SERVICE_NAME], timeout=6)
    text = (q.stdout or '') if q else ''
    state = 'MISSING' if '1060' in text else 'UNKNOWN'
    pid = 0
    for line in text.splitlines():
        up = line.upper()
        if 'STATE' in up:
            if 'STOPPED' in up:
                state = 'STOPPED'
            elif 'RUNNING' in up:
                state = 'RUNNING'
            elif 'STOP_PENDING' in up:
                state = 'STOP_PENDING'
            else:
                state = line.split(':', 1)[-1].strip() or state
        elif 'PID' in up and ':' in line:
            try:
                pid = int(line.split(':', 1)[1].strip())
            except Exception:
                pass
    return state, pid


def _stop_verified_manual_web() -> None:
    """Stop only live NetworkAutomation listeners, with bounded waits."""
    listeners = _listening_ports_and_pids()
    if not listeners:
        log('[STOP] No manual NetworkAutomation listener found in ports 8765-8785.')
        return

    victims: set[tuple[int, int, str]] = set()
    for port, pids in sorted(listeners.items()):
        live = _health(port)
        if not live or live.get('service') != 'networkautomation-operational-web':
            continue
        for pid in pids:
            victims.add((pid, port, str(live.get('version') or 'unknown')))

    if not victims:
        log('[STOP] No verified NetworkAutomation manual Web process found.')
        return

    for pid, port, version in sorted(victims):
        log(f'[STOP] Verified Web PID={pid}, port={port}, version={version}; forcing stop...')
        result = run_quiet(['taskkill', '/PID', str(pid), '/T', '/F'], timeout=8)
        if result and result.returncode != 0:
            log('[STOP] taskkill warning: ' + (result.stdout or '').strip())

    deadline = time.time() + 6
    while time.time() < deadline:
        remaining = []
        listeners = _listening_ports_and_pids()
        for port in listeners:
            live = _health(port)
            if live and live.get('service') == 'networkautomation-operational-web':
                remaining.append((port, live.get('version')))
        if not remaining:
            log('[STOP] Manual Web process stopped.')
            return
        time.sleep(.5)
    raise RuntimeError('Không dừng được Web cũ sau timeout: ' + repr(remaining))


def stop_old_modes() -> None:
    """Stop old launch modes with hard timeouts; never wait indefinitely."""
    log('[STOP 1/3] Checking Windows Service...')
    if os.name != 'nt':
        return

    state, pid = _service_state_pid()
    if state not in ('MISSING', 'STOPPED'):
        log(f'[STOP 1/3] Service state={state}, PID={pid or "?"}. Sending stop...')
        run_quiet(['sc', 'stop', SERVICE_NAME], timeout=8)
        deadline = time.time() + 8
        while time.time() < deadline:
            state, current_pid = _service_state_pid()
            if state in ('MISSING', 'STOPPED'):
                break
            if current_pid:
                pid = current_pid
            time.sleep(.5)
        if state not in ('MISSING', 'STOPPED') and pid > 0:
            log(f'[STOP 1/3] Service did not stop in time; forcing its PID {pid}...')
            run_quiet(['taskkill', '/PID', str(pid), '/T', '/F'], timeout=8)
            time.sleep(1)
            state, _ = _service_state_pid()
        log(f'[STOP 1/3] Service final state={state}.')
    else:
        log(f'[STOP 1/3] Service already {state}.')

    log('[STOP 2/3] Removing old scheduled autostart tasks...')
    for task_name in ('NetworkAutomation Web', 'NetworkAutomationWeb'):
        run_quiet(['schtasks', '/End', '/TN', task_name], timeout=5)
        run_quiet(['schtasks', '/Delete', '/F', '/TN', task_name], timeout=5)

    log('[STOP 3/3] Checking manual Web listeners...')
    _stop_verified_manual_web()
    log('[STOP] Completed.')
    time.sleep(.5)

def copytree_retry(src: Path, dst: Path, attempts: int = 8) -> None:
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            if dst.exists():
                raise FileExistsError(str(dst))
            shutil.copytree(src, dst, copy_function=shutil.copy2)
            return
        except Exception as exc:
            last = exc
            if dst.exists():
                try:
                    shutil.rmtree(dst)
                except Exception:
                    pass
            if attempt < attempts:
                time.sleep(min(0.5 * attempt, 3.0))
    raise RuntimeError(f'Không thể tạo runtime_data sau {attempts} lần thử: {last}') from last


def remove_tree_retry(path: Path, attempts: int = 8) -> None:
    if not path.exists():
        return
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            shutil.rmtree(path)
            return
        except Exception as exc:
            last = exc
            if attempt < attempts:
                time.sleep(min(0.5 * attempt, 3.0))
    raise RuntimeError(
        f'Không thể giải phóng {path}. Có tiến trình Windows đang giữ file. '
        f'OneClick đã dừng service/Web đã biết nhưng thư mục vẫn bị khóa: {last}'
    ) from last


def deploy_staging(staging: Path) -> None:
    """Commit a validated staging tree without directory rename.

    Windows/AV/Controlled Folder Access can deny directory renames even when file
    creation is allowed. Copying a validated snapshot is more compatible. If an
    invalid destination exists, it is backed up first and restored on failure.
    """
    backup: Path | None = None
    had_runtime = RUNTIME.exists()
    if had_runtime:
        backup = ROOT / ('runtime_backup_oneclick_' + time.strftime('%Y%m%d_%H%M%S'))
        suffix = 0
        while backup.exists():
            suffix += 1
            backup = ROOT / ('runtime_backup_oneclick_' + time.strftime('%Y%m%d_%H%M%S') + f'_{suffix}')
        log(f'[DATA] Backing up existing runtime before replacement: {backup}')
        shutil.copytree(RUNTIME, backup, copy_function=shutil.copy2)
        remove_tree_retry(RUNTIME)
    try:
        copytree_retry(staging, RUNTIME)
        ok, score, reason = valid_db(RUNTIME)
        if not ok:
            raise RuntimeError(f'Runtime copied but validation failed: {reason}')
        log(f'[DATA] Runtime committed safely. Indexed records={score[0]}')
    except Exception:
        try:
            if RUNTIME.exists():
                remove_tree_retry(RUNTIME)
        except Exception:
            pass
        if backup and backup.exists() and not RUNTIME.exists():
            try:
                copytree_retry(backup, RUNTIME)
                log('[ROLLBACK] Previous runtime restored.')
            except Exception as restore_exc:
                log(f'[ROLLBACK WARNING] Could not restore automatically: {restore_exc}')
                log(f'[ROLLBACK WARNING] Your preserved runtime backup is: {backup}')
        raise


def ensure_runtime() -> Path:
    ok, score, _ = valid_db(RUNTIME)
    if ok:
        log(f'[DATA] Existing runtime_data OK ({score[0]} indexed records).')
        return RUNTIME

    source, rows = choose_best_source()
    log('[DATA] Auto-detect report:')
    for row in rows:
        log(f"  - {row['root']} | {'OK' if row['ok'] else 'skip'} | records={row['records']} | {row['reason']}")
    if source is None:
        raise RuntimeError(
            'Không tìm thấy dữ liệu NetworkAutomation cũ. OneClick KHÔNG tạo runtime rỗng. '
            'Giữ thư mục Web cũ trên máy rồi chạy lại.'
        )
    if source.resolve() == RUNTIME.resolve():
        raise RuntimeError('runtime_data hiện có nhưng database không hợp lệ; không tự ghi đè dữ liệu lỗi.')

    log(f'[DATA] Selected source automatically: {source}')
    from IMPORT_APP_DATA import prepare_snapshot

    staging = Path(tempfile.mkdtemp(prefix='.oneclick591-', dir=ROOT))
    try:
        result = prepare_snapshot(source, staging, RUNTIME.resolve())
        ok, _, reason = valid_db(staging)
        if not ok:
            raise RuntimeError(f'Snapshot validation failed before commit: {reason}')
        deploy_staging(staging)
        log(f"[DATA] Import OK. Counts: {result.get('counts', {})}")
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return RUNTIME


def run(cmd: list[str | Path], *, check: bool = True, timeout: int = 600) -> subprocess.CompletedProcess:
    log('[RUN] ' + ' '.join(str(x) for x in cmd))
    p = subprocess.run([str(x) for x in cmd], cwd=str(ROOT), text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f'Command failed ({p.returncode}): {cmd[0]}')
    return p


def ensure_venv_and_dependencies() -> Path:
    vpy = ROOT / '.venv' / 'Scripts' / 'python.exe'
    if not vpy.is_file():
        py = shutil.which('py') or shutil.which('python')
        if not py:
            raise RuntimeError('Không tìm thấy Python 3. Hãy cài Python rồi chạy lại OneClick.')
        cmd = [py, '-3', '-m', 'venv', str(ROOT / '.venv')] if Path(py).name.lower().startswith('py') else [py, '-m', 'venv', str(ROOT / '.venv')]
        run(cmd)
    run([vpy, 'VERIFY_RELEASE.py'])
    run([vpy, '-m', 'pip', 'install', '-r', 'requirements.txt', '-r', 'requirements-web.txt'], timeout=1200)
    run([vpy, '-m', 'pip', 'check'])
    return vpy


def _same_python(a: Path, b: Path) -> bool:
    try:
        return os.path.normcase(str(a.resolve())) == os.path.normcase(str(b.resolve()))
    except Exception:
        return os.path.normcase(str(a)) == os.path.normcase(str(b))


def relaunch_under_venv(vpy: Path) -> int:
    """Continue OneClick inside the venv that owns the installed dependencies.

    A newly created venv does not change sys.executable of the already-running
    bootstrap process.  Importing IMPORT_APP_DATA in that old interpreter can
    therefore fail with `No module named cryptography` even though pip just
    installed cryptography successfully into .venv.
    """
    env = os.environ.copy()
    env['NETWORKAUTOMATION_ONECLICK_VENV_READY'] = '1'
    log(f'[BOOTSTRAP] Restarting OneClick with isolated Python: {vpy}')
    p = subprocess.run([str(vpy), str(Path(__file__).resolve())], cwd=str(ROOT), env=env)
    return int(p.returncode)


def install_service(vpy: Path) -> None:
    run([vpy, 'SERVICE_INSTALLER.py'], timeout=900)


def wait_for_web(expected: str, timeout: int = 45) -> int | None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.time() + timeout
    while time.time() < deadline:
        for port in range(8765, 8786):
            try:
                with opener.open(f'http://127.0.0.1:{port}/api/health', timeout=1.0) as response:
                    obj = json.load(response)
                if isinstance(obj, dict) and obj.get('service') == 'networkautomation-operational-web' and obj.get('version') == expected:
                    return port
            except Exception:
                pass
        time.sleep(.75)
    return None


def start_detached_web(vpy: Path) -> None:
    """Last-resort local launcher so a service problem does not lock the user out."""
    flags = 0
    for name in ('DETACHED_PROCESS', 'CREATE_NEW_PROCESS_GROUP', 'CREATE_NO_WINDOW'):
        flags |= int(getattr(subprocess, name, 0))
    subprocess.Popen(
        [str(vpy), str(ROOT / 'run_web.py'), '--no-browser'],
        cwd=str(ROOT),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=flags, close_fds=True,
    )


def main() -> int:
    if os.name != 'nt':
        print('Windows only.')
        return 2
    log('=== NetworkAutomation Cybersecurity UI 6.9.0 QA HOTFIX16 LAN DISCOVERY FAST/ACCURATE + INTEGRITY FIX ===')
    log('OneClick: stop -> dependencies -> re-enter venv -> preserve/import runtime -> repair Admin login/MFA -> verify -> resilient service -> Web readiness.')

    expected_vpy = ROOT / '.venv' / 'Scripts' / 'python.exe'
    venv_ready = os.environ.get('NETWORKAUTOMATION_ONECLICK_VENV_READY') == '1'

    if not venv_ready:
        stop_old_modes()

        # Bootstrap dependencies first.  If this process started from system
        # Python, installing into .venv does NOT make those packages importable
        # by the current interpreter.  Re-enter OneClick under .venv before any
        # runtime import that can load cryptography.
        vpy = ensure_venv_and_dependencies()
        if not _same_python(Path(sys.executable), vpy):
            return relaunch_under_venv(vpy)
    else:
        vpy = expected_vpy
        if not vpy.is_file():
            raise RuntimeError('Bootstrap marker is set but .venv Python is missing.')
        if not _same_python(Path(sys.executable), vpy):
            raise RuntimeError('OneClick bootstrap did not restart under the expected .venv Python.')
        log(f'[BOOTSTRAP] Running inside isolated Python: {sys.executable}')

    ensure_runtime()

    # This repair release performs the owner recovery before any diagnostic that
    # requires an enabled Admin.
    log('\n[AUTH] Repairing local Admin access before authentication diagnostics...')
    run([vpy, 'ADMIN_RECOVERY_ONECLICK.py'])
    run([vpy, 'RESET_LOGIN_MFA_SAFE.py'])
    run([vpy, 'AUTH_DIAGNOSTIC.py'])

    expected = (ROOT / 'WEB_VERSION.txt').read_text(encoding='utf-8').strip()
    service_ok = True
    try:
        install_service(vpy)
    except Exception as exc:
        service_ok = False
        log(f'[SERVICE WARNING] Windows Service repair failed: {exc}')
        log('[SERVICE WARNING] Starting a safe detached local Web fallback so you can still use the application now.')

    port = wait_for_web(expected, timeout=12 if service_ok else 3)
    if port is None:
        start_detached_web(vpy)
        port = wait_for_web(expected, timeout=45)
    if port is None:
        raise RuntimeError('Backend did not become ready on ports 8765-8785. Data was preserved; inspect service_logs and logs.')

    url = f'http://127.0.0.1:{port}'
    try:
        subprocess.Popen(['cmd', '/c', 'start', '', url], cwd=str(ROOT))
        log(f'[OPEN] Browser request sent: {url}')
    except Exception as exc:
        log(f'[OPEN] Browser auto-open warning: {exc}')

    log('\nONECLICK OK' if service_ok else '\nONECLICK OK (DEGRADED: Web running, Windows Service needs later repair)')
    log(f'Web ready: {url}')
    log('Dữ liệu cũ, database và credential key đã được giữ nguyên.')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print('\nONECLICK FAILED:', exc)
        print('Database/key KHÔNG bị reset. Nếu có backup, OneClick đã giữ nó để rollback.')
        raise SystemExit(1)
