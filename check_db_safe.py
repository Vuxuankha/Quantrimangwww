"""Offline DB triage. SQLite only opens isolated WORK COPIES, never source files.

No project imports, migration, reset, repair, .recover, config change or network call.
Stop all database writers before running. Stat/hash checks detect some concurrent
changes, but cannot make a file copy atomic while an uncooperative writer runs.
Raw DB families are preserved first; report files contain metadata/counts only.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid

VERSION = '1.0'
SIDECARS = ('', '-wal', '-shm', '-journal')
COUNT_TABLES = ('devices', 'network_devices', 'ip_mac_inventory', 'app_users',
                'alerts', 'health_samples', 'autoip_targets', 'autoip_runs',
                'autoip_steps', 'config_backups', 'server_monitor_targets')
MAX_BUNDLE = 512 * 1024 * 1024
MAX_TOTAL = 1536 * 1024 * 1024  # Raw + working copies need up to twice this space.
MAX_BACKUPS = 20
MAX_SCAN_FILES = 5000


def utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def stat_family(db: Path) -> dict:
    result = {}
    for suffix in SIDECARS:
        p = Path(str(db) + suffix)
        if p.is_symlink():
            raise ValueError('Symlink DB/sidecar refused: ' + str(p))
        if p.exists():
            if not p.is_file():
                raise ValueError('Not a regular file: ' + str(p))
            s = p.stat()
            result[suffix] = {'bytes': s.st_size, 'mtime_ns': s.st_mtime_ns,
                              'ctime_ns': s.st_ctime_ns, 'inode': s.st_ino}
    if '' not in result:
        raise FileNotFoundError('Database does not exist: ' + str(db))
    return result


def resolve_selected(project: Path, env: dict | None = None) -> tuple[Path, dict]:
    """Match run_web.py selection precedence, without importing it."""
    env = os.environ if env is None else env
    project = project.resolve()
    override = env.get('NETWORK_AUTOMATION_DATA_DIR', '')
    cfg = project / 'data_location.json'
    info = {'project_dir': str(project), 'environment_override_present': bool(override),
            'config_file_present': cfg.is_file()}
    if override:
        selected = Path(override).expanduser()
        info['selected_by'] = 'NETWORK_AUTOMATION_DATA_DIR'
        if cfg.is_file():
            info['warning'] = 'Environment variable overrides data_location.json.'
    elif cfg.is_file():
        data = json.loads(cfg.read_text(encoding='utf-8-sig'))
        selected = Path(data['data_dir'])
        info['selected_by'] = 'data_location.json'
    else:
        selected = project
        info['selected_by'] = 'project directory (no override or config)'
    if not selected.is_absolute():
        selected = project / selected
        info['relative_path_warning'] = True
    selected = selected.resolve()
    info['selected_data_dir'] = str(selected)
    info['selected_database'] = str(selected / 'database' / 'network_automation.db')
    info['credential_key_present'] = (selected / 'database' / '.credential.key').is_file()
    return selected, info


def preserve_family(db: Path, output: Path, index: int, budget: list[int]) -> tuple[Path, dict]:
    before = stat_family(db)
    size = sum(v['bytes'] for v in before.values())
    if size > MAX_BUNDLE or budget[0] + size > MAX_TOTAL:
        raise ValueError('Copy size limit exceeded; no source file changed.')
    if shutil.disk_usage(output).free < size * 2 + 64 * 1024 * 1024:
        raise ValueError('Not enough free space for raw + work copies.')
    raw_dir = output / 'PRIVATE_EVIDENCE_DO_NOT_UPLOAD' / f'{index:03d}'
    work_dir = output / 'WORK_COPIES' / f'{index:03d}'
    raw_dir.mkdir(parents=True, exist_ok=False)
    work_dir.mkdir(parents=True, exist_ok=False)
    files = []
    for suffix, meta in before.items():
        src = Path(str(db) + suffix)
        dst = raw_dir / src.name
        with src.open('rb') as inp, dst.open('xb') as out:
            shutil.copyfileobj(inp, out, length=1024 * 1024)
            out.flush()
            os.fsync(out.fileno())
        copied_hash = hash_file(dst)
        if copied_hash != hash_file(src):
            raise RuntimeError('SOURCE_CHANGED: stop all writers and repeat; partial copy retained.')
        files.append({'suffix': suffix, 'bytes': meta['bytes'], 'sha256': copied_hash})
    if stat_family(db) != before:
        raise RuntimeError('SOURCE_CHANGED: DB family changed while copying; do not use this copy.')
    # Keep the evidence byte-for-byte untouched. Journal recovery, if needed,
    # is allowed only by SQLite on this second copy, never on the source.
    for item in files:
        src = raw_dir / (db.name + item['suffix'])
        dst = work_dir / src.name
        shutil.copyfile(src, dst)
    budget[0] += size
    return work_dir / db.name, {'files': files, 'source_metadata': before,
                                'raw_copy': str(raw_dir / db.name)}


def probe_copy(path: Path, timeout: float = 15) -> dict:
    """Only use with a WORK COPY. Internal subprocess entry point."""
    if not path.is_file():
        return {'status': 'MISSING', 'structural_ok': False}
    if path.stat().st_size == 0:
        return {'status': 'EMPTY_FILE', 'structural_ok': False}
    with path.open('rb') as f:
        if f.read(16) != b'SQLite format 3\x00':
            return {'status': 'NOT_SQLITE_HEADER', 'structural_ok': False}
    c = None
    out = {'structural_ok': False}
    deadline = time.monotonic() + timeout
    try:
        # rw deliberately opens an EXISTING WORK COPY: supports hot-journal
        # recovery on the copy and cannot silently create a missing source DB.
        c = sqlite3.connect(path.resolve().as_uri() + '?mode=rw', uri=True, timeout=1)
        c.text_factory = lambda b: b.decode('utf-8', errors='replace')
        c.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        try:
            c.enable_load_extension(False)
        except AttributeError:
            pass
        c.execute('PRAGMA trusted_schema=OFF')
        c.execute('PRAGMA mmap_size=0')
        c.execute('PRAGMA query_only=ON')
        result = [str(row[0])[:1000] for row in c.execute('PRAGMA integrity_check(30)')]
        out['integrity_check'] = result
        if result != ['ok']:
            out['status'] = 'INTEGRITY_FAILED'
            return out
        out['structural_ok'] = True
        names = {row[0] for row in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        out['networkautomation_schema'] = bool({'devices', 'network_devices'} & names)
        out['counts'] = {}
        # Only allowlisted table counts; no user names, IPs, secrets, config
        # records, arbitrary views, triggers or app functions are evaluated.
        for table in COUNT_TABLES:
            if table in names:
                out['counts'][table] = c.execute('SELECT COUNT(*) FROM "' + table + '"').fetchone()[0]
        fk = c.execute('PRAGMA foreign_key_check').fetchmany(21)
        out['foreign_key_violations'] = min(len(fk), 20)
        out['foreign_key_result_truncated'] = len(fk) > 20
        out['status'] = ('STRUCTURE_OK' if out['networkautomation_schema'] else 'OTHER_SQLITE_DATABASE')
        out['candidate_for_manual_review'] = out['networkautomation_schema'] and not fk
        return out
    except sqlite3.Error as exc:
        code = getattr(exc, 'sqlite_errorcode', None)
        basecode = (code & 255) if isinstance(code, int) else None
        out.update({'status': 'SQLITE_ERROR', 'error': str(exc)[:1000],
                    'sqlite_errorname': getattr(exc, 'sqlite_errorname', None)})
        if basecode == sqlite3.SQLITE_CORRUPT:
            out['status'] = 'SQLITE_CORRUPT'
        elif basecode == sqlite3.SQLITE_NOTADB:
            out['status'] = 'NOT_A_DATABASE'
        elif basecode == sqlite3.SQLITE_INTERRUPT:
            out['status'] = 'CHECK_TIMEOUT'
        out['candidate_for_manual_review'] = False
        return out
    finally:
        if c is not None:
            c.close()


def isolated_probe(path: Path, timeout: float) -> dict:
    flags = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}
    try:
        p = subprocess.run([sys.executable, '-I', str(Path(__file__).resolve()),
                            '--_probe', str(path), '--timeout', str(timeout)],
                           capture_output=True, text=True, encoding='utf-8',
                           errors='replace', timeout=timeout + 4, **flags)
        if p.returncode:
            return {'status': 'PROBE_PROCESS_FAILED', 'structural_ok': False,
                    'exit_code': p.returncode}
        return json.loads(p.stdout)
    except subprocess.TimeoutExpired:
        return {'status': 'CHECK_TIMEOUT', 'structural_ok': False}
    except (OSError, ValueError):
        return {'status': 'PROBE_PROCESS_FAILED', 'structural_ok': False}


def discover_backups(data: Path, project: Path) -> tuple[list[Path], list[str]]:
    roots = [data / 'database' / 'db_backups', data / 'database' / 'web_preupgrade_backups',
             data / 'backups']
    warnings = []
    seen = set()
    candidates = []
    visited = 0
    for root in roots:
        if not root.is_dir() or root.is_symlink():
            continue
        for folder, dirs, files in os.walk(root, followlinks=False):
            rel_depth = len(Path(folder).relative_to(root).parts)
            dirs[:] = [d for d in sorted(dirs)
                       if rel_depth < 6 and not (Path(folder) / d).is_symlink()]
            for name in sorted(files):
                visited += 1
                if visited > MAX_SCAN_FILES:
                    warnings.append('Backup listing partial: scan limit reached.')
                    return candidates[:MAX_BACKUPS], warnings
                p = Path(folder) / name
                if p.suffix.lower() not in ('.db', '.sqlite', '.sqlite3') or p.is_symlink():
                    continue
                key = str(p.resolve()).casefold() if os.name == 'nt' else str(p.resolve())
                if key not in seen:
                    candidates.append(p.resolve())
                    seen.add(key)
    # Mtime is presentation order only; NEVER a restore decision.
    candidates.sort(key=lambda p: p.stat().st_mtime_ns, reverse=True)
    if len(candidates) > MAX_BACKUPS:
        warnings.append(f'Only {MAX_BACKUPS} of {len(candidates)} discovered backups checked; report is partial.')
    return candidates[:MAX_BACKUPS], warnings


def render_report(report: dict) -> str:
    s = ['NETWORKAUTOMATION - BAO CAO KIEM TRA DB (KHONG SUA DB GOC)',
         'UTC: ' + report['created_utc'], 'Tool: ' + VERSION,
         'Python: ' + report['python'], 'SQLite: ' + report['sqlite'], '',
         'Tat ca SQLite checks chi chay tren WORK_COPIES.',
         'Da yeu cau dung Web, desktop va cac dich vu monitor truoc khi copy.',
         'Tool khong doi cau hinh, khong reset tai khoan, khong restore tu dong.', '']
    for k, v in report.get('selection', {}).items():
        s.append(f'{k}: {v}')
    if report.get('selection_error'):
        s.append('SELECTION_ERROR: ' + report['selection_error'])
    s += ['', 'KET QUA:']
    for r in report['databases']:
        s += ['', f"[{r['index']}] {r['kind']}", 'Nguon: ' + r['source'],
              'Trang thai: ' + r.get('status', 'UNKNOWN')]
        if r.get('error'):
            s.append('Loi: ' + r['error'])
        if 'integrity_check' in r:
            s.append('integrity_check: ' + ' | '.join(r['integrity_check']))
        if r.get('counts'):
            s.append('So ban ghi: ' + ', '.join(f'{t}={n}' for t, n in r['counts'].items()))
        if 'foreign_key_violations' in r:
            s.append('Loi foreign key: ' + str(r['foreign_key_violations']) +
                     ('+' if r.get('foreign_key_result_truncated') else ''))
        for f in r.get('preserved', {}).get('files', []):
            s.append(f"File {f['suffix'] or '(main DB)'}: {f['bytes']} bytes; SHA256={f['sha256']}")
        if r.get('candidate_for_manual_review'):
            s.append('Cau truc hop le de DOI CHIEU THU CONG; chua xac nhan du lieu moi/day du, key hay dang nhap.')
    s += ['', 'CANH BAO:'] + report.get('warnings', [])
    s += ['', 'KHONG tu dong chon backup moi nhat/lon nhat.',
          'STRUCTURE_OK khong bao dam schema/day du nghiep vu, credential key hay thoi diem du lieu.',
          'Khong xoa WAL/SHM/journal, khong chay VACUUM/REINDEX/reset tren DB goc.',
          'CHI GUI BAO_CAO_DB.txt de chan doan. Khong gui PRIVATE_EVIDENCE_DO_NOT_UPLOAD,',
          'WORK_COPIES, .credential.key, known_hosts hay file DB neu chua kiem tra thong tin nhay cam.',
          'Chua co thao tac phuc hoi nao duoc thuc hien.']
    return '\n'.join(s) + '\n'


def run_diagnostics(project: Path, output: Path, timeout: float = 15) -> dict:
    project = project.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'version': VERSION, 'created_utc': utc(), 'python': sys.version.split()[0],
              'sqlite': sqlite3.sqlite_version, 'databases': [], 'warnings': []}
    try:
        data, selection = resolve_selected(project)
        report['selection'] = selection
        active = data / 'database' / 'network_automation.db'
        backups, warnings = discover_backups(data, project)
        report['warnings'].extend(warnings)
        candidates = [('SELECTED_DATABASE', active)] + [('BACKUP', p) for p in backups]
        budget = [0]
        for i, (kind, source) in enumerate(candidates, 1):
            print(f'Kiem tra {i}/{len(candidates)}: {source}', flush=True)
            r = {'index': i, 'kind': kind, 'source': str(source)}
            try:
                work, manifest = preserve_family(source, output, i, budget)
                r['preserved'] = manifest
                r.update(isolated_probe(work, timeout))
                # Catch further source changes without querying the original DB.
                if stat_family(source) != manifest['source_metadata']:
                    r['status'] = 'SOURCE_CHANGED'
                    r['candidate_for_manual_review'] = False
                    report['warnings'].append('A database writer appears to still be active; stop it and recheck.')
            except (OSError, ValueError, RuntimeError) as exc:
                r.update({'status': 'COPY_OR_INPUT_ERROR', 'error': str(exc)[:1000],
                          'candidate_for_manual_review': False})
            report['databases'].append(r)
            # Leave a usable report if a later check is interrupted.
            save_report(report, output)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        report['selection_error'] = str(exc)[:1000]
    save_report(report, output)
    return report


def save_report(report: dict, output: Path) -> None:
    (output / 'BAO_CAO_DB.txt').write_text(render_report(report), encoding='utf-8-sig')
    (output / 'BAO_CAO_DB.json').write_text(json.dumps(report, ensure_ascii=True, indent=2), encoding='utf-8')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--timeout', type=float, default=15)
    parser.add_argument('--_probe', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args._probe:
        print(json.dumps(probe_copy(args._probe, max(1, min(args.timeout, 60))), ensure_ascii=True))
        return 0
    project = args.project.resolve()
    if not (project / 'run_web.py').is_file():
        print('Hay chep KIEM_TRA_DB.bat va check_db_safe.py canh START_WEB.bat / run_web.py.')
        return 2
    try:
        _, info = resolve_selected(project)
        print('DB dang duoc chon:', info['selected_database'])
        print('Nguon cau hinh:', info['selected_by'])
    except Exception as exc:
        print('Khong doc duoc cau hinh:', exc)
    print('\nDUNG Web, desktop, Auto IP, monitor agent/service va lich tac vu truoc.')
    print('KHONG xoa DB, WAL, SHM, journal hay .credential.key.')
    print('Tool chi copy de kiem tra, khong sua DB goc / khong restore / khong reset.')
    answer = input('Da dung tat ca chuong trinh ghi DB? Go DA DUNG de tiep tuc: ').strip()
    if answer.upper() != 'DA DUNG':
        print('Da huy. Khong thay doi du lieu.')
        return 2
    output = args.output or project / ('DB_CHECK_' + datetime.now().strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:6])
    report = run_diagnostics(project, output.resolve(), max(1, min(args.timeout, 60)))
    print('\nDA TAO BAO CAO:', output / 'BAO_CAO_DB.txt')
    print('Chi gui file BAO_CAO_DB.txt. Khong gui thu muc evidence/work/key.')
    print('DB goc va cau hinh KHONG bi thay the. Chua phuc hoi du lieu.')
    if os.name == 'nt':
        try:
            os.startfile(str((output / 'BAO_CAO_DB.txt').resolve()))
        except OSError:
            pass
    return 1 if report.get('selection_error') else 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print('\nDa dung kiem tra. Cac ban sao tao ra duoc giu nguyen; DB goc khong bi thay the.')
        raise SystemExit(130)
    except Exception as exc:
        print('CHECK FAILED:', type(exc).__name__, str(exc))
        raise SystemExit(1)
