from __future__ import annotations
import json, os, shutil, socket, subprocess, sys, time, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SERVICE = "NetworkAutomationWeb"
APP_PY = ROOT / ".venv" / "Scripts" / "python.exe"
CONFIG = ROOT / "service_config.json"
LOGDIR = ROOT / "service_logs"


def run(cmd, *, check=False, timeout=180, capture=True, cwd=ROOT):
    p = subprocess.run([str(x) for x in cmd], cwd=str(cwd), text=True,
                       stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.STDOUT if capture else None,
                       timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f"COMMAND_FAILED({p.returncode}): {' '.join(map(str,cmd))}\n{p.stdout or ''}")
    return p


def host_python() -> Path:
    # Prefer the base interpreter that created the Web venv. A real/base Python
    # is a more reliable pywin32 service host than pythonservice inside a venv.
    if APP_PY.is_file():
        q = run([APP_PY, "-c", "import sys; print(sys.base_prefix)"])
        if q.returncode == 0 and q.stdout.strip():
            p = Path(q.stdout.strip()) / "python.exe"
            if p.is_file():
                return p.resolve()
    py = shutil.which("py")
    if py:
        q = run([py, "-3", "-c", "import sys; print(sys.executable)"])
        if q.returncode == 0:
            p = Path(q.stdout.strip())
            if p.is_file():
                return p.resolve()
    raise RuntimeError("Không tìm thấy Python hệ thống để làm Windows Service host.")


def ensure_app_python():
    if not APP_PY.is_file():
        raise RuntimeError("Không thấy .venv\\Scripts\\python.exe. Hãy chạy INSTALL_WEB.bat trước.")
    q = run([APP_PY, "-c", "import uvicorn; print('APP_PY_OK')"])
    if q.returncode:
        raise RuntimeError("Python của Web thiếu dependency. Hãy chạy INSTALL_WEB.bat trước.\n" + (q.stdout or ""))


def ensure_pywin32(host: Path):
    q = run([host, "-c", "import win32serviceutil,win32service,win32event,servicemanager; print('PYWIN32_OK')"])
    if q.returncode == 0:
        return
    print("Đang cài pywin32 cho Python service host...")
    run([host, "-m", "pip", "install", "--upgrade", "pywin32>=306"], check=True, timeout=300, capture=False)
    q = run([host, "-c", "import win32serviceutil,win32service,win32event,servicemanager; print('PYWIN32_OK')"])
    if q.returncode:
        raise RuntimeError("Cài pywin32 xong nhưng vẫn không import được.\n" + (q.stdout or ""))

    # Best-effort pywin32 system registration. On some Python installations it
    # is unnecessary; on others it fixes pythonservice/DLL discovery.
    scripts = host.parent / "Scripts"
    post = scripts / "pywin32_postinstall.py"
    if post.is_file():
        run([host, post, "-install"], timeout=120, capture=False)


def install_import_path(host: Path):
    code = "import site; p=site.getsitepackages(); print(p[0] if p else site.getusersitepackages())"
    q = run([host, "-c", code], check=True)
    site_dir = Path(q.stdout.strip())
    site_dir.mkdir(parents=True, exist_ok=True)
    pth = site_dir / "networkautomation_web_service.pth"
    pth.write_text(str(ROOT.resolve()) + "\n", encoding="utf-8")
    # Prove import works when current directory is System32-like, not app root.
    verify = (
        "import os, pathlib; os.chdir(r'C:\\Windows\\System32'); "
        "import web_service50; print(pathlib.Path(web_service50.__file__).resolve())"
    )
    q = run([host, "-c", verify])
    if q.returncode or str(ROOT.resolve()).lower() not in (q.stdout or "").lower():
        raise RuntimeError("Service host không import được web_service50 từ ngoài thư mục Web.\n" + (q.stdout or ""))
    return pth


def ports_in_use():
    out=[]
    for port in range(8765,8786):
        s=socket.socket(); s.settimeout(.12)
        try:
            if s.connect_ex(("127.0.0.1",port)) == 0: out.append(port)
        finally: s.close()
    return out


def write_config(host: Path):
    data = {
        "python_exe": str(APP_PY.resolve()),
        "service_host_python": str(host.resolve()),
        "root": str(ROOT.resolve()),
        "created_at": time.time(),
    }
    tmp=CONFIG.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, indent=2), encoding='utf-8')
    os.replace(tmp, CONFIG)


def stop_remove(host: Path):
    run(["sc", "stop", SERVICE], timeout=30)
    time.sleep(1)
    run([host, ROOT / "web_service50.py", "remove"], timeout=60)
    run(["sc", "delete", SERVICE], timeout=30)
    # Wait for SCM deletion to settle.
    for _ in range(20):
        q=run(["sc","query",SERVICE],timeout=10)
        if q.returncode != 0: return
        time.sleep(.5)


def install_start(host: Path):
    q = run([host, ROOT / "web_service50.py", "--startup", "auto", "install"], timeout=90)
    if q.returncode:
        raise RuntimeError("Không cài được service.\n" + (q.stdout or ""))
    # Secondary recovery layer: if the service wrapper itself stops after its
    # bounded child-restart budget, let Windows SCM restart the service.
    run(["sc", "failure", SERVICE, "reset=", "86400", "actions=", "restart/5000/restart/15000/restart/60000"], timeout=30)
    run(["sc", "failureflag", SERVICE, "1"], timeout=30)
    q = run(["sc", "start", SERVICE], timeout=30)
    # sc start can return 1053 before query settles; continue to poll.
    print((q.stdout or "").strip())
    deadline=time.time()+35
    last=""
    while time.time()<deadline:
        s=run(["sc","query",SERVICE],timeout=10)
        last=s.stdout or ""
        if "RUNNING" in last:
            return True,last
        if "STOPPED" in last and time.time()>deadline-28:
            # If it stopped after a few seconds, no need to wait full timeout.
            time.sleep(2)
            s2=run(["sc","query",SERVICE],timeout=10)
            if "STOPPED" in (s2.stdout or ""): return False,s2.stdout or last
        time.sleep(1)
    return False,last


def show_failure():
    print("\n===== SERVICE STATUS =====")
    print(run(["sc","query",SERVICE]).stdout or "")
    print("===== SERVICE CONFIG =====")
    print(run(["sc","qc",SERVICE]).stdout or "")
    for p in (LOGDIR/"web_service_bootstrap.log", LOGDIR/"web_service.log", LOGDIR/"web_service_child.log"):
        print(f"===== {p.name} =====")
        if p.is_file():
            try:
                lines=p.read_text(encoding='utf-8',errors='replace').splitlines()[-120:]
                print("\n".join(lines))
            except Exception as e: print(repr(e))
        else: print("(chưa tạo log)")
    print("===== WINDOWS APPLICATION ERRORS (recent) =====")
    q=run(["wevtutil","qe","Application","/q:*[System[(Level=1 or Level=2)]]","/f:text","/c:20"],timeout=30)
    print((q.stdout or "")[-12000:])


def main():
    if os.name != 'nt':
        print('Windows only.'); return 2
    LOGDIR.mkdir(exist_ok=True)
    ensure_app_python()
    host=host_python()
    print("Web Python     :", APP_PY.resolve())
    print("Service host   :", host)
    ensure_pywin32(host)
    pth=install_import_path(host)
    print("Service import :", pth)
    existing=ports_in_use()
    if existing:
        print("CẢNH BÁO: đang có Web/tiến trình dùng cổng:", ", ".join(map(str,existing)))
        print("Hãy bảo đảm Web chạy tay/Task Scheduler cũ đã dừng để tránh chạy trùng.")
    write_config(host)
    stop_remove(host)
    write_config(host)  # remove command may not preserve app config in older wrapper
    ok,status=install_start(host)
    if not ok:
        print("\nSERVICE START FAILED.")
        print(status)
        show_failure()
        print("\nDữ liệu runtime_data/database/key KHÔNG bị reset.")
        return 1
    # SCM RUNNING is not enough: prove the child HTTP backend is this release, not a stale process.
    expected=(ROOT/'WEB_VERSION.txt').read_text(encoding='utf-8').strip()
    health=None; health_port=None
    deadline=time.time()+35
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while time.time()<deadline and health is None:
        for port in range(8765,8786):
            try:
                with opener.open(f'http://127.0.0.1:{port}/api/health',timeout=1.2) as response:
                    obj=json.load(response)
                if isinstance(obj,dict) and obj.get('service')=='networkautomation-operational-web' and obj.get('version')==expected:
                    health=obj;health_port=port;break
            except Exception:
                pass
        if health is None: time.sleep(1)
    if health is None:
        print(f'\nSERVICE RUNNING nhưng không tìm thấy backend {expected} trên cổng 8765-8785.')
        show_failure()
        return 1
    print("\nSERVICE OK - NetworkAutomationWeb is RUNNING.")
    print(f"Backend verified: {expected} on http://127.0.0.1:{health_port}")
    print("Web data và credential được giữ nguyên.")
    return 0

if __name__=='__main__':
    raise SystemExit(main())
