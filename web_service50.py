"""Robust Windows Service wrapper for NetworkAutomation Web 5.0.

The service host used by pywin32 is not necessarily python.exe.  Therefore the
actual interpreter used by the Web virtualenv is captured at install time in
service_config.json and used explicitly for the child process.
"""
from __future__ import annotations
import json, os, subprocess, sys, time, traceback
from pathlib import Path

ROOT=Path(__file__).resolve().parent
CONFIG=ROOT/'service_config.json'
LOG_DIR=ROOT/'service_logs'
try:
    LOG_DIR.mkdir(exist_ok=True)
    with (LOG_DIR/'web_service_bootstrap.log').open('a',encoding='utf-8',errors='replace') as _f:
        _f.write(time.strftime('%Y-%m-%d %H:%M:%S')+' module imported by '+sys.executable+' cwd='+os.getcwd()+'\n')
except Exception:
    pass
SERVICE_NAME='NetworkAutomationWeb'
SERVICE_DISPLAY='NetworkAutomation Web 5.0'
SERVICE_DESCRIPTION='NetworkAutomation production Web and monitoring API.'

try:
    import win32event, win32service, win32serviceutil, servicemanager
except Exception:
    win32event=win32service=win32serviceutil=servicemanager=None


def _append(name:str,message:str):
    try:
        LOG_DIR.mkdir(exist_ok=True)
        with (LOG_DIR/name).open('a',encoding='utf-8',errors='replace') as f:
            f.write(time.strftime('%Y-%m-%d %H:%M:%S')+' '+message.rstrip()+'\n')
    except Exception:
        pass


def _config():
    obj=json.loads(CONFIG.read_text(encoding='utf-8'))
    exe=Path(obj['python_exe']).resolve();root=Path(obj['root']).resolve()
    if root!=ROOT.resolve():raise RuntimeError('SERVICE_ROOT_MISMATCH')
    if not exe.is_file():raise RuntimeError('SERVICE_PYTHON_MISSING:'+str(exe))
    return exe

if win32serviceutil:
    class NetworkAutomationWebService(win32serviceutil.ServiceFramework):
        _svc_name_=SERVICE_NAME
        _svc_display_name_=SERVICE_DISPLAY
        _svc_description_=SERVICE_DESCRIPTION
        def __init__(self,args):
            super().__init__(args);self.stop_event=win32event.CreateEvent(None,0,0,None);self.child=None;self.stream=None
        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.stop_event)
            if self.child and self.child.poll() is None:self.child.terminate()
        def SvcDoRun(self):
            try:self.ReportServiceStatus(win32service.SERVICE_START_PENDING, waitHint=30000)
            except Exception:pass
            os.chdir(ROOT);_append('web_service.log','service starting host='+sys.executable+' cwd='+os.getcwd())
            try:
                python_exe=_config()
                env=os.environ.copy();env['NA_RUN_MODE']='windows-service';env['PYTHONUNBUFFERED']='1'
                LOG_DIR.mkdir(exist_ok=True)
                child_log=LOG_DIR/'web_service_child.log'
                self.stream=child_log.open('a',encoding='utf-8',errors='replace',buffering=1)
                flags=getattr(subprocess,'CREATE_NO_WINDOW',0)
                cmd=[str(python_exe),'-u',str(ROOT/'run_web.py'),'--no-browser','--service-child']
                _append('web_service.log','child python: '+str(python_exe))
                try:self.ReportServiceStatus(win32service.SERVICE_RUNNING)
                except Exception:pass
                restart_count=0
                started_at=time.time()
                while True:
                    self.stream.write('\n--- service child start '+time.strftime('%Y-%m-%d %H:%M:%S')+f' restart={restart_count} ---\n')
                    self.child=subprocess.Popen(cmd,cwd=str(ROOT),env=env,stdout=self.stream,stderr=subprocess.STDOUT,creationflags=flags)
                    servicemanager.LogInfoMsg(SERVICE_DISPLAY+' started child PID '+str(self.child.pid))
                    child_started=time.time()
                    stop_requested=False
                    while True:
                        rc=win32event.WaitForSingleObject(self.stop_event,1000)
                        if rc==win32event.WAIT_OBJECT_0:
                            stop_requested=True
                            break
                        code=self.child.poll()
                        if code is not None:
                            break
                    if stop_requested:
                        if self.child.poll() is None:
                            self.child.terminate()
                            try:self.child.wait(timeout=20)
                            except subprocess.TimeoutExpired:self.child.kill();self.child.wait(timeout=5)
                        break
                    code=self.child.poll()
                    uptime=time.time()-child_started
                    _append('web_service.log',f'child exited unexpectedly code={code} uptime={uptime:.1f}s')
                    try:servicemanager.LogErrorMsg(SERVICE_DISPLAY+' child exited code '+str(code)+'. Automatic restart will be attempted. See '+str(child_log))
                    except Exception:pass
                    # A child that survives 10 minutes resets the crash budget. This avoids
                    # permanent lockout after a one-off dependency/network hiccup.
                    if uptime >= 600:
                        restart_count=0
                    else:
                        restart_count+=1
                    if restart_count>6:
                        _append('web_service.log','restart budget exhausted; service exits so SCM recovery can take over')
                        try:servicemanager.LogErrorMsg(SERVICE_DISPLAY+' restart budget exhausted. See service_logs\\web_service_child.log')
                        except Exception:pass
                        return
                    delay=min(2**max(0,restart_count-1),20)
                    _append('web_service.log',f'restarting child in {delay}s (attempt {restart_count}/6)')
                    if win32event.WaitForSingleObject(self.stop_event,int(delay*1000))==win32event.WAIT_OBJECT_0:
                        break
                _append('web_service.log','service stopped normally')
                servicemanager.LogInfoMsg(SERVICE_DISPLAY+' stopped')
            except BaseException as exc:
                _append('web_service.log','FATAL '+repr(exc)+'\n'+traceback.format_exc())
                try:servicemanager.LogErrorMsg(SERVICE_DISPLAY+' failed: '+repr(exc)+'. See service_logs\\web_service.log')
                except Exception:pass
                raise
            finally:
                if self.stream:
                    try:self.stream.close()
                    except Exception:pass


def main():
    if not win32serviceutil:raise SystemExit('pywin32 is required and this helper is Windows-only.')
    win32serviceutil.HandleCommandLine(NetworkAutomationWebService)

if __name__=='__main__':main()
