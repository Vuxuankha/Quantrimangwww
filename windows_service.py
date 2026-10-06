"""Install/start with the project's Python + pywin32; see UPDATE_1.1.0.md."""
import threading
import os
from pathlib import Path
import win32service
import win32serviceutil
import servicemanager

class MonitorService(win32serviceutil.ServiceFramework):
    _svc_name_='NetworkAutomationMonitor'
    _svc_display_name_='Network Automation Monitor'
    _svc_description_='Read-only network and camera reachability monitoring; optional Wi-Fi diagnostics.'

    def __init__(self,args):
        super().__init__(args)
        self.stop_event=threading.Event()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.stop_event.set()

    def SvcDoRun(self):
        servicemanager.LogInfoMsg('Network Automation Monitor starting')
        from web_data_root import resolve_web_data
        data, source = resolve_web_data(use_external=False)
        os.environ['NETWORK_AUTOMATION_DATA_DIR']=str(data)
        servicemanager.LogInfoMsg(f'Network Automation Monitor data source: {source} -> {data}')
        from monitor_agent import run
        run(self.stop_event)

if __name__=='__main__':win32serviceutil.HandleCommandLine(MonitorService)
