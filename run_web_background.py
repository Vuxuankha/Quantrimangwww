"""Unattended launcher with bounded logs. Child startup remains loopback-only.

Scheduled Task retries abnormal termination; this is NOT a Windows service.
The verified STOP_WEB command writes an intentional-stop marker so that the
wrapper exits successfully instead of triggering an unintended restart.
"""
from __future__ import annotations
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parent

def main():
    os.chdir(ROOT)
    from web_data_root import resolve_web_data
    data,_=resolve_web_data()
    logs=data/'logs';logs.mkdir(exist_ok=True)
    logger=logging.getLogger('web_background');logger.setLevel(logging.INFO)
    logger.addHandler(RotatingFileHandler(logs/'web_background.log',maxBytes=5*1024*1024,backupCount=3,encoding='utf-8'))
    marker=data/'database'/'.web46-intentional-stop'
    marker.unlink(missing_ok=True)
    exe=Path(sys.executable)
    if exe.name.lower()=='pythonw.exe':exe=exe.with_name('python.exe')
    child=subprocess.Popen([str(exe),'-u',str(ROOT/'run_web.py'),'--no-browser'],cwd=ROOT,
                           stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace',
                           creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    for line in child.stdout:logger.info(line.rstrip())
    code=child.wait()
    if marker.exists():marker.unlink(missing_ok=True);return 0
    return code

if __name__=='__main__':raise SystemExit(main())
