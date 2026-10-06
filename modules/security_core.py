"""Headless-safe security baseline and posture helpers shared by web/cloud code."""
import re
import sqlite3
from database.db import DB_PATH


def _conn():
    c=sqlite3.connect(DB_PATH); c.row_factory=sqlite3.Row
    c.execute('''CREATE TABLE IF NOT EXISTS config_baselines(
      id INTEGER PRIMARY KEY AUTOINCREMENT, device TEXT NOT NULL UNIQUE,
      config TEXT NOT NULL, source TEXT, updated_at TEXT NOT NULL)''')
    c.commit(); return c


def get_baseline(device):
    c=_conn()
    try:
        r=c.execute('SELECT * FROM config_baselines WHERE device=?',(device.strip(),)).fetchone()
        return dict(r) if r else None
    finally:
        c.close()


def posture(config):
    s=config.lower(); results=[]
    def add(name, ok, evidence, severity='WARN'):
        results.append({'control':name,'status':'PASS' if ok else severity,'evidence':evidence})
    ssh=('ip ssh' in s or 'transport input ssh' in s)
    telnet=bool(re.search(r'transport input[^\n]*telnet',s))
    http=bool(re.search(r'^\s*ip http server\s*$',s,re.M))
    https='ip http secure-server' in s
    add('SSH quản trị',ssh,'Có cấu hình SSH' if ssh else 'Không thấy cấu hình SSH','HIGH')
    add('Telnet',not telnet,'Không cho phép Telnet' if not telnet else 'Phát hiện transport input telnet','HIGH')
    add('HTTP quản trị',not http,'HTTP thường không bật' if not http else 'Phát hiện ip http server')
    add('HTTPS quản trị',https,'Có HTTPS' if https else 'Không thấy ip http secure-server','REVIEW')
    add('DHCP Snooping','ip dhcp snooping' in s,'Có DHCP Snooping' if 'ip dhcp snooping' in s else 'Chưa thấy DHCP Snooping','REVIEW')
    add('Dynamic ARP Inspection','ip arp inspection' in s,'Có DAI' if 'ip arp inspection' in s else 'Chưa thấy DAI','REVIEW')
    add('Port Security','switchport port-security' in s,'Có Port Security' if 'switchport port-security' in s else 'Chưa thấy Port Security','REVIEW')
    vlan1=bool(re.search(r'switchport access vlan\s+1\b',s))
    add('Access VLAN 1',not vlan1,'Không thấy access VLAN 1' if not vlan1 else 'Có cổng access VLAN 1','WARN')
    add('AAA','aaa new-model' in s,'Có AAA new-model' if 'aaa new-model' in s else 'Chưa thấy AAA new-model','REVIEW')
    return results
