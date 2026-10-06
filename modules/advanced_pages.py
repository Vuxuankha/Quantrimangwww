from modules.ui_ux_config import PALETTE as UI_COLORS
import queue
import re
import os
import socket
import sqlite3
import struct
import threading
import time
import urllib.parse
import urllib.request
import smtplib
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
try:
    import tkinter as tk
except (ImportError, ModuleNotFoundError):
    tk = None
try:
    from tkinter import ttk, messagebox, simpledialog
except (ImportError, ModuleNotFoundError):
    ttk = messagebox = simpledialog = None

from database.db import DB_PATH, init_database, get_connection
from app_runtime import BACKUP_DIR
from modules.nms_v5 import encrypt_secret, decrypt_secret

SESSION_SECRETS = {'telegram_token': '', 'smtp_password': ''}
BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def _now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _connect():
    init_database()
    conn = get_connection()
    return conn


def ensure_advanced_tables():
    conn = _connect()
    try:
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS snmp_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            host TEXT NOT NULL,
            community TEXT DEFAULT 'public',
            port INTEGER DEFAULT 161,
            interface_index INTEGER DEFAULT 1,
            interval_sec INTEGER DEFAULT 10,
            enabled INTEGER DEFAULT 1,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS snmp_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER,
            host TEXT,
            interface_index INTEGER,
            sys_name TEXT,
            uptime_ticks INTEGER,
            oper_status INTEGER,
            in_octets INTEGER,
            out_octets INTEGER,
            in_bps REAL,
            out_bps REAL,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS device_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_device_id INTEGER,
            target_device_id INTEGER,
            label TEXT DEFAULT '',
            created_at TEXT,
            UNIQUE(source_device_id, target_device_id)
        );
        CREATE TABLE IF NOT EXISTS ssh_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            commands TEXT,
            created_at TEXT
        );
        ''')
        # Add severity to old alert schemas without destructive migration.
        cols = {r[1] for r in conn.execute('PRAGMA table_info(alerts)').fetchall()}
        if 'severity' not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN severity TEXT DEFAULT 'Warning'")
        conn.commit()
    finally:
        conn.close()


def get_setting(key, default=''):
    conn = _connect()
    try:
        row = conn.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
        return row['value'] if row else default
    finally:
        conn.close()


def set_setting(key, value):
    conn = _connect()
    try:
        conn.execute('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, str(value)))
        conn.commit()
    finally:
        conn.close()


def log_activity(action, description=''):
    conn = _connect()
    try:
        conn.execute('INSERT INTO activity_logs(action,description,created_at) VALUES(?,?,?)', (action, description, _now()))
        conn.commit()
    finally:
        conn.close()


# ------------------------- Minimal SNMP v2c -------------------------
# Implements only what this application needs: GET of standard scalar/counter OIDs.

def _ber_len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def _ber_tlv(tag, payload):
    return bytes([tag]) + _ber_len(len(payload)) + payload


def _ber_int(n):
    if n == 0:
        payload = b'\x00'
    else:
        size = max(1, (n.bit_length() + 8) // 8)
        payload = n.to_bytes(size, 'big', signed=True)
        while len(payload) > 1 and payload[0] == 0 and not (payload[1] & 0x80):
            payload = payload[1:]
    return _ber_tlv(0x02, payload)


def _ber_str(s):
    b = s.encode('utf-8') if isinstance(s, str) else bytes(s)
    return _ber_tlv(0x04, b)


def _ber_oid(oid):
    nums = [int(x) for x in oid.strip('.').split('.')]
    if len(nums) < 2:
        raise ValueError('Invalid OID')
    out = bytearray([40 * nums[0] + nums[1]])
    for n in nums[2:]:
        chunks = [n & 0x7F]
        n >>= 7
        while n:
            chunks.append(0x80 | (n & 0x7F))
            n >>= 7
        out.extend(reversed(chunks))
    return _ber_tlv(0x06, bytes(out))


def _read_len(data, pos):
    first = data[pos]; pos += 1
    if first < 128:
        return first, pos
    count = first & 0x7F
    n = int.from_bytes(data[pos:pos+count], 'big')
    return n, pos + count


def _read_tlv(data, pos):
    tag = data[pos]; pos += 1
    length, pos = _read_len(data, pos)
    end = pos + length
    return tag, data[pos:end], end


def _decode_oid(payload):
    if not payload:
        return ''
    first = payload[0]
    nums = [first // 40, first % 40]
    value = 0
    for b in payload[1:]:
        value = (value << 7) | (b & 0x7F)
        if not (b & 0x80):
            nums.append(value); value = 0
    return '.'.join(map(str, nums))


def _decode_value(tag, payload):
    if tag == 0x04:
        try:
            return payload.decode('utf-8', errors='replace')
        except Exception:
            return payload.hex()
    if tag in (0x02, 0x41, 0x42, 0x43, 0x46):
        return int.from_bytes(payload, 'big', signed=(tag == 0x02))
    if tag == 0x06:
        return _decode_oid(payload)
    if tag in (0x05, 0x80, 0x81, 0x82):
        # NULL / noSuchObject / noSuchInstance / endOfMibView
        return None
    return payload.hex()


def snmp_get(host, community, oids, port=161, timeout=1.5):
    request_id = int(time.time() * 1000) & 0x7FFFFFFF
    varbinds = b''.join(_ber_tlv(0x30, _ber_oid(oid) + _ber_tlv(0x05, b'')) for oid in oids)
    pdu = _ber_tlv(0xA0, _ber_int(request_id) + _ber_int(0) + _ber_int(0) + _ber_tlv(0x30, varbinds))
    packet = _ber_tlv(0x30, _ber_int(1) + _ber_str(community) + pdu)  # v2c => integer 1
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.sendto(packet, (host, int(port)))
            data, _ = sock.recvfrom(65535)
        except socket.timeout as exc:
            raise TimeoutError(
                f'Thiết bị {host} không phản hồi SNMP UDP/{int(port)} trong {timeout:g} giây. '
                'Hãy kiểm tra SNMP đã bật, community có đúng và firewall có cho phép UDP/161 hay không.'
            ) from exc
        except socket.gaierror as exc:
            raise ConnectionError(f'Không phân giải được host {host}: {exc}') from exc
        except OSError as exc:
            raise ConnectionError(f'Không thể gửi yêu cầu SNMP tới {host}:{int(port)}: {exc}') from exc
    finally:
        sock.close()

    _, top, _ = _read_tlv(data, 0)
    pos = 0
    _, _, pos = _read_tlv(top, pos)  # version
    _, _, pos = _read_tlv(top, pos)  # community
    pdu_tag, pdu_payload, pos = _read_tlv(top, pos)
    if pdu_tag != 0xA2:
        raise RuntimeError('Unexpected SNMP response PDU')
    p = 0
    _, _, p = _read_tlv(pdu_payload, p)  # request id
    _, err_payload, p = _read_tlv(pdu_payload, p)
    err = int.from_bytes(err_payload, 'big', signed=True)
    _, idx_payload, p = _read_tlv(pdu_payload, p)
    err_idx = int.from_bytes(idx_payload, 'big', signed=True)
    if err:
        raise RuntimeError(f'SNMP error {err} at index {err_idx}')
    _, vb_list, p = _read_tlv(pdu_payload, p)
    out = {}
    p = 0
    while p < len(vb_list):
        _, vb, p = _read_tlv(vb_list, p)
        q = 0
        _, oid_payload, q = _read_tlv(vb, q)
        vtag, vpayload, q = _read_tlv(vb, q)
        out[_decode_oid(oid_payload)] = _decode_value(vtag, vpayload)
    return out


class BaseAdvancedPage:
    def __init__(self, parent, activity_callback=None):
        self.parent = parent
        self.activity_callback = activity_callback or (lambda m: None)
        ensure_advanced_tables()

    def activity(self, text):
        try:
            self.activity_callback(text)
        except Exception:
            pass

    def card(self):
        f = tk.Frame(self.parent, bg=UI_COLORS['surface'], bd=1, relief='solid')
        f.pack(fill='both', expand=True, padx=25, pady=(0, 15))
        return f


class SNMPMonitorPage(BaseAdvancedPage):
    SYSNAME = '1.3.6.1.2.1.1.5.0'
    UPTIME = '1.3.6.1.2.1.1.3.0'

    def __init__(self, parent, activity_callback=None):
        super().__init__(parent, activity_callback)
        self.host = tk.StringVar()
        self.community = tk.StringVar(value='public')
        self.port = tk.StringVar(value='161')
        self.ifindex = tk.StringVar(value='1')
        self.interval = tk.StringVar(value='5')
        self.status = tk.StringVar(value='Sẵn sàng')
        self.running = False
        self.worker = None
        self.samples = []
        self.last_raw = None
        self.profile_id = None
        self._build()
        self._load_profiles()

    def _build(self):
        ctl = tk.Frame(self.parent, bg=UI_COLORS['surface'], bd=1, relief='solid')
        ctl.pack(fill='x', padx=25, pady=(0, 10))
        fields = [('Host / IP', self.host, 18), ('Community', self.community, 14), ('Port', self.port, 6), ('IfIndex', self.ifindex, 7), ('Interval(s)', self.interval, 8)]
        for i, (lab, var, width) in enumerate(fields):
            tk.Label(ctl, text=lab, bg=UI_COLORS['surface']).grid(row=0, column=i*2, padx=(10, 3), pady=12)
            tk.Entry(ctl, textvariable=var, width=width).grid(row=0, column=i*2+1, pady=12)
        tk.Button(ctl, text='Kiểm tra một lần', command=self.poll_once, bg=UI_COLORS['primary'], fg=UI_COLORS['text'], relief='flat', padx=10).grid(row=1, column=1, pady=(0, 12))
        self.start_btn = tk.Button(ctl, text='Bắt đầu giám sát', command=self.toggle_monitor, padx=10)
        self.start_btn.grid(row=1, column=3, pady=(0, 12))
        tk.Button(ctl, text='Lưu hồ sơ', command=self.save_profile).grid(row=1, column=5, pady=(0, 12))
        tk.Label(ctl, textvariable=self.status, bg=UI_COLORS['surface'], fg=UI_COLORS['muted']).grid(row=1, column=7, columnspan=3, sticky='w')

        body = self.card()
        left = tk.Frame(body, bg=UI_COLORS['surface'], width=300); left.pack(side='left', fill='y', padx=10, pady=10); left.pack_propagate(False)
        tk.Label(left, text='Hồ sơ SNMP đã lưu', bg=UI_COLORS['surface'], font=('Segoe UI', 11, 'bold')).pack(anchor='w', pady=(0, 6))
        self.profile_list = tk.Listbox(left, height=22)
        self.profile_list.pack(fill='both', expand=True)
        self.profile_list.bind('<<ListboxSelect>>', self._select_profile)
        tk.Button(left, text='Xóa hồ sơ', command=self.delete_profile).pack(fill='x', pady=(6, 0))

        right = tk.Frame(body, bg=UI_COLORS['surface']); right.pack(side='left', fill='both', expand=True, padx=(0, 10), pady=10)
        self.metric = tk.StringVar(value='No SNMP data yet.')
        tk.Label(right, textvariable=self.metric, bg=UI_COLORS['surface'], justify='left', anchor='w', font=('Consolas', 10)).pack(fill='x', pady=(0, 8))
        self.canvas = tk.Canvas(right, bg=UI_COLORS['background'], highlightthickness=1, highlightbackground=UI_COLORS['surface_alt'], height=330)
        self.canvas.pack(fill='both', expand=True)
        tk.Label(right, text='Traffic graph: IN and OUT bits/sec. SNMP v2c only; community is stored locally with the profile.', bg=UI_COLORS['surface'], fg=UI_COLORS['muted']).pack(anchor='w', pady=(8, 0))

    def _oids(self):
        idx = int(self.ifindex.get())
        return [self.SYSNAME, self.UPTIME,
                f'1.3.6.1.2.1.2.2.1.8.{idx}',
                f'1.3.6.1.2.1.2.2.1.10.{idx}',
                f'1.3.6.1.2.1.2.2.1.16.{idx}']

    def _do_poll(self):
        host = self.host.get().strip()
        if not host:
            raise ValueError('Enter a host / IP.')
        port = int(self.port.get()); idx = int(self.ifindex.get())
        values = snmp_get(host, self.community.get(), self._oids(), port=port)
        now = time.time()
        in_oct = int(values.get(f'1.3.6.1.2.1.2.2.1.10.{idx}', 0) or 0)
        out_oct = int(values.get(f'1.3.6.1.2.1.2.2.1.16.{idx}', 0) or 0)
        in_bps = out_bps = 0.0
        if self.last_raw:
            dt = max(0.001, now - self.last_raw[0])
            di = in_oct - self.last_raw[1]; do = out_oct - self.last_raw[2]
            if di >= 0: in_bps = di * 8.0 / dt
            if do >= 0: out_bps = do * 8.0 / dt
        self.last_raw = (now, in_oct, out_oct)
        sample = {
            'time': now, 'sys_name': values.get(self.SYSNAME, ''), 'uptime': int(values.get(self.UPTIME, 0) or 0),
            'oper': int(values.get(f'1.3.6.1.2.1.2.2.1.8.{idx}', 0) or 0),
            'in_oct': in_oct, 'out_oct': out_oct, 'in_bps': in_bps, 'out_bps': out_bps,
        }
        self.samples.append(sample); self.samples = self.samples[-120:]
        conn = _connect()
        try:
            conn.execute('''INSERT INTO snmp_samples(profile_id,host,interface_index,sys_name,uptime_ticks,oper_status,in_octets,out_octets,in_bps,out_bps,created_at)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
                         (self.profile_id, host, idx, sample['sys_name'], sample['uptime'], sample['oper'], in_oct, out_oct, in_bps, out_bps, _now()))
            conn.commit()
        finally:
            conn.close()
        return sample

    def poll_once(self):
        self.status.set('Đang kiểm tra...')
        def worker():
            try:
                s = self._do_poll()
                self.parent.after(0, lambda: self._show_sample(s))
            except Exception as exc:
                msg = str(exc)
                self.parent.after(0, lambda m=msg: self.status.set('Lỗi: ' + m))
        threading.Thread(target=worker, daemon=True).start()

    def toggle_monitor(self):
        if self.running:
            self.running = False; self.start_btn.config(text='Bắt đầu giám sát'); self.status.set('Stopped'); return
        try:
            interval = max(1, int(self.interval.get()))
        except ValueError:
            messagebox.showerror('Giám sát SNMP', 'Interval must be a whole number.'); return
        self.running = True; self.start_btn.config(text='Dừng giám sát')
        def loop():
            while self.running:
                try:
                    s = self._do_poll(); self.parent.after(0, lambda sample=s: self._show_sample(sample))
                except Exception as exc:
                    self.parent.after(0, lambda e=str(exc): self.status.set('Error: ' + e))
                for _ in range(interval * 10):
                    if not self.running: break
                    time.sleep(0.1)
        self.worker = threading.Thread(target=loop, daemon=True); self.worker.start()

    def _show_sample(self, s):
        up = 'UP' if s['oper'] == 1 else ('DOWN' if s['oper'] == 2 else str(s['oper']))
        uptime = s['uptime'] / 100.0
        self.metric.set(f"System: {s['sys_name'] or '-'}    Interface: {self.ifindex.get()} ({up})    Uptime: {uptime:,.0f}s\nIN: {s['in_bps']/1_000_000:,.3f} Mbps    OUT: {s['out_bps']/1_000_000:,.3f} Mbps    Samples: {len(self.samples)}")
        self.status.set('Monitoring' if self.running else 'Poll completed')
        self._draw_graph()

    def _draw_graph(self):
        c = self.canvas; c.delete('all'); w = max(500, c.winfo_width()); h = max(260, c.winfo_height())
        pad = 45
        c.create_line(pad, 15, pad, h-pad, fill=UI_COLORS['muted']); c.create_line(pad, h-pad, w-15, h-pad, fill=UI_COLORS['muted'])
        if len(self.samples) < 2:
            c.create_text(w/2, h/2, text='Need at least 2 samples to calculate traffic rate.', fill=UI_COLORS['muted']); return
        vals = [(s['in_bps'], s['out_bps']) for s in self.samples]
        mx = max(1.0, max(max(x) for x in vals))
        c.create_text(6, 18, text=f'{mx/1_000_000:.2f}M', anchor='w', fill=UI_COLORS['muted'])
        c.create_text(6, h-pad, text='0', anchor='w', fill=UI_COLORS['muted'])
        n = len(vals); span = max(1, n-1)
        p_in=[]; p_out=[]
        for i,(vin,vout) in enumerate(vals):
            x = pad + (w-pad-20)*i/span
            p_in.extend([x, h-pad - (h-pad-25)*vin/mx]); p_out.extend([x, h-pad - (h-pad-25)*vout/mx])
        c.create_line(*p_in, fill=UI_COLORS['accent'], width=2, smooth=True)
        c.create_line(*p_out, fill=UI_COLORS['warning'], width=2, smooth=True)
        c.create_text(w-160, 18, text='IN', fill=UI_COLORS['accent']); c.create_text(w-90, 18, text='OUT', fill=UI_COLORS['warning'])

    def save_profile(self):
        try:
            host=self.host.get().strip(); port=int(self.port.get()); idx=int(self.ifindex.get()); interval=max(1,int(self.interval.get()))
        except ValueError:
            messagebox.showerror('Giám sát SNMP','Port, IfIndex and Interval must be integers.'); return
        if not host:
            messagebox.showwarning('Giám sát SNMP','Enter a host / IP.'); return
        name=simpledialog.askstring('Save SNMP Profile','Profile name:',initialvalue=host,parent=self.parent)
        if not name:return
        conn=_connect()
        try:
            cur=conn.execute('INSERT INTO snmp_profiles(name,host,community,port,interface_index,interval_sec,enabled,created_at) VALUES(?,?,?,?,?,?,1,?)',(name.strip(),host,self.community.get(),port,idx,interval,_now()));self.profile_id=cur.lastrowid;conn.commit()
        finally:conn.close()
        self._load_profiles(); self.activity(f'SNMP profile saved: {name}')

    def _load_profiles(self):
        conn=_connect()
        try:self.profiles=[dict(r) for r in conn.execute('SELECT * FROM snmp_profiles ORDER BY name').fetchall()]
        finally:conn.close()
        self.profile_list.delete(0,'end')
        for r in self.profiles:self.profile_list.insert('end',f"{r['name']}  [{r['host']}] if{r['interface_index']}")

    def _select_profile(self,event=None):
        sel=self.profile_list.curselection()
        if not sel:return
        r=self.profiles[sel[0]];self.profile_id=r['id'];self.host.set(r['host']);self.community.set(r['community']);self.port.set(str(r['port']));self.ifindex.set(str(r['interface_index']));self.interval.set(str(r['interval_sec']));self.samples=[];self.last_raw=None;self.status.set(f"Loaded {r['name']}")

    def delete_profile(self):
        sel=self.profile_list.curselection()
        if not sel:return
        r=self.profiles[sel[0]]
        if not messagebox.askyesno('Giám sát SNMP',f"Delete profile {r['name']}?"):return
        conn=_connect()
        try:conn.execute('DELETE FROM snmp_profiles WHERE id=?',(r['id'],));conn.commit()
        finally:conn.close()
        self.profile_id=None;self._load_profiles()


class NetworkTopologyPage(BaseAdvancedPage):
    def __init__(self,parent,activity_callback=None):
        super().__init__(parent,activity_callback);self.status=tk.StringVar(value='Topology uses managed Network Devices. Add links manually, then Refresh.');self._build();self.refresh()

    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['background']);ctl.pack(fill='x',padx=25,pady=(0,8))
        tk.Button(ctl,text='Thêm liên kết',command=self.add_link,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat',padx=12).pack(side='left')
        tk.Button(ctl,text='Xóa liên kết',command=self.delete_link).pack(side='left',padx=5)
        tk.Button(ctl,text='Làm mới',command=self.refresh).pack(side='left',padx=5)
        tk.Label(ctl,textvariable=self.status,bg=UI_COLORS['background'],fg=UI_COLORS['muted']).pack(side='left',padx=12)
        box=self.card();self.canvas=tk.Canvas(box,bg=UI_COLORS['background'],highlightthickness=0);self.canvas.pack(fill='both',expand=True,padx=10,pady=10);self.canvas.bind('<Configure>',lambda e:self.draw())

    def refresh(self):
        conn=_connect()
        try:
            self.devices=[dict(r) for r in conn.execute('SELECT * FROM network_devices ORDER BY name,ip').fetchall()]
            self.links=[dict(r) for r in conn.execute('SELECT * FROM device_links ORDER BY id').fetchall()]
        finally:conn.close()
        self.draw()

    def add_link(self):
        conn=_connect()
        try:dev=[dict(r) for r in conn.execute('SELECT id,name,ip FROM network_devices ORDER BY name,ip').fetchall()]
        finally:conn.close()
        if len(dev)<2:messagebox.showinfo('Topology','Add at least two Network Devices first.');return
        win=tk.Toplevel(self.parent);win.title('Add Topology Link');win.geometry('430x220');win.transient(self.parent.winfo_toplevel());win.grab_set()
        labels=[f"{d['name'] or d['ip']} ({d['ip']})" for d in dev];src=tk.StringVar(value=labels[0]);dst=tk.StringVar(value=labels[1]);lab=tk.StringVar()
        for i,(title,var) in enumerate([('Source',src),('Target',dst)]):tk.Label(win,text=title).grid(row=i,column=0,padx=15,pady=12,sticky='w');ttk.Combobox(win,textvariable=var,values=labels,state='readonly',width=33).grid(row=i,column=1,padx=10,pady=12)
        tk.Label(win,text='Label').grid(row=2,column=0,padx=15,pady=12,sticky='w');tk.Entry(win,textvariable=lab,width=35).grid(row=2,column=1,padx=10)
        def save():
            a=dev[labels.index(src.get())]['id'];b=dev[labels.index(dst.get())]['id']
            if a==b:messagebox.showwarning('Topology','Choose two different devices.',parent=win);return
            if a>b:a,b=b,a
            conn=_connect()
            try:conn.execute('INSERT OR IGNORE INTO device_links(source_device_id,target_device_id,label,created_at) VALUES(?,?,?,?)',(a,b,lab.get().strip(),_now()));conn.commit()
            finally:conn.close()
            win.destroy();self.refresh();self.activity('Topology link added.')
        tk.Button(win,text='Save Link',command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text']).grid(row=3,column=1,pady=18,sticky='e')

    def delete_link(self):
        if not self.links:messagebox.showinfo('Topology','No links to delete.');return
        items=[];byid={d['id']:d for d in self.devices}
        for l in self.links:
            a=byid.get(l['source_device_id'],{});b=byid.get(l['target_device_id'],{})
            items.append(f"#{l['id']} {a.get('name') or a.get('ip','?')} -- {b.get('name') or b.get('ip','?')} {l.get('label') or ''}")
        choice=simpledialog.askinteger('Xóa liên kết','Enter link ID to delete:\n'+'\n'.join(items[:12]),parent=self.parent)
        if choice is None:return
        conn=_connect()
        try:conn.execute('DELETE FROM device_links WHERE id=?',(choice,));conn.commit()
        finally:conn.close()
        self.refresh()

    def draw(self):
        if not hasattr(self,'canvas'):return
        c=self.canvas;c.delete('all');w=max(700,c.winfo_width());h=max(430,c.winfo_height())
        if not self.devices:
            c.create_text(w/2,h/2,text='No managed devices. Add devices in Network Devices first.',fill=UI_COLORS['muted'],font=('Segoe UI',12));return
        # Hierarchical layout by device type; fallback rows.
        levels={'firewall':0,'router':1,'core':2,'switch':3,'ap':4,'access point':4,'server':4,'camera':5,'pc':5}
        groups={}
        for d in self.devices:
            text=((d.get('device_type') or '')+' '+(d.get('name') or '')).lower();lvl=3
            for k,v in levels.items():
                if k in text:lvl=v;break
            groups.setdefault(lvl,[]).append(d)
        ys={lvl:55+i*(h-110)/max(1,len(groups)-1) for i,lvl in enumerate(sorted(groups))}
        pos={}
        for lvl,ds in groups.items():
            y=ys[lvl];gap=w/(len(ds)+1)
            for i,d in enumerate(ds):pos[d['id']]=(gap*(i+1),y)
        byid={d['id']:d for d in self.devices}
        for l in self.links:
            if l['source_device_id'] in pos and l['target_device_id'] in pos:
                x1,y1=pos[l['source_device_id']];x2,y2=pos[l['target_device_id']];c.create_line(x1,y1,x2,y2,fill=UI_COLORS['muted'],width=2)
                if l.get('label'):c.create_text((x1+x2)/2,(y1+y2)/2-10,text=l['label'],fill=UI_COLORS['muted'],font=('Segoe UI',8))
        for d in self.devices:
            x,y=pos[d['id']];status=(d.get('status') or 'Unknown').lower();fill=UI_COLORS['success_bg'] if status=='online' else (UI_COLORS['danger_bg'] if status=='offline' else UI_COLORS['surface_alt']);outline=UI_COLORS['success'] if status=='online' else (UI_COLORS['danger'] if status=='offline' else UI_COLORS['muted'])
            c.create_rectangle(x-72,y-26,x+72,y+26,fill=fill,outline=outline,width=2)
            c.create_text(x,y-6,text=d.get('name') or d.get('ip') or 'Device',font=('Segoe UI',9,'bold'), fill=UI_COLORS['text'])
            c.create_text(x,y+11,text=d.get('ip') or '',font=('Segoe UI',8),fill=UI_COLORS['muted'])


class SSHAutomationPage(BaseAdvancedPage):
    def __init__(self,parent,activity_callback=None,worker_threads=None):
        self.worker_threads=worker_threads if worker_threads is not None else []
        super().__init__(parent,activity_callback);self.host=tk.StringVar();self.port=tk.StringVar(value='22');self.username=tk.StringVar();self.password=tk.StringVar();self.template=tk.StringVar();self.status=tk.StringVar(value='Sẵn sàng');self.mode=tk.StringVar(value='exec');self.paging=tk.StringVar();self._busy=False;self._results=queue.Queue();self._build();self._load_templates()

    def _build(self):
        from tkinter.scrolledtext import ScrolledText
        from modules.responsive_layout import FlowRow,AdaptiveForm,ScrollablePanel
        self.panel=ScrollablePanel(self.parent);body=self.panel.body
        form=ttk.Frame(body);form.pack(fill='x');fields=[]
        for label,var in [('Máy chủ/IP',self.host),('Cổng',self.port),('Tài khoản',self.username),('Mật khẩu',self.password),('Chế độ SSH',self.mode),('Lệnh tắt phân trang',self.paging)]:
            field=ttk.Frame(form);fields.append(field);ttk.Label(field,text=label).pack(anchor='w')
            if var is self.mode:widget=ttk.Combobox(field,textvariable=var,values=('exec','shell'),state='readonly',width=1)
            else:widget=ttk.Entry(field,textvariable=var,width=1,show='*' if var is self.password else '')
            widget.pack(fill='x',pady=4)
        AdaptiveForm(form,fields)
        ttk.Label(body,text='Mẫu lệnh').pack(anchor='w',pady=(8,2))
        self.combo=ttk.Combobox(body,textvariable=self.template,state='readonly',width=1);self.combo.pack(fill='x');self.combo.bind('<<ComboboxSelected>>',lambda e:self.apply_template())
        bar=ttk.Frame(body);bar.pack(fill='x',pady=8)
        FlowRow(bar,[ttk.Button(bar,text=text,command=command) for text,command in [('Chạy lệnh',self.run_commands),('Lưu mẫu',self.save_template),('Sao lưu cấu hình đang chạy',self.backup_running)]])
        status=ttk.Label(body,textvariable=self.status,wraplength=500);status.pack(fill='x')
        body.bind('<Configure>',lambda event:status.configure(wraplength=max(200,event.width-24)),add='+')
        ttk.Label(body,text='Lệnh (mỗi dòng một lệnh)').pack(anchor='w',pady=(10,4))
        self.commands=ScrolledText(body,height=8,width=1,wrap='word',font=('Consolas',10));self.commands.pack(fill='x')
        ttk.Label(body,text='Kết quả').pack(anchor='w',pady=(10,4))
        self.output=ScrolledText(body,height=16,width=1,wrap='word',font=('Consolas',9),bg=UI_COLORS['sidebar'],fg=UI_COLORS['text']);self.output.pack(fill='both',expand=True)

    def _paramiko(self):
        try:
            import paramiko
            return paramiko
        except ImportError:
            raise RuntimeError('Paramiko is not installed. Run: pip install -r requirements.txt')

    def _snapshot(self):
        from modules.ssh_runner import connection_options
        options = connection_options(self.host.get(), self.port.get(), self.username.get(), self.password.get(), self.mode.get())
        options['paging'] = self.paging.get().strip()
        return options

    def _execute(self, commands, options):
        from modules.ssh_runner import execute_commands
        return execute_commands(options, commands, self._paramiko(), timeout=20)

    def _start_job(self, commands, backup=False):
        if self._busy:
            return
        try:
            options = self._snapshot()
        except Exception as exc:
            self.status.set(str(exc))
            return
        self._busy = True
        self.status.set('Đang sao lưu...' if backup else 'Đang kết nối...')
        self.output.delete('1.0', 'end')
        def worker():
            try:
                out = self._execute(commands, options)
                if backup:
                    name = re.sub(r'[^A-Za-z0-9_.-]', '_', options['host'])
                    dst = BACKUP_DIR / f"{name}_ssh_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.cfg"
                    dst.write_text(out, encoding='utf-8')
                    conn = _connect()
                    try:
                        conn.execute('INSERT INTO config_backups(device_name,source,file_path,size_bytes,note,created_at) VALUES(?,?,?,?,?,?)', (name,'SSH',str(dst),dst.stat().st_size,'Automatic SSH backup',_now()))
                        conn.commit()
                    finally:
                        conn.close()
                    out = str(dst)
                self._results.put((out, None, backup))
            except Exception as exc:
                self._results.put(('', str(exc), backup))
        thread=threading.Thread(target=worker,daemon=True,name='SSHAutomation')
        threads=getattr(self,'worker_threads',None)
        if threads is not None:
            threads[:]=[t for t in threads if t.is_alive()]
            threads.append(thread)
        thread.start()
        self.parent.after(100, self._poll_result)

    def _poll_result(self):
        if not self.output.winfo_exists():
            return
        try:
            out, err, backup = self._results.get_nowait()
        except queue.Empty:
            self.parent.after(100, self._poll_result)
            return
        self._busy = False
        if backup:
            self._backup_done(out, err)
        else:
            self._finish(out, err)

    def run_commands(self):
        cmds = [x.strip() for x in self.commands.get('1.0','end').splitlines() if x.strip()]
        if not cmds:
            messagebox.showwarning('Tự động hóa SSH', 'Nhập ít nhất một lệnh.')
            return
        self._start_job(cmds)

    def _finish(self,out,err):
        if err:self.status.set('Failed');self.output.insert('end','ERROR: '+err);return
        self.status.set('Completed');self.output.insert('end',out);self.activity(f"SSH commands executed on {self.host.get().strip()}")

    def save_template(self):
        name=simpledialog.askstring('SSH Template','Template name:',parent=self.parent)
        if not name:return
        commands=self.commands.get('1.0','end').strip()
        if not commands:return
        conn=_connect()
        try:conn.execute('INSERT INTO ssh_templates(name,commands,created_at) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET commands=excluded.commands',(name.strip(),commands,_now()));conn.commit()
        finally:conn.close()
        self._load_templates();self.template.set(name.strip())

    def _load_templates(self):
        conn=_connect()
        try:self.templates={r['name']:r['commands'] for r in conn.execute('SELECT * FROM ssh_templates ORDER BY name').fetchall()}
        finally:conn.close()
        self.combo['values']=list(self.templates)

    def apply_template(self):
        name=self.template.get();self.commands.delete('1.0','end');self.commands.insert('1.0',self.templates.get(name,''))

    def backup_running(self):
        # User can change this command for non-Cisco devices before running.
        cmd=simpledialog.askstring('SSH Backup','Command that prints running configuration:',initialvalue='show running-config',parent=self.parent)
        if not cmd:return
        self._start_job([cmd], backup=True)

    def _backup_done(self,path,err):
        if err:self.status.set('Backup failed: '+err);return
        self.status.set('Backup saved: '+path);self.activity(f'SSH configuration backup: {path}')


class NotificationsPage(BaseAdvancedPage):
    def __init__(self,parent,activity_callback=None):
        super().__init__(parent,activity_callback)
        self.vars={
            'notify_enabled':tk.StringVar(value=get_setting('notify_enabled','0')),
            'notify_telegram':tk.StringVar(value=get_setting('notify_telegram','1')),
            'notify_email':tk.StringVar(value=get_setting('notify_email','0')),
            'notify_offline':tk.StringVar(value=get_setting('notify_offline','1')),
            'notify_drift':tk.StringVar(value=get_setting('notify_drift','1')),
            'notify_security':tk.StringVar(value=get_setting('notify_security','1')),
            'notify_daily_audit':tk.StringVar(value=get_setting('notify_daily_audit','1')),
            'notify_cooldown_min':tk.StringVar(value=get_setting('notify_cooldown_min','60')),
            'telegram_chat_id':tk.StringVar(value=get_setting('telegram_chat_id','')),
            'smtp_host':tk.StringVar(value=get_setting('smtp_host','')),
            'smtp_port':tk.StringVar(value=get_setting('smtp_port','587')),
            'smtp_user':tk.StringVar(value=get_setting('smtp_user','')),
            'smtp_to':tk.StringVar(value=get_setting('smtp_to','')),
        }
        self.telegram_token=tk.StringVar(value=_load_secret('telegram_token_enc'))
        self.smtp_password=tk.StringVar(value=_load_secret('smtp_password_enc'))
        self.status=tk.StringVar(value='Secret được mã hóa bằng khóa credential cục bộ của ứng dụng.')
        self._build()

    def _build(self):
        box=self.card(); inner=tk.Frame(box,bg=UI_COLORS['surface']); inner.pack(anchor='nw',padx=30,pady=20,fill='x')
        tk.Label(inner,text='Notification Center',bg=UI_COLORS['surface'],fg=UI_COLORS['text'],font=('Segoe UI',15,'bold')).grid(row=0,column=0,columnspan=4,sticky='w')
        tk.Label(inner,text='Gửi cảnh báo quan trọng, có chống gửi trùng theo thời gian cooldown.',bg=UI_COLORS['surface'],fg=UI_COLORS['muted']).grid(row=1,column=0,columnspan=4,sticky='w',pady=(2,12))
        tk.Checkbutton(inner,text='Bật thông báo tự động',variable=self.vars['notify_enabled'],onvalue='1',offvalue='0',bg=UI_COLORS['surface']).grid(row=2,column=0,sticky='w')
        tk.Checkbutton(inner,text='Telegram',variable=self.vars['notify_telegram'],onvalue='1',offvalue='0',bg=UI_COLORS['surface']).grid(row=2,column=1,sticky='w')
        tk.Checkbutton(inner,text='Email SMTP',variable=self.vars['notify_email'],onvalue='1',offvalue='0',bg=UI_COLORS['surface']).grid(row=2,column=2,sticky='w')
        events=tk.LabelFrame(inner,text='Sự kiện gửi thông báo',bg=UI_COLORS['surface'],padx=8,pady=6); events.grid(row=3,column=0,columnspan=4,sticky='ew',pady=10)
        for i,(txt,key) in enumerate([('Thiết bị Offline','notify_offline'),('Configuration Drift','notify_drift'),('Security HIGH','notify_security'),('Daily Audit WARN/HIGH','notify_daily_audit')]):
            tk.Checkbutton(events,text=txt,variable=self.vars[key],onvalue='1',offvalue='0',bg=UI_COLORS['surface']).grid(row=0,column=i,sticky='w',padx=(0,18))
        fields=[('Cooldown (phút)',self.vars['notify_cooldown_min'],''),('Telegram Bot Token',self.telegram_token,'*'),('Telegram Chat ID',self.vars['telegram_chat_id'],''),('SMTP Host',self.vars['smtp_host'],''),('SMTP Port',self.vars['smtp_port'],''),('SMTP Username',self.vars['smtp_user'],''),('SMTP Password',self.smtp_password,'*'),('Email To',self.vars['smtp_to'],'')]
        for i,(lab,var,show) in enumerate(fields,4):
            tk.Label(inner,text=lab,bg=UI_COLORS['surface'],font=('Segoe UI',10,'bold')).grid(row=i,column=0,sticky='w',pady=6,padx=(0,15)); tk.Entry(inner,textvariable=var,width=42,show=show).grid(row=i,column=1,columnspan=2,sticky='w',pady=6)
        btn=tk.Frame(inner,bg=UI_COLORS['surface']); btn.grid(row=12,column=0,columnspan=4,sticky='w',pady=14)
        tk.Button(btn,text='Lưu cấu hình',command=self.save,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief='flat',padx=12).pack(side='left',padx=(0,8))
        tk.Button(btn,text='Test Telegram',command=self.test_telegram).pack(side='left',padx=4)
        tk.Button(btn,text='Test Email',command=self.test_email).pack(side='left',padx=4)
        tk.Label(inner,textvariable=self.status,bg=UI_COLORS['surface'],fg=UI_COLORS['muted'],wraplength=760,justify='left').grid(row=13,column=0,columnspan=4,sticky='w')

    def save(self):
        try:
            cd=max(0,int(self.vars['notify_cooldown_min'].get() or 0)); self.vars['notify_cooldown_min'].set(str(cd))
            for k,v in self.vars.items(): set_setting(k,v.get().strip())
            _save_secret('telegram_token_enc',self.telegram_token.get()); _save_secret('smtp_password_enc',self.smtp_password.get())
            SESSION_SECRETS['telegram_token']=self.telegram_token.get(); SESSION_SECRETS['smtp_password']=self.smtp_password.get()
            self.activity('Notification Center settings saved.'); self.status.set('Đã lưu. Token/password được mã hóa, không lưu dạng plaintext.')
        except Exception as exc:self.status.set('Lỗi lưu cấu hình: '+str(exc))

    def test_telegram(self):
        try:send_telegram(self.telegram_token.get(),self.vars['telegram_chat_id'].get(),'Network Automation Tool: Telegram test successful.');self.status.set('Đã gửi Telegram test.')
        except Exception as exc:self.status.set('Telegram error: '+str(exc))

    def test_email(self):
        try:send_email(self.vars['smtp_host'].get(),self.vars['smtp_port'].get(),self.vars['smtp_user'].get(),self.smtp_password.get(),self.vars['smtp_to'].get(),'Network Automation Tool test','Email notification test successful.');self.status.set('Đã gửi Email test.')
        except Exception as exc:self.status.set('Email error: '+str(exc))


def _save_secret(key,value):
    set_setting(key, encrypt_secret(value) if value else '')

def _load_secret(key):
    token=get_setting(key,'')
    if not token:return ''
    try:return decrypt_secret(token)
    except Exception:return ''

def send_telegram(token, chat_id, message):
    if not token or not chat_id:raise ValueError('Telegram token and chat ID are required.')
    data=urllib.parse.urlencode({'chat_id':chat_id,'text':message}).encode()
    req=urllib.request.Request(f'https://api.telegram.org/bot{token}/sendMessage',data=data,method='POST')
    with urllib.request.urlopen(req,timeout=8) as r:r.read()

def _email_recipients(to_addr):
    recipients=[x.strip() for x in str(to_addr or '').replace(';', ',').split(',') if x.strip()]
    if not recipients:
        raise ValueError('SMTP host and recipient are required.')
    return recipients

def send_email(host,port,user,password,to_addr,subject,body,attachment_path=None):
    if not host:raise ValueError('SMTP host and recipient are required.')
    recipients=_email_recipients(to_addr)
    msg=EmailMessage();msg['Subject']=subject;msg['From']=user or 'network-automation@localhost';msg['To']=', '.join(recipients);msg.set_content(body)
    if attachment_path:
        path=Path(attachment_path)
        if not path.is_file():raise FileNotFoundError('Report attachment not found: '+str(path))
        msg.add_attachment(path.read_bytes(),maintype='application',subtype='vnd.openxmlformats-officedocument.spreadsheetml.sheet',filename=path.name)
    with smtplib.SMTP(host,int(port),timeout=20) as server:
        server.ehlo()
        try:server.starttls();server.ehlo()
        except Exception:pass
        if user:server.login(user,password)
        server.send_message(msg,to_addrs=recipients)

def _notification_tables():
    c=_connect()
    try:
        c.execute("CREATE TABLE IF NOT EXISTS notification_log(id INTEGER PRIMARY KEY AUTOINCREMENT,event_key TEXT,channel TEXT,status TEXT,detail TEXT,created_at TEXT)");c.commit()
    finally:c.close()

def _event_allowed(alert_type):
    t=(alert_type or '').lower()
    if 'offline' in t:return get_setting('notify_offline','1')=='1'
    if 'drift' in t:return get_setting('notify_drift','1')=='1'
    if 'security' in t:return get_setting('notify_security','1')=='1'
    if 'daily audit' in t:return get_setting('notify_daily_audit','1')=='1'
    return True

def notify_alert(ip, alert_type, message, severity='Warning', event_key=None):
    if get_setting('notify_enabled','0')!='1' or not _event_allowed(alert_type):return []
    _notification_tables(); key=event_key or f'{ip}|{alert_type}|{message}'
    cooldown=max(0,int(get_setting('notify_cooldown_min','60') or 60))
    c=_connect()
    try:
        old=c.execute("SELECT created_at FROM notification_log WHERE event_key=? AND status='SENT' ORDER BY id DESC LIMIT 1",(key,)).fetchone()
        if old and cooldown:
            try:
                if (datetime.now()-datetime.strptime(old['created_at'],'%Y-%m-%d %H:%M:%S')).total_seconds()<cooldown*60:return ['Cooldown: skipped duplicate']
            except Exception:pass
    finally:c.close()
    text=f"[{severity}] {alert_type}\nDevice: {ip}\n{message}\nTime: {_now()}"; results=[]
    token=_load_secret('telegram_token_enc') or SESSION_SECRETS.get('telegram_token',''); chat=get_setting('telegram_chat_id','')
    if get_setting('notify_telegram','1')=='1' and token and chat:
        try:send_telegram(token,chat,text);results.append('Telegram sent');_log_notification(key,'Telegram','SENT','OK')
        except Exception as exc:results.append('Telegram failed: '+str(exc));_log_notification(key,'Telegram','FAILED',str(exc))
    host=get_setting('smtp_host','');to=get_setting('smtp_to','');pwd=_load_secret('smtp_password_enc') or SESSION_SECRETS.get('smtp_password','')
    if get_setting('notify_email','0')=='1' and host and to:
        try:send_email(host,get_setting('smtp_port','587'),get_setting('smtp_user',''),pwd,to,f'Network Alert: {alert_type}',text);results.append('Email sent');_log_notification(key,'Email','SENT','OK')
        except Exception as exc:results.append('Email failed: '+str(exc));_log_notification(key,'Email','FAILED',str(exc))
    return results

def _log_notification(key,channel,status,detail):
    c=_connect()
    try:c.execute('INSERT INTO notification_log(event_key,channel,status,detail,created_at) VALUES(?,?,?,?,?)',(key,channel,status,detail[:1000],_now()));c.commit()
    finally:c.close()

def open_device_detail(parent, device_id):
    ensure_advanced_tables();conn=_connect()
    try:
        d=conn.execute('SELECT * FROM network_devices WHERE id=?',(device_id,)).fetchone()
        if not d:return
        d=dict(d)
        samples=[dict(r) for r in conn.execute('SELECT * FROM snmp_samples WHERE host=? ORDER BY id DESC LIMIT 40',(d.get('ip'),)).fetchall()]
        backups=[dict(r) for r in conn.execute('SELECT * FROM config_backups WHERE device_name=? OR device_name=? ORDER BY id DESC LIMIT 30',(d.get('name'),d.get('ip'))).fetchall()]
        alerts=[dict(r) for r in conn.execute('SELECT * FROM alerts WHERE ip=? ORDER BY id DESC LIMIT 30',(d.get('ip'),)).fetchall()]
    finally:conn.close()
    win=tk.Toplevel(parent);win.title(f"Device Detail - {d.get('name') or d.get('ip')}");win.geometry('900x620');win.transient(parent.winfo_toplevel())
    nb=ttk.Notebook(win);nb.pack(fill='both',expand=True,padx=10,pady=10)
    ov=tk.Frame(nb,bg=UI_COLORS['surface']);nb.add(ov,text='Tổng quan')
    text='\n'.join([f"Name: {d.get('name','')}",f"IP: {d.get('ip','')}",f"Type: {d.get('device_type','')}",f"Vendor: {d.get('vendor','')}",f"Location: {d.get('location','')}",f"Status: {d.get('status','')}",f"Note: {d.get('note','')}"])
    tk.Label(ov,text=text,bg=UI_COLORS['surface'],justify='left',anchor='nw',font=('Segoe UI',11)).pack(fill='both',expand=True,padx=25,pady=25,anchor='nw')
    def table_tab(title,columns,rows):
        f=tk.Frame(nb);nb.add(f,text=title);t=ttk.Treeview(f,columns=columns,show='headings')
        for c in columns:t.heading(c,text=c.replace('_',' ').title());t.column(c,width=130,anchor='w')
        for row in rows:t.insert('','end',values=[row.get(c,'') for c in columns])
        t.pack(fill='both',expand=True,padx=8,pady=8)
    table_tab('SNMP History',('created_at','interface_index','in_bps','out_bps','oper_status'),samples)
    table_tab('Backups',('created_at','source','file_path','size_bytes','note'),backups)
    table_tab('Cảnh báo',('created_at','severity','alert_type','message','status'),alerts)


__all__=['SNMPMonitorPage','NetworkTopologyPage','SSHAutomationPage','NotificationsPage','open_device_detail','ensure_advanced_tables','snmp_get','notify_alert','send_email']
