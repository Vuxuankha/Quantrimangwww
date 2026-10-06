from modules.ui_theme import PALETTE as UI_COLORS
import csv
import os
import platform
import shutil
import socket
import sqlite3
import subprocess
import threading
from datetime import datetime, timedelta
from pathlib import Path
try:
    import tkinter as tk
except (ImportError, ModuleNotFoundError):
    tk = None
try:
    from tkinter import ttk, messagebox, filedialog, simpledialog
except (ImportError, ModuleNotFoundError):
    ttk = messagebox = filedialog = simpledialog = None

import pandas as pd

from database.db import DB_PATH, init_database, get_connection
from app_runtime import BACKUP_DIR, REPORT_DIR
from modules.ping_check import ping_host
from modules.advanced_pages import open_device_detail, notify_alert, ensure_advanced_tables


BACKUP_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _connect():
    init_database()
    conn = get_connection()
    return conn


def ensure_extra_tables():
    conn = _connect()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS remote_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT,
                host TEXT,
                port INTEGER,
                username TEXT,
                status TEXT,
                detail TEXT,
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS config_backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_name TEXT,
                source TEXT,
                file_path TEXT,
                size_bytes INTEGER DEFAULT 0,
                note TEXT DEFAULT '',
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS scheduled_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                task_type TEXT,
                target TEXT,
                interval_minutes INTEGER DEFAULT 60,
                enabled INTEGER DEFAULT 1,
                last_run TEXT,
                next_run TEXT,
                last_status TEXT,
                created_at TEXT
            );
            """
        )
        # Migrate older project schemas without deleting existing data.
        def ensure_column(table, name, definition):
            cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            if name not in cols:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")

        for name, definition in [
            ("name", "TEXT"), ("ip", "TEXT"), ("vendor", "TEXT"),
            ("status", "TEXT DEFAULT 'Unknown'"), ("note", "TEXT DEFAULT ''"),
            ("created_at", "TEXT"), ("updated_at", "TEXT")
        ]:
            ensure_column("network_devices", name, definition)
        nd_cols = {r[1] for r in conn.execute("PRAGMA table_info(network_devices)").fetchall()}
        if "device_name" in nd_cols:
            conn.execute("UPDATE network_devices SET name=COALESCE(NULLIF(name,''), device_name)")
        if "ip_address" in nd_cols:
            conn.execute("UPDATE network_devices SET ip=COALESCE(NULLIF(ip,''), ip_address)")
        if "notes" in nd_cols:
            conn.execute("UPDATE network_devices SET note=COALESCE(NULLIF(note,''), notes)")
        conn.execute("UPDATE network_devices SET status='Unknown' WHERE status IS NULL OR TRIM(status)=''")

        for name, definition in [("ip", "TEXT"), ("status", "TEXT DEFAULT 'Open'")]:
            ensure_column("alerts", name, definition)
        a_cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        if "ip_address" in a_cols:
            conn.execute("UPDATE alerts SET ip=COALESCE(NULLIF(ip,''), ip_address)")
        if "resolved" in a_cols:
            conn.execute("UPDATE alerts SET status=CASE WHEN resolved=1 THEN 'Closed' ELSE COALESCE(NULLIF(status,''),'Open') END")
        else:
            conn.execute("UPDATE alerts SET status='Open' WHERE status IS NULL OR TRIM(status)=''")

        conn.commit()
    finally:
        conn.close()


def log_activity(action, description=""):
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO activity_logs(action, description, created_at) VALUES(?,?,?)",
            (str(action), str(description), _now()),
        )
        conn.commit()
    finally:
        conn.close()


def get_setting(key, default=""):
    conn = _connect()
    try:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def set_setting(key, value):
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        conn.commit()
    finally:
        conn.close()


class BasePage:
    def __init__(self, parent, activity_callback=None):
        self.parent = parent
        self.activity_callback = activity_callback or (lambda m: None)
        ensure_extra_tables()
        ensure_advanced_tables()

    def activity(self, text):
        try:
            self.activity_callback(text)
        except Exception:
            pass

    def card(self):
        f = tk.Frame(self.parent, bg=UI_COLORS['surface'], bd=1, relief="solid")
        f.pack(fill="both", expand=True, padx=25, pady=(0, 15))
        return f


class NetworkDevicesPage(BasePage):
    FIELDS = ("name", "ip", "device_type", "vendor", "location", "status", "note")

    def __init__(self, parent, activity_callback=None):
        super().__init__(parent, activity_callback)
        self.search_var = tk.StringVar()
        self._build()
        self.refresh()

    def _build(self):
        controls = tk.Frame(self.parent, bg=UI_COLORS['background'])
        controls.pack(fill="x", padx=25, pady=(0, 8))
        tk.Label(controls, text="Tìm kiếm:", bg=UI_COLORS['background']).pack(side="left")
        ent = tk.Entry(controls, textvariable=self.search_var, width=30)
        ent.pack(side="left", padx=6)
        ent.bind("<KeyRelease>", lambda e: self.refresh())
        tk.Button(controls, text="Thêm thiết bị", command=self.add_device, bg=UI_COLORS['primary'], fg=UI_COLORS['text'], relief="flat", padx=12).pack(side="left", padx=6)
        tk.Button(controls, text="Chi tiết", command=self.view_details).pack(side="left", padx=4)
        tk.Button(controls, text="Sửa", command=self.edit_device).pack(side="left", padx=4)
        tk.Button(controls, text="Xóa", command=self.delete_device).pack(side="left", padx=4)
        tk.Button(controls, text="Ping", command=self.ping_selected).pack(side="left", padx=4)
        tk.Button(controls, text="Làm mới", command=self.refresh).pack(side="left", padx=4)
        tk.Button(controls, text="Xuất Excel", command=self.export_excel).pack(side="right")

        box = self.card()
        cols = ("name", "ip", "type", "vendor", "location", "status", "note")
        self.table = ttk.Treeview(box, columns=cols, show="headings", selectmode="browse")
        titles = {"name":"Name", "ip":"Địa chỉ IP", "type":"Type", "vendor":"Vendor", "location":"Location", "status":"Trạng thái", "note":"Note"}
        widths = {"name":150,"ip":125,"type":120,"vendor":120,"location":140,"status":90,"note":220}
        for c in cols:
            self.table.heading(c, text=titles[c])
            self.table.column(c, width=widths[c], anchor="w")
        y = ttk.Scrollbar(box, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=y.set)
        self.table.pack(side="left", fill="both", expand=True)
        y.pack(side="right", fill="y")
        self.table.bind("<Double-1>", lambda e: self.view_details())

    def refresh(self):
        q = self.search_var.get().strip().lower()
        conn = _connect()
        try:
            rows = [dict(r) for r in conn.execute("SELECT * FROM network_devices ORDER BY name, ip").fetchall()]
        finally:
            conn.close()
        for i in self.table.get_children(): self.table.delete(i)
        for r in rows:
            hay = " ".join(str(r.get(k) or "") for k in self.FIELDS).lower()
            if q and q not in hay: continue
            self.table.insert("", "end", iid=str(r["id"]), values=(r.get("name",""), r.get("ip",""), r.get("device_type",""), r.get("vendor",""), r.get("location",""), r.get("status","Unknown"), r.get("note","")))

    def _dialog(self, title, row=None):
        win = tk.Toplevel(self.parent); win.title(title); win.geometry("430x430"); win.transient(self.parent.winfo_toplevel()); win.grab_set()
        labels = ["Name", "Địa chỉ IP", "Device Type", "Vendor", "Location", "Trạng thái", "Note"]
        values = [row.get(f, "") if row else "" for f in self.FIELDS]
        vars_ = []
        for idx, (lab, val) in enumerate(zip(labels, values)):
            tk.Label(win, text=lab).grid(row=idx, column=0, sticky="w", padx=15, pady=8)
            v = tk.StringVar(value=val or ("Unknown" if lab == "Trạng thái" else "")); vars_.append(v)
            if lab == "Trạng thái":
                w = ttk.Combobox(win, textvariable=v, values=["Unknown","Online","Offline","Maintenance"], state="readonly")
            else:
                w = tk.Entry(win, textvariable=v, width=32)
            w.grid(row=idx, column=1, padx=10, pady=8)
        result = {"ok": False}
        def save():
            if not vars_[0].get().strip() or not vars_[1].get().strip():
                messagebox.showwarning(title, "Name and IP Address are required.", parent=win); return
            result["values"] = [v.get().strip() for v in vars_]; result["ok"] = True; win.destroy()
        tk.Button(win, text="Lưu", command=save, bg=UI_COLORS['primary'], fg=UI_COLORS['text'], width=12).grid(row=len(labels), column=1, sticky="e", padx=10, pady=18)
        win.wait_window(); return result.get("values") if result["ok"] else None

    def add_device(self):
        vals = self._dialog("Add Network Device")
        if not vals: return
        conn = _connect()
        try:
            conn.execute("INSERT INTO network_devices(name,ip,device_type,vendor,location,status,note) VALUES(?,?,?,?,?,?,?)", vals); conn.commit()
        finally: conn.close()
        self.activity(f"Network device added: {vals[0]} ({vals[1]}).")
        self.refresh()

    def _selected_row(self):
        sel = self.table.selection()
        if not sel: messagebox.showinfo("Thiết bị mạng", "Select a device first."); return None
        conn = _connect()
        try:
            r = conn.execute("SELECT * FROM network_devices WHERE id=?", (int(sel[0]),)).fetchone(); return dict(r) if r else None
        finally: conn.close()

    def view_details(self):
        row = self._selected_row()
        if not row: return
        open_device_detail(self.parent, row["id"])

    def edit_device(self):
        row = self._selected_row()
        if not row: return
        vals = self._dialog("Edit Network Device", row)
        if not vals: return
        conn = _connect()
        try:
            conn.execute("UPDATE network_devices SET name=?,ip=?,device_type=?,vendor=?,location=?,status=?,note=? WHERE id=?", (*vals, row["id"])); conn.commit()
        finally: conn.close()
        self.activity(f"Network device updated: {vals[0]} ({vals[1]}).")
        self.refresh()

    def delete_device(self):
        row = self._selected_row()
        if not row or not messagebox.askyesno("Xóa", f"Delete {row['name']} ({row['ip']})?"): return
        conn = _connect()
        try: conn.execute("DELETE FROM network_devices WHERE id=?", (row["id"],)); conn.commit()
        finally: conn.close()
        self.activity(f"Network device deleted: {row['name']} ({row['ip']}).")
        self.refresh()

    def ping_selected(self):
        row = self._selected_row()
        if not row: return
        self.parent.config(cursor="watch"); self.parent.update_idletasks()
        result = ping_host(row["ip"], timeout=1500)
        status = result.get("status", "Unknown")
        conn = _connect()
        try: conn.execute("UPDATE network_devices SET status=? WHERE id=?", (status, row["id"])); conn.commit()
        finally: conn.close()
        self.parent.config(cursor="")
        self.activity(f"Ping {row['ip']}: {status}.")
        self.refresh(); messagebox.showinfo("Ping", f"{row['ip']}: {status}\nResponse: {result.get('response') or '-'} ms")

    def export_excel(self):
        path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel", "*.xlsx")], initialfile="network_devices.xlsx")
        if not path: return
        conn = _connect()
        try: df = pd.read_sql_query("SELECT * FROM network_devices ORDER BY name, ip", conn)
        finally: conn.close()
        df.to_excel(path, index=False); self.activity(f"Network devices exported: {path}"); messagebox.showinfo("Export", "Export completed.")


class RemoteServicePage(BasePage):
    def __init__(self, parent, activity_callback=None):
        super().__init__(parent, activity_callback)
        self.protocol = tk.StringVar(value="SSH")
        self.host = tk.StringVar()
        self.port = tk.StringVar(value="22")
        self.username = tk.StringVar()
        self.status = tk.StringVar(value="Sẵn sàng")
        self._build(); self.refresh_history()

    def _build(self):
        control = tk.Frame(self.parent, bg=UI_COLORS['surface'], bd=1, relief="solid"); control.pack(fill="x", padx=25, pady=(0,10))
        items = [("Protocol", self.protocol), ("Host / IP", self.host), ("Port", self.port), ("Username", self.username)]
        for idx, (label, var) in enumerate(items):
            tk.Label(control, text=label, bg=UI_COLORS['surface']).grid(row=0, column=idx*2, padx=(12,4), pady=15)
            if label == "Protocol":
                w = ttk.Combobox(control, textvariable=var, values=["SSH","Telnet","RDP","HTTP","HTTPS"], state="readonly", width=10)
                w.bind("<<ComboboxSelected>>", lambda e: self._protocol_changed())
            else: w = tk.Entry(control, textvariable=var, width=16)
            w.grid(row=0, column=idx*2+1, pady=15)
        tk.Button(control, text="Kiểm tra cổng", command=self.test_port, bg=UI_COLORS['primary'], fg=UI_COLORS['text'], relief="flat", padx=12).grid(row=1, column=1, pady=(0,14))
        tk.Button(control, text="Mở trình kết nối", command=self.open_client, padx=12).grid(row=1, column=3, pady=(0,14))
        tk.Label(control, textvariable=self.status, bg=UI_COLORS['surface'], fg=UI_COLORS['muted']).grid(row=1, column=5, columnspan=3, sticky="w")

        box = self.card(); cols=("time","protocol","host","port","username","status","detail")
        self.table=ttk.Treeview(box, columns=cols, show="headings")
        widths=(150,80,160,70,130,90,300)
        for c,w in zip(cols,widths): self.table.heading(c,text=c.replace("_"," ").title()); self.table.column(c,width=w,anchor="w")
        self.table.pack(fill="both",expand=True)

    def _protocol_changed(self):
        self.port.set({"SSH":"22","Telnet":"23","RDP":"3389","HTTP":"80","HTTPS":"443"}.get(self.protocol.get(),""))

    def _record(self, status, detail):
        conn=_connect()
        try:
            conn.execute("INSERT INTO remote_history(protocol,host,port,username,status,detail,created_at) VALUES(?,?,?,?,?,?,?)",(self.protocol.get(),self.host.get().strip(),int(self.port.get() or 0),self.username.get().strip(),status,detail,_now())); conn.commit()
        finally: conn.close()
        self.refresh_history(); self.activity(f"Remote {self.protocol.get()} {self.host.get().strip()}: {status}.")

    def test_port(self):
        host=self.host.get().strip()
        try: port=int(self.port.get())
        except ValueError: messagebox.showerror("Truy cập từ xa","Invalid port."); return
        if not host: messagebox.showwarning("Truy cập từ xa","Enter a host or IP."); return
        self.status.set("Testing..."); self.parent.update_idletasks()
        try:
            with socket.create_connection((host,port),timeout=2): pass
            self.status.set("Port is open"); self._record("Open",f"TCP {port} reachable")
        except Exception as exc:
            self.status.set("Port closed/unreachable"); self._record("Failed",str(exc))

    def open_client(self):
        host=self.host.get().strip(); proto=self.protocol.get(); user=self.username.get().strip()
        try: port=int(self.port.get())
        except ValueError: messagebox.showerror("Truy cập từ xa","Invalid port."); return
        if not host: messagebox.showwarning("Truy cập từ xa","Enter a host or IP."); return
        try:
            if proto in ("HTTP","HTTPS"):
                import webbrowser; webbrowser.open(f"{proto.lower()}://{host}:{port}")
            elif proto == "RDP":
                if platform.system().lower() == "windows": subprocess.Popen(["mstsc", f"/v:{host}:{port}"])
                else: raise RuntimeError("RDP launcher is currently supported through mstsc on Windows.")
            elif proto == "SSH":
                target=f"{user+'@' if user else ''}{host}"
                if platform.system().lower()=="windows": subprocess.Popen(["cmd","/c","start","cmd","/k","ssh",target,"-p",str(port)])
                else: subprocess.Popen(["x-terminal-emulator","-e","ssh","-p",str(port),target])
            elif proto == "Telnet":
                if platform.system().lower()=="windows": subprocess.Popen(["cmd","/c","start","cmd","/k","telnet",host,str(port)])
                else: subprocess.Popen(["x-terminal-emulator","-e","telnet",host,str(port)])
            self._record("Launched","Client launched")
        except Exception as exc:
            self._record("Failed",str(exc)); messagebox.showerror("Truy cập từ xa",str(exc))

    def refresh_history(self):
        if not hasattr(self,"table"): return
        for i in self.table.get_children(): self.table.delete(i)
        conn=_connect()
        try: rows=conn.execute("SELECT * FROM remote_history ORDER BY id DESC LIMIT 300").fetchall()
        finally: conn.close()
        for r in rows: self.table.insert("","end",values=(r["created_at"],r["protocol"],r["host"],r["port"],r["username"],r["status"],r["detail"]))


class BackupConfigPage(BasePage):
    def __init__(self,parent,activity_callback=None):
        super().__init__(parent,activity_callback); self.device=tk.StringVar(); self.note=tk.StringVar(); self.source_path=tk.StringVar(); self._build(); self.refresh()

    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief="solid"); ctl.pack(fill="x",padx=25,pady=(0,10))
        tk.Label(ctl,text="Thiết bị / Tên:",bg=UI_COLORS['surface']).grid(row=0,column=0,padx=(12,5),pady=12); tk.Entry(ctl,textvariable=self.device,width=24).grid(row=0,column=1)
        tk.Label(ctl,text="Ghi chú:",bg=UI_COLORS['surface']).grid(row=0,column=2,padx=(12,5)); tk.Entry(ctl,textvariable=self.note,width=30).grid(row=0,column=3)
        tk.Label(ctl,text="Tệp nguồn:",bg=UI_COLORS['surface']).grid(row=1,column=0,padx=(12,5),pady=(0,12)); tk.Entry(ctl,textvariable=self.source_path,width=45).grid(row=1,column=1,columnspan=2,sticky="we",pady=(0,12))
        tk.Button(ctl,text="Chọn tệp",command=self.browse).grid(row=1,column=3,sticky="w",padx=5,pady=(0,12))
        tk.Button(ctl,text="Tạo bản sao lưu",command=self.create_backup,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief="flat",padx=12).grid(row=0,column=4,padx=12)
        tk.Button(ctl,text="Sao lưu nội dung dán",command=self.backup_text).grid(row=1,column=4,padx=12,pady=(0,12))
        box=self.card(); top=tk.Frame(box,bg=UI_COLORS['surface']); top.pack(fill="x",padx=10,pady=8)
        tk.Button(top,text="Mở thư mục sao lưu",command=lambda: self._open_path(BACKUP_DIR)).pack(side="left")
        tk.Button(top,text="Xuất mục đã chọn",command=self.export_selected).pack(side="left",padx=5)
        tk.Button(top,text="Xóa",command=self.delete_selected).pack(side="left",padx=5)
        tk.Button(top,text="Làm mới",command=self.refresh).pack(side="left",padx=5)
        cols=("device","source","file","size","note","created")
        self.table=ttk.Treeview(box,columns=cols,show="headings",selectmode="browse")
        widths=(140,150,250,90,200,150)
        for c,w in zip(cols,widths): self.table.heading(c,text=c.title()); self.table.column(c,width=w,anchor="w")
        self.table.pack(fill="both",expand=True,padx=10,pady=(0,10))

    def browse(self):
        p=filedialog.askopenfilename();
        if p:self.source_path.set(p)

    def create_backup(self):
        src=Path(self.source_path.get().strip())
        if not src.is_file(): messagebox.showwarning("Sao lưu cấu hình","Choose a valid source file."); return
        name=self.device.get().strip() or src.stem; stamp=datetime.now().strftime("%Y%m%d_%H%M%S"); dst=BACKUP_DIR/f"{name.replace(' ','_')}_{stamp}{src.suffix or '.cfg'}"
        try: shutil.copy2(src,dst)
        except Exception as exc: messagebox.showerror("Sao lưu cấu hình",str(exc)); return
        self._save_record(name,str(src),dst); self.activity(f"Configuration backup created: {dst.name}"); self.refresh()

    def backup_text(self):
        win=tk.Toplevel(self.parent); win.title("Paste Configuration"); win.geometry("700x500"); txt=tk.Text(win,font=("Consolas",10)); txt.pack(fill="both",expand=True,padx=10,pady=10)
        def save():
            content=txt.get("1.0","end-1c"); name=self.device.get().strip() or "device"
            if not content.strip(): messagebox.showwarning("Sao lưu cấu hình","Paste configuration text first.",parent=win); return
            dst=BACKUP_DIR/f"{name.replace(' ','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.cfg"; dst.write_text(content,encoding="utf-8")
            self._save_record(name,"Pasted text",dst); self.activity(f"Configuration text backup created: {dst.name}"); win.destroy(); self.refresh()
        tk.Button(win,text="Save Backup",command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text']).pack(pady=(0,10))

    def _save_record(self,name,source,dst):
        conn=_connect()
        try: conn.execute("INSERT INTO config_backups(device_name,source,file_path,size_bytes,note,created_at) VALUES(?,?,?,?,?,?)",(name,source,str(dst),dst.stat().st_size,self.note.get().strip(),_now())); conn.commit()
        finally: conn.close()

    def refresh(self):
        if not hasattr(self,"table"):return
        for i in self.table.get_children():self.table.delete(i)
        conn=_connect()
        try:rows=conn.execute("SELECT * FROM config_backups ORDER BY id DESC").fetchall()
        finally:conn.close()
        for r in rows:self.table.insert("","end",iid=str(r["id"]),values=(r["device_name"],r["source"],Path(r["file_path"]).name,r["size_bytes"],r["note"],r["created_at"]))

    def _row(self):
        s=self.table.selection();
        if not s:messagebox.showinfo("Sao lưu cấu hình","Select a backup first.");return None
        conn=_connect()
        try:r=conn.execute("SELECT * FROM config_backups WHERE id=?",(int(s[0]),)).fetchone();return dict(r) if r else None
        finally:conn.close()

    def export_selected(self):
        r=self._row();
        if not r:return
        src=Path(r["file_path"])
        if not src.exists():messagebox.showerror("Sao lưu cấu hình","Backup file no longer exists.");return
        dst=filedialog.asksaveasfilename(initialfile=src.name)
        if dst:shutil.copy2(src,dst);self.activity(f"Backup exported: {dst}")

    def delete_selected(self):
        r=self._row();
        if not r or not messagebox.askyesno("Sao lưu cấu hình","Delete selected backup?"):return
        try:Path(r["file_path"]).unlink(missing_ok=True)
        except Exception:pass
        conn=_connect();
        try:conn.execute("DELETE FROM config_backups WHERE id=?",(r["id"],));conn.commit()
        finally:conn.close()
        self.activity(f"Backup deleted: {Path(r['file_path']).name}");self.refresh()

    def _open_path(self,path):
        try:
            if platform.system().lower()=="windows":os.startfile(path)
            elif platform.system().lower()=="darwin":subprocess.Popen(["open",str(path)])
            else:subprocess.Popen(["xdg-open",str(path)])
        except Exception as exc:messagebox.showerror("Sao lưu cấu hình",str(exc))


class SchedulerPage(BasePage):
    def __init__(self,parent,activity_callback=None):
        super().__init__(parent,activity_callback); self.running=True; self.status=tk.StringVar(value="Scheduler active while this page is open"); self._build(); self.refresh(); self._tick()

    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['background']);ctl.pack(fill="x",padx=25,pady=(0,8))
        tk.Button(ctl,text="Thêm tác vụ",command=self.add_task,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief="flat").pack(side="left")
        tk.Button(ctl,text="Sửa",command=self.edit_task).pack(side="left",padx=5);tk.Button(ctl,text="Chạy ngay",command=self.run_now).pack(side="left",padx=5);tk.Button(ctl,text="Bật / Tắt",command=self.toggle).pack(side="left",padx=5);tk.Button(ctl,text="Xóa",command=self.delete).pack(side="left",padx=5)
        tk.Label(ctl,textvariable=self.status,bg=UI_COLORS['background'],fg=UI_COLORS['muted']).pack(side="right")
        box=self.card();cols=("name","type","target","interval","enabled","last_run","next_run","last_status")
        self.table=ttk.Treeview(box,columns=cols,show="headings",selectmode="browse")
        widths=(150,120,220,100,80,150,150,130)
        for c,w in zip(cols,widths):self.table.heading(c,text=c.replace("_"," ").title());self.table.column(c,width=w,anchor="w")
        self.table.pack(fill="both",expand=True)

    def destroy(self):self.running=False

    def _dialog(self,title,row=None):
        win=tk.Toplevel(self.parent);win.title(title);win.geometry("480x310");win.transient(self.parent.winfo_toplevel());win.grab_set()
        name=tk.StringVar(value=(row or {}).get("name",""));typ=tk.StringVar(value=(row or {}).get("task_type","Ping Device"));target=tk.StringVar(value=(row or {}).get("target",""));interval=tk.StringVar(value=str((row or {}).get("interval_minutes",60)))
        for i,(lab,var) in enumerate((("Task Name",name),("Task Type",typ),("Target",target),("Interval (minutes)",interval))):
            tk.Label(win,text=lab).grid(row=i,column=0,sticky="w",padx=15,pady=12)
            if lab=="Task Type":w=ttk.Combobox(win,textvariable=var,values=["Ping Device","TCP Port Test","Create Alert"],state="readonly",width=28)
            else:w=tk.Entry(win,textvariable=var,width=32)
            w.grid(row=i,column=1,padx=10,pady=12)
        res={}
        def save():
            try:n=max(1,int(interval.get()))
            except:messagebox.showwarning(title,"Interval must be a whole number.",parent=win);return
            if not name.get().strip() or not target.get().strip():messagebox.showwarning(title,"Name and target are required.",parent=win);return
            res["v"]=(name.get().strip(),typ.get(),target.get().strip(),n);win.destroy()
        tk.Button(win,text="Lưu",command=save,bg=UI_COLORS['primary'],fg=UI_COLORS['text']).grid(row=5,column=1,sticky="e",padx=10,pady=15);win.wait_window();return res.get("v")

    def add_task(self):
        v=self._dialog("Add Scheduled Task");
        if not v:return
        next_run=(datetime.now()+timedelta(minutes=v[3])).strftime("%Y-%m-%d %H:%M:%S")
        conn=_connect();
        try:conn.execute("INSERT INTO scheduled_tasks(name,task_type,target,interval_minutes,enabled,last_run,next_run,last_status,created_at) VALUES(?,?,?,?,1,'',?,'Waiting',?)",(*v,next_run,_now()));conn.commit()
        finally:conn.close()
        self.activity(f"Scheduled task added: {v[0]}");self.refresh()

    def _selected(self):
        s=self.table.selection();
        if not s:messagebox.showinfo("Lịch tác vụ","Select a task first.");return None
        conn=_connect();
        try:r=conn.execute("SELECT * FROM scheduled_tasks WHERE id=?",(int(s[0]),)).fetchone();return dict(r) if r else None
        finally:conn.close()

    def edit_task(self):
        r=self._selected();
        if not r:return
        v=self._dialog("Edit Scheduled Task",r);
        if not v:return
        next_run=(datetime.now()+timedelta(minutes=v[3])).strftime("%Y-%m-%d %H:%M:%S")
        conn=_connect();
        try:conn.execute("UPDATE scheduled_tasks SET name=?,task_type=?,target=?,interval_minutes=?,next_run=? WHERE id=?",(*v,next_run,r["id"]));conn.commit()
        finally:conn.close()
        self.activity(f"Scheduled task updated: {v[0]}");self.refresh()

    def run_now(self):
        r=self._selected();
        if r:self._run_task(r)

    def _run_task(self,r):
        status="Success"
        detail=""
        try:
            if r["task_type"]=="Ping Device":
                x=ping_host(r["target"],timeout=1500);status=x.get("status","Error");detail=f"Ping {r['target']} = {status}"
            elif r["task_type"]=="TCP Port Test":
                host,port=(r["target"].rsplit(":",1) if ":" in r["target"] else (r["target"],"80"));
                with socket.create_connection((host,int(port)),timeout=2):pass
                detail=f"TCP {host}:{port} open"
            elif r["task_type"]=="Create Alert":
                msg=f"Scheduled alert from task {r['name']}"
                conn=_connect();
                try:conn.execute("INSERT INTO alerts(ip,alert_type,message,created_at,status,severity) VALUES(?,?,?,?,?,?)",(r["target"],"Scheduled",msg,_now(),"Open","Warning"));conn.commit()
                finally:conn.close()
                results=notify_alert(r["target"],"Scheduled",msg,"Warning")
                detail="Alert created" + (("; "+"; ".join(results)) if results else "")
        except Exception as exc:status="Failed";detail=str(exc)
        next_run=(datetime.now()+timedelta(minutes=int(r["interval_minutes"] or 60))).strftime("%Y-%m-%d %H:%M:%S")
        conn=_connect();
        try:conn.execute("UPDATE scheduled_tasks SET last_run=?,next_run=?,last_status=? WHERE id=?",(_now(),next_run,status,r["id"]));conn.commit()
        finally:conn.close()
        self.activity(f"Scheduler task {r['name']}: {status} - {detail}");self.refresh()

    def toggle(self):
        r=self._selected();
        if not r:return
        enabled=0 if r["enabled"] else 1
        conn=_connect();
        try:conn.execute("UPDATE scheduled_tasks SET enabled=? WHERE id=?",(enabled,r["id"]));conn.commit()
        finally:conn.close()
        self.refresh()

    def delete(self):
        r=self._selected();
        if not r or not messagebox.askyesno("Lịch tác vụ",f"Delete task '{r['name']}'?"):return
        conn=_connect();
        try:conn.execute("DELETE FROM scheduled_tasks WHERE id=?",(r["id"],));conn.commit()
        finally:conn.close()
        self.refresh()

    def refresh(self):
        if not hasattr(self,"table"):return
        for i in self.table.get_children():self.table.delete(i)
        conn=_connect();
        try:rows=conn.execute("SELECT * FROM scheduled_tasks ORDER BY id DESC").fetchall()
        finally:conn.close()
        for r in rows:self.table.insert("","end",iid=str(r["id"]),values=(r["name"],r["task_type"],r["target"],r["interval_minutes"],"Yes" if r["enabled"] else "No",r["last_run"],r["next_run"],r["last_status"]))

    def _tick(self):
        if not self.running or not self.parent.winfo_exists():return
        now=_now();conn=_connect()
        try:rows=[dict(r) for r in conn.execute("SELECT * FROM scheduled_tasks WHERE enabled=1 AND next_run<>'' AND next_run<=?",(now,)).fetchall()]
        finally:conn.close()
        for r in rows:self._run_task(r)
        try:self.parent.after(5000,self._tick)
        except tk.TclError:pass


class AlertsPage(BasePage):
    def __init__(self,parent,activity_callback=None):
        super().__init__(parent,activity_callback);self.filter=tk.StringVar(value="All");self._build();self.refresh()

    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['background']);ctl.pack(fill="x",padx=25,pady=(0,8))
        tk.Button(ctl,text="Kiểm tra thiết bị ngoại tuyến",command=self.check_devices,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief="flat").pack(side="left")
        tk.Button(ctl,text="Thêm cảnh báo",command=self.add_alert).pack(side="left",padx=5);tk.Button(ctl,text="Xác nhận",command=self.ack).pack(side="left",padx=5);tk.Button(ctl,text="Đóng",command=self.close_alert).pack(side="left",padx=5);tk.Button(ctl,text="Xóa",command=self.delete).pack(side="left",padx=5)
        ttk.Combobox(ctl,textvariable=self.filter,values=["All","Open","Acknowledged","Closed"],state="readonly",width=14).pack(side="right");self.filter.trace_add("write",lambda *_:self.refresh())
        box=self.card();cols=("time","severity","ip","type","message","status")
        self.table=ttk.Treeview(box,columns=cols,show="headings",selectmode="browse")
        for c,w in zip(cols,(145,90,120,120,430,110)):self.table.heading(c,text=c.title());self.table.column(c,width=w,anchor="w")
        self.table.pack(fill="both",expand=True)

    def check_devices(self):
        conn=_connect();created=0;new_alerts=[]
        try:
            rows=conn.execute("SELECT ip,hostname,status FROM devices WHERE status='Offline' UNION SELECT ip,name,status FROM network_devices WHERE status='Offline'").fetchall()
            for r in rows:
                exists=conn.execute("SELECT 1 FROM alerts WHERE ip=? AND alert_type='Device Offline' AND status IN ('Open','Acknowledged')",(r["ip"],)).fetchone()
                if not exists:
                    msg=f"{r[1] or r['ip']} is offline"
                    conn.execute("INSERT INTO alerts(ip,alert_type,message,created_at,status,severity) VALUES(?,?,?,?,?,?)",(r["ip"],"Device Offline",msg,_now(),"Open","Critical"));created+=1;new_alerts.append((r["ip"],msg))
            conn.commit()
        finally:conn.close()
        for ip,msg in new_alerts:
            results=notify_alert(ip,"Device Offline",msg,"Critical")
            if results:self.activity("; ".join(results))
        self.activity(f"Alert check completed: {created} new alert(s).");self.refresh()

    def add_alert(self):
        ip=simpledialog.askstring("Thêm cảnh báo","IP / target:",parent=self.parent); 
        if ip is None:return
        msg=simpledialog.askstring("Thêm cảnh báo","Message:",parent=self.parent)
        if not msg:return
        conn=_connect();
        try:conn.execute("INSERT INTO alerts(ip,alert_type,message,created_at,status,severity) VALUES(?,?,?,?,?,?)",(ip.strip(),"Manual",msg.strip(),_now(),"Open","Warning"));conn.commit()
        finally:conn.close()
        self.activity(f"Manual alert added for {ip}");self.refresh()

    def _id(self):
        s=self.table.selection();
        if not s:messagebox.showinfo("Cảnh báo","Select an alert first.");return None
        return int(s[0])
    def _set(self,status):
        i=self._id();
        if i is None:return
        conn=_connect();
        try:conn.execute("UPDATE alerts SET status=? WHERE id=?",(status,i));conn.commit()
        finally:conn.close()
        self.activity(f"Alert #{i} -> {status}");self.refresh()
    def ack(self):self._set("Acknowledged")
    def close_alert(self):self._set("Closed")
    def delete(self):
        i=self._id();
        if i is None or not messagebox.askyesno("Cảnh báo","Delete selected alert?"):return
        conn=_connect();
        try:conn.execute("DELETE FROM alerts WHERE id=?",(i,));conn.commit()
        finally:conn.close()
        self.refresh()
    def refresh(self):
        if not hasattr(self,"table"):return
        for i in self.table.get_children():self.table.delete(i)
        conn=_connect();
        try:
            if self.filter.get()=="All":rows=conn.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
            else:rows=conn.execute("SELECT * FROM alerts WHERE status=? ORDER BY id DESC",(self.filter.get(),)).fetchall()
        finally:conn.close()
        for r in rows:self.table.insert("","end",iid=str(r["id"]),values=(r["created_at"],r["severity"] or "Warning",r["ip"],r["alert_type"],r["message"],r["status"]))


class ReportsPage(BasePage):
    def __init__(self,parent,activity_callback=None):
        super().__init__(parent,activity_callback);self.summary=tk.StringVar();self._build();self.refresh_summary()
    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['surface'],bd=1,relief="solid");ctl.pack(fill="x",padx=25,pady=(0,10))
        tk.Button(ctl,text="Làm mới tổng hợp",command=self.refresh_summary,bg=UI_COLORS['primary'],fg=UI_COLORS['text'],relief="flat").pack(side="left",padx=12,pady=12)
        tk.Button(ctl,text="Xuất báo cáo Excel đầy đủ",command=self.export_excel).pack(side="left",padx=5)
        tk.Button(ctl,text="Xuất CSV thiết bị",command=self.export_csv).pack(side="left",padx=5)
        box=self.card();tk.Label(box,textvariable=self.summary,bg=UI_COLORS['surface'],fg=UI_COLORS['text'],font=("Segoe UI",12),justify="left",anchor="nw").pack(fill="both",expand=True,padx=25,pady=25,anchor="nw")
    def refresh_summary(self):
        conn=_connect()
        try:
            total=conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0];online=conn.execute("SELECT COUNT(*) FROM devices WHERE status='Online'").fetchone()[0];offline=conn.execute("SELECT COUNT(*) FROM devices WHERE status='Offline'").fetchone()[0]
            ndev=conn.execute("SELECT COUNT(*) FROM network_devices").fetchone()[0];alerts=conn.execute("SELECT COUNT(*) FROM alerts WHERE status<>'Closed'").fetchone()[0];backups=conn.execute("SELECT COUNT(*) FROM config_backups").fetchone()[0];tasks=conn.execute("SELECT COUNT(*) FROM scheduled_tasks WHERE enabled=1").fetchone()[0]
            scans=conn.execute("SELECT COUNT(*) FROM network_scans").fetchone()[0];pings=conn.execute("SELECT COUNT(*) FROM ping_results").fetchone()[0]
        finally:conn.close()
        self.summary.set(f"NETWORK AUTOMATION SUMMARY\nGenerated: {_now()}\n\nDiscovered devices: {total}\n  Online: {online}\n  Offline: {offline}\nManaged network devices: {ndev}\nOpen / acknowledged alerts: {alerts}\nConfiguration backups: {backups}\nEnabled scheduled tasks: {tasks}\nNetwork scan records: {scans}\nPing records: {pings}\n\nUse 'Xuất báo cáo Excel đầy đủ' to create a multi-sheet workbook.")
    def export_excel(self):
        path=filedialog.asksaveasfilename(defaultextension=".xlsx",filetypes=[("Excel","*.xlsx")],initialfile=f"network_report_{datetime.now().strftime('%Y%m%d')}.xlsx")
        if not path:return
        conn=_connect()
        try:
            tables=["devices","network_devices","ip_mac_inventory","alerts","config_backups","scheduled_tasks","network_scans","ping_results","activity_logs"]
            with pd.ExcelWriter(path) as writer:
                for t in tables:
                    try:pd.read_sql_query(f"SELECT * FROM {t}",conn).to_excel(writer,sheet_name=t[:31],index=False)
                    except Exception:pass
        finally:conn.close()
        self.activity(f"Full Excel report exported: {path}");messagebox.showinfo("Báo cáo","Report exported successfully.")
    def export_csv(self):
        path=filedialog.asksaveasfilename(defaultextension=".csv",filetypes=[("CSV","*.csv")],initialfile="devices_report.csv")
        if not path:return
        conn=_connect();
        try:pd.read_sql_query("SELECT * FROM devices ORDER BY ip",conn).to_csv(path,index=False,encoding="utf-8-sig")
        finally:conn.close()
        self.activity(f"Device CSV report exported: {path}")


class SystemLogsPage(BasePage):
    def __init__(self,parent,activity_callback=None):
        super().__init__(parent,activity_callback);self.search=tk.StringVar();self._build();self.refresh()
    def _build(self):
        ctl=tk.Frame(self.parent,bg=UI_COLORS['background']);ctl.pack(fill="x",padx=25,pady=(0,8));tk.Label(ctl,text="Tìm kiếm:",bg=UI_COLORS['background']).pack(side="left");e=tk.Entry(ctl,textvariable=self.search,width=35);e.pack(side="left",padx=5);e.bind("<KeyRelease>",lambda ev:self.refresh())
        tk.Button(ctl,text="Làm mới",command=self.refresh).pack(side="left",padx=5);tk.Button(ctl,text="Xuất CSV",command=self.export_csv).pack(side="left",padx=5);tk.Button(ctl,text="Xóa nhật ký",command=self.clear_logs).pack(side="right")
        box=self.card();cols=("time","action","description");self.table=ttk.Treeview(box,columns=cols,show="headings");
        for c,w in zip(cols,(160,180,700)):self.table.heading(c,text=c.title());self.table.column(c,width=w,anchor="w")
        self.table.pack(fill="both",expand=True)
    def refresh(self):
        q=f"%{self.search.get().strip()}%";conn=_connect()
        try:rows=conn.execute("SELECT * FROM activity_logs WHERE action LIKE ? OR description LIKE ? OR created_at LIKE ? ORDER BY id DESC LIMIT 3000",(q,q,q)).fetchall()
        finally:conn.close()
        for i in self.table.get_children():self.table.delete(i)
        for r in rows:self.table.insert("","end",values=(r["created_at"],r["action"],r["description"]))
    def export_csv(self):
        path=filedialog.asksaveasfilename(defaultextension=".csv",filetypes=[("CSV","*.csv")],initialfile="system_logs.csv")
        if not path:return
        conn=_connect();
        try:pd.read_sql_query("SELECT * FROM activity_logs ORDER BY id DESC",conn).to_csv(path,index=False,encoding="utf-8-sig")
        finally:conn.close()
        messagebox.showinfo("Nhật ký hệ thống","Logs exported.")
    def clear_logs(self):
        if not messagebox.askyesno("Nhật ký hệ thống","Clear all persisted activity logs?"):return
        conn=_connect();
        try:conn.execute("DELETE FROM activity_logs");conn.commit()
        finally:conn.close()
        self.refresh()


class SettingsPage(BasePage):
    DEFAULTS={"default_network":"192.168.1.0/24","ping_timeout_ms":"1000","ping_interval_sec":"5","scan_workers":"50","export_directory":"","confirm_delete":"1"}
    def __init__(self,parent,activity_callback=None):
        super().__init__(parent,activity_callback);self.vars={k:tk.StringVar(value=get_setting(k,v)) for k,v in self.DEFAULTS.items()};self._build()
    def _build(self):
        from modules.responsive_layout import FlowRow,AdaptiveForm,ScrollablePanel
        self.panel=ScrollablePanel(self.parent);body=self.panel.body
        form=ttk.Frame(body);form.pack(fill='x');fields=[]
        labels=[('Mạng mặc định','default_network'),('Timeout ping (ms)','ping_timeout_ms'),('Chu kỳ ping (giây)','ping_interval_sec'),('Số luồng quét','scan_workers'),('Thư mục xuất mặc định','export_directory')]
        for label,key in labels:
            field=ttk.Frame(form);fields.append(field);ttk.Label(field,text=label).pack(anchor='w')
            ttk.Entry(field,textvariable=self.vars[key],width=1).pack(fill='x',pady=4)
        AdaptiveForm(form,fields)
        bar=ttk.Frame(body);bar.pack(fill='x',pady=15)
        FlowRow(bar,[ttk.Button(bar,text=text,command=command) for text,command in [('Chọn thư mục xuất',self.browse_export),('Lưu cài đặt',self.save),('Khôi phục mặc định',self.restore)]])
        note=ttk.Label(body,text='Cài đặt lưu trong cơ sở dữ liệu cục bộ. Một số giá trị áp dụng khi mở lại chức năng.',wraplength=500);note.pack(fill='x')
        body.bind('<Configure>',lambda event:note.configure(wraplength=max(200,event.width-24)),add='+')
    def browse_export(self):
        p=filedialog.askdirectory();
        if p:self.vars["export_directory"].set(p)
    def save(self):
        try:
            int(self.vars["ping_timeout_ms"].get());int(self.vars["ping_interval_sec"].get());int(self.vars["scan_workers"].get())
        except ValueError:messagebox.showerror("Cài đặt","Timeout, interval and workers must be whole numbers.");return
        import ipaddress
        try:ipaddress.ip_network(self.vars["default_network"].get().strip(),strict=False)
        except ValueError:messagebox.showerror("Cài đặt","Default network is invalid.");return
        for k,v in self.vars.items():set_setting(k,v.get().strip())
        self.activity("Application settings saved.");messagebox.showinfo("Cài đặt","Settings saved.")
    def restore(self):
        for k,v in self.DEFAULTS.items():self.vars[k].set(v)


__all__=["NetworkDevicesPage","RemoteServicePage","BackupConfigPage","SchedulerPage","AlertsPage","ReportsPage","SystemLogsPage","SettingsPage","ensure_extra_tables","log_activity","get_setting"]
