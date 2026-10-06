from modules.ui_theme import PALETTE as UI_COLORS
import ipaddress
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from datetime import datetime
import sqlite3
import pandas as pd

from database.db import DB_PATH, init_database, get_connection
from modules.network_scan import scan_network
from modules.extra_pages import get_setting


class IPMacManagerPage:
    """IP/MAC inventory page backed by SQLite and the existing network scanner."""

    def __init__(self, parent, activity_callback=None):
        self.parent = parent
        self.activity_callback = activity_callback or (lambda message: None)
        self.stop_event = None
        self.scan_thread = None
        self.rows = []
        self.search_var = tk.StringVar()
        self.status_var = tk.StringVar(value="All")
        self.network_var = tk.StringVar(value=get_setting("default_network", "192.168.1.0/24"))
        self.status_text = tk.StringVar(value="Sẵn sàng")
        self._init_table()
        self._build_ui()
        self.refresh()

    def _connect(self):
        return get_connection()

    def _init_table(self):
        init_database()
        conn = self._connect()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ip_mac_inventory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE NOT NULL,
                    mac TEXT,
                    hostname TEXT,
                    status TEXT DEFAULT 'Unknown',
                    note TEXT DEFAULT '',
                    first_seen TEXT,
                    last_seen TEXT
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def _build_ui(self):
        controls = tk.Frame(self.parent, bg=UI_COLORS['surface'], bd=1, relief="solid")
        controls.pack(fill="x", padx=25, pady=(0, 10))
        tk.Label(controls, text="Mạng:", bg=UI_COLORS['surface'], fg=UI_COLORS['text'], font=("Segoe UI", 10, "bold")).pack(side="left", padx=(15, 6), pady=14)
        tk.Entry(controls, textvariable=self.network_var, width=20, font=("Segoe UI", 10)).pack(side="left", pady=14)
        self.scan_btn = tk.Button(controls, text="Quét mạng", command=self.start_scan, bg=UI_COLORS['primary'], fg=UI_COLORS['text'], relief="flat", padx=14, pady=7, cursor="hand2")
        self.scan_btn.pack(side="left", padx=8)
        self.stop_btn = tk.Button(controls, text="Stop", command=self.stop_scan, bg=UI_COLORS['danger_bg'], fg=UI_COLORS['text'], relief="flat", padx=12, pady=7, state="disabled", cursor="hand2")
        self.stop_btn.pack(side="left", padx=(0, 12))
        tk.Label(controls, textvariable=self.status_text, bg=UI_COLORS['surface'], fg=UI_COLORS['muted']).pack(side="left")

        filters = tk.Frame(self.parent, bg=UI_COLORS['background'])
        filters.pack(fill="x", padx=25, pady=(0, 8))
        tk.Label(filters, text="Tìm kiếm:", bg=UI_COLORS['background']).pack(side="left")
        ent = tk.Entry(filters, textvariable=self.search_var, width=30)
        ent.pack(side="left", padx=(6, 12))
        ent.bind("<KeyRelease>", lambda e: self.apply_filters())
        ttk.Combobox(filters, textvariable=self.status_var, values=["All", "Online", "Offline", "Unknown", "Conflict"], state="readonly", width=12).pack(side="left")
        self.status_var.trace_add("write", lambda *_: self.apply_filters())
        tk.Button(filters, text="Làm mới", command=self.refresh).pack(side="left", padx=8)
        tk.Button(filters, text="Sửa ghi chú", command=self.edit_note).pack(side="left", padx=4)
        tk.Button(filters, text="Xuất Excel", command=self.export_excel).pack(side="right", padx=4)
        tk.Button(filters, text="Xuất CSV", command=self.export_csv).pack(side="right", padx=4)

        box = tk.Frame(self.parent, bg=UI_COLORS['surface'], bd=1, relief="solid")
        box.pack(fill="both", expand=True, padx=25, pady=(0, 15))
        columns = ("ip", "mac", "hostname", "status", "conflict", "note", "last_seen")
        self.table = ttk.Treeview(box, columns=columns, show="headings", selectmode="browse")
        headings = {"ip":"Địa chỉ IP", "mac":"Địa chỉ MAC", "hostname":"Tên máy", "status":"Trạng thái", "conflict":"Conflict", "note":"Note", "last_seen":"Lần cuối phát hiện"}
        widths = {"ip":130, "mac":155, "hostname":180, "status":85, "conflict":90, "note":220, "last_seen":150}
        for col in columns:
            self.table.heading(col, text=headings[col])
            self.table.column(col, width=widths[col], anchor="w")
        ybar = ttk.Scrollbar(box, orient="vertical", command=self.table.yview)
        xbar = ttk.Scrollbar(box, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        self.table.grid(row=0, column=0, sticky="nsew")
        ybar.grid(row=0, column=1, sticky="ns")
        xbar.grid(row=1, column=0, sticky="ew")
        box.rowconfigure(0, weight=1); box.columnconfigure(0, weight=1)
        self.table.bind("<Double-1>", lambda e: self.edit_note())

    def refresh(self):
        conn = self._connect()
        try:
            rows = [dict(r) for r in conn.execute("SELECT * FROM ip_mac_inventory ORDER BY ip").fetchall()]
        finally:
            conn.close()
        # A MAC appearing on multiple IPs is suspicious and is flagged for review.
        mac_counts = {}
        for r in rows:
            mac = (r.get("mac") or "").strip().upper()
            if mac:
                mac_counts[mac] = mac_counts.get(mac, 0) + 1
        for r in rows:
            mac = (r.get("mac") or "").strip().upper()
            r["conflict"] = "MAC multi-IP" if mac and mac_counts.get(mac, 0) > 1 else ""
        self.rows = rows
        self.apply_filters()
        self.status_text.set(f"{len(rows)} saved entries")

    def apply_filters(self):
        q = self.search_var.get().strip().lower()
        sf = self.status_var.get()
        for item in self.table.get_children(): self.table.delete(item)
        for r in self.rows:
            hay = " ".join(str(r.get(k) or "") for k in ("ip", "mac", "hostname", "note")).lower()
            if q and q not in hay: continue
            display_status = "Conflict" if r.get("conflict") else (r.get("status") or "Unknown")
            if sf != "All" and display_status != sf: continue
            self.table.insert("", "end", iid=str(r["id"]), values=(r.get("ip",""), r.get("mac",""), r.get("hostname",""), r.get("status","Unknown"), r.get("conflict",""), r.get("note",""), r.get("last_seen","")))

    def start_scan(self):
        network = self.network_var.get().strip()
        try: ipaddress.ip_network(network, strict=False)
        except ValueError:
            messagebox.showerror("Invalid network", "Enter a valid network, for example 192.168.1.0/24")
            return
        if self.scan_thread and self.scan_thread.is_alive(): return
        self.stop_event = threading.Event()
        self.scan_btn.config(state="disabled"); self.stop_btn.config(state="normal")
        self.status_text.set("Scanning...")
        self.scan_thread = threading.Thread(target=self._scan_worker, args=(network,), daemon=True)
        self.scan_thread.start()

    def _scan_worker(self, network):
        try:
            results = scan_network(network, max_workers=50, timeout=1000, stop_event=self.stop_event)
            self.parent.after(0, lambda: self._save_scan(results))
        except Exception as exc:
            self.parent.after(0, lambda e=str(exc): self._scan_error(e))

    def _save_scan(self, results):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = self._connect()
        try:
            for r in results:
                ip = (r.get("ip") or "").strip()
                if not ip: continue
                old = conn.execute("SELECT id, note, first_seen FROM ip_mac_inventory WHERE ip=?", (ip,)).fetchone()
                if old:
                    conn.execute("UPDATE ip_mac_inventory SET mac=?, hostname=?, status=?, last_seen=? WHERE ip=?", (r.get("mac", ""), r.get("hostname", ""), r.get("status", "Unknown"), now, ip))
                else:
                    conn.execute("INSERT INTO ip_mac_inventory(ip,mac,hostname,status,note,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)", (ip, r.get("mac", ""), r.get("hostname", ""), r.get("status", "Unknown"), "", now, now))
            conn.commit()
        finally:
            conn.close()
        stopped = bool(self.stop_event and self.stop_event.is_set())
        self.scan_btn.config(state="normal"); self.stop_btn.config(state="disabled")
        self.activity_callback(f"IP/MAC scan {'stopped' if stopped else 'completed'}: {len(results)} hosts processed.")
        self.refresh()
        self.status_text.set(f"{'Stopped' if stopped else 'Completed'} - {len(results)} hosts")

    def _scan_error(self, error):
        self.scan_btn.config(state="normal"); self.stop_btn.config(state="disabled")
        self.status_text.set("Scan error")
        messagebox.showerror("Quản lý IP / MAC", error)

    def stop_scan(self):
        if self.stop_event: self.stop_event.set()
        self.status_text.set("Stopping...")
        self.stop_btn.config(state="disabled")

    def edit_note(self):
        selected = self.table.selection()
        if not selected:
            messagebox.showinfo("Quản lý IP / MAC", "Select an entry first.")
            return
        row_id = int(selected[0])
        row = next((r for r in self.rows if r["id"] == row_id), None)
        if not row: return
        note = simpledialog.askstring("Device note", f"Note for {row['ip']}:", initialvalue=row.get("note") or "", parent=self.parent)
        if note is None: return
        conn = self._connect()
        try:
            conn.execute("UPDATE ip_mac_inventory SET note=? WHERE id=?", (note.strip(), row_id)); conn.commit()
        finally: conn.close()
        self.refresh()

    def _export_rows(self):
        return [{"Địa chỉ IP":r.get("ip",""), "Địa chỉ MAC":r.get("mac",""), "Tên máy":r.get("hostname",""), "Trạng thái":r.get("status",""), "Conflict":r.get("conflict",""), "Note":r.get("note",""), "Phát hiện lần đầu":r.get("first_seen",""), "Lần cuối phát hiện":r.get("last_seen","")} for r in self.rows]

    def export_excel(self):
        path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel workbook", "*.xlsx")], initialfile="ip_mac_inventory.xlsx")
        if not path: return
        try:
            pd.DataFrame(self._export_rows()).to_excel(path, index=False)
            messagebox.showinfo("Export", "Excel file exported successfully.")
        except Exception as exc: messagebox.showerror("Export", str(exc))

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV file", "*.csv")], initialfile="ip_mac_inventory.csv")
        if not path: return
        try:
            pd.DataFrame(self._export_rows()).to_csv(path, index=False, encoding="utf-8-sig")
            messagebox.showinfo("Export", "CSV file exported successfully.")
        except Exception as exc: messagebox.showerror("Export", str(exc))
