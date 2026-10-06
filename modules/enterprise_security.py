"""Enterprise defensive-security features for NetworkAutomation.

The module is intentionally defensive: it inventories registered assets, performs
read-only reachability/TLS checks, records security events, and calculates an
explainable risk score. It does not exploit services or alter remote systems.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import ssl
import threading
from datetime import datetime, timezone
import tkinter as tk
from tkinter import ttk, messagebox

from database.db import get_connection, init_database
from modules.ui_theme import PALETTE as UI_COLORS

DEFAULT_PORTS = (22, 80, 443, 445, 3389)
SEVERITY_POINTS = {"INFO": 0, "LOW": 5, "MEDIUM": 15, "HIGH": 30, "CRITICAL": 50}


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _connect():
    init_database()
    return get_connection()


def ensure_enterprise_security_tables():
    c = _connect()
    try:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS security_assets(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                ip TEXT NOT NULL UNIQUE,
                expected_mac TEXT DEFAULT '',
                expected_hostname TEXT DEFAULT '',
                criticality TEXT NOT NULL DEFAULT 'MEDIUM',
                owner TEXT DEFAULT '',
                environment TEXT DEFAULT 'Production',
                identity_hash TEXT DEFAULT '',
                last_verified TEXT,
                identity_status TEXT DEFAULT 'UNKNOWN',
                created_at TEXT,
                updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS security_events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_ip TEXT,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                detail TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'OPEN',
                fingerprint TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS security_checks(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_ip TEXT NOT NULL,
                check_type TEXT NOT NULL,
                result TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'INFO',
                detail_json TEXT DEFAULT '{}',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_security_events_status ON security_events(status,severity,created_at);
            CREATE INDEX IF NOT EXISTS idx_security_checks_asset ON security_checks(asset_ip,created_at);
            """
        )
        c.commit()
    finally:
        c.close()


def normalize_ip(value: str) -> str:
    return str(ipaddress.ip_address((value or "").strip()))


def asset_identity_hash(ip: str, mac: str = "", hostname: str = "") -> str:
    material = "|".join((normalize_ip(ip), (mac or "").strip().lower(), (hostname or "").strip().lower()))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def sync_registered_assets():
    """Import known devices into the security inventory without deleting manual data."""
    ensure_enterprise_security_tables()
    c = _connect()
    try:
        tables = {r["name"] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        rows = []
        if "network_devices" in tables:
            nd_cols = {r["name"] for r in c.execute("PRAGMA table_info(network_devices)")}
            mac_expr = "COALESCE(mac,'')" if "mac" in nd_cols else "''"
            host_expr = "COALESCE(name,'')" if "name" in nd_cols else ("COALESCE(device_name,'')" if "device_name" in nd_cols else "''")
            ip_col = "ip" if "ip" in nd_cols else "ip_address"
            rows.extend(c.execute(f"SELECT id,{ip_col} ip,{mac_expr} mac,{host_expr} hostname FROM network_devices WHERE {ip_col} IS NOT NULL AND TRIM({ip_col})<>''").fetchall())
        if "devices" in tables:
            d_cols = {r["name"] for r in c.execute("PRAGMA table_info(devices)")}
            mac_expr = "COALESCE(mac,'')" if "mac" in d_cols else "''"
            host_expr = "COALESCE(hostname,'')" if "hostname" in d_cols else "''"
            ip_col = "ip" if "ip" in d_cols else "ip_address"
            rows.extend(c.execute(f"SELECT id,{ip_col} ip,{mac_expr} mac,{host_expr} hostname FROM devices WHERE {ip_col} IS NOT NULL AND TRIM({ip_col})<>''").fetchall())
        count = 0
        for row in rows:
            try:
                ip = normalize_ip(row["ip"])
            except ValueError:
                continue
            mac = (row["mac"] or "").strip()
            hostname = (row["hostname"] or "").strip()
            ident = asset_identity_hash(ip, mac, hostname)
            c.execute(
                """INSERT INTO security_assets(device_id,ip,expected_mac,expected_hostname,identity_hash,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(ip) DO UPDATE SET
                     device_id=COALESCE(security_assets.device_id,excluded.device_id),
                     expected_mac=CASE WHEN security_assets.expected_mac='' THEN excluded.expected_mac ELSE security_assets.expected_mac END,
                     expected_hostname=CASE WHEN security_assets.expected_hostname='' THEN excluded.expected_hostname ELSE security_assets.expected_hostname END,
                     identity_hash=CASE WHEN security_assets.identity_hash='' THEN excluded.identity_hash ELSE security_assets.identity_hash END,
                     updated_at=excluded.updated_at""",
                (row["id"], ip, mac, hostname, ident, _now(), _now()),
            )
            count += 1
        c.commit()
        return count
    finally:
        c.close()


def record_event(asset_ip: str, source: str, event_type: str, severity: str, title: str, detail: str = ""):
    ensure_enterprise_security_tables()
    severity = severity.upper()
    if severity not in SEVERITY_POINTS:
        raise ValueError("Mức độ sự kiện không hợp lệ")
    ip = normalize_ip(asset_ip) if asset_ip else ""
    fingerprint = hashlib.sha256(f"{ip}|{source}|{event_type}|{title}|{detail}".encode()).hexdigest()
    c = _connect()
    try:
        existing = c.execute(
            "SELECT id FROM security_events WHERE fingerprint=? AND status='OPEN' ORDER BY id DESC LIMIT 1", (fingerprint,)
        ).fetchone()
        if existing:
            c.execute("UPDATE security_events SET updated_at=? WHERE id=?", (_now(), existing["id"]))
            event_id = existing["id"]
        else:
            cur = c.execute(
                "INSERT INTO security_events(asset_ip,source,event_type,severity,title,detail,status,fingerprint,created_at,updated_at) VALUES(?,?,?,?,?,?,'OPEN',?,?,?)",
                (ip, source[:80], event_type[:80], severity, title[:180], detail[:4000], fingerprint, _now(), _now()),
            )
            event_id = cur.lastrowid
        c.commit()
        return event_id
    finally:
        c.close()


def close_event(event_id: int):
    c = _connect()
    try:
        c.execute("UPDATE security_events SET status='CLOSED',updated_at=? WHERE id=?", (_now(), int(event_id)))
        c.commit()
    finally:
        c.close()


def calculate_risk(asset_ip: str) -> dict:
    """Simple explainable risk model, intentionally capped at 100."""
    ip = normalize_ip(asset_ip)
    c = _connect()
    try:
        rows = c.execute("SELECT severity,COUNT(*) n FROM security_events WHERE asset_ip=? AND status='OPEN' GROUP BY severity", (ip,)).fetchall()
        counts = {r["severity"]: r["n"] for r in rows}
        asset = c.execute("SELECT criticality,identity_status FROM security_assets WHERE ip=?", (ip,)).fetchone()
    finally:
        c.close()
    score = sum(SEVERITY_POINTS.get(k, 0) * v for k, v in counts.items())
    reasons = [f"{v} sự kiện {k}" for k, v in sorted(counts.items()) if v]
    if asset:
        if asset["criticality"] == "HIGH":
            score += 10; reasons.append("Tài sản criticality HIGH")
        elif asset["criticality"] == "CRITICAL":
            score += 20; reasons.append("Tài sản criticality CRITICAL")
        if asset["identity_status"] == "MISMATCH":
            score += 35; reasons.append("Identity mismatch")
    score = min(100, score)
    level = "LOW" if score < 20 else "MEDIUM" if score < 50 else "HIGH" if score < 80 else "CRITICAL"
    return {"score": score, "level": level, "reasons": reasons}


def verify_asset_identity(ip: str, observed_mac: str = "", observed_hostname: str = "") -> dict:
    """Compare observed identity with the registered baseline.

    Empty observed fields are treated as unavailable, not as mismatches.
    """
    ip = normalize_ip(ip)
    c = _connect()
    try:
        asset = c.execute("SELECT * FROM security_assets WHERE ip=?", (ip,)).fetchone()
        if not asset:
            raise ValueError("IP chưa có trong danh mục tài sản bảo mật")
        mismatches = []
        if observed_mac and asset["expected_mac"] and observed_mac.strip().lower() != asset["expected_mac"].strip().lower():
            mismatches.append(f"MAC expected={asset['expected_mac']} observed={observed_mac}")
        if observed_hostname and asset["expected_hostname"] and observed_hostname.strip().lower() != asset["expected_hostname"].strip().lower():
            mismatches.append(f"Hostname expected={asset['expected_hostname']} observed={observed_hostname}")
        comparable = bool((observed_mac and asset["expected_mac"]) or (observed_hostname and asset["expected_hostname"]))
        status = "MISMATCH" if mismatches else ("VERIFIED" if comparable else "UNVERIFIED")
        c.execute("UPDATE security_assets SET identity_status=?,last_verified=?,updated_at=? WHERE ip=?", (status, _now(), _now(), ip))
        c.commit()
    finally:
        c.close()
    if mismatches:
        record_event(ip, "DeviceIdentityGuard", "IDENTITY_MISMATCH", "HIGH", "Thiết bị không khớp định danh đã đăng ký", "; ".join(mismatches))
    return {"ip": ip, "status": status, "mismatches": mismatches}


def tcp_probe(ip: str, ports=DEFAULT_PORTS, timeout: float = 0.8) -> dict:
    """Read-only TCP connect check against one registered asset."""
    ip = normalize_ip(ip)
    ensure_enterprise_security_tables()
    c = _connect()
    try:
        if not c.execute("SELECT 1 FROM security_assets WHERE ip=?", (ip,)).fetchone():
            raise ValueError("Chỉ được kiểm tra IP đã đăng ký trong Security Assets")
    finally:
        c.close()
    opened = []
    for port in sorted({int(p) for p in ports if 1 <= int(p) <= 65535})[:32]:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                opened.append(port)
        except (OSError, TimeoutError):
            pass
    detail = {"open_ports": opened, "tested_ports": list(ports)}
    c = _connect()
    try:
        c.execute("INSERT INTO security_checks(asset_ip,check_type,result,severity,detail_json,created_at) VALUES(?,?,?,?,?,?)",
                  (ip, "TCP_CONNECT", "PASS", "INFO", json.dumps(detail), _now()))
        c.commit()
    finally:
        c.close()
    risky = [p for p in opened if p in (23, 21, 445, 3389)]
    if risky:
        record_event(ip, "NetworkProbe", "EXPOSED_SERVICE", "MEDIUM", "Dịch vụ cần rà soát đang mở", "Ports: " + ", ".join(map(str, risky)))
    return detail


def tls_certificate_check(ip: str, port: int = 443, timeout: float = 3.0) -> dict:
    """Inspect a TLS certificate without sending application credentials."""
    ip = normalize_ip(ip)
    c = _connect()
    try:
        if not c.execute("SELECT 1 FROM security_assets WHERE ip=?", (ip,)).fetchone():
            raise ValueError("Chỉ được kiểm tra IP đã đăng ký trong Security Assets")
    finally:
        c.close()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, int(port)), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=ip) as tls:
            cert = tls.getpeercert(binary_form=True)
            cipher = tls.cipher()
            version = tls.version()
    result = {"tls_version": version, "cipher": cipher[0] if cipher else "", "certificate_sha256": hashlib.sha256(cert).hexdigest()}
    severity = "INFO" if version in ("TLSv1.3", "TLSv1.2") else "HIGH"
    c = _connect()
    try:
        c.execute("INSERT INTO security_checks(asset_ip,check_type,result,severity,detail_json,created_at) VALUES(?,?,?,?,?,?)",
                  (ip, "TLS", "PASS" if severity == "INFO" else "REVIEW", severity, json.dumps(result), _now()))
        c.commit()
    finally:
        c.close()
    if severity == "HIGH":
        record_event(ip, "TLSCheck", "WEAK_TLS", "HIGH", "Phiên bản TLS cần nâng cấp", version or "Unknown")
    return result


class EnterpriseSecurityPage(tk.Frame):
    def __init__(self, parent, activity_callback=None, current_role="Viewer"):
        super().__init__(parent, bg=UI_COLORS["background"])
        self.pack(fill="both", expand=True)
        self.activity = activity_callback or (lambda _: None)
        self.current_role = current_role
        ensure_enterprise_security_tables()
        sync_registered_assets()
        self._build()
        self.refresh()

    def _build(self):
        summary = tk.Frame(self, bg=UI_COLORS["background"]); summary.pack(fill="x", padx=18, pady=(8, 6))
        self.summary_var = tk.StringVar(value="Đang tải...")
        tk.Label(summary, textvariable=self.summary_var, bg=UI_COLORS["background"], fg=UI_COLORS["text"], font=("Segoe UI", 11, "bold")).pack(side="left")
        ttk.Button(summary, text="Đồng bộ tài sản", command=self.sync).pack(side="right", padx=4)
        ttk.Button(summary, text="Làm mới", command=self.refresh).pack(side="right", padx=4)

        box = ttk.LabelFrame(self, text="Enterprise Security Assets")
        box.pack(fill="both", expand=True, padx=18, pady=6)
        cols = ("ip", "host", "mac", "criticality", "identity", "risk", "verified")
        self.assets = ttk.Treeview(box, columns=cols, show="headings", selectmode="browse", height=10)
        for c, h, w in [("ip","IP",130),("host","Hostname",170),("mac","MAC baseline",150),("criticality","Criticality",90),("identity","Identity",95),("risk","Risk",100),("verified","Last verified",145)]:
            self.assets.heading(c, text=h); self.assets.column(c, width=w, anchor="w")
        self.assets.pack(fill="both", expand=True, padx=8, pady=8)

        actions = tk.Frame(self, bg=UI_COLORS["background"]); actions.pack(fill="x", padx=18, pady=4)
        ttk.Button(actions, text="TCP Safety Check", command=self.probe_selected).pack(side="left", padx=3)
        ttk.Button(actions, text="TLS Check", command=self.tls_selected).pack(side="left", padx=3)
        ttk.Button(actions, text="Xác minh Identity", command=self.identity_selected).pack(side="left", padx=3)
        ttk.Button(actions, text="Đóng sự kiện", command=self.close_selected_event).pack(side="right", padx=3)

        events = ttk.LabelFrame(self, text="SOC Events / Alerts")
        events.pack(fill="both", expand=True, padx=18, pady=(6, 14))
        cols2 = ("time", "severity", "ip", "type", "title", "status")
        self.events = ttk.Treeview(events, columns=cols2, show="headings", selectmode="browse", height=9)
        for c,h,w in [("time","Time",140),("severity","Severity",80),("ip","Asset",120),("type","Type",150),("title","Title",330),("status","Status",80)]:
            self.events.heading(c,text=h); self.events.column(c,width=w,anchor="w")
        self.events.pack(fill="both",expand=True,padx=8,pady=8)

    def _selected_ip(self):
        sel = self.assets.selection()
        if not sel:
            messagebox.showinfo("Enterprise Security", "Hãy chọn một tài sản trước.", parent=self)
            return None
        return self.assets.item(sel[0], "values")[0]

    def sync(self):
        n = sync_registered_assets(); self.activity(f"Enterprise Security: đồng bộ {n} tài sản"); self.refresh()

    def refresh(self):
        for x in self.assets.get_children(): self.assets.delete(x)
        for x in self.events.get_children(): self.events.delete(x)
        c = _connect()
        try:
            assets = c.execute("SELECT * FROM security_assets ORDER BY ip").fetchall()
            events = c.execute("SELECT * FROM security_events ORDER BY CASE severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END DESC,id DESC LIMIT 250").fetchall()
        finally:
            c.close()
        for a in assets:
            risk = calculate_risk(a["ip"])
            self.assets.insert("", "end", iid=f"a{a['id']}", values=(a["ip"], a["expected_hostname"], a["expected_mac"], a["criticality"], a["identity_status"], f"{risk['score']} {risk['level']}", a["last_verified"] or "-"))
        for e in events:
            self.events.insert("", "end", iid=f"e{e['id']}", values=(e["created_at"], e["severity"], e["asset_ip"], e["event_type"], e["title"], e["status"]))
        open_count = sum(1 for e in events if e["status"] == "OPEN")
        high_count = sum(1 for e in events if e["status"] == "OPEN" and e["severity"] in ("HIGH","CRITICAL"))
        self.summary_var.set(f"Assets: {len(assets)}   |   Open events: {open_count}   |   High/Critical: {high_count}")

    def _background(self, label, fn):
        def work():
            try:
                result = fn()
                self.after(0, lambda: (self.activity(label), self.refresh(), messagebox.showinfo("Enterprise Security", json.dumps(result, ensure_ascii=False, indent=2), parent=self)))
            except Exception as exc:
                self.after(0, lambda msg=str(exc): messagebox.showerror("Enterprise Security", msg, parent=self))
        threading.Thread(target=work, daemon=True).start()

    def probe_selected(self):
        ip = self._selected_ip()
        if ip: self._background(f"TCP safety check: {ip}", lambda: tcp_probe(ip))

    def tls_selected(self):
        ip = self._selected_ip()
        if ip: self._background(f"TLS check: {ip}", lambda: tls_certificate_check(ip))

    def identity_selected(self):
        ip = self._selected_ip()
        if not ip: return
        c = _connect()
        try:
            row = c.execute("SELECT expected_mac,expected_hostname FROM security_assets WHERE ip=?", (ip,)).fetchone()
        finally:
            c.close()
        # Baseline-only verification from the UI. Automated collectors can call
        # verify_asset_identity() with newly observed MAC/hostname values.
        result = verify_asset_identity(ip, row["expected_mac"], row["expected_hostname"])
        self.activity(f"Device Identity Guard: {ip} -> {result['status']}"); self.refresh()
        messagebox.showinfo("Device Identity Guard", f"{ip}: {result['status']}", parent=self)

    def close_selected_event(self):
        if self.current_role == "Viewer":
            messagebox.showwarning("Phân quyền", "Viewer không được đóng sự kiện.", parent=self); return
        sel = self.events.selection()
        if not sel: return
        close_event(int(sel[0][1:])); self.activity("Đóng security event"); self.refresh()


__all__ = [
    "ensure_enterprise_security_tables", "sync_registered_assets", "record_event", "calculate_risk",
    "verify_asset_identity", "tcp_probe", "tls_certificate_check", "EnterpriseSecurityPage", "asset_identity_hash"
]
