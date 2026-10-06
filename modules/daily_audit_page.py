from modules.ui_theme import PALETTE as UI_COLORS
import json
import os
import platform
import subprocess
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk, messagebox
from app_runtime import resource_path, hidden_subprocess_kwargs


class DailyAuditPage(tk.Frame):
    def __init__(self, parent, activity_callback=None):
        super().__init__(parent, bg=UI_COLORS['background'])
        self.activity_callback = activity_callback or (lambda _msg: None)
        self.audit_dir = resource_path("tools", "daily_audit")
        self.config_path = self.audit_dir / "config.json"
        self.script_path = self.audit_dir / "Daily-Audit.ps1"
        self.scheduler_path = self.audit_dir / "Install-ScheduledTask.ps1"
        self.current_report = None
        self.current_json = None
        self.pack(fill="both", expand=True, padx=25, pady=(0, 20))
        self._build_ui()
        self.refresh_reports()

    def _build_ui(self):
        top = tk.Frame(self, bg=UI_COLORS['surface'], bd=1, relief="solid")
        top.pack(fill="x", pady=(0, 12))

        tk.Label(top, text="Windows Server Daily Audit", bg=UI_COLORS['surface'], fg=UI_COLORS['text'],
                 font=("Segoe UI", 16, "bold")).pack(anchor="w", padx=16, pady=(14, 2))
        tk.Label(top, text="Event Log, tài nguyên, dịch vụ, firewall, cổng TCP, Defender, tài khoản, patch và backup.",
                 bg=UI_COLORS['surface'], fg=UI_COLORS['muted'], font=("Segoe UI", 9)).pack(anchor="w", padx=16, pady=(0, 12))

        actions = tk.Frame(top, bg=UI_COLORS['surface'])
        actions.pack(fill="x", padx=16, pady=(0, 14))
        self.run_btn = ttk.Button(actions, text="Chạy Audit ngay", command=self.run_audit)
        self.run_btn.pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Làm mới báo cáo", command=self.refresh_reports).pack(side="left", padx=4)
        ttk.Button(actions, text="Mở báo cáo HTML", command=self.open_report).pack(side="left", padx=4)
        ttk.Button(actions, text="Mở thư mục báo cáo", command=self.open_report_folder).pack(side="left", padx=4)
        ttk.Button(actions, text="Cài lịch chạy hằng ngày", command=self.install_schedule).pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Sẵn sàng")
        tk.Label(top, textvariable=self.status_var, bg=UI_COLORS['surface'], fg=UI_COLORS['accent'],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=16, pady=(0, 12))

        summary = tk.Frame(self, bg=UI_COLORS['background'])
        summary.pack(fill="x", pady=(0, 12))
        self.cards = {}
        for key, label in [("High", "HIGH"), ("Warn", "WARN"), ("Review", "REVIEW"), ("Info", "INFO")]:
            card = tk.Frame(summary, bg=UI_COLORS['surface'], bd=1, relief="solid")
            card.pack(side="left", fill="x", expand=True, padx=(0, 8))
            value = tk.StringVar(value="0")
            tk.Label(card, text=label, bg=UI_COLORS['surface'], fg=UI_COLORS['muted'], font=("Segoe UI", 9, "bold")).pack(pady=(10, 0))
            tk.Label(card, textvariable=value, bg=UI_COLORS['surface'], fg=UI_COLORS['text'], font=("Segoe UI", 20, "bold")).pack(pady=(0, 10))
            self.cards[key] = value

        table_box = tk.Frame(self, bg=UI_COLORS['surface'], bd=1, relief="solid")
        table_box.pack(fill="both", expand=True)
        columns = ("Severity", "Category", "Item", "Details")
        self.tree = ttk.Treeview(table_box, columns=columns, show="headings", height=18)
        widths = {"Severity": 90, "Category": 130, "Item": 210, "Details": 620}
        for c in columns:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=widths[c], anchor="w")
        scroll_y = ttk.Scrollbar(table_box, orient="vertical", command=self.tree.yview)
        scroll_x = ttk.Scrollbar(table_box, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        scroll_y.pack(side="right", fill="y", pady=10, padx=(0, 10))
        scroll_x.pack(side="bottom", fill="x", padx=10)

    def _load_config(self):
        try:
            return json.loads(self.config_path.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            messagebox.showerror("Daily Audit", f"Không đọc được config.json:\n{exc}")
            return None

    def _expanded_report_dir(self):
        cfg = self._load_config()
        if not cfg:
            return None
        raw = str(cfg.get("ReportDirectory", r"C:\DailyAudit\Reports"))
        return Path(os.path.expandvars(raw))

    def run_audit(self):
        if platform.system() != "Windows":
            messagebox.showwarning("Daily Audit", "Tính năng này chạy trên Windows/Windows Server.")
            return
        if not self.script_path.exists():
            messagebox.showerror("Daily Audit", f"Không tìm thấy:\n{self.script_path}")
            return
        self.run_btn.configure(state="disabled")
        self.status_var.set("Đang chạy audit...")
        self.activity_callback("Bắt đầu Windows Daily Audit")
        threading.Thread(target=self._run_audit_worker, daemon=True).start()

    def _run_audit_worker(self):
        try:
            cmd = [
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(self.script_path), "-ConfigPath", str(self.config_path)
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=900, **hidden_subprocess_kwargs())
            output = (result.stdout or "") + "\n" + (result.stderr or "")
            self.after(0, lambda: self._audit_finished(result.returncode, output.strip()))
        except Exception as exc:
            self.after(0, lambda: self._audit_failed(str(exc)))

    def _audit_finished(self, code, output):
        self.run_btn.configure(state="normal")
        label = "Hoàn tất"
        if code == 2:
            label = "Hoàn tất - có HIGH"
        elif code == 1:
            label = "Hoàn tất - có WARN"
        elif code not in (0, 1, 2):
            label = f"Kết thúc với mã {code}"
        self.status_var.set(label)
        self.activity_callback(f"Windows Daily Audit: {label}")
        self.refresh_reports()
        if code in (1,2):
            try:
                from modules.advanced_pages import notify_alert
                notify_alert(platform.node() or 'localhost','Daily Audit',label,'Critical' if code==2 else 'Warning',event_key=f'daily-audit|{platform.node()}|{code}|{__import__("datetime").date.today()}')
            except Exception:
                pass
        if code not in (0, 1, 2) and output:
            messagebox.showwarning("Daily Audit", output[-3000:])

    def _audit_failed(self, error):
        self.run_btn.configure(state="normal")
        self.status_var.set("Audit thất bại")
        self.activity_callback(f"Windows Daily Audit thất bại: {error}")
        try:
            from modules.advanced_pages import notify_alert
            notify_alert(platform.node() or 'localhost','Daily Audit Failure',error,'Critical',event_key=f'daily-audit-fail|{platform.node()}|{__import__("datetime").date.today()}')
        except Exception:
            pass
        messagebox.showerror("Daily Audit", error)

    def refresh_reports(self):
        report_dir = self._expanded_report_dir()
        if not report_dir or not report_dir.exists():
            self.status_var.set("Chưa có thư mục báo cáo")
            return
        json_files = sorted(report_dir.glob("daily_audit_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        html_files = sorted(report_dir.glob("daily_audit_*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
        self.current_json = json_files[0] if json_files else None
        self.current_report = html_files[0] if html_files else None
        if not self.current_json:
            self.status_var.set("Chưa có báo cáo JSON")
            return
        try:
            data = json.loads(self.current_json.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            self.status_var.set(f"Không đọc được báo cáo: {exc}")
            return

        for row in self.tree.get_children():
            self.tree.delete(row)
        counts = {"HIGH": 0, "WARN": 0, "REVIEW": 0, "INFO": 0}
        for finding in data.get("Findings", []):
            sev = str(finding.get("Severity", "INFO")).upper()
            counts[sev] = counts.get(sev, 0) + 1
            self.tree.insert("", "end", values=(
                sev,
                finding.get("Category", ""),
                finding.get("Item", ""),
                finding.get("Details", ""),
            ))
        self.cards["High"].set(str(data.get("High", counts.get("HIGH", 0))))
        self.cards["Warn"].set(str(data.get("Warn", counts.get("WARN", 0))))
        self.cards["Review"].set(str(data.get("Review", counts.get("REVIEW", 0))))
        self.cards["Info"].set(str(counts.get("INFO", 0)))
        self.status_var.set(f"Báo cáo gần nhất: {data.get('GeneratedAt', self.current_json.name)}")

    def open_report(self):
        if not self.current_report or not self.current_report.exists():
            self.refresh_reports()
        if not self.current_report or not self.current_report.exists():
            messagebox.showinfo("Daily Audit", "Chưa có báo cáo HTML.")
            return
        os.startfile(str(self.current_report))

    def open_report_folder(self):
        report_dir = self._expanded_report_dir()
        if report_dir is None:
            return
        report_dir.mkdir(parents=True, exist_ok=True)
        if platform.system() == "Windows":
            os.startfile(str(report_dir))
        else:
            messagebox.showinfo("Daily Audit", str(report_dir))

    def install_schedule(self):
        if platform.system() != "Windows":
            messagebox.showwarning("Daily Audit", "Task Scheduler chỉ cài được trên Windows.")
            return
        if not self.scheduler_path.exists():
            messagebox.showerror("Daily Audit", f"Không tìm thấy:\n{self.scheduler_path}")
            return
        try:
            cmd = [
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(self.scheduler_path)
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, **hidden_subprocess_kwargs())
            if result.returncode == 0:
                self.activity_callback("Đã cài lịch Windows Daily Audit")
                messagebox.showinfo("Daily Audit", (result.stdout or "Đã cài lịch chạy hằng ngày.").strip())
            else:
                messagebox.showerror("Daily Audit", ((result.stdout or "") + "\n" + (result.stderr or "")).strip())
        except Exception as exc:
            messagebox.showerror("Daily Audit", str(exc))
