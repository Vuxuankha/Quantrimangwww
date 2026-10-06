from modules.ui_theme import PALETTE as UI_COLORS
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
from dataclasses import replace
import threading
import time
import ipaddress
import json
import os
from pathlib import Path
import pandas as pd
import logging
import traceback
from app_runtime import resource_path, setup_logging, LOG_DIR

from modules.network_scan import scan_network
from modules.ping_check import ping_multiple

from database.db import (
    init_database,
    create_device,
    get_all_devices,
    get_device,
    get_device_by_ip,
    search_devices,
    get_devices_by_status,
    update_device,
    delete_device,
    delete_device_by_ip,
    get_device_statistics,
    save_devices,
)
from modules.device_manager import (
    device_manager
)
from modules.ip_mac_manager import IPMacManagerPage
from modules.extra_pages import (
    NetworkDevicesPage,
    RemoteServicePage,
    BackupConfigPage,
    SchedulerPage,
    AlertsPage,
    ReportsPage,
    SystemLogsPage,
    SettingsPage,
    log_activity,
    get_setting,
    set_setting,
)
from modules.advanced_pages import (
    SNMPMonitorPage,
    NetworkTopologyPage,
    SSHAutomationPage,
    NotificationsPage,
    ensure_advanced_tables, _connect,
)
from modules.nms_v2 import (
    NOCDashboardPage, AutoDiscoveryPage, MultiPortMonitorPage, BackupSchedulerPage, NetworkHealthPage,
)
from modules.nms_v3 import ResourceMonitorPage, AdvancedPortMonitorPage, AlertRulesPage, HistoryChartsPage, ensure_v3_tables
from modules.nms_v4 import AutoTopologyPage, BackgroundAlertEngine, ensure_v4_tables
from modules.nms_v5 import (
    ensure_v5_tables, CredentialManagerPage, SecureBackupSchedulerPage,
    ConfigComparePage, UserRolePage, LoginDialog
)
from modules.nms_v6 import (
    ensure_v6_tables, audit, MonitoringService, MonitoringServicePage, AuditLogPage, RestoreConfigPage
)
from modules.nms_v7 import ensure_v7_tables, DeviceProfilesPage
from modules.nms_v8 import ensure_v8_tables, OrganizationPage, MaintenanceWindowsPage
from modules.nms_v9 import ensure_v9_tables, SLAAvailabilityPage, IncidentCenterPage, CapacityPlanningPage
from modules.nms_v10 import (
    ensure_v10_tables, RootCauseEngine, DeviceDependenciesPage,
    RootCauseAnalysisPage, ServiceImpactPage
)
from modules.nms_v11 import ensure_v11_tables, JobQueueEngine, StableCorePage
from modules.nms_v12 import ensure_v12_tables, SNMPv3CredentialsPage, VendorDriverPage, SecureSNMPDiagnosticsPage


from modules.auto_ip import AutomationEngine, load_options, parse_text, parse_excel
from modules.auto_ip_page import AutoIPPage
from modules.daily_audit_page import DailyAuditPage
from modules.security_audit import SecurityAuditPage
from modules.enterprise_security import EnterpriseSecurityPage, ensure_enterprise_security_tables
from modules.auto_audit_scheduler import AutoAuditSchedulerEngine
from modules.server_monitor import ServerMonitorPage, ensure_server_monitor_tables


class NetworkAutomationApp:

    def __init__(self, root, session_user=None):

        self.root = root
        self._closing = False
        self.exit_reason = 'close'
        self.session_user = session_user or {"username": "local-admin", "role": "Admin", "bootstrap": True}
        self.current_role = self.session_user.get("role", "Viewer")
        # Khởi tạo/migrate toàn bộ schema trước khi bất kỳ màn hình nào đọc dữ liệu.
        ensure_advanced_tables()
        ensure_v3_tables()
        ensure_v4_tables()
        ensure_v5_tables()
        ensure_v6_tables()
        ensure_v7_tables()
        ensure_v8_tables()
        ensure_v9_tables()
        ensure_v10_tables()
        ensure_v11_tables()
        ensure_v12_tables()
        ensure_enterprise_security_tables()

        self.root.title(
            "Công cụ Tự động hóa Mạng "
        )

        self.root.geometry(
            "1400x800"
        )

        self.root.minsize(
            800,
            600
        )

        # ==================================================
        # VARIABLES
        # ==================================================

        self.current_page = None

        self.activity_logs = []


        # --------------------------------------------------
        # NETWORK SCAN
        # --------------------------------------------------

        self.scan_running = False
        self.scan_stop_event = None
        self.scan_thread = None

        self.scan_total = 0
        self.scan_completed = 0
        self.scan_online = 0
        self.scan_offline = 0

        self.scan_start_time = None

        # IP đang chạy
        self.scan_active_ips = {}

        # Timer cập nhật thời gian
        self.scan_timer_job = None

        # --------------------------------------------------
        # SCAN RESULTS
        # --------------------------------------------------

        self.scan_results = []

        # --------------------------------------------------
        # PING MONITOR
        # --------------------------------------------------

        self.auto_ping_running = False
        self.auto_ping_job = None
        self.ping_running = False

        # --------------------------------------------------
        # DEVICE MANAGER
        # --------------------------------------------------

        self.device_search_var = None
        self.device_status_filter_var = None
        self.device_table = None

        # ==================================================
        # STYLE
        # ==================================================

        self.setup_style()

        # ==================================================
        # MAIN LAYOUT
        # ==================================================

        self.create_layout()

        # ==================================================
        # DEFAULT PAGE
        # ==================================================

        self.show_dashboard()

        # v3.4: tự động đánh giá Alert Rules nền mỗi 60 giây.
        self.background_alert_engine = BackgroundAlertEngine(self.root, self.add_activity)
        self.monitoring_service = MonitoringService(self.root, self.add_activity)
        self.job_queue_engine = JobQueueEngine()
        self.root_cause_engine = RootCauseEngine(self.root, self.add_activity)
        self.auto_audit_scheduler = AutoAuditSchedulerEngine(self.root, self.add_activity)
        audit(self.session_user.get('username'), self.current_role, 'Mở ứng dụng', 'Network Automation', 'Khởi tạo phiên làm việc')
        self.root.protocol('WM_DELETE_WINDOW', self.on_close)

    # ======================================================
    # STYLE
    # ======================================================

    def setup_style(self):
        from modules.ui_theme import apply_theme
        apply_theme(self.root)

    # ======================================================
    # LAYOUT
    # ======================================================

    def create_layout(self):

        from modules.responsive_layout import SidebarPolicy
        self.sidebar_policy=SidebarPolicy()
        self.topbar=tk.Frame(self.root,bg='#151F2B',height=48)
        self.topbar.pack(side='top',fill='x')
        tk.Button(self.topbar,text='☰ Menu',command=self.toggle_sidebar,bg='#151F2B',fg='#E8F0F6',relief='flat',padx=14,pady=10).grid(row=0,column=0,sticky='w')
        self.topbar_title=tk.StringVar(value='Network Automation')
        tk.Label(self.topbar,textvariable=self.topbar_title,bg='#151F2B',fg='#E8F0F6',font=('Segoe UI',11,'bold'),anchor='w',width=1).grid(row=0,column=1,sticky='ew',padx=10)
        from modules.account_ui import AccountHeader
        self.account_header = AccountHeader(self.topbar, self.session_user, [
            ('Hồ sơ cá nhân', self.open_profile),
            ('Đổi mật khẩu', self.open_password),
            ('Nhật ký hoạt động', self.show_audit_log),
            ('Đăng xuất', self.logout),
        ])
        self.account_header.frame.grid(row=0,column=2,sticky='e')
        self.topbar.columnconfigure(1,weight=1)

        self.sidebar = tk.Frame(
            self.root,
            bg=UI_COLORS['sidebar'],
            width=230
        )

        self.sidebar.pack(
            side="left",
            fill="y"
        )

        self.sidebar.pack_propagate(
            False
        )

        self.content = tk.Frame(
            self.root,
            bg=UI_COLORS['background']
        )

        self.content.pack(
            side="right",
            fill="both",
            expand=True
        )

        self.create_sidebar()
        self.root.bind("<Configure>",self.resize_shell,add="+")
        self.root.after_idle(lambda:self.resize_shell(None))

    # ======================================================
    # SIDEBAR
    # ======================================================

    def apply_sidebar_visibility(self):
        if self.sidebar_policy.visible:
            self.sidebar.pack(side='left',fill='y',before=self.content)
        else:
            self.sidebar.pack_forget()

    def toggle_sidebar(self):
        self.sidebar_policy.toggle();self.apply_sidebar_visibility()

    def resize_shell(self,event):
        if self._closing:return
        if event is not None and event.widget is not self.root:return
        self.sidebar_policy.resize(self.root.winfo_width());self.apply_sidebar_visibility()
        if hasattr(self,'account_header'):
            self.account_header.render(compact=self.root.winfo_width()<1100)

    def create_sidebar(self):

        # Phần tiêu đề cố định phía trên.
        title = tk.Label(
            self.sidebar,
            text=f"NETWORK\nAUTOMATION\n\n{self.session_user.get('username','')} • {self.current_role}",
            bg=UI_COLORS['sidebar'],
            fg=UI_COLORS['text'],
            font=("Segoe UI", 16, "bold"),
            justify="left"
        )
        title.pack(padx=20, pady=(20, 12), anchor="w")
        self.sidebar_title = title

        # Menu có thanh cuộn để vẫn dùng được trên màn hình thấp.
        menu_area = tk.Frame(self.sidebar, bg=UI_COLORS['sidebar'])
        menu_area.pack(fill="both", expand=True)

        self.sidebar_canvas = tk.Canvas(
            menu_area, bg=UI_COLORS['sidebar'], highlightthickness=0, bd=0
        )
        sidebar_scroll = tk.Scrollbar(
            menu_area, orient="vertical", command=self.sidebar_canvas.yview
        )
        self.sidebar_menu = tk.Frame(self.sidebar_canvas, bg=UI_COLORS['sidebar'])
        self.sidebar_menu.bind(
            "<Configure>",
            lambda e: self.sidebar_canvas.configure(
                scrollregion=self.sidebar_canvas.bbox("all")
            )
        )
        self._sidebar_window = self.sidebar_canvas.create_window(
            (0, 0), window=self.sidebar_menu, anchor="nw"
        )
        self.sidebar_canvas.bind(
            "<Configure>",
            lambda e: self.sidebar_canvas.itemconfigure(
                self._sidebar_window, width=e.width
            )
        )
        self.sidebar_canvas.configure(yscrollcommand=sidebar_scroll.set)
        self.sidebar_canvas.pack(side="left", fill="both", expand=True)
        sidebar_scroll.pack(side="right", fill="y")

        # Nhóm chức năng theo nghiệp vụ để thanh bên gọn và dễ tìm hơn.
        # Mỗi nhóm có thể thu gọn / mở rộng độc lập.
        menu_groups = [
            ("TỔNG QUAN", [
                ("Tổng quan", self.show_dashboard),
                ("Trung tâm NOC", self.show_noc_dashboard),
            ]),
            ("THIẾT BỊ & IP", [
                ("Quản lý thiết bị", self.show_device_manager),
                ("Quản lý IP / MAC", self.show_ip_mac_manager),
                ("Khám phá mạng", self.show_discovery_hub),
            ]),
            ("GIÁM SÁT", [
                ("Giám sát thiết bị", self.show_monitoring_hub),
                ("Application / Server", self.show_server_monitor),
                ("Wi-Fi / Camera", self.show_extensions),
                ("Sức khỏe mạng", self.show_network_health),
                ("SLA & Độ sẵn sàng", self.show_sla_availability),
            ]),
            ("TỰ ĐỘNG HÓA", [
                ("Trung tâm tự động hóa", self.show_automation_hub),
                ("Audit Windows", self.show_daily_audit),
                ("Baseline & Security", self.show_security_audit),
                ("Enterprise Security", self.show_enterprise_security),
            ]),
            ("SỰ CỐ & BÁO CÁO", [
                ("Cảnh báo", self.show_alerts),
                ("Trung tâm sự cố", self.show_incident_center),
                ("Báo cáo", self.show_reports),
            ]),
            ("QUẢN TRỊ", [
                ("Trung tâm quản trị", self.show_admin_hub),
                ("Quản lý tài khoản", self.show_user_roles),
                ("Notification Center", self.show_notifications),
                ("Cài đặt", self.show_settings),
            ]),
        ]

        # Phân quyền menu theo vai trò đăng nhập.
        if self.current_role == "Viewer":
            allowed = {
                "Tổng quan", "Trung tâm NOC", "Khám phá mạng", "Giám sát thiết bị", "Application / Server",
                "Sức khỏe mạng", "SLA & Độ sẵn sàng", "Cảnh báo", "Enterprise Security",
                "Trung tâm sự cố", "Báo cáo"
            }
            menu_groups = [(g, [(t, c) for t, c in items if t in allowed]) for g, items in menu_groups]
            menu_groups = [(g, items) for g, items in menu_groups if items]
        elif self.current_role == "Operator":
            blocked = {"Trung tâm quản trị", "Quản lý tài khoản", "Cài đặt"}
            menu_groups = [(g, [(t, c) for t, c in items if t not in blocked]) for g, items in menu_groups]
            menu_groups = [(g, items) for g, items in menu_groups if items]

        self.sidebar_groups = {}
        self.nav_buttons = {}

        def toggle_group(group_name):
            info = self.sidebar_groups[group_name]
            frame = info["frame"]
            button = info["button"]
            if info["expanded"]:
                frame.pack_forget()
                info["expanded"] = False
                button.configure(text=f"▸  {group_name}")
            else:
                # Giữ frame ngay sau tiêu đề nhóm tương ứng.
                frame.pack(fill="x", after=button)
                info["expanded"] = True
                button.configure(text=f"▾  {group_name}")

        for group_name, items in menu_groups:
            header = tk.Button(
                self.sidebar_menu,
                text=f"▾  {group_name}",
                bg=UI_COLORS['sidebar'],
                fg=UI_COLORS['accent'],
                activebackground="#172033",
                activeforeground=UI_COLORS['text'],
                relief="flat",
                bd=0,
                anchor="w",
                padx=14,
                pady=7,
                font=("Segoe UI", 9, "bold"),
                cursor="hand2",
            )
            header.pack(fill="x", pady=(4, 0))

            group_frame = tk.Frame(self.sidebar_menu, bg=UI_COLORS['sidebar'])
            group_frame.pack(fill="x")

            self.sidebar_groups[group_name] = {
                "button": header,
                "frame": group_frame,
                "expanded": True,
            }
            header.configure(command=lambda name=group_name: toggle_group(name))

            for text, command in items:
                button = tk.Button(
                    group_frame,
                    text=text,
                    command=lambda title=text,action=command:self.navigate(title,action),
                    bg=UI_COLORS['sidebar'],
                    fg=UI_COLORS['text'],
                    activebackground="#1F2937",
                    activeforeground=UI_COLORS['text'],
                    relief="flat",
                    bd=0,
                    anchor="w",
                    padx=28,
                    pady=6,
                    font=("Segoe UI", 9),
                    cursor="hand2",
                )
                button.pack(fill="x",padx=8,pady=2)
                self.nav_buttons[text]=button

    # ======================================================
    # COMMON
    # ======================================================

    def navigate(self,title,action):
        for label,button in getattr(self,'nav_buttons',{}).items():
            button.configure(bg="#593354" if label==title else UI_COLORS['sidebar'],fg=UI_COLORS['text'])
        action()
        if self.sidebar_policy.compact:
            self.sidebar_policy.visible=False;self.apply_sidebar_visibility()

    def clear_content(self):

        if hasattr(self, "auto_ip_page"):
            self.auto_ip_page.destroy()
            del self.auto_ip_page

        if hasattr(self, "scheduler_page"):
            try:
                self.scheduler_page.destroy()
            except Exception:
                pass
            try:
                del self.scheduler_page
            except Exception:
                pass

        if self.auto_ping_running:

            self.stop_auto_ping(
                silent=True
            )

        if self.scan_running:

            self.stop_scan()

        from modules.responsive_layout import cancel_page_timers
        cancel_page_timers(self.content)

        for widget in self.content.winfo_children():

            widget.destroy()

    def set_page_title(
        self,
        title,
        subtitle=""
    ):

        self.content.configure(bg=UI_COLORS['background'])
        if hasattr(self,'topbar_title'):self.topbar_title.set(title)

        header = tk.Frame(
            self.content,
            bg=UI_COLORS['background']
        )

        header.pack(
            fill="x",
            padx=25,
            pady=(20, 10)
        )

        title_label=tk.Label(
            header,
            text=title,
            wraplength=700,
            justify="left",
            bg=UI_COLORS['background'],
            fg=UI_COLORS['text'],
            font=(
                "Segoe UI",
                22,
                "bold"
            )
        )
        title_label.pack(anchor="w")
        header.bind("<Configure>",lambda event:title_label.configure(wraplength=max(250,event.width)),add="+")

        if subtitle:

            subtitle_label=tk.Label(
                header,
                text=subtitle,
                wraplength=700,
                justify="left",
                bg=UI_COLORS['background'],
                fg=UI_COLORS['muted'],
                font=(
                    "Segoe UI",
                    10
                )
            )
            subtitle_label.pack(anchor="w",pady=(3,0))
            header.bind("<Configure>",lambda event:subtitle_label.configure(wraplength=max(250,event.width)),add="+")

    def add_activity(self, message):

        if self._closing:
            return

        time_text = datetime.now().strftime(
            "%H:%M:%S"
        )

        self.activity_logs.append(
            f"[{time_text}] {message}"
        )

        try:
            log_activity("Application", message)
        except Exception:
            pass
        try:
            audit(self.session_user.get("username"), self.current_role, "Hoạt động", self.current_page or "Ứng dụng", message)
        except Exception:
            pass

    def _show_compact_hub(self, title, subtitle, actions):
        self.current_page = title
        self.clear_content()
        self.set_page_title(title, subtitle)

        wrap = tk.Frame(self.content, bg=UI_COLORS['background'])
        wrap.pack(fill="both", expand=True, padx=25, pady=(4, 20))

        tk.Label(
            wrap,
            text="Chọn công cụ cần sử dụng",
            bg=UI_COLORS['background'],
            fg=UI_COLORS['muted'],
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(0, 10))

        grid = tk.Frame(wrap, bg=UI_COLORS['background'])
        grid.pack(fill="both", expand=True)

        visible = []
        for item in actions:
            label, desc, command, roles = item
            if roles and self.current_role not in roles:
                continue
            visible.append((label, desc, command))

        columns = 3
        for i, (label, desc, command) in enumerate(visible):
            row, col = divmod(i, columns)
            grid.grid_columnconfigure(col, weight=1, uniform="hub")
            card = tk.Frame(grid, bg=UI_COLORS['surface'], bd=1, relief="solid", cursor="hand2")
            card.grid(row=row, column=col, sticky="nsew", padx=6, pady=6, ipadx=6, ipady=6)
            tk.Label(card, text=label, bg=UI_COLORS['surface'], fg=UI_COLORS['text'],
                     font=("Segoe UI", 12, "bold"), anchor="w").pack(fill="x", padx=14, pady=(12, 4))
            tk.Label(card, text=desc, bg=UI_COLORS['surface'], fg=UI_COLORS['muted'],
                     font=("Segoe UI", 9), anchor="w", justify="left", wraplength=290).pack(fill="x", padx=14, pady=(0, 10))
            btn = ttk.Button(card, text="Mở", command=command)
            btn.pack(anchor="w", padx=14, pady=(0, 12))
            for widget in (card,):
                widget.bind("<Button-1>", lambda _e, cmd=command: cmd())

    def show_discovery_hub(self):
        self._show_compact_hub(
            "Khám phá mạng",
            "Quét, phát hiện, tổ chức và dựng sơ đồ thiết bị mạng.",
            [
                ("Tự động phát hiện", "Phát hiện thiết bị mới trong mạng.", self.show_auto_discovery, None),
                ("Quét mạng", "Quét IP và trạng thái thiết bị theo dải mạng.", self.show_network_scan, None),
                ("Thiết bị mạng", "Danh sách và thông tin thiết bị mạng.", self.show_network_devices, {"Admin", "Operator"}),
                ("Site / Nhóm / VLAN", "Tổ chức thiết bị theo site, nhóm và VLAN.", self.show_organization, {"Admin", "Operator"}),
                ("Sơ đồ mạng", "Xem topology mạng hiện tại.", self.show_network_topology, None),
                ("Topology LLDP/CDP", "Tự dựng topology từ LLDP/CDP.", self.show_auto_topology, None),
                ("Hồ sơ thiết bị", "Quản lý profile thiết bị theo hãng.", self.show_device_profiles, {"Admin", "Operator"}),
                ("Vendor Driver Engine", "Driver/logic theo hãng thiết bị.", self.show_vendor_drivers, None),
            ],
        )

    def show_monitoring_hub(self):
        self._show_compact_hub(
            "Giám sát thiết bị",
            "Một nơi cho Ping, SNMP, tài nguyên, cổng, lịch sử và phân tích dung lượng.",
            [
                ("Giám sát Ping", "Theo dõi độ trễ và trạng thái kết nối.", self.show_ping_monitor, None),
                ("Giám sát SNMP", "Theo dõi thiết bị qua SNMP.", self.show_snmp_monitor, None),
                ("SNMP v2c/v3 Diagnostics", "Chẩn đoán kết nối và credential SNMP.", self.show_secure_snmp_diagnostics, None),
                ("CPU / RAM", "Giám sát tài nguyên qua SNMP.", self.show_resource_monitor, None),
                ("Giám sát cổng", "Theo dõi trạng thái và chỉ số cổng nâng cao.", self.show_advanced_port_monitor, None),
                ("Nhiều cổng", "Theo dõi nhiều cổng trên nhiều thiết bị.", self.show_multi_port_monitor, None),
                ("Biểu đồ lịch sử", "Xem dữ liệu lịch sử và xu hướng.", self.show_history_charts, None),
                ("Phân tích dung lượng", "Đánh giá xu hướng sử dụng tài nguyên.", self.show_capacity_planning, None),
                ("Phụ thuộc thiết bị", "Theo dõi dependency giữa các thiết bị.", self.show_device_dependencies, None),
                ("Dịch vụ & ảnh hưởng", "Xem mức ảnh hưởng của sự cố đến dịch vụ.", self.show_service_impact, None),
            ],
        )

    def show_extensions(self):
        from modules.extension_page import ExtensionPage
        self.current_page = "Wi-Fi / Camera"
        self.clear_content()
        self.set_page_title("Wi-Fi / Camera", "Chẩn đoán và lịch sử giám sát nền")
        ExtensionPage(self.content)

    def show_server_monitor(self):
        self.current_page = "Application / Server"
        self.clear_content()
        self.set_page_title("Application / Server Monitor", "Giám sát ứng dụng, port và sức khỏe Windows Server")
        ServerMonitorPage(self.content, activity_callback=lambda msg: log_activity(self.current_user, msg))

    def show_automation_hub(self):
        self._show_compact_hub(
            "Trung tâm tự động hóa",
            "Các tác vụ vận hành, sao lưu, SSH, lịch chạy và khôi phục.",
            [
                ("Tự động IP / Excel", "Sinh và xử lý kế hoạch IP từ Excel.", self.show_auto_ip, {"Admin", "Operator"}),
                ("Tự động hóa SSH", "Thực thi tác vụ SSH trên thiết bị.", self.show_ssh_automation, {"Admin", "Operator"}),
                ("Truy cập từ xa", "Mở hoặc quản lý truy cập dịch vụ từ xa.", self.show_remote_service, {"Admin", "Operator"}),
                ("Sao lưu cấu hình", "Sao lưu cấu hình thiết bị.", self.show_backup_config, {"Admin", "Operator"}),
                ("Lịch sao lưu bảo mật", "Lập lịch sao lưu có kiểm soát.", self.show_secure_backup_scheduler, {"Admin", "Operator"}),
                ("So sánh cấu hình", "So sánh các bản cấu hình.", self.show_config_compare, {"Admin", "Operator"}),
                ("Lịch tác vụ", "Lập lịch các job tự động.", self.show_scheduler, {"Admin", "Operator"}),
                ("Daily Audit Windows", "Audit Windows Server hằng ngày.", self.show_daily_audit, {"Admin", "Operator"}),
                ("Baseline & Security", "Phát hiện config drift và kiểm tra security posture read-only.", self.show_security_audit, {"Admin", "Operator"}),
                ("Khôi phục cấu hình", "Khôi phục cấu hình từ bản sao lưu.", self.show_restore_config, {"Admin"}),
            ],
        )

    def show_admin_hub(self):
        self._show_compact_hub(
            "Trung tâm quản trị",
            "Credential, người dùng, nhật ký, dịch vụ nền và cấu hình hệ thống.",
            [
                ("Quản lý Credential", "Lưu và quản lý credential thiết bị.", self.show_credential_manager, {"Admin"}),
                ("Credential SNMPv3", "Quản lý thông tin xác thực SNMPv3.", self.show_snmpv3_credentials, {"Admin"}),
                ("Người dùng & Phân quyền", "Quản lý tài khoản và vai trò.", self.show_user_roles, {"Admin"}),
                ("Nhật ký hệ thống", "Xem log hoạt động hệ thống.", self.show_system_logs, {"Admin", "Operator", "Viewer"}),
                ("Nhật ký Audit", "Xem lịch sử audit và thao tác quản trị.", self.show_audit_log, {"Admin"}),
                ("Dịch vụ giám sát nền", "Quản lý monitoring service chạy nền.", self.show_monitoring_service, {"Admin"}),
                ("Sức khỏe hệ thống", "Kiểm tra lõi và trạng thái ứng dụng.", self.show_stable_core, {"Admin", "Operator"}),
            ],
        )

    def _daily_audit_dashboard_summary(self):
        try:
            cfg_path = resource_path("tools", "daily_audit", "config.json")
            if not cfg_path.exists():
                return "Chưa cấu hình", "Mở Daily Audit để thiết lập", None
            cfg = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
            report_dir = Path(os.path.expandvars(str(cfg.get("ReportDirectory", r"C:\\DailyAudit\\Reports"))))
            files = sorted(report_dir.glob("daily_audit_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            if not files:
                return "Chưa có báo cáo", "Chạy Daily Audit để tạo báo cáo đầu tiên", None
            data = json.loads(files[0].read_text(encoding="utf-8-sig"))
            high = int(data.get("High", 0) or 0)
            warn = int(data.get("Warn", 0) or 0)
            review = int(data.get("Review", 0) or 0)
            status = "Ổn định" if high == 0 and warn == 0 else (f"HIGH: {high}" if high else f"WARN: {warn}")
            detail = f"{warn} WARN • {review} REVIEW • {data.get('GeneratedAt', files[0].name)}"
            return status, detail, files[0]
        except Exception:
            return "Không đọc được", "Có thể mở Daily Audit để kiểm tra chi tiết", None

    # ======================================================
    # DASHBOARD
    # ======================================================

    def show_dashboard(self):
        """Dark NOC dashboard with the existing audited One-Click actions."""
        from modules.dark_dashboard import DarkDashboard
        self.current_page='Tổng quan'
        self.clear_content()
        self.content.configure(bg='#0B131C')
        if hasattr(self,'topbar_title'):self.topbar_title.set('Tổng quan NOC')
        for name,widget in getattr(self,'nav_buttons',{}).items():
            widget.configure(bg='#593354' if name=='Tổng quan' else UI_COLORS['sidebar'],fg=UI_COLORS['text'] if name=='Tổng quan' else UI_COLORS['text'])
        self.dark_dashboard=DarkDashboard(self)

    def _quick_choose_excel(self):
        path = filedialog.askopenfilename(parent=self.root, title="Chọn file Excel IP", filetypes=[("Excel", "*.xlsx")])
        if not path:
            return
        try:
            targets, duplicates = parse_excel(path)
        except Exception as exc:
            messagebox.showerror("One-Click NOC", str(exc), parent=self.root); return
        self.quick_excel_path = path
        self.quick_ip_text.delete("1.0", "end")
        self.quick_ip_text.insert("1.0", "\n".join(t.ip for t in targets))
        self.quick_status_var.set(f"Đã nạp {len(targets)} IP từ Excel; loại {duplicates} IP trùng.")

    def _quick_run_all(self):
        try:
            if not self.quick_authorized_var.get():
                raise PermissionError("Hãy xác nhận bạn có quyền kiểm tra các IP này.")
            text_value = self.quick_ip_text.get("1.0", "end").strip()
            if not text_value:
                raise ValueError("Dán ít nhất một IP hoặc chọn file Excel.")
            targets, duplicates = parse_text(text_value)
            if not targets:
                raise ValueError("Không có IP hợp lệ.")
            if not hasattr(self, "auto_ip_engine"):
                self.auto_ip_engine = AutomationEngine()
            if self.auto_ip_engine.running:
                raise RuntimeError("Một lượt kiểm tra đang chạy.")
            base_options = load_options()
            # Options is an immutable (frozen) dataclass. Build a One-Click copy
            # instead of assigning to its fields in-place.
            options = replace(
                base_options,
                ping=True,
                tcp=True,
                snmp=True,
                resources=True,
                interfaces=True,
                topology=True,
                alerts=True,
                report=True,
                repeat=False,
                notifications=True,
                email_report_after_run=bool(self.quick_email_var.get()),
            )
            self.auto_ip_engine.start(targets, options, self.session_user, authorized=True)
            self.quick_status_var.set(f"Đang kiểm tra {len(targets)} IP" + (f" • bỏ {duplicates} IP trùng" if duplicates else ""))
            self.add_activity(f"One-Click NOC: bắt đầu kiểm tra {len(targets)} IP")
        except Exception as exc:
            messagebox.showerror("One-Click NOC", str(exc), parent=self.root)

    def _quick_poll(self,schedule=True):
        if self.current_page != "Tổng quan" or not hasattr(self, "quick_status_var"):
            return
        try:
            if hasattr(self, "auto_ip_engine"):
                snap = self.auto_ip_engine.snapshot()
                total = max(int(snap.get("total") or 0), 1)
                done = int(snap.get("done") or 0)
                self.quick_progress.configure(maximum=total, value=min(done, total))
                state = snap.get("status", "Ready")
                msg = snap.get("message", "")
                report = snap.get("report_path", "")
                suffix = f" • Báo cáo: {Path(report).name}" if report else ""
                self.quick_status_var.set(f"{state} • {done}/{int(snap.get('total') or 0)} IP" + (f" • {msg}" if msg else "") + suffix)
                self.quick_run_btn.configure(state="disabled" if snap.get("running") else "normal")
        except Exception:
            pass
        if schedule:self.root.after(700, self._quick_poll)

    def _show_dashboard_legacy(self):
        """NOC-first dashboard: surface problems before navigation."""
        self.current_page = "Tổng quan"
        self.clear_content()
        self.set_page_title("Tổng quan NOC", "Tình trạng hạ tầng, cảnh báo và công việc cần xử lý")

        # Collect dashboard data defensively so a partial schema never blocks startup.
        data = {"total": 0, "online": 0, "offline": 0, "alerts": 0, "incidents": 0}
        recent_alerts, problem_devices, recent_incidents = [], [], []
        try:
            c = _connect()
            try:
                data["total"] = c.execute("SELECT COUNT(*) FROM network_devices").fetchone()[0]
                data["online"] = c.execute("SELECT COUNT(*) FROM network_devices WHERE LOWER(COALESCE(status,''))='online'").fetchone()[0]
                data["offline"] = c.execute("SELECT COUNT(*) FROM network_devices WHERE LOWER(COALESCE(status,''))='offline'").fetchone()[0]
                data["alerts"] = c.execute("SELECT COUNT(*) FROM alerts WHERE LOWER(COALESCE(status,''))<>'closed'").fetchone()[0]
                recent_alerts = c.execute("SELECT created_at,severity,ip,alert_type,message FROM alerts WHERE LOWER(COALESCE(status,''))<>'closed' ORDER BY id DESC LIMIT 8").fetchall()
                problem_devices = c.execute("SELECT name,ip,device_type,status FROM network_devices WHERE LOWER(COALESCE(status,''))<>'online' ORDER BY updated_at DESC LIMIT 8").fetchall()
                try:
                    data["incidents"] = c.execute("SELECT COUNT(*) FROM incidents WHERE LOWER(COALESCE(status,'')) NOT IN ('closed','resolved')").fetchone()[0]
                    recent_incidents = c.execute("SELECT last_seen,severity,host,title,status FROM incidents WHERE LOWER(COALESCE(status,'')) NOT IN ('closed','resolved') ORDER BY id DESC LIMIT 6").fetchall()
                except Exception:
                    pass
            finally:
                c.close()
        except Exception:
            pass

        top = tk.Frame(self.content, bg=UI_COLORS['background'])
        top.pack(fill="x", padx=25, pady=(18, 8))
        cards = [
            ("Thiết bị", data["total"], "Tất cả thiết bị đang quản lý"),
            ("Online", data["online"], "Đang hoạt động"),
            ("Offline", data["offline"], "Cần kiểm tra"),
            ("Cảnh báo mở", data["alerts"], "Chưa đóng"),
            ("Sự cố mở", data["incidents"], "Chưa xử lý xong"),
        ]
        for title, value, note in cards:
            card = tk.Frame(top, bg=UI_COLORS['surface'], bd=1, relief="solid")
            card.pack(side="left", fill="both", expand=True, padx=4)
            tk.Label(card, text=title, bg=UI_COLORS['surface'], fg=UI_COLORS['muted'], font=("Segoe UI", 9)).pack(anchor="w", padx=14, pady=(12, 2))
            tk.Label(card, text=str(value), bg=UI_COLORS['surface'], fg=UI_COLORS['text'], font=("Segoe UI", 22, "bold")).pack(anchor="w", padx=14)
            tk.Label(card, text=note, bg=UI_COLORS['surface'], fg=UI_COLORS['muted'], font=("Segoe UI", 8)).pack(anchor="w", padx=14, pady=(0, 12))

        # Daily Audit is a first-class NOC signal.
        audit_status, audit_detail, _audit_file = self._daily_audit_dashboard_summary()
        audit = tk.Frame(self.content, bg=UI_COLORS['surface'], bd=1, relief="solid")
        audit.pack(fill="x", padx=29, pady=6)
        al = tk.Frame(audit, bg=UI_COLORS['surface']); al.pack(side="left", fill="x", expand=True, padx=14, pady=10)
        tk.Label(al, text="Daily Audit Windows", bg=UI_COLORS['surface'], fg=UI_COLORS['text'], font=("Segoe UI", 11, "bold")).pack(anchor="w")
        tk.Label(al, text=f"{audit_status}  •  {audit_detail}", bg=UI_COLORS['surface'], fg=UI_COLORS['muted'], font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 0))
        ttk.Button(audit, text="Chạy / Chi tiết", command=self.show_daily_audit).pack(side="right", padx=14, pady=10)
        ttk.Button(audit, text="Trung tâm NOC", command=self.show_noc_dashboard).pack(side="right", pady=10)

        body = tk.Frame(self.content, bg=UI_COLORS['background'])
        body.pack(fill="both", expand=True, padx=25, pady=(4, 16))
        left = tk.Frame(body, bg=UI_COLORS['surface'], bd=1, relief="solid"); left.pack(side="left", fill="both", expand=True, padx=4)
        right = tk.Frame(body, bg=UI_COLORS['surface'], bd=1, relief="solid"); right.pack(side="left", fill="both", expand=True, padx=4)

        tk.Label(left, text="Cần chú ý", bg=UI_COLORS['surface'], fg=UI_COLORS['text'], font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=12, pady=(10, 6))
        attention = ttk.Treeview(left, columns=("kind","target","detail"), show="headings", height=10)
        for c,t,w in (("kind","Loại",100),("target","Thiết bị / IP",145),("detail","Chi tiết",330)):
            attention.heading(c,text=t); attention.column(c,width=w,anchor="w")
        attention.pack(fill="both", expand=True, padx=10, pady=(0,10))
        for r in problem_devices:
            attention.insert("","end",values=("Thiết bị",r[1] or r[0],f"{r[3] or 'Unknown'} • {r[2] or 'Chưa phân loại'}"))
        for r in recent_alerts[:5]:
            attention.insert("","end",values=(r[1] or "Cảnh báo",r[2] or "-",(r[4] or r[3] or "")[:80]))
        if not attention.get_children(): attention.insert("","end",values=("OK","-","Không có mục bất thường đang hiển thị"))

        tk.Label(right, text="Sự cố & cảnh báo gần đây", bg=UI_COLORS['surface'], fg=UI_COLORS['text'], font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=12, pady=(10, 6))
        events = ttk.Treeview(right, columns=("time","level","target","detail"), show="headings", height=10)
        for c,t,w in (("time","Thời gian",125),("level","Mức",75),("target","Đích",110),("detail","Nội dung",300)):
            events.heading(c,text=t); events.column(c,width=w,anchor="w")
        events.pack(fill="both", expand=True, padx=10, pady=(0,10))
        for r in recent_incidents:
            events.insert("","end",values=(r[0] or "-",r[1] or "-",r[2] or "-",(r[3] or "")[:75]))
        for r in recent_alerts:
            events.insert("","end",values=(r[0] or "-",r[1] or "-",r[2] or "-",(r[4] or r[3] or "")[:75]))
        if not events.get_children(): events.insert("","end",values=("-","OK","-","Chưa có cảnh báo hoặc sự cố đang mở"))

    # ======================================================
    # NETWORK SCAN PAGE
    # ======================================================

    def show_network_scan(self):

        self.current_page = "Quét mạng"

        self.clear_content()

        self.set_page_title(
            "Quét mạng",
            "Realtime network device scanner"
        )

        control = tk.Frame(
            self.content,
            bg=UI_COLORS['surface'],
            bd=1,
            relief="solid"
        )

        control.pack(
            fill="x",
            padx=25,
            pady=10
        )

        tk.Label(
            control,
            text="Mạng:",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['text'],
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        ).pack(
            side="left",
            padx=(20, 8),
            pady=18
        )

        self.network_entry = tk.Entry(
            control,
            width=25,
            font=(
                "Segoe UI",
                10
            )
        )

        self.network_entry.insert(
            0,
            get_setting("default_network", "192.168.2.0/24")
        )

        self.network_entry.pack(
            side="left",
            pady=18
        )

        self.scan_dns_var = tk.BooleanVar(value=True)
        tk.Checkbutton(control, text="Tra hostname", variable=self.scan_dns_var,
                       bg=UI_COLORS['surface']).pack(side="left", padx=8)

        self.scan_button = tk.Button(
            control,
            text="Quét mạng",
            command=self.start_scan,
            bg=UI_COLORS['primary'],
            fg=UI_COLORS['text'],
            activebackground=UI_COLORS['hover'],
            activeforeground=UI_COLORS['text'],
            relief="flat",
            bd=0,
            padx=18,
            pady=8,
            cursor="hand2",
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        )

        self.scan_button.pack(
            side="left",
            padx=(15, 8)
        )

        self.stop_scan_button = tk.Button(
            control,
            text="Dừng quét",
            command=self.stop_scan,
            bg=UI_COLORS['danger_bg'],
            fg=UI_COLORS['text'],
            activebackground=UI_COLORS['danger_bg'],
            activeforeground=UI_COLORS['text'],
            relief="flat",
            bd=0,
            padx=18,
            pady=8,
            cursor="hand2",
            font=(
                "Segoe UI",
                10,
                "bold"
            ),
            state="disabled"
        )

        self.stop_scan_button.pack(
            side="left",
            padx=8
        )

        self.scan_status_label = tk.Label(
            control,
            text="Sẵn sàng",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['muted'],
            font=(
                "Segoe UI",
                10
            )
        )

        self.scan_status_label.pack(
            side="left",
            padx=15
        )

        # Wrap scan controls using their requested widths at the current DPI.
        from modules.responsive_layout import FlowRow
        scan_controls=[widget for widget in control.winfo_children() if widget is not self.scan_status_label]
        for widget in control.winfo_children():widget.pack_forget()
        scan_toolbar=ttk.Frame(control,padding=10);scan_toolbar.pack(fill='x')
        FlowRow(scan_toolbar,scan_controls)
        self.scan_status_label.pack(fill='x',padx=12,pady=(0,8))
        control.bind('<Configure>',lambda event:self.scan_status_label.configure(wraplength=max(200,event.width-24)),add='+')

        progress_frame = tk.Frame(
            self.content,
            bg=UI_COLORS['surface'],
            bd=1,
            relief="solid"
        )

        progress_frame.pack(
            fill="x",
            padx=25,
            pady=(0, 10)
        )

        tk.Label(
            progress_frame,
            text="Đang kiểm tra:",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['muted'],
            font=(
                "Segoe UI",
                10
            )
        ).pack(
            side="left",
            padx=(20, 5),
            pady=15
        )

        self.scan_current_ip_label = tk.Label(
            progress_frame,
            text="-",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['accent'],
            font=(
                "Consolas",
                11,
                "bold"
            )
        )

        self.scan_current_ip_label.pack(
            side="left",
            padx=5
        )

        self.scan_progress_label = tk.Label(
            progress_frame,
            text="0 / 0",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['text'],
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        )

        self.scan_progress_label.pack(
            side="left",
            padx=(30, 5)
        )

        self.scan_percent_label = tk.Label(
            progress_frame,
            text="0%",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['success'],
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        )

        self.scan_percent_label.pack(
            side="left",
            padx=5
        )

        self.scan_active_label = tk.Label(
            progress_frame,
            text="Running: 0",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['pink'],
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        )

        self.scan_active_label.pack(
            side="left",
            padx=20
        )

        self.scan_ip_timer_label = tk.Label(
            progress_frame,
            text="IP Time: 0.00 s",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['warning'],
            font=(
                "Consolas",
                10,
                "bold"
            )
        )

        self.scan_ip_timer_label.pack(
            side="left",
            padx=20
        )

        self.scan_total_timer_label = tk.Label(
            progress_frame,
            text="Total: 0.00 s",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['text'],
            font=(
                "Consolas",
                10
            )
        )

        self.scan_total_timer_label.pack(
            side="left",
            padx=10
        )

        self.scan_progress = ttk.Progressbar(
            progress_frame,
            orient="horizontal",
            mode="determinate"
        )

        self.scan_progress.pack(
            side="left",
            fill="x",
            expand=True,
            padx=(20, 20),
            pady=15
        )

        progress_items=[widget for widget in progress_frame.winfo_children() if widget is not self.scan_progress]
        for widget in progress_frame.winfo_children():widget.pack_forget()
        progress_toolbar=ttk.Frame(progress_frame,padding=8);progress_toolbar.pack(fill='x')
        FlowRow(progress_toolbar,progress_items)
        self.scan_progress.pack(fill='x',padx=12,pady=(0,10))

        filter_frame = tk.Frame(
            self.content,
            bg=UI_COLORS['surface'],
            bd=1,
            relief="solid"
        )

        filter_frame.pack(
            fill="x",
            padx=25,
            pady=(0, 10)
        )

        tk.Label(
            filter_frame,
            text="Tìm kiếm:",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['text'],
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        ).pack(
            side="left",
            padx=(20, 8),
            pady=12
        )

        self.scan_search_var = tk.StringVar()

        self.scan_search_entry = tk.Entry(
            filter_frame,
            textvariable=self.scan_search_var,
            width=28,
            font=(
                "Segoe UI",
                10
            )
        )

        self.scan_search_entry.pack(
            side="left",
            pady=12
        )

        self.scan_search_entry.bind(
            "<KeyRelease>",
            lambda event: self.apply_scan_filters()
        )

        tk.Label(
            filter_frame,
            text="Trạng thái:",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['text'],
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        ).pack(
            side="left",
            padx=(25, 8)
        )

        self.scan_status_filter_var = tk.StringVar(
            value="All"
        )

        self.scan_status_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.scan_status_filter_var,
            values=(
                "All",
                "Online",
                "Offline"
            ),
            width=12,
            state="readonly"
        )

        self.scan_status_combo.pack(
            side="left"
        )

        self.scan_status_combo.bind(
            "<<ComboboxSelected>>",
            lambda event: self.apply_scan_filters()
        )

        tk.Label(
            filter_frame,
            text="Sắp xếp:",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['text'],
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        ).pack(
            side="left",
            padx=(25, 8)
        )

        self.scan_sort_var = tk.StringVar(
            value="Online first"
        )

        self.scan_sort_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.scan_sort_var,
            values=(
                "Online first",
                "Offline first",
                "Địa chỉ IP",
                "Thời lượng",
                "Thời gian"
            ),
            width=18,
            state="readonly"
        )

        self.scan_sort_combo.pack(
            side="left"
        )

        self.scan_sort_combo.bind(
            "<<ComboboxSelected>>",
            lambda event: self.apply_scan_filters()
        )

        self.scan_summary_label = tk.Label(
            filter_frame,
            text="Total: 0 | Online: 0 | Offline: 0 | Showing: 0",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['text'],
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        )

        self.scan_summary_label.pack(
            side="right",
            padx=20
        )

        filter_items=[widget for widget in filter_frame.winfo_children() if widget is not self.scan_summary_label]
        for widget in filter_frame.winfo_children():widget.pack_forget()
        filter_toolbar=ttk.Frame(filter_frame,padding=8);filter_toolbar.pack(fill='x')
        FlowRow(filter_toolbar,filter_items)
        self.scan_summary_label.pack(fill='x',padx=12,pady=(0,8))
        filter_frame.bind('<Configure>',lambda event:self.scan_summary_label.configure(wraplength=max(200,event.width-24)),add='+')

        result_frame = tk.Frame(
            self.content,
            bg=UI_COLORS['surface'],
            bd=1,
            relief="solid"
        )

        result_frame.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=(0, 20)
        )

        columns = (
            "time",
            "ip",
            "hostname",
            "mac",
            "status",
            "duration"
        )

        self.scan_table = ttk.Treeview(
            result_frame,
            columns=columns,
            show="headings"
        )

        self.scan_table.heading(
            "time",
            text="Thời gian"
        )

        self.scan_table.heading(
            "ip",
            text="Địa chỉ IP"
        )

        self.scan_table.heading(
            "hostname",
            text="Tên máy"
        )

        self.scan_table.heading(
            "mac",
            text="Địa chỉ MAC"
        )

        self.scan_table.heading(
            "status",
            text="Trạng thái"
        )

        self.scan_table.heading(
            "duration",
            text="Thời lượng"
        )

        self.scan_table.column(
            "time",
            width=90,
            anchor="center"
        )

        self.scan_table.column(
            "ip",
            width=150
        )

        self.scan_table.column(
            "hostname",
            width=230
        )

        self.scan_table.column(
            "mac",
            width=180
        )

        self.scan_table.column(
            "status",
            width=100,
            anchor="center"
        )

        self.scan_table.column(
            "duration",
            width=110,
            anchor="center"
        )

        scrollbar_y = ttk.Scrollbar(
            result_frame,
            orient="vertical",
            command=self.scan_table.yview
        )

        scrollbar_x = ttk.Scrollbar(
            result_frame,
            orient="horizontal",
            command=self.scan_table.xview
        )

        self.scan_table.configure(
            yscrollcommand=scrollbar_y.set,
            xscrollcommand=scrollbar_x.set
        )

        result_frame.rowconfigure(0,weight=1);result_frame.columnconfigure(0,weight=1)
        self.scan_table.grid(row=0,column=0,sticky='nsew',padx=(12,0),pady=(12,0))
        scrollbar_y.grid(row=0,column=1,sticky='ns',padx=(0,12),pady=(12,0))
        scrollbar_x.grid(row=1,column=0,sticky='ew',padx=(12,0),pady=(0,12))

        self.scan_table.tag_configure(
            "online",
            foreground=UI_COLORS['success']
        )

        self.scan_table.tag_configure(
            "offline",
            foreground=UI_COLORS['danger']
        )

        self.scan_table.tag_configure(
            "running",
            foreground=UI_COLORS['accent']
        )

    # ======================================================
    # APPLY SEARCH / FILTER / SORT
    # ======================================================

    def apply_scan_filters(self):

        if not hasattr(
            self,
            "scan_table"
        ):

            return

        try:

            if not self.scan_table.winfo_exists():

                return

        except tk.TclError:

            return

        search_text = ""

        if hasattr(
            self,
            "scan_search_var"
        ):

            search_text = (
                self.scan_search_var
                .get()
                .strip()
                .lower()
            )

        status_filter = "All"

        if hasattr(
            self,
            "scan_status_filter_var"
        ):

            status_filter = (
                self.scan_status_filter_var
                .get()
            )

        sort_type = "Online first"

        if hasattr(
            self,
            "scan_sort_var"
        ):

            sort_type = (
                self.scan_sort_var
                .get()
            )

        filtered_results = []

        for result in self.scan_results:

            ip = str(
                result.get(
                    "ip",
                    ""
                )
            )

            hostname = str(
                result.get(
                    "hostname",
                    ""
                )
            )

            mac = str(
                result.get(
                    "mac",
                    ""
                )
            )

            status = str(
                result.get(
                    "status",
                    ""
                )
            )

            if search_text:

                searchable = (
                    f"{ip} "
                    f"{hostname} "
                    f"{mac}"
                ).lower()

                if search_text not in searchable:

                    continue

            if (
                status_filter != "All"
                and status != status_filter
            ):

                continue

            filtered_results.append(
                result
            )

        def ip_sort_key(result):

            try:

                return ipaddress.ip_address(
                    result.get(
                        "ip",
                        "0.0.0.0"
                    )
                )

            except Exception:

                return ipaddress.ip_address(
                    "0.0.0.0"
                )

        def duration_sort_key(result):

            try:

                return float(
                    result.get(
                        "duration",
                        999999
                    )
                )

            except Exception:

                return 999999

        if sort_type == "Online first":

            filtered_results.sort(
                key=lambda result: (
                    result.get(
                        "status",
                        ""
                    ) != "Online",
                    ip_sort_key(result)
                )
            )

        elif sort_type == "Offline first":

            filtered_results.sort(
                key=lambda result: (
                    result.get(
                        "status",
                        ""
                    ) != "Offline",
                    ip_sort_key(result)
                )
            )

        elif sort_type == "Địa chỉ IP":

            filtered_results.sort(
                key=ip_sort_key
            )

        elif sort_type == "Thời lượng":

            filtered_results.sort(
                key=lambda result: (
                    duration_sort_key(result),
                    ip_sort_key(result)
                )
            )

        elif sort_type == "Thời gian":

            filtered_results.sort(
                key=lambda result: (
                    result.get(
                        "time",
                        ""
                    ),
                    ip_sort_key(result)
                )
            )

        for item in self.scan_table.get_children():

            self.scan_table.delete(
                item
            )

        for result in filtered_results:

            status = result.get(
                "status",
                ""
            )

            if status == "Online":

                tag = "online"

            elif status == "Offline":

                tag = "offline"

            else:

                tag = "running"

            duration = result.get(
                "duration",
                0
            )

            try:

                duration_text = (
                    f"{float(duration):.2f} s"
                )

            except Exception:

                duration_text = "-"

            self.scan_table.insert(
                "",
                "end",
                values=(
                    result.get(
                        "time",
                        ""
                    ),
                    result.get(
                        "ip",
                        ""
                    ),
                    result.get(
                        "hostname",
                        ""
                    ),
                    result.get(
                        "mac",
                        ""
                    ),
                    status,
                    duration_text
                ),
                tags=(tag,)
            )

        total = len(
            self.scan_results
        )

        online = sum(
            1
            for result in self.scan_results
            if result.get("status") == "Online"
        )

        offline = sum(
            1
            for result in self.scan_results
            if result.get("status") == "Offline"
        )

        showing = len(
            filtered_results
        )

        self.scan_summary_label.config(
            text=(
                f"Total: {total} | "
                f"Online: {online} | "
                f"Offline: {offline} | "
                f"Showing: {showing}"
            )
        )

    # ======================================================
    # START SCAN
    # ======================================================

    def start_scan(self):

        if self.scan_running:

            return

        network = (
            self.network_entry
            .get()
            .strip()
        )

        if not network:

            self.scan_status_label.config(
                text="Please enter network."
            )

            return

        for item in self.scan_table.get_children():

            self.scan_table.delete(
                item
            )

        self.scan_results = []

        self.scan_search_var.set(
            ""
        )

        self.scan_status_filter_var.set(
            "All"
        )

        self.scan_sort_var.set(
            "Online first"
        )

        self.scan_total = 0
        self.scan_completed = 0
        self.scan_online = 0
        self.scan_offline = 0

        self.scan_active_ips = {}

        self.scan_start_time = (
            time.perf_counter()
        )

        self.scan_progress["value"] = 0

        self.scan_progress["maximum"] = 1

        self.scan_current_ip_label.config(
            text="-"
        )

        self.scan_progress_label.config(
            text="0 / 0"
        )

        self.scan_percent_label.config(
            text="0%"
        )

        self.scan_active_label.config(
            text="Running: 0"
        )

        self.scan_ip_timer_label.config(
            text="IP Time: 0.00 s"
        )

        self.scan_total_timer_label.config(
            text="Total: 0.00 s"
        )

        self.scan_summary_label.config(
            text=(
                "Total: 0 | "
                "Online: 0 | "
                "Offline: 0 | "
                "Showing: 0"
            )
        )

        self.scan_running = True

        self.scan_stop_event = (
            threading.Event()
        )

        self.scan_button.config(
            state="disabled"
        )

        self.stop_scan_button.config(
            state="normal"
        )

        self.scan_status_label.config(
            text=f"Preparing scan: {network}"
        )

        self.add_activity(
            f"Started network scan: {network}"
        )

        self.update_scan_timer()

        self.scan_thread = threading.Thread(
            target=self.scan_worker,
            args=(
                network,
                self.scan_stop_event,
                self.scan_dns_var.get()
            ),
            daemon=True
        )

        self.scan_thread.start()

    # ======================================================
    # SCAN WORKER
    # ======================================================

    def scan_worker(
        self,
        network,
        stop_event,
        resolve_hostnames=True
    ):

        try:

            results = scan_network(
                network,
                max_workers=50,
                timeout=1000,
                stop_event=stop_event,
                resolve_hostnames=resolve_hostnames,
                dns_timeout=1.0,
                callback=self.scan_callback
            )

            stopped = (
                stop_event.is_set()
            )

            if not self._closing:
                self.root.after(0, self.scan_finished, stopped, results)

        except Exception as error:

            if not self._closing:
                self.root.after(0, self.scan_error, str(error))

    # ======================================================
    # SCAN CALLBACK
    # ======================================================

    def scan_callback(
        self,
        event
    ):

        if self._closing:
            return
        event_type = event.get(
            "event"
        )

        if event_type == "total":

            total = event.get(
                "total",
                0
            )

            self.root.after(
                0,
                self.scan_set_total,
                total
            )

        elif event_type == "started":

            ip = event.get(
                "ip",
                ""
            )

            self.root.after(
                0,
                self.scan_host_started,
                ip
            )

        elif event_type == "completed":

            result = event.get(
                "result"
            )

            if result:

                self.root.after(
                    0,
                    self.scan_host_completed,
                    result
                )

    # ======================================================
    # SET TOTAL
    # ======================================================

    def scan_set_total(
        self,
        total
    ):

        if not self.scan_running:

            return

        self.scan_total = total

        self.scan_progress["maximum"] = max(
            total,
            1
        )

        self.scan_progress_label.config(
            text=f"0 / {total}"
        )

        self.scan_status_label.config(
            text=f"Scanning {total} IP addresses..."
        )

    # ======================================================
    # HOST STARTED
    # ======================================================

    def scan_host_started(
        self,
        ip
    ):

        if not self.scan_running:

            return

        self.scan_active_ips[ip] = (
            time.perf_counter()
        )

        self.scan_current_ip_label.config(
            text=ip
        )

        self.scan_active_label.config(
            text=(
                f"Running: "
                f"{len(self.scan_active_ips)}"
            )
        )

        self.scan_status_label.config(
            text=(
                f"Checking {ip}..."
            )
        )

    # ======================================================
    # HOST COMPLETED
    # ======================================================

    def scan_host_completed(
        self,
        result
    ):

        if not hasattr(
            self,
            "scan_table"
        ):

            return

        try:

            if not self.scan_table.winfo_exists():

                return

        except tk.TclError:

            return

        ip = result.get(
            "ip",
            ""
        )

        if ip in self.scan_active_ips:

            del self.scan_active_ips[ip]

        self.scan_completed += 1

        status = result.get(
            "status",
            ""
        )

        if status == "Online":

            self.scan_online += 1

        else:

            self.scan_offline += 1

        self.scan_results.append(
            result
        )

        try:

            save_devices(
                [result]
            )

        except Exception as error:

            self.add_activity(
                f"Database error {ip}: {error}"
            )

        self.apply_scan_filters()

        children = (
            self.scan_table.get_children()
        )

        if children:

            self.scan_table.see(
                children[-1]
            )

        self.update_scan_progress()

    # ======================================================
    # UPDATE PROGRESS
    # ======================================================

    def update_scan_progress(self):

        total = self.scan_total

        completed = self.scan_completed

        if total <= 0:

            percent = 0

        else:

            percent = (
                completed
                / total
                * 100
            )

        self.scan_progress["value"] = (
            completed
        )

        self.scan_progress_label.config(
            text=(
                f"{completed} / {total}"
            )
        )

        self.scan_percent_label.config(
            text=(
                f"{percent:.1f}%"
            )
        )

        self.scan_active_label.config(
            text=(
                f"Running: "
                f"{len(self.scan_active_ips)}"
            )
        )

        self.scan_status_label.config(
            text=(
                f"Scanning... "
                f"Online: {self.scan_online} | "
                f"Offline: {self.scan_offline}"
            )
        )

    # ======================================================
    # LIVE TIMER
    # ======================================================

    def update_scan_timer(self):

        if not self.scan_running:

            return

        if self.scan_start_time is not None:

            total_elapsed = (
                time.perf_counter()
                - self.scan_start_time
            )

            self.scan_total_timer_label.config(
                text=(
                    f"Total: "
                    f"{total_elapsed:.2f} s"
                )
            )

        current_ip = (
            self.scan_current_ip_label.cget(
                "text"
            )
        )

        if (
            current_ip
            and current_ip in self.scan_active_ips
        ):

            host_start = (
                self.scan_active_ips[
                    current_ip
                ]
            )

            host_elapsed = (
                time.perf_counter()
                - host_start
            )

            self.scan_ip_timer_label.config(
                text=(
                    f"IP Time: "
                    f"{host_elapsed:.2f} s"
                )
            )

        else:

            self.scan_ip_timer_label.config(
                text="IP Time: 0.00 s"
            )

        self.scan_timer_job = (
            self.root.after(
                100,
                self.update_scan_timer
            )
        )

    # ======================================================
    # FINISHED
    # ======================================================

    def scan_finished(
        self,
        stopped=False,
        results=None
    ):

        if not self.scan_running:

            return

        if results is not None:

            self.scan_results = results

        self.scan_running = False

        if self.scan_timer_job is not None:

            try:

                self.root.after_cancel(
                    self.scan_timer_job
                )

            except Exception:

                pass

            self.scan_timer_job = None

        self.scan_button.config(
            state="normal"
        )

        self.stop_scan_button.config(
            state="disabled"
        )

        total_time = 0

        if self.scan_start_time is not None:

            total_time = (
                time.perf_counter()
                - self.scan_start_time
            )

        self.scan_total_timer_label.config(
            text=(
                f"Total: "
                f"{total_time:.2f} s"
            )
        )

        self.scan_completed = len(
            self.scan_results
        )

        self.scan_online = sum(
            1
            for result in self.scan_results
            if result.get("status") == "Online"
        )

        self.scan_offline = sum(
            1
            for result in self.scan_results
            if result.get("status") == "Offline"
        )

        self.apply_scan_filters()

        if stopped:

            self.scan_status_label.config(
                text=(
                    f"Stopped | "
                    f"Scanned: "
                    f"{self.scan_completed} | "
                    f"Online: "
                    f"{self.scan_online} | "
                    f"Offline: "
                    f"{self.scan_offline}"
                )
            )

            self.add_activity(
                "Network scan stopped."
            )

        else:

            self.scan_status_label.config(
                text=(
                    f"Completed | "
                    f"Total: "
                    f"{self.scan_completed} | "
                    f"Online: "
                    f"{self.scan_online} | "
                    f"Offline: "
                    f"{self.scan_offline} | "
                    f"Time: "
                    f"{total_time:.2f}s"
                )
            )

            self.add_activity(
                "Network scan completed. "
                f"Total: {self.scan_completed}, "
                f"Online: {self.scan_online}, "
                f"Offline: {self.scan_offline}"
            )

        self.scan_current_ip_label.config(
            text="Finished"
        )

        self.scan_active_label.config(
            text="Running: 0"
        )

        self.scan_ip_timer_label.config(
            text="IP Time: 0.00 s"
        )

        self.scan_stop_event = None

        self.scan_thread = None

        self.scan_active_ips = {}

    # ======================================================
    # STOP SCAN
    # ======================================================

    def stop_scan(self):

        if not self.scan_running:

            return

        if self.scan_stop_event is not None:

            self.scan_stop_event.set()

        self.scan_status_label.config(
            text="Stopping scan..."
        )

        self.stop_scan_button.config(
            state="disabled"
        )

        self.add_activity(
            "Stopping network scan..."
        )

    # ======================================================
    # SCAN ERROR
    # ======================================================

    def scan_error(
        self,
        error
    ):

        self.scan_running = False

        if self.scan_timer_job is not None:

            try:

                self.root.after_cancel(
                    self.scan_timer_job
                )

            except Exception:

                pass

            self.scan_timer_job = None

        self.scan_stop_event = None

        self.scan_thread = None

        self.scan_button.config(
            state="normal"
        )

        self.stop_scan_button.config(
            state="disabled"
        )

        self.scan_status_label.config(
            text=f"Error: {error}"
        )

        self.add_activity(
            f"Network scan error: {error}"
        )

    # ======================================================
    # DEVICE MANAGER
    # ======================================================

    def show_device_manager(self):

        self.current_page = "Quản lý thiết bị"

        self.clear_content()

        self.set_page_title(
            "Quản lý thiết bị",
            "Manage network devices stored in database"
        )

        toolbar = tk.Frame(
            self.content,
            bg=UI_COLORS['surface'],
            bd=1,
            relief="solid"
        )

        toolbar.pack(
            fill="x",
            padx=25,
            pady=10
        )

        tk.Label(
            toolbar,
            text="Tìm kiếm:",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['text'],
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        ).pack(
            side="left",
            padx=(20, 8),
            pady=15
        )
        
        
        self.device_search_var = tk.StringVar()

        self.device_search_entry = tk.Entry(
            toolbar,
            textvariable=self.device_search_var,
            width=28,
            font=(
                "Segoe UI",
                10
            )
        )

        self.device_search_entry.pack(
            side="left",
            pady=15
        )

        self.device_search_entry.bind(
            "<KeyRelease>",
            lambda event: self.apply_device_filters()
        )

        tk.Label(
            toolbar,
            text="Trạng thái:",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['text'],
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        ).pack(
            side="left",
            padx=(25, 8)
        )

        self.device_status_filter_var = tk.StringVar(
            value="All"
        )

        self.device_status_combo = ttk.Combobox(
            toolbar,
            textvariable=self.device_status_filter_var,
            values=(
                "All",
                "Online",
                "Offline"
            ),
            width=12,
            state="readonly"
        )

        self.device_status_combo.pack(
            side="left"
        )

        self.device_status_combo.bind(
            "<<ComboboxSelected>>",
            lambda event: self.apply_device_filters()
        )

        refresh_button = tk.Button(
            toolbar,
            text="Làm mới",
            command=self.refresh_device_manager,
            bg=UI_COLORS['primary'],
            fg=UI_COLORS['text'],
            activebackground=UI_COLORS['hover'],
            activeforeground=UI_COLORS['text'],
            relief="flat",
            bd=0,
            padx=15,
            pady=7,
            cursor="hand2",
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        )

        refresh_button.pack(
            side="left",
            padx=15
        )

        # Nút Xuất Excel
        export_excel_button = tk.Button(
            toolbar,
            text="Xuất Excel",
            command=self.export_devices_excel,
            bg=UI_COLORS['success_bg'],
            fg=UI_COLORS['text'],
            activebackground=UI_COLORS['success_bg'],
            activeforeground=UI_COLORS['text'],
            relief="flat",
            bd=0,
            padx=15,
            pady=7,
            cursor="hand2",
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        )
        export_excel_button.pack(
            side="left",
            padx=5
        )

        add_button = tk.Button(
            toolbar,
            text="Thêm thiết bị",
            command=self.add_device_dialog,
            bg=UI_COLORS['success_bg'],
            fg=UI_COLORS['text'],
            activebackground=UI_COLORS['success_bg'],
            activeforeground=UI_COLORS['text'],
            relief="flat",
            bd=0,
            padx=15,
            pady=7,
            cursor="hand2",
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        )

        add_button.pack(
            side="right",
            padx=(5, 20)
        )

        summary_frame = tk.Frame(
            self.content,
            bg=UI_COLORS['surface'],
            bd=1,
            relief="solid"
        )

        summary_frame.pack(
            fill="x",
            padx=25,
            pady=(0, 10)
        )

        self.device_summary_label = tk.Label(
            summary_frame,
            text="Total: 0 | Online: 0 | Offline: 0 | Showing: 0",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['text'],
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        )

        self.device_summary_label.pack(
            anchor="w",
            padx=20,
            pady=12
        )

        result_frame = tk.Frame(
            self.content,
            bg=UI_COLORS['surface'],
            bd=1,
            relief="solid"
        )

        result_frame.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=(0, 10)
        )

        columns = (
            "id",
            "ip",
            "hostname",
            "mac",
            "status",
            "duration",
            "first_seen",
            "last_seen"
        )

        self.device_table = ttk.Treeview(
            result_frame,
            columns=columns,
            show="headings",
            selectmode="extended"  # Cho phép chọn nhiều dòng
        )

        self.device_table.heading(
            "id",
            text="ID"
        )

        self.device_table.heading(
            "ip",
            text="Địa chỉ IP"
        )

        self.device_table.heading(
            "hostname",
            text="Tên máy"
        )

        self.device_table.heading(
            "mac",
            text="Địa chỉ MAC"
        )

        self.device_table.heading(
            "status",
            text="Trạng thái"
        )

        self.device_table.heading(
            "duration",
            text="Thời lượng"
        )

        self.device_table.heading(
            "first_seen",
            text="Phát hiện lần đầu"
        )

        self.device_table.heading(
            "last_seen",
            text="Lần cuối phát hiện"
        )

        self.device_table.column(
            "id",
            width=60,
            anchor="center"
        )

        self.device_table.column(
            "ip",
            width=140
        )

        self.device_table.column(
            "hostname",
            width=200
        )

        self.device_table.column(
            "mac",
            width=180
        )

        self.device_table.column(
            "status",
            width=100,
            anchor="center"
        )

        self.device_table.column(
            "duration",
            width=100,
            anchor="center"
        )

        self.device_table.column(
            "first_seen",
            width=160
        )

        self.device_table.column(
            "last_seen",
            width=160
        )

        scrollbar_y = ttk.Scrollbar(
            result_frame,
            orient="vertical",
            command=self.device_table.yview
        )

        scrollbar_x = ttk.Scrollbar(
            result_frame,
            orient="horizontal",
            command=self.device_table.xview
        )

        self.device_table.configure(
            yscrollcommand=scrollbar_y.set,
            xscrollcommand=scrollbar_x.set
        )

        self.device_table.pack(
            side="top",
            fill="both",
            expand=True,
            padx=(15, 0),
            pady=(15, 0)
        )

        scrollbar_y.pack(
            side="right",
            fill="y",
            padx=(0, 15),
            pady=(15, 0)
        )

        scrollbar_x.pack(
            side="bottom",
            fill="x",
            padx=(15, 15),
            pady=(0, 15)
        )

        self.device_table.tag_configure(
            "online",
            foreground=UI_COLORS['success']
        )

        self.device_table.tag_configure(
            "offline",
            foreground=UI_COLORS['danger']
        )

        self.device_table.tag_configure(
            "unknown",
            foreground=UI_COLORS['muted']
        )

        self.device_table.bind(
            "<Double-1>",
            self.on_device_double_click
        )

        button_frame = tk.Frame(
            self.content,
            bg=UI_COLORS['background']
        )

        button_frame.pack(
            fill="x",
            padx=25,
            pady=(0, 20)
        )

        edit_button = tk.Button(
            button_frame,
            text="Sửa thiết bị",
            command=self.edit_selected_device,
            bg=UI_COLORS['primary'],
            fg=UI_COLORS['text'],
            activebackground=UI_COLORS['hover'],
            activeforeground=UI_COLORS['text'],
            relief="flat",
            bd=0,
            padx=18,
            pady=8,
            cursor="hand2",
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        )

        edit_button.pack(
            side="left"
        )

        delete_button = tk.Button(
            button_frame,
            text="Xóa mục đã chọn",
            command=self.delete_selected_devices,
            bg=UI_COLORS['danger_bg'],
            fg=UI_COLORS['text'],
            activebackground=UI_COLORS['danger_bg'],
            activeforeground=UI_COLORS['text'],
            relief="flat",
            bd=0,
            padx=18,
            pady=8,
            cursor="hand2",
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        )

        delete_button.pack(
            side="left",
            padx=10
        )

        select_all_button = tk.Button(
            button_frame,
            text="Chọn tất cả",
            command=self.select_all_devices,
            bg=UI_COLORS['surface_alt'],
            fg=UI_COLORS['text'],
            activebackground=UI_COLORS['surface_alt'],
            activeforeground=UI_COLORS['text'],
            relief="flat",
            bd=0,
            padx=15,
            pady=8,
            cursor="hand2",
            font=(
                "Segoe UI",
                10
            )
        )

        select_all_button.pack(
            side="left",
            padx=10
        )
        
        deselect_button = tk.Button(
            button_frame,
            text="Bỏ chọn",
            command=self.deselect_all_devices,
            bg=UI_COLORS['surface_alt'],
            fg=UI_COLORS['text'],
            activebackground=UI_COLORS['surface_alt'],
            activeforeground=UI_COLORS['text'],
            relief="flat",
            bd=0,
            padx=15,
            pady=8,
            cursor="hand2",
            font=(
                "Segoe UI",
                10
            )
        )
        deselect_button = tk.Button(
                    button_frame,
                    text="Bỏ chọn",
                    command=self.deselect_all_devices,
                    bg=UI_COLORS['surface_alt'],
                    fg=UI_COLORS['text'],
                    activebackground=UI_COLORS['surface_alt'],
                    activeforeground=UI_COLORS['text'],
                    relief="flat",
                    bd=0,
                    padx=15,
                    pady=8,
                    cursor="hand2",
                    font=(
                        "Segoe UI",
                        10
                    )
                )
        deselect_button.pack(
            side="left",
            padx=5
        )
        
        self.refresh_device_manager()

    # ======================================================
    # EXPORT DEVICES TO EXCEL
    # ======================================================

    def export_devices_excel(self):
        """Hàm xuất danh sách thiết bị từ bảng Device Manager ra file Excel"""
        if self.device_table is None:
            messagebox.showwarning("Xuất Excel", "Không tìm thấy bảng thiết bị.")
            return

        children = self.device_table.get_children()
        if not children:
            messagebox.showwarning("Xuất Excel", "Không có dữ liệu thiết bị nào để xuất.")
            return

        # Thu thập dữ liệu đang hiển thị trên bảng
        export_data = []
        for item_id in children:
            values = self.device_table.item(item_id, "values")
            if values:
                export_data.append({
                    "ID": values[0],
                    "Địa chỉ IP": values[1],
                    "Tên máy": values[2],
                    "Địa chỉ MAC": values[3],
                    "Trạng thái": values[4],
                    "Thời lượng": values[5],
                    "Phát hiện lần đầu": values[6],
                    "Lần cuối phát hiện": values[7]
                })

        if not export_data:
            messagebox.showwarning("Xuất Excel", "Danh sách dữ liệu trống.")
            return

        # Mở hộp thoại chọn nơi lưu file
        file_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")],
            initialfile=f"devices_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
            title="Lưu file Excel danh sách thiết bị"
        )

        if not file_path:
            return

        try:
            df = pd.DataFrame(export_data)
            df.to_excel(file_path, index=False)
            messagebox.showinfo("Xuất Excel", f"Xuất file Excel thành công!\nĐã lưu tại:\n{file_path}")
            self.add_activity(f"Exported {len(export_data)} devices to Excel: {file_path}")
        except Exception as error:
            messagebox.showerror("Export Error", f"Không thể xuất file Excel:\n{error}")
            self.add_activity(f"Export Excel error: {error}")

    # ======================================================
    # DEVICE FILTER
    # ======================================================

    def _normalize_device_record(self, device):

        if isinstance(device, dict):
            raw = dict(device)

        else:
            try:
                raw = dict(device)
            except Exception:
                raw = None

        if raw is None:
            try:
                return {
                    "id": device[0],
                    "ip": device[1],
                    "hostname": device[2],
                    "mac": device[3],
                    "status": device[4],
                    "duration": device[5],
                    "first_seen": device[6],
                    "last_seen": device[7],
                }
            except Exception:
                return None

        def first_value(*keys, default=None):
            for key in keys:
                if key in raw:
                    value = raw.get(key)
                    if value is not None and str(value).strip().lower() not in ("", "none", "null"):
                        return value
            return default

        return {
            "id": first_value("id", "device_id"),
            "ip": first_value(
                "ip",
                "ip_address",
                "ip_addr",
                "address",
                default=""
            ),
            "hostname": first_value(
                "hostname",
                "host_name",
                "name",
                "device_name",
                default=""
            ),
            "mac": first_value(
                "mac",
                "mac_address",
                "mac_addr",
                default=""
            ),
            "status": first_value(
                "status",
                "state",
                default="Unknown"
            ),
            "duration": first_value(
                "duration",
                "response_time",
                "latency"
            ),
            "first_seen": first_value(
                "first_seen",
                "created_at",
                "first_seen_at",
                default=""
            ),
            "last_seen": first_value(
                "last_seen",
                "updated_at",
                "last_seen_at",
                default=""
            ),
        }

    def apply_device_filters(self):

        if self.device_table is None:
            return

        try:
            if not self.device_table.winfo_exists():
                return
        except tk.TclError:
            return

        keyword = ""
        if self.device_search_var is not None:
            keyword = self.device_search_var.get().strip().lower()

        status_filter = "All"
        if self.device_status_filter_var is not None:
            status_filter = self.device_status_filter_var.get()

        try:
            raw_devices = get_all_devices() or []

            all_devices = []
            for row in raw_devices:
                device = self._normalize_device_record(row)
                if device is not None:
                    all_devices.append(device)

            total = len(all_devices)
            online = sum(
                1 for d in all_devices
                if str(d.get("status", "")).lower() == "online"
            )
            offline = sum(
                1 for d in all_devices
                if str(d.get("status", "")).lower() == "offline"
            )

            devices = all_devices

            if keyword:
                devices = [
                    d for d in devices
                    if keyword in str(d.get("ip", "")).lower()
                    or keyword in str(d.get("hostname", "")).lower()
                    or keyword in str(d.get("mac", "")).lower()
                ]

            if status_filter != "All":
                wanted = status_filter.lower()
                devices = [
                    d for d in devices
                    if str(d.get("status", "")).lower() == wanted
                ]

        except Exception as error:
            self.device_summary_label.config(
                text=f"Database Error: {error}"
            )
            return

        for item in self.device_table.get_children():
            self.device_table.delete(item)

        for index, device in enumerate(devices):

            status_text = str(device.get("status") or "Unknown")

            if status_text.lower() == "online":
                tag = "online"
            elif status_text.lower() == "offline":
                tag = "offline"
            else:
                tag = "unknown"

            duration = device.get("duration")
            if duration in (None, ""):
                duration_text = "-"
            else:
                try:
                    duration_text = f"{float(duration):.2f} s"
                except Exception:
                    duration_text = str(duration)

            device_id = device.get("id")
            iid = str(device_id) if device_id is not None else f"row_{index}"

            if self.device_table.exists(iid):
                iid = f"{iid}_{index}"

            self.device_table.insert(
                "",
                "end",
                iid=iid,
                values=(
                    device_id if device_id is not None else "",
                    device.get("ip") or "",
                    device.get("hostname") or "",
                    device.get("mac") or "",
                    status_text,
                    duration_text,
                    device.get("first_seen") or "",
                    device.get("last_seen") or "",
                ),
                tags=(tag,)
            )

        self.device_summary_label.config(
            text=(
                f"Total: {total} | "
                f"Online: {online} | "
                f"Offline: {offline} | "
                f"Showing: {len(devices)}"
            )
        )

    def refresh_device_manager(self):

        self.apply_device_filters()

    # ======================================================
    # ADD DEVICE DIALOG
    # ======================================================

    def add_device_dialog(self):
        from modules.device_dialog import DeviceEditor
        def saved(fields):
            self.add_activity('Added device: '+fields['ip'])
            self.refresh_device_manager()
        self.device_editor=DeviceEditor(self.root,device_manager.add_device,saved)

    def get_selected_device_ids(self):
        """Lấy danh sách ID của tất cả các dòng đang được chọn"""
        if self.device_table is None:
            return []

        selection = self.device_table.selection()
        if not selection:
            return []

        ids = []
        for item_id in selection:
            try:
                values = self.device_table.item(item_id, "values")
                if values and values[0]:
                    ids.append(int(values[0]))
            except Exception:
                try:
                    ids.append(int(item_id))
                except Exception:
                    pass
        return ids

    def get_selected_device_id(self):
        """Lấy ID của dòng đầu tiên được chọn (dùng cho Edit)"""
        ids = self.get_selected_device_ids()
        return ids[0] if ids else None

    def select_all_devices(self):
        """Chọn tất cả các thiết bị trên bảng"""
        if self.device_table is not None:
            children = self.device_table.get_children()
            self.device_table.selection_set(children)

    def deselect_all_devices(self):
        """Bỏ chọn tất cả"""
        if self.device_table is not None:
            selected = self.device_table.selection()
            if selected:
                self.device_table.selection_remove(selected)

    def on_device_double_click(
        self,
        event
    ):

        self.edit_selected_device()

    def edit_selected_device(self):

        device_id = (
            self.get_selected_device_id()
        )

        if device_id is None:

            messagebox.showwarning(
                "Sửa thiết bị",
                "Please select a device."
            )

            return

        device = device_manager.get_device(
            device_id
        )
        if device is not None:
            device = self._normalize_device_record(device)

        if device is None:

            messagebox.showerror(
                "Sửa thiết bị",
                "Device not found."
            )

            self.refresh_device_manager()

            return

        from functools import partial
        from modules.device_dialog import DeviceEditor
        def saved(fields):
            self.add_activity('Updated device: '+fields['ip'])
            self.refresh_device_manager()
        self.device_editor=DeviceEditor(self.root,partial(device_manager.edit_device,device_id=device_id),saved,device)

    def delete_selected_devices(self):
        """Xóa hàng loạt các thiết bị đang được chọn"""
        device_ids = self.get_selected_device_ids()

        if not device_ids:
            messagebox.showwarning(
                "Delete Devices",
                "Vui lòng chọn ít nhất một thiết bị để xóa."
            )
            return

        confirm = messagebox.askyesno(
            "Delete Devices",
            f"Bạn có chắc muốn xóa {len(device_ids)} thiết bị đã chọn không?"
        )

        if not confirm:
            return

        success_count = 0
        fail_count = 0

        for device_id in device_ids:
            try:
                result = device_manager.remove_device(device_id)
                if result and result.get("success"):
                    success_count += 1
                else:
                    fail_count += 1
            except Exception:
                fail_count += 1

        self.add_activity(f"Deleted {success_count} devices in bulk.")
        self.refresh_device_manager()

        if fail_count > 0:
            messagebox.showwarning(
                "Delete Devices",
                f"Đã xóa thành công {success_count} thiết bị, thất bại {fail_count} thiết bị."
            )
        else:
            messagebox.showinfo(
                "Delete Devices",
                f"Đã xóa thành công {success_count} thiết bị đã chọn."
            )

    # ======================================================
    # PING MONITOR
    # ======================================================

    def show_ping_monitor(self):

        self.current_page = "Giám sát Ping"

        self.clear_content()

        self.set_page_title(
            "Giám sát Ping",
            "Monitor multiple IP addresses"
        )

        top = tk.Frame(
            self.content,
            bg=UI_COLORS['surface'],
            bd=1,
            relief="solid"
        )

        top.pack(
            fill="x",
            padx=25,
            pady=10
        )

        tk.Label(
            top,
            text="IP Addresses / Hosts:",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['text'],
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=20,
            pady=(15, 5)
        )

        self.ping_entry = tk.Text(
            top,
            height=5,
            font=(
                "Consolas",
                10
            )
        )

        self.ping_entry.pack(
            fill="x",
            padx=20
        )

        self.ping_entry.insert(
            "1.0",
            "192.168.2.3\n"
            "192.168.2.10\n"
            "192.168.2.20"
        )

        button_frame = tk.Frame(
            top,
            bg=UI_COLORS['surface']
        )

        button_frame.pack(
            fill="x",
            padx=20,
            pady=15
        )

        self.ping_all_button = tk.Button(
            button_frame,
            text="Ping tất cả",
            command=self.run_ping_all,
            bg=UI_COLORS['primary'],
            fg=UI_COLORS['text'],
            relief="flat",
            bd=0,
            padx=15,
            pady=8,
            cursor="hand2",
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        )

        self.ping_all_button.pack(
            side="left"
        )

        self.auto_ping_button = tk.Button(
            button_frame,
            text="Bắt đầu Ping tự động",
            command=self.toggle_auto_ping,
            bg=UI_COLORS['success_bg'],
            fg=UI_COLORS['text'],
            relief="flat",
            bd=0,
            padx=15,
            pady=8,
            cursor="hand2",
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        )

        self.auto_ping_button.pack(
            side="left",
            padx=10
        )

        # Nút mới: Tải IP từ Device Manager
        load_devices_button = tk.Button(
            button_frame,
            text="Nạp từ thiết bị",
            command=self.load_ips_from_device_manager,
            bg=UI_COLORS['surface_alt'],
            fg=UI_COLORS['text'],
            activebackground=UI_COLORS['surface_alt'],
            activeforeground=UI_COLORS['text'],
            relief="flat",
            bd=0,
            padx=15,
            pady=8,
            cursor="hand2",
            font=(
                "Segoe UI",
                10
            )
        )
        load_devices_button.pack(
            side="left",
            padx=10
        )

        self.interval_var = tk.StringVar(
            value=get_setting("ping_interval_sec", "5")
        )

        tk.Label(
            button_frame,
            text="Chu kỳ:",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['text']
        ).pack(
            side="left",
            padx=(10, 5)
        )

        self.interval_combo = ttk.Combobox(
            button_frame,
            textvariable=self.interval_var,
            values=(
                "1",
                "5",
                "10",
                "30"
            ),
            width=8,
            state="readonly"
        )

        self.interval_combo.pack(
            side="left"
        )

        clear_button = tk.Button(
            button_frame,
            text="Xóa",
            command=self.clear_ping,
            bg=UI_COLORS['surface_alt'],
            fg=UI_COLORS['text'],
            relief="flat",
            bd=0,
            padx=15,
            pady=8,
            cursor="hand2"
        )

        clear_button.pack(
            side="left",
            padx=10
        )

        self.ping_status_label = tk.Label(
            button_frame,
            text="Sẵn sàng",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['muted']
        )

        self.ping_status_label.pack(
            side="left",
            padx=15
        )

        result_frame = tk.Frame(
            self.content,
            bg=UI_COLORS['surface'],
            bd=1,
            relief="solid"
        )

        result_frame.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=(0, 20)
        )

        columns = (
            "time",
            "ip",
            "status",
            "response"
        )

        self.ping_table = ttk.Treeview(
            result_frame,
            columns=columns,
            show="headings"
        )

        self.ping_table.heading(
            "time",
            text="Thời gian"
        )

        self.ping_table.heading(
            "ip",
            text="Địa chỉ IP"
        )

        self.ping_table.heading(
            "status",
            text="Trạng thái"
        )

        self.ping_table.heading(
            "response",
            text="Response"
        )

        self.ping_table.column(
            "time",
            width=120,
            anchor="center"
        )

        self.ping_table.column(
            "ip",
            width=200
        )

        self.ping_table.column(
            "status",
            width=150,
            anchor="center"
        )

        self.ping_table.column(
            "response",
            width=150,
            anchor="center"
        )

        scrollbar_y = ttk.Scrollbar(
            result_frame,
            orient="vertical",
            command=self.ping_table.yview
        )

        scrollbar_x = ttk.Scrollbar(
            result_frame,
            orient="horizontal",
            command=self.ping_table.xview
        )

        self.ping_table.configure(
            yscrollcommand=scrollbar_y.set,
            xscrollcommand=scrollbar_x.set
        )

        self.ping_table.pack(
            side="top",
            fill="both",
            expand=True,
            padx=(15, 0),
            pady=(15, 0)
        )

        scrollbar_y.pack(
            side="right",
            fill="y",
            padx=(0, 15),
            pady=(15, 0)
        )

        scrollbar_x.pack(
            side="bottom",
            fill="x",
            padx=(15, 15),
            pady=(0, 15)
        )

        self.ping_table.tag_configure(
            "online",
            foreground=UI_COLORS['success']
        )

        self.ping_table.tag_configure(
            "offline",
            foreground=UI_COLORS['danger']
        )

        self.ping_table.tag_configure(
            "error",
            foreground=UI_COLORS['warning']
        )

    def load_ips_from_device_manager(self):
        """Hàm xử lý lấy danh sách IP từ cơ sở dữ liệu (Device Manager) điền vào ô Ping"""
        try:
            raw_devices = get_all_devices() or []
            ips = []
            for row in raw_devices:
                device = self._normalize_device_record(row)
                if device and device.get("ip"):
                    ip = str(device.get("ip")).strip()
                    if ip and ip not in ips:
                        ips.append(ip)

            if not ips:
                messagebox.showwarning(
                    "Load Devices",
                    "Không tìm thấy IP nào trong Device Manager."
                )
                return

            self.ping_entry.delete("1.0", tk.END)
            self.ping_entry.insert("1.0", "\n".join(ips))

            self.ping_status_label.config(
                text=f"Đã tải {len(ips)} IP từ Device Manager."
            )
            self.add_activity(f"Loaded {len(ips)} IPs from Device Manager into Ping Monitor.")
        except Exception as error:
            messagebox.showerror(
                "Error",
                f"Không thể tải IP từ Device Manager: {error}"
            )

    def get_ping_ips(self):

        if not hasattr(
            self,
            "ping_entry"
        ):

            return []

        text = self.ping_entry.get(
            "1.0",
            tk.END
        )

        ips = []

        for line in text.splitlines():

            ip = line.strip()

            if ip and ip not in ips:

                ips.append(ip)

        return ips

    def run_ping_all(self):

        if self.ping_running:

            self.ping_status_label.config(
                text="A ping operation is already running."
            )

            return

        ips = self.get_ping_ips()

        if not ips:

            self.ping_status_label.config(
                text="No IP address."
            )

            return

        self.start_ping_thread(
            ips
        )

    def start_ping_thread(
        self,
        ips
    ):

        if self.ping_running:

            return

        self.ping_running = True

        self.ping_all_button.config(
            state="disabled"
        )

        self.ping_status_label.config(
            text=f"Pinging {len(ips)} hosts..."
        )

        thread = threading.Thread(
            target=self.ping_worker,
            args=(ips,),
            daemon=True
        )

        thread.start()

        self.ping_thread = thread

    def ping_worker(
        self,
        ips
    ):

        try:

            results = ping_multiple(
                ips,
                max_workers=50,
                timeout=1
            )

            if not self._closing:
                self.root.after(0, self.display_ping_results, results)

        except Exception as error:

            if not self._closing:
                self.root.after(0, self.ping_error, str(error))

    def display_ping_results(
        self,
        results
    ):

        for item in self.ping_table.get_children():

            self.ping_table.delete(
                item
            )

        online = 0
        offline = 0
        errors = 0

        for result in results:

            status = result.get(
                "status",
                "Error"
            )

            response = result.get(
                "response"
            )

            if response is None:

                response_text = "-"

            else:

                response_text = (
                    f"{response} ms"
                )

            if status == "Online":

                online += 1
                tag = "online"

            elif status == "Offline":

                offline += 1
                tag = "offline"

            else:

                errors += 1
                tag = "error"

            self.ping_table.insert(
                "",
                "end",
                values=(
                    result.get(
                        "time",
                        datetime.now().strftime(
                            "%H:%M:%S"
                        )
                    ),

                    result.get(
                        "ip",
                        ""
                    ),

                    status,

                    response_text
                ),
                tags=(tag,)
            )

        self.ping_running = False

        self.ping_all_button.config(
            state="normal"
        )

        self.ping_status_label.config(
            text=(
                f"Total: {len(results)} | "
                f"Online: {online} | "
                f"Offline: {offline} | "
                f"Error: {errors}"
            )
        )

        self.add_activity(
            "Ping completed. "
            f"Total: {len(results)}, "
            f"Online: {online}, "
            f"Offline: {offline}"
        )

        if self.auto_ping_running:

            self.schedule_auto_ping()

    def ping_error(
        self,
        error
    ):

        self.ping_running = False

        self.ping_all_button.config(
            state="normal"
        )

        self.ping_status_label.config(
            text=f"Error: {error}"
        )

        self.add_activity(
            f"Ping error: {error}"
        )

        if self.auto_ping_running:

            self.schedule_auto_ping()

    def toggle_auto_ping(self):

        if self.auto_ping_running:

            self.stop_auto_ping()

        else:

            self.start_auto_ping()

    def start_auto_ping(self):

        ips = self.get_ping_ips()

        if not ips:

            self.ping_status_label.config(
                text="No IP address."
            )

            return

        self.auto_ping_running = True

        self.auto_ping_button.config(
            text="Dừng Ping tự động",
            bg=UI_COLORS['danger_bg']
        )

        self.ping_status_label.config(
            text="Auto Ping running..."
        )

        self.add_activity(
            "Auto Ping started."
        )
 
        if not self.ping_running:

            self.start_ping_thread(
                ips
            )

    def stop_auto_ping(
        self,
        silent=False
    ):

        self.auto_ping_running = False

        if self.auto_ping_job is not None:

            try:

                self.root.after_cancel(
                    self.auto_ping_job
                )

            except Exception:

                pass

            self.auto_ping_job = None

        if hasattr(
            self,
            "auto_ping_button"
        ):

            try:

                if self.auto_ping_button.winfo_exists():

                    self.auto_ping_button.config(
                        text="Bắt đầu Ping tự động",
                        bg=UI_COLORS['success_bg']
                    )

            except tk.TclError:

                pass

        if not silent:

            if hasattr(
                self,
                "ping_status_label"
            ):

                try:

                    if self.ping_status_label.winfo_exists():

                        self.ping_status_label.config(
                            text="Auto Ping stopped."
                        )

                except tk.TclError:

                    pass

            self.add_activity(
                "Auto Ping stopped."
            )

    def schedule_auto_ping(self):

        if not self.auto_ping_running:

            return

        if self.auto_ping_job is not None:

            return

        try:

            interval = int(
                self.interval_var.get()
            )

        except Exception:

            interval = 5

        self.auto_ping_job = self.root.after(
            interval * 1000,
            self.auto_ping_tick
        )

    def auto_ping_tick(self):

        self.auto_ping_job = None

        if not self.auto_ping_running:

            return

        ips = self.get_ping_ips()

        if not ips:

            self.stop_auto_ping()

            return

        if self.ping_running:

            self.schedule_auto_ping()

            return

        self.start_ping_thread(
            ips
        )

    def clear_ping(self):

        if self.auto_ping_running:

            self.stop_auto_ping()

        for item in self.ping_table.get_children():

            self.ping_table.delete(
                item
            )

        self.ping_status_label.config(
            text="Cleared."
        )

        self.add_activity(
            "Ping monitor cleared."
        )

    def show_ip_mac_manager(self):

        self.current_page = "Quản lý IP / MAC"
        self.clear_content()
        self.set_page_title(
            "Quản lý IP / MAC",
            "Phát hiện, theo dõi và ghi chú ánh xạ IP/MAC trong mạng LAN"
        )
        self.ip_mac_manager_page = IPMacManagerPage(
            self.content,
            activity_callback=self.add_activity
        )

    def show_noc_dashboard(self):
        self.clear_content(); self.current_page = "Trung tâm giám sát NOC"
        self.set_page_title("Trung tâm giám sát NOC", "Tổng quan vận hành thiết bị, cảnh báo và giám sát SNMP")
        self.noc_dashboard_page = NOCDashboardPage(self.content, activity_callback=self.add_activity)

    def show_auto_discovery(self):
        self.clear_content(); self.current_page = "Tự động phát hiện"
        self.set_page_title("Tự động phát hiện", "Tìm thiết bị trực tuyến và thêm vào danh sách quản lý")
        self.auto_discovery_page = AutoDiscoveryPage(self.content, activity_callback=self.add_activity)

    def show_multi_port_monitor(self):
        self.clear_content(); self.current_page = "Giám sát nhiều cổng"
        self.set_page_title("Giám sát nhiều cổng", "Theo dõi nhiều cổng switch bằng SNMP v2c")
        self.multi_port_monitor_page = MultiPortMonitorPage(self.content, activity_callback=self.add_activity)

    def show_resource_monitor(self):
        self.clear_content(); self.current_page = "CPU / RAM SNMP"
        self.set_page_title("CPU / RAM SNMP", "Theo dõi tài nguyên thiết bị bằng OID SNMP theo hãng hoặc OID tùy chỉnh")
        self.resource_monitor_page = ResourceMonitorPage(self.content, activity_callback=self.add_activity)

    def show_advanced_port_monitor(self):
        self.clear_content(); self.current_page = "Giám sát cổng nâng cao"
        self.set_page_title("Giám sát cổng nâng cao", "Trạng thái, tốc độ, lỗi và discard trên từng interface")
        self.advanced_port_monitor_page = AdvancedPortMonitorPage(self.content, activity_callback=self.add_activity)

    def show_alert_rules(self):
        self.clear_content(); self.current_page = "Quy tắc cảnh báo"
        self.set_page_title("Quy tắc cảnh báo", "Tự động tạo cảnh báo khi chỉ số vượt ngưỡng đã đặt")
        self.alert_rules_page = AlertRulesPage(self.content, activity_callback=self.add_activity)

    def show_history_charts(self):
        self.clear_content(); self.current_page = "Biểu đồ lịch sử"
        self.set_page_title("Biểu đồ lịch sử", "Xem dữ liệu SNMP/CPU/RAM trong 24 giờ, 7 ngày hoặc 30 ngày")
        self.history_charts_page = HistoryChartsPage(self.content, activity_callback=self.add_activity)

    def show_network_health(self):
        self.clear_content(); self.current_page = "Sức khỏe mạng"
        self.set_page_title("Sức khỏe mạng", "Kiểm tra độ trễ, mất gói, uptime và thông tin SNMP của thiết bị")
        self.network_health_page = NetworkHealthPage(self.content, activity_callback=self.add_activity)

    def show_backup_scheduler(self):
        self.clear_content(); self.current_page = "Lịch sao lưu"
        self.set_page_title("Lịch sao lưu", "Lập lịch tự động sao lưu cấu hình qua SSH")
        self.backup_scheduler_page = BackupSchedulerPage(self.content, activity_callback=self.add_activity)

    def show_network_devices(self):

        self.current_page = "Thiết bị mạng"
        self.clear_content()
        self.set_page_title("Thiết bị mạng", "Quản lý router, switch, AP và các thiết bị hạ tầng")
        self.network_devices_page = NetworkDevicesPage(self.content, activity_callback=self.add_activity)


    def show_device_profiles(self):
        self.current_page = "Hồ sơ thiết bị theo hãng"
        self.clear_content()
        self.set_page_title("Hồ sơ thiết bị theo hãng", "Tự nhận diện Cisco/MikroTik/Ruijie/Aruba-HPE và áp dụng OID/lệnh backup phù hợp")
        self.device_profiles_page = DeviceProfilesPage(self.content, activity_callback=self.add_activity)


    def show_organization(self):
        self.current_page = "Site / Nhóm / VLAN"
        self.clear_content()
        self.set_page_title("Site / Nhóm / VLAN", "Tổ chức thiết bị theo địa điểm, nhóm nghiệp vụ, VLAN và tags")
        self.organization_page = OrganizationPage(self.content, activity_callback=self.add_activity)

    def show_maintenance_windows(self):
        self.current_page = "Lịch bảo trì"
        self.clear_content()
        self.set_page_title("Lịch bảo trì", "Tắt cảnh báo theo thiết bị, Site hoặc nhóm trong thời gian bảo trì")
        self.maintenance_windows_page = MaintenanceWindowsPage(self.content, activity_callback=self.add_activity)


    def show_sla_availability(self):
        self.clear_content(); self.current_page = "SLA & Độ sẵn sàng"
        self.set_page_title("SLA & Độ sẵn sàng", "Tính tỷ lệ sẵn sàng theo thiết bị, Site, nhóm và loại trừ thời gian bảo trì")
        self.sla_availability_page = SLAAvailabilityPage(self.content, activity_callback=self.add_activity, role=self.current_role)

    def show_capacity_planning(self):
        self.clear_content(); self.current_page = "Phân tích dung lượng"
        self.set_page_title("Phân tích dung lượng", "Tổng hợp CPU, RAM, latency, packet loss và lỗi cổng theo lịch sử giám sát")
        self.capacity_planning_page = CapacityPlanningPage(self.content, activity_callback=self.add_activity)

    def show_incident_center(self):
        self.clear_content(); self.current_page = "Trung tâm sự cố"
        self.set_page_title("Trung tâm sự cố", "Gom cảnh báo thành sự cố, xác nhận, theo dõi và đóng sự cố")
        self.incident_center_page = IncidentCenterPage(self.content, activity_callback=self.add_activity, role=self.current_role, username=self.session_user.get('username',''))

    def show_device_dependencies(self):
        self.clear_content(); self.current_page = "Phụ thuộc thiết bị"
        self.set_page_title("Phụ thuộc thiết bị", "Khai báo quan hệ cha/con để tương quan cảnh báo và xác định phạm vi ảnh hưởng")
        self.device_dependencies_page = DeviceDependenciesPage(self.content, activity_callback=self.add_activity, role=self.current_role)

    def show_service_impact(self):
        self.clear_content(); self.current_page = "Dịch vụ & Mức ảnh hưởng"
        self.set_page_title("Dịch vụ & Mức ảnh hưởng", "Gom thiết bị theo dịch vụ và đánh giá trạng thái Hoạt động / Suy giảm / Gián đoạn")
        self.service_impact_page = ServiceImpactPage(self.content, activity_callback=self.add_activity, role=self.current_role)

    def show_root_cause_analysis(self):
        self.clear_content(); self.current_page = "Phân tích nguyên nhân gốc"
        self.set_page_title("Phân tích nguyên nhân gốc", "Tương quan cảnh báo theo dependency để giảm bão cảnh báo và tìm thiết bị gốc gây sự cố")
        self.root_cause_analysis_page = RootCauseAnalysisPage(self.content, activity_callback=self.add_activity)


    def show_auto_ip(self):
        if self.current_role not in ("Admin", "Operator"):
            messagebox.showwarning("Phân quyền", "Chỉ Admin/Operator được chạy Tự động IP/Excel.")
            return
        self.clear_content()
        self.current_page = "Tự động IP/Excel"
        self.set_page_title("Tự động IP/Excel", "Chức năng riêng: nhập danh sách, chọn hồ sơ, chạy và theo dõi kết quả")
        if not hasattr(self, "auto_ip_engine"):
            self.auto_ip_engine = AutomationEngine()
        self.auto_ip_page = AutoIPPage(self.content, self.auto_ip_engine, self.session_user, self.add_activity)

    def show_secure_snmp_diagnostics(self):
        self.current_page = "Chẩn đoán SNMP v2c/v3"
        self.clear_content()
        self.set_page_title("Chẩn đoán SNMP v2c/v3", "Kiểm tra SNMPv2c/SNMPv3, nhận diện hãng và thử OID theo driver")
        self.secure_snmp_diagnostics_page = SecureSNMPDiagnosticsPage(self.content, activity_callback=self.add_activity)

    def show_vendor_drivers(self):
        self.current_page = "Vendor Driver Engine"
        self.clear_content()
        self.set_page_title("Vendor Driver Engine", "Driver theo hãng: nhận diện thiết bị, OID tài nguyên, backup và LLDP/CDP")
        self.vendor_driver_page = VendorDriverPage(self.content, activity_callback=self.add_activity)

    def show_snmpv3_credentials(self):
        if self.current_role != "Admin":
            messagebox.showwarning("Phân quyền", "Chỉ Admin được quản lý Credential SNMPv3.")
            return
        self.current_page = "Credential SNMPv3"
        self.clear_content()
        self.set_page_title("Credential SNMPv3", "Quản lý username, Auth/Privacy được mã hóa và gán cho thiết bị")
        self.snmpv3_credentials_page = SNMPv3CredentialsPage(self.content, activity_callback=self.add_activity)

    def show_snmp_monitor(self):

        self.current_page = "Giám sát SNMP"
        self.clear_content()
        self.set_page_title("Giám sát SNMP", "Giám sát SNMP v2c và biểu đồ lưu lượng cổng theo thời gian thực")
        self.snmp_monitor_page = SNMPMonitorPage(self.content, activity_callback=self.add_activity)

    def show_auto_topology(self):

        self.current_page = "Tự dựng Topology LLDP/CDP"
        self.clear_content()
        self.set_page_title("Tự dựng Topology LLDP/CDP", "Phát hiện láng giềng LLDP/CDP qua SNMP và tự thêm liên kết vào sơ đồ mạng")
        self.auto_topology_page = AutoTopologyPage(self.content, activity_callback=self.add_activity)

    def show_network_topology(self):

        self.current_page = "Sơ đồ mạng"
        self.clear_content()
        self.set_page_title("Sơ đồ mạng", "Hiển thị thiết bị và liên kết vật lý hoặc logic")
        self.network_topology_page = NetworkTopologyPage(self.content, activity_callback=self.add_activity)

    def show_ssh_automation(self):

        self.current_page = "Tự động hóa SSH"
        self.clear_content()
        self.set_page_title("Tự động hóa SSH", "Chạy mẫu lệnh và sao lưu cấu hình qua SSH")
        self.ssh_automation_page = SSHAutomationPage(self.content, activity_callback=self.add_activity)

    def show_notifications(self):

        self.current_page = "Thông báo"
        self.clear_content()
        self.set_page_title("Notification Center", "Telegram/Email, lọc sự kiện và chống gửi cảnh báo trùng")
        self.notifications_page = NotificationsPage(self.content, activity_callback=self.add_activity)

    def show_remote_service(self):

        self.current_page = "Truy cập từ xa"
        self.clear_content()
        self.set_page_title("Truy cập từ xa", "Kiểm tra cổng quản trị và mở SSH, Telnet, RDP hoặc Web")
        self.remote_service_page = RemoteServicePage(self.content, activity_callback=self.add_activity)

    def show_backup_config(self):

        self.current_page = "Sao lưu cấu hình"
        self.clear_content()
        self.set_page_title("Sao lưu cấu hình", "Tạo và quản lý bản sao lưu cấu hình thiết bị mạng")
        self.backup_config_page = BackupConfigPage(self.content, activity_callback=self.add_activity)

    def show_scheduler(self):

        self.current_page = "Lịch tác vụ"
        self.clear_content()
        self.set_page_title("Lịch tác vụ", "Chạy định kỳ Ping, kiểm tra TCP và cảnh báo khi ứng dụng đang mở")
        self.scheduler_page = SchedulerPage(self.content, activity_callback=self.add_activity)

    def show_alerts(self):

        self.current_page = "Cảnh báo"
        self.clear_content()
        self.set_page_title("Cảnh báo", "Theo dõi thiết bị ngoại tuyến và cảnh báo vận hành")
        self.alerts_page = AlertsPage(self.content, activity_callback=self.add_activity)


    def show_daily_audit(self):
        if self.current_role == "Viewer":
            messagebox.showwarning("Phân quyền", "Viewer không được chạy Daily Audit trên máy chủ.")
            return
        self.current_page = "Daily Audit Windows"
        self.clear_content()
        self.set_page_title("Daily Audit Windows", "Tự động kiểm tra Windows Server và tổng hợp cảnh báo vận hành/bảo mật")
        self.daily_audit_page = DailyAuditPage(self.content, activity_callback=self.add_activity)

    def show_security_audit(self):
        if self.current_role == "Viewer":
            messagebox.showwarning("Phân quyền", "Viewer chỉ được xem các màn hình giám sát.")
            return
        self.current_page = "Baseline & Security"
        self.clear_content()
        self.set_page_title("Configuration Baseline & Security Posture", "Phát hiện thay đổi cấu hình và audit security control ở chế độ read-only")
        self.security_audit_page = SecurityAuditPage(self.content, activity_callback=self.add_activity)

    def show_enterprise_security(self):
        self.current_page = "Enterprise Security"
        self.clear_content()
        self.set_page_title("Enterprise Cybersecurity Center", "Tài sản, Device Identity Guard, kiểm tra read-only, risk scoring và SOC events")
        self.enterprise_security_page = EnterpriseSecurityPage(
            self.content, activity_callback=self.add_activity, current_role=self.current_role
        )

    def show_reports(self):

        self.current_page = "Báo cáo"
        self.clear_content()
        self.set_page_title("Báo cáo", "Tạo báo cáo vận hành và xuất dữ liệu mạng")
        self.reports_page = ReportsPage(self.content, activity_callback=self.add_activity)

    def show_system_logs(self):

        self.current_page = "Nhật ký hệ thống"
        self.clear_content()
        self.set_page_title("Nhật ký hệ thống", "Tìm kiếm và xuất nhật ký hoạt động")
        self.system_logs_page = SystemLogsPage(self.content, activity_callback=self.add_activity)

    def show_settings(self):

        self.current_page = "Cài đặt"
        self.clear_content()
        self.set_page_title("Cài đặt", "Cấu hình mặc định cho quét mạng và giám sát")
        self.settings_page = SettingsPage(self.content, activity_callback=self.add_activity)

    def show_credential_manager(self):
        if self.current_role != "Admin":
            messagebox.showwarning("Phân quyền", "Chỉ Admin được quản lý Credential.")
            return
        self.current_page = "Quản lý Credential"
        self.clear_content()
        self.set_page_title("Quản lý Credential", "Lưu SSH/SNMP credential được mã hóa và gán cho từng thiết bị")
        self.credential_manager_page = CredentialManagerPage(self.content, activity_callback=self.add_activity)

    def show_secure_backup_scheduler(self):
        if self.current_role == "Viewer":
            messagebox.showwarning("Phân quyền", "Viewer không được chạy sao lưu cấu hình.")
            return
        self.current_page = "Lịch sao lưu bảo mật"
        self.clear_content()
        self.set_page_title("Lịch sao lưu bảo mật", "Tự động backup cấu hình SSH bằng credential đã mã hóa")
        self.secure_backup_scheduler_page = SecureBackupSchedulerPage(self.content, activity_callback=self.add_activity)

    def show_config_compare(self):
        self.current_page = "So sánh cấu hình"
        self.clear_content()
        self.set_page_title("So sánh cấu hình", "So sánh hai phiên bản backup và hiển thị thay đổi dạng diff")
        self.config_compare_page = ConfigComparePage(self.content, activity_callback=self.add_activity)

    def show_user_roles(self):
        if self.current_role != "Admin":
            messagebox.showwarning("Phân quyền", "Chỉ Admin được quản lý người dùng và phân quyền.")
            return
        self.current_page = "Quản lý tài khoản"
        self.clear_content()
        self.set_page_title("Quản lý tài khoản", "Thêm, sửa, khóa tài khoản và phân quyền kỹ thuật viên")
        self.user_role_page = UserRolePage(self.content, activity_callback=self.add_activity,
                                         session_user=self.session_user, on_session_update=self.update_session_profile)

    def update_session_profile(self, user):
        self.session_user.update(user)
        self.current_role = self.session_user['role']
        self.account_header.render(compact=self.root.winfo_width()<1100)
        self.sidebar_title.configure(text=f"NETWORK\nAUTOMATION\n\n{self.session_user['username']} • {self.current_role}")

    def open_profile(self):
        from modules.account_ui import profile_dialog
        try:
            profile_dialog(self.root, self.session_user, self.open_password, self.show_user_roles)
        except ValueError as exc:
            messagebox.showwarning('Hồ sơ cá nhân', str(exc), parent=self.root)

    def open_password(self):
        if self.session_user.get('bootstrap'):
            self.show_user_roles()
            self.user_role_page.page.add()
            return
        from modules.account_ui import password_dialog
        password_dialog(self.root, self.session_user)

    def show_monitoring_service(self):
        self.current_page = "Dịch vụ giám sát nền"
        self.clear_content(); self.set_page_title("Dịch vụ giám sát nền", "Thu thập Ping/latency/packet loss định kỳ và tự dọn lịch sử")
        MonitoringServicePage(self.content, self.monitoring_service, self.session_user)

    def show_stable_core(self):
        self.current_page = "Sức khỏe hệ thống"
        self.clear_content(); self.set_page_title("Stable Core & Worker Engine", "Worker Queue, chống cảnh báo chập chờn, kiểm tra và bảo trì Database")
        self.stable_core_page = StableCorePage(self.content, self.job_queue_engine, self.session_user)

    def show_audit_log(self):
        self.current_page = "Nhật ký hoạt động"
        subtitle = "Theo dõi hoạt động của tất cả tài khoản" if self.current_role == 'Admin' else "Theo dõi hoạt động của tài khoản đang đăng nhập"
        self.clear_content(); self.set_page_title("Nhật ký hoạt động", subtitle)
        AuditLogPage(self.content, self.session_user)

    def show_restore_config(self):
        self.current_page = "Khôi phục cấu hình"
        self.clear_content(); self.set_page_title("Khôi phục cấu hình", "Khôi phục có xác nhận và tạo safety backup trước khi thay đổi")
        RestoreConfigPage(self.content, self.session_user)

    def logout(self):
        self.on_close(reason='logout')

    def on_close(self, reason='close'):
        if self._closing:
            return
        self._closing = True
        self.exit_reason = reason
        self._closing_threads = [getattr(self, 'scan_thread', None), getattr(self, 'ping_thread', None)]
        # Stop scheduling before waiting for current workers to finish.
        for name in ('job_queue_engine', 'monitoring_service', 'background_alert_engine',
                     'root_cause_engine', 'auto_audit_scheduler', 'auto_ip_engine'):
            engine = getattr(self, name, None)
            if engine:
                try:
                    engine.stop()
                except Exception:
                    logging.getLogger(__name__).exception('Cannot stop %s', name)
        from modules.responsive_layout import cancel_page_timers
        cancel_page_timers(self.root)
        self.clear_content()
        self.topbar.pack_forget()
        self.sidebar.pack_forget()
        # Close session dialogs so no account actions can be submitted while exiting.
        for child in self.root.winfo_children():
            if isinstance(child, tk.Toplevel):
                child.destroy()
        self.root.title('Đang đăng xuất...' if reason == 'logout' else 'Đang đóng ứng dụng...')
        self.set_page_title('Đang kết thúc phiên', 'Đang dừng tác vụ nền, vui lòng chờ...')
        self._finish_close()

    def _finish_close(self):
        # Drain workers without blocking the Tk event loop or dropping DB writes.
        if hasattr(self, "auto_ip_engine") and self.auto_ip_engine.running:
            self.root.after(250, self._finish_close)
            return
        threads = list(getattr(self, '_closing_threads', []))
        for name in ('monitoring_service', 'background_alert_engine', 'auto_audit_scheduler'):
            threads.append(getattr(getattr(self, name, None), 'thread', None))
        threads.extend(getattr(getattr(self, 'job_queue_engine', None), 'threads', []))
        if any(thread and thread.is_alive() for thread in threads):
            self.root.after(250, self._finish_close)
            return
        try: audit(self.session_user.get('username'), self.current_role,
                   'Đăng xuất' if self.exit_reason == 'logout' else 'Đóng ứng dụng',
                   'Network Automation', 'Kết thúc phiên làm việc')
        except Exception: pass
        self.root.destroy()

    def show_placeholder(self):

        self.current_page = "Sắp có"

        self.clear_content()

        self.set_page_title(
            "Module",
            "This module is under development."
        )

        frame = tk.Frame(
            self.content,
            bg=UI_COLORS['surface'],
            bd=1,
            relief="solid"
        )

        frame.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=10
        )

        tk.Label(
            frame,
            text="Sắp có",
            bg=UI_COLORS['surface'],
            fg=UI_COLORS['muted'],
            font=(
                "Segoe UI",
                20,
                "bold"
            )
        ).pack(
            expand=True
        )


def run_application():
    """Return to a fresh login after logout; bootstrap is only for first launch."""
    from modules.ui_theme import apply_theme

    def _tk_exception(exc, val, tb):
        logging.getLogger("tkinter").error("Unhandled Tk callback exception", exc_info=(exc, val, tb))
        try:
            messagebox.showerror("Network Automation", f"Đã xảy ra lỗi. Chi tiết được ghi tại:\n{LOG_DIR / 'network_automation.log'}\n\n{val}")
        except Exception:
            pass

    allow_bootstrap = True
    while True:
        # Each login gets a fresh Tk tree, bindings and timers.
        root = tk.Tk()
        apply_theme(root)
        root.report_callback_exception = _tk_exception
        root.withdraw()
        session_user = LoginDialog(root, allow_bootstrap=allow_bootstrap).run()
        if session_user is None:
            root.destroy()
            break
        root.deiconify()
        app = NetworkAutomationApp(root, session_user=session_user)
        root.mainloop()
        if app.exit_reason != 'logout':
            break
        allow_bootstrap = False


if __name__ == "__main__":
    setup_logging()
    init_database()
    ensure_server_monitor_tables()
    ensure_v5_tables()
    run_application()
