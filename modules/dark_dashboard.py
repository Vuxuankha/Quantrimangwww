"""Responsive native-Tk NOC command-center dashboard.

The dashboard intentionally reuses existing application callbacks and database
queries.  This module changes presentation/interaction only; it does not start
network operations by itself.
"""
from datetime import datetime
import math
import tkinter as tk
from tkinter import ttk

from database.db import get_connection
from app_runtime import data_path
from agent_runtime import heartbeat_status
from modules.ui_theme import PALETTE as UI_COLORS
from modules.ui_ux_config import TYPE, SPACE

BG = UI_COLORS['background']
PANEL = UI_COLORS['surface']
PANEL2 = UI_COLORS['surface_alt']
FIELD = UI_COLORS.get('field', BG)
BORDER = UI_COLORS['border']
BORDER_STRONG = UI_COLORS.get('border_strong', BORDER)
TEXT = UI_COLORS['text']
MUTED = UI_COLORS['muted']
SUBTLE = UI_COLORS.get('subtle', MUTED)
CYAN = UI_COLORS['accent']
PINK = UI_COLORS['pink']
RED = UI_COLORS['danger']
GREEN = UI_COLORS['success']
WARNING = UI_COLORS.get('warning', '#F6C768')
INFO = UI_COLORS.get('info', '#72B8FF')


def dashboard_columns(width):
    """Number of KPI cards that fit the current dashboard content width."""
    return 5 if width >= 1100 else (3 if width >= 780 else 2)


def collect_snapshot(connect=get_connection):
    """Read current state, retaining unavailable flags instead of inventing health."""
    result = {
        'total': None, 'online': None, 'offline': None, 'other': None,
        'alerts': None, 'incidents': None, 'attention': [], 'events': [],
        'unavailable': [],
    }
    try:
        connection = connect()
    except Exception:
        result['unavailable'] = ['Thiết bị', 'Cảnh báo', 'Sự cố']
        return result
    try:
        try:
            counts = connection.execute(
                "SELECT LOWER(TRIM(COALESCE(status,''))),COUNT(*) "
                "FROM network_devices GROUP BY LOWER(TRIM(COALESCE(status,'')))"
            ).fetchall()
            result['total'] = sum(row[1] for row in counts)
            result['online'] = sum(row[1] for row in counts if row[0] == 'online')
            result['offline'] = sum(row[1] for row in counts if row[0] == 'offline')
            result['other'] = result['total'] - result['online'] - result['offline']
            for row in connection.execute(
                "SELECT name,ip,device_type,status FROM network_devices "
                "WHERE LOWER(TRIM(COALESCE(status,'')))<>'online' "
                "ORDER BY updated_at DESC LIMIT 8"
            ):
                result['attention'].append((
                    'Thiết bị', row[1] or row[0] or '—',
                    str(row[3] or 'Chưa xác định') + ' · ' + str(row[2] or 'Chưa phân loại')
                ))
        except Exception:
            result['unavailable'].append('Thiết bị')
        try:
            result['alerts'] = connection.execute(
                "SELECT COUNT(*) FROM alerts WHERE LOWER(TRIM(COALESCE(status,'')))<>'closed'"
            ).fetchone()[0]
            for row in connection.execute(
                "SELECT created_at,severity,ip,alert_type,message FROM alerts "
                "WHERE LOWER(TRIM(COALESCE(status,'')))<>'closed' ORDER BY id DESC LIMIT 8"
            ):
                result['events'].append((
                    row[0] or '—', row[1] or 'Cảnh báo', row[2] or '—', row[4] or row[3] or ''
                ))
                if len(result['attention']) < 12:
                    result['attention'].append((
                        row[1] or 'Cảnh báo', row[2] or '—', row[4] or row[3] or ''
                    ))
        except Exception:
            result['unavailable'].append('Cảnh báo')
        try:
            result['incidents'] = connection.execute(
                "SELECT COUNT(*) FROM incidents "
                "WHERE LOWER(TRIM(COALESCE(status,''))) NOT IN ('closed','resolved')"
            ).fetchone()[0]
            incidents = [
                (row[0] or '—', row[1] or 'Sự cố', row[2] or '—', row[3] or '')
                for row in connection.execute(
                    "SELECT last_seen,severity,host,title FROM incidents "
                    "WHERE LOWER(TRIM(COALESCE(status,''))) NOT IN ('closed','resolved') "
                    "ORDER BY id DESC LIMIT 6"
                )
            ]
            result['events'] = sorted(
                result['events'] + incidents, key=lambda row: str(row[0]), reverse=True
            )[:14]
        except Exception:
            result['unavailable'].append('Sự cố')
    finally:
        connection.close()
    return result


def label(parent, text='', **options):
    defaults = {
        'bg': parent.cget('bg'), 'fg': TEXT, 'font': TYPE['body'],
        'anchor': 'w', 'justify': 'left',
    }
    defaults.update(options)
    return tk.Label(parent, text=text, **defaults)


def button(parent, text, command, accent=False, quiet=False):
    if accent:
        bg, fg, hover = UI_COLORS['primary'], TEXT, UI_COLORS['hover']
    elif quiet:
        bg, fg, hover = PANEL, MUTED, PANEL2
    else:
        bg, fg, hover = PANEL2, TEXT, UI_COLORS['hover']
    return tk.Button(
        parent, text=text, command=command, bg=bg, fg=fg,
        activebackground=hover, activeforeground=TEXT, relief='flat', bd=0,
        padx=14, pady=8, font=TYPE['body_bold'] if accent else TYPE['body'],
        cursor='hand2', highlightthickness=1, highlightbackground=BORDER,
    )


def _noop():
    return None


class DarkDashboard:
    def __init__(self, app):
        self.app = app
        self.closed = False
        self.after_id = None
        self.tick = 0
        self.snapshot = {}
        self.columns = None
        self.wide = None
        self.frame = tk.Frame(app.content, bg=BG)
        self.frame.pack(fill='both', expand=True)
        self.frame.bind('<Destroy>', self.destroy, add='+')

        self.canvas = tk.Canvas(self.frame, bg=BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(
            self.frame, orient='vertical', command=self.canvas.yview,
            style='NOC.Vertical.TScrollbar'
        )
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        self.body = tk.Frame(self.canvas, bg=BG)
        self.body_window = self.canvas.create_window((0, 0), window=self.body, anchor='nw')
        self.canvas.bind('<Configure>', self.resize)
        self.body.bind(
            '<Configure>', lambda event: self.canvas.configure(scrollregion=self.canvas.bbox('all'))
        )

        self.styles()
        self.build()
        self.install_wheel()
        self.refresh()
        self.poll()

    def action(self, name, fallback=None):
        return getattr(self.app, name, fallback or _noop)

    def install_wheel(self):
        self.wheel_tag = 'NOCScroll' + str(self.frame)

        def scroll(event):
            units = -1 if getattr(event, 'num', None) == 4 else (
                1 if getattr(event, 'num', None) == 5 else -int(event.delta / 120)
            )
            self.canvas.yview_scroll(units, 'units')
            return 'break'

        for sequence in ('<MouseWheel>', '<Button-4>', '<Button-5>'):
            self.frame.bind_class(self.wheel_tag, sequence, scroll)

        def attach(widget):
            if widget.winfo_class() not in ('Text', 'Treeview', 'TScrollbar'):
                widget.bindtags((self.wheel_tag,) + widget.bindtags())
            for child in widget.winfo_children():
                attach(child)
        attach(self.body)

    def styles(self):
        style = ttk.Style(self.frame)
        style.configure('NOC.TFrame', background=PANEL)
        style.configure(
            'NOC.Treeview', background=PANEL, fieldbackground=PANEL,
            foreground=TEXT, rowheight=34, borderwidth=0, font=TYPE['small']
        )
        style.configure(
            'NOC.Treeview.Heading', background=PANEL2, foreground=MUTED,
            relief='flat', padding=(9, 10), font=TYPE['small_bold']
        )
        style.map(
            'NOC.Treeview', background=[('selected', UI_COLORS['selection'])],
            foreground=[('selected', TEXT)]
        )
        style.map('NOC.Treeview.Heading', background=[('active', UI_COLORS['hover'])])
        for name in ('Vertical', 'Horizontal'):
            style.configure(
                'NOC.' + name + '.TScrollbar', background=BORDER,
                troughcolor=BG, bordercolor=BG, arrowcolor=MUTED
            )
        style.configure(
            'NOC.Horizontal.TProgressbar', background=CYAN, troughcolor=FIELD,
            bordercolor=BORDER, lightcolor=CYAN, darkcolor=CYAN
        )

    def section_card(self, parent):
        return tk.Frame(parent, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)

    def build(self):
        app = self.app
        self.build_page_header()
        self.build_health_banner()
        self.build_metrics()
        self.build_quick_actions()
        self.build_status_cards()
        self.build_one_click_panel()
        self.build_tables()
        self.notice = label(self.body, fg=SUBTLE, wraplength=850, font=TYPE['small'])
        self.notice.pack(fill='x', padx=20, pady=(0, 18))

    def build_page_header(self):
        heading = tk.Frame(self.body, bg=BG)
        heading.pack(fill='x', padx=20, pady=(18, 12))
        left = tk.Frame(heading, bg=BG)
        left.pack(side='left', fill='x', expand=True)
        label(left, 'Network Operations', font=TYPE['page_title']).pack(anchor='w')
        label(
            left, 'Tổng quan vận hành, cảnh báo và tác vụ thường dùng',
            fg=MUTED, font=TYPE['small']
        ).pack(anchor='w', pady=(3, 0))

        right = tk.Frame(heading, bg=BG)
        right.pack(side='right')
        self.health_pill = label(
            right, '● Đang tải trạng thái', bg=PANEL2, fg=MUTED,
            font=TYPE['small_bold'], padx=10, pady=7
        )
        self.health_pill.pack(side='left', padx=(0, 8))
        button(right, '↻  Làm mới', self.refresh, quiet=True).pack(side='left', padx=(0, 8))
        self.time_label = label(right, fg=MUTED, font=TYPE['small'])
        self.time_label.pack(side='left')

    def build_health_banner(self):
        self.hero = tk.Canvas(
            self.body, height=96, bg=PANEL, highlightthickness=1,
            highlightbackground=BORDER
        )
        self.hero.pack(fill='x', padx=20, pady=(0, 14))
        self.hero.bind('<Configure>', self.draw_hero)
        self.hero_action = button(
            self.hero, 'Mở Trung tâm NOC  →', self.action('show_noc_dashboard'), True
        )
        self.hero_action.place(relx=1, rely=.5, anchor='e', x=-18)

    def build_metrics(self):
        self.metrics = tk.Frame(self.body, bg=BG)
        self.metrics.pack(fill='x', padx=16)
        self.cards = []
        self.values = {}
        metrics = [
            ('Tổng thiết bị', 'total', 'Hạ tầng đang quản lý', CYAN),
            ('Online', 'online', 'Thiết bị hoạt động', GREEN),
            ('Offline', 'offline', 'Cần kiểm tra kết nối', RED),
            ('Cảnh báo mở', 'alerts', 'Chưa đóng', WARNING),
            ('Sự cố mở', 'incidents', 'Chưa xử lý xong', PINK),
        ]
        for title, key, note, color in metrics:
            card = self.section_card(self.metrics)
            self.cards.append(card)
            top = tk.Frame(card, bg=PANEL)
            top.pack(fill='x', padx=15, pady=(13, 0))
            label(top, title, fg=MUTED, font=TYPE['small_bold']).pack(side='left')
            tk.Label(top, text='●', bg=PANEL, fg=color, font=('Segoe UI', 8)).pack(side='right')
            self.values[key] = tk.StringVar(value='—')
            if key == 'total':
                row = tk.Frame(card, bg=PANEL)
                row.pack(fill='both', expand=True, padx=7, pady=(0, 6))
                self.donut = tk.Canvas(row, width=102, height=102, bg=PANEL, highlightthickness=0)
                self.donut.pack(side='left', padx=(0, 2))
                summary = tk.Frame(row, bg=PANEL)
                summary.pack(side='left', fill='both', expand=True, pady=10)
                label(summary, note, fg=SUBTLE, font=TYPE['small'], wraplength=120).pack(anchor='w')
                self.total_health = label(summary, 'Đang tính trạng thái', fg=CYAN, font=TYPE['small_bold'])
                self.total_health.pack(anchor='w', pady=(8, 0))
            else:
                label(
                    card, textvariable=self.values[key], fg=color,
                    font=('Segoe UI', 28, 'bold')
                ).pack(anchor='w', padx=15, pady=(5, 0))
                label(card, note, fg=SUBTLE, font=TYPE['small']).pack(
                    anchor='w', padx=15, pady=(2, 13)
                )

    def quick_action_tile(self, parent, icon, title, description, command):
        # A Tk Button is not a reliable container for child widgets on Windows.
        # Use a frame as the card so icon/title/description render on every tile.
        tile = tk.Frame(
            parent, bg=PANEL, cursor='hand2', highlightthickness=1,
            highlightbackground=BORDER, highlightcolor=BORDER_STRONG
        )
        inner = tk.Frame(tile, bg=PANEL, cursor='hand2')
        inner.pack(fill='both', expand=True, padx=12, pady=10)
        icon_box = tk.Label(
            inner, text=icon, bg=PANEL2, fg=CYAN, width=3, height=1,
            font=('Segoe UI Symbol', 12, 'bold'), cursor='hand2'
        )
        icon_box.pack(side='left', padx=(0, 10))
        text_box = tk.Frame(inner, bg=PANEL, cursor='hand2')
        text_box.pack(side='left', fill='both', expand=True)
        title_label = label(text_box, title, font=TYPE['body_bold'], cursor='hand2')
        title_label.pack(anchor='w')
        desc_label = label(
            text_box, description, fg=SUBTLE, font=TYPE['caption'], cursor='hand2'
        )
        desc_label.pack(anchor='w', pady=(2, 0))

        widgets = (tile, inner, icon_box, text_box, title_label, desc_label)

        def invoke(_event=None):
            command()
            return 'break'

        def set_hover(active):
            color = PANEL2 if active else PANEL
            tile.configure(bg=color, highlightbackground=BORDER_STRONG if active else BORDER)
            inner.configure(bg=color)
            text_box.configure(bg=color)
            title_label.configure(bg=color)
            desc_label.configure(bg=color)

        for widget in widgets:
            widget.bind('<Button-1>', invoke)
            widget.bind('<Enter>', lambda _event: set_hover(True))
            widget.bind('<Leave>', lambda _event: set_hover(False))
        tile.bind('<Return>', invoke)
        tile.bind('<space>', invoke)
        tile.configure(takefocus=1)
        return tile

    def build_quick_actions(self):
        box = tk.Frame(self.body, bg=BG)
        box.pack(fill='x', padx=20, pady=(14, 0))
        head = tk.Frame(box, bg=BG)
        head.pack(fill='x', pady=(0, 8))
        label(head, 'Thao tác nhanh', font=TYPE['section_title']).pack(side='left')
        label(head, 'Truy cập tác vụ thường dùng', fg=SUBTLE, font=TYPE['small']).pack(side='left', padx=10)
        self.quick_actions_grid = tk.Frame(box, bg=BG)
        self.quick_actions_grid.pack(fill='x')
        actions = [
            ('▣', 'Thiết bị', 'Quản lý inventory', self.action('show_device_manager', self.action('show_noc_dashboard'))),
            ('⌁', 'Discovery', 'Tìm thiết bị mới', self.action('show_network_scan', self.action('show_noc_dashboard'))),
            ('↔', 'Ping Monitor', 'Kiểm tra khả dụng', self.action('show_ping_monitor', self.action('show_noc_dashboard'))),
            ('⚙', 'Automation', 'SSH & tác vụ tự động', self.action('show_automation_hub', self.action('show_noc_dashboard'))),
        ]
        self.quick_action_tiles = []
        for icon, title, desc, command in actions:
            self.quick_action_tiles.append(self.quick_action_tile(
                self.quick_actions_grid, icon, title, desc, command
            ))

    def build_status_cards(self):
        self.status_row = tk.Frame(self.body, bg=BG)
        self.status_row.pack(fill='x', padx=20, pady=14)

        self.connection = self.section_card(self.status_row)
        connection_text = tk.Frame(self.connection, bg=PANEL)
        connection_text.pack(fill='both', expand=True, pady=13, padx=14)
        top = tk.Frame(connection_text, bg=PANEL)
        top.pack(fill='x')
        label(top, 'Network Health', font=TYPE['section_title']).pack(side='left')
        self.network_state = label(top, 'Đang tải', fg=MUTED, font=TYPE['small_bold'])
        self.network_state.pack(side='right')
        self.legend = label(connection_text, fg=MUTED, font=TYPE['small'])
        self.legend.pack(anchor='w', pady=(8, 4))
        self.agent = label(connection_text, fg=CYAN, wraplength=320, font=TYPE['small'])
        self.agent.pack(fill='x')
        self.agent_hint = label(connection_text, fg=SUBTLE, wraplength=320, font=TYPE['caption'])
        self.agent_hint.pack(fill='x', pady=(3, 0))

        self.audit = self.section_card(self.status_row)
        audit_top = tk.Frame(self.audit, bg=PANEL)
        audit_top.pack(fill='x', padx=14, pady=(12, 5))
        label(audit_top, 'Daily Audit Windows', font=TYPE['section_title']).pack(side='left')
        button(audit_top, 'Mở Audit', self.action('show_daily_audit'), quiet=True).pack(side='right')
        self.audit_label = label(self.audit, fg=MUTED, wraplength=450, font=TYPE['small'])
        self.audit_label.pack(fill='x', padx=14, pady=(0, 13))

    def build_one_click_panel(self):
        quick_header = tk.Frame(self.body, bg=BG)
        quick_header.pack(fill='x', padx=20, pady=(0, 9))
        self.quick_toggle = button(
            quick_header, '＋  One-Click IP / Excel', self.toggle_quick, True
        )
        self.quick_toggle.pack(side='left')
        self.updated = label(quick_header, fg=SUBTLE, font=TYPE['small'])
        self.updated.pack(side='right')
        self.quick_header = quick_header
        self.quick = self.section_card(self.body)
        self.quick_open = False
        self.build_quick()

    def build_quick(self):
        from modules.responsive_layout import FlowRow
        app = self.app
        label(self.quick, 'Kiểm tra nhanh IP / danh sách Excel', font=TYPE['section_title']).pack(
            anchor='w', padx=14, pady=(12, 2)
        )
        label(
            self.quick,
            'Dán một hoặc nhiều IP, hoặc chọn tệp Excel. Tác vụ chỉ chạy khi bạn bấm nút kiểm tra.',
            fg=SUBTLE, font=TYPE['small']
        ).pack(anchor='w', padx=14, pady=(0, 8))
        app.quick_ip_text = tk.Text(
            self.quick, height=3, width=1, bg=FIELD, fg=TEXT,
            insertbackground=CYAN, relief='flat', font=('Consolas', 10),
            wrap='word', highlightthickness=1, highlightbackground=BORDER
        )
        app.quick_ip_text.pack(fill='x', padx=14)
        app.quick_excel_path = ''
        app.quick_email_var = tk.BooleanVar(value=True)
        app.quick_authorized_var = tk.BooleanVar(value=False)
        actions = tk.Frame(self.quick, bg=PANEL)
        actions.pack(fill='x', padx=14, pady=9)
        app.quick_run_btn = button(actions, 'CHẠY KIỂM TRA', self.action('_quick_run_all'), True)
        checkbox_options = dict(
            bg=PANEL, fg=TEXT, selectcolor=FIELD, activebackground=PANEL,
            activeforeground=TEXT, highlightthickness=0, font=TYPE['small']
        )
        widgets = [
            button(actions, 'Chọn Excel IP', self.action('_quick_choose_excel')),
            app.quick_run_btn,
            tk.Checkbutton(
                actions, text='Gửi email khi xong', variable=app.quick_email_var,
                **checkbox_options
            ),
            tk.Checkbutton(
                actions, text='Tôi có quyền kiểm tra IP', variable=app.quick_authorized_var,
                **checkbox_options
            ),
        ]
        FlowRow(actions, widgets, row_style='NOC.TFrame')
        app.quick_status_var = tk.StringVar(value='Sẵn sàng · Dán IP hoặc chọn Excel')
        status = label(
            self.quick, textvariable=app.quick_status_var, fg=CYAN,
            wraplength=750, font=TYPE['small']
        )
        status.pack(fill='x', padx=14)
        self.quick.bind(
            '<Configure>', lambda event: status.configure(wraplength=max(220, event.width - 32))
        )
        app.quick_progress = ttk.Progressbar(
            self.quick, mode='determinate', style='NOC.Horizontal.TProgressbar'
        )
        app.quick_progress.pack(fill='x', padx=14, pady=(8, 12))

    def build_tables(self):
        self.tables = tk.Frame(self.body, bg=BG)
        self.tables.pack(fill='both', expand=True, padx=16, pady=(0, 16))
        self.attention_box, self.attention = self.table(
            self.tables, 'Cần chú ý', 'Ưu tiên các mục cần thao tác',
            [('kind', 'Loại', 105), ('target', 'Thiết bị / IP', 145), ('detail', 'Chi tiết', 320)],
            self.action('show_alerts')
        )
        self.events_box, self.events = self.table(
            self.tables, 'Hoạt động gần đây', 'Sự cố và cảnh báo đang mở',
            [('time', 'Thời gian', 145), ('level', 'Mức', 85), ('target', 'Đích', 120), ('detail', 'Nội dung', 320)],
            self.action('show_incident_center')
        )

    def table(self, parent, title, subtitle, columns, command):
        box = self.section_card(parent)
        heading = tk.Frame(box, bg=PANEL)
        heading.pack(fill='x', padx=12, pady=(10, 8))
        text = tk.Frame(heading, bg=PANEL)
        text.pack(side='left', fill='x', expand=True)
        label(text, title, font=TYPE['section_title']).pack(anchor='w')
        label(text, subtitle, fg=SUBTLE, font=TYPE['caption']).pack(anchor='w', pady=(2, 0))
        button(heading, 'Xem tất cả  →', command, quiet=True).pack(side='right')
        grid = tk.Frame(box, bg=PANEL)
        grid.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        grid.columnconfigure(0, weight=1)
        grid.rowconfigure(0, weight=1)
        tree = ttk.Treeview(
            grid, columns=[item[0] for item in columns], show='headings',
            height=7, style='NOC.Treeview'
        )
        for key, column_title, width in columns:
            tree.heading(key, text=column_title)
            tree.column(key, width=width, minwidth=70, stretch=key == 'detail')
        ys = ttk.Scrollbar(
            grid, orient='vertical', command=tree.yview, style='NOC.Vertical.TScrollbar'
        )
        xs = ttk.Scrollbar(
            grid, orient='horizontal', command=tree.xview, style='NOC.Horizontal.TScrollbar'
        )
        tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        tree.grid(row=0, column=0, sticky='nsew')
        ys.grid(row=0, column=1, sticky='ns')
        xs.grid(row=1, column=0, sticky='ew')
        tree.tag_configure('even', background=PANEL)
        tree.tag_configure('odd', background=PANEL2)
        return box, tree

    def toggle_quick(self):
        self.quick_open = not self.quick_open
        if self.quick_open:
            self.quick.pack(fill='x', padx=20, pady=(0, 14), after=self.quick_header)
        else:
            self.quick.pack_forget()
        self.quick_toggle.configure(
            text=('−  ' if self.quick_open else '＋  ') + 'One-Click IP / Excel'
        )

    def draw_hero(self, event):
        c = self.hero
        c.delete('art')
        width = event.width
        # Decorative network pulse; values are not monitoring data.
        for index, color in enumerate((CYAN, INFO, PINK)):
            points = []
            for step in range(19):
                x = 260 + step * max(1, width - 540) / 18
                y = 48 + math.sin(step * .60 + index * .85) * (13 - index * 2)
                points.extend((x, y))
            c.create_line(*points, fill='#20303D', width=8, smooth=True, tags='art')
            c.create_line(*points, fill=color, width=1, smooth=True, tags='art')
            for step in (3, 8, 13, 17):
                x, y = points[step * 2:step * 2 + 2]
                c.create_oval(x - 3, y - 3, x + 3, y + 3, fill=PANEL, outline=color, tags='art')
        c.create_text(
            18, 30, text='NOC COMMAND CENTER', fill=TEXT, anchor='w',
            font=('Segoe UI', 13, 'bold'), tags='art'
        )
        c.create_text(
            18, 56, text='Quan sát sức khỏe mạng và xử lý vấn đề từ một nơi',
            fill=MUTED, anchor='w', font=TYPE['small'], tags='art'
        )
        c.create_line(18, 78, 170, 78, fill=CYAN, width=2, tags='art')

    def resize(self, event):
        width = event.width
        self.canvas.itemconfigure(self.body_window, width=width)
        columns = dashboard_columns(width)
        if columns != self.columns:
            for col in range(5):
                self.metrics.columnconfigure(
                    col, weight=1 if col < columns else 0,
                    uniform='cards' if col < columns else ''
                )
            for index, card in enumerate(self.cards):
                card.grid(
                    row=index // columns, column=index % columns,
                    sticky='nsew', padx=4, pady=4
                )
            self.columns = columns

        # Quick actions: 4 / 2 / 1 columns.
        action_columns = 4 if width >= 1120 else (2 if width >= 760 else 1)
        for col in range(4):
            self.quick_actions_grid.columnconfigure(
                col, weight=1 if col < action_columns else 0,
                uniform='actions' if col < action_columns else ''
            )
        for index, tile in enumerate(self.quick_action_tiles):
            tile.grid(
                row=index // action_columns, column=index % action_columns,
                sticky='nsew', padx=4, pady=4
            )

        wide = width >= 1000
        if wide != self.wide:
            for widget in (self.connection, self.audit, self.attention_box, self.events_box):
                widget.grid_forget()
            for parent in (self.status_row, self.tables):
                parent.columnconfigure(0, weight=1)
                parent.columnconfigure(1, weight=1 if wide else 0)
            self.connection.grid(
                row=0, column=0, sticky='nsew', padx=(0, 4), pady=4
            )
            self.audit.grid(
                row=0 if wide else 1, column=1 if wide else 0,
                sticky='nsew', padx=(4, 0) if wide else (0, 4), pady=4
            )
            self.attention_box.grid(
                row=0, column=0, sticky='nsew', padx=4, pady=4
            )
            self.events_box.grid(
                row=0 if wide else 1, column=1 if wide else 0,
                sticky='nsew', padx=4, pady=4
            )
            self.wide = wide
        status_wrap = max(220, (width // 2 if wide else width) - 80)
        self.audit_label.configure(wraplength=status_wrap)
        self.agent.configure(wraplength=status_wrap)
        self.agent_hint.configure(wraplength=status_wrap)
        self.notice.configure(wraplength=max(250, width - 50))

    def health_state(self, snapshot):
        if snapshot['unavailable']:
            return 'Dữ liệu chưa đầy đủ', WARNING, 'partial'
        if (snapshot.get('incidents') or 0) > 0:
            return 'Có sự cố cần xử lý', RED, 'critical'
        if (snapshot.get('offline') or 0) > 0 or (snapshot.get('alerts') or 0) > 0:
            return 'Cần chú ý', WARNING, 'warning'
        return 'Hoạt động bình thường', GREEN, 'healthy'

    def refresh(self):
        snapshot = collect_snapshot()
        self.snapshot = snapshot
        for key, var in self.values.items():
            var.set('—' if snapshot[key] is None else str(snapshot[key]))

        for tree, rows, empty in (
            (self.attention, snapshot['attention'], 'Không có mục cần chú ý trong dữ liệu hiện tại'),
            (self.events, snapshot['events'], 'Chưa có cảnh báo hoặc sự cố đang mở'),
        ):
            tree.delete(*tree.get_children())
            if snapshot['unavailable']:
                empty = 'Dữ liệu chưa đầy đủ: ' + ', '.join(snapshot['unavailable'])
            if not rows:
                rows = [('—', '—', empty)] if tree is self.attention else [('—', '—', '—', empty)]
            for index, row in enumerate(rows):
                tree.insert('', 'end', values=row, tags=('odd' if index % 2 else 'even',))

        try:
            status, detail, _ = self.app._daily_audit_dashboard_summary()
        except Exception:
            status, detail = 'Chưa sẵn sàng', 'Không đọc được trạng thái Daily Audit'
        self.audit_label.configure(text=status + ' · ' + detail)

        state, heartbeat = heartbeat_status(data_path('agent_status.json'))
        self.agent.configure(text='Agent giám sát nền · ' + state)
        if heartbeat:
            hb_dir = heartbeat.get('data_dir')
            hint = ('Heartbeat của service/agent; độc lập với số Online/Offline lưu trong CSDL.'
                    if not hb_dir else
                    'Heartbeat service/agent · dữ liệu: ' + str(hb_dir))
        else:
            hint = 'Online/Offline ở trên là trạng thái đã lưu trong CSDL; chưa xác nhận agent nền đang chạy.'
        self.agent_hint.configure(text=hint)

        state_text, state_color, _ = self.health_state(snapshot)
        self.health_pill.configure(text='● ' + state_text, fg=state_color)
        self.network_state.configure(text=state_text, fg=state_color)

        total = snapshot.get('total')
        online = snapshot.get('online')
        if total is None:
            summary = 'Không đọc được dữ liệu'
        elif total == 0:
            summary = 'Chưa có thiết bị'
        else:
            summary = f'{round((online or 0) * 100 / total)}% online'
        self.total_health.configure(text=summary)

        unavailable = snapshot['unavailable']
        self.notice.configure(
            text='Chưa đọc được dữ liệu: ' + ', '.join(unavailable)
            if unavailable else
            'Nguồn: cơ sở dữ liệu giám sát · Dashboard tự làm mới mỗi 5 giây'
        )
        self.updated.configure(text='Cập nhật ' + datetime.now().strftime('%H:%M:%S'))
        self.draw_donut()

    def draw_donut(self):
        c = self.donut
        c.delete('all')
        snap = self.snapshot
        total = snap.get('total')
        c.create_oval(12, 12, 90, 90, outline=BORDER_STRONG, width=8)
        start = 90
        if total:
            for key, color in (('online', GREEN), ('offline', RED), ('other', PINK)):
                extent = 360 * (snap[key] or 0) / total
                if extent:
                    c.create_arc(
                        12, 12, 90, 90, start=start, extent=-extent,
                        style='arc', outline=color, width=8
                    )
                start -= extent
        c.create_text(
            51, 45, text='—' if total is None else str(total),
            fill=TEXT, font=('Segoe UI', 17, 'bold')
        )
        c.create_text(51, 65, text='thiết bị', fill=SUBTLE, font=TYPE['caption'])
        self.legend.configure(
            text='Online  ' + str(snap.get('online') if snap.get('online') is not None else '—') +
                 '   ·   Offline  ' + str(snap.get('offline') if snap.get('offline') is not None else '—') +
                 '\nKhác / chưa rõ  ' + str(snap.get('other') if snap.get('other') is not None else '—')
        )

    def poll(self):
        if self.closed:
            return
        self.time_label.configure(text=datetime.now().strftime('%d/%m/%Y · %H:%M:%S'))
        try:
            self.app._quick_poll(schedule=False)
        except Exception:
            pass
        self.tick += 1
        if self.tick % 5 == 0:
            self.refresh()
        self.after_id = self.frame.after(1000, self.poll)

    def destroy(self, event):
        if event.widget is not self.frame:
            return
        self.closed = True
        if self.after_id is not None:
            try:
                self.frame.after_cancel(self.after_id)
            except tk.TclError:
                pass
        self.after_id = None
        for sequence in ('<MouseWheel>', '<Button-4>', '<Button-5>'):
            try:
                self.frame.unbind_class(self.wheel_tag, sequence)
            except tk.TclError:
                pass
