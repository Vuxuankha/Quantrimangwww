"""Central UI/UX design tokens and layout rules for NetworkAutomation.

This module is intentionally logic-free.  Pages can consume these tokens gradually
without changing networking, database, monitoring, SSH, or automation behavior.
"""

APP_NAME = "Network Automation"

# ---------------------------------------------------------------------------
# COLOR SYSTEM — dark NOC workspace
# ---------------------------------------------------------------------------
PALETTE = {
    "background": "#0B1118",
    "sidebar": "#0F1722",
    "surface": "#151F2B",
    "surface_alt": "#1B2938",
    "surface_hover": "#203246",
    "field": "#101A25",
    "border": "#2B3B4E",
    "border_strong": "#3A5068",
    "text": "#EAF2F8",
    "muted": "#9FB0C2",
    "subtle": "#73869A",
    "accent": "#49DCD7",
    "primary": "#215E6C",
    "hover": "#2B7282",
    "selection": "#314B68",
    "success": "#5FE0AA",
    "warning": "#F6C768",
    "danger": "#FF7E95",
    "info": "#72B8FF",
    "pink": "#DE82C3",
    "success_bg": "#173D34",
    "warning_bg": "#4B3F25",
    "danger_bg": "#4E2634",
    "info_bg": "#1B3652",
}

# ---------------------------------------------------------------------------
# TYPOGRAPHY
# ---------------------------------------------------------------------------
FONT_FAMILY = "Segoe UI"
TYPE = {
    "display": (FONT_FAMILY, 24, "bold"),
    "page_title": (FONT_FAMILY, 18, "bold"),
    "section_title": (FONT_FAMILY, 12, "bold"),
    "body": (FONT_FAMILY, 10),
    "body_bold": (FONT_FAMILY, 10, "bold"),
    "small": (FONT_FAMILY, 9),
    "small_bold": (FONT_FAMILY, 9, "bold"),
    "caption": (FONT_FAMILY, 8),
    "metric": (FONT_FAMILY, 22, "bold"),
}

# ---------------------------------------------------------------------------
# SPACING / SIZING
# ---------------------------------------------------------------------------
SPACE = {"xs": 4, "sm": 8, "md": 12, "lg": 16, "xl": 24, "2xl": 32}
SIZE = {
    "topbar_height": 52,
    "sidebar_width": 248,
    "sidebar_compact_width": 72,
    "page_padding": 20,
    "card_padding": 16,
    "control_height": 34,
    "table_row_height": 34,
    "touch_target": 36,
}

# Tkinter widgets do not support true radius everywhere; kept for future custom
# canvas widgets or migration to a richer desktop UI toolkit.
RADIUS = {"sm": 6, "md": 8, "lg": 12}

# ---------------------------------------------------------------------------
# RESPONSIVE RULES
# ---------------------------------------------------------------------------
BREAKPOINTS = {
    "compact": 900,       # hide sidebar by default; single-column forms
    "medium": 1150,       # sidebar can auto-collapse
    "wide": 1440,         # 4-up KPI layouts / denser monitoring views
}

LAYOUT = {
    "form_two_column_min": 760,
    "kpi_four_column_min": 1260,
    "kpi_three_column_min": 980,
    "table_min_height": 280,
    "content_max_width": 1680,
}

# ---------------------------------------------------------------------------
# SEMANTIC STATUS SYSTEM
# ---------------------------------------------------------------------------
STATUS = {
    "healthy": {"fg": PALETTE["success"], "bg": PALETTE["success_bg"], "label": "Bình thường"},
    "warning": {"fg": PALETTE["warning"], "bg": PALETTE["warning_bg"], "label": "Cảnh báo"},
    "critical": {"fg": PALETTE["danger"], "bg": PALETTE["danger_bg"], "label": "Nghiêm trọng"},
    "info": {"fg": PALETTE["info"], "bg": PALETTE["info_bg"], "label": "Thông tin"},
    "offline": {"fg": PALETTE["muted"], "bg": PALETTE["surface_alt"], "label": "Offline"},
}

# ---------------------------------------------------------------------------
# PAGE PATTERNS
# ---------------------------------------------------------------------------
PAGE_PATTERNS = {
    "dashboard": ["page_header", "kpi_cards", "attention_queue", "recent_events"],
    "list": ["page_header", "filter_bar", "summary", "data_table", "row_actions"],
    "form": ["page_header", "section_cards", "adaptive_form", "sticky_actions"],
    "monitor": ["page_header", "health_summary", "filters", "live_table", "details_panel"],
    "automation": ["page_header", "run_controls", "progress", "results", "history"],
}

# Consistent action priority.  Pages should expose no more than one primary
# action per local context.
ACTION_HIERARCHY = {
    "primary": ["Chạy", "Quét", "Thêm", "Lưu", "Kết nối"],
    "secondary": ["Làm mới", "Xuất Excel", "Xem chi tiết", "Sửa"],
    "danger": ["Xóa", "Dừng", "Ngắt kết nối"],
}

# UX copy rules for async / network actions.
FEEDBACK = {
    "loading": "Đang xử lý…",
    "empty": "Chưa có dữ liệu phù hợp.",
    "error": "Không thể hoàn tất thao tác. Kiểm tra kết nối hoặc cấu hình và thử lại.",
    "saved": "Đã lưu thay đổi.",
    "cancelled": "Đã hủy thao tác.",
}
