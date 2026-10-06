"""Shared native dark theme for every Tk/ttk application page."""
try:
    from tkinter import ttk
except (ImportError, ModuleNotFoundError):
    ttk = None

from modules.ui_ux_config import PALETTE, TYPE, SIZE

# Conversion is scoped to UI color properties, never database/network values.
BACKGROUND_MAP={
    'white':'surface','#ffffff':'surface','#f3f4f6':'background','#f9fafb':'background',
    '#f8fafc':'field','#f1f5f9':'surface_alt','#e5e7eb':'surface_alt','#e2e8f0':'surface_alt',
    '#d1d5db':'border','#cbd5e1':'border','#111827':'sidebar','#0b1220':'sidebar',
    '#2563eb':'primary','#1d4ed8':'hover','#3b82f6':'primary','#0f766e':'primary',
    '#6b7280':'surface_alt','#4b5563':'surface_alt','#374151':'surface_alt',
    '#dc2626':'danger_bg','#b91c1c':'danger_bg','#16a34a':'success_bg',
    '#15803d':'success_bg','#059669':'success_bg','#047857':'success_bg',
    '#dcfce7':'success_bg','#fee2e2':'danger_bg','#fef3c7':'warning_bg',
    '#dbeafe':'selection','#eff6ff':'surface_alt','#e0f2fe':'surface_alt',
    '#e0e7ff':'selection','#fef2f2':'danger_bg','#f0fdf4':'success_bg',
    '#fffbeb':'warning_bg','#e5e7eb':'surface_alt',
}
FOREGROUND_MAP={
    'black':'text','#000000':'text','#111827':'text','#172033':'text','#1f2937':'text',
    '#334155':'text','#374151':'text','#4b5563':'muted','#6b7280':'muted',
    '#64748b':'muted','#475569':'muted','#9ca3af':'muted','#94a3b8':'muted',
    'white':'text','#ffffff':'text','#e5e7eb':'text','#d1d5db':'text',
    '#2563eb':'accent','#1d4ed8':'accent','#3b82f6':'accent','#93c5fd':'accent',
    '#0f766e':'accent','#16a34a':'success','#15803d':'success','#059669':'success',
    'green':'success','#008000':'success','red':'danger','#dc2626':'danger',
    '#b91c1c':'danger','#d97706':'warning','#f59e0b':'warning','orange':'warning',
    '#7c3aed':'pink','#8b5cf6':'pink',
}


def color_key(value,role):
    if not isinstance(value,str):return None
    return (BACKGROUND_MAP if role=='background' else FOREGROUND_MAP).get(value.lower())


def apply_theme(root):
    """Defaults also cover future modal forms and combobox popup lists."""
    if ttk is None:
        raise RuntimeError("Tkinter is unavailable in this headless environment")
    p=PALETTE
    root.configure(background=p['background'])
    defaults={
        '*Background':p['surface'],'*Foreground':p['text'],'*Font':'{Segoe UI} 10',
        '*activeBackground':p['hover'],'*activeForeground':p['text'],
        '*selectBackground':p['selection'],'*selectForeground':p['text'],
        '*disabledForeground':p['muted'],'*highlightBackground':p['border'],
        '*highlightColor':p['accent'],'*insertBackground':p['accent'],
        '*Entry.Background':p['field'],'*Text.Background':p['field'],
        '*Listbox.Background':p['field'],'*Spinbox.Background':p['field'],
        '*Checkbutton.selectColor':p['field'],'*Radiobutton.selectColor':p['field'],
        '*Menu.Background':p['surface'],'*Menu.Foreground':p['text'],
        '*TCombobox*Listbox.background':p['field'],'*TCombobox*Listbox.foreground':p['text'],
        '*TCombobox*Listbox.selectBackground':p['selection'],
    }
    for pattern,value in defaults.items():root.option_add(pattern,value,80)
    style=ttk.Style(root)
    style.theme_use('clam')
    style.configure('.',background=p['surface'],foreground=p['text'],font=('Segoe UI',10))
    for name,bg in [('TFrame',p['background']),('Card.TFrame',p['surface']),('TLabel',p['background']),('TLabelframe',p['surface']),('TLabelframe.Label',p['surface'])]:
        style.configure(name,background=bg,foreground=p['text'],bordercolor=p['border'])
    style.configure('TButton',background=p['primary'],foreground=p['text'],padding=(12,8),bordercolor=p['border'],focusthickness=1,focuscolor=p['accent'])
    style.map('TButton',background=[('disabled',p['surface_alt']),('active',p['hover'])],foreground=[('disabled',p['muted'])])
    for name in ('TEntry','TCombobox','TSpinbox'):
        style.configure(name,fieldbackground=p['field'],background=p['surface_alt'],foreground=p['text'],insertcolor=p['accent'],bordercolor=p['border'],padding=6,arrowcolor=p['text'])
        style.map(name,fieldbackground=[('disabled',p['surface_alt']),('readonly',p['field'])],foreground=[('disabled',p['muted']),('readonly',p['text'])],selectbackground=[('!disabled',p['selection'])],selectforeground=[('!disabled',p['text'])])
    for name in ('TCheckbutton','TRadiobutton'):
        style.configure(name,background=p['background'],foreground=p['text'],indicatorbackground=p['field'],indicatorforeground=p['accent'],padding=(3,5))
        style.map(name,background=[('active',p['surface_alt'])],foreground=[('disabled',p['muted'])],indicatorbackground=[('selected',p['primary']),('disabled',p['surface_alt'])])
    style.configure('Treeview',background=p['surface'],fieldbackground=p['surface'],foreground=p['text'],rowheight=SIZE['table_row_height'],borderwidth=0,font=TYPE['body'])
    style.configure('Treeview.Heading',background=p['surface_alt'],foreground=p['muted'],relief='flat',padding=(10,10),font=TYPE['body_bold'])
    style.map('Treeview',background=[('selected',p['selection'])],foreground=[('selected',p['text'])])
    style.map('Treeview.Heading',background=[('active',p['hover'])],foreground=[('active',p['text'])])
    style.configure('TNotebook',background=p['background'],bordercolor=p['border'])
    style.configure('TNotebook.Tab',background=p['surface_alt'],foreground=p['muted'],padding=(14,9),font=('Segoe UI',10))
    style.map('TNotebook.Tab',background=[('selected',p['primary']),('active',p['hover'])],foreground=[('selected',p['text']),('active',p['text'])])
    for direction in ('Vertical','Horizontal'):
        style.configure(direction+'.TScrollbar',background=p['border'],troughcolor=p['background'],arrowcolor=p['muted'],bordercolor=p['background'])
        style.map(direction+'.TScrollbar',background=[('active',p['hover'])])
        style.configure(direction+'.TProgressbar',background=p['accent'],troughcolor=p['field'],bordercolor=p['border'],lightcolor=p['accent'],darkcolor=p['accent'])
        style.configure(direction+'.TScale',background=p['surface'],troughcolor=p['field'],bordercolor=p['border'])
    style.configure('TSeparator',background=p['border'])
    style.configure('TPanedwindow',background=p['background'])
    return style
