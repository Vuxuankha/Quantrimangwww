"""Tk UI for the independent IP/Excel workflow. Workers never touch widgets."""
from __future__ import annotations
from modules.ui_theme import PALETTE as UI_COLORS

import json
import tkinter as tk
from dataclasses import asdict
from pathlib import Path
from app_runtime import resource_path
from tkinter import filedialog, messagebox, ttk

from modules.auto_ip import (AutomationEngine, Options, TASK_NAMES, connect, credentials,
                            export_report, load_options, load_targets, parse_excel, parse_text,
                            profiles, run_history, run_steps, save_options, save_profile, save_targets)

BG = UI_COLORS['background']
STATE_TEXT = {'Ready': 'S\u1eb5n s\u00e0ng', 'Starting': '\u0110ang kh\u1edfi t\u1ea1o',
              'Running': '\u0110ang ch\u1ea1y', 'Stopping': '\u0110ang d\u1eebng',
              'Stopped': '\u0110\u00e3 d\u1eebng', 'Completed': '\u0110\u00e3 xong l\u01b0\u1ee3t',
              'Waiting': 'Ch\u1edd l\u01b0\u1ee3t ti\u1ebfp', 'Failed': 'L\u1ed7i', 'Interrupted': 'B\u1ecb gi\u00e1n \u0111o\u1ea1n'}


class AutoIPPage:
    def __init__(self, parent, engine: AutomationEngine, session_user, activity_callback=None):
        self.parent, self.engine, self.user = parent, engine, dict(session_user)
        self.activity = activity_callback or (lambda text: None)
        self.options = load_options()
        self.targets = load_targets()
        self.closed, self.job = False, None
        self.display_run, self.last_row = '', 0
        self.rows = {}
        self.controls = []
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill='both', expand=True, padx=25, pady=(0, 12))
        self.notebook = ttk.Notebook(self.frame)
        self.notebook.pack(fill='both', expand=True)
        self.run_tab = self._scroll_tab('Nh\u1eadp IP / Ch\u1ea1y')
        self.profile_tab = self._scroll_tab('H\u1ed3 s\u01a1 k\u1ebft n\u1ed1i')
        self.history_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.history_tab, text='L\u1ecbch s\u1eed / B\u00e1o c\u00e1o')
        self._build_run()
        self._build_profiles()
        self._build_history()
        self._refresh_profiles()
        self.refresh_history()
        self._poll()

    def _scroll_tab(self, title):
        outer = ttk.Frame(self.notebook)
        self.notebook.add(outer, text=title)
        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0)
        scroll = ttk.Scrollbar(outer, orient='vertical', command=canvas.yview)
        scroll.pack(side='right', fill='y')
        canvas.pack(side='left', fill='both', expand=True)
        canvas.configure(yscrollcommand=scroll.set)
        inside = ttk.Frame(canvas, padding=10)
        window = canvas.create_window((0, 0), window=inside, anchor='nw')
        inside.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>', lambda e: canvas.itemconfigure(window, width=e.width))
        return inside

    def _guard(self, action):
        try:
            action()
        except Exception as exc:
            messagebox.showerror('T\u1ef1 \u0111\u1ed9ng IP/Excel', str(exc), parent=self.frame)

    def _build_run(self):
        f = self.run_tab
        ttk.Label(f, text='Ch\u1ec9 ch\u1ea1y c\u00e1c t\u00e1c v\u1ee5 \u0111\u01b0\u1ee3c ch\u1ecdn. Kh\u00f4ng thay \u0111\u1ed5i/kh\u00f4i ph\u1ee5c c\u1ea5u h\u00ecnh thi\u1ebft b\u1ecb.',
                  wraplength=820, foreground=UI_COLORS['text']).pack(fill='x', pady=(0, 8))
        source = ttk.LabelFrame(f, text='1. Nh\u1eadp IP ho\u1eb7c Excel (.xlsx)', padding=8)
        source.pack(fill='x')
        self.text = tk.Text(source, height=3, width=50, font=('Consolas', 10), wrap='word')
        self.text.pack(fill='x')
        buttons = ttk.Frame(source)
        buttons.pack(fill='x', pady=(6, 0))
        for title, command in [('N\u1ea1p IP', self.import_text), ('Nh\u1eadp Excel', self.import_excel),
                               ('T\u1ea3i Excel m\u1eabu', self.save_template), ('Xem danh s\u00e1ch', self.show_targets)]:
            button = ttk.Button(buttons, text=title, command=lambda fn=command: self._guard(fn))
            button.pack(side='left', padx=(0, 5))
            if command in (self.import_text, self.import_excel):
                self.controls.append(button)
        self.target_status = tk.StringVar(value=f'{len(self.targets)} IP \u0111\u00e3 n\u1ea1p. C\u00f3 th\u1ec3 d\u00e1n IP c\u00e1ch nhau b\u1eb1ng d\u00f2ng, d\u1ea5u ph\u1ea9y ho\u1eb7c d\u1ea5u ch\u1ea5m ph\u1ea9y.')
        ttk.Label(source, textvariable=self.target_status, wraplength=800).pack(fill='x', pady=(5, 0))
        config = ttk.LabelFrame(f, text='2. Ch\u1ecdn t\u00e1c v\u1ee5 / Ch\u00ednh s\u00e1ch', padding=8)
        config.pack(fill='x', pady=8)
        self.vars = {}
        tasks = ['ping', 'tcp', 'snmp', 'resources', 'interfaces', 'topology', 'alerts', 'report', 'backup', 'notifications']
        for index, key in enumerate(tasks):
            var = tk.BooleanVar(value=getattr(self.options, key))
            self.vars[key] = var
            check = ttk.Checkbutton(config, text=TASK_NAMES[key], variable=var)
            check.grid(row=index // 4, column=index % 4, sticky='w', padx=(0, 12), pady=2)
            self.controls.append(check)
        row = ttk.Frame(config)
        row.grid(row=3, column=0, columnspan=4, sticky='ew', pady=(8, 2))
        ttk.Label(row, text='H\u1ed3 s\u01a1 m\u1eb7c \u0111\u1ecbnh:').pack(side='left')
        self.default_profile = tk.StringVar(value=self.options.default_profile)
        self.profile_select = ttk.Combobox(row, textvariable=self.default_profile, state='readonly', width=22)
        self.profile_select.pack(side='left', padx=6)
        self.controls.append(self.profile_select)
        ttk.Button(row, text='C\u1ea5u h\u00ecnh h\u1ed3 s\u01a1', command=lambda: self.notebook.select(1)).pack(side='left')
        ttk.Label(row, text='TCP:').pack(side='left', padx=(16, 3))
        self.ports = tk.StringVar(value=self.options.ports)
        self.port_entry = ttk.Entry(row, textvariable=self.ports, width=18)
        self.port_entry.pack(side='left')
        self.controls.append(self.port_entry)
        row2 = ttk.Frame(config)
        row2.grid(row=4, column=0, columnspan=4, sticky='ew', pady=4)
        for key, title, lo, hi, width in [('workers', 'Worker', 1, 16, 4), ('timeout', 'Timeout (s)', 0.5, 10, 5),
                                         ('retries', 'Retry', 0, 2, 3), ('interval', 'Chu k\u1ef3 (s)', 30, 86400, 6)]:
            var = tk.StringVar(value=str(getattr(self.options, key)))
            self.vars[key] = var
            ttk.Label(row2, text=title).pack(side='left', padx=(0, 4))
            field = ttk.Spinbox(row2, from_=lo, to=hi, textvariable=var, width=width)
            field.pack(side='left', padx=(0, 12))
            self.controls.append(field)
        row3 = ttk.Frame(config)
        row3.grid(row=5, column=0, columnspan=4, sticky='ew')
        for key, title in [('repeat', 'L\u1eb7p \u0111\u1ecbnh k\u1ef3'), ('auto_start', 'T\u1ef1 ch\u1ea1y sau khi n\u1ea1p IP/Excel')]:
            self.vars[key] = tk.BooleanVar(value=getattr(self.options, key))
            field = ttk.Checkbutton(row3, text=title, variable=self.vars[key])
            field.pack(side='left', padx=(0, 14))
            self.controls.append(field)
        ttk.Button(row3, text='L\u01b0u l\u1ef1a ch\u1ecdn', command=lambda: self._guard(self.save_choices)).pack(side='left')
        email_row = ttk.Frame(config)
        email_row.grid(row=6, column=0, columnspan=4, sticky='ew', pady=(6, 2))
        self.vars['email_report_after_run'] = tk.BooleanVar(value=getattr(self.options, 'email_report_after_run', False))
        email_check = ttk.Checkbutton(email_row, text='G\u1eedi Gmail/Email sau khi ch\u1ea1y xong', variable=self.vars['email_report_after_run'])
        email_check.pack(side='left', padx=(0, 10))
        self.controls.append(email_check)
        ttk.Label(email_row, text='Email nh\u1eadn:').pack(side='left')
        self.vars['report_email_to'] = tk.StringVar(value=getattr(self.options, 'report_email_to', ''))
        email_entry = ttk.Entry(email_row, textvariable=self.vars['report_email_to'], width=34)
        email_entry.pack(side='left', padx=6)
        self.controls.append(email_entry)
        ttk.Label(email_row, text='(\u0111\u1ec3 tr\u1ed1ng = Email To trong Notification Center)', foreground=UI_COLORS['muted']).pack(side='left')
        ttk.Label(config, text='SMTP/Gmail d\u00f9ng c\u1ea5u h\u00ecnh trong Notification Center. Khi b\u1eadt g\u1eedi email, app lu\u00f4n t\u1ea1o file Excel v\u00e0 \u0111\u00ednh k\u00e8m sau m\u1ed7i l\u01b0\u1ee3t ch\u1ea1y. Backup/Th\u00f4ng b\u00e1o m\u1eb7c \u0111\u1ecbnh t\u1eaft.',
                  foreground=UI_COLORS['muted'], wraplength=800).grid(row=7, column=0, columnspan=4, sticky='w', pady=(4, 0))
        self.authorized = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text='T\u00f4i c\u00f3 quy\u1ec1n qu\u1ea3n tr\u1ecb c\u00e1c IP n\u00e0y v\u00e0 \u0111\u1ed3ng \u00fd ch\u1ea1y c\u00e1c t\u00e1c v\u1ee5 \u0111\u00e3 ch\u1ecdn.',
                        variable=self.authorized).pack(anchor='w')
        bar = ttk.Frame(f)
        bar.pack(fill='x', pady=8)
        self.run_button = ttk.Button(bar, text='CH\u1ea0Y TO\u00c0N B\u1ed8', command=lambda: self._guard(self.start))
        self.run_button.pack(side='left')
        self.stop_button = ttk.Button(bar, text='D\u1eebng', command=self.engine.stop)
        self.stop_button.pack(side='left', padx=6)
        ttk.Button(bar, text='Xu\u1ea5t k\u1ebft qu\u1ea3', command=lambda: self._guard(self.export_current)).pack(side='left')
        self.progress = ttk.Progressbar(bar, mode='determinate')
        self.progress.pack(side='left', fill='x', expand=True, padx=(12, 0))
        self.status = tk.StringVar(value='S\u1eb5n s\u00e0ng')
        ttk.Label(f, textvariable=self.status, wraplength=820, foreground=UI_COLORS['accent']).pack(fill='x', pady=(0, 5))
        self.table = self._result_table(f)
        self.table.bind('<Double-1>', lambda e: self.show_detail(self.table, self.rows))
        ttk.Label(f, text='OK = xong; WARN = c\u1ea7n xem; SKIP = thi\u1ebfu \u0111i\u1ec1u ki\u1ec7n; ERROR = l\u1ed7i; CANCEL = \u0111\u00e3 d\u1eebng. Nh\u1ea5p \u0111\u00fap \u0111\u1ec3 xem chi ti\u1ebft.',
                  wraplength=820, foreground=UI_COLORS['muted']).pack(fill='x', pady=5)
        ttk.Label(f, text='Lu\u1ed3ng n\u00e0y ti\u1ebfp t\u1ee5c khi chuy\u1ec3n m\u00e0n h\u00ecnh; d\u1eebng khi tho\u00e1t \u1ee9ng d\u1ee5ng. D\u1eef li\u1ec7u thu th\u1eadp \u0111\u01b0\u1ee3c l\u01b0u v\u00e0o NMS chung.',
                  wraplength=820).pack(fill='x')

    def _result_table(self, parent):
        box = ttk.Frame(parent)
        box.pack(fill='both', expand=True)
        table = ttk.Treeview(box, columns=('ip', 'task', 'status', 'message'), show='headings', height=7)
        for col, title, width in [('ip', 'IP', 135), ('task', 'T\u00e1c v\u1ee5', 155), ('status', 'K\u1ebft qu\u1ea3', 80), ('message', 'Chi ti\u1ebft', 470)]:
            table.heading(col, text=title)
            table.column(col, width=width, minwidth=60, stretch=col == 'message')
        vertical = ttk.Scrollbar(box, orient='vertical', command=table.yview)
        horizontal = ttk.Scrollbar(box, orient='horizontal', command=table.xview)
        table.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        box.columnconfigure(0, weight=1)
        box.rowconfigure(0, weight=1)
        table.grid(row=0, column=0, sticky='nsew')
        vertical.grid(row=0, column=1, sticky='ns')
        horizontal.grid(row=1, column=0, sticky='ew')
        for name, color in [('OK', '#166534'), ('WARN', '#92400E'), ('ERROR', '#B91C1C'), ('SKIP', '#64748B'), ('CANCEL', '#64748B')]:
            table.tag_configure(name, foreground=color)
        return table

    def get_options(self):
        data = asdict(self.options)
        for key, var in self.vars.items():
            data[key] = var.get()
        for key in ('workers', 'retries', 'interval'):
            data[key] = int(data[key])
        data['timeout'] = float(data['timeout'])
        data['ports'] = self.ports.get().strip()
        data['default_profile'] = self.default_profile.get()
        return Options(**data).validate()

    def save_choices(self):
        if self.engine.running:
            raise RuntimeError('D\u1eebng lu\u1ed3ng tr\u01b0\u1edbc khi l\u01b0u thay \u0111\u1ed5i.')
        self.options = self.get_options()
        save_options(self.options)
        self.status.set('\u0110\u00e3 l\u01b0u l\u1ef1a ch\u1ecdn; kh\u00f4ng t\u1ef1 kh\u1edfi ch\u1ea1y khi m\u1edf \u1ee9ng d\u1ee5ng.')

    def _accept(self, result):
        if self.engine.running:
            raise RuntimeError('D\u1eebng lu\u1ed3ng hi\u1ec7n t\u1ea1i tr\u01b0\u1edbc khi n\u1ea1p danh s\u00e1ch m\u1edbi.')
        targets, duplicates = result
        options = self.get_options()
        names = {p['name'] for p in profiles()}
        missing = {t.profile or options.default_profile for t in targets} - names
        if missing:
            raise ValueError('T\u1ea1o h\u1ed3 s\u01a1 tr\u01b0\u1edbc: ' + ', '.join(sorted(missing)))
        self.targets = targets
        save_targets(targets)
        self.target_status.set(f'\u0110\u00e3 n\u1ea1p {len(targets)} IP h\u1ee3p l\u1ec7; lo\u1ea1i {duplicates} IP tr\u00f9ng. Danh s\u00e1ch m\u1edbi thay danh s\u00e1ch c\u0169.')
        if options.auto_start:
            if self.authorized.get():
                self.start()
            else:
                messagebox.showinfo('T\u1ef1 \u0111\u1ed9ng IP/Excel', '\u0110\u00e3 n\u1ea1p. X\u00e1c nh\u1eadn quy\u1ec1n qu\u1ea3n tr\u1ecb, sau \u0111\u00f3 b\u1ea5m CH\u1ea0Y TO\u00c0N B\u1ed8.', parent=self.frame)

    def import_text(self):
        self._accept(parse_text(self.text.get('1.0', 'end')))

    def import_excel(self):
        path = filedialog.askopenfilename(parent=self.frame, title='Nh\u1eadp IP t\u1eeb Excel', filetypes=[('Excel', '*.xlsx')])
        if path:
            self._accept(parse_excel(path))

    def save_template(self):
        source = resource_path('templates', 'IP_List_Mau.xlsx')
        path = filedialog.asksaveasfilename(parent=self.frame, initialfile=source.name, defaultextension='.xlsx', filetypes=[('Excel', '*.xlsx')])
        if path:
            Path(path).write_bytes(source.read_bytes())

    def show_targets(self):
        win = tk.Toplevel(self.frame)
        win.title('Danh s\u00e1ch IP \u0111\u00e3 n\u1ea1p')
        win.geometry('720x400')
        text = tk.Text(win, wrap='none')
        text.pack(fill='both', expand=True)
        text.insert('1.0', 'IP\tTen_thiet_bi\tHo_so\n' + '\n'.join(f'{t.ip}\t{t.name}\t{t.profile or self.default_profile.get()}' for t in self.targets))
        text.configure(state='disabled')

    def start(self):
        if not self.targets and self.text.get('1.0', 'end').strip():
            self.targets, _ = parse_text(self.text.get('1.0', 'end'))
        options = self.get_options()
        self.engine.start(self.targets, options, self.user, authorized=self.authorized.get())
        self.options = options
        self.activity(f'T\u1ef1 \u0111\u1ed9ng IP/Excel: b\u1eaft \u0111\u1ea7u {len(self.targets)} IP')

    def _build_profiles(self):
        f = self.profile_tab
        ttk.Label(f, text='C\u1ea5u h\u00ecnh m\u1ed9t l\u1ea7n. Excel ch\u1ec9 ch\u1ee9a t\u00ean h\u1ed3 s\u01a1, kh\u00f4ng ch\u1ee9a m\u1eadt kh\u1ea9u. Ch\u1ec9 Admin \u0111\u01b0\u1ee3c l\u01b0u h\u1ed3 s\u01a1.',
                  wraplength=760).grid(row=0, column=0, columnspan=2, sticky='w', pady=(0, 12))
        self.edit_profile = tk.StringVar(value='Default')
        self.edit_combo = ttk.Combobox(f, textvariable=self.edit_profile, width=36, state='readonly')
        ttk.Label(f, text='H\u1ed3 s\u01a1 \u0111\u00e3 l\u01b0u').grid(row=1, column=0, sticky='w', pady=6)
        self.edit_combo.grid(row=1, column=1, sticky='w')
        self.edit_combo.bind('<<ComboboxSelected>>', lambda e: self._load_profile())
        self.profile_name = tk.StringVar(value='Default')
        self.mode = tk.StringVar(value='assigned')
        self.community = tk.StringVar()
        self.v3 = tk.StringVar()
        self.ssh = tk.StringVar()
        self.snmp_port = tk.StringVar(value='161')
        for row, label, var, kind in [(2, 'T\u00ean h\u1ed3 s\u01a1 (t\u00ean m\u1edbi = t\u1ea1o m\u1edbi)', self.profile_name, 'entry'),
                                      (3, 'SNMP mode', self.mode, 'mode'),
                                      (4, 'Community v2c (\u0111\u1ec3 tr\u1ed1ng = gi\u1eef c\u0169)', self.community, 'secret'),
                                      (5, 'Credential SNMPv3', self.v3, 'v3'),
                                      (6, 'SNMP port v2c', self.snmp_port, 'entry'),
                                      (7, 'Credential SSH (ch\u1ec9 khi backup)', self.ssh, 'ssh')]:
            ttk.Label(f, text=label).grid(row=row, column=0, sticky='w', pady=8, padx=(0, 16))
            if kind in ('mode', 'v3', 'ssh'):
                widget = ttk.Combobox(f, textvariable=var, width=36, state='readonly')
                if kind == 'mode':
                    widget['values'] = ('assigned', 'off', 'v2c', 'v3')
                else:
                    setattr(self, kind + '_combo', widget)
            else:
                widget = ttk.Entry(f, textvariable=var, width=38, show='*' if kind == 'secret' else '')
            widget.grid(row=row, column=1, sticky='w')
        bar = ttk.Frame(f)
        bar.grid(row=8, column=0, columnspan=2, sticky='w', pady=12)
        self.save_profile_button = ttk.Button(bar, text='L\u01b0u h\u1ed3 s\u01a1', command=lambda: self._guard(self._save_profile))
        self.save_profile_button.pack(side='left')
        if self.user.get('role') != 'Admin':
            self.save_profile_button.state(['disabled'])
        ttk.Button(bar, text='N\u1ea1p l\u1ea1i danh s\u00e1ch Credential', command=lambda: self._guard(self._refresh_profiles)).pack(side='left', padx=8)
        notes = ('assigned: d\u00f9ng SNMPv3 \u0111\u00e3 g\u00e1n cho thi\u1ebft b\u1ecb; n\u1ebfu ch\u01b0a c\u00f3 th\u00ec d\u00f9ng SNMP profile v2c \u0111\u00e3 l\u01b0u. Kh\u00f4ng t\u1ef1 th\u1eed m\u1eadt kh\u1ea9u.\n\n'
                 'off: kh\u00f4ng truy c\u1eadp SNMP. v2c: d\u00f9ng Community m\u00e3 h\u00f3a. v3: d\u00f9ng Credential trong m\u1ee5c H\u1ec6 TH\u1ed0NG > Credential SNMPv3 (k\u1ec3 c\u1ea3 port/context c\u1ee7a Credential).\n\n'
                 'SSH: ch\u1ecdn Credential \u0111\u00e3 l\u01b0u trong Qu\u1ea3n l\u00fd Credential, ho\u1eb7c \u0111\u1ec3 tr\u1ed1ng \u0111\u1ec3 d\u00f9ng g\u00e1n SSH hi\u1ec7n c\u00f3. Backup y\u00eau c\u1ea7u host key \u0111\u00e3 tin c\u1eady trong ~/.ssh/known_hosts ho\u1eb7c database/known_hosts.\n\n'
                 'Kh\u00f4ng s\u1eeda h\u1ed3 s\u01a1/driver trong khi lu\u1ed3ng \u0111ang ch\u1ea1y. Gi\u1eef c\u00f9ng nhau file database v\u00e0 database/.credential.key khi sao l\u01b0u/chuy\u1ec3n m\u00e1y.')
        ttk.Label(f, text=notes, wraplength=760, justify='left').grid(row=9, column=0, columnspan=2, sticky='w')
        f.columnconfigure(1, weight=1)

    def _refresh_profiles(self):
        self.profile_rows = {p['name']: p for p in profiles()}
        names = list(self.profile_rows)
        self.profile_select['values'] = names
        self.edit_combo['values'] = names
        if self.default_profile.get() not in names:
            self.default_profile.set('Default')
        self.v3_map = {'': None, **{f"{r['id']} | {r['name']}": r['id'] for r in credentials('v3')}}
        self.ssh_map = {'': None, **{f"{r['id']} | {r['name']}": r['id'] for r in credentials('ssh')}}
        self.v3_combo['values'] = list(self.v3_map)
        self.ssh_combo['values'] = list(self.ssh_map)
        self._load_profile()

    def _load_profile(self):
        row = self.profile_rows.get(self.edit_profile.get())
        if not row:
            return
        self.profile_name.set(row['name'])
        self.mode.set(row['mode'])
        self.community.set('')
        self.snmp_port.set(str(row['port']))
        for var, mapping, key in [(self.v3, self.v3_map, 'snmpv3_id'), (self.ssh, self.ssh_map, 'ssh_id')]:
            var.set(next((label for label, value in mapping.items() if value == row[key]), ''))

    def _save_profile(self):
        if self.engine.running:
            raise RuntimeError('D\u1eebng lu\u1ed3ng tr\u01b0\u1edbc khi s\u1eeda h\u1ed3 s\u01a1.')
        save_profile(self.profile_name.get(), self.mode.get(), self.community.get(), self.v3_map.get(self.v3.get()),
                     self.ssh_map.get(self.ssh.get()), int(self.snmp_port.get()), role=self.user.get('role'))
        self.edit_profile.set(self.profile_name.get().strip())
        self._refresh_profiles()
        messagebox.showinfo('H\u1ed3 s\u01a1', '\u0110\u00e3 l\u01b0u. Ch\u1ecdn h\u1ed3 s\u01a1 n\u00e0y \u1edf tab Nh\u1eadp IP/Ch\u1ea1y ho\u1eb7c c\u1ed9t Ho_so trong Excel.', parent=self.frame)

    def _build_history(self):
        top = ttk.Frame(self.history_tab, padding=8)
        top.pack(fill='x')
        self.history_choice = tk.StringVar()
        self.history_combo = ttk.Combobox(top, textvariable=self.history_choice, state='readonly', width=56)
        self.history_combo.pack(side='left', fill='x', expand=True)
        self.history_combo.bind('<<ComboboxSelected>>', lambda e: self._guard(self.load_history))
        ttk.Button(top, text='L\u00e0m m\u1edbi', command=lambda: self._guard(self.refresh_history)).pack(side='left', padx=6)
        ttk.Button(top, text='Xu\u1ea5t Excel', command=lambda: self._guard(self.export_history)).pack(side='left')
        self.history_table = self._result_table(self.history_tab)
        self.history_rows = {}
        self.history_table.bind('<Double-1>', lambda e: self.show_detail(self.history_table, self.history_rows))
        ttk.Label(self.history_tab, text='Hi\u1ec3n th\u1ecb t\u1ed1i \u0111a 5.000 d\u00f2ng/l\u01b0\u1ee3t. Xu\u1ea5t Excel \u0111\u1ec3 xem \u0111\u1ea7y \u0111\u1ee7.', padding=8).pack(anchor='w')

    def refresh_history(self):
        entries = run_history()
        self.history_map = {f"{r['started_at']} | {STATE_TEXT.get(r['status'], r['status'])} | {r['total']} IP | {r['id'][:8]}": r['id'] for r in entries}
        self.history_combo['values'] = list(self.history_map)
        if self.history_choice.get() not in self.history_map:
            self.history_choice.set(next(iter(self.history_map), ''))
        self.load_history()

    def load_history(self):
        self.history_table.delete(*self.history_table.get_children())
        self.history_rows = {}
        run_id = self.history_map.get(self.history_choice.get())
        if run_id:
            for row in run_steps(run_id, limit=5000):
                self._insert(self.history_table, row)
                self.history_rows[str(row['id'])] = row

    def _export(self, run_id):
        if not run_id:
            raise ValueError('Ch\u01b0a c\u00f3 l\u01b0\u1ee3t ch\u1ea1y.')
        path = filedialog.asksaveasfilename(parent=self.frame, initialfile='Auto_IP_' + run_id[:8] + '.xlsx',
                                          defaultextension='.xlsx', filetypes=[('Excel', '*.xlsx')])
        if path:
            export_report(run_id, path)
            messagebox.showinfo('B\u00e1o c\u00e1o', '\u0110\u00e3 l\u01b0u: ' + path, parent=self.frame)

    def export_current(self):
        self._export(self.engine.snapshot()['run_id'])

    def export_history(self):
        self._export(self.history_map.get(self.history_choice.get()))

    @staticmethod
    def _insert(table, row):
        table.insert('', 'end', iid=str(row['id']), values=(row['ip'] or '(To\u00e0n \u0111\u1ee3t)', TASK_NAMES.get(row['task'], row['task']),
                     row['status'], row['message']), tags=(row['status'],))

    def show_detail(self, table, rows):
        selected = table.selection()
        if not selected:
            return
        row = rows.get(selected[0])
        if not row:
            return
        win = tk.Toplevel(self.frame)
        win.title(f"{row['ip']} - {TASK_NAMES.get(row['task'], row['task'])}")
        win.geometry('850x500')
        text = tk.Text(win, wrap='word')
        scroll = ttk.Scrollbar(win, orient='vertical', command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        text.pack(fill='both', expand=True)
        text.insert('1.0', row['status'] + '\n' + row['message'] + '\n\n' + json.dumps(json.loads(row['data']), ensure_ascii=False, indent=2))
        text.configure(state='disabled')

    def _poll(self):
        if self.closed:
            return
        try:
            snap = self.engine.snapshot()
            running = snap['running']
            self.run_button.state(['disabled' if running else '!disabled'])
            self.stop_button.state(['!disabled' if running else 'disabled'])
            for widget in self.controls:
                widget.state(['disabled' if running else '!disabled'])
                if not running and isinstance(widget, ttk.Combobox):
                    widget.configure(state='readonly')
            if self.user.get('role') == 'Admin':
                self.save_profile_button.state(['disabled' if running else '!disabled'])
            self.progress.configure(maximum=max(1, snap['total']), value=snap['done'])
            status = STATE_TEXT.get(snap['status'], snap['status'])
            message = f"{status} | L\u01b0\u1ee3t {snap['cycle']} | {snap['done']}/{snap['total']} IP. {snap['message']}"
            if snap.get('report_path'):
                message += '\nB\u00e1o c\u00e1o: ' + snap['report_path']
            self.status.set(message)
            if snap['run_id'] != self.display_run:
                self.display_run, self.last_row, self.rows = snap['run_id'], 0, {}
                self.table.delete(*self.table.get_children())
            if self.display_run:
                for row in run_steps(self.display_run, self.last_row, 500):
                    self.last_row = row['id']
                    self.rows[str(row['id'])] = row
                    self._insert(self.table, row)
                children = self.table.get_children()
                for old in children[:-5000]:
                    self.table.delete(old)
                    self.rows.pop(old, None)
        except (tk.TclError, RuntimeError):
            if self.closed:
                return
        except Exception as exc:
            self.status.set('L\u1ed7i \u0111\u1ecdc ti\u1ebfn \u0111\u1ed9: ' + str(exc))
        self.job = self.parent.after(600, self._poll)

    def destroy(self):
        # Navigating away detaches only the UI; engine lifetime belongs to the app.
        self.closed = True
        if self.job:
            try:
                self.parent.after_cancel(self.job)
            except tk.TclError:
                pass
            self.job = None
        if self.frame.winfo_exists():
            self.frame.destroy()
