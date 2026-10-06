"""Account forms with a scrollable body and an always-visible action footer."""
import logging
import tkinter as tk
from tkinter import ttk, messagebox

from modules import accounts
from modules.ui_theme import PALETTE
from modules.responsive_layout import FlowRow, ScrollablePanel


class AccountHeader:
    def __init__(self, parent, session, commands):
        self.session = session
        self.frame = tk.Frame(parent, bg=PALETTE['surface'])
        self.avatar = tk.Canvas(self.frame, width=36, height=36, bg=PALETTE['surface'], highlightthickness=0, cursor='hand2')
        self.avatar.pack(side='left', padx=(4, 6), pady=5)
        self.avatar.create_oval(2, 2, 34, 34, fill=PALETTE['primary'], outline=PALETTE['accent'])
        self.initials = self.avatar.create_text(18, 18, text='', fill=PALETTE['text'], font=('Segoe UI', 10, 'bold'))
        self.button = tk.Menubutton(self.frame, bg=PALETTE['surface'], fg=PALETTE['text'], activebackground=PALETTE['hover'],
                                    activeforeground=PALETTE['text'], relief='flat', padx=8, pady=7, cursor='hand2', takefocus=True)
        self.button.pack(side='left', padx=(0, 10))
        self.menu = tk.Menu(self.button, tearoff=False, bg=PALETTE['surface'], fg=PALETTE['text'],
                            activebackground=PALETTE['hover'], activeforeground=PALETTE['text'])
        for label, command in commands:
            if label == 'Đăng xuất':
                self.menu.add_separator()
            self.menu.add_command(label=label, command=command)
        self.button.configure(menu=self.menu)
        self.avatar.bind('<Button-1>', self.popup)
        self.render()

    def render(self, compact=False):
        username = self.session.get('username', 'Admin')
        role = self.session.get('role', 'Viewer')
        self.avatar.itemconfigure(self.initials, text=username[:2].upper())
        label = role if compact else f'{username[:24]} · {role}'
        self.button.configure(text=f'{label}  ▾')

    def popup(self, event):
        try:
            self.menu.tk_popup(self.frame.winfo_rootx(), self.frame.winfo_rooty()+self.frame.winfo_height())
        finally:
            self.menu.grab_release()


class AccountDialog:
    def __init__(self, parent, title, action=None, button_text='Lưu'):
        self.action = action
        self.window = tk.Toplevel(parent)
        self.window.title(title)
        width = min(500, max(360, self.window.winfo_screenwidth()-60))
        height = min(530, max(300, self.window.winfo_screenheight()-100))
        self.window.geometry(f'{width}x{height}')
        self.window.minsize(360, 300)
        self.window.transient(parent.winfo_toplevel())
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(1, weight=1)
        heading = ttk.Label(self.window, text=title, font=('Segoe UI', 17, 'bold'), padding=(18, 14), wraplength=width-36)
        heading.grid(row=0, column=0, sticky='ew')
        middle = ttk.Frame(self.window)
        middle.grid(row=1, column=0, sticky='nsew', padx=6)
        self.panel = ScrollablePanel(middle)
        self.body = self.panel.body
        self.body.columnconfigure(0, weight=1)
        self.fields = {}
        self.status = tk.StringVar()
        status_label = ttk.Label(self.window, textvariable=self.status, foreground=PALETTE['danger'], padding=(18, 4), wraplength=450)
        status_label.grid(row=2, column=0, sticky='ew')
        def resize(event):
            if event.widget is self.window:
                heading.configure(wraplength=max(250, event.width-36))
                status_label.configure(wraplength=max(250, event.width-36))
        self.window.bind('<Configure>', resize)
        footer = ttk.Frame(self.window, padding=(18, 12))
        footer.grid(row=3, column=0, sticky='ew')
        ttk.Button(footer, text='Đóng' if action is None else 'Hủy', command=self.window.destroy).pack(side='right')
        if action is not None:
            self.save_button = ttk.Button(footer, text=button_text, command=self.save)
            self.save_button.pack(side='right', padx=(0, 8))
        self.window.bind('<Escape>', lambda e: self.window.destroy())
        self.window.bind('<Control-Return>', lambda e: self.save() if self.action else None)
        self.window.grab_set()
        self.saving = False

    def field(self, key, label, value='', password=False, choices=None):
        row = ttk.Frame(self.body, padding=(4, 6))
        row.pack(fill='x')
        ttk.Label(row, text=label).pack(anchor='w', pady=(0, 4))
        var = tk.StringVar(value=value)
        if choices:
            widget = ttk.Combobox(row, textvariable=var, values=choices, state='readonly')
        else:
            widget = ttk.Entry(row, textvariable=var, show='•' if password else '')
        widget.pack(fill='x')
        if not self.fields:
            widget.focus_set()
        self.fields[key] = var
        return widget

    def note(self, text):
        label = ttk.Label(self.body, text=text, foreground=PALETTE['muted'], wraplength=400, padding=(4, 8), justify='left')
        label.pack(fill='x')
        self.body.bind('<Configure>', lambda e: label.configure(wraplength=max(240, e.width-8)), add='+')

    def save(self):
        if self.saving:
            return
        self.saving = True
        self.save_button.configure(state='disabled')
        try:
            self.action({key: var.get() for key, var in self.fields.items()})
        except ValueError as exc:
            self.status.set(str(exc))
        except Exception:
            logging.getLogger(__name__).exception('Account operation failed')
            self.status.set('Không thể lưu. Hãy thử lại; chi tiết đã được ghi vào nhật ký lỗi.')
        else:
            self.window.destroy()
        finally:
            self.saving = False
            if self.window.winfo_exists():
                self.save_button.configure(state='normal')


def password_dialog(parent, session, on_saved=None, target=None):
    def save(fields):
        if fields['password'] != fields['confirm']:
            raise ValueError('Mật khẩu xác nhận không khớp.')
        if target is None:
            accounts.change_password(session, fields['current'], fields['password'], fields['confirm'])
        else:
            accounts.reset_password(session, target['id'], fields['password'])
        if on_saved:
            on_saved()
    title = 'Đổi mật khẩu' if target is None else f'Đặt lại mật khẩu: {target["username"]}'
    dialog = AccountDialog(parent, title, save)
    if target is None:
        dialog.field('current', 'Mật khẩu hiện tại', password=True)
    dialog.field('password', 'Mật khẩu mới', password=True)
    dialog.field('confirm', 'Nhập lại mật khẩu mới', password=True)
    dialog.note('Mật khẩu có từ 8 đến 256 ký tự. Ctrl+Enter để lưu.')
    return dialog


def profile_dialog(parent, session, on_password, on_setup=None):
    profile = accounts.get_profile(session)
    dialog = AccountDialog(parent, 'Hồ sơ cá nhân')
    if profile.get('bootstrap'):
        dialog.note('Bạn đang ở phiên thiết lập ban đầu. Tạo tài khoản Admin để có hồ sơ và mật khẩu đăng nhập riêng.')
        if on_setup:
            def setup():
                dialog.window.destroy()
                on_setup()
            ttk.Button(dialog.body, text='Tạo tài khoản Admin', command=setup).pack(fill='x', pady=10)
    else:
        for label, key in [('Tài khoản', 'username'), ('Vai trò', 'role'), ('Ngày tạo', 'created_at'), ('Cập nhật gần nhất', 'updated_at')]:
            ttk.Label(dialog.body, text=label, foreground=PALETTE['muted'], padding=(4, 6)).pack(anchor='w')
            ttk.Label(dialog.body, text=profile[key] or '—', padding=(4, 0), wraplength=320).pack(anchor='w')
        def change():
            dialog.window.destroy()
            on_password()
        ttk.Button(dialog.body, text='Đổi mật khẩu', command=change).pack(fill='x', pady=(20, 0))
    return dialog


class AccountManagementPage:
    def __init__(self, parent, activity_callback=None, session_user=None, on_session_update=None):
        self.parent = parent
        self.session = session_user or {}
        self.on_session_update = on_session_update or (lambda user: None)
        self.rows = {}
        self.query = tk.StringVar()
        bar = ttk.Frame(parent, padding=(20, 4))
        bar.pack(fill='x')
        buttons = [ttk.Button(bar, text=text, command=command) for text, command in (
            ('+ Thêm tài khoản', self.add), ('Sửa / Phân quyền', self.edit),
            ('Đặt lại mật khẩu', self.password), ('Xóa tài khoản', self.delete), ('Làm mới', self.refresh))]
        self.toolbar = FlowRow(bar, buttons, row_style='TFrame')
        search = ttk.Frame(parent, padding=(25, 8))
        search.pack(fill='x')
        ttk.Label(search, text='Tìm tài khoản').pack(side='left', padx=(0, 10))
        ttk.Entry(search, textvariable=self.query).pack(side='left', fill='x', expand=True)
        self.summary = tk.StringVar()
        ttk.Label(parent, textvariable=self.summary, foreground=PALETTE['muted'], padding=(25, 4)).pack(anchor='w')
        box = ttk.Frame(parent, padding=(25, 8))
        box.pack(fill='both', expand=True)
        box.columnconfigure(0, weight=1)
        box.rowconfigure(0, weight=1)
        self.t = ttk.Treeview(box, columns=('user', 'role', 'enabled', 'created', 'updated'), show='headings', selectmode='browse')
        for col, title, width in [('user', 'Tài khoản', 190), ('role', 'Vai trò', 110), ('enabled', 'Trạng thái', 130), ('created', 'Ngày tạo', 165), ('updated', 'Cập nhật', 165)]:
            self.t.heading(col, text=title)
            self.t.column(col, width=width, minwidth=90, stretch=True)
        self.t.grid(row=0, column=0, sticky='nsew')
        ys = ttk.Scrollbar(box, orient='vertical', command=self.t.yview)
        xs = ttk.Scrollbar(box, orient='horizontal', command=self.t.xview)
        ys.grid(row=0, column=1, sticky='ns')
        xs.grid(row=1, column=0, sticky='ew')
        self.t.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.t.bind('<Double-1>', lambda e: self.edit())
        self.query.trace_add('write', lambda *args: self.render())
        hint = ttk.Label(parent, text='Admin: quản trị • Analyst: phân tích an ninh • Operator: kỹ thuật viên vận hành • Viewer: xem giám sát.\nKhông thể xóa, khóa hoặc hạ quyền tài khoản đang đăng nhập; luôn giữ ít nhất một Admin hoạt động.',
                         foreground=PALETTE['muted'], padding=(25, 10), wraplength=750, justify='left')
        hint.pack(fill='x')
        binding=parent.bind('<Configure>', lambda e: hint.configure(wraplength=max(250, e.width-50)) if e.widget is parent and hint.winfo_exists() else None, add='+')
        def detach(event):
            if event.widget is hint:
                try:
                    parent.unbind('<Configure>',binding)
                except tk.TclError:
                    pass
        hint.bind('<Destroy>',detach,add='+')
        self.refresh()

    def refresh(self):
        try:
            rows = accounts.list_users(self.session)
        except ValueError as exc:
            self.rows = {}
            self.summary.set(str(exc))
        else:
            self.rows = {row['id']: row for row in rows}
            self.summary.set(f'{len(rows)} tài khoản • {sum(bool(r["enabled"]) for r in rows)} đang hoạt động')
        self.render()

    def render(self):
        selected = self.t.selection()
        self.t.delete(*self.t.get_children())
        query = self.query.get().casefold().strip()
        for row in self.rows.values():
            if query and query not in (row['username'] + ' ' + row['role']).casefold():
                continue
            self.t.insert('', 'end', iid=str(row['id']), values=(row['username'], row['role'], 'Hoạt động' if row['enabled'] else 'Đã khóa', row['created_at'], row['updated_at']))
        if selected and self.t.exists(selected[0]):
            self.t.selection_set(selected[0])

    def selected(self):
        selection = self.t.selection()
        if not selection:
            messagebox.showinfo('Quản lý tài khoản', 'Chọn một tài khoản trong danh sách.', parent=self.parent)
            return None
        return self.rows.get(int(selection[0]))

    def editor(self, user=None):
        first = self.session.get('bootstrap', False)
        def save(fields):
            enabled = dialog.enabled.get()
            if user:
                result = accounts.update_user(self.session, user['id'], fields['username'], fields['role'], enabled)
            else:
                if fields['password'] != fields['confirm']:
                    raise ValueError('Mật khẩu xác nhận không khớp.')
                result = accounts.create_user(self.session, fields['username'], fields['password'], fields['role'], enabled)
            if first or result['id'] == self.session.get('id'):
                self.session.clear()
                self.session.update(result)
                self.on_session_update(result)
            self.refresh()
        dialog = AccountDialog(self.parent, 'Sửa tài khoản' if user else 'Thêm tài khoản', save)
        dialog.field('username', 'Tên đăng nhập', user['username'] if user else '')
        if not user:
            dialog.field('password', 'Mật khẩu', password=True)
            dialog.field('confirm', 'Nhập lại mật khẩu', password=True)
        role_widget = dialog.field('role', 'Vai trò', user['role'] if user else ('Admin' if first else 'Operator'), choices=accounts.ROLES)
        dialog.enabled = tk.BooleanVar(value=bool(user['enabled']) if user else True)
        enabled_widget = ttk.Checkbutton(dialog.body, text='Tài khoản hoạt động', variable=dialog.enabled)
        enabled_widget.pack(anchor='w', padx=4, pady=10)
        if first or (user and user['id'] == self.session.get('id')):
            role_widget.configure(state='disabled')
            enabled_widget.configure(state='disabled')
        dialog.note('Admin: toàn quyền quản trị.\nAnalyst: phân tích an ninh/SOC.\nOperator: kỹ thuật viên vận hành / giám sát.\nViewer: xem các màn hình giám sát.' + ('\nTài khoản đầu tiên sẽ là Admin đang hoạt động.' if first else ''))
        return dialog

    def add(self):
        return self.editor()

    def edit(self):
        user = self.selected()
        if user:
            return self.editor(user)

    def password(self):
        user = self.selected()
        if not user:
            return
        own = user['id'] == self.session.get('id')
        return password_dialog(self.parent, self.session, on_saved=self.refresh, target=None if own else user)

    def delete(self):
        user = self.selected()
        if not user:
            return
        if not messagebox.askyesno('Xóa tài khoản', f'Xóa tài khoản “{user["username"]}”?', parent=self.parent):
            return
        try:
            accounts.delete_user(self.session, user['id'])
        except ValueError as exc:
            messagebox.showwarning('Quản lý tài khoản', str(exc), parent=self.parent)
        except Exception:
            logging.getLogger(__name__).exception('Account delete failed')
            messagebox.showerror('Quản lý tài khoản', 'Không thể xóa tài khoản. Hãy thử lại.', parent=self.parent)
        self.refresh()
