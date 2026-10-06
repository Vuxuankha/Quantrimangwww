"""Scrollable add/edit device form with a footer outside the scrolling area."""
import ipaddress
import logging
import tkinter as tk
from tkinter import ttk,messagebox
from modules.responsive_layout import ScrollablePanel
from modules.ui_theme import PALETTE

STATUSES=('Online','Offline','Unknown')


def submit_device(values,persist):
    """Validate before touching the existing device manager/database."""
    fields={key:str(values.get(key) or '').strip() for key in ('ip','hostname','mac','status')}
    if not fields['ip']:raise ValueError('Vui lòng nhập địa chỉ IP.')
    try:ipaddress.ip_address(fields['ip'])
    except ValueError:raise ValueError('Địa chỉ IP không hợp lệ.') from None
    if fields['status'] not in STATUSES:raise ValueError('Chọn trạng thái thiết bị hợp lệ.')
    result=persist(**fields)
    if not isinstance(result,dict):raise RuntimeError('Không nhận được kết quả lưu thiết bị.')
    return result,fields


class DeviceEditor:
    def __init__(self,root,persist,on_saved,device=None):
        self.root=root;self.persist=persist;self.on_saved=on_saved;self.saving=False
        self.window=tk.Toplevel(root);self.window.title('Sửa thiết bị' if device is not None else 'Thêm thiết bị')
        self.window.transient(root);self.window.resizable(True,True);self.window.minsize(380,300)
        width=min(560,max(380,self.window.winfo_screenwidth()-60))
        height=min(580,max(300,self.window.winfo_screenheight()-120))
        self.window.geometry(f'{width}x{height}')
        self.window.columnconfigure(0,weight=1);self.window.rowconfigure(1,weight=1)
        heading=ttk.Frame(self.window,padding=(18,14));heading.grid(row=0,column=0,sticky='ew')
        title=ttk.Label(heading,text='Sửa thiết bị' if device is not None else 'Thêm thiết bị mới',font=('Segoe UI',18,'bold'),wraplength=500)
        title.pack(anchor='w')
        holder=ttk.Frame(self.window);holder.grid(row=1,column=0,sticky='nsew')
        self.panel=ScrollablePanel(holder);form=self.panel.body;form.columnconfigure(0,weight=1)
        self.vars={};self.entries={}
        for index,(key,text) in enumerate((('ip','Địa chỉ IP *'),('hostname','Tên máy'),('mac','Địa chỉ MAC'),('status','Trạng thái'))):
            default='Online' if key=='status' and device is None else ''
            value=(device or {}).get(key) or default
            if key=='status' and value not in STATUSES:value='Unknown'
            var=tk.StringVar(value=value);self.vars[key]=var
            ttk.Label(form,text=text).grid(row=index*2,column=0,sticky='w',pady=(8,4))
            entry=ttk.Combobox(form,textvariable=var,values=STATUSES,state='readonly',width=1) if key=='status' else ttk.Entry(form,textvariable=var,width=1)
            entry.grid(row=index*2+1,column=0,sticky='ew',pady=(0,7));self.entries[key]=entry
        self.status=tk.StringVar(value='* Trường bắt buộc. Ctrl+Enter để lưu.')
        status_label=ttk.Label(self.window,textvariable=self.status,foreground=PALETTE['muted'],wraplength=500)
        status_label.grid(row=2,column=0,sticky='ew',padx=18,pady=(5,0))
        # Reserve footer space independently of the requested form height.
        footer=ttk.Frame(self.window,padding=(18,12));footer.grid(row=3,column=0,sticky='ew');footer.columnconfigure(0,weight=1)
        self.save_button=ttk.Button(footer,text='Lưu',command=self.save);self.save_button.grid(row=0,column=1,padx=(0,8))
        self.cancel_button=ttk.Button(footer,text='Hủy',command=self.window.destroy);self.cancel_button.grid(row=0,column=2)
        def resize(event):
            if event.widget is self.window:
                title.configure(wraplength=max(200,event.width-40));status_label.configure(wraplength=max(200,event.width-40))
        self.window.bind('<Configure>',resize,add='+')
        self.window.bind('<Control-Return>',lambda event:(self.save(),'break')[1])
        self.window.bind('<Escape>',lambda event:(self.window.destroy(),'break')[1])
        self.window.update_idletasks()
        x=max(0,min(root.winfo_rootx()+(root.winfo_width()-width)//2,self.window.winfo_screenwidth()-width))
        y=max(0,min(root.winfo_rooty()+(root.winfo_height()-height)//2,self.window.winfo_screenheight()-height-60))
        self.window.geometry(f'{width}x{height}+{x}+{y}')
        self.window.grab_set();self.entries['ip'].focus_set()

    def save(self):
        if self.saving:return
        self.saving=True;self.save_button.configure(state='disabled')
        try:
            result,fields=submit_device({key:var.get() for key,var in self.vars.items()},self.persist)
            if not result.get('success'):
                self.status.set(result.get('message') or 'Không thể lưu thiết bị.');return
        except ValueError as exc:
            self.status.set(str(exc));self.entries['ip'].focus_set();return
        except Exception:
            logging.getLogger(__name__).exception('Cannot save device')
            self.status.set('Không thể lưu vào cơ sở dữ liệu. Xem nhật ký hoặc kiểm tra quyền truy cập.');return
        finally:
            self.saving=False
            if self.window.winfo_exists():self.save_button.configure(state='normal')
        self.window.destroy()
        try:self.on_saved(fields)
        except Exception:
            logging.getLogger(__name__).exception('Device saved but list refresh failed')
            messagebox.showwarning('Thiết bị đã lưu','Đã lưu thiết bị. Bấm Làm mới để cập nhật danh sách.',parent=self.root)
