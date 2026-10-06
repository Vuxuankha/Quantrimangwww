import json
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from modules import monitor_extensions as ext
from database.db import get_connection
from app_runtime import data_path, DATA_DIR
from agent_runtime import heartbeat_status
from tkinter.scrolledtext import ScrolledText
from modules.responsive_layout import FlowRow, AdaptiveForm, ScrollablePanel

class ExtensionPage(ttk.Frame):
    def __init__(self,parent):
        super().__init__(parent);self.pack(fill='both',expand=True,padx=15,pady=10)
        ext.ensure_tables();self.results=queue.Queue();self.busy=False;self._poll_id=None;self.stop_event=threading.Event()
        self.bind("<Destroy>",self.on_destroy,add="+")
        self.status=tk.StringVar(value='Sẵn sàng')
        tabs=ttk.Notebook(self);tabs.pack(fill='both',expand=True)
        pages=[]
        for name in ('Wi-Fi','Camera','Giám sát nền'):
            page=ttk.Frame(tabs);tabs.add(page,text=name);pages.append(ScrollablePanel(page).body)
        wifi,camera,hist=pages
        self.gateway=tk.StringVar();self.internet=tk.StringVar(value='1.1.1.1')
        form=ttk.Frame(wifi);form.pack(fill='x');fields=[]
        for label,var in [('Gateway (trống = tự tìm)',self.gateway),('IP kiểm tra Internet',self.internet)]:
            field=ttk.Frame(form);fields.append(field)
            ttk.Label(field,text=label).pack(anchor='w');ttk.Entry(field,textvariable=var,width=1).pack(fill='x',pady=3)
        AdaptiveForm(form,fields)
        ttk.Button(wifi,text='Kiểm tra Wi-Fi',command=self.wifi).pack(anchor='w',pady=5)
        self.wifi_text=ScrolledText(wifi,wrap='word',width=1,height=18);self.wifi_text.pack(fill='both',expand=True)
        self.fields={};form=ttk.Frame(camera);form.pack(fill='x');fields=[]
        for key,label,value in [('name','Tên camera',''),('host','IP / hostname',''),('port','Cổng kiểm tra','554'),('stream','URL RTSP (có thể chứa tài khoản)',''),('snapshot','URL snapshot (tùy chọn)','')]:
            var=tk.StringVar(value=value);self.fields[key]=var;field=ttk.Frame(form);fields.append(field)
            ttk.Label(field,text=label).pack(anchor='w',pady=3)
            ttk.Entry(field,textvariable=var,width=1,show='*' if key in ('stream','snapshot') else '').pack(fill='x')
        AdaptiveForm(form,fields)
        buttons=ttk.Frame(camera);buttons.pack(fill='x',pady=8)
        FlowRow(buttons,[ttk.Button(buttons,text=text,command=command) for text,command in [('Thêm',self.add_camera),('Kiểm tra',self.check_camera),('Mở luồng bằng VLC',self.open_stream),('Xóa',self.delete_camera)]])
        table=ttk.Frame(camera);table.pack(fill='both',expand=True);table.columnconfigure(0,weight=1);table.rowconfigure(0,weight=1)
        self.camera_list=ttk.Treeview(table,columns=('name','host','port'),show='headings',height=10)
        for col,title,width in [('name','Tên camera',200),('host','IP / hostname',200),('port','Cổng',80)]:
            self.camera_list.heading(col,text=title);self.camera_list.column(col,width=width,minwidth=60)
        ys=ttk.Scrollbar(table,orient='vertical',command=self.camera_list.yview);xs=ttk.Scrollbar(table,orient='horizontal',command=self.camera_list.xview)
        self.camera_list.configure(yscrollcommand=ys.set,xscrollcommand=xs.set)
        self.camera_list.grid(row=0,column=0,sticky='nsew');ys.grid(row=0,column=1,sticky='ns');xs.grid(row=1,column=0,sticky='ew');self.refresh_cameras()
        self.wifi_enabled=tk.BooleanVar(value=False)
        c=get_connection()
        try:
            row=c.execute("SELECT value FROM settings WHERE key='agent_wifi_enabled'").fetchone();self.wifi_enabled.set(bool(row and row[0]=='1'))
        finally:c.close()
        ttk.Checkbutton(hist,text='Thu thập Wi-Fi trong dịch vụ nền',variable=self.wifi_enabled,command=self.save_wifi).pack(anchor='w')
        note2=ttk.Label(hist,text='Cần card Wi-Fi. Cài dịch vụ riêng theo UPDATE_1.1.0.md.',wraplength=500);note2.pack(fill='x',pady=5)
        ttk.Button(hist,text='Làm mới trạng thái / lịch sử',command=self.refresh_history).pack(anchor='w')
        self.history_text=ScrolledText(hist,wrap='word',width=1,height=18);self.history_text.pack(fill='both',expand=True);self.refresh_history()
        status=ttk.Label(self,textvariable=self.status,wraplength=500);status.pack(fill='x',pady=5)
        self.bind('<Configure>',lambda event:status.configure(wraplength=max(200,event.width-30)),add='+')
        hist.bind('<Configure>',lambda event:note2.configure(wraplength=max(200,event.width-20)),add='+')

    def on_destroy(self,event):
        if event.widget is not self:return
        self.stop_event.set()
        if self._poll_id is not None:
            try:self.after_cancel(self._poll_id)
            except tk.TclError:pass
            self._poll_id=None

    def job(self,fn,output=None):
        if self.busy:return
        self.busy=True;self.status.set('Đang xử lý...')
        def worker():
            try:self.results.put((fn(),None,output))
            except Exception as exc:self.results.put(('',str(exc),output))
        threading.Thread(target=worker,daemon=True).start();self._poll_id=self.after(100,self.poll)

    def poll(self):
        self._poll_id=None
        try:
            if not self.winfo_exists():return
        except tk.TclError:
            return
        try:result,error,output=self.results.get_nowait()
        except queue.Empty:self._poll_id=self.after(100,self.poll);return
        self.busy=False;self.status.set(error or 'Hoàn tất')
        if output is not None:
            output.delete('1.0','end');output.insert('1.0',error or str(result))

    def wifi(self):
        gateway=self.gateway.get().strip();internet=self.internet.get().strip()
        def run():
            result=ext.wifi_diagnostics(gateway,internet,stop=self.stop_event);text=json.dumps(result,ensure_ascii=False,indent=2)
            ext.history('WiFi','Windows','Checked',text);return text
        self.job(run,self.wifi_text)

    def add_camera(self):
        try:ext.save_camera(**{k:v.get().strip() for k,v in self.fields.items()});self.refresh_cameras()
        except Exception as exc:self.status.set(str(exc))

    def refresh_cameras(self):
        self.rows={str(r['id']):r for r in ext.cameras()}
        for item in self.camera_list.get_children():self.camera_list.delete(item)
        for key,r in self.rows.items():self.camera_list.insert('', 'end',iid=key,values=(r['name'],r['host'],r['port']))

    def selected(self):
        selection=self.camera_list.selection()
        if not selection:raise ValueError('Chọn camera trong danh sách.')
        return self.rows[selection[0]]

    def check_camera(self):
        try:camera=self.selected()
        except Exception as exc:self.status.set(str(exc));return
        def run():
            status,detail=ext.check_camera(camera);ext.history('Camera',camera['host'],status,detail);return status+': '+detail
        self.job(run)

    def open_stream(self):
        try:
            import subprocess,shutil,os
            from modules.nms_v5 import decrypt_secret
            camera=self.selected();url=decrypt_secret(camera['stream_enc']) if camera['stream_enc'] else ''
            if not url:raise ValueError('Chưa có URL RTSP.')
            vlc=shutil.which('vlc')
            if not vlc:
                for base in [os.environ.get('ProgramFiles',''),os.environ.get('ProgramFiles(x86)','')]:
                    path=Path(base)/'VideoLAN/VLC/vlc.exe'
                    if path.is_file():vlc=str(path);break
            if not vlc:raise ValueError('Cài VLC để xem luồng RTSP.')
            subprocess.Popen([vlc,'--no-one-instance',url])
            self.status.set('Đã mở VLC; URL có thể hiện trong danh sách tiến trình trên máy này.')
        except Exception as exc:self.status.set(str(exc))

    def delete_camera(self):
        try:
            camera=self.selected()
            if not messagebox.askyesno('Xóa camera','Xóa '+camera['name']+'?',parent=self):return
            c=get_connection()
            try:c.execute('DELETE FROM camera_registry WHERE id=?',(camera['id'],));c.commit()
            finally:c.close()
            self.refresh_cameras()
        except Exception as exc:self.status.set(str(exc))

    def save_wifi(self):
        c=get_connection()
        try:c.execute("INSERT INTO settings(key,value) VALUES('agent_wifi_enabled',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",('1' if self.wifi_enabled.get() else '0',));c.commit()
        finally:c.close()

    def refresh_history(self):
        state, info = heartbeat_status(data_path('agent_status.json'))
        state += '\nThư mục dữ liệu: '+str(DATA_DIR)+'\n'+json.dumps(info,ensure_ascii=False,indent=2)
        c=get_connection()
        try:rows=c.execute('SELECT created_at,kind,target,status,detail FROM extension_history ORDER BY id DESC LIMIT 100').fetchall()
        finally:c.close()
        self.history_text.delete('1.0','end');self.history_text.insert('1.0',state+'\n\n'+'\n'.join(' | '.join(str(v) for v in row) for row in rows))
