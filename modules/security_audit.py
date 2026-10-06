from modules.ui_theme import PALETTE as UI_COLORS
import sqlite3, difflib, re
from pathlib import Path
from datetime import datetime
import tkinter as tk
import threading
from tkinter import ttk, messagebox, filedialog
from database.db import DB_PATH

DB = DB_PATH

def _conn():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
    c.execute('''CREATE TABLE IF NOT EXISTS config_baselines(
      id INTEGER PRIMARY KEY AUTOINCREMENT, device TEXT NOT NULL UNIQUE,
      config TEXT NOT NULL, source TEXT, updated_at TEXT NOT NULL)''')
    c.commit(); return c

def save_baseline(device, config, source='manual'):
    now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'); c=_conn()
    c.execute('''INSERT INTO config_baselines(device,config,source,updated_at) VALUES(?,?,?,?)
      ON CONFLICT(device) DO UPDATE SET config=excluded.config,source=excluded.source,updated_at=excluded.updated_at''',
      (device.strip(),config,source,now)); c.commit(); c.close()

def get_baseline(device):
    c=_conn(); r=c.execute('SELECT * FROM config_baselines WHERE device=?',(device.strip(),)).fetchone(); c.close(); return dict(r) if r else None

def posture(config):
    s=config.lower(); results=[]
    def add(name, ok, evidence, severity='WARN'):
        results.append({'control':name,'status':'PASS' if ok else severity,'evidence':evidence})
    ssh=('ip ssh' in s or 'transport input ssh' in s)
    telnet=bool(re.search(r'transport input[^\n]*telnet',s))
    http=bool(re.search(r'^\s*ip http server\s*$',s,re.M))
    https='ip http secure-server' in s
    add('SSH quản trị',ssh,'Có cấu hình SSH' if ssh else 'Không thấy cấu hình SSH','HIGH')
    add('Telnet',not telnet,'Không cho phép Telnet' if not telnet else 'Phát hiện transport input telnet','HIGH')
    add('HTTP quản trị',not http,'HTTP thường không bật' if not http else 'Phát hiện ip http server')
    add('HTTPS quản trị',https,'Có HTTPS' if https else 'Không thấy ip http secure-server','REVIEW')
    add('DHCP Snooping','ip dhcp snooping' in s,'Có DHCP Snooping' if 'ip dhcp snooping' in s else 'Chưa thấy DHCP Snooping','REVIEW')
    add('Dynamic ARP Inspection','ip arp inspection' in s,'Có DAI' if 'ip arp inspection' in s else 'Chưa thấy DAI','REVIEW')
    add('Port Security','switchport port-security' in s,'Có Port Security' if 'switchport port-security' in s else 'Chưa thấy Port Security','REVIEW')
    vlan1=bool(re.search(r'switchport access vlan\s+1\b',s))
    add('Access VLAN 1',not vlan1,'Không thấy access VLAN 1' if not vlan1 else 'Có cổng access VLAN 1','WARN')
    add('AAA','aaa new-model' in s,'Có AAA new-model' if 'aaa new-model' in s else 'Chưa thấy AAA new-model','REVIEW')
    return results

class SecurityAuditPage(tk.Frame):
    def __init__(self,parent,activity_callback=None):
        super().__init__(parent,bg=UI_COLORS['background']); self.pack(fill='both',expand=True); self.activity=activity_callback or (lambda x:None)
        top=tk.Frame(self,bg=UI_COLORS['background']); top.pack(fill='x',padx=16,pady=10)
        tk.Label(top,text='Thiết bị / tên baseline',bg=UI_COLORS['background']).pack(side='left')
        self.device=tk.StringVar(); ttk.Entry(top,textvariable=self.device,width=28).pack(side='left',padx=8)
        ttk.Button(top,text='Mở config',command=self.load_file).pack(side='left',padx=3)
        ttk.Button(top,text='Lưu làm Baseline',command=self.save).pack(side='left',padx=3)
        ttk.Button(top,text='So với Baseline',command=self.compare).pack(side='left',padx=3)
        ttk.Button(top,text='Security Posture',command=self.audit).pack(side='left',padx=3)
        ttk.Button(top,text='SSH → Audit',command=self.ssh_audit).pack(side='left',padx=3)
        ttk.Button(top,text='Auto Audit Scheduler',command=self.scheduler_dialog).pack(side='left',padx=3)
        pan=ttk.Panedwindow(self,orient='vertical'); pan.pack(fill='both',expand=True,padx=16,pady=(0,16))
        f1=ttk.Labelframe(pan,text='Running / current configuration'); self.text=tk.Text(f1,wrap='none',font=('Consolas',9)); self.text.pack(fill='both',expand=True); pan.add(f1,weight=3)
        f2=ttk.Labelframe(pan,text='Kết quả'); self.out=tk.Text(f2,wrap='word',font=('Consolas',9),state='disabled'); self.out.pack(fill='both',expand=True); pan.add(f2,weight=2)
    def _write(self,t):
        self.out.config(state='normal'); self.out.delete('1.0','end'); self.out.insert('1.0',t); self.out.config(state='disabled')
    def load_file(self):
        p=filedialog.askopenfilename(title='Chọn file cấu hình',filetypes=[('Config/Text','*.cfg *.conf *.txt'),('All','*.*')])
        if not p:return
        try: data=Path(p).read_text(encoding='utf-8',errors='replace'); self.text.delete('1.0','end'); self.text.insert('1.0',data); self.device.set(self.device.get() or Path(p).stem)
        except Exception as e: messagebox.showerror('Mở config',str(e))
    def save(self):
        d=self.device.get().strip(); cfg=self.text.get('1.0','end-1c')
        if not d or not cfg.strip(): messagebox.showwarning('Baseline','Nhập tên thiết bị và cấu hình.'); return
        save_baseline(d,cfg); self.activity('Đã cập nhật configuration baseline: '+d); messagebox.showinfo('Baseline','Đã lưu baseline cho '+d)
    def compare(self):
        d=self.device.get().strip(); b=get_baseline(d); cur=self.text.get('1.0','end-1c')
        if not b: messagebox.showwarning('Baseline','Chưa có baseline cho thiết bị này.'); return
        diff=list(difflib.unified_diff(b['config'].splitlines(),cur.splitlines(),fromfile='BASELINE',tofile='CURRENT',lineterm=''))
        if not diff:self._write('PASS - Không phát hiện configuration drift.\nBaseline: '+b['updated_at']); return
        adds=sum(1 for x in diff if x.startswith('+') and not x.startswith('+++')); rem=sum(1 for x in diff if x.startswith('-') and not x.startswith('---'))
        self._write(f'WARN - Configuration drift: +{adds} / -{rem}\nBaseline: {b["updated_at"]}\n\n'+'\n'.join(diff[:1200]))

    def scheduler_dialog(self):
        from modules.auto_audit_scheduler import get_settings, save_settings, run_all
        s=get_settings(); w=tk.Toplevel(self); w.title('Auto Audit Scheduler'); w.geometry('520x330'); w.transient(self.winfo_toplevel())
        enabled=tk.BooleanVar(value=bool(s['enabled'])); tm=tk.StringVar(value=s['run_time']); workers=tk.IntVar(value=s['max_workers']); cmd=tk.StringVar(value=s['command']); status=tk.StringVar(value=s.get('last_status') or 'Chưa chạy')
        f=ttk.Frame(w,padding=16); f.pack(fill='both',expand=True)
        ttk.Checkbutton(f,text='Bật audit SSH tự động hằng ngày',variable=enabled).grid(row=0,column=0,columnspan=2,sticky='w',pady=5)
        ttk.Label(f,text='Giờ chạy (HH:MM)').grid(row=1,column=0,sticky='w',pady=5); ttk.Entry(f,textvariable=tm,width=12).grid(row=1,column=1,sticky='w')
        ttk.Label(f,text='Số kết nối SSH song song').grid(row=2,column=0,sticky='w',pady=5); ttk.Spinbox(f,from_=1,to=8,textvariable=workers,width=10).grid(row=2,column=1,sticky='w')
        ttk.Label(f,text='Lệnh read-only').grid(row=3,column=0,sticky='w',pady=5); ttk.Entry(f,textvariable=cmd,width=32).grid(row=3,column=1,sticky='ew')
        ttk.Label(f,text='Lần chạy gần nhất').grid(row=4,column=0,sticky='nw',pady=5); ttk.Label(f,text=(s.get('last_run') or 'Chưa có')+'\n'+status.get(),wraplength=290).grid(row=4,column=1,sticky='w')
        ttk.Label(f,text='Scheduler chỉ audit thiết bị đã gán SSH credential. Không tự thay đổi cấu hình.',foreground=UI_COLORS['muted'],wraplength=470).grid(row=5,column=0,columnspan=2,sticky='w',pady=10)
        def save():
            try: save_settings(enabled.get(),tm.get().strip(),workers.get(),cmd.get()); messagebox.showinfo('Auto Audit','Đã lưu lịch audit.',parent=w); w.destroy()
            except Exception as e: messagebox.showerror('Auto Audit',str(e),parent=w)
        def runnow():
            status.set('Đang chạy...')
            def work():
                try: msg=run_all(self.activity); self.after(0,lambda:status.set(msg))
                except Exception as e: self.after(0,lambda:status.set('Lỗi: '+str(e)))
            threading.Thread(target=work,daemon=True).start()
        b=ttk.Frame(f); b.grid(row=6,column=0,columnspan=2,sticky='e',pady=8); ttk.Button(b,text='Chạy ngay',command=runnow).pack(side='left',padx=4); ttk.Button(b,text='Lưu',command=save).pack(side='left',padx=4)
        f.columnconfigure(1,weight=1)

    def ssh_audit(self):
        from modules.auto_config_audit import list_ssh_audit_devices, audit_device
        devices=list_ssh_audit_devices()
        if not devices:
            messagebox.showinfo('SSH Audit','Chưa có thiết bị trong danh mục.'); return
        ready=[d for d in devices if d.get('credential_id')]
        if not ready:
            messagebox.showwarning('SSH Audit','Chưa có thiết bị nào được gán credential SSH/Backup. Hãy gán credential trước.'); return
        w=tk.Toplevel(self); w.title('SSH → Running Config → Audit'); w.geometry('560x210'); w.transient(self.winfo_toplevel()); w.grab_set()
        labels=[f"{d.get('name') or d['ip']} ({d['ip']}) — {d.get('credential_name') or 'SSH'}" for d in ready]
        choice=tk.StringVar(value=labels[0]); command=tk.StringVar(value='show running-config')
        tk.Label(w,text='Thiết bị').pack(anchor='w',padx=16,pady=(16,3)); ttk.Combobox(w,textvariable=choice,values=labels,state='readonly',width=66).pack(fill='x',padx=16)
        tk.Label(w,text='Lệnh lấy cấu hình (read-only)').pack(anchor='w',padx=16,pady=(10,3)); ttk.Entry(w,textvariable=command).pack(fill='x',padx=16)
        status=tk.StringVar(value='Sẵn sàng'); tk.Label(w,textvariable=status,fg=UI_COLORS['muted']).pack(anchor='w',padx=16,pady=8)
        def start():
            idx=labels.index(choice.get()); d=ready[idx]; status.set('Đang kết nối SSH và audit...')
            def work():
                try:
                    r=audit_device(d['id'],command.get().strip() or 'show running-config',True)
                    def done():
                        self.device.set((r['device'].get('name') or r['device']['ip']).strip())
                        self.text.delete('1.0','end'); self.text.insert('1.0',r['config'])
                        lines=[f"AUTO SSH AUDIT | {r['status']} | {r['detail']}",'-'*76]
                        if r['baseline'] is None: lines.append('REVIEW - Chưa có baseline. Có thể dùng nút Lưu làm Baseline sau khi xác minh config.')
                        elif r['diff']:
                            lines.append('CONFIGURATION DRIFT:'); lines.extend(r['diff'][:500]); lines.append('')
                        else: lines.append('PASS - Không phát hiện configuration drift.')
                        lines.append('\nSECURITY POSTURE:')
                        for x in r['rows']: lines.append(f"{x['status']:<7} {x['control']:<26} {x['evidence']}")
                        self._write('\n'.join(lines)); self.activity('Auto SSH security audit: '+self.device.get()); status.set('Hoàn tất - '+r['status']); w.after(800,w.destroy)
                    self.after(0,done)
                except Exception as e:
                    self.after(0,lambda msg=str(e):(status.set('Lỗi'),messagebox.showerror('SSH Audit',msg,parent=w)))
            threading.Thread(target=work,daemon=True).start()
        ttk.Button(w,text='Chạy Audit',command=start).pack(anchor='e',padx=16,pady=4)
    def audit(self):
        cfg=self.text.get('1.0','end-1c')
        if not cfg.strip(): messagebox.showwarning('Security Posture','Hãy nạp hoặc dán cấu hình trước.'); return
        rows=posture(cfg); counts={k:sum(r['status']==k for r in rows) for k in ('HIGH','WARN','REVIEW','PASS')}
        lines=[f'SECURITY POSTURE  | HIGH {counts["HIGH"]}  WARN {counts["WARN"]}  REVIEW {counts["REVIEW"]}  PASS {counts["PASS"]}','-'*76]
        for r in rows: lines.append(f'{r["status"]:<7} {r["control"]:<26} {r["evidence"]}')
        lines += ['','Lưu ý: đây là audit read-only dựa trên cấu hình được cung cấp; REVIEW không mặc định đồng nghĩa cấu hình sai.']
        self._write('\n'.join(lines)); self.activity('Đã chạy Security Posture audit: '+(self.device.get().strip() or 'config'))
