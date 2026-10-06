"""Process lock and atomic liveness heartbeat, without UI/database imports."""
import json
import os
import threading
import time
from pathlib import Path

class AgentLock:
    def __init__(self,path):self.path=Path(path);self.stream=None
    def __enter__(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        stream=open(self.path,'a+b');stream.seek(0)
        if not stream.read(1):stream.write(b'0');stream.flush()
        stream.seek(0)
        try:
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:
            stream.close();raise RuntimeError('Agent đang chạy với thư mục dữ liệu này. Dừng agent/service cũ trước.') from None
        self.stream=stream;return self
    def __exit__(self,*args):
        if self.stream:
            if os.name=='nt':
                import msvcrt
                self.stream.seek(0);msvcrt.locking(self.stream.fileno(),msvcrt.LK_UNLCK,1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(),fcntl.LOCK_UN)
            self.stream.close();self.stream=None

class Heartbeat:
    def __init__(self,path):
        self.path=Path(path);self.done=threading.Event();self.lock=threading.Lock()
        self.info={'state':'starting','pid':os.getpid(),'data_dir':str(self.path.parent)}
    def write(self,**changes):
        with self.lock:
            self.info.update(changes);self.info['heartbeat']=time.time()
            tmp=self.path.with_suffix('.tmp');tmp.write_text(json.dumps(self.info,ensure_ascii=False),encoding='utf-8');os.replace(tmp,self.path)
    def start(self):
        self.write()
        def pulse():
            while not self.done.wait(10):
                try:self.write()
                except OSError:pass
        self.thread=threading.Thread(target=pulse,daemon=True);self.thread.start()
    def close(self):
        self.done.set();self.thread.join(timeout=2);self.write(state='stopped')

def heartbeat_status(path,now=None):
    path=Path(path)
    if not path.exists():
        return 'Chưa khởi động / chưa có heartbeat',{}
    try:
        info=json.loads(path.read_text(encoding='utf-8'))
        if info.get('state')=='stopped':return 'Đã dừng',info
        age=(time.time() if now is None else now)-float(info['heartbeat'])
        if age<0 or age>35:return 'Mất heartbeat — kiểm tra Windows Services',info
        return {'starting':'Đang khởi tạo','running':'Đang giám sát','waiting':'Đang chờ lượt tiếp theo','error':'Đang lỗi; sẽ thử lại'}.get(info.get('state'),'Trạng thái chưa xác định'),info
    except (ValueError,KeyError,TypeError,json.JSONDecodeError):
        return 'Heartbeat lỗi / không đọc được',{}
    except OSError:
        return 'Không đọc được heartbeat',{}
