"""Cross-process coordinator lease shared by Desktop and Web (Windows/POSIX)."""
from __future__ import annotations
import os
from pathlib import Path


class OperationLease:
    def __init__(self, path):
        self.path = Path(path)
        self.file = None

    def acquire(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        f = self.path.open('a+b')
        try:
            f.seek(0, 2)
            if f.tell() == 0:
                f.write(b'0'); f.flush()
            f.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, IOError) as exc:
            f.close()
            raise RuntimeError('COORDINATOR_BUSY: another Desktop/Web coordinator is running on this data directory') from exc
        self.file = f
        return self

    def release(self):
        f, self.file = self.file, None
        if f is None:
            return
        try:
            f.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        finally:
            f.close()
