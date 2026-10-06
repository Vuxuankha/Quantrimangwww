"""Interactive device transports. Never start a local shell or implicitly trust SSH keys.

Telnet implements bounded RFC 854/855 negotiation, BINARY, ECHO, SGA, TTYPE and
NAWS. It intentionally does not negotiate environment, X11 or authentication
extensions. Passwords for Telnet are typed into the remote login prompt.
"""
from __future__ import annotations
import asyncio
import codecs
import io
import socket
import struct
import threading

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
BINARY, ECHO, SGA, TTYPE, NAWS = 0, 1, 3, 24, 31


class TelnetCodec:
    """Incremental parser, including IAC split over TCP packets. No terminal text logs."""
    def __init__(self, cols=100, rows=30):
        self.cols, self.rows = cols, rows
        self.state = 'data'
        self.command = None
        self.sub = bytearray()
        self.local = set()
        self.remote = set()
        self.refused_local = set()
        self.refused_remote = set()

    def dimensions(self):
        raw = struct.pack('!HH', self.cols, self.rows).replace(b'\xff', b'\xff\xff')
        return bytes([IAC, SB, NAWS]) + raw + bytes([IAC, SE])

    def resize(self, cols, rows):
        self.cols, self.rows = cols, rows
        return self.dimensions() if NAWS in self.local else b''

    def feed(self, raw):
        text, reply = bytearray(), bytearray()
        for b in raw:
            if self.state == 'data':
                if b == IAC: self.state = 'iac'
                else: text.append(b)
            elif self.state == 'iac':
                if b == IAC:
                    text.append(b); self.state = 'data'
                elif b in (DO, DONT, WILL, WONT):
                    self.command = b; self.state = 'option'
                elif b == SB:
                    self.sub.clear(); self.state = 'sub'
                else: self.state = 'data'
            elif self.state == 'option':
                cmd = self.command
                if cmd == DO:
                    if b in (BINARY, SGA, TTYPE, NAWS):
                        if b not in self.local:
                            self.local.add(b); reply.extend([IAC, WILL, b])
                            if b == NAWS: reply.extend(self.dimensions())
                    elif b not in self.refused_local:
                        self.refused_local.add(b); reply.extend([IAC, WONT, b])
                elif cmd == DONT:
                    if b in self.local:
                        self.local.discard(b); reply.extend([IAC, WONT, b])
                    self.refused_local.discard(b)
                elif cmd == WILL:
                    if b in (BINARY, ECHO, SGA):
                        if b not in self.remote:
                            self.remote.add(b); reply.extend([IAC, DO, b])
                    elif b not in self.refused_remote:
                        self.refused_remote.add(b); reply.extend([IAC, DONT, b])
                elif cmd == WONT:
                    if b in self.remote:
                        self.remote.discard(b); reply.extend([IAC, DONT, b])
                    self.refused_remote.discard(b)
                self.state = 'data'
            elif self.state == 'sub':
                if b == IAC: self.state = 'sub_iac'
                else: self.sub.append(b)
            elif self.state == 'sub_iac':
                if b == SE:
                    if self.sub == bytes([TTYPE, 1]) and TTYPE in self.local:
                        reply.extend(bytes([IAC, SB, TTYPE, 0])+b'xterm-256color'+bytes([IAC, SE]))
                    self.sub.clear(); self.state = 'data'
                elif b == IAC:
                    self.sub.append(IAC); self.state = 'sub'
                else:
                    self.sub.clear(); self.state = 'data'
            if len(self.sub) > 2048:
                raise ValueError('TELNET_NEGOTIATION_TOO_LARGE')
        return bytes(text), bytes(reply)

    def encode(self, text):
        raw = text.encode('utf-8')
        if BINARY not in self.local:
            # A standalone Enter from xterm is CR. Network NVT requires CR NUL.
            raw = raw.replace(b'\r\n', b'\n').replace(b'\r', b'\r\x00').replace(b'\n', b'\r\n')
        return raw.replace(b'\xff', b'\xff\xff')


class TelnetTransport:
    def __init__(self):
        self.reader = self.writer = None
        self.codec = TelnetCodec()
        self.decoder = codecs.getincrementaldecoder('utf-8')('replace')
        self.closed = False
        self.negotiation_bytes = 0

    async def open(self, host, port, username='', password='', cols=100, rows=30):
        self.codec = TelnetCodec(cols, rows)
        self.reader, self.writer = await asyncio.wait_for(asyncio.open_connection(host, port, limit=65536), 10)
        self.writer.write(bytes([IAC, DO, ECHO, IAC, DO, SGA, IAC, WILL, TTYPE, IAC, WILL, NAWS]))
        await self.writer.drain()

    async def read(self):
        raw = await self.reader.read(8192)
        if not raw: return ''
        text, response = self.codec.feed(raw)
        self.negotiation_bytes += len(raw) if not text else 0
        if self.negotiation_bytes > 1024*1024:
            raise ValueError('TELNET_NEGOTIATION_LIMIT')
        if response:
            self.writer.write(response)
            await self.writer.drain()
        # NVT CR NUL represents a carriage return; a terminal ignores NUL.
        out = self.decoder.decode(text).replace('\x00', '')
        return out if out else None

    async def write(self, text):
        self.writer.write(self.codec.encode(text)); await self.writer.drain()

    async def resize(self, cols, rows):
        raw = self.codec.resize(cols, rows)
        if raw:
            self.writer.write(raw); await self.writer.drain()

    async def close(self):
        self.closed = True
        if self.writer:
            self.writer.close()
            try: await asyncio.wait_for(self.writer.wait_closed(), 2)
            except Exception: pass


class SSHTransport:
    def __init__(self):
        self.client = self.channel = None
        self.lock = threading.Lock()
        self.closed = False
        self.decoder = codecs.getincrementaldecoder('utf-8')('replace')

    @staticmethod
    def load_private_key(paramiko, private_key, passphrase):
        # Memory-only parsing. Never read a client-supplied path or use ssh-agent.
        for name in ('Ed25519Key', 'ECDSAKey', 'RSAKey'):
            cls = getattr(paramiko, name, None)
            if cls is None:
                continue
            try:
                return cls.from_private_key(io.StringIO(private_key), password=passphrase or None)
            except Exception:
                continue
        raise ValueError('SSH_PRIVATE_KEY_INVALID_OR_PASSPHRASE')

    def _open(self, host, port, username, password, cols, rows, private_key='', passphrase=''):
        import paramiko
        from modules.ssh_security import build_strict_ssh_client
        client = build_strict_ssh_client(paramiko)
        with self.lock:
            if self.closed: client.close(); return
            self.client = client
        try:
            auth = {'password': password}
            if private_key:
                auth = {'pkey': self.load_private_key(paramiko, private_key, passphrase)}
            client.connect(hostname=host, port=port, username=username, **auth,
                           look_for_keys=False, allow_agent=False,
                           timeout=8, banner_timeout=8, auth_timeout=10, channel_timeout=8)
            channel = client.invoke_shell(term='xterm-256color', width=cols, height=rows)
            channel.settimeout(1)
            transport = client.get_transport()
            if transport: transport.set_keepalive(20)
            with self.lock:
                if self.closed: channel.close(); client.close()
                else: self.channel = channel
        except BaseException:
            client.close(); raise

    async def open(self, host, port, username, password, cols=100, rows=30, *, private_key="", passphrase=""):
        # Socket deadlines bound the worker even if an async caller is cancelled.
        await asyncio.wait_for(asyncio.to_thread(self._open, host, port, username, password, cols, rows, private_key, passphrase), 35)

    def _read(self):
        try: return self.channel.recv(8192)
        except socket.timeout: return None

    async def read(self):
        raw = await asyncio.to_thread(self._read)
        if raw is None: return None
        if not raw: return ''
        out = self.decoder.decode(raw)
        return out if out else None

    async def write(self, text):
        await asyncio.to_thread(self.channel.sendall, text.encode('utf-8'))

    async def resize(self, cols, rows):
        await asyncio.to_thread(self.channel.resize_pty, width=cols, height=rows)

    async def close(self):
        with self.lock:
            self.closed = True
            channel, client = self.channel, self.client
        def close_all():
            if channel: channel.close()
            if client: client.close()
        await asyncio.to_thread(close_all)
