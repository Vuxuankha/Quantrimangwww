"""SSH execution without Tk access; callers provide a connection snapshot."""
import re
import time


def connection_options(host, port, username, password, mode='exec'):
    host, username = host.strip(), username.strip()
    if not host or not username:
        raise ValueError('Vui lòng nhập Máy chủ/IP và Username.')
    try:
        port = int(port)
    except (ValueError, TypeError):
        raise ValueError('Cổng SSH phải là số từ 1 đến 65535.') from None
    if not 1 <= port <= 65535:
        raise ValueError('Cổng SSH phải là số từ 1 đến 65535.')
    return dict(host=host, port=port, username=username, password=password, mode=mode)


MAX_OUTPUT_BYTES = 16 * 1024 * 1024


def read_exec_output(client, command, timeout, max_output_bytes=MAX_OUTPUT_BYTES):
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    channel = stdout.channel
    chunks, errors = [], []
    total = 0
    deadline = time.monotonic() + timeout
    try:
        stdin.close()
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError('Hết thời gian chờ lệnh: ' + command)
            # Drain both SSH streams fairly: unread stderr can fill the shared window.
            for ready, receive, collected in ((channel.recv_ready,channel.recv,chunks),
                                               (channel.recv_stderr_ready,channel.recv_stderr,errors)):
                if ready():
                    data = receive(65536)
                    total += len(data)
                    if total > max_output_bytes:
                        raise RuntimeError('Kết quả SSH vượt giới hạn dung lượng cho phép.')
                    collected.append(data)
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            time.sleep(.02)
        out = b''.join(chunks).decode(errors='replace')
        err = b''.join(errors).decode(errors='replace')
        status = channel.recv_exit_status()
        if status not in (0, -1):
            raise RuntimeError(f'Lệnh thất bại (mã {status}): {command}\n{out}{err}')
        return out, err
    finally:
        channel.close()


def _exec(client, command, timeout, max_output_bytes=MAX_OUTPUT_BYTES):
    out, err = read_exec_output(client,command,timeout,max_output_bytes)
    return out + err


def _shell_read(channel, timeout, prompt=None):
    deadline = time.monotonic() + timeout
    chunks = []
    last_data = time.monotonic()
    while time.monotonic() < deadline:
        if channel.recv_ready():
            data = channel.recv(65536)
            if not data:
                raise RuntimeError('Thiết bị đã đóng phiên SSH.')
            chunks.append(data)
            last_data = time.monotonic()
        text = b''.join(chunks).decode(errors='replace')
        text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text).replace('\r', '')
        tail = text.rstrip().split('\n')[-1]
        # Standard network CLI prompts, e.g. SW1# / SW1(config)# / user@host:~$.
        matched = re.fullmatch(r'[^\n]{1,150}[#>$]', tail)
        if matched and (prompt is None or tail.startswith(prompt)) and time.monotonic() - last_data >= .15:
            return text, tail
        if channel.closed:
            raise RuntimeError('Thiết bị đã đóng phiên SSH trước khi trả về dấu nhắc.')
        time.sleep(.02)
    raise TimeoutError('Không nhận được dấu nhắc SSH. Tắt phân trang hoặc kiểm tra lệnh đang yêu cầu nhập thêm.')


def execute_commands(options, commands, paramiko_module=None, timeout=30):
    if paramiko_module is None:
        try:
            import paramiko as paramiko_module
        except ImportError:
            raise RuntimeError('Thiếu Paramiko. Chạy: python -m pip install -r requirements.txt') from None
    from modules.ssh_security import build_strict_ssh_client, unknown_host_key_help
    client = build_strict_ssh_client(paramiko_module)
    try:
        password = options['password']
        client.connect(hostname=options['host'], port=options['port'],
                       username=options['username'], password=password or None,
                       timeout=10, banner_timeout=15, auth_timeout=15,
                       look_for_keys=not bool(password), allow_agent=not bool(password))
        pieces = []
        if options.get('mode') == 'shell':
            channel = client.invoke_shell(width=200, height=1000)
            channel.settimeout(timeout)
            try:
                _shell_read(channel, timeout)
                shell_commands = ([options['paging']] if options.get('paging') else []) + list(commands)
                for command in shell_commands:
                    channel.sendall(command + '\n')
                    output, _ = _shell_read(channel, timeout)
                    pieces.append(f'$ {command}\n{output}')
            finally:
                channel.close()
        else:
            for command in commands:
                pieces.append(f'$ {command}\n{_exec(client, command, timeout)}')
        return '\n'.join(pieces)
    except paramiko_module.SSHException as exc:
        if 'known_hosts' in str(exc).lower() or 'not found in known_hosts' in str(exc).lower():
            raise RuntimeError(unknown_host_key_help(options['host'])) from exc
        raise
    finally:
        client.close()
