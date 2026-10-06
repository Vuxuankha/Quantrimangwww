"""Shared ICMP implementation for Desktop, Web and Auto IP.

Never infer latency from process execution time or an unreachable response.
IP literals only; subprocess is called without a shell.
"""
from __future__ import annotations
import ipaddress
import math
import os
import re
import subprocess
from datetime import datetime, timezone
from app_runtime import hidden_subprocess_kwargs


def icmp_ping(ip: str, timeout_ms: int = 1000, count: int = 1) -> dict:
    result = {'ip': str(ip).strip(), 'status': 'Unknown', 'response': None,
              'packet_loss': None, 'observed_at': datetime.now(timezone.utc).isoformat(),
              'source': 'shared.icmp_probe', 'error': ''}
    try:
        address = ipaddress.ip_address(str(ip).strip())
        if address.is_multicast or address.is_unspecified:
            raise ValueError('Unicast IP required')
        timeout_ms = int(timeout_ms)
        count = int(count)
        if not 100 <= timeout_ms <= 10000 or not 1 <= count <= 4:
            raise ValueError('Timeout must be 100-10000 ms; count 1-4')
    except (ValueError, TypeError) as exc:
        return {**result, 'status': 'Error', 'error': str(exc)}
    result['ip'] = str(address)
    if os.name == 'nt':
        command = ['ping', '-n', str(count), '-w', str(timeout_ms), str(address)]
    else:
        command = ['ping', '-n', '-c', str(count), '-W', str(max(1, math.ceil(timeout_ms / 1000))), str(address)]
    try:
        p = subprocess.run(command, capture_output=True, text=True, errors='replace',
                           timeout=count * max(1, timeout_ms / 1000) + max(0, count - 1) + 2,
                           **hidden_subprocess_kwargs())
    except FileNotFoundError:
        return {**result, 'status': 'Error', 'error': 'PING_NOT_INSTALLED'}
    except (subprocess.TimeoutExpired, TimeoutError):
        return {**result, 'status': 'Offline', 'packet_loss': 100.0, 'error': 'PING_TIMEOUT'}
    except OSError as exc:
        return {**result, 'status': 'Error', 'error': 'PING_EXECUTION_ERROR: ' + str(exc)[:180]}
    text = p.stdout if isinstance(p.stdout, str) else ''
    # An echo reply contains TTL or time. Windows can return exit=0 for an
    # unreachable message; do not count that as a reply.
    echo = bool(re.search(r'(?:TTL\s*[=:]|time\s*[=<]|th\u1eddi gian\s*[=<])', text, re.I))
    online = p.returncode == 0 and (echo if os.name == 'nt' else True)
    if online:
        samples = [float(x.replace(',', '.')) for x in re.findall(
            r'(?:time|th\u1eddi gian)\s*[=<]\s*(\d+(?:[.,]\d+)?)\s*ms', text, re.I)]
        loss = re.search(r'(\d+(?:[.,]\d+)?)%\s*(?:packet loss|loss)', text, re.I)
        result['response_is_upper_bound'] = bool(re.search(r'(?:time|th\u1eddi gian)\s*<', text, re.I))
        result.update(status='Online', response=round(sum(samples) / len(samples), 3) if samples else None,
                      packet_loss=float(loss.group(1).replace(',', '.')) if loss else (0.0 if count == 1 else None))
    elif p.returncode in (0, 1):
        result.update(status='Offline', packet_loss=100.0, error='NO_ICMP_REPLY')
    else:
        result.update(status='Error', error='PING_EXECUTION_ERROR: ' + (getattr(p, 'stderr', '') or text or str(p.returncode)).strip()[:180])
    return result
