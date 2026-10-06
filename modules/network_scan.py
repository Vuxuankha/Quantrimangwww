import socket
import subprocess
import platform
import ipaddress
import re
import time
import threading
import math
import queue
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime
from app_runtime import hidden_subprocess_kwargs


# Short-lived ARP snapshot cache. During a /24 sweep many hosts can reply at
# nearly the same time; spawning one `arp` process per online host makes the
# scan unnecessarily slow and can exhaust process handles on Windows.
_arp_cache_lock = threading.Lock()
_arp_cache_at = 0.0
_arp_cache = {}
_ARP_CACHE_TTL = 0.75


# ==========================================================
# PING HOST
# ==========================================================

def ping_host(ip, timeout=1000, stop_event=None, details=False):
    """Shared bounded ICMP. Compatibility callers receive bool/None.

    The scanner requests details so missing ping/system errors are not falsely
    reported as offline devices, and RTT is never replaced by scan duration.
    """
    if stop_event is not None and stop_event.is_set():
        return None
    from modules.icmp_probe import icmp_ping
    result = icmp_ping(ip, timeout, count=1)
    return result if details else result['status'] == 'Online'


# ==========================================================
# GET HOSTNAME
# ==========================================================

_dns_slots = threading.BoundedSemaphore(16)


def get_hostname(ip, timeout=1.0, stop_event=None):
    """Bound caller wait and resolver concurrency, even if OS DNS hangs."""
    if stop_event is not None and stop_event.is_set():
        return ''
    if not _dns_slots.acquire(blocking=False):
        return ''
    result = queue.Queue(maxsize=1)
    def resolve():
        try:
            try:
                name = socket.gethostbyaddr(ip)[0]
            except Exception:
                name = ''
            result.put_nowait(name)
        finally:
            _dns_slots.release()
    thread = threading.Thread(target=resolve, daemon=True)
    try:
        thread.start()
    except Exception:
        _dns_slots.release()
        raise
    deadline = time.monotonic() + timeout
    while stop_event is None or not stop_event.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return ''
        try:
            return result.get(timeout=min(.05, remaining))
        except queue.Empty:
            pass
    return ''


# ==========================================================
# GET MAC
# ==========================================================

def _arp_snapshot(force=False):
    """Return a short-lived IP->MAC snapshot without starting a process per host."""
    global _arp_cache_at, _arp_cache
    now = time.monotonic()
    if not force and _arp_cache and now - _arp_cache_at < _ARP_CACHE_TTL:
        return dict(_arp_cache)
    with _arp_cache_lock:
        now = time.monotonic()
        if not force and _arp_cache and now - _arp_cache_at < _ARP_CACHE_TTL:
            return dict(_arp_cache)
        found = {}
        commands = [["arp", "-a"]] if platform.system().lower() == 'windows' else [["ip", "neigh", "show"], ["arp", "-an"]]
        for command in commands:
            try:
                result = subprocess.run(
                    command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    errors="ignore", timeout=2, **hidden_subprocess_kwargs()
                )
            except Exception:
                continue
            for line in (result.stdout or '').splitlines():
                ips = re.findall(r"(?<!\d)(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?!\d)", line)
                macs = re.findall(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])", line)
                if not ips or not macs:
                    continue
                mac = macs[0].replace(':', '-').upper()
                for address in ips:
                    found[address] = mac
        _arp_cache = found
        _arp_cache_at = time.monotonic()
        return dict(found)


def get_mac_from_arp(ip):
    """Get a MAC address from a shared, short-lived neighbor snapshot."""
    try:
        return _arp_snapshot().get(str(ip), "")
    except Exception:
        return ""


# ==========================================================
# SCAN HOST
# ==========================================================

def scan_host(
    ip,
    timeout=1000,
    stop_event=None,
    callback=None,
    resolve_hostnames=True,
    dns_timeout=1.0
):
    """
    Scan một host.

    callback event:

        {
            "event": "started",
            "ip": ip
        }

    Khi hoàn thành:

        {
            "event": "completed",
            "result": result
        }
    """

    if stop_event is not None and stop_event.is_set():

        return None

    # ------------------------------------------------------
    # START TIME
    # ------------------------------------------------------

    start_time = time.perf_counter()

    # ------------------------------------------------------
    # CALLBACK: HOST STARTED
    # ------------------------------------------------------

    if callback is not None:

        try:

            callback(
                {
                    "event": "started",
                    "ip": ip
                }
            )

        except Exception:
            pass

    print(
        f"Scanning: {ip}"
    )

    # ------------------------------------------------------
    # PING
    # ------------------------------------------------------

    online = ping_host(
        ip,
        timeout,
        stop_event,
        details=True
    )
    observation = online if isinstance(online, dict) else {}
    if isinstance(online, dict):
        online = online['status'] == 'Online'

    if online is None:

        return None

    # ------------------------------------------------------
    # ONLINE
    # ------------------------------------------------------

    if online:

        hostname = get_hostname(ip, dns_timeout, stop_event) if resolve_hostnames else ""

        mac = get_mac_from_arp(
            ip
        )

        status = "Online"

    # ------------------------------------------------------
    # OFFLINE
    # ------------------------------------------------------

    else:

        hostname = ""

        mac = ""

        status = observation.get('status', 'Offline')

    if stop_event is not None and stop_event.is_set():
        return None

    # ------------------------------------------------------
    # DURATION
    # ------------------------------------------------------

    duration = (
        time.perf_counter()
        - start_time
    )

    duration = round(
        duration,
        2
    )

    # ------------------------------------------------------
    # RESULT
    # ------------------------------------------------------

    result = {

        "time": datetime.now().strftime(
            "%H:%M:%S"
        ),

        "ip": ip,

        "hostname": hostname,

        "mac": mac,

        "status": status,

        "duration": duration,
        "latency_ms": observation.get('response'),
        "response": observation.get('response'),
        "packet_loss": observation.get('packet_loss'),
        "observed_at": observation.get('observed_at'),
        "error": observation.get('error', '')
    }

    # ------------------------------------------------------
    # CALLBACK: COMPLETED
    # ------------------------------------------------------

    if callback is not None:

        try:

            callback(
                {
                    "event": "completed",
                    "result": result
                }
            )

        except Exception:
            pass

    return result


# ==========================================================
# SCAN NETWORK
# ==========================================================

def scan_network(
    network,
    max_workers=50,
    timeout=1000,
    stop_event=None,
    callback=None,
    resolve_hostnames=True,
    dns_timeout=1.0
):
    """
    Scan toàn bộ network.

    callback được gọi realtime:

        started
        completed

    Ví dụ:

        scan_network(
            "192.168.1.0/24",
            callback=my_callback
        )

    """

    print(
        f"Starting network scan: {network}"
    )

    # ------------------------------------------------------
    # VALIDATE NETWORK
    # ------------------------------------------------------

    try:

        net = ipaddress.ip_network(
            network,
            strict=False
        )

    except ValueError as error:

        raise ValueError(
            f"Network không hợp lệ: {network}"
        ) from error

    # ------------------------------------------------------
    # GET HOSTS
    # ------------------------------------------------------

    if not isinstance(max_workers, int) or not 1 <= max_workers <= 256:
        raise ValueError('Số luồng phải từ 1 đến 256.')
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('Timeout phải là số dương hữu hạn (ms).')
    if not isinstance(dns_timeout, (int, float)) or not math.isfinite(dns_timeout) or dns_timeout <= 0:
        raise ValueError('DNS timeout phải là số dương hữu hạn (giây).')
    total_hosts = net.num_addresses
    if net.version == 4 and net.prefixlen < 31:
        total_hosts -= 2
    elif net.version == 6 and net.prefixlen < 127:
        total_hosts -= 1
    if callback is not None:
        try:
            callback({'event': 'total', 'total': total_hosts})
        except Exception:
            pass
    stop_event = stop_event if stop_event is not None else threading.Event()
    results = []
    if stop_event.is_set():
        return results
    hosts = iter(net.hosts())
    executor = ThreadPoolExecutor(max_workers=max_workers)
    futures = {}
    exhausted = False
    try:
        while not stop_event.is_set():
            # Keep only a small window of tasks; never materialize the subnet.
            while not exhausted and len(futures) < max_workers * 2 and not stop_event.is_set():
                ip = next(hosts, None)
                if ip is None:
                    exhausted = True
                    break
                future = executor.submit(scan_host, str(ip), timeout, stop_event, callback, resolve_hostnames, dns_timeout)
                futures[future] = str(ip)
            if not futures:
                break
            done, _ = wait(futures, timeout=.1, return_when=FIRST_COMPLETED)
            for future in done:
                ip = futures.pop(future)
                try:
                    result = future.result()
                    if result is not None:
                        results.append(result)
                except Exception as error:
                    print(f'Scan error {ip}: {error}')
    finally:
        for future in futures:
            future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------
    # SORT RESULTS
    # ------------------------------------------------------

    results.sort(
        key=lambda x:
        ipaddress.ip_address(
            x["ip"]
        )
    )

    # ------------------------------------------------------
    # FINISHED
    # ------------------------------------------------------

    if stop_event.is_set():

        print(
            "Network scan stopped."
        )

    else:

        print(
            "Network scan completed."
        )

    return results


# ==========================================================
# TEST
# ==========================================================

if __name__ == "__main__":

    print(
        "=" * 60
    )

    print(
        "NETWORK SCAN TEST"
    )

    print(
        "=" * 60
    )

    network = input(
        "Nhập network, ví dụ "
        "192.168.1.0/24: "
    ).strip()

    stop_event = threading.Event()

    def test_callback(event):

        if event["event"] == "started":

            print(
                f"[START] "
                f"{event['ip']}"
            )

        elif event["event"] == "completed":

            result = event["result"]

            print(
                f"[DONE] "
                f"{result['ip']} -> "
                f"{result['status']} "
                f"{result['duration']}s"
            )

    try:

        results = scan_network(
            network,
            max_workers=50,
            timeout=1000,
            stop_event=stop_event,
            callback=test_callback
        )

        print()

        print(
            "=" * 60
        )

        print(
            "RESULT"
        )

        print(
            "=" * 60
        )

        for device in results:

            print(
                f"{device['time']:8} | "
                f"{device['ip']:15} | "
                f"{device['hostname']:25} | "
                f"{device['mac']:17} | "
                f"{device['status']:8} | "
                f"{device['duration']}s"
            )

        print()

        print(
            f"Total: "
            f"{len(results)} devices"
        )

    except Exception as error:

        print(
            f"ERROR: {error}"
        )