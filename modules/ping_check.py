import subprocess
import platform
import math
import re
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from app_runtime import hidden_subprocess_kwargs


# ==========================================================
# PING ONE HOST
# ==========================================================

def ping_host(ip, timeout=1000):
    from modules.icmp_probe import icmp_ping
    result = icmp_ping(ip, timeout)
    result['time'] = datetime.now().strftime('%H:%M:%S')
    return result


# ==========================================================
# PING MULTIPLE HOSTS
# ==========================================================

def ping_multiple(
    ips,
    max_workers=50,
    timeout=1000
):

    results = []

    if not ips:

        return results

    workers = min(
        max_workers,
        len(ips)
    )

    with ThreadPoolExecutor(
        max_workers=workers
    ) as executor:

        futures = {
            executor.submit(
                ping_host,
                ip,
                timeout
            ): ip
            for ip in ips
        }

        for future in as_completed(futures):

            ip = futures[future]

            try:

                result = future.result()

                results.append(
                    result
                )

            except Exception as error:

                results.append(
                    {
                        "time": datetime.now().strftime(
                            "%H:%M:%S"
                        ),
                        "ip": ip,
                        "status": "Error",
                        "response": None,
                        "error": str(error)
                    }
                )

    # ======================================================
    # GIỮ NGUYÊN THỨ TỰ IP NGƯỜI DÙNG NHẬP
    # ======================================================

    order = {
        ip: index
        for index, ip in enumerate(ips)
    }

    results.sort(
        key=lambda item: order.get(
            item["ip"],
            999999
        )
    )

    return results


# ==========================================================
# TEST
# ==========================================================

if __name__ == "__main__":

    print("=" * 60)
    print("PING TEST")
    print("=" * 60)

    ips = [
        "192.168.1.1",
        "192.168.1.10",
        "192.168.1.20"
    ]

    results = ping_multiple(
        ips,
        max_workers=50,
        timeout=1000
    )

    for result in results:

        print(
            f"{result['time']} | "
            f"{result['ip']:15} | "
            f"{result['status']:8} | "
            f"{result['response']}"
        )