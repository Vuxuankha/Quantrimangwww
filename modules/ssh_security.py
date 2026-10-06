"""Shared SSH trust policy for network-device connections.

Security rule: never silently trust a new server key.  Device keys must be
present in the OS known_hosts file or in the application known_hosts file.
This prevents a changed/misdirected IP from being accepted as the expected
network device without an explicit trust decision.
"""
from __future__ import annotations

from pathlib import Path

from app_runtime import DATABASE_DIR

APP_KNOWN_HOSTS = Path(DATABASE_DIR) / "known_hosts"


def build_strict_ssh_client(paramiko_module):
    """Return an SSHClient that rejects unknown or changed host keys."""
    client = paramiko_module.SSHClient()
    client.load_system_host_keys()
    if APP_KNOWN_HOSTS.exists():
        client.load_host_keys(str(APP_KNOWN_HOSTS))
    client.set_missing_host_key_policy(paramiko_module.RejectPolicy())
    return client


def unknown_host_key_help(host: str) -> str:
    return (
        f"SSH host key của {host} chưa được tin cậy hoặc đã thay đổi. "
        f"Hãy xác minh fingerprint ngoài băng và thêm khóa đúng vào {APP_KNOWN_HOSTS}."
    )
