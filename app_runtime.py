from __future__ import annotations

import logging
import json
from logging.handlers import RotatingFileHandler
import os
import shutil
import subprocess
import sys
from pathlib import Path

APP_NAME = "NetworkAutomation"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def resource_root() -> Path:
    """Read-only application resources (source tree or PyInstaller bundle)."""
    if is_frozen() and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent


def install_root() -> Path:
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def data_root() -> Path:
    """Writable application data.

    Source/dev mode keeps the historical project layout for backwards
    compatibility. A packaged Windows build writes under LOCALAPPDATA so it
    never needs write permission in Program Files.
    """
    override = os.environ.get("NETWORK_AUTOMATION_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    config = install_root() / "data_location.json"
    if config.exists():
        value = json.loads(config.read_text(encoding="utf-8")).get("data_dir")
        if not value or not Path(value).is_absolute():
            raise ValueError("data_location.json phải chứa data_dir là đường dẫn tuyệt đối.")
        return Path(value).resolve()
    if not is_frozen():
        return Path(__file__).resolve().parent
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    if base:
        return Path(base) / APP_NAME
    return Path.home() / f".{APP_NAME.lower()}"


RESOURCE_DIR = resource_root()
DATA_DIR = data_root()
DATABASE_DIR = DATA_DIR / "database"
REPORT_DIR = DATA_DIR / "reports"
BACKUP_DIR = DATA_DIR / "backups"
LOG_DIR = DATA_DIR / "logs"

for _p in (DATA_DIR, DATABASE_DIR, REPORT_DIR, BACKUP_DIR, LOG_DIR):
    _p.mkdir(parents=True, exist_ok=True)


def resource_path(*parts: str) -> Path:
    return RESOURCE_DIR.joinpath(*parts)


def data_path(*parts: str) -> Path:
    p = DATA_DIR.joinpath(*parts)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def migrate_portable_data_once() -> None:
    """Import data placed next to an installed EXE on first run.

    To migrate an older portable/source installation, place its ``database``
    folder next to NetworkAutomation.exe before first launch. Existing AppData
    is never overwritten.
    """
    if not is_frozen():
        return
    marker = DATA_DIR / ".portable_migration_checked"
    if marker.exists():
        return
    legacy = install_root() / "database"
    try:
        for name in ("network_automation.db", ".credential.key", "known_hosts"):
            src = legacy / name
            dst = DATABASE_DIR / name
            if src.exists() and not dst.exists():
                shutil.copy2(src, dst)
    finally:
        try:
            marker.write_text("checked\n", encoding="utf-8")
        except Exception:
            pass


def hidden_subprocess_kwargs() -> dict:
    """Prevent helper console windows from flashing on Windows."""
    if os.name != "nt":
        return {}
    kwargs = {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    startup_cls = getattr(subprocess, "STARTUPINFO", None)
    if startup_cls is not None:
        si = startup_cls()
        si.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 0)
        si.wShowWindow = getattr(subprocess, "SW_HIDE", 0)
        kwargs["startupinfo"] = si
    return kwargs


def setup_logging() -> Path:
    log_file = LOG_DIR / "network_automation.log"
    # PyInstaller windowed mode may set stdout/stderr to None. Keep third-party
    # print() calls harmless and preserve their output for troubleshooting.
    if is_frozen() and (sys.stdout is None or sys.stderr is None):
        stream = open(LOG_DIR / "console_capture.log", "a", encoding="utf-8", buffering=1)
        if sys.stdout is None:
            sys.stdout = stream
        if sys.stderr is None:
            sys.stderr = stream
    logging.basicConfig(
        handlers=[RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")],
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger(__name__).info(
        "Application start frozen=%s data_dir=%s", is_frozen(), DATA_DIR
    )
    return log_file
