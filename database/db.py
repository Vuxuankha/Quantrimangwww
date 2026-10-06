
import sqlite3
import ipaddress
from pathlib import Path
from app_runtime import DATABASE_DIR, RESOURCE_DIR, migrate_portable_data_once
from upgrade_backup import backup_before_release
from datetime import datetime


# ============================================================
# DATABASE CONFIG
# ============================================================

# Writable database directory. Packaged builds use LOCALAPPDATA.
migrate_portable_data_once()
BASE_DIR = DATABASE_DIR
DB_PATH = BASE_DIR / "network_automation.db"


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection(timeout=15.0):
    """Create a production-friendly SQLite connection.

    WAL allows readers and background monitoring writers to coexist much
    better than the default rollback journal. busy_timeout prevents short
    bursts from failing immediately with ``database is locked``.
    """
    conn = sqlite3.connect(DB_PATH, timeout=float(timeout))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(f"PRAGMA busy_timeout = {max(0, int(float(timeout) * 1000))}")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA temp_store = MEMORY")
    conn.execute("PRAGMA cache_size = -20000")
    return conn


# ============================================================
# DATABASE MIGRATION HELPERS
# ============================================================

def _get_table_columns(cursor, table_name):
    """
    Lấy danh sách tên cột hiện có của bảng.
    """

    cursor.execute(f"PRAGMA table_info({table_name})")

    rows = cursor.fetchall()

    return {
        row["name"]
        for row in rows
    }


def _add_column_if_missing(
    cursor,
    table_name,
    column_name,
    column_definition
):
    """
    Nếu bảng chưa có column thì tự động thêm.
    """

    columns = _get_table_columns(cursor, table_name)

    if column_name not in columns:
        cursor.execute(
            f"""
            ALTER TABLE {table_name}
            ADD COLUMN {column_name} {column_definition}
            """
        )


# ============================================================
# DEVICES TABLE MIGRATION
# ============================================================

def _migrate_devices_table(cursor):
    """
    Đảm bảo bảng devices có đầy đủ các column cần thiết.

    Dùng để xử lý database cũ bị thiếu:
        ip
        hostname
        mac
        status
        duration
        first_seen
        last_seen
    """

    # --------------------------------------------------------
    # Nếu chưa có bảng devices thì tạo mới
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            hostname TEXT,
            mac TEXT,
            status TEXT,
            duration REAL,
            first_seen TEXT,
            last_seen TEXT
        )
    """)

    # --------------------------------------------------------
    # Migration database cũ
    # --------------------------------------------------------

    _add_column_if_missing(
        cursor,
        "devices",
        "ip",
        "TEXT"
    )

    _add_column_if_missing(
        cursor,
        "devices",
        "hostname",
        "TEXT"
    )

    _add_column_if_missing(
        cursor,
        "devices",
        "mac",
        "TEXT"
    )

    _add_column_if_missing(
        cursor,
        "devices",
        "status",
        "TEXT"
    )

    _add_column_if_missing(
        cursor,
        "devices",
        "duration",
        "REAL"
    )

    _add_column_if_missing(
        cursor,
        "devices",
        "first_seen",
        "TEXT"
    )

    _add_column_if_missing(
        cursor,
        "devices",
        "last_seen",
        "TEXT"
    )

    # --------------------------------------------------------
    # Cập nhật dữ liệu NULL
    # --------------------------------------------------------

    columns = _get_table_columns(cursor, "devices")

    # Older schemas kept addresses under different column names. Adding a
    # new column alone does not copy their values into it.
    for target, aliases in {
        "ip": ("ip_address", "ip_addr", "address"),
        "mac": ("mac_address", "mac_addr"),
    }.items():
        for alias in aliases:
            if alias not in columns:
                continue
            rows = cursor.execute(
                f'SELECT id, "{alias}" AS value FROM devices '
                f'WHERE "{target}" IS NULL OR '
                f'LOWER(TRIM("{target}")) IN (\'\', \'none\', \'null\')'
            ).fetchall()
            for row in rows:
                value = str(row["value"] or "").strip()
                if not value or value.lower() in ("none", "null"):
                    continue
                if target == "ip":
                    try:
                        value = str(ipaddress.ip_address(value))
                    except ValueError:
                        continue
                # Do not delete or merge records to resolve a UNIQUE conflict.
                cursor.execute("SAVEPOINT address_copy")
                try:
                    cursor.execute(
                        f'UPDATE devices SET "{target}" = ? WHERE id = ?',
                        (value, row["id"]),
                    )
                except sqlite3.IntegrityError:
                    cursor.execute("ROLLBACK TO address_copy")
                finally:
                    cursor.execute("RELEASE address_copy")

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    if "status" in columns:
        cursor.execute("""
            UPDATE devices
            SET status = 'Unknown'
            WHERE status IS NULL
               OR TRIM(status) = ''
        """)

    if "first_seen" in columns:
        cursor.execute("""
            UPDATE devices
            SET first_seen = ?
            WHERE first_seen IS NULL
               OR TRIM(first_seen) = ''
        """, (now,))

    if "last_seen" in columns:
        cursor.execute("""
            UPDATE devices
            SET last_seen = ?
            WHERE last_seen IS NULL
               OR TRIM(last_seen) = ''
        """, (now,))


# ============================================================
# SQL V2 MIGRATIONS / INDEXES
# ============================================================

SQL_SCHEMA_VERSION = 2


def _table_exists(cursor, table_name):
    return cursor.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone() is not None


def _backup_before_upgrade(conn, target_version):
    """Create one SQLite-consistent backup before a schema version upgrade."""
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    if int(current or 0) >= int(target_version) or not DB_PATH.exists():
        return None
    backup_dir = BASE_DIR / "db_backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = backup_dir / f"pre_sql_v{target_version}_{stamp}.db"
    dst = sqlite3.connect(out)
    try:
        conn.backup(dst)
    finally:
        dst.close()
    return out


def _ensure_sql_v2(cursor):
    """Non-destructive SQL optimizations for the NOC workload."""
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
    """)

    # Indexes are intentionally non-unique: older installations can contain
    # duplicate legacy rows and an optimization migration must never delete
    # or reject user data.
    index_specs = {
        "network_devices": [
            ("idx_network_devices_status", "status"),
            ("idx_network_devices_ip", "ip"),
            ("idx_network_devices_name", "name"),
            ("idx_network_devices_updated", "updated_at"),
        ],
        "devices": [
            ("idx_devices_status", "status"),
            ("idx_devices_last_seen", "last_seen"),
        ],
        "alerts": [
            ("idx_alerts_status_created", "status, created_at"),
            ("idx_alerts_severity_status", "severity, status"),
            ("idx_alerts_ip_created", "ip, created_at"),
        ],
        "activity_logs": [("idx_activity_logs_created", "created_at")],
        "audit_log": [
            ("idx_audit_log_created", "created_at"),
            ("idx_audit_log_user_created", "username, created_at"),
        ],
        "auth_log": [("idx_auth_log_user_created", "username, created_at")],
        "ping_results": [("idx_ping_results_ip_time", "ip_address, ping_time")],
        "health_samples": [("idx_health_samples_host_time", "host, created_at")],
        "interface_samples": [("idx_interface_samples_host_if_time", "host, ifindex, created_at")],
        "snmp_samples": [
            ("idx_snmp_samples_host_time", "host, created_at"),
            ("idx_snmp_samples_profile_time", "profile_id, created_at"),
        ],
        "config_backups": [("idx_config_backups_device_time", "device_name, created_at")],
        "remote_history": [("idx_remote_history_host_time", "host, created_at")],
        "server_monitor_results": [
            ("idx_server_results_target_time", "target_id, checked_at"),
            ("idx_server_results_status_time", "status, checked_at"),
        ],
        "server_monitor_targets": [("idx_server_targets_enabled", "enabled")],
        "config_audit_history": [
            ("idx_config_audit_device_time", "device_id, created_at"),
            ("idx_config_audit_status_time", "status, created_at"),
        ],
        "auto_audit_runs": [("idx_auto_audit_runs_started", "started_at")],
        "worker_jobs": [("idx_worker_jobs_type_status", "job_type, status, created_at")],
        "incidents": [("idx_incidents_status_updated", "status, updated_at")],
    }
    for table, specs in index_specs.items():
        if not _table_exists(cursor, table):
            continue
        columns = _get_table_columns(cursor, table)
        for index_name, expr in specs:
            needed = [x.strip().split()[0] for x in expr.split(',')]
            if all(col in columns for col in needed):
                cursor.execute(
                    f'CREATE INDEX IF NOT EXISTS "{index_name}" ON "{table}" ({expr})'
                )

    # Dashboard queries normalize text status with LOWER/COALESCE. Expression
    # indexes let SQLite optimize those queries without changing legacy data.
    if _table_exists(cursor, "network_devices"):
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_network_devices_status_lc "
            "ON network_devices(LOWER(COALESCE(status,'')))"
        )
    if _table_exists(cursor, "alerts"):
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_status_lc_id "
            "ON alerts(LOWER(COALESCE(status,'')), id DESC)"
        )

    cursor.execute(
        "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at) VALUES(?,?,?)",
        (SQL_SCHEMA_VERSION, "sqlite_wal_and_noc_indexes", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )
    cursor.execute(f"PRAGMA user_version = {SQL_SCHEMA_VERSION}")


def optimize_database(vacuum=False):
    """Run safe SQLite maintenance; VACUUM is opt-in because it needs a lock."""
    conn = get_connection()
    try:
        conn.execute("PRAGMA optimize")
        if vacuum:
            conn.execute("VACUUM")
    finally:
        conn.close()


def database_health():
    """Return lightweight DB diagnostics for support/administration UI."""
    conn = get_connection()
    try:
        quick = conn.execute("PRAGMA quick_check").fetchone()[0]
        journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        tables = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchone()[0]
        indexes = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%'"
        ).fetchone()[0]
        return {
            "quick_check": quick,
            "journal_mode": journal,
            "schema_version": version,
            "tables": tables,
            "indexes": indexes,
            "db_size_bytes": DB_PATH.stat().st_size if DB_PATH.exists() else 0,
        }
    finally:
        conn.close()


# ============================================================
# INIT DATABASE
# ============================================================

def init_database():
    """
    Tạo database và các bảng.

    Đồng thời migration database cũ.
    """

    db_preexisting = DB_PATH.exists() and DB_PATH.stat().st_size > 0
    if db_preexisting:
        backup_before_release(DB_PATH, RESOURCE_DIR)
    conn = get_connection()
    cursor = conn.cursor()

    try:

        # Back up a legacy database before applying any schema changes.
        # A brand-new database is not backed up; doing so after opening a
        # write transaction can deadlock SQLite's backup API.
        if db_preexisting:
            _backup_before_upgrade(conn, SQL_SCHEMA_VERSION)

        # ----------------------------------------------------
        # Devices
        # ----------------------------------------------------

        _migrate_devices_table(cursor)

        # ----------------------------------------------------
        # Network Scans
        # ----------------------------------------------------

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                hostname TEXT,
                mac TEXT,
                status TEXT,
                duration REAL,
                scan_time TEXT
            )
        """)

        # ----------------------------------------------------
        # Ping Results
        # ----------------------------------------------------

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ping_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                status TEXT,
                response REAL,
                ping_time TEXT
            )
        """)

        # ----------------------------------------------------
        # Network Devices
        # ----------------------------------------------------

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                ip TEXT,
                device_type TEXT,
                vendor TEXT,
                location TEXT,
                status TEXT,
                note TEXT
            )
        """)

        # Migration cho các bản NMS mới và tương thích schema cũ.
        _add_column_if_missing(cursor, "network_devices", "device_name", "TEXT")
        _add_column_if_missing(cursor, "network_devices", "ip_address", "TEXT")
        _add_column_if_missing(cursor, "network_devices", "created_at", "TEXT")
        _add_column_if_missing(cursor, "network_devices", "updated_at", "TEXT")
        cursor.execute("UPDATE network_devices SET device_name=COALESCE(NULLIF(device_name,''), name)")
        cursor.execute("UPDATE network_devices SET ip_address=COALESCE(NULLIF(ip_address,''), ip)")

        now_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "UPDATE network_devices SET created_at=? WHERE created_at IS NULL OR TRIM(created_at)=''",
            (now_text,)
        )
        cursor.execute(
            "UPDATE network_devices SET updated_at=COALESCE(NULLIF(updated_at,''), created_at) "
            "WHERE updated_at IS NULL OR TRIM(updated_at)=''"
        )

        # ----------------------------------------------------
        # Alerts
        # ----------------------------------------------------

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                alert_type TEXT,
                message TEXT,
                created_at TEXT,
                status TEXT
            )
        """)

        _add_column_if_missing(cursor, "alerts", "severity", "TEXT DEFAULT 'Warning'")
        _add_column_if_missing(cursor, "alerts", "ip_address", "TEXT")
        _add_column_if_missing(cursor, "alerts", "resolved", "INTEGER DEFAULT 0")
        cursor.execute("UPDATE alerts SET severity='Warning' WHERE severity IS NULL OR TRIM(severity)=''")
        cursor.execute("UPDATE alerts SET ip_address=COALESCE(NULLIF(ip_address,''), ip)")
        cursor.execute("UPDATE alerts SET resolved=0 WHERE resolved IS NULL")

        # ----------------------------------------------------
        # Activity Logs
        # ----------------------------------------------------

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT,
                description TEXT,
                created_at TEXT
            )
        """)

        # ----------------------------------------------------
        # Settings
        # ----------------------------------------------------

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE,
                value TEXT
            )
        """)

        _ensure_sql_v2(cursor)
        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


# ============================================================
# DEVICE CRUD
# ============================================================

# ------------------------------------------------------------
# CREATE DEVICE
# ------------------------------------------------------------

def create_device(
    ip,
    hostname="",
    mac="",
    status="Unknown",
    duration=None
):
    """
    Thêm thiết bị mới.

    Return:
        device_id nếu thành công
        None nếu IP đã tồn tại
    """

    init_database()

    conn = get_connection()
    cursor = conn.cursor()

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    try:

        cursor.execute("""
            INSERT INTO devices (
                ip,
                hostname,
                mac,
                status,
                duration,
                first_seen,
                last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            ip,
            hostname,
            mac,
            status,
            duration,
            now,
            now
        ))

        conn.commit()

        return cursor.lastrowid

    except sqlite3.IntegrityError:
        conn.rollback()
        return None

    finally:
        conn.close()


# ------------------------------------------------------------
# GET ALL DEVICES
# ------------------------------------------------------------

def get_all_devices():
    """
    Lấy toàn bộ thiết bị.
    """

    init_database()

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT
                id,
                ip,
                hostname,
                mac,
                status,
                duration,
                first_seen,
                last_seen
            FROM devices
            ORDER BY id ASC
        """)

        rows = cursor.fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


# ------------------------------------------------------------
# GET DEVICE
# ------------------------------------------------------------

def get_device(device_id):
    """
    Lấy thiết bị theo ID.
    """

    init_database()

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT
                id,
                ip,
                hostname,
                mac,
                status,
                duration,
                first_seen,
                last_seen
            FROM devices
            WHERE id = ?
        """, (device_id,))

        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        conn.close()


# ------------------------------------------------------------
# GET DEVICE BY IP
# ------------------------------------------------------------

def get_device_by_ip(ip):
    """
    Lấy thiết bị theo IP.
    """

    init_database()

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT
                id,
                ip,
                hostname,
                mac,
                status,
                duration,
                first_seen,
                last_seen
            FROM devices
            WHERE ip = ?
        """, (ip,))

        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        conn.close()


# ------------------------------------------------------------
# SEARCH DEVICES
# ------------------------------------------------------------

def search_devices(keyword=""):
    """
    Tìm thiết bị theo:
        IP
        Hostname
        MAC
    """

    init_database()

    conn = get_connection()
    cursor = conn.cursor()

    try:

        keyword = f"%{keyword}%"

        cursor.execute("""
            SELECT
                id,
                ip,
                hostname,
                mac,
                status,
                duration,
                first_seen,
                last_seen
            FROM devices
            WHERE
                ip LIKE ?
                OR hostname LIKE ?
                OR mac LIKE ?
            ORDER BY id ASC
        """, (
            keyword,
            keyword,
            keyword
        ))

        rows = cursor.fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


# ------------------------------------------------------------
# GET DEVICES BY STATUS
# ------------------------------------------------------------

def get_devices_by_status(status):
    """
    Lấy thiết bị theo status.
    """

    init_database()

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT
                id,
                ip,
                hostname,
                mac,
                status,
                duration,
                first_seen,
                last_seen
            FROM devices
            WHERE status = ?
            ORDER BY id ASC
        """, (status,))

        rows = cursor.fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


# ------------------------------------------------------------
# UPDATE DEVICE
# ------------------------------------------------------------

def update_device(
    device_id,
    ip=None,
    hostname=None,
    mac=None,
    status=None,
    duration=None
):
    """
    Cập nhật thiết bị.

    Chỉ cập nhật những giá trị được truyền vào.
    """

    init_database()

    device = get_device(device_id)

    if device is None:
        return False

    new_ip = (
        device["ip"]
        if ip is None
        else ip
    )

    new_hostname = (
        device["hostname"]
        if hostname is None
        else hostname
    )

    new_mac = (
        device["mac"]
        if mac is None
        else mac
    )

    new_status = (
        device["status"]
        if status is None
        else status
    )

    new_duration = (
        device["duration"]
        if duration is None
        else duration
    )

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            UPDATE devices
            SET
                ip = ?,
                hostname = ?,
                mac = ?,
                status = ?,
                duration = ?,
                last_seen = ?
            WHERE id = ?
        """, (
            new_ip,
            new_hostname,
            new_mac,
            new_status,
            new_duration,
            now,
            device_id
        ))

        conn.commit()

        return cursor.rowcount > 0

    except sqlite3.IntegrityError:

        conn.rollback()

        return False

    finally:
        conn.close()


# ------------------------------------------------------------
# DELETE DEVICE
# ------------------------------------------------------------

def delete_device(device_id):
    """
    Xóa thiết bị theo ID.
    """

    init_database()

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            DELETE FROM devices
            WHERE id = ?
        """, (device_id,))

        conn.commit()

        return cursor.rowcount > 0

    finally:
        conn.close()


# ------------------------------------------------------------
# DELETE DEVICE BY IP
# ------------------------------------------------------------

def delete_device_by_ip(ip):
    """
    Xóa thiết bị theo IP.
    """

    init_database()

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            DELETE FROM devices
            WHERE ip = ?
        """, (ip,))

        conn.commit()

        return cursor.rowcount > 0

    finally:
        conn.close()


# ============================================================
# NETWORK SCAN -> DEVICE DATABASE
# ============================================================

def save_devices(results):
    """Upsert by IP on both old and new schemas without erasing known data."""
    init_database()
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    columns = _get_table_columns(cursor, "devices")

    def text_value(record, *keys):
        for key in keys:
            value = record.get(key)
            if value is not None:
                value = str(value).strip()
                if value and value.lower() not in ("none", "null"):
                    return value
        return ""

    try:
        for result in results:
            if not isinstance(result, dict):
                continue
            ip = text_value(result, "ip", "ip_address", "ip_addr", "address")
            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                continue
            hostname = text_value(result, "hostname", "host_name", "device_name")
            mac = text_value(result, "mac", "mac_address", "mac_addr")
            status = text_value(result, "status", "state") or "Unknown"
            duration = result.get("duration")
            existing = cursor.execute(
                "SELECT id, hostname, mac FROM devices WHERE ip = ?", (ip,)
            ).fetchall()
            if existing:
                for row in existing:
                    values = {
                        "hostname": hostname or row["hostname"] or "",
                        "mac": mac or row["mac"] or "",
                        "status": status, "duration": duration, "last_seen": now,
                    }
                    # Mirror old MAC columns when a new value is available.
                    if mac:
                        for alias in ("mac_address", "mac_addr"):
                            if alias in columns:
                                values[alias] = mac
                    assignments = ", ".join(f'"{key}" = ?' for key in values)
                    cursor.execute(
                        f"UPDATE devices SET {assignments} WHERE id = ?",
                        (*values.values(), row["id"]),
                    )
            else:
                values = {
                    "ip": ip, "hostname": hostname, "mac": mac,
                    "status": status, "duration": duration,
                    "first_seen": now, "last_seen": now,
                }
                # Legacy address columns can be NOT NULL / UNIQUE.
                for alias in ("ip_address", "ip_addr", "address"):
                    if alias in columns:
                        values[alias] = ip
                for alias in ("mac_address", "mac_addr"):
                    if alias in columns:
                        values[alias] = mac
                names = ", ".join(f'"{key}"' for key in values)
                placeholders = ", ".join("?" for _ in values)
                cursor.execute(
                    f"INSERT INTO devices ({names}) VALUES ({placeholders})",
                    tuple(values.values()),
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ============================================================
# DEVICE STATISTICS
# ============================================================

def get_device_statistics():
    """
    Thống kê thiết bị.

    Return:
        {
            "total": ...,
            "online": ...,
            "offline": ...
        }
    """

    init_database()

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM devices
        """)

        total = cursor.fetchone()["total"]

        cursor.execute("""
            SELECT COUNT(*) AS online
            FROM devices
            WHERE status = 'Online'
        """)

        online = cursor.fetchone()["online"]

        cursor.execute("""
            SELECT COUNT(*) AS offline
            FROM devices
            WHERE status = 'Offline'
        """)

        offline = cursor.fetchone()["offline"]

        return {
            "total": total,
            "online": online,
            "offline": offline
        }

    finally:
        conn.close()


# ============================================================
# ACTIVITY LOG
# ============================================================

def add_activity_log(action, description):
    """
    Ghi log hoạt động.
    """

    init_database()

    conn = get_connection()
    cursor = conn.cursor()

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    try:

        cursor.execute("""
            INSERT INTO activity_logs (
                action,
                description,
                created_at
            )
            VALUES (?, ?, ?)
        """, (
            action,
            description,
            now
        ))

        conn.commit()

    finally:
        conn.close()


# ============================================================
# INITIALIZE DATABASE
# ============================================================

# Khi import database.db,
# tự động tạo/migration database.
init_database()


# ============================================================
# WEB / LEGACY DEVICE COMPATIBILITY OVERRIDES (3.8)
# ============================================================
# The project has shipped both `ip`/`mac` and `ip_address`/`mac_address`
# schemas.  These final definitions keep both aliases synchronized so the
# desktop and Web layers can safely share the same database.

def _device_normalize_row(row):
    if row is None:
        return None
    data = dict(row)
    data["ip"] = str(data.get("ip") or data.get("ip_address") or "").strip()
    data["mac"] = str(data.get("mac") or data.get("mac_address") or "").strip()
    return {
        "id": data.get("id"),
        "ip": data["ip"],
        "hostname": data.get("hostname") or "",
        "mac": data["mac"],
        "status": data.get("status") or "Unknown",
        "duration": data.get("duration"),
        "first_seen": data.get("first_seen"),
        "last_seen": data.get("last_seen"),
    }


def _device_ip_where(columns):
    names = [x for x in ("ip", "ip_address", "ip_addr", "address") if x in columns]
    return names, " OR ".join(f'"{x}" = ?' for x in names)


def create_device(ip, hostname="", mac="", status="Unknown", duration=None):
    init_database()
    try:
        ip = str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        return None
    hostname = str(hostname or "").strip()
    mac = str(mac or "").strip()
    status = str(status or "Unknown").strip() or "Unknown"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection(); cursor = conn.cursor()
    try:
        columns = _get_table_columns(cursor, "devices")
        ip_names, where = _device_ip_where(columns)
        if ip_names and cursor.execute(f"SELECT 1 FROM devices WHERE {where} LIMIT 1", [ip] * len(ip_names)).fetchone():
            return None
        values = {}
        for name in ("ip", "ip_address", "ip_addr", "address"):
            if name in columns: values[name] = ip
        if "hostname" in columns: values["hostname"] = hostname
        for name in ("mac", "mac_address", "mac_addr"):
            if name in columns: values[name] = mac
        if "status" in columns: values["status"] = status
        if "duration" in columns: values["duration"] = duration
        if "first_seen" in columns: values["first_seen"] = now
        if "last_seen" in columns: values["last_seen"] = now
        fields = list(values)
        cursor.execute(
            'INSERT INTO devices (' + ','.join(f'"{x}"' for x in fields) + ') VALUES (' + ','.join('?' for _ in fields) + ')',
            [values[x] for x in fields],
        )
        conn.commit(); return cursor.lastrowid
    except sqlite3.IntegrityError:
        conn.rollback(); return None
    finally:
        conn.close()


def get_all_devices():
    init_database(); conn=get_connection(); cursor=conn.cursor()
    try:
        rows=cursor.execute('SELECT * FROM devices ORDER BY id ASC').fetchall()
        return [_device_normalize_row(r) for r in rows]
    finally: conn.close()


def get_device(device_id):
    init_database(); conn=get_connection(); cursor=conn.cursor()
    try:
        return _device_normalize_row(cursor.execute('SELECT * FROM devices WHERE id=?',(device_id,)).fetchone())
    finally: conn.close()


def get_device_by_ip(ip):
    init_database()
    try: ip=str(ipaddress.ip_address(str(ip).strip()))
    except ValueError: return None
    conn=get_connection(); cursor=conn.cursor()
    try:
        columns=_get_table_columns(cursor,'devices'); names,where=_device_ip_where(columns)
        if not names: return None
        return _device_normalize_row(cursor.execute(f'SELECT * FROM devices WHERE {where} LIMIT 1',[ip]*len(names)).fetchone())
    finally: conn.close()


def search_devices(keyword=""):
    init_database(); term=f"%{str(keyword or '').strip()}%"; conn=get_connection(); cursor=conn.cursor()
    try:
        columns=_get_table_columns(cursor,'devices')
        searchable=[x for x in ('ip','ip_address','hostname','mac','mac_address') if x in columns]
        if not searchable: return []
        where=' OR '.join(f'COALESCE("{x}",\'\') LIKE ?' for x in searchable)
        rows=cursor.execute(f'SELECT * FROM devices WHERE {where} ORDER BY id ASC',[term]*len(searchable)).fetchall()
        return [_device_normalize_row(r) for r in rows]
    finally: conn.close()


def get_devices_by_status(status):
    init_database(); conn=get_connection(); cursor=conn.cursor()
    try:
        rows=cursor.execute('SELECT * FROM devices WHERE status=? ORDER BY id ASC',(status,)).fetchall()
        return [_device_normalize_row(r) for r in rows]
    finally: conn.close()


def update_device(device_id, ip=None, hostname=None, mac=None, status=None, duration=None):
    init_database(); current=get_device(device_id)
    if current is None: return False
    new_ip=current['ip'] if ip is None else str(ip).strip()
    try: new_ip=str(ipaddress.ip_address(new_ip))
    except ValueError: return False
    new_hostname=current['hostname'] if hostname is None else str(hostname or '').strip()
    new_mac=current['mac'] if mac is None else str(mac or '').strip()
    new_status=current['status'] if status is None else str(status or 'Unknown').strip()
    new_duration=current['duration'] if duration is None else duration
    now=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn=get_connection(); cursor=conn.cursor()
    try:
        columns=_get_table_columns(cursor,'devices'); ip_names,where=_device_ip_where(columns)
        if ip_names:
            other=cursor.execute(f'SELECT id FROM devices WHERE ({where}) AND id<>? LIMIT 1',[new_ip]*len(ip_names)+[device_id]).fetchone()
            if other: return False
        values={}
        for name in ('ip','ip_address','ip_addr','address'):
            if name in columns: values[name]=new_ip
        if 'hostname' in columns: values['hostname']=new_hostname
        for name in ('mac','mac_address','mac_addr'):
            if name in columns: values[name]=new_mac
        if 'status' in columns: values['status']=new_status
        if 'duration' in columns: values['duration']=new_duration
        if 'last_seen' in columns: values['last_seen']=now
        cursor.execute('UPDATE devices SET '+','.join(f'"{k}"=?' for k in values)+' WHERE id=?',list(values.values())+[device_id])
        conn.commit(); return cursor.rowcount>0
    except sqlite3.IntegrityError:
        conn.rollback(); return False
    finally: conn.close()


def delete_device_by_ip(ip):
    init_database()
    try: ip=str(ipaddress.ip_address(str(ip).strip()))
    except ValueError: return False
    conn=get_connection(); cursor=conn.cursor()
    try:
        columns=_get_table_columns(cursor,'devices'); names,where=_device_ip_where(columns)
        if not names: return False
        cursor.execute(f'DELETE FROM devices WHERE {where}',[ip]*len(names)); conn.commit(); return cursor.rowcount>0
    finally: conn.close()


def save_devices(results):
    """Compatibility upsert used by the desktop scanner; mirrors legacy/new address columns."""
    init_database(); conn=get_connection(); cursor=conn.cursor(); now=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    columns=_get_table_columns(cursor,'devices'); ip_names,where=_device_ip_where(columns)
    try:
        for result in results or []:
            if not isinstance(result,dict): continue
            raw=result.get('ip') or result.get('ip_address') or result.get('address')
            try: address=str(ipaddress.ip_address(str(raw or '').strip()))
            except ValueError: continue
            hostname=str(result.get('hostname') or '').strip(); mac=str(result.get('mac') or result.get('mac_address') or '').strip()
            status=str(result.get('status') or 'Unknown').strip() or 'Unknown'; duration=result.get('duration')
            existing=cursor.execute(f'SELECT * FROM devices WHERE {where} LIMIT 1',[address]*len(ip_names)).fetchone() if ip_names else None
            if existing:
                values={}
                for name in ('ip','ip_address','ip_addr','address'):
                    if name in columns: values[name]=address
                if 'hostname' in columns and hostname: values['hostname']=hostname
                for name in ('mac','mac_address','mac_addr'):
                    if name in columns and mac: values[name]=mac
                if 'status' in columns: values['status']=status
                if 'duration' in columns: values['duration']=duration
                if 'last_seen' in columns: values['last_seen']=now
                cursor.execute('UPDATE devices SET '+','.join(f'"{k}"=?' for k in values)+' WHERE id=?',list(values.values())+[existing['id']])
            else:
                values={}
                for name in ('ip','ip_address','ip_addr','address'):
                    if name in columns: values[name]=address
                if 'hostname' in columns: values['hostname']=hostname
                for name in ('mac','mac_address','mac_addr'):
                    if name in columns: values[name]=mac
                if 'status' in columns: values['status']=status
                if 'duration' in columns: values['duration']=duration
                if 'first_seen' in columns: values['first_seen']=now
                if 'last_seen' in columns: values['last_seen']=now
                cursor.execute('INSERT INTO devices ('+','.join(f'"{k}"' for k in values)+') VALUES ('+','.join('?' for _ in values)+')',list(values.values()))
        conn.commit()
    except Exception:
        conn.rollback(); raise
    finally: conn.close()
