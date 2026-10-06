"""Idempotent additive desktop schema setup; never starts GUI or network collectors."""
def ensure_support_tables():
    from modules.advanced_pages import ensure_advanced_tables
    from modules.extra_pages import ensure_extra_tables
    from modules.nms_v3 import ensure_v3_tables
    from modules.auto_ip import ensure_tables as ensure_autoip_tables
    from modules.auto_config_audit import _conn as audit_connection
    from webapi.runtime37 import connection
    ensure_extra_tables()
    ensure_advanced_tables()
    ensure_v3_tables()
    ensure_autoip_tables()
    # Same schema as IPMacManagerPage._init_table; instantiate no Tk widget.
    with connection() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS ip_mac_inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT UNIQUE NOT NULL,
            mac TEXT, hostname TEXT, status TEXT DEFAULT 'Unknown', note TEXT DEFAULT '',
            first_seen TEXT, last_seen TEXT)''')
    audit_connection().close()
