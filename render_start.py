"""Render/Linux entrypoint for NetworkAutomation Web.

This wrapper keeps the Windows/local launcher unchanged. On Render it creates a
fresh writable runtime database from the application's schema (no database file
needs to be committed to Git), configures host/HTTPS settings, and starts
Uvicorn on 0.0.0.0:$PORT.
"""
from __future__ import annotations

import os
from pathlib import Path


def _prepare_data_dir() -> Path:
    """Create Render's writable data directories without requiring a seed DB.

    Render Free uses an ephemeral filesystem by default. A paid persistent disk
    can mount /var/data and set NETWORK_AUTOMATION_DATA_DIR=/var/data.
    """
    requested = os.environ.get("NETWORK_AUTOMATION_DATA_DIR", "").strip()
    data_dir = Path(requested).expanduser() if requested else Path("/tmp/networkautomation")
    data_dir = data_dir.resolve()
    for name in ("database", "reports", "backups", "logs"):
        (data_dir / name).mkdir(parents=True, exist_ok=True)
    return data_dir


def _initialize_runtime_database() -> None:
    """Create/migrate the runtime SQLite schema in the configured data dir."""
    # Import only after NETWORK_AUTOMATION_DATA_DIR is set. app_runtime and
    # database.db resolve their paths at import time.
    from database.db import init_database

    init_database()


def _bootstrap_render_admin() -> None:
    """Create or synchronize the Render Admin from environment variables.

    Render deployments use an ephemeral/isolated database.  The environment
    variables are therefore the source of truth for the emergency/bootstrap
    Admin credential:

    - ``NA_BOOTSTRAP_ADMIN_USER`` (default ``Admin``)
    - ``NA_BOOTSTRAP_ADMIN_PASSWORD`` (required, 8-256 characters)

    On every Render start, the matching username is created when absent or its
    password is synchronized when already present.  The account is also kept
    enabled with the Admin role.  This makes changing the Render secret take
    effect after a redeploy without deleting the database.
    """
    from modules.nms_v5 import ensure_v5_tables, _hash_password
    from webapi.runtime37 import connection, utcnow

    ensure_v5_tables()

    username = os.environ.get('NA_BOOTSTRAP_ADMIN_USER', 'Admin').strip() or 'Admin'
    password = os.environ.get('NA_BOOTSTRAP_ADMIN_PASSWORD', '')
    if not password:
        raise RuntimeError(
            'Render Admin credential is not configured. Set environment variable '
            'NA_BOOTSTRAP_ADMIN_PASSWORD (8-256 characters), then redeploy. '
            'Optional username: NA_BOOTSTRAP_ADMIN_USER (default: Admin).'
        )

    from modules import accounts

    accounts._validate(username, 'Admin', password)
    now = utcnow()
    password_hash = _hash_password(password)

    with connection() as c:
        row = c.execute(
            'SELECT id,username FROM app_users WHERE username=? COLLATE NOCASE LIMIT 1',
            (username,),
        ).fetchone()
        if row:
            c.execute(
                'UPDATE app_users SET username=?,password_hash=?,role=?,enabled=1,updated_at=? WHERE id=?',
                (username, password_hash, 'Admin', now, row['id']),
            )
            action = 'synchronized'
        else:
            c.execute(
                'INSERT INTO app_users(username,password_hash,role,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)',
                (username, password_hash, 'Admin', 1, now, now),
            )
            action = 'created'
        c.commit()

    print(f'[render] Bootstrap Admin {action}: {username} (password synchronized from environment)')


def _disable_render_mfa() -> None:
    """Disable MFA enrollment/verification for the Render web deployment.

    The user requested simple account/password login on Render.  Clear any MFA
    state left by earlier hotfixes and set the security policy to optional/off.
    This is intentionally Render-entrypoint-only and does not change the Windows
    desktop/local launchers.
    """
    from webapi.security37 import ensure_tables
    from webapi.runtime37 import connection

    ensure_tables()
    with connection() as c:
        c.execute(
            "UPDATE web_security_policy51 SET mfa_required=0,updated_at=datetime('now') WHERE id=1"
        )
        c.execute(
            "UPDATE app_users SET mfa_enabled=0,mfa_secret_enc=NULL,mfa_updated_at=datetime('now') "
            "WHERE COALESCE(mfa_enabled,0)<>0 OR mfa_secret_enc IS NOT NULL"
        )
        c.execute('DELETE FROM web_mfa_challenges51')
        c.commit()
    print('[render] MFA disabled for Render login; username/password authentication only')


def main() -> None:
    data_dir = _prepare_data_dir()
    os.environ["NETWORK_AUTOMATION_DATA_DIR"] = str(data_dir)
    os.environ.setdefault("NA_ALLOWED_HOSTS", "*")
    os.environ.setdefault("NA_COOKIE_SECURE", "1")
    os.environ.setdefault("NA_TIMEZONE", "Asia/Ho_Chi_Minh")
    # Render cannot discover the user's private 192.168.x.x LAN directly.
    os.environ.setdefault("NA_ENABLE_AUTOIP", "0")
    # Hosted Web runs in browser-only mode. The end-user public IP and line
    # quality are measured from the browser/request path; never use the
    # Render container's private 10.x address as the user's network identity.
    os.environ.setdefault("NA_WEB_ONLY_BROWSER", "1")
    os.environ.setdefault("NA_PUBLIC_REGISTRATION", "1")
    os.environ.setdefault("NA_REGISTRATION_AUTO_ENABLE", "1")
    # Render deployment: username/password login only. Do not force or request
    # Authenticator enrollment. The desktop/local build keeps its existing MFA
    # behavior because this setting is applied only by the Render entrypoint.
    os.environ.setdefault("NA_MFA_REQUIRED", "0")
    os.environ.setdefault("NA_DISABLE_MFA", "1")
    os.environ.setdefault("NA_INSTANCE_TOKEN", "render")

    _initialize_runtime_database()
    _bootstrap_render_admin()
    _disable_render_mfa()

    port = int(os.environ.get("PORT", "10000"))
    import uvicorn

    uvicorn.run(
        "webapi.main:app",
        host="0.0.0.0",
        port=port,
        workers=1,
        proxy_headers=True,
        forwarded_allow_ips="*",
        log_level="info",
    )


if __name__ == "__main__":
    main()
