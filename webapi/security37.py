"""Central deny-by-default API authorization and revocable, expiring sessions."""
from __future__ import annotations
import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import struct
import time
from urllib.parse import urlsplit
from fastapi import HTTPException, Request, Response
from starlette.responses import JSONResponse
from webapi.runtime37 import connection, utcnow

COOKIE = 'na_session'
ABSOLUTE_TTL = 8 * 3600
IDLE_TTL = 30 * 60
PUBLIC = {'/api/health', '/api/auth/login', '/api/auth/register', '/api/auth/mfa/verify'}
ADMIN_PREFIXES = ('/api/v46', '/api/v43', '/api/v41', '/api/credentials', '/api/device-credentials', '/api/snmpv3/credentials', '/api/ssh/known-hosts', '/api/accounts', '/api/diagnostics', '/api/security-log', '/api/audit-log', '/api/connection-profiles', '/api/snmpv3/assignments')
OPERATOR_GET = ('/api/operations', '/api/autoip', '/api/ssh-audit', '/api/config-backups', '/api/ssh/hostkey', '/api/jobs')
# Read operations above still require login. Unrecognised writes are refused even for Admin.
WRITE_RULES = [
 ('POST',r'/api/devices/\d+/manage',('Admin',)),
 ('POST',r'/api/connection-profiles',('Admin',)),
 ('DELETE',r'/api/connection-profiles/[^/]+',('Admin',)),
 ('POST',r'/api/autoip/targets/[^/]+/profile',('Admin',)),
 ('POST', r'/api/auth/logout', ('Admin','Analyst','Operator','Viewer')),
 ('POST', r'/api/auth/mfa/verify', ('Admin','Analyst','Operator','Viewer')),
 ('POST', r'/api/auth/password', ('Admin','Analyst','Operator','Viewer')),
 ('POST', r'/api/devices', ('Admin',)),
 ('PUT|DELETE', r'/api/devices/\d+', ('Admin',)),
 ('POST', r'/api/devices/(\d+/ping|refresh-status)', ('Admin','Operator')),
 ('POST', r'/api/scan', ('Admin',)),
 ('POST', r'/api/scan-results/\d+/import', ('Admin',)),
 ('POST', r'/api/alerts/\d+/(close|reopen)', ('Admin','Operator')),
 ('POST', r'/api/server-targets', ('Admin',)),
 ('PUT|DELETE', r'/api/server-targets/\d+', ('Admin',)),
 ('POST', r'/api/server-monitor/run', ('Admin','Operator')),
 ('POST', r'/api/database/backup', ('Admin',)),
 ('POST', r'/api/autoip/(start|stop)', ('Admin',)),
 ('POST', r'/api/snmp/device/\d+/refresh', ('Admin','Operator')),
 ('POST', r'/api/ssh-audit/\d+', ('Admin',)),
 ('POST', r'/api/config-backup/\d+', ('Admin',)),
 ('POST', r'/api/reports/export', ('Admin','Operator')),
 ('POST|PUT|DELETE', r'/api/credentials(/\d+)?', ('Admin',)),
 ('POST|DELETE', r'/api/devices/\d+/credential(/[A-Za-z]+)?', ('Admin',)),
 ('POST', r'/api/devices/\d+/ssh-test', ('Admin','Operator')),
 ('POST', r'/api/ssh/hostkey/\d+/trust', ('Admin',)),
 ('POST|PUT|DELETE', r'/api/snmpv3/credentials(/\d+)?', ('Admin',)),
 ('POST|DELETE', r'/api/devices/\d+/snmpv3', ('Admin',)),
 ('POST', r'/api/autoip/profiles', ('Admin',)),
 ('POST', r'/api/autoip/target-profile', ('Admin',)),
 ('POST', r'/api/operations/(ssh-test|snmp-test)', ('Admin','Operator')),
 ('POST', r'/api/operations/(audit|backup)', ('Admin',)),
 ('POST', r'/api/jobs', ('Admin','Operator')),
 ('POST', r'/api/jobs/\d+/cancel', ('Admin','Operator')),
 ('POST', r'/api/v45/ipmac/delete-many', ('Admin','Operator')),
 ('POST', r'/api/v45/ipmac/delete-all', ('Admin',)),
 ('POST|PUT|DELETE', r'/api/accounts(/\d+)?', ('Admin',)),
 ('POST', r'/api/accounts/\d+/reset-password', ('Admin',)),
 ('POST', r'/api/v4/topology/dependencies', ('Admin',)),
 ('DELETE', r'/api/v4/topology/dependencies/\d+', ('Admin',)),
 ('POST', r'/api/v4/sla', ('Admin',)),
 ('PUT|DELETE', r'/api/v4/sla/\d+', ('Admin',)),
 ('POST', r'/api/v4/maintenance', ('Admin',)),
 ('PUT|DELETE', r'/api/v4/maintenance/\d+', ('Admin',)),
 ('POST', r'/api/v4/organization/(sites|groups)', ('Admin',)),
 ('PUT|DELETE', r'/api/v4/organization/(sites|groups)/\d+', ('Admin',)),
 ('PUT', r'/api/v4/organization/devices/\d+', ('Admin',)),
 ('POST', r'/api/v4/incidents/sync', ('Admin','Operator')),
 ('PUT', r'/api/v4/incidents/\d+', ('Admin','Operator')),
 ('POST', r'/api/v4/cameras', ('Admin',)),
 ('PUT|DELETE', r'/api/v4/cameras/\d+', ('Admin',)),
 ('POST', r'/api/v4/restore/prepare', ('Admin',)),
 ('POST', r'/api/v4/schedules', ('Admin',)),
 ('PUT|DELETE', r'/api/v4/schedules/\d+', ('Admin',)),
 ('POST', r'/api/v4/schedules/\d+/run', ('Admin','Operator')),
 ('PUT', r'/api/v41/retention', ('Admin',)),
 ('POST', r'/api/v41/retention/apply', ('Admin',)),
 ('POST', r'/api/v41/disaster-recovery/export', ('Admin',)),
 ('POST', r'/api/v42/lan/probe', ('Admin','Operator')),
 ('POST|PUT|DELETE', r'/api/v42/snmpv2/credentials(/\d+)?', ('Admin',)),
 ('POST', r'/api/v42/snmpv2/assign', ('Admin',)),
 ('DELETE', r'/api/v42/snmpv2/assign/\d+', ('Admin',)),
 ('POST', r'/api/v42/ssh/assign', ('Admin',)),
 # v4.4 desktop-parity operations. Keep central deny-by-default guard aligned with endpoint RBAC.
 ('POST', r'/api/v44/profiles', ('Admin',)),
 ('PUT|DELETE', r'/api/v44/profiles/\d+', ('Admin',)),
 ('POST', r'/api/v44/profiles/assign', ('Admin','Operator')),
 ('DELETE', r'/api/v44/profiles/assign/\d+', ('Admin','Operator')),
 ('POST', r'/api/v44/profiles/auto-detect/\d+', ('Admin','Operator')),
 ('POST', r'/api/v44/drivers', ('Admin',)),
 ('PUT|DELETE', r'/api/v44/drivers/\d+', ('Admin',)),
 ('POST', r'/api/v44/drivers/assign', ('Admin','Operator')),
 ('DELETE', r'/api/v44/drivers/assign/\d+', ('Admin','Operator')),
 ('POST', r'/api/v44/drivers/auto-detect/\d+', ('Admin','Operator')),
 ('POST', r'/api/v44/monitoring/(resource|interfaces)/\d+', ('Admin','Operator')),
 ('POST', r'/api/v44/alert-rules', ('Admin','Operator')),
 ('PUT|DELETE', r'/api/v44/alert-rules/\d+', ('Admin','Operator')),
 ('POST', r'/api/v44/alert-rules/evaluate', ('Admin','Operator')),
 ('PUT', r'/api/v44/notifications', ('Admin',)),
 ('POST', r'/api/v44/notifications/test', ('Admin',)),
 ('POST', r'/api/v44/services', ('Admin','Operator')),
 ('PUT|DELETE', r'/api/v44/services/\d+', ('Admin','Operator')),
 ('PUT', r'/api/v44/services/\d+/members', ('Admin','Operator')),
 ('POST', r'/api/v44/manual-backups', ('Admin',)),
 ('POST', r'/api/v44/config-compare', ('Admin','Operator')),
 ('POST', r'/api/v44/config-posture', ('Admin','Operator')),
 ('POST', r'/api/v44/baselines/from-backup', ('Admin',)),
 ('DELETE', r'/api/v44/baselines/[^/]+', ('Admin',)),
 ('PUT', r'/api/v44/settings', ('Admin',)),
 ('POST', r'/api/v44/remote/\d+/check', ('Admin','Operator')),
 ('POST', r'/api/v44/daily-audit/run', ('Admin','Operator')),
 # v5.1 Cybersecurity Center: analysts can investigate and run bounded defensive checks.
 ('POST', r'/api/v51/siem/events', ('Admin','Analyst','Operator')),
 ('POST', r'/api/v51/vulnerability/scan', ('Admin','Analyst','Operator')),
 ('POST', r'/api/v51/vulnerability/cve/lookup', ('Admin','Analyst')),
 ('POST', r'/api/v51/threat/hash-lookup', ('Admin','Analyst')),
 ('POST', r'/api/v51/crypto/(encrypt|decrypt)', ('Admin','Analyst','Operator','Viewer')),
 ('POST', r'/api/v51/password-strength', ('Admin','Analyst','Operator','Viewer')),
 ('POST', r'/api/v51/tls/check', ('Admin','Analyst','Operator')),
 ('POST', r'/api/v51/auth/mfa/reset/\d+', ('Admin',)),
 ('POST', r'/api/v51/alerts/\d+/ack', ('Admin','Analyst','Operator')),
 ('POST', r'/api/v51/alerts/\d+/(resolve|reopen)', ('Admin','Analyst')),
 ('POST', r'/api/v51/vault', ('Admin',)),
 ('POST', r'/api/v51/vault/\d+/reveal', ('Admin',)),
 ('DELETE', r'/api/v51/vault/\d+', ('Admin',)),
 # v5.3 Compliance / approval-only response workflow.
 ('PATCH', r'/api/v51/compliance/\d+', ('Admin','Analyst')),
 ('POST', r'/api/v51/playbooks', ('Admin','Analyst','Operator')),
 ('POST', r'/api/v51/playbooks/\d+/approve', ('Admin',)),
 ('POST', r'/api/v51/playbooks/\d+/cancel', ('Admin','Analyst')),
 # v5.4 defensive IOC watchlist and custom SIEM detection rules.
 ('POST', r'/api/v54/threat/iocs', ('Admin','Analyst')),
 ('POST', r'/api/v54/threat/iocs/\d+/toggle', ('Admin','Analyst')),
 ('DELETE', r'/api/v54/threat/iocs/\d+', ('Admin',)),
 ('POST', r'/api/v54/detection-rules', ('Admin','Analyst')),
 ('POST', r'/api/v54/detection-rules/\d+/toggle', ('Admin','Analyst')),
 ('DELETE', r'/api/v54/detection-rules/\d+', ('Admin',)),
 # v5.5 enterprise SOC case workflow.
 ('POST', r'/api/v55/cases', ('Admin','Analyst')),
 ('PATCH', r'/api/v55/cases/\d+', ('Admin','Analyst')),
 ('POST', r'/api/v55/cases/\d+/notes', ('Admin','Analyst','Operator')),
 ('POST', r'/api/v55/cases/\d+/alerts', ('Admin','Analyst','Operator')),
 # v5.6 enterprise notifications and report snapshots.
 ('POST', r'/api/v56/notifications/test', ('Admin',)),
 ('POST', r'/api/v56/alerts/\d+/notify', ('Admin','Analyst')),
 ('POST', r'/api/v56/reports/snapshots', ('Admin','Analyst')),
 # v5.7 daily security operations checklist.
 ('POST', r'/api/v57/daily/reviewed', ('Admin','Analyst','Operator')),
 # v5.9 network quality and explicit bandwidth diagnostics.
 ('POST', r'/api/v59/network/line-test', ('Admin','Analyst','Operator')),
 ('POST', r'/api/v59/network/speed-test', ('Admin','Analyst','Operator')),
 ('POST', r'/api/v59/network/optimize', ('Admin',)),
 ('POST', r'/api/v59/browser/upload', ('Admin','Analyst','Operator')),
 ('POST', r'/api/v59/browser/report', ('Admin','Analyst','Operator')),
 # v6.3 Kali defensive worker. Uses the same cookie session + central CSRF/RBAC guard.
 ('POST', r'/api/v1/kali/config', ('Admin',)),
 ('POST', r'/api/v1/kali/test', ('Admin','Operator')),
 ('POST', r'/api/v1/kali/run', ('Admin','Operator')),
]

def digest(value: str):
    return hashlib.sha256(value.encode()).hexdigest()

def ensure_tables():
    with connection() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS web_sessions37(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,password_stamp TEXT NOT NULL,csrf TEXT NOT NULL,issued REAL NOT NULL,last_used REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS web_login_attempts37(id INTEGER PRIMARY KEY,username TEXT,peer TEXT,success INTEGER,at REAL);
        CREATE INDEX IF NOT EXISTS ix_web_login_attempts_time ON web_login_attempts37(at);
        CREATE TABLE IF NOT EXISTS web_security_log37(id INTEGER PRIMARY KEY,actor TEXT,method TEXT,path TEXT,status INTEGER,request_id TEXT,created_at TEXT);
        CREATE TABLE IF NOT EXISTS web_mfa_challenges51(
            token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,purpose TEXT NOT NULL,issued REAL NOT NULL,expires REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS web_security_policy51(
            id INTEGER PRIMARY KEY CHECK(id=1),mfa_required INTEGER NOT NULL DEFAULT 1,updated_at TEXT
        );
        ''')
        # Additive migration for MFA state; secrets are encrypted with the existing credential vault key.
        cols={r['name'] for r in c.execute('PRAGMA table_info(app_users)').fetchall()}
        if 'mfa_enabled' not in cols: c.execute('ALTER TABLE app_users ADD COLUMN mfa_enabled INTEGER DEFAULT 0')
        if 'mfa_secret_enc' not in cols: c.execute('ALTER TABLE app_users ADD COLUMN mfa_secret_enc TEXT DEFAULT NULL')
        if 'mfa_updated_at' not in cols: c.execute('ALTER TABLE app_users ADD COLUMN mfa_updated_at TEXT DEFAULT NULL')
        default_mfa = 0 if os.environ.get('NA_MFA_REQUIRED','1') == '0' else 1
        c.execute("INSERT OR IGNORE INTO web_security_policy51(id,mfa_required,updated_at) VALUES(1,?,datetime('now'))",(default_mfa,))

def public_user(row):
    out={k:row[k] for k in ('id','username','role','enabled')}
    try: out['mfa_enabled']=bool(row['mfa_enabled'])
    except Exception: out['mfa_enabled']=False
    return out

def _session_tokens(request: Request):
    """Return every candidate session cookie in wire order.

    Older local builds sometimes left more than one na_session cookie in the
    browser after update/recovery.  Starlette's parsed cookie dict keeps only
    one value, so a stale duplicate could make a freshly issued valid session
    look logged out immediately.  Local Web accepts the first valid candidate
    and ignores malformed/stale duplicates.
    """
    values=[]
    raw=request.headers.get('cookie','') or ''
    for item in raw.split(';'):
        name,sep,value=item.strip().partition('=')
        if sep and name==COOKIE and value and len(value)<=256 and value not in values:
            values.append(value)
    parsed=request.cookies.get(COOKIE,'')
    if parsed and len(parsed)<=256 and parsed not in values:
        values.append(parsed)
    return values

def session(request: Request):
    tokens=_session_tokens(request)
    if not tokens: return None
    now = time.time()
    with connection() as c:
        for token in tokens:
            r = c.execute('''SELECT s.*,u.username,u.role,u.enabled,u.password_hash,COALESCE(u.mfa_enabled,0) mfa_enabled FROM web_sessions37 s
                             JOIN app_users u ON u.id=s.user_id WHERE s.token_hash=?''',(digest(token),)).fetchone()
            if not r:
                continue
            if not r['enabled'] or now-r['issued']>ABSOLUTE_TTL or now-r['last_used']>IDLE_TTL or not secrets.compare_digest(r['password_stamp'],digest(r['password_hash'])):
                c.execute('DELETE FROM web_sessions37 WHERE token_hash=?',(digest(token),))
                continue
            if now-r['last_used']>30: c.execute('UPDATE web_sessions37 SET last_used=? WHERE token_hash=?',(now,digest(token)))
            return {'id':r['user_id'],'username':r['username'],'role':r['role'],'enabled':r['enabled'],'mfa_enabled':bool(r['mfa_enabled']),'csrf_token':r['csrf']}
    return None

def require_role(request: Request, *roles):
    u=getattr(request.state,'user',None) or session(request)
    if not u: raise HTTPException(401,'LOGIN_REQUIRED')
    if roles and u['role'] not in roles: raise HTTPException(403,'PERMISSION_DENIED')
    return u

def _totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')


def _totp(secret: str, counter: int, digits: int=6):
    key=base64.b32decode(secret + '=' * (-len(secret) % 8), casefold=True)
    msg=struct.pack('>Q',counter)
    d=hmac.new(key,msg,hashlib.sha1).digest(); off=d[-1]&0x0f
    num=struct.unpack('>I',d[off:off+4])[0]&0x7fffffff
    return str(num%(10**digits)).zfill(digits)


def _verify_totp(secret: str, code: str, window: int=1):
    code=''.join(ch for ch in str(code or '') if ch.isdigit())
    if len(code)!=6: return False
    counter=int(time.time())//30
    return any(hmac.compare_digest(_totp(secret,counter+i),code) for i in range(-window,window+1))


def _issue_mfa_challenge(c,user_id,purpose):
    token=secrets.token_urlsafe(32); now=time.time()
    c.execute('DELETE FROM web_mfa_challenges51 WHERE expires<?',(now,))
    c.execute('DELETE FROM web_mfa_challenges51 WHERE user_id=?',(int(user_id),))
    c.execute('INSERT INTO web_mfa_challenges51(token_hash,user_id,purpose,issued,expires) VALUES(?,?,?,?,?)',
              (digest(token),int(user_id),purpose,now,now+300))
    return token


def _is_loopback_request(request: Request) -> bool:
    """True only for the local browser path explicitly supported without TLS."""
    peer=(request.client.host if request.client else '').strip().lower()
    host=(request.url.hostname or '').strip().lower()
    loop={'127.0.0.1','::1','localhost'}
    if peer=='testclient':
        return True
    return peer in loop and host in loop


def _finish_login(c,row,request,response):
    now=time.time()
    for old in _session_tokens(request):
        c.execute('DELETE FROM web_sessions37 WHERE token_hash=?',(digest(old),))
    token=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(32)
    c.execute('DELETE FROM web_sessions37 WHERE issued<? OR last_used<?',(now-ABSOLUTE_TTL,now-IDLE_TTL))
    c.execute('INSERT INTO web_sessions37 VALUES(?,?,?,?,?,?)',(digest(token),row['id'],digest(row['password_hash']),csrf,now,now))
    # Loopback HTTP is intentionally supported for the local desktop UI.  Any
    # non-loopback deployment must use HTTPS, so a remotely usable session is
    # never issued as a non-Secure cookie.
    scheme=str(request.url.scheme).lower()
    if scheme!='https' and not _is_loopback_request(request):
        c.execute('DELETE FROM web_sessions37 WHERE token_hash=?',(digest(token),))
        raise HTTPException(403,'HTTPS_REQUIRED_FOR_REMOTE_SESSION')
    cookie_secure=(scheme=='https')
    response.set_cookie(COOKIE,token,httponly=True,secure=cookie_secure,samesite='strict',path='/',max_age=ABSOLUTE_TTL)
    return {'success':True,'user':public_user(row),'csrf_token':csrf}


def register(username: str, password: str, confirmation: str, request: Request):
    """Create a bounded self-service Viewer account."""
    from modules.nms_v5 import _hash_password
    from modules.accounts import _validate

    if os.environ.get('NA_PUBLIC_REGISTRATION', '0').strip().lower() not in ('1', 'true', 'yes', 'on'):
        raise HTTPException(403, 'REGISTRATION_DISABLED')
    username=(username or '').strip()
    if password != confirmation:
        raise HTTPException(400, 'PASSWORD_CONFIRMATION_MISMATCH')
    try:
        _validate(username, 'Viewer', password)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    if len(password) < 12:
        raise HTTPException(400, 'PASSWORD_TOO_SHORT')

    ensure_tables(); now=time.time(); peer=request.client.host if request.client else 'unknown'
    auto_enable=os.environ.get('NA_REGISTRATION_AUTO_ENABLE', '1').strip().lower() in ('1','true','yes','on')
    with connection() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS web_registration_attempts16j(
            id INTEGER PRIMARY KEY, peer TEXT NOT NULL, username TEXT NOT NULL, success INTEGER NOT NULL, at REAL NOT NULL
        )""")
        c.execute('CREATE INDEX IF NOT EXISTS ix_web_registration_attempts16j_time ON web_registration_attempts16j(at)')
        c.execute('DELETE FROM web_registration_attempts16j WHERE at<?',(now-86400,))
        attempts=c.execute('SELECT COUNT(*) FROM web_registration_attempts16j WHERE peer=? AND at>?',(peer,now-3600)).fetchone()[0]
        if attempts >= 5:
            raise HTTPException(429, 'REGISTRATION_RATE_LIMITED')
        existing=c.execute('SELECT id FROM app_users WHERE username=? COLLATE NOCASE LIMIT 1',(username,)).fetchone()
        if existing:
            c.execute('INSERT INTO web_registration_attempts16j(peer,username,success,at) VALUES(?,?,0,?)',(peer,username,now))
            c.commit()
            raise HTTPException(409, 'USERNAME_TAKEN')
        total=c.execute('SELECT COUNT(*) FROM app_users').fetchone()[0]
        if total >= 100:
            raise HTTPException(503, 'REGISTRATION_CAP_REACHED')
        stamp=utcnow()
        cur=c.execute("""INSERT INTO app_users(username,password_hash,role,enabled,created_at,updated_at)
                         VALUES(?,?,?,?,?,?)""",(username,_hash_password(password),'Viewer',1 if auto_enable else 0,stamp,stamp))
        c.execute('INSERT INTO web_registration_attempts16j(peer,username,success,at) VALUES(?,?,1,?)',(peer,username,now))
        try:
            c.execute('INSERT INTO auth_log(username,success,detail,created_at) VALUES(?,?,?,?)',
                      (username,1,'Tự đăng ký tài khoản Viewer',stamp))
        except Exception:
            pass
        c.commit()
        return {'success':True,'username':username,'role':'Viewer','enabled':bool(auto_enable),'user_id':cur.lastrowid}


def login(username: str,password: str,request: Request,response: Response):
    from modules.nms_v5 import _verify_password, _hash_password, encrypt_secret, decrypt_secret
    username=username.strip()
    if not 1<=len(username)<=64 or not 1<=len(password)<=256: raise HTTPException(401,'INVALID_CREDENTIALS')
    ensure_tables(); now=time.time(); peer=request.client.host if request.client else 'unknown'
    with connection() as c:
        c.execute('DELETE FROM web_login_attempts37 WHERE at<?',(now-86400,))
        n=c.execute('SELECT COUNT(*) FROM web_login_attempts37 WHERE at>? AND success=0 AND username=? COLLATE NOCASE',(now-900,username)).fetchone()[0]
        ipn=c.execute('SELECT COUNT(*) FROM web_login_attempts37 WHERE at>? AND peer=?',(now-60,peer)).fetchone()[0]
        if n>=5 or ipn>=30: raise HTTPException(429,'LOGIN_RATE_LIMITED; wait 15 minutes',headers={'Retry-After':'900'})
        # New builds prevent case-insensitive duplicates.  For legacy databases
        # that already contain both e.g. Alice/alice, exact-case login remains
        # usable so an Admin can repair the duplicate instead of locking both out.
        exact=c.execute('SELECT * FROM app_users WHERE username=? ORDER BY id',(username,)).fetchall()
        if len(exact)==1:
            r=exact[0]
        else:
            rows=c.execute('SELECT * FROM app_users WHERE username=? COLLATE NOCASE ORDER BY id',(username,)).fetchall()
            r=rows[0] if len(rows)==1 else None
        stored=r['password_hash'] if r else _DUMMY_HASH
        good=_verify_password(password,stored) and bool(r and r['enabled'])
        c.execute('INSERT INTO web_login_attempts37(username,peer,success,at) VALUES(?,?,?,?)',(username,peer,int(good),now))
        if not good:
            c.commit(); raise HTTPException(401,'INVALID_CREDENTIALS')
        # Transparent PBKDF2 -> Argon2id migration after a successful password check.
        if not str(r['password_hash']).startswith('$argon2'):
            upgraded=_hash_password(password)
            c.execute('UPDATE app_users SET password_hash=?,updated_at=datetime(\'now\') WHERE id=?',(upgraded,r['id']))
            r=c.execute('SELECT * FROM app_users WHERE id=?',(r['id'],)).fetchone()
        required=bool(c.execute('SELECT mfa_required FROM web_security_policy51 WHERE id=1').fetchone()[0])
        if bool(r['mfa_enabled']) and r['mfa_secret_enc']:
            challenge=_issue_mfa_challenge(c,r['id'],'VERIFY'); c.commit()
            return {'success':True,'mfa_required':True,'challenge':challenge,'user':{'username':r['username']}}
        if required:
            secret=_totp_secret()
            # Release the current SQLite write transaction before the credential vault
            # initializes its encryption key. A brand-new install may need to inspect
            # the DB while creating .credential.key, which must not deadlock this login.
            c.commit()
            encrypted_secret=encrypt_secret(secret)
            c.execute("UPDATE app_users SET mfa_secret_enc=?,mfa_enabled=0,mfa_updated_at=datetime('now') WHERE id=?",(encrypted_secret,r['id']))
            challenge=_issue_mfa_challenge(c,r['id'],'ENROLL'); c.commit()
            issuer=os.environ.get('NA_TOTP_ISSUER','NetworkAutomation Cybersecurity')
            from urllib.parse import quote
            uri=f'otpauth://totp/{quote(issuer)}:{quote(r["username"])}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30'
            return {'success':True,'mfa_enroll_required':True,'challenge':challenge,'secret':secret,'otpauth_uri':uri,'user':{'username':r['username']}}
        result=_finish_login(c,r,request,response); c.commit(); return result


def verify_mfa_login(challenge: str,code: str,request: Request,response: Response):
    from modules.nms_v5 import decrypt_secret
    ensure_tables(); now=time.time()
    with connection() as c:
        ch=c.execute('SELECT * FROM web_mfa_challenges51 WHERE token_hash=?',(digest(challenge or ''),)).fetchone()
        if not ch or float(ch['expires'])<now: raise HTTPException(401,'MFA_CHALLENGE_EXPIRED')
        r=c.execute('SELECT * FROM app_users WHERE id=?',(ch['user_id'],)).fetchone()
        if not r or not r['enabled'] or not r['mfa_secret_enc']: raise HTTPException(401,'MFA_NOT_AVAILABLE')
        try: secret=decrypt_secret(r['mfa_secret_enc'])
        except Exception as exc: raise HTTPException(500,'MFA_SECRET_UNAVAILABLE') from exc
        if not _verify_totp(secret,code): raise HTTPException(401,'INVALID_MFA_CODE')
        if ch['purpose']=='ENROLL':
            c.execute("UPDATE app_users SET mfa_enabled=1,mfa_updated_at=datetime('now') WHERE id=?",(r['id'],))
            r=c.execute('SELECT * FROM app_users WHERE id=?',(r['id'],)).fetchone()
        elif not r['mfa_enabled']:
            raise HTTPException(401,'MFA_DISABLED')
        c.execute('DELETE FROM web_mfa_challenges51 WHERE token_hash=?',(digest(challenge),))
        result=_finish_login(c,r,request,response); c.commit(); return result


def reset_mfa(user_id: int) -> bool:
    ensure_tables()
    with connection() as c:
        cur=c.execute("UPDATE app_users SET mfa_enabled=0,mfa_secret_enc=NULL,mfa_updated_at=datetime('now') WHERE id=?",(int(user_id),))
        if not cur.rowcount:
            return False
        c.execute('DELETE FROM web_sessions37 WHERE user_id=?',(int(user_id),))
        c.execute('DELETE FROM web_mfa_challenges51 WHERE user_id=?',(int(user_id),))
        c.commit()
        return True

# Constant-format PBKDF2 hash only for equal-cost failed verification; not an account.
_DUMMY_HASH='pbkdf2_sha256$240000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='

def logout(request:Request,response:Response):
    # Revoke every same-name cookie candidate.  Older builds could leave a stale
    # duplicate cookie beside the valid one; deleting only request.cookies[...] 
    # could revoke the wrong token while the real session stayed active.
    tokens=_session_tokens(request)
    with connection() as c:
        for token in tokens:
            c.execute('DELETE FROM web_sessions37 WHERE token_hash=?',(digest(token),))
    response.delete_cookie(COOKIE,path='/')
    return {'success':True}

def allowed_roles(method,path):
    if method in ('GET','HEAD'):
        if path.startswith(ADMIN_PREFIXES): return ('Admin',)
        if path.startswith(OPERATOR_GET): return ('Admin','Operator')
        return ('Admin','Analyst','Operator','Viewer')
    for methods,pattern,roles in WRITE_RULES:
        if re.fullmatch(methods,method) and re.fullmatch(pattern,path): return roles
    return ()

_RATE_LOCK = __import__('threading').Lock()
_RATE_BUCKETS = {}

def _rate_check(peer, method, path):
    # Lightweight in-process protection. Reverse-proxy/WAF rate limiting is still recommended for remote deployment.
    # Test/offline QA may explicitly disable this with NA_API_RATE_LIMIT=0.
    if os.environ.get('NA_API_RATE_LIMIT','1') == '0':
        return
    now=time.time(); window=60.0
    limit=int(os.environ.get('NA_API_READS_PER_MIN','600')) if method in ('GET','HEAD','OPTIONS') else int(os.environ.get('NA_API_WRITES_PER_MIN','180'))
    key=(peer, 'read' if method in ('GET','HEAD','OPTIONS') else 'write')
    with _RATE_LOCK:
        start,count=_RATE_BUCKETS.get(key,(now,0))
        if now-start>=window: start,count=now,0
        count+=1; _RATE_BUCKETS[key]=(start,count)
        if len(_RATE_BUCKETS)>4096:
            for k,(st,_) in list(_RATE_BUCKETS.items()):
                if now-st>120: _RATE_BUCKETS.pop(k,None)
    if count>limit: raise HTTPException(429,'API_RATE_LIMITED',headers={'Retry-After':'60'})

def install(app):
    @app.middleware('http')
    async def guard(request:Request,call_next):
        started=time.monotonic()
        request_id=secrets.token_hex(8); request.state.request_id=request_id
        path=request.url.path; user=None
        try:
            peer=request.client.host if request.client else 'unknown'
            _rate_check(peer,request.method,path)
            if '..' in path or '%2e%2e' in path.lower():
                raise HTTPException(404,'Static asset not found') if path.startswith('/static/') else HTTPException(400,'INVALID_PATH')
            if path.startswith('/api/') or path in ('/docs','/redoc','/openapi.json'):
                # Plain HTTP is supported only for the local desktop browser.
                # Remote sessions must use HTTPS; never downgrade a remote cookie
                # merely because the current request arrived over http://.
                if str(request.url.scheme).lower()!='https' and not _is_loopback_request(request):
                    raise HTTPException(403,'HTTPS_REQUIRED_FOR_REMOTE_SESSION')
                if request.method not in ('GET','HEAD','OPTIONS'):
                    origin=request.headers.get('origin')
                    if origin:
                        u=urlsplit(origin)
                        if u.scheme!=request.url.scheme or u.netloc!=request.url.netloc: raise HTTPException(403,'ORIGIN_REJECTED')
                    if request.headers.get('sec-fetch-site')=='cross-site': raise HTTPException(403,'ORIGIN_REJECTED')
                if path not in PUBLIC:
                    user=session(request)
                    if not user: raise HTTPException(401,'LOGIN_REQUIRED')
                    request.state.user=user
                    roles=allowed_roles(request.method,path)
                    if user['role'] not in roles: raise HTTPException(403,'PERMISSION_DENIED')
                    if request.method not in ('GET','HEAD','OPTIONS'):
                        if not secrets.compare_digest(request.headers.get('x-csrf-token',''),user['csrf_token']): raise HTTPException(403,'CSRF_REJECTED')
                if request.method in ('POST','PUT','PATCH'):
                    length=request.headers.get('content-length','0')
                    limit = 12*1024*1024 if path in ('/api/v45/autoip/import','/api/v45/inventory/import','/api/v45/ping/import') else 1024*1024 if path in ('/api/v45/autoip/targets','/api/v45/ping/targets') else 65536
                    if not length.isdigit() or int(length)>limit: raise HTTPException(413,'REQUEST_TOO_LARGE')
                    if len(await request.body())>limit: raise HTTPException(413,'REQUEST_TOO_LARGE')
                    # No forms accepted by a JSON API, including login CSRF.
                    if int(length)>0 and request.headers.get('content-type','').split(';')[0]!='application/json': raise HTTPException(415,'JSON_REQUIRED')
            response=await call_next(request)
        except HTTPException as e:
            response=JSONResponse({'detail':e.detail,'request_id':request_id},status_code=e.status_code,headers=e.headers)
        except Exception as e:
            # Log only exception type / correlation id, not credentials or SQL values.
            logging.getLogger('web.security').error('request=%s type=%s',request_id,type(e).__name__)
            response=JSONResponse({'detail':'INTERNAL_ERROR; check local logs','request_id':request_id},status_code=500)
        security_headers={
            'X-Request-ID':request_id,
            'X-Content-Type-Options':'nosniff',
            'X-Frame-Options':'DENY',
            'Referrer-Policy':'no-referrer',
            'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
            'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        }
        # HSTS is meaningful only on HTTPS. Render/Uvicorn proxy headers restore
        # request.url.scheme=https from X-Forwarded-Proto at the edge.
        if str(request.url.scheme).lower()=='https':
            security_headers['Strict-Transport-Security']='max-age=31536000; includeSubDomains'
        # Sensitive HTML/API responses are never cached. Versioned static assets
        # may be cached aggressively because the query-string version changes on release.
        if path.startswith('/static/') and 200 <= response.status_code < 400:
            if request.query_params.get('v'):
                security_headers['Cache-Control']='public, max-age=31536000, immutable'
            else:
                security_headers['Cache-Control']='public, max-age=3600'
        else:
            security_headers['Cache-Control']='no-store'
        response.headers.update(security_headers)
        if path.startswith('/api/') and request.method not in ('GET','HEAD','OPTIONS'):
            try:
                with connection() as c:
                    c.execute('INSERT INTO web_security_log37(actor,method,path,status,request_id,created_at) VALUES(?,?,?,?,?,?)',((user or {}).get('username','anonymous'),request.method,path[:200],response.status_code,request_id,utcnow()))
            except Exception: pass
        try:
            from webapi.operations47 import record_request
            record_request(request,response,time.monotonic()-started)
        except Exception:
            pass
        return response
