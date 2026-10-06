from __future__ import annotations
import base64, hashlib, hmac, json, os, secrets, struct, time
from urllib.parse import quote
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from modules.nms_v5 import authenticate, encrypt_secret, decrypt_secret, ensure_v5_tables
from database.db import get_connection

ALGORITHM = 'HMAC-SHA256'
TOKEN_TTL = int(os.getenv('NA_ACCESS_TOKEN_TTL', '1800'))
COOKIE_NAME = os.getenv('NA_SESSION_COOKIE', 'na_session')
CSRF_COOKIE = os.getenv('NA_CSRF_COOKIE', 'na_csrf')
COOKIE_SECURE = os.getenv('NA_COOKIE_SECURE', '1') != '0'
ALLOW_BEARER = os.getenv('NA_ALLOW_BEARER', '1') != '0'
_bearer = HTTPBearer(auto_error=False)


def _secret() -> bytes:
    value = os.getenv('NA_API_SECRET', '')
    if len(value) < 32:
        raise RuntimeError('Set NA_API_SECRET to a random value of at least 32 characters before starting the API')
    return value.encode()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def _sign_payload(payload: dict) -> str:
    body = _b64(json.dumps(payload, separators=(',', ':'), sort_keys=True).encode())
    sig = _b64(hmac.new(_secret(), body.encode(), hashlib.sha256).digest())
    return body + '.' + sig


def _decode_signed(token: str) -> dict:
    try:
        body, sig = token.split('.', 1)
        expected = _b64(hmac.new(_secret(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            raise ValueError('signature')
        payload = json.loads(_unb64(body))
        if int(payload['exp']) < int(time.time()):
            raise ValueError('expired')
        return payload
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid or expired session') from exc


def create_access_token(user: dict) -> tuple[str, int]:
    now = int(time.time()); exp = now + TOKEN_TTL
    payload = {'sub': str(user['id']), 'username': user['username'], 'role': user['role'], 'iat': now, 'exp': exp, 'jti': secrets.token_hex(12), 'typ': 'access'}
    return _sign_payload(payload), exp


def decode_access_token(token: str) -> dict:
    payload = _decode_signed(token)
    if payload.get('typ') != 'access':
        raise HTTPException(status_code=401, detail='Invalid session type')
    return payload


def _ensure_mfa_columns() -> None:
    ensure_v5_tables(); c = get_connection()
    try:
        cols = {r['name'] for r in c.execute('PRAGMA table_info(app_users)').fetchall()}
        for name, ddl in [('mfa_enabled','INTEGER DEFAULT 0'),('mfa_secret_enc','TEXT DEFAULT NULL'),('mfa_updated_at','TEXT DEFAULT NULL')]:
            if name not in cols:
                c.execute(f'ALTER TABLE app_users ADD COLUMN {name} {ddl}')
        c.commit()
    finally:
        c.close()


def _load_user(user_id: int) -> dict:
    _ensure_mfa_columns(); c = get_connection()
    try:
        row = c.execute('SELECT id,username,role,enabled,COALESCE(mfa_enabled,0) mfa_enabled FROM app_users WHERE id=?', (int(user_id),)).fetchone()
    finally:
        c.close()
    if not row or not row['enabled']:
        raise HTTPException(status_code=401, detail='Account disabled or removed')
    return dict(row)


def set_session_cookies(response: Response, token: str) -> str:
    csrf = secrets.token_urlsafe(32)
    response.set_cookie(COOKIE_NAME, token, max_age=TOKEN_TTL, httponly=True, secure=COOKIE_SECURE, samesite='strict', path='/')
    response.set_cookie(CSRF_COOKIE, csrf, max_age=TOKEN_TTL, httponly=False, secure=COOKIE_SECURE, samesite='strict', path='/')
    return csrf


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path='/')
    response.delete_cookie(CSRF_COOKIE, path='/')


def _totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')


def _totp(secret: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret + '=' * (-len(secret) % 8), casefold=True)
    msg = struct.pack('>Q', counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    off = digest[-1] & 0x0f
    num = struct.unpack('>I', digest[off:off+4])[0] & 0x7fffffff
    return str(num % (10 ** digits)).zfill(digits)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    code = ''.join(ch for ch in str(code) if ch.isdigit())
    if len(code) != 6:
        return False
    counter = int(time.time()) // 30
    return any(hmac.compare_digest(_totp(secret, counter + drift), code) for drift in range(-window, window + 1))


def begin_login(username: str, password: str) -> dict:
    user = authenticate(username.strip(), password)
    if not user:
        raise HTTPException(status_code=401, detail='Invalid username or password')
    _ensure_mfa_columns(); c = get_connection()
    try:
        row = c.execute('SELECT COALESCE(mfa_enabled,0) mfa_enabled FROM app_users WHERE id=?',(user['id'],)).fetchone()
    finally:
        c.close()
    if row and row['mfa_enabled']:
        now = int(time.time())
        challenge = _sign_payload({'sub':str(user['id']),'username':user['username'],'role':user['role'],'iat':now,'exp':now+300,'typ':'mfa_challenge','jti':secrets.token_hex(12)})
        return {'mfa_required': True, 'challenge': challenge, 'user': {'username': user['username']}}
    token, exp = create_access_token(user)
    return {'mfa_required': False, 'token': token, 'expires_at': exp, 'user': user}


def complete_mfa_login(challenge: str, code: str) -> dict:
    payload = _decode_signed(challenge)
    if payload.get('typ') != 'mfa_challenge':
        raise HTTPException(401, 'Invalid MFA challenge')
    c = get_connection()
    try:
        row = c.execute('SELECT id,username,role,enabled,mfa_enabled,mfa_secret_enc FROM app_users WHERE id=?',(int(payload['sub']),)).fetchone()
    finally:
        c.close()
    if not row or not row['enabled'] or not row['mfa_enabled'] or not row['mfa_secret_enc']:
        raise HTTPException(401,'MFA is not available for this account')
    try:
        secret = decrypt_secret(row['mfa_secret_enc'])
    except Exception as exc:
        raise HTTPException(500,'Unable to read MFA secret') from exc
    if not verify_totp(secret, code):
        raise HTTPException(401,'Invalid verification code')
    user={k:row[k] for k in ('id','username','role','enabled')}
    token, exp = create_access_token(user)
    return {'token':token,'expires_at':exp,'user':user}


def setup_mfa(user: dict) -> dict:
    secret = _totp_secret()
    c=get_connection()
    try:
        c.execute('UPDATE app_users SET mfa_secret_enc=?,mfa_enabled=0,mfa_updated_at=datetime(\'now\') WHERE id=?',(encrypt_secret(secret),user['id'])); c.commit()
    finally:c.close()
    issuer=os.getenv('NA_TOTP_ISSUER','NetworkAutomation')
    uri=f'otpauth://totp/{quote(issuer)}:{quote(user["username"])}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30'
    return {'secret':secret,'otpauth_uri':uri,'note':'Verify one TOTP code before MFA is enabled.'}


def enable_mfa(user: dict, code: str) -> None:
    c=get_connection()
    try: row=c.execute('SELECT mfa_secret_enc FROM app_users WHERE id=?',(user['id'],)).fetchone()
    finally:c.close()
    if not row or not row['mfa_secret_enc']: raise HTTPException(400,'Run MFA setup first')
    if not verify_totp(decrypt_secret(row['mfa_secret_enc']),code): raise HTTPException(400,'Invalid verification code')
    c=get_connection()
    try:c.execute("UPDATE app_users SET mfa_enabled=1,mfa_updated_at=datetime('now') WHERE id=?",(user['id'],));c.commit()
    finally:c.close()


def disable_mfa(user: dict, code: str) -> None:
    c=get_connection()
    try: row=c.execute('SELECT mfa_secret_enc,mfa_enabled FROM app_users WHERE id=?',(user['id'],)).fetchone()
    finally:c.close()
    if not row or not row['mfa_enabled'] or not row['mfa_secret_enc']: return
    if not verify_totp(decrypt_secret(row['mfa_secret_enc']),code): raise HTTPException(400,'Invalid verification code')
    c=get_connection()
    try:c.execute("UPDATE app_users SET mfa_enabled=0,mfa_secret_enc=NULL,mfa_updated_at=datetime('now') WHERE id=?",(user['id'],));c.commit()
    finally:c.close()


def _token_from_request(request: Request, credentials: HTTPAuthorizationCredentials | None) -> tuple[str | None, str]:
    if ALLOW_BEARER and credentials:
        return credentials.credentials, 'bearer'
    token=request.cookies.get(COOKIE_NAME)
    return token, 'cookie'


def current_user(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> dict:
    token, auth_type = _token_from_request(request, credentials)
    if not token:
        raise HTTPException(status_code=401, detail='Authentication required')
    payload = decode_access_token(token)
    user = _load_user(int(payload['sub']))
    user['_auth_type'] = auth_type
    return user


def csrf_protect(request: Request, user=Depends(current_user)) -> dict:
    if user.get('_auth_type') == 'cookie' and request.method not in ('GET','HEAD','OPTIONS'):
        cookie=request.cookies.get(CSRF_COOKIE,'')
        header=request.headers.get('X-CSRF-Token','')
        if not cookie or not header or not hmac.compare_digest(cookie,header):
            raise HTTPException(status_code=403, detail='CSRF validation failed')
    return user


def require_roles(*roles):
    def dep(user=Depends(csrf_protect)):
        if user['role'] not in roles:
            raise HTTPException(status_code=403, detail='Insufficient role')
        return user
    return dep
