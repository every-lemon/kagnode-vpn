"""Root-broker authentication and authorization. No third-party crypto dependency."""
import base64
import hashlib
import hmac
import re
import secrets
import struct
import threading
from urllib.parse import quote

HASH_SLOTS = threading.BoundedSemaphore(2)
ROLES = ('owner', 'operator', 'auditor')
OWNER_ACTIONS = frozenset(('admin-add', 'admin-disable', 'admin-role', 'admin-device', 'access-save', 'maintenance-save', 'reboot', 'update', 'system-repair'))
OPERATOR_ACTIONS = frozenset(('user-add', 'device-add', 'rename', 'assign', 'protocol-add', 'protocols-add', 'policy', 'bundle', 'delivery-password', 'delivery-link', 'prepare-export', 'export', 'reveal', 'link', 'revoke', 'replace', 'user-revoke', 'rotate-l2tp', 'repair', 'copy', 'clear-history', 'delete-profile', 'batch-preview', 'batch-confirm', 'batch-run', 'batch-cancel', 'batch-retry', 'job-retry', 'group-add', 'group-save', 'group-delete', 'device-group', 'resource-save', 'resource-delete', 'access-policy', 'group-rule', 'device-rule', 'identity-state', 'policy-preview', 'delivery-revoke', 'delivery-reissue'))

class AuthError(RuntimeError):
    pass

def key(value):
    return hashlib.sha256(value.encode()).hexdigest()

def totp(secret, counter):
    raw = base64.b32decode(secret + '=' * (-len(secret) % 8))
    digest = hmac.new(raw, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return str((struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)

def password_hash(password, salt=None):
    if not isinstance(password, str) or not 12 <= len(password) <= 256:
        raise AuthError('Use a password between 12 and 256 characters.')
    salt = salt or secrets.token_hex(16)
    if not HASH_SLOTS.acquire(blocking=False):
        raise AuthError('Authentication busy; retry shortly.')
    try:
        result = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
        return salt + ':' + result
    finally:
        HASH_SLOTS.release()

def permitted(role, action):
    return (role == 'owner' and action in OWNER_ACTIONS | OPERATOR_ACTIONS) or (role == 'operator' and action in OPERATOR_ACTIONS)

class Authentication:
    def init_auth(self):
        with self.connect() as db:
            db.executescript('''BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS administrators(id TEXT PRIMARY KEY,username TEXT NOT NULL UNIQUE COLLATE NOCASE,password TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('owner','operator','auditor')),enabled INTEGER NOT NULL DEFAULT 1,totp TEXT NOT NULL,enrolled INTEGER NOT NULL DEFAULT 0,last_counter INTEGER NOT NULL DEFAULT -1,revision INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS admin_recovery(admin TEXT NOT NULL REFERENCES administrators(id),hash TEXT NOT NULL UNIQUE,PRIMARY KEY(admin,hash));
CREATE TABLE IF NOT EXISTS admin_sessions(hash TEXT PRIMARY KEY,admin TEXT NOT NULL REFERENCES administrators(id),csrf TEXT NOT NULL,created REAL NOT NULL,seen REAL NOT NULL,boot TEXT NOT NULL,revision INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS enrollment(hash TEXT PRIMARY KEY,admin TEXT NOT NULL REFERENCES administrators(id),expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS auth_events(id INTEGER PRIMARY KEY,time REAL NOT NULL,actor TEXT NOT NULL,event TEXT NOT NULL,target TEXT NOT NULL);
''')

    def auth_event(self, db, actor, event, target=''):
        db.execute('INSERT INTO auth_events(time,actor,event,target) VALUES (?,?,?,?)', (self.clock(), actor, event, target))

    def create_admin(self, username, password, role='operator', actor='console-bootstrap'):
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{2,39}', username) or role not in ROLES:
            raise AuthError('Use a 3–40 character username and a supported role.')
        hashed = password_hash(password)  # Never hash while holding SQLite's writer lock.
        ident, secret, token = secrets.token_hex(16), base64.b32encode(secrets.token_bytes(20)).decode().rstrip('='), secrets.token_urlsafe(48)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if actor not in ('console-bootstrap','console-recovery'):
                row = db.execute('SELECT role,enabled,enrolled FROM administrators WHERE id=?', (actor,)).fetchone()
                if not row or row != ('owner', 1, 1):
                    raise AuthError('Owner authorization required.')
            elif actor=='console-bootstrap' and db.execute('SELECT 1 FROM administrators WHERE enabled=1 AND enrolled=1').fetchone():
                raise AuthError('Bootstrap is already complete. Use an owner account or explicit console recovery.')
            db.execute('INSERT INTO administrators(id,username,password,role,totp) VALUES (?,?,?,?,?)', (ident, username, hashed, role, secret))
            db.execute('INSERT INTO enrollment VALUES (?,?,?)', (key(token), ident, self.clock() + 900))
            self.auth_event(db, actor, 'admin-created', ident)
        return {'id': ident, 'enrollment': token, 'secret': secret,
                'uri': 'otpauth://totp/' + quote('VPN:' + username) + '?secret=' + secret + '&issuer=VPN&algorithm=SHA1&digits=6&period=30'}

    def resume_enrollment(self, username, password):
        with self.connect() as db:
            row=db.execute('SELECT id,password,totp FROM administrators WHERE username=? AND enabled=1 AND enrolled=0',(username,)).fetchone()
        if not row or not hmac.compare_digest(password_hash(password,row[1].split(':')[0]),row[1]):
            raise AuthError('Pending enrollment not found or password incorrect.')
        token=secrets.token_urlsafe(48)
        with self.connect() as db:
            db.execute('DELETE FROM enrollment WHERE admin=?',(row[0],))
            db.execute('INSERT INTO enrollment VALUES (?,?,?)',(key(token),row[0],self.clock()+900))
        return {'id':row[0],'enrollment':token,'secret':row[2]}

    def enroll(self, token, code):
        with self.connect() as db:
            peer='enroll:'+key(token)
            db.execute('DELETE FROM login_failures WHERE time<?',(self.clock()-300,))
            if db.execute('SELECT count(*) FROM login_failures WHERE peer=?',(peer,)).fetchone()[0]>=5: raise AuthError('Enrollment temporarily limited; retry in five minutes.')
            db.execute('INSERT INTO login_failures VALUES (?,?)',(peer,self.clock()))
        codes = [secrets.token_hex(10) for _ in range(10)]
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT a.id,a.totp FROM enrollment e JOIN administrators a ON a.id=e.admin WHERE e.hash=? AND e.expires>? AND a.enabled=1 AND a.enrolled=0', (key(token), self.clock())).fetchone()
            counter = int(self.clock() // 30)
            matched = next((n for n in range(max(0,counter-1),counter+2) if row and hmac.compare_digest(totp(row[1], n), str(code))), None)
            if matched is None:
                raise AuthError('Enrollment expired or authenticator code incorrect.')
            db.execute('UPDATE administrators SET enrolled=1,last_counter=? WHERE id=?', (matched, row[0]))
            db.execute('DELETE FROM enrollment WHERE admin=?', (row[0],))
            db.executemany('INSERT INTO admin_recovery VALUES (?,?)', [(row[0], key(c)) for c in codes])
            db.execute('DELETE FROM login_failures WHERE peer=?',(peer,))
            self.auth_event(db, row[0], 'mfa-enrolled')
        return codes

    def has_password(self):
        with self.connect() as db:
            return db.execute('SELECT 1 FROM administrators WHERE enabled=1 AND enrolled=1').fetchone() is not None

    def set_password(self, password):
        raise AuthError('Use administrator enrollment; password-only accounts are not supported.')

    def open_window(self):
        if not self.has_password():
            raise AuthError('Enroll the first owner from the console first.')
        # Compatibility entrypoint: service availability no longer controls sessions.

    def close_window(self):
        with self.connect() as db:
            db.execute('DELETE FROM admin_sessions')

    def login(self, password, peer='local', username='', code=''):
        if not isinstance(password, str) or not 12 <= len(password) <= 256 or len(str(code)) > 128:
            raise AuthError('Login failed or temporarily limited.')
        now = self.clock()
        with self.connect() as db:
            db.execute('DELETE FROM login_failures WHERE time<?', (now - 300,))
            total, source = db.execute('SELECT count(*),coalesce(sum(peer=?),0) FROM login_failures', (peer,)).fetchone()
            row = db.execute('SELECT id,password,totp,enrolled,enabled,revision FROM administrators WHERE username=? COLLATE NOCASE', (username,)).fetchone()
        if total >= 20 or source >= 5:
            raise AuthError('Login temporarily limited. Retry in five minutes.')
        # Same cost for unknown usernames; a bounded semaphore limits memory/work.
        expected = row[1] if row else ('0' * 32 + ':' + '0' * 128)
        actual = password_hash(password, expected.split(':')[0])
        good_password = hmac.compare_digest(actual, expected)
        success = False
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            current = db.execute('SELECT enabled,enrolled,revision,last_counter FROM administrators WHERE id=?', (row[0],)).fetchone() if row else None
            if good_password and current and current[:3] == (1, 1, row[5]):
                counter = int(now // 30)
                matched = next((n for n in range(max(0, counter-1), counter+2) if n > current[3] and hmac.compare_digest(totp(row[2], n), str(code))), None)
                recovery = db.execute('DELETE FROM admin_recovery WHERE admin=? AND hash=?', (row[0], key(str(code)))).rowcount if matched is None else 0
                if matched is not None or recovery:
                    if matched is not None:
                        db.execute('UPDATE administrators SET last_counter=? WHERE id=?', (matched, row[0]))
                    success = True
                    session, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
                    db.execute('DELETE FROM admin_sessions WHERE boot!=? OR created<? OR seen<?', (self.boot, self.monotonic()-28800, self.monotonic()-1800))
                    db.execute('INSERT INTO admin_sessions VALUES (?,?,?,?,?,?,?)', (key(session), row[0], csrf, self.monotonic(), self.monotonic(), self.boot, row[5]))
                    db.execute('DELETE FROM login_failures WHERE peer=?', (peer,))
                    self.auth_event(db, row[0], 'login-recovery' if recovery else 'login')
            if not success:
                db.execute('INSERT INTO login_failures VALUES (?,?)', (peer, now))
        if not success:
            raise AuthError('Login failed or temporarily limited.')
        return session, csrf

    def identity(self, value, csrf=None, touch=False):
        with self.connect() as db:
            row = db.execute('SELECT a.id,a.username,a.role,a.enabled,a.enrolled,a.revision,s.csrf,s.created,s.seen,s.boot,s.revision FROM admin_sessions s JOIN administrators a ON a.id=s.admin WHERE s.hash=?', (key(value),)).fetchone()
            now = self.monotonic()
            if not row or row[3:5] != (1,1) or row[5] != row[10] or row[9] != self.boot or now-row[7] >= 28800 or now-row[8] >= 1800:
                raise AuthError('Session expired. Sign in again.')
            if csrf is not None and not hmac.compare_digest(row[6], str(csrf)):
                raise AuthError('Invalid form authorization.')
            if touch:
                db.execute('UPDATE admin_sessions SET seen=? WHERE hash=?', (now, key(value)))
        return {'id': row[0], 'username': row[1], 'role': row[2], 'csrf': row[6], 'remaining': max(0, min(row[7]+28800, (now if touch else row[8])+1800)-now)}

    def session(self, value, csrf=None):
        return self.identity(value, csrf)['csrf']

    def remaining(self, session):
        return self.identity(session)['remaining']

    def logout(self, session):
        with self.connect() as db:
            db.execute('DELETE FROM admin_sessions WHERE hash=?', (key(session),))

    def require_actor(self, actor, action):
        with self.connect() as db:
            row = db.execute('SELECT role,enabled,enrolled FROM administrators WHERE id=?', (actor,)).fetchone()
        if not row or row[1:] != (1,1) or not permitted(row[0], action):
            raise AuthError('Your role cannot perform this operation.')
        return row[0]

    def admin_change(self, actor, target, role=None, enabled=None):
        self.require_actor(actor, 'admin-role')
        if role is not None and role not in ROLES:
            raise AuthError('Invalid role.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT role,enabled,enrolled FROM administrators WHERE id=?', (target,)).fetchone()
            if not row:
                raise AuthError('Administrator not found.')
            next_role, next_enabled = role or row[0], row[1] if enabled is None else int(bool(enabled))
            owners = db.execute("SELECT count(*) FROM administrators WHERE role='owner' AND enabled=1 AND enrolled=1").fetchone()[0]
            if row == ('owner',1,1) and (next_role != 'owner' or not next_enabled) and owners <= 1:
                raise AuthError('Cannot remove the last enabled owner.')
            db.execute('UPDATE administrators SET role=?,enabled=?,revision=revision+1 WHERE id=?', (next_role,next_enabled,target))
            db.execute('DELETE FROM admin_sessions WHERE admin=?', (target,))
            self.auth_event(db, actor, 'admin-updated', target)
