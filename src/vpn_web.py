"""Persistent delivery on 9000 and session-authenticated management on 9001."""
import base64
import contextlib
import concurrent.futures
import queue
import grp
import hashlib
import hmac
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import socketserver
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qs, urlencode, urlsplit

SOCKET = Path('/run/vpn/control.sock')
PUBLIC = Path('/var/lib/vpn/public')
ACCOUNT = 'vpn-web'
ADMIN_ACCOUNT = 'vpn-admin'
RPC_GROUP = 'vpn-rpc'
# Runtime dependencies are pinned by content hashes.
VENV = Path('/usr/lib/vpn/venv')
TMPFILES = Path('/etc/tmpfiles.d/vpn.conf')
TMPFILES_RULES = 'f /run/xtables.lock 0600 root root -\n'
MAX_RPC = 8 * 1024**2


from vpn_auth import AuthError as WebError


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


from vpn_auth import Authentication, AuthError, permitted


class Store(Authentication):
    def __init__(self, path, clock=time.time, monotonic=None, boot=None):
        self.path, self.clock = Path(path), clock
        self.monotonic = monotonic or (time.monotonic if clock is time.time else clock)
        self.boot = boot or Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connect() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY,device TEXT,filename TEXT,generation TEXT,expires REAL,used REAL);
CREATE TABLE IF NOT EXISTS delivery_revocations(hash TEXT PRIMARY KEY REFERENCES tokens(hash) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS token_manifests(hash TEXT PRIMARY KEY REFERENCES tokens(hash) ON DELETE CASCADE,data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,csrf TEXT,expires REAL);
CREATE TABLE IF NOT EXISTS login_failures(peer TEXT,time REAL);
CREATE TABLE IF NOT EXISTS flashes(session TEXT PRIMARY KEY,message TEXT NOT NULL,expires REAL NOT NULL);
''')
            db.execute('INSERT OR IGNORE INTO settings VALUES (?,?)', ('secret', secrets.token_hex(32)))
        self.path.chmod(0o600)
        self.init_auth()

    @contextlib.contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.execute('PRAGMA foreign_keys=ON')
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def flash(self, session, message=None):
        with self.connect() as db:
            db.execute('DELETE FROM flashes WHERE expires<=?', (self.monotonic(),))
            key = digest(session)
            if message is not None:
                db.execute('INSERT OR REPLACE INTO flashes VALUES (?,?,?)', (key, str(message)[:1000], self.monotonic()+60))
                return ''
            row = db.execute('SELECT message FROM flashes WHERE session=?', (key,)).fetchone()
            db.execute('DELETE FROM flashes WHERE session=?', (key,))
        return row[0] if row else ''

    def link_status(self, hashes=None):
        with self.connect() as db:
            if hashes is not None:
                if not hashes:
                    return []
                rows = db.execute('SELECT hash,expires,used FROM tokens WHERE hash IN (' + ','.join('?' for _ in hashes) + ')', tuple(hashes))
            else:
                rows = db.execute('SELECT hash,expires,used FROM tokens ORDER BY rowid DESC LIMIT 100')
            return [{'hash':key,'remaining':max(0,expires-self.clock()) if used is None else 0} for key,expires,used in rows]

    def issue(self, device, filename, generation, lifetime=900, manifest=None):
        if lifetime not in (900, 3600, 86400, 604800, 2592000):
            raise WebError('Choose a supported delivery lifetime.')
        token = secrets.token_urlsafe(48)
        with self.connect() as db:
            db.execute('INSERT INTO tokens VALUES (?,?,?,?,?,NULL)', (digest(token), device, filename, generation, self.clock() + lifetime))
            if manifest is not None:
                db.execute('INSERT INTO token_manifests VALUES (?,?)', (digest(token), json.dumps(manifest)))
        return token

    def inspect(self, token):
        if len(token) != 64 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in token):
            raise WebError('Invalid or expired download link.')
        with self.connect() as db:
            row = db.execute('SELECT device,filename,generation,expires,used FROM tokens WHERE hash=?', (digest(token),)).fetchone()
            secret = db.execute("SELECT v FROM settings WHERE k='secret'").fetchone()[0]
        if not row or row[3] <= self.clock() or row[4] is not None:
            raise WebError('This download link is expired or already used.')
        confirm = hmac.new(secret.encode(), token.encode(), hashlib.sha256).hexdigest()
        return {'device': row[0], 'filename': row[1], 'generation': row[2], 'confirm': confirm, 'expires': row[3], 'remaining': max(0, row[3] - self.clock())}

    def claim(self, token, confirm, guard=None):
        record = self.inspect(token)
        if not hmac.compare_digest(record['confirm'], confirm):
            raise WebError('Open the download page and press Download.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if guard:
                guard(db)
            used = db.execute('UPDATE tokens SET used=? WHERE hash=? AND used IS NULL AND expires>?',
                              (self.clock(), digest(token), self.clock())).rowcount
            if used != 1:
                raise WebError('This download link is expired or already used.')
        return record

    def token_history(self):
        with self.connect() as db:
            rows=db.execute('SELECT hash,device,expires,used FROM tokens ORDER BY rowid DESC LIMIT 100').fetchall()
            has_devices=db.execute("SELECT 1 FROM sqlite_master WHERE name='devices'").fetchone()
            result=[]
            for hashed,device,expires,used in rows:
                if has_devices:
                    record=db.execute('SELECT data FROM devices WHERE id=?',(device,)).fetchone()
                    if not record or json.loads(record[0]).get('deleted'): continue
                revoked=db.execute('SELECT 1 FROM delivery_revocations WHERE hash=?',(hashed,)).fetchone()
                result.append({'hash':hashed,'device':device,'expires':expires,'status':'revoked' if revoked else 'used' if used is not None else 'expired' if expires<=self.clock() else 'available'})
            return result

    def revoke_token(self, hashed):
        if not re.fullmatch(r'[a-f0-9]{64}',hashed): raise WebError('Invalid delivery reference.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT device FROM tokens WHERE hash=?',(hashed,)).fetchone()
            if not row: raise WebError('Delivery not found.')
            db.execute('UPDATE tokens SET used=coalesce(used,?) WHERE hash=?',(self.clock(),hashed))
            db.execute('INSERT OR IGNORE INTO delivery_revocations VALUES (?)',(hashed,))
            return row[0]

    def invalidate(self, device):
        with self.connect() as db:
            db.execute('UPDATE tokens SET used=? WHERE device=? AND used IS NULL', (self.clock(), device))


def rpc(request, path=SOCKET, timeout=5):
    wire = json.dumps(request).encode() + b'\n'
    if len(wire) > 65536:
        raise WebError('Request too large.')
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(timeout)
        connection.connect(str(path))
        connection.sendall(wire)
        with connection.makefile('rb') as stream:
            data = stream.readline(MAX_RPC + 1)
    if len(data) > MAX_RPC:
        raise WebError('Response too large.')
    if not data:
        raise ConnectionError('Backend is busy or disconnected; retry shortly.')
    try:
        result = json.loads(data)
    except ValueError:
        raise ConnectionError('Backend response was incomplete; retry shortly.') from None
    if result.get('busy'):
        raise ConnectionError('Backend busy; retry shortly.')
    if not result.get('ok'):
        raise WebError(result.get('error', 'Operation failed.'))
    return result['result']


class Controller:
    def __init__(self, backend, store=None):
        self.backend = backend
        self.store = store or Store(backend.repo.path)
        self.state = backend.m.load()
        self._health = None
        self._health_lock = threading.Lock()

    def health_snapshot(self):
        # One batched systemctl call at most per cache interval, shared across browsers.
        with self._health_lock:
            now = time.monotonic()
            if self._health and now - self._health['sample_monotonic'] < 15:
                return self._health
            services = ['AdGuardHome', 'ipsec', 'xl2tpd', 'wg-quick@wg0', 'vpn-control', 'vpn-downloads']
            try:
                result = self.backend.m.command(['systemctl', 'is-active', *services], check=False, timeout=3)
                states = result.stdout.splitlines()
            except (OSError, subprocess.TimeoutExpired):
                states = ['unavailable'] * len(services)
            memory = {}
            for line in Path('/proc/meminfo').read_text().splitlines():
                if line.startswith(('MemTotal:', 'MemAvailable:')):
                    key, value, *_ = line.split()
                    memory[key.rstrip(':')] = int(value) // 1024
            self._health = {'sample_monotonic': now, 'sampled_at': time.time(), 'memory': memory,
                            'services': dict(zip(services, states))}
            return self._health

    def claim_guard(self, db, record, manifest=None):
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name='protocols'").fetchone():
            return  # Small legacy adapters have no managed registry.
        if db.execute("SELECT 1 FROM jobs WHERE action='delete-profile' AND status IN ('queued','running','failed','interrupted') AND json_extract(form,'$.device')=? LIMIT 1", (record['device'],)).fetchone():
            raise WebError('Profile deletion is pending.')
        device=db.execute('SELECT user_id,data FROM devices WHERE id=?',(record['device'],)).fetchone()
        if not device:
            raise WebError('This device is unavailable.')
        parent=db.execute('SELECT data FROM users WHERE id=?',(device[0],)).fetchone()
        flags=json.loads(device[1]);owner=json.loads(parent[0]) if parent else {}
        from vpn_business import expired
        if expired(flags) or expired(owner) or (manifest and manifest.get('user')!=device[0]):
            raise WebError('This device or delivery is unavailable.')
        rows = {name:json.loads(raw) for name,raw in db.execute('SELECT name,data FROM protocols WHERE device_id=?',(record['device'],))}
        if manifest:
            for item in manifest['files']:
                current = rows.get(item['protocol'],{})
                if current.get('status')!='active' or current.get('backend')!=item['identity'] or (item['protocol']=='ikev2' and (current.get('export') or {}).get('generation')!=item['generation']):
                    raise WebError('Profiles changed or were revoked. Request a new token.')
        elif record['filename'].endswith('.zip'):
            row = db.execute('SELECT generation,data FROM deliveries WHERE device=?',(record['device'],)).fetchone()
            if not row or row[0]!=record['generation']:
                raise WebError('This delivery has changed.')
            for protocol,identity in json.loads(row[1])['identity'].items():
                current = rows.get(protocol,{})
                if current.get('status')!='active' or not identity.startswith(current.get('backend','')+':') and identity!=current.get('backend'):
                    raise WebError('This delivery was revoked.')
        else:
            current = rows.get('ikev2',{})
            if current.get('status')!='active' or (current.get('export') or {}).get('generation')!=record['generation']:
                raise WebError('This profile was revoked or superseded.')

    def admin_context(self, request):
        import vpn_access
        sanitized={k:v for k,v in request.items() if k!='_verified_vpn_device'}
        if self.state.get('admin_mode') in ('vpn','https') and self.state.get('admin_devices') and request.get('host')==self.state['lan']+':9001':
            import vpn_policy
            identities=vpn_policy.grants(self.backend,identities=True)
            sanitized['_verified_vpn_device']=any(ident in self.state['admin_devices'] and request.get('peer')==match[match.index('-s')+1] for ident,match in identities)
        try: vpn_access.context(self.state,sanitized)
        except ValueError as exc: raise WebError(str(exc)) from None

    def authorize(self, request, mutate=False):
        self.admin_context(request)
        identity = self.store.identity(request.get('session', ''), request.get('csrf', '') if mutate else None, touch=mutate or request.get('op') == 'view')
        if identity['role'] == 'auditor' and request.get('op') != 'logout' and (mutate or request.get('op') not in ('session-csrf', 'audit-view')):
            raise WebError('Auditors can access redacted status and audit history only.')
        return identity['csrf']

    def handle(self, request, uid):
        op = request.get('op')
        if op == 'ping':
            return {'ready': True}
        try:
            public_uid = pwd.getpwnam(ACCOUNT).pw_uid if uid != 0 else -1
        except KeyError:
            public_uid = -1
        if uid == public_uid and op not in ('inspect', 'claim'):
            raise WebError('Download worker is not authorized for management operations.')
        if op == 'policy-event':
            if uid != 0:
                raise WebError('Only root VPN hooks can report authenticated sessions.')
            import vpn_policy
            vpn_policy.event(self.backend, request.get('event', {}))
            return {'message': 'Session policy reconciled.'}
        if op == 'open':
            if uid != 0:
                raise WebError('Start management from the local TUI.')
            self.store.open_window()
            return {'url': 'http://' + self.state['lan'] + ':9001/manage'}
        if op=='close':
            raise WebError('Management stays online. Sign out to end your session.')
        if op == 'management-health':
            self.admin_context(request)
            return {'ready': True}
        if op == 'dashboard':
            self.authorize(request)
            targets = json.loads(request.get('targets', '[]'))
            if not isinstance(targets, list) or len(targets) > 50:
                raise WebError('Invalid policy status request.')
            for target in targets:
                if not isinstance(target, list) or len(target) != 2 or target[0] not in ('user', 'device') or not isinstance(target[1], str):
                    raise WebError('Invalid policy status target.')
            policies = self.backend.repo.policy_targets(targets) if targets else []
            view = request.get('view', 'overview')
            if view not in ('overview','devices','device','users','jobs','batches','delivery','system','search','groups','administrators','audit'):
                raise WebError('Invalid status view.')
            revision = self.backend.repo.status_revision()
            changed = request.get('since') != revision
            selectors = {}
            for name, limit in (('jobs',25),('batches',5),('links',10)):
                values = json.loads(request.get(name,'[]'))
                if not isinstance(values,list) or len(values)>limit or any(not isinstance(value,str) or not re.fullmatch(r'[a-f0-9]{64}' if name=='links' else r'[a-f0-9]{32}',value) for value in values):
                    raise WebError('Invalid status selector.')
                selectors[name] = values
            jobs = self.backend.repo.job_subset(selectors['jobs']) if changed else []
            batches = self.backend.repo.batch_subset(selectors['batches']) if changed and view == 'batches' else []
            progress = {}
            try:
                value = json.loads((self.backend.base / 'backend-job-health.json').read_text())
                if value.get('running'):
                    progress = {'job': value.get('job', ''), 'stage': value.get('stage', '')}
            except (OSError, ValueError):
                pass
            return {'remaining': self.store.remaining(request.get('session', '')), 'health': self.health_snapshot(), 'jobs': jobs, 'batches': batches, 'links': self.store.link_status(selectors['links']), 'policies': policies, 'progress': progress, 'revision': revision}
        if op == 'flash':
            self.authorize(request, mutate=True)
            self.store.flash(request.get('session',''), request.get('message',''))
            return {'ready':True}
        if op == 'session-csrf':
            return {'csrf': self.authorize(request)}
        if op in ('enroll-info','enroll-confirm'):
            self.admin_context(request)
            token=request.get('token','')
            if len(token)!=64: raise WebError('Invalid enrollment token.')
            if op=='enroll-confirm': return {'codes':self.store.enroll(token,request.get('code',''))}
            with self.store.connect() as db:
                row=db.execute('SELECT a.username,a.totp FROM enrollment e JOIN administrators a ON a.id=e.admin WHERE e.hash=? AND e.expires>? AND a.enabled=1 AND a.enrolled=0',(digest(token),self.store.clock())).fetchone()
            if not row: raise WebError('Enrollment expired or unavailable.')
            return {'username':row[0],'secret':row[1]}
        if op == 'login':
            self.admin_context(request)
            session, csrf = self.store.login(request.get('password', ''), request.get('peer', ''), request.get('username', ''), request.get('code', ''))
            return {'session': session, 'csrf': csrf}
        if op == 'logout':
            self.authorize(request, mutate=True)
            self.store.logout(request.get('session', ''))
            return {'closed': True}
        if op in ('inspect', 'claim'):
            token = request.get('token', '')
            record = self.store.inspect(token)
            if self.backend.repo.pending_delete(record['device']):
                raise WebError('Profile deletion is pending; this link is unavailable.')
            if record['filename'] == '@device':
                import vpn_portal
                try:
                    manifest = vpn_portal.inspect(self.backend, self.store, token, record)
                    if op == 'inspect':
                        return {'filename': '@device', 'device_name': manifest['name'], 'files': [{key:item[key] for key in ('filename','protocol','size')} for item in manifest['files']], 'confirm': record['confirm'], 'expires': record['expires'], 'remaining': record['remaining']}
                    path = vpn_portal.resolve(self.backend, manifest, request.get('filename', ''))
                except ValueError as exc:
                    raise WebError(str(exc)) from None
            elif record['filename'].endswith('.zip'):
                from vpn_backend import delivery_file
                path = delivery_file(self.backend, record['device'], record['generation'], record['filename'])
            else:
                reg, device = self.backend.device(record['device'])
                info = device['protocols'].get('ikev2', {})
                if info.get('status') != 'active' or not info.get('export') or info['export']['generation'] != record['generation']:
                    raise WebError('This export is no longer active. Request a new link.')
                path = self.backend.exported_file(record['device'], record['filename'])
                if path.suffix not in ('.p12', '.mobileconfig', '.sswan'):
                    raise WebError('This file cannot be downloaded publicly.')
            if request.get('filename') and request['filename'] != path.name:
                raise WebError('This file is not authorized by the token.')
            if op == 'inspect':
                return {'filename': path.name, 'size': path.stat().st_size, 'confirm': record['confirm'], 'expires': record['expires'], 'remaining': record['remaining']}
            # Resolve and read the validated inode before consumption; never return
            # an unvalidated replacement if files change while the claim commits.
            payload = path.read_bytes()
            if record['filename']=='@device':
                expected = next(item['sha256'] for item in manifest['files'] if item['filename']==path.name)
                if hashlib.sha256(payload).hexdigest()!=expected:
                    raise WebError('This prepared file changed. Request a new token.')
            if len(payload) > 5 * 1024**2 + 65536:
                raise WebError('Profile exceeds the delivery size limit.')
            self.store.claim(token, request.get('confirm', ''), guard=lambda db:self.claim_guard(db,record,manifest if record['filename']=='@device' else None))
            return {'filename': path.name, 'data': base64.b64encode(payload).decode()}
        if op == 'admin-file':
            self.authorize(request, mutate=True)
            from vpn_admin import attachment
            if self.backend.repo.pending_delete(request.get('form', {}).get('device', '')):
                raise WebError('Profile deletion is pending; downloads are unavailable.')
            with self.backend.m.lock():
                return attachment(self.backend, self.store, self.state, request.get('form', {}))
        if op == 'audit-view':
            self.authorize(request)
            with self.store.connect() as db:
                events = [dict(time=t,actor=a,event=e,target=v) for t,a,e,v in db.execute('SELECT time,actor,event,target FROM auth_events ORDER BY id DESC LIMIT 100')]
            return {'health': self.health_snapshot(), 'events': events}
        if op == 'view':
            self.admin_context(request)
            identity = self.store.identity(request.get('session',''),touch=True)
            csrf=identity['csrf']
            if identity['role']=='auditor' or request.get('view')=='audit':
                audit=self.handle(dict(request,op='audit-view'),uid)
                return {'identity':identity,'csrf':csrf,'registry':{'users':{},'devices':{}},'audit':audit}
            if request.get('view')=='administrators' and identity['role']!='owner':
                raise WebError('Owner access required.')
            diagnostic = None
            try:
                diagnostic = json.loads((self.backend.base / 'logs/client-tool-failure-latest.json').read_text())
            except (AttributeError, OSError, ValueError):
                pass
            view = request.get('view', 'overview')
            if view not in ('overview','devices','device','users','jobs','batches','delivery','system','search','groups','administrators','audit'):
                raise WebError('Management page not found.')
            pagination = {}
            if request.get('view') and hasattr(self.backend.repo, 'view_registry'):
                lookup_view = 'devices' if view == 'search' else view
                registry, pagination = self.backend.repo.view_registry(lookup_view, request.get('device', ''), request.get('q',''), request.get('owner',''), request.get('page',1), request.get('owner_q',''))
            else:
                registry = self.backend.load()
            deliveries = []
            if registry['devices']:
                with self.backend.repo.connect() as db:
                    marks = ','.join('?' for _ in registry['devices'])
                    rows = db.execute('SELECT device,data FROM deliveries WHERE device IN (' + marks + ')', tuple(registry['devices'])).fetchall()
                for ident, raw in rows:
                    item = registry['devices'][ident]
                    valid = True
                    for protocol, identity in json.loads(raw).get('identity', {}).items():
                        value = item.get('protocols', {}).get(protocol, {})
                        expected = value.get('backend','') + ':' + (value.get('export') or {}).get('generation','')
                        if value.get('status') != 'active' or (protocol == 'ikev2' and identity != expected):
                            valid = False
                    if valid:
                        deliveries.append(ident)
            hardening = {}
            if view == 'system':
                try:
                    hardening = json.loads((self.backend.base / 'hardening.json').read_text())
                except (AttributeError, OSError, ValueError):
                    pass
            page_number = pagination.get('page', max(1, int(request.get('page',1))))
            jobs = self.backend.repo.jobs(limit=25 if view in ('jobs','device') else 8, offset=(page_number-1)*25 if view == 'jobs' else 0, device=request.get('device') or None) if hasattr(self.backend.repo,'view_registry') else self.backend.repo.jobs()
            from vpn_business import Business
            business=Business(self.backend.repo)
            values=business.snapshot()
            extra={'identity':identity,'business':{k:values[k] for k in ('groups','resources','members')}}
            if view=='administrators':
                with self.store.connect() as db:
                    extra['administrators']=[dict(id=i,username=n,role=r,enabled=bool(en),enrolled=bool(mfa)) for i,n,r,en,mfa in db.execute('SELECT id,username,role,enabled,enrolled FROM administrators ORDER BY username LIMIT 200')]
            if view=='device' and request.get('device') in registry['devices']:
                extra['effective']=business.effective(registry,request['device'],values)
            if view=='system':
                from vpn_maintenance import Coordinator
                extra['maintenance']=Coordinator(self.backend.m).status()
                extra['access']={k:self.state.get(k,'') for k in ('admin_mode','admin_origin','trusted_proxy','vpd_origin')}
                task=self.backend.base/'system-task.json'
                if task.exists():
                    item=json.loads(task.read_text());extra['system_task']={k:item[k] for k in ('status','created','started','finished','result') if k in item}
            if view=='delivery': extra['tokens']=self.store.token_history()
            return {**extra, 'registry': registry, 'csrf': csrf, 'jobs': jobs, 'diagnostic': diagnostic if view in ('system','device','jobs') else None,
                    'deliveries': deliveries, 'hardening': hardening, 'remaining': self.store.remaining(request.get('session','')),
                    'batches': self.backend.repo.batches(limit=5, offset=(page_number-1)*5) if view == 'batches' else [], 'pagination': pagination, 'flash': self.store.flash(request.get('session',''))}

        if op == 'action':
            self.authorize(request, mutate=True)
            form = {k:v for k,v in request.get('form', {}).items() if not k.startswith('_') and k != 'actor'}
            actor = self.store.identity(request.get('session', ''))['id']
            self.store.require_actor(actor, form.get('action', ''))
            form['actor'] = actor
            if form.get('device') and self.backend.repo.pending_delete(form['device']) and form.get('action') not in ('delete-profile', 'job-retry'):
                raise WebError('Deletion is pending. Complete or retry deletion before changing this device.')
            if form.get('action') == 'export':
                _, item = self.backend.device(form.get('device', ''))
                if item['protocols'].get('ikev2', {}).get('status') != 'active':
                    raise WebError('Add an active IKEv2 protocol before exporting IKEv2. WireGuard and L2TP profiles can be downloaded from the device page.')
            if form.get('action') in ('prepare-export', 'protocol-add', 'protocols-add', 'export', 'replace', 'revoke', 'user-revoke', 'rotate-l2tp', 'bundle', 'repair', 'policy', 'batch-run', 'delete-profile'):
                if form.get('action') == 'delete-profile':
                    if form.get('confirm') != 'DELETE':
                        raise WebError('Type DELETE to revoke and delete this profile.')
                    _, target = self.backend.device(form.get('device', ''))
                    if form.get('protocol', 'all') != 'all' and form.get('protocol') not in target['protocols']:
                        raise WebError('Select an existing protocol profile.')
                    self.store.invalidate(form['device'])
                ident = self.backend.repo.enqueue(form)
                return {'message': 'Job queued: ' + ident + '. Refresh to see its result.'}
            if form.get('action') == 'batch-cancel':
                self.backend.repo.batch_cancel(form.get('batch', ''))
                return {'message': 'Cancellation requested. The current operation will finish safely.'}
            if form.get('action') in ('maintenance-save','reboot','system-repair','access-save','update'):
                return self.action(form)
            with self.backend.m.lock():
                return self.action(form)
        raise WebError('Unsupported operation.')

    def disconnect_expired(self, registry=None):
        from vpn_business import expired
        from vpn_backend import disconnect_profile
        registry=registry or self.backend.load()
        for ident, device in registry['devices'].items():
            if expired(device) or expired(registry['users'][device['user']]):
                self.store.invalidate(ident)
                for protocol, record in device.get('protocols',{}).items():
                    if record.get('status')=='active':
                        if protocol=='wireguard':
                            entry=self.backend.m.load().get('clients',{}).get(record['backend'],{}).get('wireguard',{})
                            public=entry.get('public') or entry.get('public_key')
                            if public:
                                self.backend.m.command(['wg','set','wg0','peer',public,'remove'])
                        else:
                            disconnect_profile(self.backend,ident,protocol,record['backend'])

    def action(self, form):
        action = form.get('action', '')
        actor = form.get('actor', '')
        self.store.require_actor(actor, action)
        with self.store.connect() as db:
            self.store.auth_event(db, actor, 'action:' + action, form.get('device', ''))
        if action in ('system-repair','access-save','update'):
            import vpn_tasks
            return vpn_tasks.submit(self.backend.m,actor,form)
        if action=='admin-device':
            _,device=self.backend.device(form.get('device',''))
            state=self.backend.m.load();ids=set(state.get('admin_devices',[]))
            if form.get('approved')=='yes':ids.add(form['device'])
            else:ids.discard(form['device'])
            state['admin_devices']=sorted(ids);self.backend.m.save(state);self.state=state
            import vpn_policy
            vpn_policy.apply(self.backend)
            return {'message':'Administrator VPN device approval updated.'}
        if action=='policy-preview':
            from vpn_business import Business
            result=Business(self.backend.repo).preview(self.backend.load(),form.get('device'),form.get('address'),form.get('protocol','tcp'),form.get('port','0'),state=self.state)
            return {'message':('Allowed: ' if result['allowed'] else 'Denied: ')+result['reason']}
        if action.startswith('admin-'):
            if action == 'admin-add':
                result = self.store.create_admin(form.get('username',''), form.get('password',''), form.get('role','operator'), actor)
                return {'message': 'Enrollment token (give privately to this administrator): ' + result['enrollment'], 'sensitive': True}
            self.store.admin_change(actor, form.get('id',''), role=form.get('role') if action == 'admin-role' else None, enabled=form.get('enabled') == 'yes' if action == 'admin-disable' else None)
            return {'message': 'Administrator updated; existing sessions invalidated.'}
        if action=='device-rule':
            from vpn_business import Business
            policies=Business(self.backend.repo).snapshot()['policies']
            policy=dict(policies.get(('device',form.get('device')),{}))
            policy['rules']=policy.get('rules',[])+[{'effect':form.get('effect'),'resource':form.get('resource')}]
            form=dict(form,action='access-policy',kind='device',id=form.get('device'),policy=json.dumps(policy));action='access-policy'
        if action=='group-rule':
            from vpn_business import Business
            groups=Business(self.backend.repo).snapshot()['groups']
            group=groups.get(form.get('id',''))
            if not group: raise WebError('Group not found.')
            policy=dict(group['policy']); policy['rules']=policy.get('rules',[])+[{'effect':form.get('effect'),'resource':form.get('resource')}]
            form=dict(form,action='group-save',name=group['name'],policy=json.dumps(policy))
            action='group-save'
        if action=='group-add' and 'policy' not in form:
            form=dict(form,policy=json.dumps({'internet':form.get('internet')=='yes','isolation':form.get('isolation')!='no','rules':[]}))
        if action in ('group-add','group-save','group-delete','device-group','resource-save','resource-delete','access-policy'):
            from vpn_business import Business
            import vpn_policy
            business = Business(self.backend.repo)
            previous = business.snapshot()
            try:
                ident = business.change(form, apply=lambda candidate: vpn_policy.apply(self.backend, business_snapshot=candidate))
            except Exception:
                vpn_policy.apply(self.backend, business_snapshot=previous)
                raise
            return {'message':'Access policy applied and verified.', 'id':ident}
        if action=='access-save':
            import vpn_access
            self.state=vpn_access.configure(self.backend.m,form)
            return {'message':'Access settings saved. Redeploy web configuration from the console to activate the listener configuration.'}
        if action=='identity-state':
            import datetime
            import vpn_policy
            from vpn_business import expired
            kind=form.get('kind'); ident=form.get('id')
            if kind not in ('device','user'): raise WebError('Invalid identity kind.')
            registry=self.backend.load(); record=registry['devices' if kind=='device' else 'users'].get(ident)
            if not record: raise WebError('Identity not found.')
            expiry=form.get('expires','')
            parsed=datetime.datetime.fromisoformat(expiry) if expiry else None
            record['expires']=(parsed if parsed.tzinfo else parsed.replace(tzinfo=datetime.timezone.utc)).timestamp() if parsed else None
            record['disabled']=form.get('disabled')=='yes'
            try:
                vpn_policy.apply(self.backend,registry_override=registry,commit=lambda:self.backend.save(registry))
            except Exception:
                vpn_policy.apply(self.backend)
                raise
            self.disconnect_expired(registry)
            return {'message':'Identity state applied; inactive sessions disconnected.'}
        if action in ('maintenance-save','reboot'):
            from vpn_maintenance import Coordinator
            coordinator=Coordinator(self.backend.m)
            if action=='maintenance-save':
                if form.get('date'):
                    from datetime import datetime
                    from zoneinfo import ZoneInfo
                    form=dict(form,at=datetime.fromisoformat(form['date']).replace(tzinfo=ZoneInfo(form.get('timezone','UTC'))).timestamp())
                coordinator.configure(form)
                return {'message':'Maintenance schedule saved.'}
            if form.get('confirm')!='REBOOT': raise WebError('Type REBOOT to reboot now.')
            coordinator.reboot('owner request',actor)
            return {'message':'Reboot requested.'}
        if action=='system-repair':
            from vpn_repair import Doctor
            result=Doctor(self.backend.m).repair()
            return {'message':'Repair completed; evidence saved in private logs.', 'checks':result['after']}
        if action in ('delivery-revoke','delivery-reissue'):
            device=self.store.revoke_token(form.get('hash',''))
            if action=='delivery-revoke': return {'message':'Delivery token revoked.'}
            return self.action({'action':'delivery-link','device':device,'actor':actor})
        device = form.get('device', '')
        if device and action in ('prepare-export', 'export', 'protocol-add', 'protocols-add', 'replace', 'rotate-l2tp', 'bundle') and self.backend.repo.pending_delete(device):
            raise WebError('Profile deletion is pending; operation cancelled.')
        if action == 'clear-history':
            self.backend.repo.clear_history()
            return {'message': 'Completed history hidden. Audit and recovery records retained.'}
        if action == 'delete-profile':
            if form.get('confirm') != 'DELETE':
                # Retry authorization comes from the saved, validated deletion job.
                raise WebError('Type DELETE to revoke and delete this profile.')
            self.store.invalidate(device)
            return {'message': self.backend.delete_profile(device, form.get('protocol', 'all')), 'device': device}
        if action == 'batch-retry':
            self.backend.repo.retry_batch(form.get('batch', ''))
            return {'message': 'Failed batch items queued; completed items retained.'}
        if action == 'batch-preview':
            from vpn_backend import preview_batch
            return preview_batch(self.backend, form)
        if action == 'batch-confirm':
            ident = form.get('batch', '')
            data = self.backend.repo.batch(ident)
            if data['status'] == 'queued':
                self.backend.repo.enqueue({'action': 'batch-run', 'batch': ident, 'actor': actor})
                return {'message': 'Batch already queued.'}
            if data['status'] != 'preview' or data.get('cancel') or time.time() - data['created'] > 86400:
                raise WebError('This preview is no longer available. Create a new preview.')
            data['status'] = 'queued'
            self.backend.repo.save_batch(ident, data)
            self.backend.repo.enqueue({'action': 'batch-run', 'batch': ident, 'actor': actor})
            return {'message': 'Batch confirmed and queued.'}
        if action == 'batch-run':
            from vpn_backend import run_batch
            return run_batch(self.backend, form.get('batch', ''), lambda: self.store.require_actor(actor, 'batch-run'))
        if action == 'job-retry':
            self.backend.repo.retry(form.get('id'))
            return {'message': 'Job queued for retry. Any custom password must be entered again in a new request.'}
        if action == 'user-add':
            from vpn_backend import random_name
            ident = self.backend.user_add(random_name('user') if form.get('random_name') == 'yes' else form.get('name', ''))
            return {'message': 'User created: ' + ident}
        if action == 'device-add':
            from vpn_backend import random_name
            ident = self.backend.device_add(form.get('user', ''), random_name('device') if form.get('random_name') == 'yes' else form.get('name', ''))
            return {'message': 'Device created: ' + ident, 'device': ident}
        if action == 'rename':
            self.backend.rename(form.get('kind'), form.get('id'), form.get('name', ''))
        elif action == 'assign':
            self.backend.assign(device, form.get('user'))
            self.disconnect_expired()
        elif action == 'protocol-add':
            self.backend.protocol_add(device, form.get('protocol'), form.get('l2tp_password') or form.get('password') or None, username=form.get('username') or None)
        elif action == 'protocols-add':
            selected = form.get('protocols', '').split(',')
            if not selected or any(value not in ('ikev2', 'wireguard', 'l2tp') for value in selected):
                raise WebError('Select supported protocols.')
            if 'l2tp' in selected and (form.get('username') or form.get('l2tp_password')):
                self.backend.protocol_add(device, 'l2tp', form.get('l2tp_password') or None, username=form.get('username') or None)
            return {'message': self.backend.add_protocols(device, selected)}
        elif action == 'policy':
            self.backend.repo.job_progress(self.backend, True, 'Applying and verifying LAN firewall rules')
            self.backend.set_policy(form.get('kind'), form.get('id'), form.get('policy'))
        elif action == 'bundle':
            from vpn_backend import bundle
            result = bundle(self.backend, device, form.get('protocols', '').split(','), password=form.get('archive_password') or None)
            return {'message': 'Encrypted ZIP ready. Use Reveal delivery password and Create ZIP link separately.'}
        elif action == 'delivery-password':
            if form.get('confirm') != 'REVEAL':
                raise WebError('Type REVEAL to display the delivery password.')
            with self.backend.repo.connect() as db:
                row = db.execute('SELECT data FROM deliveries WHERE device=?', (device,)).fetchone()
            if not row:
                raise WebError('Create an encrypted delivery first.')
            return {'message': 'ZIP delivery password: ' + json.loads(row[0])['password']}
        elif action == 'delivery-link':
            if not (self.backend.base / 'web-enabled').exists():
                raise WebError('Enable the profile delivery service before publishing a link.')
            lifetime = delivery_lifetime(form)
            if form.get('archive') == 'yes' or form.get('scope') == 'file':
                from vpn_admin import delivery_choice
                path, generation = delivery_choice(self.backend, device, archive=form.get('archive') == 'yes')
                token = self.store.issue(device, path.name, generation, lifetime)
            else:
                import vpn_portal
                try:
                    token, manifest = vpn_portal.publish(self.backend, self.store, device, lifetime)
                except ValueError as exc:
                    raise WebError(str(exc)) from None
            url=(self.state.get('vpd_origin') or 'http://' + self.state['public'] + ':9000') + '/?' + urlencode({'token':token})
            try: svg=self.backend.m.command(['qrencode','-t','SVG','-o','-'],data=url,timeout=5).stdout
            except (OSError,RuntimeError,subprocess.TimeoutExpired): svg=''  # The direct link remains usable.
            return {'qr':base64.b64encode(svg.encode()).decode(), 'remaining': lifetime, 'delivery_hash': digest(token), 'expires': self.store.clock() + lifetime,
                    'message': 'Device delivery ready: choose one prepared file. One download total per token. Open Apple profiles in Safari.',
                    'url': (self.state.get('vpd_origin') or 'http://' + self.state['public'] + ':9000') + '/?' + urlencode({'token': token}), 'token': token}
        elif action == 'prepare-export':
            from vpn_backend import bundle
            selected = form.get('protocols', '').split(',')
            if not selected or any(value not in ('wireguard', 'ikev2', 'l2tp') for value in selected):
                raise WebError('Select active protocols to prepare.')
            _, item = self.backend.device(device)
            if any(item['protocols'].get(value, {}).get('status') != 'active' for value in selected):
                raise WebError('Configure the selected protocols first.')
            if 'ikev2' in selected:
                self.backend.export_ike(device, form.get('platform', 'other'), __import__('vpn_backend').export_password(form, self.backend.m), form.get('on_demand') == 'yes')
            if 'ikev2' in selected and form.get('platform', 'other') == 'apple':
                return {'message': 'Apple mobileconfig ready. Publish the profile link or create an email draft; Safari receives the profile directly, without a ZIP.', 'device': device}
            return {'message': 'Native profiles ready. Download to this browser, create a device delivery token, or download an HTML email draft. ZIP archives are optional.', 'device': device}
        elif action == 'export':
            result = self.backend.export_ike(device, form.get('platform'), __import__('vpn_backend').export_password(form, self.backend.m), form.get('on_demand') == 'yes')
            return {'message': result['message'], 'files': result['files'], 'device': device}
        elif action == 'reveal':
            if form.get('confirm') != 'REVEAL':
                raise WebError('Type REVEAL to display the private import password.')
            protocol = form.get('protocol', 'ikev2')
            return {'message': 'Private credentials (share separately): ' + self.backend.reveal(device, protocol)}
        elif action == 'link':
            path = self.backend.exported_file(device, form.get('filename', ''))
            reg, item = self.backend.device(device)
            info = item['protocols']['ikev2']['export']
            token = self.store.issue(device, path.name, info['generation'])
            return {'message': 'One-time link; expires in 15 minutes. Share password separately.',
                    'url': (self.state.get('vpd_origin') or 'http://' + self.state['public'] + ':9000') + '/?' + urlencode({'token': token})}
        elif action in ('revoke', 'replace'):
            if form.get('confirm') != 'REVOKE':
                raise WebError('Type REVOKE to invalidate these credentials.')
            if action == 'revoke':
                message = self.backend.revoke(device, form.get('protocol'))
            else:
                self.backend.rotate(device, form.get('protocol'))
                message = 'New credentials created; re-import the replacement profile.'
            self.store.invalidate(device)
            return {'message': message}
        elif action == 'user-revoke':
            if form.get('confirm') != 'REVOKE':
                raise WebError('Type REVOKE to revoke all this user’s devices.')
            user = form.get('user')
            self.backend.revoke_user(user)
            for ident, item in self.backend.load()['devices'].items():
                if item['user'] == user:
                    self.store.invalidate(ident)
        elif action == 'rotate-l2tp':
            self.backend.rotate_l2tp(device, form.get('password') or self.backend.m.random_password())
        elif action == 'repair':
            message = self.backend.repair(device)
            return {'message': message or 'No incomplete operation needs recovery.'}
        elif action == 'copy':
            config = json.loads((self.backend.base / 'web/config.json').read_text())
            username = config.get('download_user')
            if not username:
                raise WebError('Set the local export user in the console TUI first.')
            return {'message': self.backend.copy_export(device, username)}
        else:
            raise WebError('Unsupported management action.')
        return {'message': 'Operation completed.'}


class BoundedRPCServer(socketserver.UnixStreamServer):
    request_queue_size = 32
    def __init__(self, *args, **kwargs):
        from vpn_harden import RPC_WORKERS, RPC_CAPACITY
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=RPC_WORKERS)
        self.slots = threading.BoundedSemaphore(RPC_CAPACITY)
        super().__init__(*args, **kwargs)

    def process_request(self, request, address):
        if not self.slots.acquire(False):
            try:
                request.settimeout(.1)
                request.sendall(b'{"ok":false,"busy":true,"error":"Backend busy; retry shortly."}\n')
            except OSError:
                pass
            self.shutdown_request(request)
            return
        def execute():
            try:
                self.finish_request(request, address)
            except Exception:
                pass
            finally:
                self.shutdown_request(request)
                self.slots.release()
        self.pool.submit(execute)

    def server_close(self):
        super().server_close()
        self.pool.shutdown(wait=False, cancel_futures=True)


def maintenance_loop(backend, stop, boot):
    while not stop.is_set():
        try:
            import vpn_policy
            vpn_policy.apply(backend, skip_unchanged=True)
            Controller(backend).disconnect_expired()
            backend.repo.cleanup()
            backend.m.atomic(backend.base / 'backend-health.json', json.dumps({'boot': boot, 'monotonic': time.monotonic()}))
        except Exception:
            backend.repo.audit('maintenance', 'policy', 'failed; inspect diagnostics')
        stop.wait(30)


def control_serve(backend):
    account = grp.getgrnam(RPC_GROUP)
    allowed_uids = (0, pwd.getpwnam(ACCOUNT).pw_uid, pwd.getpwnam(ADMIN_ACCOUNT).pw_uid)
    controller = Controller(backend)
    backend.repo.recover_jobs()
    backend.repo.job_progress(backend, False, 'backend started')
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(10)
            uid = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
            if uid not in allowed_uids:
                return
            try:
                line = self.rfile.readline(65537)
                if len(line) > 65536:
                    raise WebError('Request too large.')
                result = controller.handle(json.loads(line), uid)
                response = {'ok': True, 'result': result}
            except Exception as exc:
                # Backend errors omit raw command output. Never dump requests or stack frames.
                response = {'ok': False, 'error': str(exc) if isinstance(exc, (WebError, ValueError, RuntimeError)) else 'Operation failed; review local diagnostics.'}
            self.wfile.write(json.dumps(response).encode() + b'\n')
    class Server(BoundedRPCServer):
        pass
    if int(os.environ.get('LISTEN_PID', '0')) != os.getpid() or int(os.environ.get('LISTEN_FDS', '0')) != 1:
        raise WebError('Start vpn-control.socket through systemd; socket activation descriptor missing.')
    server = Server(str(SOCKET), Handler, bind_and_activate=False)
    server.socket.close()
    server.socket = socket.socket(fileno=3)
    stop = threading.Event()
    def jobs():
        while not stop.is_set():
            try:
                worked = backend.repo.run_one(backend, controller.action)
            except Exception:
                worked = False
                backend.repo.audit('maintenance', 'jobs', 'failed; inspect diagnostics')
            stop.wait(.05 if worked else 2)
    for task in (jobs, lambda: maintenance_loop(backend, stop, controller.store.boot)):
        threading.Thread(target=task, daemon=True).start()
    notify = os.environ.get('NOTIFY_SOCKET')
    if notify:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as connection:
            connection.connect(('\0' + notify[1:]) if notify.startswith('@') else notify)
            connection.sendall(b'READY=1')
    try:
        server.serve_forever()
    finally:
        stop.set()
        server.server_close()


def page(title, body):
    from vpn_admin import STYLE
    return ('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
            '<title>' + html.escape(title) + '</title><style>' + STYLE + '</style></head><body class="' + ('management' if '<div class="app-shell"' in body else 'standalone') + '"><header><h1>' + html.escape(title) + '</h1></header><main>' + body + '</main></body></html>').encode()


def form(action, csrf, fields, extra=''):
    hidden = '<input type="hidden" name="csrf" value="' + html.escape(csrf, quote=True) + '">'
    hidden += '<input type="hidden" name="action" value="' + html.escape(action, quote=True) + '">'
    for key, value in fields.items():
        hidden += '<input type="hidden" name="' + html.escape(key, quote=True) + '" value="' + html.escape(str(value), quote=True) + '">'
    return '<form method="post" action="/manage/action">' + hidden + extra + '<button>' + html.escape(action) + '</button></form>'


def manager_html(data, message='', **options):
    from vpn_dashboard import render
    return render(data, message, document=page, **options)


class Application:
    def __init__(self, config, role, rpc_call=rpc, public=PUBLIC):
        if role not in ('downloads', 'management'):
            raise ValueError('Invalid HTTP role.')
        self.config, self.role, self.rpc, self.public = config, role, rpc_call, public

    def __call__(self, env, start):
        # no-referrer can turn HTML form POST Origin into 'null'. Management
        # needs same-origin form attribution; public token links must not leak refs.
        referrer_policy = 'same-origin' if self.role == 'management' else 'no-referrer'
        from vpn_admin import STYLE, SCRIPT
        script_hash = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
        style_hash = base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()
        headers = [('Cache-Control', 'no-store'), ('Referrer-Policy', referrer_policy), ('X-Content-Type-Options', 'nosniff'),
                   ('Content-Security-Policy', "default-src 'none'; img-src data:; style-src 'sha256-" + style_hash + "'; script-src 'sha256-" + script_hash + "'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")]
        status, kind = '200 OK', 'text/html; charset=utf-8'
        def context(op):
            session = ''
            for part in env.get('HTTP_COOKIE', '').split(';'):
                if part.strip().startswith('vpn_session='):
                    session = part.strip().split('=', 1)[1]
            return {'op': op, 'host': env.get('HTTP_HOST', '').lower(), 'peer': env.get('REMOTE_ADDR', ''), 'origin': env.get('HTTP_ORIGIN'), 'session': session, 'forwarded_proto':env.get('HTTP_X_FORWARDED_PROTO','')}
        try:
            port = 9000 if self.role == 'downloads' else 9001
            hosts = {str(self.config[k]).lower() + ':' + str(port) for k in ('lan', 'public', 'endpoint')}
            if self.role == 'management':
                hosts.update(('127.0.0.1:9001', 'localhost:9001'))
                if self.config.get('admin_origin'): hosts.add(urlsplit(self.config['admin_origin']).netloc)
            if self.role=='downloads' and self.config.get('vpd_origin'):hosts.add(urlsplit(self.config['vpd_origin']).netloc)
            if env.get('HTTP_HOST', '').lower() not in hosts:
                raise WebError('Unrecognized Host header.')
            path, method = env.get('PATH_INFO', ''), env.get('REQUEST_METHOD', '')
            if path.startswith('/api/v1/') and self.role == 'management':
                path = '/manage/' + path.removeprefix('/api/v1/')
            query = parse_qs(env.get('QUERY_STRING', ''), max_num_fields=8)
            if len(env.get('QUERY_STRING', '')) > 4096 or len(path) > 4096:
                raise WebError('Request target too large.')
            certs = {'/cert/ca.pem': 'ca.pem', '/cert/ca.der': 'ca.der', '/cert/server.pem': 'server.pem', '/cert/server.der': 'server.der'}
            if self.role == 'downloads' and method == 'GET' and path in certs:
                filename = certs[path]
                body = (self.public / 'certs' / filename).read_bytes()
                kind = 'application/octet-stream'
                headers.append(('Content-Disposition', 'attachment; filename="' + filename + '"'))
            elif self.role == 'downloads' and method == 'GET' and path == '/':
                from vpn_admin import portal_markup
                token = query.get('token', [''])[0]
                result = self.rpc({'op': 'inspect', 'token': token}) if token else None
                available = [name for name in certs.values() if (self.public / 'certs' / name).is_file()]
                body = page('VPN profile delivery', portal_markup(result, token, available))
            elif self.role == 'downloads' and method in ('GET', 'HEAD') and path.startswith('/files/'):
                from vpn_admin import profile_mime
                filename = path.removeprefix('/files/')
                if not re.fullmatch(r'[A-Za-z0-9_.-]{1,120}', filename):
                    raise WebError('Invalid file request.')
                token = query.get('token', [''])[0]
                record = self.rpc({'op': 'inspect', 'token': token})
                choices = record.get('files', [{'filename': record['filename'], 'size': record.get('size', 0)}])
                selected = next((item for item in choices if item['filename'] == filename), None)
                if selected is None:
                    raise WebError('This file is not authorized by the token.')
                kind = profile_mime(filename)
                disposition = 'inline' if filename.endswith('.mobileconfig') else 'attachment'
                headers.append(('Content-Disposition', disposition + '; filename="' + filename + '"'))
                if env.get('HTTP_RANGE'):
                    status, body = '416 Range Not Satisfiable', b''
                elif method == 'HEAD':
                    body = b''
                    head_length = int(selected.get('size', 0))
                else:
                    result = self.rpc({'op': 'claim', 'token': token, 'filename': filename, 'confirm': record['confirm']})
                    body = base64.b64decode(result['data'], validate=True)
            elif self.role == 'downloads' and method == 'GET' and path == '/profile.mobileconfig':
                record = self.rpc({'op': 'inspect', 'token': query.get('token', [''])[0]})
                if not record['filename'].endswith('.mobileconfig'):
                    raise WebError('Invalid Apple profile delivery.')
                result = self.rpc({'op': 'claim', 'token': query.get('token', [''])[0], 'confirm': query.get('confirm', [''])[0]})
                body = base64.b64decode(result['data'], validate=True)
                kind = 'application/x-apple-aspen-config'
                headers.append(('Content-Disposition', 'inline; filename="profile.mobileconfig"'))
            elif method == 'GET' and path == '/health':
                if self.role == 'management':
                    self.rpc(dict(context('health'), op='management-health'))
                else:
                    self.rpc({'op': 'ping'})
                body, kind = b'OK\n', 'text/plain'
            elif self.role == 'management' and method == 'GET' and path == '/manage/status':
                body = json.dumps(self.rpc(dict(context('dashboard'), targets=query.get('targets', ['[]'])[0], view=query.get('view',['overview'])[0], since=query.get('since',[''])[0], device=query.get('device',[''])[0], jobs=query.get('jobs',['[]'])[0], batches=query.get('batches',['[]'])[0], links=query.get('links',['[]'])[0]))).encode()
                kind = 'application/json'
            elif self.role == 'management' and method == 'GET' and path in ('/manage', '/manage/devices', '/manage/device', '/manage/users', '/manage/jobs', '/manage/batches', '/manage/delivery', '/manage/system', '/manage/search', '/manage/groups', '/manage/administrators', '/manage/audit'):
                if 'login' in query:
                    raise WebError('Login links are no longer supported. Use the management password.')
                view_name = path.removeprefix('/manage/').replace('/manage', 'overview')
                request = dict(context('view'), view=view_name, device=query.get('device',[''])[0], q=query.get('q',[''])[0][:80], owner=query.get('owner',[''])[0], page=int(query.get('page',['1'])[0]), owner_q=query.get('owner_q',[''])[0][:80])
                try:
                    view_data = self.rpc(request)
                    body = manager_html(view_data, view=path.removeprefix('/manage/').replace('/manage', 'overview'),
                        device=query.get('device', [''])[0], query=query.get('q', [''])[0][:80],
                        owner=query.get('owner', [''])[0], page=int(query.get('page', ['1'])[0]), tab=query.get('tab',['profiles'])[0])

                except WebError:
                    body = page('Management login', '<form method="post" action="/manage/login"><label>Username <input name="username" autocomplete="username" required></label><label>Password <input type="password" name="password" minlength="12" maxlength="256" autocomplete="current-password" required></label><label>Authenticator or recovery code <input name="code" autocomplete="one-time-code" required maxlength="128"></label><button>Log in</button></form><p>30-minute idle timeout · 8-hour maximum session. Background polling does not keep you signed in.</p><details><summary>Enroll a new administrator</summary><form method="post" action="/manage/enroll"><label>Private enrollment token<input name="token" required autocomplete="off"></label><button>Start enrollment</button></form></details>')
            elif method == 'POST' and ((self.role == 'management' and path in ('/manage/action', '/manage/login', '/manage/logout', '/manage/file', '/manage/enroll')) or (self.role == 'downloads' and path in ('/download', '/access'))):
                if env.get('HTTP_TRANSFER_ENCODING') or env.get('CONTENT_TYPE', '').split(';')[0] != 'application/x-www-form-urlencoded':
                    raise WebError('Unsupported form encoding.')
                length = int(env.get('CONTENT_LENGTH') or '0')
                if not 0 < length <= 65536:
                    raise WebError('Invalid form size.')
                raw = env['wsgi.input'].read(length)
                if len(raw) != length:
                    raise WebError('Incomplete form.')
                values = parse_qs(raw.decode(), max_num_fields=100, keep_blank_values=True)
                if any(len(v) != 1 for k, v in values.items() if k not in ('protocols', 'devices')):
                    raise WebError('Duplicate form field.')
                form_data = {k: ','.join(v) if k in ('protocols', 'devices') else v[0] for k, v in values.items()}
                origin = env.get('HTTP_ORIGIN')
                # Public downloads use no-referrer, which can produce Origin:null
                # on HTML form POSTs. Their token + confirmation HMAC authorize the
                # request independently of cookies. Management never permits null.
                opaque_delivery = self.role == 'downloads' and path in ('/download', '/access') and origin == 'null'
                expected_origin=self.config.get('admin_origin') if self.role=='management' and env.get('REMOTE_ADDR')==self.config.get('trusted_proxy') and env.get('HTTP_X_FORWARDED_PROTO')=='https' else 'http://'+env.get('HTTP_HOST','').lower()
                if self.role=='downloads' and self.config.get('vpd_origin') and env.get('HTTP_HOST','').lower()==urlsplit(self.config['vpd_origin']).netloc:expected_origin=self.config['vpd_origin']
                if origin and origin != expected_origin and not opaque_delivery:
                    raise WebError('Cross-origin request denied.')
                if self.role=='management' and path=='/manage/enroll':
                    token=form_data.get('token','')
                    if form_data.get('code'):
                        result=self.rpc(dict(context('enroll-confirm'),token=token,code=form_data['code']))
                        body=page('MFA enrolled','<h1>Save your recovery codes privately</h1><pre>'+html.escape('\n'.join(result['codes']))+'</pre><a href="/manage">Sign in</a>')
                    else:
                        result=self.rpc(dict(context('enroll-info'),token=token))
                        body=page('Enroll authenticator','<h1>'+html.escape(result['username'])+'</h1><p>Add this key in your authenticator app (issuer VPN):</p><code>'+html.escape(result['secret'])+'</code><form method="post" action="/manage/enroll"><input type="hidden" name="token" value="'+html.escape(token,quote=True)+'"><label>Authenticator code<input name="code" autocomplete="one-time-code" required></label><button>Finish enrollment</button></form>')
                elif self.role == 'management' and path == '/manage/login':
                    result = self.rpc(dict(context('login'), password=form_data.get('password', ''), username=form_data.get('username', ''), code=form_data.get('code', '')))
                    status, body = '303 See Other', b''
                    headers.extend([('Location', '/manage'), ('Set-Cookie', 'vpn_session=' + result['session'] + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800' + ('; Secure' if expected_origin.startswith('https://') else ''))])
                elif self.role == 'management' and path == '/manage/logout':
                    self.rpc(dict(context('logout'), csrf=form_data.get('csrf', '')))
                    status, body = '303 See Other', b''
                    headers.extend([('Location', '/manage'), ('Set-Cookie', 'vpn_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0')])
                elif self.role == 'management' and path == '/manage/file':
                    result = self.rpc(dict(context('admin-file'), form=form_data, csrf=form_data.get('csrf', '')))
                    filename = result['filename']
                    if not filename or not all(c.isascii() and (c.isalnum() or c in '-_.') for c in filename):
                        raise WebError('Invalid attachment filename.')
                    body, kind = base64.b64decode(result['data'], validate=True), result['mime']
                    disposition = 'inline' if filename.endswith('.mobileconfig') else 'attachment'
                    headers.append(('Content-Disposition', disposition + '; filename="' + filename + '"'))
                elif self.role == 'downloads':
                    token = form_data.get('token', '')
                    record = self.rpc({'op': 'inspect', 'token': token})
                    if path == '/access':
                        from vpn_admin import portal_markup
                        available = [name for name in certs.values() if (self.public / 'certs' / name).is_file()]
                        body = page('VPN profile delivery', portal_markup(record, token, available))
                    elif record.get('files'):
                        filename = form_data.get('filename', '')
                        if not any(item['filename'] == filename for item in record['files']):
                            raise WebError('Choose one authorized file.')
                        if not hmac.compare_digest(record['confirm'], form_data.get('confirm', '')):
                            raise WebError('Invalid download confirmation.')
                        status, body = '303 See Other', b''
                        headers.append(('Location', '/files/' + filename + '?' + urlencode({'token': token})))
                    elif record['filename'].endswith('.mobileconfig'):
                        if not hmac.compare_digest(record['confirm'], form_data.get('confirm', '')):
                            raise WebError('Invalid download confirmation.')
                        status, body = '303 See Other', b''
                        headers.append(('Location', '/profile.mobileconfig?' + urlencode({'token': token, 'confirm': form_data['confirm']})))
                    else:
                        result = self.rpc({'op': 'claim', 'token': token, 'confirm': form_data.get('confirm', '')})
                        filename = result['filename']
                        if not filename or not all(c.isalnum() or c in '-_.' for c in filename):
                            raise WebError('Invalid filename.')
                        from vpn_admin import profile_mime
                        body, kind = base64.b64decode(result['data'], validate=True), profile_mime(filename)
                        headers.append(('Content-Disposition', 'attachment; filename="' + filename + '"'))
                else:
                    action_attempted = True
                    result = self.rpc(dict(context('action'), form=form_data, csrf=form_data.get('csrf', '')))
                    destination = form_data.get('return_device', result.get('device', ''))
                    view = 'device' if destination else form_data.get('return_view', 'overview')
                    if view not in ('overview', 'users', 'devices', 'device', 'jobs', 'batches', 'delivery', 'system', 'search','groups','administrators','audit'):
                        view = 'overview'
                    sensitive = result.get('sensitive') or result.get('url') or form_data.get('action') in ('reveal','delivery-password')
                    if not sensitive:
                        self.rpc(dict(context('flash'), csrf=form_data.get('csrf',''), message=result.get('message','')))
                        status, body = '303 See Other', b''
                        options = {'device': destination, 'tab': form_data.get('return_tab','profiles')} if destination else {}
                        location = '/manage' + ('' if view == 'overview' else '/' + view)
                        if options:
                            location += '?' + urlencode(options)
                        headers.append(('Location',location))
                    else:
                        view_data = self.rpc(dict(context('view'), view=view, device=destination))
                        body = manager_html(view_data, result.get('message',''), view=view, device=destination, tab=form_data.get('return_tab','profiles'))
                        if result.get('url'):
                            url = html.escape(result['url'], quote=True)
                            token = html.escape(result.get('token',''), quote=True)
                            countdown = '<p>Link expires in <span data-countdown="' + str(int(result.get('remaining',900))) + '" data-delivery="' + html.escape(result.get('delivery_hash',''),quote=True) + '"></span></p>'
                            qr='<img width="220" height="220" alt="Scan this delivery link" src="data:image/svg+xml;base64,'+html.escape(result.get('qr',''),quote=True)+'">' if result.get('qr') else ''
                            card = qr + '<section class="delivery-result"><h2>Share this device delivery</h2><p><a href="' + url + '">' + url + '</a></p>' + ('<label class="block">Token<input readonly value="' + token + '" autocomplete="off"></label>' if token else '') + countdown + '<p class="muted">One download total. Share import passwords separately.</p></section>'
                            body = body.replace(b'<div data-result-slot></div>',card.encode(),1)
            else:
                status, body = '404 Not Found', page('Not found', '<p>No route is available here.</p>')
        except (OSError, ConnectionError, TimeoutError):
            status, body = '503 Service Unavailable', page('Service unavailable', '<p>Backend unavailable. Run sudo vpn --web-status for diagnostics.</p>')
            headers.append(('Retry-After', '3'))
        except Exception as exc:
            status = '403 Forbidden'
            message = str(exc) if isinstance(exc, (WebError,ValueError,RuntimeError)) else 'Operation unavailable. Review local diagnostics.'
            body = page('Request unavailable','<p>'+html.escape(message)+'</p>')
            denied = message == 'Invalid form authorization.' or message.startswith(('Management is closed','Cross-origin','LAN management','Your role cannot','Auditor','Owner access','Session expired','Administrator session'))
            if locals().get('action_attempted') and not denied:
                try:
                    destination = form_data.get('return_device','')
                    view = 'device' if destination else form_data.get('return_view','overview')
                    if view not in ('overview','device','devices','users','jobs','batches','delivery','system','search','groups','administrators','audit'):
                        view='overview'
                    data = self.rpc(dict(context('view'),view=view,device=destination,owner=form_data.get('user','')))
                    from vpn_admin import restore_form_values
                    body = manager_html(data,message,view=view,device=destination,tab=form_data.get('return_tab','profiles'))
                    body = restore_form_values(body,form_data)
                    status='422 Unprocessable Entity'
                except Exception:
                    pass
        headers.extend([('Content-Type', kind), ('Content-Length', str(locals().get('head_length', len(body))))])
        start(status, headers)
        return [body]


# Test-only HTTP adapter; production listeners exclusively use Waitress.
def handler(config, rpc_call=rpc, public=PUBLIC, role='downloads'):
    application = Application(config, role, rpc_call, public)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            parsed = urlsplit(self.path)
            env = {'REQUEST_METHOD': self.command, 'PATH_INFO': parsed.path, 'QUERY_STRING': parsed.query,
                   'REMOTE_ADDR': self.client_address[0], 'wsgi.input': self.rfile,
                   'CONTENT_LENGTH': self.headers.get('Content-Length', ''), 'CONTENT_TYPE': self.headers.get('Content-Type', '')}
            for name, value in self.headers.items():
                env['HTTP_' + name.upper().replace('-', '_')] = value
            def start(status, headers):
                self.send_response(int(status.split()[0]))
                for name, value in headers:
                    self.send_header(name, value)
                self.end_headers()
            for data in application(env, start):
                self.wfile.write(data)
        do_POST = do_GET
    return Handler


class BoundedServer(ThreadingHTTPServer):
    daemon_threads = True


def wait_ready(backend, timeout=30):
    deadline = time.monotonic() + timeout
    last = 'not ready'
    while time.monotonic() < deadline:
        try:
            if rpc({'op': 'ping'}, timeout=1).get('ready'):
                return
        except (OSError, WebError, ValueError) as exc:
            last = str(exc)
        time.sleep(.2)
    raise WebError(f'Backend did not become ready at {SOCKET}: {last}. Run: systemctl status vpn-control.socket vpn-control.service; journalctl -u vpn-control -n 40 --no-pager')


def dependencies(backend):
    from vpn_dependencies import REQUIREMENTS
    python = VENV / 'bin/python3'
    lock = backend.base / 'requirements.lock'
    backend.m.atomic(lock, REQUIREMENTS)
    if not python.exists():
        backend.m.command(['python3', '-m', 'venv', str(VENV)])
    marker = VENV / '.requirements-sha256'
    checksum = hashlib.sha256(REQUIREMENTS.encode()).hexdigest()
    if not marker.exists() or marker.read_text() != checksum:
        backend.m.command([str(python), '-m', 'pip', 'install', '--disable-pip-version-check', '--only-binary=:all:', '--require-hashes', '-r', str(lock)])
        backend.m.atomic(marker, checksum, 0o644)
    # Code directory and venv must be traversable by unprivileged HTTP workers.
    for directory in [VENV.parent, VENV] + [p for p in VENV.rglob('*') if p.is_dir()]:
        directory.chmod(0o755)
    for path in VENV.rglob('*'):
        if path.is_file() and not path.is_symlink():
            path.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
    return python


def unit_files():
    python = str(VENV / 'bin/python3')
    from vpn_harden import common_sandbox, service_limits
    common = '''UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
Restart=on-failure
RestartSec=2
TimeoutStartSec=35
TimeoutStopSec=5
'''
    common += common_sandbox()
    units = {'vpn-control.socket': '''[Unit]
Description=VPN privileged local RPC socket
[Socket]
ExecStartPre=/usr/bin/systemd-tmpfiles --create /etc/tmpfiles.d/vpn.conf
ListenStream=/run/vpn/control.sock
SocketUser=root
SocketGroup=vpn-rpc
SocketMode=0660
DirectoryMode=0750
RemoveOnStop=yes
[Install]
WantedBy=sockets.target
''', 'vpn-control.service': '''[Unit]
Description=VPN privileged backend
Requires=vpn-control.socket vpn-firewall.service
After=vpn-control.socket vpn-firewall.service network.target ipsec.service
[Service]
Type=notify
NotifyAccess=main
User=root
Group=vpn-rpc
RuntimeDirectory=vpn
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
ExecStart=''' + python + ''' /usr/lib/vpn/manage.py web-control
ReadWritePaths=/var/lib/vpn /var/log/vpn /etc/vpn /etc/wireguard /etc/ipsec.d /etc/ppp /run/vpn /run/xtables.lock -/home -/var/lib/dpkg/lock-frontend -/var/lib/dpkg/lock -/var/lib/apt/lists/lock -/var/cache/apt/archives/lock
''' + common.replace('AF_INET AF_INET6 AF_UNIX', 'AF_INET AF_INET6 AF_UNIX AF_NETLINK') + service_limits() + 'CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER CAP_SETUID CAP_SETGID CAP_KILL CAP_AUDIT_WRITE\n'}
    for name, account, role in [('vpn-downloads', ACCOUNT, 'downloads'), ('vpn-management', ADMIN_ACCOUNT, 'management')]:
        units[name + '.service'] = '''[Unit]
Description=VPN ''' + role + ''' HTTP service
Requires=vpn-control.service
After=vpn-control.service vpn-firewall.service network-online.target
Wants=network-online.target
[Service]
User=''' + account + '''
Group=''' + RPC_GROUP + '''
ProtectHome=yes
ExecStart=''' + python + ' /usr/lib/vpn/web.py --' + role + '\n' + common + service_limits(worker=True) + 'CapabilityBoundingSet=\nAmbientCapabilities=\nProtectProc=invisible\nProcSubset=pid\nMemoryDenyWriteExecute=yes\nSystemCallFilter=@system-service\n'
        if role == 'downloads':
            units[name + '.service'] = units[name + '.service'].replace('Requires=vpn-control.service', 'Wants=vpn-control.service vpn-control.socket')
        units[name + '.service'] += '[Install]\nWantedBy=multi-user.target\n'
    return units


def enable(backend, module_source, download_user=None, open_manager=True):
    m = backend.m
    # Idempotent account creation, with UID checks before deploying privileged configuration.
    try:
        group = grp.getgrnam(RPC_GROUP)
    except KeyError:
        m.command(['groupadd', '--system', RPC_GROUP])
        group = grp.getgrnam(RPC_GROUP)
    if group.gr_gid == 0:
        raise WebError('Conflicting root-owned RPC group; service deployment stopped.')
    account_uids = set()
    for name in (ACCOUNT, ADMIN_ACCOUNT):
        try:
            account = pwd.getpwnam(name)
        except KeyError:
            m.command(['useradd', '--system', '--no-create-home', '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', '--gid', RPC_GROUP, name])
            account = pwd.getpwnam(name)
        if not 0 < account.pw_uid < 1000 or account.pw_uid in account_uids or account.pw_shell not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false'):
            raise WebError('Conflicting system account: ' + name)
        account_uids.add(account.pw_uid)
    dependencies(backend)
    # Test binding only when a stack listener is not already active; report actual conflict.
    for port, address, service in [(9000, '0.0.0.0', 'vpn-downloads'), (9001, m.load()['lan'], 'vpn-management')]:
        if m.command(['systemctl', 'is-active', '--quiet', service], check=False).returncode != 0:
            try:
                with socket.socket() as probe:
                    probe.bind((address, port))
            except OSError as exc:
                raise WebError(f'Cannot bind {address}:{port}: {exc}. Existing listener was not stopped.') from None
    code_dir = Path('/usr/lib/vpn')
    code_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    code_dir.chmod(0o755)
    m.atomic(code_dir / 'web.py', module_source, 0o644)
    m.atomic(code_dir / 'vpn_admin.py', m.module_source('vpn_admin'), 0o644)
    m.atomic(code_dir / 'vpn_dashboard.py', m.module_source('vpn_dashboard'), 0o644)
    m.atomic(code_dir / 'vpn_auth.py', m.module_source('vpn_auth'), 0o644)
    PUBLIC.mkdir(parents=True, exist_ok=True, mode=0o755)
    PUBLIC.chmod(0o755)
    cert_dir = PUBLIC / 'certs'
    cert_dir.mkdir(mode=0o755, exist_ok=True)
    cert_dir.chmod(0o755)
    for name, nickname in [('ca', 'IKEv2 VPN CA'), ('server', backend.server_identity())]:
        pem = backend.cert(nickname)
        m.atomic(cert_dir / (name + '.pem'), pem, 0o644)
        m.atomic(cert_dir / (name + '.der'), backend.command(['openssl', 'x509', '-outform', 'DER'], data=pem), 0o644)
    m.atomic(PUBLIC / 'public.json', json.dumps({k: m.load().get(k,'') for k in ('lan', 'public', 'endpoint','admin_origin','trusted_proxy','vpd_origin')}), 0o644)
    existing = backend.base / 'web/config.json'
    if download_user is None and existing.exists():
        download_user = json.loads(existing.read_text()).get('download_user')
    m.atomic(existing, json.dumps({'download_user': download_user}))
    m.atomic(backend.base / 'web-enabled', 'yes\n')
    SOCKET.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    os.chown(SOCKET.parent, 0, group.gr_gid)
    SOCKET.parent.chmod(0o750)
    m.atomic(TMPFILES, TMPFILES_RULES, 0o644)
    m.command(['systemd-tmpfiles', '--create', str(TMPFILES)])
    from vpn_tasks import unit
    m.atomic(Path('/etc/systemd/system/vpn-system-task.service'),unit(),0o644)
    for name, text in unit_files().items():
        m.atomic(Path('/etc/systemd/system') / name, text, 0o644)
    m.command(['systemctl', 'daemon-reload'])
    # Migration/redeploy closes management explicitly. Ordinary opening never redeploys listeners.
    m.command(['systemctl', 'stop', 'vpn-management'])
    m.command(['systemctl', 'restart', 'vpn-firewall'])
    try:
        m.command(['systemctl', 'enable', '--now', 'vpn-control.socket', 'vpn-downloads.service', 'vpn-management.service'])
        m.command(['systemctl', 'restart', 'vpn-control.service', 'vpn-downloads.service', 'vpn-management.service'])
        wait_ready(backend)
    except Exception as exc:
        startup_diagnostics(backend)
        raise WebError('Web deployment failed: ' + str(exc) + '. Diagnose with sudo vpn --web-status and journalctl -u vpn-control -u vpn-downloads -n 40 --no-pager') from None
    return open_management(backend) if open_manager else 'Downloads enabled on 9000; authenticated management online on 9001.'


def startup_diagnostics(backend):
    """Persist evidence before failure cleanup removes the live listener."""
    units = ['vpn-control.socket', 'vpn-control.service',
             'vpn-downloads.service', 'vpn-management.service',
             'vpn-management-expire.timer']
    report = ['VPN web failure diagnostics', time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())]
    commands = [
        ['systemctl', 'show', *units, '-p', 'ActiveState', '-p', 'SubState', '-p', 'Result',
         '-p', 'ExecMainCode', '-p', 'ExecMainStatus', '-p', 'InvocationID', '-p', 'ExecStart'],
        ['journalctl', *[item for unit in units for item in ('-u', unit)],
         '--since', '15 minutes ago', '-n', '150', '--no-pager', '--output=short-iso'],
        ['ss', '-lntp', '( sport = :9000 or sport = :9001 )'],
        ['ip', '-4', 'route', 'get', backend.m.load()['lan']],
        ['iptables', '-w', '5', '-nvL', 'VPNSTACK-IN', '--line-numbers'],
    ]
    for args in commands:
        report.append('\n$ ' + ' '.join(args))
        try:
            result = backend.m.command(args, check=False, timeout=5)
            report.append('exit=' + str(result.returncode))
            report.append((result.stdout + (result.stderr or ''))[:48000])
        except Exception as exc:
            report.append('Diagnostic command failed: ' + str(exc))
    text = '\n'.join(report) + '\n'
    print(text, file=sys.stderr)
    try:
        directory = backend.base / 'logs'
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = directory / 'web-failure-latest.txt'
        backend.m.atomic(path, text, 0o600)
        backend.m.atomic(directory / ('web-failure-' + time.strftime('%Y%m%dT%H%M%S', time.gmtime()) + '-' + secrets.token_hex(3) + '.txt'), text, 0o600)
        from vpn_watchdog import prune_reports
        prune_reports(directory)
        print('Private system journal and diagnostics saved: ' + str(path), file=sys.stderr)
        return path
    except Exception as exc:
        print('Could not save diagnostic file: ' + str(exc), file=sys.stderr)
        return None


def open_management(backend):
    wait_ready(backend)
    backend.m.command(['systemctl', 'stop', 'vpn-management'])
    result = rpc({'op': 'open'})
    try:
        backend.m.command(['systemctl', 'start', 'vpn-management.service'])
        # systemd Type=simple does not guarantee bind readiness. Verify the actual LAN listener.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with socket.socket() as probe:
                probe.settimeout(.5)
                if probe.connect_ex((backend.m.load()['lan'], 9001)) == 0:
                    return result['url']
            time.sleep(.1)
        raise WebError('Management failed to listen on LAN:9001.')
    except Exception as exc:
        report = startup_diagnostics(backend)
        backend.m.command(['systemctl', 'stop', 'vpn-management'], check=False)
        raise WebError(str(exc) + (' System journal saved: ' + str(report) if report else ' Diagnostics printed above.')) from exc


def expire(backend):
    raise WebError('Management no longer uses a global expiration window.')


def stop_downloads(backend):
    store = Store(backend.repo.path)
    with store.connect() as db:
        db.execute('UPDATE tokens SET used=? WHERE used IS NULL', (store.clock(),))
    backend.m.command(['systemctl', 'disable', '--now', 'vpn-downloads'])
    (backend.base / 'web-enabled').unlink(missing_ok=True)
    backend.m.command(['systemctl', 'restart', 'vpn-firewall'])


def diagnostics(backend):
    for service in ('vpn-control.socket', 'vpn-control', 'vpn-downloads', 'vpn-management'):
        result = backend.m.command(['systemctl', 'status', '--no-pager', '--full', service], check=False)
        print(result.stdout)
    print('Socket:', SOCKET, 'exists:', SOCKET.exists())
    print(backend.m.command(['ss', '-lntp', '( sport = :9000 or sport = :9001 )'], check=False).stdout)
    print('Logs: journalctl -u vpn-control -u vpn-downloads -u vpn-management -n 60 --no-pager')


def worker_main():
    import sys
    if os.geteuid() == 0:
        raise SystemExit('HTTP workers must run unprivileged.')
    role = 'management' if '--management' in sys.argv else 'downloads'
    config = json.loads((PUBLIC / 'public.json').read_text())
    from waitress import serve
    serve(Application(config, role), host=config['lan'] if role == 'management' else '0.0.0.0',
          port=9001 if role == 'management' else 9000, threads=1, connection_limit=32,
          channel_timeout=15, cleanup_interval=1, max_request_header_size=16384,
          max_request_body_size=65536, clear_untrusted_proxy_headers=True, trusted_proxy=config.get('trusted_proxy') or None,
          trusted_proxy_headers={'x-forwarded-proto'} if config.get('trusted_proxy') else set(),
          channel_request_lookahead=0, ident='VPNStack', ipv6=False)


if __name__ == '__main__':
    worker_main()



def delivery_lifetime(form):
    try:
        value = int(form.get('lifetime', '86400'))
    except (ValueError, TypeError):
        raise WebError('Choose a supported delivery lifetime.') from None
    if value not in (3600, 86400, 604800, 2592000):
        raise WebError('Choose a supported delivery lifetime.')
    return value
