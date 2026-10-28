"""Transactional metadata, serialized jobs and encrypted delivery artifacts."""
import contextlib
import hashlib
import io
import json
import os
import re
from pathlib import Path
import secrets
import sqlite3
import time


class Repository:
    def __init__(self, base):
        self.base = Path(base)
        self.path = self.base / 'backend.db'
        self.base.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connect() as db:
            version=db.execute('PRAGMA user_version').fetchone()[0]
            if version>2:raise RuntimeError('Database schema is newer than this application; refusing a downgrade.')
            if version==2:
                if self.path.stat().st_mode&0o777!=0o600:self.path.chmod(0o600)
                return
            db.executescript('''BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS protocols(device_id TEXT NOT NULL REFERENCES devices(id),name TEXT NOT NULL CHECK(name IN ('ikev2','wireguard','l2tp')),data TEXT NOT NULL,PRIMARY KEY(device_id,name));
CREATE UNIQUE INDEX IF NOT EXISTS protocol_identity ON protocols(name,json_extract(data,'$.backend'));
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,action TEXT NOT NULL,form TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('queued','running','complete','failed','interrupted')),created REAL NOT NULL,updated REAL NOT NULL,result TEXT);
CREATE TABLE IF NOT EXISTS batches(id TEXT PRIMARY KEY,data TEXT NOT NULL,updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,time REAL NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,outcome TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS deliveries(device TEXT PRIMARY KEY,generation TEXT NOT NULL,data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS policy_sessions(key TEXT PRIMARY KEY,data TEXT NOT NULL,updated REAL NOT NULL);
''')
            db.execute("INSERT OR IGNORE INTO metadata VALUES ('revision','0')")
            if 'hidden' not in {row[1] for row in db.execute('PRAGMA table_info(jobs)')}:
                db.execute('ALTER TABLE jobs ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0')
            for statement in (
                'CREATE INDEX IF NOT EXISTS device_owner ON devices(user_id)',
                'CREATE INDEX IF NOT EXISTS job_state_time ON jobs(status,updated)',
                "CREATE INDEX IF NOT EXISTS user_name_order ON users(casefold(json_extract(data,'$.name')),id)",
                "CREATE INDEX IF NOT EXISTS device_name_order ON devices(casefold(json_extract(data,'$.name')),id)",
            ):db.execute(statement)
            db.execute('PRAGMA user_version=2')
        self.path.chmod(0o600)

    @contextlib.contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.create_function('casefold', 1, lambda value: str(value or '').casefold(), deterministic=True)
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA secure_delete=ON')
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def load(self):
        with self.connect() as db:
            db.execute('BEGIN')
            if not db.execute("SELECT 1 FROM metadata WHERE key='registry-ready'").fetchone():
                return None
            users = {key: json.loads(data) for key, data in db.execute('SELECT id,data FROM users')}
            devices = {key: dict(json.loads(data), user=user, protocols={}) for key, user, data in db.execute('SELECT id,user_id,data FROM devices')}
            for device, protocol, data in db.execute('SELECT device_id,name,data FROM protocols'):
                devices[device]['protocols'][protocol] = json.loads(data)
            revision = int(db.execute("SELECT value FROM metadata WHERE key='revision'").fetchone()[0])
        return {'schema': 1, 'users': users, 'devices': devices, '_revision': revision}

    def save(self, registry):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            revision = int(db.execute("SELECT value FROM metadata WHERE key='revision'").fetchone()[0])
            if '_revision' in registry and registry['_revision'] != revision:
                raise RuntimeError('Metadata changed during this operation. Refresh and retry; existing credentials were retained.')
            desired_protocols = {(key, protocol): json.dumps(record) for key, value in registry['devices'].items() for protocol, record in value['protocols'].items()}
            for device, protocol, raw in db.execute('SELECT device_id,name,data FROM protocols').fetchall():
                if desired_protocols.get((device, protocol)) != raw:
                    db.execute('DELETE FROM protocols WHERE device_id=? AND name=?', (device, protocol))
            for (key,) in db.execute('SELECT id FROM devices').fetchall():
                if key not in registry['devices']:
                    db.execute('DELETE FROM devices WHERE id=?', (key,))
            for key, value in registry['users'].items():
                db.execute('INSERT INTO users VALUES (?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data WHERE users.data!=excluded.data', (key, json.dumps(value)))
            for key, value in registry['devices'].items():
                data = {k: v for k, v in value.items() if k not in ('user', 'protocols')}
                db.execute('INSERT INTO devices VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET user_id=excluded.user_id,data=excluded.data WHERE devices.user_id!=excluded.user_id OR devices.data!=excluded.data', (key, value['user'], json.dumps(data)))
            for (device, protocol), raw in desired_protocols.items():
                db.execute('INSERT INTO protocols VALUES (?,?,?) ON CONFLICT(device_id,name) DO NOTHING', (device, protocol, raw))
            for (key,) in db.execute('SELECT id FROM users').fetchall():
                if key not in registry['users']:
                    db.execute('DELETE FROM users WHERE id=?', (key,))
            db.execute("UPDATE metadata SET value=? WHERE key='revision'", (str(revision + 1),))
            db.execute("INSERT OR REPLACE INTO metadata VALUES ('registry-ready','yes')")
        registry['_revision'] = revision + 1

    VISIBLE = "coalesce(json_extract(d.data,'$.deleted'),0)=0 AND (NOT EXISTS(SELECT 1 FROM protocols p WHERE p.device_id=d.id) OR EXISTS(SELECT 1 FROM protocols p WHERE p.device_id=d.id AND json_extract(p.data,'$.status')!='revoked'))"

    def view_registry(self, view='overview', device='', query='', owner='', page=1, owner_query=''):
        """A bounded read model; native lifecycle operations still use full CAS registries."""
        query, owner_query = query[:80].casefold(), owner_query[:80].casefold()
        page = max(1, min(int(page), 100000))
        with self.connect() as db:
            db.execute('BEGIN')
            summary = {'users': db.execute('SELECT count(*) FROM users').fetchone()[0],
                       'devices': db.execute('SELECT count(*) FROM devices d WHERE ' + self.VISIBLE).fetchone()[0],
                       'failed': db.execute("SELECT count(*) FROM jobs WHERE hidden=0 AND status IN ('failed','interrupted')").fetchone()[0]}
            users = {}
            devices = {}
            total = 0
            if view == 'jobs':
                total = db.execute('SELECT count(*) FROM jobs WHERE hidden=0').fetchone()[0]
                page = min(page,max(1,(total+24)//25))
            elif view == 'batches':
                total = db.execute("SELECT count(*) FROM batches WHERE coalesce(json_extract(data,'$.hidden'),0)=0").fetchone()[0]
                page = min(page,max(1,(total+4)//5))
            if view == 'users':
                condition, values = "instr(casefold(json_extract(data,'$.name')),?)>0", (query,)
                total = db.execute('SELECT count(*) FROM users WHERE ' + condition, values).fetchone()[0]
                page = min(page, max(1, (total+49)//50))
                user_rows = db.execute('SELECT id,data FROM users WHERE ' + condition + " ORDER BY casefold(json_extract(data,'$.name')),id LIMIT 50 OFFSET ?", values + ((page-1)*50,)).fetchall()
            else:
                user_rows = db.execute("SELECT id,data FROM users WHERE instr(casefold(json_extract(data,'$.name')),?)>0 ORDER BY casefold(json_extract(data,'$.name')),id LIMIT 50", (owner_query,)).fetchall()
            users.update((key, json.loads(raw)) for key, raw in user_rows)
            rows = []
            if view == 'device':
                rows = db.execute('SELECT id,user_id,data FROM devices WHERE id=?', (device,)).fetchall()
            elif view in ('devices','delivery'):
                where = self.VISIBLE + " AND (?='' OR d.user_id=?) AND instr(casefold(json_extract(d.data,'$.name') || ' ' || json_extract(u.data,'$.name')),?)>0"
                values = (owner, owner, query)
                total = db.execute('SELECT count(*) FROM devices d JOIN users u ON u.id=d.user_id WHERE ' + where, values).fetchone()[0]
                page = min(page, max(1, (total+49)//50))
                rows = db.execute('SELECT d.id,d.user_id,d.data FROM devices d JOIN users u ON u.id=d.user_id WHERE ' + where + " ORDER BY casefold(json_extract(d.data,'$.name')),d.id LIMIT 50 OFFSET ?", values+((page-1)*50,)).fetchall()
            elif view in ('overview','jobs','system','batches'):
                rows = db.execute("SELECT id,user_id,data FROM devices WHERE id IN (SELECT json_extract(form,'$.device') FROM jobs WHERE hidden=0 ORDER BY created DESC LIMIT 50)").fetchall()
            if owner and owner not in users:
                found = db.execute('SELECT data FROM users WHERE id=?', (owner,)).fetchone()
                if found:
                    users[owner] = json.loads(found[0])
            for key, user, raw in rows:
                devices[key] = dict(json.loads(raw), user=user, protocols={})
                if user not in users:
                    users[user] = json.loads(db.execute('SELECT data FROM users WHERE id=?', (user,)).fetchone()[0])
            if devices:
                marks = ','.join('?' for _ in devices)
                for key, name, raw in db.execute('SELECT device_id,name,data FROM protocols WHERE device_id IN (' + marks + ')', tuple(devices)):
                    devices[key]['protocols'][name] = json.loads(raw)
            revision = db.execute("SELECT value FROM metadata WHERE key='revision'").fetchone()[0]
        return {'schema':1,'users':users,'devices':devices}, {'page':page,'total':total,'summary':summary,'revision':revision,'owner_query':owner_query,'owners':[key for key,_ in user_rows]}

    def policy_targets(self, targets):
        result = []
        with self.connect() as db:
            for kind, ident in targets:
                table = 'users' if kind == 'user' else 'devices'
                row = db.execute('SELECT data' + (',user_id' if kind == 'device' else '') + ' FROM ' + table + ' WHERE id=?', (ident,)).fetchone()
                if not row:
                    continue
                record = json.loads(row[0])
                applied = record.get('lan_policy', 'block' if kind == 'user' else 'inherit')
                user = json.loads(db.execute('SELECT data FROM users WHERE id=?', (row[1],)).fetchone()[0]) if kind == 'device' else record
                effective = applied if applied != 'inherit' else user.get('lan_policy', 'block')
                if user.get('revoked') or user.get('disabled') or record.get('disabled') or record.get('deleted'):
                    effective = 'block'
                result.append({'kind': kind, 'id': ident, 'applied': applied, 'desired': record.get('desired_lan_policy', applied), 'effective': effective, 'status': record.get('policy_status', 'applied')})
        return result

    def status_revision(self):
        with self.connect() as db:
            values = [db.execute("SELECT value FROM metadata WHERE key='revision'").fetchone()[0]]
            for table in ('jobs', 'batches'):
                values.extend(db.execute('SELECT count(*),coalesce(max(updated),0) FROM ' + table).fetchone())
            values.append(db.execute('SELECT coalesce(max(id),0) FROM audit').fetchone()[0])
            values.append(db.execute('SELECT coalesce(sum(hidden),0) FROM jobs').fetchone()[0])
        return hashlib.sha256(json.dumps(values).encode()).hexdigest()[:24]

    def audit(self, action, target, outcome):
        with self.connect() as db:
            db.execute('INSERT INTO audit(time,action,target,outcome) VALUES (?,?,?,?)', (time.time(), action, target, outcome))

    def cleanup(self):
        with self.connect() as db:
            now = time.time()
            last = db.execute("SELECT value FROM metadata WHERE key='last_cleanup'").fetchone()
            if last and now - float(last[0]) < 3600:
                return
            db.execute('DELETE FROM audit WHERE time<? OR id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT 50000)', (now - 90 * 86400,))
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='auth_events'").fetchone():
                db.execute('DELETE FROM auth_events WHERE time<? OR id NOT IN (SELECT id FROM auth_events ORDER BY id DESC LIMIT 50000)',(now-90*86400,))
            db.execute("DELETE FROM jobs WHERE status IN ('complete','failed','interrupted') AND (updated<? OR id NOT IN (SELECT id FROM jobs ORDER BY created DESC LIMIT 1000))", (now - 30 * 86400,))
            db.execute("DELETE FROM batches WHERE updated<?", (now - 30 * 86400,))
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='tokens'").fetchone():
                db.execute('DELETE FROM tokens WHERE expires<? OR (used IS NOT NULL AND used<?)', (now-86400,now-86400))
            db.execute("INSERT OR REPLACE INTO metadata VALUES ('last_cleanup',?)", (str(now),))
        for folder in ('batch-secrets', 'job-secrets'):
            directory = self.base / folder
            if directory.exists():
                for path in directory.iterdir():
                    if path.is_file() and not path.is_symlink() and now - path.stat().st_mtime > 86400:
                        path.unlink(missing_ok=True)

    def batches(self, limit=20, offset=0):
        with self.connect() as db:
            return [dict(json.loads(raw), id=ident) for ident, raw in db.execute("SELECT id,data FROM batches WHERE coalesce(json_extract(data,'$.hidden'),0)=0 ORDER BY updated DESC LIMIT ? OFFSET ?", (min(20, max(1, limit)), max(0, offset)))]

    def batch(self, ident):
        with self.connect() as db:
            row = db.execute('SELECT data FROM batches WHERE id=?', (ident,)).fetchone()
        if not row:
            raise ValueError('Batch not found.')
        return json.loads(row[0])

    def save_batch(self, ident, value):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute('SELECT data FROM batches WHERE id=?', (ident,)).fetchone()
            if existing and json.loads(existing[0]).get('cancel'):
                value['cancel'] = True
            if value.get('cancel') and value['status'] in ('preview', 'queued', 'failed'):
                value['status'] = 'cancelled'
            db.execute('INSERT OR REPLACE INTO batches VALUES (?,?,?)', (ident, json.dumps(value), time.time()))

    def batch_cancel(self, ident):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT data FROM batches WHERE id=?', (ident,)).fetchone()
            if not row:
                raise ValueError('Batch not found.')
            value = json.loads(row[0])
            value['cancel'] = True
            if value['status'] in ('preview', 'queued', 'failed'):
                value['status'] = 'cancelled'
                (self.base / 'batch-secrets' / ident).unlink(missing_ok=True)
            db.execute('UPDATE batches SET data=?,updated=? WHERE id=?', (json.dumps(value), time.time(), ident))

    def enqueue(self, form):
        ident, now = secrets.token_hex(16), time.time()
        form = {key: value for key, value in form.items() if not key.startswith('_')}
        private = {key: form.pop(key) for key in ('password', 'l2tp_password', 'archive_password') if form.get(key)}
        form.pop('csrf', None)
        path = self.base / 'job-secrets' / ident
        try:
            with self.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                rows = db.execute("SELECT id,form FROM jobs WHERE status IN ('queued','running')").fetchall()
                for previous, raw in rows:
                    saved = json.loads(raw)
                    reference = saved.pop('_secret', '')
                    if saved != form:
                        continue
                    values = {}
                    if reference:
                        source = self.base / 'job-secrets' / reference
                        if not source.exists():
                            continue
                        values = json.loads(source.read_text())
                    if values == private:
                        return previous
                if len(rows) >= 100:
                    raise ValueError('Job queue is full; wait for current work to finish.')
                if private:
                    path.parent.mkdir(mode=0o700, exist_ok=True)
                    with open(path, 'x', opener=lambda name, flags: os.open(name, flags, 0o600)) as stream:
                        json.dump(private, stream)
                    form['_secret'] = ident
                db.execute('INSERT INTO jobs(id,action,form,status,created,updated,result) VALUES (?,?,?,?,?,?,NULL)', (ident, form['action'], json.dumps(form, sort_keys=True), 'queued', now, now))
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return ident

    def jobs(self, limit=100, offset=0, device=None):
        with self.connect() as db:
            return [dict(id=i, action=a, status=s, created=c, updated=u, device=json.loads(f).get('device', ''), result=json.loads(r) if r else None) for i, a, s, c, r, f, u in db.execute("SELECT id,action,status,created,result,form,updated FROM jobs WHERE hidden=0 AND (? IS NULL OR json_extract(form,'$.device')=?) ORDER BY created DESC LIMIT ? OFFSET ?", (device, device, min(100, max(1, limit)), max(0, offset)))]

    def job_subset(self, ids):
        if not ids:
            return []
        with self.connect() as db:
            rows = db.execute("SELECT id,action,status,created,updated,form,result FROM jobs WHERE hidden=0 AND id IN (" + ','.join('?' for _ in ids) + ')', tuple(ids))
            return [dict(id=i, action=a, status=s, created=c, updated=u, device=json.loads(f).get('device',''), result=json.loads(r) if r else None) for i,a,s,c,u,f,r in rows]

    def batch_subset(self, ids):
        if not ids:
            return []
        with self.connect() as db:
            rows = db.execute('SELECT id,data FROM batches WHERE id IN (' + ','.join('?' for _ in ids) + ')', tuple(ids))
            return [dict(json.loads(raw),id=ident) for ident,raw in rows if not json.loads(raw).get('hidden')]

    def recover_jobs(self):
        with self.connect() as db:
            db.execute("UPDATE jobs SET status='interrupted',updated=?,result=? WHERE status='running'", (time.time(), json.dumps({'message': 'Interrupted. Inspect device recovery before retrying; credentials were not regenerated automatically.'})))

    def retry(self, ident):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT form,status FROM jobs WHERE id=?', (ident,)).fetchone()
            if not row or row[1] not in ('failed', 'interrupted'):
                raise ValueError('Only failed/interrupted jobs can be retried.')
            form = json.loads(row[0])
            if form.get('action') not in ('protocols-add', 'export', 'prepare-export', 'bundle', 'policy', 'repair', 'batch-run', 'delete-profile', 'connection-check'):
                raise ValueError('Review the device and request this operation explicitly; destructive jobs are not automatically replayed.')
            if form.get('action') == 'batch-run':
                batch = db.execute('SELECT data FROM batches WHERE id=?', (form['batch'],)).fetchone()
                if not batch:
                    raise ValueError('Batch history has expired.')
                value = json.loads(batch[0])
                if value.get('cancel'):
                    raise ValueError('Cancelled batches cannot be resumed.')
                for item in value['items']:
                    if item['status'] == 'failed':
                        item['status'] = 'waiting'
                value['status'] = 'queued'
                db.execute('UPDATE batches SET data=?,updated=? WHERE id=?', (json.dumps(value), time.time(), form['batch']))
            db.execute("UPDATE jobs SET status='queued',hidden=0,updated=?,result=NULL WHERE id=?", (time.time(), ident))

    def pending_delete(self, device):
        with self.connect() as db:
            return bool(db.execute("SELECT 1 FROM jobs WHERE action='delete-profile' AND status IN ('queued','running','failed','interrupted') AND json_extract(form,'$.device')=? LIMIT 1", (device,)).fetchone())

    def retry_batch(self, ident):
        with self.connect() as db:
            row = db.execute("SELECT id FROM jobs WHERE action='batch-run' AND json_extract(form,'$.batch')=? AND status IN ('failed','interrupted') ORDER BY updated DESC LIMIT 1", (ident,)).fetchone()
        if not row:
            raise ValueError('No failed or interrupted task exists for this batch.')
        self.retry(row[0])

    def scrub_device_secrets(self, backend, device, protocol):
        keys = {'archive_password'}
        if protocol == 'ikev2':
            keys.add('password')
        if protocol == 'l2tp':
            keys.add('l2tp_password')
        directory = self.base / 'batch-secrets'
        if directory.exists():
            for path in directory.iterdir():
                if path.is_symlink() or not path.is_file():
                    continue
                data = json.loads(path.read_text())
                if device in data:
                    data[device] = {key: value for key, value in data[device].items() if key not in keys}
                    backend.m.atomic(path, json.dumps(data))
        with self.connect() as db:
            rows = list(db.execute("SELECT form FROM jobs WHERE json_extract(form,'$.device')=?", (device,)))
        for (raw,) in rows:
            reference = json.loads(raw).get('_secret', '')
            if reference and re.fullmatch(r'[a-f0-9]{32}', reference):
                path = self.base / 'job-secrets' / reference
                if path.is_file() and not path.is_symlink():
                    data = {key: value for key, value in json.loads(path.read_text()).items() if key not in keys}
                    backend.m.atomic(path, json.dumps(data))

    def clear_history(self):
        with self.connect() as db:
            db.execute("UPDATE jobs SET hidden=1 WHERE status='complete'")
            db.execute("UPDATE batches SET data=json_set(data,'$.hidden',1) WHERE json_extract(data,'$.status') IN ('complete','cancelled')")

    def job_progress(self, backend, running, stage):
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        # Boot-bound telemetry is disposable; authoritative jobs remain durable in SQLite.
        backend.m.atomic(self.base / 'backend-job-health.json', json.dumps({'boot': boot, 'monotonic': time.monotonic(), 'running': running, 'stage': stage, 'job': getattr(backend, '_job_id', '')}),durable=False)

    def run_one(self, backend, execute):
        # Acquire native-operation lock before claiming work. Competing CLI/update leaves it queued.
        try:
            with backend.m.lock():
                with self.connect() as db:
                    db.execute('BEGIN IMMEDIATE')
                    row = db.execute("SELECT id,form FROM jobs WHERE status='queued' ORDER BY CASE WHEN action IN ('policy','delete-profile') THEN 0 ELSE 1 END,updated,created LIMIT 1").fetchone()
                    if not row:
                        return False
                    db.execute("UPDATE jobs SET status='running',updated=? WHERE id=?", (time.time(), row[0]))
                try:
                    backend._job_id = row[0]
                    self.job_progress(backend, True, 'started')
                    options = json.loads(row[1])
                    secret = options.pop('_secret', '')
                    if secret:
                        path = self.base / 'job-secrets' / secret
                        if not path.exists():
                            raise ValueError('Private job password expired. Submit a new request.')
                        options.update(json.loads(path.read_text()))
                    result = execute(options)
                    status = 'queued' if result.pop('_reschedule', False) else 'complete'
                except Exception as exc:
                    self.audit('job-failure', row[0], type(exc).__name__)
                    detail = str(exc) if isinstance(exc, (ValueError, RuntimeError, OSError)) else type(exc).__name__
                    result = {'message': 'Operation failed: ' + detail + '. Inspect device recovery before retrying.', 'reference':row[0]}
                    status = 'failed'
                secret = json.loads(row[1]).get('_secret', '')
                if secret:
                    (self.base / 'job-secrets' / secret).unlink(missing_ok=True)
                backend._job_id = ''
                backend._phase = ''
                self.job_progress(backend, False, status)
                from vpn_harden import release_memory
                release_memory()
                with self.connect() as db:
                    db.execute('UPDATE jobs SET status=?,updated=?,result=?,form=? WHERE id=?', (status, time.time(), json.dumps(result), json.dumps({key: value for key, value in json.loads(row[1]).items() if key not in ('password', 'l2tp_password', 'archive_password', '_secret', 'csrf') and (key != 'confirm' or json.loads(row[1]).get('action') == 'delete-profile')}), row[0]))
                return True
        except RuntimeError as exc:
            if 'Another install or profile' in str(exc):
                return False
            raise


def bundle(backend, ident, protocols, password=None):
    import pyzipper
    protocols = sorted(set(protocols))
    if not protocols or any(p not in ('wireguard', 'ikev2', 'l2tp') for p in protocols):
        raise ValueError('Select one or more supported protocols.')
    _, device = backend.device(ident)
    files = {}
    identity = {}
    for protocol in protocols:
        record = device['protocols'].get(protocol)
        if not record or record['status'] != 'active':
            raise ValueError('An active protocol and validated export are required: ' + protocol)
        identity[protocol] = record['backend']
        if protocol == 'ikev2':
            export = record.get('export') or {}
            identity[protocol] += ':' + export.get('generation', '')
            if not export.get('files'):
                raise ValueError('Create a validated IKEv2 export before bundling.')
            for name in export['files']:
                files[protocol + '/' + name] = backend.exported_file(ident, name).read_bytes()
        else:
            name = record['backend'] + ('.conf' if protocol == 'wireguard' else '.txt')
            source = backend.base / 'clients' / protocol / name
            if source.is_symlink() or not source.is_file():
                raise ValueError('Private profile is missing or unsafe.')
            files[protocol + '/' + name] = source.read_bytes()
            identity[protocol] += ':' + hashlib.sha256(files[protocol + '/' + name]).hexdigest()
    if sum(len(data) for data in files.values()) > 5 * 1024**2:
        raise ValueError('Delivery exceeds the 5 MiB limit.')
    password = password or secrets.token_urlsafe(32)
    if not 12 <= len(password) <= 128 or any(c in password for c in '\r\n\0'):
        raise ValueError('Archive password must contain 12–128 characters without line breaks.')
    output = io.BytesIO()
    with pyzipper.AESZipFile(output, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as archive:
        archive.setpassword(password.encode())
        archive.setencryption(pyzipper.WZ_AES, nbits=256)
        for name, data in files.items():
            archive.writestr(name, data)
    # Re-read every member before publication. Native bytes must remain identical.
    with pyzipper.AESZipFile(io.BytesIO(output.getvalue())) as archive:
        archive.setpassword(password.encode())
        if {name: archive.read(name) for name in archive.namelist()} != files:
            raise RuntimeError('Encrypted delivery validation failed.')
    generation = secrets.token_hex(16)
    path = backend.base / 'deliveries' / ident / (generation + '.zip')
    backend.m.atomic(path, output.getvalue())
    metadata = {'filename': path.name, 'identity': identity, 'sha256': hashlib.sha256(output.getvalue()).hexdigest(), 'password': password}
    with backend.repo.connect() as db:
        db.execute('INSERT OR REPLACE INTO deliveries VALUES (?,?,?)', (ident, generation, json.dumps(metadata)))
    for previous in path.parent.glob('*.zip'):
        if previous != path and not previous.is_symlink():
            previous.unlink(missing_ok=True)
    return {'generation': generation, **metadata}


def delivery_file(backend, ident, generation, filename):
    with backend.repo.connect() as db:
        row = db.execute('SELECT generation,data FROM deliveries WHERE device=?', (ident,)).fetchone()
    if not row or row[0] != generation:
        raise ValueError('This delivery has been superseded. Create a new link.')
    data = json.loads(row[1])
    if filename != data['filename']:
        raise ValueError('Invalid delivery filename.')
    _, device = backend.device(ident)
    for protocol, identity in data['identity'].items():
        record = device['protocols'].get(protocol, {})
        if record.get('status') != 'active':
            raise ValueError('This delivery is revoked.')
        actual = record['backend']
        if protocol == 'ikev2':
            actual += ':' + (record.get('export') or {}).get('generation', '')
        else:
            name = record['backend'] + ('.conf' if protocol == 'wireguard' else '.txt')
            actual += ':' + hashlib.sha256((backend.base / 'clients' / protocol / name).read_bytes()).hexdigest()
        if actual != identity:
            raise ValueError('Credentials changed. Create a new delivery.')
    path = backend.base / 'deliveries' / ident / filename
    if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != data['sha256']:
        raise ValueError('Delivery integrity check failed.')
    return path


def random_name(prefix):
    return prefix + '-' + secrets.token_hex(5)


def export_password(form, manager):
    mode = form.get('password_mode', 'custom' if form.get('password') else 'keep')
    if mode not in ('keep', 'random', 'custom'):
        raise ValueError('Choose an import password mode.')
    if mode == 'custom':
        password = form.get('password', '')
        if not 12 <= len(password) <= 128 or any(c in password for c in '\r\n\0'):
            raise ValueError('Import password must contain 12–128 characters without line breaks.')
        return password
    return manager.random_password() if mode == 'random' else None


def preview_batch(backend, form):
    from vpn_clients import label, live_device
    repo, registry = backend.repo, backend.load()
    kind = form.get('batch_kind', 'create')
    selected = list(dict.fromkeys(form.get('protocols', 'ikev2').split(',')))
    if not selected or any(p not in ('ikev2', 'wireguard', 'l2tp') for p in selected):
        raise ValueError('Select supported protocols.')
    platform = form.get('platform', 'apple')
    if platform not in ('apple', 'android', 'windows', 'other'):
        raise ValueError('Unsupported platform.')
    with repo.connect() as db:
        if db.execute("SELECT count(*) FROM batches WHERE updated>?", (time.time() - 86400,)).fetchone()[0] >= 100:
            raise ValueError('Daily batch limit reached; retry after older batches expire.')
    mode = form.get('password_mode', 'random' if kind == 'create' else 'keep')
    custom = export_password(dict(form, password_mode=mode), backend.m)
    # Random passwords are generated independently below, never shared accidentally.
    if mode == 'random':
        custom = None
    items = []
    if kind == 'export':
        devices = list(dict.fromkeys(form.get('devices', '').split(',')))
        if not 1 <= len(devices) <= 50:
            raise ValueError('Select 1–50 devices.')
        for device in devices:
            row = registry['devices'].get(device)
            if not row or any(row['protocols'].get(p, {}).get('status') != 'active' for p in selected):
                raise ValueError('Every selected device must have the selected protocols active.')
            items.append({'device': device, 'user': row['user'], 'name': row['name'], 'user_name': registry['users'][row['user']]['name'], 'status': 'waiting'})
    elif kind == 'create':
        try:
            count = int(form.get('count', '1'))
        except ValueError:
            raise ValueError('Batch count must be 1–50.') from None
        if not 1 <= count <= 50:
            raise ValueError('Batch count must be 1–50.')
        ownership = form.get('ownership', 'existing')
        if ownership not in ('existing', 'new') or ownership == 'existing' and form.get('user') not in registry['users']:
            raise ValueError('Select an existing owner or new users.')
        users = {u['name'].casefold() for u in registry['users'].values()}
        names = {(d['user'], d['name'].casefold()) for d in registry['devices'].values() if live_device(d)}
        for index in range(1, count + 1):
            user = form.get('user') if ownership == 'existing' else 'usr-' + secrets.token_hex(6)
            uname = registry['users'][user]['name'] if ownership == 'existing' else (random_name('user') if form.get('random_users') == 'yes' else label(form.get('user_prefix', 'User') + '-' + str(index)))
            if ownership == 'new':
                if uname.casefold() in users:
                    raise ValueError('User name already exists: ' + uname)
                users.add(uname.casefold())
            name = random_name('device') if form.get('random_devices') == 'yes' else label(form.get('device_prefix', 'Device') + '-' + str(index))
            if (user, name.casefold()) in names:
                raise ValueError('Device name already exists: ' + name)
            names.add((user, name.casefold()))
            items.append({'device': 'dev-' + secrets.token_hex(6), 'user': user, 'new_user': ownership == 'new', 'user_name': uname, 'name': name, 'status': 'waiting'})
    else:
        raise ValueError('Unsupported batch mode.')
    if kind == 'create' and 'l2tp' in selected:
        used = {p.get('backend') for d in registry['devices'].values() for name, p in d['protocols'].items() if name == 'l2tp'}
        for index, item in enumerate(items, 1):
            native = random_name('vpn') if form.get('random_l2tp', 'yes') == 'yes' else form.get('l2tp_prefix', 'vpn') + '-' + str(index)
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', native) or native in used:
                raise ValueError('L2TP username is invalid or already reserved.')
            used.add(native)
            item['l2tp_username'] = native
    l2tp_password = form.get('l2tp_password', '')
    if l2tp_password:
        backend.m.valid_password(l2tp_password)
    ident = secrets.token_hex(16)
    private = {item['device']: {'password': custom or (backend.m.random_password() if mode == 'random' else None), 'l2tp_password': l2tp_password or backend.m.random_password()} for item in items}
    backend.m.atomic(backend.base / 'batch-secrets' / ident, json.dumps(private))
    data = {'kind': kind, 'protocols': selected, 'platform': platform, 'on_demand': form.get('on_demand') == 'yes', 'password_mode': mode, 'items': items, 'status': 'preview', 'created': time.time()}
    repo.save_batch(ident, data)
    return {'message': 'Preview ready. Review the batch below, then confirm. No users or VPN identities have been created.'}


def run_batch(backend, ident, authorize=None):
    if authorize: authorize()
    repo = backend.repo
    data = repo.batch(ident)
    if data['status'] == 'complete':
        return {'message': 'Batch already complete.'}
    if data.get('cancel'):
        data['status'] = 'cancelled'
        repo.save_batch(ident, data)
        (backend.base / 'batch-secrets' / ident).unlink(missing_ok=True)
        return {'message': 'Batch cancelled.'}
    if data['status'] == 'preview':
        raise ValueError('Confirm the preview before running this batch.')
    path = backend.base / 'batch-secrets' / ident
    private = json.loads(path.read_text()) if path.exists() else {}
    yielding = bool(getattr(backend, '_job_id', ''))
    def checkpoint(stage):
        repo.save_batch(ident, data)
        repo.job_progress(backend, True, stage)
        return {'message': stage, '_reschedule': True}
    failed = False
    for index, item in enumerate(data['items']):
        if authorize: authorize()
        if item['status'] in ('complete', 'failed'):
            continue
        if repo.batch(ident).get('cancel'):
            data.update(cancel=True, status='cancelled')
            repo.save_batch(ident, data)
            path.unlink(missing_ok=True)
            return {'message': 'Batch cancelled between operations. Completed devices were retained.'}
        repo.job_progress(backend, True, 'batch item ' + str(index + 1))
        item['status'] = 'running'
        data['status'] = 'running'
        repo.save_batch(ident, data)
        try:
            registry = backend.load()
            if data['kind'] == 'create':
                # Planned immutable IDs make metadata creation atomic and retry-safe.
                from vpn_clients import label, live_device
                if item['user'] not in registry['users']:
                    if not item.get('new_user') or any(u['name'].casefold() == item['user_name'].casefold() for u in registry['users'].values()):
                        raise ValueError('Owner no longer available or name now occupied.')
                    registry['users'][item['user']] = {'name': label(item['user_name']), 'lan_policy': 'block'}
                if item['device'] not in registry['devices']:
                    if any(live_device(d) and d['user'] == item['user'] and d['name'].casefold() == item['name'].casefold() for d in registry['devices'].values()):
                        raise ValueError('Device name now occupied.')
                    registry['devices'][item['device']] = {'name': label(item['name']), 'user': item['user'], 'lan_policy': 'inherit', 'protocols': {}}
                    backend.save(registry)
                    if yielding:
                        return checkpoint('Device created; configuring protocols next.')
                for protocol in data['protocols']:
                    if authorize: authorize()
                    if repo.batch(ident).get('cancel'):
                        break
                    record = backend.device(item['device'])[1]['protocols'].get(protocol)
                    if record and record.get('status') != 'active':
                        raise ValueError('Incomplete or revoked identity: use device recovery before retrying.')
                    if not record:
                        operation = backend.base / 'operations' / (item['device'] + '.json')
                        if operation.exists() and json.loads(operation.read_text()).get('status') != 'complete':
                            raise ValueError('Interrupted native operation: recover this device before retrying.')
                        if protocol == 'l2tp':
                            if item['device'] not in private:
                                raise ValueError('Private credentials expired; cancel and recover this device.')
                            backend.protocol_add(item['device'], protocol, private[item['device']]['l2tp_password'], username=item.get('l2tp_username'))
                        else:
                            backend.protocol_add(item['device'], protocol)
                        if yielding:
                            return checkpoint('Configured ' + protocol + '; next operation queued.')
            for protocol in data['protocols']:
                if backend.device(item['device'])[1]['protocols'].get(protocol, {}).get('status') != 'active':
                    raise ValueError('Selected protocol is not active; inspect device recovery.')
            if authorize: authorize()
            if 'ikev2' in data['protocols'] and not item.get('exported'):
                if data['password_mode'] != 'keep' and item['device'] not in private:
                    raise ValueError('Private batch password expired. Prepare a new export.')
                backend.export_ike(item['device'], data['platform'], private.get(item['device'], {}).get('password'), data['on_demand'])
                item['exported'] = True
                item.update(status='complete', message='Validated profile ready; open the device to download or deliver.')
                if yielding:
                    return checkpoint('Profile validated; finalizing this device next.')
            item.update(status='complete', message='Ready. Open the device to download, reveal credentials, or publish a delivery link.')
        except Exception:
            # Tool output and passwords must never enter the live task feed.
            item.update(status='failed', message='Operation failed. Open device recovery and diagnostics before retrying.')
            repo.audit('batch-item-failed', item['device'], 'inspect device recovery')
            failed = True
        current = repo.batch(ident)
        data['cancel'] = current.get('cancel', False)
        repo.save_batch(ident, data)
        repo.job_progress(backend, True, 'batch item finished ' + str(index + 1))
        if yielding and index + 1 < len(data['items']):
            return checkpoint('Device finished; next item queued.')
    failed = any(item['status'] == 'failed' for item in data['items'])
    data['cancel'] = repo.batch(ident).get('cancel', False)
    data['status'] = 'cancelled' if data['cancel'] else 'failed' if failed else 'complete'
    repo.save_batch(ident, data)
    if not failed or data['cancel']:
        path.unlink(missing_ok=True)
    if failed:
        raise ValueError('Batch partially failed. Completed devices were retained; inspect individual results and retry.')
    return {'message': 'Batch complete: ' + str(len(data['items'])) + ' devices ready.'}



def ike_targets(text, native):
    """Only authenticated per-client connection blocks with explicit parent SA serials."""
    blocks = {}
    for line in text.splitlines():
        match = re.match(r'^\s*(?:[0-9]{3}\s+)?("ikev2-cp"\[[0-9]+\](?:\s+[0-9.]+)?):\s*(.*)$', line)
        if match:
            blocks.setdefault(match[1], []).append(match[2])
    targets = set()
    valid_ids = {native, '@' + native, 'O=IKEv2 VPN,CN=' + native, 'CN=' + native + ',O=IKEv2 VPN'}
    for lines in blocks.values():
        identity = next((m[1].strip().strip('"\'') for line in lines if (m := re.search(r'their id=([^;]+)', line))), '')
        identity = re.sub(r'\s*,\s*', ',', identity)
        if identity not in valid_ids:
            continue
        for line in lines:
            match = re.search(r'(?:established IKE SA:|newest ISAKMP SA:)\s*#([1-9][0-9]*)', line)
            if match:
                targets.add(int(match[1]))
    return targets


def disconnect_profile(backend, ident, protocol, native):
    import signal
    if protocol == 'wireguard':
        # Native revocation removes the live peer before this stage.
        return
    with backend.repo.connect() as db:
        rows = [json.loads(raw) for (raw,) in db.execute('SELECT data FROM policy_sessions')]
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    sessions = [row for row in rows if row.get('device') == ident and row.get('protocol') == protocol and row.get('boot') == boot]
    if protocol == 'ikev2':
        before = backend.m.command(['ipsec', 'whack', '--status'], timeout=10).stdout
        targets = ike_targets(before, native)
        unparsed = 'ikev2-cp' in before and re.search(r'(?:established IKE SA:|newest ISAKMP SA:)\s*#[1-9]', before) and not re.search(r'their id=', before)
        if (sessions or unparsed) and not targets:
            raise ValueError('Credentials revoked; active IKE session cannot be matched safely. Retry after disconnect.')
        for serial in sorted(targets):
            current = backend.m.command(['ipsec', 'whack', '--status'], timeout=10).stdout
            if serial in ike_targets(current, native):
                backend.m.command(['ipsec', 'whack', '--deletestate', str(serial)], timeout=10)
        after = backend.m.command(['ipsec', 'whack', '--status'], timeout=10).stdout
        if ike_targets(after, native):
            raise ValueError('IKE disconnection is incomplete; retry deletion.')
    else:
        for row in sessions:
            interface = row['interface']
            if not re.fullmatch(r'ppp[0-9]+', interface):
                raise ValueError('PPP session identity is invalid.')
            info = backend.m.command(['ip', '-j', 'link', 'show', 'dev', interface], check=False, timeout=5)
            if info.returncode:
                continue
            link = json.loads(info.stdout)[0]
            if int(link['ifindex']) != row['ifindex'] or int(link.get('group', 0)) != row['ifindex']:
                continue  # Interface was reused; never terminate its new owner.
            pidfile = Path('/run') / (interface + '.pid')
            try:
                pid = int(pidfile.read_text().splitlines()[0])
                if pid != row.get('pid') or not row.get('process_start'):
                    raise ValueError('PPP process was not recorded by its authenticated hook; reconnect or disconnect it manually.')
                proc = Path('/proc') / str(pid)
                if pid <= 1 or proc.joinpath('exe').resolve().name != 'pppd' or proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19] != row['process_start']:
                    raise ValueError('PPP process ownership is not verified.')
                address = backend.m.command(['ip', '-j', '-4', 'addr', 'show', 'dev', interface], timeout=5)
                if not any(value.get('peer', '').split('/')[0] == row['address'] for value in json.loads(address.stdout)[0].get('addr_info', [])):
                    raise ValueError('PPP peer address no longer matches.')
                descriptor = os.pidfd_open(pid)
                try:
                    if int(pidfile.read_text().splitlines()[0]) != pid or proc.joinpath('exe').resolve().name != 'pppd' or proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19] != row['process_start']:
                        raise ValueError('PPP process changed during verification.')
                    signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                    import select
                    if not select.select([descriptor], [], [], 5)[0]:
                        raise ValueError('PPP process has not exited; retry deletion.')
                finally:
                    os.close(descriptor)
            except FileNotFoundError:
                # A missing pidfile while the interface still exists is ambiguous.
                raise ValueError('PPP session requires manual disconnect; retry deletion afterward.') from None
    with backend.repo.connect() as db:
        for row in sessions:
            db.execute("DELETE FROM policy_sessions WHERE json_extract(data,'$.device')=? AND json_extract(data,'$.protocol')=?", (ident, protocol))
