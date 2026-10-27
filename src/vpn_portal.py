"""Immutable device file grants; a token always permits one total download."""
import hashlib
import json
from pathlib import Path
import re


def device_record(backend, ident):
    with backend.repo.connect() as db:
        db.execute('BEGIN')
        row=db.execute('SELECT user_id,data FROM devices WHERE id=?',(ident,)).fetchone()
        if not row:
            raise ValueError('This device is unavailable.')
        device=dict(json.loads(row[1]),user=row[0],protocols={})
        user=json.loads(db.execute('SELECT data FROM users WHERE id=?',(row[0],)).fetchone()[0])
        device['protocols']={name:json.loads(raw) for name,raw in db.execute('SELECT name,data FROM protocols WHERE device_id=?',(ident,))}
    from vpn_business import expired
    if expired(device) or expired(user):
        raise ValueError('This device is unavailable.')
    return device


def ike_file(backend, ident, export, name):
    generation=export.get('generation','')
    for value in (ident,generation,name):
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,120}',value) or value in ('.','..'):
            raise ValueError('Prepared profile identity is invalid.')
    if name not in export.get('files',[]):
        raise ValueError('This file is unavailable.')
    folder=backend.base/'exports'/ident/generation
    path=folder/name
    if any(parent.is_symlink() for parent in (backend.base/'exports',folder.parent,folder)) or path.is_symlink() or not path.is_file() or path.stat().st_size>5*1024**2:
        raise ValueError('This prepared profile is unavailable.')
    expected=export.get('sha256',{}).get(name)
    if expected and hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
        raise ValueError('This prepared profile changed. Prepare it again.')
    return path


def snapshot(backend, ident):
    if backend.repo.pending_delete(ident):
        raise ValueError('Profile delivery is unavailable while deletion is pending.')
    device = device_record(backend,ident)
    files = []
    for protocol, record in sorted(device['protocols'].items()):
        if record.get('status') != 'active' or record.get('deletion'):
            continue
        native = record['backend']
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', native):
            raise ValueError('Profile identity is invalid.')
        if protocol == 'ikev2':
            export = record.get('export') or {}
            sources = [(name, ike_file(backend,ident,export,name), export.get('generation', '')) for name in export.get('files', [])]
        else:
            suffix = '.conf' if protocol == 'wireguard' else '.txt'
            name = native + suffix
            path = backend.base / 'clients' / protocol / name
            sources = [(name, path, native)] if path.is_file() else []
        for name, path, generation in sources:
            if path.is_symlink() or not path.is_file() or not re.fullmatch(r'[A-Za-z0-9_.-]{1,120}', name):
                raise ValueError('A prepared file is unavailable.')
            if path.stat().st_size > 5 * 1024**2:
                raise ValueError('Profile exceeds the delivery size limit.')
            files.append({'filename': name, 'protocol': protocol, 'identity': native, 'generation': generation,
                          'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'size': path.stat().st_size})
    if not files:
        raise ValueError('Prepare at least one profile before publishing a device token.')
    if len(files) > 8 or len({f['filename'] for f in files}) != len(files):
        raise ValueError('Prepared file names are ambiguous.')
    # Prefer Safari's native profile when the recipient has an Apple device.
    files.sort(key=lambda item: (not item['filename'].endswith('.mobileconfig'), item['protocol'], item['filename']))
    return {'device': ident, 'user':device['user'], 'name': device['name'], 'files': files}


def publish(backend, store, ident, lifetime):
    manifest = snapshot(backend, ident)
    generation = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    token = store.issue(ident, '@device', generation, lifetime, manifest=manifest)
    return token, manifest


def inspect(backend, store, token, record):
    with store.connect() as db:
        row = db.execute('SELECT data FROM token_manifests WHERE hash=?', (__import__('vpn_web').digest(token),)).fetchone()
    if not row:
        raise ValueError('This device delivery is unavailable.')
    manifest = json.loads(row[0])
    current = snapshot(backend, record['device'])
    # Display names may change; credential identity and exact prepared bytes may not.
    if manifest.get('user') != current['user'] or manifest['files'] != current['files']:
        raise ValueError('Profiles changed or were revoked. Request a new token.')
    return manifest


def resolve(backend, manifest, filename):
    item = next((f for f in manifest['files'] if f['filename'] == filename), None)
    if item is None:
        raise ValueError('Choose a file authorized by this token.')
    if item['protocol'] == 'ikev2':
        device=device_record(backend,manifest['device'])
        path=ike_file(backend,manifest['device'],device['protocols']['ikev2'].get('export') or {},filename)
    else:
        path = backend.base / 'clients' / item['protocol'] / filename
    if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
        raise ValueError('This prepared file has changed. Request a new token.')
    return path
