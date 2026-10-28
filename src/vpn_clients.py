"""Shared root-side users/devices backend. No network listener in this module."""
import base64
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid


class ClientError(RuntimeError):
    pass


def label(value):
    value = str(value).strip()
    if not value or len(value) > 80 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ClientError('Use a name of 1–80 characters without control characters.')
    return value


def live_device(record):
    if record.get('deleted'):
        return False
    protocols = record.get('protocols', {})
    return not protocols or any(value.get('status') != 'revoked' for value in protocols.values())


class Backend:
    def __init__(self, manager):
        self.m = manager
        self.base = manager.BASE
        self.registry = self.base / 'registry.json'
        self.db = manager.ETC / 'ipsec.d'
        from vpn_backend import Repository
        self.repo = Repository(self.base)

    @property
    def cert_db(self):
        from vpn_native import nss_directory
        return nss_directory(self.m)

    def command(self, args, *, data=None, env=None):
        progress = self.base / 'backend-job-health.json'
        try:
            running = json.loads(progress.read_text()).get('running', False)
        except (OSError, ValueError):
            running = False
        if running:
            self.repo.job_progress(self, True, getattr(self,'_phase','') or 'tool: ' + Path(str(args[0])).name)
        try:
            result = subprocess.run(list(map(str, args)), input=data, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=180, env=env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.tool_failure(args, type(exc).__name__, str(exc))
            raise ClientError(Path(str(args[0])).name + ' could not complete. See logs/client-tool-failure-latest.json.') from None
        finally:
            if running:
                self.repo.job_progress(self, True, getattr(self,'_phase','') or 'tool finished')
        if result.returncode:
            stderr = result.stderr.decode(errors='replace')
            codes = re.findall(r'\b(?:SEC_ERROR|SSL_ERROR)_[A-Z0-9_]+\b', stderr)
            reason = codes[0] if codes else 'exit ' + str(result.returncode)
            self.tool_failure(args, reason, stderr)
            raise ClientError(f'{Path(str(args[0])).name} failed ({reason}). Details: logs/client-tool-failure-latest.json. The previous export is preserved.')
        return result.stdout

    def tool_failure(self, args, reason, stderr):
        # Log stderr only: successful stdout can contain private keys or bundles.
        text = re.sub(r'-----BEGIN [^-]+-----.*?-----END [^-]+-----', '[private data removed]', stderr, flags=re.S)
        for index, arg in enumerate(args):
            candidate = None
            if str(arg).startswith('file:'):
                candidate = Path(str(arg)[5:])
            elif index and str(args[index-1]) in ('-w', '-f'):
                candidate = Path(str(arg))
            if candidate:
                try:
                    value = candidate.read_text()[:512].strip()
                    if value:
                        text = text.replace(value, '[redacted]')
                except (OSError, UnicodeError):
                    pass
        report = {'time': int(time.time()), 'tool': Path(str(args[0])).name,
                  'reason': reason, 'job': getattr(self, '_job_id', ''), 'stderr': text[:8000]}
        self.m.atomic(self.base / 'logs/client-tool-failure-latest.json', json.dumps(report, indent=2))

    def audit(self, action, target, outcome='complete'):
        self.repo.audit(action, target, outcome)
        path = self.base / 'logs/client-audit.jsonl'
        if path.exists() and path.stat().st_size > 1024 * 1024:
            os.replace(path, path.with_suffix('.previous'))
        path.parent.mkdir(mode=0o700, exist_ok=True)
        with path.open('a') as stream:
            stream.write(json.dumps({'time': int(time.time()), 'action': action, 'target': target,
                                     'outcome': outcome}) + '\n')
        path.chmod(0o600)

    def load(self):
        registry = self.repo.load()
        if registry is None:
            self.migrate()
            registry = self.repo.load()
        return registry

    def save(self, registry):
        self.repo.save(registry)
        # Compatibility snapshot, not the authoritative database.
        try:
            self.m.atomic(self.registry, json.dumps(registry, indent=2) + '\n')
        except OSError:
            self.repo.audit('snapshot', 'registry.json', 'failed; database remains authoritative')

    def migrate(self):
        if self.repo.load() is not None:
            return
        registry = {'schema': 4, 'users': {}, 'devices': {}}
        from vpn_business import Business
        Business(self.repo)
        self.repo.save(registry)
        if not self.registry.exists():
            self.m.atomic(self.registry, json.dumps(registry, indent=2) + '\n')
        self.audit('migrate-registry', 'database-schema-1')

    def add_protocols(self, ident, protocols):
        requested = list(dict.fromkeys(protocols))
        if not requested or any(p not in ('ikev2', 'wireguard', 'l2tp') for p in requested):
            raise ClientError('Select one or more supported protocols.')
        for protocol in requested:
            record = self.device(ident)[1]['protocols'].get(protocol)
            if record and record.get('status') == 'revoked':
                self.rotate(ident, protocol)
            elif not record:
                self.protocol_add(ident, protocol)
        if 'l2tp' in requested and (self.base / 'policy-installed').exists():
            import vpn_policy
            vpn_policy.configure_ppp(self)
        return 'Selected protocols are ready; export IKEv2 separately for your device type.'

    def set_policy(self, kind, ident, policy):
        import vpn_policy
        if kind not in ('user', 'device') or policy not in (('allow', 'block') if kind == 'user' else ('inherit', 'allow', 'block')):
            raise ClientError('Invalid LAN policy.')
        registry = self.load()
        collection = registry['users'] if kind == 'user' else registry['devices']
        if ident not in collection:
            raise ClientError('Record not found.')
        collection[ident]['desired_lan_policy'] = policy
        collection[ident]['policy_status'] = 'applying'
        self.save(registry)
        previous = collection[ident].get('lan_policy', 'block' if kind == 'user' else 'inherit')
        def commit():
            collection[ident]['lan_policy'] = policy
            collection[ident]['policy_status'] = 'applied'
            self.save(registry)
        try:
            with vpn_policy.budget(30):
                vpn_policy.apply(self, override=(kind, ident, policy), commit=commit)
        except Exception:
            collection[ident]['lan_policy'] = previous
            collection[ident]['policy_status'] = 'failed'
            self.save(registry)
            # Restore the previously applied policy; never leave a failed allow staged.
            with vpn_policy.budget(30):
                vpn_policy.apply(self)
            raise
        self.audit('lan-policy-' + policy, ident)

    def user_add(self, name):
        reg = self.load()
        name = label(name)
        if any(u['name'].casefold() == name.casefold() for u in reg['users'].values()):
            raise ClientError('A user with this name already exists.')
        ident = 'usr-' + secrets.token_hex(6)
        reg['users'][ident] = {'name': name, 'lan_policy': 'block'}
        self.save(reg)
        self.audit('add-user', ident)
        return ident

    def device_add(self, user, name):
        reg = self.load()
        if user not in reg['users']:
            raise ClientError('User not found.')
        name = label(name)
        if any(live_device(d) and d['user'] == user and d['name'].casefold() == name.casefold() for d in reg['devices'].values()):
            raise ClientError('This user already has a device with that name.')
        ident = 'dev-' + secrets.token_hex(6)
        reg['devices'][ident] = {'name': name, 'user': user, 'lan_policy': 'inherit', 'protocols': {}}
        self.save(reg)
        self.audit('add-device', ident)
        return ident

    def device(self, ident):
        reg = self.load()
        if ident not in reg['devices']:
            raise ClientError('Device not found.')
        return reg, reg['devices'][ident]

    def rename(self, kind, ident, name):
        reg = self.load()
        if kind not in ('user', 'device'):
            raise ClientError('Unsupported record type.')
        collection = reg['users'] if kind == 'user' else reg['devices']
        if ident not in collection:
            raise ClientError('Record not found.')
        name = label(name)
        owner = collection[ident].get('user')
        if any(key != ident and (kind == 'user' or live_device(value)) and value['name'].casefold() == name.casefold() and (kind == 'user' or value.get('user') == owner) for key, value in collection.items()):
            raise ClientError('This display name already exists.')
        collection[ident]['name'] = name
        self.save(reg)
        self.audit('rename-' + kind, ident)

    def assign(self, ident, user):
        reg, device = self.device(ident)
        if user not in reg['users']:
            raise ClientError('User not found.')
        if any(key != ident and live_device(value) and value['user'] == user and value['name'].casefold() == device['name'].casefold() for key, value in reg['devices'].items()):
            raise ClientError('The destination user already has a device with this name.')
        device['user'] = user
        if (self.base/'policy-installed').exists():
            import vpn_policy
            try:
                vpn_policy.apply(self,registry_override=reg,commit=lambda:self.save(reg))
            except Exception:
                vpn_policy.apply(self)
                raise
        else:
            self.save(reg)
        self.audit('assign-device', ident)

    def secret(self, ident):
        path = self.base / 'secrets' / (ident + '.json')
        return json.loads(path.read_text()) if path.exists() else {}

    def save_secret(self, ident, value):
        self.m.atomic(self.base / 'secrets' / (ident + '.json'), json.dumps(value) + '\n')

    def operation(self, ident, action, status, **fields):
        path = self.base / 'operations' / (ident + '.json')
        value = {'device': ident, 'action': action, 'status': status, 'time': int(time.time()), **fields}
        self.m.atomic(path, json.dumps(value, indent=2) + '\n')
        self.audit(action, ident, status)

    def cert_names(self):
        text = self.command(['certutil', '-L', '-d', 'sql:' + str(self.cert_db)]).decode()
        # NSS nickname is the text preceding the final trust-flags column.
        names = []
        for line in text.splitlines():
            match = re.match(r'^(.*?)\s+([A-Za-z,]+)\s*$', line)
            if match and match[1].strip() and match[2].count(',') == 2:
                names.append(match[1].strip())
        return names

    def cert(self, nickname):
        return self.command(['certutil', '-L', '-a', '-d', 'sql:' + str(self.cert_db), '-n', nickname])

    def server_identity(self):
        conf = (self.db / 'ikev2.conf').read_text()
        match = re.search(r'^\s*leftcert\s*=\s*(\S+)', conf, re.M)
        if not match:
            raise ClientError('IKEv2 server certificate identity is missing.')
        return match[1]

    def discover(self):
        reg = self.load()
        known = {p['backend'] for d in reg['devices'].values() for key, p in d['protocols'].items() if key == 'ikev2'}
        result = []
        for name in self.cert_names():
            if name in known or name in ('IKEv2 VPN CA', self.server_identity()):
                continue
            pem = self.cert(name)
            text = self.command(['openssl', 'x509', '-noout', '-text'], data=pem).decode()
            if 'TLS Web Client Authentication' in text:
                result.append(name)
        return result

    def adopt(self, nickname, user, display):
        if nickname not in self.discover():
            raise ClientError('This certificate is not an unassigned client certificate.')
        ident = self.device_add(user, display)
        reg = self.load()
        reg['devices'][ident]['protocols']['ikev2'] = {'backend': nickname, 'status': 'active', 'export': None}
        self.save(reg)
        self.audit('adopt-certificate', ident)
        return ident

    def helper(self, name, action):
        source = (self.base / 'upstream/ikev2.sh').read_text()
        database_setting='CERT_DB="sql:/etc/ipsec.d"'
        if source.count(database_setting)!=1:raise ClientError('Unsupported IKEv2 helper database declaration.')
        import shlex
        source=source.replace(database_setting,'CERT_DB='+shlex.quote('sql:'+str(self.cert_db)))
        marker = 'ikev2setup "$@"'
        if source.count(marker) != 1:
            raise ClientError('Unsupported IKEv2 helper entrypoint. Install the reviewed helper with update.sh.')
        # Only certificate lifecycle is delegated. Export is handled and validated here.
        overrides = '''
# VPN: no upstream exports/password output or arbitrary output locations.
check_libreswan() { ipsec_ver=$(ipsec --version); printf '%s' \"$ipsec_ver\" | grep -qi libreswan || exit 1; }
export_client_config() { :; }
print_client_info() { :; }
get_export_dir() { export_dir=/var/lib/vpn/; export_to_home_dir=0; }
'''
        env = os.environ.copy()
        for key in ('SUDO_USER', 'SUDO_UID', 'SUDO_GID', 'VPN_PROTECT_CONFIG', 'IKEV2_CONFIG_PASSWORD'):
            env.pop(key, None)
        with tempfile.TemporaryDirectory(prefix='cert-operation-', dir=self.base) as tmp:
            script = Path(tmp) / 'helper.sh'
            self.m.atomic(script, source.replace(marker, overrides + marker), 0o700)
            self.command(['bash', script, '--' + action + 'client', name, '--yes'], env=env)

    def protocol_add(self, ident, protocol, password=None, username=None):
        reg, device = self.device(ident)
        if protocol not in ('wireguard', 'ikev2', 'l2tp'):
            raise ClientError('Unsupported protocol.')
        if protocol in device['protocols']:
            raise ClientError('Protocol already exists; retry its export or explicitly replace revoked credentials.')
        native = username if protocol == 'l2tp' and username else ident
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', native):
            raise ClientError('Use 1–64 letters, digits, underscores or hyphens for the VPN username.')
        if any(p.get('backend') == native for d in reg['devices'].values() for key, p in d['protocols'].items() if key == protocol):
            raise ClientError('VPN username is already reserved.')
        if protocol == 'l2tp':
            password = self.m.valid_password(password or self.m.random_password())
            if native in self.m.load().get('clients', {}) and 'l2tp' in self.m.load()['clients'][native]:
                raise ClientError('VPN username already exists in native configuration.')
        self.operation(ident, 'add-' + protocol, 'pending', backend=native)
        try:
            if protocol == 'ikev2':
                if native not in self.cert_names():
                    self.helper(native, 'add')
            elif protocol == 'wireguard':
                self.m.add_wg(native)
            else:
                self.m.l2tp_add(native, password or self.m.random_password())
            device['protocols'][protocol] = {'backend': native, 'status': 'active', 'export': None}
            self.save(reg)
            self.operation(ident, 'add-' + protocol, 'complete')
            if protocol == 'l2tp' and (self.base / 'policy-installed').exists():
                import vpn_policy
                vpn_policy.configure_ppp(self)
        except Exception:
            # A valid certificate may already exist: preserve its metadata for retry/export.
            if protocol == 'ikev2' and native in self.cert_names():
                device['protocols'][protocol] = {'backend': native, 'status': 'export-pending', 'export': None}
                self.save(reg)
            self.operation(ident, 'add-' + protocol, 'pending-recovery', backend=native)
            raise

    def repair(self, ident):
        reg, device = self.device(ident)
        operation = self.base / 'operations' / (ident + '.json')
        if not operation.exists():
            return
        entry = json.loads(operation.read_text())
        if entry['status'] == 'complete':
            return
        if entry['action'].startswith(('add-', 'replace-')):
            protocol = entry['action'].split('-', 1)[1]
            native = entry.get('backend', device['protocols'].get(protocol, {}).get('backend', ident))
            exists = (native in self.cert_names()) if protocol == 'ikev2' else protocol in self.m.load().get('clients', {}).get(native, {})
            if exists:
                previous = device['protocols'].get(protocol, {})
                device['protocols'][protocol] = {**previous, 'backend': native, 'status': 'active',
                    'export': previous.get('export') if previous.get('backend') == native else None}
                self.save(reg)
                self.operation(ident, entry['action'], 'complete')
                return 'Existing credentials recovered. Prepare profiles again; no new key or certificate was generated.'
        if entry['action'] == 'export-ikev2':
            record = device['protocols'].get('ikev2', {})
            if record.get('status') != 'revoked' and record.get('backend') in self.cert_names():
                self.operation(ident, entry['action'], 'complete', recovery='retry export of existing certificate')
                return 'Certificate preserved. Prepare profiles again; any previous validated export is retained.'
        raise ClientError('Pending operation needs review; no credential changes were made. Retry the original action or revoke explicitly.')

    def export_ike(self, ident, platform, password=None, enabled=True):
        self._phase='export: generating'
        if platform not in ('apple', 'android', 'windows', 'other'):
            raise ClientError('Choose Apple Device, Android, Windows or Other.')
        reg, device = self.device(ident)
        record = device['protocols'].get('ikev2')
        if not record or record['status'] == 'revoked':
            raise ClientError('An active IKEv2 certificate is required.')
        if record.get('status') == 'deleting' or record.get('deletion'):
            raise ClientError('Profile deletion is pending or complete.')
        nickname = record['backend']
        self.operation(ident, 'export-ikev2', 'pending')
        current_secret = self.secret(ident)
        previous_secret = dict(current_secret)
        password = password or current_secret.get('export_password') or self.m.random_password()
        if not isinstance(password, str) or not 12 <= len(password) <= 128 or any(c in password for c in ('\n', '\r', '\x00')):
            raise ClientError('Use an import password of 12–128 characters without line breaks.')
        server = self.server_identity()
        expected = self.m.load()['endpoint']
        if server != expected:
            raise ClientError('Server identity differs from configured endpoint. Correct the server identity before exporting; no certificate was replaced.')
        exports = self.base / 'exports' / ident
        exports.mkdir(parents=True, mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.export-', dir=exports) as temporary:
            stage = Path(temporary)
            passfile = stage / 'password'
            self.m.atomic(passfile, password + '\n')
            outpass = stage / 'output-password'
            self.m.atomic(outpass, password + '\n')
            p12 = stage / (ident + '.p12')
            ca, client, server_pem = self.cert('IKEv2 VPN CA'), self.cert(nickname), self.cert(server)
            self.m.atomic(stage / 'ca.pem', ca)
            self.m.atomic(stage / 'client.pem', client)
            expires = self.command(['openssl', 'x509', '-noout', '-enddate'], data=client).decode().strip().removeprefix('notAfter=')
            self.command(['certutil', '-V', '-u', 'C', '-d', 'sql:' + str(self.cert_db), '-n', nickname])
            self.command(['openssl', 'verify', '-CAfile', stage / 'ca.pem', stage / 'client.pem'])
            server_file = stage / 'server.pem'
            self.m.atomic(server_file, server_pem)
            self.command(['openssl', 'verify', '-CAfile', stage / 'ca.pem', server_file])
            self.command(['openssl', 'x509', '-in', server_file, '-noout',
                          '-checkip' if re.fullmatch(r'[0-9.]+', server) else '-checkhost', server])
            self.command(['pk12util', '-d', 'sql:' + str(self.cert_db), '-n', nickname, '-o', p12, '-w', passfile, '-K', ''])
            # Preserve upstream PKCS#12 compatibility encoding, with strong independent passwords.
            encrypted_pem = stage / 'encrypted-key.pem'
            encrypted = self.command(['openssl', 'pkcs12', '-legacy', '-in', p12, '-passin', 'file:' + str(passfile),
                                      '-passout', 'file:' + str(outpass)])
            self.m.atomic(encrypted_pem, encrypted)
            self.command(['openssl', 'pkcs12', '-export', '-legacy', '-keypbe', 'PBE-SHA1-3DES',
                          '-certpbe', 'PBE-SHA1-3DES', '-in', encrypted_pem, '-out', p12,
                          '-passin', 'file:' + str(passfile), '-passout', 'file:' + str(outpass), '-name', nickname])
            protected = p12.read_bytes()
            self._phase='export: validating'
            self.validate_p12(protected, password, client)
            self.m.atomic(p12, protected)
            produced = [p12.name]
            if platform in ('apple', 'other'):
                profile = self.apple_profile(ident, device['name'], server, protected, ca, enabled, nickname)
                filename = ident + '.mobileconfig'
                encoded = plistlib.dumps(profile, sort_keys=False)
                parsed = plistlib.loads(encoded)
                embedded = next(p['PayloadContent'] for p in parsed['PayloadContent'] if p['PayloadType'] == 'com.apple.security.pkcs12')
                if embedded != protected:
                    raise ClientError('Apple profile certificate validation failed.')
                self.m.atomic(stage / filename, encoded)
                produced.append(filename)
            if platform in ('android', 'other'):
                filename = ident + '.sswan'
                android = {'uuid': str(uuid.uuid4()), 'name': device['name'], 'type': 'ikev2-cert',
                           'remote': {'addr': server}, 'local': {'p12': base64.b64encode(protected).decode(), 'rsa-pss': True},
                           'ike-proposal': 'aes256-sha256-modp2048', 'esp-proposal': 'aes128gcm16'}
                encoded = json.dumps(android, indent=2)
                if base64.b64decode(json.loads(encoded)['local']['p12']) != protected:
                    raise ClientError('Android profile certificate validation failed.')
                self.m.atomic(stage / filename, encoded)
                produced.append(filename)
            instructions = ('IKEv2 certificate profile for ' + device['name'] + '\nServer: ' + server + '\n'
                            'Import password is provided separately.\n'
                            'Windows: import the .p12 into Local Computer Personal and trust the VPN CA; configure IKEv2 machine certificate authentication.\n'
                            'Apple: open .mobileconfig in Settings and enter the separate certificate password.\n'
                            'Android: import .sswan in strongSwan and enter the separate certificate password.\n')
            self.m.atomic(stage / 'README.txt', instructions)
            generation = secrets.token_hex(12)
            published = exports / generation
            published.mkdir(mode=0o700)
            try:
                for filename in produced + ['README.txt']:
                    self.m.atomic(published / filename, (stage / filename).read_bytes())
                current_secret['export_password'] = password
                # Commit password and generation together; previous generations keep their own private password.
                self.m.atomic(published / '.password', password + '\n')
                self.save_secret(ident, current_secret)
                record.update(status='active', certificate_expires=expires, export={'generation': generation, 'platform': platform,
                              'files': produced, 'on_demand': bool(enabled), 'created': int(time.time()),
                              'sha256': {name: hashlib.sha256((published / name).read_bytes()).hexdigest() for name in produced}})
                self.save(reg)
            except Exception:
                shutil.rmtree(published, ignore_errors=True)
                self.save_secret(ident, previous_secret)
                raise
        self.operation(ident, 'export-ikev2', 'complete')
        return {'directory': str(published), 'files': produced, 'device': ident,
                'message': 'Validated export ready. Reveal the import password separately.'}

    def validate_p12(self, data, password, certificate=None):
        with tempfile.TemporaryDirectory(prefix='validate-', dir=self.base) as temporary:
            folder = Path(temporary)
            self.m.atomic(folder / 'bundle.p12', data)
            self.m.atomic(folder / 'password', password + '\n')
            args = ['openssl', 'pkcs12', '-legacy', '-in', folder / 'bundle.p12', '-passin', 'file:' + str(folder / 'password')]
            self.command(args + ['-info', '-noout'])
            key = self.command(args + ['-nocerts', '-nodes'])
            cert = self.command(args + ['-clcerts', '-nokeys'])
            chain = self.command(args + ['-cacerts', '-nokeys'])
            if not chain or b'BEGIN CERTIFICATE' not in chain:
                raise ClientError('Export is missing its CA certificate chain.')
            self.m.atomic(folder / 'chain.pem', chain)
            self.m.atomic(folder / 'client.pem', cert)
            self.command(['openssl', 'verify', '-CAfile', folder / 'chain.pem', folder / 'client.pem'])
            if not key or not cert:
                raise ClientError('Export is missing its client private key or certificate.')
            public_key = self.command(['openssl', 'pkey', '-pubout', '-outform', 'DER'], data=key)
            cert_pub = self.command(['openssl', 'x509', '-pubkey', '-noout'], data=cert)
            cert_pub_der = self.command(['openssl', 'pkey', '-pubin', '-outform', 'DER'], data=cert_pub)
            if public_key != cert_pub_der:
                raise ClientError('Export key does not match its certificate.')
            if certificate:
                actual = self.command(['openssl', 'x509', '-outform', 'DER'], data=cert)
                expected = self.command(['openssl', 'x509', '-outform', 'DER'], data=certificate)
                if actual != expected:
                    raise ClientError('Export contains the wrong client identity.')

    @staticmethod
    def apple_profile(ident, display, server, protected, ca_pem, enabled, nickname=''):
        def payload(kind, title):
            uid = str(uuid.uuid4())
            return {'PayloadType': kind, 'PayloadVersion': 1, 'PayloadUUID': uid,
                    'PayloadIdentifier': 'vpn.stack.' + uid, 'PayloadDisplayName': title}
        certificate = payload('com.apple.security.pkcs12', display + ' certificate')
        certificate['PayloadContent'] = protected
        certificate['PayloadCertificateFileName'] = ident + '.p12'
        ca = payload('com.apple.security.root', 'VPN CA')
        ca['PayloadContent'] = base64.b64decode(b''.join(line for line in ca_pem.splitlines() if b'CERTIFICATE' not in line))
        vpn = payload('com.apple.vpn.managed', display)
        vpn.update(VPNType='IKEv2', UserDefinedName=display, IPv4={'OverridePrimary': 1})
        vpn['IKEv2'] = {'AuthenticationMethod': 'Certificate', 'RemoteAddress': server,
                        'RemoteIdentifier': server, 'LocalIdentifier': nickname,
                        'PayloadCertificateUUID': certificate['PayloadUUID'], 'CertificateType': 'RSA',
                        'ExtendedAuthEnabled': 0, 'DeadPeerDetectionRate': 'Medium',
                        'OnDemandEnabled': int(enabled), 'OnDemandRules': ([
                            {'Action': 'Connect', 'InterfaceTypeMatch': 'WiFi'},
                            {'Action': 'Connect', 'InterfaceTypeMatch': 'Cellular'}, {'Action': 'Ignore'}] if enabled else []),
                        'IKESecurityAssociationParameters': {'EncryptionAlgorithm': 'AES-256-GCM', 'IntegrityAlgorithm': 'SHA2-256', 'DiffieHellmanGroup': 19, 'LifeTimeInMinutes': 1410},
                        'EnablePFS': 0, 'DisableRedirect': True,
                        'ChildSecurityAssociationParameters': {'EncryptionAlgorithm': 'AES-256-GCM', 'DiffieHellmanGroup': 19, 'LifeTimeInMinutes': 1410}}
        root = payload('Configuration', display + ' VPN')
        root['PayloadContent'] = [vpn, certificate, ca]
        root['PayloadDescription'] = 'IPv4 full tunnel VPN. Import password is supplied separately.'
        return root

    def exported_file(self, ident, filename):
        _, device = self.device(ident)
        record = device['protocols'].get('ikev2', {})
        export = record.get('export')
        if record.get('status') == 'revoked' or not export or filename not in export['files']:
            raise ClientError('Validated active export not found.')
        path = self.base / 'exports' / ident / export['generation'] / filename
        if path.is_symlink() or not path.is_file():
            raise ClientError('Export file is missing or unsafe.')
        if path.stat().st_size > 5 * 1024**2:
            raise ClientError('Export exceeds the download size limit.')
        expected = export.get('sha256', {}).get(filename)
        if expected and hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ClientError('Export integrity check failed. Export the existing certificate again.')
        return path

    def reveal(self, ident, protocol='ikev2'):
        _, device = self.device(ident)
        if protocol == 'ikev2':
            record = device['protocols'].get('ikev2', {})
            if not record.get('export'):
                raise ClientError('Export this device first.')
            path = self.base / 'exports' / ident / record['export']['generation'] / '.password'
            return path.read_text().strip()
        name = device['protocols'][protocol]['backend']
        if protocol == 'l2tp':
            state = self.m.load()
            return 'Username: ' + name + '\nPassword: ' + state['clients'][name]['l2tp']['password'] + '\nIPsec PSK: ' + state['psk']
        raise ClientError('WireGuard uses private keys, not login passwords.')

    def rotate_l2tp(self, ident, password):
        password = self.m.valid_password(password)
        reg, device = self.device(ident)
        record = device['protocols'].get('l2tp')
        if not record or record['status'] == 'revoked':
            raise ClientError('Active L2TP credentials required.')
        name = record['backend']
        chap = self.m.ETC / 'ppp/chap-secrets'
        old_chap, old_state = chap.read_bytes(), self.m.STATE.read_bytes()
        export_path = self.base / 'clients/l2tp' / (name + '.txt')
        old_export = export_path.read_bytes() if export_path.exists() else None
        self.operation(ident, 'rotate-l2tp', 'pending')
        try:
            lines = [line for line in old_chap.decode().splitlines() if not line.startswith('"' + name + '" ')]
            self.m.atomic(chap, '\n'.join(lines) + f'\n"{name}" l2tpd "{password}" *\n')
            state = self.m.load()
            state['clients'][name]['l2tp']['password'] = password
            self.m.save(state)
            self.m.export_l2tp(name)
            if (self.base / 'policy-installed').exists():
                import vpn_policy
                vpn_policy.configure_ppp(self)
        except Exception:
            self.m.atomic(chap, old_chap)
            self.m.atomic(self.m.STATE, old_state)
            if old_export is not None:
                self.m.atomic(export_path, old_export)
            raise
        self.operation(ident, 'rotate-l2tp', 'complete')

    def revoke(self, ident, protocol):
        reg, device = self.device(ident)
        record = device['protocols'].get(protocol)
        if not record or record['status'] == 'revoked':
            raise ClientError('Active protocol not found.')
        self.operation(ident, 'revoke-' + protocol, 'pending')
        name = record['backend']
        if protocol == 'ikev2':
            self.helper(name, 'revoke')
        elif protocol == 'wireguard':
            self.m.revoke_wg(name)
        elif protocol == 'l2tp':
            self.m.revoke_l2tp(name)
        else:
            raise ClientError('Unsupported protocol.')
        record['status'] = 'revoked'
        self.save(reg)
        self.operation(ident, 'revoke-' + protocol, 'complete')
        if (self.base / 'policy-installed').exists():
            import vpn_policy
            from vpn_backend import disconnect_profile
            try:
                vpn_policy.apply(self)
            finally:
                # Session teardown checks kernel identity/generation, never only an IP.
                disconnect_profile(self,ident,protocol,name)
        return 'Credentials revoked and verified sessions disconnected. Copied profiles cannot be erased remotely.'

    def delete_profile(self, ident, protocol='all'):
        from vpn_backend import disconnect_profile
        import vpn_policy
        registry, device = self.device(ident)
        selected = list(device['protocols']) if protocol == 'all' else [protocol]
        if (not selected and protocol != 'all') or any(p not in device['protocols'] for p in selected):
            raise ClientError('Select an existing protocol profile.')
        for name in selected:
            registry, device = self.device(ident)
            record = device['protocols'][name]
            stage = record.setdefault('deletion', {})
            if stage.get('complete'):
                continue
            native = record['backend']
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', native):
                raise ClientError('Unsafe native identity; deletion stopped.')
            if not stage.get('revoked'):
                if record.get('status') != 'revoked':
                    record['status'] = 'deleting'
                    self.save(registry)
                    # Revoke even if firewall reconciliation is unhealthy. Native
                    # revocation commits before its policy reconciliation step.
                    self.revoke(ident, name)
                    registry, device = self.device(ident)
                    record = device['protocols'][name]
                    stage = record.setdefault('deletion', {})
                stage['revoked'] = True
                self.save(registry)
            if not stage.get('disconnected'):
                disconnect_profile(self, ident, name, native)
                stage['disconnected'] = True
                self.save(registry)
            # Delete only paths derived from immutable managed IDs, never supplied paths.
            if name == 'ikev2':
                if native in self.cert_names():
                    if native == self.server_identity() or native == 'IKEv2 VPN CA':
                        raise ClientError('Refusing to delete a server or CA identity.')
                    self.command(['certutil', '-F', '-d', 'sql:' + str(self.cert_db), '-n', native])
                folder = self.base / 'exports' / ident
                if folder.is_symlink():
                    raise ClientError('Unsafe export directory; cleanup stopped.')
                if folder.exists():
                    shutil.rmtree(folder)
                (self.base / 'secrets' / (ident + '.json')).unlink(missing_ok=True)
            else:
                suffix = '.conf' if name == 'wireguard' else '.txt'
                (self.base / 'clients' / name / (native + suffix)).unlink(missing_ok=True)
            folder = self.base / 'deliveries' / ident
            if folder.is_symlink():
                raise ClientError('Unsafe delivery directory; cleanup stopped.')
            if folder.exists():
                shutil.rmtree(folder)
            with self.repo.connect() as db:
                db.execute('DELETE FROM deliveries WHERE device=?', (ident,))
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='tokens'").fetchone():
                    db.execute('DELETE FROM tokens WHERE device=?', (ident,))
            self.repo.scrub_device_secrets(self, ident, name)
            record['export'] = None
            stage['complete'] = True
            self.save(registry)
            self.audit('delete-' + name, ident)
        if protocol == 'all':
            registry, device = self.device(ident)
            device['deleted'] = True
            self.save(registry)
        return 'Profile revoked, disconnected and deleted. Remove its installed copy from the client device manually.'

    def revoke_user(self, user):
        reg = self.load()
        if user not in reg['users']:
            raise ClientError('User not found.')
        for ident, device in reg['devices'].items():
            if device['user'] == user:
                for protocol, record in device['protocols'].items():
                    if record['status'] != 'revoked':
                        self.revoke(ident, protocol)
        reg = self.load()
        reg['users'][user]['revoked'] = True
        self.save(reg)

    def copy_export(self, ident, username, protocol='ikev2'):
        account = pwd.getpwnam(username)
        if account.pw_uid < 1000 or account.pw_uid == 65534 or not Path(account.pw_dir).is_dir():
            raise ClientError('Choose an existing regular SSH user with a home directory.')
        _, device = self.device(ident)
        record = device['protocols'].get(protocol)
        if not record or record['status'] == 'revoked':
            raise ClientError('Active protocol not found.')
        if protocol == 'ikev2':
            files = (record.get('export') or {}).get('files', [])
            if not files:
                raise ClientError('Create a validated export first.')
            bundle = {name: base64.b64encode(self.exported_file(ident, name).read_bytes()).decode() for name in files}
        elif protocol in ('wireguard', 'l2tp'):
            name = record['backend'] + ('.conf' if protocol == 'wireguard' else '.txt')
            path = self.base / 'clients' / protocol / name
            if not path.is_file() or path.is_symlink():
                raise ClientError('Private profile missing or unsafe.')
            bundle = {name: base64.b64encode(path.read_bytes()).decode()}
        else:
            raise ClientError('Unsupported protocol.')
        # Write as the recipient, never as root into a user-controlled directory.
        script = '''import base64,json,os,pathlib,sys
os.umask(0o077)
home=pathlib.Path.home()
dest=home/'vpn-exports'/sys.argv[1]
dest.mkdir(parents=True,exist_ok=True,mode=0o700)
for name,data in json.load(sys.stdin).items():
 fd=os.open(dest/name,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(base64.b64decode(data))
 os.chmod(dest/name,0o600)
'''
        self.command(['runuser', '-u', username, '--', 'python3', '-c', script, ident], data=json.dumps(bundle).encode())
        self.audit('copy-export', ident)
        return str(Path(account.pw_dir) / 'vpn-exports' / ident)

    def rotate(self, ident, protocol):
        if protocol not in ('ikev2', 'wireguard', 'l2tp'):
            raise ClientError('Unsupported protocol.')
        reg, device = self.device(ident)
        old = device['protocols'].get(protocol)
        if old and old['status'] != 'revoked':
            self.revoke(ident, protocol)
        reg, device = self.device(ident)
        if old:
            device.setdefault('history', []).append({'protocol': protocol, **old})
        device['protocols'].pop(protocol, None)
        self.save(reg)
        # New backend identifiers never reuse a revoked certificate nickname.
        native = 'dev-' + secrets.token_hex(6)
        self.operation(ident, 'replace-' + protocol, 'pending', backend=native)
        if protocol == 'ikev2':
            self.helper(native, 'add')
        elif protocol == 'wireguard':
            self.m.add_wg(native)
        else:
            self.m.l2tp_add(native, self.m.random_password())
        reg, device = self.device(ident)
        device['protocols'][protocol] = {'backend': native, 'status': 'active', 'export': None}
        self.save(reg)
        self.operation(ident, 'replace-' + protocol, 'complete')
