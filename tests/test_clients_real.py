"""Real OpenSSL + temporary NSS database, with no changes to server VPN configuration."""
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import uuid
import unittest
from unittest.mock import patch
from test_manager import m
import vpn_clients as c

TOOLS = Path('/tmp/vpn-nss-tools/extracted/usr/bin')
NSS_LIB = str(TOOLS.parent / 'lib/x86_64-linux-gnu')
NSS_PATH = str(TOOLS) + os.pathsep + os.environ['PATH'] if TOOLS.exists() else os.environ['PATH']


@unittest.skipUnless(shutil.which('certutil', path=NSS_PATH) and shutil.which('pk12util', path=NSS_PATH), 'NSS tools required')
class RealExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.master = tempfile.TemporaryDirectory()
        cls.fixtures = Path(cls.master.name)
        cls.env = dict(os.environ, PATH=NSS_PATH, LD_LIBRARY_PATH=NSS_LIB)
        def run(args):
            result = subprocess.run(args, cwd=cls.fixtures, capture_output=True, env=cls.env)
            if result.returncode:
                raise RuntimeError(result.stderr.decode())
        run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30', '-subj', '/CN=VPN Test CA', '-keyout', 'ca.key', '-out', 'ca.pem'])
        for name, cn, usage in [('client-one', 'client-one', 'clientAuth'), ('client-two', 'client-two', 'clientAuth'), ('server', 'vpn.example.test', 'serverAuth')]:
            run(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + cn, '-keyout', name + '.key', '-out', name + '.csr'])
            (cls.fixtures / 'ext').write_text('extendedKeyUsage=' + usage + '\nsubjectAltName=DNS:' + cn + '\n')
            run(['openssl', 'x509', '-req', '-in', name + '.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '30', '-extfile', 'ext', '-out', name + '.pem'])
            run(['openssl', 'pkcs12', '-export', '-inkey', name + '.key', '-in', name + '.pem', '-certfile', 'ca.pem', '-name', cn, '-out', name + '.p12', '-passout', 'pass:fixture-only-password'])

    @classmethod
    def tearDownClass(cls):
        cls.master.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.base = self.root / 'stack'
        self.etc = self.root / 'etc'
        self.db = self.etc / 'ipsec.d'
        self.db.mkdir(parents=True)
        self.patches = [patch.object(m, 'BASE', self.base), patch.object(m, 'ETC', self.etc),
                        patch.object(m, 'STATE', self.base / 'state.json'), patch.dict(os.environ, {'PATH': NSS_PATH, 'LD_LIBRARY_PATH': NSS_LIB})]
        for p in self.patches:
            p.start()
        self.run_tool(['certutil', '-N', '-d', 'sql:' + str(self.db), '--empty-password'])
        self.run_tool(['certutil', '-A', '-d', 'sql:' + str(self.db), '-n', 'IKEv2 VPN CA', '-t', 'CT,,', '-i', str(self.fixtures / 'ca.pem')])
        passfile = self.root / 'import-password'
        passfile.write_text('fixture-only-password\n')
        for name in ('client-one', 'client-two', 'server'):
            self.run_tool(['pk12util', '-i', str(self.fixtures / (name + '.p12')), '-d', 'sql:' + str(self.db), '-w', str(passfile)])
        (self.db / 'ikev2.conf').write_text('conn ikev2-cp\n  leftcert=vpn.example.test\n')
        m.save({'version': 3, 'installed': True, 'endpoint': 'vpn.example.test', 'lan': '192.168.0.8',
                'public': '8.8.8.8', 'clients': {'client-one': {'ikev2': {'on_demand': True}}}})
        self.backend = c.Backend(m)
        self.backend.migrate()
        self.ident='client-one'
        from vpn_web import Store
        from auth_fixture import enroll
        self.actor,self.session,self.csrf,_=enroll(Store(self.backend.repo.path))
        self.backend.repo.save({'users':{'legacy':{'name':'Test'}},'devices':{self.ident:{'name':'Test client','user':'legacy','protocols':{'ikev2':{'backend':'client-one','status':'active','export':None}}}}})

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.temp.cleanup()

    def run_tool(self, args):
        result = subprocess.run(args, capture_output=True, env=self.env)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return result.stdout

    def test_real_exports_validate_and_retain_existing_client_identity(self):
        original = self.backend.cert('client-one')
        result = self.backend.export_ike(self.ident, 'other', 'independent-password-one', True)
        folder = Path(result['directory'])
        self.assertEqual(len(result['files']), 3)
        apple = plistlib.loads((folder / (self.ident + '.mobileconfig')).read_bytes())
        bundle = next(p for p in apple['PayloadContent'] if p['PayloadType'] == 'com.apple.security.pkcs12')
        self.assertNotIn('Password', bundle)
        android = json.loads((folder / (self.ident + '.sswan')).read_text())
        self.assertEqual(bundle['PayloadContent'], base64.b64decode(android['local']['p12']))
        self.backend.validate_p12(bundle['PayloadContent'], 'independent-password-one', original)
        self.assertEqual(self.backend.cert('client-one'), original)
        self.assertFalse((Path('/root') / (self.ident + '.p12')).exists())
        for path in folder.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_wrong_password_rejected(self):
        result = self.backend.export_ike(self.ident, 'windows', 'independent-password-one')
        bundle = (Path(result['directory']) / (self.ident + '.p12')).read_bytes()
        with self.assertRaises(c.ClientError):
            self.backend.validate_p12(bundle, 'wrong-password-long')

    def test_mismatched_identity_rejected(self):
        result = self.backend.export_ike(self.ident, 'windows', 'independent-password-one')
        bundle = (Path(result['directory']) / (self.ident + '.p12')).read_bytes()
        with self.assertRaisesRegex(c.ClientError, 'wrong client identity'):
            self.backend.validate_p12(bundle, 'independent-password-one', self.backend.cert('client-two'))

    def test_failed_new_export_keeps_previous_generation(self):
        first = self.backend.export_ike(self.ident, 'apple', 'independent-password-one')
        pointer = self.backend.load()['devices'][self.ident]['protocols']['ikev2']['export']
        with patch.object(self.backend, 'validate_p12', side_effect=c.ClientError('simulated failure')):
            with self.assertRaises(c.ClientError):
                self.backend.export_ike(self.ident, 'android', 'independent-password-two')
        self.assertEqual(self.backend.load()['devices'][self.ident]['protocols']['ikev2']['export'], pointer)
        self.assertTrue(Path(first['directory']).exists())
        self.assertEqual(self.backend.reveal(self.ident), 'independent-password-one')

    def test_export_password_with_spaces_and_quotes_is_supported_noninteractively(self):
        password = 'an import password with "quotes"'
        result = self.backend.export_ike(self.ident, 'other', password)
        data = (Path(result['directory']) / (self.ident + '.p12')).read_bytes()
        self.backend.validate_p12(data, password, self.backend.cert('client-one'))
        self.assertEqual(self.backend.reveal(self.ident), password)

    def test_web_prepare_and_admin_attachment_use_validated_existing_ikev2_identity(self):
        import vpn_web
        import vpn_admin
        original = self.backend.cert('client-one')
        controller = vpn_web.Controller(self.backend)
        result = controller.action({'actor':self.actor, 'action': 'prepare-export', 'device': self.ident, 'protocols': 'ikev2', 'platform': 'apple', 'on_demand': 'yes'})
        self.assertIn('mobileconfig ready', result['message'])
        output = vpn_admin.attachment(self.backend, controller.store, controller.state,
            {'device': self.ident, 'kind': 'ikev2', 'filename': self.ident + '.mobileconfig'})
        profile = plistlib.loads(base64.b64decode(output['data']))
        p12 = next(item['PayloadContent'] for item in profile['PayloadContent'] if item['PayloadType'] == 'com.apple.security.pkcs12')
        self.backend.validate_p12(p12, self.backend.reveal(self.ident), original)
        self.assertEqual(self.backend.cert('client-one'), original)

    @unittest.skipUnless(os.geteuid() == 0 and Path('/run/systemd/system').exists(), 'requires systemd and root')
    def test_native_export_and_bundle_work_with_production_broker_capabilities(self):
        import vpn_web
        import vpn_harden
        script = self.root / 'hardened-export.py'
        script.write_text("import sys,subprocess\nfrom pathlib import Path\nsys.path.insert(0," + repr(str(Path(__file__).resolve().parents[1] / 'src')) + ")\nimport manage as m\nm.BASE=Path(" + repr(str(self.base)) + ");m.ETC=Path(" + repr(str(self.etc)) + ");m.STATE=m.BASE/'state.json'\nb=m.clients_backend()\nr=b.export_ike(" + repr(self.ident) + ",'apple','hardened-export-password')\nfrom vpn_backend import bundle\nbundle(b," + repr(self.ident) + ",['ikev2'])\nassert subprocess.run(['runuser','-u','nobody','--','/usr/bin/true']).returncode==0\nprint('Native export, ZIP crypto and privilege drop passed')\n")
        props = vpn_harden.common_sandbox().splitlines() + vpn_harden.service_limits().splitlines()
        props += ['MemoryMax=128M', 'MemoryHigh=96M']
        props += [line for line in vpn_web.unit_files()['vpn-control.service'].splitlines() if line.startswith('CapabilityBoundingSet=')]
        props += ['NoNewPrivileges=yes', 'ProtectSystem=strict', 'ReadWritePaths=' + str(self.root)]
        args = ['systemd-run', '--unit=vpnstack-it-crypto-' + uuid.uuid4().hex[:8], '--collect', '--wait', '--pipe']
        args += ['--property=' + value for value in props]
        args += ['--setenv=PATH=' + NSS_PATH, '--setenv=LD_LIBRARY_PATH=' + NSS_LIB, '--setenv=PYTHONPATH=' + os.environ.get('PYTHONPATH', '')]
        result = subprocess.run(args + [__import__('sys').executable, str(script)], capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Native export, ZIP crypto and privilege drop passed', result.stdout)

    def test_batch_exports_validate_random_custom_and_preserved_passwords(self):
        import vpn_backend
        import vpn_web
        second = self.backend.adopt('client-two', 'legacy', 'Second device')
        original = {ident: self.backend.cert(self.backend.device(ident)[1]['protocols']['ikev2']['backend']) for ident in (self.ident, second)}
        controller = vpn_web.Controller(self.backend)
        previous = {}
        for mode in ('random', 'custom', 'keep'):
            vpn_backend.preview_batch(self.backend, {'batch_kind': 'export', 'devices': self.ident + ',' + second,
                'protocols': 'ikev2', 'platform': 'apple', 'password_mode': mode, 'password': 'Custom batch password 370'})
            batch = self.backend.repo.batches()[0]
            controller.action({'actor':self.actor, 'action': 'batch-confirm', 'batch': batch['id']})
            while self.backend.repo.run_one(self.backend, controller.action):
                pass
            self.assertEqual(self.backend.repo.batch(batch['id'])['status'], 'complete')
            current = {}
            for ident in (self.ident, second):
                current[ident] = self.backend.reveal(ident)
                record = self.backend.device(ident)[1]['protocols']['ikev2']
                profile = plistlib.loads(self.backend.exported_file(ident, ident + '.mobileconfig').read_bytes())
                p12 = next(p['PayloadContent'] for p in profile['PayloadContent'] if p['PayloadType'] == 'com.apple.security.pkcs12')
                self.backend.validate_p12(p12, current[ident], original[ident])
                self.assertEqual(self.backend.cert(record['backend']), original[ident])
            if mode == 'random':
                self.assertNotEqual(current[self.ident], current[second])
            elif mode == 'custom':
                self.assertTrue(all(value == 'Custom batch password 370' for value in current.values()))
            else:
                self.assertEqual(current, previous)
            previous = current

    def test_delete_ike_removes_only_client_key_and_exports(self):
        import vpn_backend
        ca = self.backend.cert('IKEv2 VPN CA')
        server = self.backend.cert('vpn.example.test')
        other = self.backend.cert('client-two')
        self.backend.export_ike(self.ident, 'apple', 'private-deletion-password')
        with patch.object(self.backend, 'helper') as helper, patch.object(vpn_backend, 'disconnect_profile'):
            self.backend.delete_profile(self.ident, 'ikev2')
            helper.assert_called_once_with('client-one', 'revoke')
        self.assertNotIn('client-one', self.backend.cert_names())
        self.assertEqual(self.backend.cert('IKEv2 VPN CA'), ca)
        self.assertEqual(self.backend.cert('vpn.example.test'), server)
        self.assertEqual(self.backend.cert('client-two'), other)
        self.assertFalse((self.base / 'exports' / self.ident).exists())
        self.assertFalse((self.base / 'secrets' / (self.ident + '.json')).exists())
        with patch.object(self.backend, 'helper') as helper:
            self.backend.delete_profile(self.ident, 'ikev2')
            helper.assert_not_called()

    def test_device_portal_delivers_validated_native_apple_profile_once(self):
        import vpn_web
        original=self.backend.cert('client-one')
        self.backend.export_ike(self.ident,'apple','portal-import-password')
        self.backend.m.atomic(self.base/'web-enabled','yes')
        controller=vpn_web.Controller(self.backend)
        result=controller.action({'actor':self.actor, 'action':'delivery-link','device':self.ident})
        token=result['token']
        record=controller.handle({'op':'inspect','token':token},0)
        filename=next(item['filename'] for item in record['files'] if item['filename'].endswith('.mobileconfig'))
        output=controller.handle({'op':'claim','token':token,'filename':filename,'confirm':record['confirm']},0)
        profile=plistlib.loads(base64.b64decode(output['data']))
        p12=next(item['PayloadContent'] for item in profile['PayloadContent'] if item['PayloadType']=='com.apple.security.pkcs12')
        self.backend.validate_p12(p12,'portal-import-password',original)
        self.assertEqual(self.backend.cert('client-one'),original)
        with self.assertRaises(vpn_web.WebError):
            controller.handle({'op':'claim','token':token,'filename':filename,'confirm':record['confirm']},0)

    def test_discovery_finds_unassigned_certificate_without_recreating_it(self):
        self.assertIn('client-two', self.backend.discover())
        ident = self.backend.adopt('client-two', 'legacy', 'Recovered phone')
        self.assertEqual(self.backend.load()['devices'][ident]['protocols']['ikev2']['backend'], 'client-two')

    def test_migration_preserves_original_state(self):
        before = m.STATE.read_bytes()
        self.backend.migrate()
        self.assertEqual(m.STATE.read_bytes(), before)
        self.assertEqual(self.backend.load()['schema'], 1)

    def test_per_device_passwords_are_independent(self):
        second = self.backend.adopt('client-two', 'legacy', 'Phone two')
        self.backend.export_ike(self.ident, 'apple')
        self.backend.export_ike(second, 'android')
        self.assertNotEqual(self.backend.reveal(self.ident), self.backend.reveal(second))
