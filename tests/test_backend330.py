import contextlib
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import test_manager as tm
import vpn_backend as b
import vpn_policy as policy
import vpn_web as web
m = tm.m


class BackendTests(unittest.TestCase):
    def setUp(self):
        tm.RuntimeTests.setUp(self)
        self.backend = m.clients_backend()
        self.backend.migrate()
        self.user = self.backend.user_add('Owner')
        self.ident = self.backend.device_add(self.user, 'Device')

    def tearDown(self):
        tm.RuntimeTests.tearDown(self)

    def test_policy_defaults_overrides_and_disabled_user(self):
        reg = self.backend.load()
        self.assertFalse(policy.effective(reg, self.ident))
        reg['users'][self.user]['lan_policy'] = 'allow'
        self.assertTrue(policy.effective(reg, self.ident))
        reg['devices'][self.ident]['lan_policy'] = 'block'
        self.assertFalse(policy.effective(reg, self.ident))
        reg['devices'][self.ident]['lan_policy'] = 'allow'
        reg['users'][self.user]['revoked'] = True
        self.assertFalse(policy.effective(reg, self.ident))

    def test_database_rejects_stale_save_without_losing_records(self):
        first = self.backend.load()
        self.backend.user_add('Other')
        with self.assertRaises(RuntimeError):
            self.backend.save(first)
        self.assertEqual(len(self.backend.load()['users']), 2)
        self.assertEqual(self.backend.repo.path.stat().st_mode & 0o777, 0o600)

    def test_snapshot_failure_does_not_undo_authoritative_database_commit(self):
        original = m.atomic
        def atomic(path, data, mode=0o600):
            if path == self.backend.registry:
                raise OSError('snapshot disk failure')
            return original(path, data, mode)
        with patch.object(m, 'atomic', side_effect=atomic):
            ident = self.backend.user_add('Durable')
        self.assertEqual(self.backend.load()['users'][ident]['name'], 'Durable')

    def test_multi_protocol_retry_retains_successful_existing_protocols(self):
        made = []
        def add(ident, protocol):
            made.append(protocol)
            reg, device = self.backend.device(ident)
            device['protocols'][protocol] = {'backend': ident, 'status': 'active', 'export': None}
            self.backend.save(reg)
        with patch.object(self.backend, 'protocol_add', side_effect=add):
            self.backend.add_protocols(self.ident, ['wireguard', 'ikev2'])
            self.backend.add_protocols(self.ident, ['wireguard', 'ikev2', 'l2tp'])
        self.assertEqual(made, ['wireguard', 'ikev2', 'l2tp'])

    def test_jobs_deduplicate_serialize_and_recover_interruption(self):
        form = {'action': 'protocols-add', 'device': self.ident, 'protocols': 'wireguard,ikev2'}
        ident = self.backend.repo.enqueue(form)
        self.assertEqual(ident, self.backend.repo.enqueue(form))
        execute = lambda value: {'message': 'Complete'}
        self.assertTrue(self.backend.repo.run_one(self.backend, execute))
        self.assertEqual(self.backend.repo.jobs()[0]['status'], 'complete')
        with self.backend.repo.connect() as db:
            db.execute("UPDATE jobs SET status='running' WHERE id=?", (ident,))
        self.backend.repo.recover_jobs()
        self.assertEqual(self.backend.repo.jobs()[0]['status'], 'interrupted')

    def test_zip_preserves_native_bytes_and_invalidates_when_credentials_change(self):
        try:
            import pyzipper
        except ImportError:
            self.skipTest('pyzipper required')
        reg, device = self.backend.device(self.ident)
        for protocol in ('wireguard', 'l2tp'):
            device['protocols'][protocol] = {'backend': self.ident, 'status': 'active', 'export': None}
        self.backend.save(reg)
        wg = self.base / 'clients/wireguard' / (self.ident + '.conf')
        l2tp = self.base / 'clients/l2tp' / (self.ident + '.txt')
        m.atomic(wg, '[Interface]\nPrivateKey = TEST-KEY\n')
        m.atomic(l2tp, 'Username: test\nPassword: test-secret\n')
        result = b.bundle(self.backend, self.ident, ['wireguard', 'l2tp'])
        path = b.delivery_file(self.backend, self.ident, result['generation'], result['filename'])
        with pyzipper.AESZipFile(path) as archive:
            with self.assertRaises(RuntimeError):
                archive.read(archive.namelist()[0])
            archive.setpassword(result['password'].encode())
            self.assertEqual(archive.read('wireguard/' + wg.name), wg.read_bytes())
            self.assertNotIn(result['password'].encode(), b''.join(archive.read(n) for n in archive.namelist()))
        extractor = Path('/tmp/vpn330-7zip/extracted/usr/lib/7zip/7z')
        if extractor.exists():
            # Fixture password only; this independent extractor is never used for real customer credentials.
            result7z = subprocess.run([str(extractor), 'x', '-so', '-p' + result['password'], str(path), 'wireguard/' + wg.name], capture_output=True)
            self.assertEqual(result7z.returncode, 0, result7z.stderr.decode())
            self.assertEqual(result7z.stdout, wg.read_bytes())
        m.atomic(wg, 'changed key')
        with self.assertRaises(ValueError):
            b.delivery_file(self.backend, self.ident, result['generation'], result['filename'])

    def test_ipsec_rekey_and_stale_kernel_binding_never_grant_reused_address(self):
        reg, device = self.backend.device(self.ident)
        device['lan_policy'] = 'allow'
        device['protocols']['ikev2'] = {'backend': self.ident, 'status': 'active'}
        self.backend.save(reg)
        for spi in (100, 101):
            entry = dict(protocol='ikev2', up=True, identity=self.ident, address='192.168.43.12', reqid=42, spi=str(spi))
            policy.event(self.backend, entry)
        with patch.object(policy, 'kernel_sessions', return_value={(42, 101)}):
            grants = policy.grants(self.backend)
        self.assertEqual(len(grants), 1)
        self.assertIn(hex(101), grants[0])
        with patch.object(policy, 'kernel_sessions', return_value={(43, 101)}):
            self.assertEqual(policy.grants(self.backend), [])

    def test_management_deadline_survives_wall_clock_changes_and_rejects_new_boot(self):
        wall, mono = [1000], [50]
        store = web.Store(self.base / 'clock.db', lambda: wall[0], lambda: mono[0], 'boot-one')
        from auth_fixture import enroll
        _,session,csrf,codes=enroll(store)
        wall[0]-=3600
        self.assertEqual(store.session(session),csrf)
        mono[0]+=1801
        with self.assertRaises(web.WebError): store.session(session)
        session,_=store.login('test-management-password','console','owner',codes[1])
        store.boot='boot-two'
        with self.assertRaises(web.WebError): store.session(session)

    def test_ppp_hooks_preserve_native_pool_and_authentication_configuration(self):
        chap = self.etc / 'ppp/chap-secrets'
        options = self.etc / 'ppp/options.xl2tpd'
        m.atomic(chap, '"native" l2tpd "test-password-one" *\n')
        m.atomic(options, 'require-mschap-v2\nipcp-accept-remote\n')
        original = {p: p.read_bytes() for p in (chap, options)}
        policy.configure_ppp(self.backend)
        self.assertEqual({p: p.read_bytes() for p in original}, original)
        self.assertTrue((self.etc / 'ppp/ip-up.d/vpn').is_file())
        with patch.dict('os.environ', {'PEERNAME': 'unknown', 'IPREMOTE': '192.168.42.20', 'IFNAME': 'ppp0'}):
            with self.assertRaisesRegex(RuntimeError, 'not an active managed client'):
                policy.cli_event(self.backend, ['l2tp', 'up'])

    def test_startup_diagnostics_include_failure_status_and_journal(self):
        calls = []
        def command(args, **kwargs):
            calls.append(args)
            text = 'ExecMainStatus=226\n' if args[0] == 'systemctl' else 'Failed to set up mount namespacing: /run/xtables.lock\n'
            return subprocess.CompletedProcess(args, 0, text, '')
        stream = io.StringIO()
        with patch.object(self.backend.m, 'command', side_effect=command), contextlib.redirect_stderr(stream):
            web.startup_diagnostics(self.backend)
        self.assertIn('ExecMainStatus=226', stream.getvalue())
        self.assertIn('/run/xtables.lock', stream.getvalue())
        self.assertEqual([args[0] for args in calls], ['systemctl', 'journalctl', 'ss', 'ip', 'iptables'])
        report = self.backend.base / 'logs/web-failure-latest.txt'
        self.assertEqual(report.stat().st_mode & 0o777, 0o600)
        self.assertIn('ExecMainStatus=226', report.read_text())
        self.assertIn('vpn-management.service', calls[1])

    def test_management_failure_saves_journal_before_stopping_service(self):
        events = []
        def command(args, **kwargs):
            events.append(args)
            if args[:2] == ['systemctl', 'start']:
                raise RuntimeError('worker startup failed')
            return subprocess.CompletedProcess(args, 0, 'captured system journal\n', '')
        with patch.object(web, 'wait_ready'), patch.object(web, 'rpc', return_value={'url': 'unused'}), \
             patch.object(self.backend.m, 'command', side_effect=command), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(web.WebError, 'System journal saved:'):
                web.open_management(self.backend)
        journal = next(i for i, args in enumerate(events) if args[0] == 'journalctl')
        self.assertLess(journal, len(events) - 1)
        self.assertEqual(events[-1][:2], ['systemctl', 'stop'])
        self.assertIn('captured system journal', (self.backend.base / 'logs/web-failure-latest.txt').read_text())

    def test_readiness_error_names_socket_and_services(self):
        with patch.object(web, 'rpc', side_effect=FileNotFoundError('socket missing')):
            with self.assertRaisesRegex(web.WebError, 'control.socket'):
                web.wait_ready(self.backend, timeout=.01)
