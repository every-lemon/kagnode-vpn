import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('manager', ROOT / 'src/manage.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.base = self.root / 'private'
        self.etc = self.root / 'etc'
        self.patches = [patch.object(m, 'BASE', self.base), patch.object(m, 'ETC', self.etc),
                        patch.object(m, 'STATE', self.base / 'state.json'),
                        patch.object(m, 'EXPORT_ROOT', self.root / 'exports')]
        for p in self.patches:
            p.start()
        self.state = dict(lan='192.168.0.8', lan_net='192.168.0.0/24', iface='ens18',
                          endpoint='vpn.example.com', public='8.8.8.8', wg_net='10.66.66.0/24',
                          ike_net='192.168.43.0/24', l2tp_net='192.168.42.0/24', clients={},
                          psk='test-only-not-a-real-secret', installed=True)
        m.save(self.state)

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.temp.cleanup()

    def test_address_pools_exclude_connected_and_routed_networks(self):
        routes = [{'dst': 'default'}, {'dst': '10.66.0.0/16'}, {'dst': '192.168.42.0/23'},
                  {'dst': '10.200.0.0/16'}]
        pools = [ipaddress.ip_network(n) for n in m.choose_pools(routes)]
        self.assertEqual(len(pools), 3)
        existing = [ipaddress.ip_network(r['dst']) for r in routes[1:]]
        for i, pool in enumerate(pools):
            self.assertFalse(any(pool.overlaps(n) for n in existing + pools[:i]))

    def test_profile_on_demand_toggles_preserve_certificates(self):
        profile = {'PayloadUUID': 'outer', 'PayloadContent': [
            {'PayloadType': 'com.apple.vpn.managed', 'PayloadUUID': 'vpn',
             'IKEv2': {'AuthenticationMethod': 'Certificate', 'RemoteAddress': 'vpn.example.com'}},
            {'PayloadType': 'com.apple.security.pkcs12', 'PayloadContent': b'certificate-data'}]}
        path = self.root / 'phone.mobileconfig'
        path.write_bytes(plistlib.dumps(profile))
        m.mobileconfig(path, True)
        result = plistlib.loads(path.read_bytes())
        ike = result['PayloadContent'][0]['IKEv2']
        self.assertEqual(ike['OnDemandEnabled'], 1)
        self.assertEqual([r['InterfaceTypeMatch'] for r in ike['OnDemandRules'][:2]], ['WiFi', 'Cellular'])
        self.assertTrue(all(r['Action'] == 'Connect' for r in ike['OnDemandRules'][:2]))
        self.assertEqual(result['PayloadContent'][1], profile['PayloadContent'][1])
        self.assertEqual(result['PayloadUUID'], 'outer')
        m.mobileconfig(path, False)
        ike = plistlib.loads(path.read_bytes())['PayloadContent'][0]['IKEv2']
        self.assertEqual(ike['OnDemandEnabled'], 0)
        self.assertEqual(ike['OnDemandRules'], [])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_reject_injection_names_and_passwords(self):
        for name in ('../phone', 'bad name', '-option', 'a\nroot', 'x' * 21):
            with self.assertRaises(ValueError):
                m.validate_name(name)
        for value in ('short', 'abcdefghijkl\nroot', 'abcdefghijkl"', 'abcdefghijkl\\'):
            with self.assertRaises(ValueError):
                m.valid_password(value)
        self.assertEqual(m.validate_name('first-device'), 'first-device')
        self.assertGreaterEqual(len(m.random_password()), 24)

    def seed_wireguard(self):
        m.atomic(self.etc / 'wireguard/wg0.conf', '[Interface]\nPrivateKey = TEST_SERVER_PRIVATE\n')
        m.atomic(self.base / 'wg-server.pub', 'TEST_SERVER_PUBLIC\n')

    @staticmethod
    def fake_wg(args, **kwargs):
        response = {('wg', 'show', 'wg0', 'allowed-ips'): '', ('wg', 'genkey'): 'TEST_PRIVATE\n',
                    ('wg', 'pubkey'): 'TEST_PUBLIC\n'}.get(tuple(args), '')
        return subprocess.CompletedProcess(args, 0, response, '')

    def test_wireguard_add_duplicate_and_revoke(self):
        self.seed_wireguard()
        with patch.object(m, 'command', side_effect=self.fake_wg):
            m.add_wg('phone')
            with self.assertRaises(ValueError):
                m.add_wg('phone')
            conf = (self.base / 'clients/wireguard/phone.conf').read_text()
            self.assertIn('Address = 10.66.66.2/32', conf)
            self.assertIn('DNS = 192.168.0.8', conf)
            self.assertIn('AllowedIPs = 0.0.0.0/0', conf)
            m.revoke_wg('phone')
        self.assertNotIn('BEGIN_PEER', (self.etc / 'wireguard/wg0.conf').read_text())
        self.assertFalse((self.base / 'clients/wireguard/phone.conf').exists())
        self.assertNotIn('wireguard', m.load()['clients']['phone'])

    def test_failed_live_peer_rolls_back_durable_files(self):
        self.seed_wireguard()
        before = (self.etc / 'wireguard/wg0.conf').read_bytes()
        def fake(args, **kwargs):
            if args[:2] == ['wg', 'set']:
                raise RuntimeError('simulated failure')
            return self.fake_wg(args, **kwargs)
        with patch.object(m, 'command', side_effect=fake):
            with self.assertRaises(RuntimeError):
                m.add_wg('broken')
        self.assertEqual((self.etc / 'wireguard/wg0.conf').read_bytes(), before)
        self.assertFalse((self.base / 'clients/wireguard/broken.conf').exists())

    def test_address_allocator_does_not_confuse_2_and_20(self):
        self.seed_wireguard()
        path = self.etc / 'wireguard/wg0.conf'
        m.atomic(path, path.read_text() + '\nAllowedIPs = 10.66.66.20/32\n')
        with patch.object(m, 'command', side_effect=self.fake_wg):
            m.add_wg('phone')
        self.assertEqual(m.load()['clients']['phone']['wireguard']['address'], '10.66.66.2')

    def test_l2tp_add_revoke_and_private_exports(self):
        m.atomic(self.etc / 'ppp/chap-secrets', '# existing\n')
        with patch.object(m, 'command', return_value=subprocess.CompletedProcess([], 0, 'HASH\n', '')):
            m.l2tp_add('alice', 'custom-password-123')
        path = self.base / 'clients/l2tp/alice.txt'
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertIn('Username: alice', path.read_text())
        self.assertFalse((self.etc / 'ipsec.d/passwd').exists())
        self.assertIn('custom-password-123',(self.etc/'ppp/chap-secrets').read_text())
        m.revoke_l2tp('alice')
        self.assertNotIn('alice', (self.etc / 'ppp/chap-secrets').read_text())
        self.assertFalse(path.exists())

    def test_atomic_permissions_and_shared_operation_lock(self):
        with m.lock():
            with self.assertRaises(RuntimeError):
                with m.lock():
                    pass
        self.assertEqual(m.STATE.stat().st_mode & 0o777, 0o600)

    def test_l2tp_write_failure_restores_authentication_files(self):
        chap, passwd = self.etc / 'ppp/chap-secrets', self.etc / 'ipsec.d/passwd'
        m.atomic(chap, '# chap-original\n')
        m.atomic(passwd, '# passwd-original\n')
        original_atomic = m.atomic
        failed = False
        def failing_atomic(path, data, mode=0o600):
            nonlocal failed
            if not failed and Path(path) == m.STATE and 'alice' in data:
                failed = True
                raise OSError('simulated write failure')
            return original_atomic(path, data, mode)
        with patch.object(m, 'atomic', side_effect=failing_atomic), patch.object(m, 'command', return_value=subprocess.CompletedProcess([], 0, 'HASH\n', '')):
            with self.assertRaises(OSError):
                m.l2tp_add('alice', 'custom-password-123')
        self.assertEqual(chap.read_text(), '# chap-original\n')
        self.assertEqual(passwd.read_text(), '# passwd-original\n')
        self.assertNotIn('alice', m.load()['clients'])

    def test_bandwidth_rates_handle_counter_reset(self):
        self.assertEqual(m.rate(100, 300, 2), 100)
        self.assertEqual(m.rate(300, 10, 2), 0)

    def test_public_ipv4_does_not_get_passed_as_dns_hostname(self):
        routes = subprocess.CompletedProcess([], 0, '[]', '')
        with patch.object(m, 'command', return_value=routes):
            m.configure('192.168.0.8', '192.168.0.8/24', 'ens18', '9.9.9.9', '8.8.8.8')
        self.assertEqual(m.load()['public'], '9.9.9.9')


class ArtifactTests(unittest.TestCase):
    def test_standalone_matches_sources(self):
        source = (ROOT / 'src/installer.sh').read_text()
        import base64, gzip
        release=(ROOT/'VERSION').read_text().strip()
        source=source.replace('@@VERSION@@',release).replace('@@RELEASE_KEY@@',(ROOT/'release-key.pem').read_text().strip())
        modules = {name: (ROOT / 'src' / (name + '.py')).read_text().replace('@@VERSION@@',release).replace('@@IKE_HELPER@@',base64.b64encode((ROOT/'src/vendor/ikev2.sh').read_bytes()).decode()) for name in m._MODULE_NAMES}
        blob = base64.b64encode(gzip.compress(json.dumps(modules, sort_keys=True).encode(), mtime=0)).decode()
        runtime = (ROOT / 'src/manage.py').read_text().rstrip().replace('@@MODULE_ARCHIVE@@', blob)
        expected = source.replace('@@PYTHON_RUNTIME@@', runtime)
        self.assertEqual((ROOT / 'setup.sh').read_text(), expected)
        self.assertTrue(expected.endswith('# END_VPN_STACK_INSTALLER\n'))

    def test_help_and_demo_do_not_require_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o755)
            script = directory / 'setup.sh'
            script.write_text((ROOT / 'setup.sh').read_text())
            script.chmod(0o644)
            def unprivileged():
                os.setgid(65534)
                os.setuid(65534)
            for option in ('--help', '--demo'):
                result = subprocess.run(['bash', str(script), option], capture_output=True, text=True,
                                        preexec_fn=unprivileged if os.geteuid() == 0 else None)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('Error:', result.stderr)

    def test_installer_never_creates_a_starter_client(self):
        source=(ROOT/'src/installer.sh').read_text()
        self.assertNotIn('create_initial_profiles',source)
        self.assertNotIn('manage.py" bootstrap',source)

    def test_reject_truncated_script_before_main(self):
        text = (ROOT / 'setup.sh').read_text().replace('# END_VPN_STACK_INSTALLER\n', '')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'setup.sh'
            path.write_text(text)
            result = subprocess.run(['bash', str(path), '--help'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('completion marker', result.stderr)


if __name__ == '__main__':
    unittest.main()
