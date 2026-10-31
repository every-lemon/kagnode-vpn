"""Validate generated connections with the installed Libreswan parser, without starting VPNs."""
from pathlib import Path
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import types
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
# Other tests register the standalone loader. Load the development source explicitly
# so its unembedded vendor helper resolves from a real __file__, independent of order.
_spec = importlib.util.spec_from_file_location(
    'vpn_native_parser_fixture', Path(__file__).resolve().parents[1] / 'src/vpn_native.py')
vpn_native = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vpn_native)


@unittest.skipUnless(shutil.which('ipsec'), 'Libreswan parser is required (installed by CI)')
class NativeConfigurationTests(unittest.TestCase):
    def test_generated_configuration_passes_real_parser_and_preserves_trust(self):
        executable = shutil.which('ipsec')
        with tempfile.TemporaryDirectory(prefix='vpn-native-parser-') as tmp:
            root = Path(tmp)
            base, etc = root / 'var/lib/kagnode/vpn', root / 'etc'
            base.mkdir(parents=True)
            nss = root / 'var/lib/ipsec/nss'
            nss.mkdir(parents=True)
            trust = nss / 'cert9.db'
            trust.write_bytes(b'existing-fixture-trust-not-a-real-NSS-database')
            original = trust.read_bytes()
            checked = []

            def atomic(path, content, mode=0o600):
                path = Path(path)
                self.assertTrue(path.is_relative_to(root))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content if isinstance(content, bytes) else content.encode())
                path.chmod(mode)

            def check():
                candidate = root / 'parser.conf'
                candidate.write_text((etc / 'ipsec.conf').read_text().replace(
                    'include /etc/ipsec.d/*.conf', 'include ' + str(etc / 'ipsec.d/*.conf')))
                return subprocess.run([executable, 'addconn', '--config', str(candidate), '--checkconfig'],
                                      capture_output=True, text=True, timeout=15)

            def command(args, **kwargs):
                if args[0] == executable and args[1:] == ['--version']:
                    return subprocess.run(args, capture_output=True, text=True, check=True, timeout=10)
                if args[:2] == ['ipsec', 'addconn']:
                    result = check()
                    checked.append(result.returncode)
                    if result.returncode:
                        raise AssertionError('Generated configuration rejected: ' + result.stderr)
                    return result
                if args[0] == 'certutil':
                    self.assertEqual(args[1], '-L', 'Existing trust must not be regenerated on resume.')
                else:
                    self.assertIn(args[0], ('apt-get', 'systemctl'))
                # Package/service/certificate mutations are not executed on the test host.
                return subprocess.CompletedProcess(args, 0, '', '')

            manager = types.SimpleNamespace(BASE=base, ETC=etc, atomic=atomic, command=command,
                load=lambda: {'endpoint': 'vpn.example.com', 'lan': '192.168.0.8',
                    'wg_net': '10.66.66.0/24', 'ike_net': '10.10.10.0/24',
                    'l2tp_net': '192.168.42.0/24', 'psk': 'synthetic-fixture-psk'})
            vpn_native.install(manager)
            self.assertEqual(checked, [0])
            self.assertEqual(trust.read_bytes(), original)
            connection = etc / 'ipsec.d/ikev2.conf'
            connection.write_text(connection.read_text() + '\n  invalid-vpn-fixture-keyword=yes\n')
            self.assertNotEqual(check().returncode, 0, 'The real parser must reject an invalid connection.')


if __name__ == '__main__':
    unittest.main()
