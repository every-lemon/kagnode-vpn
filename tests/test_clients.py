import json
from pathlib import Path
import subprocess
from unittest.mock import patch
import unittest
import test_manager as tm
m = tm.m
import vpn_clients as c


class ClientTests(unittest.TestCase):
    def setUp(self):
        tm.RuntimeTests.setUp(self)
        self.backend = c.Backend(m)
        self.backend.migrate()
        self.user = self.backend.user_add('Person with spaces')
        self.device = self.backend.device_add(self.user, 'Phone with spaces')

    def tearDown(self):
        tm.RuntimeTests.tearDown(self)

    def test_duplicate_and_invalid_labels(self):
        with self.assertRaises(c.ClientError):
            self.backend.user_add('PERSON WITH SPACES')
        with self.assertRaises(c.ClientError):
            self.backend.device_add(self.user, 'Phone with spaces')
        with self.assertRaises(c.ClientError):
            self.backend.rename('device', self.device, 'control\ncharacter')
        with self.assertRaises(c.ClientError):
            self.backend.rename('unknown', self.device, 'test')

    def test_pending_replacement_adopts_exact_backend_identifier(self):
        native = 'dev-replacement'
        self.backend.operation(self.device, 'replace-ikev2', 'pending', backend=native)
        with patch.object(self.backend, 'cert_names', return_value=[native]):
            self.backend.repair(self.device)
        self.assertEqual(self.backend.device(self.device)[1]['protocols']['ikev2']['backend'], native)
        entry = json.loads((self.base / 'operations' / (self.device + '.json')).read_text())
        self.assertEqual(entry['status'], 'complete')

    def test_failed_certificate_export_is_recoverable_without_regeneration(self):
        calls = []
        def helper(native, action):
            calls.append((native, action))
            raise RuntimeError('late helper failure')
        with patch.object(self.backend, 'cert_names', side_effect=[[], [self.device]]), patch.object(self.backend, 'helper', side_effect=helper):
            with self.assertRaises(RuntimeError):
                self.backend.protocol_add(self.device, 'ikev2')
        record = self.backend.device(self.device)[1]['protocols']['ikev2']
        self.assertEqual(record['backend'], self.device)
        self.assertEqual(record['status'], 'export-pending')
        self.assertEqual(len(calls), 1)
        with patch.object(self.backend, 'cert_names', return_value=[self.device]):
            self.backend.repair(self.device)
        self.assertEqual(self.backend.device(self.device)[1]['protocols']['ikev2']['status'], 'active')
        self.assertEqual(len(calls), 1)

    def test_configuring_revoked_protocol_uses_replacement_not_old_credentials(self):
        reg = self.backend.load()
        reg['devices'][self.device]['protocols']['ikev2'] = {'backend': 'revoked-native', 'status': 'revoked', 'export': None}
        self.backend.save(reg)
        with patch.object(self.backend, 'rotate') as replace, patch.object(self.backend, 'protocol_add') as add:
            self.backend.add_protocols(self.device, ['ikev2'])
        replace.assert_called_once_with(self.device, 'ikev2')
        add.assert_not_called()

    def test_removed_device_name_can_be_reused_with_a_fresh_identifier(self):
        reg = self.backend.load()
        reg['devices'][self.device]['protocols'] = {'ikev2': {'backend': 'old-revoked', 'status': 'revoked', 'export': None}}
        self.backend.save(reg)
        name = reg['devices'][self.device]['name']
        new_device = self.backend.device_add(self.user, name)
        self.assertNotEqual(new_device, self.device)
        self.assertEqual(self.backend.device(self.device)[1]['protocols']['ikev2']['status'], 'revoked')
        self.assertEqual(self.backend.device(new_device)[1]['protocols'], {})

    def test_wireguard_state_failure_removes_live_peer_and_restores_files(self):
        conf = self.etc / 'wireguard/wg0.conf'
        m.atomic(conf, '[Interface]\n')
        m.atomic(self.base / 'wg-server.pub', 'SERVER\n')
        def command(args, **kw):
            output = 'PRIVATE\n' if 'genkey' in args else 'PUBLIC\n' if 'pubkey' in args else ''
            return subprocess.CompletedProcess(args, 0, output, '')
        original = m.STATE.read_bytes()
        with patch.object(m, 'command', side_effect=command) as commands, patch.object(m, 'save', side_effect=OSError('disk failure')):
            with self.assertRaises(OSError):
                m.add_wg('testclient')
        self.assertEqual(conf.read_text(), '[Interface]\n')
        self.assertEqual(m.STATE.read_bytes(), original)
        self.assertFalse((self.base / 'clients/wireguard/testclient.conf').exists())
        self.assertTrue(any(call.args[0][-1] == 'remove' for call in commands.call_args_list))

    def test_web_renders_unexported_migrated_devices(self):
        import vpn_web
        reg = self.backend.load()
        reg['devices'][self.device]['protocols']['ikev2'] = {'backend': 'old', 'status': 'active', 'export': None}
        output = vpn_web.manager_html({'registry': reg, 'csrf': 'token'}, view='device', device=self.device)
        self.assertIn(b'Phone with spaces', output)
