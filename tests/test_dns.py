import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from test_manager import m


class DNSPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.base, self.etc, self.run = [self.root / p for p in ('private', 'etc', 'run')]
        self.patches = [patch.object(m, 'BASE', self.base), patch.object(m, 'ETC', self.etc),
                        patch.object(m, 'RUN', self.run), patch.object(m, 'STATE', self.base / 'state.json')]
        for p in self.patches:
            p.start()
        m.save({'lan': '192.168.0.8'})
        m.atomic(self.run / 'systemd/resolve/resolv.conf', 'nameserver 192.168.0.1\n')
        m.atomic(self.run / 'systemd/resolve/stub-resolv.conf', 'nameserver 127.0.0.53\n')
        self.etc.mkdir()
        (self.etc / 'resolv.conf').symlink_to(self.run / 'systemd/resolve/stub-resolv.conf')
        self.original_link = os.readlink(self.etc / 'resolv.conf')
        self.calls = []

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.temp.cleanup()

    def fake(self, args, **kwargs):
        self.calls.append(args)
        if args[0] == 'ss':
            output = ('udp UNCONN 0 0 127.0.0.53:53 0.0.0.0:* users:(("systemd-resolve",pid=10,fd=1))\n'
                      if sum(c[0] == 'ss' for c in self.calls) == 1 else '')
        else:
            output = ''
        return subprocess.CompletedProcess(args, 0, output, '')

    def test_frees_resolved_stub_and_preserves_upstream_resolution(self):
        with patch.object(m, 'command', side_effect=self.fake):
            m.prepare_dns()
        self.assertEqual(os.readlink(self.etc / 'resolv.conf'), str(self.run / 'systemd/resolve/resolv.conf'))
        self.assertIn('DNSStubListener=no', (self.etc / 'systemd/resolved.conf.d/zzzz-vpn.conf').read_text())
        self.assertIn(['getent', 'ahostsv4', 'example.com'], self.calls)
        self.assertEqual(json.loads((self.base / 'backups/resolv-link.json').read_text())['target'], self.original_link)

    def test_resolved_interface_suffix_is_recognized(self):
        first = True
        def scoped(args, **kwargs):
            nonlocal first
            if args[0] == 'ss' and first:
                first = False
                return subprocess.CompletedProcess(args, 0,
                    'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=10243,fd=14))\n'
                    'tcp LISTEN 0 4096 127.0.0.54%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=10243,fd=15))\n', '')
            if args[0] == 'ss':
                return subprocess.CompletedProcess(args, 0, '', '')
            return self.fake(args, **kwargs)
        with patch.object(m, 'command', side_effect=scoped):
            m.prepare_dns()
        self.assertIn(['systemctl', 'restart', 'systemd-resolved'], self.calls)
        self.assertEqual(os.readlink(self.etc / 'resolv.conf'), str(self.run / 'systemd/resolve/resolv.conf'))

    def test_repairs_private_dropin_directory_and_unprivileged_read(self):
        directory = self.etc / 'systemd/resolved.conf.d'
        directory.mkdir(parents=True, mode=0o700)
        # Model the real daemon: reject an unreadable directory when restart runs.
        def restart(args, **kwargs):
            if args == ['systemctl', 'restart', 'systemd-resolved']:
                self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
            return self.fake(args, **kwargs)
        with patch.object(m, 'command', side_effect=restart):
            m.prepare_dns()
        self.root.chmod(0o755)
        (self.etc / 'systemd').chmod(0o755)
        config = directory / 'zzzz-vpn.conf'
        def unprivileged():
            os.setgid(65534)
            os.setuid(65534)
        result = subprocess.run(['cat', str(config)], capture_output=True, text=True,
                                preexec_fn=unprivileged if os.geteuid() == 0 else None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('DNSStubListener=no', result.stdout)

    def test_persistent_listener_error_includes_owner_and_restores_dns(self):
        def occupied(args, **kwargs):
            if args[0] == 'ss':
                return subprocess.CompletedProcess(args, 0,
                    'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=10243,fd=14))', '')
            return self.fake(args, **kwargs)
        with patch.object(m, 'command', side_effect=occupied), patch.object(m.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'Remaining listeners:') as error:
                m.prepare_dns()
        self.assertIn('pid=10243', str(error.exception))
        self.assertEqual(os.readlink(self.etc / 'resolv.conf'), self.original_link)

    def test_waits_for_resolver_socket_release(self):
        reads = 0
        def delayed(args, **kwargs):
            nonlocal reads
            if args[0] == 'ss':
                reads += 1
                output = ('udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=10243,fd=14))'
                          if reads <= 3 else '')
                return subprocess.CompletedProcess(args, 0, output, '')
            return self.fake(args, **kwargs)
        with patch.object(m, 'command', side_effect=delayed), patch.object(m.time, 'sleep') as sleep:
            m.prepare_dns()
        self.assertEqual(sleep.call_count, 2)

    def test_failed_host_dns_restores_original_link_and_dropin(self):
        def fail(args, **kwargs):
            if args[0] == 'getent':
                raise RuntimeError('DNS unavailable')
            return self.fake(args, **kwargs)
        with patch.object(m, 'command', side_effect=fail):
            with self.assertRaises(RuntimeError):
                m.prepare_dns()
        self.assertEqual(os.readlink(self.etc / 'resolv.conf'), self.original_link)
        self.assertFalse((self.etc / 'systemd/resolved.conf.d/zzzz-vpn.conf').exists())

    def test_unrelated_dns_process_is_not_stopped(self):
        result = subprocess.CompletedProcess([], 0, 'udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* users:(("dnsmasq",pid=20,fd=1))', '')
        with patch.object(m, 'command', return_value=result) as fake:
            with self.assertRaisesRegex(RuntimeError, 'another process'):
                m.prepare_dns()
            self.assertEqual(fake.call_count, 1)
        self.assertEqual(os.readlink(self.etc / 'resolv.conf'), self.original_link)

    def test_loopback_upstream_is_rejected_without_changes(self):
        m.atomic(self.run / 'systemd/resolve/resolv.conf', 'nameserver 127.0.0.53\n')
        with patch.object(m, 'command', side_effect=self.fake):
            with self.assertRaisesRegex(RuntimeError, 'real upstream DNS'):
                m.prepare_dns()
        self.assertEqual(os.readlink(self.etc / 'resolv.conf'), self.original_link)
