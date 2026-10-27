import contextlib
import io
import subprocess
from unittest.mock import patch
import unittest
from test_manager import m


class AdGuardHealthTests(unittest.TestCase):
    def fake(self, args, **kwargs):
        if args[0] in ('iptables', 'ip6tables'):
            chain = 'VPNSTACK6-IN' if args[0] == 'ip6tables' else 'VPNSTACK-IN'
            output = '-P INPUT ACCEPT\n-A INPUT -j ' + chain + '\n' if '-S' in args else ''
        elif args[0] == 'systemctl':
            output = 'active\n'
        elif args[0] == 'dig':
            output = 'alias.example.com.\n93.184.215.14\n'
        elif ':8080' in args[-1]:
            output = 'LISTEN 0 4096 192.168.0.8%ens18:8080 0.0.0.0:* users:(("AdGuardHome",pid=123,fd=4))\n'
        else:
            output = 'udp UNCONN 0 0 192.168.0.8%ens18:53 0.0.0.0:* users:(("AdGuardHome",pid=123,fd=5))\n'
        return subprocess.CompletedProcess(args, 0, output, '')

    def run_check(self, fake):
        out = io.StringIO()
        with patch.object(m, 'load', return_value={'lan': '192.168.0.8', 'lan_net': '192.168.0.0/24', 'iface': 'ens18'}), patch.object(m, 'command', side_effect=fake), contextlib.redirect_stdout(out):
            result = m.check_adguard()
        return result, out.getvalue()

    def test_valid_scoped_addresses_pass(self):
        result, output = self.run_check(self.fake)
        self.assertTrue(result, output)
        self.assertEqual(output.count('PASS'), 5)

    def test_endpoint_variations(self):
        for line, port, expected in [
            ('LISTEN 0 4096 192.168.0.8%ens18:8080 0.0.0.0:*', 8080, '192.168.0.8'),
            ('tcp LISTEN 0 4096 [::ffff:192.168.0.8]:8080 [::]:*', 8080, '192.168.0.8'),
            ('udp UNCONN 0 0 *:53 *:*', 53, '*'),
            ('udp UNCONN 0 0 [::]:53 [::]:*', 53, '::'),
            ('udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*', 53, '0.0.0.0')]:
            with self.subTest(line=line):
                self.assertEqual(m.socket_host(line, port), expected)

    def test_dns_failure_names_protocol_without_hiding_passing_checks(self):
        def fake(args, **kwargs):
            if args[0] == 'dig' and '+tcp' in args:
                return subprocess.CompletedProcess(args, 9, 'connection timed out', '')
            return self.fake(args, **kwargs)
        result, output = self.run_check(fake)
        self.assertFalse(result)
        self.assertIn('FAIL DNS TCP', output)
        self.assertIn('PASS DNS UDP', output)
        self.assertIn('connection timed out', output)

    def test_protected_wildcard_admin_passes(self):
        def fake(args, **kwargs):
            if args[0] == 'ss' and ':8080' in args[-1]:
                return subprocess.CompletedProcess(args, 0, 'LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:*', '')
            return self.fake(args, **kwargs)
        result, output = self.run_check(fake)
        self.assertTrue(result, output)
        self.assertIn('Wildcard listener protected by LAN-only firewall rules', output)

    def test_ipv6_wildcard_dns_passes(self):
        def fake(args, **kwargs):
            if args[0] == 'ss' and ':53' in args[-1]:
                return subprocess.CompletedProcess(args, 0, 'udp UNCONN 0 0 [::]:53 [::]:* users:(("AdGuardHome",pid=123,fd=5))', '')
            return self.fake(args, **kwargs)
        result, output = self.run_check(fake)
        self.assertTrue(result, output)

    def test_ipv6_wildcard_admin_with_guard_passes(self):
        def fake(args, **kwargs):
            if args[0] == 'ss' and ':8080' in args[-1]:
                return subprocess.CompletedProcess(args, 0, 'LISTEN 0 4096 *:8080 *:* users:(("AdGuardHome",pid=11714,fd=9))', '')
            return self.fake(args, **kwargs)
        result, output = self.run_check(fake)
        self.assertTrue(result, output)

    def test_wildcard_without_firewall_is_rejected(self):
        def fake(args, **kwargs):
            if args[0] == 'ss' and ':8080' in args[-1]:
                return subprocess.CompletedProcess(args, 0, 'LISTEN 0 4096 *:8080 *:*', '')
            if args[0] in ('iptables', 'ip6tables'):
                return subprocess.CompletedProcess(args, 1, '', 'missing guard')
            return self.fake(args, **kwargs)
        result, output = self.run_check(fake)
        self.assertFalse(result)
        self.assertIn('LAN firewall protection is missing', output)
