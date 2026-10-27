"""Local watchdog state machines: every recovery/reboot command is fake."""
import fcntl
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch
from test_manager import m
import vpn_watchdog as w
import vpn_web as web


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.now, self.mono = 100000, 300
        self.calls = []
        self.manager = types.SimpleNamespace(BASE=self.base, ETC=self.base/'etc', atomic=m.atomic,
            load=lambda: {'lan': '192.168.0.8'})
        def command(args, **kwargs):
            self.calls.append(list(args))
            if args[:2] == ['systemctl', 'reboot']:
                self.assertIn(self.now, json.loads((self.base / 'watchdog-state.json').read_text())['reboots'])
            return subprocess.CompletedProcess(args, 0, '51820\n' if args[:1] == ['wg'] else 'listener\n', '')
        self.manager.command=command
        self.monitor = w.Watchdog(self.manager, command, lambda: self.now, lambda: self.mono,
                                   'test-boot', lambda: 300)

    def tearDown(self):
        self.tmp.cleanup()

    def step(self, state, failures, delta=30, config=None):
        state, actions = w.decision(state, failures, self.now, self.mono, 'test-boot', config or w.DEFAULTS)
        self.now += delta
        self.mono += delta
        return state, actions

    def test_restart_then_reboot_after_three_minutes_and_no_reboot_loop(self):
        state = {}
        actions = []
        for _ in range(7):
            state, next_actions = self.step(state, {'dns': 'unresponsive'})
            actions.extend(next_actions)
        self.assertEqual([a for a, _ in actions], ['restart', 'restart', 'reboot'])
        for _ in range(30):
            state, actions = self.step(state, {'dns': 'unresponsive'})
            self.assertFalse(any(a == 'reboot' for a, _ in actions))
        state['reboots'] = [self.now - 2000, self.now - 4000]
        state, actions = self.step(state, {'dns': 'unresponsive'})
        self.assertFalse(any(a == 'reboot' for a, _ in actions))

    def test_web_only_failure_never_reboots_and_recovery_resets_streak(self):
        state = {}
        for _ in range(100):
            state, actions = self.step(state, {'management': 'not responding'})
            self.assertFalse(any(a == 'reboot' for a, _ in actions))
        state, actions = self.step(state, {})
        self.assertEqual(state['components'], {})
        state, actions = self.step(state, {'dns': 'failed'})
        self.assertEqual(actions, [])

    def test_new_boot_preserves_reboot_budget_but_resets_failure_duration(self):
        state = {'boot': 'old', 'reboots': [self.now - 60], 'components': {'dns': {'since': 0}}}
        state, actions = self.step(state, {'dns': 'failure'})
        self.assertEqual(state['reboots'], [self.now - 90])
        self.assertEqual(actions, [])
        self.assertEqual(state['components']['dns']['since'], self.mono - 30)

    def test_clock_rollback_disables_reboots_but_not_service_restarts(self):
        state = {'last_wall': self.now + 10000}
        for _ in range(10):
            state, actions = self.step(state, {'backend': 'busy'})
            self.assertFalse(any(a == 'reboot' for a, _ in actions))
        self.assertTrue(state['clock_unsafe'])
        self.assertEqual(len(state['components']['backend']['restarts']), 2)

    def test_paused_boot_grace_and_maintenance_do_not_probe_or_recover(self):
        self.monitor.probes = lambda: self.fail('must not probe while suppressed')
        self.monitor.configure('paused', True)
        self.assertEqual(self.monitor.tick()['status'], 'paused')
        self.monitor.configure('paused', False)
        self.monitor.uptime = lambda: 30
        self.assertEqual(self.monitor.tick()['status'], 'boot grace')
        self.monitor.uptime = lambda: 300
        with (self.base / 'maintenance.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.assertEqual(self.monitor.tick()['status'], 'maintenance')
        self.assertEqual(self.calls, [])

    def test_evidence_is_collected_before_restart_and_state_is_private(self):
        self.monitor.probes = lambda: ({'dns': 'unresponsive'}, {'dns': 'unresponsive'})
        events = []
        self.monitor.report = lambda reason: events.append(('report', reason))
        original = self.monitor.run
        def run(args, **kwargs):
            events.append(('command', args))
            return original(args, **kwargs)
        self.monitor.run = run
        self.monitor.tick()
        self.now += 30; self.mono += 30
        self.monitor.tick()
        self.assertEqual(events[0][0], 'report')
        self.assertEqual(events[1][1], ['systemctl', 'restart', 'AdGuardHome.service'])
        self.assertEqual((self.base / 'watchdog-state.json').stat().st_mode & 0o777, 0o600)

    def test_reboot_budget_is_persisted_before_fake_reboot(self):
        self.monitor.probes = lambda: ({'dns': 'failed'}, {'dns': 'failed'})
        self.monitor.report = lambda reason: None
        with patch.object(w.os, 'sync'):
            for _ in range(7):
                self.monitor.tick()
                self.now += 30; self.mono += 30
        self.assertEqual(sum(args[:2] == ['systemctl', 'reboot'] for args in self.calls), 1)

    def test_persistent_management_is_probed_and_dns_upstream_failure_does_not_count(self):
        m.atomic(self.base / 'web-enabled', 'yes')
        web.Store(self.base / 'backend.db', boot='test-boot')
        m.atomic(self.base / 'backend-health.json', json.dumps({'boot': 'test-boot', 'monotonic': self.mono}))
        with patch.object(w, 'dns_probe'), patch.object(w, 'http_probe') as http, patch.object(web, 'rpc', return_value={'ready': True}):
            failures, checks = self.monitor.probes()
        self.assertEqual(failures, {})
        self.assertEqual(checks['management'], 'healthy')
        self.assertEqual([c.args for c in http.call_args_list],[('192.168.0.8',9000),('192.168.0.8',9001)])

    def test_backend_recovery_restarts_persistent_management(self):
        self.monitor.probes = lambda: ({'backend': 'unresponsive'},
            {'backend': 'unresponsive', 'downloads': 'healthy', 'management': 'healthy'})
        self.monitor.report = lambda reason: None
        self.monitor.tick()
        self.now += 30; self.mono += 30
        self.monitor.tick()
        restarts = [args for args in self.calls if args[:2] == ['systemctl', 'restart']]
        self.assertTrue(any('vpn-downloads.service' in args for args in restarts))
        self.assertTrue(any('vpn-management.service' in args for args in restarts))

    def test_no_global_window_closes_management(self):
        self.monitor.probes = lambda: ({}, {'management': 'closed'})
        state = self.monitor.tick()
        self.assertEqual(state['status'], 'healthy')
        self.assertFalse(any(args[:2]==['systemctl','stop'] for args in self.calls))
        self.assertFalse(any(args[:2] == ['systemctl', 'restart'] for args in self.calls))

    def test_report_has_system_journal_and_retention_is_bounded(self):
        self.monitor.report('test evidence')
        path = self.base / 'logs/watchdog-failure-latest.txt'
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertIn('journalctl', path.read_text())
        for n in range(25):
            m.atomic(self.base / ('logs/web-failure-' + str(n) + '.txt'), 'evidence')
        w.prune_reports(self.base / 'logs')
        self.assertLessEqual(len(list((self.base / 'logs').glob('*-failure-*.txt'))), 21)

    def test_watchdog_configuration_rejects_unsafe_limits(self):
        m.atomic(self.base / 'watchdog.json', json.dumps({'failure_seconds': 1}))
        with self.assertRaises(ValueError):
            self.monitor.config()


if __name__ == '__main__':
    unittest.main()


class DNSProbeTests(unittest.TestCase):
    def test_local_servfail_is_responsive_and_tcp_udp_are_both_validated(self):
        import socket
        import struct
        import threading
        for tcp in (False, True):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as server:
                server.bind(('127.0.0.1', 0))
                server.settimeout(2)
                port = server.getsockname()[1]
                if tcp:
                    server.listen()
                def answer():
                    if tcp:
                        with server.accept()[0] as connection:
                            size = struct.unpack('!H', connection.recv(2))[0]
                            packet = connection.recv(size)
                            response = packet[:2] + b'\x81\x82' + packet[4:]
                            connection.sendall(struct.pack('!H', len(response)) + response)
                    else:
                        packet, address = server.recvfrom(4096)
                        server.sendto(packet[:2] + b'\x81\x82' + packet[4:], address)
                thread = threading.Thread(target=answer, daemon=True)
                thread.start()
                w.dns_probe('127.0.0.1', tcp, port=port)
                thread.join(3)
                self.assertFalse(thread.is_alive())
