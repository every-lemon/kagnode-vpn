"""Actual systemd restart of a uniquely named fixture; no VPN service or reboot."""
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import types
import unittest
import uuid
from test_manager import m
import vpn_watchdog as w


@unittest.skipUnless(os.geteuid() == 0 and Path('/run/systemd/system').is_dir(), 'requires root and systemd')
class RecoveryTests(unittest.TestCase):
    def test_real_service_restart_recovers_unresponsive_health_route(self):
        name = 'vpnstack-it-recovery-' + uuid.uuid4().hex[:8] + '.service'
        unit = Path('/run/systemd/system') / name
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            script = base / 'worker.py'
            script.write_text('''from http.server import HTTPServer,BaseHTTPRequestHandler
from pathlib import Path
p=Path(__file__).with_name('starts')
count=int(p.read_text())+1 if p.exists() else 1
p.write_text(str(count))
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(503 if count==1 else 200);self.end_headers();self.wfile.write(b'OK\\n')
 def log_message(self,*args):pass
HTTPServer(('127.0.0.1', ''' + str(port) + '''),Handler).serve_forever()
''')
            unit.write_text('[Service]\nExecStart=/usr/bin/python3 ' + str(script) + '\n')
            def systemctl(*args):
                return subprocess.run(['systemctl', *args], capture_output=True, text=True, timeout=15)
            try:
                self.assertEqual(systemctl('daemon-reload').returncode, 0)
                self.assertEqual(systemctl('start', name).returncode, 0)
                deadline = time.monotonic() + 5
                while not (base / 'starts').exists() and time.monotonic() < deadline:
                    time.sleep(.05)
                manager = types.SimpleNamespace(BASE=base, ETC=base/'etc', atomic=m.atomic)
                clock = [100000, 300]
                calls = []
                def run(args, **kwargs):
                    self.assertEqual(args, ['systemctl', 'restart', 'AdGuardHome.service'])
                    calls.append(args)
                    return systemctl('restart', name)
                monitor = w.Watchdog(manager, run=run, clock=lambda: clock[0], monotonic=lambda: clock[1], boot='test', uptime=lambda: 300)
                def probes():
                    try:
                        w.http_probe('127.0.0.1', port)
                        return {}, {'dns': 'healthy'}
                    except Exception:
                        return {'dns': 'unresponsive'}, {'dns': 'unresponsive'}
                monitor.probes = probes
                def report(reason):
                    result = subprocess.run(['journalctl', '-u', name, '-n', '20', '--no-pager'], capture_output=True, text=True, timeout=5)
                    m.atomic(base / 'before-recovery.txt', result.stdout)
                monitor.report = report
                monitor.tick()
                clock[0] += 30; clock[1] += 30
                monitor.tick()
                self.assertEqual(len(calls), 1)
                deadline = time.monotonic() + 5
                while probes()[0] and time.monotonic() < deadline:
                    time.sleep(.05)
                self.assertEqual(probes()[0], {})
                self.assertTrue((base / 'before-recovery.txt').is_file())
                clock[0] += 30; clock[1] += 30
                self.assertEqual(monitor.tick()['status'], 'healthy')
            finally:
                systemctl('stop', name)
                unit.unlink(missing_ok=True)
                systemctl('daemon-reload')
                systemctl('reset-failed', name)
