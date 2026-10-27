"""Real isolated systemd socket activation and unprivileged Waitress workers on Ubuntu.
Uses unique /run units and loopback ephemeral ports; never touches VPN services.
"""
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import uuid
from test_manager import ROOT
import vpn_web as web
import vpn_watchdog as watchdog
import vpn_harden as harden


@unittest.skipUnless(os.geteuid() == 0 and Path('/run/systemd/system').is_dir(), 'requires root and systemd')
class SystemdTests(unittest.TestCase):
    def test_missing_nftables_lock_is_created_before_controller_sandbox(self):
        name = 'vpnstack-it-lock-' + uuid.uuid4().hex[:8]
        unit_dir = Path('/run/systemd/system')
        with tempfile.TemporaryDirectory(prefix=name) as folder:
            root = Path(folder)
            lock = root / 'xtables.lock'
            # Reproduce the 3.3.0 failure without changing the host's global lock file.
            broken = subprocess.run(['systemd-run', '--unit=' + name + '-broken', '--collect', '--wait', '--pipe',
                                     '--property=ProtectSystem=strict', '--property=ReadWritePaths=' + str(lock), '/usr/bin/true'], capture_output=True, text=True, timeout=15)
            self.assertEqual(broken.returncode, 226, broken.stdout + broken.stderr)
            self.assertFalse(lock.exists())
            config = root / 'tmpfiles.conf'
            config.write_text(web.TMPFILES_RULES.replace('/run/xtables.lock', str(lock)))
            script = root / 'probe.py'
            script.write_text('from pathlib import Path\nPath(' + repr(str(lock)) + ').write_text("controller-started")\n')
            socket_text = web.unit_files()['vpn-control.socket'].replace('/etc/tmpfiles.d/vpn.conf', str(config)).replace('/run/vpn/control.sock', str(root / 'control.sock')).replace('SocketGroup=vpn-rpc', 'SocketGroup=nogroup')
            service_text = '[Unit]\nRequires=' + name + '.socket\nAfter=' + name + '.socket\n[Service]\nType=oneshot\nProtectSystem=strict\nReadWritePaths=' + str(lock) + '\nExecStart=/usr/bin/python3 ' + str(script) + '\n'
            try:
                (unit_dir / (name + '.socket')).write_text(socket_text)
                (unit_dir / (name + '.service')).write_text(service_text)
                subprocess.run(['systemctl', 'daemon-reload'], check=True, capture_output=True)
                fixed = subprocess.run(['systemctl', 'start', name + '.service'], capture_output=True, text=True, timeout=15)
                self.assertEqual(fixed.returncode, 0, fixed.stderr)
                self.assertEqual(lock.read_text(), 'controller-started')
                inode = lock.stat().st_ino
                subprocess.run(['systemd-tmpfiles', '--create', str(config)], check=True, capture_output=True)
                self.assertEqual(lock.stat().st_ino, inode)
                self.assertEqual(lock.read_text(), 'controller-started')
            finally:
                subprocess.run(['systemctl', 'stop', name + '.service', name + '.socket'], capture_output=True)
                subprocess.run(['systemctl', 'reset-failed', name + '.service', name + '.socket'], capture_output=True)
                (unit_dir / (name + '.service')).unlink(missing_ok=True)
                (unit_dir / (name + '.socket')).unlink(missing_ok=True)
                subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)

    def test_production_units_are_valid_and_management_is_boot_enabled(self):
        units = web.unit_files() | watchdog.unit_files() | harden.unit_files()
        self.assertIn('WantedBy=multi-user.target', units['vpn-management.service'])
        self.assertIn('WantedBy=multi-user.target', units['vpn-downloads.service'])
        self.assertNotIn('Requires=vpn-control.service', units['vpn-downloads.service'])
        self.assertIn('AF_NETLINK', units['vpn-control.service'])
        self.assertNotIn('AF_NETLINK', units['vpn-downloads.service'])
        self.assertIn('User=vpn-admin', units['vpn-management.service'])
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name, text in units.items():
                (root / name).write_text(text.replace(str(web.VENV / 'bin/python3'), '/usr/bin/python3'))
            (root / 'vpn-firewall.service').write_text('[Service]\nType=oneshot\nExecStart=/bin/true\n')
            result = subprocess.run(['systemd-analyze', 'verify'] + [str(p) for p in root.iterdir()], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_socket_activation_privilege_separation_and_expiry_keep_downloads_running(self):
        try:
            import waitress
        except ImportError:
            self.skipTest('Waitress testing dependency required')
        name = 'vpnstack-it-' + uuid.uuid4().hex[:8]
        directory = Path(tempfile.mkdtemp(prefix=name + '-'))
        directory.chmod(0o755)
        code = directory / 'code'
        code.mkdir(mode=0o755)
        for path in (ROOT / 'src').glob('*.py'):
            shutil.copyfile(path, code / path.name)
            (code / path.name).chmod(0o644)
        shutil.copytree(Path(waitress.__file__).parent, code / 'waitress')
        for path in (code / 'waitress').rglob('*'):
            path.chmod(0o755 if path.is_dir() else 0o644)
        private = directory / 'private'
        private.mkdir(mode=0o700)
        (private / 'state.json').write_text(json.dumps({'installed': True, 'clients': {}, 'lan': '127.0.0.1', 'lan_net': '127.0.0.0/8', 'public': '8.8.8.8', 'endpoint': 'localhost'}))
        public = directory / 'public/certs'
        public.mkdir(parents=True, mode=0o755)
        (public / 'ca.pem').write_text('PUBLIC CERTIFICATE')
        sock = directory / 'control.sock'
        ports = []
        for _ in range(2):
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                ports.append(probe.getsockname()[1])
        script = directory / 'start.py'
        script.write_text('''import json,os,sys
from pathlib import Path
sys.path.insert(0,''' + repr(str(code)) + ''')
import manage as m
import vpn_web as w
m.BASE=Path(''' + repr(str(private)) + ''');m.STATE=m.BASE/'state.json'
w.SOCKET=Path(''' + repr(str(sock)) + ''');w.ACCOUNT='nobody';w.ADMIN_ACCOUNT='daemon';w.RPC_GROUP='nogroup'
config={'lan':'127.0.0.1','lan_net':'127.0.0.0/8','public':'8.8.8.8','endpoint':'localhost'}
if sys.argv[1]=='control':
 w.control_serve(m.clients_backend())
else:
 from waitress import serve
 role=sys.argv[1]
 application=w.Application(config,role,rpc_call=lambda value:w.rpc(value,path=w.SOCKET),public=Path(''' + repr(str(public.parent)) + '''))
 serve(application,host='127.0.0.1',port=int(sys.argv[2]),threads=2,connection_limit=16,channel_timeout=2)
''')
        script.chmod(0o644)
        unit_dir = Path('/run/systemd/system')
        unit_names = [name + '.socket', name + '.service', name + '-downloads.service', name + '-management.service', name + '-expire.service', name + '-expire.timer']
        env = 'Environment=PYTHONPATH=' + str(code) + '\n' + harden.common_sandbox() + harden.service_limits()
        units = {
            name + '.socket': f'[Socket]\nListenStream={sock}\nSocketMode=0666\n',
            name + '.service': f'[Unit]\nRequires={name}.socket\nAfter={name}.socket\n[Service]\nType=notify\nNotifyAccess=main\nExecStartPre=/bin/sleep 0.5\nExecStart=/usr/bin/python3 {script} control\n' + env,
        }
        for role, user, port in [('downloads', 'nobody', ports[0]), ('management', 'daemon', ports[1])]:
            units[name + '-' + role + '.service'] = f'[Unit]\nRequires={name}.service\nAfter={name}.service\n[Service]\nUser={user}\nGroup=nogroup\nNoNewPrivileges=yes\nProtectHome=yes\nProtectSystem=strict\nExecStart=/usr/bin/python3 {script} {role} {port}\n' + env + 'CapabilityBoundingSet=\nAmbientCapabilities=\nMemoryDenyWriteExecute=yes\nSystemCallFilter=@system-service\nProtectProc=invisible\nProcSubset=pid\n'
        units[name + '-expire.service'] = f'[Service]\nType=oneshot\nExecStart=/usr/bin/systemctl stop {name}-management.service\n'
        units[name + '-expire.timer'] = f'[Timer]\nOnActiveSec=2s\nAccuracySec=100ms\nUnit={name}-expire.service\n'
        def command(*args, check=True):
            result = subprocess.run(['systemctl', *args], capture_output=True, text=True, timeout=30)
            if check and result.returncode:
                logs = subprocess.run(['journalctl', '-u', name + '.service', '--no-pager', '-n', '15'], capture_output=True, text=True).stdout
                self.fail(result.stderr + logs)
            return result
        def request(port, path, hostport):
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
            connection.request('GET', path, headers={'Host': '127.0.0.1:' + str(hostport)})
            response = connection.getresponse()
            result = response.status, response.read()
            connection.close()
            return result
        try:
            for filename, text in units.items():
                (unit_dir / filename).write_text(text)
            command('daemon-reload')
            # socket activation must survive connecting before delayed broker startup.
            command('start', name + '.socket')
            self.assertTrue(web.rpc({'op': 'ping'}, path=sock, timeout=10)['ready'])
            check = subprocess.run(['runuser', '-u', 'nobody', '--', '/usr/bin/python3', '-c',
                'import sys;sys.path.insert(0,' + repr(str(code)) + ');import vpn_web as w;from pathlib import Path;w.rpc({"op":"open"},path=Path(' + repr(str(sock)) + '))'], capture_output=True, text=True)
            self.assertNotEqual(check.returncode, 0)
            self.assertIn('not authorized', check.stderr)

            command('start', name + '-downloads.service', name + '-management.service')
            for _ in range(40):
                try:
                    result = request(ports[0], '/cert/ca.pem', 9000)
                    break
                except ConnectionError:
                    time.sleep(.1)
            self.assertEqual(result, (200, b'PUBLIC CERTIFICATE'))
            self.assertEqual(request(ports[0], '/manage', 9000)[0], 404)
            for _ in range(40):
                try:
                    self.assertEqual(request(ports[1], '/manage', 9001)[0], 200)
                    break
                except ConnectionError:
                    time.sleep(.1)
            command('start', name + '-expire.timer')
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and command('is-active', '--quiet', name + '-management.service', check=False).returncode == 0:
                time.sleep(.1)
            self.assertNotEqual(command('is-active', '--quiet', name + '-management.service', check=False).returncode, 0)
            with socket.socket() as probe:
                self.assertNotEqual(probe.connect_ex(('127.0.0.1', ports[1])), 0)
            self.assertEqual(request(ports[0], '/cert/ca.pem', 9000)[0], 200)
        finally:
            command('stop', *unit_names, check=False)
            command('reset-failed', *unit_names, check=False)
            for filename in unit_names:
                (unit_dir / filename).unlink(missing_ok=True)
            command('daemon-reload', check=False)
            shutil.rmtree(directory)
