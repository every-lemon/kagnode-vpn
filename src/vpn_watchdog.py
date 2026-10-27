"""Bounded local health checks and persistent, rate-limited systemd recovery."""
import contextlib
import fcntl
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import struct
import subprocess
import time

DEFAULTS = {'paused': False, 'auto_reboot': True, 'failure_seconds': 180,
            'max_reboots': 2, 'cooldown_seconds': 1800}
SERVICES = {'backend': 'vpn-control.service', 'dns': 'AdGuardHome.service',
            'wireguard': 'wg-quick@wg0.service', 'ipsec': 'ipsec.service', 'l2tp': 'xl2tpd.service',
            'downloads': 'vpn-downloads.service', 'management': 'vpn-management.service'}
CORE = frozenset(('backend', 'dns', 'wireguard', 'ipsec', 'l2tp'))


def command(args, timeout=3):
    return subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=timeout, check=False)


def read_json(path, default):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default


def prune_reports(directory):
    reports = sorted(directory.glob('*-failure-*.txt'), key=lambda p: p.stat().st_mtime, reverse=True)
    total = 0
    count = 0
    for path in reports:
        if path.name.endswith('-latest.txt'):
            continue
        count += 1
        total += path.stat().st_size
        if count > 20 or total > 10 * 1024 * 1024:
            path.unlink(missing_ok=True)


def decision(state, failures, now, mono, boot, config):
    """Pure recovery state machine. Persist its returned state before executing actions."""
    state = json.loads(json.dumps(state))
    if state.get('boot') != boot:
        state.update(boot=boot, components={})
    backwards = now < state.get('last_wall', now)
    state['last_wall'] = max(now, state.get('last_wall', now))
    if backwards:
        state['clock_unsafe'] = True
    history = [stamp for stamp in state.get('reboots', []) if now - stamp < 86400]
    state['reboots'] = history
    actions = []
    components = state.setdefault('components', {})
    for name in list(components):
        if name not in failures:
            del components[name]
    for name in sorted(failures):
        item = components.setdefault(name, {'since': mono, 'count': 0, 'restarts': []})
        item['count'] += 1
        item['detail'] = failures[name]
        item['restarts'] = [stamp for stamp in item['restarts'] if mono - stamp < 600]
        if not actions and item['count'] >= 2 and len(item['restarts']) < 2 and (not item['restarts'] or mono - item['restarts'][-1] >= 30):
            item['restarts'].append(mono)
            actions.append(('restart', name))
    critical = [name for name in failures if name in CORE and len(components[name]['restarts']) >= 2 and mono - components[name]['since'] >= config['failure_seconds']]
    if (critical and config['auto_reboot'] and not state.get('clock_unsafe')
            and len(history) < config['max_reboots']
            and (not history or now - max(history) >= config['cooldown_seconds'])):
        state['reboots'].append(now)
        actions = [('reboot', ','.join(sorted(critical)))]
    return state, actions


def dns_probe(address, tcp, port=53):
    ident = secrets.token_bytes(2)
    packet = ident + struct.pack('!HHHHH', 0x0100, 1, 0, 0, 0) + b'\x09localhost\x00\x00\x01\x00\x01'
    def receive(stream, size):
        data = b''
        while len(data) < size:
            more = stream.recv(size - len(data))
            if not more:
                raise OSError('DNS response truncated')
            data += more
        return data
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as stream:
        stream.settimeout(1)
        stream.connect((address, port))
        if tcp:
            stream.sendall(struct.pack('!H', len(packet)) + packet)
            length = struct.unpack('!H', receive(stream, 2))[0]
            reply = receive(stream, min(length, 4096))
        else:
            stream.send(packet)
            reply = stream.recv(4096)
    # Any valid DNS response proves local responsiveness, including upstream SERVFAIL.
    if len(reply) < 12 or reply[:2] != ident or not reply[2] & 0x80:
        raise OSError('DNS did not return a valid local response')


def http_probe(address, port):
    connection = http.client.HTTPConnection(address, port, timeout=2)
    try:
        connection.request('GET', '/health', headers={'Host': address + ':' + str(port)})
        response = connection.getresponse()
        if response.status != 200 or response.read(16) != b'OK\n':
            raise OSError('HTTP health check failed')
    finally:
        connection.close()


class Watchdog:
    def __init__(self, manager, run=command, clock=time.time, monotonic=time.monotonic, boot=None, uptime=None):
        self.m, self.base, self.run = manager, manager.BASE, run
        self.clock, self.monotonic = clock, monotonic
        self.boot = boot or Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.uptime = uptime or (lambda: float(Path('/proc/uptime').read_text().split()[0]))
        self.path = self.base / 'watchdog-state.json'
        self.config_path = self.base / 'watchdog.json'

    def config(self):
        values = DEFAULTS | read_json(self.config_path, {})
        if any(type(values[k]) is not bool for k in ('paused', 'auto_reboot')):
            raise ValueError('Invalid watchdog boolean configuration')
        for key, minimum, maximum in (('failure_seconds', 90, 1800), ('max_reboots', 1, 3), ('cooldown_seconds', 900, 86400)):
            if type(values[key]) is not int or not minimum <= values[key] <= maximum:
                raise ValueError('Invalid watchdog limit: ' + key)
        return values

    def configure(self, key, value):
        config = self.config()
        config[key] = value
        self.m.atomic(self.config_path, json.dumps(config, indent=2))
        self.config()  # CLI only supplies fixed, validated choices.

    def maintenance(self):
        with (self.base / 'maintenance.lock').open('a') as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
        return False

    def probes(self):
        state = self.m.load()
        failures = {}
        checks = {}
        enabled = dict(SERVICES)
        if not (self.base / 'web-enabled').exists():
            enabled.pop('downloads')
        for name, unit in enabled.items():
            try:
                if self.run(['systemctl', 'is-active', '--quiet', unit]).returncode:
                    raise OSError('systemd service inactive')
                if name == 'dns':
                    dns_probe(state['lan'], False)
                    dns_probe(state['lan'], True)
                elif name == 'backend':
                    import vpn_web
                    if not vpn_web.rpc({'op': 'ping'}, timeout=2).get('ready'):
                        raise OSError('RPC not ready')
                    heartbeat = read_json(self.base / 'backend-health.json', {})
                    if heartbeat.get('boot') != self.boot or not 0 <= self.monotonic() - heartbeat.get('monotonic', -1e9) < 120:
                        raise OSError('policy reconciliation heartbeat stale')
                    job = read_json(self.base / 'backend-job-health.json', {})
                    if job.get('running') and job.get('boot') == self.boot and self.monotonic() - job.get('monotonic', 0) > 600:
                        raise OSError('job progress stale for more than ten minutes')
                elif name == 'wireguard':
                    interface = self.run(['wg', 'show', 'wg0', 'listen-port'])
                    if interface.returncode or interface.stdout.strip() != '51820':
                        raise OSError('WireGuard interface or expected port unavailable')
                elif name == 'ipsec':
                    if self.run(['ipsec', 'status']).returncode:
                        raise OSError('IPsec control unresponsive')
                elif name == 'l2tp':
                    result = self.run(['ss', '-H', '-lun', 'sport = :1701'])
                    if result.returncode or not result.stdout.strip():
                        raise OSError('L2TP socket unavailable')
                elif name in ('downloads', 'management'):
                    http_probe(state['lan'], 9000 if name == 'downloads' else 9001)
                checks[name] = failures.get(name, 'healthy')
            except Exception as exc:
                # No raw subprocess output, request bodies, or credentials.
                failures[name] = type(exc).__name__ + ': ' + str(exc)[:200]
                checks[name] = failures[name]
        return failures, checks

    def report(self, reason):
        text = ['VPN watchdog recovery: ' + reason, time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())]
        commands = [
            ['systemctl', 'show', *SERVICES.values(), '-p', 'Id', '-p', 'ActiveState', '-p', 'Result', '-p', 'ExecMainStatus'],
            ['journalctl', *[arg for unit in SERVICES.values() for arg in ('-u', unit)], '--since', '10 minutes ago', '-n', '100', '--no-pager'],
            ['ss', '-lntup'], ['iptables', '-w', '3', '-nvL', 'VPNSTACK-IN'],
        ]
        for args in commands:
            try:
                result = self.run(args)
                text.extend(['$ ' + ' '.join(args), (result.stdout + result.stderr)[:48000]])
            except Exception as exc:
                text.append('Diagnostic unavailable: ' + str(exc))
        for path in ('/proc/loadavg', '/proc/meminfo', '/proc/pressure/cpu', '/proc/pressure/memory', '/proc/pressure/io'):
            try:
                text.extend([path, Path(path).read_text()[:12000]])
            except OSError:
                pass
        directory = self.base / 'logs'
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        content = '\n'.join(text) + '\n'
        self.m.atomic(directory / 'watchdog-failure-latest.txt', content)
        self.m.atomic(directory / ('watchdog-failure-' + str(int(self.clock())) + '-' + secrets.token_hex(3) + '.txt'), content)
        prune_reports(directory)

    def tick(self):
        self.base.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (self.base / 'watchdog.lock').open('a') as lock, (self.base / 'maintenance.lock').open('a') as maintenance:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {'status': 'already running'}
            config = self.config()
            previous = read_json(self.path, {})
            now, mono = self.clock(), self.monotonic()
            try:
                fcntl.flock(maintenance, fcntl.LOCK_EX | fcntl.LOCK_NB)
                updating = False
            except BlockingIOError:
                updating = True
            reason = ('paused' if config['paused'] else 'maintenance' if updating
                      else 'boot grace' if self.uptime() < 180 else None)
            if reason:
                previous.update(status=reason, components={}, checked=now)
                self.m.atomic(self.path, json.dumps(previous))
                print('Watchdog: ' + reason)
                return previous
            failures, checks = self.probes()
            updated, actions = decision(previous, failures, now, mono, self.boot, config)
            updated.update(checked=now, checks=checks, status='degraded' if failures else 'healthy')
            # Reboot budget and attempted recovery are durable before any side effect.
            self.m.atomic(self.path, json.dumps(updated))
            for action, target in actions:
                try:
                    self.report(action + ': ' + target)
                except Exception as exc:
                    print('Watchdog diagnostic failure: ' + str(exc))
                outcome = 'requested'
                try:
                    if action == 'reboot':
                        from vpn_maintenance import Coordinator
                        Coordinator(self.m).reboot('watchdog: '+target,'watchdog',held=True)
                        result = subprocess.CompletedProcess([],0)
                    else:
                        from vpn_maintenance import Coordinator
                        with Coordinator(self.m).exclusive(held=True):
                            if target == 'backend':
                                result = self.run(['systemctl', 'restart', 'vpn-control.socket', SERVICES[target]], timeout=20)
                                if result.returncode == 0:
                                    web_failures, web_checks = self.probes()
                                    workers = [SERVICES[name] for name in ('downloads', 'management') if name in web_checks and web_checks[name] not in ('closed', 'unavailable')]
                                    if workers:
                                        result = self.run(['systemctl', 'restart', *workers], timeout=20)
                            else:
                                result = self.run(['systemctl', 'restart', SERVICES[target]], timeout=20)
                    outcome = 'exit=' + str(result.returncode)
                    if action=='restart' and result.returncode and target in ('backend','dns'):
                        self.run(['systemctl','start','--no-block','vpn-repair.service'],timeout=10)
                    # Record actual post-action probes without advancing recovery counters.
                    post_failures, post_checks = self.probes() if action != 'reboot' else ({}, {})
                    updated['post_checks'] = post_checks
                except Exception as exc:
                    outcome = type(exc).__name__ + ': ' + str(exc)[:200]
                updated.setdefault('history', []).append({'time': now, 'action': action, 'target': target, 'outcome': outcome})
                updated['history'] = updated['history'][-100:]
                self.m.atomic(self.path, json.dumps(updated))
                print('Watchdog ' + action + ' ' + target + ': ' + outcome)
            return updated


def unit_files():
    from vpn_repair import repair_unit
    return {'vpn-repair.service':repair_unit(), 'vpn-watchdog.service': '''[Unit]
Description=VPN local health and recovery watchdog
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/lib/vpn/manage.py watchdog-tick
TimeoutStartSec=180
UMask=0077
Nice=10
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/vpn /var/log/vpn /run -/var/lib/dpkg/lock-frontend -/var/lib/dpkg/lock -/var/lib/apt/lists/lock -/var/cache/apt/archives/lock
''', 'vpn-watchdog.timer': '''[Unit]
Description=Check VPN local health every 30 seconds
[Timer]
OnBootSec=3min
OnUnitInactiveSec=30s
AccuracySec=1s
Unit=vpn-watchdog.service
[Install]
WantedBy=timers.target
'''}


def install(manager):
    monitor = Watchdog(manager)
    if not monitor.config_path.exists():
        manager.atomic(monitor.config_path, json.dumps(DEFAULTS, indent=2))
    deadline = time.monotonic() + 10
    while True:
        failures, _ = monitor.probes()
        if not failures:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError('Watchdog not enabled: local health checks failed: ' + ', '.join(sorted(failures)))
        time.sleep(.5)
    for name, content in unit_files().items():
        manager.atomic(Path('/etc/systemd/system') / name, content, 0o644)
    manager.command(['systemctl', 'daemon-reload'])
    manager.command(['systemctl', 'enable', '--now', 'vpn-watchdog.timer'])


def status(manager):
    monitor = Watchdog(manager)
    return json.dumps({'config': monitor.config(), 'state': read_json(monitor.path, {})}, indent=2)
