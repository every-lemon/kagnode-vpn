"""VPN-appliance hardening and bounded package cleanup; invoked on the target only."""
import contextlib
import datetime
import fcntl
import gc
import json
import os
from pathlib import Path
import re
import subprocess
import time

RPC_WORKERS = 4
RPC_CAPACITY = 12
# Exact package allowlist. No wildcard purge and no autoremove.
CANDIDATES = ('ssh', 'openssh-server', 'openssh-sftp-server', 'openssh-client', 'ssh-import-id',
              'dropbear', 'dropbear-bin', 'packagekit', 'packagekit-tools', 'modemmanager',
              'avahi-daemon', 'cups', 'cups-daemon', 'cups-browsed', 'bluez', 'bluetooth',
              'apport', 'apport-symptoms', 'whoopsie', 'popularity-contest', 'fail2ban',
              'motd-news-config', 'landscape-common', 'snapd', 'multipath-tools')
PROTECTED = frozenset(('systemd', 'systemd-sysv', 'systemd-resolved', 'systemd-timesyncd',
    'netplan.io', 'iproute2', 'iptables', 'wireguard-tools', 'libreswan', 'xl2tpd', 'ppp',
    'python3', 'python3-minimal', 'python3-venv', 'libnss3-tools', 'openssl', 'libnss3',
    'apt', 'dpkg', 'sudo', 'bash', 'util-linux', 'ca-certificates', 'curl', 'wget',
    'cloud-init', 'lvm2', 'dmsetup', 'cryptsetup', 'ubuntu-minimal', 'ubuntu-standard'))
SYSCTL = '''# VPN: preserves forwarding, reverse-path policy, IPv6 and module loading.
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.tcp_syncookies=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.protected_fifos=2
fs.protected_regular=2
'''
JOURNAL = '''[Journal]
SystemMaxUse=64M
RuntimeMaxUse=16M
MaxRetentionSec=7day
Compress=yes
'''


def release_memory():
    gc.collect()
    try:
        import ctypes
        libc = ctypes.CDLL(None)
        trim = libc.malloc_trim
        trim.argtypes = [ctypes.c_size_t]
        trim.restype = ctypes.c_int
        trim(0)
    except (OSError, AttributeError):
        pass


def service_limits(worker=False):
    try:
        total = int(re.search(r'^MemTotal:\s+(\d+)', Path('/proc/meminfo').read_text(), re.M)[1]) // 1024
    except (OSError, TypeError):
        total = 1024
    maximum = (64 if total < 768 else 96) if worker else min(256, max(96, total // 4))
    high = maximum * 3 // 4
    return f'MemoryAccounting=yes\nMemoryHigh={high}M\nMemoryMax={maximum}M\nTasksMax={24 if worker else 64}\nLimitNOFILE={256 if worker else 1024}\n'


def common_sandbox():
    return '''ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
LimitCORE=0
Environment=MALLOC_ARENA_MAX=2 MALLOC_TRIM_THRESHOLD_=65536
'''


def run(args, timeout=120, env=None):
    return subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=timeout, env=env, check=False)


def validate_plan(output, candidates):
    removed = set(re.findall(r'^(?:Remv|Purg)\s+([^\s:]+)(?::[^\s]+)?', output, re.M))
    unexpected = removed - set(candidates)
    if unexpected or removed & PROTECTED:
        raise RuntimeError('Cleanup refused: removal would affect protected or unapproved packages: ' + ', '.join(sorted(unexpected | (removed & PROTECTED))))
    if candidates and not removed:
        raise RuntimeError('Cleanup refused: APT did not provide a recognized removal plan.')
    return sorted(removed)


def unit_files():
    return {}


class Hardening:
    def __init__(self, manager, runner=run, root=Path('/')):
        self.m, self.base, self.run, self.root = manager, manager.BASE, runner, Path(root)
        self.state_path = self.base / 'hardening.json'

    def path(self, value):
        return self.root / value.lstrip('/')

    def save(self, values):
        self.m.atomic(self.state_path, json.dumps(values, indent=2))

    def status(self):
        try:
            return json.loads(self.state_path.read_text())
        except FileNotFoundError:
            return {'status': 'not configured'}

    def install(self):
        self.m.atomic(self.path('/etc/sysctl.d/98-vpn-hardening.conf'), SYSCTL, 0o644)
        self.m.atomic(self.path('/etc/systemd/journald.conf.d/90-vpn.conf'), JOURNAL, 0o644)
        self.m.command(['sysctl', '-p', str(self.path('/etc/sysctl.d/98-vpn-hardening.conf'))])
        self.m.command(['systemctl', 'try-restart', 'systemd-journald.service'])
        for name, content in unit_files().items():
            self.m.atomic(self.path('/etc/systemd/system') / name, content, 0o644)
        self.m.command(['systemctl', 'daemon-reload'])
        choice=self.base/'ssh-choice.json'
        ssh=json.loads(choice.read_text()).get('choice','keep') if choice.exists() else 'keep'
        self.save({'status':'applied','ssh':ssh,'package_cleanup':'disabled','updated':int(time.time())})

    def queue(self):
        raise RuntimeError('Automatic package purging is disabled in VPN 4. SSH is an explicit setup choice.')

    def candidates(self):
        result = self.run(['dpkg-query', '-W', '-f=${binary:Package} ${db:Status-Status}\n'], timeout=30)
        if result.returncode:
            raise RuntimeError('Could not inventory installed packages; nothing was purged.')
        installed = {line.split()[0].split(':')[0] for line in result.stdout.splitlines() if len(line.split()) == 2 and line.split()[1] == 'installed'}
        selected = set(CANDIDATES) & installed
        skipped = {}
        if 'fail2ban' in selected:
            try:
                status = self.run(['fail2ban-client', 'status'], timeout=5)
                match = re.search(r'Jail list:\s*([^\n]*)', status.stdout)
                jails = {value.strip() for value in match[1].split(',') if value.strip()} if match else None
                if status.returncode or jails is None or jails - {'sshd', 'sshd-ddos'}:
                    selected.discard('fail2ban'); skipped['fail2ban'] = 'non-SSH jails or unavailable jail inventory'
            except Exception:
                selected.discard('fail2ban'); skipped['fail2ban'] = 'jail inventory unavailable'

        # Preserve snap workloads and active multipath storage.
        snaps = list(self.path('/var/lib/snapd/snaps').glob('*.snap'))
        if any(not re.fullmatch(r'(?:core\d*|snapd|bare)_\d+\.snap', path.name) for path in snaps):
            selected.discard('snapd'); skipped['snapd'] = 'application snaps installed'
        for path in self.path('/sys/block').glob('dm-*/dm/uuid'):
            try:
                if path.read_text().strip().startswith('mpath-'):
                    selected.discard('multipath-tools'); skipped['multipath-tools'] = 'active multipath storage'
            except OSError:
                selected.discard('multipath-tools'); skipped['multipath-tools'] = 'storage state unavailable'
        return sorted(selected), skipped

    def snapshot(self):
        report = {}
        try:
            report['memory'] = self.path('/proc/meminfo').read_text()[:6000]
        except OSError:
            pass
        try:
            result = self.run(['ps', '-eo', 'comm,rss', '--sort=-rss'], timeout=5)
            report['process_memory_kib'] = '\n'.join(result.stdout.splitlines()[:25])
        except Exception:
            pass
        return report

    def cleanup(self):
        # Old pending markers are never authorization to purge on a new release.
        raise RuntimeError('Automatic package purging is disabled in VPN 4. SSH is an explicit setup choice.')
