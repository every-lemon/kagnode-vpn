"""Package removal is exclusively simulated in these tests; host APT is never run."""
import fcntl
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from test_manager import m
import vpn_harden as h
import vpn_web as web


class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.base = self.root / 'stack'
        self.base.mkdir()
        self.commands = []
        self.calls = []
        self.installed = {'openssh-server', 'openssh-client', 'packagekit', 'python3', 'systemd', 'iptables'}
        self.collateral = {}
        self.jails = 'sshd'
        self.manager = types.SimpleNamespace(BASE=self.base, atomic=m.atomic, command=self.command)
        self.appliance = h.Hardening(self.manager, self.runner, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def command(self, args, **kwargs):
        self.commands.append(list(map(str, args)))
        return subprocess.CompletedProcess(args, 0, '', '')

    def runner(self, args, **kwargs):
        args = list(map(str, args)); self.calls.append(args)
        output = ''
        if args[0] == 'dpkg-query':
            output = ''.join(name + ' installed\n' for name in sorted(self.installed))
        elif args[0] == 'fail2ban-client':
            output = 'Jail list: ' + self.jails
        elif args[0] == 'apt-get' and 'purge' in args:
            names = args[args.index('purge') + 1:]
            removed = set(names) | {extra for name in names for extra in self.collateral.get(name, [])}
            if '-s' in args:
                output = ''.join('Purg ' + name + ' [1.0]\n' for name in sorted(removed))
            else:
                self.assertEqual(self.appliance.status()['status'], 'running')
                self.assertTrue(self.appliance.status()['planned_removal'])
                self.installed.difference_update(removed)
        return subprocess.CompletedProcess(args, 0, output, '')

    def test_plan_validator_rejects_unknown_or_protected_removals(self):
        for output in ('Remv python3 [1]\n', 'Purg linux-image-generic [1]\n', 'unrecognized output'):
            with self.assertRaises(RuntimeError):
                h.validate_plan(output, ['openssh-server'])
        self.assertEqual(h.validate_plan('Purg openssh-server:amd64 [1]\n', ['openssh-server']), ['openssh-server'])

    def test_active_snap_workloads_and_multipath_storage_are_preserved(self):
        self.installed |= {'snapd', 'multipath-tools'}
        m.atomic(self.root / 'var/lib/snapd/snaps/lxd_123.snap', 'workload')
        m.atomic(self.root / 'sys/block/dm-0/dm/uuid', 'mpath-test')
        names, skipped = self.appliance.candidates()
        self.assertNotIn('snapd', names); self.assertNotIn('multipath-tools', names)
        self.assertEqual(set(skipped), {'snapd', 'multipath-tools'})

    def test_non_ssh_fail2ban_jails_are_preserved(self):
        self.installed.add('fail2ban'); self.jails = 'sshd, ipsec'
        self.assertNotIn('fail2ban', self.appliance.candidates()[0])
        self.jails = 'sshd'
        self.assertIn('fail2ban', self.appliance.candidates()[0])

    def test_install_writes_only_fake_root_and_no_packages_are_removed(self):
        self.appliance.install()
        self.assertTrue((self.root / 'etc/sysctl.d/98-vpn-hardening.conf').exists())
        self.assertTrue((self.root / 'etc/systemd/journald.conf.d/90-vpn.conf').exists())
        self.assertFalse(any(args[0] == 'apt-get' for args in self.calls))

    def test_service_sandboxes_are_bounded_and_http_workers_have_no_capabilities(self):
        units = web.unit_files()
        for name in ('vpn-downloads.service', 'vpn-management.service'):
            text = units[name]
            self.assertIn('CapabilityBoundingSet=\n', text)
            self.assertIn('MemoryDenyWriteExecute=yes', text)
            self.assertIn('SystemCallFilter=@system-service', text)
            self.assertIn('MemoryMax=', text)
        control = units['vpn-control.service']
        self.assertIn('CAP_NET_ADMIN', control)
        self.assertNotIn('CAP_SYS_ADMIN', control)
        self.assertIn('ProtectKernelTunables=yes', control)
        self.assertNotIn('rp_filter', h.SYSCTL)
        self.assertNotIn('modules_disabled', h.SYSCTL)

    def test_old_pending_cleanup_never_authorizes_package_removal(self):
        self.appliance.save({'status':'pending','planned_removal':['openssh-server']})
        with self.assertRaisesRegex(RuntimeError,'disabled in VPN 4'): self.appliance.cleanup()
        with self.assertRaisesRegex(RuntimeError,'disabled in VPN 4'): self.appliance.queue()
        self.assertFalse(self.calls);self.assertFalse(self.commands)
        self.assertIn('openssh-server',self.installed)
        self.assertEqual(h.unit_files(),{})
