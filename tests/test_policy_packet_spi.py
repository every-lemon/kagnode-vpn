"""Exercise authenticated SPI rules with actual ESP packets, away from host networking."""
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ('unshare', 'nsenter', 'ip', 'iptables', 'iptables-save')


def _packet_test(parent_namespace):
    # All links, addresses, SAs and firewall rules below live in this fresh netns.
    assert os.readlink('/proc/self/ns/net') != parent_namespace
    sys.path.insert(0, str(ROOT / 'src'))
    import manage as manager
    import vpn_policy as policy

    def command(arguments, sender=False):
        if sender:
            arguments = ['nsenter', '--target', str(peer.pid), '--net', *arguments]
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=5)
        assert result.returncode == 0, (arguments, result.stdout, result.stderr)
        return result.stdout

    # No named namespaces or mounts: moving one veth into a child netns leaves
    # no host-side /run/netns entries, and both namespaces disappear on exit.
    peer = subprocess.Popen(
        ['unshare', '--net', sys.executable, '-u', '-c',
         "print('ready', flush=True); import sys; sys.stdin.read()"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert peer.stdout.readline().strip() == 'ready', peer.stderr.read()
        command(['ip', 'link', 'add', 'spi-server', 'type', 'veth', 'peer', 'name', 'spi-client'])
        command(['ip', 'link', 'set', 'spi-client', 'netns', str(peer.pid)])
        for sender, interface, outer, inner in (
                (False, 'spi-server', '192.0.2.1', '10.88.0.1'),
                (True, 'spi-client', '192.0.2.2', '10.77.0.2')):
            command(['ip', 'link', 'set', 'lo', 'up'], sender)
            command(['ip', 'addr', 'add', outer + '/24', 'dev', interface], sender)
            command(['ip', 'addr', 'add', inner + '/32', 'dev', 'lo'], sender)
            command(['ip', 'link', 'set', interface, 'up'], sender)
        command(['ip', 'route', 'add', '10.88.0.1/32', 'via', '192.0.2.1'], True)
        command(['ip', 'route', 'add', '10.77.0.2/32', 'via', '192.0.2.2'])

        first_spi, next_spi, reqid = 0x12345678, 0x89abcdef, 42
        selector = ['src', '10.77.0.2/32', 'dst', '10.88.0.1/32']
        template = ['src', '192.0.2.2', 'dst', '192.0.2.1', 'proto', 'esp',
                    'reqid', str(reqid), 'mode', 'tunnel']

        def add_sa(spi):
            for sender in (False, True):
                command(['ip', 'xfrm', 'state', 'add', *template[:6], 'spi', hex(spi),
                         *template[6:], 'auth-trunc', 'hmac(sha256)', '0x' + '11' * 32,
                         '128', 'enc', 'cbc(aes)', '0x' + '22' * 16], sender)

        def send_policy(spi, operation='update'):
            command(['ip', 'xfrm', 'policy', operation, *selector, 'dir', 'out',
                     'tmpl', *template[:6], 'spi', hex(spi), *template[6:]], True)

        add_sa(first_spi)
        send_policy(first_spi, 'add')
        command(['ip', 'xfrm', 'policy', 'add', *selector, 'dir', 'in', 'tmpl', *template])

        with tempfile.TemporaryDirectory() as temporary:
            manager.BASE = Path(temporary)
            manager.STATE = manager.BASE / 'state.json'
            manager.ETC = manager.BASE / 'etc'
            manager.save(dict(installed=True, clients={}, lan='192.0.2.1',
                              lan_net='192.0.2.0/24', public='198.51.100.1',
                              wg_net='10.66.0.0/24', ike_net='10.77.0.0/24',
                              l2tp_net='10.99.0.0/24'))
            backend = manager.clients_backend()
            backend.migrate()
            user = backend.user_add('Packet test')
            device = backend.device_add(user, 'ESP receiver')
            registry = backend.load()
            registry['devices'][device]['protocols']['ikev2'] = {'backend': device, 'status': 'active'}
            backend.save(registry)

            def event(spi, up=True):
                policy.event(backend, dict(protocol='ikev2', identity=device,
                                          address='10.77.0.2', reqid=reqid, spi=hex(spi), up=up))

            def grant():
                rows = policy.grants(backend, identities=True)
                assert len(rows) == 1 and rows[0][0] == device, rows
                return rows[0][1]

            def replace(match, name, value):
                result = list(match)
                result[result.index(name) + 1] = value
                return result

            event(first_spi)
            match = grant()
            assert match[match.index('--spi') + 1] == policy.policy_spi(first_spi)
            assert (reqid, first_spi) in policy.kernel_sessions(backend)
            with backend.repo.connect() as database:
                stored = json.loads(database.execute('SELECT data FROM policy_sessions').fetchone()[0])
            assert stored['spi'] == first_spi and stored['reqid'] == reqid

            # Real iptables-save changes addresses/protocol formatting. Its read
            # model must skip an unchanged reconcile, yet repair external damage.
            manager.atomic(manager.BASE / 'policy-installed', 'yes\n')
            policy.apply(backend)
            original_command, writes = backend.m.command, []

            def tracked(arguments, **kwargs):
                if arguments[0] == 'iptables-restore':
                    writes.append(arguments)
                return original_command(arguments, **kwargs)

            backend.m.command = tracked
            try:
                policy.apply(backend, skip_unchanged=True)
                assert not writes, writes
                command(['iptables', '-F', 'VPNSTACK-LAN-IN'])
                policy.apply(backend, skip_unchanged=True)
                assert len(writes) == 1, writes
            finally:
                backend.m.command = original_command

            chain = 'VPN-SPI-PACKET'
            command(['iptables', '-N', chain])
            command(['iptables', '-I', 'INPUT', '1', '-s', '10.77.0.2', '-d', '10.88.0.1',
                     '-p', 'udp', '--dport', '45001', '-j', chain])

            def rules(current, raw_spi, target='ACCEPT'):
                command(['iptables', '-F', chain])
                # Counter-only negative rules leave the packet to the real grant.
                for label, negative in (
                        ('canonical-spi', replace(current, '--spi', hex(raw_spi))),
                        ('wrong-reqid', replace(current, '--reqid', str(reqid + 1))),
                        ('wrong-spi', replace(current, '--spi', policy.policy_spi(raw_spi + 1)))):
                    command(['iptables', '-A', chain, *negative, '-m', 'comment', '--comment', label])
                command(['iptables', '-A', chain, *current, '-m', 'comment', '--comment',
                         'authenticated', '-j', target])
                command(['iptables', '-A', chain, '-m', 'comment', '--comment', 'untrusted', '-j', 'DROP'])

            def counters():
                saved = command(['iptables-save', '-c', '-t', 'filter'])
                values = {}
                for line in saved.splitlines():
                    if '-A ' + chain + ' ' in line:
                        count = re.match(r'\[(\d+):\d+\]', line)
                        label = re.search(r'--comment "?([A-Za-z-]+)"?', line)
                        assert count and label, line
                        values[label[1]] = int(count[1])
                return values

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
                receiver.bind(('10.88.0.1', 45001))
                receiver.settimeout(.4)

                def packet(label, delivered):
                    sender = ("import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                              "s.bind(('10.77.0.2',0)); s.sendto(sys.argv[1].encode(),('10.88.0.1',45001))")
                    command([sys.executable, '-c', sender, label], True)
                    try:
                        received = receiver.recv(256)
                    except socket.timeout:
                        received = None
                    assert received == (label.encode() if delivered else None), (label, received, counters())

                rules(match, first_spi)
                packet('encrypted-first', True)
                counts = counters()
                assert counts['authenticated'] == 1 and counts['wrong-reqid'] == counts['wrong-spi'] == 0, counts
                assert counts['canonical-spi'] == (0 if sys.byteorder == 'little' else 1), counts

                # Same inner source in plaintext must not match the SA-bound rule.
                command(['ip', 'xfrm', 'policy', 'delete', *selector, 'dir', 'out'], True)
                packet('plaintext', False)
                assert counters()['untrusted'] == 1, counters()
                send_policy(first_spi, 'add')

                # A new real ESP SA cannot use the old grant, despite a shared reqid/address.
                add_sa(next_spi)
                send_policy(next_spi)
                packet('rekey-before-hook', False)
                event(next_spi)
                event(first_spi, False)
                renewed = grant()
                rules(renewed, next_spi)
                packet('rekey-after-hook', True)
                assert counters()['authenticated'] == 1, counters()
                assert (reqid, next_spi) in policy.kernel_sessions(backend)
                send_policy(first_spi)
                packet('retired-spi', False)
                send_policy(next_spi)

                registry = backend.load()
                registry['devices'][device]['protocols']['ikev2']['status'] = 'revoked'
                backend.save(registry)
                assert not policy.grants(backend, identities=True)
                revoked = policy.revoked_matches(backend)
                assert revoked == [renewed], revoked
                rules(revoked[0], next_spi, 'DROP')
                packet('revoked-spi', False)
                assert counters()['authenticated'] == 1 and counters()['untrusted'] == 0, counters()
            print('Real ESP packets verified: SPI byte order, reqid, plaintext rejection, rekey and revocation')
    finally:
        peer.kill()
        peer.communicate(timeout=5)


@unittest.skipUnless(os.geteuid() == 0 and all(shutil.which(tool) for tool in TOOLS),
                     'requires root, network namespaces, iproute2 and iptables')
class PacketPolicyTests(unittest.TestCase):
    def test_encrypted_packets_match_authenticated_spi(self):
        available = subprocess.run(['unshare', '--net', 'true'], capture_output=True, timeout=5)
        if available.returncode:
            self.skipTest('network namespaces unavailable')
        result = subprocess.run(
            ['unshare', '--net', sys.executable, str(Path(__file__).resolve()), '--isolated',
             os.readlink('/proc/self/ns/net')], capture_output=True, text=True, timeout=40)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--isolated':
        _packet_test(sys.argv[2])
    else:
        unittest.main()
