"""Execute the generated firewall in its own Linux network namespace."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class FirewallTests(unittest.TestCase):
    @unittest.skipUnless(os.geteuid() == 0 and shutil.which('unshare') and shutil.which('iptables'),
                         'requires root, unshare and iptables')
    def test_rules_survive_reruns_and_restore_before_wireguard(self):
        supported = subprocess.run(['unshare', '--net', 'true'], capture_output=True)
        if supported.returncode:
            self.skipTest('network namespaces unavailable')
        source = (ROOT / 'src/installer.sh').read_text()
        function = source[source.index('write_firewall() {'):source.index('\nsetup_wireguard() {')]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            systemd = root / 'systemd'
            systemd.mkdir()
            function = function.replace('/etc/kagnode/vpn/state.json', str(root / 'state.json')).replace('/opt/kagnode/vpn/helpers/firewall.sh', str(root / 'firewall.sh')).replace('/etc/systemd/system', str(systemd)).replace('/var/lib/kagnode/vpn/ssh-disabled', str(root / 'ssh-disabled'))
            script = root / 'test.sh'
            script.write_text('''set -euo pipefail
BASE=''' + str(root) + '''
LAN_NET=192.168.0.0/24
LAN_IP=192.168.0.8
WG_NET=10.66.66.0/24
L2TP_NET=192.168.42.0/24
IKE_NET=192.168.43.0/24
IFACE=ens18
systemctl() { :; }
''' + function + '''
# Model the upstream terminal drop and an existing SSH rule.
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A FORWARD -j DROP
iptables-save > "$BASE/before.rules"
write_firewall
bash "$BASE/firewall.sh"
bash "$BASE/firewall.sh"
[ "$(iptables -S INPUT | grep -c '^-A INPUT -j VPNSTACK-IN$')" = 1 ]
[ "$(iptables -S FORWARD | grep -c '^-A FORWARD -j VPNSTACK-FWD$')" = 1 ]
[ "$(iptables -S FORWARD | awk '/^-A /{print;exit}')" = '-A FORWARD -j VPNSTACK-FWD' ]
iptables -C INPUT -p tcp --dport 22 -j ACCEPT
iptables -C FORWARD -j DROP
iptables -C VPNSTACK-FWD -s "$WG_NET" -j ACCEPT
iptables -C VPNSTACK-FWD -o wg0 -d "$WG_NET" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -C VPNSTACK-IN -s "$WG_NET" -d "$LAN_IP" -p udp --dport 53 -j ACCEPT
iptables -C VPNSTACK-IN -i "$IFACE" -s "$LAN_NET" -d "$LAN_IP" -p tcp --dport 8080 -j ACCEPT
iptables -C VPNSTACK-IN -p tcp --dport 8080 -j DROP
iptables -C VPNSTACK-IN -p udp --dport 53 -j DROP
if [ -f /proc/net/if_inet6 ]; then
  [ "$(ip6tables -S INPUT | grep -c '^-A INPUT -j VPNSTACK6-IN$')" = 1 ]
  ip6tables -C VPNSTACK6-IN -p tcp -m multiport --dports 53,3000,8080 -j DROP
fi
[ "$(iptables -t nat -S POSTROUTING | grep -c MASQUERADE)" = 3 ]
# LAN-address self-connects traverse lo; readiness must reach the listener.
ip link set lo up
ip address add "$LAN_IP/32" dev lo
python3 - <<'PROBE'
import socket
with socket.socket() as listener:
    listener.bind(('192.168.0.8', 9001))
    listener.listen()
    with socket.socket() as client:
        client.settimeout(2)
        client.connect(('192.168.0.8', 9001))
PROBE
# After authorized SSH removal, the dedicated guard survives subsequent reruns.
touch "$BASE/ssh-disabled"
bash "$BASE/firewall.sh"
iptables -C VPNSTACK-IN -p tcp --dport 22 -j DROP
if [ -f /proc/net/if_inet6 ]; then
 ip6tables -C VPNSTACK6-IN -p tcp --dport 22 -j DROP
fi
# A failure during rebuild leaves VPN traffic blocked, even for established flows.
if bash -c 'sysctl() { return 1; }; source "$1"' -- "$BASE/firewall.sh"; then exit 1; fi
iptables -C INPUT -s "$WG_NET" -j VPNSTACK-MAINT
iptables -C FORWARD -s "$WG_NET" -j VPNSTACK-MAINT
bash "$BASE/firewall.sh"
if iptables -C INPUT -s "$WG_NET" -j VPNSTACK-MAINT 2>/dev/null; then exit 1; fi
# Model boot: upstream restore first, then our ordered systemd service.
iptables-restore < "$BASE/before.rules"
bash "$BASE/firewall.sh"
iptables -C FORWARD -j VPNSTACK-FWD
iptables -C INPUT -p tcp --dport 22 -j ACCEPT
# The corrected probe interface is accepted by the kernel.
ip link add wg-stack-test type wireguard
ip link delete wg-stack-test
''')
            result = subprocess.run(['unshare', '--net', 'bash', str(script)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            unit = (systemd / 'vpn-firewall.service').read_text()
            self.assertIn('After=load-iptables-rules.service netfilter-persistent.service', unit)
            dropin = (systemd / 'wg-quick@wg0.service.d/vpn.conf').read_text()
            self.assertIn('Requires=vpn-firewall.service', dropin)


if __name__ == '__main__':
    unittest.main()
