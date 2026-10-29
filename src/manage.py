#!/usr/bin/env python3
"""VPN private runtime. Standard library only; installed by setup.sh."""
import base64
import contextlib
import datetime
import fcntl
import getpass
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

# The standalone runtime carries these modules; development imports use sibling sources.
_MODULE_ARCHIVE = '@@MODULE_ARCHIVE@@'
_MODULE_NAMES = ('vpn_clients', 'vpn_web', 'vpn_ui', 'vpn_backend', 'vpn_policy', 'vpn_dependencies', 'vpn_watchdog', 'vpn_admin', 'vpn_harden', 'vpn_portal', 'vpn_auth', 'vpn_version', 'vpn_business', 'vpn_native', 'vpn_maintenance', 'vpn_setup', 'vpn_repair', 'vpn_console', 'vpn_dashboard', 'vpn_access', 'vpn_release', 'vpn_tasks', 'vpn_diagnostics', 'vpn_brand')
def module_source(name):
    if name not in _MODULE_NAMES:
        raise ValueError('Unknown embedded module.')
    if _MODULE_ARCHIVE.startswith('@@'):
        return Path(__file__).with_name(name + '.py').read_text()
    import gzip
    return json.loads(gzip.decompress(base64.b64decode(_MODULE_ARCHIVE)))[name]

class _ModuleLoader:
    def find_spec(self, fullname, path=None, target=None):
        if fullname in _MODULE_NAMES:
            import importlib.util
            return importlib.util.spec_from_loader(fullname, self)
        return None
    def create_module(self, spec):
        return None
    def exec_module(self, module):
        exec(compile(module_source(module.__name__), '<embedded ' + module.__name__ + '>', 'exec'), module.__dict__)
sys.meta_path.insert(0, _ModuleLoader())


BASE = Path('/var/lib/vpn')
ETC = Path('/etc')
STATE = Path('/etc/vpn/state.json')
EXPORT_ROOT = BASE / 'native-exports'
RUN = Path('/run')
NAME = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,19}\Z')


def command(args, *, data=None, check=True, env=None, timeout=180):
    result = subprocess.run(args, input=data, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'{args[0]} failed: {result.stderr.strip()[:500]}')
    return result


def atomic(path, data, mode=0o600, *, durable=True):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data.encode() if isinstance(data, str) else data)
            stream.flush()
            if durable:os.fsync(stream.fileno())
        os.replace(tmp, path)
        if durable:
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def backup(path):
    path = Path(path)
    if path.exists():
        target = BASE / 'backups' / (path.as_posix().lstrip('/').replace('/', '_') + '-' +
                                     datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
        atomic(target, path.read_bytes())


def load():
    return json.loads(STATE.read_text())


def save(state):
    atomic(STATE, json.dumps(state, indent=2) + '\n')


@contextlib.contextmanager
def lock():
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (BASE / 'operation.lock').open('a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another install or profile operation is running.') from None
        yield


def random_password():
    return secrets.token_urlsafe(24)


def validate_name(value):
    if not NAME.fullmatch(value):
        raise ValueError('Use 1–20 letters, digits, _ or -; start with a letter.')
    return value


def valid_password(value):
    if not 12 <= len(value) <= 128 or any(ord(c) < 33 or ord(c) > 126 or c in '\\"\'' for c in value):
        raise ValueError('Use 12–128 printable ASCII characters, without spaces, quotes or backslashes.')
    return value


def choose_pools(routes):
    used = [ipaddress.ip_network(r['dst'], strict=False) for r in routes
            if r.get('dst', 'default') != 'default']
    selected = []
    preferred = ['10.66.66.0/24', '192.168.42.0/24', '192.168.43.0/24']
    candidates = preferred + [f'10.{a}.{b}.0/24' for a in range(200, 255) for b in range(256)]
    for candidate in candidates:
        network = ipaddress.ip_network(candidate)
        if not any(network.overlaps(other) for other in used + selected):
            selected.append(network)
        if len(selected) == 3:
            return [str(n) for n in selected]
    raise ValueError('Cannot find three unused VPN /24 networks. Resolve route conflicts first.')


def configure(lan, cidr, iface, endpoint, public):
    ipaddress.IPv4Address(lan)
    network = ipaddress.ip_network(cidr, strict=False)
    if ipaddress.ip_address(lan) not in network or not network.is_private:
        raise ValueError('Select a private LAN address and its assigned subnet.')
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', iface):
        raise ValueError('Invalid interface name.')
    try:
        endpoint_ip = ipaddress.IPv4Address(endpoint)
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}', endpoint):
            raise ValueError('Invalid public hostname or IPv4 address.') from None
    if not ipaddress.ip_address(public).is_global:
        raise ValueError('The detected public IPv4 is not globally routable.')
    endpoint_public = endpoint if 'endpoint_ip' in locals() else public
    if not ipaddress.ip_address(endpoint_public).is_global:
        raise ValueError('Public endpoint IPv4 must be globally routable.')
    pools = choose_pools(json.loads(command(['ip', '-j', '-4', 'route', 'show', 'table', 'all']).stdout))
    state = dict(version=4, lan=lan, lan_net=str(network), iface=iface, endpoint=endpoint,
                 public=endpoint_public, wg_net=pools[0], l2tp_net=pools[1], ike_net=pools[2],
                 clients={}, l2tp_user='', l2tp_password=random_password(),
                 psk=random_password(), installed=False, fresh_policy_default='block')
    save(state)


def shell_state():
    s = load()
    fields = dict(LAN_IP=s['lan'], LAN_NET=s['lan_net'], IFACE=s['iface'], ENDPOINT=s['endpoint'],
                  PUBLIC_IP=s['public'], WG_NET=s['wg_net'], L2TP_NET=s['l2tp_net'], IKE_NET=s['ike_net'],
                  L2TP_USER=s['l2tp_user'], L2TP_PASSWORD=s['l2tp_password'], PSK=s['psk'])
    for key, value in fields.items():
        print(key + '=' + shlex.quote(value))


def prepare_dns():
    """Free the resolved stub safely for AdGuard's wildcard DNS listener."""
    listeners = command(['ss', '-H', '-lntup', '( sport = :53 )']).stdout.splitlines()
    resolved = []
    for line in listeners:
        if 'AdGuardHome' in line:
            continue
        fields = line.split()
        endpoint = fields[4] if len(fields) > 4 else ''
        host, _, port = endpoint.rpartition(':')
        host = host.split('%', 1)[0]
        if 'systemd-resolve' in line and port == '53' and host in ('127.0.0.53', '127.0.0.54'):
            resolved.append(line)
        else:
            raise RuntimeError('DNS port 53 is owned by another process; it was not stopped: ' + line)
    if not resolved:
        print('DNS port 53 is available for AdGuard Home.')
        return
    upstream = RUN / 'systemd/resolve/resolv.conf'
    if not upstream.is_file():
        raise RuntimeError('resolved upstream resolv.conf is missing; no DNS settings were changed.')
    servers = re.findall(r'^nameserver\s+(\S+)', upstream.read_text(), re.M)
    lan = load()['lan']
    safe = [ip for ip in servers if not ipaddress.ip_address(ip).is_loopback and ip != lan]
    if len(safe) != len(servers) or not safe:
        raise RuntimeError('resolved needs real upstream DNS servers before its stub can be disabled; no settings changed.')
    dropin = ETC / 'systemd/resolved.conf.d/zzzz-vpn.conf'
    resolv = ETC / 'resolv.conf'
    old_dropin = dropin.read_bytes() if dropin.exists() else None
    old_link = os.readlink(resolv) if resolv.is_symlink() else None
    old_resolv = resolv.read_bytes() if resolv.exists() else None
    backup(dropin)
    backup(resolv)
    atomic(BASE / 'backups/resolv-link.json', json.dumps({'target': old_link}))
    def point_to(target):
        temporary = resolv.parent / ('.vpn-resolv-' + secrets.token_hex(6))
        try:
            temporary.symlink_to(target)
            os.replace(temporary, resolv)
        finally:
            temporary.unlink(missing_ok=True)
    try:
        # Preserve resolved and its DHCP/static upstream DNS; only free the stub socket.
        # resolved runs as systemd-resolve: its configuration directory must
        # be traversable. atomic() defaults to private directories for secrets.
        dropin.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        dropin.parent.chmod(0o755)  # repair directories left by <= 3.0.3
        atomic(dropin, '[Resolve]\nDNSStubListener=no\n', 0o644)
        point_to(upstream)
        command(['systemctl', 'restart', 'systemd-resolved'])
        remaining = []
        for attempt in range(10):
            after = command(['ss', '-H', '-lntup', '( sport = :53 )']).stdout.splitlines()
            remaining = [line for line in after if 'AdGuardHome' not in line]
            if not remaining:
                break
            if attempt < 9:
                time.sleep(0.5)
        if remaining:
            raise RuntimeError('Port 53 is still occupied after disabling the resolved stub. Remaining listeners:\n' + '\n'.join(remaining) + '\nInspect: journalctl -u systemd-resolved -n 30 --no-pager')
        command(['getent', 'ahostsv4', 'example.com'])
    except Exception:
        if old_dropin is None:
            dropin.unlink(missing_ok=True)
        else:
            atomic(dropin, old_dropin, 0o644)
        if old_link is not None:
            point_to(old_link)
        elif old_resolv is not None:
            atomic(resolv, old_resolv, 0o644)
        else:
            resolv.unlink(missing_ok=True)
        command(['systemctl', 'restart', 'systemd-resolved'], check=False)
        raise
    print('Freed DNS port 53. systemd-resolved remains running with its upstream DNS; host resolution verified.')


def socket_host(line, port):
    """Parse ss endpoints regardless of Netid columns, brackets or %interface."""
    for field in line.split():
        host, separator, number = field.rpartition(':')
        if separator and number == str(port):
            host = host.strip('[]').split('%', 1)[0]
            try:
                address = ipaddress.ip_address(host)
                if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                    return str(address.ipv4_mapped)
                return str(address)
            except ValueError:
                return host
    return None


def admin_firewall_ok(state, ipv6=False):
    """Accept wildcard administration only behind the installed LAN guard."""
    lan, network, iface = state.get('lan'), state.get('lan_net'), state.get('iface')
    if not all((lan, network, iface)):
        return False
    rules = command(['iptables', '-S', 'INPUT'], check=False)
    jumps = [line for line in rules.stdout.splitlines() if line.startswith('-A ')]
    if rules.returncode or not jumps or jumps[0] != '-A INPUT -j VPNSTACK-IN':
        return False
    for rule in (
        ['-C', 'VPNSTACK-IN', '-i', iface, '-s', network, '-d', lan, '-p', 'tcp', '--dport', '8080', '-j', 'ACCEPT'],
        ['-C', 'VPNSTACK-IN', '-p', 'tcp', '--dport', '8080', '-j', 'DROP'],
    ):
        if command(['iptables'] + rule, check=False).returncode:
            return False
    if ipv6:
        rules = command(['ip6tables', '-S', 'INPUT'], check=False)
        jumps = [line for line in rules.stdout.splitlines() if line.startswith('-A ')]
        if rules.returncode or not jumps or jumps[0] != '-A INPUT -j VPNSTACK6-IN':
            return False
        if command(['ip6tables', '-C', 'VPNSTACK6-IN', '-p', 'tcp', '-m', 'multiport',
                    '--dports', '53,3000,8080', '-j', 'DROP'], check=False).returncode:
            return False
    return True


def check_adguard():
    state = load()
    lan = state['lan']
    failures = []
    def report(label, ok, detail=''):
        print('  ' + ('PASS' if ok else 'FAIL') + ' ' + label + (': ' + detail if detail else ''))
        if not ok:
            failures.append(label)
    active = command(['systemctl', 'is-active', 'AdGuardHome'], check=False)
    report('AdGuard service', active.returncode == 0, active.stdout.strip() or active.stderr.strip())
    for tcp in (False, True):
        args = ['dig', '+time=3', '+tries=1', '+short']
        if tcp:
            args.append('+tcp')
        result = command(args + ['@' + lan, 'example.com', 'A'], check=False)
        ipv4 = False
        for answer in result.stdout.splitlines():
            try:
                ipv4 = ipv4 or isinstance(ipaddress.ip_address(answer.strip()), ipaddress.IPv4Address)
            except ValueError:
                pass
        ok = result.returncode == 0 and ipv4
        report('DNS ' + ('TCP' if tcp else 'UDP') + ' ' + lan + ':53', ok,
               '' if ok else (result.stderr.strip() or result.stdout.strip() or
                             'No IPv4 answer. Check AdGuard upstream DNS, access settings and Query Log.')[:700])
    admin = command(['ss', '-H', '-lntp', '( sport = :8080 )'], check=False)
    admin_lines = admin.stdout.splitlines()
    hosts = [socket_host(line, 8080) for line in admin_lines]
    accepted = (lan, '0.0.0.0', '*', '::')
    ok = admin.returncode == 0 and bool(hosts) and all(host in accepted for host in hosts)
    wildcard = any(host in ('0.0.0.0', '*', '::') for host in hosts)
    if ok and wildcard:
        ok = admin_firewall_ok(state, ipv6=any(host in ('*', '::') for host in hosts))
    detail = 'Wildcard listener protected by LAN-only firewall rules.' if ok and wildcard else ''
    if not ok:
        detail = ('Observed: ' + '; '.join(admin_lines) if admin_lines else
                  'Nothing is listening on port 8080. Complete the wizard and select port 8080.')
        if wildcard:
            detail += ' LAN firewall protection is missing; rerun Install VPN to restore its firewall rules.'
    report('Admin listener ' + lan + ':8080', ok, detail)
    dns = command(['ss', '-H', '-lntup', '( sport = :53 )'], check=False)
    owned = [line for line in dns.stdout.splitlines() if 'AdGuardHome' in line]
    ok = dns.returncode == 0 and bool(owned) and all(
        socket_host(line, 53) in (lan, '0.0.0.0', '*', '::') for line in owned)
    report('AdGuard DNS socket ownership/binding', ok,
           '' if ok else ('Observed: ' + (dns.stdout.strip() or dns.stderr.strip() or 'no DNS listeners')))
    if failures:
        print('  Fix the failing checks above; passing checks do not need reconfiguration.')
    return not failures


def mobileconfig(path, enabled):
    """Retain upstream certificate/UUIDs; change Apple IKEv2 on-demand only."""
    path = Path(path)
    profile = plistlib.loads(path.read_bytes())
    found = False
    for payload in profile.get('PayloadContent', []):
        if payload.get('PayloadType') != 'com.apple.vpn.managed':
            continue
        ike = payload['IKEv2']
        ike['OnDemandEnabled'] = int(enabled)
        ike['OnDemandRules'] = ([{'Action': 'Connect', 'InterfaceTypeMatch': 'WiFi'},
                                 {'Action': 'Connect', 'InterfaceTypeMatch': 'Cellular'},
                                 {'Action': 'Ignore'}] if enabled else [])
        payload['IPv4'] = {'OverridePrimary': 1}
        found = True
    if not found:
        raise ValueError('No IKEv2 VPN payload in exported Apple profile.')
    atomic(path, plistlib.dumps(profile, sort_keys=False))


def wg_profile(state, address, private, public):
    return (f'[Interface]\nPrivateKey = {private}\nAddress = {address}/32\nDNS = {state["lan"]}\n\n'
            f'[Peer]\nPublicKey = {public}\nEndpoint = {state["endpoint"]}:51820\n'
            'AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n')


def add_wg(name):
    s = load()
    path = BASE / 'clients' / 'wireguard' / (name + '.conf')
    conf = ETC / 'wireguard/wg0.conf'
    marker = f'# BEGIN_PEER {name}\n'
    text = conf.read_text()
    if path.exists() or marker in text:
        raise ValueError('WireGuard client already exists.')
    live = command(['wg', 'show', 'wg0', 'allowed-ips']).stdout
    pool = ipaddress.ip_network(s['wg_net'])
    address = next((str(pool[n]) for n in range(2, 251)
                    if f'AllowedIPs = {pool[n]}/32\n' not in text and f'{pool[n]}/32' not in live), None)
    if not address:
        raise ValueError('WireGuard client addresses exhausted.')
    private = command(['wg', 'genkey']).stdout.strip()
    pub = command(['wg', 'pubkey'], data=private + '\n').stdout.strip()
    server = (BASE / 'wg-server.pub').read_text().strip()
    block = f'\n{marker}[Peer]\nPublicKey = {pub}\nAllowedIPs = {address}/32\n# END_PEER {name}\n'
    backup(conf)
    # Durable configuration first; roll it back if the running interface rejects the peer.
    old_state = STATE.read_bytes()
    live_added = False
    try:
        atomic(path, wg_profile(s, address, private, server))
        atomic(conf, text + block)
        command(['wg', 'set', 'wg0', 'peer', pub, 'allowed-ips', address + '/32'])
        live_added = True
        s['clients'].setdefault(name, {})['wireguard'] = {'public': pub, 'address': address}
        save(s)
    except Exception:
        atomic(conf, text)
        atomic(STATE, old_state)
        path.unlink(missing_ok=True)
        if live_added:
            command(['wg', 'set', 'wg0', 'peer', pub, 'remove'], check=False)
        raise
    print('WireGuard profile:', path)


def revoke_wg(name):
    s = load()
    conf = ETC / 'wireguard/wg0.conf'
    text = conf.read_text()
    pattern = re.compile(r'\n?# BEGIN_PEER ' + re.escape(name) + r'\n.*?# END_PEER ' + re.escape(name) + r'\n', re.S)
    block = pattern.search(text)
    if not block:
        raise ValueError('Managed WireGuard client not found.')
    pub = re.search(r'^PublicKey = (.+)$', block.group(), re.M).group(1)
    address = re.search(r'^AllowedIPs = (.+)$', block.group(), re.M).group(1)
    path = BASE / 'clients/wireguard' / (name + '.conf')
    old_profile, old_state = path.read_bytes() if path.exists() else None, STATE.read_bytes()
    removed = False
    backup(conf)
    try:
        atomic(conf, pattern.sub('', text))
        s['clients'].get(name, {}).pop('wireguard', None)
        save(s)
        command(['wg', 'set', 'wg0', 'peer', pub, 'remove'])
        removed = True
        path.unlink(missing_ok=True)
    except Exception:
        atomic(conf, text)
        atomic(STATE, old_state)
        if old_profile is not None:
            atomic(path, old_profile)
        if removed:
            command(['wg', 'set', 'wg0', 'peer', pub, 'allowed-ips', address], check=False)
        raise


def pool_range(cidr):
    network = ipaddress.ip_network(cidr)
    return f'{network[10]}-{network[250]}'


def l2tp_add(name, password):
    s = load()
    valid_password(password)
    chap = ETC / 'ppp/chap-secrets'
    old = chap.read_text()
    if any(line.startswith('"' + name + '" ') for line in old.splitlines()):
        raise ValueError('L2TP username already exists.')
    backup(chap)
    old_state = STATE.read_bytes()
    export = BASE / 'clients/l2tp' / (name + '.txt')
    try:
        atomic(chap, old + f'\n"{name}" l2tpd "{password}" *\n')
        s['clients'].setdefault(name, {})['l2tp'] = {'password': password}
        save(s)
        export_l2tp(name)
    except Exception:
        atomic(chap, old)
        atomic(STATE, old_state)
        export.unlink(missing_ok=True)
        raise


def export_l2tp(name):
    s = load()
    record = s['clients'].get(name, {}).get('l2tp')
    if not record:
        raise ValueError('Managed L2TP user not found.')
    path = BASE / 'clients/l2tp' / (name + '.txt')
    atomic(path, f'Server: {s["endpoint"]}\nUsername: {name}\nPassword: {record["password"]}\nIPsec PSK: {s["psk"]}\nDNS: {s["lan"]}\n')
    print('Private L2TP connection details:', path)


def revoke_l2tp(name):
    s = load()
    if 'l2tp' not in s['clients'].get(name, {}):
        raise ValueError('Managed L2TP user not found.')
    chap = ETC / 'ppp/chap-secrets'
    export = BASE / 'clients/l2tp' / (name + '.txt')
    originals = {p: p.read_bytes() if p.exists() else None for p in (chap, STATE, export)}
    try:
        backup(chap)
        prefix='"'+name+'" '
        atomic(chap, '\n'.join(line for line in chap.read_text().splitlines() if not line.startswith(prefix)) + '\n')
        s['clients'][name].pop('l2tp')
        save(s)
        export.unlink(missing_ok=True)
    except Exception:
        for path, data in originals.items():
            if data is not None:
                atomic(path, data)
        raise
    print('Credentials revoked. Existing L2TP sessions remain active until they disconnect.')


def ports():
    s = load()
    print(f'\nROUTER PORT FORWARDS → {s["lan"]}')
    print('  UDP 500, UDP 4500, UDP 51820')
    print('  Never forward DNS 53, AdGuard 3000/8080, or UDP 1701.')
    print(f'  Reserve {s["lan"]} in DHCP or configure a stable LAN address.')
    print(f'  AdGuard admin: http://{s["lan"]}:8080   VPN endpoint: {s["endpoint"]}')
    print('  CGNAT prevents incoming IPv4 forwarding. Use DDNS if your public IP changes.')
    print('  Test from mobile data and check AdGuard Query Log.')
    print('  IPv4 full tunnel only: disable client IPv6 when full-tunnel privacy is needed.')


def rate(previous, current, elapsed):
    return max(0, current - previous) / max(elapsed, 0.001) if current >= previous else 0.0


def size(n):
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if n < 1024 or unit == 'TiB':
            return f'{n:.1f} {unit}'
        n /= 1024


def snapshot():
    rows = {}
    state = load()
    names = {v['wireguard']['public']: k for k, v in state['clients'].items() if 'wireguard' in v}
    result = command(['wg', 'show', 'wg0', 'dump'], check=False)
    for line in result.stdout.splitlines()[1:]:
        parts = line.split('\t')
        if len(parts) >= 8:
            pub, _, endpoint, _, handshake, rx, tx, _ = parts[:8]
            age = int(time.time()) - int(handshake) if int(handshake) else None
            status = f'handshake {age}s ago' if age is not None else 'no handshake'
            rows['WG ' + names.get(pub, pub[:10])] = (int(rx), int(tx), f'{endpoint} · {status}')
    for interface in Path('/sys/class/net').glob('ppp*'):
        try:
            rx = int((interface / 'statistics/rx_bytes').read_text())
            tx = int((interface / 'statistics/tx_bytes').read_text())
            rows['L2TP ' + interface.name] = (rx, tx, 'active PPP interface; username unavailable')
        except (FileNotFoundError, ValueError):
            pass
    # XFRM counters are per SA; keys include SPI so a rekey resets the rate baseline.
    result = command(['ip', '-s', 'xfrm', 'state'], check=False)
    for block in re.split(r'(?m)(?=^src )', result.stdout):
        header = re.search(r'^src (\S+) dst (\S+)', block)
        spi = re.search(r'proto esp spi (\S+)', block)
        count = re.search(r'lifetime current:\s*\n\s*(\d+)\(bytes\)', block)
        if header and spi and count:
            incoming = header[2] == state['lan']
            total = int(count[1])
            rows['IPsec SA ' + spi[1] + ' ' + ('in' if incoming else 'out')] = (
                total if incoming else 0, 0 if incoming else total,
                f'{header[1]} → {header[2]} (SA bytes; includes L2TP transport)')
    return rows


def status(live=False):
    previous = {}
    last = time.monotonic()
    try:
        while True:
            if live and sys.stdout.isatty():
                print('\033[2J\033[H', end='')
            print('VPN — LIVE STATUS' if live else 'VPN — STATUS')
            for service in ('AdGuardHome', 'wg-quick@wg0', 'ipsec', 'xl2tpd', 'vpn-firewall'):
                value = command(['systemctl', 'is-active', service], check=False).stdout.strip()
                print(f'  {service:24} {value or "unknown"}')
            now = time.monotonic()
            current = snapshot()
            print('\nServer RX / TX totals and rates; totals reset with peer/interface/SA lifetime.')
            print('WireGuard recent handshakes indicate activity, not a guaranteed online session.')
            for key, (rx, tx, info) in current.items():
                old = previous.get(key)
                rates = (f'{size(rate(old[0], rx, now-last))}/s / {size(rate(old[1], tx, now-last))}/s'
                         if old else 'sampling…')
                print(f'  {key}: {size(rx)} / {size(tx)} · {rates}\n    {info}')
            if not current:
                print('  No peers or active sessions reported.')
            if not live:
                return
            print('\nRefresh: 2s · Ctrl-C returns to menu. IPsec/PPP counters overlap; do not sum them.')
            previous, last = current, now
            time.sleep(2)
    except KeyboardInterrupt:
        print()


def manager_self():
    import types
    return sys.modules.get(__name__) or types.SimpleNamespace(**globals())

def clients_backend():
    import vpn_clients
    return vpn_clients.Backend(manager_self())

def main():
    os.umask(0o077)
    if os.geteuid() != 0:
        raise SystemExit('Run as root.')
    venv = Path('/usr/lib/vpn/venv/bin/python3')
    if venv.exists() and Path(sys.prefix) != venv.parent.parent:
        os.execv(str(venv), [str(venv)] + sys.argv)
    op, *args = sys.argv[1:] or ['console']
    if op=='system-task':
        import vpn_tasks
        vpn_tasks.execute(manager_self())
    elif op=='update':
        import vpn_release
        if any(a not in ('--prerelease','--apply') for a in args):raise ValueError('Use vpn update [--prerelease] [--apply].')
        if '--apply' in args:
            import vpn_console
            vpn_console.authenticate_owner(manager_self())
        print(json.dumps(vpn_release.fetch(manager_self(),'--prerelease' in args,'--apply' in args),indent=2))
    elif op in ('console','owner-enroll','recover-owner','ssh-choice'):
        import vpn_console
        if op=='console': vpn_console.run(manager_self())
        elif op=='owner-enroll': vpn_console.enroll_owner(manager_self())
        elif op=='recover-owner': vpn_console.recover_owner(manager_self())
        else: vpn_console.ssh_choice(manager_self())
    elif op in ('doctor','repair','repair-auto'):
        import vpn_repair
        doctor=vpn_repair.Doctor(manager_self())
        if op=='repair-auto': print(json.dumps(doctor.repair(),indent=2))
        elif op=='repair':
            import vpn_console
            vpn_console.run(manager_self(),'system')
        else:
            import vpn_diagnostics
            if args == ['--report']:
                import vpn_console
                vpn_console.authenticate_owner(manager_self())
                with lock(): vpn_diagnostics.collect(manager_self())
                print(vpn_diagnostics.support(manager_self()).decode())
            elif not args:
                with lock(): report=vpn_diagnostics.collect(manager_self())
                print(vpn_diagnostics.describe(report))
                print('\nManaged-resource inspection:\n'+json.dumps(doctor.inspect(),indent=2))
            else: raise ValueError('Usage: vpn doctor [--report]')
    elif op.startswith('maintenance-'):
        import vpn_maintenance
        if op=='maintenance-install': vpn_maintenance.install(manager_self())
        elif op=='maintenance-tick': vpn_maintenance.Coordinator(manager_self()).tick()
        elif op=='maintenance-status': print(json.dumps(vpn_maintenance.Coordinator(manager_self()).status(),indent=2))
        else: raise ValueError('Unknown maintenance operation.')
    elif op=='setup-stage':
        import vpn_setup
        vpn_setup.stage(manager_self(),args[0])
    elif op=='fresh-start':
        import vpn_setup
        if not sys.stdin.isatty(): raise ValueError('Fresh start requires a private interactive console.')
        print('This removes managed VPN clients, trust material, administrators, tokens and AdGuard settings. OS networking and binaries remain.')
        vpn_setup.fresh_start(manager_self(),input('Type RESET VPN AND ADGUARD: '))
    elif op == 'ui-choice':
        import vpn_ui
        try:
            print(vpn_ui.choose(args[0], [tuple(item.split('=', 1)) for item in args[1:]]))
        except vpn_ui.Cancel:
            print('0')
    elif op == 'ui-input':
        import vpn_ui
        try:
            print(vpn_ui.ask(args[0], args[1] if len(args) > 1 else ''))
        except vpn_ui.Cancel:
            sys.exit(130)
    elif op == 'migrate-registry':
        clients_backend().migrate()
    elif op == 'refresh-web':
        import vpn_web
        vpn_web.enable(clients_backend(), module_source('vpn_web'), open_manager=False)
    elif op.startswith('watchdog-'):
        import vpn_watchdog
        monitor = vpn_watchdog.Watchdog(manager_self())
        if op == 'watchdog-install':
            vpn_watchdog.install(manager_self())
        elif op == 'watchdog-tick':
            monitor.tick()
        elif op == 'watchdog-status':
            print(vpn_watchdog.status(manager_self()))
        elif op == 'watchdog-check':
            failures, checks = monitor.probes()
            print(json.dumps(checks, indent=2))
            if failures:
                sys.exit(1)
        elif op in ('watchdog-pause', 'watchdog-resume'):
            monitor.configure('paused', op == 'watchdog-pause')
        elif op == 'watchdog-reboots' and args in (['on'], ['off']):
            monitor.configure('auto_reboot', args == ['on'])
        else:
            raise ValueError('Unknown watchdog operation.')
    elif op.startswith('hardening-'):
        import vpn_harden
        appliance = vpn_harden.Hardening(manager_self())
        if op == 'hardening-install':
            appliance.install()
        elif op == 'hardening-queue':
            appliance.queue()
        elif op == 'hardening-cleanup':
            appliance.cleanup()
        elif op == 'hardening-status':
            print(json.dumps(appliance.status(), indent=2))
        else:
            raise ValueError('Unknown hardening operation.')
    elif op == 'web-password':
        raise ValueError('Use administrator accounts with MFA; shared passwords are unsupported.')
    elif op == 'web-expire':
        import vpn_web
        vpn_web.expire(clients_backend())
    elif op == 'web-status':
        import vpn_web
        vpn_web.diagnostics(clients_backend())
    elif op == 'policy-event':
        import vpn_policy
        vpn_policy.cli_event(clients_backend(), args)
    elif op == 'policy-apply':
        import vpn_policy
        vpn_policy.apply(clients_backend())
    elif op == 'policy-quiesce':
        import vpn_policy
        vpn_policy.quiesce(manager_self())
    elif op == 'policy-install':
        import vpn_policy
        vpn_policy.install(clients_backend())
    elif op == 'reset-clients':
        backend = clients_backend()
        with lock():
            for ident, device in backend.load()['devices'].items():
                for protocol, record in device['protocols'].items():
                    if record['status'] != 'revoked':
                        backend.revoke(ident, protocol)
        print('Client credentials revoked. Server CA, endpoint and AdGuard configuration retained.')
    elif op == 'web-control':
        import vpn_web
        vpn_web.control_serve(clients_backend())
    elif op == 'web':
        print('Management is continuously available at http://' + load()['lan'] + ':9001/manage')
    elif op == 'configure':
        configure(*args)
    elif op == 'check-adguard':
        sys.exit(0 if check_adguard() else 1)
    elif op == 'prepare-dns':
        prepare_dns()
    elif op == 'state-shell':
        shell_state()
    elif op == 'native-install':
        import vpn_native
        vpn_native.install(manager_self())
    elif op == 'bootstrap':
        raise RuntimeError('Starter clients are not created in VPN 4.')
    elif op == 'installed':
        state = load()
        state['installed'] = True
        save(state)
    elif op == 'profiles':
        import vpn_console
        vpn_console.run(manager_self())
    elif op == 'status':
        status()
    elif op == 'ports':
        ports()
    else:
        raise SystemExit('Unknown operation.')


if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print('\nLeaving VPN.')
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print('Error:', error, file=sys.stderr)
        sys.exit(1)
