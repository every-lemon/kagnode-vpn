"""Fail-closed per-device LAN grants tied to authenticated kernel sessions."""
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import time
import threading
import contextlib


_BUDGET = threading.local()

@contextlib.contextmanager
def budget(seconds=30):
    previous = getattr(_BUDGET, 'until', None)
    _BUDGET.until = time.monotonic() + seconds
    try:
        yield
    finally:
        _BUDGET.until = previous


def command(backend, args, **kwargs):
    remaining = (getattr(_BUDGET, 'until', None) or (time.monotonic() + 10)) - time.monotonic()
    if remaining <= 0:
        raise RuntimeError('LAN policy execution deadline exceeded.')
    return backend.m.command(args, timeout=min(10, remaining), **kwargs)


def effective(registry, ident):
    device = registry['devices'][ident]
    user = registry['users'][device['user']]
    if device.get('disabled') or user.get('revoked') or user.get('disabled'):
        return False
    policy = device.get('lan_policy', 'inherit')
    return (user.get('lan_policy', 'block') if policy == 'inherit' else policy) == 'allow'


def policy_spi(spi):
    """Encode canonical ESP SPI for libxt_policy's raw network-order ABI field."""
    if type(spi) is not int or not 0 < spi < 2**32:
        raise ValueError('Invalid kernel IPsec SPI.')
    # libxt_policy stores the CLI integer directly in __be32 without htonl;
    # xt_policy compares those bytes with xfrm_state.id.spi. Convert only here:
    # hook events, stored sessions, and kernel identity checks remain canonical.
    return hex(socket.htonl(spi))


def event(backend, value):
    # Only the local root hook CLI can call this; HTTP workers cannot submit events.
    protocol = value.get('protocol')
    if protocol not in ('ikev2', 'l2tp'):
        raise ValueError('Invalid policy event.')
    address = str(ipaddress.IPv4Address(value['address']))
    state, reg = backend.m.load(), backend.load()
    pool = ipaddress.ip_network(state['ike_net'] if protocol == 'ikev2' else state['l2tp_net'])
    if ipaddress.ip_address(address) not in pool:
        raise ValueError('Session address outside protocol pool.')
    identity = value['identity']
    device = None
    for ident, row in reg['devices'].items():
        record = row['protocols'].get(protocol, {})
        native = record.get('backend')
        if native and record.get('status') == 'active' and identity in (native, '@' + native, 'O=IKEv2 VPN,CN=' + native, 'CN=' + native + ',O=IKEv2 VPN'):
            device = ident
            break
    if protocol == 'ikev2':
        reqid = int(value['reqid'])
        spi = int(str(value['spi']), 0)
        if not 0 < reqid < 2**32 or not 0 < spi < 2**32:
            raise ValueError('Missing kernel IPsec session identifier.')
        key = f'ikev2:{address}:{reqid}:{spi}'
        value.update(reqid=reqid, spi=spi)
    else:
        interface = value['interface']
        if not re.fullmatch(r'ppp[0-9]+', interface):
            raise ValueError('Invalid PPP interface.')
        key = 'l2tp:' + interface
        if value.get('up'):
            link = json.loads(command(backend, ['ip', '-j', 'link', 'show', 'dev', interface]).stdout)[0]
            address_info = json.loads(command(backend, ['ip', '-j', '-4', 'addr', 'show', 'dev', interface]).stdout)[0]
            if not any(item.get('peer', item.get('address', '')).split('/')[0] == address for item in address_info.get('addr_info', [])):
                raise ValueError('PPP kernel peer address differs from the authenticated event.')
            value['ifindex'] = int(link['ifindex'])
            pid = str(value.get('pid', ''))
            if pid.isdigit() and int(pid) > 1:
                proc = Path('/proc') / pid
                try:
                    if proc.joinpath('exe').resolve().name == 'pppd':
                        value['pid'] = int(pid)
                        value['process_start'] = proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19]
                except OSError:
                    pass
            command(backend, ['ip', 'link', 'set', 'dev', interface, 'group', str(value['ifindex'])])
    value.update(address=address, device=device, protocol=protocol, boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    with backend.repo.connect() as db:
        if value.get('up') and device:
            db.execute('INSERT OR REPLACE INTO policy_sessions VALUES (?,?,?)', (key, json.dumps(value), time.time()))
        else:
            db.execute('DELETE FROM policy_sessions WHERE key=?', (key,))
    apply(backend)


def kernel_sessions(backend):
    result = command(backend, ['ip', '-j', 'xfrm', 'state'], check=False)
    if result.returncode:
        raise RuntimeError('Cannot inspect IPsec kernel sessions; existing firewall rules were retained.')
    try:
        rows = json.loads(result.stdout)
        return {(int(row['reqid']), int(str(row['spi']), 0)) for row in rows if row.get('proto') == 'esp' and row.get('dst') in {backend.m.load()['lan'], backend.m.load().get('public')}}
    except (ValueError, KeyError, TypeError):
        # Ubuntu 24.04 iproute2 accepts -j but still emits text for XFRM state.
        active = set()
        for block in re.split(r'(?m)(?=^src )', result.stdout):
            destination = re.search(r'^src \S+ dst (\S+)', block)
            identifier = re.search(r'\bproto esp spi (0x[0-9a-fA-F]+) reqid ([0-9]+)\b', block)
            if destination and identifier and destination[1] in {backend.m.load()['lan'], backend.m.load().get('public')}:
                active.add((int(identifier[2]), int(identifier[1], 16)))
        return active


def grants(backend, override=None, identities=False):
    reg, result = backend.load(), []
    if override:
        kind, ident, policy = override
        reg['users' if kind == 'user' else 'devices'][ident]['lan_policy'] = policy
    live_peers={}
    if any(d.get('protocols',{}).get('wireguard',{}).get('status')=='active' for d in reg['devices'].values()):
        observed=command(backend,['wg','show','wg0','allowed-ips'],check=False)
        if observed.returncode==0:
            for row in observed.stdout.splitlines():
                fields=row.split()
                if len(fields)>=2:live_peers[fields[0]]=set(''.join(fields[1:]).split(','))
    for ident, device in reg['devices'].items():
        record = device['protocols'].get('wireguard', {})
        if record.get('status') == 'active' and (identities or effective(reg, ident)):
            entry = backend.m.load().get('clients', {}).get(record['backend'], {}).get('wireguard', {})
            if entry.get('address') and str(ipaddress.IPv4Address(entry['address']))+'/32' in live_peers.get(entry.get('public'),set()):
                match = ['-i', 'wg0', '-s', str(ipaddress.IPv4Address(entry['address']))]
                result.append((ident, match) if identities else match)
    active = kernel_sessions(backend)
    with backend.repo.connect() as db:
        sessions = list(db.execute('SELECT key,data,updated FROM policy_sessions'))
        for key, encoded, updated in sessions:
            row = json.loads(encoded)
            ident, protocol = row.get('device'), row['protocol']
            valid = ident in reg['devices'] and row.get('boot') == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            if protocol == 'ikev2':
                valid = valid and (row['reqid'], row['spi']) in active
                match = ['-s', row['address'], '-m', 'policy', '--dir', 'in', '--pol', 'ipsec', '--proto', 'esp', '--reqid', str(row['reqid']), '--spi', policy_spi(row['spi'])]
            else:
                info = command(backend, ['ip', '-j', 'link', 'show', 'dev', row['interface']], check=False)
                try:
                    link = json.loads(info.stdout)[0]
                    valid = valid and int(link['ifindex']) == row['ifindex'] and int(link.get('group', 0)) == row['ifindex']
                except (ValueError, KeyError, IndexError):
                    valid = False
                match = ['-i', row['interface'], '-s', row['address'], '-m', 'devgroup', '--src-group', str(row['ifindex'])]
            if not valid:
                if not identities and (time.time() - updated > 30 or row.get('boot') != Path('/proc/sys/kernel/random/boot_id').read_text().strip()):
                    db.execute('DELETE FROM policy_sessions WHERE key=?', (key,))
                continue
            record = reg['devices'][ident]['protocols'].get(protocol, {})
            if record.get('status') == 'active' and (identities or effective(reg, ident)):
                result.append((ident, match) if identities else match)
    return result


def revoked_matches(backend):
    registry, matches = backend.load(), []
    active = kernel_sessions(backend)
    with backend.repo.connect() as db:
        rows = list(db.execute('SELECT data FROM policy_sessions'))
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    for (raw,) in rows:
        row = json.loads(raw)
        record = registry['devices'].get(row.get('device'), {}).get('protocols', {}).get(row['protocol'], {})
        if record.get('status') == 'active' or row.get('boot') != boot:
            continue
        if row['protocol'] == 'ikev2' and (row['reqid'], row['spi']) in active:
            matches.append(['-s', str(ipaddress.IPv4Address(row['address'])), '-m', 'policy', '--dir', 'in', '--pol', 'ipsec', '--proto', 'esp', '--reqid', str(row['reqid']), '--spi', policy_spi(row['spi'])])
        elif row['protocol'] == 'l2tp':
            info = command(backend, ['ip', '-j', 'link', 'show', 'dev', row['interface']], check=False)
            try:
                link = json.loads(info.stdout)[0]
                if int(link['ifindex']) == row['ifindex'] and int(link.get('group', 0)) == row['ifindex']:
                    matches.append(['-i', row['interface'], '-s', str(ipaddress.IPv4Address(row['address'])), '-m', 'devgroup', '--src-group', str(row['ifindex'])])
            except (ValueError, KeyError, IndexError):
                pass
    return matches


def protected_networks(backend):
    state = backend.m.load()
    networks = {str(ipaddress.IPv4Network(state['lan_net'], strict=False))}
    networks.update(str(ipaddress.IPv4Network(n, strict=False)) for n in state.get('protected_networks', []))
    pools = [ipaddress.ip_network(state[key]) for key in ('wg_net', 'ike_net', 'l2tp_net')]
    result = command(backend, ['ip', '-j', '-4', 'route', 'show', 'scope', 'link'], check=False)
    try:
        for route in json.loads(result.stdout):
            if route.get('dst') in (None, 'default'):
                continue
            network = ipaddress.IPv4Network(route['dst'], strict=False)
            if network.is_private and not any(network.overlaps(pool) for pool in pools):
                networks.add(str(network))
    except (ValueError, TypeError):
        pass
    with backend.repo.connect() as db:
        previous = db.execute("SELECT value FROM metadata WHERE key='protected_networks'").fetchone()
        if previous:
            networks.update(json.loads(previous[0]))
        db.execute("INSERT OR REPLACE INTO metadata VALUES ('protected_networks',?)", (json.dumps(sorted(networks)),))
    return sorted(networks)


def quiesce(manager):
    """Pause managed tunnel traffic before removing its policy controller."""
    state=manager.load()
    networks=[str(ipaddress.IPv4Network(state[key],strict=True)) for key in ('wg_net','ike_net','l2tp_net')]
    manager.command(['iptables','-w','-N','VPNSTACK-MAINT'],check=False)
    if manager.command(['iptables','-w','-C','VPNSTACK-MAINT','-j','DROP'],check=False).returncode:
        manager.command(['iptables','-w','-A','VPNSTACK-MAINT','-j','DROP'])
    for network in networks:
        for chain in ('INPUT','FORWARD'):
            rule=[chain,'-s',network,'-j','VPNSTACK-MAINT']
            if manager.command(['iptables','-w','-C',*rule],check=False).returncode:
                manager.command(['iptables','-w','-I',chain,'1',*rule[1:]])
            manager.command(['iptables','-w','-C',*rule])


def apply(backend, skip_unchanged=False, override=None, commit=None, business_snapshot=None, registry_override=None):
    # Separate lock: lifecycle hooks must never contend on the long certificate/job lock.
    with (backend.base / 'policy.lock').open('a') as lock:
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError('LAN policy update is busy. Retry shortly; no new session grant was issued.')
                time.sleep(.05)
        state = backend.m.load()
        if not (backend.base / 'policy-installed').exists():
            if override or registry_override is not None or business_snapshot is not None or commit is not None:
                raise RuntimeError('LAN policy firewall is not installed. Repair the firewall before changing access.')
            return
        networks = protected_networks(backend)
        from vpn_business import Business
        business = Business(backend.repo)
        registry = registry_override or backend.load()
        snapshot_values = business_snapshot or business.snapshot()
        identities = grants(backend, override, identities=True)
        lines = ['*filter', ':VPNSTACK-LAN-IN - [0:0]', ':VPNSTACK-LAN-FWD - [0:0]', '-F VPNSTACK-LAN-IN', '-F VPNSTACK-LAN-FWD']
        for match in revoked_matches(backend):
            lines += ['-A VPNSTACK-LAN-IN ' + ' '.join(match) + ' -j DROP', '-A VPNSTACK-LAN-FWD ' + ' '.join(match) + ' -j DROP']
        pools = [state[k] for k in ('wg_net','ike_net','l2tp_net')]
        protected = sorted(set(networks + ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','169.254.0.0/16','127.0.0.0/8','224.0.0.0/4']))
        for ident, match in identities:
            policy = business.effective(registry, ident, snapshot_values)
            prefix = ' '.join(match)
            incoming, forward = '-A VPNSTACK-LAN-IN ' + prefix, '-A VPNSTACK-LAN-FWD ' + prefix
            if policy['blocked']:
                lines += [incoming + ' -j DROP', forward + ' -j DROP']
                continue
            # Explicit denies precede every implicit DNS, delivery or administrative grant.
            for rule in policy['rules']:
                if rule['effect']!='deny': continue
                denied=' -d '+rule['cidr']
                if rule['protocol']!='any': denied+=' -p '+rule['protocol']
                if rule['ports']: denied+=' -m multiport --dports '+','.join(map(str,rule['ports']))
                lines += [incoming+denied+' -j DROP',forward+denied+' -j DROP']
            # Only authenticated and enabled devices reach DNS or delivery.
            lines += [incoming + f' -d {state["lan"]} -p {proto} --dport 53 -j RETURN' for proto in ('tcp','udp')]
            lines += [incoming + ' -p tcp --dport 9000 -j RETURN']
            if state.get('admin_mode') in ('vpn','https') and ident in state.get('admin_devices',[]):
                lines += [incoming + f' -d {state["lan"]} -p tcp --dport 9001 -j ACCEPT']
            lines += [incoming + ' -p tcp -m multiport --dports 3000,8080,9001 -j DROP']
            if policy['isolation']:
                lines += [forward + ' -d ' + pool + ' -j DROP' for pool in pools]
            for rule in policy['rules']:
                if rule['effect']=='deny': continue
                rule_match = ' -d ' + rule['cidr']
                if rule['protocol'] != 'any': rule_match += ' -p ' + rule['protocol']
                if rule['ports']: rule_match += ' -m multiport --dports ' + ','.join(map(str,rule['ports']))
                target = 'DROP' if rule['effect'] == 'deny' else 'RETURN'
                lines += [incoming + rule_match + ' -j ' + target, forward + rule_match + ' -j ' + target]
            lines += [incoming + ' -j DROP']
            lines += [forward + ' -d ' + network + ' -j DROP' for network in protected]
            lines += [forward + ' -j ' + ('RETURN' if policy['internet'] else 'DROP')]
        # No source-only fallback: unknown/late IPsec and PPP hooks remain blocked.
        lines += ['-A VPNSTACK-LAN-IN -j DROP', '-A VPNSTACK-LAN-FWD -j DROP', 'COMMIT', '']
        desired = hashlib.sha256('\n'.join(lines).encode()).hexdigest()
        snapshot = backend.base / 'policy-snapshot.json'
        def kernel_digest():
            current = command(backend, ['iptables-save', '-t', 'filter']).stdout.splitlines()
            observed = [line for line in current if line.startswith(('-A VPNSTACK-LAN-IN ', '-A VPNSTACK-LAN-FWD '))]
            return hashlib.sha256('\n'.join(observed).encode()).hexdigest()
        if skip_unchanged:
            try:
                previous = json.loads(snapshot.read_text())
            except (OSError, ValueError):
                previous = {}
            if previous.get('desired') == desired and previous.get('kernel') == kernel_digest():
                return
        command(backend, ['iptables-restore', '-w', '5', '--noflush'], data='\n'.join(lines))
        observed = kernel_digest()
        expected = hashlib.sha256('\n'.join(line for line in lines if line.startswith(('-A VPNSTACK-LAN-IN ', '-A VPNSTACK-LAN-FWD '))).encode()).hexdigest()
        if observed != expected:
            # iptables-save normalizes option order; compare token multisets per rule.
            import shlex
            saved = command(backend, ['iptables-save', '-t', 'filter']).stdout.splitlines()
            def normalized(values):
                chains = {'VPNSTACK-LAN-IN': [], 'VPNSTACK-LAN-FWD': []}
                for line in values:
                    tokens = shlex.split(line)
                    if len(tokens) < 2 or tokens[0] != '-A' or tokens[1] not in chains:
                        continue
                    pairs = []
                    for index in range(2, len(tokens), 2):
                        option, value = tokens[index:index + 2]
                        if option == '-m' and value in ('tcp', 'udp'):
                            continue
                        if option in ('-s', '-d'):
                            value = str(ipaddress.ip_network(value, strict=False))
                        if option in ('--spi', '--reqid', '--src-group'):
                            value = str(int(value, 0))
                        pairs.append((option, value))
                    chains[tokens[1]].append(sorted(pairs))
                return chains
            if normalized(saved) != normalized(lines):
                raise RuntimeError('LAN policy firewall verification failed.')
        # Admission changes follow verified drops, before committing metadata.
        from vpn_business import expired
        configured=state.get('clients',{})
        # The firewall starts before wg-quick at boot and during a rebuild. No
        # interface means no authenticated peers and therefore no WG grants.
        # wg-quick's post-start hook reconciles again once the interface exists.
        wg_active=any(d.get('protocols',{}).get('wireguard',{}).get('status')=='active' for d in registry['devices'].values())
        wg_present=wg_active and 'wg0' in command(backend,['wg','show','interfaces']).stdout.split()
        for ident, device in registry['devices'].items():
            record=device.get('protocols',{}).get('wireguard',{})
            if record.get('status')!='active' or not wg_present: continue
            entry=configured.get(record['backend'],{}).get('wireguard',{})
            public=entry.get('public'); address=entry.get('address')
            if not public or not address: continue
            if not re.fullmatch(r'[A-Za-z0-9+/]{43}=',public): raise ValueError('Invalid managed WireGuard identity.')
            if expired(device) or expired(registry['users'][device['user']]):
                command(backend,['wg','set','wg0','peer',public,'remove'])
            else:
                address=str(ipaddress.IPv4Address(address))
                command(backend,['wg','set','wg0','peer',public,'allowed-ips',address+'/32'])
        if commit:
            commit()
        backend.m.atomic(snapshot, json.dumps({'desired': desired, 'kernel': observed}))



# This root-owned, standard-library-only helper is readable by sandboxed VPN daemons.
HOOK_CLIENT = r'''#!/usr/bin/env python3
import json,os,re,socket,sys
try:
 env=os.environ
 protocol=sys.argv[1]
 if protocol=='ikev2':
  if env.get('PLUTO_CONNECTION')!='ikev2-cp' or env.get('PLUTO_VERB') not in ('up-client','down-client','up-host','down-host'):
   sys.exit(0)
  value={'protocol':protocol,'up':env['PLUTO_VERB'].startswith('up-'),'identity':re.sub(r'\s*,\s*',',',env.get('PLUTO_PEER_ID','')).strip(),'address':env.get('PLUTO_PEER_CLIENT_NET',''),'reqid':env.get('PLUTO_SA_REQID',''),'spi':env.get('SPI_OUT','')}
 else:
  value={'protocol':'l2tp','up':sys.argv[2]=='up','identity':env.get('PEERNAME',''),'address':env.get('IPREMOTE',''),'interface':env.get('IFNAME',''),'pid':env.get('PPPD_PID','')}
 with socket.socket(socket.AF_UNIX) as connection:
  connection.settimeout(5)
  connection.connect('/run/vpn/control.sock')
  connection.sendall(json.dumps({'op':'policy-event','event':value}).encode()+b'\n')
  with connection.makefile('rb') as stream:
   reply=json.loads(stream.readline(65537))
  if not reply.get('ok'):
   raise RuntimeError('Policy event refused')
except Exception:
 print('VPN: session LAN grant unavailable; no new LAN permission was issued.',file=sys.stderr)
 # Native internet/DNS connectivity must not fail because the optional LAN grant could not be issued.
 sys.exit(0)
'''


def install(backend):
    m = backend.m
    candidates = [Path(path) for path in ('/usr/local/libexec/ipsec/_updown', '/usr/libexec/ipsec/_updown', '/usr/lib/ipsec/_updown', '/usr/local/lib/ipsec/_updown')]
    routing_helper = next((path for path in candidates if path.is_file() and os.access(path, os.X_OK) and path.stat().st_uid == 0 and not path.stat().st_mode & 0o022), None)
    if routing_helper is None:
        raise RuntimeError('Libreswan routing helper is missing or writable by non-root users. Repair the IPsec installation before enabling policy hooks.')
    # Root-owned event wrappers. Preserve Libreswan routing before reporting.
    wrapper = '''#!/bin/bash
set -euo pipefail
@@ROUTING_HELPER@@ "$@"
exec /usr/bin/python3 /opt/kagnode/vpn/helpers/hook.py ikev2
'''
    code_dir = Path('/opt/kagnode/vpn/helpers')
    code_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    code_dir.chmod(0o755)
    m.atomic(code_dir / 'hook.py', HOOK_CLIENT, 0o644)
    m.atomic(code_dir / 'ipsec-updown.sh', wrapper.replace('@@ROUTING_HELPER@@', shlex.quote(str(routing_helper))), 0o755)
    conf = backend.db / 'ikev2.conf'
    text = conf.read_text()
    desired = '  leftupdown=/opt/kagnode/vpn/helpers/ipsec-updown.sh'
    existing = re.findall(r'^\s*leftupdown\s*=\s*(.*)$', text, re.M)
    if existing and any(value not in ('/var/lib/kagnode/vpn/ipsec-updown.sh', '/opt/kagnode/vpn/helpers/ipsec-updown.sh') for value in existing):
        raise RuntimeError('Custom IKEv2 updown hook found. It was preserved; policy installation stopped.')
    if existing:
        updated = re.sub(r'^\s*leftupdown\s*=.*$', desired, text, flags=re.M)
    else:
        updated = text.rstrip() + '\n' + desired + '\n'
    if updated != text:
        m.backup(conf)
        m.atomic(conf, updated)
    configure_ppp(backend)
    m.atomic(backend.base / 'policy-installed', 'yes\n')
    apply(backend)
    m.command(['ipsec', 'auto', '--replace', 'ikev2-cp'])


def cli_event(backend, args):
    env = os.environ
    if args[0] == 'ikev2':
        if env.get('PLUTO_CONNECTION') != 'ikev2-cp' or env.get('PLUTO_VERB') not in ('up-client', 'down-client', 'up-host', 'down-host'):
            return
        identity = re.sub(r'\s*,\s*', ',', env.get('PLUTO_PEER_ID', '')).strip()
        event(backend, {'protocol': 'ikev2', 'up': env['PLUTO_VERB'].startswith('up-'), 'identity': identity,
                        'address': env.get('PLUTO_PEER_CLIENT_NET', ''), 'reqid': env.get('PLUTO_SA_REQID', ''), 'spi': env.get('SPI_OUT', '')})
    else:
        identity = env.get('PEERNAME', '')
        reg = backend.load()
        known = any(row['protocols'].get('l2tp', {}).get('backend') == identity and row['protocols']['l2tp'].get('status') == 'active' for row in reg['devices'].values())
        if not known:
            raise RuntimeError('PPP authenticated account is not an active managed client; no LAN grant.')
        event(backend, {'protocol': 'l2tp', 'up': args[1] == 'up', 'identity': identity,
                        'address': env.get('IPREMOTE', ''), 'interface': env.get('IFNAME', '')})


def configure_ppp(backend):
    # Keep xl2tpd/pppd native address assignment and authentication files unchanged.
    # Identity + live interface-generation groups prevent spoofing and name/address reuse.
    m = backend.m
    for name, mode in [('ip-up.d', 'up'), ('ip-down.d', 'down')]:
        m.atomic(m.ETC / 'ppp' / name / 'vpn', '#!/bin/sh\nexec /usr/bin/python3 /opt/kagnode/vpn/helpers/hook.py l2tp ' + mode + '\n', 0o700)
