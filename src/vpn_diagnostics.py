"""Bounded, read-only connection checks. Reports contain allowlisted facts only."""
import datetime
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time

LIMIT = 65536
RETENTION = 20
SERVICE_UNITS = ('AdGuardHome', 'ipsec', 'xl2tpd', 'wg-quick@wg0',
                 'vpn-control', 'vpn-downloads', 'vpn-management', 'vpn-firewall')


def probe(args, timeout):
    """Stop this child process group on timeout or excessive output."""
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          start_new_session=True) as process:
        output = bytearray()
        completed = False
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            try:
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('Diagnostic timed out')
                    for key, _ in selector.select(min(remaining, .1)):
                        block = os.read(key.fd, 8192)
                        if not block:
                            selector.unregister(key.fileobj)
                        else:
                            output.extend(block)
                            if len(output) > LIMIT:
                                raise ValueError('Diagnostic output limit reached')
                process.wait(timeout=max(.01, deadline - time.monotonic()))
                completed = True
                return subprocess.CompletedProcess(args, process.returncode, output.decode(errors='replace'), '')
            finally:
                # Descendants may have inherited stdout even if the leader exited.
                if not completed:
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass


def path_for(manager, device=''):
    if device and not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', device):
        raise ValueError('Invalid diagnostic device.')
    return manager.BASE / 'diagnostics' / (('device-' + device if device else 'system') + '.json')


def cached(manager, device=''):
    path = path_for(manager, device)
    try:
        if path.is_symlink() or path.stat().st_size > LIMIT:
            return None
        value = json.loads(path.read_text())
        if not isinstance(value,dict) or value.get('schema') != 1: return None
        if not isinstance(value.get('sampled_at'),(int,float)) or not math.isfinite(value['sampled_at']):return None
        if not isinstance(value.get('reference'),str) or not re.fullmatch(r'[a-f0-9]{16}',value['reference']):return None
        checks=value.get('checks')
        if not isinstance(checks,list) or len(checks)>32:return None
        for row in checks:
            if not isinstance(row,dict) or row.get('status') not in ('pass','warning','failure','unknown'):return None
            if any(not isinstance(row.get(field),str) or len(row[field])>1000 for field in ('id','message','next_step')):return None
        if not isinstance(value.get('engines',{}),dict):return None
        return value
    except (OSError, ValueError):
        return None


def collect(manager, backend=None, device='', runner=probe):
    """Called under the existing operation lock; never invoked by passive polling."""
    path = path_for(manager, device)
    state = manager.load()
    record = None
    if device:
        _, record = backend.device(device)
    deadline = time.monotonic() + 15
    checks = []

    def add(ident, status, message, next_step=''):
        checks.append(dict(id=ident, status=status, message=message, next_step=next_step))

    def run(args, require_success=True):
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0: return None
            result = runner(args, min(3, remaining))
            if len(result.stdout.encode()) > LIMIT: return None
            return result if not require_success or result.returncode == 0 else None
        except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired):
            return None

    result = run(['systemctl', 'is-active', *SERVICE_UNITS], require_success=False)
    service_states = result.stdout.split() if result else []
    healthy = result is not None and result.returncode == 0 and service_states == ['active'] * len(SERVICE_UNITS)
    if healthy:
        service_message = 'All VPN and application services, including AdGuard Home, are active.'
    elif result is None:
        service_message = 'Managed service health could not be checked.'
    elif len(service_states) != len(SERVICE_UNITS):
        service_message = 'Managed service health returned an unexpected number of results.'
    elif (all(value in ('active', 'inactive', 'failed', 'activating', 'deactivating',
                        'reloading', 'maintenance', 'unknown') for value in service_states)
          and any(value != 'active' for value in service_states)):
        service_message = 'One or more managed services are unavailable.'
    else:
        service_message = 'Managed service health could not be confirmed.'
    add('services', 'pass' if healthy else 'failure', service_message,
        'Open System service health; run managed repair for a verified service fault.')
    result = run(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value'])
    add('clock', 'pass' if result and result.stdout.strip() == 'yes' else 'warning',
        'System time is synchronized.' if result and result.stdout.strip() == 'yes' else 'Time synchronization is not confirmed.',
        'Verify Ubuntu time synchronization before certificate or MFA troubleshooting.')
    try: lan = str(ipaddress.IPv4Address(state['lan']))
    except (KeyError, ValueError): lan = None
    result = run(['dig', '+time=2', '+tries=1', '+short', '@' + lan, 'example.com', 'A']) if lan else None
    resolved = False
    if result:
        for line in result.stdout.splitlines():
            try: ipaddress.IPv4Address(line.strip()); resolved = True
            except ValueError: pass
    add('dns', 'pass' if resolved else 'failure',
        'Server DNS resolves an IPv4 test name.' if resolved else 'Server DNS resolution is not confirmed.',
        'Check AdGuard service, listener and upstream DNS settings.')
    endpoint = state.get('endpoint', '')
    valid_endpoint = isinstance(endpoint, str) and bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', endpoint))
    result = run(['getent', 'ahostsv4', endpoint]) if valid_endpoint else None
    add('endpoint', 'pass' if result and result.stdout.strip() else 'warning',
        'The configured endpoint resolves locally.' if result and result.stdout.strip() else 'The configured endpoint could not be resolved locally.',
        'Confirm the public hostname/address and router forwarding from an independent network.')
    result = run(['ip', '-4', 'route', 'show', 'default'])
    add('routing', 'pass' if result and result.stdout.startswith('default ') else 'failure',
        'An IPv4 default route is present.' if result and result.stdout.startswith('default ') else 'An IPv4 default route could not be confirmed.',
        'Inspect Ubuntu networking from the console before changing routing.')
    result = run(['iptables', '-S', 'VPNSTACK-LAN-FWD'])
    add('firewall', 'pass' if result and '-N VPNSTACK-LAN-FWD' in result.stdout else 'warning',
        'The managed forwarding chain is present; this alone does not verify effective access.' if result and '-N VPNSTACK-LAN-FWD' in result.stdout else 'The managed forwarding chain could not be inspected.',
        'Review effective access and run vpn doctor before requesting a managed repair.')
    engines={}
    for name,args,pattern in (
        ('ipsec',['ipsec','--version'],r'Libreswan\s+([0-9]+(?:\.[0-9]+){1,3})'),
        ('wireguard',['wg','--version'],r'wireguard-tools\s+v([0-9]+(?:\.[0-9]+){1,3})')):
        result=run(args)
        match=re.search(pattern,result.stdout) if result else None
        if match:engines[name]=match[1][:32]
    if record:
        from vpn_business import expired
        user = backend.load()['users'][record['user']]
        blocked = expired(record) or expired(user)
        add('identity', 'failure' if blocked else 'pass',
            'This identity is disabled, expired or revoked.' if blocked else 'This identity is administratively enabled.',
            'Review device and user access settings. Enabled does not establish a live connection.')
        _observe(manager, backend, record, device, run, add)
    add('wan', 'unknown', 'Router forwarding and external reachability require a real external-client test.',
        'Test outside home Wi-Fi. Forward UDP 500/4500 for IPsec and 51820 for WireGuard; check for CGNAT or NAT loopback.')
    report = dict(schema=1, version='@@VERSION@@', reference=os.urandom(8).hex(),
                  sampled_at=time.time(), checks=checks, engines=engines)
    manager.atomic(path, json.dumps(report, sort_keys=True))
    files = sorted(path.parent.glob('*.json'), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in files[RETENTION:]:
        if old.is_file() and not old.is_symlink(): old.unlink()
    return report


def _inbound_esp(output, state):
    """Read only selectors; Ubuntu 24.04 may return text despite ip's -j flag."""
    destinations={state.get('lan'),state.get('public')}-{None,''}
    selectors=set()
    def keep(destination, protocol, reqid, spi):
        if destination not in destinations or protocol!='esp':return
        try:
            reqid=int(reqid);spi=int(str(spi),0)
            if 0<reqid<2**32 and 0<spi<2**32:selectors.add((reqid,spi))
        except (TypeError,ValueError):pass
    try:
        rows=json.loads(output)
    except ValueError:
        for block in re.split(r'(?m)(?=^src )',output):
            destination=re.search(r'^src \S+ dst (\S+)',block)
            identifier=re.search(r'\bproto esp spi (0x[0-9a-fA-F]+) reqid ([0-9]+)\b',block)
            if destination and identifier:keep(destination[1],'esp',identifier[2],identifier[1])
    else:
        for item in rows if isinstance(rows,list) else ():
            if isinstance(item,dict):keep(item.get('dst'),item.get('proto'),item.get('reqid'),item.get('spi'))
    return selectors


def _observe(manager, backend, record, device, run, add):
    """Use current kernel identity evidence, never an assigned address alone."""
    state = manager.load()
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    with backend.repo.connect() as db:
        rows = [json.loads(raw) for (raw,) in db.execute(
            "SELECT data FROM policy_sessions WHERE json_extract(data,'$.device')=? LIMIT 16", (device,))]
    for protocol, profile in record.get('protocols', {}).items():
        if profile.get('status') != 'active': continue
        observed = False
        if protocol == 'wireguard':
            entry = state.get('clients', {}).get(profile.get('backend'), {}).get('wireguard', {})
            result = run(['wg', 'show', 'wg0', 'latest-handshakes'])
            for line in result.stdout.splitlines() if result else []:
                values = line.split()
                if len(values) == 2 and values[0] == entry.get('public') and values[1].isdigit():
                    age = time.time() - int(values[1])
                    observed = 0 <= age <= 180
        elif protocol in ('ikev2', 'l2tp'):
            for row in rows:
                native = profile.get('backend', '')
                identities = (native, '@' + native, 'O=IKEv2 VPN,CN=' + native, 'CN=' + native + ',O=IKEv2 VPN')
                if row.get('boot') != boot or row.get('protocol') != protocol or row.get('identity') not in identities: continue
                if protocol == 'ikev2':
                    result = run(['ip', '-j', 'xfrm', 'state'])
                    try:
                        observed = (row['reqid'],row['spi']) in _inbound_esp(result.stdout,state) if result else False
                    except (ValueError, KeyError, TypeError): pass
                elif re.fullmatch(r'ppp[0-9]+', row.get('interface', '')):
                    result = run(['ip', '-j', 'link', 'show', 'dev', row['interface']])
                    try:
                        observed = any(item['ifindex'] == row['ifindex'] and int(item.get('group', 0)) == row['ifindex'] for item in json.loads(result.stdout)) if result else False
                    except (ValueError, KeyError, TypeError): pass
                if observed: break
        add('session-' + protocol, 'pass' if observed else 'unknown',
            protocol.upper() + (': recent authenticated session evidence observed.' if observed else ': no current authenticated session evidence confirmed.'),
            'Connect this device, then run another check. A handshake/session does not establish DNS or application access.')


def support(manager):
    """Rebuild a strict allowlist; never attach raw files, journals or identifiers."""
    saved = cached(manager) or {}
    allowed = {'services', 'clock', 'dns', 'endpoint', 'routing', 'firewall', 'wan'}
    # Static templates prevent cached or unexpected strings leaking into exports.
    statuses = {row.get('id'): row.get('status') for row in saved.get('checks', []) if isinstance(row, dict) and isinstance(row.get('id'),str)}
    result = dict(schema=1, version='@@VERSION@@', generated_at=time.time(),
                  sampled_at=saved.get('sampled_at') if isinstance(saved.get('sampled_at'), (int, float)) else None,
                  checks=[dict(id=name, status=statuses.get(name) if statuses.get(name) in ('pass','warning','failure','unknown') else 'unknown') for name in sorted(allowed)],
                  guidance='Server checks cannot prove WAN reachability. No raw journals, credentials, client names or addresses are included.')
    reference=saved.get('reference','')
    if isinstance(reference,str) and re.fullmatch(r'[a-f0-9]{16}',reference):result['reference']=reference
    result['engines']={name:value for name,value in saved.get('engines',{}).items()
                       if name in ('ipsec','wireguard') and isinstance(value,str) and re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,3}',value)}
    result['memory_mib']={}
    for line in Path('/proc/meminfo').read_text().splitlines():
        fields=line.split()
        if fields[0] in ('MemTotal:','MemAvailable:') and len(fields)>1 and fields[1].isdigit():
            result['memory_mib'][fields[0].rstrip(':')]=int(fields[1])//1024
    return json.dumps(result, indent=2).encode()


def describe(report):
    if not report: return 'No connection check recorded. Run a check to collect bounded diagnostics.'
    stamp = datetime.datetime.fromtimestamp(report['sampled_at'], datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    return 'Checked ' + stamp + '\nReference: ' + report['reference'] + '\n\n' + '\n\n'.join(
        row['status'].upper() + ' ' + row['message'] + ('\nNext: ' + row['next_step'] if row['status'] != 'pass' else '') for row in report['checks'])
