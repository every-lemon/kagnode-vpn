#!/usr/bin/env python3
"""Self-contained updater runtime; embedded with release assets by build.py."""
import base64
import contextlib
import datetime
import fcntl
import gzip
import hashlib
import ipaddress
import json
import os
import pwd
import grp
from pathlib import Path
import re
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time

PAYLOAD = '''@@UPDATE_PAYLOAD@@'''
PAYLOAD_HASH = '@@UPDATE_PAYLOAD_HASH@@'
RELEASE = '@@UPDATE_VERSION@@'


class UpdateError(RuntimeError):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


# Shared version implementation is embedded by build.py.
_VERSION_RUNTIME = """@@VERSION_RUNTIME@@"""
if _VERSION_RUNTIME.startswith('@@'):
    from vpn_version import parse as version
else:
    _version_scope = {}
    exec(_VERSION_RUNTIME, _version_scope)
    version = _version_scope['parse']


def atomic(path, data, mode=0o600, owner=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name + '-')
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            if owner is not None:
                os.fchown(stream.fileno(), *owner)
            stream.write(data.encode() if isinstance(data, str) else data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def decode_payload():
    packed = base64.b64decode(''.join(PAYLOAD.split()), validate=True)
    if sha(packed) != PAYLOAD_HASH:
        raise UpdateError('Embedded payload checksum mismatch; obtain a complete update.sh.')
    payload = json.loads(gzip.decompress(packed))
    validate_payload(payload)
    return payload


def validate_payload(payload):
    version(payload['version'])
    for name in ('setup.sh', 'manage.py', 'ikev2.sh'):
        data = payload['files'][name].encode()
        if sha(data) != payload['sha256'][name]:
            raise UpdateError('Embedded file checksum mismatch: ' + name)
    setup = payload['files']['setup.sh']
    if not setup.endswith('# END_VPN_STACK_INSTALLER\n'):
        raise UpdateError('Embedded installer is incomplete.')
    if re.search(r'^VERSION=(\S+)$', setup, re.M).group(1) != payload['version']:
        raise UpdateError('Embedded installer version mismatch.')
    runtime = payload['files']['manage.py']
    compile(runtime, 'embedded-manage.py', 'exec')
    match = re.search(r"^_MODULE_ARCHIVE = '([^']+)'$", runtime, re.M)
    if not match:
        raise UpdateError('Embedded modules are missing.')
    modules = json.loads(gzip.decompress(base64.b64decode(match[1], validate=True)))
    for name in ('vpn_clients', 'vpn_web', 'vpn_ui', 'vpn_backend', 'vpn_policy', 'vpn_dependencies', 'vpn_watchdog', 'vpn_admin', 'vpn_harden', 'vpn_portal', 'vpn_auth', 'vpn_version', 'vpn_business', 'vpn_native', 'vpn_maintenance', 'vpn_setup', 'vpn_repair', 'vpn_console', 'vpn_dashboard', 'vpn_access', 'vpn_release', 'vpn_tasks'):
        compile(modules[name], 'embedded-' + name, 'exec')


def installer_version(path):
    if not path.is_file():
        raise UpdateError('Installed setup.sh is missing; finish initial installation first.')
    text = path.read_text()
    match = re.search(r'^VERSION=(\S+)$', text, re.M)
    if not match or 'VPN' not in text or not text.endswith('# END_VPN_STACK_INSTALLER\n'):
        raise UpdateError('Unrecognized VPN installer: ' + str(path))
    return match.group(1)


class Updater:
    """4.x code-only update. Native credentials and administrative databases are preserved."""
    def __init__(self,source,payload,root=Path('/'),prerelease=False):
        self.root=Path(root); self.source=Path(source).resolve(strict=True);self.payload=payload
        self.source_bytes=self.source.read_bytes()
        self.target=payload['version'];self.base=self.path('/var/lib/kagnode/vpn');self.prerelease=prerelease
        self.code=self.path('/opt/kagnode/vpn');self.helpers=self.path('/opt/kagnode/vpn/helpers')
        self.run_dir=None
    def path(self,value):return self.root/value.lstrip('/')
    @contextlib.contextmanager
    def package_guard(self):
        # Native APT/dpkg use POSIX record locks. Retain them through code deployment
        # so a package upgrade cannot replace the same files halfway through.
        with contextlib.ExitStack() as stack:
            for filename in ('/var/lib/dpkg/lock-frontend','/var/lib/dpkg/lock','/var/lib/apt/lists/lock','/var/cache/apt/archives/lock'):
                path=self.path(filename)
                if not path.exists():continue
                stream=stack.enter_context(path.open('r+'))
                try:fcntl.lockf(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:raise UpdateError('Ubuntu package maintenance is running; retry later.') from None
            yield
    def command(self,args,check=True,timeout=600):
        with (self.run_dir/'commands.log').open('a') as log:
            log.write('\n$ '+shlex.join(map(str,args))+'\n');log.flush()
            result=subprocess.run(list(map(str,args)),stdout=log,stderr=log,timeout=timeout)
        if check and result.returncode:raise UpdateError('Command failed; see private commands.log: '+str(args[0]))
        return result
    def web_ready(self,port,timeout):
        # Type=simple can briefly be active even when its worker cannot execute.
        # Check the real listener without redirects, proxy variables or credentials.
        try:
            state=json.loads(self.path('/etc/kagnode/vpn/state.json').read_text())
            address=ipaddress.IPv4Address(state['lan'])
            if address.is_unspecified or address.is_multicast:return False
            result=subprocess.run(['curl','--disable','--silent','--fail','--noproxy','*',
                '--proto','=http','--connect-timeout','1','--max-time',str(timeout),
                '--max-filesize','16','--write-out','\n%{http_code}',
                'http://'+str(address)+':'+str(port)+'/health'],
                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,check=False)
            return result.returncode==0 and result.stdout==b'OK\n\n200'
        except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):return False
    def wait_services(self,timeout=60):
        # A requested unit may finish before its ordered PartOf dependents.
        # Check every unit independently under one deadline; never restart here.
        services=('vpn-control','vpn-management','vpn-downloads','vpn-firewall','ipsec','xl2tpd','wg-quick@wg0','AdGuardHome')
        deadline=time.monotonic()+timeout
        pending=list(services)
        while time.monotonic()<deadline:
            pending=[]
            for index,service in enumerate(services):
                remaining=deadline-time.monotonic()
                if remaining<=0:
                    pending.extend(services[index:])
                    break
                try:
                    result=self.command(['systemctl','is-active','--quiet',service],check=False,timeout=min(3,remaining))
                    ready=result.returncode==0
                except subprocess.TimeoutExpired:
                    ready=False
                if not ready:pending.append(service)
            if not pending:
                for port in (9000,9001):
                    remaining=deadline-time.monotonic()
                    if remaining<=0 or not self.web_ready(port,min(2,remaining)):
                        pending.append('web listener '+str(port))
            if not pending:return
            remaining=deadline-time.monotonic()
            if remaining>0:time.sleep(min(.5,remaining))
        raise UpdateError('Required services did not become active and responsive within '+str(timeout)+' seconds: '+', '.join(pending)+'. See private commands.log.')
    def diagnostics(self,phase):
        for command in (['journalctl','-u','vpn-control','-u','vpn-downloads','-u','vpn-management','--since','15 minutes ago','-n','150','--no-pager'],['systemctl','status','vpn-control','vpn-downloads','vpn-management','--no-pager']):
            with (self.run_dir/(phase+'-'+command[0]+'.log')).open('w') as log:
                subprocess.run(command,stdout=log,stderr=log,timeout=20,check=False)
    def run(self):
        validate_payload(self.payload)
        if '-' in self.target and not self.prerelease:raise UpdateError('Prerelease requires --prerelease. Stable selection never installs beta/RC releases.')
        state_path=self.path('/etc/kagnode/vpn/state.json')
        if not state_path.exists():raise UpdateError('No VPN 4 installation found. Use setup.sh; 3.x requires explicit --fresh-start.')
        state=json.loads(state_path.read_text())
        if state.get('version')!=4 or not state.get('installed'):raise UpdateError('Finish VPN 4 setup before updating; no legacy migration is performed.')
        archive=self.base/'updates'/('update-'+self.target+'.sh')
        if archive.exists() and archive.read_bytes()!=self.source_bytes:raise UpdateError('Conflicting updater archive; no update was applied.')
        current=(self.code/'VERSION').read_text().strip()
        if version(current)>version(self.target):raise UpdateError('Application downgrades are not supported.')
        if self.root==Path('/'):
            if os.geteuid()!=0:raise UpdateError('Run as root.')
            os_release=self.path('/etc/os-release').read_text()
            if 'ID=ubuntu' not in os_release or 'VERSION_ID="24.04"' not in os_release:raise UpdateError('Ubuntu 24.04 required.')
        self.base.mkdir(mode=0o700,parents=True,exist_ok=True)
        with (self.base/'maintenance.lock').open('a') as maintenance,(self.base/'operation.lock').open('a') as operation,self.package_guard():
            try:
                fcntl.flock(maintenance,fcntl.LOCK_EX|fcntl.LOCK_NB)
                fcntl.flock(operation,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise UpdateError('Maintenance or another job is running; retry later.') from None
            self.run_dir=self.base/'backups'/('update-'+self.target+'-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
            self.run_dir.mkdir(mode=0o700,parents=True)
            assets=self.run_dir/'staging';assets.mkdir(mode=0o700)
            for name,text in self.payload['files'].items():atomic(assets/name,text)
            self.command(['bash','-n',assets/'setup.sh'])
            paths={self.code/'manage.py':self.payload['files']['manage.py'],self.helpers/'setup.sh':self.payload['files']['setup.sh'],self.base/'upstream/ikev2.sh':self.payload['files']['ikev2.sh'],self.code/'VERSION':self.target+'\n'}
            # Back up only application-owned definitions; do not snapshot credentials.
            unit_dir=self.path('/etc/systemd/system')
            owned=list(unit_dir.glob('vpn-*.service'))+list(unit_dir.glob('vpn-*.socket'))+list(unit_dir.glob('vpn-*.timer'))
            owned += [self.helpers/'firewall.sh',unit_dir/'wg-quick@wg0.service.d/vpn.conf']
            owned_before={path:(os.readlink(path) if path.is_symlink() else path.read_bytes(),path.lstat().st_mode&0o777,path.is_symlink()) for path in owned if path.exists() or path.is_symlink()}
            for index,(path,(data,mode,link)) in enumerate(owned_before.items()):
                atomic(self.run_dir/('owned-'+str(index)),data)
            atomic(self.run_dir/'owned-index.json',json.dumps([{'path':str(p),'mode':v[1],'symlink':v[2]} for p,v in owned_before.items()]))
            previous={}
            for index,path in enumerate(paths):
                previous[path]=path.read_bytes() if path.exists() else None
                if previous[path] is not None:atomic(self.run_dir/('before-'+str(index)),previous[path])
            journal={'version':self.target,'previous':current,'status':'staged','credentials_preserved':True}
            atomic(self.run_dir/'journal.json',json.dumps(journal))
            try:
                self.command(['systemctl','stop','vpn-management','vpn-downloads','vpn-control.service','vpn-control.socket'])
                for path,data in paths.items():atomic(path,data,0o644 if path.name=='VERSION' else 0o700)
                self.command(['bash','-c','set -Eeuo pipefail; source "$1"; eval "$(python3 /opt/kagnode/vpn/manage.py state-shell)"; write_firewall','vpn-update',self.helpers/'setup.sh'])
                self.command(['python3',self.code/'manage.py','refresh-web'])
                # Package removal stops these timers. A verified application
                # redeployment must also resume monitoring and maintenance.
                self.command(['systemctl','start','vpn-watchdog.timer','vpn-maintenance.timer'])
                self.wait_services()
                journal['status']='complete';atomic(self.run_dir/'journal.json',json.dumps(journal))
            except BaseException:
                # A stalled journal or unavailable systemd must not prevent
                # restoring the previous application after deployment fails.
                try:self.diagnostics('failure')
                except Exception:
                    print('Failure diagnostics unavailable; restoring previous application files.',file=sys.stderr)
                for path,data in previous.items():
                    if data is None:path.unlink(missing_ok=True)
                    else:atomic(path,data,0o644 if path.name=='VERSION' else 0o700)
                current_owned=list(unit_dir.glob('vpn-*.service'))+list(unit_dir.glob('vpn-*.socket'))+list(unit_dir.glob('vpn-*.timer'))+[self.helpers/'firewall.sh',unit_dir/'wg-quick@wg0.service.d/vpn.conf']
                for path in current_owned:
                    if path not in owned_before:path.unlink(missing_ok=True)
                for path,(data,mode,link) in owned_before.items():
                    if link:
                        path.unlink(missing_ok=True);path.symlink_to(data)
                    else:atomic(path,data,mode)
                self.command(['systemctl','daemon-reload'],check=False)
                self.command(['systemctl','restart','vpn-firewall'],check=False)
                self.command(['python3',self.code/'manage.py','refresh-web'],check=False)
                journal['status']='code-restored';atomic(self.run_dir/'journal.json',json.dumps(journal))
                raise
            archive=self.base/'updates'/('update-'+self.target+'.sh')
            if self.source.read_bytes()!=self.source_bytes:raise UpdateError('Updater source changed during the update; source retained.')
            atomic(archive,self.source_bytes,0o700)
            if self.source!=archive:self.source.unlink()
            print('VPN '+self.target+' updated. Clients, administrators, MFA and AdGuard settings preserved.')
            print('Updater archived at '+str(archive))
            print('Private logs: '+str(self.run_dir))

def main():
    source,*args=sys.argv[1:]
    payload=decode_payload()
    if args==['--verify']:
        print('Embedded release '+payload['version']+' checksums and Python syntax verified. No changes made.');return
    if args not in ([],['--prerelease']):raise UpdateError('Use --verify or --prerelease.')
    os.umask(0o077)
    Updater(source,payload,prerelease='--prerelease' in args).run()

if __name__=='__main__':
    try:main()
    except (UpdateError,OSError,ValueError) as exc:
        print('Update stopped: '+str(exc),file=sys.stderr);sys.exit(1)
