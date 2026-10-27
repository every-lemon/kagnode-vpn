"""Explicit fresh-start orchestration. Never invoked by package maintainer scripts."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import time

STAGES = ('review','packages','owner','vpn','adguard','verified')

def stage(manager, name):
    if name not in STAGES: raise ValueError('Unknown setup stage.')
    path=manager.BASE/'setup-progress.json'
    data=json.loads(path.read_text()) if path.exists() else {'completed':[]}
    if name not in data['completed']: data['completed'].append(name)
    data['updated']=time.time(); manager.atomic(path,json.dumps(data,indent=2))


def fresh_start(manager, confirmation, root=Path('/')):
    if confirmation != 'RESET VPN AND ADGUARD':
        raise ValueError('Type RESET VPN AND ADGUARD to authorize the fresh start.')
    root=Path(root)
    legacy=root/'root/vpn-stack'; source=legacy/'state.json'
    marker=root/'var/lib/vpn/reset-progress.json'
    if marker.exists():
        state=json.loads(marker.read_text())
        if state['stage']=='complete': return state
    else:
        if not source.is_file(): raise RuntimeError('No managed 3.x installation found. Nothing was reset.')
        old=json.loads(source.read_text())
        if old.get('version') != 3: raise RuntimeError('Only managed 3.x installations support this reset.')
        # Refuse mixed-use IPsec/PPP state rather than deleting unrelated identities.
        names=set(old.get('clients',{}))
        if old.get('l2tp_user'): names.add(old['l2tp_user'])
        chap=root/'etc/ppp/chap-secrets'
        if chap.exists():
            import shlex
            for line in chap.read_text().splitlines():
                fields=shlex.split(line,comments=True)
                if fields and fields[0] not in names:
                    raise RuntimeError('Unmanaged PPP identity found; fresh start refused without deleting anything.')
        extra=[f.name for f in (root/'etc/ipsec.d').glob('*.conf') if f.name!='ikev2.conf']
        if extra:raise RuntimeError('Additional IPsec connections found; fresh start refused.')
        stamp=time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())
        archive=root/'var/lib/vpn-recovery'/stamp
        archive.mkdir(parents=True,mode=0o700)
        state={'stage':'inventory','archive':str(archive),'paths':['root/vpn-stack','etc/ipsec.conf','etc/ipsec.secrets','etc/ipsec.d','etc/wireguard/wg0.conf','etc/xl2tpd/xl2tpd.conf','etc/ppp/options.xl2tpd','etc/ppp/chap-secrets','opt/AdGuardHome/AdGuardHome.yaml','opt/AdGuardHome/data'],'ssh_disabled':(legacy/'ssh-disabled').exists()}
        for name in names | {'first-device'}:
            if __import__('re').fullmatch(r'[A-Za-z0-9_-]{1,80}',name):
                state['paths'] += ['root/'+name+suffix for suffix in ('.p12','.sswan','.mobileconfig','-README.txt')]
        manager.atomic(marker,json.dumps(state))
    archive=Path(state['archive'])
    # Stop before backing up SQLite/NSS. Disable VPN engines until deliberate setup resumes.
    units=['vpn-stack-control.socket','vpn-stack-control','vpn-stack-downloads','vpn-stack-management','vpn-stack-watchdog.timer','vpn-stack-cleanup.timer','vpn-stack-management-expire.timer','AdGuardHome','ipsec','xl2tpd','wg-quick@wg0']
    for unit in units:
        manager.command(['systemctl','disable','--now',unit],check=False)
    if state['stage']=='inventory':
        inventory={}
        for relative in state['paths']:
            origin=root/relative; target=archive/relative
            if not origin.exists(): continue
            target.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
            if origin.is_dir(): shutil.copytree(origin,target,symlinks=True,dirs_exist_ok=True)
            else: shutil.copy2(origin,target,follow_symlinks=False)
            files=origin.rglob('*') if origin.is_dir() else [origin]
            for f in files:
                if f.is_file() and not f.is_symlink():
                    rel=f.relative_to(root)
                    with f.open('rb') as stream:checksum=hashlib.file_digest(stream,'sha256').hexdigest()
                    with (archive/rel).open('rb') as stream:copied=hashlib.file_digest(stream,'sha256').hexdigest()
                    if copied!=checksum: raise RuntimeError('Backup verification failed.')
                    inventory[str(rel)]=checksum
        # The verified recovery copy must reach disk before the deletion stage is durable.
        for copied in archive.rglob('*'):
            if copied.is_file() and not copied.is_symlink():
                with copied.open('rb') as stream:os.fsync(stream.fileno())
        for directory in sorted((p for p in archive.rglob('*') if p.is_dir() and not p.is_symlink()),key=lambda p:len(p.parts),reverse=True)+[archive,archive.parent]:
            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        manager.atomic(archive/'SHA256.json',json.dumps(inventory,indent=2))
        state['stage']='backed-up'; manager.atomic(marker,json.dumps(state))
    if state['stage']=='backed-up':
        # Fixed managed paths; never remove OS networking, packages or engine binaries.
        for relative in state['paths']:
            origin=root/relative
            if origin.is_symlink() or origin.is_file(): origin.unlink()
            elif origin.is_dir(): shutil.rmtree(origin)
        # Explicitly retire legacy units; do not touch native engine definitions.
        for filename in (root/'etc/systemd/system').glob('vpn-stack-*'):
            if filename.is_file() or filename.is_symlink(): filename.unlink()
        for relative in ('etc/systemd/system/wg-quick@wg0.service.d/vpn-stack.conf','etc/ppp/ip-up.d/99-vpn-stack','etc/ppp/ip-down.d/99-vpn-stack','usr/local/sbin/vpn-stack'):
            (root/relative).unlink(missing_ok=True)
        if state['ssh_disabled']: manager.atomic(manager.BASE/'ssh-disabled','yes\n')
        state['stage']='complete'; manager.atomic(marker,json.dumps(state))
        manager.command(['systemctl','daemon-reload'])
    return state
