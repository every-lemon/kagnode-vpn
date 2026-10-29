#!/usr/bin/env python3
"""Build the native application package without modifying the build host."""
import gzip,base64,json,hashlib,os,shutil,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from vpn_version import debian
version=(ROOT/'VERSION').read_text().strip()
subprocess.run([sys.executable,str(ROOT/'build.py')],check=True)
root=ROOT/'build/package'
if root.exists():shutil.rmtree(root)
for d in ('DEBIAN','usr/bin','usr/lib/vpn','usr/libexec/vpn','usr/share/doc/vpn'):(root/d).mkdir(parents=True)
setup=(ROOT/'setup.sh').read_text()
manager=setup.split("<<'PY_RUNTIME'\n",1)[1].split('\nPY_RUNTIME\n',1)[0]
(root/'usr/lib/vpn/manage.py').write_text(manager+'\n')
shutil.copy2(ROOT/'VERSION',root/'usr/lib/vpn/VERSION')
if (ROOT/'release-key.pem').exists():shutil.copy2(ROOT/'release-key.pem',root/'usr/lib/vpn/release-key.pem')
shutil.copy2(ROOT/'setup.sh',root/'usr/libexec/vpn/setup.sh')
shutil.copy2(ROOT/'packaging/vpn',root/'usr/bin/vpn')
for name in ('postinst','prerm'):shutil.copy2(ROOT/'packaging'/name,root/'DEBIAN'/name)
for name in ('LICENSE','THIRD_PARTY_NOTICES.md','README.md'):
 if (ROOT/name).exists():shutil.copy2(ROOT/name,root/'usr/share/doc/vpn'/name)
shutil.copytree(ROOT/'assets',root/'usr/share/doc/vpn/assets')
(root/'DEBIAN/control').write_text(f'''Package: vpn
Version: {debian(version)}
Architecture: amd64
Maintainer: every-lemon <every-lemon@users.noreply.github.com>
Section: net
Priority: optional
Depends: python3 (>= 3.12), python3-venv, ca-certificates, curl, openssl, iproute2, iptables, wireguard-tools, libnss3-tools, ppp, qrencode, util-linux, dnsutils
Description: KagNode Open source VPN server
 KagNode VPN manages WireGuard, IKEv2 and L2TP with MFA, access policy and delivery.
 Initial configuration requires the explicit vpn setup command.
''')
for path in root.rglob('*'):
 if path.is_dir():path.chmod(0o755)
 elif path.name in ('vpn','postinst','prerm','setup.sh'):path.chmod(0o755)
 else:path.chmod(0o644)
dist=ROOT/'dist';dist.mkdir(exist_ok=True)
# GitHub normalizes '~' in asset names. Keep Debian ordering inside control,
# and use the canonical SemVer in the portable download filename.
package=dist/f'vpn_{version}_amd64.deb'
if any(p.name!=package.name for p in dist.glob('*.deb')):
 raise RuntimeError('dist contains another release; archive it before building this version.')
subprocess.run(['dpkg-deb','--threads-max=1','-Zxz','-z6','--root-owner-group','--build',str(root),str(package)],check=True)
for name in ('setup.sh','update.sh'):shutil.copy2(ROOT/name,dist/name)
manifest={'schema':1,'version':version,'platform':'ubuntu-24.04-amd64','assets':{p.name:{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'size':p.stat().st_size} for p in (package,dist/'setup.sh',dist/'update.sh')}}
(dist/'manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
(dist/'SHA256SUMS').write_text(''.join(v['sha256']+'  '+n+'\n' for n,v in sorted(manifest['assets'].items())))
key=os.environ.get('VPN_RELEASE_KEY')
if key:
 subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',key,'-in',str(dist/'manifest.json'),'-out',str(dist/'manifest.sig')],check=True)
 print('Signed manifest written to',dist)
else:print('Unsigned local build: set VPN_RELEASE_KEY to sign a tested release.')
