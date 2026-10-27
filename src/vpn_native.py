"""Ubuntu package engine setup; explicit setup only, never a repair action."""
import base64
import ipaddress
import re
import shutil
from pathlib import Path


def install(manager):
    state = manager.load()
    encoded='@@IKE_HELPER@@'
    helper=base64.b64decode(encoded).decode() if not encoded.startswith('@@') else Path(__file__).with_name('vendor').joinpath('ikev2.sh').read_text()
    manager.atomic(manager.BASE/'upstream/ikev2.sh',helper,0o700)
    # A working local engine takes precedence; do not install an older distro engine over it.
    engine = shutil.which('ipsec')
    if engine:
        info = manager.command([engine, '--version']).stdout
        if 'Libreswan' not in info:
            raise RuntimeError('Existing IPsec provider is not Libreswan; no engine was replaced.')
        found=re.search(r'Libreswan\s+(\d+)\.(\d+)',info)
        if not found or tuple(map(int,found.groups()))<(4,14):
            raise RuntimeError('Existing Libreswan is older than the supported Ubuntu engine. Upgrade it deliberately before setup; it was not overwritten.')
    manager.atomic(manager.BASE/'ipsec-partial','yes\n')
    if not engine:
        manager.command(['apt-get','-y','-o','DPkg::Lock::Timeout=120','install','libreswan'], timeout=600)
    manager.command(['apt-get','-y','-o','DPkg::Lock::Timeout=120','install','xl2tpd','libnss3-tools','ppp'], timeout=600)
    config = manager.ETC / 'ipsec.conf'
    virtual='%v4:10.0.0.0/8,%v4:172.16.0.0/12,%v4:192.168.0.0/16,%v4:100.64.0.0/10'
    virtual+=''.join(',%v4:!'+state[k] for k in ('wg_net','ike_net','l2tp_net'))
    manager.atomic(config, 'config setup\n  uniqueids=no\n  ikev1-policy=accept\n  virtual-private='+virtual+'\ninclude /etc/ipsec.d/*.conf\n')
    db = manager.ETC / 'ipsec.d'
    db.mkdir(mode=0o700,parents=True,exist_ok=True)
    certdb = 'sql:' + str(db)
    if not (db / 'cert9.db').exists():
        manager.command(['certutil','-N','--empty-password','-d',certdb])
    def exists(name):
        return manager.command(['certutil','-L','-d',certdb,'-n',name],check=False).returncode == 0
    noise = manager.BASE / 'nss-noise'
    import secrets
    manager.atomic(noise,secrets.token_bytes(2048))
    common=['certutil','-S','-d',certdb,'-z',str(noise),'-k','rsa','-g','3072','-v','120']
    ca='IKEv2 VPN CA'; server=state['endpoint']
    try:
        if not exists(ca):
            manager.command(common+['-m',str(secrets.randbelow(2**31-1)+1),'-x','-n',ca,'-s','O=IKEv2 VPN,CN='+ca,'-t','CT,,','-2'],data='y\n\nN\n')
        if not exists(server):
            try:
                ipaddress.IPv4Address(server); san='ip:'+server+',dns:'+server
            except ValueError:
                san='dns:'+server
            manager.command(common+['-m',str(secrets.randbelow(2**31-1)+1),'-c',ca,'-n',server,'-s','O=IKEv2 VPN,CN='+server,'-t',',,','--keyUsage','digitalSignature,keyEncipherment','--extKeyUsage','serverAuth','--extSAN',san])
    finally:
        noise.unlink(missing_ok=True)
    try:
        ipaddress.IPv4Address(server);identity=server
    except ValueError:identity='@'+server
    ike=ipaddress.IPv4Network(state['ike_net']); l2tp=ipaddress.IPv4Network(state['l2tp_net'])
    manager.atomic(db/'ikev2.conf', f'''conn ikev2-cp
  left=%defaultroute
  leftid={identity}
  leftcert={server}
  leftsendcert=always
  leftsubnet=0.0.0.0/0
  leftrsasigkey=%cert
  right=%any
  rightid=%fromcert
  rightca=%same
  rightrsasigkey=%cert
  rightaddresspool={ike[10]}-{ike[250]}
  modecfgdns={state['lan']}
  modecfgserver=yes
  modecfgpull=yes
  narrowing=yes
  ikev2=insist
  fragmentation=yes
  dpddelay=30
  dpdtimeout=120
  dpdaction=clear
  auto=add
''')
    manager.atomic(db/'l2tp.conf', '''conn l2tp-psk
  authby=secret
  pfs=no
  auto=add
  rekey=no
  type=transport
  left=%defaultroute
  leftprotoport=17/1701
  right=%any
  rightprotoport=17/%any
  ikev2=never
  dpddelay=30
  dpdtimeout=120
  dpdaction=clear

conn l2tp-psk-nat
  also=l2tp-psk
  rightsubnet=vhost:%priv
''')
    manager.atomic(manager.ETC/'ipsec.secrets', '%any %any : PSK "'+state['psk']+'"\n')
    manager.atomic(manager.ETC/'xl2tpd/xl2tpd.conf',f'''[global]
port = 1701
ipsec saref = no
force userspace = no
[lns default]
ip range = {l2tp[10]}-{l2tp[250]}
local ip = {l2tp[1]}
require authentication = yes
require chap = yes
refuse pap = yes
name = l2tpd
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
''')
    manager.atomic(manager.ETC/'ppp/options.xl2tpd',f'''ipcp-accept-local
ipcp-accept-remote
ms-dns {state['lan']}
noccp
auth
require-mschap-v2
refuse-pap
refuse-chap
refuse-mschap
mtu 1280
mru 1280
lock
hide-password
name l2tpd
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
''')
    # No starter identity is created. Existing credentials are never rewritten on resume.
    if not (manager.ETC/'ppp/chap-secrets').exists():
        manager.atomic(manager.ETC/'ppp/chap-secrets', '# VPN managed clients\n')
    manager.command(['ipsec','addconn','--checkconfig'])
    manager.command(['systemctl','enable','--now','ipsec','xl2tpd'])
    manager.command(['systemctl','restart','ipsec','xl2tpd'])
    for flag in ('ipsec-base-installed','ipsec-installed'):
        manager.atomic(manager.BASE/flag,'yes\n')
    (manager.BASE/'ipsec-partial').unlink(missing_ok=True)
