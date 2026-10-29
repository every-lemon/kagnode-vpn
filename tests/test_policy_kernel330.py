"""Real XFRM identifiers and netfilter rules, isolated from the host network."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from test_manager import ROOT


@unittest.skipUnless(os.geteuid() == 0 and shutil.which('unshare') and shutil.which('iptables'), 'requires network namespace privileges')
class KernelPolicyTests(unittest.TestCase):
    def test_kernel_reqid_spi_grants_rekey_and_deny_rules(self):
        if not shutil.which('wg'):
            self.skipTest('WireGuard tools required')
        if subprocess.run(['unshare', '--net', 'true'], capture_output=True).returncode:
            self.skipTest('network namespaces unavailable')
        program = r'''
import json,sys,tempfile
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import manage as m
import vpn_policy as p
with tempfile.TemporaryDirectory() as tmp:
 m.BASE=Path(tmp);m.STATE=m.BASE/'state.json';m.ETC=m.BASE/'etc'
 m.save(dict(installed=True,clients={},lan='192.168.0.8',lan_net='192.168.0.0/24',public='8.8.8.8',wg_net='10.66.66.0/24',ike_net='192.168.43.0/24',l2tp_net='192.168.42.0/24'))
 b=m.clients_backend();b.migrate();u=b.user_add('Test');d=b.device_add(u,'Phone')
 m.command(['ip','link','add','wg0','type','wireguard'])
 private=m.command(['wg','genkey']).stdout.strip();public=m.command(['wg','pubkey'],data=private+'\n').stdout.strip()
 m.command(['wg','set','wg0','peer',public,'allowed-ips','10.66.66.2/32'])
 state_data=m.load();state_data['clients']['native-wg']={'wireguard':{'address':'10.66.66.2','public':public}};m.save(state_data)
 reg=b.load();reg['devices'][d]['protocols']={'wireguard':{'backend':'native-wg','status':'active'},'ikev2':{'backend':d,'status':'active'}};b.save(reg)
 from vpn_business import Business
 business=Business(b.repo)
 resource=business.change(dict(action='resource-save',name='LAN',cidr='192.168.0.0/24',protocol='any',ports=''))
 allow=dict(rules=[dict(effect='allow',resource=resource)])
 business.change(dict(action='access-policy',kind='device',id=d,policy=json.dumps(allow)))
 m.atomic(m.BASE/'policy-installed','yes')
 def command(args):return m.command(args)
 def state(spi,reqid=42):
  command(['ip','xfrm','state','add','src','203.0.113.1','dst','192.168.0.8','proto','esp','spi',hex(spi),'reqid',str(reqid),'mode','tunnel','auth','sha256','0x'+'11'*32,'enc','aes','0x'+'22'*16])
 def event(spi,up=True):p.event(b,dict(protocol='ikev2',up=up,identity=d,address='192.168.43.12',reqid=42,spi=hex(spi)))
 def rule(spi):return ['iptables','-C','VPNSTACK-LAN-FWD','-s','192.168.43.12','-m','policy','--dir','in','--pol','ipsec','--proto','esp','--reqid','42','--spi',p.policy_spi(spi),'-d','192.168.0.0/24','-j','RETURN']
 state(256);event(256);command(rule(256))
 # Canonical iptables-save formatting differs from generated source text.
 # An idle reconcile must skip writes, but detect and repair external damage.
 original=b.m.command
 calls=[]
 def tracked(args,**kwargs):
  calls.append(args[0]);return original(args,**kwargs)
 b.m.command=tracked
 p.apply(b,skip_unchanged=True)
 assert 'iptables-restore' not in calls,calls
 command(['iptables','-F','VPNSTACK-LAN-IN'])
 p.apply(b,skip_unchanged=True)
 assert calls.count('iptables-restore')==1,calls
 b.m.command=original

 state(257);event(257);event(256,False);command(rule(257))
 assert m.command(rule(256),check=False).returncode!=0
 command(['iptables','-C','VPNSTACK-LAN-IN','-i','wg0','-s','10.66.66.2','-d','192.168.0.8','-p','udp','--dport','53','-j','RETURN'])
 command(['iptables','-C','VPNSTACK-LAN-IN','-j','DROP'])
 command(['iptables','-C','VPNSTACK-LAN-FWD','-i','wg0','-s','10.66.66.2','-d','192.168.0.0/24','-j','RETURN'])
 # Boot/rebuild: a missing WireGuard interface must not break firewall startup
 # or retain a grant. Reconcile again after wg-quick recreates its exact peer.
 command(['ip','link','delete','wg0']);p.apply(b)
 assert not any('wg0' in row for ident,row in p.grants(b,identities=True))
 command(['iptables','-C','VPNSTACK-LAN-FWD','-j','DROP'])
 command(['ip','link','add','wg0','type','wireguard'])
 command(['wg','set','wg0','peer',public,'allowed-ips','10.66.66.2/32']);p.apply(b)
 command(['iptables','-C','VPNSTACK-LAN-FWD','-i','wg0','-s','10.66.66.2','-d','192.168.0.0/24','-j','RETURN'])
 business.change(dict(action='access-policy',kind='device',id=d,policy='{}'));p.apply(b)
 assert m.command(rule(257),check=False).returncode!=0
 command(['iptables','-C','VPNSTACK-LAN-FWD','-i','wg0','-s','10.66.66.2','-d','192.168.0.0/24','-j','DROP'])
 # A reused source address with a different SA cannot match the old grant.
 command(['ip','xfrm','state','delete','src','203.0.113.1','dst','192.168.0.8','proto','esp','spi',hex(257)])
 business.change(dict(action='access-policy',kind='device',id=d,policy=json.dumps(allow)));p.apply(b)
 assert m.command(rule(257),check=False).returncode!=0
 # PPP grants also bind the kernel interface generation via devgroup, not its reusable name.
 reg=b.load();reg['devices'][d]['protocols']['l2tp']={'backend':d,'status':'active'};b.save(reg)
 command(['ip','link','add','ppp0','type','dummy'])
 command(['ip','addr','add','192.168.42.1','peer','192.168.42.12','dev','ppp0'])
 p.event(b,dict(protocol='l2tp',up=True,identity=d,address='192.168.42.12',interface='ppp0'))
 rows=p.grants(b,identities=True);ppp=next(row for ident,row in rows if 'ppp0' in row)
 assert '--src-group' in ppp
 command(['ip','link','delete','ppp0'])
 command(['ip','link','add','ppp0','type','dummy'])
 assert not any('ppp0' in row for ident,row in p.grants(b,identities=True))
 # Revoked sessions are denied all traffic, bound to the authenticated SPI.
 state(258);event(258)
 reg=b.load();reg['devices'][d]['protocols']['ikev2']['status']='revoked';b.save(reg)
 p.apply(b)
 deny=['iptables','-C','VPNSTACK-LAN-FWD','-s','192.168.43.12','-m','policy','--dir','in','--pol','ipsec','--proto','esp','--reqid','42','--spi',p.policy_spi(258),'-j','DROP']
 command(deny)
 command(['ip','xfrm','state','delete','src','203.0.113.1','dst','192.168.0.8','proto','esp','spi',hex(258)])
 state(259);p.apply(b)
 assert m.command(deny,check=False).returncode!=0
 # Removing the controller pauses only managed tunnel pools, ahead of other rules.
 p.quiesce(m)
 for network in ('10.66.66.0/24','192.168.43.0/24','192.168.42.0/24'):
  for chain in ('INPUT','FORWARD'):
   command(['iptables','-C',chain,'-s',network,'-j','VPNSTACK-MAINT'])
 command(['iptables','-C','VPNSTACK-MAINT','-j','DROP'])
 saved=command(['iptables-save','-t','filter']).stdout
 assert '-A INPUT -s 192.168.0.0/24 -j VPNSTACK-MAINT' not in saved
 print('XFRM, rekey, PPP interface reuse, policy overrides, revocation isolation and DNS exceptions verified')
'''
        result = subprocess.run(['unshare', '--net', sys.executable, '-c', program, str(ROOT / 'src')], capture_output=True, text=True, timeout=40)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
