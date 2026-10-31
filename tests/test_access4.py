"""Proxy trust, delivery HTTPS and evidence-first repair regressions."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch
from test_manager import m
from vpn_access import configure,context
from vpn_repair import Doctor
from vpn_backend import Repository

class AccessTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.base=self.root/'var/lib/kagnode/vpn';self.base.mkdir(parents=True)
        self.state={'lan':'192.168.0.8','lan_net':'192.168.0.0/24','admin_devices':['device-one']}
        self.saved=None;self.calls=[]
        def save(value):self.saved=copy.deepcopy(value)
        def command(args,**kw):self.calls.append(args);return subprocess.CompletedProcess(args,0,'','')
        self.manager=types.SimpleNamespace(BASE=self.base,ETC=self.root/'etc',load=lambda:copy.deepcopy(self.state),save=save,atomic=m.atomic,command=command)
    def test_https_requires_confirmed_proxy(self):
        with self.assertRaisesRegex(ValueError,'Confirm'):configure(self.manager,{'mode':'https','origin':'https://admin.example.com','proxy':'192.168.0.2'})
        self.assertIsNone(self.saved)
    def test_settings_preserve_device_approvals_and_accept_delivery_https(self):
        value=configure(self.manager,{'mode':'vpn','vpd_origin':'https://profiles.example.com'})
        self.assertEqual(value['admin_devices'],['device-one']);self.assertEqual(value['vpd_origin'],'https://profiles.example.com')
    def test_invalid_delivery_origins_do_not_mutate_settings(self):
        for value in ('http://profiles.example.com','https://user:pass@profiles.example.com','https://profiles.example.com/path','https://profiles.example.com:9000','https://profiles.example.com/?token=secret'):
            with self.subTest(value=value),self.assertRaises(ValueError):configure(self.manager,{'mode':'lan','vpd_origin':value})
        self.assertIsNone(self.saved)
    def test_only_exact_proxy_can_assert_https(self):
        state=dict(self.state,admin_mode='https',trusted_proxy='192.168.0.2',admin_origin='https://admin.example.com')
        request={'peer':'192.168.0.2','host':'admin.example.com','origin':'https://admin.example.com','forwarded_proto':'https'}
        self.assertEqual(context(state,request),'https://admin.example.com')
        for change in ({'peer':'192.168.0.3'},{'forwarded_proto':'http'},{'origin':'https://attacker.example.com'},{'host':'attacker.example.com'}):
            with self.subTest(change=change),self.assertRaises(ValueError):context(state,request|change)
    def test_forged_forwarded_headers_do_not_override_lan_origin(self):
        request={'peer':'192.168.0.22','host':'192.168.0.8:9001','origin':'http://192.168.0.8:9001','forwarded_proto':'https'}
        self.assertEqual(context(self.state,request),'http://192.168.0.8:9001')

    def test_default_https_port_and_hostname_case_match_browser_origin(self):
        state=configure(self.manager,{'mode':'https','origin':'HTTPS://Admin.Example.com:443/','vpd_origin':'HTTPS://Profiles.Example.com:443/','proxy':'192.168.0.2','tls_verified':'yes'})
        self.assertEqual(state['admin_origin'],'https://admin.example.com')
        self.assertEqual(state['vpd_origin'],'https://profiles.example.com')
        self.assertEqual(context(state,{'peer':'192.168.0.2','host':'admin.example.com','origin':'https://admin.example.com','forwarded_proto':'https'}),'https://admin.example.com')

class RepairTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.base=self.root/'var/lib/kagnode/vpn';self.base.mkdir(parents=True)
        self.repo=Repository(self.base);self.calls=[];self.active=False
        def command(args,**kwargs):
            self.calls.append(args)
            if args[:2]==['systemctl','restart']:
                self.assertTrue(list((self.base/'logs').glob('repair-*.json')))
                self.active=True
            return subprocess.CompletedProcess(args,1 if args[:2]==['systemctl','is-active'] and not self.active else 0,'active' if self.active else 'failed','')
        self.manager=types.SimpleNamespace(BASE=self.base,ETC=self.root/'etc',atomic=m.atomic,command=command,clients_backend=lambda:types.SimpleNamespace(repo=self.repo))
        self.units={'vpn-management.service':'[Service]\nExecStart=/bin/true\n'}
    def test_records_evidence_repairs_owned_unit_and_verifies(self):
        unrelated=self.root/'etc/systemd/system/unrelated.service';m.atomic(unrelated,'leave alone')
        with patch('vpn_web.unit_files',return_value=self.units):result=Doctor(self.manager).repair()
        self.assertTrue(result['verified']);self.assertEqual(unrelated.read_text(),'leave alone')
        self.assertEqual((unrelated.parent/'vpn-management.service').read_text(),self.units['vpn-management.service'])
        self.assertFalse(any('apt-get' in c or 'certutil' in c or 'wg' in c for c in self.calls))
    def test_repeated_faults_stop_at_repair_budget(self):
        with patch('vpn_web.unit_files',return_value=self.units):
            for _ in range(2):self.active=False;Doctor(self.manager).repair()
            self.active=False
            before=len([c for c in self.calls if c[:2]==['systemctl','restart']])
            with self.assertRaisesRegex(RuntimeError,'limit reached'):Doctor(self.manager).repair()
        self.assertEqual(len([c for c in self.calls if c[:2]==['systemctl','restart']]),before)
    def test_interrupted_jobs_are_marked_without_replaying_operations(self):
        ident=self.repo.enqueue({'action':'export','device':'fixture','actor':'retired'})
        with self.repo.connect() as db:db.execute("UPDATE jobs SET status='running' WHERE id=?",(ident,))
        with patch('vpn_web.unit_files',return_value=self.units):Doctor(self.manager).repair()
        self.assertEqual(self.repo.jobs()[0]['status'],'interrupted')


class WireGuardIdentityTests(unittest.TestCase):
    def test_only_expected_live_key_and_exact_allowed_ip_receive_grants(self):
        import vpn_policy
        with tempfile.TemporaryDirectory() as folder:
            repo=Repository(folder)
            public='A'*43+'='
            registry={'users':{'u':{'name':'User'}},'devices':{'d':{'name':'Device','user':'u','protocols':{'wireguard':{'backend':'native','status':'active'}}}}}
            repo.save(registry)
            state={'clients':{'native':{'wireguard':{'public':public,'address':'10.66.66.2'}}}}
            def check(output):
                manager=types.SimpleNamespace(load=lambda:state,command=lambda *a,**k:subprocess.CompletedProcess(a,0,output,''))
                backend=types.SimpleNamespace(repo=repo,m=manager,load=lambda:registry)
                with patch.object(vpn_policy,'kernel_sessions',return_value=set()):return vpn_policy.grants(backend,identities=True)
            self.assertEqual(check('B'*43+'=\t10.66.66.2/32\n'),[])
            self.assertEqual(check(public+'\t10.66.66.0/24\n'),[])
            self.assertEqual(check(public+'\t10.66.66.3/32\n'),[])
            self.assertEqual(check(public+'\t10.66.66.2/32\n'),[('d',['-i','wg0','-s','10.66.66.2'])])
