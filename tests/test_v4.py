"""VPN 4 acceptance tests; no host service/package/network mutations."""
import concurrent.futures
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from vpn_auth import AuthError,totp,permitted
from vpn_web import Store,Controller,WebError,unit_files
from vpn_backend import Repository
from vpn_business import Business,DEFAULT_GROUP
from vpn_version import parse,debian,eligible

class Clock:
    def __init__(self): self.now=1800000000
    def __call__(self): return self.now

class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.clock=Clock(); self.store=Store(Path(self.tmp.name)/'db',clock=self.clock,boot='boot1')
        self.owner=self.store.create_admin('owner','correct-test-password','owner')
        self.codes=self.store.enroll(self.owner['enrollment'],totp(self.owner['secret'],self.clock.now//30))
        self.clock.now+=30
    def login(self,code=None):
        return self.store.login('correct-test-password','127.0.0.1','owner',code or totp(self.owner['secret'],self.clock.now//30))
    def test_rfc_totp_vector(self):
        self.assertEqual(totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',1),'287082')
    def test_password_alone_cannot_login(self):
        with self.assertRaises(AuthError): self.login('') if False else self.store.login('correct-test-password','x','owner','')
    def test_unknown_user_fails(self):
        with self.assertRaises(AuthError): self.store.login('correct-test-password','x','nobody','123456')
    def test_replay_denied(self):
        self.login()
        with self.assertRaises(AuthError): self.login()
    def test_concurrent_code_only_one_success(self):
        def attempt(_):
            try: self.login(); return True
            except AuthError: return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(sum(pool.map(attempt,range(4))),1)
    def test_recovery_single_use_and_hashed(self):
        self.login(self.codes[0])
        with self.assertRaises(AuthError): self.login(self.codes[0])
        self.assertNotIn(self.codes[1].encode(),self.store.path.read_bytes())
    def test_poll_does_not_extend_idle(self):
        session,csrf=self.login(); self.clock.now+=1799
        self.assertEqual(int(self.store.remaining(session)),1)
        self.clock.now+=1
        with self.assertRaises(AuthError): self.store.session(session)
    def test_activity_extends_idle_but_not_absolute(self):
        session,csrf=self.login()
        for _ in range(28):
            self.clock.now+=1000; self.store.identity(session,csrf,touch=True)
        self.clock.now+=800
        with self.assertRaises(AuthError): self.store.identity(session,touch=True)
    def test_session_boot_binding(self):
        session,_=self.login(); self.store.boot='boot2'
        with self.assertRaises(AuthError): self.store.session(session)
    def test_csrf(self):
        session,_=self.login()
        with self.assertRaises(AuthError): self.store.identity(session,'incorrect',touch=True)
    def test_successes_not_failures(self):
        for code in self.codes[:7]: self.login(code)
        with self.store.connect() as db: self.assertEqual(db.execute('SELECT count(*) FROM login_failures').fetchone()[0],0)
    def test_failures_rate_limited(self):
        for _ in range(5):
            with self.assertRaises(AuthError): self.store.login('incorrect-password','127.0.0.1','owner','000000')
        with self.assertRaisesRegex(AuthError,'limited'): self.login(self.codes[0])
        self.clock.now+=301; self.login(self.codes[0])
    def test_last_owner_protected(self):
        with self.assertRaisesRegex(AuthError,'last enabled owner'): self.store.admin_change(self.owner['id'],self.owner['id'],enabled=False)
    def test_role_change_invalidates_session(self):
        other=self.store.create_admin('second','correct-test-password','owner',self.owner['id'])
        self.store.enroll(other['enrollment'],totp(other['secret'],self.clock.now//30))
        session,_=self.login(); self.store.admin_change(other['id'],self.owner['id'],role='auditor')
        with self.assertRaises(AuthError): self.store.session(session)
    def test_bootstrap_is_one_time(self):
        with self.assertRaises(AuthError): self.store.create_admin('extra','correct-test-password','owner')
    def test_enrollment_not_session(self):
        with self.assertRaises(AuthError): self.store.session(self.owner['enrollment'])
    def test_enrollment_token_cannot_be_reused(self):
        with self.assertRaises(AuthError): self.store.enroll(self.owner['enrollment'],totp(self.owner['secret'],self.clock.now//30))
    def test_operator_and_auditor_scopes(self):
        self.assertTrue(permitted('operator','delivery-link'))
        self.assertFalse(permitted('operator','admin-add'))
        self.assertFalse(permitted('auditor','reveal'))
        self.assertFalse(permitted('owner','arbitrary-shell'))
    def test_revoked_actor_cannot_resume_job(self):
        other=self.store.create_admin('operator','correct-test-password','operator',self.owner['id'])
        self.store.enroll(other['enrollment'],totp(other['secret'],self.clock.now//30))
        self.store.require_actor(other['id'],'export')
        self.store.admin_change(self.owner['id'],other['id'],enabled=False)
        with self.assertRaises(AuthError): self.store.require_actor(other['id'],'export')

class BusinessTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.repo=Repository(self.tmp.name);self.business=Business(self.repo)
        self.registry={'users':{'u':{'name':'User'}},'devices':{'d':{'name':'Device','user':'u','protocols':{}}}}
        self.repo.save(self.registry)
    def resource(self,**kw):
        return self.business.change(dict(action='resource-save',name='Resource',cidr='192.168.10.0/24',protocol='tcp',ports='443',**kw))
    def test_empty_default_group(self):
        data=self.business.snapshot()
        self.assertEqual(data['groups'][DEFAULT_GROUP]['name'],'ungrouped clients'); self.assertFalse(data['members'])
    def test_default_internet_and_isolation(self):
        value=self.business.effective(self.registry,'d')
        self.assertTrue(value['internet']);self.assertTrue(value['isolation']);self.assertFalse(value['rules'])
        self.assertFalse(self.business.preview(self.registry,'d','192.168.0.1','tcp',443)['allowed'])
        self.assertTrue(self.business.preview(self.registry,'d','1.1.1.1','tcp',443)['allowed'])
    def test_deny_beats_user_and_device_grants(self):
        resource=self.resource()
        group=self.business.change({'action':'group-add','name':'Team','policy':json.dumps({'rules':[{'effect':'deny','resource':resource}]})})
        self.business.change({'action':'device-group','device':'d','group':group})
        self.business.change({'action':'access-policy','kind':'device','id':'d','policy':json.dumps({'rules':[{'effect':'allow','resource':resource}]})})
        self.assertFalse(self.business.preview(self.registry,'d','192.168.10.2','tcp',443)['allowed'])
    def test_port_scoped_grant(self):
        resource=self.resource()
        self.business.change({'action':'access-policy','kind':'user','id':'u','policy':json.dumps({'rules':[{'effect':'allow','resource':resource}]})})
        self.assertTrue(self.business.preview(self.registry,'d','192.168.10.2','tcp',443)['allowed'])
        self.assertFalse(self.business.preview(self.registry,'d','192.168.10.2','tcp',80)['allowed'])
        self.assertFalse(self.business.preview(self.registry,'d','192.168.10.2','udp',443)['allowed'])
    def test_invalid_ports(self):
        for port in ('0','65536','443;reboot'):
            with self.subTest(port=port), self.assertRaises(ValueError): self.business.change({'action':'resource-save','name':'bad','cidr':'10.0.0.0/8','protocol':'tcp','ports':port})
    def test_default_group_cannot_be_deleted(self):
        with self.assertRaises(ValueError): self.business.change({'action':'group-delete','id':DEFAULT_GROUP})
    def test_cannot_delete_referenced_deny(self):
        r=self.resource(); self.business.change({'action':'access-policy','kind':'device','id':'d','policy':json.dumps({'rules':[{'effect':'deny','resource':r}]})})
        with self.assertRaises(ValueError): self.business.change({'action':'resource-delete','id':r})
    def test_apply_failure_rolls_back_metadata(self):
        before=self.business.snapshot()
        def fail(candidate): raise RuntimeError('kernel verification failed')
        with self.assertRaises(RuntimeError): self.business.change({'action':'group-add','name':'temporary','policy':'{}'},apply=fail)
        self.assertEqual(self.business.snapshot(),before)
    def test_disabled_and_expired_override(self):
        for flag,value in (('disabled',True),('expires',1),('revoked',True)):
            with self.subTest(flag=flag):
                self.registry['devices']['d'][flag]=value
                self.assertTrue(self.business.effective(self.registry,'d')['blocked'])
                del self.registry['devices']['d'][flag]

class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=Store(Path(self.tmp.name)/'db')
    def test_one_claim_total_under_concurrency(self):
        token=self.store.issue('d','p.mobileconfig','gen');confirmation=self.store.inspect(token)['confirm']
        def claim(_):
            try:self.store.claim(token,confirmation);return True
            except WebError:return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool: self.assertEqual(sum(pool.map(claim,range(8))),1)
    def test_revocation_blocks_claim(self):
        from vpn_web import digest
        token=self.store.issue('d','p.mobileconfig','gen');self.store.revoke_token(digest(token))
        with self.assertRaises(WebError):self.store.inspect(token)
        self.assertEqual(self.store.token_history()[0]['status'],'revoked')
    def test_token_hash_only(self):
        token=self.store.issue('d','p.mobileconfig','gen');self.assertNotIn(token.encode(),self.store.path.read_bytes())
    def test_inspect_nonconsuming(self):
        token=self.store.issue('d','p.mobileconfig','gen')
        self.assertEqual(self.store.inspect(token)['confirm'],self.store.inspect(token)['confirm'])
        self.assertIsNone(self.store.token_history()[0].get('used'))

class ReleaseTests(unittest.TestCase):
    def test_version_order(self):
        versions=['4.0.0-beta.1','4.0.0-beta.2','4.0.0-beta.10','4.0.0-rc.1','4.0.0','4.0.1']
        self.assertEqual(sorted(versions,key=parse),versions)
    def test_invalid_versions(self):
        for v in ('04.0.0','4.0','4.0.0.-beta','4.0.0-beta.01','4.0.0-rc.0'):
            with self.subTest(v=v),self.assertRaises(ValueError):parse(v)
    def test_debian_prerelease_and_stable_selection(self):
        self.assertEqual(debian('4.0.0-beta.1'),'4.0.0~beta.1')
        self.assertFalse(eligible('4.0.0-beta.1'));self.assertTrue(eligible('4.0.0'))
        result=subprocess.run(['dpkg','--compare-versions',debian('4.0.0-beta.1'),'lt',debian('4.0.0')]);self.assertEqual(result.returncode,0)
    def test_persistent_manager_native_paths(self):
        units=unit_files();self.assertNotIn('vpn-management-expire.timer',units)
        self.assertIn('WantedBy=multi-user.target',units['vpn-management.service'])
        self.assertNotIn('/root/', '\n'.join(units.values()))

if __name__=='__main__':unittest.main()
