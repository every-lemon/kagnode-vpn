"""HTTP authorization regressions updated for mandatory MFA and individual sessions."""
import json
import unittest
from unittest.mock import patch
import test_admin350 as fixture
import vpn_web as web
from auth_fixture import enroll

class AuthenticationTests(unittest.TestCase):
    setUp=fixture.AdminTests.setUp
    tearDown=fixture.AdminTests.tearDown
    request=fixture.AdminTests.request
    rpc=fixture.AdminTests.rpc
    def test_password_only_http_login_fails(self):
        status,_,_=self.request('/manage/login','POST',{'username':'owner','password':'management-password-350'},authenticated=False)
        self.assertEqual(status,'403 Forbidden')
    def test_login_logout_csrf_and_session_expiry(self):
        other,_,_,codes=enroll(self.store,'second','second-password-fixture','operator',self.actor)
        status,headers,_=self.request('/manage/login','POST',{'username':'second','password':'second-password-fixture','code':codes[1]},authenticated=False)
        self.assertEqual(status,'303 See Other');self.assertIn('HttpOnly',headers['Set-Cookie']);self.assertIn('SameSite=Strict',headers['Set-Cookie'])
        self.assertEqual(self.request('/manage/logout','POST',csrf=False)[0],'403 Forbidden')
        self.assertEqual(self.request('/manage/logout','POST')[0],'303 See Other')
        self.assertEqual(self.request('/manage/action','POST',{'action':'user-add','name':'denied'})[0],'403 Forbidden')
    def test_auditor_cannot_mutate_or_download_and_can_logout(self):
        _,self.session,self.csrf,_=enroll(self.store,'reader','auditor-password-fixture','auditor',self.actor)
        self.assertEqual(self.request('/manage')[0],'200 OK')
        for path,form in (('/manage/action',{'action':'user-add','name':'denied'}),('/manage/file',{'device':self.ident,'kind':'wireguard'})):
            self.assertEqual(self.request(path,'POST',form)[0],'403 Forbidden')
        self.assertEqual(self.request('/manage/logout','POST')[0],'303 See Other')
    def test_operator_cannot_forge_owner_actor(self):
        _,self.session,self.csrf,_=enroll(self.store,'operator','operator-password-fixture','operator',self.actor)
        status,_,_=self.request('/manage/action','POST',{'action':'admin-add','actor':self.actor,'username':'intruder','password':'long-password-fixture','role':'owner'})
        self.assertIn(status,('403 Forbidden','422 Unprocessable Entity'))
        with self.store.connect() as db:self.assertIsNone(db.execute("SELECT 1 FROM administrators WHERE username='intruder'").fetchone())
    def test_api_status_requires_session(self):
        self.assertEqual(self.request('/api/v1/status',authenticated=False)[0],'403 Forbidden')
        with patch.object(self.backend.m,'command') as command:
            command.return_value.stdout='active\n'*6
            self.assertEqual(self.request('/api/v1/status')[0],'200 OK')
