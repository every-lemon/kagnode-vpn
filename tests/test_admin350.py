"""Device views, authenticated attachments and existing delivery publication."""
import base64
import contextlib
import io
import json
import re
from pathlib import Path
import subprocess
import types
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, urlsplit, parse_qs
import test_manager as tm
from test_manager import m
import vpn_admin as admin
import vpn_web as web
from vpn_backend import bundle


class AdminTests(unittest.TestCase):
    def setUp(self):
        tm.RuntimeTests.setUp(self)
        self.backend = m.clients_backend()
        self.backend.migrate()
        self.user = self.backend.user_add('Example User')
        self.ident = self.backend.device_add(self.user, 'Example Phone')
        reg = self.backend.load()
        reg['devices'][self.ident]['protocols']['wireguard'] = {'backend': 'native-phone', 'status': 'active'}
        self.backend.save(reg)
        m.atomic(self.base / 'clients/wireguard/native-phone.conf', 'PRIVATE_WIREGUARD_BYTES')
        m.atomic(self.base / 'web-enabled', 'yes')
        self.store = web.Store(self.backend.repo.path)
        from vpn_auth import totp
        enrolled=self.store.create_admin('owner','management-password-350','owner')
        self.actor=enrolled['id']
        recovery=self.store.enroll(enrolled['enrollment'],totp(enrolled['secret'],int(self.store.clock()//30)))
        self.session,self.csrf=self.store.login('management-password-350',username='owner',code=recovery[0])
        self.state = m.load() | {'lan_net': '192.168.0.0/24'}
        with patch.object(self.backend.m, 'load', return_value=self.state):
            self.controller = web.Controller(self.backend, self.store)

    def tearDown(self):
        tm.RuntimeTests.tearDown(self)

    def rpc(self, request):
        return self.controller.handle(request, 0)

    def request(self, path, method='GET', form=None, authenticated=True, csrf=True):
        values = dict(form or {})
        if csrf:
            values['csrf'] = self.csrf
        payload = urlencode(values).encode()
        route, _, query = path.partition('?')
        env = {'REQUEST_METHOD': method, 'PATH_INFO': route, 'QUERY_STRING': query,
               'HTTP_HOST': '192.168.0.8:9001', 'HTTP_ORIGIN': 'http://192.168.0.8:9001',
               'REMOTE_ADDR': '192.168.0.22', 'HTTP_COOKIE': 'vpn_session=' + self.session if authenticated else '',
               'CONTENT_TYPE': 'application/x-www-form-urlencoded', 'CONTENT_LENGTH': str(len(payload)),
               'wsgi.input': io.BytesIO(payload)}
        results = []
        body = b''.join(web.Application(self.state, 'management', rpc_call=self.rpc)(env, lambda status, headers: results.extend([status, dict(headers)])))
        if results[0]=='303 See Other' and path=='/manage/action' and results[1].get('Location','').startswith('/manage'):
            return self.request(results[1]['Location'], authenticated=authenticated)
        return results[0], results[1], body

    def test_devices_are_separate_searchable_and_have_protocol_appropriate_exports(self):
        overview = self.request('/manage')[2]
        self.assertNotIn(b'Prepare selected profiles', overview)
        devices = self.request('/manage/devices')[2]
        self.assertIn(b'Example Phone', devices)
        self.assertNotIn(b'Example Phone', self.request('/manage/devices?q=missing')[2])
        detail = self.request('/manage/device?device=' + self.ident)[2]
        self.assertIn(b'Download WIREGUARD profile', detail)
        self.assertNotIn(b'Download p12', detail)
        self.assertIn(b'Download email as HTML', detail)
        self.assertIn(b'Prepare selected profiles', detail)
        self.assertNotIn(b'animation:', detail)
        self.assertIn(b'data-management', detail)
        self.assertIn(b'/manage/status', detail)

    def test_admin_native_download_requires_session_and_csrf_and_keeps_bytes(self):
        form = {'device': self.ident, 'kind': 'wireguard'}
        for authenticated, csrf in ((False, True), (True, False)):
            self.assertEqual(self.request('/manage/file', 'POST', form, authenticated, csrf)[0], '403 Forbidden')
        status, headers, body = self.request('/manage/file', 'POST', form)
        self.assertEqual(status, '200 OK')
        self.assertEqual(body, b'PRIVATE_WIREGUARD_BYTES')
        self.assertIn('attachment;', headers['Content-Disposition'])
        self.assertEqual(headers['Cache-Control'], 'no-store')

    def test_prepare_wireguard_native_delivery_without_requiring_ikev2_or_zip(self):
        result = self.controller.action({'actor': self.actor, 'action': 'prepare-export', 'device': self.ident, 'protocols': 'wireguard'})
        self.assertIn('Native profiles ready', result['message'])
        detail = self.request('/manage/device?device=' + self.ident)[2]
        self.assertIn(b'Download email as HTML', detail)
        with self.backend.repo.connect() as db:
            self.assertIsNone(db.execute('SELECT 1 FROM deliveries WHERE device=?',(self.ident,)).fetchone())
        # Explicit ZIP creation remains available for existing archive workflows.
        self.controller.action({'actor': self.actor, 'action':'bundle','device':self.ident,'protocols':'wireguard'})
        status,headers,body=self.request('/manage/file','POST',{'device':self.ident,'kind':'delivery'})
        self.assertEqual(status,'200 OK')
        self.assertTrue(body.startswith(b'PK'))

    def test_html_email_uses_existing_one_time_delivery_without_passwords(self):
        meta = bundle(self.backend, self.ident, ['wireguard'])
        status, headers, body = self.request('/manage/file', 'POST', {'device': self.ident, 'kind': 'email'})
        self.assertEqual(status, '200 OK')
        self.assertIn('.html', headers['Content-Disposition'])
        self.assertIn(b'KagNode. VPN', body)
        self.assertIn(b'data:image/svg+xml,', body)
        self.assertIn(b':9000/?token=', body)
        self.assertNotIn(meta['password'].encode(), body)
        self.assertNotIn(b'PRIVATE_WIREGUARD_BYTES', body)
        self.assertIn(b'15', self.request('/manage/device?device=' + self.ident)[2])
        token = body.decode().split('?token=', 1)[1].split('"', 1)[0]
        record = self.store.inspect(token)
        self.store.claim(token, record['confirm'])
        with self.assertRaises(web.WebError):
            self.store.inspect(token)

    def test_html_email_preserves_configured_delivery_https_without_passwords(self):
        meta = bundle(self.backend, self.ident, ['wireguard'])
        self.state['vpd_origin'] = 'https://profiles.example.com'
        self.controller.state = self.state
        status, headers, body = self.request('/manage/file', 'POST', {'device': self.ident, 'kind': 'email'})
        self.assertEqual(status, '200 OK')
        self.assertIn('.html', headers['Content-Disposition'])
        url = re.search(rb'<a href="([^"]+)">', body).group(1).decode()
        parsed = urlsplit(url)
        self.assertEqual((parsed.scheme, parsed.netloc, parsed.path), ('https', 'profiles.example.com', '/'))
        self.assertNotIn(b'http://', body)
        self.assertNotIn(b':9000/', body)
        self.assertNotIn(meta['password'].encode(), body)
        self.assertNotIn(b'PRIVATE_WIREGUARD_BYTES', body)
        token = parse_qs(parsed.query)['token'][0]
        self.assertEqual(self.store.inspect(token)['device'], self.ident)

    def test_prepared_delivery_does_not_replace_acting_administrator_in_device_view(self):
        bundle(self.backend,self.ident,['wireguard'])
        data=self.rpc(dict(op='view',session=self.session,peer='192.168.0.22',host='192.168.0.8:9001',view='device',device=self.ident))
        self.assertEqual(data['identity']['id'],self.actor)
        self.assertEqual(data['identity']['role'],'owner')
        from vpn_dashboard import render
        self.assertIn(b'app-shell',render(data,view='device',device=self.ident))

    def test_public_delivery_null_origin_form_claims_once_and_keeps_referrer_private(self):
        meta = bundle(self.backend, self.ident, ['wireguard'])
        token = self.store.issue(self.ident, meta['filename'], meta['generation'])
        application = web.Application(self.state, 'downloads', rpc_call=self.rpc)
        def request(method, path, data=None, origin='null'):
            raw = urlencode(data or {}).encode()
            env = {'REQUEST_METHOD': method, 'PATH_INFO': path, 'QUERY_STRING': 'token=' + token,
                   'HTTP_HOST': '192.168.0.8:9000', 'HTTP_ORIGIN': origin, 'REMOTE_ADDR': '8.8.4.4',
                   'CONTENT_TYPE': 'application/x-www-form-urlencoded', 'CONTENT_LENGTH': str(len(raw)), 'wsgi.input': io.BytesIO(raw)}
            result = []
            body = b''.join(application(env, lambda status, headers: result.extend([status, dict(headers)])))
            return result[0], result[1], body
        _, headers, landing = request('GET', '/')
        self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
        confirm = re.search(rb'name="confirm" value="([^"]+)"', landing).group(1).decode()
        form = {'token': token, 'confirm': confirm}
        self.assertEqual(request('POST', '/download', form, 'http://evil.test')[0], '403 Forbidden')
        self.assertEqual(request('POST', '/download', {'token': token, 'confirm': 'invalid'})[0], '403 Forbidden')
        status, headers, payload = request('POST', '/download', form)
        self.assertEqual(status, '200 OK')
        self.assertTrue(payload.startswith(b'PK'))
        self.assertEqual(request('POST', '/download', form)[0], '403 Forbidden')

    def apple_fixture(self):
        import plistlib
        import hashlib
        filename = self.ident + '.mobileconfig'
        payload = plistlib.dumps({'PayloadType': 'Configuration', 'PayloadVersion': 1, 'PayloadDisplayName': 'Example Phone', 'PayloadContent': []})
        m.atomic(self.base / 'exports' / self.ident / 'apple-generation' / filename, payload)
        reg = self.backend.load()
        reg['devices'][self.ident]['protocols']['ikev2'] = {'backend': 'native-apple', 'status': 'active', 'export': {'generation': 'apple-generation', 'files': [filename], 'sha256': {filename: hashlib.sha256(payload).hexdigest()}}}
        self.backend.save(reg)
        return filename, payload

    def test_apple_push_is_mobileconfig_and_safari_get_receives_profile_mime(self):
        filename, payload = self.apple_fixture()
        published = self.controller.action({'actor': self.actor, 'action': 'delivery-link', 'device': self.ident, 'scope':'file'})
        token = parse_qs(urlsplit(published['url']).query)['token'][0]
        self.assertIn(self.store.inspect(token)['filename'], (filename,'@device'))
        app = web.Application(self.state, 'downloads', rpc_call=self.rpc)
        def public(method, target, form=None):
            url = urlsplit(target)
            raw = urlencode(form or {}).encode()
            env = {'REQUEST_METHOD': method, 'PATH_INFO': url.path, 'QUERY_STRING': url.query,
                'HTTP_HOST': '192.168.0.8:9000', 'HTTP_ORIGIN': 'null', 'REMOTE_ADDR': '8.8.4.4',
                'CONTENT_TYPE': 'application/x-www-form-urlencoded', 'CONTENT_LENGTH': str(len(raw)), 'wsgi.input': io.BytesIO(raw)}
            result = []
            body = b''.join(app(env, lambda status, headers: result.extend([status, dict(headers)])))
            return result[0], result[1], body
        self.assertEqual(public('GET', '/?token=' + token)[0], '200 OK')
        self.assertIn(self.store.inspect(token)['filename'], (filename,'@device'))
        record = self.store.inspect(token)
        status, headers, _ = public('POST', '/download', {'token': token, 'confirm': record['confirm']})
        self.assertEqual(status, '303 See Other')
        target = headers['Location']
        self.assertEqual(urlsplit(target).path, '/profile.mobileconfig')
        self.assertEqual(public('HEAD', target)[0], '404 Not Found')
        status, headers, body = public('GET', target)
        self.assertEqual(status, '200 OK')
        self.assertEqual(headers['Content-Type'], 'application/x-apple-aspen-config')
        self.assertTrue(headers['Content-Disposition'].startswith('inline;'))
        self.assertEqual(body, payload)
        self.assertFalse(body.startswith(b'PK'))
        self.assertEqual(public('GET', target)[0], '403 Forbidden')

    def test_admin_apple_download_and_email_use_native_profile_without_zip(self):
        filename, payload = self.apple_fixture()
        status, headers, body = self.request('/manage/file', 'POST', {'device': self.ident, 'kind': 'ikev2', 'filename': filename})
        self.assertEqual(body, payload)
        self.assertEqual(headers['Content-Type'], 'application/x-apple-aspen-config')
        self.assertTrue(headers['Content-Disposition'].startswith('inline;'))
        status, _, body = self.request('/manage/file', 'POST', {'device': self.ident, 'kind': 'email'})
        self.assertEqual(status, '200 OK')
        self.assertIn(b'open in Safari', body)
        token = body.decode().split('?token=', 1)[1].split('"', 1)[0]
        self.assertIn(self.store.inspect(token)['filename'], (filename,'@device'))
        self.assertNotIn(b'ZIP password', body)
        self.assertIn(b'Download email as HTML', self.request('/manage/device?device=' + self.ident)[2])

    def test_revoked_profiles_disappear_without_resurrecting_delivery_tokens(self):
        filename, _ = self.apple_fixture()
        token = parse_qs(urlsplit(self.controller.action({'actor': self.actor, 'action': 'delivery-link', 'device': self.ident, 'scope':'file'})['url']).query)['token'][0]
        reg = self.backend.load()
        reg['devices'][self.ident]['protocols']['ikev2']['status'] = 'revoked'
        self.backend.save(reg)
        detail = self.request('/manage/device?device=' + self.ident)[2]
        self.assertNotIn(b'Revoke IKEV2', detail)
        self.assertNotIn(b'Create delivery link', detail)
        self.assertNotIn(filename.encode(), detail)
        with self.assertRaises(web.WebError):
            self.rpc({'op': 'inspect', 'token': token})
        reg = self.backend.load()
        reg['devices'][self.ident]['protocols']['wireguard']['status'] = 'revoked'
        self.backend.save(reg)
        self.assertNotIn(b'Example Phone', self.request('/manage/devices')[2])
        self.assertIn(b'Profile removed', self.request('/manage/device?device=' + self.ident)[2])
        self.assertIn(self.ident, self.backend.load()['devices'])

    def test_revoked_and_unsafe_profiles_cannot_download_or_publish(self):
        bundle(self.backend, self.ident, ['wireguard'])
        reg = self.backend.load()
        reg['devices'][self.ident]['protocols']['wireguard']['status'] = 'revoked'
        self.backend.save(reg)
        for kind in ('wireguard', 'delivery', 'email'):
            self.assertEqual(self.request('/manage/file', 'POST', {'device': self.ident, 'kind': kind})[0], '403 Forbidden')

    def test_ikev2_export_is_rejected_before_queueing_on_wireguard_only_device(self):
        before = len(self.backend.repo.jobs())
        status, _, body = self.request('/manage/action', 'POST', {'action': 'export', 'device': self.ident, 'platform': 'apple'})
        self.assertEqual(status, '422 Unprocessable Entity')
        self.assertIn(b'active IKEv2', body)
        self.assertEqual(len(self.backend.repo.jobs()), before)

    def test_job_failure_reason_and_device_name_are_visible_without_passwords(self):
        task = self.backend.repo.enqueue({'actor':self.actor, 'action': 'prepare-export', 'device': self.ident, 'protocols': 'ikev2'})
        self.backend.repo.run_one(self.backend, self.controller.action)
        body = self.request('/manage/jobs')[2]
        self.assertIn(b'Example Phone', body)
        self.assertIn(b'Configure the selected protocols first', body)
        self.assertIn(task.encode(), body)
        self.assertNotIn(b'management-password-350', body)

    def test_tool_failure_diagnostic_redacts_password_and_private_stdout(self):
        password = 'private export password'
        path = self.base / 'password'
        m.atomic(path, password)
        result = subprocess.CompletedProcess([], 1, b'PRIVATE_KEY_IN_STDOUT', ('SEC_ERROR_BAD_DATABASE ' + password).encode())
        with patch('subprocess.run', return_value=result):
            with self.assertRaisesRegex(RuntimeError, 'SEC_ERROR_BAD_DATABASE'):
                self.backend.command(['pk12util', '-w', path])
        log = self.base / 'logs/client-tool-failure-latest.json'
        content = log.read_text()
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(password, content)
        self.assertNotIn('PRIVATE_KEY_IN_STDOUT', content)
        self.assertIn('SEC_ERROR_BAD_DATABASE', content)

    def test_css_is_hash_authorized_and_management_referrer_fix_remains(self):
        _, headers, body = self.request('/manage/devices')
        self.assertIn("style-src 'sha256-", headers['Content-Security-Policy'])
        self.assertNotIn('unsafe-inline', headers['Content-Security-Policy'])
        self.assertEqual(headers['Referrer-Policy'], 'same-origin')
