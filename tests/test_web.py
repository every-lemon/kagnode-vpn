"""HTTP behavior, independent of system services or public interfaces."""
import concurrent.futures
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.parse import urlencode
from test_manager import m
import vpn_web as w


class WebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.now = 1000
        self.store = w.Store(self.root / 'access.db', lambda: self.now)

    def tearDown(self):
        self.tmp.cleanup()

    def test_management_individual_session_csrf_expiry_and_logout(self):
        from auth_fixture import enroll
        _,session,csrf,codes=enroll(self.store)
        with self.assertRaises(w.WebError):
            self.store.login('wrong-password','test','owner',codes[1])
        self.assertEqual(self.store.session(session),csrf)
        with self.assertRaises(w.WebError): self.store.session(session,'wrong')
        self.now+=1801
        with self.assertRaises(w.WebError): self.store.session(session)
        fresh,_=self.store.login('test-management-password','test','owner',codes[2])
        self.store.logout(fresh)
        with self.assertRaises(w.WebError): self.store.session(fresh)

    def test_download_landing_nonconsuming_and_concurrent_claim_once(self):
        token = self.store.issue('device', 'device.p12', 'generation')
        self.assertEqual(len(token), 64)
        record = self.store.inspect(token)
        self.assertEqual(record, self.store.inspect(token))
        with self.assertRaises(w.WebError):
            self.store.claim(token, 'wrong')
        def claim(_):
            try:
                self.store.claim(token, record['confirm'])
                return True
            except w.WebError:
                return False
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            self.assertEqual(sum(pool.map(claim, range(8))), 1)
        self.assertNotIn(token, (self.root / 'access.db').read_bytes().decode(errors='ignore'))

    def test_download_expiry_and_invalidation(self):
        token = self.store.issue('device', 'device.p12', 'g')
        self.store.invalidate('device')
        with self.assertRaises(w.WebError):
            self.store.inspect(token)
        token = self.store.issue('device', 'device.p12', 'g')
        self.now += 901
        with self.assertRaises(w.WebError):
            self.store.inspect(token)

    def test_actual_peer_host_and_origin_required(self):
        class Manager:
            def load(self):
                return {'lan': '192.168.0.8', 'lan_net': '192.168.0.0/24'}
        class Backend:
            m = Manager()
        controller = w.Controller(Backend(), self.store)
        request = {'peer': '192.168.0.22', 'host': '192.168.0.8:9001'}
        controller.admin_context(request)
        for changes in ({'peer': '8.8.8.8', 'X-Forwarded-For': '192.168.0.22'}, {'host': 'evil.test:9000'}, {'origin': 'http://evil.test'}):
            with self.assertRaises(w.WebError):
                controller.admin_context(dict(request, **changes))
        with self.assertRaises(w.WebError):
            controller.handle({'op': 'open'}, 100)

    def test_ssh_tunnel_hosts_are_accepted_only_from_the_server_itself(self):
        class Manager:
            def load(self):
                return {'lan': '192.168.0.8', 'lan_net': '192.168.0.0/24'}
        class Backend:
            m = Manager()
        controller = w.Controller(Backend(), self.store)
        request = {'peer': '192.168.0.8', 'host': '127.0.0.1:9001', 'origin': 'http://127.0.0.1:9001'}
        controller.admin_context(request)
        for peer in ('192.168.0.22', '8.8.8.8'):
            with self.assertRaises(w.WebError):
                controller.admin_context(dict(request, peer=peer))
        with self.assertRaises(w.WebError):
            controller.admin_context(dict(request, origin='http://evil.test'))

    def test_real_http_certificates_stay_available_after_admin_expiry(self):
        certs = self.root / 'certs'
        certs.mkdir()
        (certs / 'ca.pem').write_bytes(b'PUBLIC CERTIFICATE')
        token = self.store.issue('device', 'device.p12', 'g')
        def rpc(request):
            if request['op'] == 'inspect':
                return dict(self.store.inspect(request['token']), filename='device.p12')
            if request['op'] == 'claim':
                self.store.claim(request['token'], request['confirm'])
                return {'filename': 'device.p12', 'data': 'ZW5jcnlwdGVk'}
            raise w.WebError('Management closed')
        config = {'lan': '192.168.0.8', 'public': '8.8.8.8', 'endpoint': 'vpn.example.test'}
        server = w.BoundedServer(('127.0.0.1', 0), w.handler(config, rpc, self.root))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def request(method, path, body=None, host='8.8.8.8:9000', extra=None):
            connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=4)
            headers = {'Host': host}
            if body is not None:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            headers.update(extra or {})
            connection.request(method, path, body, headers)
            response = connection.getresponse()
            result = response.status, response.read(), dict(response.getheaders())
            connection.close()
            return result
        try:
            self.assertEqual(request('GET', '/manage')[0], 404)
            self.assertEqual(request('GET', '/cert/ca.pem')[:2], (200, b'PUBLIC CERTIFICATE'))
            self.assertEqual(request('GET', '/cert/../../access.db')[0], 404)
            self.assertEqual(request('GET', '/cert/ca.pem', host='evil.test')[0], 403)
            landing = request('GET', '/?' + urlencode({'token': token}))
            self.assertEqual(landing[0], 200)
            self.assertNotIn(b'<script', landing[1])
            self.assertEqual(landing[2]['Referrer-Policy'], 'no-referrer')
            confirm = self.store.inspect(token)['confirm']
            body = urlencode({'token': token, 'confirm': confirm})
            self.assertEqual(request('POST', '/download', body, extra={'Origin': 'http://evil.test'})[0], 403)
            self.assertEqual(request('POST', '/download', body)[:2], (200, b'encrypted'))
            self.assertEqual(request('POST', '/download', body)[0], 403)
            self.now += 1801
            self.assertEqual(request('GET', '/cert/ca.pem')[0], 200)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_html_escapes_labels(self):
        output = w.manager_html({'registry': {'users': {'u': {'name': '<script>bad</script>'}}, 'devices': {}}, 'csrf': 'safe'}, view='users')
        self.assertNotIn(b'<script>bad</script>', output)
        self.assertEqual(output.count(b'<script>'), 1)
        self.assertIn(b'&lt;script&gt;', output)
