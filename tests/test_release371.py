"""Responsive policy scheduling, expiry, deletion recovery and lightweight dashboard."""
import base64
import hashlib
import json
import types
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit, parse_qs
import test_admin350 as fixture
from test_manager import m
import vpn_backend as backend_module
import vpn_policy as policy
import vpn_web as web
import vpn_admin as admin


class ReleaseTests(unittest.TestCase):
    setUp = fixture.AdminTests.setUp
    tearDown = fixture.AdminTests.tearDown
    request = fixture.AdminTests.request
    rpc = fixture.AdminTests.rpc
    apple_fixture = fixture.AdminTests.apple_fixture

    def drain(self):
        for _ in range(200):
            if not self.backend.repo.run_one(self.backend, self.controller.action):
                return
        self.fail('Queue did not drain')

    def test_delivery_lifetimes_and_legacy_default_are_single_use(self):
        self.apple_fixture()
        for lifetime in (3600, 86400, 604800, 2592000):
            result = self.controller.action({'actor': self.actor, 'action': 'delivery-link', 'device': self.ident, 'lifetime': str(lifetime)})
            token = parse_qs(urlsplit(result['url']).query)['token'][0]
            record = self.store.inspect(token)
            self.assertAlmostEqual(record['remaining'], lifetime, delta=2)
            self.store.claim(token, record['confirm'])
            with self.assertRaises(web.WebError):
                self.store.inspect(token)
        token = self.store.issue(self.ident, 'legacy.p12', 'legacy')
        self.assertAlmostEqual(self.store.inspect(token)['remaining'], 900, delta=2)
        for invalid in ('0', '-1', '2592001', 'bad'):
            with self.assertRaises(web.WebError):
                self.controller.action({'actor': self.actor, 'action': 'delivery-link', 'device': self.ident, 'lifetime': invalid})

    def test_management_countdown_is_monotonic_and_cannot_extend_session(self):
        wall, mono = [10000], [100]
        store = web.Store(self.base / 'time.db', lambda: wall[0], lambda: mono[0], 'boot')
        from auth_fixture import enroll
        _,session,_,_=enroll(store)
        mono[0] += 35
        wall[0] -= 3000
        self.assertEqual(store.remaining(session), 1765)
        mono[0] += 1800
        with self.assertRaises(web.WebError):
            store.remaining(session)

    def test_status_requires_auth_and_caches_one_batched_service_read(self):
        response = types.SimpleNamespace(stdout='active\n'*6, returncode=0)
        with patch.object(self.backend.m, 'command', return_value=response) as command:
            status, _, body = self.request('/manage/status')
            self.assertEqual(status, '200 OK')
            data = json.loads(body)
            self.assertGreater(data['remaining'], 0)
            self.assertIn('MemAvailable', data['health']['memory'])
            self.request('/manage/status')
            self.assertEqual(command.call_count, 1)
            self.assertEqual(command.call_args.kwargs['timeout'], 3)
        self.assertEqual(self.request('/manage/status', authenticated=False)[0], '403 Forbidden')
        self.assertNotIn('password', body.decode())

    def test_browser_script_is_csp_hashed_and_has_no_external_dependency(self):
        _, headers, body = self.request('/manage')
        digest = base64.b64encode(hashlib.sha256(admin.SCRIPT.encode()).digest()).decode()
        self.assertIn("script-src 'sha256-" + digest + "'", headers['Content-Security-Policy'])
        self.assertIn("connect-src 'self'", headers['Content-Security-Policy'])
        self.assertNotIn("'unsafe-inline'", headers['Content-Security-Policy'])
        self.assertIn(b'DOMContentLoaded', body)
        self.assertIn(b'document.hidden', body)
        self.assertNotIn(b'<script src=', body)

    def test_policy_job_preempts_a_yielded_batch(self):
        backend_module.preview_batch(self.backend, {'batch_kind': 'create', 'ownership': 'existing', 'user': self.user,
            'count': '2', 'random_devices': 'yes', 'protocols': 'ikev2'})
        batch = self.backend.repo.batches()[0]
        self.controller.action({'actor': self.actor, 'action': 'batch-confirm', 'batch': batch['id']})
        self.backend.repo.run_one(self.backend, self.controller.action)
        self.assertEqual(self.backend.repo.jobs()[0]['status'], 'queued')
        self.backend.repo.enqueue({'actor':self.actor, 'action': 'policy', 'kind': 'device', 'id': self.ident, 'policy': 'allow'})
        with patch.object(self.backend, 'set_policy') as change:
            self.backend.repo.run_one(self.backend, self.controller.action)
            change.assert_called_once_with('device', self.ident, 'allow')
        self.assertEqual(self.backend.repo.batch(batch['id'])['status'], 'running')

    def test_failed_policy_does_not_publish_allow_and_restores_old_rules(self):
        def apply(backend, **kwargs):
            if kwargs.get('override'):
                raise RuntimeError('Simulated firewall timeout')
        with patch.object(policy, 'apply', side_effect=apply) as apply_call:
            with self.assertRaisesRegex(RuntimeError, 'timeout'):
                self.backend.set_policy('device', self.ident, 'allow')
            self.assertEqual(apply_call.call_count, 2)
        device = self.backend.device(self.ident)[1]
        self.assertEqual(device['lan_policy'], 'inherit')
        self.assertEqual(device['desired_lan_policy'], 'allow')
        self.assertEqual(device['policy_status'], 'failed')

    def test_verified_policy_commits_inside_policy_lock_callback(self):
        def apply(backend, **kwargs):
            self.assertEqual(backend.device(self.ident)[1]['lan_policy'], 'inherit')
            self.assertEqual(kwargs['override'], ('device', self.ident, 'allow'))
            kwargs['commit']()
        with patch.object(policy, 'apply', side_effect=apply):
            self.backend.set_policy('device', self.ident, 'allow')
        self.assertEqual(self.backend.device(self.ident)[1]['policy_status'], 'applied')

    def test_policy_command_budget_fails_without_launching_a_tool(self):
        with patch.object(policy.time, 'monotonic', side_effect=[0, 31]), patch.object(self.backend.m, 'command') as command:
            with policy.budget(30), self.assertRaisesRegex(RuntimeError, 'deadline'):
                policy.command(self.backend, ['iptables-save'])
            command.assert_not_called()

    def test_delete_revokes_invalidates_files_and_does_not_revoke_twice_on_retry(self):
        filename, _ = self.apple_fixture()
        # Select WG only so the IKE fixture remains intact.
        token = self.store.issue(self.ident, filename, 'apple-generation')
        form = {'action': 'delete-profile', 'device': self.ident, 'protocol': 'wireguard', 'confirm': 'DELETE', 'return_view': 'jobs'}
        self.assertEqual(self.request('/manage/action', 'POST', form, csrf=False)[0], '403 Forbidden')
        self.assertEqual(self.request('/manage/action', 'POST', form)[0], '200 OK')
        with self.assertRaises(web.WebError):
            self.store.inspect(token)
        self.assertEqual(self.request('/manage/file', 'POST', {'device': self.ident, 'kind': 'wireguard'})[0], '403 Forbidden')
        def revoke(ident, protocol):
            registry, device = self.backend.device(ident)
            device['protocols'][protocol]['status'] = 'revoked'
            self.backend.save(registry)
        path = self.base / 'clients/wireguard/native-phone.conf'
        with patch.object(self.backend, 'revoke', side_effect=revoke) as revoked, patch.object(backend_module, 'disconnect_profile', side_effect=RuntimeError('Try again')):
            self.drain()
            self.assertEqual(revoked.call_count, 1)
        self.assertTrue(path.exists())
        job = self.backend.repo.jobs()[0]
        self.assertEqual(job['status'], 'failed')
        self.backend.repo.retry(job['id'])
        with patch.object(self.backend, 'revoke') as revoked, patch.object(backend_module, 'disconnect_profile'):
            self.drain()
            revoked.assert_not_called()
        self.assertFalse(path.exists())
        self.assertTrue(self.backend.device(self.ident)[1]['protocols']['wireguard']['deletion']['complete'])
        self.assertFalse(self.backend.repo.pending_delete(self.ident))
        self.assertEqual(self.backend.device(self.ident)[1]['protocols']['ikev2']['status'], 'active')

    def test_empty_device_deletion_hides_only_that_device(self):
        ident = self.backend.device_add(self.user, 'Empty device')
        self.backend.delete_profile(ident)
        self.assertFalse(admin.visible_device(self.backend.device(ident)[1]))
        self.assertTrue(admin.visible_device(self.backend.device(self.ident)[1]))

    def test_clear_history_keeps_recovery_and_database_audit(self):
        complete = self.backend.repo.enqueue({'actor':self.actor, 'action': 'repair', 'device': self.ident})
        failed = self.backend.repo.enqueue({'actor':self.actor, 'action': 'export', 'device': self.ident})
        with self.backend.repo.connect() as db:
            db.execute("UPDATE jobs SET status='complete' WHERE id=?", (complete,))
            db.execute("UPDATE jobs SET status='failed' WHERE id=?", (failed,))
        self.backend.repo.audit('important', self.ident, 'complete')
        self.backend.repo.clear_history()
        self.assertEqual([job['id'] for job in self.backend.repo.jobs()], [failed])
        with self.backend.repo.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM jobs').fetchone()[0], 2)
            self.assertTrue(db.execute("SELECT 1 FROM audit WHERE action='important'").fetchone())

    def test_selective_ike_disconnect_uses_exact_identity_and_parent_serial(self):
        def block(native, serial, instance):
            return f'000 "ikev2-cp"[{instance}]: our id=server; their id=CN={native}, O=IKEv2 VPN\n000 "ikev2-cp"[{instance}]: routing: routed-tunnel; established IKE SA: #{serial}; established Child SA: #99;\n'
        before = block('target', 12, 1) + block('target-extra', 15, 2)
        after = block('target-extra', 15, 2)
        outputs = iter([before, before, '', after])
        calls = []
        def command(args, **kwargs):
            calls.append(args)
            return types.SimpleNamespace(stdout=next(outputs), returncode=0)
        with patch.object(self.backend.m, 'command', side_effect=command):
            backend_module.disconnect_profile(self.backend, self.ident, 'ikev2', 'target')
        self.assertIn(['ipsec', 'whack', '--deletestate', '12'], calls)
        self.assertFalse(any('15' in args for args in calls))
        self.assertFalse(any('--delete' in args or 'restart' in args for args in calls))

    def test_ambiguous_active_ike_session_is_not_terminated(self):
        with patch.object(self.backend.m, 'command', return_value=types.SimpleNamespace(stdout='000 "ikev2-cp"[1]: established IKE SA: #12;\n')) as command:
            with self.assertRaisesRegex(ValueError, 'matched safely'):
                backend_module.disconnect_profile(self.backend, self.ident, 'ikev2', 'target')
            self.assertEqual(command.call_count, 1)

    def test_link_email_expiry_matches_requested_duration(self):
        self.apple_fixture()
        before = self.store.clock()
        output = admin.attachment(self.backend, self.store, self.state, {'device': self.ident, 'kind': 'email', 'lifetime': '2592000'})
        payload = base64.b64decode(output['data']).decode()
        import re, html
        url = html.unescape(re.search(r'href="([^"]+)"', payload)[1])
        token = parse_qs(urlsplit(url).query)['token'][0]
        self.assertAlmostEqual(self.store.inspect(token)['expires'] - before, 2592000, delta=3)
        self.assertNotIn('PrivateKey', payload)
