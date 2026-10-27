"""Batch preview, credential secrecy, interruption and web authorization."""
import json
import unittest
from unittest.mock import patch
import test_admin350 as fixture
import vpn_backend as batches


class BatchTests(unittest.TestCase):
    setUp = fixture.AdminTests.setUp
    tearDown = fixture.AdminTests.tearDown
    request = fixture.AdminTests.request
    rpc = fixture.AdminTests.rpc

    def run_jobs(self):
        worked = False
        for _ in range(300):
            if not self.backend.repo.run_one(self.backend, self.controller.action):
                return worked
            worked = True
        self.fail('Job queue did not drain')

    def preview(self, **changes):
        form = {'action': 'batch-preview', 'batch_kind': 'create', 'ownership': 'existing',
                'user': self.user, 'count': '3', 'random_devices': 'yes', 'protocols': 'ikev2',
                'platform': 'apple', 'password_mode': 'random'}
        form.update(changes)
        batches.preview_batch(self.backend, form)
        return self.backend.repo.batches()[0]

    def activate(self, ident, protocol, password=None, **options):
        reg, item = self.backend.device(ident)
        item['protocols'][protocol] = {'backend': options.get('username') or ident, 'status': 'active', 'export': None}
        self.backend.save(reg)

    def start(self, batch):
        self.controller.action({'actor': self.actor, 'action': 'batch-confirm', 'batch': batch['id']})

    def test_preview_does_not_create_users_devices_or_expose_passwords(self):
        before = self.backend.load()
        batch = self.preview(ownership='new', random_users='yes', password_mode='custom', password='shared-import-secret-370')
        self.assertEqual(before, self.backend.load())
        self.assertNotIn('shared-import-secret-370', json.dumps(batch))
        path = self.base / 'batch-secrets' / batch['id']
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        values = json.loads(path.read_text())
        self.assertTrue(all(v['password'] == 'shared-import-secret-370' for v in values.values()))
        self.assertEqual(len({x['user_name'] for x in batch['items']}), 3)

    def test_independent_passwords_and_creation_is_sequential_and_idempotent(self):
        batch = self.preview()
        private = json.loads((self.base / 'batch-secrets' / batch['id']).read_text())
        passwords = [x['password'] for x in private.values()]
        self.assertEqual(len(set(passwords)), 3)
        self.start(batch)
        with patch.object(self.backend, 'protocol_add', side_effect=self.activate) as add, patch.object(self.backend, 'export_ike') as export:
            self.assertTrue(self.run_jobs())
            self.assertEqual(add.call_count, 3)
            self.assertEqual([x.args[2] for x in export.call_args_list], passwords)
            self.assertTrue(all(x.args[1] == 'apple' for x in export.call_args_list))
            batches.run_batch(self.backend, batch['id'])
            self.assertEqual(add.call_count, 3)
        self.assertFalse((self.base / 'batch-secrets' / batch['id']).exists())
        self.assertEqual(self.backend.repo.batch(batch['id'])['status'], 'complete')

    def test_partial_failure_retry_skips_completed_devices(self):
        batch = self.preview()
        self.start(batch)
        failed = batch['items'][1]['device']
        def first(ident, *args):
            if ident == failed:
                raise RuntimeError('sensitive native output secret-value')
        with patch.object(self.backend, 'protocol_add', side_effect=self.activate), patch.object(self.backend, 'export_ike', side_effect=first):
            self.run_jobs()
        data = self.backend.repo.batch(batch['id'])
        self.assertEqual([i['status'] for i in data['items']], ['complete', 'failed', 'complete'])
        self.assertNotIn('secret-value', json.dumps(data))
        job = self.backend.repo.jobs()[0]
        self.backend.repo.retry(job['id'])
        with patch.object(self.backend, 'protocol_add') as add, patch.object(self.backend, 'export_ike') as export:
            self.run_jobs()
            add.assert_not_called()
            self.assertEqual(export.call_count, 1)
            self.assertEqual(export.call_args.args[0], failed)

    def test_cancel_between_operations_preserves_completed_and_removes_secret(self):
        batch = self.preview()
        self.start(batch)
        def export(*args):
            self.backend.repo.batch_cancel(batch['id'])
        with patch.object(self.backend, 'protocol_add', side_effect=self.activate), patch.object(self.backend, 'export_ike', side_effect=export) as exp:
            self.run_jobs()
            self.assertEqual(exp.call_count, 1)
        data = self.backend.repo.batch(batch['id'])
        self.assertEqual(data['status'], 'cancelled')
        self.assertEqual(data['items'][0]['status'], 'complete')
        self.assertFalse((self.base / 'batch-secrets' / batch['id']).exists())

    def test_reexport_keeps_password_and_native_identity(self):
        reg, device = self.backend.device(self.ident)
        device['protocols']['ikev2'] = {'backend': 'original-certificate', 'status': 'active'}
        self.backend.save(reg)
        batch = self.preview(batch_kind='export', devices=self.ident, password_mode='keep')
        self.start(batch)
        with patch.object(self.backend, 'protocol_add') as add, patch.object(self.backend, 'export_ike') as export:
            self.run_jobs()
            add.assert_not_called()
            self.assertIsNone(export.call_args.args[2])
        self.assertEqual(self.backend.device(self.ident)[1]['protocols']['ikev2']['backend'], 'original-certificate')

    def test_limits_names_protocols_and_passwords_are_validated(self):
        for form in ({'count': '0'}, {'count': '51'}, {'count': 'bad'}, {'protocols': 'ssh'},
                     {'password_mode': 'custom', 'password': 'short'}, {'password_mode': 'custom', 'password': 'longpassword\ninvalid'},
                     {'batch_kind': 'export', 'devices': self.ident}):
            with self.subTest(form=form), self.assertRaises((ValueError, RuntimeError)):
                self.preview(**form)
        with patch.object(self.backend, 'protocol_add') as add:
            with self.assertRaises(RuntimeError):
                self.controller.action({'actor': self.actor, 'action': 'protocols-add', 'device': self.ident, 'protocols': 'l2tp,invalid', 'username': 'example'})
            add.assert_not_called()
        self.preview(random_devices='no', device_prefix='Phone')
        with self.assertRaises(RuntimeError):
            self.backend.device_add(self.user, 'Example Phone')

    def test_job_password_is_separate_and_removed_after_use(self):
        password = 'private-import-password-370'
        ident = self.backend.repo.enqueue({'actor':self.actor, 'action': 'export', 'device': self.ident, 'password': password, '_secret': '/etc/passwd'})
        with self.backend.repo.connect() as db:
            raw = db.execute('SELECT form FROM jobs WHERE id=?', (ident,)).fetchone()[0]
        self.assertNotIn(password, raw)
        self.assertNotIn('/etc/passwd', raw)
        self.assertEqual(ident, self.backend.repo.enqueue({'actor':self.actor, 'action': 'export', 'device': self.ident, 'password': password}))
        seen = []
        self.backend.repo.run_one(self.backend, lambda form: seen.append(form['password']) or {'message': 'ready'})
        self.assertEqual(seen, [password])
        self.assertFalse((self.base / 'job-secrets' / ident).exists())
        self.assertNotIn(password, json.dumps(self.backend.repo.jobs()))

    def test_web_preview_confirmation_and_live_progress_require_auth(self):
        payload = {'action': 'batch-preview', 'batch_kind': 'create', 'ownership': 'existing', 'user': self.user,
                   'count': '2', 'random_devices': 'yes', 'protocols': 'ikev2', 'return_view': 'batches'}
        self.assertEqual(self.request('/manage/action', 'POST', payload, csrf=False)[0], '403 Forbidden')
        status, headers, body = self.request('/manage/action', 'POST', payload)
        self.assertEqual(status, '200 OK')
        self.assertIn(b'Confirm this batch', body)
        self.assertNotIn('Refresh', headers)
        self.assertEqual(len(self.backend.repo.jobs()), 0)
        batch = self.backend.repo.batches()[0]
        self.assertEqual(self.request('/manage/action', 'POST', {'action': 'batch-confirm', 'batch': batch['id'], 'return_view': 'batches'})[0], '200 OK')
        self.assertEqual(len(self.backend.repo.jobs()), 1)
        self.assertNotIn('Refresh', self.request('/manage/jobs')[1])
        self.assertIn(b'/manage/status', self.request('/manage/batches')[2])

    def test_cancelled_preview_cannot_be_confirmed(self):
        batch = self.preview()
        self.backend.repo.batch_cancel(batch['id'])
        with self.assertRaises(RuntimeError):
            self.start(batch)
        self.assertFalse((self.base / 'batch-secrets' / batch['id']).exists())

    def test_incomplete_native_operation_requires_recovery(self):
        batch = self.preview(count='1')
        ident = batch['items'][0]['device']
        self.backend.operation(ident, 'add-ikev2', 'pending')
        self.start(batch)
        with patch.object(self.backend, 'protocol_add') as add:
            self.run_jobs()
            add.assert_not_called()
        self.assertEqual(self.backend.repo.batch(batch['id'])['items'][0]['status'], 'failed')

    def test_l2tp_login_choices_are_distinct_from_import_password(self):
        batch = self.preview(protocols='l2tp', count='2', random_l2tp='no', l2tp_prefix='employee', l2tp_password='Shared-login-pass-370')
        self.assertEqual([x['l2tp_username'] for x in batch['items']], ['employee-1', 'employee-2'])
        self.start(batch)
        with patch.object(self.backend, 'protocol_add', side_effect=self.activate) as add:
            self.run_jobs()
        self.assertEqual(add.call_args_list[0].args[2], 'Shared-login-pass-370')
        self.assertEqual(add.call_args_list[0].kwargs['username'], 'employee-1')
        self.assertNotIn('Shared-login-pass-370', json.dumps(self.backend.repo.batches()))
