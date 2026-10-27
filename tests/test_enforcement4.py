"""Identity changes must not outrun verified kernel policy."""
import datetime
import unittest
from unittest.mock import patch
import test_admin350 as fixture
import vpn_policy


class IdentityChanges(unittest.TestCase):
    setUp=fixture.AdminTests.setUp
    tearDown=fixture.AdminTests.tearDown

    def test_owner_change_commits_only_after_verified_policy(self):
        other=self.backend.user_add('New owner')
        self.backend.m.atomic(self.base/'policy-installed','yes')
        def apply(backend,**kw):
            self.assertEqual(backend.load()['devices'][self.ident]['user'],self.user)
            self.assertEqual(kw['registry_override']['devices'][self.ident]['user'],other)
            kw['commit']()
        with patch.object(vpn_policy,'apply',side_effect=apply):self.backend.assign(self.ident,other)
        self.assertEqual(self.backend.load()['devices'][self.ident]['user'],other)

    def test_owner_change_failure_retains_old_owner_and_restores_policy(self):
        other=self.backend.user_add('New owner')
        self.backend.m.atomic(self.base/'policy-installed','yes')
        with patch.object(vpn_policy,'apply',side_effect=[RuntimeError('kernel rejected'),None]) as apply:
            with self.assertRaisesRegex(RuntimeError,'kernel rejected'):self.backend.assign(self.ident,other)
        self.assertEqual(self.backend.load()['devices'][self.ident]['user'],self.user)
        self.assertEqual(apply.call_count,2)

    def test_missing_firewall_cannot_report_identity_change_as_applied(self):
        with self.assertRaisesRegex(RuntimeError,'not installed'):
            vpn_policy.apply(self.backend,registry_override=self.backend.load(),commit=lambda:self.fail('Must not commit'))

    def test_expiry_offset_is_preserved_and_policy_failure_does_not_commit(self):
        form=dict(actor=self.actor,action='identity-state',kind='device',id=self.ident,disabled='no',expires='2030-01-02T03:04:00+02:00')
        def apply(backend,**kw):kw['commit']()
        with patch.object(vpn_policy,'apply',side_effect=apply),patch.object(self.controller,'disconnect_expired'):
            self.controller.action(form)
        expected=datetime.datetime.fromisoformat(form['expires']).timestamp()
        self.assertEqual(self.backend.load()['devices'][self.ident]['expires'],expected)
        with patch.object(vpn_policy,'apply',side_effect=[RuntimeError('kernel rejected'),None]):
            with self.assertRaisesRegex(RuntimeError,'kernel rejected'):self.controller.action(form|{'disabled':'yes'})
        self.assertFalse(self.backend.load()['devices'][self.ident]['disabled'])

    def test_revocation_disconnects_verified_sessions_even_when_policy_apply_fails(self):
        self.backend.m.atomic(self.base/'policy-installed','yes')
        with patch.object(self.backend.m,'revoke_wg'),patch.object(vpn_policy,'apply',side_effect=RuntimeError('kernel rejected')),patch('vpn_backend.disconnect_profile') as disconnect:
            with self.assertRaisesRegex(RuntimeError,'kernel rejected'):self.backend.revoke(self.ident,'wireguard')
            disconnect.assert_called_once_with(self.backend,self.ident,'wireguard','native-phone')
        self.assertEqual(self.backend.load()['devices'][self.ident]['protocols']['wireguard']['status'],'revoked')
