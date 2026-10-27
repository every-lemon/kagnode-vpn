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

    def test_access_forms_display_current_state_instead_of_reset_defaults(self):
        from vpn_dashboard import device_access,maintenance
        from vpn_admin import form
        data={'csrf':'fixture','identity':{'role':'owner'},'admin_approved':True,
              'registry':{'devices':{'d':{'disabled':True,'expires':1893456000}}},
              'business':{'groups':{'ungrouped':{'name':'ungrouped'},'office':{'name':'Office'}},'members':{'d':'office'}}}
        rendered=device_access(data,'d',form)
        self.assertIn('value="office" selected',rendered)
        self.assertIn('value="yes" selected>Disabled',rendered)
        self.assertIn('value="2030-01-01T00:00"',rendered)
        self.assertIn('value="yes" selected>Approve',rendered)
        rendered=maintenance({'csrf':'fixture','identity':{'role':'owner'},'maintenance':{'mode':'window'},'access':{'admin_mode':'https'}},form)
        self.assertIn('value="window" selected',rendered)
        self.assertIn('value="https" selected',rendered)

    def test_group_edits_preserve_denies_and_rule_removal_is_explicit(self):
        from vpn_business import Business
        business=Business(self.backend.repo)
        resource=business.change(dict(action='resource-save',name='Office',cidr='192.168.20.0/24',protocol='tcp',ports='443'))
        group=business.change(dict(action='group-add',name='Staff',policy='{"internet":true,"isolation":true,"rules":[]}'))
        def action(action_name,**values):
            with patch.object(vpn_policy,'apply'):
                return self.controller.action(dict(actor=self.actor,action=action_name,**values))
        action('group-rule',id=group,effect='deny',resource=resource)
        action('group-settings',id=group,name='Staff renamed',internet='no',isolation='yes')
        saved=business.snapshot()['groups'][group]
        self.assertEqual(saved['name'],'Staff renamed')
        self.assertFalse(saved['policy']['internet'])
        self.assertEqual(saved['policy']['rules'],[{'effect':'deny','resource':resource}])
        action('user-rule',id=self.user,effect='allow',resource=resource)
        self.assertEqual(business.snapshot()['policies'][('user',self.user)]['rules'],[{'effect':'allow','resource':resource}])
        action('user-rule-remove',id=self.user,effect='allow',resource=resource)
        action('group-rule-remove',id=group,effect='deny',resource=resource)
        self.assertEqual(business.snapshot()['groups'][group]['policy']['rules'],[])
        with self.assertRaisesRegex(RuntimeError,'changed'):
            action('group-rule-remove',id=group,effect='deny',resource=resource)
        with self.assertRaisesRegex(ValueError,'built-in'):
            action('group-settings',id='ungrouped',name='Changed',internet='no',isolation='no')
