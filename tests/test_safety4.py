"""Recovery and maintenance safety; all OS writes are confined to fixture roots."""
import concurrent.futures
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch
from test_manager import m, ROOT
from auth_fixture import enroll
from vpn_web import Store
import vpn_setup
import vpn_tasks
from vpn_maintenance import Coordinator

class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.base=self.root/'var/lib/vpn';self.base.mkdir(parents=True)
        self.commands=[]
        def command(args,**kw):
            self.commands.append(args);return subprocess.CompletedProcess(args,0,'','')
        self.manager=types.SimpleNamespace(BASE=self.base,ETC=self.root/'etc',atomic=m.atomic,command=command)
    def legacy(self):
        m.atomic(self.root/'root/vpn-stack/state.json',json.dumps({'version':3,'clients':{'phone':{}},'l2tp_user':'old-login'}))
        m.atomic(self.root/'etc/ipsec.d/key.db',b'old trust fixture')
        m.atomic(self.root/'etc/ipsec.conf','old config')
        m.atomic(self.root/'etc/ppp/chap-secrets','"old-login" l2tpd "fixture-password" *\n')
        m.atomic(self.root/'etc/netplan/50-cloud-init.yaml','network fixture')
    def test_reset_confirms_and_retains_verified_backup_without_network_changes(self):
        self.legacy()
        with self.assertRaises(ValueError):vpn_setup.fresh_start(self.manager,'yes',self.root)
        result=vpn_setup.fresh_start(self.manager,'RESET VPN AND ADGUARD',self.root)
        self.assertEqual(result['stage'],'complete')
        self.assertFalse((self.root/'etc/ipsec.d').exists())
        self.assertEqual((Path(result['archive'])/'etc/ipsec.d/key.db').read_bytes(),b'old trust fixture')
        self.assertEqual((self.root/'etc/netplan/50-cloud-init.yaml').read_text(),'network fixture')
        self.assertFalse(any('start' in call or 'restart' in call for call in self.commands))
        self.assertEqual(vpn_setup.fresh_start(self.manager,'RESET VPN AND ADGUARD',self.root),result)
    def test_reset_hashes_backup_files_without_unbounded_reads(self):
        self.legacy()
        with patch.object(Path,'read_bytes',side_effect=AssertionError('Unbounded file read')):
            result=vpn_setup.fresh_start(self.manager,'RESET VPN AND ADGUARD',self.root)
        self.assertEqual(result['stage'],'complete')
    def test_reset_refuses_unmanaged_identity_before_stopping_services(self):
        self.legacy();m.atomic(self.root/'etc/ppp/chap-secrets','unrelated l2tpd fixture *\n')
        with self.assertRaisesRegex(RuntimeError,'Unmanaged PPP'):vpn_setup.fresh_start(self.manager,'RESET VPN AND ADGUARD',self.root)
        self.assertFalse(self.commands);self.assertTrue((self.root/'etc/ipsec.d/key.db').exists())
    def test_interrupted_reset_resumes_without_reactivating_old_keys(self):
        self.legacy();original=vpn_setup.shutil.rmtree
        def fail(path,*args,**kw):
            if Path(path)==self.root/'etc/ipsec.d':raise OSError('simulated interruption')
            return original(path,*args,**kw)
        with patch.object(vpn_setup.shutil,'rmtree',side_effect=fail):
            with self.assertRaises(OSError):vpn_setup.fresh_start(self.manager,'RESET VPN AND ADGUARD',self.root)
        self.assertEqual(json.loads((self.base/'reset-progress.json').read_text())['stage'],'backed-up')
        self.assertFalse(any('restart' in c or 'start' in c for c in self.commands))
        self.assertEqual(vpn_setup.fresh_start(self.manager,'RESET VPN AND ADGUARD',self.root)['stage'],'complete')
    def test_system_task_concurrent_submission_only_one_queue(self):
        store=Store(self.base/'backend.db');actor,*_=enroll(store)
        def submit(_):
            try:vpn_tasks.submit(self.manager,actor,{'action':'system-repair'});return True
            except ValueError:return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:self.assertEqual(sum(pool.map(submit,range(4))),1)
        self.assertEqual(len(self.commands),1)
    def test_system_task_rechecks_disabled_actor_before_execution(self):
        store=Store(self.base/'backend.db');owner,*_=enroll(store)
        actor,*_=enroll(store,'second','second-fixture-password','owner',owner)
        vpn_tasks.submit(self.manager,actor,{'action':'system-repair'})
        store.admin_change(owner,actor,enabled=False)
        with patch('vpn_repair.Doctor.repair') as repair:
            with self.assertRaisesRegex(RuntimeError,'role cannot'):vpn_tasks.execute(self.manager)
            repair.assert_not_called()
        self.assertEqual(json.loads((self.base/'system-task.json').read_text())['status'],'failed')
    def test_reboot_budget_recorded_before_request_and_failed_request_not_repeated(self):
        now=[1800000000];coordinator=Coordinator(self.manager,lambda:now[0])
        def fail(args,**kw):
            self.assertEqual(coordinator.load()['reboots'],[now[0]])
            raise RuntimeError('reboot rejected')
        self.manager.command=fail
        with patch('vpn_maintenance.os.sync'):
            with self.assertRaisesRegex(RuntimeError,'reboot rejected'):coordinator.reboot('test','owner')
            with self.assertRaisesRegex(RuntimeError,'budget/cooldown'):coordinator.reboot('test','owner')
    def test_ui_preview_is_read_only_and_launcher_matches_package(self):
        source=(ROOT/'src/installer.sh').read_text()
        function=source[source.index('ensure_ui() {'):source.index('\nui_choice() {')]
        self.assertNotIn('/usr/',function);self.assertNotIn('/var/',function)
        launcher=source.split("<<'VPN_LAUNCHER'\n",1)[1].split('\nVPN_LAUNCHER',1)[0]
        self.assertEqual(launcher+'\n',(ROOT/'packaging/vpn').read_text())
