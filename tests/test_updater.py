"""4.x update preservation, rollback, archives and explicit prerelease selection."""
import contextlib
import fcntl
import io
import json
import re
import subprocess
import sys
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'update.sh').read_text()
runtime=source.split("<<'VPN_STACK_UPDATER_PY'\n",1)[1].split('\nVPN_STACK_UPDATER_PY\n',1)[0]
embedded=types.ModuleType('embedded_updater');exec(compile(runtime,'updater-runtime','exec'),embedded.__dict__)
PAYLOAD=embedded.decode_payload()
sys.path.insert(0,str(ROOT/'src'))
u=types.ModuleType('updater_runtime');exec(compile((ROOT/'src/updater.py').read_text(),'updater-source','exec'),u.__dict__)

def release_payload(version):
    payload=json.loads(json.dumps(PAYLOAD))
    payload['version']=version
    payload['files']['setup.sh']=re.sub(r'^VERSION=\S+$','VERSION='+version,payload['files']['setup.sh'],flags=re.M)
    payload['sha256']['setup.sh']=u.sha(payload['files']['setup.sh'].encode())
    return payload

class FakeUpdater(u.Updater):
    def __init__(self,*args,fail=None,**kw):super().__init__(*args,**kw);self.calls=[];self.fail=fail
    def web_ready(self,port,timeout):return True
    def command(self,args,check=True,timeout=600):
        self.calls.append(list(map(str,args)))
        if self.fail and self.fail in list(map(str,args)) and check:raise u.UpdateError('simulated deployment failure')
        return types.SimpleNamespace(returncode=0)
    def diagnostics(self,phase):(self.run_dir/(phase+'-journal.log')).write_text('captured before rollback')

class Clock:
    def __init__(self):self.now=0
    def __call__(self):return self.now
    def sleep(self,seconds):self.now+=seconds

class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.base=self.root/'var/lib/kagnode/vpn';self.code=self.root/'opt/kagnode/vpn';self.helpers=self.root/'opt/kagnode/vpn/helpers'
        for path in (self.base,self.code,self.helpers,self.root/'etc/kagnode/vpn'):path.mkdir(parents=True,exist_ok=True)
        self.state=self.root/'etc/kagnode/vpn/state.json';self.state.write_text(json.dumps({'version':4,'installed':True,'clients':{'device':{'private':'fixture'}}}))
        (self.base/'backend.db').write_bytes(b'private admin MFA tokens fixture')
        (self.code/'VERSION').write_text('4.0.0-beta.1\n');(self.code/'manage.py').write_text('old runtime')
        (self.helpers/'setup.sh').write_text('old installer')
        self.source=self.root/'update.sh';self.source.write_text('test updater bytes')
        self.before={p:p.read_bytes() for p in (self.state,self.base/'backend.db')}
    def updater(self,**kw):return FakeUpdater(self.source,PAYLOAD,self.root,prerelease=True,**kw)
    def execute(self,updater):
        with contextlib.redirect_stdout(io.StringIO()):updater.run()
    def assert_private_unchanged(self):
        for path,data in self.before.items():self.assertEqual(path.read_bytes(),data)
    def test_private_state_preserved_and_updater_archived(self):
        update=self.updater();self.execute(update);self.assert_private_unchanged()
        self.assertFalse(self.source.exists());self.assertEqual((self.base/'updates'/('update-'+PAYLOAD['version']+'.sh')).read_text(),'test updater bytes')
        self.assertFalse(any('apt-get' in c or 'purge' in c for c in update.calls))
    def test_legacy_schema_refused(self):
        self.state.write_text('{"version":3,"installed":true}')
        with self.assertRaisesRegex(u.UpdateError,'Finish VPN 4'):self.execute(self.updater())
        self.assertEqual((self.code/'manage.py').read_text(),'old runtime');self.assertTrue(self.source.exists())
    def test_prerelease_opt_in_required(self):
        update=FakeUpdater(self.source,release_payload('4.0.0-rc.1'),self.root)
        with self.assertRaisesRegex(u.UpdateError,'Prerelease'):self.execute(update)
    def test_stable_upgrade_from_rc_preserves_private_state_without_opt_in(self):
        (self.code/'VERSION').write_text('4.0.0-rc.1\n')
        update=FakeUpdater(self.source,release_payload('4.0.0'),self.root)
        self.execute(update);self.assert_private_unchanged()
        self.assertEqual((self.code/'VERSION').read_text(),'4.0.0\n')
    def test_downgrade_refused(self):
        (self.code/'VERSION').write_text('99.0.0')
        with self.assertRaisesRegex(u.UpdateError,'downgrade'):self.execute(self.updater())
    def test_failure_captures_journal_and_restores_code_only(self):
        update=self.updater(fail='refresh-web')
        with self.assertRaisesRegex(u.UpdateError,'deployment'):self.execute(update)
        self.assert_private_unchanged();self.assertTrue(self.source.exists())
        self.assertEqual((self.code/'manage.py').read_text(),'old runtime')
        self.assertTrue((update.run_dir/'failure-journal.log').exists())
        self.assertEqual(json.loads((update.run_dir/'journal.json').read_text())['status'],'code-restored')
    def test_one_failed_service_cannot_be_hidden_by_healthy_services(self):
        for service in ('vpn-control','vpn-management','vpn-downloads','vpn-firewall','ipsec','xl2tpd','wg-quick@wg0','AdGuardHome'):
            with self.subTest(service=service):
                update=self.updater();original=update.command
                clock=Clock()
                def probe(args,check=True,timeout=600):
                    if args==['systemctl','is-active','--quiet',service]:
                        return types.SimpleNamespace(returncode=3)
                    return original(args,check,timeout)
                update.command=probe
                with patch.object(u.time,'monotonic',clock),patch.object(u.time,'sleep',clock.sleep):
                    with self.assertRaisesRegex(u.UpdateError,'did not become active'):self.execute(update)
                self.assertEqual(clock.now,60)
                self.assertEqual((self.code/'manage.py').read_text(),'old runtime')
                self.assertTrue(self.source.exists());self.assert_private_unchanged()
                self.assertFalse((self.base/'updates'/('update-'+PAYLOAD['version']+'.sh')).exists())
                self.assertEqual(json.loads((update.run_dir/'journal.json').read_text())['status'],'code-restored')
    def test_ordered_service_restart_can_finish_before_update_commits(self):
        update=self.updater();original=update.command;clock=Clock();probes=[]
        def probe(args,check=True,timeout=600):
            if args[:3]==['systemctl','is-active','--quiet']:
                probes.append((args[-1],clock.now,check,timeout))
                if args[-1]=='wg-quick@wg0' and clock.now<2:return types.SimpleNamespace(returncode=3)
            return original(args,check,timeout)
        update.command=probe
        with patch.object(u.time,'monotonic',clock),patch.object(u.time,'sleep',clock.sleep):self.execute(update)
        self.assertEqual(clock.now,2);self.assert_private_unchanged()
        self.assertEqual((self.code/'VERSION').read_text(),PAYLOAD['version']+'\n')
        self.assertFalse(self.source.exists())
        self.assertEqual(len({service for service,when,_,_ in probes if when==2}),8)
        self.assertTrue(all(not check and 0<timeout<=3 for _,_,check,timeout in probes))
        self.assertFalse(any(c[:2]==['systemctl','restart'] for c in update.calls))
    def test_active_unit_with_dead_http_worker_cannot_commit_update(self):
        for port in (9000,9001):
            with self.subTest(port=port):
                update=self.updater();clock=Clock()
                update.web_ready=lambda listener,timeout:listener!=port
                with patch.object(u.time,'monotonic',clock),patch.object(u.time,'sleep',clock.sleep):
                    with self.assertRaisesRegex(u.UpdateError,'web listener '+str(port)):
                        self.execute(update)
                self.assertEqual(clock.now,60);self.assert_private_unchanged()
                self.assertEqual((self.code/'manage.py').read_text(),'old runtime')
                self.assertTrue(self.source.exists())
                self.assertFalse((self.base/'updates'/('update-'+PAYLOAD['version']+'.sh')).exists())
    def test_http_probes_share_the_service_readiness_deadline(self):
        update=self.updater();clock=Clock();timeouts=[]
        def unavailable(port,timeout):
            timeouts.append(timeout);clock.sleep(timeout);return False
        update.web_ready=unavailable
        with patch.object(u.time,'monotonic',clock),patch.object(u.time,'sleep',clock.sleep):
            with self.assertRaisesRegex(u.UpdateError,'responsive'):
                self.execute(update)
        self.assertEqual(clock.now,60)
        self.assertTrue(all(0<t<=2 for t in timeouts));self.assert_private_unchanged()
    def test_http_probe_requires_exact_health_response_and_ignores_proxy_environment(self):
        state=json.loads(self.state.read_text());state['lan']='192.0.2.10';self.state.write_text(json.dumps(state))
        update=self.updater()
        for body,code,expected in ((b'OK\n\n200',0,True),(b'OK\n\n302',0,False),(b'HTML\n200',0,False),(b'OK\n\n200',7,False)):
            with self.subTest(body=body,code=code),patch.object(u.subprocess,'run',return_value=types.SimpleNamespace(returncode=code,stdout=body)) as run:
                self.assertEqual(u.Updater.web_ready(update,9001,.75),expected)
                args=run.call_args.args[0]
                self.assertEqual(args[-1],'http://192.0.2.10:9001/health')
                self.assertEqual(args[args.index('--noproxy')+1],'*')
                self.assertEqual(run.call_args.kwargs['timeout'],.75)
        with patch.object(u.subprocess,'run',side_effect=subprocess.TimeoutExpired('curl',.75)):
            self.assertFalse(u.Updater.web_ready(update,9000,.75))
    def test_hung_service_probes_share_deadline_and_diagnostics_cannot_block_rollback(self):
        update=self.updater();original=update.command;clock=Clock();timeouts=[]
        def probe(args,check=True,timeout=600):
            if args[:3]==['systemctl','is-active','--quiet']:
                timeouts.append(timeout);clock.sleep(timeout)
                raise subprocess.TimeoutExpired(args,timeout)
            return original(args,check,timeout)
        update.command=probe
        with patch.object(u.time,'monotonic',clock),patch.object(u.time,'sleep',clock.sleep),patch.object(update,'diagnostics',side_effect=OSError('journal unavailable')),contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(u.UpdateError,'did not become active'):self.execute(update)
        self.assertEqual(clock.now,60)
        self.assertTrue(all(0<timeout<=3 for timeout in timeouts))
        self.assertEqual((self.code/'manage.py').read_text(),'old runtime')
        self.assertTrue(self.source.exists());self.assert_private_unchanged()
        self.assertEqual(json.loads((update.run_dir/'journal.json').read_text())['status'],'code-restored')
    def test_diagnostic_timeout_cannot_prevent_rollback(self):
        update=self.updater(fail='refresh-web')
        with patch.object(update,'diagnostics',side_effect=subprocess.TimeoutExpired('journalctl',20)),contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(u.UpdateError,'deployment'):self.execute(update)
        self.assertEqual((self.code/'manage.py').read_text(),'old runtime')
        self.assertTrue(self.source.exists());self.assert_private_unchanged()
        self.assertEqual(json.loads((update.run_dir/'journal.json').read_text())['status'],'code-restored')
    def test_failure_restores_owned_firewall_and_units_without_touching_unrelated_units(self):
        units=self.root/'etc/systemd/system';units.mkdir(parents=True)
        firewall=self.helpers/'firewall.sh';firewall.write_text('old scoped firewall');firewall.chmod(0o700)
        owned=units/'vpn-management.service';owned.write_text('old service')
        unrelated=units/'other.service';unrelated.write_text('unrelated')
        update=self.updater();original=update.command
        def fail(args,check=True,timeout=600):
            if 'refresh-web' in args and check:
                firewall.write_text('new firewall');owned.write_text('new service')
                (units/'vpn-new.service').write_text('new unit')
                raise u.UpdateError('deployment failed')
            return original(args,check,timeout)
        update.command=fail
        with self.assertRaisesRegex(u.UpdateError,'deployment'):self.execute(update)
        self.assertEqual(firewall.read_text(),'old scoped firewall')
        self.assertEqual(owned.read_text(),'old service');self.assertFalse((units/'vpn-new.service').exists())
        self.assertEqual(unrelated.read_text(),'unrelated');self.assert_private_unchanged()
    def test_archive_collision_fails_before_service_changes(self):
        archive=self.base/'updates'/('update-'+PAYLOAD['version']+'.sh');archive.parent.mkdir();archive.write_text('different')
        update=self.updater()
        with self.assertRaisesRegex(u.UpdateError,'Conflicting'):self.execute(update)
        self.assertFalse(update.calls)
    def test_shared_locks_block_mutations(self):
        for name in ('maintenance.lock','operation.lock'):
            with self.subTest(name=name),(self.base/name).open('a') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX)
                update=self.updater()
                with self.assertRaisesRegex(u.UpdateError,'running'):self.execute(update)
                self.assertFalse(update.calls)
    def test_modified_source_not_removed(self):
        update=self.updater();original=update.command
        def modify(args,check=True,timeout=600):
            result=original(args,check,timeout)
            if 'refresh-web' in args:self.source.write_text('changed')
            return result
        update.command=modify
        with self.assertRaisesRegex(u.UpdateError,'source changed'):self.execute(update)
        self.assertEqual(self.source.read_text(),'changed');self.assert_private_unchanged()
    def test_native_package_lock_blocks_code_update_before_service_changes(self):
        lock=self.root/'var/lib/dpkg/lock-frontend';lock.parent.mkdir(parents=True);lock.touch()
        child=subprocess.Popen([sys.executable,'-c',
            'import fcntl,sys; f=open(sys.argv[1],"r+"); fcntl.lockf(f,fcntl.LOCK_EX); print("locked",flush=True); sys.stdin.read()',str(lock)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(),'locked')
            update=self.updater()
            with self.assertRaisesRegex(u.UpdateError,'Ubuntu package maintenance'):self.execute(update)
            self.assertFalse(update.calls);self.assert_private_unchanged()
            self.assertEqual((self.code/'manage.py').read_text(),'old runtime')
        finally:
            child.communicate('',timeout=5)
    def test_rerun_from_archive_preserves_archive(self):
        self.execute(self.updater());archive=self.base/'updates'/('update-'+PAYLOAD['version']+'.sh')
        self.execute(FakeUpdater(archive,PAYLOAD,self.root,prerelease=True));self.assertTrue(archive.exists())

class PayloadTests(unittest.TestCase):
    def test_embedded_payload_matches_generated_setup(self):
        self.assertEqual(PAYLOAD['files']['setup.sh'],(ROOT/'setup.sh').read_text());u.validate_payload(PAYLOAD);embedded.validate_payload(PAYLOAD)
    def test_modified_payload_rejected(self):
        payload=json.loads(json.dumps(PAYLOAD));payload['files']['manage.py']+='\n# modified'
        with self.assertRaises(u.UpdateError):u.validate_payload(payload)
