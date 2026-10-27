"""4.x update preservation, rollback, archives and explicit prerelease selection."""
import contextlib
import fcntl
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'update.sh').read_text()
runtime=source.split("<<'VPN_STACK_UPDATER_PY'\n",1)[1].split('\nVPN_STACK_UPDATER_PY\n',1)[0]
u=types.ModuleType('updater_runtime');exec(compile(runtime,'updater-runtime','exec'),u.__dict__)
PAYLOAD=u.decode_payload()

class FakeUpdater(u.Updater):
    def __init__(self,*args,fail=None,**kw):super().__init__(*args,**kw);self.calls=[];self.fail=fail
    def command(self,args,check=True):
        self.calls.append(list(map(str,args)))
        if self.fail and self.fail in list(map(str,args)) and check:raise u.UpdateError('simulated deployment failure')
        return types.SimpleNamespace(returncode=0)
    def diagnostics(self,phase):(self.run_dir/(phase+'-journal.log')).write_text('captured before rollback')

class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.base=self.root/'var/lib/vpn';self.code=self.root/'usr/lib/vpn';self.helpers=self.root/'usr/libexec/vpn'
        for path in (self.base,self.code,self.helpers,self.root/'etc/vpn'):path.mkdir(parents=True,exist_ok=True)
        self.state=self.root/'etc/vpn/state.json';self.state.write_text(json.dumps({'version':4,'installed':True,'clients':{'device':{'private':'fixture'}}}))
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
        with self.assertRaisesRegex(u.UpdateError,'Prerelease'):self.execute(FakeUpdater(self.source,PAYLOAD,self.root))
    def test_downgrade_refused(self):
        (self.code/'VERSION').write_text('4.0.1')
        with self.assertRaisesRegex(u.UpdateError,'downgrade'):self.execute(self.updater())
    def test_failure_captures_journal_and_restores_code_only(self):
        update=self.updater(fail='refresh-web')
        with self.assertRaisesRegex(u.UpdateError,'deployment'):self.execute(update)
        self.assert_private_unchanged();self.assertTrue(self.source.exists())
        self.assertEqual((self.code/'manage.py').read_text(),'old runtime')
        self.assertTrue((update.run_dir/'failure-journal.log').exists())
        self.assertEqual(json.loads((update.run_dir/'journal.json').read_text())['status'],'code-restored')
    def test_failure_restores_owned_firewall_and_units_without_touching_unrelated_units(self):
        units=self.root/'etc/systemd/system';units.mkdir(parents=True)
        firewall=self.helpers/'firewall.sh';firewall.write_text('old scoped firewall');firewall.chmod(0o700)
        owned=units/'vpn-management.service';owned.write_text('old service')
        unrelated=units/'other.service';unrelated.write_text('unrelated')
        update=self.updater();original=update.command
        def fail(args,check=True):
            if 'refresh-web' in args and check:
                firewall.write_text('new firewall');owned.write_text('new service')
                (units/'vpn-new.service').write_text('new unit')
                raise u.UpdateError('deployment failed')
            return original(args,check)
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
        def modify(args,check=True):
            result=original(args,check)
            if 'refresh-web' in args:self.source.write_text('changed')
            return result
        update.command=modify
        with self.assertRaisesRegex(u.UpdateError,'source changed'):self.execute(update)
        self.assertEqual(self.source.read_text(),'changed');self.assert_private_unchanged()
    def test_rerun_from_archive_preserves_archive(self):
        self.execute(self.updater());archive=self.base/'updates'/('update-'+PAYLOAD['version']+'.sh')
        self.execute(FakeUpdater(archive,PAYLOAD,self.root,prerelease=True));self.assertTrue(archive.exists())

class PayloadTests(unittest.TestCase):
    def test_embedded_payload_matches_generated_setup(self):
        self.assertEqual(PAYLOAD['files']['setup.sh'],(ROOT/'setup.sh').read_text());u.validate_payload(PAYLOAD)
    def test_modified_payload_rejected(self):
        payload=json.loads(json.dumps(PAYLOAD));payload['files']['manage.py']+='\n# modified'
        with self.assertRaises(u.UpdateError):u.validate_payload(payload)
