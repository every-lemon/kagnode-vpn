"""RC diagnostics bound resource use and expose only authorized, allowlisted facts."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import test_admin350 as fixture
from test_manager import m
import vpn_diagnostics as diagnostics
from auth_fixture import enroll


class DiagnosticTests(unittest.TestCase):
    setUp = fixture.AdminTests.setUp
    tearDown = fixture.AdminTests.tearDown
    request = fixture.AdminTests.request
    rpc = fixture.AdminTests.rpc

    def runner(self, args, timeout):
        self.assertLessEqual(timeout, 3)
        output = {'systemctl':'active\n'*len(args[2:]), 'timedatectl':'yes\n', 'dig':'93.184.215.14\n',
                  'getent':'203.0.113.9 endpoint\n', 'ip':'default via 192.168.0.1 dev ens18\n',
                  'iptables':'-N VPNSTACK-LAN-FWD\n', 'wg':'wireguard-tools v1.0.20210914\n', 'ipsec':'Linux Libreswan 5.3\n'}[args[0]]
        return subprocess.CompletedProcess(args,0,output,'')

    def test_service_health_covers_all_eight_units_including_adguard(self):
        requested = []
        def runner(args, timeout):
            if args[:2] == ['systemctl', 'is-active']:
                requested.extend(args[2:])
                return subprocess.CompletedProcess(args, 0, 'active\n' * 8, '')
            return self.runner(args, timeout)
        report = diagnostics.collect(m, runner=runner)
        self.assertEqual(requested, ['AdGuardHome', 'ipsec', 'xl2tpd', 'wg-quick@wg0',
                                     'vpn-control', 'vpn-downloads', 'vpn-management', 'vpn-firewall'])
        self.assertEqual(report['checks'][0]['status'], 'pass')
        self.assertIn('AdGuard Home', report['checks'][0]['message'])

    def test_failed_or_missing_service_is_unavailable_even_with_nonzero_exit(self):
        for state, returncode in (('failed', 0), ('failed', 3), ('inactive', 3), ('unknown', 4)):
            with self.subTest(state=state, returncode=returncode):
                def runner(args, timeout):
                    if args[:2] == ['systemctl', 'is-active']:
                        return subprocess.CompletedProcess(args, returncode, state + '\n' + 'active\n' * 7, 'private-tool-output')
                    return self.runner(args, timeout)
                report = diagnostics.collect(m, runner=runner)
                check = report['checks'][0]
                self.assertEqual(check['status'], 'failure')
                self.assertEqual(check['message'], 'One or more managed services are unavailable.')
                self.assertTrue(check['next_step'])
                self.assertNotIn('private-tool-output', json.dumps(report))

    def test_incomplete_malformed_and_failed_service_probes_never_pass(self):
        for output, returncode in (('active\n' * 7, 0), ('active\n' * 9, 0), ('', 0),
                                   ('active\n' * 8, 1), ('private-tool-output\n' * 8, 0)):
            with self.subTest(rows=len(output.split()), returncode=returncode):
                def runner(args, timeout):
                    if args[:2] == ['systemctl', 'is-active']:
                        return subprocess.CompletedProcess(args, returncode, output, '')
                    return self.runner(args, timeout)
                report = diagnostics.collect(m, runner=runner)
                self.assertEqual(report['checks'][0]['status'], 'failure')
                self.assertTrue(report['checks'][0]['next_step'])
                self.assertNotIn('private-tool-output', json.dumps(report))

    def test_findings_never_claim_wan_connectivity_and_do_not_contain_addresses(self):
        report=diagnostics.collect(m,self.backend,self.ident,runner=self.runner)
        self.assertEqual(report['checks'][-1]['id'],'wan')
        self.assertEqual(report['checks'][-1]['status'],'unknown')
        self.assertEqual(next(c for c in report['checks'] if c['id']=='session-wireguard')['status'],'unknown')
        raw=json.dumps(report)
        for secret in ('192.168.0.8','203.0.113.9','vpn.example.com','Example Phone','PRIVATE_WIREGUARD_BYTES'):
            self.assertNotIn(secret,raw)
        self.assertEqual(diagnostics.path_for(m,self.ident).stat().st_mode&0o777,0o600)

    def test_timeout_failure_is_actionable_without_raw_tool_output(self):
        def failed(args,timeout):raise TimeoutError('secret-raw-tool-output')
        report=diagnostics.collect(m,runner=failed)
        self.assertEqual(report['checks'][0]['status'],'failure')
        self.assertTrue(report['checks'][0]['next_step'])
        self.assertNotIn('secret-raw-tool-output',json.dumps(report))

    def test_corrupt_cache_does_not_break_management_views(self):
        m.atomic(diagnostics.path_for(m,self.ident),json.dumps({'schema':1,'checks':'corrupt'}))
        self.assertIsNone(diagnostics.cached(m,self.ident))
        self.assertEqual(self.request('/manage/device?device='+self.ident)[0],'200 OK')
        self.assertNotEqual(diagnostics.path_for(m,'system'),diagnostics.path_for(m))

    def test_support_export_rebuilds_allowlist_instead_of_copying_cached_strings(self):
        diagnostics.collect(m,runner=self.runner)
        path=diagnostics.path_for(m)
        saved=json.loads(path.read_text());saved['password']='TOP_SECRET';saved['checks'][0]['message']='TOP_SECRET'
        saved['checks'].append({'id':'TOP_SECRET','status':'TOP_SECRET'});m.atomic(path,json.dumps(saved))
        raw=diagnostics.support(m)
        self.assertNotIn(b'TOP_SECRET',raw)
        self.assertEqual(len(json.loads(raw)['checks']),7)

    def test_report_download_requires_owner_session_and_csrf(self):
        status,headers,body=self.request('/api/v1/file','POST',{'kind':'support'})
        self.assertEqual(status,'200 OK');self.assertEqual(headers['Content-Type'],'application/json')
        self.assertIn('vpn-support.json',headers['Content-Disposition'])
        self.assertEqual(self.request('/manage/file','POST',{'kind':'support'},csrf=False)[0],'403 Forbidden')
        owner_session=self.session
        _,self.session,self.csrf,_=enroll(self.store,'operator','operator-fixture-password','operator',self.actor)
        self.assertEqual(self.request('/manage/file','POST',{'kind':'support'})[0],'403 Forbidden')
        self.session=owner_session

    def test_queued_check_rechecks_actor_and_deduplicates(self):
        form={'action':'connection-check','device':self.ident}
        with patch.object(diagnostics,'collect') as collect:
            self.controller.handle({'op':'action','session':self.session,'csrf':self.csrf,'peer':self.state['lan'],'host':self.state['lan']+':9001','form':form},0)
            self.controller.handle({'op':'action','session':self.session,'csrf':self.csrf,'peer':self.state['lan'],'host':self.state['lan']+':9001','form':form},0)
            self.assertEqual(len(self.backend.repo.jobs()),1)
            collect.assert_not_called()
            with self.store.connect() as db:db.execute('UPDATE administrators SET enabled=0 WHERE id=?',(self.actor,))
            self.backend.repo.run_one(self.backend,self.controller.action)
            collect.assert_not_called()
        self.assertEqual(self.backend.repo.jobs()[0]['status'],'failed')

    def test_page_views_and_polling_only_read_saved_findings(self):
        diagnostics.collect(m,self.backend,self.ident,runner=self.runner)
        with patch.object(diagnostics,'probe',side_effect=AssertionError('Must not probe while rendering')):
            status,_,body=self.request('/manage/device?device='+self.ident)
            self.assertEqual(status,'200 OK')
            self.assertIn(b'Administrative state:',body)
            self.assertIn(b'Connection checks',body)
            self.assertIn(b'UNKNOWN',body)
            self.assertIn(b'Recent profile tasks',body)
            self.assertNotIn(b'run managed repair for a verified service fault',body)
            self.assertIn(b'Connect this device, then run another check',body)
        self.assertFalse(b'animation:' in body)

    def test_recent_wireguard_handshake_must_match_exact_managed_peer(self):
        state=m.load();state['clients']['native-phone']={'wireguard':{'public':'correct-peer'}};m.save(state)
        def runner(args,timeout):
            if args[0]=='wg':return subprocess.CompletedProcess(args,0,'wrong-peer\t'+str(int(time.time()))+'\n','')
            return self.runner(args,timeout)
        report=diagnostics.collect(m,self.backend,self.ident,runner=runner)
        self.assertEqual(next(c for c in report['checks'] if c['id']=='session-wireguard')['status'],'unknown')
        def exact(args,timeout):
            if args[0]=='wg':return subprocess.CompletedProcess(args,0,'correct-peer\t'+str(int(time.time()))+'\n','')
            return self.runner(args,timeout)
        report=diagnostics.collect(m,self.backend,self.ident,runner=exact)
        self.assertEqual(next(c for c in report['checks'] if c['id']=='session-wireguard')['status'],'pass')

    def test_cache_retention_is_bounded(self):
        folder=m.BASE/'diagnostics';folder.mkdir()
        for n in range(25):(folder/(format(n,'032x')+'.json')).write_text('{}')
        diagnostics.collect(m,runner=self.runner)
        self.assertEqual(len(list(folder.glob('*.json'))),diagnostics.RETENTION)
        with self.assertRaises(ValueError):diagnostics.cached(m,'../../private')

    def add_session(self, protocol, **fields):
        record=self.backend.load()
        record['devices'][self.ident]['protocols']={protocol:{'backend':'native-phone','status':'active'}}
        self.backend.save(record)
        row=dict(device=self.ident,protocol=protocol,identity='native-phone',boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),**fields)
        with self.backend.repo.connect() as db:db.execute('INSERT OR REPLACE INTO policy_sessions VALUES (?,?,?)',('test',json.dumps(row),time.time()))
        return row

    def test_ike_observation_requires_current_boot_identity_and_exact_spi(self):
        self.add_session('ikev2',reqid=7,spi=42)
        def runner(args,timeout):
            if args[:4]==['ip','-j','xfrm','state']:return subprocess.CompletedProcess(args,0,json.dumps([{'reqid':7,'spi':'0x2a','proto':'esp','dst':'192.168.0.8'}]),'')
            return self.runner(args,timeout)
        result=diagnostics.collect(m,self.backend,self.ident,runner=runner)
        self.assertEqual(next(c for c in result['checks'] if c['id']=='session-ikev2')['status'],'pass')
        with self.backend.repo.connect() as db:db.execute("UPDATE policy_sessions SET data=json_set(data,'$.spi',43)")
        result=diagnostics.collect(m,self.backend,self.ident,runner=runner)
        self.assertEqual(next(c for c in result['checks'] if c['id']=='session-ikev2')['status'],'unknown')
        with self.backend.repo.connect() as db:db.execute("UPDATE policy_sessions SET data=json_set(data,'$.spi',42,'$.boot','old-boot')")
        result=diagnostics.collect(m,self.backend,self.ident,runner=runner)
        self.assertEqual(next(c for c in result['checks'] if c['id']=='session-ikev2')['status'],'unknown')
        with self.backend.repo.connect() as db:db.execute("UPDATE policy_sessions SET data=json_set(data,'$.boot',?,'$.identity','different-device')",(Path('/proc/sys/kernel/random/boot_id').read_text().strip(),))
        result=diagnostics.collect(m,self.backend,self.ident,runner=runner)
        self.assertEqual(next(c for c in result['checks'] if c['id']=='session-ikev2')['status'],'unknown')

    def test_ike_json_and_ubuntu_text_require_exact_inbound_esp_selectors(self):
        self.add_session('ikev2',reqid=7,spi=42)
        for encoding in ('json','text'):
            for changes,expected in (({},'pass'),({'dst':'8.8.8.8'},'pass'),({'dst':'203.0.113.7'},'unknown'),
                                     ({'spi':'0x2b'},'unknown'),({'reqid':8},'unknown'),({'proto':'ah'},'unknown')):
                item={'src':'203.0.113.7','dst':'192.168.0.8','proto':'esp','spi':'0x2a','reqid':7,**changes}
                if encoding=='json':output=json.dumps([item|{'auth':'PRIVATE_XFRM_KEY'}])
                else:output=('src {src} dst {dst}\n\tproto {proto} spi {spi} reqid {reqid} mode tunnel\n'
                             '\tauth-trunc hmac(sha256) PRIVATE_XFRM_KEY 128\n').format(**item)
                def runner(args,timeout):
                    self.assertLessEqual(timeout,3)
                    if args[:4]==['ip','-j','xfrm','state']:return subprocess.CompletedProcess(args,0,output,'')
                    return self.runner(args,timeout)
                with self.subTest(encoding=encoding,changes=changes):
                    report=diagnostics.collect(m,self.backend,self.ident,runner=runner)
                    self.assertEqual(next(c for c in report['checks'] if c['id']=='session-ikev2')['status'],expected)
                    self.assertNotIn('PRIVATE_XFRM_KEY',json.dumps(report))
                    self.assertNotIn('203.0.113.7',json.dumps(report))

    def test_ike_malformed_output_and_separate_states_never_match(self):
        self.add_session('ikev2',reqid=7,spi=42)
        for output in ('{}','[null]', '[{"dst":{},"proto":"esp"}]', 'private unexpected output',
                       'src 203.0.113.7 dst 192.168.0.8\n proto esp spi 0x2b reqid 7\n'
                       'src 192.168.0.8 dst 203.0.113.7\n proto esp spi 0x2a reqid 7\n'):
            def runner(args,timeout):
                if args[:4]==['ip','-j','xfrm','state']:return subprocess.CompletedProcess(args,0,output,'')
                return self.runner(args,timeout)
            with self.subTest(output=output):
                report=diagnostics.collect(m,self.backend,self.ident,runner=runner)
                self.assertEqual(next(c for c in report['checks'] if c['id']=='session-ikev2')['status'],'unknown')
    def test_ppp_reused_interface_does_not_claim_session(self):
        self.add_session('l2tp',interface='ppp9',ifindex=20)
        def runner(args,timeout):
            if args[:4]==['ip','-j','link','show']:return subprocess.CompletedProcess(args,0,json.dumps([{'ifindex':21,'group':21}]),'')
            return self.runner(args,timeout)
        result=diagnostics.collect(m,self.backend,self.ident,runner=runner)
        self.assertEqual(next(c for c in result['checks'] if c['id']=='session-l2tp')['status'],'unknown')


class ProbeTests(unittest.TestCase):
    def test_real_child_timeout_is_bounded(self):
        start=time.monotonic()
        with self.assertRaises(TimeoutError):diagnostics.probe([sys.executable,'-c','import time;time.sleep(10)'],.1)
        self.assertLess(time.monotonic()-start,2)

    def test_real_child_output_is_bounded(self):
        with self.assertRaisesRegex(ValueError,'output limit'):
            diagnostics.probe([sys.executable,'-c','import os;os.write(1,b"x"*1000000)'],2)

    def test_real_child_output_and_returncode(self):
        result=diagnostics.probe([sys.executable,'-c','print("bounded");raise SystemExit(3)'],2)
        self.assertEqual(result.returncode,3);self.assertEqual(result.stdout,'bounded\n')
