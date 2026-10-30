"""Observation counters do not export private job details or watchdog strings."""
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from observe_rc import job_summary,watchdog_summary,summarize,network_summary,UNITS,NETWORK_PROBES

class ObservationTests(unittest.TestCase):
    def test_job_counters_exclude_old_failures_and_never_export_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'jobs.db'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE jobs(status TEXT,updated REAL,form TEXT,result TEXT)')
                db.executemany('INSERT INTO jobs VALUES (?,?,?,?)',[(state,when,'PRIVATE_CREDENTIAL','PRIVATE_CREDENTIAL') for state,when in [('failed',10),('interrupted',30),('running',30),('complete',40)]])
            result=job_summary(path,20)
            self.assertEqual(result,{'failed_or_interrupted_since_start':1,'pending':1})
            self.assertNotIn('PRIVATE_CREDENTIAL',json.dumps(result))
    def test_missing_database_is_not_created(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'missing.db'
            self.assertEqual(job_summary(path,0),{'available':False});self.assertFalse(path.exists())
    def test_watchdog_report_only_contains_bounded_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'watchdog.json'
            path.write_text(json.dumps({'reboots':[1,2],'components':{'PRIVATE_CREDENTIAL':{'restarts':[1,2]}},'secret':'PRIVATE_CREDENTIAL'}))
            self.assertEqual(watchdog_summary(path),{'recorded_reboots':2,'recent_restart_attempts':2})
            path.write_text('corrupt')
            self.assertEqual(watchdog_summary(path),{'available':False})

    def log(self):
        common={'installer_sha256':'a'*64,'boot_id':'synthetic-boot'}
        services={unit:{'state':'active'} for unit in UNITS}
        return [dict(common,event='started',at=100000)]+[
            dict(common,at=100000+i,elapsed_seconds=i,services=services,probes={name:True for name in NETWORK_PROBES}) for i in range(0,86401,60)
        ]+[dict(common,event='finished',at=186400,elapsed_seconds=86400)]

    def summary(self,rows):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'observation.jsonl'
            path.write_text(''.join(json.dumps(row)+'\n' for row in rows))
            return summarize(path)

    def test_summary_binds_completed_log_without_automatically_qualifying(self):
        result=self.summary(self.log())
        self.assertFalse(result['passed']);self.assertEqual(result['elapsed_seconds'],86400)
        self.assertEqual(result['sample_count'],1441);self.assertEqual(result['max_gap_seconds'],60)
        self.assertEqual(len(result['log_sha256']),64)
        self.assertTrue(result['candidate_unchanged']);self.assertTrue(result['boot_unchanged'])
        self.assertTrue(result['services_healthy'])
        self.assertTrue(result['probes_healthy'])

    def test_active_services_cannot_hide_failed_or_missing_network_probes(self):
        for name in NETWORK_PROBES:
            rows=self.log();rows[10]['probes'][name]=False
            result=self.summary(rows)
            with self.subTest(name=name):
                self.assertTrue(result['services_healthy']);self.assertFalse(result['probes_healthy'])
        rows=self.log();del rows[10]['probes']
        self.assertFalse(self.summary(rows)['probes_healthy'])

    def probes(self,lan,runner):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'public.json';path.write_text(json.dumps({'lan':lan}))
            with patch('observe_rc.subprocess.run',side_effect=runner):return network_summary(path)

    def test_network_probe_results_are_strict_bounded_and_redacted(self):
        calls=[]
        def runner(args,**kwargs):
            calls.append(args)
            self.assertEqual(kwargs['timeout'],2);self.assertEqual(kwargs['stderr'],subprocess.DEVNULL)
            if args[0]=='dig':
                self.assertIn('-r',args);self.assertIn('+tries=1',args);self.assertIn('+time=1',args)
                output=b'93.184.215.14\n'
            else:
                self.assertEqual(args[:2],['curl','--disable']);self.assertIn('--noproxy',args)
                self.assertIn('--max-filesize',args);self.assertTrue(args[-1].endswith('/health'))
                output=b'OK\n\n200'
            return subprocess.CompletedProcess(args,0,output)
        result=self.probes('192.168.0.8',runner)
        self.assertEqual(result,{name:True for name in NETWORK_PROBES})
        self.assertEqual(len(calls),4);self.assertIn('+notcp',calls[0]);self.assertIn('+tcp',calls[1])
        self.assertNotIn('192.168.0.8',json.dumps(result));self.assertNotIn('93.184.215.14',json.dumps(result))

    def test_bad_http_dns_and_timeouts_cannot_look_healthy(self):
        for failure in ('timeout','nonzero','dns','http','redirect','oversize'):
            def runner(args,**kwargs):
                if failure=='timeout':raise subprocess.TimeoutExpired(args,2,output=b'PRIVATE_CREDENTIAL')
                output=b'93.184.215.14\n' if args[0]=='dig' else b'OK\n\n200'
                if failure=='dns' and args[0]=='dig':output=b'0.0.0.0\nPRIVATE_CREDENTIAL\n'
                if failure=='http' and args[0]=='curl':output=b'PRIVATE_CREDENTIAL\n200'
                if failure=='redirect' and args[0]=='curl':output=b'OK\n\n302'
                if failure=='oversize':output=b'x'*4097
                return subprocess.CompletedProcess(args,1 if failure=='nonzero' else 0,output)
            result=self.probes('192.168.0.8',runner)
            with self.subTest(failure=failure):
                self.assertFalse(all(result.values()));self.assertNotIn('PRIVATE_CREDENTIAL',json.dumps(result))

    def test_untrusted_lan_never_launches_any_probe(self):
        for lan in ('example.com','http://192.168.0.8','192.168.0.8:53','127.0.0.1','0.0.0.0','224.0.0.1','::1',None,[]):
            def runner(*args,**kwargs):raise AssertionError('Invalid LAN must not launch a probe')
            with self.subTest(lan=lan):self.assertEqual(self.probes(lan,runner),{name:False for name in NETWORK_PROBES})

    def test_summary_detects_candidate_reboot_service_and_sampling_changes(self):
        for field,value,flag in [('installer_sha256','b'*64,'candidate_unchanged'),
                                 ('boot_id','new-boot','boot_unchanged'),('services',{},'services_healthy')]:
            rows=self.log();rows[20][field]=value
            with self.subTest(field=field):self.assertFalse(self.summary(rows)[flag])
        rows=self.log();del rows[10:20]
        self.assertGreater(self.summary(rows)['max_gap_seconds'],150)

    def test_summary_rejects_interrupted_runs_clock_steps_and_missing_identity(self):
        for mutation in ('interrupted','clock','identity','nan'):
            rows=self.log()
            if mutation=='interrupted':rows.pop()
            if mutation=='clock':rows[20]['at']+=3600
            if mutation=='identity':del rows[0]['installer_sha256']
            if mutation=='nan':rows[-1]['elapsed_seconds']=float('nan')
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.summary(rows)
