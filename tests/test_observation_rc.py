"""Observation counters do not export private job details or watchdog strings."""
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from observe_rc import job_summary,watchdog_summary,summarize,UNITS

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
            dict(common,at=100000+i,elapsed_seconds=i,services=services) for i in range(0,86401,60)
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
