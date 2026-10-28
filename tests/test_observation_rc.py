"""Observation counters do not export private job details or watchdog strings."""
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from observe_rc import job_summary,watchdog_summary

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
