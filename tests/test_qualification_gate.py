"""A prerelease tag cannot bypass manual qualification or the observation period."""
import copy
import datetime
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from qualify_release import REQUIRED,verify

class GateTests(unittest.TestCase):
    def record(self):
        now=datetime.datetime.now(datetime.timezone.utc)
        return {'version':'4.0.0-rc.1','installer_sha256':'digest',
            'checks':{name:{'passed':True,'evidence':'Synthetic qualification evidence only.'} for name in REQUIRED},
            'observation':{'passed':True,'started_at':(now-datetime.timedelta(hours=25)).isoformat(),
                'finished_at':(now-datetime.timedelta(minutes=1)).isoformat(),'evidence':'Synthetic observation evidence only.'}}
    def test_complete_matching_candidate_is_accepted(self):verify(self.record(),'4.0.0-rc.1','digest')
    def test_each_required_gate_is_enforced(self):
        for name in REQUIRED:
            value=self.record();value['checks'][name]['passed']=False
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,name):verify(value,'4.0.0-rc.1','digest')
    def test_changed_payload_invalidates_evidence(self):
        with self.assertRaisesRegex(ValueError,'exact installer'):verify(self.record(),'4.0.0-rc.1','different-digest')
    def test_short_observation_is_refused(self):
        value=self.record();value['observation']['started_at']=value['observation']['finished_at']
        with self.assertRaisesRegex(ValueError,'24 completed'):verify(value,'4.0.0-rc.1','digest')
    def test_future_observation_is_refused(self):
        value=self.record();value['observation']['finished_at']=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=1)).isoformat()
        with self.assertRaisesRegex(ValueError,'24 completed'):verify(value,'4.0.0-rc.1','digest')
