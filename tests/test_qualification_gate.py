"""A prerelease tag cannot bypass manual qualification or the observation period."""
import copy
import datetime
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from qualify_release import REQUIRED,STABLE_REQUIRED,verify

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

    def stable(self):
        value=self.record();value['version']='4.0.0';value['installer_sha256']='a'*64
        value['checks'].update({name:{'passed':True,'evidence':'Synthetic stable qualification evidence only.'} for name in STABLE_REQUIRED})
        finished=datetime.datetime.fromisoformat(value['observation']['finished_at'])
        value['observation']['started_at']=(finished-datetime.timedelta(seconds=86460)).isoformat()
        value['artifacts']={'setup.sh':'a'*64,'update.sh':'b'*64,'vpn_4.0.0_amd64.deb':'c'*64}
        value['observation'].update(installer_sha256='a'*64,log_sha256='d'*64,elapsed_seconds=86460,
            sample_count=1442,max_gap_seconds=60,candidate_unchanged=True,boot_unchanged=True,services_healthy=True,probes_healthy=True)
        return value

    def test_each_stable_specific_gate_is_required(self):
        for name in STABLE_REQUIRED:
            for missing in (True,False):
                value=self.stable()
                if missing:del value['checks'][name]
                else:value['checks'][name]['passed']=False
                with self.subTest(name=name,missing=missing),self.assertRaisesRegex(ValueError,name):
                    verify(value,'4.0.0','a'*64,value['artifacts'])

    def test_stable_requires_exact_package_and_updater_not_only_installer(self):
        value=self.stable();verify(value,'4.0.0','a'*64,value['artifacts'])
        for name in value['artifacts']:
            actual=dict(value['artifacts']);actual[name]='e'*64
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'every exact'):
                verify(value,'4.0.0','a'*64,actual)
        with self.assertRaisesRegex(ValueError,'every exact'):verify(value,'4.0.0','a'*64)

    def test_stable_rejects_wrong_candidate_missing_or_discontinuous_observation(self):
        for field,bad in [('installer_sha256','b'*64),('log_sha256',''),('candidate_unchanged',False),
                          ('boot_unchanged',False),('services_healthy',False),('probes_healthy',False),('elapsed_seconds',86399),
                          ('elapsed_seconds',90000),
                          ('elapsed_seconds',float('nan')),('max_gap_seconds',151),('sample_count',2)]:
            value=self.stable();value['observation'][field]=bad
            with self.subTest(field=field,bad=bad),self.assertRaises(ValueError):
                verify(value,'4.0.0','a'*64,value['artifacts'])
