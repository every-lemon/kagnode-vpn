#!/usr/bin/env python3
"""RC/stable publication requires recorded qualification of the exact installer."""
import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
REQUIRED=('automated', 'deployed_reset', 'beta2_upgrade', 'native_protocols', 'apple_import', 'external_ikev2')
STABLE_REQUIRED=('fresh_install', 'rc_upgrade', 'interrupted_update', 'package_lifecycle', 'web_usability')


def verify(record, version, digest, artifacts=None):
    if record.get('version')!=version or record.get('installer_sha256')!=digest:
        raise ValueError('Qualification must identify this version and exact installer digest.')
    checks=record.get('checks',{})
    for name in REQUIRED+(STABLE_REQUIRED if '-' not in version else ()):
        row=checks.get(name,{})
        if row.get('passed') is not True or not isinstance(row.get('evidence'),str) or len(row['evidence'].strip())<20:
            raise ValueError('Missing qualification evidence: '+name)
    observation=record.get('observation',{})
    if observation.get('passed') is not True:raise ValueError('24-hour observation has not passed.')
    times=[]
    for field in ('started_at','finished_at'):
        value=datetime.datetime.fromisoformat(observation.get(field,'').replace('Z','+00:00'))
        if value.utcoffset()!=datetime.timedelta(0):raise ValueError('Observation timestamps must use UTC.')
        times.append(value.timestamp())
    now=datetime.datetime.now(datetime.timezone.utc).timestamp()
    if times[1]-times[0]<86400 or times[1]>now:
        raise ValueError('Observation requires at least 24 completed hours.')
    if not isinstance(observation.get('evidence'),str) or len(observation['evidence'].strip())<20:
        raise ValueError('Observation evidence is missing.')
    if '-' not in version:
        expected={f'vpn_{version}_amd64.deb','setup.sh','update.sh'}
        recorded=record.get('artifacts',{})
        if (not isinstance(recorded,dict) or set(recorded)!=expected or
                any(not isinstance(value,str) or not re.fullmatch(r'[a-f0-9]{64}',value) for value in recorded.values()) or
                recorded!=artifacts or recorded.get('setup.sh')!=digest):
            raise ValueError('Stable qualification must identify every exact release artifact.')
        if observation.get('installer_sha256')!=digest:
            raise ValueError('Observation must identify the exact installed candidate.')
        if not re.fullmatch(r'[a-f0-9]{64}',str(observation.get('log_sha256',''))):
            raise ValueError('Observation log digest is missing.')
        for field in ('candidate_unchanged','boot_unchanged','services_healthy','probes_healthy'):
            if observation.get(field) is not True:
                raise ValueError('Observation failed: '+field)
        for field in ('elapsed_seconds','max_gap_seconds'):
            value=observation.get(field)
            if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value):
                raise ValueError('Invalid observation measurement: '+field)
        count=observation.get('sample_count')
        if (observation['elapsed_seconds']<86400 or not 0<observation['max_gap_seconds']<=150 or
                abs((times[1]-times[0])-observation['elapsed_seconds'])>120 or
                type(count) is not int or count<577):
            raise ValueError('Observation requires continuous measurements for 24 completed hours.')


if __name__=='__main__':
    version=(ROOT/'VERSION').read_text().strip()
    if '-beta.' not in version:
        path=ROOT/'qualification'/(version+'.json')
        if not path.is_file():raise SystemExit('RC/stable qualification record missing: '+str(path))
        artifacts=None
        if '-' not in version:
            from verify_release import verify as verify_assets
            manifest=verify_assets(ROOT/'dist',ROOT/'release-key.pem',version)
            artifacts={name:row['sha256'] for name,row in manifest['assets'].items()}
        verify(json.loads(path.read_text()),version,hashlib.sha256((ROOT/'setup.sh').read_bytes()).hexdigest(),artifacts)
        print('Exact candidate qualification and 24-hour observation verified.')
    else:print('Beta qualification remains documented separately.')
