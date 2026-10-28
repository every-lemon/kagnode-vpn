#!/usr/bin/env python3
"""RC/stable publication requires recorded qualification of the exact installer."""
import datetime
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
REQUIRED=('automated', 'deployed_reset', 'beta2_upgrade', 'native_protocols', 'apple_import', 'external_ikev2')


def verify(record, version, digest):
    if record.get('version')!=version or record.get('installer_sha256')!=digest:
        raise ValueError('Qualification must identify this version and exact installer digest.')
    checks=record.get('checks',{})
    for name in REQUIRED:
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


if __name__=='__main__':
    version=(ROOT/'VERSION').read_text().strip()
    if '-beta.' not in version:
        path=ROOT/'qualification'/(version+'.json')
        if not path.is_file():raise SystemExit('RC/stable qualification record missing: '+str(path))
        verify(json.loads(path.read_text()),version,hashlib.sha256((ROOT/'setup.sh').read_bytes()).hexdigest())
        print('Exact candidate qualification and 24-hour observation verified.')
    else:print('Beta qualification remains documented separately.')
