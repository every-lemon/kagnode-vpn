#!/usr/bin/env python3
"""Record bounded, read-only RC observation locally; no credential or journal reads."""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sqlite3
import time

UNITS=('AdGuardHome','ipsec','xl2tpd','wg-quick@wg0','vpn-control','vpn-downloads','vpn-management','vpn-firewall')
INSTALLER=Path('/usr/libexec/vpn/setup.sh')

def installed_digest(path=INSTALLER):
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size>8*1024*1024:return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:return None

def boot_identity():
    try:return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    except OSError:return None

def summarize(path):
    """Produce public-safe continuity evidence; a human must still review health."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size>16*1024*1024:
        raise ValueError('Observation must be a regular log of at most 16 MiB.')
    data=path.read_bytes()
    rows=[json.loads(line) for line in data.splitlines()]
    if len(rows)<3 or not all(isinstance(row,dict) for row in rows):
        raise ValueError('Observation is empty or malformed.')
    started,finished=rows[0],rows[-1];samples=rows[1:-1]
    if started.get('event')!='started' or finished.get('event')!='finished' or any('event' in row for row in samples):
        raise ValueError('Observation is incomplete or contains multiple runs.')
    digest=started.get('installer_sha256')
    if not isinstance(digest,str) or not re.fullmatch(r'[a-f0-9]{64}',digest):
        raise ValueError('Observation does not identify its installed candidate.')
    def number(value):
        if isinstance(value,bool) or not isinstance(value,(float,int)) or not math.isfinite(value):
            raise ValueError('Invalid observation timestamp.')
        return value
    start=number(started.get('at'));end=number(finished.get('at'))
    duration=number(finished.get('elapsed_seconds'))
    elapsed=[0]+[number(row.get('elapsed_seconds')) for row in samples]+[duration]
    gaps=[after-before for before,after in zip(elapsed,elapsed[1:])]
    if any(gap<0 for gap in gaps) or abs((end-start)-duration)>120:
        raise ValueError('Observation clock discontinuity detected.')
    for row in samples:
        if abs(number(row.get('at'))-start-row['elapsed_seconds'])>120:
            raise ValueError('Observation clock discontinuity detected.')
    def healthy(row):
        services=row.get('services',{})
        return (not row.get('probe_failed') and isinstance(services,dict) and set(services)==set(UNITS) and
                all(isinstance(service,dict) and service.get('state')=='active' for service in services.values()))
    boot=started.get('boot_id')
    return {'passed':False, 'installer_sha256':digest,'log_sha256':hashlib.sha256(data).hexdigest(),
        'started_at':datetime.datetime.fromtimestamp(start,datetime.timezone.utc).isoformat(),
        'finished_at':datetime.datetime.fromtimestamp(end,datetime.timezone.utc).isoformat(),
        'elapsed_seconds':duration,'sample_count':len(samples),'max_gap_seconds':max(gaps),
        'candidate_unchanged':all(row.get('installer_sha256')==digest for row in samples+[finished]),
        'boot_unchanged':bool(boot) and all(row.get('boot_id')==boot for row in samples+[finished]),
        'services_healthy':all(healthy(row) for row in samples),
        'evidence':'Collector summary only. Review private health logs, recovery attempts, memory and real-client checks before marking passed.'}

def job_summary(path, since):
    """Aggregate counters only; never select job forms, results or identities."""
    try:
        with sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True,timeout=1) as db:
            db.execute('PRAGMA query_only=ON')
            failed=db.execute("SELECT count(*) FROM jobs WHERE status IN ('failed','interrupted') AND updated>=?",(since,)).fetchone()[0]
            pending=db.execute("SELECT count(*) FROM jobs WHERE status IN ('queued','running')").fetchone()[0]
        return {'failed_or_interrupted_since_start':failed,'pending':pending}
    except sqlite3.Error:return {'available':False}

def watchdog_summary(path):
    try:
        if path.is_symlink() or path.stat().st_size>65536:return {'available':False}
        value=json.loads(path.read_text());reboots=value.get('reboots',[]);components=value.get('components',{})
        if not isinstance(reboots,list) or not isinstance(components,dict):return {'available':False}
        attempts=sum(min(len(row['restarts']),10) for row in list(components.values())[:16] if isinstance(row,dict) and isinstance(row.get('restarts'),list))
        return {'recorded_reboots':min(len(reboots),10),'recent_restart_attempts':attempts}
    except (OSError,ValueError,AttributeError):return {'available':False}

def sample(since):
    result={'at':time.time(),'uptime_seconds':float(Path('/proc/uptime').read_text().split()[0]),'services':{},
            'installer_sha256':installed_digest(),'boot_id':boot_identity()}
    result['memory_mib']={}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key,value,*_=line.split()
        if key in ('MemAvailable:','MemTotal:'):result['memory_mib'][key[:-1]]=int(value)//1024
    try:
        response=subprocess.run(['systemctl','show',*[unit+'.service' for unit in UNITS],
            '-p','Id','-p','ActiveState','-p','NRestarts','-p','MemoryCurrent'],capture_output=True,text=True,timeout=5,check=True)
        for block in response.stdout.split('\n\n'):
            fields=dict(row.split('=',1) for row in block.splitlines() if '=' in row)
            unit=fields.get('Id','').removesuffix('.service')
            if unit not in UNITS:continue
            active=fields.get('ActiveState','unknown')
            result['services'][unit]={'state':active if active in ('active','inactive','failed','activating','deactivating','reloading') else 'unknown'}
            for key in ('NRestarts','MemoryCurrent'):
                value=fields.get(key,'')
                result['services'][unit][key]=int(value) if value.isdigit() else None
    except (OSError,subprocess.SubprocessError):result['probe_failed']=True
    result['jobs']=job_summary(Path('/var/lib/vpn/backend.db'),since)
    result['watchdog']=watchdog_summary(Path('/var/lib/vpn/watchdog-state.json'))
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hours',type=float,default=24)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--summary',type=Path,help='Summarize a completed log without changing its evidence or marking qualification passed.')
    args=parser.parse_args()
    if args.summary:
        if args.output:parser.error('Choose --summary or --output, not both.')
        print(json.dumps(summarize(args.summary),sort_keys=True,indent=2));return
    if not args.output:parser.error('--output is required when collecting.')
    if not 0<args.hours<=72:parser.error('Choose greater than zero and at most 72 hours.')
    if os.geteuid()!=0:parser.error('Run on the test server as root.')
    os.umask(0o077)
    digest=installed_digest()
    if digest is None:parser.error('Installed canonical setup.sh is missing or unsafe; cannot identify this candidate.')
    start=time.monotonic();started_wall=time.time();deadline=start+args.hours*3600
    # Exclusive creation retains previous observation evidence.
    with args.output.open('x') as stream:
        stream.write(json.dumps({'event':'started','at':started_wall,'duration_hours':args.hours,
            'installer_sha256':digest,'boot_id':boot_identity()})+'\n');stream.flush()
        while True:
            result=sample(started_wall);result['elapsed_seconds']=time.monotonic()-start
            stream.write(json.dumps(result,sort_keys=True)+'\n');stream.flush()
            remaining=deadline-time.monotonic()
            if remaining<=0:break
            time.sleep(min(60,remaining))
        stream.write(json.dumps({'event':'finished','at':time.time(),'elapsed_seconds':time.monotonic()-start,
            'installer_sha256':installed_digest(),'boot_id':boot_identity()})+'\n');stream.flush();os.fsync(stream.fileno())
    print('Observation recorded. Review service/restart trends, private journals and client checks before marking qualification passed.')

if __name__=='__main__':main()
