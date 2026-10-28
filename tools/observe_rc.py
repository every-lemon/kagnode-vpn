#!/usr/bin/env python3
"""Record bounded, read-only RC observation locally; no credential or journal reads."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sqlite3
import time

UNITS=('AdGuardHome','ipsec','xl2tpd','wg-quick@wg0','vpn-control','vpn-downloads','vpn-management','vpn-firewall')

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
    result={'at':time.time(),'uptime_seconds':float(Path('/proc/uptime').read_text().split()[0]),'services':{}}
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
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if not 0<args.hours<=72:parser.error('Choose greater than zero and at most 72 hours.')
    if os.geteuid()!=0:parser.error('Run on the test server as root.')
    os.umask(0o077)
    start=time.monotonic();started_wall=time.time();deadline=start+args.hours*3600
    # Exclusive creation retains previous observation evidence.
    with args.output.open('x') as stream:
        stream.write(json.dumps({'event':'started','at':time.time(),'duration_hours':args.hours})+'\n');stream.flush()
        while True:
            stream.write(json.dumps(sample(started_wall),sort_keys=True)+'\n');stream.flush()
            remaining=deadline-time.monotonic()
            if remaining<=0:break
            time.sleep(min(60,remaining))
        stream.write(json.dumps({'event':'finished','at':time.time(),'elapsed_seconds':time.monotonic()-start})+'\n');stream.flush();os.fsync(stream.fileno())
    print('Observation recorded. Review service/restart trends, private journals and client checks before marking qualification passed.')

if __name__=='__main__':main()
