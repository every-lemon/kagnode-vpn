#!/usr/bin/env python3
"""Development guard: reserve 1 GiB and account for the next operation."""
from pathlib import Path
import sys
needed=int(sys.argv[1]) if len(sys.argv)>1 else 1024
values={k:int(v.split()[0]) for k,v in (line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())}
available=values['MemAvailable']//1024
limit=Path('/sys/fs/cgroup/memory.max');current=Path('/sys/fs/cgroup/memory.current')
if limit.exists() and limit.read_text().strip()!='max':
    available=min(available,(int(limit.read_text())-int(current.read_text()))//1024**2)
print(f'Available: {available} MiB; next operation budget: {needed} MiB; reserve: 1024 MiB')
if available<needed+1024:raise SystemExit('Insufficient memory headroom. Stop test workloads before proceeding.')
