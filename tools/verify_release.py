#!/usr/bin/env python3
"""Verify the exact downloaded release before publishing its draft."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from vpn_version import parse

def verify(directory,key,version):
    parse(version)
    directory=Path(directory)
    subprocess.run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(key),'-rawin',
                    '-in',str(directory/'manifest.json'),'-sigfile',str(directory/'manifest.sig')],
                   check=True,capture_output=True)
    manifest=json.loads((directory/'manifest.json').read_text())
    if (manifest.get('schema'),manifest.get('version'),manifest.get('platform'))!=(1,version,'ubuntu-24.04-amd64'):
        raise ValueError('Signed release metadata mismatch.')
    expected={f'vpn_{version}_amd64.deb','setup.sh','update.sh'}
    if set(manifest['assets'])!=expected:
        raise ValueError('Signed asset filenames do not match this release.')
    if {p.name for p in directory.iterdir()}!=expected|{'manifest.json','manifest.sig','SHA256SUMS'}:
        raise ValueError('Downloaded assets are missing, renamed or unexpected.')
    checksums=''
    for name,item in sorted(manifest['assets'].items()):
        path=directory/name
        if path.is_symlink() or not path.is_file() or path.stat().st_size!=item['size']:
            raise ValueError('Asset type or size mismatch: '+name)
        if hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']:
            raise ValueError('Asset checksum mismatch: '+name)
        checksums+=item['sha256']+'  '+name+'\n'
    if (directory/'SHA256SUMS').read_text()!=checksums:
        raise ValueError('SHA256SUMS does not match the signed manifest.')
    return manifest

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('version')
    parser.add_argument('--key',type=Path,default=ROOT/'release-key.pem')
    args=parser.parse_args()
    verify(args.directory,args.key,args.version)
    print('Verified published filenames, signature and all asset checksums for '+args.version)
