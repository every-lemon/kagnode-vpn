"""Explicit release selection, pinned-key signature verification and bounded downloads."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.request
from vpn_version import parse,eligible

REPOSITORY='every-lemon/kagnode-vpn'

def download(url,limit):
    if not url.startswith('https://'):raise ValueError('HTTPS download required.')
    request=urllib.request.Request(url,headers={'Accept':'application/vnd.github+json','User-Agent':'vpn-release-check'})
    with urllib.request.urlopen(request,timeout=30) as response:
        if not response.geturl().startswith('https://'):raise ValueError('Insecure redirect refused.')
        data=response.read(limit+1)
    if len(data)>limit:raise ValueError('Release asset exceeds size limit.')
    return data

def select(releases,prerelease=False):
    candidates=[]
    for release in releases:
        if release.get('draft'):continue
        name=release.get('tag_name','')
        if not name.startswith('v'):continue
        try:order=parse(name[1:])
        except ValueError:continue
        if eligible(name[1:],prerelease) and (prerelease or not release.get('prerelease')):candidates.append((order,release))
    if not candidates:raise ValueError('No eligible release is published.')
    return max(candidates,key=lambda item:item[0])[1]

def fetch(manager,prerelease=False,apply=False):
    releases=json.loads(download('https://api.github.com/repos/'+REPOSITORY+'/releases?per_page=100',2*1024**2))
    release=select(releases,prerelease);version=release['tag_name'][1:]
    current=Path('/opt/kagnode/vpn/VERSION').read_text().strip()
    if parse(version)<=parse(current):return {'version':current,'update':False}
    assets={a['name']:a['browser_download_url'] for a in release['assets']}
    with tempfile.TemporaryDirectory(prefix='release-',dir=manager.BASE) as directory:
        tmp=Path(directory)
        manifest=download(assets['manifest.json'],65536);signature=download(assets['manifest.sig'],4096)
        (tmp/'manifest.json').write_bytes(manifest);(tmp/'manifest.sig').write_bytes(signature)
        manager.command(['openssl','pkeyutl','-verify','-pubin','-inkey','/opt/kagnode/vpn/release-key.pem','-rawin','-in',str(tmp/'manifest.json'),'-sigfile',str(tmp/'manifest.sig')])
        data=json.loads(manifest)
        if data.get('schema')!=1 or data.get('version')!=version or data.get('platform')!='ubuntu-24.04-amd64':raise ValueError('Signed release metadata mismatch.')
        if not apply:return {'version':version,'update':True,'signature':'verified'}
        script=download(assets['update.sh'],8*1024**2);expected=data['assets']['update.sh']
        if len(script)!=expected['size'] or hashlib.sha256(script).hexdigest()!=expected['sha256']:raise ValueError('Update payload checksum mismatch.')
        path=tmp/'update.sh';manager.atomic(path,script,0o700)
        manager.command(['bash',str(path)]+(['--prerelease'] if prerelease else []),timeout=1800)
        return {'version':version,'updated':True}
