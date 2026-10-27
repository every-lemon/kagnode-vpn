"""Real signatures and post-upload filename/integrity qualification."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from verify_release import verify

class DownloadedReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.assets=self.root/'assets';self.assets.mkdir()
        self.version='4.0.0-beta.2';self.key=self.root/'private.pem';self.public=self.root/'public.pem'
        self.command('openssl','genpkey','-algorithm','ED25519','-out',str(self.key))
        self.command('openssl','pkey','-in',str(self.key),'-pubout','-out',str(self.public))
        names=['setup.sh','update.sh','vpn_'+self.version+'_amd64.deb']
        items={}
        for name in names:
            data=('synthetic artifact '+name).encode();(self.assets/name).write_bytes(data)
            items[name]={'sha256':hashlib.sha256(data).hexdigest(),'size':len(data)}
        (self.assets/'manifest.json').write_text(json.dumps({'schema':1,'version':self.version,'platform':'ubuntu-24.04-amd64','assets':items}))
        (self.assets/'SHA256SUMS').write_text(''.join(row['sha256']+'  '+name+'\n' for name,row in sorted(items.items())))
        self.command('openssl','pkeyutl','-sign','-rawin','-inkey',str(self.key),'-in',str(self.assets/'manifest.json'),'-out',str(self.assets/'manifest.sig'))
    def command(self,*args):return subprocess.run(args,check=True,capture_output=True)
    def test_valid_downloaded_release(self):
        self.assertEqual(verify(self.assets,self.public,self.version)['version'],self.version)
    def test_server_renamed_package_is_rejected_before_publication(self):
        path=self.assets/('vpn_'+self.version+'_amd64.deb');path.rename(self.assets/'server-renamed.deb')
        with self.assertRaisesRegex(ValueError,'renamed'):verify(self.assets,self.public,self.version)
    def test_modified_asset_is_rejected(self):
        path=self.assets/'update.sh';data=path.read_bytes();path.write_bytes(b'X'+data[1:])
        with self.assertRaisesRegex(ValueError,'checksum'):verify(self.assets,self.public,self.version)
    def test_modified_manifest_fails_signature(self):
        path=self.assets/'manifest.json';path.write_text(path.read_text()+' ')
        with self.assertRaises(subprocess.CalledProcessError):verify(self.assets,self.public,self.version)
    def test_unsigned_checksum_list_must_match_signed_metadata(self):
        (self.assets/'SHA256SUMS').write_text('untrusted checksums')
        with self.assertRaisesRegex(ValueError,'SHA256SUMS'):verify(self.assets,self.public,self.version)
