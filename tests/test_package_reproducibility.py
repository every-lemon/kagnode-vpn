"""Exact stable package qualification survives checkout/build timestamp changes."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]

@unittest.skipUnless(shutil.which('dpkg-deb'),'dpkg-deb required')
class PackageReproducibilityTests(unittest.TestCase):
    def test_actual_package_is_identical_after_checkout_timestamps_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ('src','packaging'):shutil.copytree(ROOT/name,root/name,ignore=shutil.ignore_patterns('__pycache__'))
            for name in ('VERSION','build.py','release-key.pem','LICENSE','THIRD_PARTY_NOTICES.md','README.md'):
                shutil.copy2(ROOT/name,root/name)
            (root/'tools').mkdir();shutil.copy2(ROOT/'tools/package.py',root/'tools/package.py')
            env={key:value for key,value in os.environ.items() if key!='VPN_RELEASE_KEY'}
            env['SOURCE_DATE_EPOCH']='1800000000'
            def build():
                subprocess.run([sys.executable,str(root/'tools/package.py')],check=True,capture_output=True,env=env)
                return hashlib.sha256(next((root/'dist').glob('*.deb')).read_bytes()).hexdigest()
            before=build()
            for path in root.rglob('*'):
                if path.is_file() and 'dist' not in path.parts:os.utime(path,(1900000000,1900000000))
            env['SOURCE_DATE_EPOCH']='2000000000'
            self.assertEqual(before,build())
