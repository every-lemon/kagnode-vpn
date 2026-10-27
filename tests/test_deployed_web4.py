"""Exercise the installed worker entrypoint without development modules on sys.path."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_manager import ROOT

class DeployedWorkerTests(unittest.TestCase):
    def test_shared_renderers_load_from_actual_deployment_layout(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name in ('vpn_auth','vpn_admin','vpn_dashboard'):
                (root/(name+'.py')).write_bytes((ROOT/'src'/(name+'.py')).read_bytes())
            text=(ROOT/'src/vpn_web.py').read_text().replace("PUBLIC = Path('/var/lib/vpn/public')",'PUBLIC = Path('+repr(str(root))+')')
            (root/'web.py').write_text(text)
            (root/'public.json').write_text(json.dumps({'lan':'127.0.0.1','public':'8.8.8.8','endpoint':'vpn.example.test'}))
            harness='''import os,sys,types,runpy
sys.path.insert(0,sys.argv[1])
os.geteuid=lambda:1001
def serve(app,**kwargs):
 from vpn_dashboard import render
 data={'registry':{'users':{},'devices':{}},'csrf':'fixture','identity':{'role':'owner','username':'Fixture'}}
 for view in ('overview','groups','administrators','audit'):
  assert b'app-shell' in render(data,view=view)
 print('Installed worker renderers passed')
sys.modules['waitress']=types.SimpleNamespace(serve=serve)
runpy.run_path(sys.argv[1]+'/web.py',run_name='__main__')
'''
            result=subprocess.run([sys.executable,'-I','-c',harness,str(root)],capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
