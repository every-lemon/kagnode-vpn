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
            for name in ('vpn_auth','vpn_admin','vpn_dashboard','vpn_brand'):
                (root/(name+'.py')).write_bytes((ROOT/'src'/(name+'.py')).read_bytes())
            text=(ROOT/'src/vpn_web.py').read_text().replace("PUBLIC = Path('/var/lib/vpn/public')",'PUBLIC = Path('+repr(str(root))+')')
            (root/'web.py').write_text(text)
            (root/'public.json').write_text(json.dumps({'lan':'127.0.0.1','public':'8.8.8.8','endpoint':'vpn.example.test'}))
            harness='''import io,os,sys,types,runpy
from pathlib import Path
sys.path.insert(0,sys.argv[1])
os.geteuid=lambda:1001
def serve(app,**kwargs):
 from vpn_dashboard import render
 from vpn_brand import NAME,PROJECT
 data={'registry':{'users':{},'devices':{}},'csrf':'fixture','identity':{'role':'owner','username':'Fixture'}}
 for view in ('overview','groups','administrators','audit'):
  document=render(data,view=view)
  assert b'app-shell' in document
  assert NAME.encode() in document and b'<svg ' in document
  assert b'data:image/svg+xml,' in document
 for role,path,port in (('management','/manage',9001),('downloads','/',9000)):
  import vpn_web
  def rpc(request):raise vpn_web.WebError('Session expired')
  worker=vpn_web.Application({'lan':'127.0.0.1','public':'8.8.8.8','endpoint':'vpn.example.test'},role,rpc_call=rpc,public=Path(sys.argv[1]))
  response=[]
  env={'REQUEST_METHOD':'GET','PATH_INFO':path,'QUERY_STRING':'','HTTP_HOST':'127.0.0.1:'+str(port),'REMOTE_ADDR':'127.0.0.1','wsgi.input':io.BytesIO()}
  document=b''.join(worker(env,lambda status,headers:response.extend([status,dict(headers)])))
  assert response[0]=='200 OK',response
  assert NAME.encode() in document and PROJECT.encode() in document and b'<svg ' in document
  assert b'data:image/svg+xml,' in document
  assert "default-src 'none'" in response[1]['Content-Security-Policy']
  assert "img-src data:" in response[1]['Content-Security-Policy']
  assert "'unsafe-inline'" not in response[1]['Content-Security-Policy']
 print('Installed worker renderers passed')
sys.modules['waitress']=types.SimpleNamespace(serve=serve)
runpy.run_path(sys.argv[1]+'/web.py',run_name='__main__')
'''
            result=subprocess.run([sys.executable,'-I','-c',harness,str(root)],capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
