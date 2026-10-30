"""Exercise the installed worker entrypoint without development modules on sys.path."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_manager import ROOT
from vpn_web import WORKER_MODULES

class DeployedWorkerTests(unittest.TestCase):
    def test_shared_renderers_load_from_actual_deployment_layout(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name in WORKER_MODULES:
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
 data={'registry':{'users':{'u':{'name':'Fixture user'}},'devices':{'d':{'name':'Fixture device','user':'u','protocols':{'wireguard':{'status':'active','backend':'fixture-native'},'ikev2':{'status':'active','backend':'fixture-ike','export':{'files':['fixture.mobileconfig'],'generation':'fixture-generation'}}}}}},'csrf':'fixture','identity':{'role':'owner','username':'Fixture'},'remaining':1800,
 'jobs':[{'id':'a'*32,'action':'export','status':'complete','device':'d','created':1800000000,'updated':1800000000,'result':{'message':'Fixture export ready'}}],
 'tokens':[{'hash':'b'*64,'device':'d','device_name':'Fixture device','expires':1900000000,'status':'available'}],
 'business':{'groups':{'ungrouped':{'name':'ungrouped clients','policy':{'internet':True,'isolation':True,'rules':[]}}},'resources':{},'members':{}},
 'administrators':[{'id':'fixture-admin','username':'Fixture','role':'owner','enabled':True,'enrolled':True}],
 'maintenance':{'reboot_required':False,'mode':'manual','timezone':'UTC'},'audit':{'events':[]}}
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
 # The worker must render populated RPC responses using only its deployed
 # files; importing the development manager can hide missing dependencies.
 worker=vpn_web.Application({'lan':'127.0.0.1','public':'8.8.8.8','endpoint':'vpn.example.test'},'management',rpc_call=lambda request:__import__('json').loads(__import__('json').dumps(data)))
 routes=['/manage','/manage/devices','/manage/users','/manage/jobs','/manage/batches','/manage/system','/manage/delivery','/manage/search','/manage/groups','/manage/administrators','/manage/audit']
 routes += ['/manage/device?device=d&tab='+tab for tab in ('profiles','access','settings','activity')]
 for route in routes:
  path,_,query=route.partition('?');response=[]
  env={'REQUEST_METHOD':'GET','PATH_INFO':path,'QUERY_STRING':query,'HTTP_HOST':'127.0.0.1:9001','REMOTE_ADDR':'127.0.0.1','wsgi.input':io.BytesIO()}
  document=b''.join(worker(env,lambda status,headers:response.extend([status,dict(headers)])))
  assert response[0]=='200 OK',(route,response[0],document[-500:])
  assert b'app-shell' in document,(route,'missing shell')
  assert b'Operation unavailable' not in document,route
 print('All 15 populated worker routes passed')
 # Unexpected failures are identifiable in the private system journal without
 # dumping exception messages, cookies, query strings or form data.
 import contextlib
 secret='PRIVATE-REQUEST-AND-EXCEPTION-FIXTURE'
 def broken(request):raise KeyError(secret)
 worker=vpn_web.Application({'lan':'127.0.0.1','public':'8.8.8.8','endpoint':'vpn.example.test'},'management',rpc_call=broken)
 env={'REQUEST_METHOD':'GET','PATH_INFO':'/manage/device','QUERY_STRING':'device='+secret,'HTTP_HOST':'127.0.0.1:9001','REMOTE_ADDR':'127.0.0.1','HTTP_COOKIE':'vpn_session='+secret,'wsgi.input':io.BytesIO()}
 logged=io.StringIO();response=[]
 with contextlib.redirect_stderr(logged):
  document=b''.join(worker(env,lambda status,headers:response.extend([status,dict(headers)])))
 assert response[0]=='403 Forbidden'
 assert 'type=KeyError' in logged.getvalue() and 'route=/manage/device' in logged.getvalue()
 assert 'location=web.py:' in logged.getvalue()
 assert secret not in logged.getvalue() and secret.encode() not in document
 logged=io.StringIO()
 with contextlib.redirect_stderr(logged):vpn_web.log_worker_error(KeyError(secret),'management','/files/'+secret)
 assert 'route=other' in logged.getvalue() and secret not in logged.getvalue()
 print('Installed worker renderers passed')
sys.modules['waitress']=types.SimpleNamespace(serve=serve)
runpy.run_path(sys.argv[1]+'/web.py',run_name='__main__')
'''
            result=subprocess.run([sys.executable,'-I','-c',harness,str(root)],capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
