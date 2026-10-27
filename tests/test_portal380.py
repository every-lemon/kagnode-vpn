"""Device grants, legacy compatibility, native MIME and total single-use claims."""
import hashlib
import io
import json
import threading
import types
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, urlsplit, parse_qs
import test_admin350 as fixture
import vpn_web as web


class PortalTests(unittest.TestCase):
    setUp = fixture.AdminTests.setUp
    tearDown = fixture.AdminTests.tearDown
    request = fixture.AdminTests.request
    rpc = fixture.AdminTests.rpc
    apple_fixture = fixture.AdminTests.apple_fixture

    def publish(self):
        self.filename, self.apple_bytes = self.apple_fixture()
        result = self.controller.action({'actor': self.actor, 'action':'delivery-link','device':self.ident})
        return parse_qs(urlsplit(result['url']).query)['token'][0]

    def public(self, method, target, form=None, extra=None):
        url = urlsplit(target)
        raw = urlencode(form or {}).encode()
        env = {'REQUEST_METHOD':method,'PATH_INFO':url.path,'QUERY_STRING':url.query,
               'HTTP_HOST':self.state['public']+':9000','REMOTE_ADDR':'203.0.113.22',
               'CONTENT_TYPE':'application/x-www-form-urlencoded','CONTENT_LENGTH':str(len(raw)),'wsgi.input':io.BytesIO(raw)}
        env.update(extra or {})
        result=[]
        body=b''.join(web.Application(self.state,'downloads',rpc_call=self.rpc,public=self.base/'public')(env,lambda status,headers:result.extend([status,dict(headers)])))
        return result[0],result[1],body

    def test_landing_lists_only_public_certificates_and_accepts_token(self):
        token = self.publish()
        path=self.base/'public/certs';path.mkdir(parents=True)
        (path/'ca.pem').write_text('PUBLIC CERT')
        status,_,body=self.public('GET','/')
        self.assertEqual(status,'200 OK')
        self.assertIn(b'/access',body)
        self.assertIn(b'/cert/ca.pem',body)
        self.assertNotIn(b'Example Phone',body)
        self.assertNotIn(b'native-phone',body)
        status,_,body=self.public('POST','/access',{'token':token})
        self.assertEqual(status,'200 OK')
        self.assertIn(b'Example Phone',body)
        self.assertIn(b'one download total',body)
        self.assertIn(self.filename.encode(),body)
        self.assertIn(b'native-phone.conf',body)
        self.store.inspect(token)

    def test_apple_selection_redirects_to_native_file_and_consumes_all_choices(self):
        token=self.publish();record=self.store.inspect(token)
        status,headers,_=self.public('POST','/download',{'token':token,'confirm':record['confirm'],'filename':self.filename})
        self.assertEqual(status,'303 See Other')
        self.assertTrue(headers['Location'].startswith('/files/'))
        self.store.inspect(token)
        status,headers,body=self.public('GET',headers['Location'])
        self.assertEqual(status,'200 OK')
        self.assertEqual(headers['Content-Type'],'application/x-apple-aspen-config')
        self.assertIn('inline',headers['Content-Disposition'])
        self.assertEqual(body,self.apple_bytes)
        self.assertEqual(self.public('GET','/files/native-phone.conf?token='+token)[0],'403 Forbidden')

    def test_direct_file_head_and_range_do_not_consume(self):
        token=self.publish();target='/files/'+self.filename+'?'+urlencode({'token':token})
        status,headers,body=self.public('HEAD',target)
        self.assertEqual(status,'200 OK')
        self.assertEqual(body,b'')
        self.assertEqual(int(headers['Content-Length']),len(self.apple_bytes))
        self.assertEqual(self.public('GET',target,extra={'HTTP_RANGE':'bytes=0-20'})[0],'416 Range Not Satisfiable')
        self.store.inspect(token)
        self.assertEqual(self.public('GET',target)[2],self.apple_bytes)

    def test_two_file_choices_share_one_atomic_claim(self):
        token=self.publish();barrier=threading.Barrier(2);out=[]
        def claim(name):
            barrier.wait()
            out.append(self.public('GET','/files/'+name+'?token='+token)[0])
        threads=[threading.Thread(target=claim,args=(name,)) for name in (self.filename,'native-phone.conf')]
        for thread in threads:thread.start()
        for thread in threads:thread.join()
        self.assertEqual(sorted(out),['200 OK','403 Forbidden'])

    def test_file_changes_revocation_and_deletion_invalidate_device_grants(self):
        token=self.publish()
        (self.base/'clients/wireguard/native-phone.conf').write_text('CHANGED SECRET')
        self.assertEqual(self.public('GET','/?token='+token)[0],'403 Forbidden')
        token=self.controller.action({'actor': self.actor, 'action':'delivery-link','device':self.ident})['token']
        registry,device=self.backend.device(self.ident)
        device['protocols']['wireguard']['status']='revoked';self.backend.save(registry)
        self.assertEqual(self.public('GET','/?token='+token)[0],'403 Forbidden')
        token=self.controller.action({'actor': self.actor, 'action':'delivery-link','device':self.ident})['token']
        self.backend.repo.enqueue({'action':'delete-profile','device':self.ident,'protocol':'all','confirm':'DELETE'})
        self.assertEqual(self.public('GET','/?token='+token)[0],'403 Forbidden')

    def test_unknown_file_and_path_traversal_do_not_consume(self):
        token=self.publish()
        for name in ('other-device.conf','../state.json','state.json'):
            self.assertEqual(self.public('GET','/files/'+name+'?token='+token)[0],'403 Forbidden')
        self.store.inspect(token)
        self.assertEqual(self.public('GET','/files/'+self.filename)[0],'403 Forbidden')

    def test_revocation_between_validation_and_claim_is_atomic(self):
        token=self.publish()
        original=self.store.claim
        def revoke_then_claim(value, confirmation, guard=None):
            registry,device=self.backend.device(self.ident)
            device['protocols']['ikev2']['status']='revoked'
            self.backend.save(registry)
            return original(value,confirmation,guard=guard)
        with patch.object(self.store,'claim',side_effect=revoke_then_claim):
            self.assertEqual(self.public('GET','/files/'+self.filename+'?token='+token)[0],'403 Forbidden')
        # Failed authorization did not spend the capability or transmit bytes.
        self.store.inspect(token)

    def test_device_grants_use_targeted_reads_and_reject_owner_changes(self):
        with patch.object(self.backend,'load',side_effect=AssertionError('Full registry read')):
            result=self.controller.action({'actor': self.actor, 'action':'delivery-link','device':self.ident})
            token=result['token']
            self.assertEqual(self.public('GET','/files/native-phone.conf?token='+token)[0],'200 OK')
        token=self.publish()
        other=self.backend.user_add('New owner')
        self.backend.assign(self.ident,other)
        self.assertEqual(self.public('GET','/?token='+token)[0],'403 Forbidden')

    def test_legacy_file_tokens_and_old_apple_route_remain_valid(self):
        filename,payload=self.apple_fixture()
        token=self.store.issue(self.ident,filename,'apple-generation')
        record=self.store.inspect(token)
        self.assertEqual(record['filename'],filename)
        target='/profile.mobileconfig?'+urlencode({'token':token,'confirm':record['confirm']})
        self.assertEqual(self.public('GET',target)[2],payload)

    def test_wireguard_does_not_require_ikev2_or_zip(self):
        result=self.controller.action({'actor': self.actor, 'action':'delivery-link','device':self.ident})
        token=result['token']
        self.assertEqual(self.public('GET','/files/native-phone.conf?token='+token)[2],b'PRIVATE_WIREGUARD_BYTES')

    def test_disabled_owners_cannot_publish_prepared_files(self):
        registry=self.backend.load();registry['users'][self.user]['disabled']=True;self.backend.save(registry)
        with self.assertRaises(web.WebError):
            self.controller.action({'actor': self.actor, 'action':'delivery-link','device':self.ident})

    def test_expiry_and_manifest_cleanup_preserve_active_legacy_tokens(self):
        token=self.publish()
        with self.store.connect() as db:
            db.execute('UPDATE tokens SET expires=? WHERE hash=?',(self.store.clock()-90000,web.digest(token)))
        legacy=self.store.issue(self.ident,'unused.p12','legacy',2592000)
        self.backend.repo.cleanup()
        with self.store.connect() as db:
            self.assertIsNone(db.execute('SELECT 1 FROM token_manifests WHERE hash=?',(web.digest(token),)).fetchone())
        self.store.inspect(legacy)


class ReadModelTests(unittest.TestCase):
    setUp = fixture.AdminTests.setUp
    tearDown = fixture.AdminTests.tearDown
    request = fixture.AdminTests.request
    rpc = fixture.AdminTests.rpc

    def seed(self):
        registry=self.backend.load()
        for index in range(1500):
            registry['devices']['seed-'+str(index)]={'name':f'Device {index:04}','user':self.user,'lan_policy':'inherit','protocols':{}}
        self.backend.save(registry)

    def test_pagination_and_search_do_not_load_full_registry(self):
        self.seed()
        with patch.object(self.backend,'load',side_effect=AssertionError('Full registry read')):
            status,_,body=self.request('/manage/devices?page=2')
            self.assertEqual(status,'200 OK')
            self.assertIn(b'Page 2',body)
            status,_,body=self.request('/manage/devices?q=Device+1499')
            self.assertEqual(status,'200 OK')
            self.assertIn(b'Device 1499',body)
            self.assertNotIn(b'Device 1498',body)
        registry,metadata=self.backend.repo.view_registry('devices',page=2)
        self.assertEqual(len(registry['devices']),50)
        self.assertEqual(metadata['total'],1501)

    def test_one_device_update_does_not_rewrite_other_records(self):
        self.seed()
        with self.backend.repo.connect() as db:
            db.executescript('CREATE TABLE write_probe(id TEXT); CREATE TRIGGER count_device_update AFTER UPDATE ON devices BEGIN INSERT INTO write_probe VALUES(new.id); END; CREATE TRIGGER count_device_insert AFTER INSERT ON devices BEGIN INSERT INTO write_probe VALUES(new.id); END;')
        registry,device=self.backend.device(self.ident)
        device['name']='Only changed device';self.backend.save(registry)
        with self.backend.repo.connect() as db:
            self.assertEqual(db.execute('SELECT id FROM write_probe').fetchall(),[(self.ident,)])
            self.assertEqual(db.execute('SELECT count(*) FROM devices').fetchone()[0],1501)
        self.assertEqual(self.backend.device(self.ident)[1]['protocols']['wireguard']['backend'],'native-phone')

    def test_status_uses_visible_ids_and_skips_unchanged_sections(self):
        jobs=[self.backend.repo.enqueue({'action':'repair','device':self.ident,'tag':str(i)}) for i in range(35)]
        values={'view':'jobs','jobs':json.dumps(jobs[:2]),'targets':json.dumps([['device',self.ident]])}
        response=types.SimpleNamespace(stdout='active\n'*6,returncode=0)
        with patch.object(self.backend,'load',side_effect=AssertionError('Full registry read')),patch.object(self.backend.m,'command',return_value=response):
            status,_,body=self.request('/manage/status?'+urlencode(values))
            data=json.loads(body);self.assertEqual(status,'200 OK')
            self.assertEqual(len(data['jobs']),2)
            self.assertLess(len(body),10000)
            values['since']=data['revision']
            _,_,body=self.request('/manage/status?'+urlencode(values))
            self.assertEqual(json.loads(body)['jobs'],[])

    def test_failed_health_read_is_cached(self):
        import subprocess
        with patch.object(self.backend.m,'command',side_effect=subprocess.TimeoutExpired('systemctl',3)) as command:
            for _ in range(2):
                status,_,body=self.request('/manage/status')
                self.assertEqual(status,'200 OK')
                self.assertIn('unavailable',body.decode())
            self.assertEqual(command.call_count,1)


class ManagementFlowTests(unittest.TestCase):
    setUp=fixture.AdminTests.setUp
    tearDown=fixture.AdminTests.tearDown
    request=fixture.AdminTests.request
    rpc=fixture.AdminTests.rpc

    def test_device_tabs_separate_forms_without_losing_access_controls(self):
        target='/manage/device?device='+self.ident
        profiles=self.request(target)[2]
        access=self.request(target+'&tab=access')[2]
        settings=self.request(target+'&tab=settings')[2]
        activity=self.request(target+'&tab=activity')[2]
        self.assertIn(b'Prepare selected profiles',profiles)
        self.assertNotIn(b'name="action" value="rename"',profiles)
        self.assertIn(b'name="action" value="device-group"',access)
        self.assertNotIn(b'name="action" value="rename"',access)
        self.assertIn(b'name="action" value="rename"',settings)
        self.assertIn(b'Revoke and delete',settings)
        self.assertNotIn(b'Prepare selected profiles',activity)

    def test_validation_restores_non_secret_fields(self):
        status,_,body=self.request('/manage/action','POST',{'action':'user-add','name':'Example User','return_view':'users','password':'Never-echo-this-secret'})
        self.assertEqual(status,'422 Unprocessable Entity')
        self.assertIn(b'value="Example User"',body)
        self.assertNotIn(b'Never-echo-this-secret',body)
        self.assertIn(b'already exists',body)

    def test_regular_mutations_redirect_without_private_query_data(self):
        # Disable the helper's redirect-follow by using its original WSGI adapter.
        from urllib.parse import urlencode
        data=urlencode({'csrf':self.csrf,'action':'user-add','name':'New owner','return_view':'users'}).encode()
        env={'REQUEST_METHOD':'POST','PATH_INFO':'/manage/action','QUERY_STRING':'',
             'HTTP_HOST':'192.168.0.8:9001','HTTP_ORIGIN':'http://192.168.0.8:9001','REMOTE_ADDR':'192.168.0.22',
             'HTTP_COOKIE':'vpn_session='+self.session,'CONTENT_TYPE':'application/x-www-form-urlencoded',
             'CONTENT_LENGTH':str(len(data)),'wsgi.input':io.BytesIO(data)}
        response=[]
        body=b''.join(web.Application(self.state,'management',rpc_call=self.rpc)(env,lambda status,headers:response.extend([status,dict(headers)])))
        self.assertEqual(response[0],'303 See Other')
        self.assertEqual(response[1]['Location'],'/manage/users')
        self.assertEqual(body,b'')
        self.assertIn(b'User created',self.request('/manage/users')[2])
        self.assertNotIn(b'User created',self.request('/manage/users')[2])
