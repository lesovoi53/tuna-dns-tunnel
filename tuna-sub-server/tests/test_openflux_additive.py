import base64
import copy
import importlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import urllib.request
import subprocess
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
tuna = importlib.import_module('tuna-subscriptions')

class AdditiveImport(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        cfg = copy.deepcopy(tuna.DEFAULT_CONFIG)
        cfg['database']['path'] = str(Path(self.temp.name)/'db.sqlite')
        self.app = tuna.SubscriptionApp(cfg)
        self.addCleanup(self.app.conn.close)
        _, self.user = self.app.create_user({'nickname':'fixture'})
        self.uid = self.user['id']
        status, group = self.app.create_openflux_group({'name':'Original group','mode':'classic','transport':'mailru','urls':['https://cloud.mail.ru/public/local/one'],'codec':'batched','encryption_key':'original-key-123456'})
        self.assertEqual(status,201,group)
        code, self.original = self.app.update_user_openflux(self.uid, {'name':'Original','enabled':True,'group_ids':[group['id']]})
        self.assertEqual(code,200)
        _, exported = self.app.export_user_openflux(self.uid)
        self.original_uri = exported['uri']
        self.payload = copy.deepcopy(exported['payload'])
        self.payload.update(issuer_id=str(uuid.uuid4()),id=str(uuid.uuid4()),name='Additional')
        self.payload['groups'][0].update(id=str(uuid.uuid4()),urls=['https://cloud.mail.ru/public/remote/one'])

    def snapshot(self):
        return {t:[tuple(r) for r in self.app.conn.execute('SELECT * FROM '+t+' ORDER BY rowid')] for t in ('user_openflux_config','user_openflux_selection','openflux_groups','server_metadata')}

    def add(self, payload=None, **kw):
        return self.app.import_user_openflux(self.uid, {'payload':payload or self.payload,'commit':True,**kw})

    def test_preserves_original_and_emits_two_separate_bundles(self):
        before=self.snapshot()
        status,result=self.add()
        self.assertEqual(status,200,result)
        self.assertEqual(self.snapshot(),before)
        status,_,body=self.app.get_subscription_payload(self.user['token'])
        self.assertEqual(status,200)
        lines=base64.b64decode(body).decode().splitlines()
        self.assertIn(self.original_uri,lines)
        self.assertEqual(len(lines),2)
        self.assertIn(self.payload,[tuna.deserialize_openflux_v2_bundle(x)[2] for x in lines])

    def test_repeat_is_noop_and_conflicting_identity_does_not_replace(self):
        self.assertEqual(self.add()[0],200)
        rev=self.app.get_user(self.uid)[1]['revision']
        self.assertTrue(self.add()[1]['no_op'])
        self.assertEqual(self.app.get_user(self.uid)[1]['revision'],rev)
        changed=copy.deepcopy(self.payload);changed['name']='Changed'
        self.assertEqual(self.add(changed)[0],409)
        self.assertEqual(self.app.get_user(self.uid)[1]['revision'],rev)

    def test_stale_preview_and_invalid_payload_are_atomic(self):
        status,preview=self.app.import_user_openflux(self.uid,{'payload':self.payload})
        self.assertEqual(status,200)
        self.app.update_user(self.uid,{'nickname':'renamed'})
        self.assertEqual(self.add(expected_state_token=preview['state_token'])[0],409)
        bad=copy.deepcopy(self.payload);bad['groups']=[]
        before=self.snapshot()
        self.assertEqual(self.add(bad)[0],400)
        self.assertEqual(self.snapshot(),before)

    def test_disabled_original_stays_disabled_external_can_be_toggled_and_deleted(self):
        self.app.update_user_openflux(self.uid,{'enabled':False})
        before=self.snapshot()
        status,added=self.add();self.assertEqual(status,200)
        self.assertEqual(self.snapshot(),before)
        self.assertEqual(self.app.get_subscription_payload(self.user['token'])[0],200)
        item=added['import_id']
        status,items=self.app.list_imported_openflux(self.uid)
        self.assertEqual(status,200)
        self.assertEqual(self.app.change_imported_openflux(self.uid,item,{'action':'disable','expected_state_token':items['state_token']})[0],200)
        self.assertEqual(self.app.get_subscription_payload(self.user['token'])[0],204)
        token=self.app.list_imported_openflux(self.uid)[1]['state_token']
        self.assertEqual(self.app.change_imported_openflux(self.uid,item,{'action':'delete','expected_state_token':token})[0],200)
        self.assertEqual(self.snapshot(),before)

    def test_self_import_is_noop_and_local_identity_collision_rejected(self):
        before=self.snapshot()
        result=self.app.import_user_openflux(self.uid,{'uri':self.original_uri,'commit':True})
        self.assertEqual(result[0],200)
        self.assertTrue(result[1]['no_op'])
        p=tuna.deserialize_openflux_v2_bundle(self.original_uri)[2];p['name']='Do not overwrite'
        self.assertEqual(self.add(p)[0],409)
        self.assertEqual(self.snapshot(),before)

    def test_database_failure_rolls_back_insert_and_revision(self):
        before=self.app.get_user(self.uid)[1]['revision']
        with self.app.conn:
            self.app.conn.execute("CREATE TRIGGER reject_revision BEFORE UPDATE ON users BEGIN SELECT RAISE(ABORT,'fixture failure'); END")
        self.assertEqual(self.add()[0],500)
        self.assertEqual(self.app.list_imported_openflux(self.uid)[1]['connections'],[])
        self.assertEqual(self.app.get_user(self.uid)[1]['revision'],before)

    def test_upgrade_preserves_rows_and_import_survives_restart(self):
        self.assertEqual(self.add()[0],200)
        before=self.snapshot()
        app=tuna.SubscriptionApp(self.app.config)
        try:
            self.assertEqual(len(app.list_imported_openflux(self.uid)[1]['connections']),1)
            self.assertEqual(app.get_subscription_payload(self.user['token'])[2],self.app.get_subscription_payload(self.user['token'])[2])
            self.assertEqual(self.snapshot(),before)
        finally:app.conn.close()

    def test_http_emits_only_enabled_imported_connections(self):
        status, added = self.add()
        self.assertEqual(status,200)
        server=tuna.ThreadingHTTPServer(('127.0.0.1',0),tuna.SubscriptionRequestHandler)
        server.app=self.app
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            state = self.app.list_imported_openflux(self.uid)[1]['state_token']
            self.assertEqual(self.app.change_imported_openflux(self.uid,added['import_id'],{'action':'disable','expected_state_token':state})[0],200)
            url='http://127.0.0.1:'+str(server.server_address[1])+'/sub/'+self.user['token']
            with urllib.request.urlopen(url) as reply:lines=base64.b64decode(reply.read()).decode().splitlines()
            self.assertEqual(lines,[self.original_uri])
            self.assertTrue(self.app.get_user_openflux(self.uid)[1]['enabled'])
        finally:
            server.shutdown();server.server_close();thread.join()

if __name__=='__main__':unittest.main()
