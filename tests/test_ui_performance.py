import gzip
import ast
import json
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from core import db
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app
from webui import config_editor


class UIReadPerformanceTests(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        self.root=Path(folder.name)
        context=patch.multiple(db,**storage(self.root));context.start();self.addCleanup(context.stop)
        db._ensure_sqlite()
        db._save_accounts([{'id':i,'email':f'fixture{i}@example.test','access_token':'fixture',
                           'created_at':'2026-10-01','extra_json':json.dumps({'large_fixture':'x'*20000})}
                          for i in range(1,301)])
        db.import_imap_emails([{'email':'fixture1@example.test','password':'fixture','server':'imap.example.test'}])
        self.job=db.create_job('imap','fixture1@example.test')
        self.client=create_app(auth_code='fixture').test_client()
        self.headers={'X-Auth-Code':'fixture','Accept-Encoding':'identity'}

    def test_point_reads_and_job_list_never_decode_the_whole_account_collection(self):
        with patch.object(db,'_load_accounts',side_effect=AssertionError('full account scan')), \
             patch.object(db,'_load_jobs',side_effect=AssertionError('full job scan')), \
             patch.object(db,'_load_imap_emails',side_effect=AssertionError('full mailbox scan')):
            self.assertEqual(db.get_account(1)['email'],'fixture1@example.test')
            self.assertEqual(db.get_account_by_email('FIXTURE1@example.test')['id'],1)
            self.assertEqual(db.get_imap_email_by_email('FIXTURE1@example.test')['imap_server'],'imap.example.test')
            self.assertEqual(db.get_job(self.job['id'])['id'],self.job['id'])
            self.assertIsNone(db.get_successful_retry_for_job(self.job['id']))
            response=self.client.get('/api/jobs?paged=1&page_size=20',headers=self.headers)
            self.assertEqual(response.status_code,200)
            self.assertEqual(response.get_json()['total'],1)

    def test_all_page_reads_proceed_while_an_unrelated_python_writer_is_busy(self):
        done=threading.Event();errors=[]
        def read():
            try:
                db.get_account(1);db.get_account_by_email('fixture1@example.test');db.get_job(self.job['id'])
                db.list_accounts_page(limit=20);db.list_account_plan_check_statuses(limit=20)
                db.list_jobs_page();db.count_accounts();db.imap_email_pool_summary();db.codex_accounts_summary()
            except Exception as exc:errors.append(exc)
            finally:done.set()
        with db._LOCK:
            worker=threading.Thread(target=read);worker.start();finished=done.wait(2)
        worker.join(3)
        self.assertTrue(finished,'read request blocked on unrelated writer lock')
        self.assertEqual(errors,[])

    def test_status_and_metadata_updates_only_write_the_target_row(self):
        with closing(db._sqlite_conn()) as conn,conn:
            conn.executescript("""CREATE TABLE account_write_audit(id INTEGER,op TEXT);
                CREATE TRIGGER audit_account_update AFTER UPDATE ON accounts BEGIN
                INSERT INTO account_write_audit VALUES(NEW.id,'update'); END;
                CREATE TRIGGER audit_account_delete AFTER DELETE ON accounts BEGIN
                INSERT INTO account_write_audit VALUES(OLD.id,'delete'); END;
                CREATE TRIGGER audit_account_insert AFTER INSERT ON accounts BEGIN
                INSERT INTO account_write_audit VALUES(NEW.id,'insert'); END;""")
            untouched=list(conn.execute('SELECT id,payload FROM accounts WHERE id!=1 ORDER BY id'))
        with patch.object(db,'_load_accounts',side_effect=AssertionError('full account scan')), \
             patch.object(db,'_save_accounts',side_effect=AssertionError('full account rewrite')):
            self.assertTrue(db.claim_account_totp_setup(1))
            self.assertTrue(db.mark_account_totp_setup_running(1))
            self.assertTrue(db.update_account_totp_secret(1,{'ok':True,'status':'success','totp_secret':'fixture-secret'}))
            self.assertTrue(db.claim_account_plan_check(acc_id=1))
            self.assertTrue(db.mark_account_plan_check_running(1))
            self.assertTrue(db.update_account_plan_check(acc_id=1,result={'ok':True,'current_plan_type':'free'}))
            self.assertTrue(db.update_account_note(1,'fixture-note'))
            self.assertTrue(db.update_account_group(1,'fixture-group'))
            self.assertTrue(db.update_account_flow(1,traffic={'available':True,'total_bytes':123}))
            self.assertTrue(db.update_account_liveness(1,{'ok':True,'status':'live','access_token':'fixture-new'}))
        with closing(db._sqlite_conn()) as conn:
            self.assertEqual([tuple(r) for r in conn.execute('SELECT id,payload FROM accounts WHERE id!=1 ORDER BY id')],
                             [tuple(r) for r in untouched])
            events=[tuple(r) for r in conn.execute('SELECT id,op FROM account_write_audit')]
        self.assertEqual(events,[(1,'update')]*10)
        row=db.get_account(1)
        self.assertEqual(row['account_group'],'fixture-group')
        self.assertEqual(row['access_token'],'fixture-new')
        self.assertEqual(row['totp_secret'],'fixture-secret')

    def test_html_compression_only_when_requested_and_never_changes_rendered_content(self):
        identity=self.client.get('/',headers=self.headers)
        compressed=self.client.get('/',headers={**self.headers,'Accept-Encoding':'gzip'})
        self.assertEqual(compressed.headers['Content-Encoding'],'gzip')
        self.assertEqual(gzip.decompress(compressed.data),identity.data)
        self.assertLess(len(compressed.data),len(identity.data)/2)

    def test_config_sources_are_parsed_once_per_file_without_stale_cross_request_values(self):
        source=self.root/'fixture-config.py'
        source.write_text('UI_FIXTURE_A = 3\nUI_FIXTURE_B = False\nUI_FIXTURE_C = ["fixture"]\n',encoding='utf-8')
        fields=[{'key':key,'file':'fixture-config.py','type':kind} for key,kind in
                [('UI_FIXTURE_A','int'),('UI_FIXTURE_B','bool'),('UI_FIXTURE_C','list_str_multiline')]]
        with patch.object(config_editor,'EDITABLE_FIELDS',fields), \
             patch.object(config_editor,'_config_path',return_value=source), \
             patch('config.env_loader.load_env'),patch('config.env_loader.read_env_file',return_value={}), \
             patch.object(config_editor.ast,'parse',wraps=ast.parse) as parse:
            result=config_editor.get_config()
            self.assertEqual([row['value'] for row in result],[3,False,['fixture']])
            self.assertEqual(parse.call_count,1)
            source.write_text('UI_FIXTURE_A = 5\nUI_FIXTURE_B = False\nUI_FIXTURE_C = ["fixture"]\n',encoding='utf-8')
            self.assertEqual(config_editor.get_config()[0]['value'],5)
            self.assertEqual(parse.call_count,2)

    def test_unchanged_status_poll_returns_only_revision_but_changes_still_arrive(self):
        path='/api/accounts/plan-check-status'
        query={'page_size':20,'page':1}
        first=self.client.get(path,query_string=query,headers=self.headers).get_json()
        response=self.client.get(path,query_string={**query,'revision':first['revision']},headers=self.headers)
        self.assertTrue(response.get_json()['unchanged'])
        self.assertNotIn('items',response.get_json())
        self.assertLess(len(response.data),1024)
        db.update_account_note(300,'changed fixture note')
        changed=self.client.get(path,query_string={**query,'revision':first['revision']},headers=self.headers).get_json()
        self.assertFalse(changed.get('unchanged',False))
        self.assertNotEqual(changed['revision'],first['revision'])
        self.assertTrue(changed['items'])
