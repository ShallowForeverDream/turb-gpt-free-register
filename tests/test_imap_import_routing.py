import json
import os
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from config import env_loader
from core import db, imap_mail_client as imap, imap_receivers as receivers
from tests.test_forwarded_imap_and_account_import import storage
from webui import config_editor
from webui.app import create_app


class ImportedReceiverTests(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.root=Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.multiple(db,**storage(self.root)))
        self.stack.enter_context(patch.object(env_loader,'_ENV_PATH',self.root/'.env'))
        self.stack.enter_context(patch.dict(os.environ,{},clear=True))
        self.stack.enter_context(patch('core.workflow_driver.require_driver_ready',return_value='protocol'))
        db.import_forwarded_imap_emails([{'email':'a@icloud.com'}],inbox='receiver@163.com',server='imap.163.com')
        db.import_forwarded_imap_emails([{'email':'b@icloud.com'}],inbox='receiver@yeah.net',server='imap.yeah.net')
        self.a=db.get_imap_email_by_email('a@icloud.com');self.b=db.get_imap_email_by_email('b@icloud.com')
        self.key_a=self.a['imap_auth_key'];self.key_b=self.b['imap_auth_key']
        env_loader.write_env_values({self.key_a:'fixture-163',self.key_b:'fixture-yeah'})

    def test_each_imported_receiver_uses_its_own_route_and_credential(self):
        with patch.object(imap._email_cfg,'FORWARDED_IMAP_PASSWORD','wrong-global'):
            a=imap.get_account_context('a@icloud.com');b=imap.get_account_context('b@icloud.com')
        self.assertEqual((a.username,a.server,a.password),('receiver@163.com','imap.163.com','fixture-163'))
        self.assertEqual((b.username,b.server,b.password),('receiver@yeah.net','imap.yeah.net','fixture-yeah'))
        self.assertNotEqual(imap._inbox_key(a),imap._inbox_key(b))
        for row in (self.a,self.b):
            self.assertNotIn('fixture-',json.dumps(row))
            self.assertNotIn('imap_password',row)

    def test_import_snapshot_cannot_be_overridden_by_unrelated_flat_field_changes(self):
        rows=db._load_imap_emails();row=next(r for r in rows if r['email']=='a@icloud.com')
        row.update(imap_username='wrong@yeah.net',imap_server='wrong.example.test',imap_port='bad-port')
        db._save_imap_emails(rows)
        account=imap.get_account_context('a@icloud.com')
        self.assertEqual((account.username,account.server,account.port),('receiver@163.com','imap.163.com',993))
        displayed=db.get_imap_email_by_email('a@icloud.com')
        self.assertEqual(displayed['imap_username'],'receiver@163.com')

    def test_explicit_reimport_updates_only_the_listed_recipient_and_preserves_status(self):
        db.import_forwarded_imap_emails([{'email':'c@icloud.com'}],inbox='receiver@163.com',server='imap.163.com')
        untouched=db.get_imap_email_by_email('c@icloud.com')['imap_imported_route']
        db.import_registered_email_accounts([{'email':'a@icloud.com',**self.a}],source='imap')
        original=db.get_account_by_email('a@icloud.com')
        self.assertEqual(db.import_forwarded_imap_emails([{'email':'a@icloud.com'}],
            inbox='receiver@yeah.net',server='imap.yeah.net'),(0,1,0))
        row=db.get_imap_email_by_email('a@icloud.com')
        self.assertEqual((row['status'],row['registered_account_id']),('used',original['id']))
        self.assertEqual(imap.get_account_context('a@icloud.com').password,'fixture-yeah')
        self.assertEqual(db.get_imap_email_by_email('b@icloud.com')['imap_imported_route'],self.b['imap_imported_route'])
        self.assertEqual(db.get_imap_email_by_email('c@icloud.com')['imap_imported_route'],untouched)
        self.assertEqual(imap.get_account_context('c@icloud.com').password,'fixture-163')

    def test_missing_receiver_authorization_never_borrows_global_or_other_receiver(self):
        env_loader.write_env_values({self.key_a:''})
        with patch.object(imap._email_cfg,'FORWARDED_IMAP_PASSWORD','wrong-global'), \
             patch.object(imap,'_connect') as connect:
            with self.assertRaises(imap.ImapConfigurationError) as caught:
                imap.fetch_latest_otp('a@icloud.com',max_wait=0)
        self.assertFalse(caught.exception.retryable)
        connect.assert_not_called()
        self.assertEqual(imap.get_account_context('b@icloud.com').password,'fixture-yeah')
        with self.assertRaises(imap.ImapConfigurationError):imap.pick_account()
        self.assertEqual(db.get_imap_email_by_email('a@icloud.com')['status'],'available')

    def test_arbitrary_environment_key_cannot_be_used_as_a_credential_reference(self):
        rows=db._load_imap_emails();rows[0]['imap_auth_key']='UNRELATED_SECRET'
        db._save_imap_emails(rows)
        with patch.dict(os.environ,{'UNRELATED_SECRET':'must-not-be-used'}):
            with self.assertRaises(imap.ImapConfigurationError) as caught:imap.get_account_context('a@icloud.com')
        self.assertNotIn('must-not-be-used',str(caught.exception))

    def test_missing_reference_on_a_snapshotted_import_still_cannot_fall_back_to_global(self):
        rows=db._load_imap_emails();rows[0].pop('imap_auth_key');db._save_imap_emails(rows)
        env_loader.write_env_values({self.key_a:''})
        with patch.object(imap._email_cfg,'FORWARDED_IMAP_PASSWORD','wrong-global'):
            self.assertEqual(imap.get_account_context('a@icloud.com').password,'')
        self.assertIn(self.key_a,{f['key'] for f in receivers.credential_fields()})

    def test_profile_config_fields_are_secret_and_save_only_the_selected_receiver(self):
        fields=receivers.credential_fields()
        self.assertEqual({f['key'] for f in fields},{self.key_a,self.key_b})
        self.assertTrue(all(f['secret'] for f in fields))
        self.assertTrue(any('receiver@163.com' in f['label'] for f in fields))
        result=config_editor.update_config({self.key_a:'updated-fixture-163'})
        self.assertIn(self.key_a,result['updated'])
        self.assertEqual(imap.get_account_context('a@icloud.com').password,'updated-fixture-163')
        self.assertEqual(imap.get_account_context('b@icloud.com').password,'fixture-yeah')

    def test_mailbox_query_reports_missing_config_without_network_or_resending(self):
        client=create_app(auth_code='fixture').test_client()
        env_loader.write_env_values({self.key_a:''})
        with patch.object(imap,'_connect') as connect:
            response=client.get('/api/outlook/email-otp?source=imap&email=a@icloud.com',headers={'X-Auth-Code':'fixture'})
        self.assertEqual(response.status_code,400)
        self.assertEqual(response.get_json()['error_code'],'imap_receiver_configuration')
        self.assertFalse(response.get_json()['retryable'])
        connect.assert_not_called()

    def test_missing_receiver_auth_is_rejected_before_registration_jobs_are_created(self):
        client=create_app(auth_code='fixture').test_client()
        env_loader.write_env_values({self.key_a:''})
        with patch('core.registration_service.submit_registration') as submit, patch('config.email.USE_EMAIL_SERVICE',True):
            response=client.post('/api/jobs',json={'count':200,'email_source':'imap'},headers={'X-Auth-Code':'fixture'})
        self.assertEqual(response.status_code,400)
        self.assertEqual(response.get_json()['error_code'],'imap_receiver_configuration')
        self.assertEqual(db.list_jobs_page()['total'],0)
        self.assertEqual(db.get_imap_email_by_email('a@icloud.com')['status'],'available')
        submit.assert_not_called()


if __name__=='__main__':unittest.main()
