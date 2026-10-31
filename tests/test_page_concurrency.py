import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from config import env_loader
from core import account_concurrency as limits, db, registration_service, twofa_service, plan_check_service
from core import live_check_service, extract_link_service, codex_agent_service, codex_retry_service, email_change_service
from core.concurrency_limit import ConcurrencyLimit
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app


class PageConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.folder = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.multiple(db, **storage(self.folder)))
        self.stack.enter_context(patch.object(env_loader, '_ENV_PATH', self.folder/'.env'))
        self.stack.enter_context(patch.dict(os.environ))
        self.stack.enter_context(patch.object(limits, '_LIMIT', ConcurrencyLimit(1)))
        self.client = create_app(auth_code='fixture').test_client()
        self.headers = {'X-Auth-Code':'fixture'}

    def save(self, workers):
        response = self.client.post('/api/accounts/concurrency', headers=self.headers, json={'workers':workers})
        self.assertEqual(response.status_code, 200)
        return response.get_json()

    def test_save_is_authenticated_persistent_and_does_not_dispatch_account_actions(self):
        self.assertEqual(self.client.get('/api/accounts/concurrency').status_code, 401)
        self.assertEqual(self.client.post('/api/accounts/concurrency',json={'workers':3}).status_code, 401)
        with patch.object(twofa_service, 'enqueue_account_totp_setup') as enqueue:
            state = self.save(3)
        enqueue.assert_not_called()
        self.assertEqual(state['workers'], 3)
        self.assertFalse(state['restart_required'])
        self.assertEqual(set(state['features']), {'live_check','plan','twofa','codex','codex_agent','extract_link','email_change'})
        self.assertEqual(env_loader.read_env_file()['ACCOUNT_WORKERS'], '3')
        for service in (twofa_service,plan_check_service,live_check_service,extract_link_service):
            self.assertEqual(service.queue_settings()['workers'], 3)
        self.assertEqual(self.client.get('/api/accounts/concurrency',headers=self.headers).get_json()['workers'], 3)

    def test_bad_saves_never_mutate_config(self):
        for data in ({'workers':0},{'workers':17},{'workers':True},{'workers':2.5},{'workers':'3'},
                     {'workers':3,'scope':'other'}, {}, [], None):
            with self.subTest(data=data), patch.object(env_loader,'write_env_values') as write:
                response=self.client.post('/api/accounts/concurrency',headers=self.headers,json=data)
                self.assertEqual(response.status_code,400)
                self.assertEqual(limits.queue_settings()['workers'],1)
                write.assert_not_called()

    def test_registration_and_account_pages_never_override_each_other(self):
        old=registration_service.get_executor_workers()
        self.addCleanup(registration_service.configure_workers,old)
        self.save(3)
        response=self.client.post('/api/jobs/concurrency',headers=self.headers,json={'workers':5})
        self.assertEqual(response.status_code,200)
        self.assertEqual(registration_service.get_executor_workers(),5)
        self.assertEqual(limits.queue_settings()['workers'],3)
        self.save(2)
        self.assertEqual(registration_service.get_executor_workers(),5)

    def test_stale_bulk_worker_field_cannot_change_saved_account_limit(self):
        account=db.insert_account(email='fixture@example.test',access_token='fixture')
        self.save(3)
        with patch.object(live_check_service,'enqueue_account_live_check',return_value={'accepted':True}):
            result=self.client.post('/api/accounts/check-live-bulk',headers=self.headers,
                json={'account_ids':[account],'workers':1})
        self.assertEqual(result.get_json()['workers'],3)
        self.assertEqual(limits.queue_settings()['workers'],3)

    def test_nested_owner_thread_uses_one_slot_but_new_thread_does_not_inherit_ownership(self):
        with limits.SLOTS,limits.SLOTS:
            self.assertEqual(limits.queue_settings()['running'],1)
            with ThreadPoolExecutor(1) as pool:
                self.assertFalse(pool.submit(limits.SLOTS.acquire,0).result(1))
        self.assertEqual(limits.queue_settings()['running'],0)

    def test_registration_post_steps_do_not_wait_on_account_pages_one_slot(self):
        started=threading.Barrier(6)
        release=threading.Event()

        def registration_post_step():
            with limits.registration_scope(),twofa_service._EXECUTION_SLOTS,plan_check_service._EXECUTION_SLOTS:
                started.wait(timeout=3)
                release.wait(3)

        with ThreadPoolExecutor(5) as pool:
            futures=[pool.submit(registration_post_step) for _ in range(5)]
            try:
                started.wait(timeout=3)
                self.assertEqual(limits.queue_settings()['running'],0)
            finally:
                release.set()
            for future in futures:future.result(3)

    def test_every_slow_account_service_has_capacity_for_live_increases(self):
        for service in (twofa_service,plan_check_service,live_check_service,extract_link_service,codex_agent_service,email_change_service):
            self.assertEqual(service._EXECUTOR._max_workers,16)
        for worker in (extract_link_service._run_extract,codex_agent_service._run_generate,
                       email_change_service._run,codex_retry_service.run_worker):
            self.assertTrue(hasattr(worker,'__wrapped__'))
        self.assertIs(twofa_service._EXECUTION_SLOTS,limits.SLOTS)
        self.assertIs(plan_check_service._EXECUTION_SLOTS,limits.SLOTS)
        self.assertIs(live_check_service._EXECUTION_SLOTS,limits.SLOTS)

    def test_actual_twofa_queue_hot_resizes_one_to_three_and_back_without_new_submissions(self):
        ids=[db.insert_account(email=f'fixture{i}@example.test',access_token='fixture') for i in range(5)]
        released={f'fixture{i}@example.test':threading.Event() for i in range(5)}
        changed=threading.Condition()
        entered=[]
        futures=[]

        def setup(session,email,**kwargs):
            with changed:
                entered.append(email)
                changed.notify_all()
            if not released[email].wait(5):raise AssertionError('fixture gate timed out')
            return 'fixture-secret'

        def wait_count(count):
            with changed:
                self.assertTrue(changed.wait_for(lambda:len(entered)>=count,timeout=3))

        session=SimpleNamespace(proxy=None,device_id='fixture',fingerprint_summary_text=lambda:'fixture')
        with ThreadPoolExecutor(16) as pool, ExitStack() as patches:
            patches.enter_context(patch.object(twofa_service,'_EXECUTOR',pool))
            patches.enter_context(patch.object(twofa_service,'_RUNNING',set()))
            patches.enter_context(patch.object(twofa_service,'_QUEUE_SLOTS',threading.BoundedSemaphore(20)))
            patches.enter_context(patch.object(twofa_service,'_resolve_twofa_proxy',return_value=(None,None,'fixture')))
            patches.enter_context(patch.object(twofa_service,'_append_log'))
            patches.enter_context(patch.object(twofa_service,'log_path',side_effect=lambda email:self.folder/(email+'.log')))
            patches.enter_context(patch.object(twofa_service,'setup_2fa',side_effect=setup))
            patches.enter_context(patch.object(twofa_service,'close_browser_session'))
            patches.enter_context(patch('core.workflow_driver.create_account_session',return_value=session))
            patches.enter_context(patch('core.workflow_driver.require_driver_ready',return_value='protocol'))
            patches.enter_context(patch('config.email.USE_EMAIL_SERVICE',True))
            try:
                for i,account_id in enumerate(ids):
                    result=twofa_service.enqueue_account_totp_setup(account_id=account_id,
                        email=f'fixture{i}@example.test',access_token='fixture')
                    self.assertTrue(result['accepted'])
                    futures.append(result['future'])
                wait_count(1)
                self.assertEqual(twofa_service.queue_settings()['running'],1)
                self.save(3)
                wait_count(3)
                self.assertEqual(twofa_service.queue_settings()['running'],3)
                statuses=[db.get_account(i)['totp_setup_status'] for i in ids]
                self.assertEqual((statuses.count('running'),statuses.count('queued')),(3,2))
                self.save(1)
                first_three=list(entered)
                released[first_three[0]].set();released[first_three[1]].set()
                with changed:
                    self.assertFalse(changed.wait_for(lambda:len(entered)>3,timeout=0.08))
                released[first_three[2]].set()
                wait_count(4)
                self.assertEqual(limits.queue_settings()['running'],1)
            finally:
                for event in released.values():event.set()
                for future in futures:future.result(timeout=5)
        self.assertTrue(all(db.get_account(i)['totp_setup_status']=='success' for i in ids))
        self.assertEqual(limits.queue_settings()['running'],0)


if __name__=='__main__':
    unittest.main()
