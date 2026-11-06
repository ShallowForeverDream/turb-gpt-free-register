"""Bounded local queue tests; no provider requests or live registrations."""
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
import tempfile
import threading
import unittest

from core import db, registration_service as svc, twofa_service as twofa, account_concurrency
from core.concurrency_limit import ConcurrencyLimit
from tests.test_forwarded_imap_and_account_import import storage


class RegistrationIntakeTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.multiple(db, **storage(self.root), _LOG_DIR=self.root/'logs'))
        self.stack.enter_context(patch.multiple(svc, _executor=None, _executor_workers=2,
            _EXECUTION_SLOTS=ConcurrencyLimit(2), _PENDING_TASKS=deque(), _DISPATCHED_TASKS={},
            _ACTIVE_JOBS=set(), _STOP_EVENTS={}, _PAUSED_JOBS=set(), _PAUSE_GATE=threading.Event(),
            _PAUSE_LOCK=threading.Lock(), _STARTING_ONE=False, _STARTING_JOBS=set()))
        svc._PAUSE_GATE.set()
        self.stack.enter_context(patch('core.workflow_driver.require_driver_ready', return_value='protocol'))
        self.stack.enter_context(patch('config.email.USE_EMAIL_SERVICE', True))
        db.import_generic_api_emails([{'email':f'fixture{i}@example.test','code_url':f'https://mail.example.test/{i}'} for i in range(6)])
        self.entered=[]
        self.failed=set()
        self.changed=threading.Condition()
        self.release={f'fixture{i}@example.test':threading.Event() for i in range(6)}
        def register(*, email, on_email_acquired, **kwargs):
            if not email:
                email=db.claim_next_generic_api_email()['email']
                on_email_acquired(email)
            with self.changed:
                self.entered.append(email);self.changed.notify_all()
            if not self.release[email].wait(5):
                raise RuntimeError('fixture timeout')
            svc.check_stop_requested()
            if email in self.failed:
                db.release_generic_api_email(email,status='available')
                return {'success':False,'email':email,'error':'fixture network error'}
            return {'success':True,'email':email}
        self.stack.enter_context(patch('main.run_registration',side_effect=register))
        self.addCleanup(self.drain)

    def drain(self):
        svc.stop_registration()
        for release in self.release.values():release.set()
        svc.shutdown_executor()

    def wait_started(self,n):
        with self.changed:self.assertTrue(self.changed.wait_for(lambda:len(self.entered)>=n,3))

    def wait_finished(self,ids):
        with svc._executor_lock:
            futures=[svc._DISPATCHED_TASKS.get(id) for id in ids]
        for future in futures:
            if future:future.result(4)

    def select(self,n):
        return [{'email':f'fixture{i}@example.test','source':'generic_api'} for i in range(n)]

    def test_selected_batch_only_claims_admitted_and_pause_resume_keeps_same_total(self):
        jobs=svc.submit_registration(count=4, workers=2, selected_emails=self.select(4))
        self.wait_started(2)
        self.assertEqual(len(svc._DISPATCHED_TASKS),2)
        self.assertEqual([db.get_generic_api_email_by_email(f'fixture{i}@example.test')['status'] for i in range(4)],['used','used','available','available'])
        svc.pause_registration()
        for email in list(self.entered):self.release[email].set()
        self.wait_finished([j['id'] for j in jobs[:2]])
        self.assertEqual(len(self.entered),2)
        self.assertEqual(svc.registration_pause_status()['waiting_jobs'],2)
        self.assertEqual([db.get_job(j['id'])['status'] for j in jobs],['success','success','pending','pending'])
        svc.resume_registration();self.wait_started(4)
        for release in self.release.values():release.set()
        self.wait_finished([j['id'] for j in jobs])
        self.assertEqual(db.list_jobs_page()['total'],4)
        self.assertTrue(all(db.get_job(j['id'])['status']=='success' for j in jobs))

    def test_manual_start_while_paused_runs_one_and_keeps_batch_paused(self):
        svc.pause_registration()
        jobs=svc.submit_registration(count=3,workers=2,selected_emails=self.select(3))
        self.assertEqual(len(self.entered),0)
        self.assertEqual(svc.admit_queued(),1)
        self.wait_started(1)
        self.assertEqual(len(self.entered),1)
        self.release[self.entered[0]].set()
        self.wait_finished([jobs[0]['id']])
        self.assertEqual(len(self.entered),1)
        self.assertEqual(svc.registration_pause_status()['waiting_jobs'],2)
        svc.resume_registration()
        self.wait_started(3)
        for release in self.release.values():release.set()
        self.wait_finished([job['id'] for job in jobs])

    def test_stop_cancels_only_waiting_and_resume_cannot_resurrect_them(self):
        jobs=svc.submit_registration(count=5,workers=2,selected_emails=self.select(5));self.wait_started(2)
        svc.pause_registration();result=svc.stop_registration()
        self.assertEqual(result['cancelled'],3)
        self.assertFalse(svc.is_stop_requested(jobs[0]['id']))
        svc.resume_registration()
        for email in list(self.entered):self.release[email].set()
        self.wait_finished([j['id'] for j in jobs[:2]])
        self.assertEqual(len(self.entered),2)
        self.assertEqual([db.get_job(j['id'])['status'] for j in jobs],['success','success','cancelled','cancelled','cancelled'])
        self.assertEqual(db.get_generic_api_email_by_email('fixture4@example.test')['status'],'available')

    def test_restart_recovery_requeues_pending_paused_and_fails_interrupted_running(self):
        svc.pause_registration()
        jobs = svc.submit_registration(count=3, workers=2, selected_emails=self.select(3))
        # Simulate a previous process: one pending row and one running row with no thread.
        db.update_job(jobs[0]['id'], status='running', started_at='2026-11-04T00:00:00')
        with svc._executor_lock:
            svc._PENDING_TASKS.clear(); svc._DISPATCHED_TASKS.clear()
        result = svc.recover_interrupted_queue()
        self.assertEqual(result['interrupted'], 1)
        self.assertEqual(result['queued'], 2)
        self.assertTrue(result['paused'])
        self.assertEqual(db.get_job(jobs[0]['id'])['status'], 'failed')
        self.assertEqual([db.get_job(j['id'])['status'] for j in jobs[1:]], ['pending', 'pending'])
        self.assertEqual(len(svc._PENDING_TASKS), 2)
        self.assertTrue(svc.registration_pause_status()['paused'])

    def test_history_only_shows_started_rows_and_filters_before_counting(self):
        from webui.app import create_app
        client=create_app(auth_code='fixture').test_client()
        headers={'X-Auth-Code':'fixture','Accept-Encoding':'identity'}
        svc.pause_registration()
        jobs=svc.submit_registration(count=5,workers=2,selected_emails=self.select(5))
        page=client.get('/api/jobs?paged=1&page_size=1',headers=headers).get_json()
        self.assertEqual((page['total'],page['waiting_jobs']),(0,5))
        self.assertEqual(client.get('/api/jobs?limit=1',headers=headers).get_json(),[])
        self.assertEqual(page['status_counts']['active'],0)
        svc.resume_registration();self.wait_started(2)
        page=client.get('/api/jobs?paged=1&page_size=1',headers=headers).get_json()
        self.assertEqual((page['total'],len(page['items']),page['waiting_jobs']),(2,1,3))
        self.assertEqual(page['status_counts']['running'],2)
        self.assertNotIn('pending',page['status_counts'])
        self.assertEqual(client.get('/api/jobs?paged=1&q=fixture4',headers=headers).get_json()['total'],0)
        svc.pause_registration()
        self.release['fixture0@example.test'].set();self.wait_finished([jobs[0]['id']])
        self.assertEqual(db.list_jobs_page(history_only=True)['total'],2)
        svc.resume_registration();self.wait_started(3)
        self.assertEqual(db.list_jobs_page(history_only=True)['total'],3)
        svc.stop_registration()
        self.assertEqual(db.list_jobs_page(history_only=True)['total'],3)
        self.assertEqual(db.list_jobs_page()['total'],5)

    def test_automatic_batch_refills_only_when_whole_task_releases_slot(self):
        jobs=svc.submit_registration(count=5,workers=2,email_source='generic_api');self.wait_started(2)
        self.release[self.entered[0]].set();self.wait_started(3)
        self.assertEqual(len(self.entered),3)
        self.assertEqual(len(svc._DISPATCHED_TASKS),2)
        for release in self.release.values():release.set()
        svc.shutdown_executor()
        # Shutdown deliberately does not launch fresh work.
        self.assertLessEqual(len(self.entered),5)
        self.assertEqual(db.list_jobs_page()['total'],5)

    def test_selected_waiting_mailbox_is_reserved_without_changing_pool_status(self):
        svc.pause_registration()
        svc.submit_registration(count=1,workers=2,selected_emails=self.select(1))
        self.assertEqual(db.get_generic_api_email_by_email('fixture0@example.test')['status'],'available')
        self.assertEqual(db.claim_next_generic_api_email()['email'],'fixture1@example.test')
        with self.assertRaises(ValueError):
            svc.submit_registration(count=1,selected_emails=self.select(1))

    def test_automatic_batch_moves_to_remaining_email_after_failure(self):
        self.failed.add('fixture0@example.test')
        jobs=svc.submit_registration(count=3,workers=1,email_source='generic_api')
        self.wait_started(1);self.release['fixture0@example.test'].set();self.wait_started(2)
        self.assertEqual(self.entered[:2],['fixture0@example.test','fixture1@example.test'])
        self.release['fixture1@example.test'].set();self.wait_started(3)
        self.assertEqual(self.entered,['fixture0@example.test','fixture1@example.test','fixture2@example.test'])
        self.release['fixture2@example.test'].set();self.wait_finished([j['id'] for j in jobs])
        self.assertEqual(len({db.get_job(j['id'])['registration_batch_id'] for j in jobs}),1)

    def test_resize_increases_admission_and_decrease_does_not_interrupt(self):
        jobs=svc.submit_registration(count=5,workers=1,selected_emails=self.select(5));self.wait_started(1)
        svc.configure_workers(3);self.wait_started(3);svc.configure_workers(1)
        self.assertEqual(len(svc._DISPATCHED_TASKS),3)
        svc.pause_registration()
        for email in list(self.entered):self.release[email].set()
        self.wait_finished([j['id'] for j in jobs[:3]])
        self.assertEqual(len(self.entered),3)
        self.assertTrue(all(db.get_job(j['id'])['status']=='success' for j in jobs[:3]))

    def test_webui_selected_batch_claims_each_mailbox_once(self):
        from webui.app import create_app
        client=create_app(auth_code='fixture').test_client()
        headers={'X-Auth-Code':'fixture','Accept-Encoding':'identity'}
        svc.pause_registration()
        emails=[f'fixture{i}@example.test' for i in range(6)]
        response=client.post('/api/jobs',headers=headers,json={
            'selected_emails':[{'email':email,'source':'generic_api'} for email in emails],
            'email_source':'generic_api',
        })
        self.assertEqual(response.status_code,200,response.get_data(as_text=True))
        self.assertEqual(response.get_json()['submitted'],len(emails))
        self.assertEqual(db.list_jobs_page()['total'],len(emails))
        self.assertEqual(len(svc._PENDING_TASKS),len(emails))
        # Waiting mailboxes stay available until admitted; their batch reservation blocks another job.
        self.assertTrue(all(db.get_generic_api_email_by_email(email)['status']=='available' for email in emails))
        with self.assertRaises(ValueError):
            svc.submit_registration(count=1,selected_emails=[{'email':emails[0],'source':'generic_api'}])

    def test_api_pause_selected_start_stop_and_resume_never_claims_waiting_pool(self):
        from webui.app import create_app
        client=create_app(auth_code='fixture').test_client()
        headers={'X-Auth-Code':'fixture','Accept-Encoding':'identity'}
        self.assertEqual(client.post('/api/jobs/stop').status_code,401)
        svc.configure_workers(2)
        client.post('/api/jobs/pause',headers=headers)
        response=client.post('/api/jobs',headers=headers,json={'selected_emails':self.select(4),'email_source':'generic_api'})
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.get_json()['submitted'],4)
        self.assertTrue(all(db.get_generic_api_email_by_email(x['email'])['status']=='available' for x in self.select(4)))
        self.assertEqual(len(self.entered),0)
        result=client.post('/api/jobs/stop',headers=headers).get_json()
        self.assertEqual(result['cancelled'],4)
        client.post('/api/jobs/resume',headers=headers)
        self.assertEqual(len(self.entered),0)
        self.assertEqual(db.list_jobs_page()['total'],4)


class RegistrationTwofaParallelTests(unittest.TestCase):
    def test_ten_registration_children_overlap_even_when_account_page_is_full(self):
        with ExitStack() as stack:
            root=Path(stack.enter_context(tempfile.TemporaryDirectory()))
            stack.enter_context(patch.multiple(db,**storage(root)))
            ids=[db.insert_account(email=f'fixture{i}@example.test',access_token='fixture') for i in range(10)]
            stack.enter_context(patch.object(svc,'_EXECUTION_SLOTS',ConcurrencyLimit(10)))
            stack.enter_context(patch.object(account_concurrency,'_LIMIT',ConcurrencyLimit(1)))
            queue=threading.BoundedSemaphore(1);queue.acquire()
            stack.enter_context(patch.object(twofa,'_QUEUE_SLOTS',queue))
            stack.enter_context(patch.object(twofa,'_RUNNING',set()))
            stack.enter_context(patch.object(twofa,'_append_log'))
            stack.enter_context(patch.object(twofa,'log_path',side_effect=lambda email:root/(email+'.log')))
            stack.enter_context(patch('core.workflow_driver.require_driver_ready',return_value='protocol'))
            stack.enter_context(patch('config.email.USE_EMAIL_SERVICE',True))
            entered=threading.Barrier(11);release=threading.Event();owners=[]
            def setup(session,email,**kwargs):
                owners.append((threading.get_ident(),session.owner));entered.wait(5);release.wait(5);return 'fixture-secret'
            stack.enter_context(patch.object(twofa,'setup_2fa',side_effect=setup))
            stack.enter_context(patch('core.workflow_driver.create_account_session',side_effect=lambda **kw:SimpleNamespace(owner=threading.get_ident(),proxy=None,device_id='fixture',fingerprint_summary_text=lambda:'fixture')))
            stack.enter_context(patch.object(twofa,'_resolve_twofa_proxy',return_value=(None,None,'fixture')))
            stack.enter_context(patch.object(twofa,'close_browser_session'))
            stack.enter_context(patch.object(twofa,'_EXECUTOR',Mock(submit=Mock(side_effect=AssertionError('must stay inline')))))
            def child(i):
                queued=twofa.enqueue_account_totp_setup(account_id=ids[i],email=f'fixture{i}@example.test',access_token='fixture',trigger='registration_auto')
                return queued['future'].result()
            with ThreadPoolExecutor(10) as pool:
                futures=[pool.submit(svc._run_limited,child,i) for i in range(10)]
                try:
                    entered.wait(5)
                    self.assertEqual(len(twofa._RUNNING),10)
                    self.assertEqual(svc._EXECUTION_SLOTS.snapshot()['running'],10)
                    self.assertEqual(account_concurrency.queue_settings()['running'],0)
                    self.assertTrue(all(a==b for a,b in owners))
                finally:release.set()
                self.assertTrue(all(f.result(5)['ok'] for f in futures))
            self.assertTrue(all(db.get_account(id)['totp_setup_status']=='success' for id in ids))
