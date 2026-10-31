import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from config import env_loader
from core import db, registration_service as registration, twofa_service as twofa
from core.concurrency_limit import ConcurrencyLimit
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app


class LiveConcurrencyTests(unittest.TestCase):
    def test_increase_wakes_existing_waiters_and_decrease_does_not_interrupt_work(self):
        gate = ConcurrencyLimit(1)
        entered = [threading.Event() for _ in range(4)]
        release = [threading.Event() for _ in range(4)]

        def task(index):
            with gate:
                entered[index].set()
                if not release[index].wait(3):
                    raise AssertionError("fixture release timed out")

        with ThreadPoolExecutor(max_workers=4) as pool:
            try:
                futures = [pool.submit(task, 0)]
                self.assertTrue(entered[0].wait(1))
                futures.extend(pool.submit(task, i) for i in (1, 2))
                self.assertFalse(entered[1].wait(0.05))
                gate.set_limit(3)
                self.assertTrue(entered[1].wait(1))
                self.assertTrue(entered[2].wait(1))
                gate.set_limit(1)
                futures.append(pool.submit(task, 3))
                release[0].set(); release[1].set()
                self.assertFalse(entered[3].wait(0.05))
                release[2].set()
                self.assertTrue(entered[3].wait(1))
            finally:
                for event in release: event.set()
            for future in futures: future.result(timeout=2)

    def test_registration_resize_keeps_same_executor_and_applies_to_already_queued_work(self):
        old = registration.get_executor_workers()
        registration.shutdown_executor()
        entered, release, first_started = threading.Event(), threading.Event(), threading.Event()
        def running():
            first_started.set()
            release.wait(3)
        try:
            executor = registration.get_executor(1)
            first = executor.submit(registration._run_limited, running)
            self.assertTrue(first_started.wait(1))
            second = executor.submit(registration._run_limited, entered.set)
            self.assertFalse(entered.wait(0.05))
            self.assertIs(registration.get_executor(2), executor)
            self.assertTrue(entered.wait(1))
            release.set(); first.result(timeout=2); second.result(timeout=2)
        finally:
            release.set(); registration.shutdown_executor(); registration.configure_workers(old)

    def test_twofa_limit_can_be_changed_without_replacing_its_executor(self):
        original, executor = twofa.queue_settings()["workers"], twofa._EXECUTOR
        try:
            twofa.configure_workers(3)
            self.assertEqual(twofa.queue_settings()["workers"], 3)
            self.assertIs(twofa._EXECUTOR, executor)
            # Nested post-steps on the owner thread occupy one page task, not
            # three slots. Real overlapping workers are covered separately.
            from core import account_concurrency
            with twofa._EXECUTION_SLOTS, twofa._EXECUTION_SLOTS:
                self.assertEqual(account_concurrency.queue_settings()['running'], 1)
            self.assertEqual(account_concurrency.queue_settings()['running'], 0)
        finally:
            twofa.configure_workers(original)


class QueueControlsApiTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for context in [patch.multiple(db, **storage(root)), patch.object(env_loader, "_ENV_PATH", root / ".env"), patch.dict(os.environ)]:
            context.start(); self.addCleanup(context.stop)
        old_reg, old_twofa = registration.get_executor_workers(), twofa.queue_settings()["workers"]
        self.addCleanup(registration.configure_workers, old_reg)
        self.addCleanup(twofa.configure_workers, old_twofa)
        self.client = create_app(auth_code="fixture").test_client()
        self.headers = {"X-Auth-Code": "fixture", "Accept-Encoding": "identity"}

    def test_save_is_authenticated_persisted_live_and_does_not_submit_jobs(self):
        self.assertEqual(self.client.get('/api/jobs/concurrency').status_code, 401)
        with patch.object(registration, "submit_registration") as submit:
            response = self.client.post('/api/jobs/concurrency', headers=self.headers,
                                        json={"workers": 3, "twofa_workers": 2})
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.get_json()['restart_required'])
            self.assertEqual(registration.get_executor_workers(), 3)
            self.assertEqual(twofa.queue_settings()['workers'], 2)
            self.assertEqual(env_loader.read_env_file()['REGISTRATION_WORKERS'], '3')
            self.assertEqual(env_loader.read_env_file()['TWOFA_WORKERS'], '2')
            submit.assert_not_called()

    def test_invalid_values_never_write_config(self):
        for invalid in (0, 17, 1.5, True, "3"):
            with self.subTest(value=invalid), patch.object(env_loader, 'write_env_values') as write:
                response = self.client.post('/api/jobs/concurrency', headers=self.headers,
                                            json={"workers": invalid, "twofa_workers": 2})
                self.assertEqual(response.status_code, 400)
                write.assert_not_called()

    def test_each_save_preserves_the_other_queue_limit(self):
        self.client.post('/api/jobs/concurrency',headers=self.headers,json={'workers':3,'twofa_workers':2})
        state=self.client.post('/api/jobs/concurrency',headers=self.headers,json={'workers':5}).get_json()
        self.assertEqual((state['workers'],state['twofa_workers']),(5,2))
        state=self.client.post('/api/jobs/concurrency',headers=self.headers,json={'twofa_workers':4}).get_json()
        self.assertEqual((state['workers'],state['twofa_workers']),(5,4))


class AccountOfferFilterTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        state = patch.multiple(db, **storage(Path(tmp.name)))
        state.start(); self.addCleanup(state.stop)
        self.ids = {}
        for name, (product, percentage, months) in db._ACCOUNT_PROMO_FILTERS.items():
            self.ids[name] = self.add(name, product, percentage, months)
        self.add('unknown', 'plus', None, 12)
        self.add('quarter', 'plus', 50, 1, period='quarter')
        self.add('already_plus', 'plus', 50, 1, plan='plus')
        self.client = create_app(auth_code='fixture').test_client()
        self.headers = {'X-Auth-Code': 'fixture', 'Accept-Encoding': 'identity'}

    def add(self, name, product, percentage, months, *, period='month', plan='free'):
        aid = db.insert_account(email=name+'@example.test', access_token='fixture', plan_type=plan)
        db.update_account_plan_check(aid, result={'ok': True, 'current_plan_type': plan,
            'eligible_promo_campaigns': {product: {'metadata': {
                'discount': {'percentage': percentage}, 'duration': {'num_periods': months, 'period': period}}}}})
        return aid

    def test_all_eight_filters_match_sql_python_pagination_and_status_poll(self):
        for key, aid in self.ids.items():
            with self.subTest(filter=key):
                matching = db.list_accounts_page(plan_filter=key, limit=20)
                self.assertEqual(matching['total'], 1)
                self.assertEqual(matching['items'][0]['id'], aid)
                self.assertTrue(db._account_matches_plan_filter(db.get_account(aid), key))
                for endpoint in ('/api/accounts?paged=1&plan=', '/api/accounts/plan-check-status?plan='):
                    data = self.client.get(endpoint+key, headers=self.headers).get_json()
                    self.assertEqual(data['total'], 1)
                    self.assertEqual(data['items'][0]['id'], aid)

    def test_half_price_is_not_classified_as_free_trial(self):
        row = db.get_account(self.ids['plus_half_1m'])
        self.assertFalse(db._account_matches_plan_filter(row, 'plus_trial_1m'))
        row['eligible_promo_campaigns']['plus']['metadata'] = 'malformed'
        self.assertFalse(db._account_matches_plan_filter(row, 'plus_half_1m'))

    def test_saved_legacy_plus_fields_are_supported_without_guessing_unknown_offers(self):
        aid = db.insert_account(email='legacy@example.test', access_token='fixture', plan_type='free')
        db.update_account_plan_check(aid, result={'ok': True, 'current_plan_type': 'free',
            'plus_trial_eligible': True, 'plus_trial_discount_percentage': 100,
            'plus_trial_duration_num_periods': 1, 'plus_trial_duration_period': 'month'})
        self.assertEqual(db.list_accounts_page(plan_filter='plus_trial_1m')['total'], 2)
        self.assertTrue(db._account_matches_plan_filter(db.get_account(aid), 'plus_trial_1m'))

    def test_both_uis_put_filters_inside_the_accounts_table_header(self):
        for mode in ('modern', 'legacy'):
            html = self.client.get('/?ui='+mode, headers=self.headers).get_data(as_text=True)
            suffix = 'V2' if mode == 'modern' else ''
            start = html.index('id="accountsSelectAll'+suffix+'"')
            end = html.index('</thead>', start)
            header = html[start:end]
            for field in ['plan', 'status', 'group', 'twofa', 'codex']:
                self.assertTrue('data-account-filter="'+field+'"' in header, field)
            self.assertNotIn('<select', header)
            self.assertNotIn('id="showPlusAccountsOnly'+suffix+'"', html)
            options = self.client.get('/api/accounts/filter-options?column=plan',headers=self.headers).get_json()['items']
            for name in self.ids: self.assertIn(name, [option['value'] for option in options])


if __name__ == '__main__':
    unittest.main()
