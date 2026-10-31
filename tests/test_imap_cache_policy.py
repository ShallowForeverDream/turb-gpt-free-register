import sqlite3
import inspect
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from core import account_export, account_liveness, imap_mail_client as imap, imap_message_cache as cache
from tests.test_imap_bounded_reads import Mailbox, SHARED, TARGET, fixture, message


class _Clock:
    def __init__(self):
        self.elapsed = 0.0
        self.started = time.time()

    def monotonic(self):
        return self.elapsed

    def time(self):
        return self.started + self.elapsed

    def sleep(self, seconds):
        self.elapsed += seconds

    def deadline(self, seconds):
        clock = self

        class Deadline:
            expires_at = clock.elapsed + seconds

            def __enter__(self): return self
            def __exit__(self, *args): pass
            def remaining(self): return max(0.001, self.expires_at - clock.elapsed)
            def bind_socket(self, sock): pass
            def release_socket(self, sock): return True
            def close_socket(self): pass

        return Deadline()


class ImapCachePolicyTests(unittest.TestCase):
    def setUp(self):
        imap.close_shared_imap_connections()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.addCleanup(imap.close_shared_imap_connections)
        folder = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.stack.enter_context(patch.object(cache, 'CACHE_PATH', Path(folder) / 'cache.sqlite3'))
        self.account = imap.ImapEmailAccount(TARGET, 'fixture-private', 'imap.example.test',
            username=SHARED, forwarded=True, cache_enabled=True)

    def item(self, *, recipient=TARGET, stamp=None, code='123456'):
        return {'to':recipient, 'from':'OpenAI <noreply@openai.com>',
            'date':datetime.fromtimestamp(stamp or time.time(), timezone.utc).isoformat(),
            'subject':'Verification code is ' + code, 'text':'Your code is ' + code}

    def test_disk_cache_hit_does_not_open_imap_even_after_process_cache_clear(self):
        item = self.item()
        cache.write(self.account, [(TARGET, item, imap._message_timestamp(item))])
        with patch.object(imap, 'get_account_context', return_value=self.account), \
             patch.object(imap, '_connect') as connect:
            code = imap.fetch_latest_otp(TARGET, after_ts=time.time(), max_wait=2, settle_seconds=0)
        self.assertEqual(code, '123456')
        connect.assert_not_called()
        self.assertFalse(imap._SHARED_INBOXES)

    def test_disk_cache_is_exact_recipient_and_credential_scoped(self):
        item = self.item()
        cache.write(self.account, [(TARGET, item, imap._message_timestamp(item))])
        for recipient in ('a' + TARGET, SHARED, TARGET.replace('@', '+tag@')):
            self.assertEqual(cache.read(self.account, recipient, time.time()-60), [])
        self.account.password = 'different-fixture'
        self.assertEqual(cache.read(self.account, TARGET, time.time()-60), [])
        self.account.password = 'fixture-private'
        self.account.server = 'different.example.test'
        self.assertEqual(cache.read(self.account, TARGET, time.time()-60), [])

    def test_cache_physically_prunes_old_rows_and_never_stores_older_mail(self):
        now = time.time()
        fresh, stale = self.item(stamp=now), self.item(stamp=now-86401)
        cache.write(self.account, [(TARGET, fresh, now), (TARGET, stale, now-86401)])
        with closing(sqlite3.connect(cache.CACHE_PATH)) as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM messages').fetchone()[0], 1)
        with patch.object(cache.time, 'time', return_value=now+86401):
            self.assertEqual(cache.read(self.account, TARGET, 0), [])
        with closing(sqlite3.connect(cache.CACHE_PATH)) as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM messages').fetchone()[0], 0)

    def test_old_code_outside_the_new_send_window_is_not_returned(self):
        stamp = time.time()-45
        cache.write(self.account, [(TARGET, self.item(stamp=stamp), stamp)])
        self.assertEqual(cache.read(self.account, TARGET, time.time()-30), [])

    def test_rejected_recent_code_cannot_win_over_new_mail_from_either_cache(self):
        item = self.item(code='123456')
        cache.write(self.account, [(TARGET,item,imap._message_timestamp(item))])
        mail = Mailbox({b'1':message(subject='Verification code is 123456'),
                        b'2':message(subject='Verification code is 654321')})
        mail.sock, mail.shutdown = Mock(), Mock()
        with patch.object(imap, 'get_account_context', return_value=self.account), \
             patch.object(imap, '_connect', return_value=mail) as connect:
            code = imap.fetch_latest_otp(TARGET, after_ts=time.time(), max_wait=2,
                                        settle_seconds=0, exclude_codes={'123456'})
        self.assertEqual(code, '654321')
        connect.assert_called_once()
        with patch.object(imap, 'get_account_context', return_value=self.account), \
             patch.object(imap, '_connect') as connect:
            self.assertEqual(imap.fetch_latest_otp(TARGET, after_ts=time.time(), max_wait=2,
                settle_seconds=0, exclude_codes={'123456'}), '654321')
        connect.assert_not_called()

    def test_persisted_snapshot_contains_no_password_or_full_body(self):
        item = self.item()
        item['text'] += '\nprivate unrelated message tail'
        state = imap._SearchState(items={b'1':item})
        imap._cache_snapshot(self.account, state)
        raw = cache.CACHE_PATH.read_bytes()
        self.assertNotIn(b'fixture-private', raw)
        self.assertNotIn(b'private unrelated message tail', raw)
        self.assertEqual(imap.extract_otp(cache.read(self.account, TARGET, time.time()-60)[0]), '123456')

    def test_state_prunes_mail_older_than_one_day_without_resetting_uid_cursor(self):
        state = imap._SearchState(items={b'1':self.item(stamp=time.time()-86401)},
            headers={b'1':b'old'}, window=[b'1'], body_uids={b'1'}, seen={b'1'}, highest_uid=10)
        imap._cache_snapshot(self.account, state)
        self.assertEqual((state.items, state.headers, state.window), ({},{},[]))
        self.assertEqual(state.highest_uid, 10)

    def virtual_query(self, *, failure=None, arrive_at=None):
        clock = _Clock()
        account = imap.ImapEmailAccount(TARGET, 'fixture', 'imap.example.test', username=SHARED, forwarded=True)
        mail = Mailbox({})
        mail.sock, mail.shutdown = Mock(), Mock()
        connect = Mock(return_value=mail, side_effect=failure)
        calls = []
        original = mail.uid

        def uid(command, *args):
            if command == 'SEARCH':
                calls.append(clock.elapsed)
                if arrive_at is not None and clock.elapsed >= arrive_at:
                    mail.messages[b'1'] = message(subject='Verification code is 654321')
            return original(command, *args)

        mail.uid = uid
        with patch.object(imap, 'time', clock), patch.object(imap, 'ImapDeadline', clock.deadline), \
             patch.object(imap, 'get_account_context', return_value=account), patch.object(imap, '_connect', connect):
            try:
                result = imap.fetch_latest_otp(TARGET, after_ts=clock.started, max_wait=9999,
                    poll_interval=1, settle_seconds=0)
            except imap.ImapOtpTimeout:
                result = None
        return result, clock.elapsed, calls, connect.call_count

    def test_production_refresh_interval_is_sixty_and_wait_is_capped_at_180(self):
        self.assertEqual(imap._REMOTE_REFRESH_SECONDS, 60)
        result, elapsed, searches, connects = self.virtual_query()
        self.assertIsNone(result)
        self.assertEqual(elapsed, 180)
        self.assertEqual(searches, [0,60,120])
        self.assertEqual(connects, 1)

    def test_connection_failures_cannot_reconnect_every_local_cache_poll(self):
        result, elapsed, searches, connects = self.virtual_query(failure=imap.ImapMailError('fixture'))
        self.assertIsNone(result)
        self.assertEqual((elapsed, searches, connects), (180, [], 3))

    def test_late_arrival_is_found_at_next_minute_not_missed_by_uid_cursor(self):
        result, elapsed, searches, connects = self.virtual_query(arrive_at=60)
        self.assertEqual((result, elapsed, searches, connects), ('654321',60,[0,60],1))

    def test_real_shared_connection_publishes_five_aliases_then_disk_serves_without_network(self):
        expected = {f'alias{i}@example.test':str(100000+i) for i in range(5)}
        data = {str(i+1).encode():message(to=SHARED, body=f'To: {email}\nYour code is {code}'.encode())
                for i,(email,code) in enumerate(expected.items())}
        with fixture(messages=data, refresh_interval=60) as server:
            def context(email):
                return imap.ImapEmailAccount(email, 'fixture', '127.0.0.1', server.server_address[1],
                    username=SHARED, use_ssl=False, forwarded=True, cache_enabled=True)

            def read(email):
                return imap.fetch_latest_otp(email, after_ts=time.time()-5, max_wait=3, settle_seconds=0)

            with patch.object(imap, 'get_account_context', side_effect=context), ThreadPoolExecutor(5) as pool:
                self.assertEqual(dict(zip(expected, pool.map(read, expected))), expected)
                self.assertEqual(server.commands.count('LOGIN'), 1)
                self.assertEqual((server.searches, server.header_fetches, server.body_fetches), (1,5,5))
                imap.close_shared_imap_connections()
                commands = len(server.commands)
                with patch.object(imap, '_connect') as connect:
                    self.assertEqual(dict(zip(expected, pool.map(read, expected))), expected)
                connect.assert_not_called()
                self.assertEqual(len(server.commands), commands)


class MailTimeoutRoundTests(unittest.TestCase):
    def test_invalid_otp_is_excluded_when_waiting_for_its_replacement(self):
        with patch.object(account_liveness, 'wait_for_otp', side_effect=['123456','654321']) as wait, \
             patch.object(account_liveness, 'send_email_otp'), \
             patch.object(account_liveness, 'validate_email_otp',
                side_effect=[account_liveness.EmailOtpInvalidError('fixture'), {'ok':True}]), \
             patch.object(account_liveness.time, 'sleep'):
            self.assertEqual(account_liveness._validate_with_retry(Mock(), TARGET, time.time()), {'ok':True})
        self.assertNotIn('exclude_codes', wait.call_args_list[0].kwargs)
        self.assertEqual(wait.call_args_list[1].kwargs['exclude_codes'], {'123456'})

    def test_registration_three_timeouts_release_mailbox_without_disabling_it(self):
        import main
        session = SimpleNamespace(proxy=None, device_id='fixture', auth_session_logging_id='fixture')
        with ExitStack() as stack:
            for name in ('network_preflight','get_providers','get_csrf_token','signin_openai',
                         'follow_authorize','human_delay','close_browser_session'):
                stack.enter_context(patch.object(main, name))
            stack.enter_context(patch('core.workflow_driver.require_driver_ready', return_value='protocol'))
            stack.enter_context(patch.object(main, 'BrowserSession', return_value=session))
            stack.enter_context(patch.object(main, '_prepare_registration_otp', return_value=(None,time.time())))
            stack.enter_context(patch.object(main._email_cfg, 'USE_EMAIL_SERVICE', True))
            stack.enter_context(patch.object(main._protocol_cfg, 'CHATGPT_ANON_BOOTSTRAP_ENABLED', False))
            wait = stack.enter_context(patch.object(main, 'wait_for_otp', side_effect=imap.ImapOtpTimeout('fixture')))
            send = stack.enter_context(patch.object(main, 'send_email_otp'))
            create = stack.enter_context(patch.object(main, 'create_account'))
            release = stack.enter_context(patch('core.email_provider.release_email'))
            result = inspect.unwrap(main.run_registration)(TARGET, 'Fixture', '1990-01-01')
        self.assertFalse(result['success'])
        self.assertEqual((wait.call_count,send.call_count), (3,2))
        create.assert_not_called()
        self.assertEqual(release.call_args.kwargs['status'], 'available')

    def test_live_check_stops_after_three_timeouts_and_two_resends(self):
        for operation in (account_liveness._validate_with_retry, account_liveness._validate_reauth_with_retry):
            with self.subTest(operation=operation.__name__), \
                 patch.object(account_liveness, 'wait_for_otp', side_effect=imap.ImapOtpTimeout('fixture')) as wait, \
                 patch.object(account_liveness, 'send_email_otp') as send, \
                 patch.object(account_liveness.time, 'sleep'), patch.object(account_liveness, 'human_delay'):
                with self.assertRaises(imap.ImapOtpTimeout):
                    operation(Mock(), TARGET, time.time())
                self.assertEqual((wait.call_count,send.call_count), (3,2))
        self.assertFalse(account_liveness._is_retryable_network_error(imap.ImapOtpTimeout('fixture')))

    def test_later_code_completes_wait_without_a_fourth_round(self):
        with patch.object(account_liveness, 'wait_for_otp',
                 side_effect=[imap.ImapOtpTimeout('fixture'), imap.ImapOtpTimeout('fixture'), '654321']) as wait, \
             patch.object(account_liveness, 'send_email_otp') as send, \
             patch.object(account_liveness, 'validate_email_otp', return_value={'ok':True}) as validate, \
             patch.object(account_liveness.time, 'sleep'):
            self.assertEqual(account_liveness._validate_with_retry(Mock(), TARGET, time.time()), {'ok':True})
        self.assertEqual((wait.call_count,send.call_count,validate.call_count), (3,2,1))

    def test_send_refusal_stops_instead_of_waiting_again(self):
        with patch.object(account_liveness, 'wait_for_otp', side_effect=imap.ImapOtpTimeout('fixture')) as wait, \
             patch.object(account_liveness, 'send_email_otp', side_effect=RuntimeError('HTTP 429')) as send:
            with self.assertRaisesRegex(RuntimeError, '429'):
                account_liveness._validate_with_retry(Mock(), TARGET, time.time())
        self.assertEqual((wait.call_count,send.call_count), (1,1))

    def test_twofa_three_timeouts_do_not_restart_authentication_or_enroll(self):
        with patch.object(account_export, '_trigger_reauth_with_retry', return_value='https://example.test/auth') as trigger, \
             patch.object(account_export, '_follow_reauth_with_retry'), patch.object(account_export, 'human_delay'), \
             patch('config.email.USE_EMAIL_SERVICE', True), \
             patch('core.openai_auth.send_email_otp') as send, \
             patch('core.email_provider.wait_for_otp', side_effect=imap.ImapOtpTimeout('fixture')) as wait, \
             patch.object(account_export, '_enroll_totp') as enroll:
            with self.assertRaises(imap.ImapOtpTimeout):
                account_export.setup_2fa(SimpleNamespace(), TARGET)
        self.assertEqual((wait.call_count,send.call_count,trigger.call_count), (3,3,1))
        enroll.assert_not_called()


if __name__ == '__main__':
    unittest.main()
