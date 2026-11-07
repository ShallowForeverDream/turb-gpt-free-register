"""Sanitized fixtures only. No real mailbox token, mail body or service request."""
import json
import tempfile
import time
import unittest
from contextlib import ExitStack, closing
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from core import db, grok_mail, grok_store, icapi_mailbox as mail
from core import generic_api_mail_client as generic
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app

EMAIL = 'fixture@icloud.com'
VIEW = mail.ORIGIN + '/v#token=' + 'A' * 43
NOW = 1804200000
BATCH = '2026-10-28T21:08:15'


def message(mid=1, *, platform='grok', code='123456', age=1, **extra):
    data = {'id': mid, 'subject': f'{"Grok" if platform == "grok" else "OpenAI"} confirmation code: {code}',
            'from': 'forwarder@icloud.com', 'sender': '', 'reply_to': '', 'recipient': EMAIL,
            'received_at': datetime.fromtimestamp(NOW - age, timezone.utc).isoformat()}
    data.update(extra)
    return data


def response(payload, status=200):
    return Mock(status_code=status, json=Mock(return_value=payload))


class MailboxTests(unittest.TestCase):
    def setUp(self):
        self.clock = patch.object(mail.time, 'time', return_value=NOW)
        self.clock.start(); self.addCleanup(self.clock.stop)

    def read(self, messages, *, platform='grok', detail=None, **kwargs):
        http = Mock()
        http.get.side_effect = [response({'mailbox': EMAIL, 'messages': messages}), response(detail)]
        value = mail.latest_code(EMAIL, VIEW, platform=platform, http=http, **kwargs)
        return value, http

    def test_viewer_link_is_not_derived_from_legacy_api_token(self):
        self.assertEqual(mail.viewer_token(VIEW), 'A' * 43)
        for url in (VIEW.replace('https:', 'http:'), VIEW.replace('/v#', '/api#'), VIEW+'&token=duplicate',
                    VIEW.replace('icapi.oaibx.com', 'evil.test'), VIEW.replace('/v#', ':444/v#'),
                    VIEW.replace('https://', 'https://user:pass@'), VIEW+'%0A', VIEW.replace('#', '?')):
            self.assertFalse(mail.is_viewer_url(url))

    def test_numeric_grok_and_gpt_are_selected_by_platform_not_code_shape(self):
        messages = [message(1), message(2, platform='gpt', code='654321', age=0)]
        grok, http = self.read(messages)
        gpt, _ = self.read(messages, platform='gpt')
        self.assertEqual((grok, gpt), ('123456', '654321'))
        http.get.assert_called_once()
        args = http.get.call_args
        self.assertEqual(args.args[0], mail.ORIGIN+'/api/v1/public/messages')
        self.assertEqual(args.kwargs['headers']['Authorization'], 'Bearer '+'A'*43)
        self.assertFalse(args.kwargs['allow_redirects']); self.assertTrue(args.kwargs['verify'])

    def test_sorting_uses_time_then_id_and_does_not_fall_back_to_older_codes(self):
        value, _ = self.read([message(5, code='111111', age=1), message(6, code='222222', age=1), message(9, code='333333', age=5)])
        self.assertEqual(value, '222222')
        newest = message(10, code='', subject='Grok email confirmation', age=0)
        value, http = self.read([message(1), newest], detail={**newest, 'text_body': 'No code yet'})
        self.assertEqual(value, ''); self.assertEqual(http.get.call_count, 2)

    def test_send_time_excluded_codes_and_ambiguous_platform_are_not_reused(self):
        self.assertEqual(self.read([message(age=30)], after_ts=NOW-10)[0], '')
        self.assertEqual(self.read([message()], exclude_codes={'123456'})[0], '')
        self.assertEqual(self.read([message(subject='Grok OpenAI confirmation code: 123456')])[0], '')
        self.assertEqual(self.read([message(recipient='other@icloud.com')])[0], '')

    def test_subject_and_html_body_regex_accept_actual_numeric_and_alphanumeric_shapes(self):
        for code in ('123456', 'A1B-C2D', 'ABCDEF'):
            self.assertEqual(self.read([message(code=code)])[0], code.replace('-', ''))
        data = message(subject='Grok verification', code='')
        value, http = self.read([data], detail={**data, 'text_body': 'Verify\nThanks',
                                              'sanitized_html': '<script>111111</script><style>222222</style><p>Validate your email</p><strong>654321</strong>'})
        self.assertEqual(value, '654321'); self.assertEqual(http.get.call_count, 2)
        self.assertEqual(mail.code_from_text('Verify\nThanks', 'grok'), '')
        self.assertEqual(mail.code_from_text('OpenAI confirmation code: ABCDEF', 'gpt'), '')

    def test_mailbox_and_detail_identity_fail_closed(self):
        http = Mock(); http.get.return_value = response({'mailbox': 'other@icloud.com', 'messages': [message()]})
        with self.assertRaises(mail.MailboxError): mail.latest_code(EMAIL, VIEW, platform='grok', http=http)
        http.get.assert_called_once()
        latest = message(subject='Grok verification')
        for detail in ({**latest, 'recipient': 'other@icloud.com'}, {**latest, 'id': 42}, {**latest, 'subject': 'OpenAI verification'}):
            with self.assertRaises(mail.MailboxError): self.read([latest], detail=detail)

    def test_invalid_ids_and_timestamps_never_choose_historical_candidate(self):
        for bad in (message(id='../private'), message(received_at='invalid'), message(age=-1000)):
            with self.assertRaises(mail.MailboxError): self.read([message(2, age=30), bad])

    def test_refusals_timeout_and_malformed_json_are_redacted_and_never_redirected(self):
        for status in (401, 403, 429):
            http = Mock(); http.get.return_value = response({}, status)
            with self.assertRaises(mail.MailboxError) as caught: mail.latest_code(EMAIL, VIEW, platform='grok', http=http)
            self.assertEqual(caught.exception.http_status, status)
            self.assertFalse(caught.exception.retryable); http.get.assert_called_once()
        http = Mock(); http.get.side_effect = requests.Timeout('private-token https://private.test')
        with self.assertRaises(mail.MailboxError) as caught: mail.latest_code(EMAIL, VIEW, platform='grok', http=http)
        self.assertTrue(caught.exception.retryable); self.assertNotIn('private', str(caught.exception))
        http.get.side_effect = None; http.get.return_value = Mock(status_code=200, json=Mock(side_effect=ValueError('private-json')))
        with self.assertRaises(mail.MailboxError) as caught: mail.latest_code(EMAIL, VIEW, platform='grok', http=http)
        self.assertFalse(caught.exception.retryable); self.assertNotIn('private', str(caught.exception))

    def test_grok_adapter_accepts_numeric_only_with_verified_mailbox_attribution(self):
        http = Mock(); http.get.return_value = response({'mailbox': EMAIL, 'messages': [message()]})
        seen = []
        code = grok_mail.read_once({'email': EMAIL, 'source': 'generic_api', 'code_url': VIEW}, http=http, diagnostic=seen.append)
        self.assertEqual(code, '123-456')
        self.assertNotIn('123456', json.dumps(seen)); self.assertNotIn('A'*43, json.dumps(seen))
        self.assertEqual(grok_mail.extract_code({'code': 1, 'data': {'code': '123456'}}), '')

    def test_pool_lookup_accepts_any_sender_and_returns_candidates(self):
        cases = {
            1: ('SteamGuard verification code', 'Your code: A1B2-C3D', 'A1B2-C3D', ['A1B2-C3D']),
            2: ('GitHub', 'Your verification code is 1234-5678', '1234-5678', ['1234-5678']),
            3: ('Discord', 'Your code: 98 – 57 – 22 – 01', '98572201', ['98572201']),
            4: ('Shop', 'Order 998877 shipped. Your code is 445566', '445566', ['445566']),
            5: ('Some service', '验证码：AB12CD', 'AB12CD', ['AB12CD']),
        }
        for mid, (sender, body, code, candidates) in cases.items():
            with self.subTest(body=body):
                latest = message(mid, platform='grok', code='', subject=sender)
                http = Mock()
                http.get.side_effect = [response({'mailbox': EMAIL, 'messages': [latest]}),
                                        response({**latest, 'text_body': body})]
                read = mail.latest_code_any(EMAIL, VIEW, http=http)
                self.assertEqual(read.code, code)
                self.assertEqual(read.candidates, candidates)

    def test_pool_lookup_requires_own_mailbox_and_problems_stay_redacted(self):
        http = Mock(); http.get.return_value = response({'mailbox': 'other@icloud.com', 'messages': []})
        with self.assertRaises(mail.MailboxError):
            mail.latest_code_any(EMAIL, VIEW, http=http)
        http.get.assert_called_once()

    def test_generic_polling_has_three_30_second_rounds_with_no_old_api_fallback(self):
        account = generic.GenericApiEmailAccount(EMAIL, VIEW)
        http = Mock()
        with patch.object(generic, '_new_http_session', return_value=http), \
             patch.object(generic, '_wait_icapi_delay') as sleep, \
             patch.object(generic, '_mailbox_latest_code', side_effect=['', '', '123456']) as fetch, \
             patch('core.registration_service.check_stop_requested'):
            code = generic._fetch_direct_icapi_otp(account, after_ts=NOW-20)
        self.assertEqual(code, '123456'); self.assertEqual(fetch.call_count, 3)
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [30, 30, 30])
        # A send-time anchor must reach the mailbox reader; otherwise a code
        # left in the inbox before this verification request can be reused.
        self.assertEqual(fetch.call_args.kwargs['after_ts'], NOW - 20 - 90)
        http.get.assert_not_called(); http.close.assert_called_once()

    def test_icapi_page_30_second_delay_starts_when_the_page_is_ready(self):
        account = generic.GenericApiEmailAccount(EMAIL, VIEW)
        with patch.object(generic, '_new_http_session', return_value=Mock()), \
             patch.object(generic, '_wait_icapi_delay') as sleep, \
             patch.object(generic, '_mailbox_latest_code', return_value='654321'), \
             patch('core.registration_service.check_stop_requested'):
            self.assertEqual(generic._fetch_direct_icapi_otp(account, ready_at=NOW), '654321')
            self.assertEqual(sleep.call_args.args[0], 30)
            generic._wait_icapi_delay.reset_mock()
            self.assertEqual(generic._fetch_direct_icapi_otp(account, ready_at=NOW - 40), '654321')
            self.assertEqual(sleep.call_args.args[0], 0)


class MailboxConfigTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.multiple(db, **storage(root)))
        self.stack.enter_context(patch.object(db, '_now', return_value=BATCH))
        self.other = 'second@icloud.com'
        db.import_generic_api_emails([{'email': EMAIL, 'code_url': 'https://icapi.oaibx.com/api?token=old-fixture'},
                                      {'email': self.other, 'code_url': 'https://icapi.oaibx.com/api?token=second-old'}])
        self.records = [{'email': EMAIL, 'url': VIEW}, {'email': self.other, 'url': VIEW.replace('A'*43, 'B'*43)}]

    def snapshot(self):
        with closing(db._sqlite_conn()) as conn:
            return [tuple(row) for row in conn.execute('SELECT * FROM email_pool ORDER BY id')]

    def test_batch_changes_only_link_fields_and_keeps_account_state(self):
        aid = db.insert_account(email=EMAIL, access_token='private-gpt-fixture')
        original = db.get_account(aid)
        before = db.get_generic_api_email_by_email(EMAIL)
        self.assertEqual(db.configure_icapi_mailboxes(self.records, imported_at=BATCH), 2)
        after = db.get_generic_api_email_by_email(EMAIL)
        self.assertEqual(after['code_url'], VIEW)
        self.assertEqual(after['previous_code_url'], before['code_url'])
        for key in ('id', 'email', 'status', 'used_at', 'imported_at', 'note'):
            self.assertEqual(after.get(key), before.get(key))
        self.assertEqual(db.get_account(aid), original)
        self.assertEqual(db._resolve_email_api_link(EMAIL, 'generic_api'), VIEW)

    def test_invalid_batch_duplicates_and_busy_mailbox_roll_back_atomically(self):
        original = self.snapshot()
        for rows, batch in ((self.records, 'wrong-batch'), ([self.records[0], self.records[0]], BATCH),
                            ([self.records[0], {'email': 'missing@icloud.com', 'url': self.records[1]['url']}], BATCH),
                            ([self.records[0], {'email': self.other, 'url': VIEW}], BATCH)):
            with self.assertRaises((ValueError, mail.MailboxError)): db.configure_icapi_mailboxes(rows, imported_at=batch)
            self.assertEqual(self.snapshot(), original)
        grok_store.create_jobs([{'email': self.other, 'source': 'generic_api'}])
        with self.assertRaises(ValueError): db.configure_icapi_mailboxes(self.records, imported_at=BATCH)
        self.assertEqual(self.snapshot(), original)

    def test_import_endpoint_auth_no_store_cache_invalidation_and_secret_link(self):
        client = create_app(auth_code='fixture').test_client(); headers = {'X-Auth-Code': 'fixture'}
        text = '\n'.join(row['email']+'----'+row['url'] for row in self.records)
        self.assertEqual(client.post('/api/grok/mailboxes/viewer-links', json={'text': text}).status_code, 401)
        with patch.dict(generic._CONTEXT_CACHE, {EMAIL: object()}):
            result = client.post('/api/grok/mailboxes/viewer-links', json={'text': text}, headers=headers)
            self.assertEqual(result.status_code, 200)
            self.assertNotIn(EMAIL, generic._CONTEXT_CACHE)
        self.assertEqual(result.get_json()['updated'], 2)
        self.assertEqual(result.headers['Cache-Control'], 'no-store')
        path = '/api/grok/mailbox-link?email='+EMAIL
        self.assertEqual(client.get(path).status_code, 401)
        self.assertEqual(client.get(path, headers=headers).get_json()['url'], VIEW)
        self.assertNotIn('A'*43, json.dumps(client.get('/api/grok/mailboxes', headers=headers).get_json()))

    def test_import_does_not_dispatch_or_access_mailboxes_and_rejects_invalid_lines(self):
        client = create_app(auth_code='fixture').test_client(); headers = {'X-Auth-Code': 'fixture'}
        original = self.snapshot()
        with patch('core.grok_service.submit') as submit, patch('core.icapi_mailbox.latest_code') as read:
            for text in ('bad-secret-line', EMAIL+'----https://evil.test/v#token='+'A'*43, ''):
                result = client.post('/api/grok/mailboxes/viewer-links', json={'text': text}, headers=headers)
                self.assertEqual(result.status_code, 400)
                self.assertNotIn('bad-secret-line', result.get_data(as_text=True))
            submit.assert_not_called(); read.assert_not_called()
        self.assertEqual(self.snapshot(), original)


if __name__ == '__main__': unittest.main()
