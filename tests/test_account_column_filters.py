import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from core import db
from core.account_column_filters import COLUMNS, normalize_filters
from tests.test_forwarded_imap_and_account_import import storage
from webui.app import create_app


class AccountColumnFilterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        scope = patch.multiple(db, **storage(Path(temporary.name)))
        scope.start(); self.addCleanup(scope.stop)
        self.ids = {}
        db.import_outlook_accounts([{'email':'alpha@example.test','password':'fixture-mail-password'}])
        timezone_cn = timezone(timedelta(hours=8))
        stamps = [datetime(2026,10,10,23,59,59,tzinfo=timezone_cn).timestamp(),
                  datetime(2026,10,20,0,0,tzinfo=timezone_cn).timestamp()*1000]
        for name, source, token, group, note in [
            ('alpha','outlook','fixture-access-token','待处理','alpha note'),
            ('beta','imap','','已卖',''), ('gamma','outlook','fixture-token-2','','beta note'),
            ('delta','generic_api','fixture-token-3','<img onerror="bad">',"' OR 1=1 --"),
            ('dead','imap','fixture-dead-token','','')]:
            self.ids[name] = db.insert_account(email=name+'@example.test',access_token=token,
                email_source=source,plan_type='free')
        rows = db._load_accounts()
        for row in rows:
            name = row['email'].split('@')[0]
            row['account_group'] = {'alpha':'待处理','beta':'已卖','delta':'<img onerror="bad">'}.get(name,'')
            row['note'] = {'alpha':'alpha note','gamma':'beta note','delta':"' OR 1=1 --"}.get(name,'')
            row['codex_status'] = {'alpha':'success','beta':'failed','gamma':'retrying'}.get(name,'')
            if name in {'gamma','dead'}: row['archived'] = True
            if name == 'dead': row['live_check_status'] = 'deactivated'
            if name in {'alpha','beta'}:
                row['extra_json'] = json.dumps({'account':{'createdTime':stamps[0 if name=='alpha' else 1]},
                    **({'registration_password':'fixture-gpt-password'} if name=='alpha' else {})})
                row['flow_traffic'] = {'available':True,'total_bytes':(2 if name=='alpha' else 5)*1048576,
                                       'dynamic_ip_bytes':(1 if name=='alpha' else 2)*1048576}
            if name == 'alpha': row['totp_secret'] = 'fixture-secret'
            if name == 'delta':
                row['registration_password'] = 'fixture-direct-gpt-password'
                row['extra_json'] = json.dumps({'account':{'createdTime':'1e'}})
                row['flow_traffic'] = {'available':False,'total_bytes':9*1048576}
        db._save_accounts(rows)
        for product, name, percent in [('plus','alpha',50),('go','beta',100)]:
            db.update_account_plan_check(self.ids[name],result={'ok':True,'current_plan_type':'free',
                'eligible_promo_campaigns':{product:{'metadata':{'discount':{'percentage':percent},
                    'duration':{'num_periods':1,'period':'month'}}}}})
        self.client = create_app(auth_code='fixture').test_client()
        self.headers = {'X-Auth-Code':'fixture','Accept-Encoding':'identity'}
        rows = db._load_accounts()
        next(row for row in rows if row['id']==self.ids['gamma'])['totp_setup_status']='queued'
        db._save_accounts(rows)

    def query(self, filters, **kwargs):
        response = self.client.get('/api/accounts',query_string={'paged':1,'filters':json.dumps(filters),**kwargs},headers=self.headers)
        self.assertEqual(response.status_code,200,response.get_data(as_text=True))
        return response.get_json()

    def names(self, filters):
        return {row['email'].split('@')[0] for row in self.query(filters)['items']}

    def test_all_sixteen_columns_filter_without_enumerating_secret_values(self):
        cases = [
            ('id',{'values':[str(self.ids['alpha'])]}, {'alpha'}),
            ('status',{'values':['archived']},{'gamma'}),
            ('email',{'values':['ALPHA@example.test','beta@example.test']},{'alpha','beta'}),
            ('group',{'values':['待处理','已卖']},{'alpha','beta'}),
            ('source',{'values':['imap']},{'beta'}),
            ('email_otp',{'values':['unsupported']},set()),
            ('token',{'values':['missing']},{'beta'}),
            ('gpt_password',{'values':['present']},{'alpha','delta'}),
            ('mail_password',{'values':['present']},{'alpha'}),
            ('plan',{'values':['plus_half_1m','go_trial_1m']},{'alpha','beta'}),
            ('note',{'text':'alpha'},{'alpha'}),
            ('twofa',{'values':['enabled']},{'alpha'}),
            ('codex',{'values':['success','failed']},{'alpha','beta'}),
            ('registered_at',{'values':['missing']},{'gamma','delta'}),
            ('traffic',{'min':2.1,'max':6,'dynamic_max':2},{'beta'}),
            ('actions',{'values':['twofa']},{'delta'}),
        ]
        self.assertEqual({key for key,_,_ in cases},set(COLUMNS))
        for key, value, expected in cases:
            with self.subTest(column=key): self.assertEqual(self.names({key:value}),expected)

    def test_column_or_and_combination_pagination_and_poll_scope(self):
        filters={'source':{'values':['outlook','imap']},'status':{'values':['unarchived']}}
        rows=self.query(filters,page_size=1,page=2)
        poll=self.client.get('/api/accounts/plan-check-status',headers=self.headers,
            query_string={'filters':json.dumps(filters),'page_size':1,'page':2}).get_json()
        self.assertEqual(rows['total'],2);self.assertEqual(poll['total'],2)
        self.assertEqual([r['id'] for r in rows['items']],[r['id'] for r in poll['items']])
        self.assertEqual(self.names({'status':{'values':['unarchived','archived']}}),{'alpha','beta','gamma','delta'})

    def test_general_free_plus_eligibility_has_a_selectable_option(self):
        rows = db._load_accounts()
        for row in rows:
            row['plus_trial_eligible'] = row['email'].startswith(('alpha@','beta@','gamma@'))
            if row['email'].startswith('gamma@'):
                row['current_plan_type'] = 'plus'
        db._save_accounts(rows)
        filters = {'plan':{'values':['plus_trial']}}
        self.assertEqual(self.names(filters), {'alpha','beta'})
        # General eligibility is not a claim of a specific 100%-off campaign.
        self.assertEqual(self.names({'plan':{'values':['plus_trial_1m']}}), set())
        response = self.client.get('/api/accounts/filter-options?column=plan',headers=self.headers).get_json()
        self.assertIn({'value':'plus_trial','label':'free(可Plus试用)'}, response['items'])
        poll = self.client.get('/api/accounts/plan-check-status', headers=self.headers,
            query_string={'filters':json.dumps(filters)}).get_json()
        self.assertEqual(poll['total'], 2)

    def test_date_range_is_inclusive_and_uses_real_registration_not_import_time(self):
        self.assertEqual(self.names({'registered_at':{'from':'2026-10-10','to':'2026-10-10'}}),{'alpha'})
        self.assertEqual(self.names({'registered_at':{'from':'2026-10-20','to':'2026-10-20'}}),{'beta'})
        self.assertEqual(self.names({'registered_at':{'from':'2026-10-10','to':'2026-10-20'}}),{'alpha','beta'})
        self.assertEqual(self.names({'registered_at':{'from':'2026-10-25','to':'2026-10-25'}}),set())

    def test_facets_are_cross_column_paginated_and_do_not_apply_their_own_selection(self):
        filters={'email':{'values':['alpha@example.test']},'source':{'values':['outlook']}}
        response=self.client.get('/api/accounts/filter-options',headers=self.headers,
            query_string={'column':'email','filters':json.dumps(filters),'limit':1}).get_json()
        self.assertTrue(response['has_more']);self.assertEqual(len(response['items']),1)
        second=self.client.get('/api/accounts/filter-options',headers=self.headers,
            query_string={'column':'email','filters':json.dumps(filters),'limit':1,'offset':1}).get_json()
        self.assertNotEqual(response['items'][0]['value'],second['items'][0]['value'])
        for column in ('token','gpt_password','mail_password'):
            raw=self.client.get('/api/accounts/filter-options?column='+column,headers=self.headers).get_data(as_text=True)
            self.assertNotIn('fixture-',raw);self.assertIn('present',raw)

    def test_search_is_literal_and_group_labels_remain_data(self):
        self.assertEqual(self.names({'note':{'text':"' OR 1=1 --"}}),{'delta'})
        self.assertEqual(self.names({'group':{'values':['<img onerror="bad">']}}),{'delta'})

    def test_invalid_filters_fail_before_query_and_are_authenticated(self):
        self.assertEqual(self.client.get('/api/accounts/filter-options?column=email').status_code,401)
        invalid=[{'token':{'values':['fixture-secret']}},{'no_such_column':{}},
            {'traffic':{'min':float('nan')}},{'traffic':{'min':5,'max':1}},
            {'registered_at':{'from':'2026-02-30'}},{'registered_at':{'to':'9999-12-31'}},
            {'registered_at':{'from':'2026-10-20','to':'2026-10-10'}}]
        for filters in invalid:
            for path in ('/api/accounts','/api/accounts/plan-check-status'):
                response=self.client.get(path,headers=self.headers,query_string={'filters':json.dumps(filters)})
                self.assertEqual(response.status_code,400)
                self.assertNotIn('fixture-secret',response.get_data(as_text=True))

    def test_page_and_dynamic_options_do_not_load_all_account_payloads_into_python(self):
        with patch.object(db,'_load_accounts',side_effect=AssertionError('unbounded account load')):
            self.assertEqual(db.list_accounts_page(limit=1,column_filters={'token':['present']})['total'],3)
            self.assertEqual(len(db.list_account_filter_options('email',limit=1)['items']),1)


if __name__=='__main__':
    unittest.main()
