#!/usr/bin/env python
#
# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import json
from unittest import TestCase
from mock import patch

from managesf import sfauth


class Fake:
    cookies = {'auth_pubtkt': '1234'}


class FakeJSONResponse(object):
    def __init__(self, dic):
        self.dic = dic
        self.status_code = 200

    def json(self):
        return self.dic


class TestSFAuth(TestCase):
    def test_get_cookie(self):
        with patch('managesf.sfauth.requests.get') as g:
            methods = ['Password', 'GithubPersonalAccessToken', 'APIKey']
            header = {'Content-Type': 'application/json'}
            info = {'service': {'name': 'cauth',
                                'version': '0.4.1',
                                'auth_methods': methods}}
            g.return_value = FakeJSONResponse(info)
            with patch('managesf.sfauth.requests.post') as p:
                p.return_value = Fake()
                self.assertEqual(
                    '1234',
                    sfauth.get_cookie('https://auth.tests.dom', 'user1',
                                      'userpass'))
                auth_context = {'back': '/',
                                'args': {'username': 'user1',
                                         'password': 'userpass'},
                                'method': 'Password', }
                p.assert_called_with('https://auth.tests.dom/auth/login',
                                     json.dumps(auth_context, sort_keys=True),
                                     allow_redirects=False,
                                     headers=header,
                                     verify=True)
                self.assertEqual(
                    '1234',
                    sfauth.get_cookie('https://auth.tests.dom',
                                      github_access_token='abcd'))
                auth_context = {'back': '/',
                                'method': 'GithubPersonalAccessToken',
                                'args': {'token': 'abcd'}}
                p.assert_called_with('https://auth.tests.dom/auth/login',
                                     json.dumps(auth_context, sort_keys=True),
                                     allow_redirects=False,
                                     headers=header,
                                     verify=True)
                self.assertEqual(
                    '1234',
                    sfauth.get_cookie('auth.tests.dom',
                                      api_key='abcd'))
                auth_context = {'back': '/',
                                'method': 'APIKey',
                                'args': {'api_key': 'abcd'}}
                p.assert_called_with('https://auth.tests.dom/auth/login',
                                     json.dumps(auth_context, sort_keys=True),
                                     allow_redirects=False,
                                     headers=header,
                                     verify=True)

    def test_get_cauth_info(self):
        with patch('managesf.sfauth.requests.get') as g:
            g.return_value = FakeJSONResponse({'service': {
                'name': 'cauth',
                'version': 'x.y.z',
                'auth_methods': ['password', 'openid']}})
            i = sfauth.get_cauth_info('https://auth.tests.dom')
            g.assert_called_with('https://auth.tests.dom/auth/about/',
                                 allow_redirects=False,
                                 verify=True)
            self.assertEqual('cauth',
                             i['service']['name'])

    def test_get_managesf_info(self):
        with patch('requests.get') as g:
            g.return_value = FakeJSONResponse({'service': {
                'name': 'managesf',
                'version': 'x.y.z',
                'services': ['gerrit', ]}})
            i = sfauth.get_managesf_info('https://auth.tests.dom')
            g.assert_called_with('https://auth.tests.dom/about/',
                                 allow_redirects=False,
                                 verify=True)
            self.assertEqual('managesf',
                             i['service']['name'])
