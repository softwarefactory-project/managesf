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

import argparse
import json
from tempfile import mkstemp

from unittest import TestCase
from mock import patch

from managesf import cli


class FakeResponse(object):
    def __init__(self, status_code=200, text='fake'):
        self.status_code = status_code
        self.text = text


class BaseFunctionalTest(TestCase):
    def setUp(self):
        _, self.temp_path = mkstemp()
        with open(self.temp_path, 'w') as f:
            f.write('dummy data')
        self.parser = argparse.ArgumentParser(description="test")
        cli.default_arguments(self.parser)
        cli.command_options(self.parser)
        self.base_url = "http://tests.dom/"
        self.headers = {'Authorization': 'Basic blipblop'}
        self.default_args = ['--url', self.base_url, '--auth', 'titi:toto',
                             '--auth-server-url', self.base_url]

    def tearDown(self):
        pass


class TestProjectUserAction(BaseFunctionalTest):
    def test_deprecated_syntax(self):
        with patch('managesf.cli.get_cookie') as c:
            c.return_value = 'fake_cookie'
            with patch('requests.get') as g:
                g.return_value = FakeResponse()
                args = self.parser.parse_args(self.default_args +
                                              ['list_active_users'])
                self.assertTrue(cli.project_user_action(args,
                                                        self.base_url,
                                                        self.headers))
            with patch('requests.put') as g:
                g.return_value = FakeResponse()
                args = self.parser.parse_args(self.default_args +
                                              ['add_user', '--name', 'a',
                                               '--user', 'b',
                                               '--groups', 'c'])
                self.assertTrue(cli.project_user_action(args,
                                                        self.base_url,
                                                        self.headers))
            with patch('requests.delete') as g:
                g.return_value = FakeResponse()
                args = self.parser.parse_args(self.default_args +
                                              ['delete_user', '--name', 'a',
                                               '--user', 'b', '--group', 'c'])
                self.assertTrue(cli.project_user_action(args,
                                                        self.base_url,
                                                        self.headers))

    def test_project_add_user(self):
        with patch('managesf.cli.get_cookie') as c:
            c.return_value = 'fake_cookie'
            with patch('requests.put') as g:
                g.return_value = FakeResponse()
                args = self.parser.parse_args(self.default_args +
                                              ['project', 'add_user',
                                               '--name', 'a',
                                               '--user', 'b',
                                               '--groups', 'c'])
                self.assertTrue(cli.project_user_action(args,
                                                        self.base_url,
                                                        self.headers))
                url = self.base_url + '/project/membership/a/b/'
                g.assert_called_with(url,
                                     headers=self.headers,
                                     data=json.dumps({'groups': ['c']}),
                                     cookies={'auth_pubtkt': 'fake_cookie'})
