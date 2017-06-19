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

import os
import shutil

from unittest import TestCase
from webtest import TestApp
from pecan import load_app
from mock import patch

from managesf.tests import dummy_conf


class V2FunctionalTest(TestCase):
    def setUp(self):
        self.to_delete = []
        c = dummy_conf()
        self.config = {'services': c.services,
                       'gerrit': c.gerrit,
                       'app': c.app,
                       'admin': c.admin,
                       'sqlalchemy': c.sqlalchemy,
                       'auth': c.auth,
                       'htpasswd': c.htpasswd,
                       'managesf': c.managesf,
                       'storyboard': c.storyboard,
                       'mysql': c.mysql,
                       'policy': c.policy,
                       'resources': c.resources,
                       'jenkins': c.jenkins,
                       'nodepool': c.nodepool,
                       'api': c.api, }
        # App must be loaded before we can import v2 managers
        self.app = TestApp(load_app(self.config))

        from managesf.controllers.api.v2 import builds as v2_builds
        self.api_managers = {'builds': v2_builds.manager,
                             }

    def tearDown(self):
        # Remove the sqlite db
        os.unlink(self.config['sqlalchemy']['url'][len('sqlite:///'):])
        for path in self.to_delete:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.unlink(path)


class TestManageSFV2BuildController(V2FunctionalTest):

    def test_get_build(self):
        with patch('managesf.controllers.api.v2.base.authorize'):
            environ = {'REMOTE_USER': 'user'}
            self.api_managers['builds'].builds.get.return_value = 'yo yo'
            response = self.app.get('/api/v2/builds/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 200)
            self.assertEqual('yo yo', response.json)

    def test_get_build_errors(self):
        with patch('managesf.controllers.api.v2.base.authorize'):
            environ = {'REMOTE_USER': 'user'}
            self.api_managers['builds'].builds.get.return_value = 'yo yo'
            response = self.app.get('/api/v2/builds/?started_before=wrong',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 400)
            response = self.app.get('/api/v2/builds/?started_after=wrong',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 400)
            e = Exception('nope')
            self.api_managers['builds'].builds.get.side_effect = e
            response = self.app.get('/api/v2/builds/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 500)
            self.assertEqual('nope',
                             response.json.get('error_description'))

    def test_get_buildset(self):
        with patch('managesf.controllers.api.v2.base.authorize'):
            environ = {'REMOTE_USER': 'user'}
            self.api_managers['builds'].buildsets.get.return_value = 'yo yo'
            response = self.app.get('/api/v2/buildsets/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 200)
            self.assertEqual('yo yo', response.json)

    def test_get_buildset_errors(self):
        with patch('managesf.controllers.api.v2.base.authorize'):
            environ = {'REMOTE_USER': 'user'}
            e = Exception('nope')
            self.api_managers['builds'].buildsets.get.side_effect = e
            response = self.app.get('/api/v2/buildsets/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 500)
            self.assertEqual('nope',
                             response.json.get('error_description'))
