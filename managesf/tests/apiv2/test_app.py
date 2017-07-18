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

from unittest import TestCase
from webtest import TestApp
from pecan import load_app
from mock import patch

from managesf.tests import dummy_conf


class V2FunctionalTest(TestCase):
    def setUp(self):
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

    def tearDown(self):
        # Remove the sqlite db
        os.unlink(self.config['sqlalchemy']['url'][len('sqlite:///'):])


class TestManageSFV2BuildController(V2FunctionalTest):

    @patch('managesf.controllers.api.v2.builds.manager')
    def test_get_build(self, bm):
        with patch('managesf.controllers.api.v2.base.authorize'):
            environ = {'REMOTE_USER': 'user'}
            retval = {'skipped': 0,
                      'total': 20,
                      'limit': 1,
                      'results': ['yo yo']}
            bm.builds.get.return_value = retval
            response = self.app.get('/v2/builds/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 200)
            self.assertEqual('yo yo', response.json['results'][0])
            uri = '/v2/builds/?started_before=2017-06-29T11:45:32'
            response = self.app.get(uri,
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 200)
            self.assertEqual('yo yo', response.json['results'][0])
            uri = '/v2/builds/?started_after=2017-06-29T11:45:32'
            response = self.app.get(uri,
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 200)
            self.assertEqual('yo yo', response.json['results'][0])

    @patch('managesf.controllers.api.v2.builds.manager')
    def test_get_build_errors(self, bm):
        with patch('managesf.controllers.api.v2.base.authorize'):
            environ = {'REMOTE_USER': 'user'}
            retval = {'skipped': 0,
                      'total': 20,
                      'limit': 1,
                      'results': ['yo yo']}
            bm.builds.get.return_value = retval
            response = self.app.get('/v2/builds/?started_before=wrong',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 400)
            response = self.app.get('/v2/builds/?started_after=wrong',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 400)
            # no results give 404
            retval['total'] = 0
            response = self.app.get('/v2/builds/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 404)
            e = Exception('nope')
            bm.builds.get.side_effect = e
            response = self.app.get('/v2/builds/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 500)
            self.assertEqual('nope',
                             response.json.get('error_description'))

    @patch('managesf.controllers.api.v2.builds.manager')
    def test_get_buildset(self, bm):
        with patch('managesf.controllers.api.v2.base.authorize'):
            environ = {'REMOTE_USER': 'user'}
            retval = {'skipped': 0,
                      'total': 20,
                      'limit': 1,
                      'results': ['yo yo']}
            bm.buildsets.get.return_value = retval
            response = self.app.get('/v2/buildsets/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 200)
            self.assertEqual('yo yo', response.json['results'][0])

    @patch('managesf.controllers.api.v2.builds.manager')
    def test_get_buildset_errors(self, bm):
        with patch('managesf.controllers.api.v2.base.authorize'):
            environ = {'REMOTE_USER': 'user'}
            retval = {'skipped': 0,
                      'total': 0,
                      'limit': 1,
                      'results': []}
            bm.buildsets.get.return_value = retval
            response = self.app.get('/v2/buildsets/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 404)
            e = Exception('nope')
            bm.buildsets.get.side_effect = e
            response = self.app.get('/v2/buildsets/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 500)
            self.assertEqual('nope',
                             response.json.get('error_description'))


class TestManageSFV2JobController(V2FunctionalTest):

    @patch('managesf.controllers.api.v2.jobs.manager')
    def test_get_job(self, jm):
        with patch('managesf.controllers.api.v2.base.authorize'):
            environ = {'REMOTE_USER': 'user'}
            retval = {'skipped': 0,
                      'total': 10,
                      'limit': 1,
                      'results': ['yo yo']}
            jm.jobs.get.return_value = retval
            response = self.app.get('/v2/jobs/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 200, response.text)
            self.assertEqual('yo yo', response.json['results'][0])
            retval['total'] = 0
            response = self.app.get('/v2/jobs/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 404, response.text)


class TestManageSFV2ResourcesController(V2FunctionalTest):

    @patch('managesf.controllers.api.v2.resources.manager')
    def test_get_resources(self, rm):
        with patch('managesf.controllers.api.v2.base.authorize'):
            environ = {'REMOTE_USER': 'user'}
            # not the real format of the answer here but who cares, it's a test
            retval = {'skipped': 0,
                      'total': 10,
                      'limit': 1,
                      'results': ['yo yo']}
            rm.resources.get.return_value = retval
            response = self.app.get('/v2/resources/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 200, response.text)
            self.assertEqual('yo yo', response.json['results'][0])
            # check specific args
            response = self.app.get('/v2/resources/'
                                    '?get_missing_resources=true',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 200, response.text)
            _, kwargs = rm.resources.get.call_args
            self.assertEqual(True,
                             kwargs.get('get_missing_resources'),
                             kwargs)

    @patch('managesf.controllers.api.v2.resources.manager')
    def test_validate_resources(self, rm):
        with patch('managesf.controllers.api.v2.base.authorize'):
            environ = {'REMOTE_USER': 'user'}
            # not the real format of the answer here but who cares, it's a test
            retval = True, 'yo yo'
            rm.resources.create.return_value = retval
            response = self.app.post('/v2/resources/',
                                     extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 200, response.text)
            self.assertEqual('yo yo', response.json)
            retval = False, 'yo yo'
            rm.resources.update.return_value = retval
            response = self.app.put('/v2/resources/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 409, response.text)
            self.assertEqual('yo yo', response.json)
            rm.resources.update.side_effect = ValueError('blop')
            response = self.app.put('/v2/resources/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 400, response.text)
            self.assertEqual('blop', response.json.get('error_description'))

    @patch('managesf.controllers.api.v2.resources.manager')
    def test_apply_resources(self, rm):
        with patch('managesf.controllers.api.v2.base.authorize'):
            environ = {'REMOTE_USER': 'user'}
            # not the real format of the answer here but who cares, it's a test
            retval = True, 'yo yo'
            rm.resources.update.return_value = retval
            response = self.app.put('/v2/resources/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201, response.text)
            self.assertEqual('yo yo', response.json)
            retval = False, 'yo yo'
            rm.resources.update.return_value = retval
            response = self.app.put('/v2/resources/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 409, response.text)
            self.assertEqual('yo yo', response.json)
            rm.resources.update.side_effect = ValueError('blop')
            response = self.app.put('/v2/resources/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 400, response.text)
            self.assertEqual('blop', response.json.get('error_description'))


class TestManageSFV2ACLController(V2FunctionalTest):

    @patch('managesf.controllers.api.v2.resources.manager')
    def test_get_acl(self, rm):
        with patch('managesf.controllers.api.v2.base.authorize'):
            environ = {'REMOTE_USER': 'user'}
            retval = {'skipped': 0,
                      'total': 10,
                      'limit': 1,
                      'results': ['yo yo']}
            rm.acls.get.return_value = retval
            response = self.app.get('/v2/acl/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 200, response.text)
            self.assertEqual('yo yo', response.json['results'][0])
            retval['total'] = 0
            response = self.app.get('/v2/acl/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 404, response.text)


class TestManageSFV2ProjectsController(V2FunctionalTest):

    @patch('managesf.controllers.api.v2.resources.manager')
    def test_get_acl(self, rm):
        with patch('managesf.controllers.api.v2.base.authorize'):
            environ = {'REMOTE_USER': 'user'}
            retval = {'skipped': 0,
                      'total': 10,
                      'limit': 1,
                      'results': ['yo yo']}
            rm.projects.get.return_value = retval
            response = self.app.get('/v2/projects/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 200, response.text)
            self.assertEqual('yo yo', response.json['results'][0])
            retval['total'] = 0
            response = self.app.get('/v2/projects/',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 404, response.text)
