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
                       'zuul': c.zuul,
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


class TestManageSFV2ZuulController(V2FunctionalTest):
    """Test the zuul REST proxy"""
    @patch('requests.get')
    def test_get_unknown_endpoint(self, get):
        """Test that calls to unknown endpoints result in 401 unauthorized"""
        environ = {'REMOTE_USER': 'user'}
        with patch('managesf.controllers.api.v2.base.authorize') as auth:
            auth.return_value = False
            x = self.app.get('/v2/zuul/I/am/a/little/teapot/',
                             extra_environ=environ, status="*")
            self.assertEqual(401, x.status_code, x.body)
            auth.assert_called_with('rule:none', target={})

    @patch('requests.get')
    def test_get_paramaters_are_forwarded(self, get):
        """Make sure that passed parameters get forwarded to zuul"""
        zuul_url = self.config['zuul']['api_root_url']
        with patch('managesf.controllers.api.v2.base.authorize'):
            environ = {'REMOTE_USER': 'user'}
            self.app.get('/v2/zuul/XXX/jobs.json?job_name=my_cool_job',
                         extra_environ=environ, status="*")
            get.assert_called_with(zuul_url + 'XXX/jobs.json',
                                   params={'job_name': 'my_cool_job'})

    @patch('requests.get')
    def test_get_is_redirected(self, get):
        """Test that calls to zuul are correctly redirected, authorized"""
        zuul_url = self.config['zuul']['api_root_url']
        with patch('managesf.controllers.api.v2.base.authorize') as auth:
            environ = {'REMOTE_USER': 'user'}
            self.app.get('/v2/zuul/tenants.json',
                         extra_environ=environ, status="*")
            auth.assert_called_with('zuul.tenants:get',
                                    target={})
            get.assert_called_with(zuul_url + 'tenants.json')
        with patch('managesf.controllers.api.v2.base.authorize') as auth:
            environ = {'REMOTE_USER': 'user'}
            self.app.get('/v2/zuul/tenants',
                         extra_environ=environ, status="*")
            auth.assert_called_with('zuul.tenants:get',
                                    target={})
            get.assert_called_with(zuul_url + 'tenants')
        with patch('managesf.controllers.api.v2.base.authorize') as auth:
            environ = {'REMOTE_USER': 'user'}
            self.app.get('/v2/zuul/a_tenant/status.json',
                         extra_environ=environ, status="*")
            auth.assert_called_with('zuul.tenant.status:get',
                                    target={'tenant': 'a_tenant'})
            get.assert_called_with(zuul_url + 'a_tenant/status.json')
        with patch('managesf.controllers.api.v2.base.authorize') as auth:
            environ = {'REMOTE_USER': 'user'}
            self.app.get('/v2/zuul/a_tenant/status',
                         extra_environ=environ, status="*")
            auth.assert_called_with('zuul.tenant.status:get',
                                    target={'tenant': 'a_tenant'})
            get.assert_called_with(zuul_url + 'a_tenant/status')
        with patch('managesf.controllers.api.v2.base.authorize') as auth:
            environ = {'REMOTE_USER': 'user'}
            self.app.get('/v2/zuul/a_tenant/jobs.json',
                         extra_environ=environ, status="*")
            auth.assert_called_with('zuul.tenant.jobs:get',
                                    target={'tenant': 'a_tenant'})
            get.assert_called_with(zuul_url + 'a_tenant/jobs.json')
        with patch('managesf.controllers.api.v2.base.authorize') as auth:
            environ = {'REMOTE_USER': 'user'}
            self.app.get('/v2/zuul/a_tenant/jobs',
                         extra_environ=environ, status="*")
            auth.assert_called_with('zuul.tenant.jobs:get',
                                    target={'tenant': 'a_tenant'})
            get.assert_called_with(zuul_url + 'a_tenant/jobs')
        with patch('managesf.controllers.api.v2.base.authorize') as auth:
            environ = {'REMOTE_USER': 'user'}
            self.app.get('/v2/zuul/a_tenant/builds.json',
                         extra_environ=environ, status="*")
            auth.assert_called_with('zuul.tenant.builds:get',
                                    target={'tenant': 'a_tenant'})
            get.assert_called_with(zuul_url + 'a_tenant/builds.json')
        with patch('managesf.controllers.api.v2.base.authorize') as auth:
            environ = {'REMOTE_USER': 'user'}
            self.app.get('/v2/zuul/a_tenant/builds',
                         extra_environ=environ, status="*")
            auth.assert_called_with('zuul.tenant.builds:get',
                                    target={'tenant': 'a_tenant'})
            get.assert_called_with(zuul_url + 'a_tenant/builds')
        with patch('managesf.controllers.api.v2.base.authorize') as auth:
            environ = {'REMOTE_USER': 'user'}
            self.app.get('/v2/zuul/another_tenant/console-stream',
                         extra_environ=environ, status="*")
            auth.assert_called_with('zuul.tenant.console-stream:get',
                                    target={'tenant': 'another_tenant'})
            get.assert_called_with(zuul_url + 'another_tenant/console-stream')
        with patch('managesf.controllers.api.v2.base.authorize') as auth:
            environ = {'REMOTE_USER': 'user'}
            self.app.get('/v2/zuul/status',
                         extra_environ=environ, status="*")
            auth.assert_called_with('zuul.status:get',
                                    target={})
            get.assert_called_with(zuul_url + 'status')
        with patch('managesf.controllers.api.v2.base.authorize') as auth:
            environ = {'REMOTE_USER': 'user'}
            self.app.get('/v2/zuul/status.json',
                         extra_environ=environ, status="*")
            auth.assert_called_with('zuul.status:get',
                                    target={})
            get.assert_called_with(zuul_url + 'status.json')
        with patch('managesf.controllers.api.v2.base.authorize') as auth:
            environ = {'REMOTE_USER': 'user'}
            self.app.get('/v2/zuul/status/change/123,3',
                         extra_environ=environ, status="*")
            auth.assert_called_with('zuul.status.change:get',
                                    target={'change': '123',
                                            'revision': '3'})
            get.assert_called_with(zuul_url + 'status/change/123,3')
        with patch('managesf.controllers.api.v2.base.authorize') as auth:
            environ = {'REMOTE_USER': 'user'}
            self.app.get('/v2/zuul/keys/gerrit/sex-bobomb.pub',
                         extra_environ=environ, status="*")
            auth.assert_called_with('zuul.project.public_key:get',
                                    target={'source': 'gerrit',
                                            'repository': 'sex-bobomb'})
            get.assert_called_with(zuul_url + 'keys/gerrit/sex-bobomb.pub')
