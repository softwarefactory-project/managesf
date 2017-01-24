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
import json
import shutil
import base64
import tempfile
# from StringIO import StringIO
# import time
# import random

from unittest import TestCase
from webtest import TestApp
from pecan import load_app
from mock import patch, MagicMock

from basicauth import encode
from redmine.exceptions import ValidationError

from pysflib.sfredmine import RedmineUtils
from managesf.tests import dummy_conf

from managesf.services import exceptions as exc

from managesf.controllers.SFuser import SFUserManager

# plugins imports
# TODO: should be done dynamically depending on what plugins we want

from managesf.services.gerrit import project
from managesf.services.gerrit import utils
from managesf.services.gerrit.membership import SFGerritMembershipManager
from managesf.services.gerrit.project import SFGerritProjectManager
from managesf.services.gerrit.review import SFGerritReviewManager
from managesf.services.gerrit.group import SFGerritGroupManager
from managesf.services.gerrit.role import SFGerritRoleManager
from managesf.services.gerrit import user as g_user
from managesf.services.redmine import SoftwareFactoryRedmine
from managesf.services.redmine.membership import SFRedmineMembershipManager
from managesf.services.redmine.project import SFRedmineProjectManager
from managesf.services.redmine.user import SFRedmineUserManager
from managesf.services.storyboard.user import StoryboardUserManager
from managesf.services.redmine.group import RedmineGroupManager
from managesf.services.jenkins.job import SFJenkinsJobManager
from managesf.services.nodepool.node import SFNodepoolNodeManager as SFNNM
from managesf.services.nodepool.image import SFNodepoolImageManager as SFNIM

from managesf.tests import resources_test_utils as rtu
from managesf.model.yamlbkd.resources.dummy import Dummy


FIND_PROJECT_PATH = 'managesf.controllers.root.ProjectController._find_project'


def raiseexc(*args, **kwargs):
    raise Exception('FakeExcMsg')


class FunctionalTest(TestCase):
    def setUp(self):
        self.to_delete = []
        c = dummy_conf()
        self.config = {'services': c.services,
                       'gerrit': c.gerrit,
                       'redmine': c.redmine,
                       'app': c.app,
                       'admin': c.admin,
                       'sqlalchemy': c.sqlalchemy,
                       'auth': c.auth,
                       'htpasswd': c.htpasswd,
                       'managesf': c.managesf,
                       'storyboard': c.storyboard,
                       'mysql': c.mysql,
                       'pages': c.pages,
                       'policy': c.policy,
                       'resources': c.resources,
                       'jenkins': c.jenkins,
                       'nodepool': c.nodepool, }
        # deactivate loggin that polute test output
        # even nologcapture option of nose effetcs
        # 'logging': c.logging}
        self.app = TestApp(load_app(self.config))

    def tearDown(self):
        # Remove the sqlite db
        os.unlink(self.config['sqlalchemy']['url'][len('sqlite:///'):])
        for path in self.to_delete:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.unlink(path)


class TestManageSFIntrospectionController(FunctionalTest):

    def test_instrospection(self):
        response = self.app.get('/about/').json
        self.assertEqual('managesf',
                         response['service']['name'])
        self.assertEqual(set(self.config['services']),
                         set(response['service']['services']))


class TestManageSFAppLocaluserController(FunctionalTest):

    def test_add_or_update_user(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            gug.return_value = []
            environ = {'REMOTE_USER': 'admin'}
            infos = {'email': 'john@tests.dom', 'sshkey': 'sshkey',
                     'fullname': 'John Doe', 'password': 'secret'}
            response = self.app.post_json('/user/john', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)
            infos = {'email': 'john2@tests.dom', 'sshkey': 'sshkey',
                     'fullname': 'John Doe', 'password': 'bigsecret'}
            response = self.app.post_json('/user/john', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 200)
            infos = {'wrongkey': 'heyhey'}
            response = self.app.post_json('/user/john', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 400)

            # Only admin can add user to that database
            environ = {'REMOTE_USER': 'boss'}
            infos = {'email': 'john2@tests.dom', 'sshkey': 'sshkey',
                     'fullname': 'John Doe 2', 'password': 'secret'}
            response = self.app.post_json('/user/john2', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 401)

            # john can update his own data
            environ = {'REMOTE_USER': 'john'}
            infos = {'email': 'otherjohn@tests.dom', 'sshkey': 'sshkey',
                     'fullname': 'other john', 'password': 'secret'}
            response = self.app.post_json('/user/john', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 200)
            response = self.app.get('/user/john',
                                    extra_environ=environ, status="*")
            expected = {u'sshkey': u'sshkey',
                        u'username': u'john',
                        u'email': u'otherjohn@tests.dom',
                        u'fullname': u'other john'}
            self.assertEqual(response.status_int, 200)
            self.assertDictEqual(response.json, expected)

            # but jack cannot update john's data
            environ = {'REMOTE_USER': 'jack'}
            infos = {'email': 'jack@tests.dom', 'sshkey': 'sshkey',
                     'fullname': 'handsome jack', 'password': 'secret'}
            response = self.app.post_json('/user/john', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 401)
            # jack can read it though
            response = self.app.get('/user/john',
                                    extra_environ=environ, status="*")
            expected = {u'sshkey': u'sshkey',
                        u'username': u'john',
                        u'email': u'otherjohn@tests.dom',
                        u'fullname': u'other john'}
            self.assertEqual(response.status_int, 200)
            self.assertDictEqual(response.json, expected)

    def test_get_user(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            gug.return_value = []
            environ = {'REMOTE_USER': 'admin'}
            infos = {'email': 'john@tests.dom', 'sshkey': 'sshkey',
                     'fullname': 'John Doe', 'password': 'secret'}
            response = self.app.post_json('/user/john', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)

            response = self.app.get('/user/john',
                                    extra_environ=environ, status="*")
            expected = {u'sshkey': u'sshkey',
                        u'username': u'john',
                        u'email': u'john@tests.dom',
                        u'fullname': u'John Doe'}
            self.assertEqual(response.status_int, 200)
            self.assertDictEqual(response.json, expected)

            response = self.app.get('/user/notexists',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 404)

            environ = {'REMOTE_USER': 'john'}
            response = self.app.get('/user/john',
                                    extra_environ=environ, status="*")
            expected = {u'sshkey': u'sshkey',
                        u'username': u'john',
                        u'email': u'john@tests.dom',
                        u'fullname': u'John Doe'}
            self.assertEqual(response.status_int, 200)
            self.assertDictEqual(response.json, expected)

            environ = {'REMOTE_USER': 'boss'}
            response = self.app.get('/user/john',
                                    extra_environ=environ, status="*")
            expected = {u'sshkey': u'sshkey',
                        u'username': u'john',
                        u'email': u'john@tests.dom',
                        u'fullname': u'John Doe'}
            self.assertEqual(response.status_int, 200)
            self.assertDictEqual(response.json, expected)

    def test_delete_user(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            gug.return_value = []
            environ = {'REMOTE_USER': 'admin'}
            infos = {'email': 'john@tests.dom', 'sshkey': 'sshkey',
                     'fullname': 'John Doe', 'password': 'secret'}
            response = self.app.post_json('/user/john', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)

            environ = {'REMOTE_USER': 'boss'}
            response = self.app.delete('/user/john',
                                       extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 401)

            environ = {'REMOTE_USER': 'admin'}
            response = self.app.delete('/user/john',
                                       extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 200)
            response = self.app.get('/user/john',
                                    extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 404)

    def test_bind_user(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            gug.return_value = []
            environ = {'REMOTE_USER': 'admin'}
            base_infos = {'email': 'john@tests.dom', 'sshkey': 'sshkey',
                          'fullname': 'John Doe', }
            infos = {'password': 'secret'}
            public_infos = {'username': 'john'}
            infos.update(base_infos)
            public_infos.update(base_infos)
            response = self.app.post_json('/user/john', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)

            headers = {"Authorization": encode("john", "secret")}
            response = self.app.get('/bind', headers=headers,
                                    status="*")
            self.assertEqual(response.status_int, 200)
            self.assertEqual(public_infos,
                             response.json,
                             response.json)

            headers = {"Authorization": encode("john", "badsecret")}
            response = self.app.get('/bind', headers=headers,
                                    status="*")
            self.assertEqual(response.status_int, 401)

            headers = {"Authorization": encode("boss", "secret")}
            response = self.app.get('/bind', headers=headers,
                                    status="*")
            self.assertEqual(response.status_int, 401)


def project_get(*args, **kwargs):
    if kwargs.get('by_user'):
        return ['p1', ]
    return ['p0', 'p1']


class TestManageSFAppProjectController(FunctionalTest):

    def test_config(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            # Test that the guest has no permissions
            response = self.app.get('/config/', status="*")
            self.assertEqual(401, response.status_int)
            environ = {'REMOTE_USER': 'just_someone'}
            response = self.app.get('/config/', extra_environ=environ)
            self.assertEqual(False, response.json['create_projects'])
            # Test with an admin user
            environ = {'REMOTE_USER': 'admin'}
            response = self.app.get('/config/', extra_environ=environ)
            self.assertEqual(True, response.json['create_projects'])

    def test_project_get_all(self):
        with patch.object(SFGerritProjectManager, 'get') as p_get,  \
                patch.object(SFGerritReviewManager, 'get') as r_get, \
                patch.object(SFGerritProjectManager,
                             'get_user_groups') as get_user_groups, \
                patch.object(SFGerritProjectManager,
                             'get_projects_groups_id') \
                as get_projects_groups_id, \
                patch.object(SFGerritProjectManager,
                             'get_groups_details') as get_groups_details, \
                patch.object(SoftwareFactoryRedmine, 'get_open_issues') as goi:
            p_get.side_effect = project_get
            r_get.return_value = [{'project': 'p0'}, ]
            get_user_groups.return_value = [{'id': 1, 'name': 'p0-ptl'},
                                            {'id': 3, 'name': 'p2-ptl'}]
            get_groups_details.return_value = {'p0-ptl': {'id': 1,
                                                          'members': ['u1']}}
            get_projects_groups_id.return_value = {'p0': {'others': [],
                                                          'owners': [1]},
                                                   'p1': {'others': [],
                                                          'owners': [2]}}
            goi.return_value = {'issues': [{'project': {'name': 'p0'}}]}
            # Cookie is only required for the internal cache
            response = self.app.set_cookie('auth_pubtkt', 'something')
            response = self.app.get('/project/')
            self.assertEqual(200, response.status_int)
            body = json.loads(response.body)
            expected = {u'p0': {u'open_issues': 1,
                                u'open_reviews': 1,
                                u'admin': 1,
                                u'groups': {u'ptl': {u'members': [u'u1'],
                                                     u'id': 1}}},
                        u'p1': {u'open_issues': 0,
                                u'open_reviews': 0,
                                u'admin': 0,
                                u'groups': {}}
                        }
            self.assertDictEqual(body, expected)
            for _mock in (p_get, r_get, get_user_groups,
                          get_projects_groups_id,
                          get_groups_details, goi):
                self.assertTrue(_mock.called)

            # Second request, will be cached - no internal calls
            for _mock in (p_get, r_get, get_user_groups,
                          get_projects_groups_id,
                          get_groups_details, goi):
                _mock.reset_mock()
            response = self.app.get('/project/')
            # get_user_groups is called by the policy engine
            for _mock in (p_get, r_get,
                          get_projects_groups_id,
                          get_groups_details, goi):
                self.assertFalse(_mock.called)
            self.assertEqual(200, response.status_int)

    def test_project_get_one(self):
        with patch.object(SFGerritProjectManager, 'get') as p_get, \
                patch.object(SFGerritReviewManager, 'get') as r_get, \
                patch.object(SFGerritProjectManager,
                             'get_user_groups') as get_user_groups, \
                patch.object(SFGerritProjectManager,
                             'get_projects_groups_id') \
                as get_projects_groups_id, \
                patch.object(SFGerritProjectManager,
                             'get_groups_details') as get_groups_details, \
                patch.object(SoftwareFactoryRedmine,
                             'get_open_issues') as goi:
            p_get.side_effect = project_get
            r_get.return_value = [{'project': 'p0'}, ]
            get_user_groups.return_value = [{'id': 1, 'name': 'p0-ptl'}]
            get_groups_details.return_value = {'p0-ptl': {'id': 1,
                                                          'members': ['u1']}}
            get_projects_groups_id.return_value = {'p0': {'others': [],
                                                          'owners': [1]},
                                                   'p1': {'others': [],
                                                          'owners': [2]}}
            goi.return_value = {'issues': [{'project': {'name': 'p0'}}]}
            response = self.app.set_cookie('auth_pubtkt', 'something')
            name = '===' + base64.urlsafe_b64encode('p0')
            response = self.app.get('/project/%s/' % name)
        self.assertEqual(200, response.status_int)
        expected = {u'open_issues': 1, u'open_reviews': 1,
                    u'groups': {u'ptl': {u'id': 1,
                                         u'members': [u'u1']}},
                    u'admin': 1}
        self.assertDictEqual(response.json, expected)

    def test_project_put(self):
        # Create a project with no name
        with patch('managesf.controllers.root.authorize') as authorize:
            response = self.app.put('/project/', status="*")
            self.assertEqual(response.status_int, 500)
        # Create a project with name, but without administrator status
        with patch('managesf.controllers.root.authorize') as authorize:
            authorize.return_value = False
            response = self.app.put('/project/p1', status="*")
            self.assertEqual(response.status_int, 401)
        # Create a project with name
        with patch.object(project.SFGerritProjectManager, 'create') as gip, \
                patch.object(project.SFGerritProjectManager,
                             'get_user_groups') as gug, \
                patch.object(SFRedmineProjectManager, 'create') as rip, \
                patch(FIND_PROJECT_PATH) as pfn:
            gug.return_value = []
            pfn.return_value = {}
            response = self.app.put('/project/p1', status="*",
                                    extra_environ={'REMOTE_USER': 'admin'})
            self.assertTupleEqual(('p1', 'admin', {}), gip.mock_calls[0][1])
            self.assertTupleEqual(('p1', 'admin', {}), rip.mock_calls[0][1])
            self.assertEqual(response.status_int, 201)
            self.assertEqual(json.loads(response.body),
                             'Project p1 has been created.')
        # Create a project with name - an error occurs
        with patch.object(project.SFGerritProjectManager, 'create') as gip, \
                patch.object(project.SFGerritProjectManager,
                             'get_user_groups'), \
                patch.object(SFRedmineProjectManager, 'create',
                             side_effect=raiseexc) as rip, \
                patch(FIND_PROJECT_PATH) as fpn:
            gug.return_value = []
            fpn.return_value = {}
            response = self.app.put('/project/p1', status="*",
                                    extra_environ={'REMOTE_USER': 'admin'})
            self.assertEqual(response.status_int, 500)
            self.assertEqual(json.loads(response.body),
                             'Unable to process your request, failed '
                             'with unhandled error (server side): FakeExcMsg')

        # Create a project based on an upstream and test early fail
        # if upstream is not reachable
        with patch.object(project.SFGerritProjectManager, 'create') as gip, \
                patch.object(project.SFGerritProjectManager,
                             'get_user_groups'), \
                patch.object(SFRedmineProjectManager, 'create') as rip, \
                patch.object(utils.GerritRepo, 'check_upstream') as cu, \
                patch(FIND_PROJECT_PATH) as pfn:
            pfn.return_value = {}
            gug.return_value = []
            cu.return_value = [False, "fatal: unable to access remote"]
            response = self.app.put_json(
                '/project/p1',
                {'upstream': 'git@github.com/account/repo.git'},
                status="*",
                extra_environ={'REMOTE_USER': 'admin'})
            self.assertEqual(response.status_int, 400)
            self.assertEqual(json.loads(response.body),
                             "fatal: unable to access remote")
            cu.return_value = [True, None]
            response = self.app.put_json(
                '/project/p1',
                {'upstream': 'git@github.com/account/repo.git'},
                status="*",
                extra_environ={'REMOTE_USER': 'admin'})
            self.assertEqual(response.status_int, 201)

        # Create a project with upstream and include all branches
        with patch.object(project.SFGerritProjectManager, 'create') as gip, \
                patch.object(project.SFGerritProjectManager,
                             'get_user_groups'), \
                patch.object(SFRedmineProjectManager, 'create') as rip, \
                patch.object(utils.GerritRepo, 'check_upstream') as cu, \
                patch(FIND_PROJECT_PATH) as pfn:
            pfn.return_value = {}
            cu.return_value = [True, None]
            data = {'upstream': 'git@github.com/account/repo.git',
                    'add-branches': True}
            env = {'REMOTE_USER': 'admin'}
            response = self.app.put_json('/project/prj2',
                                         data,
                                         status='*',
                                         extra_environ=env)
            self.assertEqual(response.status_code, 201)

    def test_project_delete(self):
        # Need to be admin or ptl with default rules
        with patch.object(project.SFGerritProjectManager,
                          'get_user_groups') as gug:
            gug.return_value = []
            response = self.app.delete('/project/whatevs/', status="*",
                                       extra_environ={'REMOTE_USER': 'testy'})
            self.assertEqual(401, response.status_int)
        # Delete a project with no name
        response = self.app.delete('/project/', status="*",
                                   extra_environ={'REMOTE_USER': 'admin'})
        self.assertEqual(response.status_int, 500)
        # Deletion of config project is not possible
        response = self.app.delete('/project/config', status="*",
                                   extra_environ={'REMOTE_USER': 'admin'})
        self.assertEqual(response.status_int, 500)
        # Delete a project with name
        with patch.object(SFGerritProjectManager, 'delete') as gdp, \
                patch.object(SFRedmineProjectManager, 'delete') as rdp, \
                patch(FIND_PROJECT_PATH) as pfn, \
                patch.object(project.SFGerritProjectManager,
                             'get_user_groups') as gug:
            gug.return_value = []
            pfn.return_value = {'name': 'p1'}
            name = '===' + base64.urlsafe_b64encode('p1')
            response = self.app.delete('/project/%s/' % name, status="*",
                                       extra_environ={'REMOTE_USER': 'admin'})
            self.assertTupleEqual(('p1', 'admin'), gdp.mock_calls[0][1])
            self.assertTupleEqual(('p1', 'admin'), rdp.mock_calls[0][1])
            self.assertEqual(response.status_int, 200)
            self.assertEqual(json.loads(response.body),
                             'Project p1 has been deleted.')
        # Delete a project as PTL (default rule)
        with patch.object(SFGerritProjectManager, 'delete') as gdp, \
                patch.object(SFRedmineProjectManager, 'delete') as rdp, \
                patch(FIND_PROJECT_PATH) as pfn, \
                patch.object(project.SFGerritProjectManager,
                             'get_user_groups') as gug:
            gug.return_value = [{'name': 'p1-ptl'}, ]
            pfn.return_value = {'name': 'p1'}
            name = '===' + base64.urlsafe_b64encode('p1')
            response = self.app.delete('/project/%s/' % name, status="*",
                                       extra_environ={'REMOTE_USER': 'bob'})
            self.assertTupleEqual(('p1', 'bob'), gdp.mock_calls[0][1])
            self.assertTupleEqual(('p1', 'bob'), rdp.mock_calls[0][1])
            self.assertEqual(response.status_int, 200)
            self.assertEqual(json.loads(response.body),
                             'Project p1 has been deleted.')
        # Delete a project with name - an error occurs
        with patch.object(SFGerritProjectManager, 'delete'), \
                patch.object(SFRedmineProjectManager, 'delete',
                             side_effect=raiseexc), \
                patch(FIND_PROJECT_PATH) as pfn, \
                patch.object(project.SFGerritProjectManager,
                             'get_user_groups') as gug:
            pfn.return_value = ('p1', None)
            response = self.app.delete('/project/p1', status="*",
                                       extra_environ={'REMOTE_USER': 'admin'})
            self.assertEqual(response.status_int, 500)
            self.assertEqual(json.loads(response.body),
                             'Unable to process your request, failed '
                             'with unhandled error (server side): FakeExcMsg')


class TestManageSFAppBackupController(FunctionalTest):
    def tearDown(self):
        bkp = os.path.join(self.config['managesf']['backup_dir'],
                           'sf_backup.tar.gz')
        if os.path.isfile(bkp):
            os.unlink(bkp)

    def test_backup_get(self):
        bkp = os.path.join(self.config['managesf']['backup_dir'],
                           'sf_backup.tar.gz')
        file(bkp, 'w').write('backup content')
        with patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            gug.return_value = []
            response = self.app.get('/backup', status="*")
            self.assertEqual(response.status_int, 401)
            # TODO policies don't play nice with the test admin user
            environ = {'REMOTE_USER': 'admin'}
            response = self.app.get('/backup',
                                    extra_environ=environ,
                                    status="*")
            self.assertEqual(response.body, 'backup content')
            os.unlink(bkp)
            response = self.app.get('/backup',
                                    extra_environ=environ,
                                    status="*")
            self.assertEqual(response.status_int, 404)

    def test_backup_post(self):
        with patch('managesf.controllers.backup.'
                   'backup_start') as backup_start, \
                patch.object(SFGerritProjectManager,
                             'get_user_groups') as gug:
            gug.return_value = []
            response = self.app.post('/backup', status="*")
            self.assertEqual(response.status_int, 401)
            environ = {'REMOTE_USER': 'admin'}
            response = self.app.post('/backup',
                                     extra_environ=environ,
                                     status="*")
            self.assertEqual(response.status_int, 204)
            self.assertTrue(backup_start.called)


class TestManageSFAppMembershipController(FunctionalTest):
    def test_get_all_users(self):
        environ = {'REMOTE_USER': 'admin'}
        users = [{'email': 'u%i@bip.dom' % x,
                  'ssh_keys': ['ora', 'oraora'],
                  'full_name': 'User %i' % x,
                  'username': 'user%i' % x} for x in range(10)]
        with patch.object(SFRedmineUserManager, 'create') as redmine_create, \
                patch.object(StoryboardUserManager, 'create') as sb_create, \
                patch.object(g_user.SFGerritUserManager,
                             'create') as gerrit_create, \
                patch.object(SFRedmineUserManager, 'get') as r_get, \
                patch.object(StoryboardUserManager, 'get') as s_get, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch.object(SFGerritProjectManager,
                             'get_user_groups') as gug:
            r_get.return_value = None
            s_get.return_value = None
            g_get.return_value = None
            gug.return_value = []
            for x in range(10):
                redmine_create.return_value = x
                gerrit_create.return_value = x
                sb_create.return_value = x
                response = self.app.post_json('/services_users/', users[x],
                                              extra_environ=environ,
                                              status="*")
                self.assertEqual(response.status_int, 201)
            user_list = self.app.get('/project/membership/', status="*")
            try:
                user_list = user_list.json
            except:
                raise Exception(user_list)
            for u in users:
                u_info = [u['username'], u['email'], u['full_name']]
                self.assertTrue(u_info in user_list,
                                '%s not in %s' % (u_info, user_list))

    def test_put_empty_values(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            gug.return_value = []
            environ = {'REMOTE_USER': 'admin'}
            response = self.app.put_json('/project/membership/', {},
                                         status="*",
                                         extra_environ=environ)
            self.assertEqual(response.status_int, 400)
            response = self.app.put_json('/project/p1/membership/', {},
                                         status="*",
                                         extra_environ=environ)
            self.assertEqual(response.status_int, 400)
            response = self.app.put_json('/project/p1/membership/john', {},
                                         status="*",
                                         extra_environ=environ)
            self.assertEqual(response.status_int, 400)

    def test_put(self):
        environ = {'REMOTE_USER': 'totally_not_an_admin'}
        with patch.object(SFRedmineMembershipManager, 'create'), \
                patch.object(SFGerritMembershipManager, 'create'), \
                patch.object(SFUserManager, 'get') as c, \
                patch.object(SFGerritProjectManager,
                             'get_user_groups') as gug:
            c.return_value = {'email': 'john@tests.dom'}
            gug.return_value = [{'name': 'p1-ptl'}, ]
            project_name = '===' + base64.urlsafe_b64encode('p1')
            response = self.app.put_json(
                '/project/%s/membership/john@tests.dom' % project_name,
                {'groups': ['ptl-group', 'core-group']},
                status="*",
                extra_environ=environ)
            self.assertEqual(201, response.status_int,
                             response)
            self.assertEqual(json.loads(response.body),
                             "User john@tests.dom has been added in group(s):"
                             " ptl-group, core-group for project p1")
        with patch.object(SFGerritMembershipManager, 'create',
                          side_effect=raiseexc), \
                patch.object(SFRedmineMembershipManager, 'create'), \
                patch.object(SFUserManager, 'get') as c, \
                patch.object(SFGerritProjectManager,
                             'get_user_groups') as gug:
            c.return_value = {'email': 'john@tests.dom'}
            gug.return_value = [{'name': 'p1-ptl'}, ]
            response = self.app.put_json(
                '/project/p1/membership/john@tests.dom',
                {'groups': ['ptl-group', 'core-group']},
                status="*",
                extra_environ=environ)
            self.assertEqual(response.status_int, 500)
            self.assertEqual(json.loads(response.body),
                             'Unable to process your request, failed '
                             'with unhandled error (server side): FakeExcMsg')

    def test_delete(self):
        def notfound(*args, **kwargs):
            raise exc.GroupNotFoundException

        def err(*args, **kwargs):
            raise Exception

        environ = {'REMOTE_USER': 'just_a_dude'}
        project_name = '===' + base64.urlsafe_b64encode('p1')
        with patch.object(SFGerritGroupManager, 'get') as a, \
                patch.object(SFUserManager, 'get') as b, \
                patch.object(SFGerritProjectManager,
                             'get_user_groups') as gug:
            b.return_value = {}
            a.side_effect = notfound
            gug.return_value = [{'name': 'p1-ptl'}, ]
            response = self.app.delete('/project/%s/membership/john' % (
                                       project_name), status="*",
                                       extra_environ=environ)
            self.assertEqual(response.status_int, 400)
        with patch.object(SFGerritMembershipManager, 'delete'), \
                patch.object(SFRedmineMembershipManager, 'delete'), \
                patch.object(SFUserManager, 'get') as c, \
                patch.object(SFGerritGroupManager, 'get'), \
                patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            c.return_value = {}
            gug.return_value = [{'name': 'p1-ptl'}, ]
            response = self.app.delete(
                '/project/p1/membership/grp1',
                status="*",
                extra_environ=environ)
            self.assertEqual(response.status_int, 200)
            c.return_value = {'email': 'john@tests.dom'}
            response = self.app.delete(
                '/project/p1/membership/john@tests.dom',
                status="*",
                extra_environ=environ)
            self.assertEqual(response.status_int, 200)
            self.assertEqual(json.loads(response.body),
                             "User john@tests.dom has been deleted from all "
                             "groups for project p1.")
            response = self.app.delete(
                '/project/p1/membership/john@tests.dom/core-group',
                status="*",
                extra_environ=environ)
            self.assertEqual(response.status_int, 200)
            self.assertEqual(json.loads(response.body),
                             "User john@tests.dom has been deleted from group "
                             "core-group for project p1.")
        with patch.object(SFGerritMembershipManager,
                          'delete', side_effect=raiseexc), \
                patch.object(SFRedmineMembershipManager,
                             'delete'), \
                patch.object(SFUserManager, 'get') as c, \
                patch.object(SFGerritGroupManager, 'get'), \
                patch.object(SFGerritProjectManager,
                             'get_user_groups') as gug:
            c.return_value = {'email': 'john@tests.dom'}
            gug.return_value = [{'name': 'p1-ptl'}, ]
            response = self.app.delete(
                '/project/p1/membership/john@tests.dom',
                status="*",
                extra_environ=environ)
            self.assertEqual(response.status_int, 500)
            self.assertEqual(json.loads(response.body),
                             'Unable to process your request, failed '
                             'with unhandled error (server side): FakeExcMsg')


class TestGroupController(FunctionalTest):

    def exc1(*args, **kwargs):
        raise exc.CreateGroupException('FakeExcMsg')

    def exc2(*args, **kwargs):
        raise exc.UpdateGroupException('FakeExcMsg')

    def exc23(*args, **kwargs):
        raise exc.GroupNotFoundException('FakeExcMsg')

    def test_create_group(self):
        env = {'REMOTE_USER': 'user1'}
        with patch.object(SFGerritGroupManager, 'create') as sgm, \
                patch.object(RedmineGroupManager, 'create') as rgm, \
                patch.object(SFUserManager, 'get') as sfum, \
                patch.object(SFGerritProjectManager,
                             'get_user_groups') as gug:
            gug.return_value = []
            sfum.return_value = {'email': "user1@sftests.com"}
            resp = self.app.put_json('/group/grp1',
                                     {'description': 'Nice dev team'},
                                     extra_environ=env,
                                     status="*")
            sgm.assert_called_with('grp1', 'user1@sftests.com',
                                   'Nice dev team')
            rgm.assert_called_with('grp1', 'user1@sftests.com',
                                   'Nice dev team')
        self.assertEqual(resp.status_int, 201)
        with patch.object(SFGerritGroupManager, 'create') as sgm, \
                patch.object(RedmineGroupManager, 'create') as rgm, \
                patch.object(SFUserManager, 'get') as sfum, \
                patch.object(SFGerritProjectManager,
                             'get_user_groups') as gug:
            sgm.side_effect = self.exc1
            sfum.return_value = {'email': "user1@sftests.com"}
            gug.return_value = []
            resp = self.app.put_json('/group/grp1',
                                     {'description': 'Nice dev team'},
                                     extra_environ=env,
                                     status="*")
            sgm.assert_called_with('grp1', 'user1@sftests.com',
                                   'Nice dev team')
            rgm.assert_not_called()
        self.assertEqual(resp.status_int, 409)
        with patch.object(SFGerritGroupManager, 'create') as sgm, \
                patch.object(RedmineGroupManager, 'create') as rgm, \
                patch.object(SFUserManager, 'get') as sfum, \
                patch.object(SFGerritProjectManager,
                             'get_user_groups') as gug:
            rgm.side_effect = self.exc1
            sfum.return_value = {'email': "user1@sftests.com"}
            gug.return_value = []
            resp = self.app.put_json('/group/grp1',
                                     {'description': 'Nice dev team'},
                                     extra_environ=env,
                                     status="*")
            sgm.assert_called_with('grp1', 'user1@sftests.com',
                                   'Nice dev team')
            rgm.assert_called_with('grp1', 'user1@sftests.com',
                                   'Nice dev team')
        # We consider other services than Gerrit shouldn't
        # return an error if at least Gerrit changes pass
        self.assertEqual(resp.status_int, 201)

    def test_delete_group(self):
        env = {'REMOTE_USER': 'user1'}
        with patch.object(SFGerritRoleManager, 'delete') as srm, \
                patch.object(RedmineGroupManager, 'delete') as rgm, \
                patch.object(SFGerritGroupManager, 'get') as sgg, \
                patch.object(SFUserManager, 'get') as sfum, \
                patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            sgg.return_value = {'grp1': [{'email': 'user1@sftests.com'}]}
            gug.return_value = [{'name': 'grp2'}, ]
            resp = self.app.delete('/group/grp1',
                                   extra_environ=env,
                                   status="*")
            srm.assert_not_called()
            rgm.assert_not_called()
        # user is not part of the group
        self.assertEqual(resp.status_int, 401)
        with patch.object(SFGerritRoleManager, 'delete') as srm, \
                patch.object(RedmineGroupManager, 'delete') as rgm, \
                patch.object(SFGerritGroupManager, 'get') as sgg, \
                patch.object(SFUserManager, 'get') as sfum, \
                patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            sfum.return_value = {'email': 'user1@sftests.com'}
            sgg.return_value = {'grp1': [{'email': 'user1@sftests.com'}]}
            gug.return_value = [{'name': 'grp1'}, ]
            resp = self.app.delete('/group/grp1',
                                   extra_environ=env,
                                   status="*")
            srm.assert_called_with('grp1')
            rgm.assert_called_with('grp1')
        # user is part of the group so delete is accepted
        self.assertEqual(resp.status_int, 204)

    def test_get_group(self):
        env = {'REMOTE_USER': 'user1'}
        with patch.object(SFGerritProjectManager, 'get_user_groups') as gug, \
                patch.object(SFGerritGroupManager, 'get') as sgg:
            sgg.return_value = {'grp1': [{'email': 'user1@sftests.com'}]}
            gug.return_value = [{'name': 'grp1'}, ]
            resp = self.app.get('/group/grp1',
                                extra_environ=env,
                                status="*")
        self.assertEqual(resp.status_int, 200)
        self.assertDictEqual(resp.json, sgg.return_value)

        with patch.object(SFGerritProjectManager, 'get_user_groups') as gug, \
                patch.object(SFGerritGroupManager, 'get') as sgg:
            sgg.return_value = {'grp1': [{'email': 'user1@sftests.com'}],
                                'grp2': [{'email': 'user2@sftests.com'}]}
            gug.return_value = [{'name': 'grp1'}, {'name': 'grp2'}, ]
            resp = self.app.get('/group/',
                                extra_environ=env,
                                status="*")
        self.assertEqual(resp.status_int, 200)
        self.assertDictEqual(resp.json, sgg.return_value)


class TestManageSFPagesController(FunctionalTest):
    def test_unauthenticated(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            gug.return_value = []
            resp = self.app.get('/pages/p1', status="*")
            self.assertEqual(resp.status_int, 401)

            resp = self.app.post_json('/pages/p1', {}, status="*")
            self.assertEqual(resp.status_int, 401)

            resp = self.app.delete('/pages/p1', status="*")
            self.assertEqual(resp.status_int, 401)

    def test_authenticated(self):
        env = {'REMOTE_USER': 'user1'}
        with patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            gug.return_value = [{'name': 'p2-dev'}, ]
            resp = self.app.post_json('/pages/p1', {'url': 'http://target'},
                                      extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 401)

            # Now user1 is a project PTL
            gug.return_value = [{'name': 'p1-ptl'}, {'name': 'p2-ptl'}, ]
            resp = self.app.post_json('/pages/p1', {'url': 'http://target'},
                                      extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 201)
            resp = self.app.post_json('/pages/p1', {'url': 'http://target'},
                                      extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 200)
            resp = self.app.post_json('/pages/p2', {'url': 'http://target2'},
                                      extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 201)

            # Try to fetch configured target for p1 and p2
            resp = self.app.get('/pages/p1',
                                extra_environ=env, status="*")
            self.assertEqual(resp.json, 'http://target')
            resp = self.app.get('/pages/p2',
                                extra_environ=env, status="*")
            self.assertEqual(resp.json, 'http://target2')
            gug.return_value = [{'name': 'p2-dev'}, ]
            resp = self.app.get('/pages/p1',
                                extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 401)

            # Try to add an invalid target
            gug.return_value = [{'name': 'p3-ptl'}, ]
            resp = self.app.post_json('/pages/p3', {'url': 'invalid'},
                                      extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 400)

            # Try to delete a target
            gug.return_value = [{'name': 'p2-dev'}, ]
            resp = self.app.delete('/pages/p1',
                                   extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 401)
            gug.return_value = [{'name': 'p1-ptl'}, {'name': 'p2-ptl'}, ]
            resp = self.app.delete('/pages/p1',
                                   extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 200)
            resp = self.app.delete('/pages/p2',
                                   extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 200)

            # Try to delete a non existing target
            gug.return_value = [{'name': 'p3-ptl'}, ]
            resp = self.app.delete('/pages/p3',
                                   extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 404)


class TestManageSFHtpasswdController(FunctionalTest):
    def test_unauthenticated(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            resp = self.app.put_json('/htpasswd/', {}, status="*")
            self.assertEqual(resp.status_int, 401)

            resp = self.app.get('/htpasswd/', {}, status="*")
            self.assertEqual(resp.status_int, 401)

            resp = self.app.delete('/htpasswd/', {}, status="*")
            self.assertEqual(resp.status_int, 401)

    def test_authenticated(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            env = {'REMOTE_USER': 'admin'}

            resp = self.app.get('/htpasswd/', extra_environ=env, status="*")
            self.assertEqual(404, resp.status_int)

            resp = self.app.put_json('/htpasswd/', {}, extra_environ=env)
            self.assertEqual(resp.status_int, 201)
            self.assertTrue(len(resp.body) >= 12)

            # Create new password
            old_password = resp.body
            resp = self.app.put_json('/htpasswd/', {}, extra_environ=env)
            self.assertEqual(resp.status_int, 201)
            self.assertTrue(len(resp.body) >= 12)

            self.assertTrue(old_password != resp.body)

            # Create password for a different user
            newenv = {'REMOTE_USER': 'random'}
            resp = self.app.put_json('/htpasswd/', {}, extra_environ=newenv)
            self.assertEqual(resp.status_int, 201)
            self.assertTrue(len(resp.body) >= 12)

            # Ensure there are password entries for both users
            resp = self.app.get('/htpasswd/', extra_environ=env)
            self.assertEqual(204, resp.status_int)
            self.assertEqual(resp.body, 'null')

            resp = self.app.get('/htpasswd/', extra_environ=newenv)
            self.assertEqual(204, resp.status_int)
            self.assertEqual(resp.body, 'null')

            # Delete passwords
            resp = self.app.delete('/htpasswd/', extra_environ=env)
            self.assertEqual(204, resp.status_int)

            resp = self.app.delete('/htpasswd/', extra_environ=newenv)
            self.assertEqual(204, resp.status_int)

            resp = self.app.get('/htpasswd/', extra_environ=env, status="*")
            self.assertEqual(404, resp.status_int)

    def test_missing_htpasswd_file(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            os.remove(self.config['htpasswd']['filename'])
            env = {'REMOTE_USER': 'admin'}

            resp = self.app.put('/htpasswd/', extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 406)

            resp = self.app.get('/htpasswd/', extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 406)

            resp = self.app.delete('/htpasswd/', extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 406)


class TestProjectTestsController(FunctionalTest):
    def test_init_project_test(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            environ = {'REMOTE_USER': 'ptl_for_this_project'}
            gug.return_value = [{'name': 'toto-ptl'}, ]
            with patch.object(SFGerritProjectManager, 'get') as gp, \
                    patch.object(SFGerritReviewManager,
                                 'propose_test_definition'):
                gp.return_value = 'p1'
                resp = self.app.put_json('/tests/toto',
                                         {'project-scripts': False},
                                         extra_environ=environ, status="*")
                self.assertEqual(resp.status_int, 201)

    def test_init_project_test_with_project_scripts(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            environ = {'REMOTE_USER': 'ptl_for_this_project'}
            gug.return_value = [{'name': 'toto-ptl'}, ]
            with patch.object(SFGerritProjectManager, 'get') as gp, \
                    patch.object(SFGerritReviewManager,
                                 'propose_test_definition'), \
                    patch.object(SFGerritReviewManager,
                                 'propose_test_scripts'):
                gp.return_value = 'p1'
                resp = self.app.put_json('/tests/toto',
                                         {'project-scripts': True},
                                         extra_environ=environ, status="*")
                self.assertEqual(resp.status_int, 201)


class TestManageSFServicesUserController(FunctionalTest):

    def test_add_user_in_backends_non_admin(self):
        environ = {'REMOTE_USER': 'dio'}
        infos = {'email': 'jojo@starplatinum.dom',
                 'ssh_keys': ['ora', 'oraora'],
                 'full_name': 'Jotaro Kujoh', 'username': 'jojo'}
        with patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            gug.return_value = []
            response = self.app.post_json('/services_users/', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 401)

    def test_add_user_in_backends(self):
        environ = {'REMOTE_USER': 'admin'}
        rm_user = MagicMock()
        rm_user.id = 9
        sb_user = MagicMock()
        sb_user.id = 10
        gerrit_created = {"_account_id": 5,
                          "name": "Jotaro Kujoh",
                          "email": "jojo@starplatinum.dom",
                          "username": "jojo",
                          "avatars": [{"url": "meh",
                                       "height": 26}]}
        infos = {'email': 'jojo@starplatinum.dom',
                 'ssh_keys': ['ora', 'oraora'],
                 'full_name': 'Jotaro Kujoh', 'username': 'jojo'}
        rm_user2 = MagicMock()
        rm_user2.id = 12
        sb_user2 = MagicMock()
        sb_user2.id = 13
        gerrit2_created = {"_account_id": 8,
                           "name": "Dio Brando",
                           "email": "dio@wryyyyy.dom",
                           "username": "dio-sama",
                           "avatars": [{"url": "meh",
                                        "height": 26}]}
        infos2 = {'email': 'dio@wryyyyy.dom',
                  'ssh_keys': ['ora', 'oraora'],
                  'full_name': 'Dio Brando', 'username': 'dio-sama'}
        infos3 = {'email': 'john@joestar.dom',
                  'ssh_keys': ['ora', 'oraora'],
                  'full_name': 'Jonathan Joestar', 'username': 'Jon'}
        with patch.object(SFRedmineUserManager, 'create') as redmine_create, \
                patch.object(StoryboardUserManager, 'create') as sb_create, \
                patch.object(g_user.SFGerritUserManager,
                             'create') as gerrit_create, \
                patch.object(SFRedmineUserManager, 'get') as r_get, \
                patch.object(StoryboardUserManager, 'get') as s_get, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch.object(SFGerritProjectManager,
                             'get_user_groups'):
            r_get.return_value = None
            s_get.return_value = None
            g_get.return_value = None
            redmine_create.return_value = rm_user.id
            sb_create.return_value = sb_user.id
            gerrit_create.return_value = gerrit_created["_account_id"]
            response = self.app.post_json('/services_users/', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)
            _, redmine_args = redmine_create.call_args
            _, gerrit_args = gerrit_create.call_args
            for k, v in (
                ("username", infos.get('username')),
                ("email", infos.get('email')),
                ("full_name", infos.get('full_name')),
                ("ssh_keys", infos['ssh_keys'])
            ):
                self.assertEqual(redmine_args[k], v)
                self.assertEqual(gerrit_args[k], v)
            self.assertTrue("cauth_id" in redmine_args)
            self.assertTrue("cauth_id" in gerrit_args)
            # TODO(mhu) test if mapping is set correctly
        # mock at a lower level
        with patch('managesf.services.gerrit.get_cookie') as get_cookie, \
                patch.object(RedmineUtils, 'create_user') as rm_create_user, \
                patch.object(StoryboardUserManager, 'create') as s_create, \
                patch.object(g_user.SFGerritUserManager, '_add_sshkeys'), \
                patch.object(g_user.SFGerritUserManager,
                             '_add_account_as_external'), \
                patch('pysflib.sfgerrit.GerritUtils.create_account') \
                as create_account, \
                patch.object(SFRedmineUserManager, 'get') as r_get, \
                patch.object(StoryboardUserManager, 'get') as s_get, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch('pysflib.sfgerrit.GerritUtils.update_account'), \
                patch.object(SFRedmineUserManager, 'update'), \
                patch.object(StoryboardUserManager, 'update'), \
                patch.object(SFGerritProjectManager, 'get_user_groups'):
            get_cookie.return_value = 'admin_cookie'

            rm_create_user.return_value = rm_user2
            s_create.return_value = sb_user2.id
            create_account.return_value = gerrit2_created
            r_get.return_value = None
            s_get.return_value = None
            g_get.return_value = None
            response = self.app.post_json('/services_users/', infos2,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)
            rm_create_user.assert_called_with(infos2['username'],
                                              infos2['email'],
                                              infos2['full_name'])

        with patch.object(SFRedmineUserManager, 'create') as redmine_create, \
                patch.object(StoryboardUserManager, 'create') as sb_create, \
                patch.object(g_user.SFGerritUserManager,
                             'create') as gerrit_create, \
                patch.object(SFRedmineUserManager, 'get') as r_get, \
                patch.object(StoryboardUserManager, 'get') as s_get, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch.object(SFGerritProjectManager,
                             'get_user_groups'):
            # assert that raising UnavailableActionError won't fail
            def unavailable(*args, **kwargs):
                raise exc.UnavailableActionError
            redmine_create.side_effect = unavailable
            r_get.side_effect = unavailable
            s_get.side_effect = unavailable
            g_get.return_value = 14
            gerrit_create.return_value = 14
            response = self.app.post_json('/services_users/', infos3,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)

        with patch('managesf.services.gerrit.get_cookie') as get_cookie, \
                patch.object(RedmineUtils, 'create_user') as rm_create_user, \
                patch.object(StoryboardUserManager, 'create') as s_create, \
                patch.object(g_user.SFGerritUserManager, '_add_sshkeys'), \
                patch.object(g_user.SFGerritUserManager,
                             '_add_account_as_external'), \
                patch('pysflib.sfgerrit.GerritUtils.create_account') \
                as create_account, \
                patch.object(SFRedmineUserManager, 'get') as r_get, \
                patch.object(StoryboardUserManager, 'get') as s_get, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch('pysflib.sfgerrit.GerritUtils.update_account'), \
                patch.object(SFRedmineUserManager, 'update'), \
                patch.object(StoryboardUserManager, 'update'), \
                patch.object(SFGerritProjectManager, 'get_user_groups'):

            get_cookie.return_value = 'admin_cookie'
            # assert that user already existing in backend won't fail

            def already(*args, **kwargs):
                raise ValidationError('Resource already exists')
            r_get.return_value = rm_user.id
            s_get.return_value = sb_user.id
            g_get.return_value = gerrit_created["_account_id"]
            create_account.return_value = gerrit_created
            rm_create_user.side_effect = already
            response = self.app.post_json('/services_users/', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)

        with patch('managesf.services.gerrit.get_cookie') as get_cookie, \
                patch.object(RedmineUtils, 'create_user') as rm_create_user, \
                patch.object(StoryboardUserManager, 'create') as s_create, \
                patch.object(g_user.SFGerritUserManager, '_add_sshkeys'), \
                patch.object(g_user.SFGerritUserManager,
                             '_add_account_as_external'), \
                patch('pysflib.sfgerrit.GerritUtils.create_account') \
                as create_account, \
                patch.object(SFRedmineUserManager, 'get') as r_get, \
                patch.object(StoryboardUserManager, 'get') as s_get, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch('pysflib.sfgerrit.GerritUtils.update_account'), \
                patch.object(SFRedmineUserManager, 'update'), \
                patch.object(StoryboardUserManager, 'update'), \
                patch.object(SFGerritProjectManager, 'get_user_groups'):
            get_cookie.return_value = 'admin_cookie'
            # assert that user found in backend will skip gracefully
            r_get.return_value = rm_user.id
            s_get.return_value = sb_user.id
            g_get.return_value = gerrit_created["_account_id"]
            create_account.return_value = gerrit_created
            response = self.app.post_json('/services_users/', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)

    def test_add_user_in_backends_failures(self):
        environ = {'REMOTE_USER': self.config['admin']['name']}
        infos = {'email': 'jojo@starplatinum.dom',
                 'ssh_keys': ['ora', 'oraora'],
                 'full_name': 'Jotaro Kujoh', 'username': 'jojo'}
        with patch.object(RedmineUtils, 'create_user') as rm_create_user:
            # assert that other errors will fail
            def already(*args, **kwargs):
                raise ValidationError('No idea what I am doing')
            rm_create_user.side_effect = already
            response = self.app.post_json('/services_users/', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 500)
        # forget the username
        infos = {'email': 'jojo@starplatinum.dom',
                 'ssh_keys': ['ora', 'oraora'],
                 'full_name': 'Jotaro Kujoh', }
        with patch.object(RedmineUtils, 'create_user'):
            response = self.app.post_json('/services_users/', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 400)

    def test_delete_user_in_backends_non_admin(self):
        environ = {'REMOTE_USER': 'dio'}
        params = {'username': 'iggy'}
        with patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            gug.return_value = []
            response = self.app.delete('/services_users/', params,
                                       extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 401)

    def test_delete_user_in_backends(self):
        environ = {'REMOTE_USER': 'admin'}
        infos = {'email': 'iggy@stooges.dom',
                 'ssh_keys': ['ora', 'oraora'],
                 'full_name': 'iggy the fool', 'username': 'iggy'}
        with patch.object(SFRedmineUserManager, 'delete') as redmine_delete, \
                patch.object(StoryboardUserManager, 'delete') as sb_delete, \
                patch.object(g_user.SFGerritUserManager,
                             'delete') as gerrit_delete, \
                patch.object(SFRedmineUserManager,
                             'create') as redmine_create, \
                patch.object(StoryboardUserManager,
                             'create') as sb_create, \
                patch.object(g_user.SFGerritUserManager,
                             'create') as gerrit_create, \
                patch.object(SFRedmineUserManager, 'get') as redmine_get, \
                patch.object(StoryboardUserManager, 'get') as sb_get, \
                patch.object(g_user.SFGerritUserManager,
                             'get') as gerrit_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            gug.return_value = []
            # Test deletion of non existing user
            response = self.app.delete('/services_users/?username=iggy',
                                       extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 404)
            # test deletion of existing user
            redmine_create.return_value = 99
            sb_create.return_value = 99
            gerrit_create.return_value = 99
            redmine_get.return_value = None
            sb_get.return_value = None
            gerrit_get.return_value = None
            self.app.post_json('/services_users/', infos,
                               extra_environ=environ, status="*")
            response = self.app.delete('/services_users/?username=iggy',
                                       extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 204)
            redmine_delete.assert_called_with(username='iggy', email=None)
            sb_delete.assert_called_with(username='iggy', email=None)
            gerrit_delete.assert_called_with(username='iggy', email=None)

        with patch.object(SFRedmineUserManager, 'delete') as redmine_delete, \
                patch.object(StoryboardUserManager, 'delete') as sb_delete, \
                patch.object(g_user.SFGerritUserManager,
                             'delete') as gerrit_delete, \
                patch.object(SFRedmineUserManager,
                             'create') as redmine_create, \
                patch.object(StoryboardUserManager,
                             'create') as sb_create, \
                patch.object(g_user.SFGerritUserManager,
                             'create') as gerrit_create, \
                patch.object(SFRedmineUserManager, 'get') as redmine_get, \
                patch.object(StoryboardUserManager, 'get') as sb_get, \
                patch.object(g_user.SFGerritUserManager,
                             'get') as gerrit_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            gug.return_value = []
            redmine_create.return_value = 100
            sb_create.return_value = 100
            gerrit_create.return_value = 100
            redmine_get.return_value = None
            sb_get.return_value = None
            gerrit_get.return_value = None
            self.app.post_json('/services_users/', infos,
                               extra_environ=environ, status="*")
            response = self.app.delete(
                '/services_users/?email=iggy@stooges.dom',
                extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 204)
            redmine_delete.assert_called_with(username=None,
                                              email='iggy@stooges.dom')
            sb_delete.assert_called_with(username=None,
                                         email='iggy@stooges.dom')
            gerrit_delete.assert_called_with(username=None,
                                             email='iggy@stooges.dom')
            # deleted from SF backend too
            iggy = self.app.get('/services_users/?username=iggy',
                                extra_environ=environ, status="*")
            self.assertEqual({}, iggy.json)

    def test_all(self):
        environ = {'REMOTE_USER': 'admin'}
        infos_kira = {'email': 'kira@jojolion.dom',
                      'ssh_keys': ['ora', 'oraora'],
                      'full_name': 'yoshikage kira', 'username': 'kira'}
        with patch.object(SFRedmineUserManager, 'delete'), \
                patch.object(StoryboardUserManager, 'delete'), \
                patch.object(g_user.SFGerritUserManager, 'delete'), \
                patch.object(SFRedmineUserManager, 'create') as r_create, \
                patch.object(StoryboardUserManager, 'create') as s_create, \
                patch.object(g_user.SFGerritUserManager,
                             'create') as g_create, \
                patch.object(SFRedmineUserManager, 'get') as r_get, \
                patch.object(StoryboardUserManager, 'get') as s_get, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups'):

            r_get.return_value = None
            s_get.return_value = None
            g_get.return_value = None
            r_create.return_value = 12
            s_create.return_value = 12
            g_create.return_value = 13
            response = self.app.post_json('/services_users/', infos_kira,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)
            response = self.app.get('/services_users/',
                                    extra_environ=environ, status="*")
            user_list = response.json
            self.assertTrue(len(user_list) >= 1,
                            user_list)
            self.assertTrue(any(x['username'] == 'kira' for x in user_list))

    def test_get_user(self):
        environ = {'REMOTE_USER': 'admin'}
        infos_jojo = {'email': 'jojo@starplatinum.dom',
                      'ssh_keys': ['ora', 'oraora'],
                      'full_name': 'Jotaro Kujoh', 'username': 'jojo'}
        infos_poln = {'email': 'polnareff@chariot.dom',
                      'ssh_keys': ['ora', 'oraora'],
                      'full_name': 'Polnareff', 'username': 'chariot'}
        with patch.object(SFRedmineUserManager, 'delete'), \
                patch.object(StoryboardUserManager, 'delete'), \
                patch.object(g_user.SFGerritUserManager, 'delete'), \
                patch.object(SFRedmineUserManager,
                             'create') as r_create, \
                patch.object(StoryboardUserManager,
                             'create') as s_create, \
                patch.object(g_user.SFGerritUserManager,
                             'create') as g_create, \
                patch.object(SFRedmineUserManager, 'get') as r_get, \
                patch.object(StoryboardUserManager, 'get') as s_get, \
                patch.object(g_user.SFGerritUserManager,
                             'get') as g_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups') as gug:

            r_get.return_value = None
            s_get.return_value = None
            g_get.return_value = None
            r_create.return_value = 12
            s_create.return_value = 12
            g_create.return_value = 13
            gug.return_value = []
            response = self.app.post_json('/services_users/', infos_jojo,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)
            r_create.return_value = 14
            g_create.return_value = 15
            response = self.app.post_json('/services_users/', infos_poln,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)
            # endpoint allowed to all authenticated users
            environ = {'REMOTE_USER': 'dio'}
            jojo = self.app.get('/services_users/?username=jojo',
                                extra_environ=environ, status="*")
            self.assertEqual(200, jojo.status_int)
            self.assertEqual('Jotaro Kujoh', jojo.json.get('fullname'))
            self.assertTrue('id' in jojo.json.keys())
            self.assertEqual('-1', jojo.json.get('cauth_id'))
            jojo = self.app.get('/services_users/?fullname=Jotaro%20Kujoh',
                                extra_environ=environ, status="*")
            self.assertEqual(200, jojo.status_int)
            self.assertEqual('Jotaro Kujoh', jojo.json.get('fullname'))
            self.assertTrue('id' in jojo.json.keys())
            self.assertEqual('-1', jojo.json.get('cauth_id'))
            # no user
            jojo = self.app.get('/services_users/?username=dio',
                                extra_environ=environ, status="*")
            self.assertEqual(200, jojo.status_int)
            self.assertEqual({}, jojo.json)
            # retrieve all users
            jojo = self.app.get('/services_users/',
                                extra_environ=environ, status="*")
            self.assertEqual(200, jojo.status_int)
            self.assertEqual(2, len(jojo.json))
            # update external id
            infos_jojo = {'email': 'jojo@starplatinum.dom',
                          'ssh_keys': ['ora', 'oraora'],
                          'full_name': 'Jotaro Kujoh', 'username': 'jojo',
                          'external_id': 99}
            environ = {'REMOTE_USER': 'admin'}
            response = self.app.post_json('/services_users/', infos_jojo,
                                          extra_environ=environ, status="*")
            jojo = self.app.get('/services_users/?username=jojo',
                                extra_environ=environ, status="*")
            self.assertEqual('99', jojo.json.get('cauth_id'))

    def test_idp_sync(self):
        environ = {'REMOTE_USER': 'admin'}
        infos_jojo = {'email': 'jojo@starplatinum.dom',
                      'ssh_keys': ['ora', 'oraora'],
                      'full_name': 'Jotaro Kujoh', 'username': 'jojo',
                      'external_id': 42}
        with patch.object(SFRedmineUserManager, 'update') as r_up, \
                patch.object(StoryboardUserManager, 'update') as s_up, \
                patch.object(g_user.SFGerritUserManager, 'update') as g_up, \
                patch.object(SFRedmineUserManager,
                             'create') as r_create, \
                patch.object(StoryboardUserManager,
                             'create') as s_create, \
                patch.object(g_user.SFGerritUserManager,
                             'create') as g_create, \
                patch.object(SFRedmineUserManager, 'get') as r_get, \
                patch.object(StoryboardUserManager, 'get') as s_get, \
                patch.object(g_user.SFGerritUserManager,
                             'get') as g_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups'):
            for mock in (r_up, s_up, g_up, r_get, s_get, g_get):
                mock.return_value = None
            r_create.return_value = 12
            s_create.return_value = 12
            g_create.return_value = 13

            # User logs in
            response = self.app.post_json('/services_users/', infos_jojo,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)

            # User disable idp_sync
            disable_idp = {'idp_sync': False}
            user_cred = {'REMOTE_USER': 'jojo'}
            response = self.app.put_json('/services_users/?username=jojo',
                                         disable_idp, extra_environ=user_cred,
                                         status="*")
            self.assertEqual(response.status_int, 200)

            # User change its mail on idp and logs in again
            infos_jojo['email'] = 'jojo@galactica.com'
            response = self.app.post_json('/services_users/', infos_jojo,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)

            # Check user mail didn't change because idp_sync is False
            response = self.app.get('/services_users/?username=jojo',
                                    extra_environ=environ, status="*")
            self.assertNotEqual(response.json['email'], infos_jojo['email'])

    def test_update_user(self):
        environ = {'REMOTE_USER': 'admin'}
        infos_jojo = {'email': 'jojo@starplatinum.dom',
                      'ssh_keys': ['ora', 'oraora'],
                      'full_name': 'Jotaro Kujoh', 'username': 'jojo'}
        with patch.object(StoryboardUserManager, 'create') as s_create, \
                patch.object(StoryboardUserManager, 'update') as s_update, \
                patch.object(StoryboardUserManager, 'get') as s_get, \
                patch.object(SFRedmineUserManager, 'create') as r_create, \
                patch.object(SFRedmineUserManager, 'update') as r_update, \
                patch.object(SFRedmineUserManager, 'get') as r_get, \
                patch.object(g_user.SFGerritUserManager,
                             'create') as g_create, \
                patch.object(g_user.SFGerritUserManager,
                             'update') as g_update, \
                patch.object(g_user.SFGerritUserManager,
                             'get') as g_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups') as gug:

            gug.return_value = []
            for mock in (r_get, r_update, s_get, s_update, g_get, g_update):
                mock.return_value = None
            r_create.return_value = 12
            s_create.return_value = 12
            g_create.return_value = 13
            response = self.app.post_json('/services_users/', infos_jojo,
                                          extra_environ=environ, status="*")
            response = self.app.get('/services_users/?username=jojo',
                                    extra_environ=environ, status="*")
            jojo_id = response.json.get('id')
            # try to update as someone else
            environ = {'REMOTE_USER': 'dio'}
            payload = {'full_name': 'Dio Brando'}
            resp = self.app.put_json('/services_users/?username=jojo',
                                     payload,
                                     extra_environ=environ, status="*")
            self.assertEqual(401, resp.status_int)
            resp = self.app.put_json(
                '/services_users/?email=jojo@starplatinum.dom',
                payload, extra_environ=environ, status="*")
            self.assertEqual(401, resp.status_int)
            resp = self.app.put_json(
                '/services_users/?id=%s' % jojo_id,
                payload, extra_environ=environ, status="*")
            self.assertEqual(401, resp.status_int)
            # try wrong payload
            for i in ('admin', infos_jojo['username']):
                environ = {'REMOTE_USER': i}
                payload = {'username': 'dio'}
                resp = self.app.put_json('/services_users/?username=jojo',
                                         payload,
                                         extra_environ=environ, status="*")
                self.assertEqual(400, resp.status_int)
                self.assertTrue('You tried to update immutable fields' in
                                resp.body)
                resp = self.app.put_json(
                    '/services_users/?email=jojo@starplatinum.dom',
                    payload, extra_environ=environ, status="*")
                self.assertEqual(400, resp.status_int)
                self.assertTrue('You tried to update immutable fields' in
                                resp.body)
                resp = self.app.put_json(
                    '/services_users/?id=%s' % jojo_id,
                    payload, extra_environ=environ, status="*")
                self.assertEqual(400, resp.status_int)
                self.assertTrue('You tried to update immutable fields' in
                                resp.body)
            # try empty payload
            for i in ('admin', infos_jojo['username']):
                environ = {'REMOTE_USER': i}
                payload = {}
                resp = self.app.put_json('/services_users/?username=jojo',
                                         payload,
                                         extra_environ=environ, status="*")
                self.assertEqual(400, resp.status_int)
                self.assertTrue('Nothing to do' in resp.body)
                resp = self.app.put_json(
                    '/services_users/?email=jojo@starplatinum.dom',
                    payload, extra_environ=environ, status="*")
                self.assertEqual(400, resp.status_int)
                self.assertTrue('Nothing to do' in resp.body)
                resp = self.app.put_json(
                    '/services_users/?id=%s' % jojo_id,
                    payload, extra_environ=environ, status="*")
                self.assertEqual(400, resp.status_int)
                self.assertTrue('Nothing to do' in resp.body)
            # try doing it right
            c = 0
            for i in ('admin', infos_jojo['username']):
                environ = {'REMOTE_USER': i}
                payload = {'full_name': '%i' % c}
                resp = self.app.put_json('/services_users/?username=jojo',
                                         payload,
                                         extra_environ=environ, status="*")
                self.assertEqual(200, resp.status_int)
                self.assertEqual({'updated_fields': payload},
                                 resp.json)
                response = self.app.get('/services_users/?username=jojo',
                                        extra_environ=environ, status="*")
                self.assertEqual(payload['full_name'],
                                 response.json.get('fullname'))
                c += 1
                payload = {'full_name': '%i' % c}
                resp = self.app.put_json(
                    '/services_users/?email=jojo@starplatinum.dom',
                    payload, extra_environ=environ, status="*")
                self.assertEqual(200, resp.status_int)
                self.assertEqual({'updated_fields': payload},
                                 resp.json)
                response = self.app.get('/services_users/?username=jojo',
                                        extra_environ=environ, status="*")
                self.assertEqual(payload['full_name'],
                                 response.json.get('fullname'))
                c += 1
                payload = {'full_name': '%i' % c}
                resp = self.app.put_json(
                    '/services_users/?id=%s' % jojo_id,
                    payload, extra_environ=environ, status="*")
                self.assertEqual(200, resp.status_int)
                self.assertEqual({'updated_fields': payload},
                                 resp.json)
                response = self.app.get('/services_users/?username=jojo',
                                        extra_environ=environ, status="*")
                self.assertEqual(payload['full_name'],
                                 response.json.get('fullname'))
                c += 1


class TestHooksController(FunctionalTest):
    def test_non_existing_hook(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            environ = {'REMOTE_USER': 'SF_SERVICE_USER'}
            resp = self.app.post_json('/hooks/toto', {'arg1': 1, 'arg2': 2},
                                      extra_environ=environ, status="*")
            self.assertEqual(400, resp.status_int)

    def test_patchset_created(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'), \
                patch('managesf.model.yamlbkd.engine.'
                      'SFResourceBackendEngine.get') as r:
            r.return_value = {'resources': {}}
            environ = {'REMOTE_USER': 'SF_SERVICE_USER'}
            hooks_kwargs = {'change': 123,
                            'is_draft': False,
                            'change_url': 'blop',
                            'project': 'testytest',
                            'branch': 'branchy',
                            'topic': 'thunder',
                            'uploader': 'Doe',
                            'commit': 456,
                            'patchset': 1,
                            'commit_message': 'fix the thing Closes: #789'}
            with patch.object(RedmineUtils,
                              'set_issue_status') as set_issue_status:
                set_issue_status.return_value = True
                resp = self.app.post_json('/hooks/patchset_created',
                                          hooks_kwargs,
                                          extra_environ=environ, status="*")
                self.assertEqual(200, resp.status_int)
                issue_msg = """Fix proposed to branch: branchy by Doe
Review: blop
"""
                set_issue_status.assert_called_with('789',
                                                    2,
                                                    message=issue_msg)
                j = json.loads(resp.body)
                self.assertEqual('Success',
                                 j['msg'])
                # oh no ! something went wrong with redmine
                set_issue_status.return_value = False
                resp = self.app.post_json('/hooks/patchset_created',
                                          hooks_kwargs,
                                          extra_environ=environ, status="*")
                self.assertEqual(400, resp.status_int)
                j = json.loads(resp.body)
                self.assertEqual("Could not change status of issue #789",
                                 j['msg'])

    def test_change_merged(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'), \
                patch('managesf.model.yamlbkd.engine.'
                      'SFResourceBackendEngine.get') as r:
            r.return_value = {'resources': {}}
            environ = {'REMOTE_USER': 'SF_SERVICE_USER'}
            hooks_kwargs = {'change': 123,
                            'change_url': 'blop',
                            'project': 'testytest',
                            'branch': 'b',
                            'topic': 'thunder',
                            'submitter': 'Doe',
                            'commit': 456,
                            'commit_message': 'fix the thing Closes: #789'}
            with patch.object(RedmineUtils,
                              'set_issue_status') as set_issue_status:
                set_issue_status.return_value = True
                resp = self.app.post_json('/hooks/change_merged',
                                          hooks_kwargs,
                                          extra_environ=environ, status="*")
                self.assertEqual(200, resp.status_int)
                issue_msg = (
                    """The following change on Gerrit has been merged to: b
Review: blop
Submitter: Doe

Commit message:
fix the thing Closes: #789

gitweb: http://redmine.tests.dom/r/gitweb?p=testytest.git;a=commit;h=456
""")
                set_issue_status.assert_called_with('789',
                                                    5,
                                                    message=issue_msg)
                j = json.loads(resp.body)
                self.assertEqual('Success',
                                 j['msg'])
                # oh no ! something went wrong with redmine
                set_issue_status.return_value = False
                resp = self.app.post_json('/hooks/change_merged',
                                          hooks_kwargs,
                                          extra_environ=environ, status="*")
                self.assertEqual(400, resp.status_int)
                j = json.loads(resp.body)
                self.assertEqual("Could not change status of issue #789",
                                 j['msg'])


class TestJobsController(FunctionalTest):
    def test_get(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            environ = {'REMOTE_USER': 'SF_SERVICE_USER'}
            with patch.object(SFJenkinsJobManager, 'get_job') as get:
                get.return_value = [{'status': 'SUCCESS',
                                     'job_name': 'mockjob',
                                     'job_id': '9999'}, ]
                # no filtering arg
                resp = self.app.get('/jobs/mockjob/',
                                    extra_environ=environ, status="*")
                self.assertEqual(200, resp.status_int)
                get.assert_called_with('mockjob')
                j = json.loads(resp.body)
                self.assertTrue('jenkins' in j.keys())
                j = j['jenkins']
                self.assertTrue(isinstance(j, list))
                self.assertEqual(1,
                                 len(j))
                self.assertTrue(all(get.return_value[0][u] == j[0][u]
                                    for u in get.return_value[0]),
                                j)
                # wrong filtering arg
                resp = self.app.get('/jobs/mockjob/?wrong=superwrong',
                                    extra_environ=environ, status="*")
                self.assertEqual(403, resp.status_int)
                # add filtering arg
                resp = self.app.get('/jobs/mockjob/?change=3&patchset=5',
                                    extra_environ=environ, status="*")
                self.assertEqual(200, resp.status_int)
                get.assert_called_with('mockjob', change='3', patchset='5')
                j = json.loads(resp.body)
                self.assertTrue('jenkins' in j.keys())
                j = j['jenkins']
                self.assertTrue(isinstance(j, list))
                self.assertEqual(1,
                                 len(j))
                self.assertTrue(all(get.return_value[0][u] == j[0][u]
                                    for u in get.return_value[0]),
                                j)

    def test_get_by_id(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            environ = {'REMOTE_USER': 'SF_SERVICE_USER'}
            with patch.object(SFJenkinsJobManager, 'get_job_status') as get:
                get.return_value = {'status': 'SUCCESS',
                                    'job_name': 'mockjob',
                                    'job_id': '9999'}
                resp = self.app.get('/jobs/mockjob/id/9999/',
                                    extra_environ=environ, status="*")
                self.assertEqual(200, resp.status_int)
                get.assert_called_with('mockjob', 9999)
                j = json.loads(resp.body)
                self.assertTrue('jenkins' in j.keys())
                j = j['jenkins']
                self.assertTrue(isinstance(j, list))
                self.assertEqual(1,
                                 len(j))
                self.assertTrue(all(get.return_value[u] == j[0][u]
                                    for u in get.return_value),
                                j)

    def test_get_parameters(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            environ = {'REMOTE_USER': 'SF_SERVICE_USER'}
            with patch.object(SFJenkinsJobManager, 'get_job_parameters') as g:
                g.return_value = {'parameters': [{'name': 'a',
                                                  'value': 'b'},
                                                 {'name': 'c',
                                                  'value': 'd'}, ],
                                  'job_name': 'mockjob',
                                  'job_id': '9999'}
                resp = self.app.get('/jobs/mockjob/id/9999/parameters',
                                    extra_environ=environ, status="*")
                self.assertEqual(200, resp.status_int)
                g.assert_called_with('mockjob', '9999')
                j = json.loads(resp.body)
                self.assertTrue('jenkins' in j.keys())
                j = j['jenkins']
                self.assertTrue(all(g.return_value[u] == j[u]
                                    for u in g.return_value),
                                j)

    def test_get_logs_url(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            environ = {'REMOTE_USER': 'SF_SERVICE_USER'}
            with patch.object(SFJenkinsJobManager, 'get_job_logs') as g:
                g.return_value = {'logs_url': 'http://mockurl',
                                  'job_name': 'mockjob',
                                  'job_id': '9999'}
                resp = self.app.get('/jobs/mockjob/id/9999/logs',
                                    extra_environ=environ, status="*")
                self.assertEqual(200, resp.status_int)
                g.assert_called_with('mockjob', '9999')
                j = json.loads(resp.body)
                self.assertTrue('jenkins' in j.keys())
                j = j['jenkins']
                self.assertTrue(all(g.return_value[u] == j[u]
                                    for u in g.return_value),
                                j)

    def test_run(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            environ = {'REMOTE_USER': 'SF_SERVICE_USER'}
            with patch.object(SFJenkinsJobManager, 'run') as run:
                run.return_value = {'status': 'pending',
                                    'job_name': 'mockjob',
                                    'job_id': '9999'}
                job_params = {'arg1': 'val1', 'arg2': 'val2'}
                resp = self.app.post_json('/jobs/mockjob/',
                                          job_params,
                                          extra_environ=environ, status="*")
                self.assertEqual(201, resp.status_int)
                run.assert_called_with('mockjob', job_params)
                j = json.loads(resp.body)
                self.assertTrue('jenkins' in j.keys())
                j = j['jenkins']
                self.assertTrue(all(run.return_value[u] == j[u]
                                    for u in run.return_value),
                                j)

    def test_stop(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            environ = {'REMOTE_USER': 'SF_SERVICE_USER'}
            with patch.object(SFJenkinsJobManager, 'stop') as stop:
                stop.return_value = {'status': 'aborted',
                                     'job_name': 'mockjob',
                                     'job_id': '9999'}
                resp = self.app.delete('/jobs/mockjob/id/9999/',
                                       extra_environ=environ, status="*")
                self.assertEqual(200, resp.status_int)
                stop.assert_called_with('mockjob', '9999')
                j = json.loads(resp.body)
                self.assertTrue('jenkins' in j.keys())
                j = j['jenkins']
                self.assertTrue(all(stop.return_value[u] == j[u]
                                    for u in stop.return_value),
                                j)


# class SlowStringIO(StringIO):
#    def __init__(self, contents, max_wait=2):
#        StringIO.__init__(self, contents)
#        self.max_wait = max_wait

#    def __iter__(self):
#        return self

#    def next(self):
#        wait = random.random() * self.max_wait
#        time.sleep(wait)
#        return StringIO.next(self)


class TestNodesController(FunctionalTest):
    def test_get(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            environ = {'REMOTE_USER': 'SF_SERVICE_USER'}
            with patch.object(SFNNM, 'get') as get:
                get.return_value = [{'mock1': 'val1', },
                                    {'mock2': 'val2', }, ]
                # no filtering arg
                resp = self.app.get('/nodes/',
                                    extra_environ=environ, status="*")
                self.assertEqual(200, resp.status_int)
                j = json.loads(resp.body)
                self.assertTrue('nodepool' in j.keys())
                j = j['nodepool']
                self.assertTrue(isinstance(j, list))
                self.assertEqual(2,
                                 len(j))
                # with id
                resp = self.app.get('/nodes/id/27',
                                    extra_environ=environ, status="*")
                get.assert_called_with(27)
                self.assertEqual(200, resp.status_int)
                j = json.loads(resp.body)
                self.assertTrue('nodepool' in j.keys())
                j = j['nodepool']
                self.assertTrue(isinstance(j, list))
                self.assertEqual(2,
                                 len(j))
                # wrong id type
                resp = self.app.get('/nodes/id/yeah_no',
                                    extra_environ=environ, status="*")
                self.assertEqual(400, resp.status_int)

    def test_put(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            environ = {'REMOTE_USER': 'SF_SERVICE_USER'}
            with patch.object(SFNNM, 'get') as get, \
                    patch.object(SFNNM, 'hold') as hold:
                get.return_value = [{'mock1': 'val1', },
                                    {'mock2': 'val2', }, ]
                # no filtering arg
                resp = self.app.put('/nodes/id/123/',
                                    extra_environ=environ, status="*")
                self.assertEqual(200, resp.status_int)
                j = json.loads(resp.body)
                self.assertTrue('nodepool' in j.keys())
                j = j['nodepool']
                self.assertTrue(isinstance(j, list))
                self.assertEqual(2,
                                 len(j))
                get.assert_called_with(123)
                hold.assert_called_with(123)
                # wrong id type
                resp = self.app.put('/nodes/id/yeah_no',
                                    extra_environ=environ, status="*")
                self.assertEqual(400, resp.status_int)

    def test_delete(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            environ = {'REMOTE_USER': 'SF_SERVICE_USER'}
            with patch.object(SFNNM, 'get') as get, \
                    patch.object(SFNNM, 'delete') as delete:
                get.return_value = [{'mock1': 'val1', },
                                    {'mock2': 'val2', }, ]
                # no filtering arg
                resp = self.app.delete('/nodes/id/123/',
                                       extra_environ=environ, status="*")
                self.assertEqual(200, resp.status_int)
                j = json.loads(resp.body)
                self.assertTrue('nodepool' in j.keys())
                j = j['nodepool']
                self.assertTrue(isinstance(j, list))
                self.assertEqual(2,
                                 len(j))
                get.assert_called_with(123)
                delete.assert_called_with(123)
                # wrong id type
                resp = self.app.put('/nodes/id/yeah_no',
                                    extra_environ=environ, status="*")
                self.assertEqual(400, resp.status_int)

    def test_errors(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            environ = {'REMOTE_USER': 'SF_SERVICE_USER'}
            with patch.object(SFNNM, 'get') as get, \
                    patch.object(SFNNM, 'delete') as delete, \
                    patch.object(SFNNM, 'hold') as hold:
                get.side_effect = Exception('Not a chance')
                resp = self.app.get('/nodes/id/123/',
                                    extra_environ=environ, status="*")
                self.assertEqual(500, resp.status_int)
                j = json.loads(resp.body)
                self.assertEqual('Not a chance',
                                 j['nodepool']['error_description'])
                k = "ssh-rsa abcdef== polnareff@chariot"
                resp = self.app.post_json('/nodes/id/123/authorize_key/',
                                          {'public_key': k, 'user': 'b'},
                                          extra_environ=environ, status="*")
                self.assertEqual(500, resp.status_int)
                j = json.loads(resp.body)
                self.assertEqual('Not a chance',
                                 j['nodepool']['error_description'])
                hold.side_effect = Exception('Not a chance (hold)')
                resp = self.app.put('/nodes/id/123/',
                                    extra_environ=environ, status="*")
                self.assertEqual(500, resp.status_int)
                j = json.loads(resp.body)
                self.assertEqual('Not a chance (hold)',
                                 j['nodepool']['error_description'])
                delete.side_effect = Exception('Not a chance (del)')
                resp = self.app.delete('/nodes/id/123/',
                                       extra_environ=environ, status="*")
                self.assertEqual(500, resp.status_int)
                j = json.loads(resp.body)
                self.assertEqual('Not a chance (del)',
                                 j['nodepool']['error_description'])

    def test_add_authorized_key(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            environ = {'REMOTE_USER': 'SF_SERVICE_USER'}
            with patch.object(SFNNM, 'get') as get:
                # node not found
                get.return_value = None
                k = "ssh-rsa abcdef== jojo@starplatinum"
                resp = self.app.post_json('/nodes/id/123/authorize_key/',
                                          {'public_key': k, 'user': 'b'},
                                          extra_environ=environ, status="*")
                self.assertEqual(500, resp.status_int)
                j = json.loads(resp.body)
                self.assertEqual('Node 123 not found',
                                 j['nodepool']['error_description'])
                resp = self.app.post_json('/nodes/id/123/authorize_key/',
                                          {'public_key': 'ora', 'user': 'b'},
                                          extra_environ=environ, status="*")
                self.assertEqual(500, resp.status_int)
                j = json.loads(resp.body)
                self.assertEqual('invalid public key ora(...)',
                                 j['nodepool']['error_description'])
            with patch.object(SFNNM, 'get') as get, \
                    patch.object(SFNNM, 'add_authorized_key') as add:
                resp = self.app.post_json('/nodes/id/123/authorize_key/',
                                          {'public_key': k, 'user': 'b'},
                                          extra_environ=environ, status="*")
                self.assertEqual(201, resp.status_int)
                j = json.loads(resp.body)
                self.assertEqual({'nodepool': 'OK'},
                                 j)
                add.assert_called_with(123, k, 'b')
                # test non JSON data
                resp = self.app.post('/nodes/id/123/authorize_key/',
                                     {'public_key': k, 'user': 'b'},
                                     extra_environ=environ, status="*")
                self.assertEqual(201, resp.status_int)

    def test_image_get(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            environ = {'REMOTE_USER': 'SF_SERVICE_USER'}
            with patch.object(SFNIM, 'get') as get:
                get.return_value = [{'mock1': 'val1', },
                                    {'mock2': 'val2', }, ]
                # no filtering arg
                resp = self.app.get('/nodes/images///',
                                    extra_environ=environ, status="*")
                self.assertEqual(200, resp.status_int)
                get.assert_called_with(None, None)
                j = json.loads(resp.body)
                self.assertTrue('nodepool' in j.keys())
                j = j['nodepool']
                self.assertTrue(isinstance(j, list))
                self.assertEqual(2,
                                 len(j))
                # with provider
                resp = self.app.get('/nodes/images/blip//',
                                    extra_environ=environ, status="*")
                get.assert_called_with("blip", None)
                self.assertEqual(200, resp.status_int)
                j = json.loads(resp.body)
                self.assertTrue('nodepool' in j.keys())
                j = j['nodepool']
                self.assertTrue(isinstance(j, list))
                self.assertEqual(2,
                                 len(j))
                # with both
                resp = self.app.get('/nodes/images/blip/blop/',
                                    extra_environ=environ, status="*")
                get.assert_called_with("blip", "blop")
                self.assertEqual(200, resp.status_int)
                j = json.loads(resp.body)
                self.assertTrue('nodepool' in j.keys())
                j = j['nodepool']
                self.assertTrue(isinstance(j, list))
                self.assertEqual(2,
                                 len(j))

#    def test_image_update(self):
#        with patch.object(SFGerritProjectManager, 'get_user_groups'):
#            environ = {'REMOTE_USER': 'SF_SERVICE_USER'}
#            with patch.object(SFNIM, 'update') as update:
#                update.return_value = SlowStringIO('well that went OK' * 4096,
#                                                   max_wait=10)
#                resp = self.app.put('/nodes/image/blip/blop/',
#                                    extra_environ=environ, status="*")
#                update.assert_called_with("blip", "blop")
#                self.assertEqual(201, resp.status_int, resp.body)
#                self.assertEqual('well that went OK' * 4096,
#                                 resp.body)


class TestResourcesController(FunctionalTest):

    def prepare_repo(self, data):
        repo_path = rtu.prepare_git_repo(self.to_delete)
        rtu.add_yaml_data(repo_path, data)
        return repo_path

    def test_get(self):
        workdir = tempfile.mkdtemp()
        self.to_delete.append(workdir)

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine.get') as get:
            get.return_value = {}
            resp = self.app.get('/resources/')

        data = {'resources': {'dummies': {
                'id1': {'name': 'resource_a'}
                }}}
        repo_path = self.prepare_repo(data)
        with patch('managesf.controllers.root.conf') as conf:
            conf.resources = {'workdir': workdir,
                              'subdir': 'resources',
                              'master_repo': repo_path}
            resp = self.app.get('/resources/')
            self.assertIn("resources", resp.json)

    def test_post(self):
        workdir = tempfile.mkdtemp()
        self.to_delete.append(workdir)

        environ = {'REMOTE_USER': 'SF_SERVICE_USER'}

        data = {'resources': {'dummies': {}}}
        repo_path = self.prepare_repo(data)
        proposed_data = {'resources': {'dummies': {
                         'id1': {'namespace': 'awesome',
                                 'name': 'p1'}}}}
        repo_path_zuul = self.prepare_repo(proposed_data)
        # This patch.object for the policy engine
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            with patch('managesf.controllers.root.conf') as conf:
                conf.resources = {'workdir': workdir,
                                  'subdir': 'resources',
                                  'master_repo': repo_path}
                kwargs = {'zuul_url': repo_path_zuul,
                          'zuul_ref': 'master'}
                with patch.dict('managesf.model.yamlbkd.engine.MAPPING',
                                {'dummies': Dummy}):
                    resp = self.app.post_json('/resources/',
                                              kwargs,
                                              extra_environ=environ,
                                              status="*")
                self.assertIn(
                    'Resource [type: dummies, ID: id1] is going '
                    'to be created.',
                    resp.json)
                self.assertEqual(resp.status_code, 200)

                proposed_data = {'resources': {'dummies': {
                                 'idbogus': {'namespace': 'awesome',
                                             'n4me': 'p3'},
                                 'id2': {'namespace': 'awesome',
                                         'name': 'p2'}
                                 }}}
                repo_path_zuul = self.prepare_repo(proposed_data)
                kwargs = {'zuul_url': repo_path_zuul,
                          'zuul_ref': 'master'}
                with patch.dict('managesf.model.yamlbkd.engine.MAPPING',
                                {'dummies': Dummy}):
                    resp = self.app.post_json('/resources/',
                                              kwargs,
                                              extra_environ=environ,
                                              status="*")
                self.assertIn(
                    "Resource [type: dummy, ID: idbogus] contains extra keys. "
                    "Please check the model.",
                    resp.json)
                self.assertEqual(resp.status_code, 409)

    def test_put(self):
        workdir = tempfile.mkdtemp()
        self.to_delete.append(workdir)

        environ = {'REMOTE_USER': 'SF_SERVICE_USER'}

        data = {'resources': {'dummies': {}}}
        repo_path = self.prepare_repo(data)
        new_data = {'resources': {'dummies': {
                    'id1': {'namespace': 'awesome',
                            'name': 'p1'}}}}
        rtu.add_yaml_data(repo_path, new_data)
        # This patch.object for the policy engine
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            with patch('managesf.controllers.root.conf') as conf:
                conf.resources = {'workdir': workdir,
                                  'subdir': 'resources',
                                  'master_repo': repo_path}
                with patch.dict('managesf.model.yamlbkd.engine.MAPPING',
                                {'dummies': Dummy}):
                    resp = self.app.put('/resources/',
                                        extra_environ=environ,
                                        status="*")
                self.assertIn("Resource [type: dummies, ID: id1] will be "
                              "created.",
                              resp.json)
                self.assertIn("Resource [type: dummies, ID: id1] has been "
                              "created.",
                              resp.json)
                self.assertEqual(len(resp.json), 2)
                with patch.dict('managesf.model.yamlbkd.engine.MAPPING',
                                {'dummies': Dummy}, clear=True):
                    prev = "resources: {}"
                    new = """resources:
  dummies:
    id1:
      name: dum
      namespace: a
"""
                    kwargs = {'prev': prev, 'new': new}
                    resp = self.app.put_json('/resources/',
                                             kwargs,
                                             extra_environ=environ,
                                             status="*")
                    self.assertListEqual(
                        resp.json,
                        ["Resource [type: dummies, ID: id1] is "
                         "going to be created.",
                         "Resource [type: dummies, ID: id1] will "
                         "be created.",
                         "Resource [type: dummies, ID: id1] has "
                         "been created."])
                    kwargs = {'wrong': None}
                    resp = self.app.put_json('/resources/',
                                             kwargs,
                                             extra_environ=environ,
                                             status="*")
                    self.assertEqual(resp.status_code, 400)

    def test_get_missing_resources(self):
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine.get_missing_resources') as gmr:
            gmr.return_value = ([], {})
            self.app.get('/resources/?get_missing_resources=true')
            self.assertTrue(gmr.called)
