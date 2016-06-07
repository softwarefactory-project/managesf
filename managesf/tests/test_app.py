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

import base64
import json
import os

from unittest import TestCase
from webtest import TestApp
from pecan import load_app, set_config
from contextlib import nested
from mock import patch, MagicMock

from basicauth import encode
from redmine.exceptions import ValidationError

from pysflib.sfredmine import RedmineUtils
from managesf.tests import dummy_conf

from managesf.services.base import BackupManager, BaseHooksManager
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


FIND_PROJECT_PATH = 'managesf.controllers.root.ProjectController._find_project'


def raiseexc(*args, **kwargs):
    raise Exception('FakeExcMsg')


class FunctionalTest(TestCase):
    def setUp(self):
        c = dummy_conf()
        self.config = {'services': c.services,
                       'gerrit': c.gerrit,
                       'redmine': c.redmine,
                       'app': c.app,
                       'admin': c.admin,
                       'sqlalchemy': c.sqlalchemy,
                       'auth': c.auth,
                       'htpasswd': c.htpasswd,
                       'sshconfig': c.sshconfig,
                       'managesf': c.managesf,
                       'jenkins': c.jenkins,
                       'storyboard': c.storyboard,
                       'mysql': c.mysql,
                       'nodepool': c.nodepool,
                       'etherpad': c.etherpad,
                       'lodgeit': c.lodgeit,
                       'pages': c.pages, }
        # deactivate loggin that polute test output
        # even nologcapture option of nose effetcs
        # 'logging': c.logging}
        self.app = TestApp(load_app(self.config))

    def tearDown(self):
        # Remove the sqlite db
        os.unlink(self.config['sqlalchemy']['url'][len('sqlite:///'):])


class TestManageSFIntrospectionController(FunctionalTest):

    def test_instrospection(self):
        response = self.app.get('/about/').json
        self.assertEqual('managesf',
                         response['service']['name'])
        self.assertEqual(set(self.config['services']),
                         set(response['service']['services']))


class TestManageSFAppLocaluserController(FunctionalTest):

    def test_add_or_update_user(self):
        environ = {'REMOTE_USER': self.config['admin']['name']}
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
        self.assertEqual(response.status_int, 403)

    def test_get_user(self):
        environ = {'REMOTE_USER': self.config['admin']['name']}
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
        self.assertEqual(response.status_int, 403)

    def test_delete_user(self):
        environ = {'REMOTE_USER': self.config['admin']['name']}
        infos = {'email': 'john@tests.dom', 'sshkey': 'sshkey',
                 'fullname': 'John Doe', 'password': 'secret'}
        response = self.app.post_json('/user/john', infos,
                                      extra_environ=environ, status="*")
        self.assertEqual(response.status_int, 201)

        environ = {'REMOTE_USER': 'boss'}
        response = self.app.delete('/user/john',
                                   extra_environ=environ, status="*")
        self.assertEqual(response.status_int, 403)

        environ = {'REMOTE_USER': self.config['admin']['name']}
        response = self.app.delete('/user/john',
                                   extra_environ=environ, status="*")
        self.assertEqual(response.status_int, 200)
        response = self.app.get('/user/john',
                                extra_environ=environ, status="*")
        self.assertEqual(response.status_int, 404)

    def test_bind_user(self):
        environ = {'REMOTE_USER': self.config['admin']['name']}
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
        response = self.app.set_cookie('auth_pubtkt', 'something')
        # Test that the guest has no permissions
        response = self.app.get('/config/')
        self.assertEqual(200, response.status_int)
        self.assertEqual(False, response.json['create_projects'])

        # Test with an admin user
        environ = {'REMOTE_USER': self.config['admin']['name']}
        with patch('managesf.controllers.root.is_admin') as gia:
            gia.return_value = True
            response = self.app.get('/config/', extra_environ=environ)
            self.assertEqual(True, response.json['create_projects'])
            gia.assert_called_with(self.config['admin']['name'])

        # Test with the permissions is set to false
        set_config({'project_create_administrator_only': False})
        response = self.app.get('/config/')
        self.assertEqual(True, response.json['create_projects'])

    def test_project_get_all(self):
        ctx = [patch.object(SFGerritProjectManager, 'get'),
               patch.object(SFGerritReviewManager, 'get'),
               patch.object(SFGerritProjectManager, 'get_user_groups'),
               patch.object(SFGerritProjectManager, 'get_projects_groups_id'),
               patch.object(SFGerritProjectManager, 'get_groups_details'),
               patch.object(SoftwareFactoryRedmine,
                            'get_open_issues')]
        with nested(*ctx) as (p_get, r_get, get_user_groups,
                              get_projects_groups_id,
                              get_groups_details, goi):
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
            for _mock in (p_get, r_get, get_user_groups,
                          get_projects_groups_id,
                          get_groups_details, goi):
                self.assertFalse(_mock.called)
            self.assertEqual(200, response.status_int)

    def test_project_get_one(self):
        ctx = [patch.object(SFGerritProjectManager, 'get'),
               patch.object(SFGerritReviewManager, 'get'),
               patch.object(SFGerritProjectManager, 'get_user_groups'),
               patch.object(SFGerritProjectManager, 'get_projects_groups_id'),
               patch.object(SFGerritProjectManager, 'get_groups_details'),
               patch.object(SoftwareFactoryRedmine,
                            'get_open_issues')]
        with nested(*ctx) as (p_get, r_get, get_user_groups,
                              get_projects_groups_id,
                              get_groups_details, goi):
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
        with patch('managesf.controllers.root.is_admin') as gia:
            response = self.app.put('/project/', status="*")
            self.assertEqual(response.status_int, 500)
        # Create a project with name, but without administrator status
        with patch('managesf.controllers.root.is_admin') as gia:
            gia.return_value = False
            response = self.app.put('/project/p1', status="*")
            self.assertEqual(response.status_int, 401)
        # Create a project with name
        ctx = [patch.object(project.SFGerritProjectManager, 'create'),
               patch('managesf.controllers.root.is_admin'),
               patch.object(SFRedmineProjectManager, 'create'),
               patch(FIND_PROJECT_PATH)]
        with nested(*ctx) as (gip, gia, rip, pfn):
            pfn.return_value = {}
            response = self.app.put('/project/p1', status="*",
                                    extra_environ={'REMOTE_USER': 'bob'})
            self.assertTupleEqual(('p1', 'bob', {}), gip.mock_calls[0][1])
            self.assertTupleEqual(('p1', 'bob', {}), rip.mock_calls[0][1])
            self.assertEqual(response.status_int, 201)
            self.assertEqual(json.loads(response.body),
                             'Project p1 has been created.')
        # Create a project with name - an error occurs
        ctx = [patch.object(project.SFGerritProjectManager, 'create'),
               patch('managesf.controllers.root.is_admin'),
               patch.object(SFRedmineProjectManager, 'create',
                            side_effect=raiseexc),
               patch(FIND_PROJECT_PATH)]
        with nested(*ctx) as (gip, gia, rip, fpn):
            fpn.return_value = {}
            response = self.app.put('/project/p1', status="*",
                                    extra_environ={'REMOTE_USER': 'bob'})
            self.assertEqual(response.status_int, 500)
            self.assertEqual(json.loads(response.body),
                             'Unable to process your request, failed '
                             'with unhandled error (server side): FakeExcMsg')

        # Create a project based on an upstream and test early fail
        # if upstream is not reachable
        ctx = [patch.object(project.SFGerritProjectManager, 'create'),
               patch('managesf.controllers.root.is_admin'),
               patch.object(SFRedmineProjectManager, 'create'),
               patch.object(utils.GerritRepo, 'check_upstream'),
               patch(FIND_PROJECT_PATH)]
        with nested(*ctx) as (gip, gia, rip, cu, pfn):
            pfn.return_value = {}
            cu.return_value = [False, "fatal: unable to access remote"]
            response = self.app.put_json(
                '/project/p1',
                {'upstream': 'git@github.com/account/repo.git'},
                status="*",
                extra_environ={'REMOTE_USER': 'bob'})
            self.assertEqual(response.status_int, 400)
            self.assertEqual(json.loads(response.body),
                             "fatal: unable to access remote")
            cu.return_value = [True, None]
            response = self.app.put_json(
                '/project/p1',
                {'upstream': 'git@github.com/account/repo.git'},
                status="*",
                extra_environ={'REMOTE_USER': 'bob'})
            self.assertEqual(response.status_int, 201)

        # Create a project with upstream and include all branches
        ctx = [patch.object(project.SFGerritProjectManager, 'create'),
               patch('managesf.controllers.root.is_admin'),
               patch.object(SFRedmineProjectManager, 'create'),
               patch.object(utils.GerritRepo, 'check_upstream'),
               patch(FIND_PROJECT_PATH)]
        with nested(*ctx) as (gip, gia, rip, cu, pfn):
            pfn.return_value = {}
            cu.return_value = [True, None]
            data = {'upstream': 'git@github.com/account/repo.git',
                    'add-branches': True}
            response = self.app.put_json('/project/prj2',
                                         data,
                                         status='*',
                                         extra_environ={'REMOTE_USER': 'BOB'})
            self.assertEqual(response.status_code, 201)

    def test_project_delete(self):
        # Delete a project with no name
        response = self.app.delete('/project/', status="*")
        self.assertEqual(response.status_int, 500)
        # Deletion of config project is not possible
        response = self.app.delete('/project/config', status="*")
        self.assertEqual(response.status_int, 500)
        # Delete a project with name
        ctx = [patch.object(SFGerritProjectManager, 'delete'),
               patch.object(SFRedmineProjectManager, 'delete'),
               patch(FIND_PROJECT_PATH)]
        with nested(*ctx) as (gdp, rdp, pfn):
            pfn.return_value = {'name': 'p1'}
            name = '===' + base64.urlsafe_b64encode('p1')
            response = self.app.delete('/project/%s/' % name, status="*",
                                       extra_environ={'REMOTE_USER': 'testy'})
            self.assertTupleEqual(('p1', 'testy'), gdp.mock_calls[0][1])
            self.assertTupleEqual(('p1', 'testy'), rdp.mock_calls[0][1])
            self.assertEqual(response.status_int, 200)
            self.assertEqual(json.loads(response.body),
                             'Project p1 has been deleted.')
        # Delete a project with name - an error occurs
        ctx = [patch.object(SFGerritProjectManager, 'delete'),
               patch.object(SFRedmineProjectManager, 'delete',
                            side_effect=raiseexc),
               patch(FIND_PROJECT_PATH)]
        with nested(*ctx) as (gip, rip, pfn):
            pfn.return_value = ('p1', None)
            response = self.app.delete('/project/p1', status="*")
            self.assertEqual(response.status_int, 500)
            self.assertEqual(json.loads(response.body),
                             'Unable to process your request, failed '
                             'with unhandled error (server side): FakeExcMsg')


class TestManageSFAppRestoreController(FunctionalTest):
    def tearDown(self):
        bkp = os.path.join(self.config['managesf']['backup_dir'],
                           'sf_backup.tar.gz')
        if os.path.isfile(bkp):
            os.unlink(bkp)

    def test_restore_post(self):
        bkp = os.path.join(self.config['managesf']['backup_dir'],
                           'sf_backup.tar.gz')
        files = [('file', 'useless', 'backup content')]
        # restore a provided backup
        environ = {'REMOTE_USER': self.config['admin']['name']}
        ctx = [patch('managesf.controllers.backup.backup_restore'),
               patch('managesf.controllers.backup.backup_unpack'),
               patch.object(BackupManager, 'restore')]
        with nested(*ctx) as (backup_restore, backup_unpack,
                              restore):
            response = self.app.post('/restore', status="*",
                                     upload_files=files)
            self.assertEqual(response.status_int, 401)

            response = self.app.post('/restore',
                                     extra_environ=environ,
                                     status="*",
                                     upload_files=files)
            self.assertTrue(os.path.isfile(bkp))
            self.assertTrue(backup_unpack.called)
            self.assertTrue(backup_restore.called)
            self.assertEqual(len(dummy_conf.services),
                             len(restore.mock_calls))
            self.assertEqual(response.status_int, 204)
        # restore a provided backup - an error occurs
        with nested(*ctx) as (backup_restore, backup_unpack,
                              restore):
            backup_restore.side_effect = raiseexc
            response = self.app.post('/restore',
                                     extra_environ=environ,
                                     status="*",
                                     upload_files=files)
            self.assertTrue(os.path.isfile(bkp))
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

        response = self.app.get('/backup', status="*")
        self.assertEqual(response.status_int, 401)

        environ = {'REMOTE_USER': self.config['admin']['name']}
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
        ctx = [patch('managesf.controllers.backup.backup_start'),
               patch.object(BackupManager, 'backup')]
        with nested(*ctx) as (backup_start, backup):
            response = self.app.post('/backup', status="*")
            self.assertEqual(response.status_int, 401)
            environ = {'REMOTE_USER': self.config['admin']['name']}
            response = self.app.post('/backup',
                                     extra_environ=environ,
                                     status="*")
            self.assertEqual(response.status_int, 204)
            self.assertEqual(len(dummy_conf.services),
                             len(backup.mock_calls))
            self.assertTrue(backup_start.called)


class TestManageSFAppMembershipController(FunctionalTest):
    def test_get_all_users(self):
        environ = {'REMOTE_USER': self.config['admin']['name']}
        users = [{'email': 'u%i@bip.dom' % x,
                  'ssh_keys': ['ora', 'oraora'],
                  'full_name': 'User %i' % x,
                  'username': 'user%i' % x} for x in range(10)]
        ctx = [patch.object(SFRedmineUserManager, 'create'),
               patch.object(StoryboardUserManager, 'create'),
               patch.object(g_user.SFGerritUserManager, 'create'),
               patch.object(SFRedmineUserManager, 'get'),
               patch.object(StoryboardUserManager, 'get'),
               patch.object(g_user.SFGerritUserManager, 'get'), ]
        with nested(*ctx) as (redmine_create, sb_create, gerrit_create,
                              r_get, s_get, g_get, ):
            r_get.return_value = None
            s_get.return_value = None
            g_get.return_value = None
            for x in range(10):
                redmine_create.return_value = x
                gerrit_create.return_value = x
                sb_create.return_value = x
                response = self.app.post_json('/services_users/', users[x],
                                              extra_environ=environ,
                                              status="*")
                self.assertEqual(response.status_int, 201)
            user_list = self.app.get('/project/membership/', status="*").json
            for u in users:
                u_info = [u['username'], u['email'], u['full_name']]
                self.assertTrue(u_info in user_list,
                                '%s not in %s' % (u_info, user_list))

    def test_put_empty_values(self):
        response = self.app.put_json('/project/membership/', {}, status="*")
        self.assertEqual(response.status_int, 400)
        response = self.app.put_json('/project/p1/membership/', {}, status="*")
        self.assertEqual(response.status_int, 400)
        response = self.app.put_json('/project/p1/membership/john', {},
                                     status="*")
        self.assertEqual(response.status_int, 400)

    def test_put(self):
        ctx = [patch.object(SFRedmineMembershipManager,
                            'create'),
               patch.object(SFGerritMembershipManager,
                            'create'),
               patch.object(SFUserManager, 'get')]
        with nested(*ctx) as (gaupg, raupg, c):
            c.return_value = {'email': 'john@tests.dom'}
            project_name = '===' + base64.urlsafe_b64encode('p1')
            response = self.app.put_json(
                '/project/%s/membership/john@tests.dom' % project_name,
                {'groups': ['ptl-group', 'core-group']},
                status="*")
            self.assertEqual(response.status_int, 201)
            self.assertEqual(json.loads(response.body),
                             "User john@tests.dom has been added in group(s):"
                             " ptl-group, core-group for project p1")
        ctx = [patch.object(SFGerritMembershipManager,
                            'create',
                            side_effect=raiseexc),
               patch.object(SFRedmineMembershipManager,
                            'create'),
               patch.object(SFUserManager, 'get')]
        with nested(*ctx) as (gaupg, raupg, c):
            c.return_value = {'email': 'john@tests.dom'}
            response = self.app.put_json(
                '/project/p1/membership/john@tests.dom',
                {'groups': ['ptl-group', 'core-group']},
                status="*")
            self.assertEqual(response.status_int, 500)
            self.assertEqual(json.loads(response.body),
                             'Unable to process your request, failed '
                             'with unhandled error (server side): FakeExcMsg')

    def test_delete(self):
        def notfound(*args, **kwargs):
            raise exc.GroupNotFoundException

        def err(*args, **kwargs):
            raise Exception

        project_name = '===' + base64.urlsafe_b64encode('p1')
        ctx = [patch.object(SFGerritGroupManager, 'get'),
               patch.object(SFUserManager, 'get')]
        with nested(*ctx) as (a, b):
            b.return_value = {}
            a.side_effect = notfound
            response = self.app.delete('/project/%s/membership/john' % (
                                       project_name), status="*")
            self.assertEqual(response.status_int, 400)
        ctx = [
            patch.object(SFGerritMembershipManager,
                         'delete'),
            patch.object(SFRedmineMembershipManager,
                         'delete'),
            patch.object(SFUserManager, 'get'),
            patch.object(SFGerritGroupManager, 'get')]
        with nested(*ctx) as (gdupg, rdupg, c, d):
            c.return_value = {}
            response = self.app.delete(
                '/project/p1/membership/grp1',
                status="*")
            self.assertEqual(response.status_int, 200)
            c.return_value = {'email': 'john@tests.dom'}
            response = self.app.delete(
                '/project/p1/membership/john@tests.dom',
                status="*")
            self.assertEqual(response.status_int, 200)
            self.assertEqual(json.loads(response.body),
                             "User john@tests.dom has been deleted from all "
                             "groups for project p1.")
            response = self.app.delete(
                '/project/p1/membership/john@tests.dom/core-group',
                status="*")
            self.assertEqual(response.status_int, 200)
            self.assertEqual(json.loads(response.body),
                             "User john@tests.dom has been deleted from group "
                             "core-group for project p1.")
        ctx = [
            patch.object(SFGerritMembershipManager,
                         'delete',
                         side_effect=raiseexc),
            patch.object(SFRedmineMembershipManager,
                         'delete'),
            patch.object(SFUserManager, 'get'),
            patch.object(SFGerritGroupManager, 'get')]
        with nested(*ctx) as (gdupg, rdupg, c, d):
            c.return_value = {'email': 'john@tests.dom'}
            response = self.app.delete(
                '/project/p1/membership/john@tests.dom',
                status="*")
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
        ctx = [patch.object(SFGerritGroupManager, 'create'),
               patch.object(RedmineGroupManager, 'create'),
               patch.object(SFUserManager, 'get')]
        with nested(*ctx) as (sgm, rgm, sfum):
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
        with nested(*ctx) as (sgm, rgm, sfum):
            sgm.side_effect = self.exc1
            sfum.return_value = {'email': "user1@sftests.com"}
            resp = self.app.put_json('/group/grp1',
                                     {'description': 'Nice dev team'},
                                     extra_environ=env,
                                     status="*")
            sgm.assert_called_with('grp1', 'user1@sftests.com',
                                   'Nice dev team')
            rgm.assert_not_called()
        self.assertEqual(resp.status_int, 409)
        with nested(*ctx) as (sgm, rgm, sfum):
            rgm.side_effect = self.exc1
            sfum.return_value = {'email': "user1@sftests.com"}
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
        ctx = [patch.object(SFGerritRoleManager, 'delete'),
               patch.object(RedmineGroupManager, 'delete'),
               patch.object(SFGerritGroupManager, 'get'),
               patch.object(SFUserManager, 'get')]
        with nested(*ctx) as (srm, rgm, sgg, sfum):
            sgg.return_value = {'grp1': [{'email': 'user1@sftests.com'}]}
            resp = self.app.delete('/group/grp1',
                                   extra_environ=env,
                                   status="*")
            srm.assert_not_called()
            rgm.assert_not_called()
        # user is not part of the group
        self.assertEqual(resp.status_int, 403)
        with nested(*ctx) as (srm, rgm, sgg, sfum):
            sfum.return_value = {'email': 'user1@sftests.com'}
            sgg.return_value = {'grp1': [{'email': 'user1@sftests.com'}]}
            resp = self.app.delete('/group/grp1',
                                   extra_environ=env,
                                   status="*")
            srm.assert_called_with('grp1')
            rgm.assert_called_with('grp1')
        # user is part of the group so delete is accepted
        self.assertEqual(resp.status_int, 204)

    def test_get_group(self):
        env = {'REMOTE_USER': 'user1'}
        with patch.object(SFGerritGroupManager, 'get') as sgg:
            sgg.return_value = {'grp1': [{'email': 'user1@sftests.com'}]}
            resp = self.app.get('/group/grp1',
                                extra_environ=env,
                                status="*")
            sgg.assert_called_with('grp1')
        self.assertEqual(resp.status_int, 200)
        self.assertDictEqual(resp.json, sgg.return_value)

        with patch.object(SFGerritGroupManager, 'get') as sgg:
            sgg.return_value = {'grp1': [{'email': 'user1@sftests.com'}],
                                'grp2': [{'email': 'user2@sftests.com'}]}
            resp = self.app.get('/group/',
                                extra_environ=env,
                                status="*")
            sgg.assert_called_with(None)
        self.assertEqual(resp.status_int, 200)
        self.assertDictEqual(resp.json, sgg.return_value)


class TestManageSFPagesController(FunctionalTest):
    def test_unauthenticated(self):
        resp = self.app.get('/pages/p1', status="*")
        self.assertEqual(resp.status_int, 401)

        resp = self.app.post_json('/pages/p1', {}, status="*")
        self.assertEqual(resp.status_int, 401)

        resp = self.app.delete('/pages/p1', status="*")
        self.assertEqual(resp.status_int, 401)

    def test_authenticated(self):
        env = {'REMOTE_USER': 'user1'}
        with patch.object(SFGerritProjectManager, 'user_owns_project') as uop:
            uop.return_value = False
            resp = self.app.post_json('/pages/p1', {'url': 'http://target'},
                                      extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 403)

            # Now user1 is the project onwer
            uop.return_value = True
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
            uop.return_value = False
            resp = self.app.get('/pages/p1',
                                extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 403)

            # Try to add an invalid target
            uop.return_value = True
            resp = self.app.post_json('/pages/p3', {'url': 'invalid'},
                                      extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 400)

            # Try to delete a target
            uop.return_value = False
            resp = self.app.delete('/pages/p1',
                                   extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 403)
            uop.return_value = True
            resp = self.app.delete('/pages/p1',
                                   extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 200)
            resp = self.app.delete('/pages/p2',
                                   extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 200)

            # Trye to delete a non existing target
            resp = self.app.delete('/pages/p3',
                                   extra_environ=env, status="*")
            self.assertEqual(resp.status_int, 404)


class TestManageSFHtpasswdController(FunctionalTest):
    def test_unauthenticated(self):
        resp = self.app.put_json('/htpasswd/', {}, status="*")
        self.assertEqual(resp.status_int, 401)

        resp = self.app.get('/htpasswd/', {}, status="*")
        self.assertEqual(resp.status_int, 401)

        resp = self.app.delete('/htpasswd/', {}, status="*")
        self.assertEqual(resp.status_int, 401)

    def test_authenticated(self):
        env = {'REMOTE_USER': self.config['admin']['name']}

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
        os.remove(self.config['htpasswd']['filename'])
        env = {'REMOTE_USER': self.config['admin']['name']}

        resp = self.app.put('/htpasswd/', extra_environ=env, status="*")
        self.assertEqual(resp.status_int, 406)

        resp = self.app.get('/htpasswd/', extra_environ=env, status="*")
        self.assertEqual(resp.status_int, 406)

        resp = self.app.delete('/htpasswd/', extra_environ=env, status="*")
        self.assertEqual(resp.status_int, 406)


class TestProjectTestsController(FunctionalTest):
    def test_init_project_test(self):
        environ = {'REMOTE_USER': self.config['admin']['name']}
        ctx = [patch.object(SFGerritProjectManager, 'get'),
               patch.object(SFGerritReviewManager, 'propose_test_definition')]
        with nested(*ctx) as (gp, ptd):
            gp.return_value = 'p1'
            resp = self.app.put_json('/tests/toto', {'project-scripts': False},
                                     extra_environ=environ, status="*")
            self.assertEqual(resp.status_int, 201)

    def test_init_project_test_with_project_scripts(self):
        environ = {'REMOTE_USER': self.config['admin']['name']}
        ctx = [patch.object(SFGerritProjectManager, 'get'),
               patch.object(SFGerritReviewManager, 'propose_test_definition'),
               patch.object(SFGerritReviewManager, 'propose_test_scripts')]
        with nested(*ctx) as (gp, ptd, pts):
            gp.return_value = 'p1'
            resp = self.app.put_json('/tests/toto', {'project-scripts': True},
                                     extra_environ=environ, status="*")
            self.assertEqual(resp.status_int, 201)


class TestManageSFServicesUserController(FunctionalTest):

    def test_add_user_in_backends_non_admin(self):
        environ = {'REMOTE_USER': 'dio'}
        infos = {'email': 'jojo@starplatinum.dom',
                 'ssh_keys': ['ora', 'oraora'],
                 'full_name': 'Jotaro Kujoh', 'username': 'jojo'}
        response = self.app.post_json('/services_users/', infos,
                                      extra_environ=environ, status="*")
        self.assertEqual(response.status_int, 403)

    def test_add_user_in_backends(self):
        environ = {'REMOTE_USER': self.config['admin']['name']}
        ctx = [patch.object(SFRedmineUserManager, 'create'),
               patch.object(StoryboardUserManager, 'create'),
               patch.object(g_user.SFGerritUserManager, 'create'),
               patch.object(SFRedmineUserManager, 'get'),
               patch.object(StoryboardUserManager, 'get'),
               patch.object(g_user.SFGerritUserManager, 'get'), ]
        create_ctx = [patch('managesf.services.gerrit.get_cookie'),
                      patch.object(RedmineUtils, 'create_user'),
                      patch.object(StoryboardUserManager, 'create'),
                      patch.object(g_user.SFGerritUserManager, '_add_sshkeys'),
                      patch.object(g_user.SFGerritUserManager,
                                   '_add_account_as_external'),
                      patch('pysflib.sfgerrit.GerritUtils.create_account'),
                      patch.object(SFRedmineUserManager, 'get'),
                      patch.object(StoryboardUserManager, 'get'),
                      patch.object(g_user.SFGerritUserManager, 'get'),
                      patch('pysflib.sfgerrit.GerritUtils.update_account'),
                      patch.object(SFRedmineUserManager, 'update'),
                      patch.object(StoryboardUserManager, 'update'),
                      ]
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
        with nested(*ctx) as (redmine_create, sb_create, gerrit_create,
                              r_get, s_get, g_get, ):
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
        with nested(*create_ctx) as (get_cookie, rm_create_user, s_create, ssh,
                                     external, create_account,
                                     r_get, s_get, g_get,
                                     g_update, s_update, r_update):
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

        with nested(*ctx) as (redmine_create, storyboard_create, gerrit_create,
                              r_get, s_get, g_get, ):
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
        with nested(*create_ctx) as (get_cookie, rm_create_user, s_create, ssh,
                                     external, create_account,
                                     r_get, s_get, g_get,
                                     g_update, s_update, r_update):
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
        with nested(*create_ctx) as (get_cookie, rm_create_user, s_create, ssh,
                                     external, create_account,
                                     r_get, s_get, g_get,
                                     g_update, s_update, r_update):
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
        ctx = [patch.object(SFRedmineUserManager, 'create'), ]
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
        with nested(*ctx) as (redmine_create, ):
            response = self.app.post_json('/services_users/', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 400)

    def test_delete_user_in_backends_non_admin(self):
        environ = {'REMOTE_USER': 'dio'}
        params = {'username': 'iggy'}
        response = self.app.delete('/services_users/', params,
                                   extra_environ=environ, status="*")
        self.assertEqual(response.status_int, 403)

    def test_delete_user_in_backends(self):
        environ = {'REMOTE_USER': self.config['admin']['name']}
        infos = {'email': 'iggy@stooges.dom',
                 'ssh_keys': ['ora', 'oraora'],
                 'full_name': 'iggy the fool', 'username': 'iggy'}
        ctx = [patch.object(SFRedmineUserManager, 'delete'),
               patch.object(StoryboardUserManager, 'delete'),
               patch.object(g_user.SFGerritUserManager, 'delete'),
               patch.object(SFRedmineUserManager, 'create'),
               patch.object(StoryboardUserManager, 'create'),
               patch.object(g_user.SFGerritUserManager, 'create'),
               patch.object(SFRedmineUserManager, 'get'),
               patch.object(StoryboardUserManager, 'get'),
               patch.object(g_user.SFGerritUserManager, 'get'), ]
        with nested(*ctx) as (redmine_delete, sb_delete, gerrit_delete,
                              redmine_create, sb_create, gerrit_create,
                              redmine_get, sb_get, gerrit_get):
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
        with nested(*ctx) as (redmine_delete, sb_delete, gerrit_delete,
                              redmine_create, sb_create, gerrit_create,
                              redmine_get, sb_get, gerrit_get):
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
        environ = {'REMOTE_USER': self.config['admin']['name']}
        infos_kira = {'email': 'kira@jojolion.dom',
                      'ssh_keys': ['ora', 'oraora'],
                      'full_name': 'yoshikage kira', 'username': 'kira'}
        ctx = [patch.object(SFRedmineUserManager, 'create'),
               patch.object(StoryboardUserManager, 'create'),
               patch.object(g_user.SFGerritUserManager, 'create'),
               patch.object(SFRedmineUserManager, 'get'),
               patch.object(StoryboardUserManager, 'get'),
               patch.object(g_user.SFGerritUserManager, 'get'), ]
        with nested(*ctx) as (redmine_create, sb_create, gerrit_create,
                              r_get, s_get, g_get, ):
            r_get.return_value = None
            s_get.return_value = None
            g_get.return_value = None
            redmine_create.return_value = 12
            sb_create.return_value = 12
            gerrit_create.return_value = 13
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
        environ = {'REMOTE_USER': self.config['admin']['name']}
        infos_jojo = {'email': 'jojo@starplatinum.dom',
                      'ssh_keys': ['ora', 'oraora'],
                      'full_name': 'Jotaro Kujoh', 'username': 'jojo'}
        infos_poln = {'email': 'polnareff@chariot.dom',
                      'ssh_keys': ['ora', 'oraora'],
                      'full_name': 'Polnareff', 'username': 'chariot'}
        ctx = [patch.object(SFRedmineUserManager, 'create'),
               patch.object(StoryboardUserManager, 'create'),
               patch.object(g_user.SFGerritUserManager, 'create'),
               patch.object(SFRedmineUserManager, 'get'),
               patch.object(StoryboardUserManager, 'get'),
               patch.object(g_user.SFGerritUserManager, 'get'), ]
        with nested(*ctx) as (redmine_create, sb_create, gerrit_create,
                              r_get, s_get, g_get, ):
            r_get.return_value = None
            s_get.return_value = None
            g_get.return_value = None
            redmine_create.return_value = 12
            sb_create.return_value = 12
            gerrit_create.return_value = 13
            response = self.app.post_json('/services_users/', infos_jojo,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)
            redmine_create.return_value = 14
            gerrit_create.return_value = 15
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
            environ = {'REMOTE_USER': self.config['admin']['name']}
            response = self.app.post_json('/services_users/', infos_jojo,
                                          extra_environ=environ, status="*")
            jojo = self.app.get('/services_users/?username=jojo',
                                extra_environ=environ, status="*")
            self.assertEqual('99', jojo.json.get('cauth_id'))

    def test_update_user(self):
        environ = {'REMOTE_USER': self.config['admin']['name']}
        infos_jojo = {'email': 'jojo@starplatinum.dom',
                      'ssh_keys': ['ora', 'oraora'],
                      'full_name': 'Jotaro Kujoh', 'username': 'jojo'}
        ctx = [patch.object(SFRedmineUserManager, 'create'),
               patch.object(StoryboardUserManager, 'create'),
               patch.object(g_user.SFGerritUserManager, 'create'),
               patch.object(SFRedmineUserManager, 'update'),
               patch.object(StoryboardUserManager, 'update'),
               patch.object(g_user.SFGerritUserManager, 'update'),
               patch.object(SFRedmineUserManager, 'get'),
               patch.object(StoryboardUserManager, 'get'),
               patch.object(g_user.SFGerritUserManager, 'get'), ]
        with nested(*ctx) as (redmine_create, sb_create, gerrit_create,
                              redmine_update, sb_update, gerrit_update,
                              r_get, s_get, g_get, ):
            r_get.return_value = None
            s_get.return_value = None
            g_get.return_value = None
            redmine_create.return_value = 12
            sb_create.return_value = 12
            gerrit_create.return_value = 13
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
            for i in (self.config['admin']['name'], infos_jojo['username']):
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
            for i in (self.config['admin']['name'], infos_jojo['username']):
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
            for i in (self.config['admin']['name'], infos_jojo['username']):
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
        environ = {'REMOTE_USER': self.config['admin']['name']}
        resp = self.app.post_json('/hooks/toto', {'arg1': 1, 'arg2': 2},
                                  extra_environ=environ, status="*")
        self.assertEqual(404, resp.status_int)
        j = json.loads(resp.body)
        self.assertEqual(len(self.config['services']) + 1,
                         len(j))

    def test_non_existing_service(self):
        environ = {'REMOTE_USER': self.config['admin']['name']}
        resp = self.app.post_json('/hooks/toto/blagh', {'arg1': 1, 'arg2': 2},
                                  extra_environ=environ, status="*")
        self.assertEqual(404, resp.status_int)
        j = json.loads(resp.body)
        self.assertEqual('Unknown service',
                         j['blagh'])

    def test_patchset_created(self):
        environ = {'REMOTE_USER': self.config['admin']['name']}
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
            # +1 from adding the name of the hook
            self.assertEqual(len(self.config['services']) + 1,
                             len(j))
            self.assertEqual('patchset_created',
                             j['hook_name'])
            self.assertEqual('Success',
                             j['redmine'])
            # oh no ! something went wrong with redmine
            set_issue_status.return_value = False
            resp = self.app.post_json('/hooks/patchset_created',
                                      hooks_kwargs,
                                      extra_environ=environ, status="*")
            self.assertEqual(400, resp.status_int)
            j = json.loads(resp.body)
            # +1 from adding the name of the hook
            self.assertEqual(len(self.config['services']) + 1,
                             len(j))
            self.assertEqual('patchset_created',
                             j['hook_name'])
            self.assertEqual("Could not change status of issue #789",
                             j['redmine'])

    def test_patchset_created_one_service(self):
        environ = {'REMOTE_USER': self.config['admin']['name']}
        with patch.object(BaseHooksManager,
                          'patchset_created') as patchset_created:
            patchset_created.return_value = "mocked"
            resp = self.app.post_json('/hooks/patchset_created/etherpad',
                                      {'arg1': 1, 'arg2': 2},
                                      extra_environ=environ, status="*")
            self.assertEqual(200, resp.status_int)
            patchset_created.assert_called_with(arg1=1,
                                                arg2=2)
            j = json.loads(resp.body)
            # only one service called
            self.assertEqual(2,
                             len(j))
            self.assertEqual('patchset_created',
                             j['hook_name'])
            self.assertEqual('mocked',
                             j['etherpad'])
            # call hook for nonexistent service
            resp = self.app.post_json('/hooks/patchset_created/blagh',
                                      {'arg1': 1, 'arg2': 2},
                                      extra_environ=environ, status="*")
            self.assertEqual(404, resp.status_int)
            j = json.loads(resp.body)
            self.assertEqual('Unknown service',
                             j['blagh'])

    def test_change_merged(self):
        environ = {'REMOTE_USER': self.config['admin']['name']}
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
            issue_msg = """The following change on Gerrit has been merged to: b
Review: blop
Submitter: Doe

Commit message:
fix the thing Closes: #789

gitweb: http://redmine.tests.dom/r/gitweb?p=testytest.git;a=commit;h=456
"""
            set_issue_status.assert_called_with('789',
                                                5,
                                                message=issue_msg)
            j = json.loads(resp.body)
            # +1 from adding the name of the hook
            self.assertEqual(len(self.config['services']) + 1,
                             len(j))
            self.assertEqual('change_merged',
                             j['hook_name'])
            self.assertEqual('Success',
                             j['redmine'])
            # oh no ! something went wrong with redmine
            set_issue_status.return_value = False
            resp = self.app.post_json('/hooks/change_merged',
                                      hooks_kwargs,
                                      extra_environ=environ, status="*")
            self.assertEqual(400, resp.status_int)
            j = json.loads(resp.body)
            # +1 from adding the name of the hook
            self.assertEqual(len(self.config['services']) + 1,
                             len(j))
            self.assertEqual('change_merged',
                             j['hook_name'])
            self.assertEqual("Could not change status of issue #789",
                             j['redmine'])
