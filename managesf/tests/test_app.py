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
import tempfile

from unittest import TestCase
from webtest import TestApp
from pecan import load_app
from mock import patch, MagicMock

from basicauth import encode

from managesf.tests import dummy_conf

from managesf.services import exceptions as exc

# plugins imports
# TODO: should be done dynamically depending on what plugins we want

from managesf.services.gerrit.project import SFGerritProjectManager
from managesf.services.gerrit import user as g_user
from managesf.services.storyboard.user import StoryboardUserManager
from managesf.services.jenkins.job import SFJenkinsJobManager
from managesf.services.nodepool.node import SFNodepoolNodeManager as SFNNM
from managesf.services.nodepool.image import SFNodepoolImageManager as SFNIM

from managesf.tests import resources_test_utils as rtu
from managesf.model.yamlbkd.resources.dummy import Dummy


def raiseexc(*args, **kwargs):
    raise Exception('FakeExcMsg')


class FunctionalTest(TestCase):
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
        with patch.object(StoryboardUserManager, 'create') as sb_create, \
                patch.object(g_user.SFGerritUserManager,
                             'create') as gerrit_create, \
                patch.object(StoryboardUserManager, 'get') as s_get, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch.object(SFGerritProjectManager,
                             'get_user_groups'):
            s_get.return_value = None
            g_get.return_value = None
            sb_create.return_value = sb_user.id
            gerrit_create.return_value = gerrit_created["_account_id"]
            response = self.app.post_json('/services_users/', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)
            _, gerrit_args = gerrit_create.call_args
            for k, v in (
                ("username", infos.get('username')),
                ("email", infos.get('email')),
                ("full_name", infos.get('full_name')),
                ("ssh_keys", infos['ssh_keys'])
            ):
                self.assertEqual(gerrit_args[k], v)
            self.assertTrue("cauth_id" in gerrit_args)
            # TODO(mhu) test if mapping is set correctly
        # mock at a lower level
        with patch('managesf.services.gerrit.get_cookie') as get_cookie, \
                patch.object(StoryboardUserManager, 'create') as s_create, \
                patch.object(g_user.SFGerritUserManager, '_add_sshkeys'), \
                patch.object(g_user.SFGerritUserManager,
                             '_add_account_as_external'), \
                patch('pysflib.sfgerrit.GerritUtils.create_account') \
                as create_account, \
                patch.object(StoryboardUserManager, 'get') as s_get, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch('pysflib.sfgerrit.GerritUtils.update_account'), \
                patch.object(StoryboardUserManager, 'update'), \
                patch.object(SFGerritProjectManager, 'get_user_groups'):
            get_cookie.return_value = 'admin_cookie'

            s_create.return_value = sb_user2.id
            create_account.return_value = gerrit2_created
            s_get.return_value = None
            g_get.return_value = None
            response = self.app.post_json('/services_users/', infos2,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)

        with patch.object(StoryboardUserManager, 'create') as sb_create, \
                patch.object(g_user.SFGerritUserManager,
                             'create') as gerrit_create, \
                patch.object(StoryboardUserManager, 'get') as s_get, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch.object(SFGerritProjectManager,
                             'get_user_groups'):
            # assert that raising UnavailableActionError won't fail
            def unavailable(*args, **kwargs):
                raise exc.UnavailableActionError
            s_get.side_effect = unavailable
            g_get.return_value = 14
            gerrit_create.return_value = 14
            response = self.app.post_json('/services_users/', infos3,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)

        with patch('managesf.services.gerrit.get_cookie') as get_cookie, \
                patch.object(StoryboardUserManager, 'create') as s_create, \
                patch.object(g_user.SFGerritUserManager, '_add_sshkeys'), \
                patch.object(g_user.SFGerritUserManager,
                             '_add_account_as_external'), \
                patch('pysflib.sfgerrit.GerritUtils.create_account') \
                as create_account, \
                patch.object(StoryboardUserManager, 'get') as s_get, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch('pysflib.sfgerrit.GerritUtils.update_account'), \
                patch.object(StoryboardUserManager, 'update'), \
                patch.object(SFGerritProjectManager, 'get_user_groups'):

            get_cookie.return_value = 'admin_cookie'
            s_get.return_value = sb_user.id
            g_get.return_value = gerrit_created["_account_id"]
            create_account.return_value = gerrit_created
            response = self.app.post_json('/services_users/', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)

        with patch('managesf.services.gerrit.get_cookie') as get_cookie, \
                patch.object(StoryboardUserManager, 'create') as s_create, \
                patch.object(g_user.SFGerritUserManager, '_add_sshkeys'), \
                patch.object(g_user.SFGerritUserManager,
                             '_add_account_as_external'), \
                patch('pysflib.sfgerrit.GerritUtils.create_account') \
                as create_account, \
                patch.object(StoryboardUserManager, 'get') as s_get, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch('pysflib.sfgerrit.GerritUtils.update_account'), \
                patch.object(StoryboardUserManager, 'update'), \
                patch.object(SFGerritProjectManager, 'get_user_groups'):
            get_cookie.return_value = 'admin_cookie'
            # assert that user found in backend will skip gracefully
            s_get.return_value = sb_user.id
            g_get.return_value = gerrit_created["_account_id"]
            create_account.return_value = gerrit_created
            response = self.app.post_json('/services_users/', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)

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
        with patch.object(StoryboardUserManager, 'delete') as sb_delete, \
                patch.object(g_user.SFGerritUserManager,
                             'delete') as gerrit_delete, \
                patch.object(StoryboardUserManager,
                             'create') as sb_create, \
                patch.object(g_user.SFGerritUserManager,
                             'create') as gerrit_create, \
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
            sb_create.return_value = 99
            gerrit_create.return_value = 99
            sb_get.return_value = None
            gerrit_get.return_value = None
            self.app.post_json('/services_users/', infos,
                               extra_environ=environ, status="*")
            response = self.app.delete('/services_users/?username=iggy',
                                       extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 204)
            sb_delete.assert_called_with(username='iggy', email=None)
            gerrit_delete.assert_called_with(username='iggy', email=None)

        with patch.object(StoryboardUserManager, 'delete') as sb_delete, \
                patch.object(g_user.SFGerritUserManager,
                             'delete') as gerrit_delete, \
                patch.object(StoryboardUserManager,
                             'create') as sb_create, \
                patch.object(g_user.SFGerritUserManager,
                             'create') as gerrit_create, \
                patch.object(StoryboardUserManager, 'get') as sb_get, \
                patch.object(g_user.SFGerritUserManager,
                             'get') as gerrit_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            gug.return_value = []
            sb_create.return_value = 100
            gerrit_create.return_value = 100
            sb_get.return_value = None
            gerrit_get.return_value = None
            self.app.post_json('/services_users/', infos,
                               extra_environ=environ, status="*")
            response = self.app.delete(
                '/services_users/?email=iggy@stooges.dom',
                extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 204)
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
        with patch.object(StoryboardUserManager, 'delete'), \
                patch.object(g_user.SFGerritUserManager, 'delete'), \
                patch.object(StoryboardUserManager, 'create') as s_create, \
                patch.object(g_user.SFGerritUserManager,
                             'create') as g_create, \
                patch.object(StoryboardUserManager, 'get') as s_get, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups'):

            s_get.return_value = None
            g_get.return_value = None
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
        with patch.object(StoryboardUserManager, 'delete'), \
                patch.object(g_user.SFGerritUserManager, 'delete'), \
                patch.object(StoryboardUserManager,
                             'create') as s_create, \
                patch.object(g_user.SFGerritUserManager,
                             'create') as g_create, \
                patch.object(StoryboardUserManager, 'get') as s_get, \
                patch.object(g_user.SFGerritUserManager,
                             'get') as g_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups') as gug:

            s_get.return_value = None
            g_get.return_value = None
            s_create.return_value = 12
            g_create.return_value = 13
            gug.return_value = []
            response = self.app.post_json('/services_users/', infos_jojo,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)
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
        with patch.object(StoryboardUserManager, 'update') as s_up, \
                patch.object(g_user.SFGerritUserManager, 'update') as g_up, \
                patch.object(StoryboardUserManager,
                             'create') as s_create, \
                patch.object(g_user.SFGerritUserManager,
                             'create') as g_create, \
                patch.object(StoryboardUserManager, 'get') as s_get, \
                patch.object(g_user.SFGerritUserManager,
                             'get') as g_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups'):
            for mock in (s_up, g_up, s_get, g_get):
                mock.return_value = None
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
                patch.object(g_user.SFGerritUserManager,
                             'create') as g_create, \
                patch.object(g_user.SFGerritUserManager,
                             'update') as g_update, \
                patch.object(g_user.SFGerritUserManager,
                             'get') as g_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups') as gug:

            gug.return_value = []
            for mock in (s_get, s_update, g_get, g_update):
                mock.return_value = None
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

    def test_image_update(self):
        with patch.object(SFGerritProjectManager, 'get_user_groups'):
            environ = {'REMOTE_USER': 'SF_SERVICE_USER'}
            with patch.object(SFNIM, 'start_update') as start_update:
                start_update.return_value = 54
                resp = self.app.put('/nodes/images/update/blip/blop/',
                                    extra_environ=environ, status="*")
                start_update.assert_called_with("blip", "blop")
                self.assertEqual(201, resp.status_int, resp.body)
                self.assertTrue(str(start_update.return_value) in resp.body,
                                resp.body)
            with patch.object(SFNIM, 'get_update_info') as get_info:
                dummy = {'id': 51,
                         'status': 'bleh',
                         'provider': 'blip',
                         'image': 'blop',
                         'exit_code': 23,
                         'output': 'huehuehue',
                         'error': 'hohoho'}
                get_info.return_value = dummy
                resp = self.app.get('/nodes/images/update/51/',
                                    extra_environ=environ, status="*")
                get_info.assert_called_with(u'51')
                self.assertEqual(200, resp.status_int, resp.body)
                j = json.loads(resp.body)
                self.assertTrue('nodepool' in j.keys())
                j = j['nodepool']
                for u in dummy:
                    self.assertEqual(str(dummy[u]), str(j[u]))


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
