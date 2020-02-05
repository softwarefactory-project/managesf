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
from mock import patch, MagicMock

from basicauth import encode

from managesf.tests import dummy_conf

from managesf.services import exceptions as exc

# plugins imports
# TODO: should be done dynamically depending on what plugins we want

from managesf.services.gerrit.project import SFGerritProjectManager
from managesf.services.gerrit import user as g_user


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
                       'managesf': c.managesf,
                       'policy': c.policy,
                       'resources': c.resources,
                       'api': c.api, }
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


class TestManageSFAPIv2(FunctionalTest):
    def test_get_api_endpoint(self):
        response = self.app.get('/v2/about/').json
        self.assertEqual('managesf',
                         response['service']['name'])
        self.assertEqual(set(self.config['services']),
                         set(response['service']['services']))


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

            auth = encode(u"john", "secret")
            response = self.app.get(
                '/bind', headers={"Authorization": auth}, status="*")
            self.assertEqual(response.status_int, 200)
            self.assertEqual(public_infos,
                             response.json,
                             response.json)

            auth = encode(u"john", "badsecret")
            response = self.app.get(
                '/bind', headers={"Authorization": auth}, status="*")
            self.assertEqual(response.status_int, 401)

            auth = encode(u"boss", "secret")
            response = self.app.get(
                '/bind', headers={"Authorization": auth}, status="*")
            self.assertEqual(response.status_int, 401)


def project_get(*args, **kwargs):
    if kwargs.get('by_user'):
        return ['p1', ]
    return ['p0', 'p1']


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
        with patch.object(g_user.SFGerritUserManager,
                          'create') as gerrit_create, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch.object(SFGerritProjectManager,
                             'get_user_groups'):
            g_get.return_value = None
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
        with patch('managesf.services.gerrit.utils.'
                   'GerritClient.add_pubkey'), \
                patch.object(g_user.SFGerritUserManager,
                             '_add_account_as_external'), \
                patch('managesf.services.gerrit.utils.'
                      'GerritClient.create_account') \
                as create_account, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups'):
            create_account.return_value = gerrit2_created
            g_get.return_value = None
            response = self.app.post_json('/services_users/', infos2,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)

        with patch.object(g_user.SFGerritUserManager,
                          'create') as gerrit_create, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch.object(SFGerritProjectManager,
                             'get_user_groups'):
            # assert that raising UnavailableActionError won't fail
            def unavailable(*args, **kwargs):
                raise exc.UnavailableActionError
            g_get.side_effect = unavailable
            gerrit_create.return_value = 14
            response = self.app.post_json('/services_users/', infos3,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)

        with patch.object(g_user.SFGerritUserManager,
                          '_add_account_as_external'), \
                patch('managesf.services.gerrit.utils.'
                      'GerritClient.create_account') \
                as create_account, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups'):

            g_get.return_value = gerrit_created["_account_id"]
            create_account.return_value = gerrit_created
            response = self.app.post_json('/services_users/', infos,
                                          extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 201)

        with patch.object(g_user.SFGerritUserManager,
                          '_add_account_as_external'), \
                patch('managesf.services.gerrit.utils.'
                      'GerritClient.create_account') \
                as create_account, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups'):
            # assert that user found in backend will skip gracefully
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
        with patch.object(g_user.SFGerritUserManager,
                          'delete') as gerrit_delete, \
                patch.object(g_user.SFGerritUserManager,
                             'create') as gerrit_create, \
                patch.object(g_user.SFGerritUserManager,
                             'get') as gerrit_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups') as gug:
            gug.return_value = []
            # Test deletion of non existing user
            response = self.app.delete('/services_users/?username=iggy',
                                       extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 404)
            # test deletion of existing user
            gerrit_create.return_value = 99
            gerrit_get.return_value = None
            self.app.post_json('/services_users/', infos,
                               extra_environ=environ, status="*")
            response = self.app.delete('/services_users/?username=iggy',
                                       extra_environ=environ, status="*")
            self.assertEqual(response.status_int, 204)
            gerrit_delete.assert_called_with(username='iggy')

    def test_all(self):
        environ = {'REMOTE_USER': 'admin'}
        infos_kira = {'email': 'kira@jojolion.dom',
                      'ssh_keys': ['ora', 'oraora'],
                      'full_name': 'yoshikage kira', 'username': 'kira'}
        with patch.object(g_user.SFGerritUserManager, 'delete'), \
                patch.object(g_user.SFGerritUserManager,
                             'create') as g_create, \
                patch.object(g_user.SFGerritUserManager, 'get') as g_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups'):

            g_get.return_value = None
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
        with patch.object(g_user.SFGerritUserManager, 'delete'), \
                patch.object(g_user.SFGerritUserManager,
                             'create') as g_create, \
                patch.object(g_user.SFGerritUserManager,
                             'get') as g_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups') as gug:

            g_get.return_value = None
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
        with patch.object(g_user.SFGerritUserManager, 'update') as g_up, \
                patch.object(g_user.SFGerritUserManager,
                             'create') as g_create, \
                patch.object(g_user.SFGerritUserManager,
                             'get') as g_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups'):
            for mock in (g_up, g_get):
                mock.return_value = None
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
        with patch.object(g_user.SFGerritUserManager,
                          'create') as g_create, \
                patch.object(g_user.SFGerritUserManager,
                             'update') as g_update, \
                patch.object(g_user.SFGerritUserManager,
                             'get') as g_get, \
                patch.object(SFGerritProjectManager, 'get_user_groups') as gug:

            gug.return_value = []
            for mock in (g_get, g_update):
                mock.return_value = None
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
            # try empty payload
            for i in ('admin', infos_jojo['username']):
                environ = {'REMOTE_USER': i}
                payload = {}
                resp = self.app.put_json('/services_users/?username=jojo',
                                         payload,
                                         extra_environ=environ, status="*")
                self.assertEqual(400, resp.status_int)
                self.assertTrue(b'Nothing to do' in resp.body)
                resp = self.app.put_json(
                    '/services_users/?email=jojo@starplatinum.dom',
                    payload, extra_environ=environ, status="*")
                self.assertEqual(400, resp.status_int)
                self.assertTrue(b'Nothing to do' in resp.body)
                resp = self.app.put_json(
                    '/services_users/?id=%s' % jojo_id,
                    payload, extra_environ=environ, status="*")
                self.assertEqual(400, resp.status_int)
                self.assertTrue(b'Nothing to do' in resp.body)
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
