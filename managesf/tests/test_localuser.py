#
# Copyright (c) 2015 Red Hat, Inc.
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

from mock import patch
from unittest import TestCase

from basicauth import encode

from managesf.controllers import localuser
from managesf.tests import dummy_conf


class TestLocaluserController(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()
        localuser.conf = cls.conf
        localuser.model.conf = cls.conf

    def setUp(self):
        localuser.model.init_model()

    def tearDown(self):
        os.unlink(self.conf.sqlalchemy['url'][len('sqlite:///'):])

    @patch('managesf.controllers.localuser.request')
    def test_add_user_as_admin(self, request_mock):
        request_mock.remote_user = self.conf.admin['name']
        infos = {'fullname': 'John Doe',
                 'email': 'john@tests.dom',
                 'password': "abc"}
        localuser.update_user('john', infos)
        expected = {'username': 'john',
                    'fullname': 'John Doe',
                    'email': 'john@tests.dom',
                    'sshkey': 'None'}
        ret = localuser.model.get_user('john')
        del ret['hashed_password']
        self.assertDictEqual(ret, expected)

    @patch('managesf.controllers.localuser.request')
    def test_add_user_as_not_admin(self, request_mock):
        request_mock.remote_user = 'denis'
        infos = {'fullname': 'John Doe',
                 'email': 'john@tests.dom',
                 'password': "abc"}
        self.assertRaises(localuser.AddUserForbidden,
                          lambda: localuser.update_user('john', infos))

    @patch('managesf.controllers.localuser.request')
    def test_add_user_admin(self, request_mock):
        request_mock.remote_user = self.conf.admin['name']
        infos = {'fullname': 'I am root',
                 'email': 'john@tests.dom',
                 'password': "abc"}
        self.assertRaises(localuser.AddUserForbidden,
                          lambda: localuser.update_user(
                              self.conf.admin['name'],
                              infos))

    @patch('managesf.controllers.localuser.request')
    def test_add_update_user_bad_input(self, request_mock):
        request_mock.remote_user = self.conf.admin['name']
        infos = {'fullname': 'John Doe',
                 'email': 'john@tests.dom',
                 'hashed_password': "abc"}
        self.assertRaises(localuser.InvalidInfosInput,
                          lambda: localuser.update_user('john', infos))

    @patch('managesf.controllers.localuser.request')
    def test_update_user_as_admin(self, request_mock):
        request_mock.remote_user = self.conf.admin['name']
        infos = {'fullname': 'John Doe',
                 'email': 'john@tests.dom',
                 'password': "abc"}
        localuser.update_user('john', infos)
        infos = {'fullname': 'Maria Doe',
                 'email': 'maria@tests.dom',
                 'password': "abc"}
        localuser.update_user('john', infos)
        expected = {'username': 'john',
                    'fullname': 'Maria Doe',
                    'email': 'maria@tests.dom',
                    'sshkey': 'None'}
        ret = localuser.model.get_user('john')
        del ret['hashed_password']
        self.assertDictEqual(ret, expected)

    @patch('managesf.controllers.localuser.request')
    def test_update_user_as_owner(self, request_mock):
        request_mock.remote_user = self.conf.admin['name']
        infos = {'fullname': 'John Doe',
                 'email': 'john@tests.dom',
                 'password': "abc"}
        localuser.update_user('john', infos)
        # John trying to update its account
        request_mock.remote_user = 'john'
        infos = {'fullname': 'Maria Doe',
                 'email': 'maria@tests.dom',
                 'password': "abc"}
        localuser.update_user('john', infos)
        expected = {'username': 'john',
                    'email': 'maria@tests.dom',
                    'fullname': 'Maria Doe',
                    'sshkey': 'None'}
        ret = localuser.model.get_user('john')
        del ret['hashed_password']
        self.assertDictEqual(ret, expected)

    @patch('managesf.controllers.localuser.request')
    def test_update_user_as_not_owner(self, request_mock):
        request_mock.remote_user = self.conf.admin['name']
        infos = {'fullname': 'John Doe',
                 'email': 'john@tests.dom',
                 'password': "abc"}
        localuser.update_user('john', infos)
        # Denis trying to update john account
        request_mock.remote_user = 'denis'
        infos['fullname'] = 'Maria Doe'
        self.assertRaises(localuser.UpdateUserForbidden,
                          lambda: localuser.update_user('john', infos))

    @patch('managesf.controllers.localuser.request')
    def test_delete_user_as_admin(self, request_mock):
        request_mock.remote_user = self.conf.admin['name']
        infos = {'fullname': 'John Doe',
                 'email': 'john@tests.dom',
                 'password': "abc"}
        localuser.update_user('john', infos)
        self.assertIsInstance(localuser.model.get_user('john'), dict)
        localuser.delete_user('john')
        self.assertFalse(localuser.model.get_user('john'))
        # Also test good behavior trying to remove user that not exixt
        self.assertRaises(localuser.UserNotFound,
                          lambda: localuser.delete_user('john'))

    @patch('managesf.controllers.localuser.request')
    def test_delete_user_as_user(self, request_mock):
        request_mock.remote_user = self.conf.admin['name']
        infos = {'fullname': 'John Doe',
                 'email': 'john@tests.dom',
                 'password': "abc"}
        localuser.update_user('john', infos)
        request_mock.remote_user = 'denis'
        self.assertRaises(localuser.DeleteUserForbidden,
                          lambda: localuser.delete_user('john'))

    @patch('managesf.controllers.localuser.request')
    def test_get_user(self, request_mock):
        request_mock.remote_user = self.conf.admin['name']
        infos = {'fullname': 'John Doe',
                 'email': 'john@tests.dom',
                 'password': "abc"}
        localuser.update_user('john', infos)
        expected = {'username': 'john',
                    'email': 'john@tests.dom',
                    'fullname': 'John Doe',
                    'sshkey': 'None'}
        ret = localuser.model.get_user('john')
        del ret['hashed_password']
        self.assertDictEqual(ret, expected)
        request_mock.remote_user = 'denis'
        self.assertRaises(localuser.GetUserForbidden,
                          lambda: localuser.get_user('john'))
        request_mock.remote_user = 'john'
        ret = localuser.model.get_user('john')
        del ret['hashed_password']
        self.assertDictEqual(ret, expected)
        request_mock.remote_user = self.conf.admin['name']
        self.assertRaises(localuser.UserNotFound,
                          lambda: localuser.get_user('maria'))

    @patch('managesf.controllers.localuser.request')
    def test_bind_user(self, request_mock):
        request_mock.remote_user = self.conf.admin['name']
        infos = {'fullname': 'John Doe',
                 'email': 'john@tests.dom',
                 'password': "abc"}
        localuser.update_user('john', infos)
        authorization = encode('john', "abc")
        self.assertTrue(localuser.bind_user(authorization), True)
        authorization = encode('john', "abc123")
        self.assertRaises(localuser.BindForbidden,
                          lambda: localuser.bind_user(authorization))
        authorization = encode('denis', "abc")
        self.assertRaises(localuser.UserNotFound,
                          lambda: localuser.bind_user(authorization))
