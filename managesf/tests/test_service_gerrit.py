#!/usr/bin/env python
#
# Copyright (C) 2015  Red Hat <licensing@enovance.com>
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

from unittest import TestCase
from mock import patch, call

from managesf.tests import dummy_conf
from managesf.services import gerrit
from pysflib.sfgerrit import GerritUtils


class BaseSFGerritService(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()
        cls.gerrit = gerrit.SoftwareFactoryGerrit(cls.conf)
        cls.auth_patch = patch('managesf.services.gerrit.get_cookie')
        cls.auth_patch.start()

    @classmethod
    def tearDownClass(cls):
        cls.auth_patch.stop()


class TestSFGerritUserManager(BaseSFGerritService):
    user_data = {"_account_id": 5,
                 "name": "Jotaro Kujoh",
                 "email": "jojo@starplatinum.dom",
                 "username": "jojo",
                 "avatars": [{"url": "meh",
                              "height": 26}]}

    def test_create(self):
        with patch.object(self.gerrit.user,
                          '_add_account_as_external') as add_external, \
                    patch.object(self.gerrit.user,
                                 '_add_sshkeys') as add_sshkeys, \
                    patch('pysflib.sfgerrit.GerritUtils.'
                          'create_account') as create:
            create.return_value = self.user_data
            self.gerrit.user.create('jojo', 'jojo@starplatinum.dom',
                                    'Jotaro Kujoh')
            _user = {'name': unicode('Jotaro Kujoh'),
                     'email': unicode('jojo@starplatinum.dom')}
            create.assert_called_with('jojo',
                                      _user)
            add_external.assert_called_with(5, 'jojo')
            self.gerrit.user.create('jojo', 'jojo@starplatinum.dom',
                                    'Jotaro Kujoh',
                                    ssh_keys=[{'key': 'bop'}])
            add_sshkeys.assert_called_with('jojo',
                                           [{'key': 'bop'}])
        # Test fringe case where we try to create the admin user
        self.assertEqual(1,
                         self.gerrit.user.create(None, 'dio@wryyyyy.org',
                                                 'Dio Brando',
                                                 cauth_id=1))

    def test_get(self):
        self.assertRaises(TypeError,
                          self.gerrit.user.get)
        self.assertRaises(TypeError,
                          self.gerrit.user.get,
                          'mail@address.com', 'extra_user_param')
        with patch('pysflib.sfgerrit.GerritUtils.get_account') as get:
            get.return_value = self.user_data
            u = self.gerrit.user.get(email='jojo@starplatinum.dom')
            get.assert_called_with('jojo@starplatinum.dom')
            self.assertEqual(5,
                             u)

    def test_delete(self):
        self.assertRaises(TypeError,
                          self.gerrit.user.delete)
        self.assertRaises(TypeError,
                          self.gerrit.user.delete,
                          'mail@address.com', 'username')
        with patch.object(self.gerrit.user, 'get') as get, \
                patch.object(self.gerrit.user, 'session') as session, \
                patch('managesf.services.gerrit.user.G.Gerrit._ssh') as ssh:
            get.return_value = self.user_data['_account_id']
            sql = """DELETE FROM account_group_members WHERE account_id=5;
DELETE FROM accounts WHERE account_id=5;
DELETE FROM account_external_ids WHERE account_id=5;"""
            self.gerrit.user.delete(email='jojo@starplatinum.dom')
            session.execute.assert_called_with(sql)
            calls = [call('gerrit flush-caches --cache %s' % c)
                     for c in ('accounts', 'accounts_byemail',
                               'accounts_byname', 'groups_members')]
            ssh.assert_has_calls(calls)
            session.reset_mock()
            ssh.reset_mock()
            self.gerrit.user.delete(username='jojo@starplatinum.dom')
            session.execute.assert_called_with(sql)
            calls = [call('gerrit flush-caches --cache %s' % c)
                     for c in ('accounts', 'accounts_byemail',
                               'accounts_byname', 'groups_members')]
            ssh.assert_has_calls(calls)


def ggi_side_effect(grp_name):
    return {'testproject-ptl': 'ptl_gid',
            'testproject-core': 'core_gid',
            'testproject-dev': 'dev_gid', }[grp_name]


class TestSFGerritGroupManager(BaseSFGerritService):
    def test_get(self):
        with patch.object(GerritUtils, 'get_project_groups_id') as a, \
                patch.object(GerritUtils, 'get_projects'), \
                patch.object(GerritUtils, 'get_group_id') as c, \
                patch.object(GerritUtils, 'get_group_members') as d, \
                patch.object(GerritUtils, 'get_groups'):
            a.return_value = {'p1': {'owners': ['1'],
                                     'others': ['2']}}
            c.return_value = 3
            d.return_value = ['user1@sftests.com']
            ret = self.gerrit.group.get('grp1')
            self.assertIn('user1@sftests.com', ret['grp1'])
