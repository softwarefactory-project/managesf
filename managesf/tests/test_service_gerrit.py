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
from mock import patch

from managesf.tests import dummy_conf
from managesf.services import gerrit


class BaseSFGerritService(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()
        cls.gerrit = gerrit.SoftwareFactoryGerrit(cls.conf)


class TestSFGerritUserManager(BaseSFGerritService):
    user_data = {"_account_id": 5,
                 "name": "Jotaro Kujoh",
                 "email": "jojo@starplatinum.dom",
                 "username": "jojo",
                 "avatars": [{"url": "meh",
                              "height": 26}]}

    def test_update(self):
        # TODO: implement it
        pass

    def test_create(self):
        with patch.object(self.gerrit.user,
                          '_add_account_as_external') as add_external, \
                    patch('managesf.services.gerrit.utils.GerritClient.'
                          'create_account') as create:
            create.return_value = self.user_data
            self.gerrit.user.create('jojo', 'jojo@starplatinum.dom',
                                    'Jotaro Kujoh', None, 10)
            _user = {'name': str('Jotaro Kujoh'),
                     'email': str('jojo@starplatinum.dom')}
            create.assert_called_with('jojo', _user)
            add_external.assert_called_with(5, 'jojo')
            create.reset_mock()
            _user["ssh_key"] = 'bop'
            self.gerrit.user.create('jojo', 'jojo@starplatinum.dom',
                                    'Jotaro Kujoh', [{'key': 'bop'}], 10)
            create.assert_called_with('jojo', _user)
        # Test fringe case where we try to create the admin user
        self.assertEqual(1,
                         self.gerrit.user.create(None, 'dio@wryyyyy.org',
                                                 'Dio Brando', None, 1))
        # TODO: Add case where the user exists and update is called by create

    def test_get(self):
        with patch('managesf.services.gerrit.utils.GerritClient.'
                   'get_account') as get:
            get.return_value = self.user_data
            u = self.gerrit.user.get('jojo')
            get.assert_called_with('jojo')
            self.assertEqual(5, u)

    def test_delete(self):
        self.assertEquals(self.gerrit.user.delete('jojo'), None)
