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
from mock import patch, MagicMock
from redmine import managers

from managesf.services import exceptions as exc
from managesf.services import redmine
from managesf.tests import dummy_conf
from pysflib.sfredmine import RedmineUtils


class BaseSFRedmineService(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()
        cls.redmine = redmine.SoftwareFactoryRedmine(cls.conf)

    @classmethod
    def tearDownClass(cls):
        pass


class TestSFRedmineGetAPIKey(BaseSFRedmineService):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()
        cls.redmine = redmine.SoftwareFactoryRedmine(cls.conf)
        cls.api_key = cls.conf.redmine['api_key']

    def test_get_api_key_from_conf(self):
        self.assertEqual(self.conf.redmine['api_key'],
                         self.redmine._get_api_key())

    @patch('managesf.services.redmine.create_engine')
    def test_get_api_key_from_db(self, c_e):
        engine = MagicMock()
        engine.execute.return_value = ((('value', 'abcd'),),)
        c_e.return_value = engine
        del self.conf.redmine['api_key']
        self.conf.redmine['db_url'] = 'mocksql://..'
        red = redmine.SoftwareFactoryRedmine(self.conf)
        self.assertEqual('abcd',
                         red._get_api_key())

    @classmethod
    def tearDownClass(cls):
        cls.conf.redmine['api_key'] = cls.api_key
        del cls.conf.redmine['db_url']


class TestSFRedmineHooksManager(BaseSFRedmineService):
    def test_hooks_are_present(self):
        self.assertRaises(exc.UnavailableActionError,
                          self.redmine.hooks.just_a_random_hook,
                          'dummy arg')

    def test_patch_created(self):
        args = ('change', 'is_draft', 'change_url', 'project',
                'branch', 'topic', 'uploader', 'commit',
                'patchset', 'commit_message')
        kwargs = dict((k, None) for k in args)
        with patch.object(RedmineUtils,
                          'set_issue_status') as set_issue_status:
            kwargs['patchset'] = 12
            self.assertEqual('Do nothing as the patchset is not the first',
                             self.redmine.hooks.patchset_created(**kwargs))
            kwargs['patchset'] = 1
            kwargs['project'] = 'aaa'
            kwargs['commit'] = 123
            kwargs['branch'] = 'test_branch'
            kwargs['change_url'] = 'ccc'
            kwargs['submitter'] = 'doe'
            kwargs['commit_message'] = 'super patch'
            msg = "No issue found in the commit message, nothing to do."
            self.assertEqual(msg,
                             self.redmine.hooks.patchset_created(**kwargs))
            kwargs['commit_message'] = 'super patch Related-To: #1234'
            msg = "Success"
            ticket_msg = """Fix proposed to branch: test_branch by doe
Review: ccc
"""
            self.assertEqual(msg,
                             self.redmine.hooks.patchset_created(**kwargs))
            set_issue_status.assert_called_with('1234',
                                                2,
                                                message=ticket_msg)
            kwargs['commit_message'] = 'super patch Closes-Bug: #1234'
            self.assertEqual(msg,
                             self.redmine.hooks.patchset_created(**kwargs))
            set_issue_status.assert_called_with('1234',
                                                2,
                                                message=ticket_msg)
            set_issue_status.return_value = False
            msg = "Could not change status of issue #1234"
            try:
                self.redmine.hooks.patchset_created(**kwargs)
                self.assertFail()
            except Exception as e:
                self.assertEqual(msg,
                                 unicode(e))
            kwargs['commit_message'] = 'uuu Related: #789 Fix: #1234'
            try:
                self.redmine.hooks.patchset_created(**kwargs)
                self.assertFail()
            except Exception as e:
                self.assertEqual(msg,
                                 unicode(e))

    def test_change_merged(self):
        args = ('change', 'change_url', 'project',
                'branch', 'topic', 'submitter', 'commit')
        kwargs = dict((k, None) for k in args)
        with patch.object(RedmineUtils,
                          'set_issue_status') as set_issue_status:
            kwargs['project'] = 'aaa'
            kwargs['commit'] = 123
            kwargs['branch'] = 'test_branch'
            kwargs['topic'] = 'super_duper'
            kwargs['change_url'] = 'ccc'
            kwargs['submitter'] = 'doe'
            kwargs['commit_message'] = 'super patch'
            msg = "No issue found in the commit message, nothing to do."
            self.assertEqual(msg,
                             self.redmine.hooks.change_merged(**kwargs))
            kwargs['commit_message'] = 'super patch Related-To: #1234'
            msg = "Success"
            ticket_msg = ('The following change on Gerrit has been merged to: '
                          'test_branch\nReview: ccc\nSubmitter: doe\n\nCommit '
                          'message:\nsuper patch Related-To: #1234\n\ngitweb: '
                          'http://redmine.tests.dom/r/gitweb?'
                          'p=aaa.git;a=commit;h=123\n')
            self.assertEqual(msg,
                             self.redmine.hooks.change_merged(**kwargs))
            set_issue_status.assert_called_with('1234',
                                                2,
                                                message=ticket_msg)
            kwargs['commit_message'] = 'super patch Closes-Bug: #1234'
            ticket_msg = ('The following change on Gerrit has been merged to: '
                          'test_branch\nReview: ccc\nSubmitter: doe\n\nCommit '
                          'message:\nsuper patch Closes-Bug: #1234\n\ngitweb: '
                          'http://redmine.tests.dom/r/gitweb?'
                          'p=aaa.git;a=commit;h=123\n')
            self.assertEqual(msg,
                             self.redmine.hooks.change_merged(**kwargs))
            set_issue_status.assert_called_with('1234',
                                                5,
                                                message=ticket_msg)
            set_issue_status.return_value = False
            msg = "Could not change status of issue #1234"
            try:
                self.redmine.hooks.change_merged(**kwargs)
                self.assertFail()
            except Exception as e:
                self.assertEqual(msg,
                                 unicode(e))
            kwargs['commit_message'] = 'uuu Related: #789 Fix: #1234'
            try:
                self.redmine.hooks.change_merged(**kwargs)
                self.assertFail()
            except Exception as e:
                self.assertEqual(msg,
                                 unicode(e))


class TestSFRedmineUserManager(BaseSFRedmineService):
    def test_create(self):
        with patch.object(RedmineUtils, 'create_user') as cu_mock:
            self.redmine.user.create('test_username',
                                     'test@test',
                                     'test_lastname')
            cu_mock.assert_called_with('test_username',
                                       'test@test',
                                       'test_lastname')

    def test_get(self):
        self.assertRaises(exc.UnavailableActionError,
                          self.redmine.user.get)
        self.assertRaises(exc.UnavailableActionError,
                          self.redmine.user.get,
                          'mail@address.com', 'extra_user_param')
        with patch.object(RedmineUtils, 'get_user_id') as g:
            g.return_value = 'testuserid'
            self.assertEqual('testuserid',
                             self.redmine.user.get(email='mail@address.com'))
        with patch.object(RedmineUtils, 'get_user_id_by_username') as g:
            g.return_value = 'testuserid'
            self.assertEqual('testuserid',
                             self.redmine.user.get(username='testy'))

    def test_delete(self):
        self.assertRaises(TypeError,
                          self.redmine.user.delete)
        self.assertRaises(TypeError,
                          self.redmine.user.delete,
                          'mail@address.com', 'username')
        with patch.object(RedmineUtils, 'get_user_id') as gui, \
                patch.object(managers.ResourceManager, 'delete') as d, \
                patch.object(RedmineUtils, 'get_user_id_by_username') as guib:
            gui.return_value = 1
            guib.return_value = 2
            self.redmine.user.delete(username='blip')
            d.assert_called_with(2)
            self.redmine.user.delete(email='blip')
            d.assert_called_with(1)


class TestSFRedmineBackupManager(BaseSFRedmineService):
    # placeholder
    pass
