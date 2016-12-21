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
from mock import patch, call, MagicMock
from redmine import managers
from redmine.exceptions import ValidationError

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


class TestSFRedmineRoleManager(BaseSFRedmineService):
    def test_is_admin(self):
        self.assertEqual(True,
                         self.redmine.role.is_admin(self.conf.admin['name']))
        self.assertEqual(False,
                         self.redmine.role.is_admin('not_an_admin'))

    def test_get(self):
        with patch.object(RedmineUtils,
                          'get_user_id_by_username') as uid_mock, \
                patch.object(RedmineUtils,
                             'get_project_roles_for_user') as roles_mock:
            uid_mock.return_value = 'test@test'
            roles_mock.return_value = ['Developer']
            self.assertEqual(['Developer'],
                             self.redmine.role.get('test',
                                                   'MyLittleProject'))
            uid_mock.assert_called_with('test')
            roles_mock.assert_called_with('MyLittleProject', 'test@test')


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


class TestSFRedmineMembershipManager(BaseSFRedmineService):
    def test_get_uid(self):
        with patch.object(RedmineUtils, 'get_user_id') as m, \
                patch.object(RedmineUtils, 'get_user_id_by_username') as u:
            u.return_value = None
            m.return_value = 'testuserid2'
            self.assertEqual('testuserid2',
                             self.redmine.membership._get_uid('user'))

    def test_create_failure(self):
        self.assertRaises(exc.UnavailableActionError,
                          self.redmine.membership.create,
                          'requestor', 'a', 'b', ['ptl-group', 'd'])
        with patch.object(self.redmine.role, 'get') as role_get_mock:
            role_get_mock.return_value = ['Developer']
            self.assertRaises(exc.Unauthorized,
                              self.redmine.membership.create,
                              'requestor', 'user',
                              'myproject', ['ptl-group', ])
        with patch.object(self.redmine.role, 'get') as role_get_mock:
            role_get_mock.return_value = ['just_a_random_role']
            self.assertRaises(exc.Unauthorized,
                              self.redmine.membership.create,
                              'requestor', 'user',
                              'myproject', ['core-group', ])
            self.assertRaises(exc.Unauthorized,
                              self.redmine.membership.create,
                              'requestor', 'user',
                              'myproject', ['dev-group', ])

    def test_create_no_prior_membership(self):
        with patch.object(self.redmine.role, 'get') as role_get, \
                patch.object(RedmineUtils, 'get_role_id') as role_id_get, \
                patch.object(self.redmine.membership,
                             '_get_uid') as uid_get, \
                patch.object(RedmineUtils,
                             'get_project_membership_for_user') \
                as project_membership_user_get, \
                patch.object(RedmineUtils,
                             'update_project_membership') \
                as project_membership_update:
            role_get.return_value = ['Manager', 'Developer']
            role_id_get.return_value = 'generic_role_id'
            uid_get.return_value = 'meh'
            project_membership_user_get.return_value = None
            self.redmine.membership.create('requestor',
                                           'test_user',
                                           'test_project',
                                           ['ptl-group',
                                            'core-group',
                                            'dev-group'])
            memberships = {'user_id': 'meh',
                           'role_ids': ['generic_role_id',
                                        'generic_role_id']}
            project_membership_update.assert_called_with('test_project',
                                                         [memberships])

            role_get.return_value = ['Developer', ]
            self.redmine.membership.create('requestor',
                                           'test_user',
                                           'test_project',
                                           ['core-group', ])
            memberships = {'user_id': 'meh',
                           'role_ids': ['generic_role_id', ]}
            project_membership_update.assert_called_with('test_project',
                                                         [memberships])

    def test_create_with_prior_membership(self):
        with patch.object(self.redmine.role,
                          'get') as role_get, \
                patch.object(RedmineUtils, 'get_role_id') as role_id_get, \
                patch.object(self.redmine.membership,
                             '_get_uid') as uid_get, \
                patch.object(RedmineUtils,
                             'get_project_membership_for_user') \
                as project_membership_user_get, \
                patch.object(RedmineUtils,
                             'get_project_roles_for_user') \
                as project_roles_get, \
                patch.object(RedmineUtils,
                             'update_membership') as membership_update:
            role_get.return_value = ['Manager', 'Developer']
            role_id_get.return_value = 'generic_role_id'
            uid_get.return_value = 'meh'
            project_membership_user_get.return_value = 'membership'
            project_roles_get.return_value = [1, ] * 5
            self.redmine.membership.create('requestor',
                                           'test_user',
                                           'test_project',
                                           ['ptl-group',
                                            'core-group',
                                            'dev-group'])
            membership_update.assert_called_with('membership',
                                                 ['generic_role_id', ] * 7)

            role_get.return_value = ['Developer', ]
            self.redmine.membership.create('requestor',
                                           'test_user',
                                           'test_project',
                                           ['core-group', ])
            membership_update.assert_called_with('membership',
                                                 ['generic_role_id', ] * 6)

    def test_delete_failure(self):
        with patch.object(self.redmine.membership, '_get_uid') as a, \
                patch.object(self.redmine.membership, 'get') as b, \
                patch.object(self.redmine.role, 'get') as c, \
                patch.object(RedmineUtils,
                             'get_project_membership_for_user') as d:
            a.return_value = 'testuser'
            b.return_value = 'membership'
            c.return_value = ['Developer', ]
            d.return_value = [1, 2]
            self.assertRaises(exc.Unauthorized,
                              self.redmine.membership.delete,
                              'requestor', 'u', 'proj', None)
            self.assertRaises(exc.UnavailableActionError,
                              self.redmine.membership.delete,
                              'requestor', 'u', 'proj', 'weird-group')
            self.assertRaises(exc.Unauthorized,
                              self.redmine.membership.delete,
                              'requestor', 'u', 'proj', 'ptl-group')
            c.return_value = ['just_any_role', ]
            self.assertRaises(exc.Unauthorized,
                              self.redmine.membership.delete,
                              'requestor', 'u', 'proj', 'dev-group')


class TestSFRedmineProjectManager(BaseSFRedmineService):
    def test_get(self):
        with patch.object(managers.ResourceManager, 'get') as g, \
                patch.object(managers.ResourceManager, 'all') as a:
            g.return_value = ['p_test', ]
            a.return_value = ['p1', 'p2']
            self.assertEqual(['p_test', ],
                             self.redmine.project.get('p/test'))
            g.assert_called_with('p_test')
            self.assertEqual(['p1', 'p2'],
                             self.redmine.project.get())

    def test_create(self):
        with patch.object(self.redmine.project, '_create') as _c, \
                patch.object(self.redmine.membership, 'create') as m_c:
            self.redmine.project.create('ns/prj', 'u')
            _c.assert_called_with('ns_prj', '', False)
            membership_calls = [call(requestor='u',
                                     username='u',
                                     project='ns_prj',
                                     groups=['ptl-group'],
                                     user_is_owner=True),
                                call(requestor='u',
                                     username='u',
                                     project='ns_prj',
                                     groups=['dev-group'])]
            m_c.assert_has_calls(membership_calls)
            m_c.reset_mock()
            _c.reset_mock()
            proj_data = {'description': 'eh',
                         'private': True}
            self.redmine.project.create('p', 'u', proj_data)
            _c.assert_called_with('p', 'eh', True)

    def test_create_project_exists(self):
        with patch.object(self.redmine.project, '_create') as _c, \
                patch.object(self.redmine.membership, 'create') as m_c:
            err = 'Identifier has already been taken'
            _c.side_effect = ValidationError(err)
            self.redmine.project.create('p', 'u')
            # assert that we proceed normally nevertheless
            membership_calls = [call(requestor='u',
                                     username='u',
                                     project='p',
                                     groups=['ptl-group'],
                                     user_is_owner=True),
                                call(requestor='u',
                                     username='u',
                                     project='p',
                                     groups=['dev-group'])]
            m_c.assert_has_calls(membership_calls)
            m_c.reset_mock()
            _c.reset_mock()
            _c.side_effect = ValidationError('Something completely different')
            self.assertRaises(ValidationError,
                              self.redmine.project.create, 'pp', 'uu')

    def test_delete(self):
        with patch.object(self.redmine.role, 'get') as g, \
                patch.object(self.redmine.project, '_delete') as d:
            g.return_value = ['Manager', ]
            self.redmine.project.delete('nss/proj1', 'u')
            d.assert_called_with('nss_proj1')


class TestRedmineGroupManager(BaseSFRedmineService):
    def test_create(self):
        with patch.object(RedmineUtils, 'create_group') as a, \
                patch.object(RedmineUtils, 'get_group_id') as b, \
                patch.object(RedmineUtils, 'get_user_id') as c, \
                patch.object(RedmineUtils, 'set_group_members') as d:
            a.return_value = True
            b.return_value = 1
            c.return_value = 2
            self.redmine.group.create('grp1', 'user1@sftests.com')
            a.assert_called_with('grp1')
            d.assert_called_with(1, [2])
        with patch.object(RedmineUtils, 'create_group') as a, \
                patch.object(RedmineUtils, 'get_group_id') as b, \
                patch.object(RedmineUtils, 'get_user_id') as c, \
                patch.object(RedmineUtils, 'set_group_members') as d:
            a.return_value = None
            self.assertRaises(exc.CreateGroupException,
                              self.redmine.group.create, 'grp1',
                              'user1@sftests.com')

    def test_update(self):
        with patch.object(RedmineUtils, 'get_group_id') as a, \
                patch.object(RedmineUtils, 'get_user_id') as b, \
                patch.object(RedmineUtils, 'set_group_members') as c:
            a.return_value = 1
            b.side_effect = [10, 11]
            self.redmine.group.update('grp1', ['user1@sftests.com',
                                               'user2@sftests.com'])
            c.assert_called_with(1, [10, 11])
        with patch.object(RedmineUtils, 'get_group_id') as a, \
                patch.object(RedmineUtils, 'get_user_id') as b, \
                patch.object(RedmineUtils, 'set_group_members') as c:
            a.return_value = None
            self.assertRaises(exc.GroupNotFoundException,
                              self.redmine.group.update,
                              'grp1',
                              ['user1@sftests.com',
                               'user2@sftests.com'])

    def test_delete(self):
        with patch.object(RedmineUtils, 'get_group_id') as a, \
                patch.object(RedmineUtils, 'delete_group') as b:
            a.return_value = 1
            self.redmine.group.delete('grp1')
            b.assert_called_with(1)
        with patch.object(RedmineUtils, 'get_group_id') as a, \
                patch.object(RedmineUtils, 'delete_group') as b:
            a.return_value = None
            self.assertRaises(exc.GroupNotFoundException,
                              self.redmine.group.delete, 'grp1')
