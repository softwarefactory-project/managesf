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
from mock import patch, call, Mock
from contextlib import nested
from gerritlib.gerrit import Gerrit


from managesf.services import exceptions as exc
from managesf.services import gerrit
from managesf.tests import dummy_conf
from pysflib.sfgerrit import GerritUtils
from managesf.services.gerrit import utils


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


class TestSFGerritRoleManager(BaseSFGerritService):
    def test_is_admin(self):
        self.assertEqual(True,
                         self.gerrit.role.is_admin(self.conf.admin['name']))
        self.assertEqual(False,
                         self.gerrit.role.is_admin('not_an_admin'))

    def test_create(self):
        patches = [patch.object(GerritUtils,
                                'create_group'),
                   patch.object(GerritUtils,
                                'add_group_member'), ]
        with nested(*patches) as (c, a):
            self.gerrit.role.create("requestor", "rolename", "")
            c.assert_called_with("rolename", "No description available")
            a.assert_called_with("requestor", "rolename")

    def test_delete(self):
        patches = [patch.object(Gerrit, '_ssh'), ]
        with nested(*patches) as s:
            s[0].return_value = (0, 0)
            self.gerrit.role.delete('bad_role')
            tables = ['account_group_members',
                      'account_group_members_audit',
                      'account_group_by_id',
                      'account_group_by_id_aud',
                      'account_groups']
            cmd = 'gerrit gsql -c \'delete from %(table)s where ' \
                  'group_id=(%(grp_id)s)\''
            grp_id = "select group_id from account_group_names " \
                     "where name=\"bad_role\""
            calls = [call(cmd % {'table': t, 'grp_id': grp_id})
                     for t in tables]
            cmd = 'gerrit gsql -c \'delete from account_group_names ' \
                  'where name=\"bad_role\"'
            calls.append(call(cmd))
            s[0].assert_has_calls(calls)


class TestSFGerritUserManager(BaseSFGerritService):
    user_data = ''')]}\'
{
  "_account_id": 5,
  "name": "Jotaro Kujoh",
  "email": "jojo@starplatinum.dom",
  "username": "jojo",
  "avatars": [
    {
      "url": "meh",
      "height": 26
    }
  ]
}'''

    def test_create(self):
        patches = [patch.object(self.gerrit.user, '_add_account_as_external'),
                   patch.object(self.gerrit.user, '_add_sshkeys'),
                   patch('managesf.services.gerrit.user.requests.get'),
                   patch('managesf.services.gerrit.user.requests.put'),
                   patch('managesf.services.gerrit.get_cookie'), ]
        with nested(*patches) as (add_external, add_sshkeys,
                                  get, put, get_cookie):
            get.return_value = Mock(status_code=200, content=self.user_data)
            get_cookie.return_value = 'admin_cookie'
            self.gerrit.user.create('jojo', 'jojo@starplatinum.dom',
                                    'Jotaro Kujoh')
            url = "%s/r/a/accounts/%s" % (self.gerrit.conf['url'],
                                          'jojo')
            h = {"Content-type": "application/json"}
            cookies = {'auth_pubtkt': 'admin_cookie'}
            get.assert_called_with(url,
                                   headers=h,
                                   cookies=cookies)
            add_external.assert_called_with(5, 'jojo')
            self.gerrit.user.create('jojo', 'jojo@starplatinum.dom',
                                    'Jotaro Kujoh',
                                    ssh_keys=[{'key': 'bop'}])
            add_sshkeys.assert_called_with('jojo',
                                           [{'key': 'bop'}],
                                           cookies)

    def test_get(self):
        self.assertRaises(TypeError,
                          self.gerrit.user.get)
        self.assertRaises(TypeError,
                          self.gerrit.user.get,
                          'mail@address.com', 'extra_user_param')
        patches = [patch('managesf.services.gerrit.get_cookie'),
                   patch('managesf.services.gerrit.user.requests.get'), ]
        with nested(*patches) as (get_cookie, get, ):
            get.return_value = Mock(status_code=200, content=self.user_data)
            get_cookie.return_value = 'admin_cookie'
            u = self.gerrit.user.get(email='jojo@starplatinum.dom')
            url = "%s/r/a/accounts/%s" % (self.gerrit.conf['url'],
                                          'jojo@starplatinum.dom')
            h = {"Content-type": "application/json"}
            cookies = {'auth_pubtkt': 'admin_cookie'}
            get.assert_called_with(url,
                                   headers=h,
                                   cookies=cookies)
            self.assertEqual('jojo',
                             u['username'])

    def test_delete(self):
        self.assertRaises(TypeError,
                          self.gerrit.user.delete)
        self.assertRaises(TypeError,
                          self.gerrit.user.delete,
                          'mail@address.com', 'username')
        patches = [patch('managesf.services.gerrit.user.requests.get'),
                   patch.object(self.gerrit.user, 'session'),
                   patch('managesf.services.gerrit.user.G.Gerrit._ssh'), ]
        with nested(*patches) as (get, session, ssh):
            get.return_value = Mock(status_code=200, content=self.user_data)
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


class TestSFGerritBackupManager(BaseSFGerritService):
    # placeholder
    pass


class TestSFGerritRepositoryManager(BaseSFGerritService):
    def test_create(self):
        patches = [patch.object(GerritUtils,
                                'get_group_id'),
                   patch.object(utils.GerritRepo,
                                'clone'),
                   patch.object(utils.GerritRepo,
                                'push_config'),
                   patch.object(utils.GerritRepo,
                                'push_master')]

        def ggi(prj):
            return {'ore': 1, 'ptl': 2, 'dev': 3}.get(prj[-3:], 0)

        with nested(*patches) as (get_group_id,
                                  clone,
                                  push_config,
                                  push_master):
            get_group_id.side_effect = ggi
            self.gerrit.repository.create('proj', 'proj description',
                                          None,
                                          False)

            proj_conf = ('[project]\n'
                         '\tdescription = proj description\n'
                         '[access "refs/*"]\n'
                         '  read = group proj-core\n'
                         '  owner = group proj-ptl\n'
                         '[access "refs/heads/*"]\n'
                         '\tlabel-Code-Review = -2..+2 group proj-core\n'
                         '\tlabel-Code-Review = -2..+2 group proj-ptl\n'
                         '\tlabel-Verified = -2..+2 group proj-ptl\n'
                         '\tlabel-Workflow = -1..+1 group proj-core\n'
                         '\tlabel-Workflow = -1..+1 group proj-ptl\n'
                         '\tlabel-Workflow = -1..+0 group Registered Users\n'
                         '\tsubmit = group proj-ptl\n'
                         '\tread = group proj-core\n'
                         '    read = group Registered Users\n'
                         '[access "refs/meta/config"]\n'
                         '    read = group proj-core\n'
                         '    read = group Registered Users\n'
                         '[receive]\n'
                         '\trequireChangeId = true\n'
                         '[submit]\n'
                         '\tmergeContent = false\n'
                         '\taction = fast forward only\n')

            config_paths = {'project.config': proj_conf,
                            'groups': ('# UUID          Group Name\n'
                                       '0 \tNon-Interactive Users\n'
                                       '1       \tproj-core\n'
                                       '2        \tproj-ptl\n'
                                       'global:Registered-Users\t'
                                       '\tRegistered Users\n')}
            push_config.assert_called_with(config_paths)
            gitreview = '''[gerrit]
host=tests.dom
port=2929
project=proj
defaultbranch=master
'''
            master_paths = {'.gitreview': gitreview}
            push_master.assert_called_with(master_paths)


def ggi_side_effect(grp_name):
    return {'testproject-ptl': 'ptl_gid',
            'testproject-core': 'core_gid',
            'testproject-dev': 'dev_gid', }[grp_name]


class TestSFGerritMembershipManager(BaseSFGerritService):

    def test_create_failure(self):
        self.assertRaises(exc.UnavailableActionError,
                          self.gerrit.membership.create,
                          'requestor', 'a', 'b', ['ptl-group', 'd'])
        patches = [patch.object(GerritUtils,
                                'get_user_groups_id'),
                   patch.object(GerritUtils,
                                'get_group_id'),
                   patch.object(self.gerrit.role,
                                'is_admin'), ]
        with nested(*patches) as (gmg, ggi, ia):
            gmg.return_value = ['1', '2', '3']
            ggi.return_value = '4'
            ia.return_value = False
            self.assertRaises(exc.Unauthorized,
                              self.gerrit.membership.create,
                              'requestor', 'user',
                              'myproject', ['ptl-group', ])
            self.assertRaises(exc.Unauthorized,
                              self.gerrit.membership.create,
                              'requestor', 'user',
                              'myproject', ['core-group', ])
        patches.append(patch.object(GerritUtils,
                                    'group_exists'))
        with nested(*patches) as (gmg, ggi, ia, ge):
            gmg.return_value = ['1', '2', '3']
            ggi.return_value = '4'
            ia.return_value = False
            ge.return_value = True
            self.assertRaises(exc.Unauthorized,
                              self.gerrit.membership.create,
                              'requestor', 'user',
                              'myproject', ['dev-group', ])

    def test_create(self):
        patches = [patch.object(GerritUtils,
                                'get_user_groups_id'),
                   patch.object(GerritUtils,
                                'get_group_id'),
                   patch.object(self.gerrit.role,
                                'is_admin'),
                   patch.object(GerritUtils,
                                'add_group_member'),
                   patch.object(GerritUtils,
                                'group_exists'), ]

        # Testing a ptl requestor
        with nested(*patches) as (get_my_groups_id,
                                  get_group_id,
                                  is_admin,
                                  add_group_member,
                                  group_exists):
            get_my_groups_id.return_value = ('ptl_gid', )
            get_group_id.side_effect = ggi_side_effect
            is_admin.return_value = False
            group_exists.return_value = True
            self.gerrit.membership.create('requestor',
                                          'test_user',
                                          'testproject',
                                          ['ptl-group',
                                           'core-group',
                                           'dev-group'])
            calls = [call('test_user', 'testproject-ptl'),
                     call('test_user', 'testproject-core'),
                     call('test_user', 'testproject-dev'), ]
            add_group_member.assert_has_calls(calls)
        with nested(*patches) as (get_my_groups_id,
                                  get_group_id,
                                  is_admin,
                                  add_group_member,
                                  group_exists):
            get_my_groups_id.return_value = ('ptl_gid', )
            get_group_id.side_effect = ggi_side_effect
            is_admin.return_value = False
            group_exists.return_value = True
            self.gerrit.membership.create('requestor',
                                          'test_user',
                                          'testproject',
                                          ['core-group',
                                           'dev-group'])
            calls = [call('test_user', 'testproject-core'),
                     call('test_user', 'testproject-dev'), ]
            add_group_member.assert_has_calls(calls)
        with nested(*patches) as (get_my_groups_id,
                                  get_group_id,
                                  is_admin,
                                  add_group_member,
                                  group_exists):
            get_my_groups_id.return_value = ('ptl_gid', )
            get_group_id.side_effect = ggi_side_effect
            is_admin.return_value = False
            group_exists.return_value = True
            self.gerrit.membership.create('requestor',
                                          'test_user',
                                          'testproject',
                                          ['dev-group'])
            calls = [call('test_user', 'testproject-dev'), ]
            add_group_member.assert_has_calls(calls)
        # Test a core-dev user
        with nested(*patches) as (get_my_groups_id,
                                  get_group_id,
                                  is_admin,
                                  add_group_member,
                                  group_exists):
            get_my_groups_id.return_value = ('core_gid', )
            get_group_id.side_effect = ggi_side_effect
            is_admin.return_value = False
            group_exists.return_value = True
            self.gerrit.membership.create('requestor',
                                          'test_user',
                                          'testproject',
                                          ['core-group',
                                           'dev-group'])
            calls = [call('test_user', 'testproject-core'),
                     call('test_user', 'testproject-dev'), ]
            add_group_member.assert_has_calls(calls)

    def test_delete(self):
        patches = [patch.object(GerritUtils,
                                'get_user_groups_id'),
                   patch.object(GerritUtils,
                                'get_group_id'),
                   patch.object(self.gerrit.role,
                                'is_admin'),
                   patch.object(GerritUtils,
                                'delete_group_member'),
                   patch.object(GerritUtils,
                                'group_exists'),
                   patch.object(GerritUtils,
                                'get_group_member_id'), ]
        self.assertRaises(exc.UnavailableActionError,
                          self.gerrit.membership.delete,
                          'requestor', 'u', 'proj', 'made_up_group')
        # Test a ptl user
        with nested(*patches) as (get_my_groups_id,
                                  get_group_id,
                                  is_admin,
                                  delete_group_member,
                                  group_exists,
                                  get_group_member_id):
            get_my_groups_id.return_value = ('ptl_gid',)
            get_group_id.side_effect = ggi_side_effect
            is_admin.return_value = False
            group_exists.return_value = True
            get_group_member_id.return_value = 'bogus_id'
            self.gerrit.membership.delete('requestor',
                                          'test_user',
                                          'testproject',
                                          None)
            calls = [call('dev_gid', 'bogus_id'),
                     call('ptl_gid', 'bogus_id'),
                     call('core_gid', 'bogus_id'), ]
            delete_group_member.assert_has_calls(calls)


class TestSFGerritProjectManager(BaseSFGerritService):
    def test_get(self):
        patches = [patch.object(GerritUtils,
                                'get_project'),
                   patch.object(GerritUtils,
                                'get_projects'),
                   patch.object(self.gerrit.role,
                                'is_admin'),
                   patch.object(GerritUtils,
                                'get_my_groups'),
                   patch.object(GerritUtils,
                                'get_user_groups'),
                   patch.object(GerritUtils,
                                'get_project_owner'), ]
        with nested(*patches) as (get_project,
                                  get_projects,
                                  is_admin,
                                  get_my_groups,
                                  get_user_groups,
                                  get_project_owner):
            get_project.return_value = 'p1'
            get_projects.return_value = ['p1', 'p2', 'p3', 'p4']
            is_admin.return_value = False
            get_my_groups.return_value = ['grp1', 'grp3']
            get_user_groups.return_value = ['grp1', 'grp3']

            def gpo_side_effect(project):
                return 'gr' + project

            get_project_owner.side_effect = gpo_side_effect
            self.assertEqual('p1',
                             self.gerrit.project.get(project_name='p1'))
            self.assertEqual(['p1', 'p2', 'p3', 'p4'],
                             self.gerrit.project.get())
            self.assertEqual(['p1', 'p3'],
                             self.gerrit.project.get(by_user=True))
            is_admin.return_value = True
            self.assertEqual(['p1', 'p2', 'p3', 'p4'],
                             self.gerrit.project.get(by_user=True))

    def test_get_groups(self):
        patches = [patch.object(GerritUtils,
                                'get_project_groups'), ]
        with nested(*patches) as (gpg,):
            gpg.return_value = False
            self.assertEqual([],
                             self.gerrit.project.get_groups('p1'))
            gpg.return_value = ['grp1', 'grp2']
            self.assertEqual(['grp1', 'grp2'],
                             self.gerrit.project.get_groups('p1'))

    def test_create(self):
        patches = [patch.object(self.gerrit.role, 'create'),
                   patch.object(self.gerrit.membership, 'create'),
                   patch.object(GerritUtils, 'create_project'),
                   patch.object(self.gerrit.repository, 'create'),
                   patch.object(GerritUtils, 'project_exists'), ]
        with nested(*patches) as (r_create, m_create,
                                  create_project, rep_create,
                                  project_exists):
            project_exists.return_value = False
            self.gerrit.project.create('p_name', 'u_name')
            role_calls = [call('u_name',
                               'p_name-core',
                               'Core developers for project p_name'),
                          call('u_name',
                               'p_name-ptl',
                               'Project team lead for project p_name'), ]
            r_create.assert_has_calls(role_calls)
            create_project.assert_called_with('p_name', '', ['p_name-ptl'])
            rep_create.assert_called_with('p_name', '', None, False, False,
                                          False)
            r_create.reset_mock()
            create_project.reset_mock()
            rep_create.reset_mock()
            proj_data = {'description': 'eh',
                         'ptl-group-members': ['a', 'b'],
                         'private': True,
                         'core-group-members': ['b', 'c'],
                         'dev-group-members': ['d', 'e']}
            self.gerrit.project.create('p', 'u', proj_data)
            role_calls = [call('u',
                               'p-core',
                               'Core developers for project p'),
                          call('u',
                               'p-ptl',
                               'Project team lead for project p'),
                          call('u',
                               'p-dev',
                               'Developers for project p'), ]
            r_create.assert_has_calls(role_calls)
            membership_calls = [call('u',
                                     'b',
                                     'p',
                                     ['core-group']),
                                call('u',
                                     'c',
                                     'p',
                                     ['core-group']),
                                call('u',
                                     'a',
                                     'p',
                                     ['ptl-group']),
                                call('u',
                                     'b',
                                     'p',
                                     ['ptl-group']),
                                call('u',
                                     'd',
                                     'p',
                                     ['dev-group']),
                                call('u',
                                     'e',
                                     'p',
                                     ['dev-group']), ]
            m_create.assert_has_calls(membership_calls)

    def test_delete(self):
        patches = [patch.object(GerritUtils, 'get_project_owner'),
                   patch.object(GerritUtils,
                                'get_user_groups_id'),
                   patch.object(self.gerrit.role, 'is_admin'),
                   patch.object(self.gerrit.role, 'delete'),
                   patch.object(GerritUtils,
                                'delete_project'), ]
        with nested(*patches) as (get_project_owner, get_my_groups_id,
                                  is_admin, role_delete, delete_project):
            is_admin.return_value = False
            get_project_owner.return_value = 'nope'
            get_my_groups_id.return_value = ['nopity', 'nopenope']
            self.assertRaises(exc.Unauthorized,
                              self.gerrit.project.delete,
                              'p', 'requestor')
            get_project_owner.return_value = 'yep'
            get_my_groups_id.return_value = ['yep', 'yepyep']
            self.gerrit.project.delete('p', 'requestor')
            delete_project.assert_called_with('p', force=True)
            delete_calls = [call('p-core'),
                            call('p-ptl'),
                            call('p-dev'), ]
            role_delete.assert_has_calls(delete_calls)
