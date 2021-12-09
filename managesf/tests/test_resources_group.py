# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 Red Hat, Inc.
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
from managesf.model.yamlbkd.resources.group import GroupOps
from managesf.services.gerrit import utils


class GroupOpsTest(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()

    def test_create(self):
        o = GroupOps(self.conf, None)

        kwargs = {'name': 'space/g1',
                  'description': 'A description',
                  'members': ['body@sftests.com', 'body2@sftests.com']}
        with patch('managesf.services.gerrit.utils.'
                   'GerritClient.create_group') as cg, \
                patch('managesf.services.gerrit.utils.'
                      'GerritClient.add_group_member') as agm, \
                patch('managesf.services.gerrit.utils.'
                      'GerritClient.delete_group_member') as dgm:
            logs = o.create(**kwargs)
            self.assertEqual(len(cg.call_args_list), 1)
            self.assertEqual(cg.call_args_list[0],
                             call('space/g1', 'A description'))
            self.assertEqual(len(agm.call_args_list), 2)
            self.assertEqual(agm.call_args_list[0],
                             call('body@sftests.com', 'space/g1'))
            self.assertEqual(agm.call_args_list[1],
                             call('body2@sftests.com', 'space/g1'))
            self.assertEqual(len(dgm.call_args_list), 1)
            self.assertEqual(dgm.call_args_list[0],
                             call('space/g1', "admin"))
            self.assertEqual(len(logs), 0)
        with patch('managesf.services.gerrit.utils.'
                   'GerritClient.create_group') as cg, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'add_group_member') as agm, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'delete_group_member') as dgm:
            cg.side_effect = Exception('Random error')
            agm.side_effect = Exception("HTTP 404/409")
            dgm.side_effect = Exception("HTTP 404/409")
            logs = o.create(**kwargs)
            self.assertIn('Group create: err API returned Random error',
                          logs)
            self.assertIn('Group create [add member: body@sftests.com]: '
                          'err API returned HTTP 404/409', logs)
            self.assertIn('Group create [add member: body2@sftests.com]: '
                          'err API returned HTTP 404/409', logs)
            self.assertIn('Group create [del member: admin]: '
                          'err API returned HTTP 404/409', logs)
            self.assertEqual(len(logs), 4)

    def test_delete(self):
        o = GroupOps(self.conf, None)

        kwargs = {'name': 'space/g1'}

        with patch('managesf.services.gerrit.utils.'
                   'GerritClient.get_group_id') as ggi, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'get_group_members') as ggm, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'delete_group_member') as dgm, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'get_group_group_members') as gggm, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'delete_group_group_member') as dggm, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'rename_group') as rg:
            ggm.return_value = [{'email': 'body@sftests.com'},
                                {'email': 'body2@sftests.com'},
                                {'email': self.conf.admin['email']}]
            gggm.return_value = []
            logs = o.delete(**kwargs)
            self.assertEqual(len(ggi.call_args_list), 1)
            self.assertEqual(ggi.call_args_list[0],
                             call('space/g1'))
            self.assertEqual(len(ggm.call_args_list), 1)
            self.assertEqual(len(dgm.call_args_list), 3)
            self.assertEqual(len(rg.call_args_list), 1)
            self.assertListEqual([call('space/g1', 'body@sftests.com'),
                                  call('space/g1', 'body2@sftests.com'),
                                  call('space/g1', self.conf.admin['email'])],
                                 dgm.call_args_list)
            self.assertEqual(len(logs), 0)

        with patch('managesf.services.gerrit.utils.'
                   'GerritClient.get_group_id') as ggi, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'get_group_members') as ggm, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'delete_group_member') as dgm, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'get_group_group_members') as gggm, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'delete_group_group_member') as dggm, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'rename_group') as rg:

            ggm.return_value = []
            ggi.return_value = '666'
            gggm.return_value = [{'name': 'included_group'}]
            logs = o.delete(**kwargs)
            self.assertEqual(len(ggi.call_args_list), 1)
            self.assertEqual(len(gggm.call_args_list), 1)
            self.assertEqual(len(rg.call_args_list), 1)
            self.assertEqual(gggm.call_args_list[0],
                             call('666'))
            self.assertEqual(len(dggm.call_args_list), 1)
            self.assertEqual(call('666', 'included_group'),
                             dggm.call_args_list[0])
            self.assertEqual(len(logs), 0)

        with patch('managesf.services.gerrit.utils.'
                   'GerritClient.get_group_id') as ggi, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'get_group_members') as ggm, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'delete_group_member') as dgm, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'get_group_group_members') as gggm, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'delete_group_group_member') as dggm, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'rename_group'):

            ggm.return_value = [{'email': 'body@sftests.com'},
                                {'email': 'body2@sftests.com'},
                                {'email': self.conf.admin['email']}]
            dgm.side_effect = Exception('Random Error')
            gggm.return_value = []
            logs = o.delete(**kwargs)
            self.assertIn('Group delete [del member: body@sftests.com]: '
                          'err API returned Random Error', logs)
            self.assertIn('Group delete [del member: body2@sftests.com]: '
                          'err API returned Random Error', logs)
            self.assertIn('Group delete [del member: %s]: '
                          'err API returned Random Error' % (
                              self.conf.admin['email']), logs)
            self.assertEqual(len(logs), 3)

    def test_update(self):
        o = GroupOps(self.conf, None)

        kwargs = {'name': 'space/g1',
                  'description': 'An awesome project',
                  'members': ['body@sftests.com', 'body2@sftests.com']}

        with patch('managesf.services.gerrit.utils.'
                   'GerritClient.get_group_id'), \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'get_group_members') as ggm, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'add_group_member') as agm, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'delete_group_member') as dgm, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'get_group_group_members') as gggm, \
                patch('managesf.services.gerrit.utils.GerritClient.'
                      'delete_group_group_member') as dggm, \
                patch.object(GroupOps, 'group_update_description') as gup:
            ggm.return_value = [{'email': 'body3@sftests.com'},
                                {'id': 'John Doe'}]
            gggm.return_value = [{'name': 'included_group'}]
            logs = o.update(**kwargs)
            self.assertEqual(len(agm.call_args_list), 2)
            self.assertIn(call('body2@sftests.com', 'space/g1'),
                          agm.call_args_list)
            self.assertIn(call('body@sftests.com', 'space/g1'),
                          agm.call_args_list)
            self.assertEqual(len(dgm.call_args_list), 1)
            self.assertEqual(call('space/g1', 'body3@sftests.com'),
                             dgm.call_args_list[0])
            self.assertEqual(len(gup.call_args_list), 1)
            self.assertEqual(call('space/g1', 'An awesome project'),
                             gup.call_args_list[0])
            self.assertTrue(gggm.called)
            self.assertTrue(dggm.called)
            self.assertEqual(len(logs), 0)

    def test_extra_validations(self):
        kwargs = {'name': 'space/g1',
                  'members': ['body@sftests.com', 'body2@sftests.com']}
        o = GroupOps(self.conf, None)
        with patch('managesf.services.gerrit.utils.'
                   'GerritClient.get_account') as ga:
            ga.return_value = {}
            logs = o.extra_validations(**kwargs)
            self.assertEqual(len(ga.call_args_list), 2)
            self.assertEqual(len(logs), 0)
        with patch('managesf.services.gerrit.utils.'
                   'GerritClient.get_account') as ga:
            ga.side_effect = utils.NotFound()
            logs = o.extra_validations(**kwargs)
            self.assertEqual(len(ga.call_args_list), 2)
            self.assertEqual(len(logs), 2)
            self.assertIn('Check group members [body@sftests.com does '
                          'not exists]: err API unable to find the member',
                          logs)
            self.assertIn('Check group members [body2@sftests.com '
                          'does not exists]: err API unable to '
                          'find the member', logs)

    def test_get_all(self):
        o = GroupOps(self.conf, None)

        def fake_get_groups():
            return {
                'g1': {
                    'description': 'd1',
                    'group_id': 1,
                    },
                'g2': {
                    'description': 'd2',
                    'group_id': 2,
                    },
                'Administrators': {
                    'description': 'Gerrit Admin groups',
                    'group_id': 3,
                    },
                'Service Users': {
                    'description': 'Gerrit Service Users groups',
                    'group_id': 4,
                    },
            }

        def fake_get_group_members(group_id):
            groups = {
                '1': [
                    {'email': 'user1@sftests.com'},
                    {'email': 'user3@sftests.com'},
                    {'id': 'John Doe'}
                ],
                '2': [
                    {'email': 'user2@sftests.com'}
                ],
                '3': [
                    {'email': 'user2@sftests.com'}
                ],
                '4': [
                    {'email': 'user2@sftests.com'}
                ],
            }
            return groups[group_id]

        with patch('managesf.services.gerrit.utils.'
                   'GerritClient.get_groups') as gg, \
                patch('managesf.services.gerrit.utils.'
                      'GerritClient.get_group_members') as ggm:
            gg.side_effect = fake_get_groups
            ggm.side_effect = fake_get_group_members
            logs, g_tree = o.get_all()
            self.assertListEqual(logs, [])
            self.assertIn('g1', g_tree['groups'].keys())
            self.assertIn('g2', g_tree['groups'].keys())
            self.assertEqual(len(g_tree['groups'].keys()), 2)
            self.assertIn('user1@sftests.com',
                          g_tree['groups']['g1']['members'])
            self.assertIn('user3@sftests.com',
                          g_tree['groups']['g1']['members'])
            self.assertEqual(len(g_tree['groups']['g1']['members']), 2)
            self.assertIn('user2@sftests.com',
                          g_tree['groups']['g2']['members'])
            self.assertEqual(len(g_tree['groups']['g2']['members']), 1)
