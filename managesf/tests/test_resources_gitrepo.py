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

import os
import hashlib
import tempfile

from unittest import TestCase

from mock import patch, call, Mock

from managesf.tests import dummy_conf
from managesf.model.yamlbkd.resources.gitrepository import GitRepositoryOps


class GitRepositoryOpsTest(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()

    def test_create(self):
        o = GitRepositoryOps(self.conf, None)

        kwargs = {'name': 'space/g1',
                  'description': 'A description',
                  'acl': 'a1'}

        with patch('managesf.services.gerrit.utils.'
                   'GerritClient.create_project') as cp, \
            patch('managesf.services.gerrit.utils.GerritRepo.clone'), \
            patch.object(GitRepositoryOps,
                         'install_acl') as ia, \
            patch.object(GitRepositoryOps,
                         'create_branches') as cb, \
            patch.object(GitRepositoryOps,
                         'install_git_review_file') as ig:
            ia.return_value = []
            cb.return_value = []
            ig.return_value = []
            logs = o.create(**kwargs)
            self.assertEqual(len(cp.call_args_list), 1)
            self.assertEqual(cp.call_args_list[0],
                             call('space/g1', 'A description',
                                  ['Administrators']))
            self.assertEqual(len(logs), 0)

        with patch('managesf.services.gerrit.utils.'
                   'GerritClient.create_project') as cp, \
            patch('managesf.services.gerrit.utils.GerritRepo.clone'), \
            patch.object(GitRepositoryOps,
                         'install_acl') as ia, \
            patch.object(GitRepositoryOps,
                         'create_branches') as cb, \
            patch.object(GitRepositoryOps,
                         'install_git_review_file') as ig:
            ia.return_value = []
            cb.return_value = []
            ig.return_value = []
            cp.side_effect = Exception('Random Error')
            logs = o.create(**kwargs)
            self.assertEqual(len(logs), 1)
            self.assertIn('Repo create: err API returned Random Error',
                          logs)

    def test_install_git_review_file(self):
        o = GitRepositoryOps(self.conf, {})

        MGR = Mock()

        logs = o.install_git_review_file(MGR, 'space/g1', 'br1')
        self.assertTrue(MGR.push_branch.called)
        self.assertEqual(
            MGR.push_branch.call_args,
            call('br1',
                 {'.gitreview': '[gerrit]\nhost=tests.dom\nport=2929'
                  '\nproject=space/g1\ndefaultbranch=br1\n'})
        )
        self.assertEqual(len(logs), 0)

    def test_create_branches(self):
        o = GitRepositoryOps(self.conf, {})
        o._set_client()

        MGR = Mock()
        MGR.list_remote_branches.return_value = {
            'HEAD': 'master',
            'master': '100',
            'dev3': '125'}

        kwargs = {'name': 'space/g1',
                  'default-branch': '',
                  'branches': {}}
        logs = o.create_branches(MGR, **kwargs)
        self.assertTrue(MGR.list_remote_branches.called)
        self.assertTrue(not MGR.create_remote_branch.called)
        self.assertTrue(not MGR.delete_remote_branch.called)
        self.assertEqual(len(logs), 0)

        MGR.reset_mock()

        MGR.list_remote_branches.return_value = {
            'HEAD': 'rpm-master',
            'master': '100',
            'dev3': '125'}
        kwargs = {'name': 'space/g1',
                  'default-branch': '',
                  'branches': {
                      'dev': '123',
                      'dev2': '124',
                      'dev3': '0'}}
        with patch.object(GitRepositoryOps,
                          'set_default_branch') as sdb, \
            patch.object(GitRepositoryOps,
                         'install_git_review_file') as igrf:
            logs = o.create_branches(MGR, **kwargs)
        MGR.list_remote_branches.assert_called()
        MGR.create_remote_branch.assert_called()
        igrf.assert_called()
        sdb.assert_not_called()
        MGR.delete_remote_branch.assert_called()
        self.assertEqual(len(logs), 0)
        self.assertIn(call('dev2', '124'),
                      MGR.create_remote_branch.call_args_list)
        self.assertIn(call('dev', '123'),
                      MGR.create_remote_branch.call_args_list)
        self.assertIn(call(MGR, 'space/g1', 'dev2'), igrf.call_args_list)
        self.assertIn(call(MGR, 'space/g1', 'dev'), igrf.call_args_list)
        self.assertTrue(len(igrf.call_args_list), 2)
        self.assertTrue(len(MGR.create_remote_branch.call_args_list), 2)
        self.assertIn(call('dev3'), MGR.delete_remote_branch.call_args_list)
        self.assertTrue(len(MGR.delete_remote_branch.call_args_list), 1)

        MGR.reset_mock()

        MGR.list_remote_branches.return_value = {
            'HEAD': 'master',
            'master': '100',
            'dev3': '125'}
        kwargs = {'name': 'space/g1',
                  'default-branch': 'dev',
                  'branches': {
                      'dev': '123'}}
        with patch.object(GitRepositoryOps,
                          'set_default_branch') as sdb, \
            patch.object(GitRepositoryOps,
                         'install_git_review_file') as igrf:
            logs = o.create_branches(MGR, **kwargs)

        MGR.list_remote_branches.assert_called()
        MGR.create_remote_branch.assert_called()
        sdb.assert_called()
        igrf.assert_called()
        MGR.delete_remote_branch.assert_not_called()
        self.assertEqual(len(logs), 0)
        self.assertIn(call('dev', '123'),
                      MGR.create_remote_branch.call_args_list)
        self.assertTrue(len(MGR.create_remote_branch.call_args_list), 1)
        self.assertIn(call(MGR, 'space/g1', 'dev'), igrf.call_args_list)
        self.assertTrue(len(igrf.call_args_list), 1)
        self.assertIn(call('space/g1', 'dev'), sdb.call_args_list)
        self.assertTrue(len(sdb.call_args_list), 1)

        MGR.reset_mock()

        MGR.list_remote_branches.return_value = {
            'HEAD': 'master',
            'master': '100'}
        kwargs = {'name': 'space/g1',
                  'default-branch': 'rpm-master',
                  'branches': {}}
        with patch.object(GitRepositoryOps,
                          'set_default_branch') as sdb, \
            patch.object(GitRepositoryOps,
                         'install_git_review_file') as igrf:

            logs = o.create_branches(MGR, **kwargs)

        MGR.list_remote_branches.assert_called()
        MGR.create_remote_branch.assert_called()
        sdb.assert_called()
        igrf.assert_called()
        not MGR.delete_remote_branch.assert_not_called()
        self.assertEqual(len(logs), 0)
        self.assertIn(call('rpm-master', 'HEAD'),
                      MGR.create_remote_branch.call_args_list)
        self.assertTrue(len(MGR.create_remote_branch.call_args_list), 1)
        self.assertIn(call(MGR, 'space/g1', 'rpm-master'), igrf.call_args_list)
        self.assertTrue(len(igrf.call_args_list), 1)
        self.assertIn(call('space/g1', 'rpm-master'), sdb.call_args_list)
        self.assertTrue(len(sdb.call_args_list), 1)

    def test_install_acl(self):
        new = {
            'resources': {
                'acls': {
                    'a1': {
                        'file': '',
                        'groups': ['g1'],
                    }
                },
                'groups': {
                    'g1': {
                        'name': 'sf/g1',
                        'members': ['body@sftests.com'],
                    }
                }
            }
        }

        o = GitRepositoryOps(self.conf, new)
        o._set_client()

        kwargs = {'name': 'space/g1',
                  'description': 'A description',
                  'acl': ''}

        db = {'Administrators': '666',
              'Anonymous Users': '777',
              'Service Users': '888'}

        MGR = Mock()

        with patch('managesf.services.gerrit.utils.'
                   'GerritClient.get_group_id') as ggi:
            ggi.side_effect = lambda x: db[x]
            logs = o.install_acl(MGR, **kwargs)
        self.assertIn(call('Administrators'), ggi.call_args_list)
        self.assertIn(call('Anonymous Users'), ggi.call_args_list)
        self.assertIn(call('Service Users'), ggi.call_args_list)
        self.assertEqual(len(ggi.call_args_list), 3)
        self.assertGreater(
            int(str(MGR.push_config.call_args).find(
                "666\\tAdministrators")), 0)
        self.assertGreater(
            int(str(MGR.push_config.call_args).find(
                "777\\tAnonymous Users")), 0)
        self.assertGreater(
            int(str(MGR.push_config.call_args).find(
                "888\\tService Users")), 0)
        self.assertGreater(
            int(str(MGR.push_config.call_args).find(
                "description = A description")), 0)
        self.assertEqual(len(logs), 0)

        kwargs = {'name': 'space/g1',
                  'description': 'A description',
                  'acl': 'a1'}

        db = {'Administrators': '666',
              'Anonymous Users': '777',
              'Service Users': '888',
              'sf/g1': 999}

        MGR.reset_mock()

        with patch('managesf.services.gerrit.utils.'
                   'GerritClient.get_group_id') as ggi:
            ggi.side_effect = lambda x: db[x]
            logs = o.install_acl(MGR, **kwargs)
        self.assertGreater(
            int(str(MGR.push_config.call_args).find(
                "666\\tAdministrators")), 0)
        self.assertGreater(
            int(str(MGR.push_config.call_args).find(
                "777\\tAnonymous Users")), 0)
        self.assertGreater(
            int(str(MGR.push_config.call_args).find(
                "888\\tService Users")), 0)
        self.assertGreater(
            int(str(MGR.push_config.call_args).find(
                "999\\tsf/g1")), 0)
        self.assertGreater(
            int(str(MGR.push_config.call_args).find(
                "description = A description")), 0)
        self.assertEqual(len(logs), 0)

        MGR.reset_mock()

        with patch('managesf.services.gerrit.utils.'
                   'GerritClient.get_group_id') as ggi:
            ggi.side_effect = lambda x: db[x]
            MGR.push_config.side_effect = Exception('Random error')
            logs = o.install_acl(MGR, **kwargs)
        self.assertListEqual(['Random error'], logs)

    def test_update(self):
        with patch.object(GitRepositoryOps, 'install_acl') as ia, \
                patch('managesf.services.gerrit.utils.GerritRepo.clone'), \
                patch.object(GitRepositoryOps, 'create_branches') as cb:
            ia.return_value = ['log']
            cb.return_value = []
            o = GitRepositoryOps(self.conf, None)
            logs = o.update(name='space/p1', k='v')
            self.assertTrue(ia.called)
            self.assertTrue(cb.called)
            self.assertIn('log', logs)

    def test_delete(self):
        o = GitRepositoryOps(self.conf, None)

        kwargs = {'name': 'space/g1'}
        with patch('managesf.services.gerrit.utils.'
                   'GerritClient.delete_project') as dp:
            logs = o.delete(**kwargs)
            self.assertEqual(len(dp.call_args_list), 1)
            self.assertEqual(dp.call_args_list[0],
                             call('space/g1', True,))
            self.assertEqual(len(logs), 0)

    def test_get_all(self):
        a1 = """[project]
    description = This is the project p1
[access "refs/*"]
  read = group Anonymous Users
    read = group p1-core
  owner = group p1-ptl
[access "refs/heads/*"]
    label-Code-Review = -2..+2 group p1-core
    label-Verified = -2..+2 group p1-ptl
    label-Workflow = -1..+1 group p1-core
    submit = group p1-ptl
    read = group Anonymous Users
    read = group p1-core
[access "refs/meta/config"]
    read = group p1-core
[receive]
    requireChangeId = true
[submit]
    mergeContent = false
    action = fast forward only
"""

        a2 = """[submit]
    mergeContent = false
    action = fast forward only
"""

        clean_a1 = """[access "refs/*"]
  read = group Anonymous Users
    read = group p1-core
  owner = group p1-ptl
[access "refs/heads/*"]
    label-Code-Review = -2..+2 group p1-core
    label-Verified = -2..+2 group p1-ptl
    label-Workflow = -1..+1 group p1-core
    submit = group p1-ptl
    read = group Anonymous Users
    read = group p1-core
[access "refs/meta/config"]
    read = group p1-core
[receive]
    requireChangeId = true
[submit]
    mergeContent = false
    action = fast forward only
"""

        m = hashlib.md5()
        m.update(clean_a1.encode())
        a1_id = m.hexdigest()
        m = hashlib.md5()
        m.update(a2.encode())
        a2_id = m.hexdigest()

        def fake_get_projects():
            return ['p1', 'p2']

        def fake_repo_utils(name, conf):
            class FakeGerritRepo():
                def __init__(self, name, conf):
                    self.name = name
                    self.conf = conf

                def get_raw_acls(self):
                    data = {
                        'p1': a1,
                        'p2': a2,
                    }
                    f, p = tempfile.mkstemp()
                    os.close(f)
                    open(p, 'w').write(data[self.name])
                    return p
            return FakeGerritRepo(name, conf)

        o = GitRepositoryOps(self.conf, None)
        with patch('managesf.services.gerrit.utils.'
                   'GerritClient.get_projects') as gps, \
                patch('managesf.services.gerrit.utils.GerritRepo') as gr:
            gps.side_effect = fake_get_projects
            gr.side_effect = fake_repo_utils
            logs, tree = o.get_all()
            self.assertIn('repos', tree.keys())
            self.assertIn('acls', tree.keys())
            self.assertIn(a1_id, tree['acls'].keys())
            self.assertIn(a2_id, tree['acls'].keys())
            self.assertEqual(len(tree['acls'].keys()), 2)
            self.assertIn('p1', tree['repos'].keys())
            self.assertIn('p2', tree['repos'].keys())
            self.assertEqual(len(tree['repos'].keys()), 2)
            self.assertDictEqual(tree['repos']['p1'],
                                 {'name': 'p1',
                                  'description': 'This is the project p1',
                                  'acl': a1_id})
            self.assertDictEqual(tree['repos']['p2'],
                                 {'name': 'p2',
                                  'acl': a2_id})
            self.assertEqual(tree['acls'][a1_id]['file'], clean_a1)
            self.assertIn('p1-ptl', tree['acls'][a1_id]['groups'])
            self.assertIn('p1-core', tree['acls'][a1_id]['groups'])
            self.assertEqual(len(tree['acls'][a1_id]['groups']), 2)
            self.assertEqual(tree['acls'][a2_id]['file'], a2)
            self.assertEqual(len(tree['acls'][a2_id]['groups']), 0)
