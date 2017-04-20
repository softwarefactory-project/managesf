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

from mock import patch, call

from managesf.tests import dummy_conf
from managesf.model.yamlbkd.resources.gitrepository import GitRepositoryOps


class GitRepositoryOpsTest(TestCase):
    @classmethod
    def setupClass(cls):
        cls.auth_patch = patch('managesf.services.gerrit.get_cookie')
        cls.auth_patch.start()
        cls.conf = dummy_conf()

    @classmethod
    def tearDownClass(cls):
        cls.auth_patch.stop()

    def test_create(self):
        o = GitRepositoryOps(self.conf, None)

        kwargs = {'name': 'space/g1',
                  'description': 'A description',
                  'acl': 'a1'}

        with patch('pysflib.sfgerrit.GerritUtils.create_project') as cp, \
                patch.object(GitRepositoryOps, 'install_acl') as ia, \
                patch.object(GitRepositoryOps, 'create_branches') as cb, \
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
        with patch('pysflib.sfgerrit.GerritUtils.create_project') as cp, \
                patch.object(GitRepositoryOps, 'install_acl') as ia, \
                patch.object(GitRepositoryOps, 'create_branches') as cb, \
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

        kwargs = {'name': 'space/g1'}

        with patch('managesf.services.gerrit.utils.GerritRepo.clone') as c, \
                patch('managesf.services.gerrit.utils.GerritRepo.'
                      'push_master') as pm:
            logs = o.install_git_review_file(**kwargs)
            self.assertTrue(c.called)
            self.assertTrue(pm.called)
            self.assertEqual(
                pm.call_args,
                call({'.gitreview': '[gerrit]\nhost=tests.dom\nport=2929'
                      '\nproject=space/g1\ndefaultbranch=master\n'})
            )
            self.assertEqual(len(logs), 0)

    def test_create_branches(self):
        o = GitRepositoryOps(self.conf, {})

        with patch('managesf.services.gerrit.utils.GerritRepo.clone') as c, \
                patch('managesf.services.gerrit.utils.GerritRepo.'
                      'list_remote_branches') as lrb, \
                patch('managesf.services.gerrit.utils.GerritRepo.'
                      'create_remote_branch') as crb, \
                patch.object(GitRepositoryOps, 'set_default_branch') as sdb, \
                patch('managesf.services.gerrit.utils.GerritRepo.'
                      'delete_remote_branch') as drb:

            lrb.return_value = {'HEAD': 'master',
                                'master': '100',
                                'dev3': '125'}
            kwargs = {'name': 'space/g1',
                      'default-branch': 'master',
                      'branches': {}}
            logs = o.create_branches(**kwargs)
            self.assertTrue(c.called)
            self.assertTrue(lrb.called)
            self.assertTrue(not crb.called)
            self.assertTrue(not drb.called)
            self.assertEqual(len(logs), 0)

            for ob in (c, lrb, crb, sdb, drb):
                ob.reset_mock()

            lrb.return_value = {'HEAD': 'master',
                                'master': '100',
                                'dev3': '125'}
            kwargs = {'name': 'space/g1',
                      'default-branch': 'master',
                      'branches': {
                          'dev': '123',
                          'dev2': '124',
                          'dev3': '0'}}
            logs = o.create_branches(**kwargs)
            self.assertTrue(c.called)
            self.assertTrue(lrb.called)
            self.assertTrue(crb.called)
            self.assertTrue(drb.called)
            self.assertEqual(len(logs), 0)
            self.assertIn(call('dev2', '124'), crb.call_args_list)
            self.assertIn(call('dev', '123'), crb.call_args_list)
            self.assertTrue(len(crb.call_args_list), 2)
            self.assertIn(call('dev3'), drb.call_args_list)
            self.assertTrue(len(drb.call_args_list), 1)

            for ob in (c, lrb, crb, sdb, drb):
                ob.reset_mock()

            lrb.return_value = {'HEAD': 'master',
                                'master': '100',
                                'dev3': '125'}
            kwargs = {'name': 'space/g1',
                      'default-branch': 'dev',
                      'branches': {
                          'dev': '123'}}
            logs = o.create_branches(**kwargs)
            self.assertTrue(c.called)
            self.assertTrue(lrb.called)
            self.assertTrue(crb.called)
            self.assertTrue(sdb.called)
            self.assertTrue(not drb.called)
            self.assertEqual(len(logs), 0)
            self.assertIn(call('dev', '123'), crb.call_args_list)
            self.assertTrue(len(crb.call_args_list), 1)
            self.assertIn(call('space/g1', 'dev'), sdb.call_args_list)
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

        kwargs = {'name': 'space/g1',
                  'description': 'A description',
                  'acl': ''}

        db = {'Administrators': '666',
              'Anonymous Users': '777',
              'Non-Interactive Users': '888'}

        with patch('pysflib.sfgerrit.GerritUtils.get_group_id') as ggi, \
                patch('managesf.services.gerrit.utils.GerritRepo.'
                      'clone') as c, \
                patch('managesf.services.gerrit.utils.GerritRepo.'
                      'push_config') as pc:
            ggi.side_effect = lambda x: db[x]
            logs = o.install_acl(**kwargs)
            self.assertIn(call('Administrators'), ggi.call_args_list)
            self.assertIn(call('Anonymous Users'), ggi.call_args_list)
            self.assertIn(call('Non-Interactive Users'), ggi.call_args_list)
            self.assertEqual(len(ggi.call_args_list), 3)
            self.assertTrue(c.called)
            self.assertGreater(
                int(str(pc.call_args).find("666\\tAdministrators")), 0)
            self.assertGreater(
                int(str(pc.call_args).find("777\\tAnonymous Users")), 0)
            self.assertGreater(
                int(str(pc.call_args).find("888\\tNon-Interactive Users")), 0)
            self.assertGreater(
                int(str(pc.call_args).find("description = A description")), 0)
            self.assertEqual(len(logs), 0)

        kwargs = {'name': 'space/g1',
                  'description': 'A description',
                  'acl': 'a1'}

        db = {'Administrators': '666',
              'Anonymous Users': '777',
              'Non-Interactive Users': '888',
              'sf/g1': 999}

        with patch('pysflib.sfgerrit.GerritUtils.get_group_id') as ggi, \
                patch('managesf.services.gerrit.utils.GerritRepo.'
                      'clone') as c, \
                patch('managesf.services.gerrit.utils.GerritRepo.'
                      'push_config') as pc:
            ggi.side_effect = lambda x: db[x]
            logs = o.install_acl(**kwargs)
            self.assertGreater(
                int(str(pc.call_args).find("666\\tAdministrators")), 0)
            self.assertGreater(
                int(str(pc.call_args).find("777\\tAnonymous Users")), 0)
            self.assertGreater(
                int(str(pc.call_args).find("888\\tNon-Interactive Users")), 0)
            self.assertGreater(
                int(str(pc.call_args).find("999\\tsf/g1")), 0)
            self.assertGreater(
                int(str(pc.call_args).find("description = A description")), 0)
            self.assertEqual(len(logs), 0)

        with patch('pysflib.sfgerrit.GerritUtils.get_group_id') as ggi, \
                patch('managesf.services.gerrit.utils.GerritRepo.'
                      'clone') as c, \
                patch('managesf.services.gerrit.utils.GerritRepo.'
                      'push_config') as pc:
            ggi.side_effect = lambda x: db[x]
            pc.side_effect = Exception('Random error')
            logs = o.install_acl(**kwargs)
            self.assertListEqual(['Random error'], logs)

    def test_update(self):
        with patch.object(GitRepositoryOps, 'install_acl') as ia, \
                patch.object(GitRepositoryOps, 'create_branches') as cb:
            ia.return_value = ['log']
            cb.return_value = []
            o = GitRepositoryOps(None, None)
            logs = o.update(k='v')
            self.assertTrue(ia.called)
            self.assertTrue(cb.called)
            self.assertIn('log', logs)

    def test_delete(self):
        o = GitRepositoryOps(self.conf, None)

        kwargs = {'name': 'space/g1'}
        with patch('pysflib.sfgerrit.GerritUtils.delete_project') as dp:
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
        m.update(clean_a1)
        a1_id = m.hexdigest()
        m = hashlib.md5()
        m.update(a2)
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
                    file(p, 'w').write(data[self.name])
                    return p
            return FakeGerritRepo(name, conf)

        o = GitRepositoryOps(self.conf, None)
        with patch('pysflib.sfgerrit.GerritUtils.get_projects') as gps, \
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
