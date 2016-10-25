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
from contextlib import nested

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
        patches = [
            patch('pysflib.sfgerrit.GerritUtils.create_project'),
            patch.object(GitRepositoryOps, 'install_acl'),
            patch.object(GitRepositoryOps, 'install_git_review_file'),
        ]
        o = GitRepositoryOps(self.conf, None)

        kwargs = {'name': 'space/g1',
                  'description': 'A description',
                  'acl': 'a1'}
        with nested(*patches) as (cp, ia, ig):
            ia.return_value = []
            ig.return_value = []
            logs = o.create(**kwargs)
            self.assertEqual(len(cp.call_args_list), 1)
            self.assertEqual(cp.call_args_list[0],
                             call('space/g1', 'A description',
                                  ['Administrators']))
            self.assertEqual(len(logs), 0)
        with nested(*patches) as (cp, ia, ig):
            ia.return_value = []
            ig.return_value = []
            cp.side_effect = Exception('Random Error')
            logs = o.create(**kwargs)
            self.assertEqual(len(logs), 1)
            self.assertIn('Repo create: err API returned Random Error',
                          logs)

    def test_install_git_review_file(self):
        patches = [
            patch('managesf.services.gerrit.utils.GerritRepo.clone'),
            patch('managesf.services.gerrit.utils.GerritRepo.push_master'),
        ]
        o = GitRepositoryOps(self.conf, {})

        kwargs = {'name': 'space/g1'}

        with nested(*patches) as (c, pm):
            logs = o.install_git_review_file(**kwargs)
            self.assertTrue(c.called)
            self.assertTrue(pm.called)
            self.assertEqual(
                pm.call_args,
                call({'.gitreview': '[gerrit]\nhost=tests.dom\nport=2929'
                      '\nproject=space/g1\ndefaultbranch=master\n'})
            )
            self.assertEqual(len(logs), 0)

    def test_install_acl(self):
        patches = [
            patch('pysflib.sfgerrit.GerritUtils.get_group_id'),
            patch('managesf.services.gerrit.utils.GerritRepo.clone'),
            patch('managesf.services.gerrit.utils.GerritRepo.push_config'),
        ]
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

        with nested(*patches) as (ggi, c, pc):
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

        with nested(*patches) as (ggi, c, pc):
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

        with nested(*patches) as (ggi, c, pc):
            ggi.side_effect = lambda x: db[x]
            pc.side_effect = Exception('Random error')
            logs = o.install_acl(**kwargs)
            self.assertListEqual(['Random error'], logs)

    def test_update(self):
        with patch.object(GitRepositoryOps, 'install_acl') as ia:
            with patch.object(
                    GitRepositoryOps, 'install_git_review_file') as ig:
                ia.return_value = ['log']
                ig.return_value = ['log2']
                o = GitRepositoryOps(None, None)
                logs = o.update(k='v')
                self.assertTrue(ia.called)
                self.assertTrue(ig.called)
                self.assertIn('log', logs)
                self.assertIn('log2', logs)

    def test_delete(self):
        patches = [
            patch('pysflib.sfgerrit.GerritUtils.delete_project'),
        ]
        o = GitRepositoryOps(self.conf, None)

        kwargs = {'name': 'space/g1'}
        with nested(*patches) as (dp, ):
            logs = o.delete(**kwargs)
            self.assertEqual(len(dp.call_args_list), 1)
            self.assertEqual(dp.call_args_list[0],
                             call('space/g1', True,))
            self.assertEqual(len(logs), 0)

    def test_get_all(self):
        patches = [
            patch('pysflib.sfgerrit.GerritUtils.get_projects'),
            patch('managesf.services.gerrit.utils.GerritRepo'),
        ]

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
        with nested(*patches) as (gps, gr):
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
