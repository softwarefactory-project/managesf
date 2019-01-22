# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
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

import os

from managesf.services.gerrit import utils
from managesf.tests import dummy_conf


class TestGerritRepo(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()

    def test_init(self):
        gr = utils.GerritRepo('p1', self.conf)
        self.assertTrue(gr.infos['localcopy_path'].endswith('p1'))
        self.assertTrue(os.path.isfile(gr.env['GIT_SSH']))
        self.assertTrue(gr.env['GIT_COMMITTER_NAME'])
        self.assertTrue(gr.env['GIT_COMMITTER_EMAIL'])

    def test_exec(self):
        gr = utils.GerritRepo('p1', self.conf)
        gr._exec('touch f')
        self.assertTrue(os.path.isfile(os.path.join(gr.infos['localcopy_path'],
                                                    'f')))

    def test_clone(self):
        gr = utils.GerritRepo('p1', self.conf)
        with patch.object(gr, '_exec') as ex:
            gr.clone()
            self.assertEqual(
                'git clone ssh://user1@gerrit.test.dom:2929/p1 %s' %
                gr.infos['localcopy_path'],
                ex.mock_calls[0][1][0])

    def test_add_file(self):
        gr = utils.GerritRepo('p1', self.conf)
        with patch.object(gr, '_exec') as ex:
            gr.add_file('thefile', 'thecontent')
            p = os.path.join(gr.infos['localcopy_path'], 'thefile')
            self.assertTrue(os.path.isfile(p))
            self.assertEqual('thecontent', open(p).read())
            self.assertEqual('git add thefile', ex.mock_calls[0][1][0])

    def test_push_config(self):
        gr = utils.GerritRepo('p1', self.conf)
        with patch.object(gr, '_exec') as ex:
            with patch.object(gr, 'add_file') as af:
                gr.push_config({'f1': 'contentf1', 'f2': 'contentf2'})
                self.assertEqual(2, len(af.mock_calls))
                self.assertEqual(6, len(ex.mock_calls))

    def test_push_branch(self):
        gr = utils.GerritRepo('p1', self.conf)
        with patch.object(gr, '_exec') as ex:
            with patch.object(gr, 'add_file') as af:
                ex.return_value = True
                gr.push_branch('master', {'f1': 'contentf1',
                                          'f2': 'contentf2'})
        self.assertListEqual(
            [call('git checkout master'),
             call('git reset --hard origin/master'),
             call('git status -s'),
             call("git commit -a --author 'user1 "
                  "<user1@tests.dom>' -m'ManageSF commit'"),
             call('git push origin master')],
            ex.call_args_list)
        self.assertTrue(len(af.call_args_list), 2)

    def test_push_master_from_git_remote(self):
        gr = utils.GerritRepo('p1', self.conf)
        with patch.object(gr, '_exec') as ex:
            gr.push_master_from_git_remote('git://tests.dom/git/oldp1.git')
            self.assertEqual(5, len(ex.mock_calls))

    def test_review_changes(self):
        gr = utils.GerritRepo('p1', self.conf)
        with patch.object(gr, '_exec') as ex:
            gr.review_changes('this is a test')
            self.assertEqual(3, len(ex.mock_calls))
            self.assertTrue(ex.mock_calls[0][1][0].startswith(
                'ssh-agent bash -c'))
            self.assertTrue(ex.mock_calls[1][1][0].startswith('git commit -a'))
            self.assertEqual('git review', ex.mock_calls[2][1][0])

    def test_list_remote_branches(self):
        gr = utils.GerritRepo('p1', self.conf)
        with patch.object(gr, '_exec') as ex:
            ex.return_value = """  origin/HEAD   -> origin/master
  origin/master 9dc37aee187412073a10c9df85b6878bc39bd1a2 Cmt msg
  origin/meta/config 3d5c40c888109a69c1211281a67c6dbaadf7ae56 Provides ACLs
  origin/stable/ocata 4d5c40c888109a69c1211281a67c6dbaadf7ae56 ABC
"""
            refs = gr.list_remote_branches()
            self.assertDictEqual(
                refs,
                {'HEAD': 'master',
                 'master': '9dc37aee187412073a10c9df85b6878bc39bd1a2',
                 'stable/ocata': '4d5c40c888109a69c1211281a67c6dbaadf7ae56',
                 'meta/config': '3d5c40c888109a69c1211281a67c6dbaadf7ae56'})

        with patch.object(gr, '_exec') as ex:
            ex.return_value = """  origin/HEAD   -> origin/stable/ocata
  origin/master 9dc37aee187412073a10c9df85b6878bc39bd1a2 Cmt msg
  origin/meta/config 3d5c40c888109a69c1211281a67c6dbaadf7ae56 Provides ACLs
  origin/stable/ocata 4d5c40c888109a69c1211281a67c6dbaadf7ae56 ABC
"""
            refs = gr.list_remote_branches()
            self.assertDictEqual(
                refs,
                {'HEAD': 'stable/ocata',
                 'master': '9dc37aee187412073a10c9df85b6878bc39bd1a2',
                 'stable/ocata': '4d5c40c888109a69c1211281a67c6dbaadf7ae56',
                 'meta/config': '3d5c40c888109a69c1211281a67c6dbaadf7ae56'})

    def test_create_remote_branch(self):
        gr = utils.GerritRepo('p1', self.conf)
        with patch.object(gr, '_exec') as ex:
            with patch.object(gr, 'list_remote_branches') as lrb:
                lrb.return_value = {}
                gr.create_remote_branch('mybranch', '123')
                self.assertEqual(
                    'git branch mybranch 123',
                    ex.mock_calls[0][1][0])
                self.assertEqual(
                    'git push origin mybranch',
                    ex.mock_calls[1][1][0])
        with patch.object(gr, '_exec') as ex:
            with patch.object(gr, 'list_remote_branches') as lrb:
                lrb.return_value = {'fromthisbranch': '124'}
                gr.create_remote_branch('mybranch', 'fromthisbranch')
                self.assertEqual(
                    'git branch mybranch 124',
                    ex.mock_calls[0][1][0])
                self.assertEqual(
                    'git push origin mybranch',
                    ex.mock_calls[1][1][0])

    def test_delete_remote_branch(self):
        gr = utils.GerritRepo('p1', self.conf)
        with patch.object(gr, '_exec') as ex:
            gr.delete_remote_branch('mybranch')
            self.assertEqual(
                'git push --delete origin mybranch',
                ex.mock_calls[0][1][0])
