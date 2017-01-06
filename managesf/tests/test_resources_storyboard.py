# -*- coding: utf-8 -*-
#
# Copyright (c) 2017 Red Hat, Inc.
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

from managesf.tests import dummy_conf
from managesf.model.yamlbkd.resources.storyboard import StoryboardOps


class StoryboardOpsTest(TestCase):

    def test_is_activated(self):
        conf = dummy_conf()
        s = StoryboardOps(conf, None)
        project = {'issue-tracker': 'SFStoryboard'}
        self.assertTrue(s.is_activated(**project))
        project = {'issue-tracker': ''}
        self.assertFalse(s.is_activated(**project))
        conf.services.remove('SFStoryboard')
        project = {'issue-tracker': 'SFStoryboard'}
        self.assertFalse(s.is_activated(**project))

    def test_extra_validation(self):
        conf = dummy_conf()
        s = StoryboardOps(conf, None)
        project = {
            'source-repositories': ['repo1', 'repo2']
        }
        logs = s.extra_validations(**project)
        self.assertTrue(len(logs) == 0)
        project = {
            'source-repositories': ['repo', '-hjook']
        }
        logs = s.extra_validations(**project)
        self.assertTrue('Minimal len is 5' in logs[0])
        self.assertTrue('should match the RE' in logs[1])

    def test_update_project(self):
        class FakeItem(object):
            def __init__(self, name, id):
                self.name = name
                self.id = id
        conf = dummy_conf()
        s = StoryboardOps(conf, None)
        patches = [
            patch('storyboardclient.v1.projects.ProjectsManager.get_all'),
            patch('storyboardclient.v1.projects.ProjectsManager.update'),
            patch('storyboardclient.v1.projects.ProjectsManager.create')]
        with nested(*patches) as (get_all, update, create):
            get_all.return_value = [FakeItem('project1', 1)]
            s.update_project('project1', 'A desc')
            self.assertTrue(get_all.called)
            self.assertTrue(update.called)
            self.assertFalse(create.called)
        with nested(*patches) as (get_all, update, create):
            get_all.return_value = [FakeItem('project1', 1)]
            s.update_project('project2', 'A desc')
            self.assertTrue(get_all.called)
            self.assertFalse(update.called)
            self.assertTrue(create.called)

    def test_update_project_group(self):
        class FakeItem(object):
            def __init__(self, name, id):
                self.name = name
                self.id = id
        conf = dummy_conf()
        patches = [
            patch('storyboardclient.v1.project_groups.'
                  'ProjectGroupsManager.get_all'),
            patch('storyboardclient.v1.project_groups.'
                  'ProjectGroupsManager.create'),
            patch.object(StoryboardOps, 'update_project'),
            patch('storyboardclient.v1.project_groups.'
                  'ProjectGroupsManager.get'),
            patch('storyboardclient.v1.project_groups.'
                  'ProjectGroupsManager.update'),
            patch('storyboardclient.v1.projects.'
                  'ProjectsManager.get_all')]
        with nested(*patches) as (get_all, create, update_project,
                                  get, update, p_get_all):
            new = {
                'resources': {
                    'repos': {
                        'project1': {'description': 'A desc'},
                        'project2': {'description': 'A desc'}
                    }
                }
            }
            s = StoryboardOps(conf, new)
            get_all.return_value = [FakeItem('pg1', 1)]

            fake_subprojects = [
                FakeItem('project1', 1),
                FakeItem('project2', 2)]
            mput = Mock()
            mdelete = Mock()

            class fprojects():
                def get_all(self):
                    return fake_subprojects

                def put(self, id):
                    mput(id)

                def delete(self, id):
                    mdelete(id)

            class NestedProjects():
                def __init__(self):
                    self.projects = fprojects()

            get.return_value = NestedProjects()
            update.return_value = NestedProjects()
            p_get_all.return_value = fake_subprojects

            # Here projects are already included in the project
            # group so nothing will be added/removed in the project
            # group. Just projects will be updated.
            s.update_project_groups(
                **{'name': 'pg1',
                   'source-repositories': ['project1', 'project2']})
            self.assertFalse(mput.called)
            self.assertFalse(mdelete.called)
            self.assertTrue(len(update_project.mock_calls), 2)

            # Here project1 and project2 are already included but
            # the resources project decription only defines the
            # project2 to be included. So we make sure the delete
            # is called with id 1.
            mput.reset_mock()
            mdelete.reset_mock()
            update_project.reset_mock()
            s.update_project_groups(
                **{'name': 'pg1',
                   'source-repositories': ['project2']})
            self.assertFalse(mput.called)
            self.assertTrue(mdelete.called)
            self.assertListEqual(mdelete.call_args_list, [call(1)])
            self.assertTrue(len(update_project.mock_calls), 1)

            # Here only project1 is already included but
            # the resources project decription defines the
            # project1 and project2 to be included. So we make sure
            # the put is called with id 2.
            mput.reset_mock()
            mdelete.reset_mock()
            update_project.reset_mock()
            fake_subprojects = [
                FakeItem('project1', 1)]
            s.update_project_groups(
                **{'name': 'pg1',
                   'source-repositories': ['project1', 'project2']})
            self.assertTrue(mput.called)
            self.assertListEqual(mput.call_args_list, [call(2)])
            self.assertFalse(mdelete.called)
            self.assertTrue(len(update_project.mock_calls), 1)

            # Here the project group does not exist. So we verify
            # it is created and provisionned with two projects
            # included.
            get_all.return_value = []
            p_get_all.return_value = [
                FakeItem('project1', 1),
                FakeItem('project2', 2)]
            fake_subprojects = []
            get.return_value = NestedProjects()
            update.return_value = NestedProjects()
            mput.reset_mock()
            mdelete.reset_mock()
            update_project.reset_mock()
            s.update_project_groups(
                **{'name': 'pg1',
                   'source-repositories': ['project1', 'project2']})
            self.assertTrue(create.called)
            self.assertTrue(len(update_project.mock_calls), 2)
            self.assertTrue(len(mput.mock_calls), 2)
            self.assertFalse(mdelete.called)

    def test_delete_project_group(self):
        class FakeItem(object):
            def __init__(self, name, id):
                self.name = name
                self.id = id
        conf = dummy_conf()
        patches = [
            patch('storyboardclient.v1.project_groups.'
                  'ProjectGroupsManager.get_all'),
            patch('storyboardclient.v1.project_groups.'
                  'ProjectGroupsManager.get'),
            patch('storyboardclient.v1.project_groups.'
                  'ProjectGroupsManager.update'),
            patch('storyboardclient.v1.project_groups.'
                  'ProjectGroupsManager.delete')]
        with nested(*patches) as (get_all, get, update, delete):
            s = StoryboardOps(conf, None)
            get_all.return_value = [FakeItem('pg1', 3)]
            mdelete = Mock()
            fake_subprojects = [
                FakeItem('project1', 1),
                FakeItem('project2', 2)]

            class fprojects():
                def get_all(self):
                    return fake_subprojects

                def delete(self, id):
                    mdelete(id)

            class NestedProjects():
                def __init__(self):
                    self.projects = fprojects()

            get.return_value = NestedProjects()
            update.return_value = NestedProjects()

            s.delete_project_groups(**{'name': 'pg1'})
            self.assertEqual(len(mdelete.call_args_list), 2)
            self.assertIn(call(1), mdelete.call_args_list)
            self.assertIn(call(2), mdelete.call_args_list)
            self.assertListEqual(delete.call_args_list, [call(id=3)])
