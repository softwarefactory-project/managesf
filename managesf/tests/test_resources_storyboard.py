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

from managesf.tests import dummy_conf
from managesf.model.yamlbkd.resources.storyboard import StoryboardOps


def FakeItem(name, id):
    fi = Mock()
    fi.name = name
    fi.id = id
    return fi


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
            'name': 'project1',
            'source-repositories': ['repo1', 'repo2']
        }
        logs = s.extra_validations(**project)
        self.assertTrue(len(logs) == 0)
        project = {
            'name': 'project2',
            'source-repositories': ['re', '-hjook']
        }
        logs = s.extra_validations(**project)
        self.assertTrue('Minimal len is 3' in logs[0])
        self.assertTrue('should match the RE' in logs[1])

    def test_update_project(self):
        conf = dummy_conf()
        s = StoryboardOps(conf, None)
        with patch('storyboardclient.v1.projects.'
                   'ProjectsManager.get_all') as get_all, \
            patch('storyboardclient.v1.projects.'
                  'ProjectsManager.update') as update, \
            patch('storyboardclient.v1.projects.'
                  'ProjectsManager.create') as create:
            get_all.return_value = [FakeItem('project1', 1)]
            s.update_project('project1', 'A desc')
            get_all.assert_called_with(name='project1')
            update.assert_called()
            create.assert_not_called()
        with patch('storyboardclient.v1.projects.'
                   'ProjectsManager.get_all') as get_all, \
            patch('storyboardclient.v1.projects.'
                  'ProjectsManager.update') as update, \
            patch('storyboardclient.v1.projects.'
                  'ProjectsManager.create') as create:
            get_all.return_value = [FakeItem('project1', 1)]
            s.update_project('project2', 'A desc')
            get_all.assert_called_with(name='project2')
            update.assert_not_called()
            create.assert_called()

    def test_update_project_group(self):
        conf = dummy_conf()
        with patch('storyboardclient.v1.project_groups.'
                   'ProjectGroupsManager.get_all') as get_all, \
            patch('storyboardclient.v1.project_groups.'
                  'ProjectGroupsManager.create') as create, \
            patch.object(StoryboardOps, 'update_project') as update_project, \
            patch('storyboardclient.v1.project_groups.'
                  'ProjectGroupsManager.get') as get, \
            patch('storyboardclient.v1.project_groups.'
                  'ProjectGroupsManager.update') as update, \
            patch('storyboardclient.v1.projects.'
                  'ProjectsManager.get_all') as p_get_all:
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

            fprojects = Mock()
            fprojects.get_all.return_value = fake_subprojects

            nestedProjects = Mock()
            nestedProjects.projects = fprojects

            get.return_value = nestedProjects
            update.return_value = nestedProjects
            p_get_all.return_value = fake_subprojects

            # Here projects are already included in the project
            # group so nothing will be added/removed in the project
            # group. Just projects will be updated.
            s.update_project_groups(
                **{'name': 'pg1',
                   'source-repositories': ['project1', 'project2']})
            fprojects.put.assert_not_called()
            fprojects.delete.assert_not_called()
            self.assertTrue(len(update_project.mock_calls), 2)

            # Here project1 and project2 are already included but
            # the resources project decription only defines the
            # project2 to be included. So we make sure the delete
            # is called with id 1.
            nestedProjects.reset_mock()
            update_project.reset_mock()
            s.update_project_groups(
                **{'name': 'pg1',
                   'source-repositories': ['project2']})
            fprojects.put.assert_not_called()
            fprojects.delete.assert_called()
            self.assertListEqual(fprojects.delete.call_args_list, [call(id=1)])
            self.assertTrue(len(update_project.mock_calls), 1)

            # Here only project1 is already included but
            # the resources project decription defines the
            # project1 and project2 to be included. So we make sure
            # the put is called with id 2.
            nestedProjects.reset_mock()
            update_project.reset_mock()
            fake_subprojects = [
                FakeItem('project1', 1)]
            fprojects.get_all.return_value = fake_subprojects
            s.update_project_groups(
                **{'name': 'pg1',
                   'source-repositories': ['project1', 'project2']})
            fprojects.put.assert_called()
            self.assertListEqual(fprojects.put.call_args_list, [call(id=2)])
            fprojects.delete.assert_not_called()
            self.assertTrue(len(update_project.mock_calls), 1)

            # Here the project group does not exist. So we verify
            # it is created and provisionned with two projects
            # included.
            get_all.return_value = []
            p_get_all.return_value = [
                FakeItem('project1', 1),
                FakeItem('project2', 2)]
            fake_subprojects = []
            fprojects.get_all.return_value = fake_subprojects
            get.return_value = nestedProjects
            update.return_value = nestedProjects
            nestedProjects.reset_mock()
            update_project.reset_mock()
            s.update_project_groups(
                **{'name': 'pg1',
                   'source-repositories': ['project1', 'project2']})
            create.assert_called()
            self.assertTrue(len(update_project.mock_calls), 2)
            self.assertTrue(len(fprojects.put.mock_calls), 2)
            fprojects.delete.assert_not_called()

    def test_delete_project_group(self):

        conf = dummy_conf()
        with patch('storyboardclient.v1.project_groups.'
                   'ProjectGroupsManager.get_all') as get_all, \
            patch('storyboardclient.v1.project_groups.'
                  'ProjectGroupsManager.get') as get, \
            patch('storyboardclient.v1.project_groups.'
                  'ProjectGroupsManager.update') as update, \
            patch('storyboardclient.v1.project_groups.'
                  'ProjectGroupsManager.delete') as delete:
            s = StoryboardOps(conf, None)
            get_all.return_value = [FakeItem('pg1', 3)]
            fake_subprojects = [
                FakeItem('project1', 1),
                FakeItem('project2', 2)]

            fprojects = Mock()
            fprojects.get_all.return_value = fake_subprojects

            def NestedProjects():
                np = Mock()
                np.projects = fprojects
                return np

            get.return_value = NestedProjects()
            update.return_value = NestedProjects()

            s.delete_project_groups(**{'name': 'pg1'})
            self.assertEqual(len(fprojects.delete.call_args_list), 2)
            self.assertIn(call(id=1), fprojects.delete.call_args_list)
            self.assertIn(call(id=2), fprojects.delete.call_args_list)
            self.assertListEqual(delete.call_args_list, [call(id=3)])
