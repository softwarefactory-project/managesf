# Copyright (C) 2017 Red Hat
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

from mock import Mock, patch
from managesf.tests import dummy_conf
from managesf.tests.fixtures import SAMPLE_RESOURCES_TREE

from webtest import TestApp
from pecan import load_app


c = dummy_conf()
config = {'services': c.services,
          'gerrit': c.gerrit,
          'app': c.app,
          'admin': c.admin,
          'sqlalchemy': c.sqlalchemy,
          'auth': c.auth,
          'htpasswd': c.htpasswd,
          'managesf': c.managesf,
          'storyboard': c.storyboard,
          'mysql': c.mysql,
          'policy': c.policy,
          'resources': c.resources,
          'jenkins': c.jenkins,
          'nodepool': c.nodepool,
          'api': c.api,
          'zuul': c.zuul, }

# App must be loaded before we can import v2 managers
TestApp(load_app(config))


from managesf.api.v2.resources.services import manageSF  # noQA


class TestPrepareResources(TestCase):
    def test_prepare_for_project(self):
        """test flattening resources for looking projects up"""
        mail = '%s@softwarefactory-project.io'
        raw_projects = manageSF.prepare_resources_data(SAMPLE_RESOURCES_TREE,
                                                       'project')
        self.assertTrue('tdpw-project' in raw_projects)
        self.assertEqual(9, len(raw_projects['tdpw-project']['repository']))
        self.assertEqual('tdpw', raw_projects['tdpw-project']['name'])
        self.assertTrue('tdpw-acl' in raw_projects['tdpw-project']['acl'])
        self.assertTrue(
            mail % 'adev' in raw_projects['tdpw-project']['member_id'])
        self.assertTrue(
            mail % 'alead' in raw_projects['tdpw-project']['member_id'])

    def test_prepare_for_acl(self):
        """test flattening resources for looking ACL up"""
        mail = 'admin@sftests.com'
        raw_acl = manageSF.prepare_resources_data(SAMPLE_RESOURCES_TREE,
                                                  'acl')
        self.assertTrue('config-acl' in raw_acl)
        self.assertEqual(2, len(raw_acl['config-acl']['repository']))
        self.assertEqual('config-acl', raw_acl['config-acl']['id'])
        self.assertTrue('internal' in raw_acl['config-acl']['project'])
        self.assertTrue('my_project' in raw_acl['config-acl']['project'])
        self.assertTrue(
            mail in raw_acl['config-acl']['member_id'])
        self.assertTrue(
            'sexbobomb' in raw_acl['config-acl']['repository'])
        self.assertTrue(
            'config' in raw_acl['config-acl']['repository'])


class TestProjectManager(TestCase):
    @classmethod
    def setupClass(cls):
        cls.manager = manageSF.SFResourcesManager(c)

    def test_get_ordering(self):
        """test ordering options when searching projects"""
        mock_engine = Mock()
        with patch.object(self.manager, 'get_engine') as ge:
            ge.return_value = mock_engine
            mock_engine.get.return_value = SAMPLE_RESOURCES_TREE
            # id
            projects = self.manager.projects.get(order_by='id')
            self.assertEqual(9, projects['total'], projects)
            ids = [p.id for p in projects['results']]
            sorted_ids = sorted(['tdpw-project', 'internal', 'my_project',
                                 'dummy_project86', 'dummy_project4',
                                 'dummy_project6', 'dummy_project1',
                                 'dummy_project2', 'dummy_project3', ])
            self.assertEqual(sorted_ids, ids, ids)
            # id, reversed
            projects = self.manager.projects.get(order_by='id', desc=True)
            self.assertEqual(9, projects['total'], projects)
            ids = [p.id for p in projects['results']]
            sorted_ids = sorted(['tdpw-project', 'internal', 'my_project',
                                 'dummy_project86', 'dummy_project4',
                                 'dummy_project6', 'dummy_project1',
                                 'dummy_project2', 'dummy_project3', ],
                                reverse=True)
            self.assertEqual(sorted_ids, ids, ids)
            # name
            projects = self.manager.projects.get(order_by='name')
            self.assertEqual(9, projects['total'], projects)
            names = [p.name for p in projects['results']]
            sorted_names = sorted(['tdpw', 'internal', 'my_project',
                                   'dummy_project86', 'dummy_project4',
                                   'dummy_project6', 'dummy_project1',
                                   'dummy_project2', 'dummy_project3', ])
            self.assertEqual(sorted_names, names, names)
            # name, reversed
            projects = self.manager.projects.get(order_by='name', desc=True)
            self.assertEqual(9, projects['total'], projects)
            names = [p.name for p in projects['results']]
            sorted_names = sorted(['tdpw', 'internal', 'my_project',
                                   'dummy_project86', 'dummy_project4',
                                   'dummy_project6', 'dummy_project1',
                                   'dummy_project2', 'dummy_project3', ],
                                  reverse=True)
            self.assertEqual(sorted_names, names, names)

    def test_get_filtering(self):
        """test filter options when searching projects"""
        mock_engine = Mock()
        with patch.object(self.manager, 'get_engine') as ge:
            ge.return_value = mock_engine
            mock_engine.get.return_value = SAMPLE_RESOURCES_TREE
            # id
            project = self.manager.projects.get(id='my_project')
            self.assertEqual(1, project['total'], project)
            self.assertEqual('my_project', project['results'][0].id)
            # name
            project = self.manager.projects.get(name='my_project')
            self.assertEqual(1, project['total'], project)
            self.assertEqual('my_project', project['results'][0].name)
            # website
            project = self.manager.projects.get(website='http://project.com')
            self.assertEqual(1, project['total'], project)
            self.assertEqual('http://project.com',
                             project['results'][0].website)
            # documentation
            project = self.manager.projects.get(
                documentation='http://doc.project.com')
            self.assertEqual(1, project['total'], project)
            self.assertEqual('http://doc.project.com',
                             project['results'][0].documentation)
            # issue_tracker
            project = self.manager.projects.get(
                issue_tracker='SFStoryboard')
            self.assertEqual(9, project['total'], project)
            self.assertTrue(all(p.issue_tracker == 'SFStoryboard'
                                for p in project['results']))
            # mailing_list
            project = self.manager.projects.get(
                mailing_list='ml@project.com')
            self.assertEqual(1, project['total'], project)
            self.assertTrue(
                'ml@project.com' in project['results'][0].mailing_lists)
            # contact
            project = self.manager.projects.get(
                contact='boss@project.com')
            self.assertEqual(1, project['total'], project)
            self.assertTrue(
                'boss@project.com' in project['results'][0].contacts)
            # repository
            project = self.manager.projects.get(
                repository='sexbobomb')
            self.assertEqual(1, project['total'], project)
            self.assertTrue(
                any(r.name == 'sexbobomb'
                    for r in project['results'][0].repositories))
            # member_email
            project = self.manager.projects.get(
                member_email='admin@sftests.com')
            self.assertEqual(8, project['total'], project)
            aggregated_members = {}
            for p in project['results']:
                for r in p.repositories:
                    for g in r.acl.groups:
                        for m in g.members:
                            aggregated_members[m] = 0
            aggregated_members = aggregated_members.keys() or []
            self.assertTrue('admin@sftests.com' in aggregated_members)
