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

import os
import yaml
import shutil
from unittest import TestCase

from managesf.tests import dummy_conf
from managesf.tests.fixtures import SAMPLE_RESOURCES_TREE
from managesf.tests import resources_test_utils as rtu

from webtest import TestApp
from pecan import load_app
import sqlalchemy as sqla
from mock import patch

from managesf.model.yamlbkd.resources.dummy import Dummy

c = dummy_conf()
config = {'services': c.services,
          'gerrit': c.gerrit,
          'app': c.app,
          'admin': c.admin,
          'sqlalchemy': c.sqlalchemy,
          'auth': c.auth,
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


class BaseTestResourceEndpoint(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db_path = []
        repo_path = rtu.prepare_git_repo(cls.db_path)
        rtu.add_yaml_data(repo_path, SAMPLE_RESOURCES_TREE)
        # Init the YAML DB
        clone_path, cache_path = rtu.prepare_db_env(cls.db_path)
        c.resources['master_repo'] = 'file://%s' % repo_path
        cls.manager = manageSF.SFResourcesManager(c)

    @classmethod
    def tearDownClass(cls):
        for db_path in cls.db_path:
            if os.path.isdir(db_path):
                shutil.rmtree(db_path)
            else:
                os.unlink(db_path)


class TestResourcesManager(BaseTestResourceEndpoint):

    @classmethod
    def setUpClass(cls):
        cls.db_path = []

    def prepare_repo(self, data):
        repo_path = rtu.prepare_git_repo(self.db_path)
        rtu.add_yaml_data(repo_path, data)
        # Init the YAML DB
        clone_path, cache_path = rtu.prepare_db_env(self.db_path)
        return repo_path

    def test_get(self):
        """test raw resources get on resources manager"""
        data = {'resources': {'dummies': {
                'id1': {'name': 'resource_a'}
                }}}
        repo_path = self.prepare_repo(data)
        c.resources['master_repo'] = 'file://%s' % repo_path
        manager = manageSF.SFResourcesManager(c)
        ret = manager.resources.get()
        self.assertIn("resources", ret)
        self.assertEqual(
            ret.get("config-repo"), 'file://%s' % repo_path)

    def test_create(self):
        """test validate resources on the resources manager"""
        data = {'resources': {'dummies': {}}}
        repo_path = self.prepare_repo(data)
        proposed_data = {
            'resources': {
                'dummies': {
                    'id1': {
                        'namespace': 'awesome',
                        'name': 'p1'}
                }
            }
        }
        c.resources['master_repo'] = 'file://%s' % repo_path
        manager = manageSF.SFResourcesManager(c)
        kwargs = {
            'data': {
                'fakepath': yaml.dump(proposed_data,
                                      default_flow_style=False)
            }
        }
        with patch.dict('managesf.model.yamlbkd.engine.MAPPING',
                        {'dummies': Dummy}):
            status, log = manager.resources.create(**kwargs)
        self.assertTrue(status)
        self.assertIn(
            'Resource [type: dummies, ID: id1] is going '
            'to be created.', log)
        proposed_data = {
            'resources': {
                'dummies': {
                    'idbogus': {
                        'namespace': 'awesome',
                        'n4me': 'p3'},
                    'id2': {
                        'namespace': 'awesome',
                        'name': 'p2'}
                }
            }
        }
        kwargs = {
            'data': {
                'fakepath': yaml.dump(proposed_data,
                                      default_flow_style=False)
            }
        }
        with patch.dict('managesf.model.yamlbkd.engine.MAPPING',
                        {'dummies': Dummy}):
            status, log = manager.resources.create(**kwargs)
        self.assertFalse(status)
        self.assertIn(
            "Resource [type: dummy, ID: idbogus] contains extra keys. "
            "Please check the model.", log)

    def test_update(self):
        """test apply resources on the resources manager"""
        data = {'resources': {'dummies': {}}}
        repo_path = self.prepare_repo(data)
        new_data = {'resources': {'dummies': {
                    'id1': {'namespace': 'awesome',
                            'name': 'p1'}}}}
        rtu.add_yaml_data(repo_path, new_data)
        c.resources['master_repo'] = 'file://%s' % repo_path
        manager = manageSF.SFResourcesManager(c)
        with patch.dict('managesf.model.yamlbkd.engine.MAPPING',
                        {'dummies': Dummy}):
            status, log = manager.resources.update()
        self.assertIn("Resource [type: dummies, ID: id1] will be "
                      "created.", log)
        self.assertIn("Resource [type: dummies, ID: id1] has been "
                      "created.", log)
        self.assertEqual(len(log), 2)
        self.assertTrue(status)
        # Direct apply
        prev = "resources: {}"
        new = """resources:
  dummies:
    id1:
      name: dum
      namespace: a
"""
        kwargs = {'prev': prev, 'new': new}
        with patch.dict('managesf.model.yamlbkd.engine.MAPPING',
                        {'dummies': Dummy}):
            status, log = manager.resources.update(**kwargs)
        self.assertListEqual(
            log,
            ["Resource [type: dummies, ID: id1] is going to be created.",
             "Resource [type: dummies, ID: id1] will be created.",
             "Resource [type: dummies, ID: id1] has been created."])
        self.assertTrue(status)


class TestSQLiteResources(BaseTestResourceEndpoint):

    def test_sqlite_resources(self):
        """Make sure resources are correctly cached in SQLite base"""
        r = self.manager.get_engine('read').get_sql(self.manager.master_repo,
                                                    'master')
        engine = r['engine']
        tables = r['tables']
        counts = {'project': 9,
                  'mailing_list': 1,
                  'contact': 1,
                  'acl': 8,
                  'repository': 17,
                  'project_repo': 17,
                  'group': 16,
                  'acl_group': 16,
                  'member': 16}
        for t in ['project', 'mailing_list', 'contact', 'acl',
                  'repository', 'project_repo', 'group', 'member',
                  'acl_group']:
            self.assertTrue(t in tables)
            with engine.begin() as conn:
                query = sqla.select([sqla.func.count('*')])
                query = query.select_from(tables[t])
                check_query = tables[t].select()
                total = conn.execute(query).fetchall()
                check = conn.execute(check_query).fetchall()
                if total:
                    total = total[0][0]
                else:
                    total = 0
                self.assertEqual(counts[t], total,
                                 "%s:\n %s" % (t, check))


class TestProjectManager(BaseTestResourceEndpoint):

    def test_get_ordering(self):
        """test ordering options when searching projects"""
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
        sorted_ids = sorted(sorted_ids, reverse=True)
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
        sorted_names = sorted(sorted_names, reverse=True)
        self.assertEqual(sorted_names, names, names)

    def test_get_filtering(self):
        """test filter options when searching projects"""
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
            'sexbobomb' in project['results'][0].source_repositories,
            project['results'][0].to_dict())
        # member_email
        project = self.manager.projects.get(
            member_email='admin@sftests.com')
        self.assertEqual(8, project['total'], project)
        aggregated_members = {}
        for p in project['results']:
            for r in p.source_repositories:
                repo = self.manager.repositories.get(id=r)['results'][0]
                ACL = self.manager.acls.get(id=repo.acl)['results'][0]
                for g in ACL.groups:
                    grp = self.manager.groups.get(id=g)['results'][0]
                    for m in grp.members:
                        aggregated_members[m] = 0
        aggregated_members = aggregated_members.keys() or []
        self.assertTrue('admin@sftests.com' in aggregated_members)


class TestRepositoryManager(BaseTestResourceEndpoint):

    def test_get_ordering(self):
        """test ordering options when searching repositories"""
        # id
        repos = self.manager.repositories.get(order_by='id')
        self.assertEqual(17, repos['total'], repos)
        ids = [r.id for r in repos['results']]
        sorted_ids = sorted([u'tdpw/python-readerlib',
                             u'tdpw/python-readerlib-distgit',
                             u'tdpw/reader', u'tdpw/reader-ansible',
                             u'tdpw/reader-ansible-distgit',
                             u'tdpw/reader-distgit',
                             u'tdpw/tdpw-info',
                             u'tdpw/tdpw-installer',
                             u'tdpw/tdpw-installer-distgit',
                             'config', 'sexbobomb',
                             'dummy_project86', 'dummy_project4',
                             'dummy_project6', 'dummy_project1',
                             'dummy_project2', 'dummy_project3', ])
        self.assertEqual(sorted_ids, ids, '%s != %s' % (ids, sorted_ids))
        # id, reversed
        repos = self.manager.repositories.get(order_by='id', desc=True)
        self.assertEqual(17, repos['total'], repos)
        ids = [r.id for r in repos['results']]
        sorted_ids = sorted(sorted_ids, reverse=True)
        self.assertEqual(sorted_ids, ids, ids)
        # name
        repos = self.manager.repositories.get(order_by='name')
        self.assertEqual(17, repos['total'], repos)
        names = [r.name for r in repos['results']]
        sorted_names = sorted([u'tdpw/python-readerlib',
                               u'tdpw/python-readerlib-distgit',
                               u'tdpw/reader', u'tdpw/reader-ansible',
                               u'tdpw/reader-ansible-distgit',
                               u'tdpw/reader-distgit',
                               u'tdpw/tdpw-info',
                               u'tdpw/tdpw-installer',
                               u'tdpw/tdpw-installer-distgit',
                               'config', 'sexbobomb',
                               'dummy_project86', 'dummy_project4',
                               'dummy_project6', 'dummy_project1',
                               'dummy_project2', 'dummy_project3', ])
        self.assertEqual(sorted_names, names, names)
        # name, reversed
        repos = self.manager.repositories.get(order_by='name', desc=True)
        self.assertEqual(17, repos['total'], repos)
        names = [r.name for r in repos['results']]
        sorted_names = sorted(sorted_names, reverse=True)
        self.assertEqual(sorted_names, names, names)

    def test_get_filtering(self):
        """test filter options when searching repositories"""
        # id
        repo = self.manager.repositories.get(id='sexbobomb')
        self.assertEqual(1, repo['total'], repo)
        self.assertEqual('sexbobomb', repo['results'][0].id)
        # name
        repo = self.manager.repositories.get(name='sexbobomb')
        self.assertEqual(1, repo['total'], repo)
        self.assertEqual('sexbobomb', repo['results'][0].name)
        # project
        repo = self.manager.repositories.get(
            project='my_project')
        self.assertEqual(1, repo['total'], repo)
        self.assertEqual('sexbobomb', repo['results'][0].id)
        # acl
        repo = self.manager.repositories.get(
            acl='dummy_project6-acl')
        self.assertEqual(1, repo['total'], repo)
        self.assertEqual('dummy_project6', repo['results'][0].name)
        # member_email
        repo = self.manager.repositories.get(
            member_email='alead@softwarefactory-project.io')
        self.assertEqual(9, repo['total'], repo)
        aggregated_members = {}
        for r in repo['results']:
            ACL = self.manager.acls.get(id=r.acl)['results'][0]
            for g in ACL.groups:
                grp = self.manager.groups.get(id=g)['results'][0]
                for m in grp.members:
                    aggregated_members[m] = 0
        aggregated_members = aggregated_members.keys() or []
        self.assertTrue(
            'alead@softwarefactory-project.io' in aggregated_members)


class TestACLManager(BaseTestResourceEndpoint):

    def test_get_ordering(self):
        """test ordering options when searching ACLs"""
        # id
        acl = self.manager.acls.get(order_by='id')
        self.assertEqual(8, acl['total'], acl)
        ids = [a.id for a in acl['results']]
        sorted_ids = sorted([u'tdpw-acl', 'config-acl',
                             'dummy_project86-acl', 'dummy_project4-acl',
                             'dummy_project6-acl', 'dummy_project1-acl',
                             'dummy_project2-acl', 'dummy_project3-acl', ])
        self.assertEqual(sorted_ids, ids, '%s != %s' % (ids, sorted_ids))
        # id, reversed
        acl = self.manager.acls.get(order_by='id', desc=True)
        self.assertEqual(8, acl['total'], acl)
        ids = [a.id for a in acl['results']]
        sorted_ids = sorted(sorted_ids, reverse=True)
        self.assertEqual(sorted_ids, ids, '%s != %s' % (ids, sorted_ids))

    def test_get_filtering(self):
        """test filter options when searching ACLs"""
        # id
        acl = self.manager.acls.get(id='config-acl')
        self.assertEqual(1, acl['total'], acl)
        self.assertEqual('config-acl', acl['results'][0].id)
        # group
        acl = self.manager.acls.get(group='config-core')
        self.assertEqual(1, acl['total'], acl)
        self.assertEqual('config-acl', acl['results'][0].id)
        self.assertTrue('config-core' in acl['results'][0].groups)
        # project
        acl = self.manager.acls.get(
            project='my_project')
        self.assertEqual(1, acl['total'], acl)
        self.assertEqual('config-acl', acl['results'][0].id)
        # repository
        acl = self.manager.acls.get(
            repository='sexbobomb')
        self.assertEqual(1, acl['total'], acl)
        self.assertEqual('config-acl', acl['results'][0].id)
        # member_email
        acl = self.manager.acls.get(
            member_email='alead@softwarefactory-project.io')
        self.assertEqual(1, acl['total'], acl)
        self.assertEqual('tdpw-acl', acl['results'][0].id)
        aggregated_members = {}
        for a in acl['results']:
            for g in a.groups:
                grp = self.manager.groups.get(id=g)['results'][0]
                for m in grp.members:
                    aggregated_members[m] = 0
        aggregated_members = aggregated_members.keys() or []
        self.assertTrue(
            'alead@softwarefactory-project.io' in aggregated_members)


class TestGroupManager(BaseTestResourceEndpoint):

    def test_get_ordering(self):
        """test ordering options when searching groups"""
        # id
        grp = self.manager.groups.get(order_by='id')
        self.assertEqual(16, grp['total'], grp)
        ids = [g.id for g in grp['results']]
        sorted_ids = sorted([u'tdpw-ptl', 'tdpw-core',
                             'config-ptl', 'config-core',
                             'dummy_project86-ptl', 'dummy_project86-core',
                             'dummy_project4-ptl', 'dummy_project4-core',
                             'dummy_project6-ptl', 'dummy_project6-core',
                             'dummy_project1-ptl', 'dummy_project1-core',
                             'dummy_project2-ptl', 'dummy_project2-core',
                             'dummy_project3-ptl', 'dummy_project3-core'])
        self.assertEqual(sorted_ids, ids, '%s != %s' % (ids, sorted_ids))
        # id, reversed
        grp = self.manager.groups.get(order_by='id', desc=True)
        self.assertEqual(16, grp['total'], grp)
        ids = [g.id for g in grp['results']]
        sorted_ids = sorted(sorted_ids, reverse=True)
        self.assertEqual(sorted_ids, ids, '%s != %s' % (ids, sorted_ids))
        # name
        grp = self.manager.groups.get(order_by='name')
        self.assertEqual(16, grp['total'], grp)
        ids = [g.name for g in grp['results']]
        sorted_ids = sorted([u'tdpw-ptl', 'tdpw-core',
                             'config-ptl', 'config-core',
                             'dummy_project86-ptl', 'dummy_project86-core',
                             'dummy_project4-ptl', 'dummy_project4-core',
                             'dummy_project6-ptl', 'dummy_project6-core',
                             'dummy_project1-ptl', 'dummy_project1-core',
                             'dummy_project2-ptl', 'dummy_project2-core',
                             'dummy_project3-ptl', 'dummy_project3-core'])
        self.assertEqual(sorted_ids, ids, '%s != %s' % (ids, sorted_ids))
        # name, reversed
        grp = self.manager.groups.get(order_by='name', desc=True)
        self.assertEqual(16, grp['total'], grp)
        ids = [g.name for g in grp['results']]
        sorted_ids = sorted(sorted_ids, reverse=True)
        self.assertEqual(sorted_ids, ids, '%s != %s' % (ids, sorted_ids))

    def test_get_filtering(self):
        """test filter options when searching groups"""
        # id
        grp = self.manager.groups.get(id='config-core')
        self.assertEqual(1, grp['total'], grp)
        self.assertEqual('config-core', grp['results'][0].id)
        # name
        grp = self.manager.groups.get(name='config-core')
        self.assertEqual(1, grp['total'], grp)
        self.assertEqual('config-core', grp['results'][0].name)
        # acl
        grp = self.manager.groups.get(acl='config-acl')
        self.assertEqual(2, grp['total'], grp)
        for x in ['config-core', 'config-ptl']:
            self.assertTrue(any(g.id == x for g in grp['results']))
        # project
        grp = self.manager.groups.get(
            project='my_project')
        self.assertEqual(2, grp['total'], grp)
        for x in ['config-core', 'config-ptl']:
            self.assertTrue(any(g.id == x for g in grp['results']))
        # repository
        grp = self.manager.groups.get(
            repository='sexbobomb')
        self.assertEqual(2, grp['total'], grp)
        for x in ['config-core', 'config-ptl']:
            self.assertTrue(any(g.id == x for g in grp['results']))
        # member_email
        grp = self.manager.groups.get(
            member_email='adev@softwarefactory-project.io')
        self.assertEqual(1, grp['total'], grp)
        self.assertEqual('tdpw-core', grp['results'][0].id)
        self.assertTrue(
            'adev@softwarefactory-project.io' in grp['results'][0].members)
