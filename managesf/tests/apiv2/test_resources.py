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
from mock import patch

from managesf.model.yamlbkd.resources.dummy import Dummy

c = dummy_conf()
config = {'services': c.services,
          'gerrit': c.gerrit,
          'app': c.app,
          'admin': c.admin,
          'sqlalchemy': c.sqlalchemy,
          'managesf': c.managesf,
          'policy': c.policy,
          'resources': c.resources,
          'api': c.api, }

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
        rtu.prepare_db_env(cls.db_path)
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
        rtu.prepare_db_env(self.db_path)
        return repo_path

    def test_get(self):
        """test raw resources get on resources manager"""
        data = {'resources': {'dummies': {
                'id1': {'name': 'resource_a'}
                }}}
        repo_path = self.prepare_repo(data)
        c.resources['master_repo'] = 'file://%s' % repo_path
        manager = manageSF.SFResourcesManager(c)
        with patch.dict('managesf.model.yamlbkd.engine.MAPPING',
                        {'dummies': Dummy}):
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
