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
import yaml
import shutil

from unittest import TestCase
from mock import patch

from managesf.model.yamlbkd import yamlbackend
from managesf.tests import resources_test_utils as rtu


class YAMLBackendTest(TestCase):
    def setUp(self):
        self.db_path = []

    def tearDown(self):
        for db_path in self.db_path:
            if os.path.isdir(db_path):
                shutil.rmtree(db_path)
            else:
                os.unlink(db_path)

    def test_load_valid_db_data(self):
        # Prepare a GIT repo with content
        repo_path = rtu.prepare_git_repo(self.db_path)
        # Add a file of data
        data = {'resources': {'projects': {
                'id1': {'name': 'resource_a'}
                }}}
        rtu.add_yaml_data(repo_path, data)
        # Init the YAML DB
        clone_path, cache_path = rtu.prepare_db_env(self.db_path)
        db = yamlbackend.YAMLBackend("file://%s" % repo_path,
                                     "master", "resources",
                                     clone_path, cache_path)
        self.assertIn('id1', db.get_data()['resources']['projects'])
        # Add another file of data
        data = {'resources': {'projects': {
                'id2': {'name': 'resource_b'}
                }}}
        rtu.add_yaml_data(repo_path, data)
        db.refresh()
        project_ids = db.get_data()['resources']['projects'].keys()
        self.assertIn('id1', project_ids)
        self.assertIn('id2', project_ids)
        self.assertEqual(len(project_ids), 2)
        # Add another file of data for another resource
        data = {'resources': {'groups': {
                'id': {'name': 'resource_a'}
                }}}
        rtu.add_yaml_data(repo_path, data)
        db.refresh()
        group_ids = db.get_data()['resources']['groups'].keys()
        self.assertIn('id', group_ids)

    def test_load_invalid_db_data(self):
        # Prepare a GIT repo with content
        repo_path = rtu.prepare_git_repo(self.db_path)
        # Add a file of invalid data
        data = {'resources': {'projects': {
                'id1': {'name': 'resource_a'},
                }}}
        data2 = {'resources': {'projects': {
                 'id1': {'name': 'resource_b'},
                 }}}
        rtu.add_yaml_data(repo_path, data)
        rtu.add_yaml_data(repo_path, data2)
        # Init the YAML DB
        clone_path, cache_path = rtu.prepare_db_env(self.db_path)
        with self.assertRaises(yamlbackend.YAMLDBException):
            yamlbackend.YAMLBackend("file://%s" % repo_path,
                                    "master", "resources",
                                    clone_path,
                                    cache_path)

    def test_db_data_struct(self):
        # Init the DB with valid data
        repo_path = rtu.prepare_git_repo(self.db_path)
        data = {'resources': {'projects': {}}}
        rtu.add_yaml_data(repo_path, data)
        clone_path, cache_path = rtu.prepare_db_env(self.db_path)
        db = yamlbackend.YAMLBackend("file://%s" % repo_path,
                                     "master", "resources",
                                     clone_path,
                                     cache_path)
        # Try to validate a bunch a invalid data
        for data in [
            42,
            [],
            {'wrong': {}},
            {'resources': {4: []}},
            {'resources': {'projects': [None]}},
            {'resources': {'projects': {None: []}}},
            {'resources': {'projects': {'id': []}}},
            {'resources': {'projects': {'id': []}, 'groups': {'id': []}}},
        ]:
            self.assertRaises(yamlbackend.YAMLDBException,
                              db.validate, data)

    def test_db_data_struct_extra(self):
        # Init the DB with valid data
        repo_path = rtu.prepare_git_repo(self.db_path)

        data = """
'
   resources:
projects: {}
"""
        rtu.add_yaml_data(repo_path, data, free_style=True)
        clone_path, cache_path = rtu.prepare_db_env(self.db_path)
        self.assertRaises(yamlbackend.YAMLDBException,
                          yamlbackend.YAMLBackend,
                          "file://%s" % repo_path,
                          "master", "resources",
                          clone_path, cache_path)

    def test_db_cache(self):
        # Init the DB with validate data
        repo_path = rtu.prepare_git_repo(self.db_path)
        data = {'resources': {'projects': {}}}
        rtu.add_yaml_data(repo_path, data)
        clone_path, cache_path = rtu.prepare_db_env(self.db_path)
        db = yamlbackend.YAMLBackend("file://%s" % repo_path,
                                     "master", "resources",
                                     clone_path,
                                     cache_path)
        # Some verification about the cache content
        repo_hash = db._get_repo_hash()
        cache_hash = db._get_cache_hash()
        self.assertEqual(repo_hash, cache_hash)
        cached_data = yaml.load(file(db.cache_path))
        self.assertIn('projects', cached_data['resources'])
        # Add more data in the db
        data = {'resources': {'groups': {}}}
        rtu.add_yaml_data(repo_path, data)
        db = yamlbackend.YAMLBackend("file://%s" % repo_path,
                                     "master", "resources",
                                     clone_path,
                                     cache_path)
        repo_hash2 = db._get_repo_hash()
        cache_hash2 = db._get_cache_hash()
        self.assertEqual(repo_hash2, cache_hash2)
        self.assertNotEqual(cache_hash, cache_hash2)
        cached_data2 = yaml.load(file(db.cache_path))
        self.assertIn('projects', cached_data2['resources'])
        self.assertIn('groups', cached_data2['resources'])
        # Re-create the YAMLBackend instance whithout changed
        # in the upstream GIT repo
        with patch.object(yamlbackend.YAMLBackend, '_load_db') as l:
            with patch.object(yamlbackend.YAMLBackend, '_update_cache') as u:
                db = yamlbackend.YAMLBackend("file://%s" % repo_path,
                                             "master", "resources",
                                             clone_path,
                                             cache_path)
        cache_hash3 = db._get_cache_hash()
        self.assertEqual(cache_hash3, cache_hash2)
        self.assertFalse(l.called or u.called)
