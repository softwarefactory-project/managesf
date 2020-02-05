# -*- coding: utf-8 -*-
#
# Copyright (c) 2015 Red Hat, Inc.
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

import yaml
import os
from unittest import TestCase
from webtest import TestApp
import tempfile

from pecan import load_app

from managesf.tests import dummy_conf
from managesf import policy
from managesf.policies import base


""""Test the policy engine"""


class TestPolicyEngine(TestCase):
    def setUp(self):
        c = dummy_conf()
        self.config = {'services': c.services,
                       'gerrit': c.gerrit,
                       'app': c.app,
                       'admin': c.admin,
                       'sqlalchemy': c.sqlalchemy,
                       'managesf': c.managesf,
                       'policy': c.policy,
                       'api': c.api, }
        self.app = TestApp(load_app(self.config))

    def tearDown(self):
        # Remove the sqlite db
        os.unlink(self.config['sqlalchemy']['url'][len('sqlite:///'):])

    def test_config_policies(self):
        """Test the default config endpoint policies"""
        credentials = {}
        target = {}
        self.assertFalse(policy.authorize('managesf.config:get',
                                          target, credentials))
        credentials = {'username': 'BirdPerson'}
        self.assertTrue(policy.authorize('managesf.config:get',
                                         target, credentials))

    def test_hooks_policies(self):
        """Test the default hooks endpoint policies"""
        credentials = {}
        target = {}
        self.assertFalse(policy.authorize('managesf.hooks:trigger',
                                          target, credentials))
        credentials = {'username': 'RickSanchez'}
        self.assertFalse(policy.authorize('managesf.hooks:trigger',
                                          target, credentials))
        credentials = {'username': 'admin'}
        self.assertTrue(policy.authorize('managesf.hooks:trigger',
                                         target, credentials))
        credentials = {'username': 'SF_SERVICE_USER'}
        self.assertTrue(policy.authorize('managesf.hooks:trigger',
                                         target, credentials))

    def test_localuser_policies(self):
        """Test the default localuser endpoint policies"""
        credentials = {}
        target = {}
        self.assertFalse(policy.authorize('managesf.localuser:get',
                                          target, credentials))
        self.assertFalse(policy.authorize('managesf.localuser:create_update',
                                          target, credentials))
        self.assertFalse(policy.authorize('managesf.localuser:delete',
                                          target, credentials))
        self.assertTrue(policy.authorize('managesf.localuser:bind',
                                         target, credentials))
        credentials = {'username': 'RickSanchez',
                       'groups': []}
        self.assertTrue(policy.authorize('managesf.localuser:get',
                                         target, credentials))
        self.assertFalse(policy.authorize('managesf.localuser:create_update',
                                          target, credentials))
        self.assertFalse(policy.authorize('managesf.localuser:delete',
                                          target, credentials))
        self.assertTrue(policy.authorize('managesf.localuser:bind',
                                         target, credentials))
        target = {'username': 'RickSanchez'}
        self.assertTrue(policy.authorize('managesf.localuser:create_update',
                                         target, credentials))
        self.assertTrue(policy.authorize('managesf.localuser:delete',
                                         target, credentials))
        target = {'username': 'Morty'}
        self.assertTrue(policy.authorize('managesf.localuser:get',
                                         target, credentials))
        self.assertFalse(policy.authorize('managesf.localuser:create_update',
                                          target, credentials))
        self.assertFalse(policy.authorize('managesf.localuser:delete',
                                          target, credentials))
        credentials['username'] = 'Morty'
        self.assertTrue(policy.authorize('managesf.localuser:create_update',
                                         target, credentials))
        self.assertTrue(policy.authorize('managesf.localuser:delete',
                                         target, credentials))

    def test_resources_policies(self):
        """Test the default resources endpoint policies"""
        credentials = {}
        self.assertTrue(policy.authorize('managesf.resources:get',
                                         {}, credentials))
        self.assertFalse(policy.authorize('managesf.resources:validate',
                                          {}, credentials))
        self.assertFalse(policy.authorize('managesf.resources:apply',
                                          {}, credentials))
        credentials = {'username': 'shimajiro'}
        self.assertTrue(policy.authorize('managesf.resources:get',
                                         {}, credentials))
        self.assertFalse(policy.authorize('managesf.resources:validate',
                                          {}, credentials))
        self.assertFalse(policy.authorize('managesf.resources:apply',
                                          {}, credentials))
        credentials = {'username': 'admin'}
        self.assertTrue(policy.authorize('managesf.resources:get',
                                         {}, credentials))
        self.assertTrue(policy.authorize('managesf.resources:validate',
                                         {}, credentials))
        self.assertTrue(policy.authorize('managesf.resources:apply',
                                         {}, credentials))
        credentials = {'username': 'SF_SERVICE_USER'}
        self.assertTrue(policy.authorize('managesf.resources:get',
                                         {}, credentials))
        self.assertTrue(policy.authorize('managesf.resources:validate',
                                         {}, credentials))
        self.assertTrue(policy.authorize('managesf.resources:apply',
                                         {}, credentials))

    def test_default_policies(self):
        """Test the default policies that come with a default deployment"""
        credentials = {}
        target = {}
        try:
            admin_account = self.config.admin['name']
        except AttributeError:
            admin_account = 'admin'
        self.assertTrue(policy.authorize('any',
                                         target, credentials))
        self.assertFalse(policy.authorize('none',
                                          target, credentials))
        self.assertFalse(policy.authorize('authenticated_api',
                                          target, credentials))
        credentials = {'username': 'Morty'}
        self.assertTrue(policy.authorize('any',
                                         target, credentials))
        self.assertFalse(policy.authorize('none',
                                          target, credentials))
        self.assertTrue(policy.authorize('authenticated_api',
                                         target, credentials))
        self.assertFalse(policy.authorize('admin_api',
                                          target, credentials))
        credentials = {'username': admin_account}
        self.assertTrue(policy.authorize('authenticated_api',
                                         target, credentials))
        self.assertTrue(policy.authorize('any',
                                         target, credentials))
        self.assertFalse(policy.authorize('none',
                                          target, credentials))
        self.assertTrue(policy.authorize('admin_api',
                                         target, credentials))
        self.assertTrue(policy.authorize('admin_or_service',
                                         target, credentials))
        self.assertFalse(policy.authorize('owner_api',
                                          target, credentials))
        self.assertTrue(policy.authorize('admin_or_owner',
                                         target, credentials))
        self.assertFalse(policy.authorize('contributor_api',
                                          target, credentials))
        credentials = {'username': base.SERVICE_USER}
        self.assertTrue(policy.authorize('authenticated_api',
                                         target, credentials))
        self.assertTrue(policy.authorize('any',
                                         target, credentials))
        self.assertFalse(policy.authorize('none',
                                          target, credentials))
        self.assertFalse(policy.authorize('admin_api',
                                          target, credentials))
        self.assertTrue(policy.authorize('admin_or_service',
                                         target, credentials))
        self.assertFalse(policy.authorize('owner_api',
                                          target, credentials))
        credentials = {'username': 'Jerry'}
        target = {'username': 'Summer'}
        self.assertTrue(policy.authorize('authenticated_api',
                                         target, credentials))
        self.assertTrue(policy.authorize('any',
                                         target, credentials))
        self.assertFalse(policy.authorize('none',
                                          target, credentials))
        self.assertFalse(policy.authorize('admin_api',
                                          target, credentials))
        self.assertFalse(policy.authorize('owner_api',
                                          target, credentials))
        target = {'username': 'Jerry'}
        self.assertTrue(policy.authorize('owner_api',
                                         target, credentials))
        credentials['groups'] = ['p0-dev', ]
        target = {'project': 'p1'}
        self.assertTrue(policy.authorize('any',
                                         target, credentials))
        self.assertFalse(policy.authorize('dev_api',
                                          target, credentials))
        self.assertFalse(policy.authorize('core_api',
                                          target, credentials))
        self.assertFalse(policy.authorize('ptl_api',
                                          target, credentials))
        self.assertFalse(policy.authorize('contributor_api',
                                          target, credentials))
        target = {'project': 'p0'}
        self.assertTrue(policy.authorize('dev_api',
                                         target, credentials))
        self.assertFalse(policy.authorize('core_api',
                                          target, credentials))
        self.assertFalse(policy.authorize('ptl_api',
                                          target, credentials))
        self.assertTrue(policy.authorize('contributor_api',
                                         target, credentials))
        credentials['groups'] = ['p0-core', ]
        self.assertFalse(policy.authorize('dev_api',
                                          target, credentials))
        self.assertTrue(policy.authorize('core_api',
                                         target, credentials))
        self.assertFalse(policy.authorize('ptl_api',
                                          target, credentials))
        self.assertTrue(policy.authorize('contributor_api',
                                         target, credentials))
        credentials['groups'] = ['p0-ptl', ]
        self.assertFalse(policy.authorize('dev_api',
                                          target, credentials))
        self.assertFalse(policy.authorize('core_api',
                                          target, credentials))
        self.assertTrue(policy.authorize('ptl_api',
                                         target, credentials))
        self.assertTrue(policy.authorize('contributor_api',
                                         target, credentials))


class TestPolicyEngineFromFile(TestCase):
    def setUp(self):
        c = dummy_conf()
        self.config = {'services': c.services,
                       'gerrit': c.gerrit,
                       'app': c.app,
                       'admin': c.admin,
                       'sqlalchemy': c.sqlalchemy,
                       'managesf': c.managesf,
                       'policy': c.policy, }
        pol_file = tempfile.mkstemp()[1] + '.yaml'
        with open(pol_file, 'w') as p:
            yaml.dump(
                {"is_morty": "username:morty",
                 "morty_api": "rule:is_morty"},
                p, default_flow_style=False)
        self.config['policy']['policy_file'] = pol_file
        self.app = TestApp(load_app(self.config))

    def test_file_policies(self):
        """Test that the specified policies are taken into account"""
        credentials = {}
        target = {}
        try:
            admin_account = self.config.admin['name']
        except AttributeError:
            admin_account = 'admin'
        # make sure default rules are there
        self.assertFalse(policy.authorize('admin_api',
                                          target, credentials))
        self.assertTrue(policy.authorize('admin_api',
                                         target,
                                         {'username': admin_account}))
        self.assertFalse(policy.authorize('morty_api',
                                          target, credentials))
        credentials['username'] = 'Rick'
        self.assertFalse(policy.authorize('admin_api',
                                          target, credentials))
        self.assertFalse(policy.authorize('morty_api',
                                          target, credentials))
        credentials['username'] = 'morty'
        self.assertFalse(policy.authorize('admin_api',
                                          target, credentials))
        self.assertTrue(policy.authorize('morty_api',
                                         target, credentials))

    def test_change_in_file_policies(self):
        pol_file = self.config['policy']['policy_file']
        with open(pol_file, 'w') as p:
            yaml.dump(
                {"is_rick": "username:Rick",
                 "rick_api": "rule:is_rick"},
                p, default_flow_style=False)
        credentials = {}
        target = {}
        try:
            admin_account = self.config.admin['name']
        except AttributeError:
            admin_account = 'admin'
        # make sure default rules are there
        self.assertFalse(policy.authorize('admin_api',
                                          target, credentials))
        self.assertFalse(policy.authorize('rick_api',
                                          target, credentials))
        credentials['username'] = 'Rick'
        self.assertFalse(policy.authorize('admin_api',
                                          target, credentials))
        self.assertTrue(policy.authorize('rick_api',
                                         target, credentials))
        credentials['username'] = 'morty'
        self.assertFalse(policy.authorize('admin_api',
                                          target, credentials))
        self.assertFalse(policy.authorize('rick_api',
                                          target, credentials))
        credentials['username'] = admin_account
        self.assertTrue(policy.authorize('admin_api',
                                         target, credentials))
        self.assertFalse(policy.authorize('rick_api',
                                          target, credentials))
        # set back to normal
        with open(pol_file, 'w') as p:
            yaml.dump(
                {"is_morty": "username:morty",
                 "morty_api": "rule:is_morty"},
                p, default_flow_style=False)

    def tearDown(self):
        # Remove the sqlite db
        os.unlink(self.config['sqlalchemy']['url'][len('sqlite:///'):])
        os.unlink(self.config['policy']['policy_file'])
