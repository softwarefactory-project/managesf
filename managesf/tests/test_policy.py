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

import json
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
                       'redmine': c.redmine,
                       'app': c.app,
                       'admin': c.admin,
                       'sqlalchemy': c.sqlalchemy,
                       'auth': c.auth,
                       'htpasswd': c.htpasswd,
                       'sshconfig': c.sshconfig,
                       'managesf': c.managesf,
                       'jenkins': c.jenkins,
                       'storyboard': c.storyboard,
                       'mysql': c.mysql,
                       'nodepool': c.nodepool,
                       'etherpad': c.etherpad,
                       'lodgeit': c.lodgeit,
                       'pages': c.pages,
                       'policy': c.policy, }
        self.app = TestApp(load_app(self.config))

    def tearDown(self):
        # Remove the sqlite db
        os.unlink(self.config['sqlalchemy']['url'][len('sqlite:///'):])

    def test_project_policies(self):
        """Test the default project endpoint policies"""
        credentials = {}
        target = {}
        self.assertTrue(policy.authorize('managesf.project:get_one',
                                         target, credentials))
        self.assertTrue(policy.authorize('managesf.project:get_all',
                                         target, credentials))
        credentials = {'username': 'RickSanchez'}
        self.assertTrue(policy.authorize('managesf.project:get_one',
                                         target, credentials))
        self.assertTrue(policy.authorize('managesf.project:get_all',
                                         target, credentials))
        target = {'project': 'phoenix'}
        self.assertFalse(policy.authorize('managesf.project:create',
                                          target, credentials))
        self.assertFalse(policy.authorize('managesf.project:delete',
                                          target, credentials))
        credentials['groups'] = ['phoenix-core', ]
        self.assertFalse(policy.authorize('managesf.project:delete',
                                          target, credentials))
        credentials['groups'].append('phoenix-ptl')
        self.assertTrue(policy.authorize('managesf.project:delete',
                                         target, credentials))
        credentials['groups'] = ['schwifty-ptl']
        self.assertFalse(policy.authorize('managesf.project:delete',
                                          target, credentials))
        credentials = {'username': 'admin'}
        self.assertTrue(policy.authorize('managesf.project:delete',
                                         target, credentials))
        self.assertTrue(policy.authorize('managesf.project:create',
                                         target, credentials))

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
                       'redmine': c.redmine,
                       'app': c.app,
                       'admin': c.admin,
                       'sqlalchemy': c.sqlalchemy,
                       'auth': c.auth,
                       'htpasswd': c.htpasswd,
                       'sshconfig': c.sshconfig,
                       'managesf': c.managesf,
                       'jenkins': c.jenkins,
                       'storyboard': c.storyboard,
                       'mysql': c.mysql,
                       'nodepool': c.nodepool,
                       'etherpad': c.etherpad,
                       'lodgeit': c.lodgeit,
                       'pages': c.pages,
                       'policy': c.policy, }
        pol_file = tempfile.mkstemp()[1]
        with open(pol_file, 'w') as p:
            p.write(json.dumps(
                {"managesf.project:get_one": "rule:any",
                 "managesf.project:get_all": "rule:any",
                 "managesf.project:create": "rule:any",
                 "managesf.project:delete": "rule:any",
                 "is_morty": "username:morty",
                 "morty_api": "rule:is_morty"}))
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
        self.assertTrue(policy.authorize('managesf.project:create',
                                         target, credentials))
        self.assertTrue(policy.authorize('managesf.project:delete',
                                         target, credentials))
        self.assertFalse(policy.authorize('morty_api',
                                          target, credentials))
        credentials['username'] = 'Rick'
        self.assertFalse(policy.authorize('admin_api',
                                          target, credentials))
        self.assertTrue(policy.authorize('managesf.project:create',
                                         target, credentials))
        self.assertTrue(policy.authorize('managesf.project:delete',
                                         target, credentials))
        self.assertFalse(policy.authorize('morty_api',
                                          target, credentials))
        credentials['username'] = 'morty'
        self.assertFalse(policy.authorize('admin_api',
                                          target, credentials))
        self.assertTrue(policy.authorize('managesf.project:create',
                                         target, credentials))
        self.assertTrue(policy.authorize('managesf.project:delete',
                                         target, credentials))
        self.assertTrue(policy.authorize('morty_api',
                                         target, credentials))

    def test_change_in_file_policies(self):
        pol_file = self.config['policy']['policy_file']
        with open(pol_file, 'w') as p:
            p.write(json.dumps(
                {"managesf.project:get_one": "rule:any",
                 "managesf.project:get_all": "rule:any",
                 "managesf.project:create": "rule:none",
                 "is_rick": "username:Rick",
                 "rick_api": "rule:is_rick"}))
        credentials = {}
        target = {}
        try:
            admin_account = self.config.admin['name']
        except AttributeError:
            admin_account = 'admin'
        # make sure default rules are there
        self.assertFalse(policy.authorize('admin_api',
                                          target, credentials))
        self.assertFalse(policy.authorize('managesf.project:create',
                                          target, credentials))
        self.assertFalse(policy.authorize('managesf.project:delete',
                                          target, credentials))
        self.assertFalse(policy.authorize('rick_api',
                                          target, credentials))
        credentials['username'] = 'Rick'
        self.assertFalse(policy.authorize('admin_api',
                                          target, credentials))
        self.assertFalse(policy.authorize('managesf.project:create',
                                          target, credentials))
        self.assertFalse(policy.authorize('managesf.project:delete',
                                          target, credentials))
        self.assertTrue(policy.authorize('rick_api',
                                         target, credentials))
        credentials['username'] = 'morty'
        self.assertFalse(policy.authorize('admin_api',
                                          target, credentials))
        self.assertFalse(policy.authorize('managesf.project:create',
                                          target, credentials))
        self.assertFalse(policy.authorize('managesf.project:delete',
                                          target, credentials))
        self.assertFalse(policy.authorize('rick_api',
                                          target, credentials))
        credentials['username'] = admin_account
        self.assertTrue(policy.authorize('admin_api',
                                         target, credentials))
        self.assertFalse(policy.authorize('managesf.project:create',
                                          target, credentials))
        # the default rule should be used here
        self.assertTrue(policy.authorize('managesf.project:delete',
                                         target, credentials))
        self.assertFalse(policy.authorize('rick_api',
                                          target, credentials))
        # set back to normal
        with open(pol_file, 'w') as p:
            p.write(json.dumps(
                {"managesf.project:get_one": "rule:any",
                 "managesf.project:get_all": "rule:any",
                 "managesf.project:create": "rule:any",
                 "managesf.project:delete": "rule:any",
                 "is_morty": "username:morty",
                 "morty_api": "rule:is_morty"}))

    def tearDown(self):
        # Remove the sqlite db
        os.unlink(self.config['sqlalchemy']['url'][len('sqlite:///'):])
        os.unlink(self.config['policy']['policy_file'])
