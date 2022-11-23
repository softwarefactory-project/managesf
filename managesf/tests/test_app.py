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

import os
import shutil

from unittest import TestCase
from webtest import TestApp
from pecan import load_app


from managesf.tests import dummy_conf

# plugins imports
# TODO: should be done dynamically depending on what plugins we want


def raiseexc(*args, **kwargs):
    raise Exception('FakeExcMsg')


class FunctionalTest(TestCase):
    def setUp(self):
        self.to_delete = []
        c = dummy_conf()
        self.config = {'services': c.services,
                       'gerrit': c.gerrit,
                       'app': c.app,
                       'admin': c.admin,
                       'sqlalchemy': c.sqlalchemy,
                       'managesf': c.managesf,
                       'policy': c.policy,
                       'resources': c.resources,
                       'api': c.api, }
        # deactivate loggin that polute test output
        # even nologcapture option of nose effetcs
        # 'logging': c.logging}
        self.app = TestApp(load_app(self.config))

    def tearDown(self):
        # Remove the sqlite db
        os.unlink(self.config['sqlalchemy']['url'][len('sqlite:///'):])
        for path in self.to_delete:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.unlink(path)


class TestManageSFAPIv2(FunctionalTest):
    def test_get_api_endpoint(self):
        response = self.app.get('/v2/about/').json
        self.assertEqual('managesf',
                         response['service']['name'])
        self.assertEqual(set(self.config['services']),
                         set(response['service']['services']))


class TestManageSFIntrospectionController(FunctionalTest):

    def test_instrospection(self):
        response = self.app.get('/about/').json
        self.assertEqual('managesf',
                         response['service']['name'])
        self.assertEqual(set(self.config['services']),
                         set(response['service']['services']))


# def project_get(*args, **kwargs):
#     if kwargs.get('by_user'):
#         return ['p1', ]
#     return ['p0', 'p1']
