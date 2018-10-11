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
import shutil
import tempfile

from unittest import TestCase
from mock import patch

from managesf.tests import dummy_conf

from managesf.model.yamlbkd import engine
from managesf.model.yamlbkd.engine import SFResourceBackendEngine
from managesf.model.yamlbkd.engine import ResourceDepsException
from managesf.model.yamlbkd.engine import ResourceUnicityException
from managesf.model.yamlbkd.engine import RTYPENotDefinedException

from managesf.model.yamlbkd.yamlbackend import YAMLDBException
from managesf.model.yamlbkd.resource import BaseResource
from managesf.model.yamlbkd.resource import ModelInvalidException
from managesf.model.yamlbkd.resource import ResourceInvalidException
from managesf.model.yamlbkd.resources.dummy import Dummy


class EngineTest(TestCase):

    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()
        engine.conf = cls.conf

    def setUp(self):
        self.to_delete = []

    def tearDown(self):
        for d in self.to_delete:
            shutil.rmtree(d)

    def test_init_engine(self):
        SFResourceBackendEngine('/tmp/dir',
                                'resources')

    def test_get_resources_priority(self):
        class A(BaseResource):
            PRIORITY = 60
            PRIMARY_KEY = None

        class B(BaseResource):
            PRIORITY = 40
            PRIMARY_KEY = None

        class C(BaseResource):
            PRIORITY = 55
            PRIMARY_KEY = None

        en = SFResourceBackendEngine(None, None)
        with patch.dict(engine.MAPPING,
                        {'dummies': Dummy,
                         'A': A,
                         'B': B,
                         'C': C}, clear=True):
            # Resource callback will be called in that
            # order A, C, dummies, B
            self.assertEqual([('A', 60),
                              ('C', 55),
                              ('dummies', 50),
                              ('B', 40)],
                             en._get_resources_priority())
            self.assertTrue(len(en._get_resources_priority()), 4)

    def test_load_resource_data(self):
        path = tempfile.mkdtemp()
        self.to_delete.append(path)
        with patch('managesf.model.yamlbkd.yamlbackend.'
                   'YAMLBackend.__init__') as i, \
                patch('managesf.model.yamlbkd.yamlbackend.'
                      'YAMLBackend.get_data') as g:
            i.return_value = None
            g.return_value = {}
            en = SFResourceBackendEngine(path,
                                         'resources')
            en._load_resource_data(
                'http://sftests.com/r/config.git',
                'heads/master', 'mark')
        self.assertTrue(os.path.isdir(
            os.path.join(path, 'mark')))
        self.assertTrue(i.called)
        self.assertTrue(g.called)

    def test_load_resources_data(self):
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resource_data') as lrd:
            lrd.return_value = {}
            en = SFResourceBackendEngine(None, None)
            en._load_resources_data(
                'http://sftests.com/r/config.git',
                'heads/master',
                'http://sftests.com/r/config.git',
                'changes/99/899/1')
        self.assertEqual(len(lrd.mock_calls), 2)

    def test_validate(self):
        path = tempfile.mkdtemp()
        self.to_delete.append(path)

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_get_data_diff') as gdd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_deps_constraints') as cdc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_unicity_constraints') as cu, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_validate_changes') as vc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_rtype_defined') as cd:
            lrd.return_value = (None, None)
            eng = SFResourceBackendEngine(path, None)
            status, _ = eng.validate(None, None, None, None)
            self.assertTrue(lrd.called)
            self.assertTrue(gdd.called)
            self.assertTrue(cdc.called)
            self.assertTrue(cu.called)
            self.assertTrue(vc.called)
            self.assertTrue(cd.called)
            self.assertTrue(status)

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_get_data_diff') as gdd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_deps_constraints') as cdc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_unicity_constraints') as cu, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_validate_changes') as vc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_rtype_defined') as cd:
            lrd.side_effect = YAMLDBException('')
            eng = SFResourceBackendEngine(path, None)
            status, logs = eng.validate(None, None, None, None)
            self.assertEqual(len(logs), 1)
            self.assertFalse(status)

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_get_data_diff') as gdd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_deps_constraints') as cdc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_unicity_constraints') as cu, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_validate_changes') as vc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_rtype_defined') as cd:
            lrd.return_value = (None, None)
            vc.side_effect = ResourceInvalidException('')
            eng = SFResourceBackendEngine(path, None)
            status, logs = eng.validate(None, None, None, None)
            self.assertEqual(len(logs), 1)
            self.assertFalse(status)

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_get_data_diff') as gdd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_deps_constraints') as cdc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_unicity_constraints') as cu, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_validate_changes') as vc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_rtype_defined') as cd:

            lrd.return_value = (None, None)
            vc.side_effect = ResourceDepsException('')
            eng = SFResourceBackendEngine(path, None)
            status, logs = eng.validate(None, None, None, None)
            self.assertEqual(len(logs), 1)
            self.assertFalse(status)

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_get_data_diff') as gdd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_deps_constraints') as cdc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_unicity_constraints') as cu, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_validate_changes') as vc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_rtype_defined') as cd:

            lrd.return_value = (None, None)
            cu.side_effect = ResourceUnicityException('')
            eng = SFResourceBackendEngine(path, None)
            status, logs = eng.validate(None, None, None, None)
            self.assertEqual(len(logs), 1)
            self.assertFalse(status)

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_get_data_diff') as gdd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_deps_constraints') as cdc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_unicity_constraints') as cu, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_validate_changes') as vc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_rtype_defined') as cd:

            lrd.return_value = (None, None)
            cd.side_effect = RTYPENotDefinedException('')
            eng = SFResourceBackendEngine(path, None)
            status, logs = eng.validate(None, None, None, None)
            self.assertEqual(len(logs), 1)
            self.assertFalse(status)

    def test_validate_from_structured_data(self):
        path = tempfile.mkdtemp()
        self.to_delete.append(path)

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resource_data') as lrd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_deps_constraints') as cdc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_unicity_constraints') as cu, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_load_resource_data_from_memory') as lm, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_get_data_diff') as gdd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_validate_changes') as vc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_rtype_defined') as cd:
            lrd.return_value = (None, None)
            eng = SFResourceBackendEngine(path, None)
            status, _ = eng.validate_from_structured_data(
                None, None, None)
            self.assertTrue(lrd.called)
            self.assertTrue(cdc.called)
            self.assertTrue(cu.called)
            self.assertTrue(lm.called)
            self.assertTrue(gdd.called)
            self.assertTrue(vc.called)
            self.assertTrue(cd.called)
            self.assertTrue(status)

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resource_data') as lrd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_deps_constraints') as cdc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_unicity_constraints') as cu, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_load_resource_data_from_memory') as lm, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_get_data_diff') as gdd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_validate_changes') as vc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_rtype_defined') as cd:
            lrd.side_effect = YAMLDBException('')
            eng = SFResourceBackendEngine(path, None)
            status, logs = eng.validate_from_structured_data(
                None, None, None)
            self.assertEqual(len(logs), 1)
            self.assertFalse(status)

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resource_data') as lrd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_deps_constraints') as cdc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_unicity_constraints') as cu, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_load_resource_data_from_memory') as lm, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_get_data_diff') as gdd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_validate_changes') as v, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_rtype_defined') as cd:
            lrd.return_value = (None, None)
            v.side_effect = ResourceInvalidException('')
            eng = SFResourceBackendEngine(path, None)
            status, logs = eng.validate_from_structured_data(
                None, None, None)
            self.assertEqual(len(logs), 1)
            self.assertFalse(status)

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resource_data') as lrd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_deps_constraints') as cdc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_unicity_constraints') as cu, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_load_resource_data_from_memory') as lm, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_get_data_diff') as gdd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_validate_changes') as v, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_rtype_defined') as cd:
            lrd.return_value = (None, None)
            v.side_effect = ResourceInvalidException('')
            eng = SFResourceBackendEngine(path, None)
            status, logs = eng.validate_from_structured_data(
                None, None, None)
            self.assertEqual(len(logs), 1)
            self.assertFalse(status)

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resource_data') as lrd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_deps_constraints') as cdc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_unicity_constraints') as cu, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_load_resource_data_from_memory') as lm, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_get_data_diff') as gdd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_validate_changes') as v, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_rtype_defined') as cd:
            lrd.return_value = (None, None)
            cd.side_effect = RTYPENotDefinedException('')
            eng = SFResourceBackendEngine(path, None)
            status, logs = eng.validate_from_structured_data(
                None, None, None)
            self.assertEqual(len(logs), 1)
            self.assertFalse(status)

    def test_apply(self):
        path = tempfile.mkdtemp()
        self.to_delete.append(path)
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('managesf.model.yamlbkd.engine.'
                      'SFResourceBackendEngine._get_data_diff') as gdd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_resolv_resources_need_refresh') as rrnr, \
                patch('managesf.model.yamlbkd.engine.'
                      'SFResourceBackendEngine._apply_changes') as ac:
            lrd.return_value = (None, None)
            ac.return_value = False
            rrnr.return_value = []
            eng = SFResourceBackendEngine(path, None)
            status, logs = eng.apply(None, None, None, None)
            self.assertTrue(lrd.called)
            self.assertTrue(gdd.called)
            self.assertTrue(rrnr.called)
            self.assertTrue(ac.called)
            self.assertTrue(status)
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('managesf.model.yamlbkd.engine.'
                      'SFResourceBackendEngine._get_data_diff') as gdd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_resolv_resources_need_refresh') as rrnr, \
                patch('managesf.model.yamlbkd.engine.'
                      'SFResourceBackendEngine._apply_changes') as ac:
            lrd.side_effect = YAMLDBException('')
            eng = SFResourceBackendEngine(path, None)
            status, logs = eng.apply(None, None, None, None)
            self.assertEqual(len(logs), 1)
            self.assertFalse(status)

    def test_direct_apply(self):
        path = tempfile.mkdtemp()
        self.to_delete.append(path)
        with patch('yaml.safe_load'), \
                patch('managesf.model.yamlbkd.yamlbackend.YAMLBackend.'
                      '_validate_base_struct'), \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_get_data_diff') as gdd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_deps_constraints') as cd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_unicity_constraints') as cu, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_validate_changes') as vc, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_resolv_resources_need_refresh') as rrnr, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_apply_changes') as ac:
            ac.return_value = False
            eng = SFResourceBackendEngine(path, None)
            status, logs = eng.direct_apply(None, None)
            self.assertTrue(status)
            self.assertEqual(len(logs), 0)
            self.assertTrue(gdd.called)
            self.assertTrue(cd.called)
            self.assertTrue(cu.called)
            self.assertTrue(vc.called)
            self.assertTrue(rrnr.called)
            self.assertTrue(ac.called)
            self.assertTrue(status)

        with patch('yaml.safe_load'), \
                patch('managesf.model.yamlbkd.yamlbackend.YAMLBackend.'
                      '_validate_base_struct'), \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_get_data_diff') as g, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_deps_constraints') as cd, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_check_unicity_constraints') as cu, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_validate_changes') as v, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_resolv_resources_need_refresh') as r, \
                patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                      '_apply_changes') as a:
            v.side_effect = ResourceInvalidException('')
            eng = SFResourceBackendEngine(path, None)
            status, logs = eng.direct_apply(None, None)
            self.assertFalse(status)
            self.assertEqual(len(logs), 1)
            self.assertTrue(g.called)
            self.assertTrue(cd.called)
            self.assertTrue(cu.called)
            self.assertFalse(r.called)
            self.assertFalse(a.called)
        with patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                   '_apply_changes') as a, \
                patch.dict(engine.MAPPING, {'dummies': Dummy},
                           clear=True):
            a.return_value = False
            prev = "resources: {}"
            new = """resources:
  dummies:
    id1:
      name: dum
      namespace: a
"""
            eng = SFResourceBackendEngine(path, None)
            status, logs = eng.direct_apply(prev, new)
            self.assertIn(
                'id1', a.call_args[0][0]['dummies']['create'])
            self.assertEqual(
                len(a.call_args[0][0]['dummies']['update']), 0)
            self.assertEqual(
                len(a.call_args[0][0]['dummies']['delete']), 0)
            self.assertTrue(status)
        with patch('managesf.model.yamlbkd.engine.SFResourceBackendEngine.'
                   '_apply_changes') as a, \
                patch.dict(engine.MAPPING, {'dummies': Dummy},
                           clear=True):
            new = "a: True"
            eng = SFResourceBackendEngine(path, None)
            status, logs = eng.direct_apply(prev, new)
            self.assertFalse(status)
            self.assertListEqual(
                ['The main resource data structure is invalid'],
                logs)
            self.assertFalse(status)

    def test_get(self):
        with patch('managesf.model.yamlbkd.yamlbackend.'
                   'YAMLBackend.__init__') as i, \
                patch('managesf.model.yamlbkd.yamlbackend.'
                      'YAMLBackend.get_data') as g:
            i.return_value = None
            g.return_value = {}
            eng = SFResourceBackendEngine('/tmp/adir', None)
            data = eng.get('https://sftests.com/r/config', None)
            self.assertTrue(
                data.get('config-repo'), 'https://sftests.com/r/config')
            self.assertNotIn('connections', data['resources'])
            with patch('managesf.model.yamlbkd.engine.conf') as c:
                c.resources.get.return_value = {
                    'github.com': {'base_url': 'https://github.com'}}
                data = eng.get('https://sftests.com/r/config', None)
                self.assertTrue(
                    data.get('config-repo'), 'https://sftests.com/r/config')
                self.assertIn('connections', data['resources'])
                self.assertIn('github.com', data['resources']['connections'])

    def test_get_data_diff(self):
        with patch.dict(engine.MAPPING, {'dummies': Dummy}):
            # Test add resource change detected
            prev = {'resources': {'dummies': {}}}
            new = {'resources': {'dummies': {'myprojectid': {
                   'namespace': 'sf',
                   'name': 'myproject'},
            }}}
            eng = SFResourceBackendEngine(None, None)
            ret = eng._get_data_diff(prev, new)
            self.assertIn('dummies', ret)
            self.assertIn('create', ret['dummies'])
            self.assertIn('myprojectid', ret['dummies']['create'])
            self.assertDictEqual(new['resources']['dummies']['myprojectid'],
                                 ret['dummies']['create']['myprojectid'])
            self.assertEqual(len(ret['dummies']['delete'].keys()), 0)
            self.assertEqual(len(ret['dummies']['update'].keys()), 0)
            # Test delete resource change detected
            prev = {'resources': {'dummies': {'myprojectid': {
                    'namespace': 'sf',
                    'name': 'myproject'},
            }}}
            new = {'resources': {'dummies': {}}}
            eng = SFResourceBackendEngine(None, None)
            ret = eng._get_data_diff(prev, new)
            self.assertIn('myprojectid', ret['dummies']['delete'])
            self.assertEqual(len(ret['dummies']['create'].keys()), 0)
            self.assertEqual(len(ret['dummies']['update'].keys()), 0)
            # Test update resource change detected
            prev = {'resources': {'dummies': {'myprojectid': {
                    'namespace': 'sf'},
            }}}
            new = {'resources': {'dummies': {'myprojectid': {
                   'namespace': 'sf2'},
            }}}
            path = tempfile.mkdtemp()
            self.to_delete.append(path)
            eng = SFResourceBackendEngine(path, None)
            ret = eng._get_data_diff(prev, new)
            self.assertIn('myprojectid', ret['dummies']['update'])
            self.assertIn(
                'namespace',
                ret['dummies']['update']['myprojectid']['changed'])
            self.assertDictEqual(
                new['resources']['dummies']['myprojectid'],
                ret['dummies']['update']['myprojectid']['data'])
            # Test that multiple resource changes are detected
            prev = {'resources': {
                'dummies': {
                    'myprojectid': {
                        'namespace': 'sf',
                        'name': 'myproject'},
                    'superid': {
                        'namespace': 'super',
                        'name': 'project'}
                    },
                'groups': {}
            }}
            new = {'resources': {
                'dummies': {
                    'myprojectid': {
                        'namespace': 'sfnew',
                        'name': 'mynewproject'},
                    'myproject2id': {
                        'namespace': 'sfnew',
                        'name': 'newproject'}
                    },
                'groups': {
                    'mygroupid': {
                        'name': 'mynewgroup'},
                }
            }}
            eng = SFResourceBackendEngine(None, None)
            ret = eng._get_data_diff(prev, new)
            self.assertDictEqual(ret['dummies']['delete']['superid'],
                                 prev['resources']['dummies']['superid'])
            self.assertDictEqual(ret['dummies']['create']['myproject2id'],
                                 new['resources']['dummies']['myproject2id'])
            self.assertIn('namespace',
                          ret['dummies']['update']['myprojectid']['changed'])
            self.assertDictEqual(
                ret['dummies']['update']['myprojectid']['data'],
                new['resources']['dummies']['myprojectid'])
            self.assertDictEqual(ret['groups']['create']['mygroupid'],
                                 new['resources']['groups']['mygroupid'])
            # Test update resource change detected on a list
            prev = {'resources': {'dummies': {'myprojectid': {
                    'members': ['joe', 'paul']}}}}
            new = {'resources': {'dummies': {'myprojectid': {
                   'members': ['paul']}}}}
            path = tempfile.mkdtemp()
            self.to_delete.append(path)
            eng = SFResourceBackendEngine(path, None)
            ret = eng._get_data_diff(prev, new)
            self.assertSetEqual(
                ret['dummies']['update']['myprojectid']['changed'],
                set(['members']))

    def test_validate_changes(self):
        eng = SFResourceBackendEngine(None, None)
        validation_logs = []
        with patch.dict(engine.MAPPING, {'dummies': Dummy}):
            with patch.object(Dummy, 'validate') as v:
                changes = {'dummies': {'create': {'myprojectid': {}}}}
                eng._validate_changes(changes, validation_logs, {})
                self.assertTrue(v.called)
                v.reset_mock()
                changes = {'dummies': {'update': {
                    'myprojectid': {'data': {}, 'changed': []}}}}
                eng._validate_changes(changes, validation_logs, {})
                self.assertTrue(v.called)
                with patch.object(Dummy, 'is_mutable') as i:
                    v.reset_mock()
                    changes = {'dummies': {'update': {
                        'myprojectid': {'data': {}, 'changed': ['name']}}}}
                    eng._validate_changes(changes, validation_logs, {})
                    self.assertTrue(v.called)
                    self.assertTrue(i.called)
            # Be sure we have 3 validation msgs
            self.assertTrue(len(validation_logs), 3)
            validation_logs = []
            with patch.object(Dummy, 'validate') as v:
                v.side_effect = ResourceInvalidException('')
                changes = {'dummies': {'create': {'myprojectid': {}}}}
                self.assertRaises(ResourceInvalidException,
                                  eng._validate_changes,
                                  changes,
                                  validation_logs,
                                  {})
            with patch.object(Dummy, 'validate') as v:
                v.side_effect = ModelInvalidException('')
                changes = {'dummies': {'create': {'myprojectid': {}}}}
                self.assertRaises(ModelInvalidException,
                                  eng._validate_changes,
                                  changes,
                                  validation_logs,
                                  {})
            # Verify extra validations will be handled
            validation_logs = []
            with patch('managesf.model.yamlbkd.resources.'
                       'dummy.DummyOps.extra_validations') as xv:
                xv.return_value = ['error msg1', ' error msg2']
                changes = {'dummies': {'create': {'myprojectid': {
                    'namespace': 'sf', 'name': 'p1'}}}}
                self.assertRaises(ResourceInvalidException,
                                  eng._validate_changes,
                                  changes,
                                  validation_logs,
                                  {})
                self.assertTrue(xv.called)
                self.assertListEqual(['error msg1', ' error msg2'],
                                     validation_logs)

    def test_check_unicity_constraints(self):
        class Master(BaseResource):
            MODEL_TYPE = 'master'
            MODEL = {
                'name': (str, "+*", True, None, True, "desc"),
            }
            PRIORITY = 40
            PRIMARY_KEY = 'name'

        new = {
            'resources': {
                'masters': {
                    'm1': {
                        'name': 'ichiban',
                    },
                    'm2': {
                        'name': 'ichiban',
                    }
                }
            }
        }
        en = SFResourceBackendEngine(None, None)
        with patch.dict(engine.MAPPING,
                        {'masters': Master}):
            self.assertRaises(ResourceUnicityException,
                              en._check_unicity_constraints,
                              new)

    def test_check_deps_constraints(self):
        class Master(BaseResource):
            MODEL_TYPE = 'master'
            MODEL = {
                'name': (str, "+*", True, None, True, "desc"),
                'key1': (str, "+*", True, None, True, "desc"),
                'key2': (list, "+*", True, None, True, "desc"),
            }
            PRIORITY = 40
            PRIMARY_KEY = None

            def get_deps(self):
                deps = {'dummies': set([])}
                deps['dummies'].add(self.resource['key1'])
                for e in self.resource['key2']:
                    deps['dummies'].add(e)
                return deps

        new = {
            'resources': {
                'dummies': {
                    'd1': {
                        'name': 'dummy1',
                        'namespace': 'space',
                    },
                    'd2': {
                        'name': 'dummy2',
                        'namespace': 'space',
                    },
                    'd3': {
                        'name': 'dummy3',
                        'namespace': 'space',
                    },
                },
                'masters': {
                    'm1': {
                        'key1': 'd1',
                        'key2': ['d1', 'd2'],
                    }
                }
            }
        }

        en = SFResourceBackendEngine(None, None)
        with patch.dict(engine.MAPPING,
                        {'dummies': Dummy,
                         'masters': Master}):
            en._check_deps_constraints(new)
            # Add an unknown dependency
            new['resources']['masters']['m1']['key1'] = 'd4'
            self.assertRaises(ResourceDepsException,
                              en._check_deps_constraints,
                              new)

    def test_resolv_resources_need_refresh(self):
        class Master(BaseResource):
            MODEL_TYPE = 'master'
            MODEL = {
                'name': (str, "+*", True, None, True, "desc"),
                'key': (list, "+*", True, None, True, "desc"),
            }
            PRIORITY = 40
            PRIMARY_KEY = None

            def get_deps(self):
                deps = {'dummies': set([])}
                deps['dummies'].add(self.resource['key'])
                return deps

        # Engine dectected dummies:d1 has been updated
        changes = {'dummies': {'update': {'d1': {}}}}

        # masters:m1:key depends on dummies:d1
        tree = {
            'resources': {
                'dummies': {
                    'd1': {
                        'name': 'dummy1',
                        'namespace': 'space',
                    },
                },
                'masters': {
                    'm1': {
                        'key': 'd1',
                    }
                }
            }
        }

        en = SFResourceBackendEngine(None, None)
        with patch.dict(engine.MAPPING,
                        {'dummies': Dummy,
                         'masters': Master}):
            logs = en._resolv_resources_need_refresh(changes, tree)
            self.assertIn('m1', changes['masters']['update'])
            self.assertIn('d1', changes['dummies']['update'])
            self.assertEqual(len(changes['masters']['update']), 1)
            self.assertEqual(len(changes['dummies']['update']), 1)
            self.assertIn('Resource [type: masters, ID: m1] need a '
                          'refresh as at least one of its dependencies '
                          'has been updated', logs)
            self.assertEqual(len(logs), 1)

        # Engine dectected masters:m1 has been updated
        changes = {'masters': {'update': {'m1': {}}}}

        en = SFResourceBackendEngine(None, None)
        with patch.dict(engine.MAPPING,
                        {'dummies': Dummy,
                         'masters': Master}):
            logs = en._resolv_resources_need_refresh(changes, tree)
            # masters:m1 is on top of dependency chain
            # no addtionnal update trigger will be scheduled then
            self.assertEqual(len(logs), 0)
            self.assertIn('m1', changes['masters']['update'])
            self.assertEqual(len(changes['masters']['update']), 1)
            self.assertNotIn('dummies', changes)

        class Master2(BaseResource):
            MODEL_TYPE = 'master2'
            MODEL = {
                'name': (str, "+*", True, None, True, "desc"),
                'key': (str, "+*", True, None, True, "desc"),
            }
            PRIORITY = 30
            PRIMARY_KEY = None

            def get_deps(self):
                return {'masters': set([self.resource['key']])}

        # Engine dectected dummies:d1 has been updated
        changes = {'dummies': {'update': {'d1': {}}}}

        # masters:m1:key depends on dummies:d1
        # masters2:m1:key depends on master:m1
        tree = {
            'resources': {
                'dummies': {
                    'd1': {
                        'name': 'dummy1',
                        'namespace': 'space',
                    },
                },
                'masters': {
                    'm1': {
                        'key': 'd1',
                    }
                },
                'masters2': {
                    'm1': {
                        'key': 'm1',
                    }
                }
            }
        }
        en = SFResourceBackendEngine(None, None)
        with patch.dict(engine.MAPPING,
                        {'dummies': Dummy,
                         'masters': Master,
                         'masters2': Master2}):
            logs = en._resolv_resources_need_refresh(changes, tree)
            self.assertTrue(len(logs), 2)
            self.assertIn('Resource [type: masters, ID: m1] need a refresh '
                          'as at least one of its dependencies has been '
                          'updated', logs)
            self.assertIn('Resource [type: masters2, ID: m1] need a refresh '
                          'as at least one of its dependencies has been '
                          'updated', logs)
            self.assertIn('m1', changes['masters2']['update'])
            self.assertIn('m1', changes['masters']['update'])
            self.assertIn('d1', changes['dummies']['update'])
            self.assertTrue(len(changes['masters2']['update']), 1)
            self.assertTrue(len(changes['masters']['update']), 1)
            self.assertTrue(len(changes['dummies']['update']), 1)

    def test_apply_changes(self):
        eng = SFResourceBackendEngine(None, None)
        apply_logs = []
        with patch.dict(engine.MAPPING, {'dummies': Dummy}):
            with patch('managesf.model.yamlbkd.resources.'
                       'dummy.DummyOps.create') as c:
                c.return_value = []
                changes = {'dummies': {'create': {'myprojectid': {}}}}
                self.assertFalse(eng._apply_changes(changes, apply_logs, {}))
                self.assertTrue(c.called)
            self.assertIn(
                'Resource [type: dummies, ID: myprojectid] '
                'will be created.',
                apply_logs)
            self.assertIn(
                'Resource [type: dummies, ID: myprojectid] '
                'has been created.',
                apply_logs)
            self.assertTrue(len(apply_logs), 2)

            apply_logs = []
            with patch('managesf.model.yamlbkd.resources.'
                       'dummy.DummyOps.create') as c:
                c.return_value = ["Resource API error"]
                changes = {'dummies': {'create': {'myprojectid': {}}}}
                self.assertTrue(eng._apply_changes(changes, apply_logs, {}))

            apply_logs = []
            with patch('managesf.model.yamlbkd.resources.'
                       'dummy.DummyOps.create') as c:
                c.return_value = ["Resource API error"]
                changes = {
                    'dummies': {
                        'create': {
                            'myprojectid': {}
                        },
                        'update': {
                            'myprojectid2': {
                                'data': {'key': 'value'},
                                'changed': ['key']
                            }
                        }
                    }
                }
                self.assertTrue(eng._apply_changes(changes, apply_logs, {}))
                self.assertIn('Resource [type: dummies, ID: myprojectid] '
                              'will be created.',
                              apply_logs)
                self.assertIn('Resource API error',
                              apply_logs)
                self.assertIn('Resource [type: dummies, ID: myprojectid] '
                              'create op failed.',
                              apply_logs)
                self.assertIn('Resource [type: dummies, ID: myprojectid2] '
                              'will be updated.',
                              apply_logs)
                self.assertIn('Resource [type: dummies, ID: myprojectid2] '
                              'has been updated.',
                              apply_logs)

            # Verify an unexpected exception is properly catched
            apply_logs = []
            with patch('managesf.model.yamlbkd.resources.'
                       'dummy.DummyOps.create') as c:
                c.side_effect = Exception('Random Error msg')
                changes = {'dummies': {'create': {'myprojectid': {}}}}
                self.assertTrue(eng._apply_changes(changes, apply_logs, {}))
                self.assertIn('Resource [type: dummies, ID: myprojectid] '
                              'create op error (Random Error msg).',
                              apply_logs)

            # Verify an unexpected exception does not exit _apply_changes
            apply_logs = []
            with patch('managesf.model.yamlbkd.resources.'
                       'dummy.DummyOps.create') as c:
                c.side_effect = Exception('Random Error msg')
                changes = {
                    'dummies': {
                        'create': {
                            'myprojectid1': {},
                            'myprojectid2': {},
                            'myprojectid3': {},
                        },
                    }
                }
                self.assertTrue(eng._apply_changes(changes, apply_logs, {}))
                for r in ('myprojectid1', 'myprojectid2', 'myprojectid3'):
                    self.assertIn(
                        'Resource [type: dummies, ID: %s] will be created.' % (
                            r), apply_logs)
                    self.assertIn(
                        'Resource [type: dummies, ID: %s] create op error '
                        '(Random Error msg).' % r, apply_logs)
                    self.assertIn(
                        'Resource [type: dummies, ID: %s] create op '
                        'failed.' % r, apply_logs)

    def test_get_missing_resources(self):
        class Dummy2(Dummy):
            MODEL_TYPE = 'dummy2'
            MODEL = {
                'name': (
                    str,
                    '.*',
                    True,
                    None,
                    False,
                    "Resource name",
                ),
                'deps': (
                    list,
                    '.*',
                    False,
                    [],
                    True,
                    "Resource dependencies",
                ),
            }
            PRIMARY_KEY = 'name'

            def get_deps(self, keyname=False):
                if keyname:
                    return 'deps'
                else:
                    return {'dummies': set(self.resource['deps'])}

        with patch('managesf.model.yamlbkd.yamlbackend.'
                   'YAMLBackend.__init__'), \
                patch.object(SFResourceBackendEngine, 'get') as g, \
                patch.dict(engine.MAPPING,
                           {'dummies': Dummy, 'dummies2': Dummy2},
                           clear=True), \
                patch('managesf.model.yamlbkd.resources.'
                      'dummy.DummyOps.get_all') as ga:
            eng = SFResourceBackendEngine(None, None)
            # PRIMARY_KEY of Dummy is 'name'
            # PRIMARY_KEY of Dummy2 is 'name'

            # Check basic scenario. dummies:d2 is really new
            current_resources = {
                'dummies': {
                    'd1': {
                        'namespace': 'sf',
                        'name': 'd1',
                    },
                }
            }
            real_resources = {
                'dummies': {
                    'd2': {
                        'namespace': 'sf',
                        'name': 'd2',
                    },
                }
            }
            g.return_value = {'resources': current_resources}
            ga.return_value = ([], real_resources)
            logs, ret = eng.get_missing_resources(None, None)
            expected = {
                'resources': {
                    'dummies': {
                        'd2': {
                            'namespace': 'sf',
                        },
                    }
                }
            }
            self.assertDictEqual(ret, expected)
            self.assertListEqual(logs, [])

            # Check both resources are detected similar.
            # dummies:d1 is dummies:dummy-d1-id
            current_resources = {
                'dummies': {
                    'd1': {
                        'namespace': 'sf',
                    },
                }
            }
            real_resources = {
                'dummies': {
                    'd1': {
                        'namespace': 'sf',
                    },
                }
            }
            g.return_value = {'resources': current_resources}
            ga.return_value = ([], real_resources)
            logs, ret = eng.get_missing_resources(None, None)
            expected = {
                'resources': {}
            }
            self.assertDictEqual(ret, expected)
            self.assertListEqual(logs, [])

            # Check both resources are detected similar.
            # dummies:d1 is dummies:dummy-d1-id
            # dummies2:d2_1 depends on dummies:d1 but
            # dummies:d1 is know under dummies:dummy-d1-id
            # This check make sure the deps if is updated.
            current_resources = {
                'dummies': {
                    'd1': {
                        'namespace': 'sf',
                    },
                }
            }
            real_resources = {
                'dummies': {
                    'd1': {
                        'namespace': 'sf',
                    },
                },
                'dummies2': {
                    'd2_1': {
                        'deps': ['d1'],
                    },
                },
            }
            g.return_value = {'resources': current_resources}
            ga.return_value = ([], real_resources)
            logs, ret = eng.get_missing_resources(None, None)
            expected = {
                'resources': {
                    'dummies2': {
                        'd2_1': {
                            'deps': ['d1'],
                        }
                    }
                }
            }
            self.assertDictEqual(ret, expected)
            self.assertListEqual(logs, [])
